//! Repository-scoped forge resolution and independent, host-bound credentials.

use std::collections::BTreeMap;
use std::sync::Arc;

use intent_core::settings_file::{SourceControlConnectionSettings, SourceControlProvider};
use intent_core::{Error, GitRemoteUrl, RepoRef, Result, Workspace, WorkspaceApi, WorkspaceId};
use intent_sourcecontrol::{
    GithubSettings, GitlabSettings, SourceControl, SourceControlRegistry, SourceControlSettings,
    TokenSource,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{github_browse_ops, pr_ops, Services};

#[derive(Clone, Default)]
pub(crate) struct SourceControlRuntime {
    generation: Arc<std::sync::atomic::AtomicU64>,
    rate_limit: Arc<crate::rate_limit::RateLimitGate>,
    fetch_cache: crate::pr_monitor::PrMonitorFetchCache,
    logged_interval: Arc<std::sync::Mutex<Option<crate::pr_monitor::LoggedCadence>>>,
}

const GITHUB: &str = "https://github.com";
const GITLAB: &str = "https://gitlab.com";

fn normalize_instance(value: &str) -> Result<String> {
    intent_sourcecontrol::gitlab_token::normalize_instance_url(value).map_err(pr_ops::map_sc_err)
}

fn secret_account(instance: &str) -> String {
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(instance.as_bytes()) {
        write!(digest, "{byte:02x}").expect("writing a string cannot fail");
    }
    format!("sourceControl.connections.{digest}.token")
}

fn token_source_name<T: serde::Serialize>(source: T) -> String {
    serde_json::to_value(source)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "auto".into())
}

/// Legacy configuration is imported as independent entries, without mutating
/// settings on a read. An explicit registry entry (including a disconnect
/// tombstone) wins over legacy settings and cannot resurrect a removed token.
pub(crate) fn configured_connections(
    config: &intent_core::settings_file::SourceControlSettings,
) -> BTreeMap<String, SourceControlConnectionSettings> {
    let mut entries = BTreeMap::new();
    entries.insert(
        GITHUB.into(),
        SourceControlConnectionSettings {
            provider: SourceControlProvider::Github,
            token_source: token_source_name(config.github.token_source),
            expose_git_credential_to_children: config.github.expose_git_credential_to_children,
            ..Default::default()
        },
    );
    entries.insert(
        GITLAB.into(),
        SourceControlConnectionSettings {
            provider: SourceControlProvider::Gitlab,
            ..Default::default()
        },
    );
    if let Ok(instance) = normalize_instance(&config.gitlab.instance_url) {
        entries.insert(
            instance,
            SourceControlConnectionSettings {
                provider: SourceControlProvider::Gitlab,
                token_source: token_source_name(config.gitlab.token_source),
                ..Default::default()
            },
        );
    }
    entries.extend(config.connections.clone());
    entries
}

fn repo_on_connection(
    instance: &str,
    connection: &SourceControlConnectionSettings,
    remote: &GitRemoteUrl,
) -> Option<RepoRef> {
    match connection.provider {
        SourceControlProvider::Github => {
            if instance != GITHUB {
                return None;
            }
            let path = remote.path().trim_matches('/');
            let mut parts = path.split('/');
            let owner = parts.next()?;
            let name = parts.next()?;
            let suffix = parts.next();
            if suffix.is_some_and(|s| !matches!(s, "pull" | "issues" | "tree" | "commit")) {
                return None;
            }
            let github =
                GitRemoteUrl::parse(if remote.host().eq_ignore_ascii_case("www.github.com") {
                    "https://www.github.com/_/_"
                } else {
                    "https://github.com/_/_"
                })?;
            if !remote.same_forge_host(&github) {
                return None;
            }
            GitRemoteUrl::parse(&format!("https://{}/{owner}/{name}", remote.host()))?.github_repo()
        }
        SourceControlProvider::Gitlab => remote.gitlab_repo(instance),
    }
}

pub(crate) fn connection_for_url(
    config: &intent_core::settings_file::SourceControlSettings,
    url: &str,
) -> Option<(String, RepoRef)> {
    let remote = GitRemoteUrl::parse(url)?;
    // Prefer the most specific configured installation prefix on a shared host.
    let mut matches = configured_connections(config)
        .into_iter()
        .filter_map(|(id, entry)| repo_on_connection(&id, &entry, &remote).map(|repo| (id, repo)))
        .collect::<Vec<_>>();
    let http = url.split_once("://").is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    });
    if !http && matches.len() > 1 {
        return None;
    }
    matches.sort_by_key(|(id, _)| id.len());
    matches.pop()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionInput {
    provider: SourceControlProvider,
    instance_url: String,
    #[serde(default = "default_token_source")]
    token_source: String,
    token: Option<String>,
}
fn default_token_source() -> String {
    "auto".into()
}

impl Services {
    pub(crate) fn with_source_control_scope(&self, id: &str) -> Self {
        let mut scoped = self.clone();
        let mut runtimes = self.source_control_runtimes.lock().unwrap();
        runtimes
            .entry(GITHUB.into())
            .or_insert_with(|| SourceControlRuntime {
                generation: Arc::default(),
                rate_limit: self.sweep_rate_limit.clone(),
                fetch_cache: self.pr_monitor_fetch_cache.clone(),
                logged_interval: self.pr_monitor_logged_interval.clone(),
            });
        let runtime = runtimes.entry(id.into()).or_default();
        scoped.source_control_connection = Some(id.into());
        scoped.source_control_generation = Some(
            runtime
                .generation
                .load(std::sync::atomic::Ordering::Acquire),
        );
        scoped.sweep_rate_limit = runtime.rate_limit.clone();
        scoped.pr_monitor_fetch_cache = runtime.fetch_cache.clone();
        scoped.pr_monitor_logged_interval = runtime.logged_interval.clone();
        scoped
    }

    fn connection_config(&self, id: &str) -> Result<(String, SourceControlConnectionSettings)> {
        let id = normalize_instance(id)?;
        let config = configured_connections(&self.effective_settings().source_control)
            .remove(&id)
            .ok_or_else(|| {
                Error::InvalidParams("Source-control instance is not registered".into())
            })?;
        Ok((id, config))
    }

    async fn connection_token(
        &self,
        id: &str,
        config: &SourceControlConnectionSettings,
    ) -> Result<String> {
        if !config.enabled {
            return Err(Error::Internal(
                "Source-control connection is disconnected".into(),
            ));
        }
        let stored = self
            .secrets
            .load(&secret_account(id))
            .await?
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .filter(|record| {
                record["instanceUrl"].as_str() == Some(id)
                    && record["provider"] == json!(config.provider)
            })
            .and_then(|record| record["token"].as_str().map(str::to_owned));
        let stored = if stored.is_some() {
            stored
        } else if config.provider == SourceControlProvider::Github && id == GITHUB {
            self.secrets.load("sourceControl.github.token").await?
        } else if config.provider == SourceControlProvider::Gitlab {
            self.secrets
                .load("sourceControl.gitlab.token")
                .await?
                .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                .filter(|record| {
                    record["instanceUrl"]
                        .as_str()
                        .and_then(|url| normalize_instance(url).ok())
                        .as_deref()
                        == Some(id)
                })
                .and_then(|record| record["token"].as_str().map(str::to_owned))
        } else {
            None
        };
        match config.provider {
            SourceControlProvider::Gitlab => {
                let source = serde_json::from_value(json!(config.token_source))
                    .map_err(|_| Error::InvalidParams("Unsupported GitLab token source".into()))?;
                intent_sourcecontrol::gitlab_token::resolve(&GitlabSettings {
                    instance_url: id.into(),
                    token_source: source,
                    token: stored,
                    token_host: Some(id.into()),
                })
                .await
                .map_err(pr_ops::map_sc_err)
            }
            SourceControlProvider::Github => {
                if id != GITHUB {
                    return Err(Error::InvalidParams(
                        "GitHub connections currently require https://github.com".into(),
                    ));
                }
                if matches!(config.token_source.as_str(), "auto" | "explicit") {
                    if let Some(token) = stored.filter(|token| !token.trim().is_empty()) {
                        return Ok(token);
                    }
                }
                // The injected secrets store above is authoritative: never reread
                // a process-global default file while resolving another daemon.
                let token = match config.token_source.as_str() {
                    "env" => intent_sourcecontrol::token::resolve(&TokenSource::Env).await,
                    "gh-cli" => intent_sourcecontrol::token::resolve(&TokenSource::GhCli).await,
                    "auto" => match intent_sourcecontrol::token::resolve(&TokenSource::Env).await {
                        Some(token) => Some(token),
                        None => intent_sourcecontrol::token::resolve(&TokenSource::GhCli).await,
                    },
                    "explicit" => None,
                    _ => {
                        return Err(Error::InvalidParams(
                            "Unsupported GitHub token source".into(),
                        ))
                    }
                };
                token.ok_or_else(|| {
                    Error::Internal("Source-control connection is not authenticated".into())
                })
            }
        }
    }

    pub(crate) async fn resolve_source_control_connection(
        &self,
        id: &str,
    ) -> Result<Arc<dyn SourceControl>> {
        if let Some(sc) = &self.source_control {
            return Ok(sc.clone());
        }
        let (id, config) = self.connection_config(id)?;
        let token = self.connection_token(&id, &config).await?;
        SourceControlRegistry::from_settings(&SourceControlSettings {
            active_provider: token_source_name(config.provider),
            github: GithubSettings {
                token: Some(token.clone()),
                token_source: TokenSource::Explicit,
                api_base_url: Some(self.effective_settings().source_control.github.api_base_url),
            },
            gitlab: GitlabSettings {
                instance_url: id.clone(),
                token: Some(token),
                token_host: Some(id),
                token_source: intent_sourcecontrol::GitlabTokenSource::Explicit,
            },
        })
        .await
        .map_err(pr_ops::map_sc_err)
    }

    pub(crate) async fn resolve_source_control_for_url(
        &self,
        url: &str,
    ) -> Result<Arc<dyn SourceControl>> {
        if let Some(sc) = &self.source_control {
            return Ok(sc.clone());
        }
        let (id, _) = connection_for_url(&self.effective_settings().source_control, url)
            .ok_or_else(|| {
                Error::InvalidParams(
                    "Repository URL has no registered source-control connection".into(),
                )
            })?;
        self.resolve_source_control_connection(&id).await
    }

    /// Legacy explicit `github.*` methods are always GitHub. Neutral aliases
    /// supply a request-local connection without changing any other request.
    pub(crate) async fn resolve_source_control(&self) -> Result<Arc<dyn SourceControl>> {
        self.resolve_source_control_connection(
            self.source_control_connection.as_deref().unwrap_or(GITHUB),
        )
        .await
    }

    pub(crate) async fn workspace_source_control_connection(
        &self,
        ws: &Workspace,
    ) -> Result<String> {
        if self.source_control.is_some() {
            return Ok(self
                .source_control_connection
                .clone()
                .unwrap_or_else(|| GITHUB.into()));
        }
        if let Some(path) = ws.worktree_path.as_ref().or(ws.repository_path.as_ref()) {
            let path = path.clone();
            let origin = tokio::task::spawn_blocking(move || {
                intent_git::remote::origin_url(std::path::Path::new(&path))
            })
            .await
            .map_err(|e| Error::Internal(format!("Repository origin probe failed: {e}")))??;
            if let Some(origin) = origin {
                return connection_for_url(&self.effective_settings().source_control, &origin)
                    .map(|(id, _)| id)
                    .ok_or_else(|| {
                        Error::InvalidParams(
                            "Repository origin has no registered source-control connection".into(),
                        )
                    });
            }
        }
        if let Some(url) = ws.pr_url.as_deref().filter(|url| !url.is_empty()) {
            return connection_for_url(&self.effective_settings().source_control, url)
                .map(|(id, _)| id)
                .ok_or_else(|| {
                    Error::InvalidParams(
                        "Workspace pull request has no registered source-control connection".into(),
                    )
                });
        }
        // Existing GitHub-only rows did not record host provenance.
        Ok(GITHUB.into())
    }

    pub(crate) async fn monitor_source_control_connection(
        &self,
        monitor: &intent_core::PrMonitor,
    ) -> Result<String> {
        let ws = self.store.get_workspace(&monitor.workspace_id).await?;
        let origin = self
            .source_control_provenance(
                None,
                ws.worktree_path
                    .as_deref()
                    .or(ws.repository_path.as_deref()),
            )
            .await;
        let snapshot_url = monitor
            .last_snapshot
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|snapshot| snapshot["url"].as_str().map(str::to_owned));
        if let Some(url) = origin.or(snapshot_url).or(ws.pr_url) {
            return connection_for_url(&self.effective_settings().source_control, &url)
                .map(|(id, _)| id)
                .ok_or_else(|| {
                    Error::InvalidParams(
                        "Monitor repository has no registered source-control connection".into(),
                    )
                });
        }
        Ok(GITHUB.into())
    }

    pub(crate) async fn monitor_rate_limit_paused_until(
        &self,
        monitor: &intent_core::PrMonitor,
    ) -> Option<String> {
        if self.source_control.is_some() && self.source_control_connection.is_none() {
            return self.sweep_rate_limit_paused_until();
        }
        let id = self.monitor_source_control_connection(monitor).await.ok()?;
        self.with_source_control_scope(&id)
            .sweep_rate_limit_paused_until()
    }

    pub(crate) async fn connection_monitor_ids(
        &self,
    ) -> Result<Option<Vec<intent_core::PrMonitorId>>> {
        let Some(id) = self.source_control_connection.as_deref() else {
            return Ok(None);
        };
        let mut ids = Vec::new();
        for monitor in self.store.load_active_pr_monitors().await? {
            if self
                .monitor_source_control_connection(&monitor)
                .await
                .ok()
                .as_deref()
                == Some(id)
            {
                ids.push(monitor.monitor_id);
            }
        }
        Ok(Some(ids))
    }

    pub(crate) async fn resolve_workspace_source_control(
        &self,
        ws: &Workspace,
    ) -> Result<Arc<dyn SourceControl>> {
        if let Some(sc) = &self.source_control {
            return Ok(sc.clone());
        }
        self.resolve_source_control_connection(&self.workspace_source_control_connection(ws).await?)
            .await
    }

    pub(crate) async fn ensure_workspace_source_control(&self, ws: &Workspace) -> Result<()> {
        if self.source_control.is_some() {
            return Ok(());
        }
        self.workspace_source_control_connection(ws)
            .await
            .map(|_| ())
    }

    pub(crate) fn configured_repo_from_url(&self, url: &str) -> Option<RepoRef> {
        configured_repo_from_url(&self.effective_settings().source_control, url)
    }
    pub(crate) fn source_control_url_matches(&self, url: &str) -> bool {
        connection_for_url(&self.effective_settings().source_control, url).is_some()
    }
    pub(crate) async fn source_control_provenance(
        &self,
        pr_url: Option<&str>,
        path: Option<&str>,
    ) -> Option<String> {
        if let Some(path) = path {
            let path = path.to_string();
            if let Some(origin) = tokio::task::spawn_blocking(move || {
                intent_git::remote::origin_url(std::path::Path::new(&path))
            })
            .await
            .ok()
            .and_then(std::result::Result::ok)
            .flatten()
            {
                return Some(origin);
            }
        }
        pr_url.filter(|url| !url.is_empty()).map(str::to_owned)
    }
    fn source_control_connection_is_current(
        &self,
        before: &intent_core::settings_file::SourceControlSettings,
        id: &str,
    ) -> bool {
        let current = configured_connections(&self.effective_settings().source_control);
        let Some(entry) = current.get(id) else {
            return false;
        };
        let generation_matches = self.source_control_generation.is_none_or(|generation| {
            self.source_control_runtimes
                .lock()
                .unwrap()
                .get(id)
                .is_none_or(|runtime| {
                    runtime
                        .generation
                        .load(std::sync::atomic::Ordering::Acquire)
                        == generation
                })
        });
        entry.enabled && configured_connections(before).get(id) == Some(entry) && generation_matches
    }

    pub(crate) fn source_control_result_matches(
        &self,
        config: &intent_core::settings_file::SourceControlSettings,
        expected_url: Option<&str>,
        fetched_url: &str,
    ) -> bool {
        let current = self.effective_settings().source_control;
        let connection_matches =
            connection_for_url(&current, fetched_url).is_some_and(|(id, _)| {
                self.source_control_connection_is_current(config, &id)
                    && self
                        .source_control_connection
                        .as_ref()
                        .is_none_or(|scope| scope == &id)
            });
        (self.source_control.is_some() || connection_matches)
            && expected_url.is_none_or(|expected| {
                match (
                    GitRemoteUrl::parse(expected),
                    GitRemoteUrl::parse(fetched_url),
                ) {
                    (Some(left), Some(right)) => same_repository_remote(&left, &right),
                    _ => false,
                }
            })
    }

    fn git_credential_connection(&self, url: &str) -> Option<String> {
        configured_connections(&self.effective_settings().source_control)
            .into_iter()
            .filter(|(id, config)| {
                let username = if config.provider == SourceControlProvider::Gitlab {
                    "oauth2"
                } else {
                    "x-access-token"
                };
                intent_git::auth::GitCredential::new(id, username, "scope")
                    .is_some_and(|credential| credential.matches_url(url))
            })
            .map(|(id, _)| id)
            .max_by_key(String::len)
    }
    /// Resolve one scoped HTTPS credential using the same connection and secret
    /// registry as the REST API. Redirect checks remain owned by intent-git.
    pub async fn git_credential_for_url(
        &self,
        url: &str,
    ) -> Option<intent_git::auth::GitCredential> {
        let id = self.git_credential_connection(url)?;
        let (_, config) = self.connection_config(&id).ok()?;
        let token = self.connection_token(&id, &config).await.ok()?;
        let username = if config.provider == SourceControlProvider::Gitlab {
            "oauth2"
        } else {
            "x-access-token"
        };
        let credential = intent_git::auth::GitCredential::new(&id, username, &token)?;
        credential.matches_url(url).then_some(credential)
    }
    /// Resolve a repository credential only when this connection permits child-process access.
    pub async fn git_credential_for_child_url(
        &self,
        url: &str,
    ) -> Option<intent_git::auth::GitCredential> {
        let id = self.git_credential_connection(url)?;
        let (_, config) = self.connection_config(&id).ok()?;
        if !config.expose_git_credential_to_children {
            return None;
        }
        self.git_credential_for_url(url).await
    }
    /// Return the independently enabled credential scopes available to child processes.
    #[must_use]
    pub fn git_credential_instances_for_children(&self) -> Vec<String> {
        configured_connections(&self.effective_settings().source_control)
            .into_iter()
            .filter(|(_, config)| config.enabled && config.expose_git_credential_to_children)
            .map(|(id, _)| id)
            .collect()
    }

    async fn connection_status(&self, id: &str) -> Result<Value> {
        let (id, config) = self.connection_config(id)?;
        let user = match self.resolve_source_control_connection(&id).await {
            Ok(sc) => sc
                .get_user()
                .await
                .ok()
                .map(|user| github_browse_ops::user_to_wire(&user)),
            Err(_) => None,
        };
        Ok(
            json!({"id":id,"provider":config.provider,"instanceUrl":id,"tokenSource":config.token_source,"enabled":config.enabled,"isConfigured":user.is_some(),"user":user}),
        )
    }

    pub(crate) async fn list_source_control_connections(&self) -> Result<Value> {
        Self::require_administrator("sourceControl.connections.list")?;
        let mut results = Vec::new();
        for id in configured_connections(&self.effective_settings().source_control).keys() {
            results.push(self.connection_status(id).await?);
        }
        Ok(json!({"connections":results}))
    }
    pub(crate) async fn source_control_connection_status(&self, id: &str) -> Result<Value> {
        Self::require_administrator("sourceControl.authStatus")?;
        Ok(json!({"connection":self.connection_status(id).await?}))
    }
    pub(crate) async fn configure_source_control_connection(&self, value: Value) -> Result<Value> {
        Self::require_administrator("sourceControl.connections.configure")?;
        let input: ConnectionInput = serde_json::from_value(value).map_err(|_| {
            Error::InvalidParams("Invalid source-control connection configuration".into())
        })?;
        let id = normalize_instance(&input.instance_url)?;
        let allowed = match input.provider {
            SourceControlProvider::Github => &["auto", "explicit", "env", "gh-cli"][..],
            SourceControlProvider::Gitlab => &["auto", "explicit", "env", "glab-cli"][..],
        };
        if !allowed.contains(&input.token_source.as_str())
            || (input.provider == SourceControlProvider::Github && id != GITHUB)
            || (input.provider == SourceControlProvider::Gitlab && id == GITHUB)
        {
            return Err(Error::InvalidParams(
                "Unsupported source-control provider or token source for this instance".into(),
            ));
        }
        let guard = self.source_control_config_gate.lock().await;
        let key = if input.provider == SourceControlProvider::Github {
            "sourceControl.github.token".into()
        } else {
            secret_account(&id)
        };
        let previous = self.secrets.load(&key).await?;
        if let Some(token) = input
            .token
            .as_ref()
            .filter(|token| !token.trim().is_empty())
        {
            let record = if input.provider == SourceControlProvider::Github {
                token.clone()
            } else {
                json!({"provider":input.provider,"instanceUrl":id,"token":token}).to_string()
            };
            self.secrets.store(&key, &record).await?;
        }
        let mut entries = self.effective_settings().source_control.connections;
        let expose_git_credential_to_children =
            self.connection_config(&id).map_or(true, |(_, existing)| {
                existing.expose_git_credential_to_children
            });
        entries.insert(
            id.clone(),
            SourceControlConnectionSettings {
                provider: input.provider,
                token_source: input.token_source,
                enabled: true,
                expose_git_credential_to_children,
            },
        );
        if let Err(error) = self
            .settings_update(json!([{"path":"sourceControl.connections","value":entries}]))
            .await
        {
            if input.token.is_some() {
                match previous {
                    Some(old) => self.secrets.store(&key, &old).await?,
                    None => self.secrets.delete(&key).await?,
                }
            }
            return Err(error);
        }
        self.invalidate_source_control_connection(&id);
        drop(guard);
        self.source_control_connection_status(&id).await
    }
    pub(crate) fn invalidate_source_control_connection(&self, id: &str) {
        if let Some(runtime) = self.source_control_runtimes.lock().unwrap().get_mut(id) {
            runtime
                .generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            // Old requests retain their detached cache; a late fetch cannot
            // populate the fresh account's cache through an ABA generation.
            runtime.fetch_cache = Arc::default();
        }
    }

    pub(crate) fn invalidate_source_control_settings_change(
        &self,
        before: &intent_core::settings_file::SourceControlSettings,
        changes: &[Value],
    ) {
        let after = self.effective_settings().source_control;
        let old_entries = configured_connections(before);
        let new_entries = configured_connections(&after);
        let mut affected = std::collections::BTreeSet::new();
        for id in old_entries.keys().chain(new_entries.keys()) {
            if old_entries.get(id) != new_entries.get(id) {
                affected.insert(id.clone());
            }
        }
        for path in changes.iter().filter_map(|change| change["path"].as_str()) {
            if path.starts_with("sourceControl.github.") {
                affected.insert(GITHUB.into());
            }
            if path.starts_with("sourceControl.gitlab.") {
                for instance in [&before.gitlab.instance_url, &after.gitlab.instance_url] {
                    if let Ok(id) = normalize_instance(instance) {
                        affected.insert(id);
                    }
                }
            }
        }
        for id in affected {
            self.invalidate_source_control_connection(&id);
        }
    }

    pub(crate) async fn source_control_origin_unchanged(
        &self,
        config: &intent_core::settings_file::SourceControlSettings,
        expected: Option<&str>,
        path: Option<&str>,
    ) -> bool {
        let current = self.source_control_provenance(None, path).await;
        if self.source_control.is_none()
            && !self.source_control_connection_is_current(
                config,
                self.source_control_connection.as_deref().unwrap_or(GITHUB),
            )
        {
            return false;
        }
        current.is_none_or(|current| {
            expected.is_some_and(|expected| {
                expected == current
                    || match (GitRemoteUrl::parse(expected), GitRemoteUrl::parse(&current)) {
                        (Some(old), Some(current)) => same_repository_remote(&old, &current),
                        _ => false,
                    }
            })
        })
    }

    pub(crate) async fn enable_github_oauth_connection(&self) -> Result<()> {
        self.invalidate_source_control_connection(GITHUB);
        let _guard = self.source_control_config_gate.lock().await;
        let mut entries = self.effective_settings().source_control.connections;
        if let Some(entry) = entries.get_mut(GITHUB) {
            entry.enabled = true;
            entry.token_source = "auto".into();
            self.settings_update(json!([{"path":"sourceControl.connections","value":entries}]))
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn disconnect_source_control_connection(&self, id: &str) -> Result<Value> {
        Self::require_administrator("sourceControl.connections.disconnect")?;
        let guard = self.source_control_config_gate.lock().await;
        let (id, mut entry) = self.connection_config(id)?;
        entry.enabled = false;
        entry.token_source = "explicit".into();
        let mut entries = self.effective_settings().source_control.connections;
        entries.insert(id.clone(), entry);
        // Disable first: any old credential remains unusable even if secret deletion fails.
        self.settings_update(json!([{"path":"sourceControl.connections","value":entries}]))
            .await?;
        self.secrets.delete(&secret_account(&id)).await?;
        if id == GITHUB {
            self.secrets.delete("sourceControl.github.token").await?;
        }
        self.invalidate_source_control_connection(&id);
        drop(guard);
        self.source_control_connection_status(&id).await
    }

    async fn target_connection(&self, target: &Value) -> Result<(String, Option<RepoRef>)> {
        let mut resolved = None;
        if let Some(workspace) = target.get("workspaceId").and_then(Value::as_str) {
            let workspace_id = WorkspaceId::from_string(workspace);
            self.require_member(&workspace_id).await?;
            let ws = self.store.get_workspace(&workspace_id).await?;
            let origin = self
                .source_control_provenance(
                    ws.pr_url.as_deref(),
                    ws.worktree_path
                        .as_deref()
                        .or(ws.repository_path.as_deref()),
                )
                .await;
            let repo = origin
                .as_deref()
                .and_then(|url| self.configured_repo_from_url(url))
                .or_else(|| pr_ops::repo_of(&ws).ok());
            resolved = Some((self.workspace_source_control_connection(&ws).await?, repo));
        }
        if let Some(url) = target.get("repoUrl").and_then(Value::as_str) {
            let (id, repo) = connection_for_url(&self.effective_settings().source_control, url)
                .ok_or_else(|| {
                    Error::InvalidParams(
                        "Repository URL has no registered source-control connection".into(),
                    )
                })?;
            if resolved.as_ref().is_some_and(|(previous, previous_repo)| {
                previous != &id
                    || previous_repo
                        .as_ref()
                        .is_some_and(|previous_repo| previous_repo != &repo)
            }) {
                return Err(Error::InvalidParams(
                    "Conflicting source-control targets".into(),
                ));
            }
            resolved = Some((id, Some(repo)));
        }
        if let Some(id) = target.get("connectionId").and_then(Value::as_str) {
            let (id, _) = self.connection_config(id)?;
            if resolved
                .as_ref()
                .is_some_and(|(previous, _)| previous != &id)
            {
                return Err(Error::InvalidParams(
                    "Conflicting source-control targets".into(),
                ));
            }
            if resolved.is_none() {
                resolved = Some((id, None));
            }
        }
        resolved.ok_or_else(|| {
            Error::InvalidParams("Supply connectionId, repoUrl, or workspaceId".into())
        })
    }
    pub(crate) async fn scoped_source_control(
        &self,
        target: Value,
    ) -> Result<Arc<dyn WorkspaceApi>> {
        Self::require_administrator("sourceControl.repositoryOperation")?;
        let (id, repo) = self.target_connection(&target).await?;
        if let Some(repo) = repo {
            if let (Some(owner), Some(name)) = (
                target.get("owner").and_then(Value::as_str),
                target.get("repo").and_then(Value::as_str),
            ) {
                if repo != RepoRef::new(owner, name) {
                    return Err(Error::InvalidParams(
                        "Repository parameters disagree with target URL".into(),
                    ));
                }
            }
        }
        Ok(Arc::new(self.with_source_control_scope(&id)))
    }
    pub(crate) async fn resolve_source_control_target(&self, target: Value) -> Result<Value> {
        let (id, repo) = self.target_connection(&target).await?;
        let (_, config) = self.connection_config(&id)?;
        let repo = repo.map(|repo| json!({"owner":repo.owner,"name":repo.name,"htmlUrl":format!("{id}/{}/{}",repo.owner,repo.name)}));
        let resource = target
            .get("repoUrl")
            .and_then(Value::as_str)
            .and_then(GitRemoteUrl::parse)
            .and_then(|remote| {
                let canonical = GitRemoteUrl::parse(repo.as_ref()?["htmlUrl"].as_str()?)?;
                remote
                    .resource_number(&canonical)
                    .map(|(kind, number)| json!({"kind":kind,"number":number}))
            });
        Ok(
            json!({"connectionId":id,"provider":config.provider,"instanceUrl":id,"repo":repo,"resource":resource}),
        )
    }
}

pub(crate) fn configured_repo_from_url(
    config: &intent_core::settings_file::SourceControlSettings,
    url: &str,
) -> Option<RepoRef> {
    connection_for_url(config, url).map(|(_, repo)| repo)
}

pub(crate) fn same_repository_remote(left: &GitRemoteUrl, right: &GitRemoteUrl) -> bool {
    let repository_path = |remote: &GitRemoteUrl| {
        let path = remote.path().trim_matches('/');
        let path = path.split("/-/").next().unwrap_or(path);
        let path = if ["github.com", "www.github.com"]
            .iter()
            .any(|host| remote.host().eq_ignore_ascii_case(host))
        {
            path.split("/pull/").next().unwrap_or(path)
        } else {
            path
        };
        let path = path.trim_end_matches('/');
        let path = if path.to_ascii_lowercase().ends_with(".git") {
            &path[..path.len() - 4]
        } else {
            path
        };
        path.to_owned()
    };
    let left_path = repository_path(left);
    let right_path = repository_path(right);
    left.same_forge_host(right)
        && if ["github.com", "www.github.com"]
            .iter()
            .any(|host| left.host().eq_ignore_ascii_case(host))
        {
            match (left_path.rsplit_once('/'), right_path.rsplit_once('/')) {
                (Some((owner_a, name_a)), Some((owner_b, name_b))) => {
                    RepoRef::new(owner_a, name_a) == RepoRef::new(owner_b, name_b)
                }
                _ => false,
            }
        } else {
            left_path == right_path
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{AsyncSecretStore, InMemorySecretStore, SecretStore, SettingsService};
    use crate::SettingsRegistry;
    use intent_store::Store;
    use serde_json::json;

    #[test]
    fn registered_instances_resolve_ports_prefixes_and_reject_ambiguous_ssh() {
        let mut config = intent_core::settings_file::SourceControlSettings::default();
        for instance in [
            "https://git.example.test",
            "https://git.example.test/second",
            "https://git.example.test:8443",
        ] {
            config.connections.insert(
                instance.into(),
                SourceControlConnectionSettings {
                    provider: SourceControlProvider::Gitlab,
                    ..Default::default()
                },
            );
        }
        for (url, expected, owner) in [
            ("https://github.com/group/project/pull/7", GITHUB, "group"),
            (
                "https://git.example.test/group/sub/project.git",
                "https://git.example.test",
                "group/sub",
            ),
            (
                "https://git.example.test/second/group/sub/project/-/issues/8",
                "https://git.example.test/second",
                "group/sub",
            ),
            (
                "https://git.example.test:8443/group/project",
                "https://git.example.test:8443",
                "group",
            ),
        ] {
            let (id, repo) = connection_for_url(&config, url).unwrap();
            assert_eq!(id, expected);
            assert_eq!(repo.owner, owner);
            assert_eq!(repo.name, "project");
        }
        assert!(connection_for_url(&config, "https://foreign.example/group/project").is_none());
        assert!(
            connection_for_url(&config, "https://git.example.test:9443/group/project").is_none()
        );
        assert!(
            connection_for_url(&config, "git@git.example.test:group/project.git").is_none(),
            "SSH cannot choose between multiple installations sharing a host"
        );
    }

    #[tokio::test]
    async fn connection_rotation_invalidates_only_its_own_pending_results() {
        let dir = crate::test_support::test_tempdir("connection-generation-");
        let store = Store::open(&dir.path().join("intentd.db")).await.unwrap();
        let registry = Arc::new(SettingsRegistry::load(dir.path().join("config.toml")).unwrap());
        registry
            .apply(&[(
                "sourceControl.gitlab.instanceUrl".into(),
                json!("https://git.example.test"),
            )])
            .unwrap();
        let svc = Services::new(store).with_settings_registry(registry.clone());
        let gh = svc.with_source_control_scope(GITHUB);
        let gl = svc.with_source_control_scope("https://git.example.test");
        let before = svc.effective_settings().source_control;
        let original_url = "https://github.com/group/project/pull/7";
        let other_forge_url = "https://git.example.test/group/project/-/merge_requests/7";
        assert!(gh.source_control_result_matches(&before, Some(original_url), original_url));
        assert!(gl.source_control_result_matches(&before, Some(other_forge_url), other_forge_url));
        svc.invalidate_source_control_connection("https://git.example.test");
        assert!(!gl.source_control_result_matches(&before, Some(other_forge_url), other_forge_url));
        assert!(gh.source_control_result_matches(&before, Some(original_url), original_url));
        let fresh = svc.with_source_control_scope("https://git.example.test");
        assert!(fresh.source_control_result_matches(
            &before,
            Some(other_forge_url),
            other_forge_url
        ));
        registry.apply(&[("sourceControl.connections".into(),json!({"https://git.example.test":{"provider":"gitlab","tokenSource":"explicit","enabled":false}}))]).unwrap();
        assert!(!fresh.source_control_result_matches(
            &before,
            Some(other_forge_url),
            other_forge_url
        ));
        assert!(gh.source_control_result_matches(&before, Some(original_url), original_url));
    }

    #[tokio::test]
    async fn legacy_secret_settings_mutations_invalidate_only_their_connection() {
        let dir = crate::test_support::test_tempdir("legacy-connection-generation-");
        let store = Store::open(&dir.path().join("intentd.db")).await.unwrap();
        let registry = Arc::new(SettingsRegistry::load(dir.path().join("config.toml")).unwrap());
        registry
            .apply(&[(
                "sourceControl.gitlab.instanceUrl".into(),
                json!("https://git.example.test"),
            )])
            .unwrap();
        let svc = Services::new(store)
            .with_settings_registry(registry)
            .with_secret_store(Arc::new(InMemorySecretStore::default()));
        let before = svc.effective_settings().source_control;
        let original = svc.with_source_control_scope(GITHUB);
        let unaffected = svc.with_source_control_scope("https://git.example.test");
        let public_url = "https://github.com/group/project/pull/7";
        let private_url = "https://git.example.test/group/project/-/merge_requests/7";
        intent_core::with_caller(
            intent_core::Caller::Daemon,
            svc.settings_update(
                json!([{"path":"sourceControl.github.token","value":"test-token"}]),
            ),
        )
        .await
        .unwrap();
        assert!(!original.source_control_result_matches(&before, Some(public_url), public_url));
        assert!(unaffected.source_control_result_matches(&before, Some(private_url), private_url));
        let refreshed = svc.with_source_control_scope(GITHUB);
        intent_core::with_caller(
            intent_core::Caller::Daemon,
            svc.settings_reset("sourceControl.github.token".into()),
        )
        .await
        .unwrap();
        assert!(!refreshed.source_control_result_matches(&before, Some(public_url), public_url));
        assert!(unaffected.source_control_result_matches(&before, Some(private_url), private_url));
    }

    #[tokio::test]
    async fn gitlab_token_binding_is_atomic_and_cannot_be_rebound_by_public_settings() {
        let dir = crate::test_support::test_tempdir("gitlab-secret-binding-");
        let store = Store::open(&dir.path().join("intentd.db")).await.unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let registry = Arc::new(SettingsRegistry::load(&config_path).unwrap());
        let raw = Arc::new(InMemorySecretStore::default());
        let secrets = AsyncSecretStore::new(raw.clone());
        let settings = SettingsService::new(&store, &secrets, Some(&registry));
        let changes = json!([
            {"path":"sourceControl.activeProvider","value":"gitlab"},
            {"path":"sourceControl.gitlab.instanceUrl","value":"https://git.euraika.net"},
            {"path":"sourceControl.gitlab.tokenHost","value":"https://git.euraika.net"},
            {"path":"sourceControl.gitlab.tokenSource","value":"explicit"},
            {"path":"sourceControl.gitlab.token","value":"private-test-token"}
        ]);
        let applied = settings.update(&changes).await.unwrap();
        assert!(!serde_json::to_string(&applied)
            .unwrap()
            .contains("private-test-token"));
        assert!(!std::fs::read_to_string(&config_path)
            .unwrap()
            .contains("private-test-token"));
        let credential: serde_json::Value =
            serde_json::from_str(&raw.load("sourceControl.gitlab.token").unwrap().unwrap())
                .unwrap();
        assert_eq!(credential["instanceUrl"], "https://git.euraika.net");
        assert_eq!(credential["token"], "private-test-token");
        let services = Services::new(store.clone())
            .with_secret_store(raw.clone())
            .with_settings_registry(registry.clone());
        assert_eq!(
            services
                .resolve_source_control_connection("https://git.euraika.net")
                .await
                .unwrap()
                .provider_id(),
            "gitlab"
        );
        settings
            .update(&json!([
                {"path":"sourceControl.gitlab.instanceUrl","value":"https://foreign.invalid"},
                {"path":"sourceControl.gitlab.tokenHost","value":"https://foreign.invalid"}
            ]))
            .await
            .unwrap();
        assert!(
            services
                .resolve_source_control_connection("https://foreign.invalid")
                .await
                .is_err(),
            "an old token must never be rebound by editing nonsecret settings"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &raw.load("sourceControl.gitlab.token").unwrap().unwrap()
            )
            .unwrap(),
            credential
        );
    }

    #[tokio::test]
    async fn gitlab_token_without_instance_binding_rejects_the_entire_settings_batch() {
        let dir = crate::test_support::test_tempdir("gitlab-missing-binding-");
        let store = Store::open(&dir.path().join("intentd.db")).await.unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let registry = SettingsRegistry::load(&config_path).unwrap();
        let raw = Arc::new(InMemorySecretStore::default());
        let secrets = AsyncSecretStore::new(raw.clone());
        let settings = SettingsService::new(&store, &secrets, Some(&registry));
        assert!(settings
            .update(&json!([
                {"path":"sourceControl.activeProvider","value":"gitlab"},
                {"path":"sourceControl.gitlab.token","value":"private-test-token"}
            ]))
            .await
            .is_err());
        assert_eq!(
            registry.get("sourceControl.activeProvider"),
            Some(json!("github"))
        );
        assert!(raw.load("sourceControl.gitlab.token").unwrap().is_none());
    }
    #[test]
    fn cross_workspace_siblings_with_same_slug_keep_forge_hosts_separate() {
        let mut github = crate::tests::workspace(&intent_core::WorkspaceId::from("github"));
        github.repository_owner = Some("group".into());
        github.repository_name = Some("project".into());
        github.pr_url = Some("https://github.com/group/project/pull/1".into());
        let mut gitlab = github.clone();
        gitlab.id = intent_core::WorkspaceId::from("gitlab");
        gitlab.pr_url = Some("https://git.euraika.net/group/project/-/merge_requests/1".into());
        assert!(crate::workspaces_share_repository(&github, &gitlab));
        assert!(!crate::workspaces_share_repository_on_host(
            &github, &gitlab
        ));
        let mut second_instance = gitlab.clone();
        second_instance.pr_url =
            Some("https://git.euraika.net:8443/group/project/-/merge_requests/1".into());
        assert!(!crate::workspaces_share_repository_on_host(
            &gitlab,
            &second_instance
        ));
        second_instance.pr_url =
            Some("https://git.euraika.net/group/project/-/merge_requests/2".into());
        assert!(crate::workspaces_share_repository_on_host(
            &gitlab,
            &second_instance
        ));
        gitlab.pr_url =
            Some("https://git.euraika.net/gitlab-one/group/project/-/merge_requests/1".into());
        second_instance.pr_url =
            Some("https://git.euraika.net/gitlab-two/group/project/-/merge_requests/1".into());
        assert!(!crate::workspaces_share_repository_on_host(
            &gitlab,
            &second_instance
        ));
        second_instance.pr_url =
            Some("https://git.euraika.net/gitlab-one/group/project.git".into());
        assert!(crate::workspaces_share_repository_on_host(
            &gitlab,
            &second_instance
        ));
        second_instance.pr_url = Some("git@git.euraika.net:group/project.git".into());
        assert!(!crate::workspaces_share_repository_on_host(
            &gitlab,
            &second_instance
        ));
        gitlab.pr_url = Some("https://git.euraika.net/group/project/-/merge_requests/1".into());
        assert!(crate::workspaces_share_repository_on_host(
            &gitlab,
            &second_instance
        ));
    }
}
