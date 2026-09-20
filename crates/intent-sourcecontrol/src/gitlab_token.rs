//! Host-bound GitLab credential resolution. Never print CLI output or credentials.
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Source used to obtain a GitLab credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitlabTokenSource {
    #[default]
    Auto,
    Explicit,
    Env,
    GlabCli,
}

/// Normalize and validate an instance URL before associating credentials with it.
///
/// # Errors
/// Rejects URLs that cannot safely identify a GitLab instance.
pub fn normalize_instance_url(value: &str) -> Result<String> {
    intent_core::source_control_instance::normalize(value)
        .map_err(|error| Error::Config(error.to_string()))
}

/// Resolve a token bound to the configured GitLab instance.
///
/// # Errors
/// Returns an error when the configured source has no token for this instance.
pub async fn resolve(settings: &crate::registry::GitlabSettings) -> Result<String> {
    let instance = normalize_instance_url(&settings.instance_url)?;
    let bound = settings
        .token_host
        .as_deref()
        .and_then(|host| normalize_instance_url(host).ok())
        .is_some_and(|host| host == instance);
    if matches!(
        settings.token_source,
        GitlabTokenSource::Auto | GitlabTokenSource::Explicit
    ) {
        if bound {
            if let Some(token) = settings.token.as_deref().filter(|v| !v.trim().is_empty()) {
                return Ok(token.trim().to_owned());
            }
        } else if settings.token.is_some() || settings.token_host.is_some() {
            return Err(Error::NotConfigured(
                "GitLab stored token belongs to another instance; reconnect this instance".into(),
            ));
        }
    }
    if matches!(
        settings.token_source,
        GitlabTokenSource::Auto | GitlabTokenSource::Env
    ) {
        let host = std::env::var("GITLAB_HOST")
            .or_else(|_| std::env::var("GL_HOST"))
            .ok();
        let bound_env = host
            .as_deref()
            .map_or(instance == "https://gitlab.com", |host| {
                let host = if host.contains("://") {
                    host.to_owned()
                } else {
                    format!("https://{host}")
                };
                normalize_instance_url(&host).is_ok_and(|url| url == instance)
            });
        if bound_env {
            if let Some(token) = ["GITLAB_TOKEN", "GL_TOKEN"]
                .iter()
                .filter_map(|name| std::env::var(name).ok())
                .find(|token| !token.trim().is_empty())
            {
                return Ok(token.trim().to_owned());
            }
        }
    }
    if matches!(
        settings.token_source,
        GitlabTokenSource::Auto | GitlabTokenSource::GlabCli
    ) {
        let url = reqwest::Url::parse(&instance)
            .map_err(|_| Error::Config("invalid GitLab URL".into()))?;
        // glab's credentials are keyed by host, not a relative URL prefix.
        if !url.path().trim_matches('/').is_empty() {
            return Err(Error::NotConfigured("GitLab instances under a URL prefix require a stored or host-bound environment token".into()));
        }
        let host = url
            .host_str()
            .map(|host| {
                url.port()
                    .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"))
            })
            .ok_or_else(|| Error::Config("GitLab URL has no host".into()))?;
        let discovery = tokio::task::spawn_blocking(|| {
            intent_core::path_utils::enhanced_path_dirs()
                .iter()
                .map(|dir| dir.join(if cfg!(windows) { "glab.exe" } else { "glab" }))
                .find(|path| path.is_file())
        });
        if let Ok(Ok(Some(binary))) = tokio::time::timeout(Duration::from_secs(3), discovery).await
        {
            if let Some(token) = glab_token(&binary, &host).await {
                return Ok(token);
            }
        }
    }
    Err(Error::NotConfigured("GitLab: no host-bound token found; store a token for this instance, set GITLAB_HOST and GITLAB_TOKEN, or run glab auth login --hostname <host>".into()))
}

// glab does not implement gh's `auth token`; `config get token --host` is its
// documented host-scoped credential read, including the configured keyring.
async fn glab_token(binary: &std::path::Path, host: &str) -> Option<String> {
    // status checks cfg.Hosts() before looking up credentials or contacting an
    // API. A previously unknown instance cannot receive a global fallback token.
    // It also lets glab refresh OAuth credentials before the native client reads them.
    let status = glab_command(binary, host, &["auth", "status", "--hostname", host]).await?;
    if !status.status.success() {
        return None;
    }
    let output = glab_command(binary, host, &["config", "get", "token", "--host", host]).await?;
    if !output.status.success() {
        return None;
    }
    let token = String::from_utf8(output.stdout).ok()?;
    let token = token.trim();
    (!token.is_empty() && !token.contains(['\r', '\n'])).then(|| token.to_owned())
}

async fn glab_command(
    binary: &std::path::Path,
    host: &str,
    args: &[&str],
) -> Option<std::process::Output> {
    let mut command = tokio::process::Command::new(binary);
    command
        .args(args)
        .current_dir(std::env::temp_dir())
        .env_remove("GITLAB_TOKEN")
        .env_remove("GL_TOKEN")
        .env_remove("GITLAB_ACCESS_TOKEN")
        .env_remove("OAUTH_TOKEN")
        .env("GITLAB_HOST", host)
        .env("GITLAB_API_HOST", host)
        .env("GLAB_API_PROTOCOL", "https")
        .env("GITLAB_SUBFOLDER", "")
        .env("GLAB_CHECK_UPDATE", "false")
        .env("GLAB_NO_PROMPT", "true")
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(5), command.output())
        .await
        .ok()?
        .ok()
}

#[cfg(all(test, unix))]
mod tests {
    use super::glab_token;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn glab_uses_supported_config_command_with_explicit_host() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("glab");
        std::fs::write(&binary, "#!/bin/sh\n[ \"$*\" = \"auth status --hostname git.example\" ] && exit 0\n[ \"$*\" = \"config get token --host git.example\" ] || exit 2\n[ \"$GITLAB_HOST\" = \"git.example\" ] || exit 3\n[ -z \"$GITLAB_TOKEN$GL_TOKEN$GITLAB_ACCESS_TOKEN$OAUTH_TOKEN\" ] || exit 4\nprintf fixture-token\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            glab_token(&binary, "git.example").await.as_deref(),
            Some("fixture-token")
        );
        assert!(glab_token(&binary, "another.example").await.is_none());
    }

    #[tokio::test]
    async fn unknown_glab_host_never_reads_global_fallback_token() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("glab");
        std::fs::write(&binary, "#!/bin/sh\nif [ \"$1\" = auth ]; then exit 1; fi\nprintf read > \"${0}.read\"\nprintf global-fallback-secret\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(glab_token(&binary, "unknown.example").await.is_none());
        assert!(!dir.path().join("glab.read").exists());
    }

    #[tokio::test]
    async fn glab_rejects_nonzero_and_multiline_output() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("glab");
        std::fs::write(&binary, "#!/bin/sh\nprintf 'first\\nsecond\\n'\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(glab_token(&binary, "git.example").await.is_none());
        std::fs::write(&binary, "#!/bin/sh\nprintf fixture-token\nexit 1\n").unwrap();
        assert!(glab_token(&binary, "git.example").await.is_none());
    }
}
