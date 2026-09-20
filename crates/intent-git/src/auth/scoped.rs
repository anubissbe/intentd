//! Credentials carry their HTTPS authority and installation prefix through
//! every Git operation. Redirects and submodules must pass that same boundary.

use std::path::Path;
use std::process::{Command, Stdio};

use url::Url;

use super::{config_parameters, sh_quote, usable_token, GIT_CONFIG_PARAMETERS_ENV};

const PASSWORD_ENV: &str = "INTENT_GIT_SCOPED_PASSWORD";
const USERNAME_ENV: &str = "INTENT_GIT_SCOPED_USERNAME";

/// A secret bound to one forge installation. Debug output never reveals it.
#[derive(Clone)]
pub struct GitCredential {
    instance: Url,
    username: String,
    password: String,
}

impl std::fmt::Debug for GitCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitCredential")
            .field("instance", &self.instance.as_str())
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

// A proxy or Git server may decode separators after URL parsing. Refuse
// those ambiguous paths before the library normalizes dot segments, so both
// the libgit2 callback and daemon helper enforce the shell helper's boundary.
fn unambiguous_url(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    !raw.chars().any(char::is_control)
        && !raw.contains('\\')
        && !raw.contains("/../")
        && !raw.ends_with("/..")
        && !["%2e", "%2f", "%5c"]
            .iter()
            .any(|encoded| lower.contains(encoded))
}

fn instance_url(raw: &str) -> Option<Url> {
    if !unambiguous_url(raw) || raw.contains(['*', '?', '#']) {
        return None;
    }
    let mut url = Url::parse(raw).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Some(url)
}

impl GitCredential {
    #[must_use]
    pub fn new(instance: &str, username: &str, password: &str) -> Option<Self> {
        Some(Self {
            instance: instance_url(instance)?,
            username: usable_token(Some(username))?.to_string(),
            password: usable_token(Some(password))?.to_string(),
        })
    }

    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    #[must_use]
    pub fn instance_url(&self) -> &str {
        self.instance.as_str().trim_end_matches('/')
    }

    /// Reject a redirect to another authority, installation or explicit user.
    #[must_use]
    pub fn matches_url(&self, raw: &str) -> bool {
        if !unambiguous_url(raw) {
            return false;
        }
        let Ok(url) = Url::parse(raw) else {
            return false;
        };
        url.scheme() == "https"
            && url.host_str() == self.instance.host_str()
            && url.port_or_known_default() == self.instance.port_or_known_default()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && (url.username().is_empty() || url.username() == self.username)
            && path_contains(self.instance.path(), url.path())
    }

    /// The secret travels only in the short-lived Git child's environment.
    /// Git's URL matcher scopes the helper and useHttpPath preserves subpaths.
    #[must_use]
    pub fn environment(
        &self,
        cwd: Option<&Path>,
        inherited: Option<&str>,
    ) -> Vec<(String, String)> {
        let scope = self.instance_url();
        let authority = &self.instance[url::Position::BeforeHost..url::Position::AfterPort];
        let prefix = self.instance.path().trim_matches('/');
        let authority_gate = if self.instance.port().is_none() {
            format!(
                "case \"$host\" in {}|{}) ;; *) exit 0;; esac; ",
                sh_quote(authority),
                sh_quote(&format!("{authority}:443"))
            )
        } else {
            format!("test \"$host\" = {} || exit 0; ", sh_quote(authority))
        };
        let path_gate = if prefix.is_empty() {
            String::new()
        } else {
            format!(
                "case \"$path\" in {}|{}/*) ;; *) exit 0;; esac; ",
                sh_quote(prefix),
                sh_quote(prefix)
            )
        };
        let entry = format!(
            "credential.{scope}.helper=!f() {{ test \"$1\" = get || exit 0; protocol= host= path= username=; while IFS='=' read -r key value; do test -n \"$key\" || break; case \"$key\" in protocol) protocol=$value;; host) host=$value;; path) path=$value;; username) username=$value;; esac; done; test \"$protocol\" = https || exit 0; host=$(printf '%s' \"$host\" | tr '[:upper:]' '[:lower:]'); {authority_gate}case \"$path\" in ../*|*/../*|*/..|..|*%2e*|*%2E*|*%2f*|*%2F*|*%5c*|*%5C*) exit 0;; esac; {path_gate}test -z \"$username\" || test \"$username\" = \"${USERNAME_ENV}\" || exit 0; printf 'username=%s\\npassword=%s\\n' \"${USERNAME_ENV}\" \"${PASSWORD_ENV}\"; }}; f"
        );
        let entries = helper_entries(&self.instance, entry, cwd, inherited);
        vec![
            (
                GIT_CONFIG_PARAMETERS_ENV.to_string(),
                config_parameters(inherited, &entries),
            ),
            (USERNAME_ENV.to_string(), self.username.clone()),
            (PASSWORD_ENV.to_string(), self.password.clone()),
        ]
    }
}

fn path_contains(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    prefix.is_empty()
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Offer a token-free daemon helper for each configured forge. Existing
/// user helpers retain their original scopes behind the daemon helper.
#[must_use]
pub fn daemon_helpers_for_instances(
    intentd_path: &str,
    instances: &[String],
    cwd: Option<&Path>,
    inherited: Option<&str>,
) -> Vec<(String, String)> {
    let mut parameters = inherited.map(str::to_string);
    for raw in instances {
        let Some(instance) = instance_url(raw) else {
            continue;
        };
        let scope = instance.as_str().trim_end_matches('/');
        let entry = format!(
            "credential.{scope}.helper=!{} git-credential",
            sh_quote(intentd_path)
        );
        let entries = helper_entries(&instance, entry, cwd, parameters.as_deref());
        parameters = Some(config_parameters(parameters.as_deref(), &entries));
    }
    parameters
        .filter(|value| Some(value.as_str()) != inherited)
        .map(|value| vec![(GIT_CONFIG_PARAMETERS_ENV.to_string(), value)])
        .unwrap_or_default()
}

fn helper_entries(
    instance: &Url,
    entry: String,
    cwd: Option<&Path>,
    inherited: Option<&str>,
) -> Vec<String> {
    let scope = instance.as_str().trim_end_matches('/');
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(cwd.unwrap_or(Path::new("/")))
        .args(["config", "--list", "-z"])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    if let Some(value) = inherited {
        command.env(GIT_CONFIG_PARAMETERS_ENV, value);
    } else {
        command.env_remove(GIT_CONFIG_PARAMETERS_ENV);
    }
    let output = command
        .output()
        .ok()
        .filter(|output| output.status.success());
    let Some(output) = output else {
        return vec![
            format!("credential.{scope}.useHttpPath=true"),
            entry,
            "http.followRedirects=false".to_string(),
        ];
    };
    let config = String::from_utf8_lossy(&output.stdout);
    let fallbacks = helpers_from_config(instance, &config);
    let mut entries = vec![
        format!("credential.{scope}.helper="),
        entry.clone(),
        format!("credential.{scope}.useHttpPath=true"),
    ];
    // URL-specific http settings beat the global setting even from a lower
    // config level. Override every existing scoped redirect rule in the
    // short-lived child, including narrower installation/project paths.
    entries.push("http.followRedirects=false".to_string());
    for record in config.split('\0') {
        let key = record.split_once('\n').map_or(record, |(key, _)| key);
        let normalized = key.to_ascii_lowercase();
        if normalized.starts_with("http.") && normalized.ends_with(".followredirects") {
            entries.push(format!("{key}=false"));
        }
    }
    for fallback in fallbacks {
        if fallback != entry && !entries.contains(&fallback) {
            entries.push(fallback);
        }
    }
    entries
}

fn helpers_from_config(instance: &Url, config: &str) -> Vec<String> {
    let scope = instance.as_str().trim_end_matches('/');
    let mut helpers = Vec::new();
    for record in config.split('\0') {
        let Some((key, value)) = record.split_once('\n') else {
            continue;
        };
        let (covers_all, relevant) = if key == "credential.helper" {
            (true, true)
        } else if let Some(raw) = key
            .strip_prefix("credential.")
            .and_then(|key| key.strip_suffix(".helper"))
        {
            let normalized = if raw.contains("://") {
                raw.to_string()
            } else {
                format!("https://{raw}")
            };
            let Ok(url) = Url::parse(&normalized) else {
                continue;
            };
            if url.scheme() != "https"
                || url.host_str() != instance.host_str()
                || url.port_or_known_default() != instance.port_or_known_default()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                continue;
            }
            (
                path_contains(url.path(), instance.path()),
                path_contains(url.path(), instance.path())
                    || path_contains(instance.path(), url.path()),
            )
        } else {
            (false, false)
        };
        if !relevant {
            continue;
        }
        if covers_all {
            if value.is_empty() {
                helpers.clear();
            } else {
                helpers.push(format!("credential.{scope}.helper={value}"));
            }
        } else {
            helpers.push(format!("{key}={value}"));
        }
    }
    helpers
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn credentials_are_bound_to_https_authority_installation_and_identity() {
        let credential =
            GitCredential::new("https://git.example:8443/gitlab", "oauth2", "secret").unwrap();
        for url in [
            "https://git.example:8443/gitlab/group/repo.git",
            "https://oauth2@git.example:8443/gitlab/a/b",
        ] {
            assert!(credential.matches_url(url), "{url}");
        }
        for url in [
            "https://git.example/gitlab/a/b",
            "https://git.example:8443/gitlab-other/a/b",
            "https://git.example:8443/else/a/b",
            "http://git.example:8443/gitlab/a/b",
            "https://evil.example:8443/gitlab/a/b",
            "https://alice@git.example:8443/gitlab/a/b",
            "https://git.example:8443/gitlab/../else/a/b",
            "https://git.example:8443/gitlab/%2f..%2felse/a/b",
            "https://git.example:8443/gitlab/%2F..%2Felse/a/b",
            "https://git.example:8443/gitlab/%5c..%5celse/a/b",
            "https://git.example:8443/gitlab/%2e%2e%2felse/a/b",
            "https://git.example:8443/gitlab/a/../b",
            "https://git.example:8443/gitlab/a\\..\\b",
            "https://git.example:8443/gitlab/a/b?redirect=outside",
            "https://git.example:8443/gitlab/a/b#fragment",
        ] {
            assert!(!credential.matches_url(url), "{url}");
        }
        assert!(!format!("{credential:?}").contains("secret"));
        assert!(GitCredential::new("https://*.example", "oauth2", "secret").is_none());
        assert!(GitCredential::new("https://git.example", "oauth2", "secret\ninjection").is_none());
    }

    #[test]
    fn fallback_helpers_keep_narrower_scopes_and_reset_order() {
        let instance = instance_url("https://git.example/gitlab").unwrap();
        let helpers = helpers_from_config(&instance, "credential.helper\nglobal\0credential.https://git.example/gitlab/team.helper\nteam\0credential.https://other.example.helper\nother\0");
        assert_eq!(
            helpers,
            vec![
                "credential.https://git.example/gitlab.helper=global",
                "credential.https://git.example/gitlab/team.helper=team"
            ]
        );
    }

    #[test]
    fn real_git_credential_fill_never_crosses_host_port_path_or_username() {
        let credential = GitCredential::new(
            "https://git.example:8443/gitlab",
            "oauth2",
            "fixture-password",
        )
        .unwrap();
        let environment = credential.environment(None, Some("'credential.helper='"));
        for (remote, granted) in [
            (
                "https://git.example:8443/gitlab/group/nested/project.git",
                true,
            ),
            (
                "https://oauth2@git.example:8443/gitlab/group/project.git",
                true,
            ),
            (
                "https://alice@git.example:8443/gitlab/group/project.git",
                false,
            ),
            ("https://git.example/gitlab/group/project.git", false),
            ("https://git.example:8443/other/group/project.git", false),
            (
                "https://git.example:8443/gitlab-other/group/project.git",
                false,
            ),
            ("https://other.example:8443/gitlab/group/project.git", false),
            ("https://GIT.EXAMPLE:8443/gitlab/group/project.git", true),
            ("https://git.example:8443/gitlab/../else/project.git", false),
            (
                "https://git.example:8443/gitlab/%2e%2e/else/project.git",
                false,
            ),
            ("http://git.example:8443/gitlab/group/project.git", false),
        ] {
            let mut child = Command::new("git")
                .args(["credential", "fill"])
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_TERMINAL_PROMPT", "0")
                .envs(environment.clone())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            writeln!(child.stdin.take().unwrap(), "url={remote}\n").unwrap();
            let output = child.wait_with_output().unwrap();
            let text = String::from_utf8(output.stdout).unwrap();
            assert_eq!(output.status.success(), granted, "{remote}");
            assert_eq!(
                text.contains("password=fixture-password"),
                granted,
                "{remote}"
            );
        }
    }

    #[test]
    fn scoped_redirect_settings_cannot_override_credential_redirect_guard() {
        let dir = tempfile::Builder::new()
            .prefix("intent-git-redirect-config-")
            .tempdir()
            .unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let mut config = repo.config().unwrap();
        for scope in [
            "https://git.example/gitlab",
            "https://git.example/gitlab/team/project.git",
        ] {
            config
                .set_bool(&format!("http.{scope}.followRedirects"), true)
                .unwrap();
        }
        let credential =
            GitCredential::new("https://git.example/gitlab", "oauth2", "fixture-password").unwrap();
        let token_environment = credential.environment(Some(dir.path()), None);
        let daemon_environment = daemon_helpers_for_instances(
            "/tmp/intentd",
            &["https://git.example/gitlab".into()],
            Some(dir.path()),
            None,
        );
        for environment in [token_environment, daemon_environment] {
            for url in [
                "https://git.example/gitlab/team/project.git",
                "https://git.example/gitlab/other/project.git",
            ] {
                let output = Command::new("git")
                    .arg("-C")
                    .arg(dir.path())
                    .args(["config", "--get-urlmatch", "http.followRedirects", url])
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env_remove(GIT_CONFIG_PARAMETERS_ENV)
                    .envs(environment.clone())
                    .output()
                    .unwrap();
                assert!(output.status.success());
                assert_eq!(
                    String::from_utf8(output.stdout).unwrap().trim(),
                    "false",
                    "{url}"
                );
            }
        }
    }

    #[test]
    fn libgit2_callback_uses_scoped_token_and_bounds_retries() {
        let credential =
            GitCredential::new("https://git.example/gitlab", "oauth2", "fixture-password").unwrap();
        let mut callback = super::super::scoped_credentials_callback(Some(credential));
        let allowed = git2::CredentialType::USER_PASS_PLAINTEXT;
        assert!(callback("https://git.example/gitlab/a/b", Some("oauth2"), allowed).is_ok());
        assert!(callback("https://git.example/gitlab/a/b", Some("oauth2"), allowed).is_ok());
        assert!(callback("https://git.example/gitlab/a/b", Some("oauth2"), allowed).is_ok());
        assert!(
            callback("https://git.example/gitlab/a/b", Some("oauth2"), allowed)
                .err()
                .unwrap()
                .message()
                .contains("exhausted")
        );
    }
}
