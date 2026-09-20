//! Canonical credential authority shared by settings and forge adapters.

use crate::{Error, Result};

/// Normalize an instance URL without weakening its credential boundary.
///
/// # Errors
/// Rejects credentials, query/fragment, wildcard hosts and insecure nonloopback URLs.
pub fn normalize(value: &str) -> Result<String> {
    let invalid = || {
        Error::InvalidInput("Source-control instance requires an HTTPS URL without credentials, query, fragment or wildcard (HTTP is allowed only on loopback)".into())
    };
    if value.chars().any(char::is_control) || value.contains(['\\', '*']) {
        return Err(invalid());
    }
    let mut url = url::Url::parse(value.trim()).map_err(|_| invalid())?;
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host == "[::1]"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https" && !(url.scheme() == "http" && local))
    {
        return Err(invalid());
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Ok(url.as_str().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_instance_preserves_port_and_installation_prefix() {
        assert_eq!(
            normalize("https://GIT.EXAMPLE:8443/gitlab/").unwrap(),
            "https://git.example:8443/gitlab"
        );
        assert_eq!(
            normalize("https://git.example:443/").unwrap(),
            "https://git.example"
        );
        assert_eq!(
            normalize("http://127.0.0.1:8042").unwrap(),
            "http://127.0.0.1:8042"
        );
        for raw in [
            "http://git.example",
            "https://user:secret@git.example",
            "https://git.example?query",
            "https://git.example#fragment",
            "https://*.example",
            "https://git.example\\evil",
            "https://git.example\n",
        ] {
            assert!(normalize(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn settings_reject_noncanonical_keys_and_wrong_provider_token_sources() {
        use crate::settings_file::{
            SettingsFile, SourceControlConnectionSettings, SourceControlProvider,
        };
        for (instance, source) in [
            ("https://git.example/", "explicit"),
            ("http://git.example", "auto"),
            ("https://git.example", "gh-cli"),
            ("https://github.com", "explicit"),
        ] {
            let mut settings = SettingsFile::default();
            settings.source_control.connections.insert(
                instance.into(),
                SourceControlConnectionSettings {
                    provider: SourceControlProvider::Gitlab,
                    token_source: source.into(),
                    ..Default::default()
                },
            );
            assert!(settings.validate().is_err(), "{instance} {source}");
        }
        let mut settings = SettingsFile::default();
        settings.source_control.connections.insert(
            "https://git.example:8443/gitlab".into(),
            SourceControlConnectionSettings {
                provider: SourceControlProvider::Gitlab,
                token_source: "explicit".into(),
                ..Default::default()
            },
        );
        assert!(settings.validate().is_ok());
    }
}
