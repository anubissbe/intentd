//! Registered-forge URLs at the workspace creation boundary.
use intent_core::{ContextLink, ContextLinkKind, GitRemoteUrl, WorkspaceCreate};

use crate::{source_control_ops, Services};

impl Services {
    pub(crate) fn source_control_clone_url(&self, url: &str) -> String {
        clone_url(&self.effective_settings().source_control, url)
    }

    pub(crate) fn normalize_workspace_source_url(&self, input: &mut WorkspaceCreate) {
        normalize_source_url(&self.effective_settings().source_control, input);
    }
}

// GitLab's web URL redirects smart HTTP to the .git endpoint. Choose that
// endpoint before invoking Git: credentialed Git deliberately rejects redirects.
// Only normalize HTTP(S) on a registered GitLab connection; preserve SSH/local
// transports and other forges rather than guessing their clone conventions.
fn clone_url(config: &intent_core::settings_file::SourceControlSettings, url: &str) -> String {
    let http = url.trim().split_once("://").is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
    });
    if http {
        if let Some((instance, repo)) = source_control_ops::connection_for_url(config, url) {
            if source_control_ops::configured_connections(config)
                .get(&instance)
                .is_some_and(|connection| {
                    connection.provider == intent_core::settings_file::SourceControlProvider::Gitlab
                })
            {
                return format!("{instance}/{}/{}.git", repo.owner, repo.name);
            }
        }
    }
    url.to_string()
}

fn normalize_source_url(
    config: &intent_core::settings_file::SourceControlSettings,
    input: &mut WorkspaceCreate,
) {
    let Some(url) = input.github_url.as_deref() else {
        return;
    };
    let Some((instance, repo)) = source_control_ops::connection_for_url(config, url) else {
        return;
    };
    let canonical = format!("{instance}/{}/{}", repo.owner, repo.name);
    let Some(resource) = GitRemoteUrl::parse(url)
        .and_then(|remote| remote.resource_number(&GitRemoteUrl::parse(&canonical)?))
    else {
        input.github_url = Some(clone_url(config, url));
        return;
    };
    let (kind, number) = resource;
    let route = if instance == "https://github.com" {
        if kind == ContextLinkKind::Pr {
            "pull"
        } else {
            "issues"
        }
    } else if kind == ContextLinkKind::Pr {
        "-/merge_requests"
    } else {
        "-/issues"
    };
    let link = ContextLink {
        kind,
        number,
        url: format!("{canonical}/{route}/{number}"),
        owner: repo.owner,
        repo: repo.name,
    };
    input.github_url = Some(clone_url(config, &canonical));
    let links = input.context_links.get_or_insert_with(Vec::new);
    if !links.iter().any(|existing| existing.url == link.url) {
        links.insert(0, link);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent_core::settings_file::{
        SourceControlConnectionSettings, SourceControlProvider, SourceControlSettings,
    };

    #[test]
    fn gitlab_project_urls_use_the_clone_endpoint_without_redirects() {
        let mut config = SourceControlSettings::default();
        config.connections.insert(
            "https://git.example:8443/forge".into(),
            SourceControlConnectionSettings {
                provider: SourceControlProvider::Gitlab,
                ..Default::default()
            },
        );
        for url in [
            "https://git.example:8443/forge/team/sub/project",
            "https://git.example:8443/forge/team/sub/project/",
            "https://git.example:8443/forge/team/sub/project.git",
            "https://git.example:8443/forge/team/sub/project.git/",
        ] {
            let mut input = WorkspaceCreate {
                github_url: Some(url.into()),
                ..Default::default()
            };
            normalize_source_url(&config, &mut input);
            assert_eq!(
                input.github_url.as_deref(),
                Some("https://git.example:8443/forge/team/sub/project.git"),
                "GitLab's web URL redirects smart HTTP to its .git endpoint: {url}"
            );
            assert!(input.context_links.is_none());
        }
    }

    #[test]
    fn create_resource_urls_become_canonical_repository_and_context_link() {
        let mut config = SourceControlSettings::default();
        config.connections.insert(
            "https://git.example/forge".into(),
            SourceControlConnectionSettings {
                provider: SourceControlProvider::Gitlab,
                ..Default::default()
            },
        );
        for (url, expected, owner, kind, number) in [
            (
                "https://git.example/forge/team/sub/project/-/merge_requests/17/diffs",
                "https://git.example/forge/team/sub/project.git",
                "team/sub",
                ContextLinkKind::Pr,
                17,
            ),
            (
                "https://git.example/forge/team/sub/project/-/issues/31",
                "https://git.example/forge/team/sub/project.git",
                "team/sub",
                ContextLinkKind::Issue,
                31,
            ),
            (
                "https://github.com/team/project/pull/9",
                "https://github.com/team/project",
                "team",
                ContextLinkKind::Pr,
                9,
            ),
        ] {
            let mut input = WorkspaceCreate {
                github_url: Some(url.into()),
                ..Default::default()
            };
            normalize_source_url(&config, &mut input);
            assert_eq!(input.github_url.as_deref(), Some(expected));
            let links = input.context_links.unwrap();
            assert_eq!(links.len(), 1);
            assert_eq!(links[0].owner, owner);
            assert_eq!(links[0].repo, "project");
            assert_eq!(links[0].kind, kind);
            assert_eq!(links[0].number, number);
            assert_eq!(links[0].url, url.trim_end_matches("/diffs"));
            assert!(!links[0].url.contains(".git/"));
        }
    }

    #[test]
    fn plain_ssh_and_unregistered_hosts_are_not_reinterpreted() {
        let mut config = SourceControlSettings::default();
        config.connections.insert(
            "https://git.example:8443/forge".into(),
            SourceControlConnectionSettings {
                provider: SourceControlProvider::Gitlab,
                ..Default::default()
            },
        );
        for url in [
            "git@gitlab.com:team/sub/project.git",
            "ssh://git@git.example/team/sub/project.git",
            "https://github.com/team/project",
            "https://git.example:8443/outside/team/project",
            "http://git.example:8443/forge/team/project",
            "https://git.example/forge/team/project",
            "file:///tmp/team/project",
            "https://unregistered.example/team/sub/project/-/merge_requests/7",
        ] {
            let mut input = WorkspaceCreate {
                github_url: Some(url.into()),
                ..Default::default()
            };
            normalize_source_url(&config, &mut input);
            assert_eq!(input.github_url.as_deref(), Some(url));
            assert_eq!(clone_url(&config, url), url);
            assert!(input.context_links.is_none());
        }
    }
}
