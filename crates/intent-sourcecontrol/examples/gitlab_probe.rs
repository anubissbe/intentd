//! Read-only authentication smoke probe; credentials never appear in argv or output.
use intent_sourcecontrol::{
    GitlabSettings, GitlabTokenSource, PageParams, SourceControlRegistry, SourceControlSettings,
};

#[tokio::main]
async fn main() {
    let instance_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://gitlab.com".into());
    let settings = SourceControlSettings {
        active_provider: "gitlab".into(),
        gitlab: GitlabSettings {
            instance_url,
            token_source: GitlabTokenSource::GlabCli,
            ..GitlabSettings::default()
        },
        ..SourceControlSettings::default()
    };
    let result = async {
        let provider = SourceControlRegistry::from_settings(&settings).await?;
        let auth = provider.check_auth().await?;
        let repos = provider.list_repos(PageParams::first(1)).await?;
        println!(
            "provider={} authenticated={} repositories_returned={}",
            provider.provider_id(),
            auth.authenticated,
            repos.items.len()
        );
        intent_sourcecontrol::Result::Ok(())
    }
    .await;
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
