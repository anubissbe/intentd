//! Real HTTP fixture coverage for GitLab request semantics and credential boundaries.
use intent_sourcecontrol::{
    Error, GitLabSourceControl, GitlabSettings, GitlabTokenSource, MergeMethod, MergeOptions,
    PageParams, PrPatch, PrQuery, PrState, RateLimitStatus, RepoRef, SourceControl,
    SourceControlRegistry, SourceControlSettings,
};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

struct Exchange {
    method: &'static str,
    path: &'static str,
    status: u16,
    response: Value,
    headers: Vec<(String, String)>,
    expected_body: Option<Value>,
}
impl Exchange {
    fn get(path: &'static str, response: Value) -> Self {
        Self {
            method: "GET",
            path,
            status: 200,
            response,
            headers: vec![],
            expected_body: None,
        }
    }
    fn write(method: &'static str, path: &'static str, body: Value, response: Value) -> Self {
        Self {
            method,
            expected_body: Some(body),
            ..Self::get(path, response)
        }
    }
}
async fn fixture(exchanges: Vec<Exchange>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        for exchange in exchanges {
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut part = [0; 4096];
                let count = stream.read(&mut part).await.unwrap();
                assert!(count > 0, "connection closed before headers");
                bytes.extend_from_slice(&part[..count]);
                if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
            let mut lines = headers.lines();
            let first = lines.next().unwrap();
            assert_eq!(
                first,
                format!("{} {} HTTP/1.1", exchange.method, exchange.path)
            );
            let fields: Vec<_> = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                .collect();
            assert_eq!(
                fields
                    .iter()
                    .find(|(key, _)| key == "authorization")
                    .map(|(_, value)| value.as_str()),
                Some("Bearer fixture-secret")
            );
            let length = fields
                .iter()
                .find(|(key, _)| key == "content-length")
                .map_or(0, |(_, value)| value.parse::<usize>().unwrap());
            while bytes.len() < header_end + length {
                let mut part = [0; 4096];
                let count = stream.read(&mut part).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&part[..count]);
            }
            if let Some(expected) = exchange.expected_body {
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes[header_end..header_end + length])
                        .unwrap(),
                    expected
                );
            }
            let body = exchange.response.to_string();
            let extra = exchange
                .headers
                .iter()
                .fold(String::new(), |mut out, (key, value)| {
                    use std::fmt::Write as _;
                    write!(out, "{key}: {value}\r\n").unwrap();
                    out
                });
            let response = format!("HTTP/1.1 {} Fixture\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n{}", exchange.status, body.len(), extra, body);
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (url, handle)
}
fn mr() -> Value {
    json!({"iid": 7, "web_url":"https://git.example/team/sub/project/-/merge_requests/7", "title":"Implement thing", "description": "Details", "state":"opened", "draft":false, "source_branch":"feature", "target_branch":"main", "author":{"username":"bert"}, "detailed_merge_status":"mergeable", "sha":"reviewed-sha", "created_at":"2026-09-19T10:00:00Z", "updated_at":"2026-09-19T11:00:00Z"})
}
fn repo() -> RepoRef {
    RepoRef::new("team/sub", "project")
}

#[tokio::test]
async fn nested_projects_auth_and_pagination_use_native_api() {
    let project = json!({"path_with_namespace":"team/sub/project","web_url":"https://git.example/team/sub/project", "default_branch":"main"});
    let mut first = Exchange::get(
        "/api/v4/projects?membership=true&order_by=last_activity_at&simple=true&page=1&per_page=1",
        json!([project]),
    );
    first.headers.push(("x-next-page".into(), "2".into()));
    let (url, task) = fixture(vec![
        Exchange::get("/api/v4/user", json!({"username":"bert","id":42})),
        first,
        Exchange::get(
            "/api/v4/projects?membership=true&order_by=last_activity_at&simple=true&page=2&per_page=1",
            json!([]),
        ),
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject", project),
    ])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    assert!(client.check_auth().await.unwrap().authenticated);
    let page = client.list_repos(PageParams::first(1)).await.unwrap();
    assert_eq!(page.items[0].owner, "team/sub");
    assert_eq!(page.next_cursor.as_deref(), Some("2"));
    assert!(client
        .list_repos(PageParams {
            limit: 1,
            cursor: page.next_cursor
        })
        .await
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        client.get_repo("team/sub", "project").await.unwrap().name,
        "project"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn project_picker_requests_summaries_and_preserves_all_repo_fields() {
    // These fields are present in GitLab's simple project representation; full
    // project policy/settings responses are unnecessary for listing and search.
    let summary = json!({
        "path_with_namespace": "team/sub/project",
        "web_url": "https://git.example/team/sub/project",
        "default_branch": "main",
        "created_at": "2026-09-19T10:00:00Z",
        "last_activity_at": "2026-09-20T11:00:00Z"
    });
    let (url, task) = fixture(vec![
        Exchange::get(
            "/api/v4/projects?membership=true&order_by=last_activity_at&simple=true&page=1&per_page=50",
            json!([summary]),
        ),
        Exchange::get(
            "/api/v4/projects?search=team%2Fsub&search_namespaces=true&simple=true&page=1&per_page=50",
            json!([summary]),
        ),
    ])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    for page in [
        client.list_repos(PageParams::first(50)).await.unwrap(),
        client
            .search_repos("team/sub", PageParams::first(50))
            .await
            .unwrap(),
    ] {
        assert_eq!(page.items.len(), 1);
        assert!(page.next_cursor.is_none());
        let project = &page.items[0];
        assert_eq!(project.owner, "team/sub");
        assert_eq!(project.name, "project");
        assert_eq!(
            project.url.as_deref(),
            Some("https://git.example/team/sub/project")
        );
        assert_eq!(project.default_branch.as_deref(), Some("main"));
        assert_eq!(project.created_at.as_deref(), Some("2026-09-19T10:00:00Z"));
        assert_eq!(project.updated_at.as_deref(), Some("2026-09-20T11:00:00Z"));
    }
    task.await.unwrap();
}

#[tokio::test]
async fn merge_sends_sha_and_never_reports_accepted_as_merged() {
    let (url, task) = fixture(vec![
        Exchange::get(
            "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
            mr(),
        ),
        Exchange::write(
            "PUT",
            "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/merge",
            json!({"sha":"reviewed-sha","squash":true}),
            mr(),
        ),
    ])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    let outcome = client
        .merge_pr(&repo(), 7, MergeMethod::Squash, MergeOptions::default())
        .await
        .unwrap();
    assert!(!outcome.merged);
    task.await.unwrap();
}

#[tokio::test]
async fn updates_map_draft_and_close_to_gitlab_fields() {
    let (url, task) = fixture(vec![Exchange::write(
        "PUT",
        "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
        json!({"title":"Draft: Next", "description":"Text", "state_event":"close"}),
        mr(),
    )])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    client
        .update_pr(
            &repo(),
            7,
            PrPatch {
                title: Some("Next".into()),
                body: Some("Text".into()),
                draft: Some(true),
                state: Some(PrState::Closed),
                ..PrPatch::default()
            },
        )
        .await
        .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn errors_are_typed_and_never_echo_server_secrets() {
    for (status, expected) in [
        (401, "auth"),
        (403, "auth"),
        (404, "not found"),
        (409, "conflict"),
        (429, "rate limited"),
        (500, "api error"),
    ] {
        let mut exchange = Exchange::get(
            "/api/v4/user",
            json!({"message":"fixture-secret echoed by unsafe server"}),
        );
        exchange.status = status;
        let (url, task) = fixture(vec![exchange]).await;
        let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
        let error = client.get_user().await.unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("fixture-secret"));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn refuses_redirects_and_cross_origin_pagination() {
    let receiver = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("http://{}/steal", receiver.local_addr().unwrap());
    let mut redirect = Exchange::get("/api/v4/user", json!({}));
    redirect.status = 302;
    redirect.headers.push(("location".into(), target.clone()));
    let (url, task) = fixture(vec![redirect]).await;
    assert!(GitLabSourceControl::new("fixture-secret", &url)
        .unwrap()
        .get_user()
        .await
        .unwrap_err()
        .to_string()
        .contains("redirect refused"));
    task.await.unwrap();
    let mut link = Exchange::get(
        "/api/v4/projects?membership=true&order_by=last_activity_at&simple=true&page=1&per_page=10",
        json!([]),
    );
    link.headers
        .push(("link".into(), format!("<{target}?page=2>; rel=\"next\"")));
    let (url, task) = fixture(vec![link]).await;
    assert!(GitLabSourceControl::new("fixture-secret", &url)
        .unwrap()
        .list_repos(PageParams::first(10))
        .await
        .unwrap_err()
        .to_string()
        .contains("escaped"));
    task.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), receiver.accept())
            .await
            .is_err(),
        "credentials reached redirect target"
    );
}

#[tokio::test]
async fn pagination_cannot_loop_or_silently_truncate() {
    let mut exchange = Exchange::get(
        "/api/v4/projects?membership=true&order_by=last_activity_at&simple=true&page=1&per_page=10",
        json!([]),
    );
    exchange.headers.push(("x-next-page".into(), "1".into()));
    let (url, task) = fixture(vec![exchange]).await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    assert!(client
        .list_repos(PageParams::first(10))
        .await
        .unwrap_err()
        .to_string()
        .contains("did not advance"));
    assert!(client
        .list_repos(PageParams {
            limit: 10,
            cursor: Some("101".into())
        })
        .await
        .is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn gitlab_filters_and_missing_file_are_explicit() {
    let mut missing = Exchange::get(
        "/api/v4/projects/team%2Fsub%2Fproject/repository/files/folder%2Fconfig.json?ref=main",
        json!({}),
    );
    missing.status = 404;
    let (url, task) = fixture(vec![Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/merge_requests?scope=all&state=opened&source_branch=feature&search=widget&page=1&per_page=30", json!([mr()])), missing]).await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    assert_eq!(
        client
            .list_prs(
                &repo(),
                PrQuery {
                    state: Some(PrState::Open),
                    head: Some("feature".into()),
                    search: Some("widget".into()),
                    ..PrQuery::default()
                }
            )
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    assert!(client
        .get_file_content(&repo(), "folder/config.json", Some("main"))
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        client
            .merge_pr(&repo(), 7, MergeMethod::Rebase, MergeOptions::default())
            .await,
        Err(Error::Unsupported(_))
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn credentials_are_bound_to_full_instance_and_debug_redacted() {
    let settings = GitlabSettings {
        instance_url: "https://git.example".into(),
        token: Some("super-secret".into()),
        token_host: Some("https://other.example".into()),
        token_source: GitlabTokenSource::Explicit,
    };
    assert!(!format!("{settings:?}").contains("super-secret"));
    let result = SourceControlRegistry::from_settings(&SourceControlSettings {
        active_provider: "gitlab".into(),
        gitlab: settings,
        ..SourceControlSettings::default()
    })
    .await;
    assert!(matches!(result, Err(Error::NotConfigured(_))));
    for url in [
        "http://git.example",
        "https://user:secret@git.example",
        "https://git.example?q=secret",
        "https://git.example/#secret",
        "file:///etc/passwd",
    ] {
        assert!(
            GitLabSourceControl::new("fixture-secret", url).is_err(),
            "{url}"
        );
    }
    assert!(GitLabSourceControl::new("secret\r\nInjected: value", "https://git.example").is_err());
}

#[tokio::test]
async fn discussion_identifiers_are_bound_to_instance_before_mutation() {
    let note = json!({"id": 11, "body":"Check this", "author":{"username":"bert"}, "created_at":"2026-09-19T10:00:00Z", "updated_at":"2026-09-19T10:00:00Z", "resolvable":true,"resolved":false,"type":"DiffNote", "position":{"new_path":"src/a.rs","new_line":3}});
    let discussion = json!({"id":"discussion-a", "notes":[note]});
    let mut resolved = discussion.clone();
    resolved["notes"][0]["resolved"] = json!(true);
    let (url, task) = fixture(vec![
        Exchange::get(
            "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/discussions?page=1&per_page=30",
            json!([discussion]),
        ),
        Exchange::write(
            "PUT",
            "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/discussions/discussion-a",
            json!({"resolved":true}),
            resolved,
        ),
    ])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    let threads = client
        .get_review_threads(&repo(), 7, PageParams::first(30))
        .await
        .unwrap();
    let id = &threads.items[0].id;
    assert!(!threads.items[0].is_resolved);
    let other = GitLabSourceControl::new("fixture-secret", "https://another.example").unwrap();
    assert!(matches!(
        other.resolve_thread(id).await,
        Err(Error::Config(_))
    ));
    assert!(client.resolve_thread(id).await.unwrap());
    task.await.unwrap();
}

#[tokio::test]
async fn pipeline_jobs_use_exact_sha_and_optional_manual_is_neutral() {
    let (url, task) = fixture(vec![
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/repository/commits/feature%2Fbranch", json!({"id":"head-sha"})),
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/repository/commits/head-sha/statuses?page=1&per_page=100", json!([])),
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/pipelines?sha=head-sha&order_by=id&sort=desc&page=1&per_page=1", json!([{"id":9,"status":"success","web_url":"https://git.example/pipeline/9"}])),
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/pipelines/9/jobs?page=1&per_page=100", json!([{"name":"optional deploy","status":"manual","allow_failure":true},{"name":"mandatory review","status":"manual","allow_failure":false}]))
    ]).await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    let checks = client.check_runs(&repo(), "feature/branch").await.unwrap();
    assert_eq!(checks[0].state, intent_sourcecontrol::CheckState::Success);
    assert_eq!(checks[1].state, intent_sourcecontrol::CheckState::Neutral);
    assert_eq!(checks[2].state, intent_sourcecontrol::CheckState::Pending);
    task.await.unwrap();
}

fn policy(required_ci: bool, skipped: bool, resolved: bool) -> Value {
    json!({
        "only_allow_merge_if_pipeline_succeeds": required_ci,
        "allow_merge_on_skipped_pipeline": skipped,
        "only_allow_merge_if_all_discussions_are_resolved": resolved,
    })
}

fn approvals(required: u32, approved: bool) -> Value {
    json!({"approved":approved,"approvals_required":required,"approvals_left":if approved {0} else {required},"approved_by":[]})
}

#[tokio::test]
async fn observation_reuses_native_resources_and_preserves_required_rules() {
    use intent_sourcecontrol::{CheckState, ReviewDecision};
    let mut head = mr();
    head["head_pipeline"] = json!({"id":12,"project_id":42,"sha":"merged-results-sha","status":"running","web_url":"https://git.example/pipeline/12"});
    let approval = json!({"approved":false,"approvals_required":2,"approvals_left":1,"approved_by":[{"user":{"username":"alice"}},{"user":{"username":"bob"}},{"user":{"username":"carol"}}]});
    let mut jobs = Exchange::get(
        "/api/v4/projects/42/pipelines/12/jobs?page=1&per_page=100",
        json!([
            {"name":"test","status":"success","allow_failure":false},
            {"name":"optional fail","status":"failed","allow_failure":true},
            {"name":"optional manual","status":"manual","allow_failure":true},
            {"name":"optional running","status":"running","allow_failure":true}
        ]),
    );
    jobs.headers.push(("x-next-page".into(), "2".into()));
    let mut discussions = Exchange::get(
        "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/discussions?page=1&per_page=100",
        json!([
            {"notes":[{"type":"DiffNote","resolvable":true,"resolved":false},{"resolvable":false}]},
            {"notes":[{"type":"DiffNote","resolvable":true,"resolved":true}]},
            {"notes":[{"system":true}]}
        ]),
    );
    discussions.headers.push(("x-next-page".into(), "2".into()));
    let (url, task) = fixture(vec![
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7", head),
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject", policy(true,false,true)),
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/approvals", approval),
        jobs,
        Exchange::get("/api/v4/projects/42/pipelines/12/jobs?page=2&per_page=100", json!([{"name":"release gate","status":"manual","allow_failure":false}])),
        discussions,
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/discussions?page=2&per_page=100", json!([{"notes":[{"body":"General discussion"},{"body":"Reply"}]}])),
    ]).await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    let observation = client.pr_observation(&repo(), 7).await.unwrap().unwrap();
    assert_eq!(observation.pr.head_sha.as_deref(), Some("reviewed-sha"));
    let signals = observation.signals;
    assert!(signals.checks_known);
    assert_eq!(
        signals.review_decision,
        Some(ReviewDecision::ReviewRequired)
    );
    assert_eq!(observation.reviews.unwrap().len(), 3); // Counts do not override rule eligibility.
    let rules = signals.branch_rules.unwrap();
    assert_eq!(rules.required_approving_review_count, Some(2));
    assert_eq!(rules.required_conversation_resolution, Some(true));
    assert_eq!(rules.required_status_checks, ["GitLab pipeline"]);
    assert_eq!(signals.checks.len(), 6);
    assert!(signals.checks[0].is_required);
    assert!(signals.checks[1].is_required);
    for check in &signals.checks[2..5] {
        assert!(!check.is_required);
    }
    assert_eq!(signals.checks[2].state, CheckState::Neutral);
    assert_eq!(signals.checks[3].state, CheckState::Neutral);
    assert_eq!(signals.checks[4].state, CheckState::Pending);
    assert!(signals.checks[5].is_required);
    assert_eq!(signals.checks[5].state, CheckState::Pending);
    assert_eq!(observation.threads.unwrap().review_comment_count, 3);
    assert_eq!(observation.threads.unwrap().unresolved, 1);
    assert_eq!(observation.conversation_count, 2);
    task.await.unwrap(); // Exact exchange list also guards accidental duplicate/N+1 requests.
}

#[tokio::test]
async fn pipeline_requirement_respects_disabled_skipped_and_missing_ci() {
    use intent_sourcecontrol::CheckState;
    for (required, skipped_allowed, status, expected, count) in [
        (false, false, "failed", CheckState::Failure, 1),
        (true, false, "skipped", CheckState::Failure, 1),
        (true, true, "skipped", CheckState::Success, 1),
        (true, false, "", CheckState::Pending, 1),
        (false, false, "", CheckState::Pending, 0),
    ] {
        let mut head = mr();
        if !status.is_empty() {
            head["head_pipeline"] = json!({"id":9,"status":status});
        }
        let mut exchanges = vec![
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
                head,
            ),
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject",
                policy(required, skipped_allowed, false),
            ),
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/approvals",
                approvals(0, false),
            ),
        ];
        if !status.is_empty() {
            exchanges.push(Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject/pipelines/9/jobs?page=1&per_page=100",
                json!([]),
            ));
        }
        let (url, task) = fixture(exchanges).await;
        let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
        let signals = client.merge_requirements(&repo(), 7).await.unwrap();
        assert!(signals.checks_known);
        assert_eq!(signals.checks.len(), count);
        if count > 0 {
            assert_eq!(signals.checks[0].state, expected);
            assert_eq!(signals.checks[0].is_required, required);
        }
        assert_eq!(signals.review_decision, None); // CE: voluntary approval absent, no requirement.
        assert_eq!(
            signals
                .branch_rules
                .unwrap()
                .required_approving_review_count,
            Some(0)
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn mergeability_uses_project_pipeline_policy() {
    for (required, skipped, status, passed) in [
        (false, false, "failed", true),
        (true, false, "skipped", false),
        (true, true, "skipped", true),
        (true, false, "success", true),
        (true, false, "", false),
    ] {
        let mut head = mr();
        head["head_pipeline"] = json!({"status":status});
        let (url, task) = fixture(vec![
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
                head,
            ),
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject",
                policy(required, skipped, false),
            ),
        ])
        .await;
        let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
        assert_eq!(
            client
                .mergeability(&repo(), 7)
                .await
                .unwrap()
                .required_checks_passed,
            passed
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn unavailable_rules_and_approvals_stay_unknown_and_quota_never_degrades() {
    let mut unavailable = Exchange::get("/api/v4/projects/team%2Fsub%2Fproject", json!({}));
    unavailable.status = 403;
    let mut unavailable_approvals = Exchange::get(
        "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/approvals",
        json!({}),
    );
    unavailable_approvals.status = 404;
    let (url, task) = fixture(vec![
        Exchange::get(
            "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
            mr(),
        ),
        unavailable,
        unavailable_approvals,
    ])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    let signals = client.merge_requirements(&repo(), 7).await.unwrap();
    assert!(!signals.checks_known);
    assert!(signals.branch_rules.is_none());
    assert!(signals.review_decision.is_none());
    task.await.unwrap();
    let mut limited = Exchange::get(
        "/api/v4/projects/team%2Fsub%2Fproject",
        json!({"message":"fixture-secret"}),
    );
    limited.status = 429;
    let (url, task) = fixture(vec![
        Exchange::get(
            "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
            mr(),
        ),
        limited,
    ])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    assert!(matches!(
        client.merge_requirements(&repo(), 7).await,
        Err(Error::RateLimited(_))
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn branch_rules_report_only_available_project_policy() {
    let (url, task) = fixture(vec![Exchange::get(
        "/api/v4/projects/team%2Fsub%2Fproject",
        policy(true, false, true),
    )])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    let rules = client.branch_rules(&repo(), "main").await.unwrap();
    assert_eq!(rules.required_approving_review_count, None);
    assert_eq!(rules.required_conversation_resolution, Some(true));
    assert_eq!(rules.required_status_checks, ["GitLab pipeline"]);
    task.await.unwrap();
}

#[tokio::test]
async fn quota_probe_reuses_headers_even_when_request_is_throttled() {
    let mut first = Exchange::get("/api/v4/user", json!({"username":"bert"}));
    first.headers = vec![
        ("RateLimit-Limit".into(), "60".into()),
        ("RateLimit-Remaining".into(), "3".into()),
        ("RateLimit-Reset".into(), "2000000000".into()),
    ];
    let mut second = Exchange::get("/api/v4/user", json!({}));
    second.status = 429;
    second.headers = vec![("Retry-After".into(), "30".into())];
    let (url, task) = fixture(vec![first, second]).await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    assert_eq!(
        client.rate_limit_status().await.unwrap(),
        RateLimitStatus::default()
    );
    client.check_auth().await.unwrap();
    let quota = client.clone().rate_limit_status().await.unwrap();
    assert_eq!(quota.limit, Some(60));
    assert_eq!(quota.remaining, Some(3));
    assert_eq!(quota.reset_at, Some(2_000_000_000));
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(matches!(
        client.check_auth().await,
        Err(Error::RateLimited(_))
    ));
    let quota = client.rate_limit_status().await.unwrap();
    assert_eq!(quota.remaining, Some(0));
    assert_eq!(quota.limit, None); // This could be an unrelated application throttle.
    assert!(quota.reset_at.unwrap() >= before + 30);
    task.await.unwrap(); // Probing quota itself made no HTTP request.
}
