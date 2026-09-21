use super::*;
use intent_sourcecontrol::{IssueQuery, PrInvolvement, ReviewVerdict};

#[tokio::test]
async fn branch_update_waits_until_rebase_finishes_and_reports_errors() {
    for failed in [false, true] {
        let mut completed = mr();
        completed["rebase_in_progress"] = json!(false);
        completed["merge_error"] = if failed {
            json!("conflict")
        } else {
            Value::Null
        };
        let (url, task) = fixture(vec![
            Exchange::write("PUT", "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/rebase", json!({}), json!({"rebase_in_progress":true})),
            Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7?include_rebase_in_progress=true", json!({"rebase_in_progress":true})),
            Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7?include_rebase_in_progress=true", completed),
        ]).await;
        let result = GitLabSourceControl::new("fixture-secret", &url)
            .unwrap()
            .update_branch(&repo(), 7)
            .await;
        assert_eq!(result.is_err(), failed);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn rebase_merge_honors_project_policy_and_requires_review_of_new_head() {
    for fast_forward in [false, true] {
        let mut exchanges = vec![
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
                mr(),
            ),
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject",
                json!({"merge_method": if fast_forward {"ff"} else {"merge"}}),
            ),
        ];
        if fast_forward {
            let mut rebased = mr();
            rebased["sha"] = json!("new-head");
            rebased["rebase_in_progress"] = json!(false);
            exchanges.extend([
                Exchange::write("PUT","/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/rebase",json!({}),json!({"rebase_in_progress":true})),
                Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7?include_rebase_in_progress=true",rebased),
            ]);
        }
        let (url, task) = fixture(exchanges).await;
        let result = GitLabSourceControl::new("fixture-secret", &url)
            .unwrap()
            .merge_pr(
                &repo(),
                7,
                MergeMethod::Rebase,
                MergeOptions {
                    expected_head_sha: Some("reviewed-sha".into()),
                    ..MergeOptions::default()
                },
            )
            .await;
        if fast_forward {
            let result = result.unwrap();
            assert!(!result.merged);
            assert_eq!(result.sha.as_deref(), Some("new-head"));
            assert!(result.message.contains("Review"));
        } else {
            assert!(matches!(result, Err(Error::Config(_))));
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn stale_reviewed_head_refuses_merge_before_any_write() {
    let (url, task) = fixture(vec![Exchange::get(
        "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
        mr(),
    )])
    .await;
    let result = GitLabSourceControl::new("fixture-secret", &url)
        .unwrap()
        .merge_pr(
            &repo(),
            7,
            MergeMethod::Squash,
            MergeOptions {
                expected_head_sha: Some("obsolete".into()),
                ..MergeOptions::default()
            },
        )
        .await;
    assert!(matches!(result, Err(Error::Conflict(_))));
    task.await.unwrap();
}

#[tokio::test]
async fn request_changes_uses_graphql_and_does_not_hide_rejection_or_partial_success() {
    for outcome in ["success", "rejected", "summary-failed"] {
        let mut exchanges = vec![
            Exchange::get("/api/v4/user", json!({"id":42,"username":"bert"})),
            Exchange::write(
                "POST",
                "/api/graphql",
                json!({
                    "query":"mutation IntentRequestChanges($input: MergeRequestRequestChangesInput!) { mergeRequestRequestChanges(input: $input) { errors mergeRequest { iid } } }",
                    "variables":{"input":{"projectPath":"team/sub/project","iid":"7"}}
                }),
                if outcome == "rejected" {
                    json!({"data":{"mergeRequestRequestChanges":{"errors":["not allowed"],"mergeRequest":null}}})
                } else {
                    json!({"data":{"mergeRequestRequestChanges":{"errors":[],"mergeRequest":{"iid":"7"}}}})
                },
            ),
        ];
        if outcome != "rejected" {
            let mut note = Exchange::write(
                "POST",
                "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/notes",
                json!({"body":"Please fix"}),
                json!({"id":1,"body":"Please fix","author":{"username":"bert"},"created_at":"2026-09-21T09:00:00Z"}),
            );
            if outcome == "summary-failed" {
                note.status = 500;
            }
            exchanges.push(note);
        }
        let (url, task) = fixture(exchanges).await;
        let result = GitLabSourceControl::new("fixture-secret", &url)
            .unwrap()
            .submit_review(
                &repo(),
                7,
                ReviewVerdict::RequestChanges,
                Some("Please fix".into()),
            )
            .await;
        match outcome {
            "success" => assert_eq!(result.unwrap().verdict, ReviewVerdict::RequestChanges),
            "rejected" => assert!(matches!(result, Err(Error::Conflict(_)))),
            _ => assert!(result
                .unwrap_err()
                .to_string()
                .contains("change request succeeded")),
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn search_resumes_across_projects_without_losing_equal_iids() {
    let mut other = mr();
    other["web_url"] = json!("https://git.example/other/sub/project/-/merge_requests/7");
    let (url, task) = fixture(vec![
        Exchange::get(
            "/api/v4/projects/team%2Fsub%2Fproject/merge_requests?scope=all&page=1&per_page=30",
            json!([mr()]),
        ),
        Exchange::get(
            "/api/v4/projects/other%2Fsub%2Fproject/merge_requests?scope=all&page=1&per_page=30",
            json!([other]),
        ),
    ])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    let mut query = PrQuery {
        extra_repos: vec![repo(), RepoRef::new("other/sub", "project")],
        ..PrQuery::default()
    };
    let first = client.list_prs(&repo(), query.clone()).await.unwrap();
    assert_eq!(first.items.len(), 1);
    assert!(first.next_cursor.is_some());
    query.cursor = first.next_cursor;
    let second = client.list_prs(&repo(), query.clone()).await.unwrap();
    assert_eq!(second.items[0].number, first.items[0].number);
    assert_ne!(second.items[0].url, first.items[0].url);
    assert!(second.next_cursor.is_none());
    query.search = Some("different query".into());
    assert!(matches!(
        client.list_prs(&repo(), query).await,
        Err(Error::Config(_))
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn involves_search_includes_comment_participants_and_keeps_empty_page_cursor() {
    let mut first = Exchange::get(
        "/api/v4/projects/team%2Fsub%2Fproject/issues?scope=all&page=1&per_page=30",
        json!([mr()]),
    );
    first.headers.push(("x-next-page".into(), "2".into()));
    let (url, task) = fixture(vec![
        Exchange::get("/api/v4/user", json!({"username":"commenter","id":42})),
        first,
        Exchange::get(
            "/api/v4/projects/team%2Fsub%2Fproject/issues/7/participants?page=1&per_page=100",
            json!([]),
        ),
        Exchange::get("/api/v4/user", json!({"username":"commenter","id":42})),
        Exchange::get(
            "/api/v4/projects/team%2Fsub%2Fproject/issues?scope=all&page=2&per_page=30",
            json!([mr()]),
        ),
        Exchange::get(
            "/api/v4/projects/team%2Fsub%2Fproject/issues/7/participants?page=1&per_page=100",
            json!([{"username":"commenter"}]),
        ),
    ])
    .await;
    let client = GitLabSourceControl::new("fixture-secret", &url).unwrap();
    let mut query = IssueQuery {
        involvement: Some(PrInvolvement::Involves),
        ..IssueQuery::default()
    };
    let first = client.list_issues(&repo(), query.clone()).await.unwrap();
    assert!(first.items.is_empty());
    assert!(first.next_cursor.is_some());
    query.cursor = first.next_cursor;
    let second = client.list_issues(&repo(), query).await.unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());
    task.await.unwrap();
}

#[tokio::test]
async fn merge_train_and_blocking_review_are_mapped_without_guessing_unavailable_state() {
    for (status, expected) in [
        ("fresh", Some(true)),
        ("merging", Some(true)),
        ("merged", Some(false)),
        ("new_future_state", None),
    ] {
        let mut head = mr();
        head["detailed_merge_status"] = json!("requested_changes");
        let (url, task) = fixture(vec![
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
                head,
            ),
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject",
                json!({"merge_trains_enabled":true,"only_allow_merge_if_pipeline_succeeds":false}),
            ),
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/approvals",
                json!({"approvals_required":0,"approvals_left":0,"approved_by":[]}),
            ),
            Exchange::get(
                "/api/v4/projects/team%2Fsub%2Fproject/merge_trains/merge_requests/7",
                json!({"status":status}),
            ),
        ])
        .await;
        let signals = GitLabSourceControl::new("fixture-secret", &url)
            .unwrap()
            .merge_requirements(&repo(), 7)
            .await
            .unwrap();
        assert_eq!(signals.is_in_merge_queue, expected);
        assert_eq!(
            signals.review_decision,
            Some(intent_sourcecontrol::ReviewDecision::ChangesRequested)
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn approval_with_summary_confirms_verdict_and_posts_text() {
    let (url,task)=fixture(vec![
        Exchange::get("/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",mr()),
        Exchange::get("/api/v4/user",json!({"id":42,"username":"bert"})),
        Exchange::write("POST","/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/approve",json!({"sha":"reviewed-sha"}),json!({"approved_by":[{"user":{"username":"bert"},"approved_at":"2026-09-21T09:00:00Z"}]})),
        Exchange::write("POST","/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7/notes",json!({"body":"Looks good"}),json!({"id":12,"body":"Looks good","author":{"username":"bert"},"created_at":"2026-09-21T09:00:00Z"})),
    ]).await;
    let review = GitLabSourceControl::new("fixture-secret", &url)
        .unwrap()
        .submit_review(
            &repo(),
            7,
            ReviewVerdict::Approve,
            Some("Looks good".into()),
        )
        .await
        .unwrap();
    assert_eq!(review.body.as_deref(), Some("Looks good"));
    assert_eq!(review.verdict, ReviewVerdict::Approve);
    task.await.unwrap();
}

#[tokio::test]
async fn direct_review_decision_preserves_gitlab_change_request_block() {
    let mut head = mr();
    head["detailed_merge_status"] = json!("requested_changes");
    let (url, task) = fixture(vec![Exchange::get(
        "/api/v4/projects/team%2Fsub%2Fproject/merge_requests/7",
        head,
    )])
    .await;
    let decision = GitLabSourceControl::new("fixture-secret", &url)
        .unwrap()
        .review_decision(&repo(), 7)
        .await
        .unwrap();
    assert_eq!(
        decision,
        Some(intent_sourcecontrol::ReviewDecision::ChangesRequested)
    );
    task.await.unwrap();
}
