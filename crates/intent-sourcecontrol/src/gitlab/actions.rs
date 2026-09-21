//! GitLab review mutations and asynchronous branch updates.
use super::{
    json, mr, number, project, to_pr, Comment, Duration, Error, GitLabSourceControl, Method,
    PullRequest, RepoRef, Result, SourceControl, Value,
};

impl GitLabSourceControl {
    pub(super) async fn rebase_branch(&self, repo: &RepoRef, iid: u64) -> Result<PullRequest> {
        self.write(Method::PUT, &format!("{}/rebase", mr(repo, iid)), json!({}))
            .await?;
        // Enqueued is not completed. Check the documented status, never infer
        // success from a 202 or a missing field. Stop after a bounded interval.
        for attempt in 0..40 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let (head, _) = self
                .request(
                    Method::GET,
                    &mr(repo, iid),
                    &[("include_rebase_in_progress".into(), "true".into())],
                    None,
                )
                .await?;
            if head["merge_error"].as_str().is_some_and(|s| !s.is_empty()) {
                return Err(Error::Conflict(
                    "GitLab rebase failed; inspect the merge request before retrying".into(),
                ));
            }
            match head["rebase_in_progress"].as_bool() {
                Some(false) => return to_pr(head),
                Some(true) => {}
                None => {
                    return Err(Error::Decode(
                        "GitLab omitted rebase status; completion is unknown".into(),
                    ))
                }
            }
        }
        Err(Error::Conflict(
            "GitLab rebase is still running; refresh the merge request before retrying".into(),
        ))
    }

    pub(super) async fn request_changes(&self, repo: &RepoRef, iid: u64) -> Result<()> {
        let query = "mutation IntentRequestChanges($input: MergeRequestRequestChangesInput!) { mergeRequestRequestChanges(input: $input) { errors mergeRequest { iid } } }";
        let (value, _) = self.request(Method::POST, "../graphql", &[], Some(json!({
            "query": query, "variables": {"input": {"projectPath": format!("{}/{}", repo.owner, repo.name), "iid": iid.to_string()}}
        }))).await?;
        if value
            .get("errors")
            .is_some_and(|v| v.as_array().is_none_or(|e| !e.is_empty()))
        {
            return Err(Error::Api("GitLab rejected the request-changes operation; check server version, tier and review permissions".into()));
        }
        let result = &value["data"]["mergeRequestRequestChanges"];
        if result["errors"].as_array().is_none_or(|e| !e.is_empty())
            || result["mergeRequest"]["iid"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                != Some(iid)
        {
            return Err(Error::Conflict(
                "GitLab did not confirm the change request; check review permissions".into(),
            ));
        }
        Ok(())
    }

    pub(super) async fn review_summary(
        &self,
        repo: &RepoRef,
        iid: u64,
        body: Option<&str>,
        verdict: &str,
    ) -> Result<Option<Comment>> {
        let Some(body) = body.filter(|text| !text.trim().is_empty()) else {
            return Ok(None);
        };
        self.add_comment(repo, iid, body, None).await.map(Some).map_err(|_| Error::Api(format!(
            "GitLab {verdict} succeeded, but its summary comment could not be confirmed. Inspect the MR before retrying the comment."
        )))
    }

    pub(super) async fn merge_train_state(
        &self,
        repo: &RepoRef,
        head: &Value,
        policy: Option<&Value>,
    ) -> Result<Option<bool>> {
        match policy.and_then(|p| p["merge_trains_enabled"].as_bool()) {
            Some(false) => Ok(Some(false)),
            None => Ok(None),
            Some(true) => {
                let iid = number(head, "iid")?;
                match self
                    .get(&format!(
                        "{}/merge_trains/merge_requests/{iid}",
                        project(repo)
                    ))
                    .await
                {
                    Ok(car) => match car["status"].as_str() {
                        Some("idle" | "fresh" | "stale" | "merging") => Ok(Some(true)),
                        Some("merged" | "skip_merged") => Ok(Some(false)),
                        _ => Ok(None),
                    },
                    // A 404 can also hide an unavailable feature; do not invent
                    // a trustworthy negative from a permission/version failure.
                    Err(Error::Auth(_) | Error::NotFound(_)) => Ok(None),
                    Err(error) => Err(error),
                }
            }
        }
    }
}
