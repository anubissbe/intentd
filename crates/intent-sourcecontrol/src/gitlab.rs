//! Native GitLab REST v4 adapter. Credentials never leave the configured instance.
use std::{
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Method, Url,
};
use serde_json::{json, Value};

use crate::{
    model::{
        AuthStatus, Branch, BranchRules, CheckRun, CheckState, Comment, CommentAnchor, Issue,
        IssueQuery, MergeMethod, MergeOptions, MergeOutcome, MergeRequirementSignals, Mergeability,
        NewPullRequest, Page, PageParams, PrInvolvement, PrObservation, PrPatch, PrQuery, PrState,
        PullRequest, RateLimitStatus, Repo, RepoRef, Review, ReviewComment, ReviewDecision,
        ReviewThread, ReviewThreadComment, ReviewThreadTally, ReviewVerdict, RollupCheck,
        RollupCheckKind, ScCapabilities, UserIdentity,
    },
    Error, Result, SourceControl,
};

const MAX_PAGES: u32 = 100;
const PIPELINE_CHECK: &str = "GitLab pipeline";
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// GitLab.com and self-managed GitLab source control.
#[derive(Clone)]
pub struct GitLabSourceControl {
    client: reqwest::Client,
    api: Url,
    rate_limit: Arc<RwLock<RateLimitStatus>>,
}

impl GitLabSourceControl {
    /// Construct a client. HTTP is permitted only for loopback fixtures.
    ///
    /// # Errors
    /// Returns a configuration error for an unsafe URL or invalid token header.
    pub fn new(token: &str, instance_url: &str) -> Result<Self> {
        let instance = crate::gitlab_token::normalize_instance_url(instance_url)?;
        if token.trim().is_empty() {
            return Err(Error::NotConfigured("GitLab token is empty".into()));
        }
        let mut header = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Error::Config("GitLab token contains invalid header characters".into()))?;
        header.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, header);
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .user_agent("intent-sourcecontrol")
            .build()
            .map_err(|_| Error::Config("cannot construct GitLab HTTP client".into()))?;
        let api = Url::parse(&format!("{instance}/api/v4/"))
            .map_err(|_| Error::Config("invalid GitLab API URL".into()))?;
        Ok(Self {
            client,
            api,
            rate_limit: Arc::default(),
        })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<Value>,
    ) -> Result<(Value, HeaderMap)> {
        let url = self
            .api
            .join(path)
            .map_err(|_| Error::Config("invalid GitLab endpoint".into()))?;
        if url.origin() != self.api.origin() || !url.path().starts_with(self.api.path()) {
            return Err(Error::Config(
                "GitLab endpoint escaped configured instance".into(),
            ));
        }
        let mut request = self.client.request(method, url).query(query);
        if let Some(body) = body {
            request = request.json(&body);
        }
        // Never return reqwest errors, response bodies, or redirect targets: they may contain secrets.
        let response = request
            .send()
            .await
            .map_err(|_| Error::Api("GitLab request failed (network or timeout)".into()))?;
        let status = response.status();
        let headers = response.headers().clone();
        self.observe_rate_limit(&headers, status.as_u16() == 429);
        if !status.is_success() {
            let message = format!("GitLab HTTP {}", status.as_u16());
            return Err(match status.as_u16() {
                401 | 403 => Error::Auth(message),
                404 => Error::NotFound(message),
                405 | 409 | 422 => Error::Conflict(message),
                429 => Error::RateLimited(message),
                300..=399 => Error::Api(
                    "GitLab redirect refused; update the configured instance or project path"
                        .into(),
                ),
                _ => Error::Api(message),
            });
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
        {
            return Err(Error::Api("GitLab response exceeds size limit".into()));
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error::Api("GitLab response interrupted".into()))?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(Error::Api("GitLab response exceeds size limit".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|_| Error::Decode("GitLab response was not valid JSON".into()))?
        };
        Ok((value, headers))
    }

    // GitLab has no quota-free probe. Preserve only server-provided quota headers; a
    // 429 may also be an application-specific limit that has no RateLimit headers.
    fn observe_rate_limit(&self, headers: &HeaderMap, throttled: bool) {
        let header_number = |name: &str| headers.get(name)?.to_str().ok()?.parse::<u64>().ok();
        let reset_at = header_number("ratelimit-reset").or_else(|| {
            if !throttled {
                return None;
            }
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_secs()
                .checked_add(header_number("retry-after")?)
        });
        let remaining = if throttled {
            Some(0)
        } else {
            header_number("ratelimit-remaining")
        };
        let limit = header_number("ratelimit-limit");
        if reset_at.is_some() || remaining.is_some() || limit.is_some() {
            if let Ok(mut held) = self.rate_limit.write() {
                *held = RateLimitStatus {
                    reset_at,
                    remaining,
                    limit,
                };
            }
        }
    }

    /// Optional policy reads degrade only when unavailable, never on quota exhaustion.
    async fn optional_get(&self, path: &str) -> Result<Option<Value>> {
        match self.get(path).await {
            Ok(value) => Ok(Some(value)),
            Err(Error::Auth(_) | Error::NotFound(_) | Error::Unsupported(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn mr_checks(
        &self,
        repo: &RepoRef,
        head: &Value,
        policy: Option<&Value>,
    ) -> Result<Vec<RollupCheck>> {
        let required = policy.is_some_and(|p| p["only_allow_merge_if_pipeline_succeeds"] == true);
        let pipeline = &head["head_pipeline"];
        if pipeline.is_null() {
            // Missing / invisible CI cannot satisfy a mandatory pipeline. This also
            // prevents an empty check list from looking ready while CI is starting.
            return Ok(if required {
                vec![pipeline_check(pipeline, policy)]
            } else {
                vec![]
            });
        }
        let id = number(pipeline, "id")?;
        // Fork and merged-results pipelines can live in another project and use a
        // synthetic SHA. The MR's own association is stronger than a SHA search.
        let pipeline_project = pipeline["project_id"]
            .as_u64()
            .map_or_else(|| project(repo), |id| format!("projects/{id}"));
        let mut checks = vec![pipeline_check(pipeline, policy)];
        let jobs = self
            .all(&format!("{pipeline_project}/pipelines/{id}/jobs"), vec![])
            .await?;
        for job in jobs {
            checks.push(RollupCheck {
                name: string(&job, "name")?,
                kind: RollupCheckKind::CheckRun,
                state: job_state(&job)?,
                is_required: required && job["allow_failure"] == false,
                url: optional(&job, "web_url"),
                started_at: optional(&job, "started_at"),
            });
        }
        Ok(checks)
    }

    async fn requirements_for_head(
        &self,
        repo: &RepoRef,
        head: &Value,
        approvals: Option<&Value>,
        policy: Option<&Value>,
    ) -> Result<MergeRequirementSignals> {
        let mut rules = policy.map(project_rules);
        if let Some(rules) = &mut rules {
            // This is the effective MR count (including MR-specific overrides),
            // not a sum of overlapping project/code-owner rule counts.
            rules.required_approving_review_count = approvals
                .and_then(|a| a["approvals_required"].as_u64())
                .and_then(|count| u32::try_from(count).ok());
        }
        let checks = self.mr_checks(repo, head, policy).await?;
        Ok(MergeRequirementSignals {
            merge_state_status: optional(head, "detailed_merge_status"),
            review_decision: approvals.and_then(approval_decision),
            checks,
            checks_known: policy
                .is_some_and(|p| p["only_allow_merge_if_pipeline_succeeds"].is_boolean()),
            branch_rules: rules,
            ..MergeRequirementSignals::default()
        })
    }

    async fn get(&self, path: &str) -> Result<Value> {
        self.request(Method::GET, path, &[], None)
            .await
            .map(|(value, _)| value)
    }

    async fn write(&self, method: Method, path: &str, body: Value) -> Result<Value> {
        self.request(method, path, &[], Some(body))
            .await
            .map(|(value, _)| value)
    }

    async fn page(
        &self,
        path: &str,
        mut query: Vec<(String, String)>,
        page: PageParams,
    ) -> Result<Page<Value>> {
        let current = page
            .cursor
            .as_deref()
            .unwrap_or("1")
            .parse::<u32>()
            .ok()
            .filter(|page| (1..=MAX_PAGES).contains(page))
            .ok_or_else(|| Error::Config("invalid or excessive GitLab page cursor".into()))?;
        let limit = page.limit.clamp(1, 100);
        query.push(("page".into(), current.to_string()));
        query.push(("per_page".into(), limit.to_string()));
        let (value, headers) = self.request(Method::GET, path, &query, None).await?;
        let items = value
            .as_array()
            .ok_or_else(|| Error::Decode("GitLab list response is not an array".into()))?
            .clone();
        let next = if let Some(header) = headers.get("x-next-page") {
            let text = header
                .to_str()
                .map_err(|_| Error::Decode("invalid GitLab next-page header".into()))?;
            if text.is_empty() {
                None
            } else {
                Some(
                    text.parse::<u32>()
                        .map_err(|_| Error::Decode("invalid GitLab next-page header".into()))?,
                )
            }
        } else if let Some(link) = headers.get("link").and_then(|h| h.to_str().ok()) {
            let mut next = None;
            for entry in link
                .split(',')
                .filter(|entry| entry.contains("rel=\"next\"") || entry.contains("rel=next"))
            {
                let target = entry
                    .split('<')
                    .nth(1)
                    .and_then(|v| v.split('>').next())
                    .and_then(|target| Url::parse(target).ok())
                    .ok_or_else(|| Error::Decode("invalid GitLab pagination link".into()))?;
                if target.origin() != self.api.origin()
                    || !target.path().starts_with(self.api.path())
                {
                    return Err(Error::Api(
                        "GitLab pagination link escaped configured instance".into(),
                    ));
                }
                next = target
                    .query_pairs()
                    .find(|(key, _)| key == "page")
                    .and_then(|(_, value)| value.parse::<u32>().ok());
                if next.is_none() {
                    return Err(Error::Unsupported(
                        "GitLab keyset pagination on this endpoint".into(),
                    ));
                }
            }
            next
        } else if items.len() == usize::from(limit) {
            Some(current + 1)
        } else {
            None
        };
        if next.is_some_and(|next| next <= current || next > MAX_PAGES) {
            return Err(Error::Api(
                "GitLab pagination exceeded safety limit or did not advance".into(),
            ));
        }
        Ok(Page {
            items,
            next_cursor: next.map(|page| page.to_string()),
        })
    }

    async fn all(&self, path: &str, query: Vec<(String, String)>) -> Result<Vec<Value>> {
        let mut output = Vec::new();
        let mut page = PageParams::first(100);
        loop {
            let result = self.page(path, query.clone(), page).await?;
            output.extend(result.items);
            let Some(cursor) = result.next_cursor else {
                return Ok(output);
            };
            page = PageParams {
                limit: 100,
                cursor: Some(cursor),
            };
        }
    }

    async fn set_thread(&self, thread: &str, resolved: bool) -> Result<bool> {
        let (instance, project, iid, discussion): (String, String, u64, String) =
            decode_thread(thread)?;
        if instance != self.api.as_str() {
            return Err(Error::Config(
                "GitLab thread belongs to another instance".into(),
            ));
        }
        let path = format!(
            "projects/{}/merge_requests/{iid}/discussions/{}",
            encode(&project),
            encode(&discussion)
        );
        let response = self
            .write(Method::PUT, &path, json!({"resolved": resolved}))
            .await?;
        let notes = array(&response, "notes")?;
        let states: Vec<bool> = notes
            .iter()
            .filter(|note| note["resolvable"] == true)
            .filter_map(|note| note["resolved"].as_bool())
            .collect();
        if states.is_empty() {
            return Err(Error::Decode(
                "GitLab did not report discussion resolution".into(),
            ));
        }
        Ok(states.iter().all(|state| *state))
    }
}

fn encode(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .fold(String::new(), |mut out, byte| {
            use std::fmt::Write as _;
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                out.push(char::from(*byte));
            } else {
                let _ = write!(out, "%{byte:02X}");
            }
            out
        })
}
fn project(repo: &RepoRef) -> String {
    format!(
        "projects/{}",
        encode(&format!("{}/{}", repo.owner, repo.name))
    )
}
fn mr(repo: &RepoRef, number: u64) -> String {
    format!("{}/merge_requests/{number}", project(repo))
}
fn string(value: &Value, key: &str) -> Result<String> {
    value[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::Decode(format!("GitLab response missing {key}")))
}
fn optional(value: &Value, key: &str) -> Option<String> {
    value[key].as_str().map(str::to_owned)
}
fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .ok_or_else(|| Error::Decode(format!("GitLab response missing {key}")))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value[key]
        .as_array()
        .ok_or_else(|| Error::Decode(format!("GitLab response missing {key}")))
}
fn author(value: &Value) -> String {
    value["author"]["username"]
        .as_str()
        .unwrap_or("ghost")
        .into()
}
fn map_page<T>(page: Page<Value>, map: impl Fn(Value) -> Result<T>) -> Result<Page<T>> {
    Ok(Page {
        items: page.items.into_iter().map(map).collect::<Result<_>>()?,
        next_cursor: page.next_cursor,
    })
}
fn mergeable(status: &str) -> Option<bool> {
    match status {
        "mergeable" => Some(true),
        "checking" | "unchecked" | "preparing" | "approvals_syncing" | "" => None,
        _ => Some(false),
    }
}
fn normalized_merge_status(status: &str) -> String {
    match status {
        "mergeable" => "clean",
        "conflict" => "dirty",
        "need_rebase" => "behind",
        "checking" | "unchecked" | "preparing" | "approvals_syncing" => "unknown",
        "ci_still_running" | "ci_must_pass" => "unstable",
        _ => "blocked",
    }
    .into()
}

// Owned callback shared by direct responses and map_page.
#[expect(clippy::needless_pass_by_value)]
fn to_pr(value: Value) -> Result<PullRequest> {
    let status = optional(&value, "detailed_merge_status");
    let state = match value["state"].as_str() {
        Some("opened" | "locked") => PrState::Open,
        Some("merged") => PrState::Merged,
        Some("closed") => PrState::Closed,
        _ => return Err(Error::Decode("unknown GitLab merge request state".into())),
    };
    Ok(PullRequest {
        number: number(&value, "iid")?,
        url: string(&value, "web_url")?,
        title: string(&value, "title")?,
        body: optional(&value, "description"),
        state,
        draft: value["draft"].as_bool().unwrap_or(false),
        source_branch: string(&value, "source_branch")?,
        target_branch: string(&value, "target_branch")?,
        author: author(&value),
        mergeable: status.as_deref().and_then(mergeable),
        mergeable_state: status.as_deref().map(normalized_merge_status),
        head_sha: optional(&value, "sha"),
        created_at: string(&value, "created_at")?,
        updated_at: string(&value, "updated_at")?,
    })
}
// Owned callback shared by direct responses and map_page.
#[expect(clippy::needless_pass_by_value)]
fn to_repo(value: Value) -> Result<Repo> {
    let path = string(&value, "path_with_namespace")?;
    let (owner, name) = path
        .rsplit_once('/')
        .ok_or_else(|| Error::Decode("GitLab project has no namespace".into()))?;
    Ok(Repo {
        owner: owner.into(),
        name: name.into(),
        url: optional(&value, "web_url"),
        default_branch: optional(&value, "default_branch"),
        created_at: optional(&value, "created_at"),
        updated_at: optional(&value, "last_activity_at"),
    })
}
// Owned callback shared by direct responses and map_page.
#[expect(clippy::needless_pass_by_value)]
fn to_issue(value: Value) -> Result<Issue> {
    Ok(Issue {
        number: number(&value, "iid")?,
        title: string(&value, "title")?,
        body: optional(&value, "description"),
        state: match value["state"].as_str() {
            Some("opened") => "open".into(),
            Some("closed") => "closed".into(),
            _ => return Err(Error::Decode("unknown GitLab issue state".into())),
        },
        url: string(&value, "web_url")?,
        author: author(&value),
        created_at: string(&value, "created_at")?,
        updated_at: string(&value, "updated_at")?,
    })
}
fn to_comment(value: &Value) -> Result<Comment> {
    Ok(Comment {
        id: number(value, "id")?.to_string(),
        author: author(value),
        body: string(value, "body")?,
        path: optional(&value["position"], "new_path")
            .or_else(|| optional(&value["position"], "old_path")),
        line: value["position"]["new_line"]
            .as_u64()
            .or_else(|| value["position"]["old_line"].as_u64()),
        created_at: string(value, "created_at")?,
        url: optional(value, "url"),
    })
}
fn to_review_comment(value: &Value, reply_to: Option<u64>) -> Result<ReviewComment> {
    let comment = to_comment(value)?;
    Ok(ReviewComment {
        id: number(value, "id")?,
        body: comment.body,
        path: comment.path.unwrap_or_default(),
        line: comment.line,
        author: comment.author,
        created_at: comment.created_at,
        updated_at: string(value, "updated_at")?,
        in_reply_to_id: reply_to,
        url: comment.url.unwrap_or_default(),
    })
}
fn encode_thread(instance: &str, repo: &RepoRef, iid: u64, id: &str) -> String {
    format!(
        "gitlab:{}",
        URL_SAFE_NO_PAD.encode(
            json!([instance, format!("{}/{}", repo.owner, repo.name), iid, id]).to_string()
        )
    )
}
fn decode_thread(value: &str) -> Result<(String, String, u64, String)> {
    let bytes = value
        .strip_prefix("gitlab:")
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        .ok_or_else(|| Error::Config("invalid GitLab thread identifier".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| Error::Config("invalid GitLab thread identifier".into()))
}
fn state(value: &str) -> CheckState {
    match value {
        "success" => CheckState::Success,
        "failed" => CheckState::Failure,
        "canceled" => CheckState::Cancelled,
        "skipped" => CheckState::Neutral,
        _ => CheckState::Pending,
    }
}
fn job_state(job: &Value) -> Result<CheckState> {
    let status = string(job, "status")?;
    Ok(
        if job["allow_failure"] == true
            && matches!(status.as_str(), "failed" | "manual" | "canceled")
        {
            CheckState::Neutral
        } else {
            state(&status)
        },
    )
}

fn pipeline_check(pipeline: &Value, policy: Option<&Value>) -> RollupCheck {
    let required = policy.is_some_and(|p| p["only_allow_merge_if_pipeline_succeeds"] == true);
    let status = pipeline["status"].as_str().unwrap_or_default();
    let state = if status == "skipped" && required {
        if policy.is_some_and(|p| p["allow_merge_on_skipped_pipeline"] == true) {
            CheckState::Success
        } else {
            CheckState::Failure
        }
    } else {
        state(status)
    };
    RollupCheck {
        name: PIPELINE_CHECK.into(),
        kind: RollupCheckKind::CheckRun,
        state,
        is_required: required,
        url: optional(pipeline, "web_url"),
        started_at: optional(pipeline, "started_at").or_else(|| optional(pipeline, "created_at")),
    }
}

fn project_rules(policy: &Value) -> BranchRules {
    BranchRules {
        // Branch-only reads cannot know which code-owner/MR override rules apply.
        required_approving_review_count: None,
        required_conversation_resolution: policy
            ["only_allow_merge_if_all_discussions_are_resolved"]
            .as_bool(),
        required_status_checks: if policy["only_allow_merge_if_pipeline_succeeds"] == true {
            vec![PIPELINE_CHECK.into()]
        } else {
            vec![]
        },
    }
}

fn approval_decision(value: &Value) -> Option<ReviewDecision> {
    // `approved` is authoritative for effective rules in EE. CE has no required
    // rules and reports false until somebody voluntarily approves the MR.
    if value["approved"] == true {
        Some(ReviewDecision::Approved)
    } else if value["approvals_left"]
        .as_u64()
        .is_some_and(|left| left > 0)
        || value["approvals_required"]
            .as_u64()
            .is_some_and(|required| required > 0)
    {
        Some(ReviewDecision::ReviewRequired)
    } else {
        None
    }
}

fn approval_reviews(value: &Value) -> Result<Vec<Review>> {
    array(value, "approved_by")?
        .iter()
        .map(|entry| {
            Ok(Review {
                author: string(&entry["user"], "username")?,
                verdict: ReviewVerdict::Approve,
                body: None,
                submitted_at: optional(entry, "approved_at").unwrap_or_default(),
            })
        })
        .collect()
}

fn discussion_tally(discussions: &[Value]) -> Result<(ReviewThreadTally, i64)> {
    let mut tally = ReviewThreadTally::default();
    let mut conversation_count = 0;
    for discussion in discussions {
        let notes = array(discussion, "notes")?;
        let review_thread = notes.iter().any(|note| note["resolvable"] == true);
        let count = i64::try_from(notes.iter().filter(|note| note["system"] != true).count())
            .map_err(|_| Error::Decode("too many GitLab discussion notes".into()))?;
        if review_thread {
            tally.review_comment_count += count;
            if notes
                .iter()
                .any(|note| note["resolvable"] == true && note["resolved"] != true)
            {
                tally.unresolved += 1;
            }
        } else {
            conversation_count += count;
        }
    }
    Ok((tally, conversation_count))
}

// GitLab requires both positions for context lines, but only the changed side for additions/deletions.
fn diff_position(diff: &str, anchor: &CommentAnchor) -> Result<(Option<u64>, Option<u64>)> {
    let left = match anchor.side.as_deref() {
        Some("LEFT" | "left") => true,
        Some("RIGHT" | "right") | None => false,
        _ => return Err(Error::Config("comment side must be LEFT or RIGHT".into())),
    };
    let (mut old, mut new) = (0, 0);
    let mut in_hunk = false;
    for line in diff.lines() {
        if line.starts_with("@@ ") {
            let mut ranges = line.split_whitespace().skip(1);
            let parse = |range: Option<&str>| {
                range
                    .and_then(|range| range.get(1..))
                    .and_then(|range| range.split(',').next())
                    .and_then(|line| line.parse::<u64>().ok())
            };
            old = parse(ranges.next())
                .ok_or_else(|| Error::Decode("invalid GitLab diff hunk".into()))?;
            new = parse(ranges.next())
                .ok_or_else(|| Error::Decode("invalid GitLab diff hunk".into()))?;
            in_hunk = true;
            continue;
        }
        if !in_hunk {
            continue;
        }
        let (old_line, new_line) = match line.as_bytes().first() {
            Some(b'+') => (None, Some(new)),
            Some(b'-') => (Some(old), None),
            Some(b' ') => (Some(old), Some(new)),
            _ => continue,
        };
        if (if left { old_line } else { new_line }) == Some(anchor.line) {
            return Ok((old_line, new_line));
        }
        if old_line.is_some() {
            old += 1;
        }
        if new_line.is_some() {
            new += 1;
        }
    }
    Err(Error::Config(
        "comment line is not present on the requested side of the GitLab diff".into(),
    ))
}

fn draft_title(title: &str, draft: bool) -> String {
    let clean = ["Draft: ", "WIP: ", "[Draft] ", "(Draft) "]
        .iter()
        .find_map(|prefix| title.strip_prefix(prefix))
        .unwrap_or(title);
    if draft {
        format!("Draft: {clean}")
    } else {
        clean.into()
    }
}

#[async_trait]
impl SourceControl for GitLabSourceControl {
    fn provider_id(&self) -> &'static str {
        "gitlab"
    }
    fn capabilities(&self) -> ScCapabilities {
        ScCapabilities {
            draft_prs: true,
            squash_merge: true,
            rebase_merge: false,
            review_required_changes: false,
            check_runs: true,
            issues: true,
        }
    }
    async fn rate_limit_status(&self) -> Result<RateLimitStatus> {
        Ok(self
            .rate_limit
            .read()
            .map(|status| *status)
            .unwrap_or_default())
    }
    async fn check_auth(&self) -> Result<AuthStatus> {
        let user = self.get_user().await?;
        Ok(AuthStatus {
            authenticated: true,
            login: Some(user.login),
            scopes: vec![],
        })
    }
    async fn get_user(&self) -> Result<UserIdentity> {
        let value = self.get("user").await?;
        Ok(UserIdentity {
            login: string(&value, "username")?,
            id: value["id"].as_u64(),
            name: optional(&value, "name"),
            avatar_url: optional(&value, "avatar_url"),
            html_url: optional(&value, "web_url"),
        })
    }
    async fn list_repos(&self, page: PageParams) -> Result<Page<Repo>> {
        map_page(
            self.page(
                "projects",
                vec![
                    ("membership".into(), "true".into()),
                    ("order_by".into(), "last_activity_at".into()),
                    // The picker only needs project summaries, not per-project policy details.
                    ("simple".into(), "true".into()),
                ],
                page,
            )
            .await?,
            to_repo,
        )
    }
    async fn search_repos(&self, query: &str, page: PageParams) -> Result<Page<Repo>> {
        map_page(
            self.page(
                "projects",
                vec![
                    ("search".into(), query.into()),
                    ("search_namespaces".into(), "true".into()),
                    ("simple".into(), "true".into()),
                ],
                page,
            )
            .await?,
            to_repo,
        )
    }
    async fn get_repo(&self, owner: &str, name: &str) -> Result<Repo> {
        to_repo(self.get(&project(&RepoRef::new(owner, name))).await?)
    }
    async fn list_remote_branches(
        &self,
        owner: &str,
        name: &str,
        prefix: Option<&str>,
        page: PageParams,
    ) -> Result<Page<Branch>> {
        let query = prefix
            .filter(|v| !v.is_empty())
            .map(|v| vec![("search".into(), format!("^{v}"))])
            .unwrap_or_default();
        map_page(
            self.page(
                &format!(
                    "{}/repository/branches",
                    project(&RepoRef::new(owner, name))
                ),
                query,
                page,
            )
            .await?,
            |value| {
                Ok(Branch {
                    name: string(&value, "name")?,
                    commit_sha: optional(&value["commit"], "id"),
                    protected: value["protected"].as_bool().unwrap_or(false),
                })
            },
        )
    }
    async fn get_file_content(
        &self,
        repo: &RepoRef,
        path: &str,
        git_ref: Option<&str>,
    ) -> Result<Option<String>> {
        let response = self
            .request(
                Method::GET,
                &format!("{}/repository/files/{}", project(repo), encode(path)),
                &[("ref".into(), git_ref.unwrap_or("HEAD").into())],
                None,
            )
            .await;
        let value = match response {
            Ok((value, _)) => value,
            Err(Error::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        if value["encoding"] != "base64" {
            return Err(Error::Decode("unsupported GitLab file encoding".into()));
        }
        let encoded = string(&value, "content")?.replace(['\n', '\r'], "");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| Error::Decode("invalid GitLab file content".into()))?;
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| Error::Decode("GitLab file is not UTF-8".into()))
    }
    async fn create_pr(&self, repo: &RepoRef, input: NewPullRequest) -> Result<PullRequest> {
        to_pr(self.write(Method::POST, &format!("{}/merge_requests", project(repo)), json!({"title": draft_title(&input.title, input.draft), "description": input.body, "source_branch": input.source_branch, "target_branch": input.target_branch})).await?)
    }
    async fn get_pr(&self, repo: &RepoRef, number: u64) -> Result<PullRequest> {
        to_pr(self.get(&mr(repo, number)).await?)
    }
    async fn list_prs(&self, repo: &RepoRef, query: PrQuery) -> Result<Page<PullRequest>> {
        if !query.extra_repos.is_empty() {
            return Err(Error::Unsupported("GitLab multi-project MR search".into()));
        }
        let mut params = vec![("scope".into(), "all".into())];
        if let Some(state) = query.state {
            params.push((
                "state".into(),
                match state {
                    PrState::Open => "opened",
                    PrState::Closed => "closed",
                    PrState::Merged => "merged",
                }
                .into(),
            ));
        }
        for (key, value) in [
            ("source_branch", query.head),
            ("target_branch", query.base),
            ("author_username", query.author),
            ("search", query.search),
        ] {
            if let Some(value) = value {
                params.push((key.into(), value));
            }
        }
        if let Some(involvement) = query.involvement {
            let user = self.get_user().await?;
            let key = match involvement {
                PrInvolvement::Created => "author_username",
                PrInvolvement::Assigned => "assignee_username",
                PrInvolvement::ReviewRequested => "reviewer_username",
                PrInvolvement::Involves => {
                    return Err(Error::Unsupported("GitLab involves-me MR search".into()))
                }
            };
            params.push((key.into(), user.login));
        }
        map_page(
            self.page(
                &format!("{}/merge_requests", project(repo)),
                params,
                PageParams {
                    limit: query.limit.unwrap_or(30),
                    cursor: query.cursor,
                },
            )
            .await?,
            to_pr,
        )
    }
    async fn update_pr(&self, repo: &RepoRef, number: u64, patch: PrPatch) -> Result<PullRequest> {
        let mut body = json!({});
        if let Some(draft) = patch.draft {
            let title = match patch.title {
                Some(title) => title,
                None => self.get_pr(repo, number).await?.title,
            };
            body["title"] = json!(draft_title(&title, draft));
        } else if let Some(title) = patch.title {
            body["title"] = json!(title);
        }
        if let Some(description) = patch.body {
            body["description"] = json!(description);
        }
        if let Some(target) = patch.target_branch {
            body["target_branch"] = json!(target);
        }
        if let Some(state) = patch.state {
            body["state_event"] = json!(match state {
                PrState::Open => "reopen",
                PrState::Closed => "close",
                PrState::Merged =>
                    return Err(Error::Unsupported(
                        "use merge_pr to merge GitLab merge requests".into()
                    )),
            });
        }
        to_pr(self.write(Method::PUT, &mr(repo, number), body).await?)
    }
    async fn merge_pr(
        &self,
        repo: &RepoRef,
        number: u64,
        method: MergeMethod,
        options: MergeOptions,
    ) -> Result<MergeOutcome> {
        if method == MergeMethod::Rebase {
            return Err(Error::Unsupported(
                "GitLab merge strategy is a project setting; rebase merge is not supported".into(),
            ));
        }
        let head = self
            .get_pr(repo, number)
            .await?
            .head_sha
            .ok_or_else(|| Error::Conflict("GitLab MR head SHA is not ready".into()))?;
        let mut body = json!({"sha": head, "squash": method == MergeMethod::Squash});
        let message = [options.commit_title, options.commit_message]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n\n");
        if !message.is_empty() {
            body[if method == MergeMethod::Squash {
                "squash_commit_message"
            } else {
                "merge_commit_message"
            }] = json!(message);
        }
        let value = self
            .write(Method::PUT, &format!("{}/merge", mr(repo, number)), body)
            .await?;
        let merged = value["state"] == "merged";
        Ok(MergeOutcome {
            merged,
            message: if merged {
                "Merge request merged".into()
            } else {
                "GitLab has not completed the merge".into()
            },
            sha: optional(&value, "merge_commit_sha")
                .or_else(|| optional(&value, "squash_commit_sha")),
        })
    }
    async fn mergeability(&self, repo: &RepoRef, number: u64) -> Result<Mergeability> {
        let value = self.get(&mr(repo, number)).await?;
        let policy = self.optional_get(&project(repo)).await?;
        let checks_passed = match policy
            .as_ref()
            .and_then(|p| p["only_allow_merge_if_pipeline_succeeds"].as_bool())
        {
            Some(false) => true,
            Some(true) => {
                pipeline_check(&value["head_pipeline"], policy.as_ref()).state
                    == CheckState::Success
            }
            None => value["detailed_merge_status"] == "mergeable",
        };
        Ok(Mergeability {
            mergeable: value["detailed_merge_status"].as_str().and_then(mergeable),
            conflicts: value["has_conflicts"] == true,
            required_checks_passed: checks_passed,
        })
    }
    async fn update_branch(&self, _repo: &RepoRef, _number: u64) -> Result<()> {
        Err(Error::Unsupported("GitLab branch update cannot faithfully emulate a base-branch merge; rebase explicitly in Git".into()))
    }
    async fn submit_review(
        &self,
        repo: &RepoRef,
        number: u64,
        verdict: ReviewVerdict,
        body: Option<String>,
    ) -> Result<Review> {
        match verdict {
            ReviewVerdict::RequestChanges => Err(Error::Unsupported(
                "GitLab request-changes reviews are not supported by this adapter".into(),
            )),
            ReviewVerdict::Comment => {
                let body =
                    body.ok_or_else(|| Error::Config("a comment review needs text".into()))?;
                let note = self.add_comment(repo, number, &body, None).await?;
                Ok(Review {
                    author: note.author,
                    verdict,
                    body: Some(note.body),
                    submitted_at: note.created_at,
                })
            }
            ReviewVerdict::Approve => {
                if body.as_deref().is_some_and(|text| !text.is_empty()) {
                    return Err(Error::Unsupported(
                        "GitLab approval with a body is not atomic; post the comment separately"
                            .into(),
                    ));
                }
                let head = self
                    .get_pr(repo, number)
                    .await?
                    .head_sha
                    .ok_or_else(|| Error::Conflict("GitLab MR head SHA is not ready".into()))?;
                let user = self.get_user().await?;
                let value = self
                    .write(
                        Method::POST,
                        &format!("{}/approve", mr(repo, number)),
                        json!({"sha": head}),
                    )
                    .await?;
                let approval = array(&value, "approved_by")?
                    .iter()
                    .find(|entry| entry["user"]["username"] == user.login)
                    .ok_or_else(|| Error::Decode("GitLab did not confirm the approval".into()))?;
                Ok(Review {
                    author: user.login,
                    verdict,
                    body: None,
                    submitted_at: optional(approval, "approved_at").unwrap_or_default(),
                })
            }
        }
    }
    async fn list_reviews(&self, repo: &RepoRef, number: u64) -> Result<Vec<Review>> {
        approval_reviews(&self.get(&format!("{}/approvals", mr(repo, number))).await?)
    }
    async fn review_decision(&self, repo: &RepoRef, number: u64) -> Result<Option<ReviewDecision>> {
        Ok(approval_decision(
            &self.get(&format!("{}/approvals", mr(repo, number))).await?,
        ))
    }
    async fn branch_rules(&self, repo: &RepoRef, _branch: &str) -> Result<BranchRules> {
        Ok(project_rules(&self.get(&project(repo)).await?))
    }
    async fn merge_requirements(
        &self,
        repo: &RepoRef,
        number: u64,
    ) -> Result<MergeRequirementSignals> {
        let head = self.get(&mr(repo, number)).await?;
        let policy = self.optional_get(&project(repo)).await?;
        let approvals = self
            .optional_get(&format!("{}/approvals", mr(repo, number)))
            .await?;
        self.requirements_for_head(repo, &head, approvals.as_ref(), policy.as_ref())
            .await
    }
    async fn pr_observation(&self, repo: &RepoRef, number: u64) -> Result<Option<PrObservation>> {
        // REST cannot fold these into one round trip. Each resource is read once:
        // the MR supplies its pipeline, approvals supply both verdict and reviews,
        // and paged discussions supply both comment counts and thread resolution.
        let head = self.get(&mr(repo, number)).await?;
        let policy = self.optional_get(&project(repo)).await?;
        let approvals = self
            .optional_get(&format!("{}/approvals", mr(repo, number)))
            .await?;
        let signals = self
            .requirements_for_head(repo, &head, approvals.as_ref(), policy.as_ref())
            .await?;
        let discussions = self
            .all(&format!("{}/discussions", mr(repo, number)), vec![])
            .await?;
        let (threads, conversation_count) = discussion_tally(&discussions)?;
        Ok(Some(PrObservation {
            pr: to_pr(head)?,
            signals,
            reviews: approvals.as_ref().map(approval_reviews).transpose()?,
            threads: Some(threads),
            conversation_count,
        }))
    }
    async fn list_comments(&self, repo: &RepoRef, number: u64) -> Result<Vec<Comment>> {
        self.all(&format!("{}/notes", mr(repo, number)), vec![])
            .await?
            .iter()
            .filter(|note| note["system"] != true && note["type"] != "DiffNote")
            .map(to_comment)
            .collect()
    }
    async fn add_comment(
        &self,
        repo: &RepoRef,
        number: u64,
        body: &str,
        anchor: Option<CommentAnchor>,
    ) -> Result<Comment> {
        if let Some(anchor) = anchor {
            let head = self.get(&mr(repo, number)).await?;
            let diffs = self
                .all(&format!("{}/diffs", mr(repo, number)), vec![])
                .await?;
            let file = diffs
                .iter()
                .find(|file| file["new_path"] == anchor.path || file["old_path"] == anchor.path)
                .ok_or_else(|| Error::NotFound("comment path is not in the GitLab diff".into()))?;
            if file["too_large"] == true || file["collapsed"] == true {
                return Err(Error::Unsupported(
                    "GitLab diff is incomplete; cannot safely anchor comment".into(),
                ));
            }
            let mut position = json!({"position_type": "text", "base_sha": string(&head["diff_refs"], "base_sha")?, "start_sha": string(&head["diff_refs"], "start_sha")?, "head_sha": string(&head["diff_refs"], "head_sha")?, "old_path": string(file, "old_path")?, "new_path": string(file, "new_path")?});
            let (old_line, new_line) = diff_position(&string(file, "diff")?, &anchor)?;
            if let Some(line) = old_line {
                position["old_line"] = json!(line);
            }
            if let Some(line) = new_line {
                position["new_line"] = json!(line);
            }
            let current = self.get_pr(repo, number).await?;
            if current.head_sha.as_deref() != head["diff_refs"]["head_sha"].as_str() {
                return Err(Error::Conflict(
                    "GitLab diff changed while preparing the comment; refresh the diff".into(),
                ));
            }
            let value = self
                .write(
                    Method::POST,
                    &format!("{}/discussions", mr(repo, number)),
                    json!({"body": body, "position": position}),
                )
                .await?;
            return to_comment(
                array(&value, "notes")?
                    .first()
                    .ok_or_else(|| Error::Decode("GitLab returned empty discussion".into()))?,
            );
        }
        to_comment(
            &self
                .write(
                    Method::POST,
                    &format!("{}/notes", mr(repo, number)),
                    json!({"body": body}),
                )
                .await?,
        )
    }
    async fn list_review_comments(
        &self,
        repo: &RepoRef,
        number: u64,
        page: PageParams,
    ) -> Result<Page<ReviewComment>> {
        let page = self
            .page(&format!("{}/discussions", mr(repo, number)), vec![], page)
            .await?;
        let mut items = Vec::new();
        for thread in page.items {
            let notes = array(&thread, "notes")?;
            if notes.first().is_some_and(|note| note["type"] == "DiffNote") {
                let first = notes.first().and_then(|note| note["id"].as_u64());
                for (index, note) in notes.iter().enumerate() {
                    items.push(to_review_comment(
                        note,
                        if index == 0 { None } else { first },
                    )?);
                }
            }
        }
        Ok(Page {
            items,
            next_cursor: page.next_cursor,
        })
    }
    async fn reply_to_review_comment(
        &self,
        repo: &RepoRef,
        number: u64,
        comment_id: u64,
        body: &str,
    ) -> Result<ReviewComment> {
        let discussions = self
            .all(&format!("{}/discussions", mr(repo, number)), vec![])
            .await?;
        let discussion = discussions
            .iter()
            .find(|thread| {
                thread["notes"].as_array().is_some_and(|notes| {
                    notes
                        .iter()
                        .any(|note| note["id"].as_u64() == Some(comment_id))
                })
            })
            .ok_or_else(|| Error::NotFound("GitLab discussion for comment not found".into()))?;
        let value = self
            .write(
                Method::POST,
                &format!(
                    "{}/discussions/{}/notes",
                    mr(repo, number),
                    encode(&string(discussion, "id")?)
                ),
                json!({"body": body}),
            )
            .await?;
        to_review_comment(&value, Some(comment_id))
    }
    async fn get_review_threads(
        &self,
        repo: &RepoRef,
        number: u64,
        page: PageParams,
    ) -> Result<Page<ReviewThread>> {
        let page = self
            .page(&format!("{}/discussions", mr(repo, number)), vec![], page)
            .await?;
        let mut items = Vec::new();
        for thread in page.items {
            let notes = array(&thread, "notes")?;
            if !notes.iter().any(|note| note["resolvable"] == true) {
                continue;
            }
            let root = notes
                .first()
                .ok_or_else(|| Error::Decode("GitLab returned an empty discussion".into()))?;
            let root_comment = to_comment(root)?;
            let comments = notes
                .iter()
                .filter(|note| note["system"] != true)
                .map(|note| {
                    let comment = to_comment(note)?;
                    Ok(ReviewThreadComment {
                        id: comment.id,
                        body: comment.body,
                        author: comment.author,
                        path: comment
                            .path
                            .or_else(|| root_comment.path.clone())
                            .unwrap_or_default(),
                        line: comment.line.or(root_comment.line),
                        created_at: comment.created_at,
                    })
                })
                .collect::<Result<_>>()?;
            items.push(ReviewThread {
                id: encode_thread(self.api.as_str(), repo, number, &string(&thread, "id")?),
                is_resolved: notes
                    .iter()
                    .filter(|note| note["resolvable"] == true)
                    .all(|note| note["resolved"] == true),
                comments,
            });
        }
        Ok(Page {
            items,
            next_cursor: page.next_cursor,
        })
    }
    async fn resolve_thread(&self, thread_id: &str) -> Result<bool> {
        self.set_thread(thread_id, true).await
    }
    async fn unresolve_thread(&self, thread_id: &str) -> Result<bool> {
        self.set_thread(thread_id, false).await
    }
    async fn check_runs(&self, repo: &RepoRef, git_ref: &str) -> Result<Vec<CheckRun>> {
        let commit = self
            .get(&format!(
                "{}/repository/commits/{}",
                project(repo),
                encode(git_ref)
            ))
            .await?;
        let sha = string(&commit, "id")?;
        let statuses = self
            .all(
                &format!(
                    "{}/repository/commits/{}/statuses",
                    project(repo),
                    encode(&sha)
                ),
                vec![],
            )
            .await?;
        let mut checks = statuses
            .iter()
            .map(|value| {
                Ok(CheckRun {
                    name: string(value, "name")?,
                    state: state(&string(value, "status")?),
                    url: optional(value, "target_url"),
                    started_at: optional(value, "started_at"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let pipelines = self
            .page(
                &format!("{}/pipelines", project(repo)),
                vec![
                    ("sha".into(), sha),
                    ("order_by".into(), "id".into()),
                    ("sort".into(), "desc".into()),
                ],
                PageParams::first(1),
            )
            .await?;
        if let Some(pipeline) = pipelines.items.first() {
            let id = number(pipeline, "id")?;
            checks.push(CheckRun {
                name: "GitLab pipeline".into(),
                state: state(&string(pipeline, "status")?),
                url: optional(pipeline, "web_url"),
                started_at: optional(pipeline, "created_at"),
            });
            let jobs = self
                .all(&format!("{}/pipelines/{id}/jobs", project(repo)), vec![])
                .await?;
            for job in jobs {
                checks.push(CheckRun {
                    name: string(&job, "name")?,
                    state: job_state(&job)?,
                    url: optional(&job, "web_url"),
                    started_at: optional(&job, "started_at"),
                });
            }
        }
        Ok(checks)
    }
    async fn create_issue(&self, repo: &RepoRef, title: &str, body: Option<&str>) -> Result<Issue> {
        to_issue(
            self.write(
                Method::POST,
                &format!("{}/issues", project(repo)),
                json!({"title": title, "description": body}),
            )
            .await?,
        )
    }
    async fn get_issue(&self, repo: &RepoRef, number: u64) -> Result<Issue> {
        to_issue(
            self.get(&format!("{}/issues/{number}", project(repo)))
                .await?,
        )
    }
    async fn list_issues(&self, repo: &RepoRef, query: IssueQuery) -> Result<Page<Issue>> {
        if !query.extra_repos.is_empty() {
            return Err(Error::Unsupported(
                "GitLab multi-project issue search".into(),
            ));
        }
        let mut params = vec![("scope".into(), "all".into())];
        if let Some(state) = query.state {
            params.push((
                "state".into(),
                if state == "open" {
                    "opened".into()
                } else {
                    state
                },
            ));
        }
        if let Some(labels) = query.labels {
            params.push(("labels".into(), labels));
        }
        if let Some(search) = query.search {
            params.push(("search".into(), search));
        }
        map_page(
            self.page(
                &format!("{}/issues", project(repo)),
                params,
                PageParams {
                    limit: query.limit.unwrap_or(30),
                    cursor: query.cursor,
                },
            )
            .await?,
            to_issue,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{diff_position, CommentAnchor};

    #[test]
    fn maps_added_removed_and_context_lines() {
        let diff = "@@ -5,3 +5,3 @@\n context\n-removed\n+added\n same\n";
        let anchor = |line, side: &str| CommentAnchor {
            path: "file".into(),
            line,
            side: Some(side.into()),
        };
        assert_eq!(
            diff_position(diff, &anchor(5, "RIGHT")).unwrap(),
            (Some(5), Some(5))
        );
        assert_eq!(
            diff_position(diff, &anchor(6, "LEFT")).unwrap(),
            (Some(6), None)
        );
        assert_eq!(
            diff_position(diff, &anchor(6, "RIGHT")).unwrap(),
            (None, Some(6))
        );
        assert!(diff_position(diff, &anchor(99, "RIGHT")).is_err());
    }
}
