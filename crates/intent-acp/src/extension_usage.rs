//! Out-of-band usage reports from a bundled provider-side extension
//! (intent-hq/intent#3802).
//!
//! `pi-acp` never populates `PromptResponse.usage` and never emits
//! `usage_update`, so a pi session's tokens and cost read as zero on the ACP
//! wire. The bundled pi extension (`intent-services/src/pi_mcp_extension.ts`)
//! sees every finished assistant message's `usage` and forwards it over the
//! per-agent MCP bridge as the [`EXTENSION_USAGE_NOTIFICATION`] JSON-RPC
//! notification. [`ExtensionUsageRegistry`] buckets those per-LLM-call
//! reports by agent; the turn-end accounting seam drains the bucket as the
//! turn's per-turn report (`PerTurn` SUM semantics — a report that lands
//! after the drain is simply folded into the next turn, never lost or
//! double-counted).

use std::collections::HashMap;
use std::sync::Mutex;

use intent_core::{AgentId, UsageCost};
use serde::Deserialize;
use serde_json::Value;

use crate::session::Usage;

/// Method name of the MCP notification the bundled extension sends. `params`
/// carries `usage` in ACP `Usage` camelCase wire shape (`inputTokens`,
/// `outputTokens`, `totalTokens`, optional `cachedReadTokens` /
/// `cachedWriteTokens` / `thoughtTokens`) plus an optional
/// `cost: { amount, currency }`.
pub const EXTENSION_USAGE_NOTIFICATION: &str = "notifications/intentd/usage";

#[derive(Deserialize)]
struct ExtensionUsageParams {
    usage: Usage,
    #[serde(default)]
    cost: Option<UsageCost>,
}

/// Summed per-LLM-call counters awaiting the turn-end drain.
#[derive(Debug, Default, Clone, PartialEq)]
struct Pending {
    total_tokens: u64,
    input_tokens: u64,
    output_tokens: u64,
    thought_tokens: u64,
    cached_read_tokens: u64,
    cached_write_tokens: u64,
    cost: Option<UsageCost>,
}

impl Pending {
    fn add(&mut self, usage: &Usage, cost: Option<&UsageCost>) {
        self.total_tokens = self.total_tokens.saturating_add(usage.total_tokens);
        self.input_tokens = self.input_tokens.saturating_add(usage.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(usage.output_tokens);
        self.thought_tokens = self
            .thought_tokens
            .saturating_add(usage.thought_tokens.unwrap_or(0));
        self.cached_read_tokens = self
            .cached_read_tokens
            .saturating_add(usage.cached_read_tokens.unwrap_or(0));
        self.cached_write_tokens = self
            .cached_write_tokens
            .saturating_add(usage.cached_write_tokens.unwrap_or(0));
        if cost.is_some() {
            self.cost = UsageCost::merge(self.cost.as_ref(), cost);
        }
    }

    fn is_empty(&self) -> bool {
        self.total_tokens == 0
            && self.input_tokens == 0
            && self.output_tokens == 0
            && self.thought_tokens == 0
            && self.cached_read_tokens == 0
            && self.cached_write_tokens == 0
            && self.cost.is_none()
    }

    fn into_report(self) -> (Usage, Option<UsageCost>) {
        let usage = Usage::new(self.total_tokens, self.input_tokens, self.output_tokens)
            .thought_tokens(self.thought_tokens)
            .cached_read_tokens(self.cached_read_tokens)
            .cached_write_tokens(self.cached_write_tokens);
        (usage, self.cost)
    }
}

/// Per-agent buckets of extension-reported usage. Shared (behind an `Arc`)
/// between each agent's `WorkspaceMcpServer` (record side) and the
/// turn-end accounting seam in `intent-services` (drain side).
#[derive(Default)]
pub struct ExtensionUsageRegistry {
    inner: Mutex<HashMap<AgentId, Pending>>,
}

impl ExtensionUsageRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one per-LLM-call report into `agent_id`'s pending bucket.
    pub fn record(&self, agent_id: &AgentId, usage: &Usage, cost: Option<&UsageCost>) {
        if let Ok(mut map) = self.inner.lock() {
            map.entry(agent_id.clone()).or_default().add(usage, cost);
        }
    }

    /// Parse the [`EXTENSION_USAGE_NOTIFICATION`] `params` and record them.
    /// Returns `false` (recording nothing) when the payload does not parse.
    pub fn record_notification(&self, agent_id: &AgentId, params: Option<&Value>) -> bool {
        let Some(params) = params else { return false };
        match serde_json::from_value::<ExtensionUsageParams>(params.clone()) {
            Ok(report) => {
                self.record(agent_id, &report.usage, report.cost.as_ref());
                true
            }
            Err(_) => false,
        }
    }

    /// Drain `agent_id`'s bucket as one per-turn report. `None` when nothing
    /// (or only zeroes without a cost) was reported since the last drain.
    pub fn take(&self, agent_id: &AgentId) -> Option<(Usage, Option<UsageCost>)> {
        let pending = self.inner.lock().ok()?.remove(agent_id)?;
        (!pending.is_empty()).then(|| pending.into_report())
    }

    /// Whether `agent_id` has an undrained bucket (test/diagnostic aid).
    #[must_use]
    pub fn has_pending(&self, agent_id: &AgentId) -> bool {
        self.inner
            .lock()
            .ok()
            .is_some_and(|map| map.get(agent_id).is_some_and(|p| !p.is_empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn agent(s: &str) -> AgentId {
        AgentId::from_string(s)
    }

    fn usd(amount: f64) -> UsageCost {
        UsageCost {
            amount,
            currency: "USD".to_string(),
        }
    }

    #[test]
    fn take_on_empty_registry_is_none() {
        let reg = ExtensionUsageRegistry::new();
        assert!(reg.take(&agent("a")).is_none());
        assert!(!reg.has_pending(&agent("a")));
    }

    #[test]
    fn record_notification_sums_per_call_reports_and_take_drains() {
        let reg = ExtensionUsageRegistry::new();
        let a = agent("a");
        assert!(reg.record_notification(
            &a,
            Some(&json!({
                "usage": {
                    "totalTokens": 1500, "inputTokens": 1000, "outputTokens": 200,
                    "thoughtTokens": 100, "cachedReadTokens": 200, "cachedWriteTokens": 0
                },
                "cost": { "amount": 0.01, "currency": "USD" }
            }))
        ));
        assert!(reg.record_notification(
            &a,
            Some(&json!({
                "usage": { "totalTokens": 700, "inputTokens": 500, "outputTokens": 100, "cachedReadTokens": 100 },
                "cost": { "amount": 0.005, "currency": "USD" }
            }))
        ));
        assert!(reg.has_pending(&a));

        let (usage, cost) = reg.take(&a).expect("drained report");
        assert_eq!(usage.total_tokens, 2200);
        assert_eq!(usage.input_tokens, 1500);
        assert_eq!(usage.output_tokens, 300);
        assert_eq!(usage.thought_tokens, Some(100));
        assert_eq!(usage.cached_read_tokens, Some(300));
        assert_eq!(usage.cached_write_tokens, Some(0));
        let cost = cost.expect("summed cost");
        assert_eq!(cost.currency, "USD");
        assert!((cost.amount - 0.015).abs() < 1e-12, "{}", cost.amount);

        // Drained: a second take is empty, and the bucket is gone.
        assert!(reg.take(&a).is_none());
        assert!(!reg.has_pending(&a));
    }

    #[test]
    fn buckets_are_per_agent() {
        let reg = ExtensionUsageRegistry::new();
        reg.record(&agent("a"), &Usage::new(10, 6, 4), None);
        reg.record(&agent("b"), &Usage::new(20, 12, 8), Some(&usd(0.5)));
        let (a_usage, a_cost) = reg.take(&agent("a")).expect("a");
        assert_eq!(a_usage.total_tokens, 10);
        assert!(a_cost.is_none());
        let (b_usage, b_cost) = reg.take(&agent("b")).expect("b");
        assert_eq!(b_usage.total_tokens, 20);
        assert_eq!(b_cost, Some(usd(0.5)));
    }

    #[test]
    fn cost_only_report_is_kept() {
        let reg = ExtensionUsageRegistry::new();
        reg.record(&agent("a"), &Usage::new(0, 0, 0), Some(&usd(0.002)));
        let (usage, cost) = reg.take(&agent("a")).expect("cost-only report");
        assert_eq!(usage.total_tokens, 0);
        assert_eq!(cost, Some(usd(0.002)));
    }

    #[test]
    fn all_zero_report_without_cost_drains_as_none() {
        let reg = ExtensionUsageRegistry::new();
        reg.record(&agent("a"), &Usage::new(0, 0, 0), None);
        assert!(!reg.has_pending(&agent("a")));
        assert!(reg.take(&agent("a")).is_none());
    }

    #[test]
    fn malformed_notification_records_nothing() {
        let reg = ExtensionUsageRegistry::new();
        let a = agent("a");
        assert!(!reg.record_notification(&a, None));
        assert!(!reg.record_notification(&a, Some(&json!({}))));
        assert!(!reg.record_notification(&a, Some(&json!({ "usage": "nope" }))));
        assert!(!reg.record_notification(
            &a,
            Some(&json!({ "usage": { "inputTokens": 1, "outputTokens": 1 } }))
        ));
        assert!(!reg.has_pending(&a));
        assert!(reg.take(&a).is_none());
    }

    #[test]
    fn cost_is_optional_on_the_wire() {
        let reg = ExtensionUsageRegistry::new();
        let a = agent("a");
        assert!(reg.record_notification(
            &a,
            Some(&json!({ "usage": { "totalTokens": 3, "inputTokens": 2, "outputTokens": 1 } }))
        ));
        let (usage, cost) = reg.take(&a).expect("tokens-only report");
        assert_eq!(usage.total_tokens, 3);
        assert!(cost.is_none());
    }
}
