//! Jev advisory model routing (3D).
//!
//! Jev classifies the task and *recommends* a model. The host then rechecks
//! the recommendation against policy, the lease's model/provider classes,
//! and budget headroom before asking Pi to switch. Jev grants nothing: the
//! recommendation is inert data, and the switch decision is made -- and
//! recorded -- host-side. In particular Jev cannot grant tools, secrets,
//! network access, or additional spend.

use std::{collections::VecDeque, future::Future, pin::Pin, sync::Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    kernel_client::now_ms,
    model_gateway::{ModelPolicy, SpendPool},
};

/// The task profile handed to Jev. Deliberately coarse: Jev classifies the
/// task, it does not need raw user content or session history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskProfile {
    /// Host-assigned task class (e.g. "codegen", "summarize", "plan").
    pub task_class: String,
    /// Rough size bucket for the expected work.
    pub size_bucket: SizeBucket,
    /// Whether interactive latency matters more than thoroughness.
    pub latency_sensitive: bool,
    /// Session-local counter so recommendations stay ordered.
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeBucket {
    Tiny,
    Small,
    Medium,
    Large,
}

/// A Jev model recommendation. Advisory only: carries no authority, no
/// lease, no budget. Expires quickly so a stale recommendation cannot be
/// replayed into a later decision; the host additionally bounds the TTL
/// ([`MAX_RECOMMENDATION_TTL_MS`]) and requires `sequence` to match the
/// task profile it answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JevRecommendation {
    pub model: String,
    pub provider: String,
    pub reason: String,
    /// Unix millis after which the host must not act on this recommendation.
    pub expires_at_ms: i64,
    pub sequence: u64,
}

/// Maximum recommendation TTL the host will honor (5 minutes). A
/// recommendation that lives longer widens the replay window for a stale
/// model switch, so the host rejects it outright.
pub const MAX_RECOMMENDATION_TTL_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Error)]
pub enum JevError {
    #[error("jev unavailable: {0}")]
    Unavailable(String),
    #[error("jev returned an unusable recommendation: {0}")]
    BadRecommendation(String),
}

/// Boxed future for [`JevRouter`] (object-safe seam).
pub type JevFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, JevError>> + Send + 'a>>;

/// Jev router seam. The real implementation classifies the task profile;
/// the mock returns scripted recommendations for tests.
pub trait JevRouter: Send + Sync {
    fn recommend<'a>(&'a self, profile: &'a TaskProfile) -> JevFuture<'a, JevRecommendation>;
}

/// Outcome of the host's recheck of a Jev recommendation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelSwitchDecision {
    /// The host will ask Pi to switch models.
    Switch { model: String, provider: String },
    /// The host keeps the current model; the recommendation is recorded
    /// with the reason it was not followed.
    Keep { reason: String },
}

/// Host-side application of a Jev recommendation.
///
/// Checks, in order: recommendation freshness, TTL bound, sequence
/// ordering against the task profile the host sent, current-model churn,
/// lease policy (model/provider classes), and budget headroom for one
/// request ceiling. Every rejection names its reason.
pub fn apply_recommendation(
    recommendation: &JevRecommendation,
    current_model: &str,
    policy: &ModelPolicy,
    pool: &dyn SpendPool,
    expected_sequence: u64,
    now_ms: i64,
) -> ModelSwitchDecision {
    if recommendation.expires_at_ms <= now_ms {
        return ModelSwitchDecision::Keep {
            reason: "jev recommendation expired".to_string(),
        };
    }
    if recommendation.expires_at_ms - now_ms > MAX_RECOMMENDATION_TTL_MS {
        return ModelSwitchDecision::Keep {
            reason: "jev recommendation TTL exceeds maximum".to_string(),
        };
    }
    if recommendation.sequence != expected_sequence {
        return ModelSwitchDecision::Keep {
            reason: "jev recommendation sequence mismatch (stale or replayed)".to_string(),
        };
    }
    if recommendation.model.trim().is_empty() || recommendation.provider.trim().is_empty() {
        return ModelSwitchDecision::Keep {
            reason: "jev recommendation missing model or provider".to_string(),
        };
    }
    if recommendation.model == current_model {
        return ModelSwitchDecision::Keep {
            reason: "already on recommended model".to_string(),
        };
    }
    if !policy.permits(&recommendation.provider, &recommendation.model) {
        return ModelSwitchDecision::Keep {
            reason: format!(
                "recommended model {} on {} not permitted by lease policy",
                recommendation.model, recommendation.provider
            ),
        };
    }
    if !pool.try_reserve(policy.max_cost_micros_per_request) {
        return ModelSwitchDecision::Keep {
            reason: "insufficient budget headroom for model switch".to_string(),
        };
    }
    pool.release(policy.max_cost_micros_per_request);
    ModelSwitchDecision::Switch {
        model: recommendation.model.clone(),
        provider: recommendation.provider.clone(),
    }
}

/// Scripted Jev router for tests.
#[derive(Debug, Default)]
pub struct MockJevRouter {
    script: Mutex<VecDeque<Result<JevRecommendation, JevError>>>,
}

impl MockJevRouter {
    pub fn new(script: Vec<Result<JevRecommendation, JevError>>) -> Self {
        Self {
            script: Mutex::new(script.into_iter().collect()),
        }
    }

    pub fn recommend_model(
        model: impl Into<String>,
        provider: impl Into<String>,
        ttl_ms: i64,
        sequence: u64,
    ) -> JevRecommendation {
        JevRecommendation {
            model: model.into(),
            provider: provider.into(),
            reason: "mock classification".to_string(),
            expires_at_ms: now_ms() + ttl_ms,
            sequence,
        }
    }
}

impl JevRouter for MockJevRouter {
    fn recommend<'a>(&'a self, profile: &'a TaskProfile) -> JevFuture<'a, JevRecommendation> {
        Box::pin(async move {
            self.script.lock().unwrap().pop_front().unwrap_or_else(|| {
                Ok(JevRecommendation {
                    model: "mock-model".to_string(),
                    provider: "mock-provider".to_string(),
                    reason: "default mock recommendation".to_string(),
                    expires_at_ms: now_ms() + 60_000,
                    sequence: profile.sequence,
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_gateway::MemorySpendPool;

    fn policy() -> ModelPolicy {
        ModelPolicy {
            allowed_models: vec!["acme-large".to_string()],
            allowed_providers: vec!["acme".to_string()],
            max_cost_micros_per_request: 1000,
            max_output_tokens: 1000,
        }
    }

    fn profile() -> TaskProfile {
        TaskProfile {
            task_class: "codegen".to_string(),
            size_bucket: SizeBucket::Medium,
            latency_sensitive: false,
            sequence: 1,
        }
    }

    #[tokio::test]
    async fn jev_recommendation_flows_to_host_decision() {
        let router = MockJevRouter::new(vec![Ok(MockJevRouter::recommend_model(
            "acme-large",
            "acme",
            60_000,
            1,
        ))]);
        let pool = MemorySpendPool::new(1_000_000);
        let rec = router.recommend(&profile()).await.unwrap();
        let decision = apply_recommendation(
            &rec,
            "acme-small",
            &policy(),
            &pool,
            profile().sequence,
            now_ms(),
        );
        assert!(matches!(
            decision,
            ModelSwitchDecision::Switch { model, .. } if model == "acme-large"
        ));
    }

    #[test]
    fn host_rejects_recommendation_outside_policy() {
        let pool = MemorySpendPool::new(1_000_000);
        let rec = MockJevRouter::recommend_model("evil-model", "evil-provider", 60_000, 1);
        let decision = apply_recommendation(&rec, "acme-large", &policy(), &pool, 1, now_ms());
        assert!(matches!(
            decision,
            ModelSwitchDecision::Keep { reason } if reason.contains("not permitted")
        ));
    }

    #[test]
    fn host_rejects_expired_recommendation() {
        let pool = MemorySpendPool::new(1_000_000);
        let mut rec = MockJevRouter::recommend_model("acme-large", "acme", 60_000, 1);
        rec.expires_at_ms = now_ms() - 1;
        let decision = apply_recommendation(&rec, "acme-small", &policy(), &pool, 1, now_ms());
        assert!(matches!(
            decision,
            ModelSwitchDecision::Keep { reason } if reason.contains("expired")
        ));
    }

    #[test]
    fn host_rejects_switch_without_budget_headroom() {
        let pool = MemorySpendPool::new(10); // less than the 1000 ceiling
        let rec = MockJevRouter::recommend_model("acme-large", "acme", 60_000, 1);
        let decision = apply_recommendation(&rec, "acme-small", &policy(), &pool, 1, now_ms());
        assert!(matches!(
            decision,
            ModelSwitchDecision::Keep { reason } if reason.contains("budget")
        ));
    }

    #[test]
    fn host_rejects_recommendation_with_excessive_ttl() {
        let pool = MemorySpendPool::new(1_000_000);
        // Well beyond the host's TTL bound (with margin so the check
        // cannot flake on clock skew between the two now_ms() calls).
        let rec = MockJevRouter::recommend_model(
            "acme-large",
            "acme",
            MAX_RECOMMENDATION_TTL_MS + 60_000,
            1,
        );
        let decision = apply_recommendation(&rec, "acme-small", &policy(), &pool, 1, now_ms());
        assert!(matches!(
            decision,
            ModelSwitchDecision::Keep { reason } if reason.contains("TTL exceeds maximum")
        ));
    }

    #[test]
    fn host_accepts_recommendation_at_max_ttl_boundary() {
        let pool = MemorySpendPool::new(1_000_000);
        let rec =
            MockJevRouter::recommend_model("acme-large", "acme", MAX_RECOMMENDATION_TTL_MS, 1);
        let decision = apply_recommendation(&rec, "acme-small", &policy(), &pool, 1, now_ms());
        assert!(matches!(decision, ModelSwitchDecision::Switch { .. }));
    }

    #[test]
    fn host_rejects_stale_or_replayed_sequence() {
        let pool = MemorySpendPool::new(1_000_000);
        // Recommendation answering an older task profile, replayed
        // against a newer one.
        let rec = MockJevRouter::recommend_model("acme-large", "acme", 60_000, 1);
        let decision = apply_recommendation(&rec, "acme-small", &policy(), &pool, 2, now_ms());
        assert!(matches!(
            decision,
            ModelSwitchDecision::Keep { reason } if reason.contains("sequence mismatch")
        ));
    }

    #[test]
    fn host_avoids_churn_on_same_model() {
        let pool = MemorySpendPool::new(1_000_000);
        let rec = MockJevRouter::recommend_model("acme-large", "acme", 60_000, 1);
        let decision = apply_recommendation(&rec, "acme-large", &policy(), &pool, 1, now_ms());
        assert!(matches!(
            decision,
            ModelSwitchDecision::Keep { reason } if reason.contains("already on")
        ));
    }

    #[test]
    fn recommendation_carries_no_authority_fields() {
        // Type-level guard: serializing a recommendation must not leak
        // anything that looks like a grant.
        let rec = MockJevRouter::recommend_model("acme-large", "acme", 60_000, 1);
        let serialized = serde_json::to_string(&rec).unwrap();
        for forbidden in ["lease", "signature", "budget", "secret", "token"] {
            assert!(
                !serialized.contains(forbidden),
                "recommendation leaks '{forbidden}'"
            );
        }
    }
}
