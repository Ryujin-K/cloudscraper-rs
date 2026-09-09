//! Challenge solver module registry.
//!
//! Each submodule implements a solver for a specific Cloudflare mitigation.

pub mod access_denied;
pub mod bot_management;
pub mod browser;
pub mod javascript_v1;
pub mod javascript_v2;
pub mod managed_v3;
pub mod rate_limit;
pub mod turnstile;

use std::collections::HashMap;
use std::time::Duration;

/// Common solver interface to be implemented once logic is ported.
pub trait ChallengeSolver {
    fn name(&self) -> &'static str;
}

/// Records domain-level mitigation failures without depending on the full state manager.
pub trait FailureRecorder {
    fn record_failure(&self, domain: &str, reason: &str);
}

/// Provides fingerprint invalidation semantics for mitigation strategies.
pub trait FingerprintManager {
    fn invalidate(&mut self, domain: &str);
}

/// Provides TLS profile rotation semantics for mitigation strategies.
pub trait TlsProfileManager {
    fn rotate_profile(&mut self, domain: &str);
}

/// Standardised mitigation instructions returned by non-form-based solvers.
#[derive(Debug, Clone, PartialEq)]
pub struct MitigationPlan {
    pub should_retry: bool,
    pub wait: Option<Duration>,
    pub reason: String,
    pub new_proxy: Option<String>,
    pub headers: HashMap<String, String>,
    pub metadata: HashMap<String, String>,
}

impl MitigationPlan {
    pub fn retry_after(wait: Duration, reason: impl Into<String>) -> Self {
        Self {
            should_retry: true,
            wait: Some(wait),
            reason: reason.into(),
            new_proxy: None,
            headers: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn retry_immediately(reason: impl Into<String>) -> Self {
        Self {
            should_retry: true,
            wait: None,
            reason: reason.into(),
            new_proxy: None,
            headers: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn no_retry(reason: impl Into<String>) -> Self {
        Self {
            should_retry: false,
            wait: None,
            reason: reason.into(),
            new_proxy: None,
            headers: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_proxy(mut self, proxy: impl Into<String>) -> Self {
        self.new_proxy = Some(proxy.into());
        self
    }

    pub fn insert_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Helper enum referencing all solver variants.
#[allow(dead_code)]
pub enum SolverVariant {
    JavascriptV1,
    JavascriptV2,
    ManagedV3,
    Turnstile,
    RateLimit,
    AccessDenied,
    BotManagement,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_carries_wait_and_reason() {
        let plan = MitigationPlan::retry_after(Duration::from_secs(2), "wait");
        assert!(plan.should_retry);
        assert_eq!(plan.wait, Some(Duration::from_secs(2)));
        assert_eq!(plan.reason, "wait");
        assert!(plan.new_proxy.is_none());
    }

    #[test]
    fn retry_immediately_has_no_wait() {
        let plan = MitigationPlan::retry_immediately("go");
        assert!(plan.should_retry);
        assert!(plan.wait.is_none());
        assert_eq!(plan.reason, "go");
    }

    #[test]
    fn no_retry_disables_retry() {
        let plan = MitigationPlan::no_retry("stop");
        assert!(!plan.should_retry);
        assert!(plan.wait.is_none());
    }

    #[test]
    fn builder_helpers_attach_proxy_and_metadata() {
        let plan = MitigationPlan::retry_immediately("r")
            .with_proxy("http://p")
            .insert_metadata("k", "v");
        assert_eq!(plan.new_proxy.as_deref(), Some("http://p"));
        assert_eq!(plan.metadata.get("k").unwrap(), "v");
    }
}
