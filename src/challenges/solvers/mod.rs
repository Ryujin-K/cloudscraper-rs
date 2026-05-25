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
