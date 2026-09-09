//! Captcha provider integrations.
//!
//! These adapters provide a unified interface for third-party captcha
//! solvers such as AntiCaptcha, CapSolver, and TwoCaptcha. The core solver can
//! remain agnostic of vendor-specific details while still retrieving challenge
//! tokens when necessary.

mod anticaptcha;
mod capsolver;
mod twocaptcha;

pub use anticaptcha::AntiCaptchaProvider;
pub use capsolver::CapSolverProvider;
pub use twocaptcha::TwoCaptchaProvider;

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use url::Url;

/// High-level configuration that controls captcha solving behaviour.
#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    pub timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for CaptchaConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            poll_interval: Duration::from_secs(2),
        }
    }
}

/// Details describing the captcha Cloudflare issued.
#[derive(Debug, Clone)]
pub struct CaptchaTask {
    pub site_key: String,
    pub page_url: Url,
    pub action: Option<String>,
    pub data: HashMap<String, String>,
}

impl CaptchaTask {
    pub fn new(site_key: impl Into<String>, page_url: Url) -> Self {
        Self {
            site_key: site_key.into(),
            page_url,
            action: None,
            data: HashMap::new(),
        }
    }

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    pub fn insert_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }
}

/// Resolved captcha token and optional metadata.
#[derive(Debug, Clone)]
pub struct CaptchaSolution {
    pub token: String,
    pub expires_in: Option<Duration>,
    pub metadata: HashMap<String, String>,
}

impl CaptchaSolution {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            expires_in: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_expiry(mut self, ttl: Duration) -> Self {
        self.expires_in = Some(ttl);
        self
    }

    pub fn insert_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Common result type returned by captcha providers.
pub type CaptchaResult = Result<CaptchaSolution, CaptchaError>;

/// Shared interface implemented by captcha vendors.
#[async_trait]
pub trait CaptchaProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn solve(&self, task: &CaptchaTask) -> CaptchaResult;
}

/// Errors surfaced by captcha providers.
#[derive(Debug, Error)]
pub enum CaptchaError {
    #[error("captcha provider misconfigured: {0}")]
    Configuration(String),
    #[error("captcha provider request failed: {0}")]
    Provider(String),
    #[error("captcha solving timed out after {0:?}")]
    Timeout(Duration),
    #[error("captcha provider {0} not implemented")]
    NotImplemented(&'static str),
    #[error("captcha error: {0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_task() -> CaptchaTask {
        CaptchaTask::new("sitekey", Url::parse("https://example.com/").unwrap())
            .with_action("login")
            .insert_metadata("k", "v")
    }

    #[test]
    fn captcha_task_builder_sets_fields() {
        let task = sample_task();
        assert_eq!(task.site_key, "sitekey");
        assert_eq!(task.action.as_deref(), Some("login"));
        assert_eq!(task.data.get("k").unwrap(), "v");
    }

    #[test]
    fn captcha_solution_builder_sets_fields() {
        let solution = CaptchaSolution::new("tok")
            .with_expiry(Duration::from_secs(30))
            .insert_metadata("a", "b");
        assert_eq!(solution.token, "tok");
        assert_eq!(solution.expires_in, Some(Duration::from_secs(30)));
        assert_eq!(solution.metadata.get("a").unwrap(), "b");
    }

    #[test]
    fn config_has_sane_defaults() {
        let config = CaptchaConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(120));
        assert_eq!(config.poll_interval, Duration::from_secs(2));
    }

    #[test]
    fn with_config_constructors_compile_for_all_providers() {
        let config = CaptchaConfig {
            timeout: Duration::from_secs(5),
            poll_interval: Duration::from_secs(1),
        };
        let _ = AntiCaptchaProvider::with_config("k", config.clone());
        let _ = CapSolverProvider::with_config("k", config.clone());
        let _ = TwoCaptchaProvider::with_config("k", config);
    }

    #[tokio::test]
    async fn providers_expose_names_and_report_not_implemented() {
        let providers: Vec<Box<dyn CaptchaProvider>> = vec![
            Box::new(AntiCaptchaProvider::new("key")),
            Box::new(CapSolverProvider::new("key")),
            Box::new(TwoCaptchaProvider::new("key")),
        ];
        let task = sample_task();
        for provider in providers {
            assert!(!provider.name().is_empty());
            let err = provider.solve(&task).await.unwrap_err();
            assert!(matches!(err, CaptchaError::NotImplemented(_)));
        }
    }
}
