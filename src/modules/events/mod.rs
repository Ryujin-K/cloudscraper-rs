//! Event system for the advanced infrastructure.
//!
//! Provides hooks for metrics, logging, and custom reactions around pipeline
//! activity.

use chrono::{DateTime, Utc};
use http::{HeaderMap, Method};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

use super::metrics::MetricsCollector;

/// Structured pre-request event.
#[derive(Debug, Clone)]
pub struct PreRequestEvent {
    pub url: Url,
    pub method: Method,
    pub headers: HeaderMap,
    pub timestamp: DateTime<Utc>,
}

/// Structured post-response event.
#[derive(Debug, Clone)]
pub struct PostResponseEvent {
    pub url: Url,
    pub method: Method,
    pub status: u16,
    pub latency: Duration,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ChallengeEvent {
    pub domain: String,
    pub challenge_type: String,
    pub success: bool,
    pub metadata: Vec<(String, String)>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ErrorEvent {
    pub domain: String,
    pub error: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RetryEvent {
    pub domain: String,
    pub attempt: u32,
    pub reason: String,
    pub scheduled_after: Duration,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum ScraperEvent {
    PreRequest(PreRequestEvent),
    PostResponse(PostResponseEvent),
    Challenge(ChallengeEvent),
    Error(ErrorEvent),
    Retry(RetryEvent),
}

/// Trait implemented by event handlers.
pub trait EventHandler: Send + Sync {
    fn handle(&self, event: &ScraperEvent);
}

/// Dispatcher that broadcasts events to registered handlers.
#[derive(Default)]
pub struct EventDispatcher {
    handlers: Vec<Arc<dyn EventHandler>>,
}

impl EventDispatcher {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    pub fn register_handler(&mut self, handler: Arc<dyn EventHandler>) {
        self.handlers.push(handler);
    }

    pub fn dispatch(&self, event: ScraperEvent) {
        for handler in &self.handlers {
            handler.handle(&event);
        }
    }
}

/// Logs events using the `log` crate.
#[derive(Debug)]
pub struct LoggingHandler;

impl EventHandler for LoggingHandler {
    fn handle(&self, event: &ScraperEvent) {
        match event {
            ScraperEvent::PreRequest(pre) => {
                log::debug!("-> {} {}", pre.method, pre.url);
            }
            ScraperEvent::PostResponse(post) => {
                log::debug!(
                    "<- {} {} -> {} ({:.2}s)",
                    post.method,
                    post.url,
                    post.status,
                    post.latency.as_secs_f64()
                );
            }
            ScraperEvent::Challenge(challenge) => {
                log::info!(
                    "challenge {} ({}) success={}",
                    challenge.domain,
                    challenge.challenge_type,
                    challenge.success
                );
            }
            ScraperEvent::Error(error) => {
                log::warn!("warning {} -> {}", error.domain, error.error);
            }
            ScraperEvent::Retry(retry) => {
                log::info!(
                    "retry {} attempt {} after {:.2}s",
                    retry.domain,
                    retry.attempt,
                    retry.scheduled_after.as_secs_f64()
                );
            }
        }
    }
}

/// Metrics handler that feeds the metrics collector.
#[derive(Clone, Debug)]
pub struct MetricsHandler {
    metrics: MetricsCollector,
}

impl MetricsHandler {
    pub fn new(metrics: MetricsCollector) -> Self {
        Self { metrics }
    }
}

impl EventHandler for MetricsHandler {
    fn handle(&self, event: &ScraperEvent) {
        match event {
            ScraperEvent::PostResponse(post) => {
                self.metrics.record_response(
                    post.url.host_str().unwrap_or(""),
                    post.status,
                    post.latency,
                );
            }
            ScraperEvent::Error(error) => {
                self.metrics.record_error(&error.domain);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingHandler(std::sync::Mutex<usize>);

    impl EventHandler for CountingHandler {
        fn handle(&self, _event: &ScraperEvent) {
            *self.0.lock().unwrap() += 1;
        }
    }

    #[test]
    fn dispatches_to_handlers() {
        let mut dispatcher = EventDispatcher::new();
        let counter = Arc::new(CountingHandler(std::sync::Mutex::new(0)));
        dispatcher.register_handler(counter.clone());
        dispatcher.dispatch(ScraperEvent::Error(ErrorEvent {
            domain: "example.com".into(),
            error: "timeout".into(),
            timestamp: Utc::now(),
        }));
        assert_eq!(*counter.0.lock().unwrap(), 1);
    }
}
