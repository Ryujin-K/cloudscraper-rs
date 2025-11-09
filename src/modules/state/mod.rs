//! Shared state management for domains.
//!
//! Maintains per-domain telemetry, request history, and adaptive signals while
//! staying lightweight for async callers.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::challenges::solvers::FailureRecorder;

const ERROR_HISTORY_LIMIT: usize = 50;
const RECENT_DELAY_LIMIT: usize = 32;

fn chrono_duration(duration: Duration) -> chrono::Duration {
    chrono::Duration::from_std(duration).unwrap_or_else(|_| {
        let millis = duration.as_millis().min(i64::MAX as u128);
        chrono::Duration::milliseconds(millis as i64)
    })
}

#[derive(Debug, Clone)]
pub struct TimingState {
    pub success_rate: f32,
    pub avg_response_time_secs: f32,
    pub consecutive_failures: u8,
    pub optimal_delay: Option<Duration>,
    pub recent_delays: VecDeque<Duration>,
}

impl Default for TimingState {
    fn default() -> Self {
        Self {
            success_rate: 1.0,
            avg_response_time_secs: 1.0,
            consecutive_failures: 0,
            optimal_delay: None,
            recent_delays: VecDeque::with_capacity(RECENT_DELAY_LIMIT),
        }
    }
}

impl TimingState {
    pub fn register_outcome(
        &mut self,
        success: bool,
        response_time: Duration,
        applied_delay: Duration,
    ) {
        self.apply_boolean_outcome(success);

        let alpha = 0.05;
        let response_secs = response_time.as_secs_f32();
        if self.avg_response_time_secs <= 0.0 {
            self.avg_response_time_secs = response_secs;
        } else {
            self.avg_response_time_secs =
                (1.0 - alpha) * self.avg_response_time_secs + alpha * response_secs;
        }

        if success {
            let delay_secs = applied_delay.as_secs_f32();
            self.optimal_delay = Some(match self.optimal_delay {
                None => applied_delay,
                Some(current) => {
                    let blended = (1.0 - alpha) * current.as_secs_f32() + alpha * delay_secs;
                    Duration::from_secs_f32(blended)
                }
            });
        }

        self.recent_delays.push_back(applied_delay);
        if self.recent_delays.len() > RECENT_DELAY_LIMIT {
            self.recent_delays.pop_front();
        }
    }

    pub fn apply_boolean_outcome(&mut self, success: bool) {
        let alpha = 0.05;
        let target = if success { 1.0 } else { 0.0 };
        self.success_rate = (1.0 - alpha) * self.success_rate + alpha * target;

        if success {
            self.consecutive_failures = 0;
        } else {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimingPatternState {
    pub last_request: Option<DateTime<Utc>>,
    pub avg_interval: Duration,
    pub variance: Duration,
}

impl Default for TimingPatternState {
    fn default() -> Self {
        Self {
            last_request: None,
            avg_interval: Duration::from_secs_f32(2.0),
            variance: Duration::from_secs_f32(1.0),
        }
    }
}

impl TimingPatternState {
    pub fn mark_request(&mut self, now: DateTime<Utc>) {
        self.last_request = Some(now);
    }

    pub fn update_targets(&mut self, avg_interval: Duration, variance: Duration) {
        self.avg_interval = avg_interval;
        self.variance = variance;
    }
}

#[derive(Debug, Clone)]
pub struct BurstState {
    pub window: VecDeque<DateTime<Utc>>,
    pub max_burst: u32,
    pub window_size: Duration,
    pub cooldown_base: Duration,
    pub cooldown_until: Option<DateTime<Utc>>,
}

impl Default for BurstState {
    fn default() -> Self {
        Self {
            window: VecDeque::with_capacity(32),
            max_burst: 5,
            window_size: Duration::from_secs(60),
            cooldown_base: Duration::from_secs(10),
            cooldown_until: None,
        }
    }
}

impl BurstState {
    pub fn record(&mut self, timestamp: DateTime<Utc>) {
        let horizon = chrono_duration(self.window_size);
        while let Some(front) = self.window.front().cloned() {
            if front + horizon < timestamp {
                self.window.pop_front();
            } else {
                break;
            }
        }
        self.window.push_back(timestamp);
    }

    pub fn set_cooldown(&mut self, duration: Duration) {
        self.cooldown_until = Some(Utc::now() + chrono_duration(duration));
    }

    pub fn cooldown_remaining(&self, now: DateTime<Utc>) -> Option<Duration> {
        self.cooldown_until
            .and_then(|until| (until > now).then(|| (until - now).to_std().ok()).flatten())
    }
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub last_activity: Option<DateTime<Utc>>,
    pub min_interval: Duration,
    pub request_count: u32,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            id: None,
            created_at: None,
            last_activity: None,
            min_interval: Duration::from_millis(500),
            request_count: 0,
        }
    }
}

impl SessionState {
    pub fn ensure_initialized(&mut self, now: DateTime<Utc>) {
        if self.id.is_none() {
            self.id = Some(format!("sess-{}", now.timestamp_millis()));
            self.created_at = Some(now);
        }
    }

    pub fn touch(&mut self, now: DateTime<Utc>) {
        self.ensure_initialized(now);
        self.last_activity = Some(now);
        self.request_count = self.request_count.saturating_add(1);
    }
}

#[derive(Debug, Clone, Default)]
pub struct FingerprintProfile {
    pub gpu_vendor: Option<String>,
    pub performance_tier: Option<String>,
    pub browser_type: Option<String>,
    pub operating_system: Option<String>,
    pub last_updated: Option<DateTime<Utc>>,
    pub canvas_hash: Option<String>,
    pub webgl_hash: Option<String>,
}

impl FingerprintProfile {
    pub fn update_profile(
        &mut self,
        gpu_vendor: Option<String>,
        performance_tier: Option<String>,
        browser_type: Option<String>,
        operating_system: Option<String>,
    ) {
        self.gpu_vendor = gpu_vendor;
        self.performance_tier = performance_tier;
        self.browser_type = browser_type;
        self.operating_system = operating_system;
        self.last_updated = Some(Utc::now());
    }

    pub fn update_hashes(&mut self, canvas_hash: Option<String>, webgl_hash: Option<String>) {
        if canvas_hash.is_some() {
            self.canvas_hash = canvas_hash;
        }
        if webgl_hash.is_some() {
            self.webgl_hash = webgl_hash;
        }
        self.last_updated = Some(Utc::now());
    }
}

#[derive(Debug, Clone, Default)]
pub struct MlStrategyState {
    pub last_strategy: Option<String>,
    pub success_counter: u32,
    pub failure_counter: u32,
    pub last_updated: Option<DateTime<Utc>>,
}

impl MlStrategyState {
    pub fn record(&mut self, strategy: &str, success: bool) {
        self.last_strategy = Some(strategy.to_string());
        if success {
            self.success_counter = self.success_counter.saturating_add(1);
        } else {
            self.failure_counter = self.failure_counter.saturating_add(1);
        }
        self.last_updated = Some(Utc::now());
    }
}

#[derive(Debug, Clone)]
pub struct DomainErrorRecord {
    pub timestamp: DateTime<Utc>,
    pub code: Option<u16>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct DomainState {
    pub last_success: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub failure_streak: u32,
    pub success_streak: u32,
    pub timing: TimingState,
    pub timing_pattern: TimingPatternState,
    pub burst: BurstState,
    pub session: SessionState,
    pub fingerprint: FingerprintProfile,
    pub ml: MlStrategyState,
    pub recent_errors: VecDeque<DomainErrorRecord>,
    pub cookies: HashMap<String, String>,
    pub sticky_headers: HashMap<String, String>,
    pub metadata: HashMap<String, Value>,
}

impl Default for DomainState {
    fn default() -> Self {
        Self {
            last_success: None,
            last_error: None,
            failure_streak: 0,
            success_streak: 0,
            timing: TimingState::default(),
            timing_pattern: TimingPatternState::default(),
            burst: BurstState::default(),
            session: SessionState::default(),
            fingerprint: FingerprintProfile::default(),
            ml: MlStrategyState::default(),
            recent_errors: VecDeque::with_capacity(ERROR_HISTORY_LIMIT),
            cookies: HashMap::new(),
            sticky_headers: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
}

impl DomainState {
    pub fn record_success(&mut self) {
        self.record_outcome(true, None, None, None);
    }

    pub fn record_failure(&mut self, error: impl Into<String>) {
        self.record_outcome(false, None, None, Some(error.into()));
    }

    pub fn record_outcome(
        &mut self,
        success: bool,
        response_time: Option<Duration>,
        applied_delay: Option<Duration>,
        error: Option<String>,
    ) {
        let now = Utc::now();
        if success {
            self.success_streak = self.success_streak.saturating_add(1);
            self.failure_streak = 0;
            self.last_success = Some(now);
            self.last_error = None;
            self.recent_errors.clear();
        } else {
            self.failure_streak = self.failure_streak.saturating_add(1);
            self.success_streak = 0;
            if let Some(ref err) = error {
                self.last_error = Some(err.clone());
            }
        }

        match (response_time, applied_delay) {
            (Some(response), Some(delay)) => {
                self.timing.register_outcome(success, response, delay);
            }
            _ => {
                self.timing.apply_boolean_outcome(success);
            }
        }

        if !success {
            let message = error.unwrap_or_else(|| "unknown error".to_string());
            self.push_error(None, message);
        }
    }

    pub fn record_outcome_with_metrics(
        &mut self,
        success: bool,
        response_time: Duration,
        applied_delay: Duration,
        error: Option<String>,
    ) {
        self.record_outcome(success, Some(response_time), Some(applied_delay), error);
    }

    pub fn push_error(&mut self, code: Option<u16>, message: impl Into<String>) {
        let msg = message.into();
        self.last_error = Some(msg.clone());
        self.recent_errors.push_back(DomainErrorRecord {
            timestamp: Utc::now(),
            code,
            message: msg,
        });
        if self.recent_errors.len() > ERROR_HISTORY_LIMIT {
            self.recent_errors.pop_front();
        }
    }

    pub fn set_cookie(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.cookies.insert(key.into(), value.into());
    }

    pub fn set_header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.sticky_headers.insert(key.into(), value.into());
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: Value) {
        self.metadata.insert(key.into(), value);
    }

    pub fn mark_request(&mut self) {
        let now = Utc::now();
        self.timing_pattern.mark_request(now);
        self.session.touch(now);
        self.burst.record(now);
    }

    pub fn update_timing_targets(&mut self, avg_interval: Duration, variance: Duration) {
        self.timing_pattern.update_targets(avg_interval, variance);
    }

    pub fn update_session_min_interval(&mut self, interval: Duration) {
        self.session.min_interval = interval;
    }
}

/// Thread-safe state manager.
#[derive(Clone, Debug)]
pub struct StateManager {
    inner: Arc<RwLock<HashMap<String, DomainState>>>,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get(&self, domain: &str) -> Option<DomainState> {
        self.inner
            .read()
            .ok()
            .and_then(|map| map.get(domain).cloned())
    }

    pub fn get_or_create(&self, domain: &str) -> DomainState {
        let mut guard = self.inner.write().expect("state lock poisoned");
        guard.entry(domain.to_string()).or_default().clone()
    }

    pub fn update<F>(&self, domain: &str, mut f: F)
    where
        F: FnMut(&mut DomainState),
    {
        if let Ok(mut guard) = self.inner.write() {
            let state = guard.entry(domain.to_string()).or_default();
            f(state);
        }
    }

    pub fn record_success(&self, domain: &str) {
        self.update(domain, |state| state.record_success());
    }

    pub fn record_failure(&self, domain: &str, error: impl Into<String>) {
        let message = error.into();
        self.update(domain, |state| state.record_failure(message.clone()));
    }

    pub fn record_outcome(
        &self,
        domain: &str,
        success: bool,
        response_time: Option<Duration>,
        applied_delay: Option<Duration>,
        error: Option<String>,
    ) {
        self.update(domain, |state| {
            state.record_outcome(success, response_time, applied_delay, error.clone());
        });
    }

    pub fn mark_request(&self, domain: &str) {
        self.update(domain, |state| state.mark_request());
    }

    pub fn push_error(&self, domain: &str, code: Option<u16>, message: impl Into<String>) {
        let msg = message.into();
        self.update(domain, |state| state.push_error(code, msg.clone()));
    }

    pub fn clear(&self, domain: &str) {
        if let Ok(mut guard) = self.inner.write() {
            guard.remove(domain);
        }
    }

    pub fn clear_all(&self) {
        if let Ok(mut guard) = self.inner.write() {
            guard.clear();
        }
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FailureRecorder for StateManager {
    fn record_failure(&self, domain: &str, reason: &str) {
        StateManager::record_failure(self, domain, reason.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_success_and_failure() {
        let manager = StateManager::new();
        manager.record_failure("example.com", "timeout");
        manager.record_success("example.com");
        let state = manager.get("example.com").unwrap();
        assert_eq!(state.failure_streak, 0);
        assert_eq!(state.success_streak, 1);
        assert!(state.last_success.is_some());
        assert!(state.recent_errors.is_empty());
    }
}
