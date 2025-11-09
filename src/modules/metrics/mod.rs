//! Metrics collection utilities.
//!
//! Provides aggregated global and per-domain statistics with latency
//! percentiles for observability.

use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Aggregated metrics across all domains.
#[derive(Debug, Clone)]
pub struct GlobalStats {
    pub started_at: DateTime<Utc>,
    pub total_requests: u64,
    pub successes: u64,
    pub failures: u64,
    pub average_latency: Option<Duration>,
    pub p95_latency: Option<Duration>,
}

impl Default for GlobalStats {
    fn default() -> Self {
        Self {
            started_at: Utc::now(),
            total_requests: 0,
            successes: 0,
            failures: 0,
            average_latency: None,
            p95_latency: None,
        }
    }
}

/// Domain-scoped metrics snapshot.
#[derive(Debug, Clone)]
pub struct DomainStats {
    pub domain: String,
    pub total_requests: u64,
    pub successes: u64,
    pub failures: u64,
    pub average_latency: Option<Duration>,
    pub p95_latency: Option<Duration>,
    pub consecutive_failures: u32,
    pub last_status: Option<u16>,
}

impl DomainStats {
    fn from_accumulator(domain: &str, acc: &DomainAccumulator) -> Self {
        let (avg, p95) = acc.latency_stats();
        Self {
            domain: domain.to_string(),
            total_requests: acc.total_requests,
            successes: acc.successes,
            failures: acc.failures,
            average_latency: avg,
            p95_latency: p95,
            consecutive_failures: acc.consecutive_failures,
            last_status: acc.last_status,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub global: GlobalStats,
    pub domains: Vec<DomainStats>,
}

#[derive(Debug)]
struct DomainAccumulator {
    total_requests: u64,
    successes: u64,
    failures: u64,
    latencies: VecDeque<Duration>,
    max_window: usize,
    consecutive_failures: u32,
    last_status: Option<u16>,
}

impl DomainAccumulator {
    fn new(max_window: usize) -> Self {
        Self {
            total_requests: 0,
            successes: 0,
            failures: 0,
            latencies: VecDeque::with_capacity(max_window),
            max_window,
            consecutive_failures: 0,
            last_status: None,
        }
    }

    fn record(&mut self, status: u16, latency: Duration) {
        self.total_requests += 1;
        self.last_status = Some(status);

        if status < 500 {
            self.successes += 1;
            self.consecutive_failures = 0;
        } else {
            self.failures += 1;
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }

        if self.latencies.len() == self.max_window {
            self.latencies.pop_front();
        }
        self.latencies.push_back(latency);
    }

    fn latency_stats(&self) -> (Option<Duration>, Option<Duration>) {
        if self.latencies.is_empty() {
            return (None, None);
        }
        let mut samples: Vec<_> = self.latencies.iter().cloned().collect();
        samples.sort_unstable();
        let avg = samples.iter().map(|d| d.as_secs_f64()).sum::<f64>() / samples.len() as f64;
        let p95_index = ((samples.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
        let p95 = samples[p95_index];
        (Some(Duration::from_secs_f64(avg)), Some(p95))
    }
}

#[derive(Debug)]
struct MetricsState {
    global: GlobalStats,
    max_window: usize,
    domains: HashMap<String, DomainAccumulator>,
}

impl MetricsState {
    fn new(max_window: usize) -> Self {
        Self {
            global: GlobalStats::default(),
            max_window,
            domains: HashMap::new(),
        }
    }

    fn accumulator_mut(&mut self, domain: &str) -> &mut DomainAccumulator {
        self.domains
            .entry(domain.to_string())
            .or_insert_with(|| DomainAccumulator::new(self.max_window))
    }
}

/// Thread-safe metrics collector used by the orchestration layer.
#[derive(Clone, Debug)]
pub struct MetricsCollector {
    inner: Arc<Mutex<MetricsState>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MetricsState::new(128))),
        }
    }

    pub fn with_window(window: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MetricsState::new(window.max(16)))),
        }
    }

    pub fn record_response(&self, domain: &str, status: u16, latency: Duration) {
        let mut guard = self.inner.lock().expect("metrics lock poisoned");
        guard.global.total_requests += 1;
        if status < 500 {
            guard.global.successes += 1;
        } else {
            guard.global.failures += 1;
        }

        if let Some(avg) = guard.global.average_latency {
            let blended = (avg.as_secs_f64() * 0.9) + (latency.as_secs_f64() * 0.1);
            guard.global.average_latency = Some(Duration::from_secs_f64(blended));
        } else {
            guard.global.average_latency = Some(latency);
        }

        let acc = guard.accumulator_mut(domain);
        acc.record(status, latency);

        // Update global p95 from all samples (approximation using domain 95th blending).
        let mut percentile_samples: Vec<_> = guard
            .domains
            .values()
            .flat_map(|domain| domain.latencies.iter())
            .cloned()
            .collect();
        percentile_samples.sort_unstable();
        if !percentile_samples.is_empty() {
            let idx = ((percentile_samples.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
            guard.global.p95_latency = Some(percentile_samples[idx]);
        }
    }

    pub fn record_error(&self, domain: &str) {
        let mut guard = self.inner.lock().expect("metrics lock poisoned");
        guard.global.total_requests += 1;
        guard.global.failures += 1;
        let acc = guard.accumulator_mut(domain);
        acc.total_requests += 1;
        acc.failures += 1;
        acc.consecutive_failures = acc.consecutive_failures.saturating_add(1);
        acc.last_status = Some(0);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let guard = self.inner.lock().expect("metrics lock poisoned");
        let domains = guard
            .domains
            .iter()
            .map(|(domain, acc)| DomainStats::from_accumulator(domain, acc))
            .collect();
        MetricsSnapshot {
            global: guard.global.clone(),
            domains,
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn records_success_and_failure() {
        let metrics = MetricsCollector::new();
        metrics.record_response("example.com", 200, Duration::from_millis(150));
        metrics.record_response("example.com", 503, Duration::from_millis(800));
        metrics.record_error("example.com");

        let snapshot = metrics.snapshot();
        let domain = snapshot
            .domains
            .iter()
            .find(|d| d.domain == "example.com")
            .unwrap();
        assert_eq!(domain.total_requests, 3);
        assert_eq!(domain.successes, 1);
        assert_eq!(domain.failures, 2);
    }
}
