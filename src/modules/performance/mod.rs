//! Performance monitoring utilities.
//!
//! Tracks latency and error trends, then surfaces alerts when thresholds are
//! exceeded.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    pub window: usize,
    pub latency_threshold: Duration,
    pub error_rate_threshold: f64,
    pub min_samples: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            window: 100,
            latency_threshold: Duration::from_secs_f32(4.0),
            error_rate_threshold: 0.25,
            min_samples: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerformanceReport {
    pub global_latency: Option<Duration>,
    pub slow_domains: Vec<(String, Duration)>,
    pub error_domains: Vec<(String, f64)>,
    pub alerts: Vec<String>,
}

impl PerformanceReport {
    fn empty() -> Self {
        Self {
            global_latency: None,
            slow_domains: Vec::new(),
            error_domains: Vec::new(),
            alerts: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct DomainPerformance {
    latencies: VecDeque<Duration>,
    successes: usize,
    failures: usize,
    window: usize,
}

impl DomainPerformance {
    fn new(window: usize) -> Self {
        Self {
            latencies: VecDeque::with_capacity(window),
            successes: 0,
            failures: 0,
            window,
        }
    }

    fn record(&mut self, latency: Duration, success: bool) {
        if self.latencies.len() == self.window {
            self.latencies.pop_front();
        }
        self.latencies.push_back(latency);
        if success {
            self.successes += 1;
        } else {
            self.failures += 1;
        }
    }

    fn average_latency(&self) -> Option<Duration> {
        if self.latencies.is_empty() {
            return None;
        }
        let total = self.latencies.iter().map(|d| d.as_secs_f64()).sum::<f64>();
        Some(Duration::from_secs_f64(total / self.latencies.len() as f64))
    }

    fn error_rate(&self) -> Option<f64> {
        let total = self.successes + self.failures;
        if total == 0 {
            return None;
        }
        Some(self.failures as f64 / total as f64)
    }
}

/// Observes per-domain performance with rolling statistics.
#[derive(Debug)]
pub struct PerformanceMonitor {
    config: PerformanceConfig,
    domains: HashMap<String, DomainPerformance>,
    global_latencies: VecDeque<Duration>,
}

impl PerformanceMonitor {
    pub fn new(config: PerformanceConfig) -> Self {
        Self {
            global_latencies: VecDeque::with_capacity(config.window),
            domains: HashMap::new(),
            config,
        }
    }

    fn domain_mut(&mut self, domain: &str) -> &mut DomainPerformance {
        self.domains
            .entry(domain.to_string())
            .or_insert_with(|| DomainPerformance::new(self.config.window))
    }

    /// Record a latency measurement and return an optional alert report.
    pub fn record(
        &mut self,
        domain: &str,
        latency: Duration,
        success: bool,
    ) -> Option<PerformanceReport> {
        if self.global_latencies.len() == self.config.window {
            self.global_latencies.pop_front();
        }
        self.global_latencies.push_back(latency);

        let domain_state = self.domain_mut(domain);
        domain_state.record(latency, success);

        let should_report = domain_state.latencies.len() >= self.config.min_samples
            || self.global_latencies.len() >= self.config.min_samples;
        if !should_report {
            return None;
        }

        let mut report = PerformanceReport::empty();
        report.global_latency = self.global_latency();

        for (domain_name, perf) in &self.domains {
            if let Some(avg) = perf.average_latency()
                && avg > self.config.latency_threshold
            {
                report.slow_domains.push((domain_name.clone(), avg));
            }

            if let Some(error_rate) = perf.error_rate()
                && error_rate >= self.config.error_rate_threshold
            {
                report.error_domains.push((domain_name.clone(), error_rate));
            }
        }

        if let Some(global) = report.global_latency
            && global > self.config.latency_threshold
        {
            report.alerts.push(format!(
                "Global latency {:.2}s exceeded threshold {:.2}s",
                global.as_secs_f64(),
                self.config.latency_threshold.as_secs_f64()
            ));
        }

        for (domain, latency) in &report.slow_domains {
            report.alerts.push(format!(
                "Domain {} average latency {:.2}s exceeds threshold",
                domain,
                latency.as_secs_f64()
            ));
        }

        for (domain, rate) in &report.error_domains {
            report.alerts.push(format!(
                "Domain {} error rate {:.1}% exceeds threshold",
                domain,
                rate * 100.0
            ));
        }

        Some(report)
    }

    pub fn snapshot(&self) -> PerformanceReport {
        let mut report = PerformanceReport::empty();
        report.global_latency = self.global_latency();
        for (domain, perf) in &self.domains {
            if let Some(avg) = perf.average_latency()
                && avg > self.config.latency_threshold
            {
                report.slow_domains.push((domain.clone(), avg));
            }
            if let Some(rate) = perf.error_rate()
                && rate >= self.config.error_rate_threshold
            {
                report.error_domains.push((domain.clone(), rate));
            }
        }
        report
    }

    fn global_latency(&self) -> Option<Duration> {
        if self.global_latencies.is_empty() {
            return None;
        }
        let total = self
            .global_latencies
            .iter()
            .map(|d| d.as_secs_f64())
            .sum::<f64>();
        Some(Duration::from_secs_f64(
            total / self.global_latencies.len() as f64,
        ))
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new(PerformanceConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_alert_for_high_latency() {
        let mut monitor = PerformanceMonitor::new(PerformanceConfig {
            latency_threshold: Duration::from_millis(200),
            min_samples: 3,
            ..Default::default()
        });
        for _ in 0..3 {
            monitor.record("example.com", Duration::from_millis(500), true);
        }
        let report = monitor.snapshot();
        assert!(!report.slow_domains.is_empty());
    }
}
