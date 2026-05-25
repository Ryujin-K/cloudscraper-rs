//! Adaptive timing utilities.
//!
//! These abstractions provide a simplified feedback-driven delay system that
//! solvers and the pipeline can reuse as a foundation for dynamic delays.

use std::cmp::Ordering;
use std::time::Duration;

/// Feedback emitted after solving attempts.
#[derive(Debug, Clone, Copy)]
pub enum TimingFeedback {
    Success,
    Failure,
    RateLimited,
}

/// Strategies used to compute the next delay before replaying a challenge.
#[derive(Debug, Clone)]
pub struct DelayStrategy {
    base_delay_ms: u64,
    min_delay_ms: u64,
    max_delay_ms: u64,
    variance_pct: f64,
    recent_failures: u32,
}

impl DelayStrategy {
    pub fn new(base_delay_ms: u64) -> Self {
        Self {
            base_delay_ms,
            min_delay_ms: base_delay_ms / 2,
            max_delay_ms: base_delay_ms * 2,
            variance_pct: 0.25,
            recent_failures: 0,
        }
    }

    pub fn with_bounds(mut self, min_delay_ms: u64, max_delay_ms: u64) -> Self {
        self.min_delay_ms = min_delay_ms;
        self.max_delay_ms = max_delay_ms;
        self
    }

    pub fn with_variance(mut self, variance_pct: f64) -> Self {
        self.variance_pct = variance_pct;
        self
    }

    pub fn register_feedback(&mut self, feedback: TimingFeedback) {
        match feedback {
            TimingFeedback::Success => {
                self.recent_failures = self.recent_failures.saturating_sub(1);
            }
            TimingFeedback::Failure => {
                self.recent_failures = self.recent_failures.saturating_add(1);
            }
            TimingFeedback::RateLimited => {
                self.recent_failures = self.recent_failures.saturating_add(2);
            }
        }
    }

    pub fn next_delay(&self) -> Duration {
        let mut delay = self.base_delay_ms as f64;

        match self.recent_failures.cmp(&2) {
            Ordering::Less => {}
            Ordering::Equal => delay *= 1.5,
            Ordering::Greater => delay *= 2.0,
        }

        let variance = delay * self.variance_pct;
        let jitter = rand::random::<f64>() * variance - (variance / 2.0);
        delay = (delay + jitter).clamp(self.min_delay_ms as f64, self.max_delay_ms as f64);
        Duration::from_millis(delay.max(0.0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_delay_respects_bounds() {
        let strategy = DelayStrategy::new(1000)
            .with_bounds(500, 2000)
            .with_variance(0.25);
        for _ in 0..50 {
            let delay = strategy.next_delay().as_millis() as u64;
            assert!((500..=2000).contains(&delay), "delay {delay} out of bounds");
        }
    }

    #[test]
    fn failures_escalate_delay() {
        // Variance 0 makes the delay deterministic; wide bounds avoid clamping.
        let mut strategy = DelayStrategy::new(1000)
            .with_variance(0.0)
            .with_bounds(0, 100_000);
        let base = strategy.next_delay();

        strategy.register_feedback(TimingFeedback::Failure);
        strategy.register_feedback(TimingFeedback::Failure); // recent_failures == 2 -> x1.5
        let escalated = strategy.next_delay();
        assert!(escalated > base);

        strategy.register_feedback(TimingFeedback::Failure); // > 2 -> x2.0
        let escalated_more = strategy.next_delay();
        assert!(escalated_more > escalated);
    }

    #[test]
    fn rate_limited_then_success_recovers() {
        let mut strategy = DelayStrategy::new(1000)
            .with_variance(0.0)
            .with_bounds(0, 100_000);
        strategy.register_feedback(TimingFeedback::RateLimited); // +2 -> x1.5
        assert!(strategy.next_delay() > Duration::from_millis(1000));

        strategy.register_feedback(TimingFeedback::Success); // -1
        strategy.register_feedback(TimingFeedback::Success); // -1 -> back to 0
        assert_eq!(strategy.next_delay(), Duration::from_millis(1000));
    }

    #[test]
    fn success_below_floor_saturates_at_zero() {
        let mut strategy = DelayStrategy::new(500).with_variance(0.0);
        strategy.register_feedback(TimingFeedback::Success); // saturating_sub on 0
        // No panic and delay stays sane.
        assert!(strategy.next_delay() <= Duration::from_millis(1000));
    }
}
