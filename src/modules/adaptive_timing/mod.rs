//! Adaptive timing algorithms for human-like request pacing.
//!
//! Provides behavioural profiles, adaptive delay calculation, circadian
//! adjustments, and per-domain learning.

use chrono::{DateTime, Local, Timelike};
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Behaviour profiles that control the high-level timing envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BehaviorProfile {
    Casual,
    Focused,
    Research,
    Mobile,
}

/// High-level request kinds for timing adjustments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Other,
}

impl RequestKind {
    fn delay_multiplier(self) -> f32 {
        match self {
            RequestKind::Post | RequestKind::Put | RequestKind::Patch => 1.35,
            RequestKind::Delete => 0.9,
            RequestKind::Head | RequestKind::Options => 0.6,
            _ => 1.0,
        }
    }
}

/// Configuration describing the base timing envelope for a profile.
#[derive(Debug, Clone, Copy)]
pub struct TimingProfile {
    pub base_delay: f32,
    pub min_delay: f32,
    pub max_delay: f32,
    pub variance_factor: f32,
    pub burst_threshold: usize,
    pub cooldown_multiplier: f32,
    pub success_rate_threshold: f32,
}

impl TimingProfile {
    fn clamp(&self, value: f32) -> f32 {
        value.clamp(self.min_delay, self.max_delay)
    }
}

/// Request metadata supplied to timing strategies.
#[derive(Debug, Clone, Copy)]
pub struct TimingRequest {
    pub kind: RequestKind,
    pub content_length: usize,
}

impl TimingRequest {
    pub fn new(kind: RequestKind, content_length: usize) -> Self {
        Self {
            kind,
            content_length,
        }
    }
}

/// Outcome recorded after each request for adaptive learning.
#[derive(Debug, Clone, Copy)]
pub struct TimingOutcome {
    pub success: bool,
    pub response_time: Duration,
    pub applied_delay: Duration,
}

/// Snapshot of learned state for observability.
#[derive(Debug, Clone, Copy)]
pub struct DomainTimingSnapshot {
    pub success_rate: f32,
    pub consecutive_failures: u8,
    pub average_response_time: Duration,
    pub optimal_timing: Option<Duration>,
}

/// Interface for adaptive timing controllers.
pub trait AdaptiveTimingStrategy: Send + Sync {
    fn set_behavior_profile(&mut self, profile: BehaviorProfile);
    fn behavior_profile(&self) -> BehaviorProfile;
    fn calculate_delay(&mut self, domain: &str, request: &TimingRequest) -> Duration;
    fn record_outcome(&mut self, domain: &str, outcome: &TimingOutcome);
    fn snapshot(&self, domain: &str) -> Option<DomainTimingSnapshot>;
}

/// Default adaptive timing strategy that applies human-like pacing heuristics.
#[derive(Debug)]
pub struct DefaultAdaptiveTiming {
    profiles: HashMap<BehaviorProfile, TimingProfile>,
    active_profile: BehaviorProfile,
    domain_state: HashMap<String, DomainTimingState>,
    global_history: VecDeque<bool>,
    last_global_request: Option<Instant>,
}

#[derive(Debug, Clone)]
struct DomainTimingState {
    success_rate: f32,
    consecutive_failures: u8,
    average_response_time: f32,
    optimal_timing: Option<f32>,
    last_request: Option<Instant>,
    recent_delays: VecDeque<f32>,
}

impl Default for DomainTimingState {
    fn default() -> Self {
        Self {
            success_rate: 1.0,
            consecutive_failures: 0,
            average_response_time: 1.0,
            optimal_timing: None,
            last_request: None,
            recent_delays: VecDeque::with_capacity(32),
        }
    }
}

impl DefaultAdaptiveTiming {
    pub fn new() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert(
            BehaviorProfile::Casual,
            TimingProfile {
                base_delay: 1.5,
                min_delay: 0.5,
                max_delay: 3.0,
                variance_factor: 0.4,
                burst_threshold: 3,
                cooldown_multiplier: 1.5,
                success_rate_threshold: 0.8,
            },
        );
        profiles.insert(
            BehaviorProfile::Focused,
            TimingProfile {
                base_delay: 0.9,
                min_delay: 0.25,
                max_delay: 2.0,
                variance_factor: 0.3,
                burst_threshold: 5,
                cooldown_multiplier: 1.2,
                success_rate_threshold: 0.85,
            },
        );
        profiles.insert(
            BehaviorProfile::Research,
            TimingProfile {
                base_delay: 2.5,
                min_delay: 1.0,
                max_delay: 6.0,
                variance_factor: 0.6,
                burst_threshold: 2,
                cooldown_multiplier: 2.0,
                success_rate_threshold: 0.7,
            },
        );
        profiles.insert(
            BehaviorProfile::Mobile,
            TimingProfile {
                base_delay: 1.2,
                min_delay: 0.4,
                max_delay: 3.0,
                variance_factor: 0.4,
                burst_threshold: 4,
                cooldown_multiplier: 1.3,
                success_rate_threshold: 0.75,
            },
        );

        Self {
            profiles,
            active_profile: BehaviorProfile::Casual,
            domain_state: HashMap::new(),
            global_history: VecDeque::with_capacity(128),
            last_global_request: None,
        }
    }

    fn profile(&self) -> TimingProfile {
        self.profiles
            .get(&self.active_profile)
            .copied()
            .expect("profile missing")
    }

    fn circadian_multiplier() -> f32 {
        let now: DateTime<Local> = Local::now();
        let hour = now.hour() as i32;
        let base = match hour {
            0 => 0.3,
            1..=3 => 0.2,
            4 => 0.3,
            5 => 0.4,
            6 => 0.6,
            7 => 0.8,
            8 => 0.9,
            9..=11 => 1.0,
            12 => 0.9,
            13 => 0.75,
            14 => 0.85,
            15 | 16 => 1.0,
            17 => 0.9,
            18 => 0.8,
            19 => 0.7,
            20 => 0.6,
            21 => 0.5,
            22 => 0.4,
            23 => 0.3,
            _ => 0.5,
        };
        let mut rng = rand::thread_rng();
        base * rng.gen_range(0.85..=1.15)
    }

    fn ensure_domain_state(&mut self, domain: &str) -> &mut DomainTimingState {
        self.domain_state.entry(domain.to_string()).or_default()
    }

    fn apply_human_jitter(mut delay: f32, profile: TimingProfile, content_length: usize) -> f32 {
        let mut rng = rand::thread_rng();
        // Reading delay heuristics
        if content_length > 500 {
            let words = (content_length as f32 / 5.0).max(1.0);
            let reading_speed = rng.gen_range(200.0..=300.0);
            let reading_time = (words / reading_speed) * 60.0;
            let processing = rng.gen_range(0.5..=2.0);
            delay = delay.max(reading_time + processing);
        }

        // Reaction jitter
        let reaction_time = rng.gen_range(0.15..=0.4);
        delay += reaction_time;

        // Distraction chance
        if rng.r#gen::<f32>() < 0.05 {
            let distraction_delay = rng.gen_range(5.0..=60.0);
            delay += distraction_delay;
        }

        profile.clamp(delay)
    }
}

impl Default for DefaultAdaptiveTiming {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveTimingStrategy for DefaultAdaptiveTiming {
    fn set_behavior_profile(&mut self, profile: BehaviorProfile) {
        if self.profiles.contains_key(&profile) {
            self.active_profile = profile;
        }
    }

    fn behavior_profile(&self) -> BehaviorProfile {
        self.active_profile
    }

    fn calculate_delay(&mut self, domain: &str, request: &TimingRequest) -> Duration {
        let profile = self.profile();
        let state = self.ensure_domain_state(domain);

        let mut delay = profile.base_delay * request.kind.delay_multiplier();
        let mut rng = rand::thread_rng();
        let variance = rng.gen_range(1.0 - profile.variance_factor..=1.0 + profile.variance_factor);
        delay *= variance;

        if state.success_rate < profile.success_rate_threshold {
            let delta = profile.success_rate_threshold - state.success_rate;
            delay *= 1.0 + delta.max(0.05);
        }

        if state.consecutive_failures > 0 {
            let penalty = 1.0 + (state.consecutive_failures as f32 * 0.2);
            delay *= penalty;
        }

        if let Some(optimal) = state.optimal_timing {
            delay = (delay * 0.8) + (optimal * 0.2);
        }

        let response_factor = state.average_response_time.clamp(0.6, 1.5);
        delay *= response_factor;

        delay = Self::apply_human_jitter(delay, profile, request.content_length);

        let circadian = Self::circadian_multiplier().max(0.2);
        delay /= circadian;

        let now = Instant::now();
        if let Some(last) = state.last_request {
            let min_spacing = Duration::from_secs_f32(profile.min_delay * 0.6);
            if let Some(remaining) = min_spacing.checked_sub(now.saturating_duration_since(last)) {
                delay = delay.max(remaining.as_secs_f32());
            }
        }

        state.last_request = Some(now);
        self.last_global_request = Some(now);

        Duration::from_secs_f32(profile.clamp(delay))
    }

    fn record_outcome(&mut self, domain: &str, outcome: &TimingOutcome) {
        let state = self.ensure_domain_state(domain);
        let alpha = 0.1;
        let success_value = if outcome.success { 1.0 } else { 0.0 };

        state.success_rate = (1.0 - alpha) * state.success_rate + alpha * success_value;

        if outcome.success {
            state.consecutive_failures = 0;
            let applied = outcome.applied_delay.as_secs_f32().min(10.0);
            state.optimal_timing = Some(match state.optimal_timing {
                None => applied,
                Some(prev) => (0.9 * prev) + (0.1 * applied),
            });
        } else {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1).min(5);
        }

        let response_time = outcome.response_time.as_secs_f32().min(30.0);
        state.average_response_time =
            (1.0 - alpha) * state.average_response_time + alpha * response_time;

        if state.recent_delays.len() == 32 {
            state.recent_delays.pop_front();
        }
        state
            .recent_delays
            .push_back(outcome.applied_delay.as_secs_f32().min(10.0));

        if self.global_history.len() == 256 {
            self.global_history.pop_front();
        }
        self.global_history.push_back(outcome.success);
    }

    fn snapshot(&self, domain: &str) -> Option<DomainTimingSnapshot> {
        self.domain_state
            .get(domain)
            .map(|state| DomainTimingSnapshot {
                success_rate: state.success_rate,
                consecutive_failures: state.consecutive_failures,
                average_response_time: Duration::from_secs_f32(state.average_response_time),
                optimal_timing: state.optimal_timing.map(Duration::from_secs_f32),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_timing_learns_success() {
        let mut timing = DefaultAdaptiveTiming::new();
        let request = TimingRequest::new(RequestKind::Get, 2000);
        let delay1 = timing.calculate_delay("example.com", &request);
        assert!(delay1 > Duration::from_millis(100));

        for _ in 0..20 {
            timing.record_outcome(
                "example.com",
                &TimingOutcome {
                    success: true,
                    response_time: Duration::from_secs_f32(1.2),
                    applied_delay: delay1,
                },
            );
        }

        let delay2 = timing.calculate_delay("example.com", &request);
        // After successive successes the delay should tend to decrease a bit.
        assert!(delay2 <= delay1 * 2);
    }
}
