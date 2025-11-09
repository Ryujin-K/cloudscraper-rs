//! Traffic pattern and anti-detection utilities.
//!
//! Provides request obfuscation, burst control, and adaptive cooldowns for the
//! layer that prepares requests before they hit the network.

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use url::Url;

/// Configuration toggles for anti-detection behaviour.
#[derive(Debug, Clone)]
pub struct AntiDetectionConfig {
    pub randomize_headers: bool,
    pub inject_noise_headers: bool,
    pub header_noise_range: (usize, usize),
    pub burst_window: Duration,
    pub max_requests_per_window: usize,
    pub cooldown: Duration,
    pub failure_cooldown: Duration,
    pub jitter_range: (f32, f32),
}

impl Default for AntiDetectionConfig {
    fn default() -> Self {
        Self {
            randomize_headers: true,
            inject_noise_headers: true,
            header_noise_range: (1, 3),
            burst_window: Duration::from_secs(30),
            max_requests_per_window: 10,
            cooldown: Duration::from_secs(3),
            failure_cooldown: Duration::from_secs(20),
            jitter_range: (0.85, 1.25),
        }
    }
}

/// Context object mutated by anti-detection strategies before dispatch.
#[derive(Debug, Clone)]
pub struct AntiDetectionContext {
    pub url: Url,
    pub method: Method,
    pub headers: HeaderMap,
    pub body_size: usize,
    pub user_agent: Option<String>,
    pub delay_hint: Option<Duration>,
    pub metadata: HashMap<String, String>,
}

impl AntiDetectionContext {
    pub fn new(url: Url, method: Method) -> Self {
        Self {
            url,
            method,
            headers: HeaderMap::new(),
            body_size: 0,
            user_agent: None,
            delay_hint: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    pub fn set_body_size(&mut self, size: usize) {
        self.body_size = size;
    }

    pub fn set_user_agent(&mut self, value: impl Into<String>) {
        self.user_agent = Some(value.into());
    }

    pub fn delay_hint(&self) -> Option<Duration> {
        self.delay_hint
    }
}

/// Trait describing an anti detection step.
pub trait AntiDetectionStrategy: Send + Sync {
    fn prepare_request(&mut self, domain: &str, ctx: &mut AntiDetectionContext);
    fn record_response(&mut self, domain: &str, status: u16, latency: Duration);
}

/// Default anti-detection layer combining header jitter, burst throttling, and
/// cooldown management.
#[derive(Debug)]
pub struct DefaultAntiDetection {
    config: AntiDetectionConfig,
    per_domain: HashMap<String, DomainAntiDetection>,
}

#[derive(Debug)]
struct DomainAntiDetection {
    recent_requests: VecDeque<Instant>,
    failure_streak: u8,
    cooldown_until: Option<Instant>,
    rolling_latency: VecDeque<f32>,
    fingerprint_salt: u32,
}

impl Default for DomainAntiDetection {
    fn default() -> Self {
        Self {
            recent_requests: VecDeque::with_capacity(32),
            failure_streak: 0,
            cooldown_until: None,
            rolling_latency: VecDeque::with_capacity(32),
            fingerprint_salt: rand::thread_rng().r#gen(),
        }
    }
}

impl DefaultAntiDetection {
    pub fn new(config: AntiDetectionConfig) -> Self {
        Self {
            config,
            per_domain: HashMap::new(),
        }
    }

    pub fn config(&self) -> &AntiDetectionConfig {
        &self.config
    }

    fn state_mut(&mut self, domain: &str) -> &mut DomainAntiDetection {
        self.per_domain.entry(domain.to_string()).or_default()
    }

    fn prune_old_requests(state: &mut DomainAntiDetection, window: Duration) {
        let cutoff = Instant::now() - window;
        while matches!(state.recent_requests.front(), Some(ts) if *ts < cutoff) {
            state.recent_requests.pop_front();
        }
    }

    fn enforce_burst_limits(
        config: &AntiDetectionConfig,
        state: &mut DomainAntiDetection,
        ctx: &mut AntiDetectionContext,
    ) {
        Self::prune_old_requests(state, config.burst_window);
        if state.recent_requests.len() > config.max_requests_per_window && ctx.delay_hint.is_none()
        {
            ctx.delay_hint = Some(config.cooldown);
        }
    }

    fn maybe_apply_cooldown(state: &mut DomainAntiDetection, ctx: &mut AntiDetectionContext) {
        if let Some(until) = state.cooldown_until {
            let now = Instant::now();
            if now < until {
                let remaining = until - now;
                ctx.delay_hint = Some(ctx.delay_hint.map_or(remaining, |hint| hint.max(remaining)));
            } else {
                state.cooldown_until = None;
            }
        }
    }

    fn randomize_headers(
        config: &AntiDetectionConfig,
        state: &DomainAntiDetection,
        ctx: &mut AntiDetectionContext,
    ) {
        if !config.randomize_headers {
            return;
        }

        let mut rng = rand::thread_rng();
        // Rotate a few headers that commonly trigger fingerprinting.
        static TARGET_HEADERS: &[&str] = &[
            "accept-language",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
        ];

        for header in TARGET_HEADERS {
            if let Ok(name) = HeaderName::from_lowercase(header.as_bytes())
                && rng.gen_bool(0.3)
            {
                let value = random_header_value(&mut rng, state.fingerprint_salt);
                ctx.headers.insert(name, value);
            }
        }

        if let Some(agent) = &ctx.user_agent {
            let name = HeaderName::from_static("user-agent");
            let value = HeaderValue::from_str(agent)
                .unwrap_or_else(|_| HeaderValue::from_static("Mozilla/5.0"));
            ctx.headers.insert(name, value);
        }
    }

    fn inject_noise_headers(config: &AntiDetectionConfig, ctx: &mut AntiDetectionContext) {
        if !config.inject_noise_headers {
            return;
        }

        let mut rng = rand::thread_rng();
        let (min, max) = config.header_noise_range;
        let upper = max.max(min);
        let count = rng.gen_range(min..=upper);

        for _ in 0..count {
            let token: String = (0..8)
                .map(|_| format!("{:x}", rng.r#gen::<u16>()))
                .collect();
            let name = format!("x-cf-client-{}", token);
            if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes())
                && let Ok(header_value) =
                    HeaderValue::from_str(&format!("{}-{}", rng.r#gen::<u32>(), ctx.body_size))
            {
                ctx.headers.insert(header_name, header_value);
            }
        }
    }
}

impl AntiDetectionStrategy for DefaultAntiDetection {
    fn prepare_request(&mut self, domain: &str, ctx: &mut AntiDetectionContext) {
        let config = self.config.clone();
        {
            let state = self.state_mut(domain);
            state.recent_requests.push_back(Instant::now());
            Self::enforce_burst_limits(&config, state, ctx);
            Self::maybe_apply_cooldown(state, ctx);
            Self::randomize_headers(&config, state, ctx);
        }

        Self::inject_noise_headers(&config, ctx);

        // Apply jitter hint so that timing layer can increase randomness.
        let jitter = {
            let mut rng = rand::thread_rng();
            rng.gen_range(config.jitter_range.0..=config.jitter_range.1)
        };
        ctx.metadata
            .insert("anti_detection_jitter".into(), format!("{:.3}", jitter));
    }

    fn record_response(&mut self, domain: &str, status: u16, latency: Duration) {
        let failure_cooldown = self.config.failure_cooldown;
        let state = self.state_mut(domain);
        let success = status < 500;

        if !success {
            state.failure_streak = state.failure_streak.saturating_add(1);
            state.cooldown_until = Some(Instant::now() + failure_cooldown);
        } else {
            state.failure_streak = 0;
        }

        if state.rolling_latency.len() == 32 {
            state.rolling_latency.pop_front();
        }
        state
            .rolling_latency
            .push_back(latency.as_secs_f32().min(30.0));
    }
}

fn random_header_value<R: Rng + ?Sized>(rng: &mut R, salt: u32) -> HeaderValue {
    let seed = rng.r#gen::<u32>() ^ salt;
    let choices = [
        format!("same-origin;sid={:x}", seed),
        format!("cross-site;hash={:x}", seed.rotate_left(5)),
        format!("none;trace={:x}", seed.rotate_right(7)),
    ];
    HeaderValue::from_str(&choices[rng.gen_range(0..choices.len())])
        .unwrap_or_else(|_| HeaderValue::from_static("same-origin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_delay_hint_when_bursting() {
        let mut strategy = DefaultAntiDetection::new(AntiDetectionConfig {
            max_requests_per_window: 2,
            burst_window: Duration::from_secs(60),
            cooldown: Duration::from_secs(5),
            ..Default::default()
        });

        let url = Url::parse("https://example.com").unwrap();
        let method = Method::GET;

        let mut ctx1 = AntiDetectionContext::new(url.clone(), method.clone());
        strategy.prepare_request("example.com", &mut ctx1);
        assert!(ctx1.delay_hint.is_none());

        let mut ctx2 = AntiDetectionContext::new(url.clone(), method.clone());
        strategy.prepare_request("example.com", &mut ctx2);
        assert!(ctx2.delay_hint.is_none());

        let mut ctx3 = AntiDetectionContext::new(url, method);
        strategy.prepare_request("example.com", &mut ctx3);
        assert!(ctx3.delay_hint.is_some());
    }
}
