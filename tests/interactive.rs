use std::collections::HashMap;
use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use cloudscraper_rs::{
    CloudScraper, UserAgentOptions, VERSION,
    modules::{
        AdaptiveTimingStrategy, AntiDetectionConfig, AntiDetectionContext, AntiDetectionStrategy,
        BehaviorProfile, BrowserType, ConsistencyLevel, DefaultAdaptiveTiming,
        DefaultAntiDetection, DefaultTLSManager, FeatureVector, MLConfig, MLOptimizer, ProxyConfig,
        ProxyManager, RequestKind, RotationStrategy, StateManager, StrategyRecommendation,
        TLSConfig, TimingOutcome, TimingRequest,
    },
};
use http::Method;
use tokio::runtime::Runtime;
use url::Url;

fn prompt(label: &str) -> io::Result<String> {
    print!("{} ", label);
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn parse_bool(input: &str, default: bool) -> bool {
    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" | "true" => true,
        "n" | "no" | "false" => false,
        _ => default,
    }
}

fn parse_usize(input: &str, default: usize) -> usize {
    input
        .trim()
        .parse()
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[test]
#[ignore = "Requires network access and manual input"]
fn interactive_full_stack() -> Result<(), Box<dyn Error>> {
    println!("cloudscraper-rs {} interactive smoke test", VERSION);
    println!("Provide inputs when prompted. Press Enter to accept defaults.\n");

    let url_input = prompt("Target URL [https://example.com]:")?;
    let target_url = if url_input.is_empty() {
        "https://example.com".to_string()
    } else {
        url_input
    };

    let domain = Url::parse(&target_url)?
        .host_str()
        .unwrap_or("example.com")
        .to_string();

    let mobile_answer = prompt("Use mobile user-agent? (y/N):")?;
    let brotli_answer = prompt("Allow Brotli encoding? (y/N):")?;
    let proxies_answer = prompt("Proxy list (comma separated, blank for none):")?;
    let attempts_answer = prompt("Max challenge attempts [3]:")?;

    let disable_metrics_answer = prompt("Disable metrics collection? (y/N):")?;
    let disable_performance_answer = prompt("Disable performance monitor? (y/N):")?;
    let disable_tls_answer = prompt("Disable TLS rotation? (y/N):")?;
    let disable_anti_detection_answer = prompt("Disable anti-detection layer? (y/N):")?;
    let disable_spoofing_answer = prompt("Disable spoofing? (y/N):")?;
    let disable_adaptive_answer = prompt("Disable adaptive timing? (y/N):")?;
    let disable_ml_answer = prompt("Disable ML optimizer? (y/N):")?;

    let mut ua_opts = UserAgentOptions::default();
    if parse_bool(&mobile_answer, false) {
        ua_opts.desktop = false;
        ua_opts.mobile = true;
    }
    ua_opts.allow_brotli = parse_bool(&brotli_answer, ua_opts.allow_brotli);

    let proxy_endpoints: Vec<String> = proxies_answer
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let max_attempts = parse_usize(&attempts_answer, 3);

    let proxy_config = ProxyConfig {
        rotation_strategy: if proxy_endpoints.len() > 1 {
            RotationStrategy::Smart
        } else {
            RotationStrategy::Sequential
        },
        ban_time: Duration::from_secs(120),
        failure_threshold: 2,
        cooldown: Duration::from_secs(30),
    };

    let tls_config = TLSConfig {
        rotate_ja3: !parse_bool(&disable_tls_answer, false),
        rotate_ciphers: !parse_bool(&disable_tls_answer, false),
        preferred_browser: if parse_bool(&mobile_answer, false) {
            BrowserType::MobileChrome
        } else {
            BrowserType::Chrome
        },
        rotation_interval: 3,
    };

    let mut builder = CloudScraper::builder()
        .with_user_agent_options(ua_opts)
        .with_proxy_config(proxy_config)
        .with_behavior_profile(BehaviorProfile::Focused)
        .with_spoofing_consistency(ConsistencyLevel::Global)
        .with_tls_config(tls_config)
        .with_max_challenge_attempts(max_attempts);

    if !proxy_endpoints.is_empty() {
        builder = builder.with_proxies(proxy_endpoints.iter().cloned());
    }
    if parse_bool(&disable_metrics_answer, false) {
        builder = builder.disable_metrics();
    }
    if parse_bool(&disable_performance_answer, false) {
        builder = builder.disable_performance_monitoring();
    }
    if parse_bool(&disable_tls_answer, false) {
        builder = builder.disable_tls_fingerprinting();
    }
    if parse_bool(&disable_anti_detection_answer, false) {
        builder = builder.disable_anti_detection();
    }
    if parse_bool(&disable_spoofing_answer, false) {
        builder = builder.disable_spoofing();
    }
    if parse_bool(&disable_adaptive_answer, false) {
        builder = builder.disable_adaptive_timing();
    }
    if parse_bool(&disable_ml_answer, false) {
        builder = builder.disable_ml_optimization();
    }

    let scraper = builder.build()?;
    let runtime = Runtime::new()?;

    println!("\nFetching {}...", target_url);
    let response = runtime.block_on(scraper.get(&target_url))?;
    println!("Status: {}", response.status());
    println!("Final URL: {}", response.url());
    println!("Headers received: {}", response.headers().len());

    let body_future = response.text();
    let body_preview = runtime.block_on(body_future)?;
    let snippet: String = body_preview.chars().take(400).collect();
    println!("Body preview (first 400 chars):\n{}\n", snippet);

    exercise_supporting_modules(&domain)?;

    println!("Interactive test complete. Re-run with different inputs as needed.");
    Ok(())
}

fn exercise_supporting_modules(domain: &str) -> Result<(), Box<dyn Error>> {
    println!("\n--- Exercising supporting modules ---");

    let mut proxy_manager = ProxyManager::new(ProxyConfig {
        rotation_strategy: RotationStrategy::Smart,
        ban_time: Duration::from_secs(90),
        failure_threshold: 1,
        cooldown: Duration::from_secs(20),
    });
    proxy_manager.load(["http://127.0.0.1:8080", "http://127.0.0.1:9090"]);
    if let Some(proxy) = proxy_manager.next_proxy() {
        proxy_manager.report_failure(&proxy);
    }
    let proxy_health = proxy_manager.health_report();
    println!(
        "Proxy pool -> total: {}, banned: {}",
        proxy_health.total_proxies, proxy_health.banned_proxies
    );

    let mut tls_manager = DefaultTLSManager::new(TLSConfig {
        rotate_ja3: true,
        rotate_ciphers: true,
        preferred_browser: BrowserType::Firefox,
        rotation_interval: 2,
    });
    let tls_profile = tls_manager.current_profile(domain);
    println!("TLS profile for {} -> {:?}", domain, tls_profile.browser);

    let state_manager = StateManager::new();
    state_manager.mark_request(domain);
    state_manager.record_failure(domain, "simulated failure for demo");
    state_manager.record_success(domain);
    if let Some(state) = state_manager.get(domain) {
        println!(
            "State snapshot -> success_streak: {}, failure_streak: {}",
            state.success_streak, state.failure_streak
        );
    }

    let mut anti_detection = DefaultAntiDetection::new(AntiDetectionConfig::default());
    let mut ctx =
        AntiDetectionContext::new(Url::parse(&format!("https://{}", domain))?, Method::GET);
    ctx.set_body_size(512);
    ctx.set_user_agent("InteractiveTest/1.0");
    anti_detection.prepare_request(domain, &mut ctx);
    anti_detection.record_response(domain, 429, Duration::from_millis(750));
    if let Some(delay) = ctx.delay_hint() {
        println!("Anti-detection delay hint: {:?}", delay);
    }

    let mut timing = DefaultAdaptiveTiming::new();
    timing.set_behavior_profile(BehaviorProfile::Focused);
    let request = TimingRequest::new(RequestKind::Get, 2048);
    let delay = timing.calculate_delay(domain, &request);
    timing.record_outcome(
        domain,
        &TimingOutcome {
            success: true,
            response_time: Duration::from_secs_f32(1.3),
            applied_delay: delay,
        },
    );
    if let Some(snapshot) = timing.snapshot(domain) {
        println!(
            "Adaptive timing snapshot -> success_rate: {:.2}, avg_response: {:.2}s",
            snapshot.success_rate,
            snapshot.average_response_time.as_secs_f32()
        );
    }

    let mut optimizer = MLOptimizer::new(MLConfig {
        window_size: 5,
        learning_rate: 0.25,
        min_samples: 1,
        exploration_chance: 0.0,
    });
    let mut features: FeatureVector = HashMap::new();
    features.insert("latency_ms".into(), 320.0);
    features.insert("challenge_score".into(), 0.8);
    optimizer.record_attempt(domain, features, true, Some(1.1));
    if let Some(StrategyRecommendation {
        confidence,
        suggested_delay,
        ..
    }) = optimizer.recommend(domain)
    {
        println!(
            "ML recommendation -> confidence: {:.2}, delay: {:?}",
            confidence, suggested_delay
        );
    }

    println!("--- Module exercise complete ---\n");
    Ok(())
}
