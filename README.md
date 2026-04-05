# cloudscraper-rs

A Cloudflare challenge solver that reimagines the Python `cloudscraper` ethos in Rust.

> **Status:** This crate is still early-stage. Expect sharp edges, missing features, and ecosystem gaps while the Rust tooling for advanced bypass work catches up. Contributions and bug reports are welcome.

## Quick Start

```rust
use cloudscraper_rs::CloudScraper;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scraper = CloudScraper::new()?;
    let response = scraper.get("https://example.com").await?;
    let html = response.text().await?;
    
    println!("Success! Got {} bytes", html.len());
    Ok(())
}
```

## Installation

```toml
[dependencies]
cloudscraper-rs = "0.2"
tokio = { version = "1.0", features = ["full"] }
```

## Configuration

```rust
use cloudscraper_rs::UserAgentOptions;

let ua_opts = UserAgentOptions {
    desktop: false,
    mobile: true,
    ..Default::default()
};

let scraper = CloudScraper::builder()
    .with_max_challenge_attempts(5)     // Retry budget for the pipeline
    .with_user_agent_options(ua_opts)   // Customise UA/platform selection
    .with_proxies(["http://127.0.0.1:8888"]) // Optional proxy pool
    .disable_adaptive_timing()              // Toggle subsystems as needed
    .disable_ml_optimization()
    .build()?;
```

See `cloudscraper.rs` for additional builder toggles (custom captcha provider, TLS config, spoofing consistency, etc.).

## Supported Challenges

- ✅ Cloudflare v1 (IUAM)
- ✅ Cloudflare v2 (JavaScript + captcha)
- ✅ Cloudflare v3 (Managed JS VM)
- ✅ Cloudflare Turnstile
- ✅ Access Denied / Bot Management mitigations
- ✅ Rate limiting guidance
- ⚠️ Headless browser fallback (planned)

## Architecture

```
CloudScraper
├─ Reqwest client pool (shared cookie jar, proxy aware)
├─ Challenge pipeline
│  ├─ detectors → pattern scoring / adaptive learning
│  ├─ solvers   → javascript_v1/v2, managed_v3, turnstile, rate_limit, access_denied, bot_management
│  └─ mitigation planner → retries, proxy hints, wait suggestions
├─ Adaptive modules
│  ├─ anti_detection  (header randomisation & cooldowns)
│  ├─ adaptive_timing (behavioural delays)
│  ├─ spoofing        (consistent fingerprints & UAs)
│  ├─ tls             (JA3 / cipher rotation)
│  ├─ metrics/events  (telemetry + logging hooks)
│  └─ ml optimisation (feature scoring)
└─ State manager (per-domain history, error tracking)
```

**Flow:** `request()` → prepare headers/timing → fetch → detector identifies challenge → solver produces submission or mitigation → retry with solved tokens.

## TODO

- [ ] Ship optional headless fallback integration
- [ ] Expand captcha provider catalogue
- [ ] Persist state/metrics for long-running bots
- [ ] Add first-class CLI / interactive probe tool
- [ ] Harden JavaScript VM sandboxing further


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the Python [cloudscraper](https://github.com/zinzied/cloudscraper) library

## Disclaimer

This library is for educational purposes only. Please respect website terms of service and robots.txt files. The authors are not responsible for misuse of this software.

---
