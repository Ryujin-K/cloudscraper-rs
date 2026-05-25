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

The user-agent dataset (`browsers.json`) is **embedded in the crate**, so it works
out of the box with no extra files. To ship a customised dataset, point the
`CLOUDSCRAPER_BROWSERS_JSON` environment variable at your own file (or place a
`browsers.json` in the working directory); it takes precedence over the embedded
one.

### Cargo features

| Feature   | Default | Description |
|-----------|---------|-------------|
| `browser` | off     | Headless-browser fallback for interactive challenges (`orchestrate/chl_page`). Pulls in `headless_chrome` and needs a Chrome/Chromium binary at runtime. |
| `full`    | off     | Enables all optional features (currently `browser`). |

```toml
[dependencies]
cloudscraper-rs = { version = "0.2", features = ["browser"] }
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

## Cookies

A single cookie jar is shared across the request client and the challenge client,
so tokens issued while solving (e.g. `cf_clearance`) persist and stay readable:

```rust
use url::Url;

let url = Url::parse("https://example.com")?;
let _ = scraper.get(url.as_str()).await?;

// Read the full accumulated jar for a domain.
for cookie in scraper.cookies(&url) {
    println!("{}={}", cookie.name(), cookie.value());
}

// Seed a pre-obtained token.
scraper.set_cookie(&url, "cf_clearance=...; Domain=example.com; Path=/");
```

`ScraperResponse::cookies()` returns only the `Set-Cookie` headers of that single
response; `CloudScraper::cookies(&url)` returns the full jar.

## Headless browser fallback

Modern interactive challenges (`orchestrate/chl_page/v1`) require executing
Cloudflare's browser VM, which the in-process JS interpreter cannot do. With the
`browser` feature, an opt-in headless-Chrome fallback clears them: it runs through
the same proxy and User-Agent, harvests `cf_clearance` into the shared jar, and
retries the original request.

```rust
// Requires `features = ["browser"]` and a Chrome/Chromium binary.
let scraper = CloudScraper::builder()
    .enable_headless_browser()
    .build()?;

let response = scraper.get("https://protected.example").await?;
```

You can also plug in a custom implementation via
`.with_browser_solver(Arc<dyn BrowserChallengeSolver>)`. See
[`examples/headless.rs`](examples/headless.rs):

```bash
cargo run --example headless --features browser -- https://example.com
```

Without a configured solver, an interactive challenge surfaces as
`CloudScraperError::Unsupported` (rather than a silent `403`), so callers can
detect and handle it explicitly.

## Supported Challenges

- ✅ Cloudflare v1 (IUAM)
- ✅ Cloudflare v2 (JavaScript + captcha)
- ✅ Cloudflare v3 (Managed JS VM)
- ✅ Cloudflare Turnstile
- ✅ Access Denied / Bot Management mitigations
- ✅ Rate limiting guidance
- ✅ Managed interactive challenge (`orchestrate/chl_page`) — detection built in; solving via the `browser` feature
- ⚠️ Real TLS/JA3 impersonation (planned; `reqwest`/`native-tls` cannot yet emit custom fingerprints)

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

- [x] Ship optional headless fallback integration (`browser` feature)
- [ ] Real TLS/JA3 impersonation (pluggable transport)
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
