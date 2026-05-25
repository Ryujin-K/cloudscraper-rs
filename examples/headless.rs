//! Headless-browser fallback example.
//!
//! Demonstrates clearing an interactive Cloudflare challenge
//! (`orchestrate/chl_page/v1`) with the bundled `headless_chrome` solver, then
//! reading the resulting `cf_clearance` cookie.
//!
//! Requires the `browser` feature and a Chrome/Chromium binary on the host:
//!
//! ```bash
//! cargo run --example headless --features browser -- https://example.com
//! ```

use std::error::Error;

use cloudscraper_rs::CloudScraper;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com".to_string());

    // `enable_headless_browser()` installs the headless_chrome fallback. It only
    // fires when an interactive challenge is detected; ordinary pages and the
    // in-process JS solvers are unaffected.
    let scraper = CloudScraper::builder().enable_headless_browser().build()?;

    println!("Fetching {target} ...");
    let response = scraper.get(&target).await?;

    println!("Status : {}", response.status());
    println!("Final  : {}", response.url());
    println!("Body   : {} bytes", response.bytes().await.len());

    // Read the full cookie jar (includes cf_clearance harvested by the browser).
    let url = Url::parse(&target)?;
    let cookies = scraper.cookies(&url);
    if cookies.is_empty() {
        println!("Cookies: <none>");
    } else {
        println!("Cookies:");
        for cookie in cookies {
            println!("  - {}={}", cookie.name(), cookie.value());
        }
    }

    Ok(())
}
