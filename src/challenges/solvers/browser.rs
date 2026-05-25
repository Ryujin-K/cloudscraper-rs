//! Headless-browser fallback for interactive Cloudflare challenges.
//!
//! Some modern challenges (e.g. `orchestrate/chl_page/v1`, detected as
//! [`ChallengeType::ManagedInteractive`]) require executing Cloudflare's browser
//! VM, which the in-process JavaScript interpreter cannot do. This module defines
//! a transport-agnostic [`BrowserChallengeSolver`] trait whose job is to drive a
//! real browser until the challenge clears and return the resulting cookies
//! (notably `cf_clearance`) plus the rendered page.
//!
//! The concrete [`HeadlessChromeSolver`] is gated behind the `browser` cargo
//! feature so the default build stays free of the heavyweight `headless_chrome`
//! dependency. Callers can also supply their own implementation of the trait.
//!
//! [`ChallengeType::ManagedInteractive`]: crate::challenges::detectors::ChallengeType::ManagedInteractive

use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use url::Url;

/// Default per-challenge time budget for the browser to clear the page.
pub const DEFAULT_BROWSER_TIMEOUT: Duration = Duration::from_secs(30);

/// Inputs for a single browser-driven solve attempt.
///
/// The user-agent and proxy must match the HTTP client that will replay the
/// request afterwards: Cloudflare binds `cf_clearance` to the egress IP and
/// User-Agent, so a mismatch yields a token that is immediately re-challenged.
#[derive(Debug, Clone)]
pub struct BrowserSolveRequest<'a> {
    /// URL that returned the interactive challenge.
    pub url: &'a Url,
    /// User-Agent to emulate (should equal the one used on the retry).
    pub user_agent: Option<&'a str>,
    /// Upstream proxy the browser must egress through (e.g. `http://host:port`).
    pub proxy: Option<&'a str>,
    /// Maximum time to wait for the challenge to clear.
    pub timeout: Duration,
}

impl<'a> BrowserSolveRequest<'a> {
    /// Build a request with the default timeout.
    pub fn new(url: &'a Url) -> Self {
        Self {
            url,
            user_agent: None,
            proxy: None,
            timeout: DEFAULT_BROWSER_TIMEOUT,
        }
    }

    /// Set the User-Agent to emulate.
    pub fn with_user_agent(mut self, user_agent: Option<&'a str>) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Set the egress proxy.
    pub fn with_proxy(mut self, proxy: Option<&'a str>) -> Self {
        self.proxy = proxy;
        self
    }

    /// Set the solve timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// A cookie harvested from the browser after a successful solve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolvedCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
}

impl SolvedCookie {
    /// Render the cookie as a `Set-Cookie`-style string suitable for injecting
    /// into a cookie jar.
    pub fn to_set_cookie(&self) -> String {
        let domain = self.domain.trim_start_matches('.');
        let mut s = format!(
            "{}={}; Domain={}; Path={}",
            self.name, self.value, domain, self.path
        );
        if self.secure {
            s.push_str("; Secure");
        }
        s
    }

    /// A canonical `https://<domain>/` URL used as the reference when storing the
    /// cookie in a jar.
    pub fn reference_url(&self) -> Option<Url> {
        let domain = self.domain.trim_start_matches('.');
        Url::parse(&format!("https://{domain}/")).ok()
    }
}

/// Result of a browser-driven solve.
#[derive(Debug, Clone)]
pub struct BrowserSolveOutcome {
    /// Cookies present after the challenge cleared (includes `cf_clearance`).
    pub cookies: Vec<SolvedCookie>,
    /// Final URL after any in-challenge redirects.
    pub final_url: Url,
    /// Rendered page HTML at the end of the solve.
    pub html: String,
    /// User-Agent the browser actually used, if known.
    pub user_agent: Option<String>,
}

impl BrowserSolveOutcome {
    /// Whether a `cf_clearance` cookie was obtained.
    pub fn has_clearance(&self) -> bool {
        self.cookies.iter().any(|c| c.name == "cf_clearance")
    }
}

/// Errors surfaced by a browser solve attempt.
#[derive(Debug, Error)]
pub enum BrowserSolveError {
    #[error("failed to launch browser: {0}")]
    Launch(String),
    #[error("browser navigation failed: {0}")]
    Navigation(String),
    #[error("challenge did not clear within the timeout")]
    Timeout,
    #[error("browser interaction failed: {0}")]
    Interaction(String),
    #[error("browser task panicked or was cancelled: {0}")]
    Join(String),
}

/// Drives an out-of-process browser to clear an interactive challenge.
///
/// Implementations must egress through `request.proxy` and emulate
/// `request.user_agent` when provided, then return the resulting cookies.
#[async_trait]
pub trait BrowserChallengeSolver: Send + Sync {
    /// Solve the challenge at `request.url`, returning harvested cookies.
    async fn solve(
        &self,
        request: BrowserSolveRequest<'_>,
    ) -> Result<BrowserSolveOutcome, BrowserSolveError>;
}

/// Body markers that indicate a Cloudflare interstitial is still being shown.
/// Used to decide whether the browser has cleared the challenge yet.
#[cfg(any(feature = "browser", test))]
fn still_challenged(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "just a moment",
        "challenge-platform",
        "_cf_chl_opt",
        "cf_chl_opt",
        "cf-turnstile",
        "challenge-running",
    ];
    MARKERS.iter().any(|m| lower.contains(m))
}

#[cfg(feature = "browser")]
pub use headless::HeadlessChromeSolver;

#[cfg(feature = "browser")]
mod headless {
    use super::{
        BrowserChallengeSolver, BrowserSolveError, BrowserSolveOutcome, BrowserSolveRequest,
        SolvedCookie, still_challenged,
    };

    use std::ffi::OsString;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use headless_chrome::{Browser, LaunchOptions};
    use url::Url;

    /// How often to re-check whether the challenge has cleared.
    const POLL_INTERVAL: Duration = Duration::from_millis(500);

    /// Default [`BrowserChallengeSolver`] backed by `headless_chrome`.
    ///
    /// Each solve launches a fresh headless Chrome, navigates to the challenge
    /// URL, waits for Cloudflare's VM to resolve, and harvests the cookies.
    /// The `headless_chrome` API is synchronous, so the work runs inside
    /// [`tokio::task::spawn_blocking`].
    #[derive(Debug, Clone)]
    pub struct HeadlessChromeSolver {
        headless: bool,
    }

    impl Default for HeadlessChromeSolver {
        fn default() -> Self {
            Self { headless: true }
        }
    }

    impl HeadlessChromeSolver {
        /// Create a solver (headless by default).
        pub fn new() -> Self {
            Self::default()
        }

        /// Run with a visible browser window (useful for debugging).
        pub fn with_headful(mut self) -> Self {
            self.headless = false;
            self
        }

        fn solve_blocking(
            headless: bool,
            url: String,
            user_agent: Option<String>,
            proxy: Option<String>,
            timeout: Duration,
        ) -> Result<BrowserSolveOutcome, BrowserSolveError> {
            let mut args: Vec<OsString> = vec![
                OsString::from("--disable-blink-features=AutomationControlled"),
                OsString::from("--disable-gpu"),
                OsString::from("--no-sandbox"),
                OsString::from("--disable-dev-shm-usage"),
            ];
            if let Some(ref ua) = user_agent {
                args.push(OsString::from(format!("--user-agent={ua}")));
            }
            if let Some(ref endpoint) = proxy {
                args.push(OsString::from(format!("--proxy-server={endpoint}")));
            }

            let launch_options = LaunchOptions::default_builder()
                .headless(headless)
                .args(args.iter().map(|s| s.as_os_str()).collect())
                .build()
                .map_err(|e| BrowserSolveError::Launch(e.to_string()))?;

            let browser = Browser::new(launch_options)
                .map_err(|e| BrowserSolveError::Launch(e.to_string()))?;
            let tab = browser
                .new_tab()
                .map_err(|e| BrowserSolveError::Launch(e.to_string()))?;

            if let Some(ref ua) = user_agent {
                // Best-effort: align the JS-visible UA with the launch arg.
                let _ = tab.set_user_agent(ua, None, None);
            }

            tab.navigate_to(&url)
                .map_err(|e| BrowserSolveError::Navigation(e.to_string()))?;
            tab.wait_until_navigated()
                .map_err(|e| BrowserSolveError::Navigation(e.to_string()))?;

            // Poll until the interstitial disappears or the budget is spent.
            let deadline = Instant::now() + timeout;
            let mut cleared = false;
            loop {
                let body = tab.get_content().unwrap_or_default();
                if !still_challenged(&body) {
                    cleared = true;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(POLL_INTERVAL);
            }

            let cookies = tab
                .get_cookies()
                .map(|list| {
                    list.into_iter()
                        .map(|c| SolvedCookie {
                            name: c.name,
                            value: c.value,
                            domain: c.domain,
                            path: c.path,
                            secure: c.secure,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let html = tab.get_content().unwrap_or_default();
            let final_url = Url::parse(&tab.get_url())
                .or_else(|_| Url::parse(&url))
                .map_err(|e| BrowserSolveError::Navigation(e.to_string()))?;

            let has_clearance = cookies.iter().any(|c| c.name == "cf_clearance");
            if !cleared && !has_clearance {
                return Err(BrowserSolveError::Timeout);
            }

            Ok(BrowserSolveOutcome {
                cookies,
                final_url,
                html,
                user_agent,
            })
        }
    }

    #[async_trait]
    impl BrowserChallengeSolver for HeadlessChromeSolver {
        async fn solve(
            &self,
            request: BrowserSolveRequest<'_>,
        ) -> Result<BrowserSolveOutcome, BrowserSolveError> {
            // Own everything the blocking closure needs; the browser API is sync.
            let headless = self.headless;
            let url = request.url.to_string();
            let user_agent = request.user_agent.map(str::to_owned);
            let proxy = request.proxy.map(str::to_owned);
            let timeout = request.timeout;

            tokio::task::spawn_blocking(move || {
                Self::solve_blocking(headless, url, user_agent, proxy, timeout)
            })
            .await
            .map_err(|e| BrowserSolveError::Join(e.to_string()))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn still_challenged_detects_interstitial() {
        assert!(still_challenged("<title>Just a moment...</title>"));
        assert!(still_challenged("loading /cdn-cgi/challenge-platform/ ..."));
        assert!(!still_challenged("<html><body>real content</body></html>"));
    }

    #[test]
    fn solved_cookie_renders_set_cookie_string() {
        let cookie = SolvedCookie {
            name: "cf_clearance".into(),
            value: "abc123".into(),
            domain: ".example.com".into(),
            path: "/".into(),
            secure: true,
        };
        assert_eq!(
            cookie.to_set_cookie(),
            "cf_clearance=abc123; Domain=example.com; Path=/; Secure"
        );
        assert_eq!(
            cookie.reference_url().unwrap().as_str(),
            "https://example.com/"
        );
    }
}
