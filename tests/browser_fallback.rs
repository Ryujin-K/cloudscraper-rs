//! Integration test for the headless-browser fallback wiring.
//!
//! Verifies the end-to-end orchestration without a real browser: a mock
//! [`BrowserChallengeSolver`] stands in for headless Chrome, and a tiny local
//! HTTP server serves an interactive Cloudflare challenge (`chl_page`) on the
//! first request and a clear page on the retry. The test asserts the fallback
//! runs once and the original request is transparently retried to success.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use async_trait::async_trait;
use cloudscraper_rs::{
    BrowserChallengeSolver, BrowserSolveError, BrowserSolveOutcome, BrowserSolveRequest,
    CloudScraper, SolvedCookie,
};

/// Trimmed modern managed challenge (orchestrate/chl_page/v1, no form).
const CHALLENGE_BODY: &str = r#"<!DOCTYPE html><html><head><title>Just a moment...</title></head>
<body><script>window._cf_chl_opt = {cvId:'3',cType:'managed'};
var a=document.createElement('script');
a.src='/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1?ray=abc';</script></body></html>"#;

const CLEAR_BODY: &str = "<html><body>cleared content</body></html>";

/// Mock browser solver: records invocations and returns a cf_clearance cookie.
struct MockBrowserSolver {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl BrowserChallengeSolver for MockBrowserSolver {
    async fn solve(
        &self,
        request: BrowserSolveRequest<'_>,
    ) -> Result<BrowserSolveOutcome, BrowserSolveError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let host = request.url.host_str().unwrap_or("localhost").to_string();
        Ok(BrowserSolveOutcome {
            cookies: vec![SolvedCookie {
                name: "cf_clearance".into(),
                value: "mock-token".into(),
                domain: host,
                path: "/".into(),
                secure: false,
            }],
            final_url: request.url.clone(),
            html: String::new(),
            user_agent: request.user_agent.map(str::to_owned),
        })
    }
}

/// Serves a Cloudflare challenge first, then a clear 200 page. Each response
/// closes its connection so request boundaries are unambiguous.
fn spawn_challenge_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    thread::spawn(move || {
        for (served, stream) in listener.incoming().enumerate() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf); // consume request headers; content ignored

            let response = if served == 0 {
                format!(
                    "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    CHALLENGE_BODY.len(),
                    CHALLENGE_BODY
                )
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    CLEAR_BODY.len(),
                    CLEAR_BODY
                )
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    format!("http://{addr}/")
}

#[tokio::test]
async fn browser_fallback_clears_challenge_and_retries() {
    let calls = Arc::new(AtomicUsize::new(0));
    let solver = Arc::new(MockBrowserSolver {
        calls: calls.clone(),
    });
    let url = spawn_challenge_server();

    let scraper = CloudScraper::builder()
        .with_browser_solver(solver)
        .disable_adaptive_timing() // keep the test fast and deterministic
        .build()
        .expect("scraper builds");

    let response = scraper
        .get(&url)
        .await
        .expect("request should succeed after the browser fallback retries it");

    assert_eq!(response.status(), 200, "retry should return the clear page");
    let body = response.text().await.expect("utf-8 body");
    assert!(
        body.contains("cleared content"),
        "expected the cleared page, got: {body}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "browser fallback should be invoked exactly once"
    );
}

#[tokio::test]
async fn interactive_challenge_without_solver_is_unsupported() {
    // Same challenge, but no browser solver configured: the caller gets a clear
    // Unsupported error instead of a silent 403.
    let url = spawn_challenge_server();

    let scraper = CloudScraper::builder()
        .disable_adaptive_timing()
        .build()
        .expect("scraper builds");

    let err = scraper
        .get(&url)
        .await
        .expect_err("interactive challenge without a browser solver should error");

    assert!(
        err.to_string().contains("browser_fallback"),
        "error should point at the missing browser fallback, got: {err}"
    );
}
