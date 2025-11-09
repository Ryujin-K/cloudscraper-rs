//! Solver for Cloudflare Managed Challenge v3.
//!
//! Executes the embedded JavaScript VM payload and applies fallback strategies
//! when full execution is not possible.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use html_escape::decode_html_entities;
use once_cell::sync::Lazy;
use rand::Rng;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::challenges::core::{
    ChallengeExecutionError, ChallengeHttpClient, ChallengeHttpResponse, ChallengeResponse,
    ChallengeSubmission, OriginalRequest, execute_challenge_submission, is_cloudflare_response,
    origin_from_url,
};
use crate::external_deps::interpreters::{InterpreterError, JavascriptInterpreter};

use super::ChallengeSolver;

const DEFAULT_DELAY_MIN_SECS: f32 = 1.0;
const DEFAULT_DELAY_MAX_SECS: f32 = 5.0;

/// Cloudflare Managed v3/V3 JavaScript challenge solver.
pub struct ManagedV3Solver {
    interpreter: Arc<dyn JavascriptInterpreter>,
    delay_min: Duration,
    delay_max: Duration,
}

impl ManagedV3Solver {
    pub fn new(interpreter: Arc<dyn JavascriptInterpreter>) -> Self {
        Self {
            interpreter,
            delay_min: Duration::from_secs_f32(DEFAULT_DELAY_MIN_SECS),
            delay_max: Duration::from_secs_f32(DEFAULT_DELAY_MAX_SECS),
        }
    }

    pub fn with_delay_range(mut self, min: Duration, max: Duration) -> Self {
        self.delay_min = min;
        self.delay_max = if max < min { min } else { max };
        self
    }

    pub fn is_challenge(response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && matches!(response.status, 403 | 429 | 503)
            && (V3_PLATFORM_RE.is_match(response.body)
                || V3_CONTEXT_RE.is_match(response.body)
                || V3_FORM_RE.is_match(response.body))
    }

    pub fn solve(
        &self,
        response: &ChallengeResponse<'_>,
    ) -> Result<ChallengeSubmission, ManagedV3Error> {
        if !Self::is_challenge(response) {
            return Err(ManagedV3Error::NotV3Challenge);
        }

        let info = Self::extract_challenge_info(response.body)?;
        let host = response
            .url
            .host_str()
            .ok_or(ManagedV3Error::MissingHost)?
            .to_string();

        let challenge_answer = match info.vm_script {
            Some(ref script) => self.execute_vm(&info, script, &host).unwrap_or_else(|err| {
                log::warn!("Managed v3 VM execution failed: {err}; using fallback");
                Self::fallback_answer(&info)
            }),
            None => Self::fallback_answer(&info),
        };

        let payload = Self::generate_payload(response.body, &challenge_answer)?;
        self.build_submission(response, &info.form_action, payload)
    }

    pub async fn solve_and_submit(
        &self,
        client: Arc<dyn ChallengeHttpClient>,
        response: &ChallengeResponse<'_>,
        original_request: OriginalRequest,
    ) -> Result<ChallengeHttpResponse, ManagedV3Error> {
        let submission = self.solve(response)?;
        execute_challenge_submission(client, submission, original_request)
            .await
            .map_err(ManagedV3Error::Submission)
    }

    fn execute_vm(
        &self,
        info: &ChallengeInfo,
        vm_script: &str,
        host: &str,
    ) -> Result<String, ManagedV3Error> {
        let ctx_json = serde_json::to_string(&info.ctx_data).unwrap_or_else(|_| "{}".into());
        let opt_json = serde_json::to_string(&info.opt_data).unwrap_or_else(|_| "{}".into());

        let script = format!(
            r#"
            var window = {{
                location: {{
                    href: 'https://{host}/',
                    hostname: '{host}',
                    protocol: 'https:',
                    pathname: '/'
                }},
                navigator: {{
                    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    platform: 'Win32',
                    language: 'en-US'
                }},
                document: {{
                    getElementById: function() {{ return {{ value: '', style: {{}} }}; }},
                    createElement: function() {{ return {{ firstChild: {{ href: 'https://{host}/' }}, style: {{}} }}; }}
                }},
                _cf_chl_ctx: {ctx},
                _cf_chl_opt: {opt},
                _cf_chl_enter: function() {{ return true; }}
            }};
            window.self = window;
            window.top = window;
            window.parent = window;
            window.setTimeout = window.setTimeout || function(fn) {{ return fn(); }};
            window.clearTimeout = window.clearTimeout || function() {{ return true; }};
            window.addEventListener = window.addEventListener || function() {{ return true; }};
            var document = window.document;
            var navigator = window.navigator;
            var location = window.location;
            var _cf_chl_ctx = window._cf_chl_ctx;
            var _cf_chl_opt = window._cf_chl_opt;
            {vm_script}
            if (typeof window._cf_chl_answer !== 'undefined') {{
                window._cf_chl_answer;
            }} else if (typeof _cf_chl_answer !== 'undefined') {{
                _cf_chl_answer;
            }} else {{
                Math.random().toString(36).substring(2, 15);
            }}
            "#,
            host = host,
            ctx = ctx_json,
            opt = opt_json,
            vm_script = vm_script
        );

        self.interpreter
            .execute(&script, host)
            .map_err(ManagedV3Error::Interpreter)
            .map(|answer| answer.trim().to_string())
    }

    fn fallback_answer(info: &ChallengeInfo) -> String {
        if let Some(page_data) = info.opt_data.chl_page_data.as_ref() {
            return (hash_str(page_data) % 1_000_000).to_string();
        }
        if let Some(cv_id) = info.ctx_data.cv_id.as_ref() {
            return (hash_str(cv_id) % 1_000_000).to_string();
        }
        rand::thread_rng().gen_range(100_000..=999_999).to_string()
    }

    fn build_submission(
        &self,
        response: &ChallengeResponse<'_>,
        form_action: &str,
        mut payload: HashMap<String, String>,
    ) -> Result<ChallengeSubmission, ManagedV3Error> {
        let form_action = decode_html_entities(form_action).into_owned();
        let target_url = response
            .url
            .join(&form_action)
            .map_err(|err| ManagedV3Error::InvalidFormAction(form_action.clone(), err))?;

        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        headers.insert("Referer".into(), response.url.as_str().to_string());
        headers.insert("Origin".into(), origin_from_url(response.url));

        let wait = self.random_delay();
        payload.entry("jschl_answer".into()).or_default();
        payload.entry("cf_captcha_token".into()).or_default();

        Ok(ChallengeSubmission::new(
            http::Method::POST,
            target_url,
            payload,
            headers,
            wait,
        ))
    }

    fn random_delay(&self) -> Duration {
        if self.delay_max <= self.delay_min {
            return self.delay_min;
        }
        let mut rng = rand::thread_rng();
        let min = self.delay_min.as_secs_f32();
        let max = self.delay_max.as_secs_f32();
        Duration::from_secs_f32(rng.gen_range(min..max))
    }

    fn extract_challenge_info(body: &str) -> Result<ChallengeInfo, ManagedV3Error> {
        let ctx_data = Self::extract_json_block(body, "window._cf_chl_ctx")?
            .map(|json| serde_json::from_str::<ChallengeJson>(&json))
            .transpose()
            .map_err(ManagedV3Error::JsonParse)?
            .unwrap_or_default();
        let opt_data = Self::extract_json_block(body, "window._cf_chl_opt")?
            .map(|json| serde_json::from_str::<ChallengeJson>(&json))
            .transpose()
            .map_err(ManagedV3Error::JsonParse)?
            .unwrap_or_default();
        let form_action = V3_FORM_RE
            .captures(body)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or(ManagedV3Error::FormActionMissing)?;
        let vm_script = Self::extract_vm_script(body);

        Ok(ChallengeInfo {
            ctx_data,
            opt_data,
            form_action,
            vm_script,
        })
    }

    fn extract_json_block(body: &str, marker: &str) -> Result<Option<String>, ManagedV3Error> {
        let start = match body.find(marker) {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let brace_start = match body[start..].find('{') {
            Some(offset) => start + offset,
            None => return Ok(None),
        };

        let mut depth = 0_i32;
        let mut in_string = false;
        let mut escape = false;

        for (offset, ch) in body[brace_start..].char_indices() {
            if in_string {
                if escape {
                    escape = false;
                    continue;
                }

                match ch {
                    '\\' => {
                        escape = true;
                    }
                    '"' => {
                        in_string = false;
                    }
                    _ => {}
                }
                continue;
            }

            match ch {
                '{' => {
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        let end = brace_start + offset;
                        return Ok(Some(body[brace_start..=end].to_string()));
                    }
                }
                '"' => {
                    in_string = true;
                }
                _ => {}
            }
        }

        Err(ManagedV3Error::JsonExtractionFailed(marker.to_string()))
    }

    fn extract_vm_script(body: &str) -> Option<String> {
        let enter_idx = body.find("window._cf_chl_enter")?;
        let script_open = body[..enter_idx].rfind("<script")?;
        let content_start = body[script_open..].find('>')? + script_open + 1;
        let script_close = body[enter_idx..].find("</script>")? + enter_idx;
        Some(body[content_start..script_close].trim().to_string())
    }

    fn generate_payload(
        body: &str,
        answer: &str,
    ) -> Result<HashMap<String, String>, ManagedV3Error> {
        let r_token = R_TOKEN_RE
            .captures(body)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or(ManagedV3Error::MissingToken("r"))?;

        let mut payload = HashMap::new();
        payload.insert("r".into(), r_token);
        payload.insert("jschl_answer".into(), answer.to_string());

        for caps in INPUT_FIELD_RE.captures_iter(body) {
            if let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) {
                let key = name.as_str();
                if key != "jschl_answer" && !payload.contains_key(key) {
                    payload.insert(key.to_string(), value.as_str().to_string());
                }
            }
        }

        Ok(payload)
    }
}

impl ChallengeSolver for ManagedV3Solver {
    fn name(&self) -> &'static str {
        "managed_v3"
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct ChallengeJson {
    #[serde(rename = "cvId")]
    cv_id: Option<String>,
    #[serde(rename = "chlPageData")]
    chl_page_data: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Value,
}

struct ChallengeInfo {
    ctx_data: ChallengeJson,
    opt_data: ChallengeJson,
    form_action: String,
    vm_script: Option<String>,
}

#[derive(Debug, Error)]
pub enum ManagedV3Error {
    #[error("response is not a Cloudflare v3 challenge")]
    NotV3Challenge,
    #[error("missing host in challenge URL")]
    MissingHost,
    #[error("challenge form action missing")]
    FormActionMissing,
    #[error("missing token '{0}' in challenge page")]
    MissingToken(&'static str),
    #[error("invalid form action '{0}': {1}")]
    InvalidFormAction(String, url::ParseError),
    #[error("javascript interpreter error: {0}")]
    Interpreter(#[source] InterpreterError),
    #[error("challenge submission failed: {0}")]
    Submission(#[source] ChallengeExecutionError),
    #[error("json parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("failed to extract JSON block for marker '{0}'")]
    JsonExtractionFailed(String),
}

static V3_PLATFORM_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"cpo\.src\s*=\s*['"]/cdn-cgi/challenge-platform/\S+orchestrate/jsch/v3"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid v3 platform regex")
});

static V3_CONTEXT_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"window\._cf_chl_ctx\s*=")
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid v3 context regex")
});

static V3_FORM_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r#"<form[^>]*id=['"]challenge-form['"][^>]*action=['"]([^'"]*__cf_chl_rt_tk=[^'"]*)['"]"#,
    )
    .case_insensitive(true)
    .dot_matches_new_line(true)
    .build()
    .expect("invalid v3 form regex")
});

static R_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"name=['"]r['"]\s+value=['"]([^'"]+)['"]"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid v3 r token regex")
});

static INPUT_FIELD_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"<input[^>]*name=['"]([^'"]+)['"][^>]*value=['"]([^'"]*)['"]"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid v3 input regex")
});

fn hash_str(input: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, Method, header::SERVER};
    use url::Url;

    struct ResponseFixture {
        url: Url,
        headers: HeaderMap,
        method: Method,
        body: String,
        status: u16,
    }

    impl ResponseFixture {
        fn new(body: &str, status: u16) -> Self {
            let mut headers = HeaderMap::new();
            headers.insert(SERVER, "cloudflare".parse().unwrap());
            Self {
                url: Url::parse("https://example.com/").unwrap(),
                headers,
                method: Method::GET,
                body: body.to_string(),
                status,
            }
        }

        fn response(&self) -> ChallengeResponse<'_> {
            ChallengeResponse {
                url: &self.url,
                status: self.status,
                headers: &self.headers,
                body: &self.body,
                request_method: &self.method,
            }
        }
    }

    struct StubInterpreter;

    impl JavascriptInterpreter for StubInterpreter {
        fn solve_challenge(
            &self,
            _page_html: &str,
            _host: &str,
        ) -> Result<String, InterpreterError> {
            Ok("stub".into())
        }

        fn execute(&self, script: &str, _host: &str) -> Result<String, InterpreterError> {
            if script.contains("_cf_chl_answer") {
                Ok("987654".into())
            } else {
                Err(InterpreterError::Execution("missing answer".into()))
            }
        }
    }

    fn sample_html(with_vm: bool) -> String {
        let vm = if with_vm {
            "<script>window._cf_chl_enter=function(){return true;};window._cf_chl_answer='123456';</script>"
        } else {
            ""
        };

        format!(
            r#"
            <html>
              <head>
                <script>window._cf_chl_ctx={{"cvId":"cv123"}};</script>
                <script>window._cf_chl_opt={{"chlPageData":"page-data"}};</script>
              </head>
              <body>
                <script>var cpo={{}};cpo.src="/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v3";</script>
                <form id="challenge-form" action="/cdn-cgi/challenge-platform/h/b/orchestrate/form?__cf_chl_rt_tk=foo" method="POST">
                  <input type="hidden" name="r" value="token-r"/>
                  <input type="hidden" name="cf_chl_seq_i" value="1"/>
                </form>
                {vm}
              </body>
            </html>
        "#,
            vm = vm
        )
    }

    #[test]
    fn solve_uses_vm_answer() {
        let html = sample_html(true);
        let fixture = ResponseFixture::new(&html, 403);
        let solver = ManagedV3Solver::new(Arc::new(StubInterpreter));
        assert!(ManagedV3Solver::is_challenge(&fixture.response()));
        let submission = solver.solve(&fixture.response()).expect("should solve");
        assert_eq!(
            submission.form_fields.get("jschl_answer"),
            Some(&"987654".to_string())
        );
    }

    #[test]
    fn fallback_when_no_vm() {
        let html = sample_html(false);
        let fixture = ResponseFixture::new(&html, 403);
        let solver = ManagedV3Solver::new(Arc::new(StubInterpreter));
        let submission = solver.solve(&fixture.response()).expect("fallback works");
        assert!(submission.form_fields.contains_key("jschl_answer"));
    }
}
