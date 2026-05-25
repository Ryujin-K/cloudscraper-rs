//! Challenge page parsing helpers and utilities.
//!
//! Provides the building blocks needed to inspect Cloudflare challenge HTML and
//! extract the parameters required by the solvers.

use http::header::SERVER;
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};
use thiserror::Error;
use url::Url;

use super::types::{ChallengeResponse, ChallengeSubmission};

/// Minimal snapshot of the IUAM challenge form used by solvers.
#[derive(Debug, Clone)]
pub struct IuamChallengeBlueprint {
    pub action: String,
    pub hidden_fields: Vec<(String, String)>,
}

impl IuamChallengeBlueprint {
    pub fn to_submission(
        self,
        base_url: &Url,
        mut payload: Vec<(String, String)>,
    ) -> Result<ChallengeSubmission, ChallengeParseError> {
        payload.extend(self.hidden_fields);
        let form_fields = payload
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();

        let submit_url = base_url
            .join(&self.action)
            .map_err(ChallengeParseError::InvalidAction)?;

        Ok(ChallengeSubmission::new(
            http::Method::POST,
            submit_url,
            form_fields,
            Default::default(),
            std::time::Duration::from_secs(0),
        ))
    }
}

/// Outcomes when parsing a Cloudflare challenge fails.
#[derive(Debug, Error)]
pub enum ChallengeParseError {
    #[error("response is not a Cloudflare challenge")]
    NotCloudflare,
    #[error("unable to locate challenge form")]
    FormNotFound,
    #[error("missing required hidden field: {0}")]
    MissingField(&'static str),
    #[error("invalid challenge action: {0}")]
    InvalidAction(url::ParseError),
}

/// Extract IUAM challenge blueprint (action + hidden fields) from HTML body.
pub fn parse_iuam_challenge(
    response: &ChallengeResponse<'_>,
) -> Result<IuamChallengeBlueprint, ChallengeParseError> {
    if !is_cloudflare_response(response) {
        return Err(ChallengeParseError::NotCloudflare);
    }

    let captures = IUAM_FORM_RE
        .captures(response.body)
        .ok_or(ChallengeParseError::FormNotFound)?;

    let action = captures
        .name("action")
        .map(|m| html_escape::decode_html_entities(m.as_str()).to_string())
        .ok_or(ChallengeParseError::FormNotFound)?;

    let inputs = captures.name("inputs").map(|m| m.as_str()).unwrap_or("");
    let hidden_fields = extract_hidden_fields(inputs)?;

    Ok(IuamChallengeBlueprint {
        action,
        hidden_fields,
    })
}

fn extract_hidden_fields(fragment: &str) -> Result<Vec<(String, String)>, ChallengeParseError> {
    static INPUT_RE: Lazy<Regex> = Lazy::new(|| {
        RegexBuilder::new(r#"(?si)<input\s+([^>]+?)/?>"#)
            .case_insensitive(true)
            .dot_matches_new_line(true)
            .build()
            .unwrap()
    });
    static ATTR_RE: Lazy<Regex> = Lazy::new(|| {
        RegexBuilder::new(r#"(?si)(?P<name>[^\s=]+)=['"](?P<value>[^'"]*)['"]"#)
            .case_insensitive(true)
            .build()
            .unwrap()
    });

    let mut payload = Vec::new();

    for caps in INPUT_RE.captures_iter(fragment) {
        let attributes = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let mut field_name: Option<String> = None;
        let mut field_value: Option<String> = None;

        for attr_caps in ATTR_RE.captures_iter(attributes) {
            if let (Some(name), Some(value)) = (attr_caps.name("name"), attr_caps.name("value")) {
                match name.as_str().to_ascii_lowercase().as_str() {
                    "name" => field_name = Some(value.as_str().to_string()),
                    "value" => field_value = Some(value.as_str().to_string()),
                    _ => {}
                }
            }
        }

        if let (Some(name), Some(value)) = (field_name, field_value)
            && matches!(name.as_str(), "r" | "jschl_vc" | "pass")
        {
            payload.push((name, value));
        }
    }

    for key in ["r", "jschl_vc", "pass"] {
        if !payload.iter().any(|(name, _)| name == key) {
            return Err(ChallengeParseError::MissingField(key));
        }
    }

    Ok(payload)
}

/// Detect whether the response is served by Cloudflare.
///
/// Modern challenges are not always served with `Server: cloudflare` visible to
/// the client, so this also checks edge headers (`cf-ray`, `cf-mitigated`) and,
/// as a last resort, body fingerprints (`/cdn-cgi/`). This breadth is what lets
/// the detector recognise newer flows such as `orchestrate/chl_page/v1`.
pub fn is_cloudflare_response(response: &ChallengeResponse<'_>) -> bool {
    let server_is_cf = response
        .headers
        .get(SERVER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().starts_with("cloudflare"))
        .unwrap_or(false);

    if server_is_cf
        || response.headers.contains_key("cf-ray")
        || response.headers.contains_key("cf-mitigated")
    {
        return true;
    }

    let body = response.body;
    body.contains("/cdn-cgi/") || body.contains("cloudflare") || body.contains("Cloudflare")
}

/// Build origin header value from URL (`scheme://host[:port]`).
pub fn origin_from_url(url: &Url) -> String {
    let mut origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    origin
}

static IUAM_FORM_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r#"(?si)<form[^>]*id=['"]challenge-form['"][^>]*action=['"](?P<action>[^"']*__cf_chl_f_tk=[^"']+)['"][^>]*>(?P<inputs>.*?)</form>"#,
    )
    .case_insensitive(true)
    .dot_matches_new_line(true)
    .build()
    .unwrap()
});
