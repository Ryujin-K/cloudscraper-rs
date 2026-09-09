//! User-Agent profile manager.
//!
//! Responsibilities:
//! - Load user-agent definitions (headers + cipher suites) from `browsers.json`.
//! - Provide filtered selections based on platform/browser/mobile flags.
//! - Allow custom overrides while falling back to sensible defaults.

use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;

/// User-agent dataset embedded at compile time.
///
/// Guarantees the crate works out of the box when consumed as a dependency: the
/// data ships inside the binary instead of being read from a path that only
/// exists in this repository. An on-disk dataset (see [`candidate_paths`]) still
/// takes precedence so callers can supply a customised `browsers.json`.
static EMBEDDED_BROWSERS_JSON: &str = include_str!("browsers.json");

/// Top level representation of `browsers.json`.
#[derive(Debug, Deserialize)]
struct UserAgentData {
    headers: HashMap<String, HeaderProfile>,
    #[serde(rename = "cipherSuite")]
    cipher_suites: HashMap<String, Vec<String>>,
    #[serde(rename = "user_agents")]
    user_agents: HashMap<DeviceKind, HashMap<String, HashMap<String, Vec<String>>>>,
}

#[derive(Debug, Deserialize, Clone)]
struct HeaderProfile {
    #[serde(rename = "User-Agent")]
    user_agent: Option<String>,
    #[serde(rename = "Accept")]
    accept: String,
    #[serde(rename = "Accept-Language")]
    accept_language: String,
    #[serde(rename = "Accept-Encoding")]
    accept_encoding: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Hash, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum DeviceKind {
    Desktop,
    Mobile,
}

/// Options to filter/select a profile.
#[derive(Debug, Clone)]
pub struct UserAgentOptions {
    pub custom: Option<String>,
    pub platform: Option<String>,
    pub browser: Option<String>,
    pub desktop: bool,
    pub mobile: bool,
    pub allow_brotli: bool,
}

impl Default for UserAgentOptions {
    fn default() -> Self {
        Self {
            custom: None,
            platform: None,
            browser: None,
            desktop: true,
            mobile: true,
            allow_brotli: false,
        }
    }
}

/// Final selected profile.
#[derive(Debug, Clone)]
pub struct UserAgentProfile {
    pub headers: HashMap<String, String>,
    pub cipher_suites: Vec<String>,
}

/// Provides user-agent profiles for challenge solvers.
#[derive(Debug)]
pub struct UserAgentManager {
    data: UserAgentData,
}

/// Global singleton loaded on demand.
///
/// Resolution order:
/// 1. An on-disk override (env var `CLOUDSCRAPER_BROWSERS_JSON`, then
///    `./browsers.json`) — lets callers ship a customised dataset.
/// 2. The dataset embedded at compile time, which is always available.
static USER_AGENT_MANAGER: Lazy<Result<UserAgentManager, UserAgentError>> = Lazy::new(|| {
    for path in candidate_paths() {
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let data =
                    parse_dataset(&contents).map_err(|source| UserAgentError::InvalidJson {
                        path: path.clone(),
                        source,
                    })?;
                return Ok(UserAgentManager { data });
            }
            // A missing override is expected; fall through to the next candidate.
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(UserAgentError::Io { path, source: err }),
        }
    }

    // Guaranteed fallback: the dataset compiled into the binary.
    let data = parse_dataset(EMBEDDED_BROWSERS_JSON).map_err(UserAgentError::InvalidEmbedded)?;
    Ok(UserAgentManager { data })
});

fn parse_dataset(contents: &str) -> Result<UserAgentData, serde_json::Error> {
    serde_json::from_str(contents)
}

/// Retrieve a profile using given options.
pub fn get_user_agent_profile(opts: UserAgentOptions) -> Result<UserAgentProfile, UserAgentError> {
    let manager = USER_AGENT_MANAGER
        .as_ref()
        .map_err(|err| UserAgentError::InitializationFailure(err.to_string()))?;
    manager.select_profile(opts)
}

fn permitted_device_kinds(opts: &UserAgentOptions) -> Vec<DeviceKind> {
    let mut kinds = Vec::new();
    if opts.desktop {
        kinds.push(DeviceKind::Desktop);
    }
    if opts.mobile {
        kinds.push(DeviceKind::Mobile);
    }
    kinds
}

impl UserAgentManager {
    fn select_profile(&self, opts: UserAgentOptions) -> Result<UserAgentProfile, UserAgentError> {
        if !opts.desktop && !opts.mobile {
            return Err(UserAgentError::InvalidOptions(
                "Desktop and mobile cannot both be disabled".into(),
            ));
        }

        if let Some(custom) = opts.custom {
            return self.custom_profile(custom);
        }

        let permitted_kinds = permitted_device_kinds(&opts);

        let platform = self.resolve_platform(&opts, &permitted_kinds)?;

        let filtered = self.collect_profiles(&permitted_kinds, &platform);

        if filtered.is_empty() {
            return Err(UserAgentError::ProfileNotFound);
        }

        let browser = match opts.browser {
            Some(browser) => {
                if !filtered.contains_key(&browser) {
                    return Err(UserAgentError::InvalidOptions(
                        format!("Browser '{browser}' not available for platform '{platform}'")
                            .into(),
                    ));
                }
                browser
            }
            None => {
                let browsers: Vec<String> = filtered.keys().cloned().collect();
                random_choice(&browsers)
            }
        };

        let agents = filtered
            .get(&browser)
            .ok_or(UserAgentError::ProfileNotFound)?;

        if agents.is_empty() {
            return Err(UserAgentError::ProfileNotFound);
        }

        let user_agent = random_choice(agents);
        let mut headers = self
            .data
            .headers
            .get(&browser)
            .cloned()
            .ok_or(UserAgentError::ProfileNotFound)?;
        headers.user_agent = Some(user_agent);

        let mut map = header_profile_to_map(&headers);
        if !opts.allow_brotli {
            strip_brotli(&mut map);
        }

        let cipher_suites = self
            .data
            .cipher_suites
            .get(&browser)
            .cloned()
            .unwrap_or_default();

        Ok(UserAgentProfile {
            headers: map,
            cipher_suites,
        })
    }

    fn custom_profile(&self, custom: String) -> Result<UserAgentProfile, UserAgentError> {
        if let Some((browser, headers)) = self.try_match_custom(&custom) {
            let mut map = header_profile_to_map(headers);
            map.insert("User-Agent".into(), custom.clone());

            let cipher_suites = self
                .data
                .cipher_suites
                .get(browser)
                .cloned()
                .unwrap_or_else(default_cipher_suites);

            Ok(UserAgentProfile {
                headers: map,
                cipher_suites,
            })
        } else {
            Ok(UserAgentProfile {
                headers: default_headers(&custom),
                cipher_suites: default_cipher_suites(),
            })
        }
    }

    fn try_match_custom(&self, custom: &str) -> Option<(&String, &HeaderProfile)> {
        for device_map in self.data.user_agents.values() {
            for platform_map in device_map.values() {
                for (browser, agents) in platform_map {
                    if agents.iter().any(|agent| agent.contains(custom))
                        && let Some(headers) = self.data.headers.get(browser)
                    {
                        return Some((browser, headers));
                    }
                }
            }
        }
        None
    }

    fn resolve_platform(
        &self,
        opts: &UserAgentOptions,
        permitted_kinds: &[DeviceKind],
    ) -> Result<String, UserAgentError> {
        const VALID: &[&str] = &["linux", "windows", "darwin", "android", "ios"];

        match opts.platform {
            Some(ref platform) => {
                if !VALID.contains(&platform.as_str()) {
                    return Err(UserAgentError::InvalidOptions(
                        format!("Invalid platform '{platform}'; valid: {}", VALID.join(", "))
                            .into(),
                    ));
                }
                if !self.platform_available(permitted_kinds, platform) {
                    return Err(UserAgentError::ProfileNotFound);
                }
                Ok(platform.clone())
            }
            None => {
                let candidates: Vec<&str> = VALID
                    .iter()
                    .copied()
                    .filter(|platform| self.platform_available(permitted_kinds, platform))
                    .collect();

                if candidates.is_empty() {
                    return Err(UserAgentError::ProfileNotFound);
                }

                Ok(random_choice(&candidates).to_string())
            }
        }
    }

    fn collect_profiles(
        &self,
        permitted_kinds: &[DeviceKind],
        platform: &str,
    ) -> HashMap<String, Vec<String>> {
        let mut filtered = HashMap::new();

        for device_kind in permitted_kinds {
            if let Some(device_map) = self.data.user_agents.get(device_kind)
                && let Some(platform_map) = device_map.get(platform)
            {
                for (browser, agents) in platform_map {
                    if agents.is_empty() {
                        continue;
                    }

                    filtered
                        .entry(browser.clone())
                        .or_insert_with(Vec::new)
                        .extend(agents.iter().cloned());
                }
            }
        }

        filtered
    }

    fn platform_available(&self, permitted_kinds: &[DeviceKind], platform: &str) -> bool {
        permitted_kinds.iter().any(|kind| {
            self.data
                .user_agents
                .get(kind)
                .and_then(|device_map| device_map.get(platform))
                .map(|platform_map| platform_map.values().any(|agents| !agents.is_empty()))
                .unwrap_or(false)
        })
    }
}

/// Optional on-disk overrides for the embedded dataset.
///
/// Checked in order: the `CLOUDSCRAPER_BROWSERS_JSON` environment variable
/// (an explicit path), then `browsers.json` in the current working directory.
/// When none exist, the loader falls back to [`EMBEDDED_BROWSERS_JSON`].
fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(custom) = std::env::var("CLOUDSCRAPER_BROWSERS_JSON")
        && !custom.is_empty()
    {
        paths.push(PathBuf::from(custom));
    }

    if let Ok(current) = std::env::current_dir() {
        paths.push(current.join("browsers.json"));
    }

    paths
}

fn header_profile_to_map(profile: &HeaderProfile) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(ref ua) = profile.user_agent {
        map.insert("User-Agent".into(), ua.clone());
    }
    map.insert("Accept".into(), profile.accept.clone());
    map.insert("Accept-Language".into(), profile.accept_language.clone());
    map.insert("Accept-Encoding".into(), profile.accept_encoding.clone());
    map
}

fn strip_brotli(headers: &mut HashMap<String, String>) {
    if let Some(encoding) = headers.get_mut("Accept-Encoding") {
        let filtered = encoding
            .split(',')
            .map(str::trim)
            .filter(|enc| !enc.eq_ignore_ascii_case("br"))
            .collect::<Vec<_>>()
            .join(", ");
        *encoding = filtered;
    }
}

fn random_choice<T: Clone>(items: &[T]) -> T {
    let mut rng = thread_rng();
    items
        .choose(&mut rng)
        .cloned()
        .expect("random choice on empty slice")
}

fn default_headers(custom: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("User-Agent".into(), custom.to_string());
    map.insert(
        "Accept".into(),
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
            .into(),
    );
    map.insert("Accept-Language".into(), "en-US,en;q=0.9".into());
    map.insert("Accept-Encoding".into(), "gzip, deflate".into());
    map
}

fn default_cipher_suites() -> Vec<String> {
    vec![
        "TLS_AES_128_GCM_SHA256".into(),
        "TLS_AES_256_GCM_SHA384".into(),
        "ECDHE-ECDSA-AES128-GCM-SHA256".into(),
        "ECDHE-RSA-AES128-GCM-SHA256".into(),
        "ECDHE-ECDSA-AES256-GCM-SHA384".into(),
        "ECDHE-RSA-AES256-GCM-SHA384".into(),
    ]
}

#[derive(Debug, thiserror::Error)]
pub enum UserAgentError {
    #[error("user-agent data file missing: {path:?}")]
    FileMissing { path: PathBuf },
    #[error("user-agent JSON invalid at {path:?}: {source}")]
    InvalidJson {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("embedded user-agent dataset is invalid: {0}")]
    InvalidEmbedded(serde_json::Error),
    #[error("I/O error reading {path:?}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("no user-agent data sources found")]
    NoDataSources,
    #[error("invalid user-agent options: {0}")]
    InvalidOptions(Cow<'static, str>),
    #[error("no matching user-agent profile found")]
    ProfileNotFound,
    #[error("user-agent manager initialization failed: {0}")]
    InitializationFailure(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_dataset_is_valid_json() {
        // The dataset compiled into the binary must always parse, otherwise the
        // crate cannot work as a dependency (regression guard for issue #6).
        parse_dataset(EMBEDDED_BROWSERS_JSON).expect("embedded browsers.json must be valid");
    }

    #[test]
    fn manager_loads_without_on_disk_file() {
        // No reliance on filesystem layout: loading must succeed from the
        // embedded fallback alone.
        let manager = USER_AGENT_MANAGER
            .as_ref()
            .expect("user-agent manager should load from the embedded dataset");
        let profile = manager.select_profile(UserAgentOptions::default()).unwrap();
        assert!(profile.headers.contains_key("User-Agent"));
    }

    #[test]
    fn both_devices_disabled_is_invalid() {
        let opts = UserAgentOptions {
            desktop: false,
            mobile: false,
            ..Default::default()
        };
        assert!(matches!(
            get_user_agent_profile(opts),
            Err(UserAgentError::InvalidOptions(_))
        ));
    }

    #[test]
    fn invalid_platform_is_rejected() {
        let opts = UserAgentOptions {
            platform: Some("mars".into()),
            ..Default::default()
        };
        assert!(matches!(
            get_user_agent_profile(opts),
            Err(UserAgentError::InvalidOptions(_))
        ));
    }

    #[test]
    fn custom_user_agent_is_returned_verbatim() {
        let opts = UserAgentOptions {
            custom: Some("CustomUA/9.9".into()),
            ..Default::default()
        };
        let profile = get_user_agent_profile(opts).unwrap();
        assert_eq!(profile.headers.get("User-Agent").unwrap(), "CustomUA/9.9");
        assert!(!profile.cipher_suites.is_empty());
    }

    #[test]
    fn default_profile_has_all_core_headers() {
        let profile = get_user_agent_profile(UserAgentOptions::default()).unwrap();
        for header in ["User-Agent", "Accept", "Accept-Language", "Accept-Encoding"] {
            assert!(profile.headers.contains_key(header), "missing {header}");
        }
    }

    #[test]
    fn brotli_is_stripped_by_default() {
        let profile = get_user_agent_profile(UserAgentOptions::default()).unwrap();
        let encoding = profile
            .headers
            .get("Accept-Encoding")
            .cloned()
            .unwrap_or_default();
        assert!(
            !encoding
                .split(',')
                .any(|e| e.trim().eq_ignore_ascii_case("br")),
            "brotli should be stripped: {encoding}"
        );
    }

    #[test]
    fn strip_brotli_removes_only_br_token() {
        let mut map = HashMap::new();
        map.insert(
            "Accept-Encoding".to_string(),
            "gzip, br, deflate".to_string(),
        );
        strip_brotli(&mut map);
        assert_eq!(map.get("Accept-Encoding").unwrap(), "gzip, deflate");
    }

    #[test]
    fn default_cipher_suites_are_present() {
        assert!(!default_cipher_suites().is_empty());
    }
}
