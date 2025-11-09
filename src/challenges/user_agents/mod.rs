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
use std::path::{Path, PathBuf};

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
static USER_AGENT_MANAGER: Lazy<Result<UserAgentManager, UserAgentError>> = Lazy::new(|| {
    let paths = candidate_paths();
    let mut last_err = None;

    for path in paths {
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let data: UserAgentData =
                    serde_json::from_str(&contents).map_err(|err| UserAgentError::InvalidJson {
                        path: path.clone(),
                        source: err,
                    })?;
                return Ok(UserAgentManager { data });
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                last_err = Some(UserAgentError::FileMissing { path });
                continue;
            }
            Err(err) => {
                return Err(UserAgentError::Io { path, source: err });
            }
        }
    }

    Err(last_err.unwrap_or(UserAgentError::NoDataSources))
});

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

/// List all candidate paths to locate `browsers.json`.
fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let manifest_path = Path::new(&manifest);

        let legacy_path = manifest_path
            .join("cloudscraper-master (zied)")
            .join("cloudscraper-master")
            .join("cloudscraper")
            .join("user_agent")
            .join("browsers.json");
        paths.push(legacy_path);

        let embedded_path = manifest_path
            .join("src")
            .join("challenges")
            .join("user_agents")
            .join("browsers.json");
        paths.push(embedded_path);
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
    fn default_selection_returns_profile() {
        if let Ok(manager) = USER_AGENT_MANAGER.as_ref() {
            let profile = manager.select_profile(UserAgentOptions::default()).unwrap();
            assert!(profile.headers.contains_key("User-Agent"));
        }
    }
}
