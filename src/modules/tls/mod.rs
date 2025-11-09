//! TLS fingerprint rotation utilities.
//!
//! Supplies browser TLS profiles plus per-domain rotation to vary JA3
//! fingerprints and cipher suites.

use rand::Rng;
use rand::seq::SliceRandom;
use std::collections::HashMap;

use super::spoofing::BrowserType;

use crate::challenges::solvers::TlsProfileManager;

#[derive(Debug, Clone)]
pub struct BrowserProfile {
    pub browser: BrowserType,
    pub ja3: String,
    pub cipher_suites: Vec<String>,
    pub alpn_protocols: Vec<String>,
    pub tls_extensions: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct TLSConfig {
    pub rotate_ja3: bool,
    pub rotate_ciphers: bool,
    pub preferred_browser: BrowserType,
    pub rotation_interval: usize,
}

impl Default for TLSConfig {
    fn default() -> Self {
        Self {
            rotate_ja3: true,
            rotate_ciphers: true,
            preferred_browser: BrowserType::Chrome,
            rotation_interval: 5,
        }
    }
}

#[derive(Debug)]
struct DomainTLSState {
    profile_index: usize,
    requests_since_rotation: usize,
}

impl DomainTLSState {
    fn new(index: usize) -> Self {
        Self {
            profile_index: index,
            requests_since_rotation: 0,
        }
    }
}

/// Default TLS manager mirroring smart JA3 rotation.
#[derive(Debug)]
pub struct DefaultTLSManager {
    config: TLSConfig,
    profiles: Vec<BrowserProfile>,
    per_domain: HashMap<String, DomainTLSState>,
    rng: rand::rngs::ThreadRng,
}

impl DefaultTLSManager {
    pub fn new(config: TLSConfig) -> Self {
        let mut manager = Self {
            profiles: build_default_profiles(),
            rng: rand::thread_rng(),
            per_domain: HashMap::new(),
            config,
        };
        // Ensure preferred browser is first in rotation order for quicker access.
        manager.promote_preferred_profile();
        manager
    }

    fn promote_preferred_profile(&mut self) {
        if let Some(pos) = self
            .profiles
            .iter()
            .position(|p| p.browser == self.config.preferred_browser)
        {
            self.profiles.swap(0, pos);
        }
    }

    fn domain_state_mut(&mut self, domain: &str) -> &mut DomainTLSState {
        let idx = self.rng.gen_range(0..self.profiles.len());
        self.per_domain
            .entry(domain.to_string())
            .or_insert_with(|| DomainTLSState::new(idx))
    }

    pub fn current_profile(&mut self, domain: &str) -> BrowserProfile {
        let should_rotate = {
            let state = self.domain_state_mut(domain);
            state.requests_since_rotation += 1;
            state.requests_since_rotation >= self.config.rotation_interval
        };

        if should_rotate {
            self.rotate_profile(domain);
        }

        let index = self.domain_state_mut(domain).profile_index;
        self.profiles[index].clone()
    }

    pub fn rotate_profile(&mut self, domain: &str) {
        let profiles_len = self.profiles.len();
        let current_index = {
            let state = self.domain_state_mut(domain);
            state.requests_since_rotation = 0;
            state.profile_index
        };

        if profiles_len <= 1 {
            return;
        }

        let mut candidates: Vec<usize> = (0..profiles_len).collect();
        candidates.retain(|idx| *idx != current_index);
        if let Some(next_index) = candidates.choose(&mut self.rng).copied() {
            let state = self.domain_state_mut(domain);
            state.profile_index = next_index;
        }
    }

    pub fn add_custom_profile(&mut self, profile: BrowserProfile) {
        self.profiles.push(profile);
    }
}

impl Default for DefaultTLSManager {
    fn default() -> Self {
        Self::new(TLSConfig::default())
    }
}

impl TlsProfileManager for DefaultTLSManager {
    fn rotate_profile(&mut self, domain: &str) {
        DefaultTLSManager::rotate_profile(self, domain);
    }
}

fn build_default_profiles() -> Vec<BrowserProfile> {
    vec![
        BrowserProfile {
            browser: BrowserType::Chrome,
            ja3: "771,4866-4865-4867-49196-49195-52393,0-11-10-35-13-45-16-43,29-23-24,0".into(),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".into(),
                "TLS_AES_256_GCM_SHA384".into(),
                "TLS_CHACHA20_POLY1305_SHA256".into(),
            ],
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            tls_extensions: vec![0, 11, 10, 35, 13, 45, 16, 43],
        },
        BrowserProfile {
            browser: BrowserType::Firefox,
            ja3: "771,4866-4865-4867-49196-49200,0-11-10-35-13-27,23-24,0".into(),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".into(),
                "TLS_AES_256_GCM_SHA384".into(),
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
            ],
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            tls_extensions: vec![0, 11, 10, 35, 13, 27],
        },
        BrowserProfile {
            browser: BrowserType::Safari,
            ja3: "771,4865-4866-4867-49195-49196,0-11-10-35-13-16,29-23-24,0".into(),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".into(),
                "TLS_CHACHA20_POLY1305_SHA256".into(),
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
            ],
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            tls_extensions: vec![0, 11, 10, 35, 13, 16],
        },
        BrowserProfile {
            browser: BrowserType::MobileChrome,
            ja3: "771,4866-4865-4867-49196,0-11-10-35-13-45,29-23-24,0".into(),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".into(),
                "TLS_CHACHA20_POLY1305_SHA256".into(),
            ],
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            tls_extensions: vec![0, 11, 10, 35, 13, 45],
        },
        BrowserProfile {
            browser: BrowserType::MobileSafari,
            ja3: "771,4865-4866-4867-49195,0-11-10-35-16,29-23-24,0".into(),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".into(),
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
            ],
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            tls_extensions: vec![0, 11, 10, 35, 16],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_profiles() {
        let mut manager = DefaultTLSManager::default();
        let profile1 = manager.current_profile("example.com");
        manager.rotate_profile("example.com");
        let profile2 = manager.current_profile("example.com");
        assert!(profile1.ja3 != profile2.ja3 || profile1.browser != profile2.browser);
    }
}
