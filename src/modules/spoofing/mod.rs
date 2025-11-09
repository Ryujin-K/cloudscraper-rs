//! Browser fingerprint spoofing utilities.
//!
//! Generates browser fingerprints with configurable consistency so solvers can
//! present stable client identities when required.

use chrono::{DateTime, Utc};
use rand::{Rng, seq::SliceRandom};
use std::collections::HashMap;

use crate::challenges::solvers::FingerprintManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Safari,
    Edge,
    MobileChrome,
    MobileSafari,
}

#[derive(Debug, Clone)]
pub struct BrowserFingerprint {
    pub user_agent: String,
    pub accept_language: String,
    pub platform: String,
    pub screen_resolution: (u16, u16),
    pub timezone: String,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    pub canvas_fingerprint: String,
    pub audio_fingerprint: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy)]
pub enum ConsistencyLevel {
    None,
    Domain,
    Global,
}

/// Generates realistic fingerprints for spoofing Canvas/WebGL APIs.
#[derive(Debug)]
pub struct FingerprintGenerator {
    browser: BrowserType,
    consistency: ConsistencyLevel,
    cache: HashMap<String, BrowserFingerprint>,
    global: Option<BrowserFingerprint>,
}

impl FingerprintGenerator {
    pub fn new(browser: BrowserType) -> Self {
        Self {
            browser,
            consistency: ConsistencyLevel::Domain,
            cache: HashMap::new(),
            global: None,
        }
    }

    pub fn with_consistency(mut self, level: ConsistencyLevel) -> Self {
        self.consistency = level;
        self
    }

    pub fn set_browser(&mut self, browser: BrowserType) {
        if self.browser != browser {
            self.cache.clear();
            self.global = None;
            self.browser = browser;
        }
    }

    pub fn generate_for(&mut self, domain: &str) -> BrowserFingerprint {
        match self.consistency {
            ConsistencyLevel::None => Self::random_fingerprint(self.browser),
            ConsistencyLevel::Global => {
                if self.global.is_none() {
                    self.global = Some(Self::random_fingerprint(self.browser));
                }
                self.global.clone().unwrap()
            }
            ConsistencyLevel::Domain => {
                let browser = self.browser;
                self.cache
                    .entry(domain.to_string())
                    .or_insert_with(|| Self::random_fingerprint(browser))
                    .clone()
            }
        }
    }

    pub fn invalidate(&mut self, domain: &str) {
        self.cache.remove(domain);
    }

    fn random_fingerprint(browser: BrowserType) -> BrowserFingerprint {
        let templates = templates_for_browser(browser);
        let mut rng = rand::thread_rng();
        let template = templates.choose(&mut rng).unwrap_or(&templates[0]);

        let screen_resolution = template
            .screen_resolutions
            .choose(&mut rng)
            .copied()
            .unwrap_or((1920, 1080));

        let timezone = template
            .timezones
            .choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| "UTC".to_string());

        let webgl_vendor = template
            .webgl_vendors
            .choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| "Google Inc.".into());
        let webgl_renderer = template
            .webgl_renderers
            .choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| "ANGLE (NVIDIA GeForce GTX 1660)".into());

        let canvas_seed: u64 = rng.r#gen();
        let audio_seed: u64 = rng.r#gen();

        BrowserFingerprint {
            user_agent: template.user_agent.clone(),
            accept_language: template
                .accept_languages
                .choose(&mut rng)
                .cloned()
                .unwrap_or_else(|| "en-US,en;q=0.9".into()),
            platform: template.platform.clone(),
            screen_resolution,
            timezone,
            webgl_vendor,
            webgl_renderer,
            canvas_fingerprint: format!("canvas-{canvas_seed:016x}"),
            audio_fingerprint: format!("audio-{audio_seed:016x}"),
            created_at: Utc::now(),
        }
    }
}

impl Default for FingerprintGenerator {
    fn default() -> Self {
        Self::new(BrowserType::Chrome)
    }
}

impl FingerprintManager for FingerprintGenerator {
    fn invalidate(&mut self, domain: &str) {
        FingerprintGenerator::invalidate(self, domain);
    }
}

#[derive(Clone)]
struct FingerprintTemplate {
    user_agent: String,
    platform: String,
    accept_languages: Vec<String>,
    screen_resolutions: Vec<(u16, u16)>,
    timezones: Vec<String>,
    webgl_vendors: Vec<String>,
    webgl_renderers: Vec<String>,
}

fn templates_for_browser(browser: BrowserType) -> Vec<FingerprintTemplate> {
    match browser {
        BrowserType::Chrome | BrowserType::Edge => vec![FingerprintTemplate {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
            platform: "Win32".into(),
            accept_languages: vec!["en-US,en;q=0.9".into(), "en-GB,en;q=0.8".into()],
            screen_resolutions: vec![(1920, 1080), (2560, 1440), (1366, 768)],
            timezones: vec!["America/New_York".into(), "Europe/Berlin".into(), "Asia/Tokyo".into()],
            webgl_vendors: vec!["Google Inc.".into(), "Microsoft".into()],
            webgl_renderers: vec![
                "ANGLE (NVIDIA GeForce RTX 3080)".into(),
                "ANGLE (AMD Radeon RX 6800)".into(),
            ],
        }],
        BrowserType::Firefox => vec![FingerprintTemplate {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0".into(),
            platform: "Win64".into(),
            accept_languages: vec!["en-US,en;q=0.8".into(), "fr-FR,fr;q=0.7".into()],
            screen_resolutions: vec![(1920, 1080), (1680, 1050)],
            timezones: vec!["America/Los_Angeles".into(), "Europe/London".into()],
            webgl_vendors: vec!["Mozilla".into(), "Google Inc.".into()],
            webgl_renderers: vec![
                "ANGLE (NVIDIA GeForce GTX 1050 Ti)".into(),
                "ANGLE (Intel(R) UHD Graphics 630)".into(),
            ],
        }],
        BrowserType::Safari => vec![FingerprintTemplate {
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15".into(),
            platform: "MacIntel".into(),
            accept_languages: vec!["en-US,en;q=0.9".into(), "en-AU,en;q=0.8".into()],
            screen_resolutions: vec![(2560, 1600), (2880, 1800)],
            timezones: vec!["America/Los_Angeles".into(), "Australia/Sydney".into()],
            webgl_vendors: vec!["Apple".into()],
            webgl_renderers: vec!["Apple GPU".into(), "Metal Renderer".into()],
        }],
        BrowserType::MobileChrome => vec![FingerprintTemplate {
            user_agent: "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36".into(),
            platform: "Linux armv8l".into(),
            accept_languages: vec!["en-US,en;q=0.8".into(), "es-ES,es;q=0.7".into()],
            screen_resolutions: vec![(1080, 2400), (1170, 2532)],
            timezones: vec!["America/New_York".into(), "Europe/Madrid".into()],
            webgl_vendors: vec!["Qualcomm".into(), "ARM".into()],
            webgl_renderers: vec!["Adreno (TM) 730".into(), "Mali-G710".into()],
        }],
        BrowserType::MobileSafari => vec![FingerprintTemplate {
            user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1".into(),
            platform: "iPhone".into(),
            accept_languages: vec!["en-US,en;q=0.9".into(), "ja-JP,ja;q=0.8".into()],
            screen_resolutions: vec![(1170, 2532), (1125, 2436)],
            timezones: vec!["America/Chicago".into(), "Asia/Tokyo".into()],
            webgl_vendors: vec!["Apple".into()],
            webgl_renderers: vec!["Apple A16 GPU".into(), "Apple A15 GPU".into()],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_consistent_domain_fingerprints() {
        let mut generator = FingerprintGenerator::default();
        let fp1 = generator.generate_for("example.com");
        let fp2 = generator.generate_for("example.com");
        let fp3 = generator.generate_for("example.org");
        assert_eq!(fp1.user_agent, fp2.user_agent);
        assert_ne!(fp1.canvas_fingerprint, fp3.canvas_fingerprint);
    }
}
