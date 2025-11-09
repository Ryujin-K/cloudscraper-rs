//! Proxy rotation and health tracking utilities.
//!
//! Tracks proxy performance, bans unhealthy endpoints, and selects the next
//! candidate based on the chosen rotation strategy.

use rand::Rng;
use rand::seq::SliceRandom;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::challenges::solvers::access_denied::ProxyPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStrategy {
    Sequential,
    Random,
    Smart,
    Weighted,
    RoundRobinSmart,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub rotation_strategy: RotationStrategy,
    pub ban_time: Duration,
    pub failure_threshold: u32,
    pub cooldown: Duration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            rotation_strategy: RotationStrategy::Sequential,
            ban_time: Duration::from_secs(300),
            failure_threshold: 3,
            cooldown: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyHealthReport {
    pub total_proxies: usize,
    pub available_proxies: usize,
    pub banned_proxies: usize,
    pub details: HashMap<String, ProxyStats>,
}

#[derive(Debug, Clone, Default)]
pub struct ProxyStats {
    pub successes: u64,
    pub failures: u64,
    pub last_used: Option<Instant>,
    pub last_failure: Option<Instant>,
}

#[derive(Debug, Clone)]
struct ProxyEntry {
    endpoint: String,
    stats: ProxyStats,
    banned_until: Option<Instant>,
}

impl ProxyEntry {
    fn is_available(&self) -> bool {
        match self.banned_until {
            Some(until) => Instant::now() >= until,
            None => true,
        }
    }

    fn score(&self) -> f64 {
        let total = self.stats.successes + self.stats.failures;
        let success_rate = if total == 0 {
            1.0
        } else {
            self.stats.successes as f64 / total as f64
        };
        let recency = self
            .stats
            .last_used
            .map(|ts| (Instant::now() - ts).as_secs_f64())
            .unwrap_or(300.0)
            / 300.0;
        (success_rate * 0.7) + (recency.clamp(0.0, 1.0) * 0.3)
    }
}

/// Proxy manager with rotation policies.
#[derive(Debug)]
pub struct ProxyManager {
    config: ProxyConfig,
    proxies: Vec<ProxyEntry>,
    current_index: usize,
    rng: rand::rngs::ThreadRng,
}

impl ProxyManager {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            proxies: Vec::new(),
            current_index: 0,
            rng: rand::thread_rng(),
        }
    }

    pub fn load<I>(&mut self, proxies: I)
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        self.proxies.clear();
        for proxy in proxies {
            self.add_proxy(proxy);
        }
    }

    pub fn add_proxy(&mut self, proxy: impl Into<String>) {
        let endpoint = proxy.into();
        if self.proxies.iter().any(|entry| entry.endpoint == endpoint) {
            return;
        }
        self.proxies.push(ProxyEntry {
            endpoint,
            stats: ProxyStats::default(),
            banned_until: None,
        });
    }

    pub fn remove_proxy(&mut self, proxy: &str) {
        self.proxies.retain(|entry| entry.endpoint != proxy);
    }

    pub fn next_proxy(&mut self) -> Option<String> {
        if self.proxies.is_empty() {
            return None;
        }

        let now = Instant::now();
        let mut available_indices = Vec::new();
        for idx in 0..self.proxies.len() {
            let entry = &mut self.proxies[idx];
            if let Some(until) = entry.banned_until {
                if until <= now {
                    entry.banned_until = None;
                    available_indices.push(idx);
                }
            } else {
                available_indices.push(idx);
            }
        }

        let selected_index = if available_indices.is_empty() {
            let index = self
                .proxies
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.banned_until.unwrap_or(now))
                .map(|(idx, _)| idx)?;
            let entry = &mut self.proxies[index];
            entry.banned_until = None;
            index
        } else {
            match self.config.rotation_strategy {
                RotationStrategy::Sequential => {
                    let idx_in_pool = self.current_index % available_indices.len();
                    self.current_index = (self.current_index + 1) % available_indices.len();
                    available_indices[idx_in_pool]
                }
                RotationStrategy::Random => {
                    available_indices.choose(&mut self.rng).copied().unwrap()
                }
                RotationStrategy::Smart => *available_indices
                    .iter()
                    .max_by(|&&a, &&b| {
                        let lhs = self.proxies[a].score();
                        let rhs = self.proxies[b].score();
                        lhs.partial_cmp(&rhs).unwrap_or(Ordering::Equal)
                    })
                    .unwrap(),
                RotationStrategy::Weighted => {
                    weighted_choice_index(&mut self.rng, &self.proxies, &available_indices)
                        .unwrap_or(available_indices[0])
                }
                RotationStrategy::RoundRobinSmart => {
                    let filtered: Vec<usize> = available_indices
                        .iter()
                        .copied()
                        .filter(|&idx| {
                            if let Some(last_failure) = self.proxies[idx].stats.last_failure {
                                now.duration_since(last_failure) > self.config.cooldown
                            } else {
                                true
                            }
                        })
                        .collect();
                    let pool = if filtered.is_empty() {
                        &available_indices
                    } else {
                        &filtered
                    };
                    let idx_in_pool = self.current_index % pool.len();
                    self.current_index = (self.current_index + 1) % pool.len();
                    pool[idx_in_pool]
                }
            }
        };

        let entry = &mut self.proxies[selected_index];
        entry.stats.last_used = Some(Instant::now());
        Some(entry.endpoint.clone())
    }

    pub fn report_success(&mut self, proxy: &str) {
        if let Some(entry) = self
            .proxies
            .iter_mut()
            .find(|entry| entry.endpoint == proxy)
        {
            entry.stats.successes += 1;
            entry.banned_until = None;
        }
    }

    pub fn report_failure(&mut self, proxy: &str) {
        if let Some(entry) = self
            .proxies
            .iter_mut()
            .find(|entry| entry.endpoint == proxy)
        {
            entry.stats.failures += 1;
            entry.stats.last_failure = Some(Instant::now());
            if entry.stats.failures % self.config.failure_threshold as u64 == 0 {
                entry.banned_until = Some(Instant::now() + self.config.ban_time);
            }
        }
    }

    pub fn health_report(&self) -> ProxyHealthReport {
        let mut details = HashMap::new();
        let mut available = 0;
        let mut banned = 0;
        for entry in &self.proxies {
            if entry.is_available() {
                available += 1;
            } else {
                banned += 1;
            }
            details.insert(entry.endpoint.clone(), entry.stats.clone());
        }

        ProxyHealthReport {
            total_proxies: self.proxies.len(),
            available_proxies: available,
            banned_proxies: banned,
            details,
        }
    }
}

impl Default for ProxyManager {
    fn default() -> Self {
        Self::new(ProxyConfig::default())
    }
}

impl ProxyPool for ProxyManager {
    fn report_failure(&mut self, proxy: &str) {
        ProxyManager::report_failure(self, proxy);
    }

    fn next_proxy(&mut self) -> Option<String> {
        ProxyManager::next_proxy(self)
    }
}

fn weighted_choice_index(
    rng: &mut rand::rngs::ThreadRng,
    proxies: &[ProxyEntry],
    indices: &[usize],
) -> Option<usize> {
    if indices.is_empty() {
        return None;
    }

    let weights: Vec<f64> = indices
        .iter()
        .map(|&idx| proxies[idx].score().max(0.1))
        .collect();
    let total: f64 = weights.iter().sum();
    if total <= f64::EPSILON {
        return indices.choose(rng).copied();
    }

    let mut target = rng.gen_range(0.0..total);
    for (index, weight) in indices.iter().zip(weights.iter()) {
        if target <= *weight {
            return Some(*index);
        }
        target -= *weight;
    }

    indices.last().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_proxies() {
        let mut manager = ProxyManager::default();
        manager.load(["http://1.1.1.1:8080", "http://2.2.2.2:8080"]);
        let first = manager.next_proxy().unwrap();
        let second = manager.next_proxy().unwrap();
        assert!(!first.is_empty());
        assert!(!second.is_empty());
    }

    #[test]
    fn bans_after_failures() {
        let mut manager = ProxyManager::new(ProxyConfig {
            failure_threshold: 1,
            ban_time: Duration::from_secs(60),
            ..Default::default()
        });
        manager.add_proxy("http://1.1.1.1:8080");
        let proxy = manager.next_proxy().unwrap();
        manager.report_failure(&proxy);
        let report = manager.health_report();
        assert_eq!(report.banned_proxies, 1);
    }
}
