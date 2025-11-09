//! Lightweight ML-inspired optimizer for strategy selection.
//!
//! Learns correlations between recorded features and bypass success rates so
//! adaptive strategies can make informed recommendations.

use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};

/// Feature vector represented as numeric values.
pub type FeatureVector = HashMap<String, f64>;

/// Configuration for the ML optimizer.
#[derive(Debug, Clone)]
pub struct MLConfig {
    pub window_size: usize,
    pub learning_rate: f64,
    pub min_samples: usize,
    pub exploration_chance: f64,
}

impl Default for MLConfig {
    fn default() -> Self {
        Self {
            window_size: 200,
            learning_rate: 0.15,
            min_samples: 20,
            exploration_chance: 0.1,
        }
    }
}

/// Recommendation returned after evaluating recorded samples.
#[derive(Debug, Clone)]
pub struct StrategyRecommendation {
    pub domain: String,
    pub confidence: f64,
    pub suggested_delay: Option<f64>,
    pub feature_weights: HashMap<String, f64>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct AttemptRecord {
    features: FeatureVector,
    success: bool,
    delay_used: Option<f64>,
}

#[derive(Debug)]
struct DomainModel {
    attempts: VecDeque<AttemptRecord>,
    weights: HashMap<String, f64>,
    success_rate: f64,
    window_size: usize,
}

impl DomainModel {
    fn new(window_size: usize) -> Self {
        Self {
            attempts: VecDeque::with_capacity(window_size),
            weights: HashMap::new(),
            success_rate: 1.0,
            window_size,
        }
    }

    fn push(&mut self, record: AttemptRecord) {
        if self.attempts.len() == self.window_size {
            self.attempts.pop_front();
        }
        self.attempts.push_back(record);
    }
}

/// ML-based optimizer wrapper.
#[derive(Debug)]
pub struct MLOptimizer {
    config: MLConfig,
    domains: HashMap<String, DomainModel>,
}

impl MLOptimizer {
    pub fn new(config: MLConfig) -> Self {
        Self {
            domains: HashMap::new(),
            config,
        }
    }

    fn model_mut(&mut self, domain: &str) -> &mut DomainModel {
        self.domains
            .entry(domain.to_string())
            .or_insert_with(|| DomainModel::new(self.config.window_size))
    }

    /// Record the outcome of a bypass attempt.
    pub fn record_attempt(
        &mut self,
        domain: &str,
        features: FeatureVector,
        success: bool,
        delay_used: Option<f64>,
    ) {
        let alpha = self.config.learning_rate;
        let model = self.model_mut(domain);
        model.push(AttemptRecord {
            features,
            success,
            delay_used,
        });

        model.success_rate =
            (1.0 - alpha) * model.success_rate + alpha * if success { 1.0 } else { 0.0 };

        // Recalculate weights via simple correlation (success minus failure averages).
        let mut success_sums: HashMap<String, f64> = HashMap::new();
        let mut failure_sums: HashMap<String, f64> = HashMap::new();
        let mut success_counts: HashMap<String, f64> = HashMap::new();
        let mut failure_counts: HashMap<String, f64> = HashMap::new();

        for attempt in &model.attempts {
            for (feature, value) in &attempt.features {
                if attempt.success {
                    *success_sums.entry(feature.clone()).or_default() += value;
                    *success_counts.entry(feature.clone()).or_default() += 1.0;
                } else {
                    *failure_sums.entry(feature.clone()).or_default() += value;
                    *failure_counts.entry(feature.clone()).or_default() += 1.0;
                }
            }
        }

        let mut seen: HashSet<&String> = HashSet::new();
        for feature in success_sums.keys().chain(failure_sums.keys()) {
            if !seen.insert(feature) {
                continue;
            }

            let success_sum = *success_sums.get(feature).unwrap_or(&0.0);
            let success_count = *success_counts.get(feature).unwrap_or(&0.0);
            let success_avg = if success_count > f64::EPSILON {
                success_sum / success_count
            } else {
                0.0
            };

            let failure_sum = *failure_sums.get(feature).unwrap_or(&0.0);
            let failure_count = *failure_counts.get(feature).unwrap_or(&0.0);
            let failure_avg = if failure_count > f64::EPSILON {
                failure_sum / failure_count
            } else {
                0.0
            };

            let weight = success_avg - failure_avg;
            model.weights.insert(feature.clone(), weight);
        }
    }

    /// Produce a recommendation for the domain based on learned weights.
    pub fn recommend(&self, domain: &str) -> Option<StrategyRecommendation> {
        let model = self.domains.get(domain)?;
        if model.attempts.len() < self.config.min_samples {
            return None;
        }

        let mut rng = rand::thread_rng();
        let mut notes = Vec::new();
        let confidence = model.success_rate;

        let suggested_delay = if let Some(delay) = self.estimate_delay(model) {
            notes.push(format!("using learned optimal delay {:.2}s", delay));
            Some(delay)
        } else if rng.gen_bool(self.config.exploration_chance.min(0.5)) {
            let jitter = rng.gen_range(0.5..=1.5);
            notes.push(format!("exploration jitter {:.2}", jitter));
            Some(jitter)
        } else {
            None
        };

        Some(StrategyRecommendation {
            domain: domain.to_string(),
            confidence,
            suggested_delay,
            feature_weights: model.weights.clone(),
            notes,
        })
    }

    fn estimate_delay(&self, model: &DomainModel) -> Option<f64> {
        let mut successful_delays: Vec<f64> = model
            .attempts
            .iter()
            .filter_map(|attempt| {
                if attempt.success {
                    attempt.delay_used
                } else {
                    None
                }
            })
            .collect();
        if successful_delays.is_empty() {
            return None;
        }
        successful_delays.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = successful_delays[successful_delays.len() / 2];
        Some((median * 0.9).clamp(0.2, 10.0))
    }

    pub fn clear_domain(&mut self, domain: &str) {
        self.domains.remove(domain);
    }
}

impl Default for MLOptimizer {
    fn default() -> Self {
        Self::new(MLConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learns_feature_weights() {
        let mut optimizer = MLOptimizer::default();
        for i in 0..40 {
            let mut features = FeatureVector::new();
            features.insert("timing".into(), 1.0);
            features.insert("difficulty".into(), if i % 2 == 0 { 0.5 } else { 1.5 });
            let success = i % 3 != 0;
            optimizer.record_attempt("example.com", features, success, Some(1.0));
        }

        let recommendation = optimizer.recommend("example.com");
        assert!(recommendation.is_some());
        let rec = recommendation.unwrap();
        assert!(rec.feature_weights.contains_key("timing"));
    }
}
