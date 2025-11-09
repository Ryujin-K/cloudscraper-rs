//! Cross-cutting services module
//!
//! Augments requests with stealth, metrics, timing, ML, and TLS strategies.
//! All modules support feature gating for lean builds.

pub mod adaptive_timing;
pub mod anti_detection;
pub mod events;
pub mod metrics;
pub mod ml;
pub mod performance;
pub mod proxy;
pub mod spoofing;
pub mod state;
pub mod tls;

// Re-export commonly used types
pub use adaptive_timing::{
    AdaptiveTimingStrategy, BehaviorProfile, DefaultAdaptiveTiming, DomainTimingSnapshot,
    RequestKind, TimingOutcome, TimingProfile, TimingRequest,
};
pub use anti_detection::{
    AntiDetectionConfig, AntiDetectionContext, AntiDetectionStrategy, DefaultAntiDetection,
};
pub use events::{
    ChallengeEvent, ErrorEvent, EventDispatcher, EventHandler, LoggingHandler, MetricsHandler,
    PostResponseEvent, PreRequestEvent, RetryEvent, ScraperEvent,
};
pub use metrics::{DomainStats, GlobalStats, MetricsCollector, MetricsSnapshot};
pub use ml::{FeatureVector, MLConfig, MLOptimizer, StrategyRecommendation};
pub use performance::{PerformanceConfig, PerformanceMonitor, PerformanceReport};
pub use proxy::{ProxyConfig, ProxyHealthReport, ProxyManager, RotationStrategy};
pub use spoofing::{BrowserFingerprint, BrowserType, ConsistencyLevel, FingerprintGenerator};
pub use state::{DomainState, StateManager};
pub use tls::{BrowserProfile, DefaultTLSManager, TLSConfig};
