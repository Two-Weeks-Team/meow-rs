use crate::adapter_type::AdapterType;
use crate::conn::{ProxyConn, ProxyPacketConn};
use crate::error::Result;
use crate::metadata::Metadata;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayHistory {
    #[serde(with = "rfc3339_system_time")]
    pub time: SystemTime,
    pub delay: u16,
}

/// Wire format for [`DelayHistory::time`]: an RFC 3339 string, matching
/// upstream Go mihomo where `history[].time` marshals via `time.Time`
/// (`"2024-01-15T10:30:45Z"`). serde's default `SystemTime` representation
/// is a `{secs_since_epoch, nanos_since_epoch}` object, which breaks API
/// clients and dashboards that decode the upstream string shape — a probe
/// recording history made `GET /proxies` undecodable for them.
mod rfc3339_system_time {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::SystemTime;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(t: &SystemTime, serializer: S) -> Result<S::Ok, S::Error> {
        let formatted = OffsetDateTime::from(*t)
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&formatted)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SystemTime, D::Error> {
        let s = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&s, &Rfc3339)
            .map(SystemTime::from)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyState {
    pub alive: bool,
    pub history: Vec<DelayHistory>,
}

/// How many consecutive real dial failures mark a member dead.
///
/// One is too few. Transient failures happen, and sing-box's habit of
/// clearing a member's history on a single dial error makes a group flap
/// (`urltest.go:140`). Upstream meow-rs has the opposite problem: user dials
/// never touch liveness at all, so a member every connection fails on stays
/// alive until the next probe, up to 300 s away by default. Three consecutive
/// failures with no success in between is neither.
pub const DIAL_FAILURES_BEFORE_DEAD: u32 = 3;

/// Retry spacing for something that keeps failing. One success resets it.
///
/// Upstream has nothing like this — the whole workspace contains no backoff,
/// cooldown, or circuit breaker — so the health check probes every member on
/// every tick no matter how long it has been failing
/// (`meow-app/src/health_check.rs`).
pub struct Backoff {
    base: Duration,
    max: Duration,
    failures: u32,
    next_at: Option<Instant>,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            failures: 0,
            next_at: None,
        }
    }

    /// Wait until the next attempt. Doubles per call, capped at `max`.
    pub fn on_failure(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        let shift = self.failures.saturating_sub(1).min(31);
        let wait = self
            .base
            .checked_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
            .unwrap_or(self.max)
            .min(self.max);
        self.next_at = Instant::now().checked_add(wait);
        wait
    }

    pub fn on_success(&mut self) {
        self.failures = 0;
        self.next_at = None;
    }

    pub fn due(&self, now: Instant) -> bool {
        self.next_at.is_none_or(|t| now >= t)
    }
}

/// Per-adapter liveness + rolling delay history. Owned by every concrete
/// adapter and accessed via [`ProxyAdapter::health`]. Writers use interior
/// mutability so the trait method can return `&ProxyHealth`.
pub struct ProxyHealth {
    alive: AtomicBool,
    history: RwLock<VecDeque<DelayHistory>>,
    max_history: usize,
    /// Consecutive real-traffic dial failures since the last success. Kept
    /// apart from `history`, which is the probe's record and feeds delay
    /// ranking — a dial failure is evidence about liveness, not about speed.
    dial_failures: AtomicU32,
}

impl ProxyHealth {
    pub fn new() -> Self {
        Self {
            alive: AtomicBool::new(true),
            history: RwLock::new(VecDeque::new()),
            max_history: 10,
            dial_failures: AtomicU32::new(0),
        }
    }

    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::Relaxed);
    }

    pub fn last_delay(&self) -> u16 {
        self.history
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .back()
            .map_or(0, |h| h.delay)
    }

    pub fn delay_history(&self) -> Vec<DelayHistory> {
        self.history
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// A real connection through this member failed.
    ///
    /// Upstream has no such path: `record_delay`'s only callers are the two
    /// probe paths, and the tunnel's dial-failure arms only log
    /// (`meow-tunnel/src/tcp.rs`, `udp.rs`). A member that fails every user
    /// connection therefore stays `alive` until the next probe.
    ///
    /// Returns true if this call is what marked the member dead.
    pub fn record_dial_failure(&self) -> bool {
        let n = self.dial_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= DIAL_FAILURES_BEFORE_DEAD && self.alive.swap(false, Ordering::Relaxed) {
            return true;
        }
        false
    }

    /// A real connection through this member succeeded. Stronger evidence
    /// than a probe to a fixed third-party URL, so it also clears a dead mark
    /// — a member that carries traffic is alive whatever the probe thinks.
    pub fn record_dial_success(&self) {
        self.dial_failures.store(0, Ordering::Relaxed);
        self.alive.store(true, Ordering::Relaxed);
    }

    pub fn record_delay(&self, delay: u16) {
        let mut history = self
            .history
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        history.push_back(DelayHistory {
            time: SystemTime::now(),
            delay,
        });
        if history.len() > self.max_history {
            history.pop_front();
        }
        if delay > 0 {
            // A successful probe is evidence too; do not let a stale dial
            // count push the member back over the threshold.
            self.dial_failures.store(0, Ordering::Relaxed);
        }
        self.alive.store(delay > 0, Ordering::Relaxed);
    }

    pub fn state(&self) -> ProxyState {
        ProxyState {
            alive: self.alive(),
            history: self.delay_history(),
        }
    }
}

impl Default for ProxyHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait ProxyAdapter: Send + Sync {
    fn name(&self) -> &str;
    fn adapter_type(&self) -> AdapterType;
    fn addr(&self) -> &str;
    fn support_udp(&self) -> bool;
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>>;
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>>;
    /// Run this adapter's handshake over an already-established `stream`.
    ///
    /// Used by relay groups (M1.C-2) to chain proxy hops without dialling a
    /// new TCP connection.  The TLS-wrap step from `dial_tcp` is intentionally
    /// skipped — the passed stream is already inside whatever encryption the
    /// relay chain provides.
    ///
    /// Default implementation returns `Err(NotSupported)`.  Override in
    /// adapters that support relay chaining (HTTP CONNECT, SOCKS5, …).
    ///
    /// upstream: `adapter/outbound/<proto>.go` — `DialContextWithDialer`
    async fn connect_over(
        &self,
        _stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Err(crate::error::MeowError::NotSupported(format!(
            "{}: connect_over not supported",
            self.name()
        )))
    }
    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        None
    }
    /// Per-adapter health handle — owned, infallible. Dashboards (via the
    /// delay endpoints) record probe results through `health().record_delay`
    /// so `GET /proxies/:name` reflects the measurement.
    fn health(&self) -> &ProxyHealth;
}

/// Shared live proxy list owned by a `ProxyProvider`.
/// Groups hold `Vec<ProviderSlot>` and call `effective_proxies()` at dial time
/// to merge static members with provider-supplied proxies without caching.
pub type ProviderSlot = std::sync::Arc<parking_lot::RwLock<Vec<std::sync::Arc<dyn Proxy>>>>;

/// Runtime selection capability implemented by mihomo-compatible outbound
/// groups. `Selector`, `URLTest`, and `Fallback` are selectable; leaf
/// adapters and non-selectable groups return `None` from [`Proxy::selection`].
#[async_trait]
pub trait ProxySelection: Send + Sync {
    /// Validate and select a member by name.
    async fn set(&self, name: &str) -> Result<()>;

    /// Set or clear a selection without validation. This mirrors mihomo's
    /// `SelectAble.ForceSet` and is used to unfix automatic groups before a
    /// group health check.
    fn force_set(&self, name: Option<&str>);

    /// Value exposed as the mihomo `fixed` field. Automatic groups return
    /// `Some("")` while unfixed; selectors return `None` because upstream
    /// does not expose `fixed` for them.
    fn fixed(&self) -> Option<String>;

    /// Only automatic groups can be returned to automatic mode through
    /// `DELETE /proxies/{name}`.
    fn can_unfix(&self) -> bool;
}

pub trait Proxy: ProxyAdapter {
    fn alive(&self) -> bool;
    fn alive_for_url(&self, url: &str) -> bool;
    fn last_delay(&self) -> u16;
    fn last_delay_for_url(&self, url: &str) -> u16;
    fn delay_history(&self) -> Vec<DelayHistory>;
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }
    /// For group adapters: the ordered list of member proxy names.
    /// Leaf adapters return `None`.
    fn members(&self) -> Option<Vec<String>> {
        None
    }
    /// For group adapters: the name of the currently active member
    /// (selected/fastest/first-alive depending on group kind).
    fn current(&self) -> Option<String> {
        None
    }

    /// Optional runtime selection capability for outbound groups.
    fn selection(&self) -> Option<&dyn ProxySelection> {
        None
    }

    /// Group health-check URL exposed by the mihomo API.
    fn test_url(&self) -> Option<&str> {
        None
    }

    /// Group expected-status expression exposed by the mihomo API.
    fn expected_status(&self) -> Option<&str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn failures_double_the_wait_up_to_a_ceiling() {
        let mut b = Backoff::new(Duration::from_secs(300), Duration::from_secs(1800));
        assert_eq!(b.on_failure(), Duration::from_secs(300));
        assert_eq!(b.on_failure(), Duration::from_secs(600));
        assert_eq!(b.on_failure(), Duration::from_secs(1200));
        assert_eq!(b.on_failure(), Duration::from_secs(1800), "천장에서 멈춘다");
        assert_eq!(b.on_failure(), Duration::from_secs(1800));
    }

    #[test]
    fn a_single_success_wipes_the_penalty() {
        let mut b = Backoff::new(Duration::from_secs(300), Duration::from_secs(1800));
        for _ in 0..5 {
            b.on_failure();
        }
        b.on_success();
        assert_eq!(b.on_failure(), Duration::from_secs(300));
    }

    /// 64회 실패해도 곱셈이 넘치지 않아야 한다.
    #[test]
    fn the_multiplier_never_overflows() {
        let mut b = Backoff::new(Duration::from_secs(300), Duration::from_secs(1800));
        for _ in 0..64 {
            assert!(b.on_failure() <= Duration::from_secs(1800));
        }
    }

    #[test]
    fn a_fresh_node_is_due_immediately() {
        let b = Backoff::new(Duration::from_secs(300), Duration::from_secs(1800));
        assert!(b.due(Instant::now()));
    }

    #[test]
    fn a_backed_off_node_is_not_due_yet() {
        let mut b = Backoff::new(Duration::from_secs(300), Duration::from_secs(1800));
        b.on_failure();
        assert!(!b.due(Instant::now()), "실패 직후인데 바로 또 시도한다");
    }

    /// 실사용 dial 실패도 헬스에 반영돼야 한다. 상류는 로그만 남긴다
    /// (meow-tunnel/src/tcp.rs).
    #[test]
    fn repeated_dial_failures_mark_the_member_dead() {
        let h = ProxyHealth::new();
        h.record_delay(42);
        assert!(h.alive());
        for _ in 0..DIAL_FAILURES_BEFORE_DEAD - 1 {
            assert!(!h.record_dial_failure(), "한 번 실패에 죽으면 과민하다");
            assert!(h.alive());
        }
        assert!(h.record_dial_failure(), "임계에 도달했는데 죽지 않았다");
        assert!(!h.alive());
    }

    #[test]
    fn a_dial_success_clears_the_failure_run() {
        let h = ProxyHealth::new();
        h.record_dial_failure();
        h.record_dial_failure();
        h.record_dial_success();
        for _ in 0..DIAL_FAILURES_BEFORE_DEAD - 1 {
            assert!(!h.record_dial_failure());
        }
        assert!(h.alive(), "성공이 실패 연속을 끊지 못했다");
    }

    /// 트래픽이 실제로 흐르면 프로브가 뭐라 했든 살아 있는 것이다 — 프로브 URL
    /// 자체가 막힌 상황(중국)에서 노드를 되살리는 유일한 경로다.
    #[test]
    fn a_dial_success_revives_a_member_a_probe_had_killed() {
        let h = ProxyHealth::new();
        h.record_delay(0);
        assert!(!h.alive());
        h.record_dial_success();
        assert!(h.alive());
    }

    /// 프로브 성공도 실패 연속을 끊는다. 안 그러면 몇 시간 전 실패 둘이
    /// 남아 있다가 새 실패 하나에 노드를 죽인다.
    #[test]
    fn a_successful_probe_also_clears_the_failure_run() {
        let h = ProxyHealth::new();
        h.record_dial_failure();
        h.record_dial_failure();
        h.record_delay(30);
        assert!(!h.record_dial_failure());
        assert!(h.alive());
    }

    #[test]
    fn delay_history_time_serializes_as_rfc3339_string() {
        let entry = DelayHistory {
            time: UNIX_EPOCH + Duration::from_secs(1_751_527_000),
            delay: 76,
        };
        let json = serde_json::to_value(&entry).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({"time": "2025-07-03T07:16:40Z", "delay": 76}),
        );
    }

    #[test]
    fn delay_history_round_trips_through_json() {
        let entry = DelayHistory {
            time: UNIX_EPOCH + Duration::from_secs(1_751_527_000),
            delay: 321,
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let back: DelayHistory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.time, entry.time);
        assert_eq!(back.delay, entry.delay);
    }
}
