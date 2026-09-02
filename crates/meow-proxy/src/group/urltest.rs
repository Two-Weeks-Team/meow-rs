use super::selector_store::SelectorStore;
use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, ProxySelection, Result,
};
use parking_lot::RwLock;
use smol_str::SmolStr;
use std::sync::Arc;

/// Matches the health-check probe timeout (`meow-app`'s `PROBE_TIMEOUT`), so a
/// bootstrap race gives up on the same schedule a probe would.
const BOOTSTRAP_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Upper bound on how many members a single cold-boot race opens at once. A
/// group with dozens of members should not answer its first request with
/// dozens of simultaneous connections.
const MAX_BOOTSTRAP_RACE: usize = 4;

pub struct UrlTestGroup {
    name: SmolStr,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,
    tolerance: u16,
    /// User-fixed member. This is independent from `fastest`, which remains
    /// the automatic URL-test incumbent.
    fixed: RwLock<Option<SmolStr>>,
    store: Option<Arc<SelectorStore>>,
    test_url: String,
    expected_status: String,
    /// Name of the currently selected proxy; `None` means "not yet picked,
    /// use the first available".  Updated by `pick_for_dial` whenever it
    /// promotes a new best.
    fastest: RwLock<Option<SmolStr>>,
    health: ProxyHealth,
}

impl UrlTestGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>, tolerance: u16) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: Vec::new(),
            tolerance,
            fixed: RwLock::new(None),
            store: None,
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            fastest: RwLock::new(None),
            health: ProxyHealth::new(),
        }
    }

    pub fn new_with_providers(
        name: &str,
        proxies: Vec<Arc<dyn Proxy>>,
        tolerance: u16,
        slots: Vec<ProviderSlot>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: slots,
            tolerance,
            fixed: RwLock::new(None),
            store: None,
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            fastest: RwLock::new(None),
            health: ProxyHealth::new(),
        }
    }

    #[must_use]
    pub fn with_runtime_options(
        mut self,
        test_url: String,
        expected_status: String,
        store: Option<Arc<SelectorStore>>,
    ) -> Self {
        self.test_url = test_url;
        self.expected_status = expected_status;
        if let Some(store) = store {
            if let Some(prev) = store.get(&self.name).filter(|v| !v.is_empty()) {
                *self.fixed.write() = Some(SmolStr::from(prev));
            }
            self.store = Some(store);
        }
        self
    }

    fn contains_name(&self, name: &str) -> bool {
        self.static_proxies.iter().any(|p| p.name() == name)
            || self.provider_slots.iter().any(|slot| {
                let guard = slot.read();
                guard.iter().any(|p| p.name() == name)
            })
    }

    fn fixed_proxy_if_alive(&self) -> Option<Arc<dyn Proxy>> {
        let name = self.fixed.read().clone()?;
        for p in &self.static_proxies {
            if p.name() == name && p.alive_for_url(&self.test_url) {
                return Some(Arc::clone(p));
            }
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                if p.name() == name && p.alive_for_url(&self.test_url) {
                    return Some(Arc::clone(p));
                }
            }
        }
        None
    }

    /// Single-pass dial-path selector: walks `static_proxies` + provider
    /// slots once without allocating a unified Vec, updates `self.fastest`
    /// if a strictly-better-by-tolerance alternative exists (or if the
    /// current pick has died), and returns the chosen proxy.
    ///
    /// Previously this was three separate full scans per dial:
    /// `update_fastest` cloned the Vec once, scanned to find best, then
    /// scanned again to read the current proxy's delay/aliveness; then
    /// `fastest_proxy` cloned the Vec a second time to look up by name.
    fn pick_for_dial(&self) -> Option<Arc<dyn Proxy>> {
        if let Some(proxy) = self.fixed_proxy_if_alive() {
            return Some(proxy);
        }
        let current_name: Option<SmolStr> = self.fastest.read().clone();

        let mut best_proxy: Option<Arc<dyn Proxy>> = None;
        let mut best_delay: u16 = u16::MAX;
        let mut current_proxy: Option<Arc<dyn Proxy>> = None;
        let mut current_delay: u16 = u16::MAX;
        let mut current_alive = false;
        let mut first_any: Option<Arc<dyn Proxy>> = None;
        // The first member that is at least *marked* alive. `first_any` says
        // nothing about liveness — it is whatever the config listed first —
        // so falling back to it hands the dial to a member already known to
        // be down while a live one sits next to it.
        let mut first_alive: Option<Arc<dyn Proxy>> = None;

        // Inline visit logic to avoid an `FnMut` closure that would conflict
        // with the multiple mutable borrows below.
        macro_rules! visit {
            ($p:expr) => {{
                let p: &Arc<dyn Proxy> = $p;
                if first_any.is_none() {
                    first_any = Some(Arc::clone(p));
                }
                if p.alive() {
                    if first_alive.is_none() {
                        first_alive = Some(Arc::clone(p));
                    }
                    let d = p.last_delay();
                    if let Some(ref n) = current_name {
                        if p.name() == n.as_str() {
                            current_alive = true;
                            current_delay = d;
                            current_proxy = Some(Arc::clone(p));
                        }
                    }
                    if d > 0 && d < best_delay {
                        best_delay = d;
                        best_proxy = Some(Arc::clone(p));
                    }
                }
            }};
        }

        for p in &self.static_proxies {
            visit!(p);
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                visit!(p);
            }
        }

        if let Some(bp) = best_proxy.as_ref() {
            if best_delay.saturating_add(self.tolerance) < current_delay || !current_alive {
                *self.fastest.write() = Some(SmolStr::from(bp.name()));
                return Some(Arc::clone(bp));
            }
        } else if !current_alive {
            // Return the fallback but do NOT record it as `fastest`. This is
            // a guess made with no measurements at all, and writing it makes
            // it permanent: the guess then reports `current_delay == 0` and
            // `current_alive == true`, so the promotion test below
            // (`best + tolerance < current_delay`) can never hold again and a
            // member that later gets a real measurement is never promoted.
            // `fastest` is written only where a measurement justifies it.
            //
            // Prefer a member that is still alive. Only when nobody is does
            // the first member win, and then deliberately: surfacing a real
            // network error beats a "no proxy available" config error.
            return first_alive.clone().or_else(|| first_any.clone());
        }
        current_proxy.or(best_proxy).or(first_alive).or(first_any)
    }

    /// Members worth racing while the group has no measurement to rank by.
    ///
    /// `Some` only when no member carries a delay (and the user has not
    /// pinned one, and no incumbent has been promoted). Two situations reach
    /// that state, and the second is the one that matters in production:
    ///
    /// - a genuinely cold boot — nothing probed yet. The health check runs
    ///   every 300 s by default, so this window is not always small.
    /// - **every probe failed.** That does not mean every node is unusable:
    ///   the URL test dials a fixed probe URL (`www.gstatic.com` by default),
    ///   and where that host is unreachable every member is marked dead while
    ///   the nodes themselves work fine. Selection then has nothing to go on
    ///   and hands every dial to whichever member the config listed first.
    ///
    /// So liveness is deliberately *not* a filter here. A `false` recorded by
    /// a probe that could not reach its own target says nothing about whether
    /// the node can carry traffic; the only way to find out is to try.
    /// `last_delay() > 0` is the real signal, and the moment any member has
    /// it this returns `None` and ordinary selection takes over.
    ///
    /// The common case costs one lock read: after a race wins, `fastest` is
    /// set and this returns `None` immediately.
    fn cold_boot_candidates(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        if self.fixed.read().is_some() || self.fastest.read().is_some() {
            return None;
        }
        let mut out: Vec<Arc<dyn Proxy>> = Vec::new();
        macro_rules! consider {
            ($p:expr) => {{
                let p: &Arc<dyn Proxy> = $p;
                if p.last_delay() > 0 {
                    // Somebody has been measured — ordinary selection knows
                    // more than a race would.
                    return None;
                }
                if out.len() < MAX_BOOTSTRAP_RACE {
                    out.push(Arc::clone(p));
                }
            }};
        }
        for p in &self.static_proxies {
            consider!(p);
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                consider!(p);
            }
        }
        (out.len() > 1).then_some(out)
    }

    /// Dial every candidate at once and keep the first connection that comes
    /// up; the rest are dropped, which cancels them.
    ///
    /// No user payload rides on the losers. `dial_tcp` only establishes the
    /// connection to the node — the tunnel writes the request afterwards, on
    /// the single connection returned here.
    async fn bootstrap_race(
        &self,
        candidates: &[Arc<dyn Proxy>],
        metadata: &Metadata,
    ) -> Option<(Arc<dyn Proxy>, Box<dyn ProxyConn>)> {
        use futures::stream::{FuturesUnordered, StreamExt};
        let mut futs = FuturesUnordered::new();
        for c in candidates {
            let c = Arc::clone(c);
            futs.push(async move {
                match tokio::time::timeout(BOOTSTRAP_DIAL_TIMEOUT, c.dial_tcp(metadata)).await {
                    Ok(Ok(conn)) => Some((c, conn)),
                    _ => None,
                }
            });
        }
        while let Some(r) = futs.next().await {
            if let Some(hit) = r {
                return Some(hit);
            }
        }
        None
    }

    /// Read-only lookup of whatever `fastest` currently points at — used by
    /// the REST/info methods below.  No Vec allocation; falls back to the
    /// first proxy if `fastest` is unset or names something no longer present.
    fn fastest_proxy(&self) -> Option<Arc<dyn Proxy>> {
        if let Some(proxy) = self.fixed_proxy_if_alive() {
            return Some(proxy);
        }
        let name = self.fastest.read().clone();
        let mut first_any: Option<Arc<dyn Proxy>> = None;
        if let Some(n) = name {
            for p in &self.static_proxies {
                if first_any.is_none() {
                    first_any = Some(Arc::clone(p));
                }
                if p.name() == n {
                    return Some(Arc::clone(p));
                }
            }
            for slot in &self.provider_slots {
                let guard = slot.read();
                for p in guard.iter() {
                    if first_any.is_none() {
                        first_any = Some(Arc::clone(p));
                    }
                    if p.name() == n {
                        return Some(Arc::clone(p));
                    }
                }
            }
            return first_any;
        }
        // No selection yet: return first proxy if any.
        if let Some(p) = self.static_proxies.first() {
            return Some(Arc::clone(p));
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            if let Some(p) = guard.first() {
                return Some(Arc::clone(p));
            }
        }
        None
    }

    fn member_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .static_proxies
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                out.push(p.name().to_string());
            }
        }
        out
    }
}

#[async_trait]
impl ProxyAdapter for UrlTestGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::UrlTest
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.fastest_proxy().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        // On a genuinely cold boot there is nothing to rank, so race instead
        // of trusting the config's ordering. The winner becomes the incumbent
        // and this path is skipped from the next dial on.
        if let Some(candidates) = self.cold_boot_candidates() {
            if let Some((winner, conn)) = self.bootstrap_race(&candidates, metadata).await {
                *self.fastest.write() = Some(SmolStr::from(winner.name()));
                return Ok(conn);
            }
        }
        let proxy = self
            .pick_for_dial()
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let proxy = self
            .pick_for_dial()
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
        proxy.dial_udp(metadata).await
    }

    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.fastest_proxy()
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for UrlTestGroup {
    fn alive(&self) -> bool {
        self.fastest_proxy().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.fastest_proxy().is_some_and(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.fastest_proxy().map_or(0, |p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.fastest_proxy()
            .map_or(0, |p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.fastest_proxy()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.member_names())
    }

    fn current(&self) -> Option<String> {
        self.fastest_proxy().map(|p| p.name().into())
    }

    fn selection(&self) -> Option<&dyn ProxySelection> {
        Some(self)
    }

    fn test_url(&self) -> Option<&str> {
        Some(&self.test_url)
    }

    fn expected_status(&self) -> Option<&str> {
        Some(&self.expected_status)
    }
}

#[async_trait]
impl ProxySelection for UrlTestGroup {
    async fn set(&self, name: &str) -> Result<()> {
        if !self.contains_name(name) {
            return Err(MeowError::Proxy("proxy not exist".into()));
        }
        self.force_set(Some(name));
        Ok(())
    }

    fn force_set(&self, name: Option<&str>) {
        *self.fixed.write() = name.map(SmolStr::from);
        if let Some(store) = &self.store {
            store.set(&self.name, name.unwrap_or(""));
        }
    }

    fn fixed(&self) -> Option<String> {
        Some(
            self.fixed
                .read()
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
        )
    }

    fn can_unfix(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::test_support::MockProxy;
    use meow_common::Metadata;

    fn pick(g: &UrlTestGroup) -> String {
        g.pick_for_dial().unwrap().name().to_string()
    }

    #[test]
    fn first_pick_chooses_lowest_delay_among_alive() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let c = MockProxy::new("c");
        a.set_delay(120);
        b.set_delay(30);
        c.set_delay(60);
        let g = UrlTestGroup::new("ut", vec![a, b, c], 0);
        assert_eq!(pick(&g), "b");
    }

    #[test]
    fn tolerance_keeps_current_pick_until_strictly_better() {
        // tolerance = 50: once an incumbent exists, a challenger must beat
        // it by MORE than 50 ms before the selection flips.
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(100);
        b.set_delay(80);
        let a_ref = Arc::clone(&a);
        let g = UrlTestGroup::new("ut", vec![a, b], 50);
        // First pick has no incumbent → goes to the lowest-delay member.
        assert_eq!(pick(&g), "b");

        // a comes in just inside the tolerance band — must stick with b.
        a_ref.set_delay(40);
        assert_eq!(pick(&g), "b", "tolerance prevents flapping");

        // a improves enough to clear the band → must promote.
        a_ref.set_delay(20);
        assert_eq!(pick(&g), "a");
    }

    #[test]
    fn dead_current_forces_repick_even_inside_tolerance() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(50);
        b.set_delay(80);
        let a_ref = Arc::clone(&a);
        let g = UrlTestGroup::new("ut", vec![a, b], 100);
        assert_eq!(pick(&g), "a");
        a_ref.set_alive(false);
        assert_eq!(pick(&g), "b", "current died -> must promote next best");
    }

    #[test]
    fn no_alive_members_returns_first_proxy_as_fallback() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_alive(false);
        b.set_alive(false);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);
        assert_eq!(
            g.pick_for_dial().unwrap().name(),
            "a",
            "graceful degradation: surface a real network error from a, \
             not a 'no proxy' config error"
        );
    }

    /// Cold boot has no delay history, so the picker cannot rank anyone and
    /// falls back to the first member. Latching that guess into `fastest`
    /// makes it permanent for as long as the guess stays *marked* alive:
    /// `current_delay` is then 0 and `current_alive` is true, so the
    /// promotion test `best + tolerance < current_delay` can never hold. A
    /// member that later reports a real delay is never promoted.
    ///
    /// Staying marked alive while being useless is the normal case, not a
    /// contrived one: nothing but the health check writes liveness, user
    /// dial failures do not (see `record_delay`'s only callers), and the
    /// check runs every 300 s by default.
    #[test]
    fn a_cold_boot_pick_does_not_latch_the_first_member() {
        let unprobed = MockProxy::new("unprobed");
        let live = MockProxy::new("live");
        let live_ref = Arc::clone(&live);
        let g = UrlTestGroup::new("ut", vec![unprobed, live], 150);

        // Cold boot: no history, everyone still marked alive.
        let _ = g.pick_for_dial();

        // A probe lands on `live` only. `unprobed` keeps alive=true and
        // last_delay=0 — the health check has not reached it yet.
        live_ref.set_delay(40);

        assert_eq!(
            pick(&g),
            "live",
            "a member with a real measurement lost to a latched guess"
        );
    }

    /// A cold-boot dial must reach every candidate, not only the one the
    /// config listed first. Without the race, a dead first member makes the
    /// first connection fail outright and the node order in the config
    /// decides whether the tunnel works at all.
    ///
    /// `MockProxy::dial_tcp` always fails, so no winner is possible here —
    /// what this pins is that both members were *tried*.
    #[tokio::test]
    async fn a_cold_boot_dial_reaches_every_candidate() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let g = UrlTestGroup::new("ut", vec![a, b], 150);

        let _ = g.dial_tcp(&Metadata::default()).await;

        assert!(a_ref.dials() >= 1, "첫 멤버를 시도하지 않았다");
        assert!(b_ref.dials() >= 1, "두 번째 멤버는 아예 시도되지 않았다");
    }

    /// Once anyone carries a measurement the race stops: ordinary selection
    /// knows more than a race does, and racing every dial would open a
    /// connection per member forever.
    #[tokio::test]
    async fn the_race_stops_as_soon_as_anyone_has_been_measured() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        b_ref.set_delay(30);
        let g = UrlTestGroup::new("ut", vec![a, b], 150);

        let _ = g.dial_tcp(&Metadata::default()).await;

        assert_eq!(a_ref.dials(), 0, "측정치가 있는데도 레이스를 돌았다");
        assert_eq!(b_ref.dials(), 1, "가장 빠른 멤버 하나만 걸어야 한다");
    }

    /// A member already known to be down must not win the fallback just
    /// because the config listed it first. Found by the interop harness:
    /// the startup URL test marks the unreachable node dead, which takes it
    /// out of the cold-boot race — and the fallback then handed every dial
    /// straight back to it.
    #[test]
    fn a_fallback_prefers_a_member_that_is_still_alive() {
        let dead = MockProxy::new("dead");
        dead.set_alive(false);
        let live = MockProxy::new("live"); // alive but never measured
        let g = UrlTestGroup::new("ut", vec![dead, live], 150);
        assert_eq!(pick(&g), "live", "이미 죽은 줄 아는 노드로 걸었다");
    }

    /// Every probe failing does not mean every node is unusable — the probe
    /// URL itself may be unreachable. With no measurement anywhere, the race
    /// must still try the members rather than hand every dial to member 0.
    #[tokio::test]
    async fn a_group_whose_probes_all_failed_still_races() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        // What a failed probe leaves behind: marked dead, no usable delay.
        a_ref.set_alive(false);
        b_ref.set_alive(false);
        let g = UrlTestGroup::new("ut", vec![a, b], 150);

        let _ = g.dial_tcp(&Metadata::default()).await;

        assert!(
            a_ref.dials() >= 1 && b_ref.dials() >= 1,
            "죽었다고 표시됐다는 이유로 아무도 시도하지 않았다"
        );
    }

    #[test]
    fn zero_delay_is_treated_as_unknown_not_best() {
        // last_delay == 0 means "never probed / dead"; the picker must NOT
        // consider it the lowest delay.
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        // a has no recorded delay (last_delay=0), b has 100.
        b.set_delay(100);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);
        assert_eq!(pick(&g), "b", "0-delay proxy must not win");
    }

    #[tokio::test]
    async fn dial_tcp_routes_through_pick() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(100);
        b.set_delay(20);
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert_eq!(a_ref.dials(), 0);
        assert_eq!(b_ref.dials(), 1);
    }

    #[tokio::test]
    async fn user_pin_overrides_fastest_and_can_be_cleared() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(100);
        b.set_delay(10);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);

        ProxySelection::set(&g, "a").await.unwrap();
        assert_eq!(pick(&g), "a");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some("a"));

        ProxySelection::force_set(&g, None);
        assert_eq!(pick(&g), "b");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some(""));
    }

    #[tokio::test]
    async fn dead_url_test_pin_falls_back_without_forgetting_pin() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_alive(false);
        b.set_delay(20);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);

        ProxySelection::set(&g, "a").await.unwrap();
        assert_eq!(pick(&g), "b");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some("a"));
    }
}
