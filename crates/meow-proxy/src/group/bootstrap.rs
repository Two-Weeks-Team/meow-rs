//! Cold-boot bootstrap race and dial-outcome reporting, shared by the
//! `url-test` and `fallback` groups.
//!
//! Both groups face the same blind spot: right after boot — or whenever the
//! probe URL itself is unreachable (China, where `www.gstatic.com` is
//! blocked) — every member is marked dead and nothing carries a measurement.
//! Ranking then has nothing to go on, and handing the dial to whichever
//! member the config listed first turns a dead first node into a dead tunnel.
//! The only way to learn who can carry traffic is to try; racing the members
//! and keeping the first connection that comes up is that attempt.
//!
//! `record_dial` is the other half: a real dial's outcome feeds the member's
//! health, so a node that keeps failing is eventually taken out of rotation
//! even when the probe cannot see it (hangil fork P-4).
use meow_common::{Metadata, Proxy, ProxyConn, Result};
use std::sync::Arc;
use tracing::warn;

/// Matches the health-check probe timeout (`meow-app`'s `PROBE_TIMEOUT`), so a
/// bootstrap race gives up on the same schedule a probe would.
pub(super) const BOOTSTRAP_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Upper bound on how many members a single cold-boot race opens at once. A
/// group with dozens of members should not answer its first request with
/// dozens of simultaneous connections.
pub(super) const MAX_BOOTSTRAP_RACE: usize = 4;

/// Dial every candidate at once and keep the first connection that comes
/// up; the rest are dropped, which cancels them.
///
/// No user payload rides on the losers. `dial_tcp` only establishes the
/// connection to the node — the tunnel writes the request afterwards, on
/// the single connection returned here.
pub(super) async fn bootstrap_race(
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

/// Feed the outcome of a real dial back into the member's health.
///
/// This belongs in the group rather than in the tunnel. The tunnel holds the
/// *group*, and a group's own `ProxyHealth` is not what selection reads —
/// the group delegates `alive` to whichever member is current — so reporting
/// there would change nothing. Here we know which member was actually
/// dialled.
///
/// A single failure does not condemn a member; `record_dial_failure` counts
/// consecutive failures and only marks it dead at the threshold.
pub(super) fn record_dial<T>(proxy: &Arc<dyn Proxy>, outcome: Result<T>) -> Result<T> {
    match outcome {
        Ok(v) => {
            proxy.health().record_dial_success();
            Ok(v)
        }
        Err(e) => {
            if proxy.health().record_dial_failure() {
                warn!(
                    "{} marked dead after {} consecutive dial failures; last: {}",
                    proxy.name(),
                    meow_common::DIAL_FAILURES_BEFORE_DEAD,
                    e
                );
            }
            Err(e)
        }
    }
}
