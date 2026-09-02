use meow_common::Backoff;
use meow_tunnel::Tunnel;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const DEFAULT_URL: &str = "http://www.gstatic.com/generate_204";
const DEFAULT_INTERVAL_SECS: u64 = 300;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Ceiling on how far a failing member's probes are spaced out. Half an hour
/// is long enough to stop hammering a node that is simply gone, and short
/// enough that one which comes back is noticed without a restart.
const MAX_PROBE_BACKOFF: Duration = Duration::from_secs(1800);

pub struct HealthCheckSpec {
    pub group_name: String,
    pub url: String,
    pub interval_secs: u64,
    pub lazy: bool,
}

pub fn extract_specs(raw_groups: &[meow_config::raw::RawProxyGroup]) -> Vec<HealthCheckSpec> {
    raw_groups
        .iter()
        .filter(|g| matches!(g.group_type.as_str(), "fallback" | "url-test"))
        .map(|g| HealthCheckSpec {
            group_name: g.name.clone(),
            url: g.url.as_deref().unwrap_or(DEFAULT_URL).to_string(),
            interval_secs: g
                .interval
                .filter(|interval| *interval > 0)
                .unwrap_or(DEFAULT_INTERVAL_SECS),
            lazy: g.lazy.unwrap_or(false),
        })
        .collect()
}

pub fn spawn_health_checks(tunnel: &Tunnel, specs: Vec<HealthCheckSpec>) {
    for spec in specs {
        let tunnel = tunnel.clone();
        tokio::spawn(async move {
            run_health_check_loop(tunnel, spec).await;
        });
    }
}

async fn run_health_check_loop(tunnel: Tunnel, spec: HealthCheckSpec) {
    let mut ticker = tokio::time::interval(Duration::from_secs(spec.interval_secs));

    if spec.lazy {
        ticker.tick().await;
    }

    // Per-member retry spacing. Upstream probes every member on every tick
    // regardless of how long it has been failing, so a node that is simply
    // gone is dialled every interval forever — on a phone that is a wake-up
    // and a handshake attempt each time. One success clears the penalty.
    //
    // Kept here rather than inside `ProxyHealth` on purpose: that type is
    // owned by around thirty adapter implementations, and putting mutable
    // scheduling state in it would touch all of them. The loop that does the
    // scheduling is the thing that needs to remember.
    let mut backoff: HashMap<String, Backoff> = HashMap::new();

    loop {
        ticker.tick().await;

        let route = tunnel.route_snapshot();
        let proxies = &route.proxies;
        let Some(group) = proxies.get(spec.group_name.as_str()).cloned() else {
            debug!(
                "health-check: group '{}' not found, skipping tick",
                spec.group_name
            );
            continue;
        };
        let Some(member_names) = group.members() else {
            continue;
        };

        let all_members: Vec<_> = member_names
            .into_iter()
            .filter_map(|n| proxies.get(n.as_str()).cloned().map(|p| (n, p)))
            .collect();
        drop(route);

        // Forget members that have left the group, so a provider that churns
        // its node list cannot grow this map without bound.
        backoff.retain(|name, _| all_members.iter().any(|(n, _)| n.as_str() == name));

        let now = Instant::now();
        let mut skipped = 0u32;
        let members: Vec<_> = all_members
            .into_iter()
            .filter(|(name, _)| {
                let due = backoff.get(name.as_str()).is_none_or(|b| b.due(now));
                if !due {
                    skipped += 1;
                }
                due
            })
            .collect();
        if members.is_empty() {
            debug!(
                "health-check: {} — every member is backing off, skipping tick",
                spec.group_name
            );
            continue;
        }

        let mut alive_count = 0u32;
        let mut total_count = 0u32;
        for (name, delay) in meow_proxy::health::probe_many_bounded(
            members,
            &spec.url,
            None,
            PROBE_TIMEOUT,
            meow_proxy::health::PROVIDER_HEALTHCHECK_CONCURRENCY,
        )
        .await
        {
            total_count += 1;
            if delay > 0 {
                alive_count += 1;
                backoff.remove(name.as_str());
            } else {
                let wait = backoff
                    .entry(name.to_string())
                    .or_insert_with(|| {
                        Backoff::new(Duration::from_secs(spec.interval_secs), MAX_PROBE_BACKOFF)
                    })
                    .on_failure();
                warn!(
                    "health-check: {} / {} is dead (probe failed); next probe in {}s",
                    spec.group_name,
                    name,
                    wait.as_secs()
                );
            }
        }

        if skipped > 0 {
            info!(
                "health-check: {} — {}/{} alive ({} backing off)",
                spec.group_name, alive_count, total_count, skipped
            );
        } else {
            info!(
                "health-check: {} — {}/{} alive",
                spec.group_name, alive_count, total_count
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_interval_uses_safe_default() {
        let group = meow_config::raw::RawProxyGroup {
            name: "auto".into(),
            group_type: "url-test".into(),
            interval: Some(0),
            ..Default::default()
        };
        let specs = extract_specs(&[group]);
        assert_eq!(specs[0].interval_secs, DEFAULT_INTERVAL_SECS);
    }
}
