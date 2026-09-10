//! RAII route installation for the TUN inbound's `auto-route`.
//!
//! Fake-IP mode deliberately routes only the fake-IP range into the device
//! (see the module docs in `mod.rs` for the loop-freedom argument). Global
//! mode installs only owned split defaults into the device. Existing
//! more-specific LAN routes are left untouched; outbound sockets bind to the
//! physical interface for proxy and DIRECT egress. Routes are added with the
//! blocking `route_manager` API at listener startup and removed on drop.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use route_manager::{Route, RouteManager};
use tracing::{debug, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PhysicalEgress {
    if_index: Option<u32>,
    if_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedRoute {
    net: IpNet,
    if_index: u32,
}

pub(super) struct RouteGuard {
    manager: RouteManager,
    installed: Vec<Route>,
}

impl RouteGuard {
    /// Install one on-link route per net through interface `if_index`.
    /// Individual failures are logged and skipped so a pre-existing
    /// equivalent route does not abort listener startup.
    pub(super) fn setup(if_index: u32, nets: &[IpNet]) -> std::io::Result<Self> {
        let mut manager = RouteManager::new()?;
        let plan = fake_ip_route_plan(if_index, nets);
        let installed = add_best_effort(&mut manager, &plan);
        Ok(Self { manager, installed })
    }

    /// Install global-capture routes and fail closed on any add failure.
    /// Already-added routes are removed before returning the error, so a
    /// startup failure cannot leave half of the split default active.
    pub(super) fn setup_global(if_index: u32) -> std::io::Result<Self> {
        let mut manager = RouteManager::new()?;
        let plan = global_route_plan(if_index);
        let installed = add_required_with_rollback(&mut manager, &plan)?;
        Ok(Self { manager, installed })
    }
}

trait RouteBackend {
    fn add_route(&mut self, route: &Route) -> std::io::Result<()>;
    fn delete_route(&mut self, route: &Route) -> std::io::Result<()>;
}

impl RouteBackend for RouteManager {
    fn add_route(&mut self, route: &Route) -> std::io::Result<()> {
        self.add(route)
    }

    fn delete_route(&mut self, route: &Route) -> std::io::Result<()> {
        self.delete(route)
    }
}

fn add_best_effort(manager: &mut impl RouteBackend, plan: &[PlannedRoute]) -> Vec<Route> {
    let mut installed = Vec::with_capacity(plan.len());
    for planned in plan {
        let route = planned.to_route();
        match manager.add_route(&route) {
            Ok(()) => {
                debug!("tun auto-route: added {}", planned.describe());
                installed.push(route);
            }
            Err(e) => warn!(
                "tun auto-route: failed to add {}: {e} (continuing — the device subnet may \
                 already cover it)",
                planned.describe()
            ),
        }
    }
    installed
}

fn add_required_with_rollback(
    manager: &mut impl RouteBackend,
    plan: &[PlannedRoute],
) -> std::io::Result<Vec<Route>> {
    let mut installed = Vec::with_capacity(plan.len());
    for planned in plan {
        let route = planned.to_route();
        match manager.add_route(&route) {
            Ok(()) => {
                debug!("tun auto-route: added {}", planned.describe());
                installed.push(route);
            }
            Err(e) => {
                for route in installed.iter().rev() {
                    if let Err(delete_err) = manager.delete_route(route) {
                        warn!("tun auto-route: rollback failed to remove {route}: {delete_err}");
                    }
                }
                return Err(std::io::Error::other(format!(
                    "failed to add {}: {e}",
                    planned.describe()
                )));
            }
        }
    }
    Ok(installed)
}

impl PlannedRoute {
    fn to_route(&self) -> Route {
        let mut route = Route::new(self.net.network(), self.net.prefix_len());
        route = route.with_if_index(self.if_index);
        route
    }

    fn describe(&self) -> String {
        format!("{} via tun if_index {}", self.net, self.if_index)
    }
}

fn fake_ip_route_plan(if_index: u32, nets: &[IpNet]) -> Vec<PlannedRoute> {
    nets.iter()
        .copied()
        .map(|net| PlannedRoute { net, if_index })
        .collect()
}

fn global_route_plan(if_index: u32) -> Vec<PlannedRoute> {
    vec![
        PlannedRoute {
            net: cidr("0.0.0.0/1"),
            if_index,
        },
        PlannedRoute {
            net: cidr("128.0.0.0/1"),
            if_index,
        },
    ]
}

fn cidr(net: &str) -> IpNet {
    net.parse().expect("static CIDR parses")
}

pub(super) fn default_egress() -> std::io::Result<PhysicalEgress> {
    let mut manager = RouteManager::new()?;
    let route = manager
        .find_route(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))?
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no IPv4 default route found")
        })?;

    Ok(PhysicalEgress {
        if_index: route.if_index(),
        if_name: route.if_name().cloned(),
    })
}

/// Pick a usable interface identifier for the outbound-socket binding hook.
/// Prefer the configured value, otherwise use the default egress name when
/// available and fall back to the interface index. Linux resolves that index
/// to a name because SO_BINDTODEVICE takes a name rather than an index.
pub(super) fn outbound_interface_name(
    configured: Option<String>,
    physical: Option<&PhysicalEgress>,
) -> std::io::Result<String> {
    if let Some(name) = configured.filter(|s| !s.is_empty()) {
        return Ok(name);
    }
    let physical = physical.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no configured outbound interface and no default egress was discovered",
        )
    })?;
    if let Some(name) = &physical.if_name {
        return Ok(name.clone());
    }
    if let Some(index) = physical.if_index {
        #[cfg(target_os = "linux")]
        {
            return linux_if_index_to_name(index);
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Ok(index.to_string());
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "default route did not include an interface name or index",
    ))
}

#[cfg(target_os = "linux")]
fn linux_if_index_to_name(index: u32) -> std::io::Result<String> {
    let mut ifname = [0 as libc::c_char; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(index, ifname.as_mut_ptr()) };
    if ptr.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    unsafe { std::ffi::CStr::from_ptr(ifname.as_ptr()) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("interface index {index} resolved to non-UTF-8 name"),
            )
        })
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for route in &self.installed {
            if let Err(e) = self.manager.delete(route) {
                warn!("tun auto-route: failed to remove {route}: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv4Net;

    #[test]
    fn global_route_plan_only_owns_split_defaults() {
        let plan = global_route_plan(42);
        let nets: Vec<String> = plan.iter().map(|p| p.net.to_string()).collect();
        assert_eq!(nets, vec!["0.0.0.0/1", "128.0.0.0/1"]);
        assert!(plan.iter().all(|p| p.if_index == 42));
    }

    #[test]
    fn fake_ip_route_plan_only_routes_requested_nets() {
        let nets = vec![IpNet::V4(
            Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 16).unwrap(),
        )];
        let plan = fake_ip_route_plan(9, &nets);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].net.to_string(), "198.18.0.0/16");
        assert_eq!(plan[0].if_index, 9);
    }

    #[derive(Default)]
    struct FakeBackend {
        fail_add_at: Option<usize>,
        adds: Vec<Route>,
        deletes: Vec<Route>,
    }

    impl RouteBackend for FakeBackend {
        fn add_route(&mut self, route: &Route) -> std::io::Result<()> {
            if self.fail_add_at == Some(self.adds.len()) {
                return Err(std::io::Error::other("injected add failure"));
            }
            self.adds.push(route.clone());
            Ok(())
        }

        fn delete_route(&mut self, route: &Route) -> std::io::Result<()> {
            self.deletes.push(route.clone());
            Ok(())
        }
    }

    #[test]
    fn required_setup_rolls_back_on_add_failure() {
        let plan = global_route_plan(42);
        let mut backend = FakeBackend {
            fail_add_at: Some(1),
            ..Default::default()
        };
        let err = add_required_with_rollback(&mut backend, &plan).unwrap_err();
        assert!(err.to_string().contains("128.0.0.0/1"), "{err}");
        assert_eq!(backend.adds.len(), 1);
        assert_eq!(
            backend.deletes,
            backend.adds.iter().rev().cloned().collect::<Vec<_>>()
        );
    }

    #[test]
    fn best_effort_setup_keeps_successful_routes() {
        let plan = fake_ip_route_plan(
            9,
            &[
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 16).unwrap()),
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(203, 0, 113, 0), 24).unwrap()),
            ],
        );
        let mut backend = FakeBackend {
            fail_add_at: Some(1),
            ..Default::default()
        };
        let installed = add_best_effort(&mut backend, &plan);
        assert_eq!(installed.len(), 1);
        assert_eq!(backend.deletes.len(), 0);
    }

    #[test]
    fn outbound_interface_uses_config_then_default_name_then_index() {
        let physical = PhysicalEgress {
            if_index: Some(7),
            if_name: Some("en0".into()),
        };
        assert_eq!(
            outbound_interface_name(Some("Ethernet".into()), None).unwrap(),
            "Ethernet"
        );
        assert_eq!(
            outbound_interface_name(None, Some(&physical)).unwrap(),
            "en0"
        );

        #[cfg(not(target_os = "linux"))]
        {
            let physical = PhysicalEgress {
                if_index: Some(7),
                if_name: None,
            };
            assert_eq!(outbound_interface_name(None, Some(&physical)).unwrap(), "7");
        }
        assert!(outbound_interface_name(None, None).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_outbound_interface_resolves_index_to_name() {
        let lo = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(lo, 0, "lo must exist");
        let physical = PhysicalEgress {
            if_index: Some(lo),
            if_name: None,
        };
        assert_eq!(
            outbound_interface_name(None, Some(&physical)).unwrap(),
            "lo"
        );
        assert!(linux_if_index_to_name(0).is_err());
    }
}
