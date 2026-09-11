//! RAII route installation for the TUN inbound's `auto-route`.
//!
//! Fake-IP mode deliberately routes only the fake-IP range into the device
//! (see the module docs in `mod.rs` for the loop-freedom argument). Global
//! mode installs owned split defaults into the device. On macOS it first
//! ensures a scoped physical default route exists for sockets bound with
//! `IP_BOUND_IF`; that route is owned and cleaned up only when meow added it.
//! Existing more-specific LAN routes are left untouched; outbound sockets bind
//! to the physical interface for proxy and DIRECT egress. Routes are added
//! with the blocking `route_manager` API at listener startup and removed on
//! drop.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use route_manager::{Route, RouteManager};
use tracing::{debug, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PhysicalEgress {
    if_index: Option<u32>,
    if_name: Option<String>,
    gateway: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PlannedRoute {
    Tun {
        net: IpNet,
        if_index: u32,
    },
    #[cfg(target_os = "macos")]
    MacScopedDefault {
        if_index: u32,
        if_name: Option<String>,
        gateway: IpAddr,
    },
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
    pub(super) fn setup_global(
        if_index: u32,
        physical: Option<&PhysicalEgress>,
    ) -> std::io::Result<Self> {
        let mut manager = RouteManager::new()?;
        #[cfg(target_os = "macos")]
        let existing = manager.list()?;
        #[cfg(not(target_os = "macos"))]
        let existing = Vec::new();
        let plan = global_route_plan(if_index, physical, &existing)?;
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
        match self {
            PlannedRoute::Tun { net, if_index } => {
                Route::new(net.network(), net.prefix_len()).with_if_index(*if_index)
            }
            #[cfg(target_os = "macos")]
            PlannedRoute::MacScopedDefault {
                if_index,
                if_name,
                gateway,
            } => {
                let mut route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                    .with_gateway(*gateway)
                    .with_if_index(*if_index)
                    .with_if_scope(true);
                if let Some(name) = if_name.clone() {
                    route = route.with_if_name(name);
                }
                route
            }
        }
    }

    fn describe(&self) -> String {
        match self {
            PlannedRoute::Tun { net, if_index } => {
                format!("{net} via tun if_index {if_index}")
            }
            #[cfg(target_os = "macos")]
            PlannedRoute::MacScopedDefault {
                if_index, gateway, ..
            } => format!("default via gateway {gateway} scoped to if_index {if_index}"),
        }
    }
}

fn fake_ip_route_plan(if_index: u32, nets: &[IpNet]) -> Vec<PlannedRoute> {
    nets.iter()
        .copied()
        .map(|net| PlannedRoute::Tun { net, if_index })
        .collect()
}

fn global_route_plan(
    if_index: u32,
    physical: Option<&PhysicalEgress>,
    existing: &[Route],
) -> std::io::Result<Vec<PlannedRoute>> {
    let mut routes = Vec::with_capacity(3);

    #[cfg(target_os = "macos")]
    {
        let scoped_default = macos_scoped_default_plan(physical)?;
        if !existing.iter().any(|route| scoped_default.matches(route)) {
            routes.push(PlannedRoute::MacScopedDefault {
                if_index: scoped_default.if_index,
                if_name: scoped_default.if_name,
                gateway: scoped_default.gateway,
            });
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = physical;
        let _ = existing;
    }

    routes.extend([
        PlannedRoute::Tun {
            net: cidr("0.0.0.0/1"),
            if_index,
        },
        PlannedRoute::Tun {
            net: cidr("128.0.0.0/1"),
            if_index,
        },
    ]);
    Ok(routes)
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct MacScopedDefaultPlan {
    if_index: u32,
    if_name: Option<String>,
    gateway: IpAddr,
}

#[cfg(target_os = "macos")]
impl MacScopedDefaultPlan {
    fn matches(&self, route: &Route) -> bool {
        route.destination() == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            && route.prefix() == 0
            && route.gateway() == Some(self.gateway)
            && route.if_scope()
            && (route.if_index() == Some(self.if_index)
                || self
                    .if_name
                    .as_ref()
                    .is_some_and(|name| route.if_name() == Some(name)))
    }
}

#[cfg(target_os = "macos")]
fn macos_scoped_default_plan(
    physical: Option<&PhysicalEgress>,
) -> std::io::Result<MacScopedDefaultPlan> {
    let Some(physical) = physical else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "macOS global auto-route requires the pre-TUN physical egress",
        ));
    };
    let if_index = physical.if_index.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "macOS physical egress did not include an interface index",
        )
    })?;
    let gateway = physical.gateway.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "macOS physical egress did not include a gateway for scoped default route",
        )
    })?;
    Ok(MacScopedDefaultPlan {
        if_index,
        if_name: physical.if_name.clone(),
        gateway,
    })
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

    Ok(physical_egress_from_route(&route))
}

#[cfg(target_os = "macos")]
pub(super) fn default_egress_for_interface(configured: &str) -> std::io::Result<PhysicalEgress> {
    let mut manager = RouteManager::new()?;
    let routes = manager.list()?;
    default_egress_for_interface_from_routes(configured, &routes)
}

fn physical_egress_from_route(route: &Route) -> PhysicalEgress {
    PhysicalEgress {
        if_index: route.if_index(),
        if_name: route.if_name().cloned(),
        gateway: route.gateway(),
    }
}

#[cfg(target_os = "macos")]
fn default_egress_for_interface_from_routes(
    configured: &str,
    routes: &[Route],
) -> std::io::Result<PhysicalEgress> {
    routes
        .iter()
        .find(|route| {
            route.destination() == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                && route.prefix() == 0
                && route.gateway().is_some()
                && route_matches_interface(route, configured)
        })
        .map(physical_egress_from_route)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no IPv4 default route found for outbound interface '{configured}'"),
            )
        })
}

#[cfg(target_os = "macos")]
fn route_matches_interface(route: &Route, configured: &str) -> bool {
    if route.if_name().is_some_and(|name| name == configured) {
        return true;
    }
    configured
        .parse::<u32>()
        .is_ok_and(|index| route.if_index() == Some(index))
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
        for route in self.installed.iter().rev() {
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

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn global_route_plan_only_owns_split_defaults() {
        let plan = global_route_plan(42, None, &[]).unwrap();
        let nets: Vec<String> = plan
            .iter()
            .map(|p| match p {
                PlannedRoute::Tun { net, .. } => net.to_string(),
            })
            .collect();
        assert_eq!(nets, vec!["0.0.0.0/1", "128.0.0.0/1"]);
        assert!(plan
            .iter()
            .all(|p| matches!(p, PlannedRoute::Tun { if_index: 42, .. })));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_global_route_plan_adds_scoped_default_before_split_defaults() {
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 64, 1));
        let physical = PhysicalEgress {
            if_index: Some(7),
            if_name: Some("en0".into()),
            gateway: Some(gateway),
        };
        let plan = global_route_plan(42, Some(&physical), &[]).unwrap();
        assert_eq!(plan.len(), 3);
        assert!(matches!(
            &plan[0],
            PlannedRoute::MacScopedDefault {
                if_index: 7,
                if_name,
                gateway: route_gateway,
            } if if_name.as_deref() == Some("en0") && *route_gateway == gateway
        ));
        assert!(matches!(
            &plan[1],
            PlannedRoute::Tun { net, if_index: 42 } if net.to_string() == "0.0.0.0/1"
        ));
        assert!(matches!(
            &plan[2],
            PlannedRoute::Tun { net, if_index: 42 } if net.to_string() == "128.0.0.0/1"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_global_route_plan_preserves_existing_scoped_default() {
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 64, 1));
        let physical = PhysicalEgress {
            if_index: Some(7),
            if_name: Some("en0".into()),
            gateway: Some(gateway),
        };
        let existing = vec![Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .with_gateway(gateway)
            .with_if_index(7)
            .with_if_name("en0".into())
            .with_if_scope(true)];
        let plan = global_route_plan(42, Some(&physical), &existing).unwrap();
        assert_eq!(plan.len(), 2);
        assert!(plan
            .iter()
            .all(|planned| matches!(planned, PlannedRoute::Tun { .. })));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_global_route_plan_requires_physical_gateway() {
        let physical = PhysicalEgress {
            if_index: Some(7),
            if_name: Some("en0".into()),
            gateway: None,
        };
        let err = global_route_plan(42, Some(&physical), &[]).unwrap_err();
        assert!(err.to_string().contains("gateway"), "{err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_configured_interface_selects_matching_default_route() {
        let en0_gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 64, 1));
        let en1_gateway = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let routes = vec![
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                .with_gateway(en0_gateway)
                .with_if_index(7)
                .with_if_name("en0".into()),
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                .with_gateway(en1_gateway)
                .with_if_index(8)
                .with_if_name("en1".into()),
        ];

        let by_name = default_egress_for_interface_from_routes("en1", &routes).unwrap();
        assert_eq!(by_name.if_index, Some(8));
        assert_eq!(by_name.if_name.as_deref(), Some("en1"));
        assert_eq!(by_name.gateway, Some(en1_gateway));

        let by_index = default_egress_for_interface_from_routes("7", &routes).unwrap();
        assert_eq!(by_index.if_index, Some(7));
        assert_eq!(by_index.gateway, Some(en0_gateway));

        let err = default_egress_for_interface_from_routes("en2", &routes).unwrap_err();
        assert!(err.to_string().contains("en2"), "{err}");
    }

    #[test]
    fn fake_ip_route_plan_only_routes_requested_nets() {
        let nets = vec![IpNet::V4(
            Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 16).unwrap(),
        )];
        let plan = fake_ip_route_plan(9, &nets);
        assert_eq!(plan.len(), 1);
        assert!(matches!(
            &plan[0],
            PlannedRoute::Tun { net, if_index: 9 } if net.to_string() == "198.18.0.0/16"
        ));
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
        let plan = vec![
            PlannedRoute::Tun {
                net: cidr("0.0.0.0/1"),
                if_index: 42,
            },
            PlannedRoute::Tun {
                net: cidr("128.0.0.0/1"),
                if_index: 42,
            },
        ];
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

    #[cfg(target_os = "macos")]
    #[test]
    fn required_setup_rolls_back_owned_scoped_default_on_split_failure() {
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 64, 1));
        let physical = PhysicalEgress {
            if_index: Some(7),
            if_name: Some("en0".into()),
            gateway: Some(gateway),
        };
        let plan = global_route_plan(42, Some(&physical), &[]).unwrap();
        let mut backend = FakeBackend {
            fail_add_at: Some(1),
            ..Default::default()
        };
        let err = add_required_with_rollback(&mut backend, &plan).unwrap_err();
        assert!(err.to_string().contains("0.0.0.0/1"), "{err}");
        assert_eq!(backend.adds.len(), 1);
        assert_eq!(backend.deletes, backend.adds);
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
            gateway: None,
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
                gateway: None,
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
            gateway: None,
        };
        assert_eq!(
            outbound_interface_name(None, Some(&physical)).unwrap(),
            "lo"
        );
        assert!(linux_if_index_to_name(0).is_err());
    }
}
