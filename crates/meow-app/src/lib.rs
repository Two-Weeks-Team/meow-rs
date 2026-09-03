//! CLI and service helpers for the meow-rs proxy kernel.
//!
//! Library surface used by the `meow` binary: systemd unit generation,
//! geodata fetch, health checks, and subscription refresh. The binary wires
//! configuration, the tunnel, listeners, DNS, and the REST API together.

pub mod geodata_fetch;
pub mod health_check;
pub mod subscription_refresh;

/// Generate a systemd unit file for the meow service.
///
/// Returns the unit file content as a string.
///
/// # Arguments
/// * `exe_path` - Absolute path to the meow binary
/// * `config_path` - Absolute path to the configuration file
pub fn generate_systemd_unit(exe_path: &str, config_path: &str) -> String {
    let work_dir = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("/"))
        .to_string_lossy()
        .to_string();

    format!(
        r#"[Unit]
Description=meow-rs proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe_path} -f {config_path}
WorkingDirectory={work_dir}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={work_dir}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#,
    )
}

// ── hangil 포크 패치 ────────────────────────────────────────────────────────
// `run()` 은 `main.rs` 안의 비공개 함수라 임베더가 쓸 수 없었다. 여기로 옮겨
// `pub` 으로 만든다. `ShutdownSignal` 과 `ReadyCallback` 은 그 시그니처에
//나타나므로 함께 옮긴다. 로직은 한 줄도 바꾸지 않았다 — 가시성만 바뀌었다.
use anyhow::Result;
use dashmap::DashMap;
#[cfg(feature = "listener-tun")]
use meow_api::tun_config_to_listener_config;
use meow_api::ApiServer;
use meow_config::proxy_provider::ProxyProvider;
use meow_dns::DnsServer;
#[cfg(feature = "listener-mixed")]
use meow_listener::MixedListener;
use meow_listener::SnifferRuntime;
#[cfg(feature = "listener-tproxy")]
use meow_listener::TProxyListener;
#[cfg(feature = "listener-tun")]
use meow_listener::TunListener;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{error, info, warn};

// hangil 포크: P-1 이 `run()` 을 `main.rs` 에서 여기로 옮기면서
// `#[cfg(target_os = "windows")] mod windows_service;` 선언까지 함께 복사했다.
// 그 모듈은 **바이너리의 것**이다 — `super::{Args, LogTarget, run_application}`
// 을 참조하는데 셋 다 `main.rs` 에만 있다. 그래서 Windows 를 타깃하면
// 라이브러리가 그 파일을 자기 루트에 대고 컴파일하려다 죽는다:
//   error[E0432]: unresolved imports `super::Args`, `super::LogTarget`
//   error[E0425]: cannot find function `run_application` in module `super`
// `main.rs:15` 가 같은 선언을 그대로 갖고 있고 호출부 4곳도 거기 있으므로,
// 여기서는 지우기만 하면 된다. lib.rs 안에는 참조가 한 곳도 없었다.
//
// P-3 과 같은 종류의 잔재다 — P-1 이 옮기면서 남긴 것을, 그 플랫폼을
// 빌드해 보기 전까지 아무도 볼 수 없었다.

pub enum ShutdownSignal {
    Console,
    #[cfg(target_os = "windows")]
    WindowsService(tokio::sync::oneshot::Receiver<()>),
}

impl ShutdownSignal {
    pub async fn wait(self) -> Result<()> {
        match self {
            Self::Console => {
                #[cfg(unix)]
                {
                    let mut sigterm =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {},
                        _ = sigterm.recv() => {},
                    }
                }
                #[cfg(not(unix))]
                {
                    tokio::signal::ctrl_c().await?;
                }
                Ok(())
            }
            #[cfg(target_os = "windows")]
            Self::WindowsService(receiver) => receiver
                .await
                .map_err(|_| anyhow::anyhow!("Windows service shutdown channel closed")),
        }
    }
}

pub type ReadyCallback = Box<dyn FnOnce() -> Result<()> + Send>;

/// Build a listener bind address from an IP-literal `listen` string and a port.
///
/// Parses `listen` as an `IpAddr` and composes via `SocketAddr::new`, instead
/// of `format!("{listen}:{port}")`. The string form produces an unparseable
/// `:::7890` for an IPv6 listen address like `::`, which silently broke
/// dual-stack binding (`bind-address: '::'`); `SocketAddr::new` handles IPv4
/// and IPv6 uniformly. `listen` is always an IP literal here (`0.0.0.0`, `::`,
/// `127.0.0.1`, or a specific address).
fn bind_socket_addr(listen: &str, port: u16) -> Result<SocketAddr> {
    let ip: IpAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address '{listen}': {e}"))?;
    Ok(SocketAddr::new(ip, port))
}

pub async fn run(
    config: meow_config::Config,
    config_path: String,
    log_tx: tokio::sync::broadcast::Sender<meow_api::log_stream::LogMessage>,
    shutdown: ShutdownSignal,
    on_ready: Option<ReadyCallback>,
) -> Result<()> {
    // Keep raw config in shared state for runtime mutations
    let raw_config = Arc::new(RwLock::new(config.raw.clone()));

    // Wrap proxy providers in a DashMap for concurrent access.
    let proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>> = {
        let map = DashMap::new();
        for (name, provider) in config.proxy_providers {
            map.insert(name, provider);
        }
        Arc::new(map)
    };

    // Rule providers in shared state for runtime refresh and API exposure.
    let rule_providers = Arc::new(RwLock::new(config.rule_providers));

    // Keep a resolver clone for the auto-update task before it moves into the tunnel.
    let resolver = Arc::clone(&config.dns.resolver);

    // Install the configured resolver as the global host-resolver hook used
    // by `meow_common::connect_tcp_host` / `resolve_host`, so a proxy node's
    // own server hostname is resolved by the DNS in the config — matching
    // mihomo, and matching what `DirectAdapter` already does for destination
    // hostnames. Without it the proxy adapters fall back to libc's
    // `getaddrinfo`, which ignores `dns:` entirely (wrong nameserver,
    // wrong `hosts:` entries) and, on a VPN-active device, opens DNS sockets
    // that bypass `VpnService.protect(fd)` so the query loops back through
    // our own tunnel. See `meow-common/src/socket_protect.rs` for the full
    // failure mode; the Android `SocketProtector` is installed separately by
    // the JNI bridge.
    //
    // On desktop this is gated on `dns.enable`: with DNS off,
    // `config.dns.resolver` is a stub pointing at a hard-coded upstream, and
    // forcing every proxy dial through it would be worse than the OS resolver
    // the user asked for. Clearing otherwise keeps a config reload from
    // leaving a stale hook installed.
    //
    // The VPN platforms are the exception and install it unconditionally.
    // There the hook is not a DNS-quality choice but a correctness one: it is
    // the only thing keeping proxy-server lookups off libc `getaddrinfo`,
    // whose sockets bypass `VpnService.protect(fd)` / the NE tunnel's
    // exclusion and therefore loop the query back through our own tunnel.
    // Android installed it unconditionally before proxy-server resolution
    // moved cross-platform; gating it on `dns.enable` there would resurrect
    // that loop for `dns.enable: false` configs (the very case
    // `socket_protect::resolve_addrs` warns about). The stub upstream is a
    // worse resolver than the OS one, but a reachable one beats a lookup that
    // deadlocks against the tunnel carrying it.
    const VPN_PLATFORM: bool = cfg!(any(target_os = "android", target_os = "ios"));
    if config.dns.enabled || VPN_PLATFORM {
        meow_common::set_host_resolver(Arc::new(
            meow_dns::ResolverHostHook::new_with_proxy_resolver(
                Arc::clone(&config.dns.resolver),
                config.dns.proxy_resolver.clone(),
            ),
        ));
    } else {
        meow_common::clear_host_resolver();
    }

    // Create the tunnel (core routing engine)
    let tunnel = Tunnel::new(Arc::clone(&config.dns.resolver));
    tunnel.set_mode(config.general.mode);
    tunnel.update_rules(config.rules);
    tunnel.update_proxies(config.proxies);
    tunnel.spawn_background_tasks();

    // Spawn periodic health checks for fallback / url-test proxy groups.
    {
        let raw_groups = config.raw.proxy_groups.as_deref().unwrap_or(&[]);
        let specs = crate::health_check::extract_specs(raw_groups);
        if !specs.is_empty() {
            info!("Starting health checks for {} group(s)", specs.len());
            crate::health_check::spawn_health_checks(&tunnel, specs);
        }
    }

    // Start DNS server if configured
    if let Some(listen_addr) = config.dns.listen_addr {
        let dns_server = DnsServer::new(Arc::clone(&config.dns.resolver), listen_addr);
        tokio::spawn(async move {
            if let Err(e) = dns_server.run().await {
                error!("DNS server error: {}", e);
            }
        });
    }

    // Spawn background refresh tasks for HTTP rule-providers with interval > 0.
    {
        let providers_snap: Vec<_> = rule_providers
            .read()
            .values()
            .filter(|p| {
                p.interval > 0 && p.provider_type == meow_config::rule_provider::ProviderType::Http
            })
            .cloned()
            .collect();
        for provider in providers_snap {
            let interval_secs = provider.interval;
            tokio::spawn(async move {
                let ctx = meow_rules::ParserContext::empty();
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                ticker.tick().await; // skip the immediate first tick
                loop {
                    ticker.tick().await;
                    if let Err(e) = provider.refresh(&ctx).await {
                        error!(provider = %provider.name, "background refresh failed: {:#}", e);
                    }
                }
            });
        }
    }

    // Start subscription background refresh task
    {
        let raw_config = Arc::clone(&raw_config);
        let tunnel = tunnel.clone();
        let config_path = config_path.clone();
        tokio::spawn(async move {
            crate::subscription_refresh::run_loop(raw_config, tunnel, config_path).await;
        });
    }

    // Fetch any missing geodata DBs on startup (unconditional — independent of
    // geodata.auto-update). Runs in the background so listener startup is not
    // blocked; rules are rebuilt afterward if anything was downloaded.
    {
        let geodata = config.geodata.clone();
        let tunnel = tunnel.clone();
        let raw_config = Arc::clone(&raw_config);
        let resolver = Arc::clone(&resolver);
        let cache_dir = meow_config::resource_cache_dir_for_config_path(&config_path);
        tokio::spawn(async move {
            crate::geodata_fetch::run_on_startup(geodata, tunnel, raw_config, resolver, cache_dir)
                .await;
        });
    }

    // Spawn geodata auto-update task if enabled.
    if config.geodata.auto_update {
        let geodata = config.geodata.clone();
        let tunnel = tunnel.clone();
        let raw_config = Arc::clone(&raw_config);
        let resolver = Arc::clone(&resolver);
        let cache_dir = meow_config::resource_cache_dir_for_config_path(&config_path);
        tokio::spawn(async move {
            crate::geodata_fetch::auto_update_loop(
                geodata, tunnel, raw_config, resolver, cache_dir,
            )
            .await;
        });
    }

    // Build shared SnifferRuntime from config (once per startup).
    let sniffer_runtime = Arc::new(SnifferRuntime::new(config.sniffer));
    let auth = config.auth;
    // Suppress unused-variable warnings: sniffer_runtime and auth are
    // consumed only inside feature-gated listener blocks below.
    let _ = (&sniffer_runtime, &auth);

    // Start listeners. Bind before spawning the accept loops so a `port: 0`
    // (ephemeral) listener resolves to its OS-assigned port up front; the
    // resolved ports are patched into `named_listeners`, which feeds the
    // startup logs and the API snapshot (`GET /listeners`) below.
    use meow_config::ListenerType;

    let mut named_listeners = config.listeners.named.clone();
    for nl in &mut named_listeners {
        let addr = bind_socket_addr(&nl.listen, nl.port)
            .map_err(|e| anyhow::anyhow!("listener '{}': {e}", nl.name))?;
        // Suppress unused-variable warning: addr is consumed only inside
        // feature-gated match arms below.
        let _ = addr;
        match nl.listener_type {
            ListenerType::Mixed | ListenerType::Http | ListenerType::Socks5 => {
                #[cfg(feature = "listener-mixed")]
                {
                    let socket = match tokio::net::TcpListener::bind(addr).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("listener '{}': bind {} failed: {}", nl.name, addr, e);
                            continue;
                        }
                    };
                    let bound = socket.local_addr().unwrap_or(addr);
                    nl.port = bound.port();
                    let listener = MixedListener::new(tunnel.clone(), bound, nl.name.clone())
                        .with_sniffer(Arc::clone(&sniffer_runtime))
                        .with_auth(Arc::clone(&auth))
                        .with_max_connections(nl.max_connections);
                    tokio::spawn(async move {
                        if let Err(e) = listener.run_on(socket).await {
                            error!("Listener error: {}", e);
                        }
                    });
                }
                #[cfg(not(feature = "listener-mixed"))]
                tracing::warn!(
                    "listener '{}': type {:?} requires feature 'listener-mixed'",
                    nl.name,
                    nl.listener_type
                );
            }
            ListenerType::TProxy => {
                #[cfg(feature = "listener-tproxy")]
                {
                    let socket = match tokio::net::TcpListener::bind(addr).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("listener '{}': bind {} failed: {}", nl.name, addr, e);
                            continue;
                        }
                    };
                    let bound = socket.local_addr().unwrap_or(addr);
                    nl.port = bound.port();
                    let listener = TProxyListener::new(
                        tunnel.clone(),
                        bound,
                        nl.tproxy_sni,
                        config.listeners.routing_mark,
                        nl.name.clone(),
                    )
                    .with_sniffer(Arc::clone(&sniffer_runtime))
                    .with_max_connections(nl.max_connections);
                    tokio::spawn(async move {
                        if let Err(e) = listener.run_on(socket).await {
                            error!("TProxy listener error: {}", e);
                        }
                    });
                }
                #[cfg(not(feature = "listener-tproxy"))]
                tracing::warn!(
                    "listener '{}': TProxy requires feature 'listener-tproxy'",
                    nl.name
                );
            }
        }
    }

    // Start REST API if configured. Runs after the listener bind phase so the
    // `GET /listeners` snapshot reports OS-assigned ports for `port: 0`
    // (ephemeral) listeners rather than the configured `0`.
    if let Some(api_addr) = config.api.external_controller {
        // `external-ui-url` auto-download is gated behind the optional
        // `external-ui-download` feature (it pulls in the `zip` crate, against
        // the ADR-0007 size caps). Without the feature we just hint the user to
        // populate the directory manually. See issue #223.
        if let (Some(url), Some(dir)) = (&config.api.external_ui_url, &config.api.external_ui) {
            if !dir.is_dir() {
                // Auto-download is gated behind `external-ui-download` AND is
                // force-disabled on iOS/Android (mobile ships its own UI).
                #[cfg(all(
                    feature = "external-ui-download",
                    not(any(target_os = "ios", target_os = "android"))
                ))]
                {
                    if let Err(e) = meow_config::external_ui::download_external_ui(url, dir).await {
                        warn!("failed to download external-ui from {url}: {e:#}");
                    }
                }
                #[cfg(not(all(
                    feature = "external-ui-download",
                    not(any(target_os = "ios", target_os = "android"))
                )))]
                {
                    warn!(
                        "external-ui-url ({url}) is set but auto-download is unavailable in this \
                         build; download and extract the UI into {} manually",
                        dir.display()
                    );
                }
            }
        }
        let api_server = ApiServer::new(
            tunnel.clone(),
            api_addr,
            config.api.secret.clone(),
            config_path.clone(),
            Arc::clone(&raw_config),
            log_tx.clone(),
            Arc::clone(&proxy_providers),
            Arc::clone(&rule_providers),
            named_listeners.clone(),
            config.api.external_ui.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = api_server.run().await {
                error!("API server error: {}", e);
            }
        });
    }

    // TUN inbound (issue #326) — spawned from the top-level `tun:` section,
    // not the `listeners:` array (mihomo layout).
    if config.tun.enable {
        #[cfg(feature = "listener-tun")]
        {
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let listener = TunListener::new(
                tunnel.clone(),
                tun_config_to_listener_config(&config.tun),
                "meow-tun".to_string(),
            )
            .with_readiness_signal(ready_tx);

            let handle = tokio::spawn(async move {
                if let Err(e) = listener.run().await {
                    error!("TUN listener error: {}", e);
                }
            });

            // Await device readiness before treating TUN as "running".
            // If device creation fails (permission denied, etc.) the
            // notifier sends `TunReady::Failed` immediately — no timeout
            // wait.  Only a genuinely stuck setup hits the timeout.
            match tokio::time::timeout(meow_api::TUN_STARTUP_TIMEOUT, ready_rx).await {
                Ok(Ok(meow_listener::TunReady::Ready)) => {
                    tunnel.set_tun_handle(handle).await;
                }
                Ok(Ok(meow_listener::TunReady::Failed(msg))) => {
                    if msg.contains("wintun.dll") {
                        error!("TUN listener failed to start: {msg}");
                    } else {
                        error!(
                            "TUN listener failed to start: {msg} — \
                             check permissions / admin / CAP_NET_ADMIN"
                        );
                    }
                    handle.abort();
                }
                Ok(Err(_)) => {
                    error!("TUN listener readiness signal dropped unexpectedly");
                    handle.abort();
                }
                Err(_) => {
                    error!(
                        "TUN listener startup timed out after {} s",
                        meow_api::TUN_STARTUP_TIMEOUT.as_secs()
                    );
                    handle.abort();
                }
            }
        }
        #[cfg(not(feature = "listener-tun"))]
        warn!("tun.enable is set but this build lacks the 'listener-tun' feature");
    }

    if let Some(on_ready) = on_ready {
        on_ready()?;
    }
    info!("meow-rs is running");

    // Wait for shutdown signal
    shutdown.wait().await?;
    info!("Shutting down...");

    Ok(())
}

// hangil 포크: `bind_socket_addr` 이 `main.rs` 에서 여기로 옮겨 오면서(P-1)
// 그 테스트는 `main.rs` 에 남아 `use super::bind_socket_addr` 로 사라진 이름을
// 가리키게 됐다. 바이너리 테스트 타깃이 컴파일되지 않는다. 테스트를 함수 옆으로
// 옮긴다 — 함수를 `pub` 으로 넓히는 것보다 낫다.
#[cfg(test)]
mod bind_addr_tests {
    use super::bind_socket_addr;

    #[test]
    fn ipv4_bind_address() {
        let a = bind_socket_addr("0.0.0.0", 7890).unwrap();
        assert_eq!(a.to_string(), "0.0.0.0:7890");
        assert!(a.is_ipv4());
    }

    #[test]
    fn ipv6_unspecified_bind_address_is_dual_stack() {
        // Regression: format!("{}:{}", "::", port) yields the unparseable
        // ":::7890". SocketAddr::new must bracket it correctly so that
        // `bind-address: '::'` actually binds (and on Linux accepts both
        // IPv4 and IPv6 LAN clients).
        let a = bind_socket_addr("::", 7890).unwrap();
        assert_eq!(a.to_string(), "[::]:7890");
        assert!(a.is_ipv6());
    }

    #[test]
    fn specific_ipv6_bind_address() {
        let a = bind_socket_addr("2408:820c:8f4b:9b41::1001", 9090).unwrap();
        assert_eq!(a.to_string(), "[2408:820c:8f4b:9b41::1001]:9090");
    }

    #[test]
    fn invalid_bind_address_errors() {
        assert!(bind_socket_addr("not-an-ip", 80).is_err());
    }
}
