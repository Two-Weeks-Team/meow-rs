//! OS DNS resolver configuration for the TUN inbound.
//!
//! When `dns-hijack` is active, the OS resolver must be pointed at a
//! DNS server that returns fake IPs.  On macOS/Linux this is the fake-IP
//! gateway (e.g. `198.18.0.1`) — queries enter the TUN device and are
//! answered by `dns-hijack`. Windows uses its separate device-owned backend
//! in `windows_dns.rs`.
//!
//! `DnsGuard` backs up the current resolver configuration at startup,
//! installs the DNS server addresses on all active adapters, and
//! restores the original configuration on drop.
//!
//! Individual failures are logged and skipped: a DNS configuration error
//! does not abort the TUN listener startup, and a recovery failure is
//! similarly non-fatal.

use std::net::IpAddr;
use tracing::{debug, warn};

/// RAII guard that restores original DNS settings on drop.
///
/// When created, it saves the current OS DNS state and replaces it with
/// the configured DNS address using the platform backend. On drop,
/// the original configuration is restored. Failed operations are logged
/// at `warn!` level rather than panicking.
pub(super) struct DnsGuard {
    #[cfg(target_os = "macos")]
    backup: Vec<(String, Vec<String>)>,
    #[cfg(target_os = "linux")]
    backup: Option<linux::ResolvConfBackup>,
}

impl DnsGuard {
    /// Save current DNS settings and set all interfaces to `dns_addr`.
    /// Returns `None` on platforms without a supported backend, or when
    /// the backup fails.
    pub(super) fn setup(dns_addr: IpAddr) -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            match macos::backup(dns_addr) {
                Ok(backup) => {
                    if let Err(e) = macos::set_all(dns_addr) {
                        warn!("tun dns-guard: failed to set DNS to {dns_addr}: {e}");
                    }
                    debug!("tun dns-guard: DNS set to {dns_addr} on all network services");
                    Some(Self { backup })
                }
                Err(e) => {
                    warn!("tun dns-guard: failed to back up DNS settings: {e}");
                    None
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            match linux::backup_and_set(dns_addr) {
                Ok(backup) => {
                    debug!("tun dns-guard: DNS set to {dns_addr} in /etc/resolv.conf");
                    Some(Self {
                        backup: Some(backup),
                    })
                }
                Err(e) => {
                    warn!("tun dns-guard: failed to configure DNS: {e}");
                    None
                }
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            let _ = dns_addr;
            debug!("tun dns-guard: no DNS backend for this platform; skipping");
            None
        }
    }
}

// Restore runs synchronously in Drop — deliberately. `Tunnel::stop_tun`
// awaits the aborted task, so a config-reload disable→enable cannot start a
// new backup until this restore has finished; offloading to another thread
// would open that race, and the process-exit path must block anyway or the
// restore is lost.
impl Drop for DnsGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            macos::restore(&self.backup);
            debug!("tun dns-guard: DNS settings restored");
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(backup) = self.backup.take() {
                if let Err(e) = linux::restore(&backup) {
                    warn!("tun dns-guard: failed to restore /etc/resolv.conf: {e}");
                } else {
                    debug!("tun dns-guard: /etc/resolv.conf restored");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS backend — networksetup
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::net::IpAddr;
    use std::process::Command;

    pub(super) fn backup(dns_addr: IpAddr) -> io::Result<Vec<(String, Vec<String>)>> {
        let services = list_services()?;
        let mut result = Vec::with_capacity(services.len());
        for svc in services {
            match get_dns(&svc) {
                Ok(servers) => {
                    // Never back up the fake-IP gateway meow itself installs:
                    // after an unclean shutdown it is still the active DNS, and
                    // keeping it would make a later clean exit "restore" the
                    // broken state. An emptied list restores to "Empty"
                    // (DHCP/automatic) instead.
                    let filtered: Vec<String> = servers
                        .into_iter()
                        .filter(|s| s.parse::<IpAddr>() != Ok(dns_addr))
                        .collect();
                    result.push((svc, filtered));
                }
                Err(e) => super::warn!("tun dns-guard: failed to get DNS for '{svc}': {e}"),
            }
        }
        Ok(result)
    }

    pub(super) fn set_all(dns_addr: IpAddr) -> io::Result<()> {
        let services = list_services()?;
        let addr = dns_addr.to_string();
        let mut had_error = false;
        for svc in services {
            if let Err(e) = set_dns(&svc, std::slice::from_ref(&addr)) {
                super::warn!("tun dns-guard: failed to set DNS on '{svc}': {e}");
                had_error = true;
            }
        }
        if had_error {
            Err(io::Error::other("some DNS sets failed"))
        } else {
            Ok(())
        }
    }

    pub(super) fn restore(saved: &[(String, Vec<String>)]) {
        for (svc, servers) in saved {
            if let Err(e) = set_dns(svc, servers) {
                super::warn!("tun dns-guard: failed to restore DNS on '{svc}': {e}");
            }
        }
    }

    fn list_services() -> io::Result<Vec<String>> {
        let output = Command::new("networksetup")
            .args(["-listallnetworkservices"])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .skip(1) // skip "An asterisk (*) denotes..." header
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('*'))
            .collect())
    }

    fn get_dns(service: &str) -> io::Result<Vec<String>> {
        let output = Command::new("networksetup")
            .args(["-getdnsservers", service])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim() == "There aren't any DNS Servers set on this device." {
            return Ok(vec![]);
        }
        Ok(stdout
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    fn set_dns(service: &str, servers: &[String]) -> io::Result<()> {
        if servers.is_empty() {
            Command::new("networksetup")
                .args(["-setdnsservers", service, "Empty"])
                .output()?;
        } else {
            let mut args: Vec<&str> = vec!["-setdnsservers", service];
            for s in servers {
                args.push(s.as_str());
            }
            Command::new("networksetup").args(&args).output()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Linux backend — /etc/resolv.conf
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io;
    use std::net::IpAddr;
    use std::path::PathBuf;

    const MARKER: &str = "# Generated by meow-rs TUN dns-guard";
    /// On-disk copy of the pre-meow resolv.conf, written before we touch
    /// the real file so the original survives an unclean shutdown.
    const SIDECAR: &str = "/etc/resolv.conf.meow-backup";

    pub(super) struct ResolvConfBackup {
        path: PathBuf,
        content: Vec<u8>,
    }

    pub(super) fn backup_and_set(dns_addr: IpAddr) -> io::Result<ResolvConfBackup> {
        let path = PathBuf::from("/etc/resolv.conf");
        let current = fs::read(&path)?;

        let content = if current.starts_with(MARKER.as_bytes()) {
            // resolv.conf is our own generated file — a previous run exited
            // uncleanly. Recover the true original from the sidecar instead
            // of backing up (and later "restoring") the broken state.
            match fs::read(SIDECAR) {
                Ok(original) => {
                    super::warn!(
                        "tun dns-guard: /etc/resolv.conf was left over from an unclean \
                         shutdown; recovered the original from {SIDECAR}"
                    );
                    original
                }
                Err(e) => {
                    super::warn!(
                        "tun dns-guard: /etc/resolv.conf was left over from an unclean \
                         shutdown and no sidecar backup exists ({e}); will restore public \
                         resolvers on exit — reconfigure your resolver manually if needed"
                    );
                    b"# meow-rs tun dns-guard: the original /etc/resolv.conf was lost in an\n\
                      # unclean shutdown; falling back to public resolvers.\n\
                      nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
                        .to_vec()
                }
            }
        } else {
            fs::write(SIDECAR, &current)?;
            current
        };

        let new_content = format!("{MARKER}\nnameserver {dns_addr}\n");
        fs::write(&path, new_content.as_bytes())?;
        Ok(ResolvConfBackup { path, content })
    }

    pub(super) fn restore(backup: &ResolvConfBackup) -> io::Result<()> {
        fs::write(&backup.path, &backup.content)?;
        let _ = fs::remove_file(SIDECAR);
        Ok(())
    }
}
