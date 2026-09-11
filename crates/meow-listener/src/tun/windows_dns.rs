//! DNS configuration and leak protection owned by one Wintun device.
//!
//! Only that device receives DNS settings. The BFE removes the dynamic WFP
//! session's filters on close, process death (RPC rundown), or reboot:
//! https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
//!
//! The core executable may still use its configured upstream/bootstrap DNS.
//! Every other application must send UDP/TCP port 53 through this TUN. Match
//! the next-hop LUID, not the source-address interface (Windows weak-host
//! sends can use a source address from a different interface).

use std::io;
use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::{UuidCreate, RPC_C_AUTHN_WINNT, RPC_S_UUID_LOCAL_ONLY};

/// Kept inside TunDevice, so DNS, routes, the adapter and leak protection
/// share one lifetime even when a blocking startup task is cancelled.
pub(super) struct DnsGuard {
    _filters: WfpSession,
}

impl DnsGuard {
    pub(super) fn setup(device: &tun_rs::AsyncDevice, dns: IpAddr) -> io::Result<Self> {
        #[cfg(not(test))]
        {
            Self::setup_inner(device, dns)
        }
        #[cfg(test)]
        {
            Self::setup_with_after_dns(device, dns, &mut || Ok(()))
        }
    }

    /// Native fixtures can fail at the real partial-setup boundary. This
    /// control is absent from production builds and has no environment switch.
    #[cfg(test)]
    pub(super) fn setup_with_after_dns(
        device: &tun_rs::AsyncDevice,
        dns: IpAddr,
        after_dns: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        Self::setup_inner(device, dns, Some(after_dns))
    }

    fn setup_inner(
        device: &tun_rs::AsyncDevice,
        dns: IpAddr,
        #[cfg(test)] after_dns: Option<&mut dyn FnMut() -> io::Result<()>>,
    ) -> io::Result<Self> {
        if !dns.is_ipv4() || device.addresses()?.contains(&dns) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows TUN DNS requires a routed IPv4 gateway distinct from its local address",
            ));
        }
        let luid = device.if_luid()?;
        // SAFETY: NET_LUID_LH.Value is the documented 64-bit LUID value.
        let filters = WfpSession::install(unsafe { luid.Value })?;

        // Any failure drops the dynamic session, and the caller drops this
        // newly-created adapter and its routes. No pre-existing interface
        // has been modified, so there is no machine-wide restore operation.
        device
            .set_dns_servers(&[dns])
            .map_err(|e| io::Error::other(format!("set DNS on owned TUN adapter: {e}")))?;
        #[cfg(test)]
        if let Some(after_dns) = after_dns {
            after_dns()?;
        }
        device
            .clear_dns_servers(false)
            .map_err(|e| io::Error::other(format!("clear IPv6 DNS on owned TUN adapter: {e}")))?;
        device
            .set_metric(1)
            .map_err(|e| io::Error::other(format!("set DNS priority on owned TUN adapter: {e}")))?;

        // Cache invalidation changes no adapter configuration. A failed
        // flush is observable but cannot invalidate the installed policy.
        match std::process::Command::new("ipconfig")
            .arg("/flushdns")
            .output()
        {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                tracing::warn!("tun windows-dns: DNS cache flush exited {}", output.status)
            }
            Err(e) => tracing::warn!("tun windows-dns: DNS cache flush failed: {e}"),
        }
        Ok(Self { _filters: filters })
    }
}

struct WfpSession {
    handle: HANDLE,
}

// SAFETY: the handle is an RPC session handle without thread affinity. It
// is used for setup before publication and thereafter only closed on Drop.
unsafe impl Send for WfpSession {}
unsafe impl Sync for WfpSession {}

impl WfpSession {
    fn install(mut tun_luid: u64) -> io::Result<Self> {
        // Let WFP canonicalize the full path into its exact ALE_APP_ID.
        // There is no process-name, directory, or svchost exemption.
        let executable: Vec<u16> = std::env::current_exe()?
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut app_id = AppId(ptr::null_mut());
        // SAFETY: executable is NUL-terminated and app_id is writable.
        check(
            unsafe { FwpmGetAppIdFromFileName0(executable.as_ptr(), &mut app_id.0) },
            "resolve core WFP application identity",
        )?;

        let mut name = wide("meow-rs TUN DNS protection");
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: ptr::null_mut(),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txnWaitTimeoutInMSec: 5000,
            ..Default::default()
        };
        let mut guard = Self {
            handle: ptr::null_mut(),
        };
        // SAFETY: all pointers remain valid for the synchronous RPC call.
        check(
            unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &session,
                    &mut guard.handle,
                )
            },
            "open dynamic DNS protection session",
        )?;
        check(
            unsafe { FwpmTransactionBegin0(guard.handle, 0) },
            "begin DNS protection transaction",
        )?;

        // A different GUID per session allows a replacement core to start
        // while Windows finishes RPC rundown of a crashed predecessor.
        let mut sublayer_key = GUID::from_u128(0);
        // UuidCreate may report RPC_S_UUID_LOCAL_ONLY (1824); a locally
        // unique ID is sufficient for this machine-local ephemeral object.
        let status = unsafe { UuidCreate(&mut sublayer_key) };
        if status != 0 && status != RPC_S_UUID_LOCAL_ONLY {
            return Err(io::Error::other(format!(
                "create DNS protection sublayer ID: {status}"
            )));
        }
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: sublayer_key,
            displayData: session.displayData,
            weight: u16::MAX,
            ..Default::default()
        };
        check(
            unsafe { FwpmSubLayerAdd0(guard.handle, &sublayer, ptr::null_mut()) },
            "add dynamic DNS protection sublayer",
        )?;

        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ] {
            for protocol in [6, 17] {
                let mut conditions = dns_conditions(&mut tun_luid, app_id.0, protocol);
                let filter = FWPM_FILTER0 {
                    displayData: session.displayData,
                    layerKey: layer,
                    subLayerKey: sublayer_key,
                    weight: FWP_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_VALUE0_0 { uint8: 15 },
                    },
                    numFilterConditions: conditions.len() as u32,
                    filterCondition: conditions.as_mut_ptr(),
                    action: FWPM_ACTION0 {
                        r#type: FWP_ACTION_BLOCK,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                // All four conditions are ANDed. BFE copies their data,
                // including the LUID and app-ID buffers, during this call.
                check(
                    unsafe {
                        FwpmFilterAdd0(guard.handle, &filter, ptr::null_mut(), ptr::null_mut())
                    },
                    "add UDP/TCP DNS protection filter",
                )?;
            }
        }
        check(
            unsafe { FwpmTransactionCommit0(guard.handle) },
            "commit DNS protection transaction",
        )?;
        Ok(guard)
    }
}

impl Drop for WfpSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // Closing also aborts an uncommitted transaction. Thus an error
            // on filter N never commits filters 0..N, including on panic.
            let status = unsafe { FwpmEngineClose0(self.handle) };
            if status != 0 {
                tracing::warn!("tun windows-dns: close dynamic WFP session failed: {status:#x}");
            }
        }
    }
}

struct AppId(*mut FWP_BYTE_BLOB);

impl Drop for AppId {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this allocation came from FwpmGetAppIdFromFileName0.
            unsafe { FwpmFreeMemory0((&mut self.0 as *mut *mut FWP_BYTE_BLOB).cast()) };
        }
    }
}

fn check(status: u32, operation: &str) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{operation}: {} ({status:#x})",
            io::Error::from_raw_os_error(status as i32)
        )))
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn dns_conditions(
    tun_luid: *mut u64,
    app_id: *mut FWP_BYTE_BLOB,
    protocol: u8,
) -> [FWPM_FILTER_CONDITION0; 4] {
    [
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: protocol },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: 53 },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
            matchType: FWP_MATCH_NOT_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint64: tun_luid },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_NOT_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same_guid(a: GUID, b: GUID) -> bool {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    }

    #[test]
    fn dns_filters_protect_both_transports_and_only_exempt_owned_tun_or_exact_core() {
        let mut luid = 0x1000000001u64;
        let mut executable = br"\device\harddiskvolume1\ansim\ansim-core.exe".to_vec();
        let mut app_id = FWP_BYTE_BLOB {
            size: executable.len() as u32,
            data: executable.as_mut_ptr(),
        };
        let filters = [
            dns_conditions(&mut luid, &mut app_id, 6),
            dns_conditions(&mut luid, &mut app_id, 17),
        ];

        // Interpret the actual FFI conditions that will be sent to BFE.
        let blocks = |protocol, port, next_hop, app: &[u8]| {
            filters.iter().any(|conditions| {
                conditions.iter().all(|c| {
                    let equal = unsafe {
                        match c.conditionValue.r#type {
                            FWP_UINT8 => {
                                same_guid(c.fieldKey, FWPM_CONDITION_IP_PROTOCOL)
                                    && protocol == c.conditionValue.Anonymous.uint8
                            }
                            FWP_UINT16 => {
                                same_guid(c.fieldKey, FWPM_CONDITION_IP_REMOTE_PORT)
                                    && port == c.conditionValue.Anonymous.uint16
                            }
                            FWP_UINT64 => {
                                assert!(same_guid(c.fieldKey, FWPM_CONDITION_IP_NEXTHOP_INTERFACE));
                                next_hop == *c.conditionValue.Anonymous.uint64
                            }
                            FWP_BYTE_BLOB_TYPE => {
                                assert!(same_guid(c.fieldKey, FWPM_CONDITION_ALE_APP_ID));
                                let blob = &*c.conditionValue.Anonymous.byteBlob;
                                app == std::slice::from_raw_parts(blob.data, blob.size as usize)
                            }
                            _ => panic!("unexpected DNS filter field"),
                        }
                    };
                    match c.matchType {
                        FWP_MATCH_EQUAL => equal,
                        FWP_MATCH_NOT_EQUAL => !equal,
                        _ => panic!("broad match type in DNS protection"),
                    }
                })
            })
        };
        for protocol in [6, 17] {
            assert!(blocks(
                protocol,
                53,
                2,
                br"\device\harddiskvolume1\browser.exe"
            ));
            assert!(blocks(
                protocol,
                53,
                2,
                br"\device\harddiskvolume2\ansim\ansim-core.exe"
            ));
            assert!(blocks(
                protocol,
                53,
                2,
                br"\device\harddiskvolume1\ansim\other.exe"
            ));
            assert!(!blocks(protocol, 53, luid, b"any application"));
            assert!(!blocks(protocol, 53, 2, &executable));
            assert!(!blocks(protocol, 443, 2, b"any application"));
        }
        assert!(!blocks(1, 53, 2, b"any application"));
    }
}
