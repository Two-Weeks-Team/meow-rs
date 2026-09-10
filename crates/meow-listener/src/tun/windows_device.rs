//! Establish a fresh Wintun identity before changing any interface settings.
//!
//! tun-rs 2.8's L3 builder can open an existing adapter even with
//! `reuse_dev(false)`. Its normal builder also configures the interface before
//! returning it. Keep acquisition unconfigured and verify the requested fresh
//! GUID before applying MTU, addresses, or starting a packet session.

use std::io;
use std::net::Ipv4Addr;
use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, FreeMibTable, GetIfTable2, GetIpInterfaceEntry,
    SetIpInterfaceEntry, MIB_IF_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Rpc::{UuidCreate, RPC_S_UUID_LOCAL_ONLY};

pub(super) fn create_owned(
    name: &str,
    wintun_file: String,
    mtu: u16,
    addr: Ipv4Addr,
    prefix: u8,
) -> io::Result<tun_rs::AsyncDevice> {
    let requested = fresh_guid()?;
    ensure_absent(name, requested)?;
    let device = acquire_unconfigured(name, requested, wintun_file)?;

    // This handle has the fresh GUID requested above. A failed setting drops
    // its creating handle, which removes only this newly created adapter.
    device.set_mtu(mtu)?;
    device.set_mtu_v6(mtu)?;
    // This private L3 interface has no neighboring hosts to probe. Disable DAD
    // before adding its address, otherwise Windows can expose an Up adapter
    // whose tentative address still cannot serve the system DNS resolver.
    let luid = device.if_luid()?;
    let mut row = ipv4_interface(luid)?;
    row.DadTransmits = 0;
    // Required by SetIpInterfaceEntry for IPv4, including read-modify-write.
    row.SitePrefixLength = 0;
    // SAFETY: row is the current IPv4 entry for this verified fresh LUID.
    let status = unsafe { SetIpInterfaceEntry(&mut row) };
    if status != 0 {
        return Err(io::Error::other(format!(
            "disable duplicate address detection on owned Wintun: {}",
            io::Error::from_raw_os_error(status as i32)
        )));
    }
    if ipv4_interface(luid)?.DadTransmits != 0 {
        return Err(io::Error::other(
            "owned Wintun duplicate address detection remained enabled",
        ));
    }
    device.set_network_address(addr, prefix, None)?;
    device.enabled(true)?;
    tun_rs::AsyncDevice::new(device)
}

fn ipv4_interface(luid: NET_LUID_LH) -> io::Result<MIB_IPINTERFACE_ROW> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: AF_INET,
        InterfaceLuid: luid,
        ..Default::default()
    };
    // SAFETY: row is a live, aligned entry keyed by address family and LUID.
    let status = unsafe { GetIpInterfaceEntry(&mut row) };
    if status != 0 {
        return Err(io::Error::other(format!(
            "read owned Wintun IPv4 interface: {}",
            io::Error::from_raw_os_error(status as i32)
        )));
    }
    Ok(row)
}

fn acquire_unconfigured(
    name: &str,
    requested: u128,
    wintun_file: String,
) -> io::Result<tun_rs::SyncDevice> {
    // Do not add address/MTU/metric settings or use build_async here. In the
    // existing-adapter branch, even starting a session precedes ownership.
    let device = tun_rs::DeviceBuilder::new()
        .name(name)
        .device_guid(requested)
        .wintun_file(wintun_file)
        .wintun_log(true)
        .inherit_enable_state()
        .build_sync()?;
    let luid = device.if_luid()?;
    let mut actual = GUID::default();
    // SAFETY: both pointers refer to live, correctly aligned values.
    let status = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut actual) };
    if status != 0 {
        return Err(io::Error::other(format!(
            "read Wintun identity before configuration: {}",
            io::Error::from_raw_os_error(status as i32)
        )));
    }
    if guid_value(actual) != requested {
        // A same-name adapter may have appeared after ensure_absent. An Open
        // handle ignores requested GUID; dropping it neither changes settings
        // nor removes that existing adapter. No session has been started.
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("Wintun '{name}' is not the newly requested adapter; refusing to configure it"),
        ));
    }
    Ok(device)
}

fn fresh_guid() -> io::Result<u128> {
    let mut guid = GUID::default();
    // A machine-local UUID is sufficient for this machine-local interface.
    let status = unsafe { UuidCreate(&mut guid) };
    if status != 0 && status != RPC_S_UUID_LOCAL_ONLY {
        return Err(io::Error::other(format!(
            "generate fresh Wintun identity: {status}"
        )));
    }
    Ok(guid_value(guid))
}

fn guid_value(guid: GUID) -> u128 {
    (u128::from(guid.data1) << 96)
        | (u128::from(guid.data2) << 80)
        | (u128::from(guid.data3) << 64)
        | u128::from(u64::from_be_bytes(guid.data4))
}

fn ensure_absent(name: &str, requested: u128) -> io::Result<()> {
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    if name_utf16.is_empty() || name_utf16.len() >= 256 || name_utf16.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Wintun name must contain 1..255 UTF-16 code units without NUL",
        ));
    }
    let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
    // GetIfTable2 enumerates physical and logical interfaces, including those
    // without IP addresses. A failed lookup is never evidence of absence.
    let status = unsafe { GetIfTable2(&mut table) };
    if status != 0 {
        return Err(io::Error::other(format!(
            "enumerate interfaces before Wintun creation: {}",
            io::Error::from_raw_os_error(status as i32)
        )));
    }
    if table.is_null() {
        return Err(io::Error::other("GetIfTable2 returned no interface table"));
    }
    // SAFETY: the successful call owns an array of NumEntries properly
    // aligned rows at Table. It stays live until FreeMibTable below.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let result = rows.iter().try_for_each(|row| {
        let alias_len = row.Alias.iter().position(|&c| c == 0).unwrap_or(row.Alias.len());
        // Use Windows' case folding for Unicode aliases, not ASCII-only name
        // comparison. Both lengths are bounded by the interface name limits.
        let comparison = unsafe {
            CompareStringOrdinal(
                row.Alias.as_ptr(),
                alias_len as i32,
                name_utf16.as_ptr(),
                name_utf16.len() as i32,
                1,
            )
        };
        if comparison == 0 {
            return Err(io::Error::last_os_error());
        }
        if comparison == CSTR_EQUAL || guid_value(row.InterfaceGuid) == requested {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Wintun '{name}' name or requested identity already exists; refusing to reuse it"),
            ));
        }
        Ok(())
    });
    // SAFETY: table came from GetIfTable2 and is released exactly once.
    unsafe { FreeMibTable(table.cast()) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::{
        IpDadStatePreferred, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_INET,
    };

    #[test]
    fn guid_round_trip_matches_tun_rs_requested_guid() {
        let id = 0x12345678_9abc_def0_1122_334455667788;
        assert_eq!(guid_value(GUID::from_u128(id)), id);
    }

    // These tests create only an isolated, randomly named test adapter. They
    // require elevation and an absolute MEOW_TEST_WINTUN_DLL path, and must be
    // invoked explicitly with --ignored on a Windows verification machine.
    fn fixture() -> (String, String, tun_rs::AsyncDevice) {
        let dll = std::env::var("MEOW_TEST_WINTUN_DLL")
            .expect("set MEOW_TEST_WINTUN_DLL to the official wintun.dll absolute path");
        assert!(std::path::Path::new(&dll).is_absolute());
        assert!(std::path::Path::new(&dll).is_file());
        let name = format!("meow-owner-test-{:032x}", fresh_guid().unwrap());
        let device = create_owned(&name, dll.clone(), 1420, Ipv4Addr::new(192, 0, 2, 1), 32)
            .expect("create isolated test adapter (requires Administrator)");
        // Query the exact address immediately, before slower enumeration could
        // hide a tentative interval. No sleeps or retries may mask this check.
        let mut address = MIB_UNICASTIPADDRESS_ROW {
            InterfaceLuid: device.if_luid().unwrap(),
            Address: SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes([192, 0, 2, 1]),
                        },
                    },
                    ..Default::default()
                },
            },
            ..Default::default()
        };
        // SAFETY: address identifies this fixture's LUID and IPv4 address.
        let status = unsafe { GetUnicastIpAddressEntry(&mut address) };
        assert_eq!(status, 0, "read the fixture's exact IPv4 address");
        assert_eq!(address.DadState, IpDadStatePreferred);
        assert_eq!(
            ipv4_interface(device.if_luid().unwrap())
                .unwrap()
                .DadTransmits,
            0
        );
        assert_eq!(device.mtu().unwrap(), 1420);
        assert_eq!(device.mtu_v6().unwrap(), 1420);
        assert!(ipv4_addresses(&device).contains(&Ipv4Addr::new(192, 0, 2, 1).into()));
        (name, dll, device)
    }

    fn ipv4_addresses(device: &tun_rs::AsyncDevice) -> Vec<std::net::IpAddr> {
        let mut addresses: Vec<_> = device
            .addresses()
            .unwrap()
            .into_iter()
            .filter(|ip| ip.is_ipv4())
            .collect();
        addresses.sort();
        addresses
    }

    fn enable_fixture_dad(device: &tun_rs::AsyncDevice) {
        let luid = device.if_luid().unwrap();
        let mut row = ipv4_interface(luid).unwrap();
        // Use a nonzero sentinel so an attempted reuse that writes zero before
        // checking ownership cannot pass the preservation assertions below.
        row.DadTransmits = 2;
        row.SitePrefixLength = 0;
        // SAFETY: row belongs only to the isolated fixture created by this test.
        assert_eq!(unsafe { SetIpInterfaceEntry(&mut row) }, 0);
        assert_eq!(ipv4_interface(luid).unwrap().DadTransmits, 2);
    }

    #[test]
    #[ignore = "requires Windows Administrator and MEOW_TEST_WINTUN_DLL; creates an isolated adapter"]
    fn new_adapter_ipv4_is_immediately_preferred() {
        let (_name, _dll, _device) = fixture();
    }

    #[test]
    #[ignore = "requires Windows Administrator and MEOW_TEST_WINTUN_DLL; creates an isolated adapter"]
    fn existing_adapter_is_rejected_before_configuration() {
        let (name, dll, existing) = fixture();
        enable_fixture_dad(&existing);
        let before = (
            existing.mtu().unwrap(),
            existing.mtu_v6().unwrap(),
            ipv4_addresses(&existing),
            ipv4_interface(existing.if_luid().unwrap())
                .unwrap()
                .DadTransmits,
        );
        for collision in [name.clone(), name.to_uppercase()] {
            let error = create_owned(
                &collision,
                dll.clone(),
                1300,
                Ipv4Addr::new(192, 0, 2, 2),
                32,
            )
            .err()
            .expect("same-name adapter must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(
                (
                    existing.mtu().unwrap(),
                    existing.mtu_v6().unwrap(),
                    ipv4_addresses(&existing),
                    ipv4_interface(existing.if_luid().unwrap())
                        .unwrap()
                        .DadTransmits,
                ),
                before
            );
        }

        // The listener can retry a rejected name without reusing or deleting
        // its occupant. Use a separate address so this checks name ownership
        // independently of the listener's later address-conflict retries.
        let replacement = create_owned(
            &format!("{name}-1"),
            dll,
            1300,
            Ipv4Addr::new(192, 0, 2, 2),
            32,
        )
        .expect("a rejected name must not prevent acquiring a different fresh adapter");
        assert_ne!(
            replacement.if_index().unwrap(),
            existing.if_index().unwrap()
        );
        assert_eq!(replacement.mtu().unwrap(), 1300);
        assert!(ipv4_addresses(&replacement).contains(&Ipv4Addr::new(192, 0, 2, 2).into()));
        assert_eq!(
            (
                existing.mtu().unwrap(),
                existing.mtu_v6().unwrap(),
                ipv4_addresses(&existing),
                ipv4_interface(existing.if_luid().unwrap())
                    .unwrap()
                    .DadTransmits,
            ),
            before
        );
    }

    #[test]
    #[ignore = "requires Windows Administrator and MEOW_TEST_WINTUN_DLL; creates an isolated adapter"]
    fn adapter_appearing_after_preflight_is_rejected_before_configuration() {
        let (name, dll, existing) = fixture();
        enable_fixture_dad(&existing);
        let before = (
            existing.mtu().unwrap(),
            existing.mtu_v6().unwrap(),
            ipv4_addresses(&existing),
            ipv4_interface(existing.if_luid().unwrap())
                .unwrap()
                .DadTransmits,
        );
        // Exercise the acquisition seam directly as if another process created
        // this adapter after the initial inventory. tun-rs takes its Open path.
        let error = acquire_unconfigured(&name, fresh_guid().unwrap(), dll)
            .err()
            .expect("an opened adapter must not pass fresh identity verification");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            (
                existing.mtu().unwrap(),
                existing.mtu_v6().unwrap(),
                ipv4_addresses(&existing),
                ipv4_interface(existing.if_luid().unwrap())
                    .unwrap()
                    .DadTransmits,
            ),
            before
        );
    }
}
