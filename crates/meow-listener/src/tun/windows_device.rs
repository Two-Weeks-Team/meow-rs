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
    ConvertInterfaceLuidToGuid, FreeMibTable, GetIfTable2, MIB_IF_TABLE2,
};
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
    device.set_network_address(addr, prefix, None)?;
    device.enabled(true)?;
    tun_rs::AsyncDevice::new(device)
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

    #[test]
    #[ignore = "requires Windows Administrator and MEOW_TEST_WINTUN_DLL; creates an isolated adapter"]
    fn existing_adapter_is_rejected_before_configuration() {
        let (name, dll, existing) = fixture();
        let before = (
            existing.mtu().unwrap(),
            existing.mtu_v6().unwrap(),
            ipv4_addresses(&existing),
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
                ),
                before
            );
        }
    }

    #[test]
    #[ignore = "requires Windows Administrator and MEOW_TEST_WINTUN_DLL; creates an isolated adapter"]
    fn adapter_appearing_after_preflight_is_rejected_before_configuration() {
        let (name, dll, existing) = fixture();
        let before = (
            existing.mtu().unwrap(),
            existing.mtu_v6().unwrap(),
            ipv4_addresses(&existing),
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
            ),
            before
        );
    }
}
