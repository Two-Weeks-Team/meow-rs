//! Read-only change monitoring for the installed physical IPv4 LUID.

use std::{io, sync::Arc};

use parking_lot::Mutex;
use tokio::sync::watch;
use windows_sys::Win32::{
    Foundation::{ERROR_NOT_FOUND, ERROR_SUCCESS, HANDLE},
    NetworkManagement::{
        IpHelper::{
            CancelMibChangeNotify2, ConvertInterfaceIndexToLuid, FreeMibTable, GetIpInterfaceEntry,
            GetUnicastIpAddressTable, MibAddInstance, MibDeleteInstance, MibInitialNotification,
            NotifyIpInterfaceChange, NotifyUnicastIpAddressChange, MIB_IPINTERFACE_ROW,
            MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{IpDadStatePreferred, AF_INET},
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SourceAddress {
    address: u32,
    dad_state: i32,
    skip_as_source: bool,
    prefix_length: u8,
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    connected: bool,
    mtu: u32,
    addresses: Vec<SourceAddress>,
}

#[derive(Debug)]
struct State {
    generation: u64,
    snapshot: Option<Result<Snapshot, Arc<str>>>,
    changes: watch::Sender<Result<u64, Arc<str>>>,
}

impl State {
    fn record(&mut self, snapshot: Result<Snapshot, Arc<str>>, topology_changed: bool) {
        let different = self.snapshot.as_ref().is_some_and(|old| old != &snapshot);
        if topology_changed || different {
            self.generation = self.generation.wrapping_add(1);
        } else if self.snapshot.is_some() {
            // Parameter notifications also report receive/offload changes.
            // An unchanged link must not close healthy authenticated sessions.
            return;
        }
        let status = match &snapshot {
            Err(error) => Err(Arc::clone(error)),
            Ok(row) if !row.connected => Err(Arc::from("physical IPv4 interface is disconnected")),
            Ok(row)
                if !row.addresses.iter().any(|address| {
                    !address.skip_as_source && address.dad_state == IpDadStatePreferred
                }) =>
            {
                Err(Arc::from("physical interface has no usable IPv4 source"))
            }
            Ok(_) => Ok(self.generation),
        };
        self.snapshot = Some(snapshot);
        let _ = self.changes.send_replace(status);
    }
}

#[derive(Debug)]
struct Context {
    luid: u64,
    state: Mutex<State>,
}

impl Context {
    fn refresh(&self, topology_changed: bool) -> io::Result<()> {
        // Both notification registrations use this lock. Cancellation never
        // holds it, and callbacks never acquire the global interface lock.
        let mut state = self.state.lock();
        let snapshot = self.read_snapshot();
        let error = snapshot.as_ref().err().cloned();
        state.record(snapshot, topology_changed);
        error.map_or(Ok(()), |error| Err(io::Error::other(error.to_string())))
    }

    fn read_snapshot(&self) -> Result<Snapshot, Arc<str>> {
        let mut row = MIB_IPINTERFACE_ROW {
            Family: AF_INET,
            InterfaceLuid: NET_LUID_LH { Value: self.luid },
            ..Default::default()
        };
        // SAFETY: this is our fresh row, not the OS-owned partial callback row.
        let result = unsafe { GetIpInterfaceEntry(&mut row) };
        if result != ERROR_SUCCESS {
            return Err(Arc::from(format!(
                "physical IPv4 interface LUID {} query failed: {}",
                self.luid,
                io::Error::from_raw_os_error(result as i32)
            )));
        }
        let mut snapshot = Snapshot {
            connected: row.Connected,
            mtu: row.NlMtu,
            addresses: Vec::new(),
        };
        if !row.Connected {
            return Ok(snapshot);
        }
        let mut table = std::ptr::null_mut();
        let result = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
        if result == ERROR_NOT_FOUND {
            return Ok(snapshot);
        }
        if result != ERROR_SUCCESS {
            return Err(Arc::from(format!(
                "physical IPv4 address inventory failed: {}",
                io::Error::from_raw_os_error(result as i32)
            )));
        }
        // SAFETY: a successful getter owns a variable-length table allocated
        // by Windows. Use its generated Table offset (including ABI padding),
        // copy only IPv4 rows for this LUID, then release the allocation.
        unsafe {
            for address in
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            {
                if address.InterfaceLuid.Value == self.luid && address.Address.si_family == AF_INET
                {
                    snapshot.addresses.push(SourceAddress {
                        address: address.Address.Ipv4.sin_addr.S_un.S_addr,
                        dad_state: address.DadState,
                        skip_as_source: address.SkipAsSource,
                        prefix_length: address.OnLinkPrefixLength,
                    });
                }
            }
            FreeMibTable(table.cast());
        }
        // Enumeration order and ticking DHCP lifetimes do not change the
        // usable source addresses. Neither belongs in the session identity.
        snapshot.addresses.sort_unstable();
        Ok(snapshot)
    }

    fn changed(&self, luid: u64, kind: MIB_NOTIFICATION_TYPE) {
        if luid != self.luid {
            return;
        }
        // Add/delete notifications prove a topology transition even if both
        // callbacks observe the same final snapshot. Observed failures also
        // advance the epoch; do not debounce them back into a healthy session.
        let topology_changed = kind == MibAddInstance || kind == MibDeleteInstance;
        if let Err(error) = self.refresh(topology_changed) {
            tracing::warn!("{error}");
        }
    }
}

/// Owns callback registration and its stable allocation. Integer handle storage
/// avoids asserting Send/Sync for an arbitrary borrowed Windows pointer.
#[derive(Debug)]
pub(super) struct InterfaceMonitor {
    handles: [usize; 2],
    context: Option<Box<Context>>,
}

impl InterfaceMonitor {
    pub(super) fn new(index: u32) -> io::Result<Self> {
        let mut luid = NET_LUID_LH::default();
        let result = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let (changes, _) =
            watch::channel(Err(Arc::from("physical interface monitor initializing")));
        let mut monitor = Self {
            handles: [0; 2],
            context: Some(Box::new(Context {
                // SAFETY: the conversion initialized this NET_LUID value.
                luid: unsafe { luid.Value },
                state: Mutex::new(State {
                    generation: 0,
                    snapshot: None,
                    changes,
                }),
            })),
        };
        let context = monitor.context.as_deref().expect("new monitor context");
        let pointer = (context as *const Context).cast();
        let mut handle = std::ptr::null_mut();
        // SAFETY: the boxed context stays at this address until both
        // registrations are cancelled, including partial setup rollback.
        let result = unsafe {
            NotifyIpInterfaceChange(
                AF_INET,
                Some(interface_changed),
                pointer,
                false,
                &mut handle,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        monitor.handles[0] = handle as usize;
        let result = unsafe {
            NotifyUnicastIpAddressChange(
                AF_INET,
                Some(address_changed),
                pointer,
                false,
                &mut handle,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        monitor.handles[1] = handle as usize;
        // Register first, then read: a change during the initial inventory is
        // either reflected by this read or delivered with a later generation.
        context.refresh(false)?;
        Ok(monitor)
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<Result<u64, Arc<str>>> {
        self.context
            .as_ref()
            .expect("live monitor context")
            .state
            .lock()
            .changes
            .subscribe()
    }
}

impl Drop for InterfaceMonitor {
    fn drop(&mut self) {
        let mut cancelled = true;
        for handle in self.handles.into_iter().filter(|handle| *handle != 0) {
            // This owner is never moved into a callback. No callback lock is
            // held here: Cancel waits for callbacks before their context drops.
            let result = unsafe { CancelMibChangeNotify2(handle as HANDLE) };
            if result != ERROR_SUCCESS {
                cancelled = false;
                tracing::error!(
                    "physical interface notification cancellation failed: {}",
                    io::Error::from_raw_os_error(result as i32)
                );
            }
        }
        if !cancelled {
            // An OS cancellation failure cannot justify freeing memory which
            // may still be used by a callback. Publish failure and retain only
            // this context until process exit; never leave a usable old epoch.
            if let Some(context) = self.context.take() {
                let _ = context.state.lock().changes.send_replace(Err(Arc::from(
                    "physical interface notification cancellation failed",
                )));
                Box::leak(context);
            }
        }
    }
}

unsafe extern "system" fn interface_changed(
    context: *const core::ffi::c_void,
    row: *const MIB_IPINTERFACE_ROW,
    kind: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() || row.is_null() || kind == MibInitialNotification {
        return;
    }
    // Only the identity fields are valid in this OS-owned partial row. Never
    // retain/free the row or treat its Connected/address fields as a snapshot.
    unsafe { (&*context.cast::<Context>()).changed((*row).InterfaceLuid.Value, kind) };
}

unsafe extern "system" fn address_changed(
    context: *const core::ffi::c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    kind: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() || row.is_null() || kind == MibInitialNotification {
        return;
    }
    unsafe { (&*context.cast::<Context>()).changed((*row).InterfaceLuid.Value, kind) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> Result<Snapshot, Arc<str>> {
        Ok(Snapshot {
            connected: true,
            mtu: 1500,
            addresses: vec![SourceAddress {
                address: 1,
                dad_state: 4,
                skip_as_source: false,
                prefix_length: 24,
            }],
        })
    }

    fn state() -> (State, watch::Receiver<Result<u64, Arc<str>>>) {
        let (changes, receiver) = watch::channel(Err(Arc::from("initializing")));
        let mut state = State {
            generation: 0,
            snapshot: None,
            changes,
        };
        state.record(ready(), false);
        (state, receiver)
    }

    #[test]
    fn unchanged_parameter_events_preserve_the_transport_epoch() {
        let (mut state, mut receiver) = state();
        assert_eq!(*receiver.borrow_and_update(), Ok(0));
        for _ in 0..20 {
            state.record(ready(), false);
        }
        assert_eq!(*receiver.borrow(), Ok(0));
        assert!(!receiver.has_changed().unwrap());
    }

    #[test]
    fn observed_loss_survives_recovery_before_a_subscriber_wakes() {
        let (mut state, receiver) = state();
        let mut down = ready().unwrap();
        down.connected = false;
        state.record(Ok(down), false);
        assert!(receiver.borrow().is_err());
        state.record(ready(), false);
        assert_eq!(*receiver.borrow(), Ok(2));
    }

    #[test]
    fn query_failure_survives_recovery_before_a_subscriber_wakes() {
        let (mut state, receiver) = state();
        state.record(Err(Arc::from("interface removed")), false);
        assert!(receiver.borrow().is_err());
        state.record(ready(), false);
        assert_eq!(*receiver.borrow(), Ok(2));
    }

    #[test]
    fn add_delete_events_preserve_a_transition_with_identical_final_inventory() {
        let (mut state, receiver) = state();
        state.record(ready(), true);
        state.record(ready(), true);
        assert_eq!(*receiver.borrow(), Ok(2));
    }

    #[test]
    fn mtu_and_source_address_changes_invalidate_sessions() {
        let mutations: [fn(&mut Snapshot); 3] = [
            |s| s.mtu = 1400,
            |s| s.addresses[0].address = 2,
            |s| s.addresses[0].prefix_length = 16,
        ];
        for mutate in mutations {
            let (mut state, receiver) = state();
            let mut changed = ready().unwrap();
            mutate(&mut changed);
            state.record(Ok(changed), false);
            assert_eq!(*receiver.borrow(), Ok(1));
        }
    }

    #[test]
    fn unusable_source_addresses_block_dials_until_recovery() {
        let mutations: [fn(&mut Snapshot); 6] = [
            |s| s.addresses.clear(),
            |s| s.addresses[0].dad_state = 0,
            |s| s.addresses[0].dad_state = 1,
            |s| s.addresses[0].dad_state = 2,
            |s| s.addresses[0].dad_state = 3,
            |s| s.addresses[0].skip_as_source = true,
        ];
        for mutate in mutations {
            let (mut state, receiver) = state();
            let mut unavailable = ready().unwrap();
            mutate(&mut unavailable);
            state.record(Ok(unavailable), false);
            assert!(receiver.borrow().is_err());
            state.record(ready(), false);
            assert_eq!(*receiver.borrow(), Ok(2));
        }
    }
}
