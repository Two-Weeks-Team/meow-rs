//! Read-only change monitoring for the installed physical IPv4 LUID.

use std::{io, sync::Arc};

use parking_lot::Mutex;
use tokio::sync::watch;
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, HANDLE},
    NetworkManagement::{
        IpHelper::{
            CancelMibChangeNotify2, ConvertInterfaceIndexToLuid, GetIpInterfaceEntry,
            MibInitialNotification, NotifyIpInterfaceChange, NotifyUnicastIpAddressChange,
            MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::AF_INET,
};

#[derive(Debug)]
struct State {
    generation: u64,
    changes: watch::Sender<Result<u64, Arc<str>>>,
}

#[derive(Debug)]
struct Context {
    luid: u64,
    state: Mutex<State>,
}

impl Context {
    fn refresh(&self, changed: bool) -> io::Result<()> {
        // Both notification registrations use this lock. Cancellation never
        // holds it, and callbacks never acquire the global interface lock.
        let mut state = self.state.lock();
        if changed {
            state.generation = state.generation.wrapping_add(1);
        }
        let mut row = MIB_IPINTERFACE_ROW {
            Family: AF_INET,
            InterfaceLuid: NET_LUID_LH { Value: self.luid },
            ..Default::default()
        };
        // SAFETY: this is our fresh row, not the OS-owned partial callback row.
        let result = unsafe { GetIpInterfaceEntry(&mut row) };
        let status = if result != ERROR_SUCCESS {
            Err(format!(
                "physical IPv4 interface LUID {} query failed: {}",
                self.luid,
                io::Error::from_raw_os_error(result as i32)
            ))
        } else if !row.Connected {
            Err(format!(
                "physical IPv4 interface LUID {} is disconnected",
                self.luid
            ))
        } else {
            Ok(state.generation)
        };
        let _ = state
            .changes
            .send_replace(status.clone().map_err(Arc::from));
        if let Err(error) = status {
            // A known disconnected link is a valid monitored state. A failed
            // initial inventory read cannot establish a usable registration.
            if result != ERROR_SUCCESS {
                return Err(io::Error::other(error));
            }
        }
        Ok(())
    }

    fn changed(&self, luid: u64) {
        if luid != self.luid {
            return;
        }
        // Every matching notification advances the epoch, including a failed
        // state read. Do not coalesce a down/up cycle back into the old epoch.
        if let Err(error) = self.refresh(true) {
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
    unsafe { (&*context.cast::<Context>()).changed((*row).InterfaceLuid.Value) };
}

unsafe extern "system" fn address_changed(
    context: *const core::ffi::c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    kind: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() || row.is_null() || kind == MibInitialNotification {
        return;
    }
    unsafe { (&*context.cast::<Context>()).changed((*row).InterfaceLuid.Value) };
}
