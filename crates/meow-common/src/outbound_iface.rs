//! Outbound-socket interface binding for TUN global-route mode (#375).
//!
//! With `tun.auto-route: global` the split default routes send all IPv4
//! traffic into the TUN device, including meow's own dials to proxy upstreams
//! and DIRECT destinations. The countermeasure is per-socket: every outbound
//! socket meow creates is bound to the physical interface before
//! `connect()`/`bind()`, so its packets take the physical route regardless of
//! the routing table (Linux `SO_BINDTODEVICE`, macOS `IP_BOUND_IF`, Windows
//! `IP_UNICAST_IF`).

use std::io;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::num::NonZeroU32;
use std::sync::Arc;

use parking_lot::RwLock;

#[derive(Debug)]
struct OutboundInterface {
    name: Arc<str>,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    index: NonZeroU32,
}

static INTERFACE: RwLock<Option<Arc<OutboundInterface>>> = RwLock::new(None);

/// Install the physical interface every subsequent outbound socket binds to.
/// Callers must treat any error as fatal for global-route mode.
pub fn set_outbound_interface(name: &str) -> io::Result<()> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound interface name is empty",
        ));
    }

    #[cfg(target_os = "linux")]
    {
        validate_linux_interface(name)?;
        *INTERFACE.write() = Some(Arc::new(OutboundInterface {
            name: Arc::from(name),
        }));
        tracing::info!("outbound sockets bound to interface '{name}' (SO_BINDTODEVICE)");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let index = resolve_macos_interface_index(name)?;
        *INTERFACE.write() = Some(Arc::new(OutboundInterface {
            name: Arc::from(name),
            index,
        }));
        tracing::info!(
            "outbound sockets bound to interface '{}' (index {}, IP_BOUND_IF)",
            name,
            index
        );
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        let index = resolve_windows_interface_index(name)?;
        *INTERFACE.write() = Some(Arc::new(OutboundInterface {
            name: Arc::from(name),
            index,
        }));
        tracing::info!(
            "outbound sockets bound to interface '{}' (index {}, IP_UNICAST_IF)",
            name,
            index
        );
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("outbound interface binding ('{name}') is not implemented on this platform"),
        ))
    }
}

/// Remove the installed interface; subsequent sockets bind normally.
pub fn clear_outbound_interface() {
    if INTERFACE.write().take().is_some() {
        tracing::info!("outbound interface binding cleared");
    }
}

/// The currently installed interface, if any.
pub fn outbound_interface() -> Option<Arc<str>> {
    current_interface().map(|i| Arc::clone(&i.name))
}

fn current_interface() -> Option<Arc<OutboundInterface>> {
    INTERFACE.read().clone()
}

/// Bind `socket` to the installed interface, if one is installed. No-op when
/// none is. Callers must invoke this before `connect()`/`bind()` so the first
/// packet already takes the physical route.
pub fn apply_outbound_interface(socket: &socket2::Socket) -> io::Result<()> {
    let Some(iface) = current_interface() else {
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        socket.bind_device(Some(iface.name.as_bytes()))?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        apply_macos_outbound_interface(socket, iface.index)
    }

    #[cfg(target_os = "windows")]
    {
        apply_windows_outbound_interface(socket, iface.index.get())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = socket;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "outbound interface binding ('{}') is not implemented on this platform",
                iface.name
            ),
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unix_if_name_cstring(name: &str) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("outbound interface name '{name}' contains a NUL byte"),
        )
    })
}

#[cfg(target_os = "linux")]
fn validate_linux_interface(name: &str) -> io::Result<()> {
    let c_name = unix_if_name_cstring(name)?;
    // SAFETY: `c_name` is a valid NUL-terminated string for the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("outbound interface '{name}' does not exist"),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn resolve_macos_interface_index(name: &str) -> io::Result<NonZeroU32> {
    if let Ok(index) = name.parse::<u32>() {
        if let Some(index) = NonZeroU32::new(index) {
            return Ok(index);
        }
    }

    let c_name = unix_if_name_cstring(name)?;
    // SAFETY: `c_name` is a valid NUL-terminated string for the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    NonZeroU32::new(index).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("outbound interface '{name}' does not exist"),
        )
    })
}

#[cfg(target_os = "windows")]
fn resolve_windows_interface_index(name: &str) -> io::Result<NonZeroU32> {
    if let Ok(index) = name.parse::<u32>() {
        if let Some(index) = NonZeroU32::new(index) {
            return Ok(index);
        }
    }

    resolve_windows_interface_name(name).or_else(|_| resolve_windows_interface_alias(name))
}

#[cfg(target_os = "windows")]
fn resolve_windows_interface_name(name: &str) -> io::Result<NonZeroU32> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceNameToLuidA;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let c_name = std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("outbound interface name '{name}' contains a NUL byte"),
        )
    })?;
    let mut luid = NET_LUID_LH::default();
    // SAFETY: pointers are valid for the duration of the calls.
    let ret = unsafe { ConvertInterfaceNameToLuidA(c_name.as_ptr().cast(), &mut luid) };
    if ret != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(ret as i32));
    }
    luid_to_index(name, &luid)
}

#[cfg(target_os = "windows")]
fn resolve_windows_interface_alias(name: &str) -> io::Result<NonZeroU32> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `wide` is NUL-terminated and valid for the duration of the call.
    let ret = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    if ret != ERROR_SUCCESS {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("outbound interface '{name}' does not exist"),
        ));
    }
    luid_to_index(name, &luid)
}

#[cfg(target_os = "windows")]
fn luid_to_index(
    name: &str,
    luid: &windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH,
) -> io::Result<NonZeroU32> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex;

    let mut index = 0u32;
    // SAFETY: `luid` came from an IP Helper conversion API.
    let ret = unsafe { ConvertInterfaceLuidToIndex(luid, &mut index) };
    if ret != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(ret as i32));
    }
    NonZeroU32::new(index).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("outbound interface '{name}' resolved to index 0"),
        )
    })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
enum SocketFamily {
    Ipv4,
    Ipv6,
}

#[cfg(target_os = "macos")]
fn socket_family(socket: &socket2::Socket) -> io::Result<SocketFamily> {
    let addr = socket.local_addr()?;
    if addr.as_socket_ipv4().is_some() {
        Ok(SocketFamily::Ipv4)
    } else if addr.as_socket_ipv6().is_some() {
        Ok(SocketFamily::Ipv6)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "outbound interface binding supports only IPv4/IPv6 sockets",
        ))
    }
}

#[cfg(target_os = "windows")]
fn socket_family(socket: &socket2::Socket) -> io::Result<SocketFamily> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        getsockopt, AF_INET, AF_INET6, SOCKET, SOCKET_ERROR, SOL_SOCKET, SO_PROTOCOL_INFOW,
        WSAPROTOCOL_INFOW,
    };

    let mut info = WSAPROTOCOL_INFOW::default();
    let mut len = std::mem::size_of::<WSAPROTOCOL_INFOW>() as i32;
    let ret = unsafe {
        getsockopt(
            socket.as_raw_socket() as SOCKET,
            SOL_SOCKET,
            SO_PROTOCOL_INFOW as i32,
            (&mut info as *mut WSAPROTOCOL_INFOW).cast(),
            &mut len,
        )
    };
    if ret == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    match info.iAddressFamily {
        family if family == i32::from(AF_INET) => Ok(SocketFamily::Ipv4),
        family if family == i32::from(AF_INET6) => Ok(SocketFamily::Ipv6),
        family => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("outbound interface binding does not support address family {family}"),
        )),
    }
}

#[cfg(target_os = "macos")]
fn apply_macos_outbound_interface(socket: &socket2::Socket, index: NonZeroU32) -> io::Result<()> {
    match socket_family(socket)? {
        SocketFamily::Ipv4 => socket.bind_device_by_index_v4(Some(index)),
        SocketFamily::Ipv6 => socket.bind_device_by_index_v6(Some(index)),
    }
}

#[cfg(target_os = "windows")]
fn apply_windows_outbound_interface(socket: &socket2::Socket, index: u32) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET, SOCKET_ERROR,
    };

    let raw = socket.as_raw_socket() as SOCKET;
    let (level, option, index) = match socket_family(socket)? {
        SocketFamily::Ipv4 => (IPPROTO_IP, IP_UNICAST_IF, index.to_be()),
        SocketFamily::Ipv6 => (IPPROTO_IPV6, IPV6_UNICAST_IF, index),
    };

    let ret = unsafe {
        setsockopt(
            raw,
            level,
            option,
            (&index as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if ret == SOCKET_ERROR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn registry_rejects_empty_and_clears() {
        let _guard = TEST_LOCK.lock();
        clear_outbound_interface();
        assert!(set_outbound_interface("").is_err());
        assert!(outbound_interface().is_none());
        clear_outbound_interface();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_install_apply_clear_roundtrip() {
        let _guard = TEST_LOCK.lock();
        clear_outbound_interface();
        assert!(set_outbound_interface("no-such-iface-zz9").is_err());
        assert!(outbound_interface().is_none());

        set_outbound_interface("lo").expect("lo must exist");
        assert_eq!(outbound_interface().as_deref(), Some("lo"));

        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_outbound_interface(&socket).expect("bind_device to lo");

        clear_outbound_interface();
        assert!(outbound_interface().is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_install_apply_clear_roundtrip() {
        let _guard = TEST_LOCK.lock();
        clear_outbound_interface();
        assert!(set_outbound_interface("no-such-iface-zz9").is_err());
        assert!(outbound_interface().is_none());

        set_outbound_interface("lo0").expect("lo0 must exist");
        assert_eq!(outbound_interface().as_deref(), Some("lo0"));
        let index = resolve_macos_interface_index("lo0").unwrap();

        let v4 = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_outbound_interface(&v4).expect("IP_BOUND_IF to lo0");
        assert_eq!(macos_bound_if_v4(&v4).unwrap(), index.get());

        let v6 = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_outbound_interface(&v6).expect("IPV6_BOUND_IF to lo0");
        assert_eq!(macos_bound_if_v6(&v6).unwrap(), index.get());

        clear_outbound_interface();
        assert!(outbound_interface().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_applies_ipv4_and_ipv6_bindings() {
        let _guard = TEST_LOCK.lock();
        clear_outbound_interface();
        set_outbound_interface("1").expect("loopback interface index 1 must exist on Windows");

        let v4 = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_outbound_interface(&v4).expect("IP_UNICAST_IF on IPv4 socket");

        let v6 = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_outbound_interface(&v6).expect("IPV6_UNICAST_IF on IPv6 socket");

        clear_outbound_interface();
    }

    #[cfg(target_os = "macos")]
    fn macos_bound_if_v4(socket: &socket2::Socket) -> io::Result<u32> {
        macos_get_bound_if(socket, libc::IPPROTO_IP, libc::IP_BOUND_IF)
    }

    #[cfg(target_os = "macos")]
    fn macos_bound_if_v6(socket: &socket2::Socket) -> io::Result<u32> {
        macos_get_bound_if(socket, libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    }

    #[cfg(target_os = "macos")]
    fn macos_get_bound_if(
        socket: &socket2::Socket,
        level: libc::c_int,
        name: libc::c_int,
    ) -> io::Result<u32> {
        use std::os::fd::AsRawFd;

        let mut value = 0u32;
        let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                name,
                (&mut value as *mut u32).cast(),
                &mut len,
            )
        };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(value)
        }
    }
}
