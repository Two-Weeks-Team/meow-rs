use super::config::Config;
use super::socket::{bind_protected_std_udp, Hy2UdpSocket};
use super::tcp::{self, DuplexStream};
use super::tls;
use super::udp::{self, UdpRouter, UdpSession};
use super::{Error, Result};
use bytes::Buf;
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::Runtime;
use quinn::{Connection, Endpoint};
use std::future::pending;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicU16;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ReconnectableClient {
    cfg: Arc<Config>,
    conn: Mutex<Option<Arc<ClientConnection>>>,
}

impl ReconnectableClient {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(cfg),
            conn: Mutex::new(None),
        }
    }

    pub async fn tcp_connect(&self, target: &str) -> Result<DuplexStream> {
        let client = self.connection().await?;
        let (mut send, recv) = client
            .connection
            .open_bi()
            .await
            .map_err(|e| Error::Quic(e.to_string()))?;

        if !self.cfg.fast_open {
            tcp::write_initial_request(&mut send, target).await?;
        }

        Ok(DuplexStream::new(
            send,
            recv,
            target.to_string(),
            !self.cfg.fast_open,
        ))
    }

    pub async fn udp(&self) -> Result<UdpSession> {
        let client = self.connection().await?;
        UdpSession::new(client)
    }

    async fn connection(&self) -> Result<Arc<ClientConnection>> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            if conn.is_active() {
                return Ok(Arc::clone(conn));
            }
        }

        let conn = Arc::new(connect_new(Arc::clone(&self.cfg)).await?);
        *guard = Some(Arc::clone(&conn));
        Ok(conn)
    }
}

pub(crate) struct ClientConnection {
    pub(crate) connection: Connection,
    _endpoint: Endpoint,
    h3_driver: tokio::task::JoinHandle<()>,
    udp_driver: Option<tokio::task::JoinHandle<()>>,
    pub(crate) udp_enabled: bool,
    pub(crate) udp_router: Arc<UdpRouter>,
    pub(crate) next_session_id: std::sync::atomic::AtomicU32,
    pub(crate) next_packet_id: AtomicU16,
    #[cfg(any(target_os = "windows", test))]
    interface: Option<InterfaceWatch>,
    #[cfg(any(target_os = "windows", test))]
    interface_driver: Option<tokio::task::JoinHandle<()>>,
}

impl ClientConnection {
    fn is_active(&self) -> bool {
        #[cfg(any(target_os = "windows", test))]
        if self
            .interface
            .as_ref()
            .is_some_and(|watch| watch.check().is_err())
        {
            self.connection
                .close(0u32.into(), b"physical interface changed");
            return false;
        }
        self.connection.close_reason().is_none()
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        #[cfg(any(target_os = "windows", test))]
        {
            self.connection.close(0u32.into(), b"client dropped");
            if let Some(driver) = &self.interface_driver {
                driver.abort();
            }
        }
        self.h3_driver.abort();
        if let Some(driver) = &self.udp_driver {
            driver.abort();
        }
    }
}

async fn connect_new(cfg: Arc<Config>) -> Result<ClientConnection> {
    let server = ServerTarget::parse(&cfg.server_addr)?;
    let addrs = meow_common::resolve_host_all(&server.host, server.port)
        .await
        .map_err(|e| Error::Resolve(format!("{}:{}: {e}", server.host, server.port)))?;
    let server_name = if cfg.server_name.trim().is_empty() {
        server.host.clone()
    } else {
        cfg.server_name.trim().to_string()
    };

    let mut last_error = None;
    for addr in addrs {
        match connect_addr(Arc::clone(&cfg), addr, &server_name).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or_else(|| Error::Resolve("no address resolved".into())))
}

async fn connect_addr(
    cfg: Arc<Config>,
    server_addr: SocketAddr,
    server_name: &str,
) -> Result<ClientConnection> {
    #[cfg(target_os = "windows")]
    {
        // Subscribe before creating a socket. The same epoch guards all
        // awaits, including QUIC setup and HTTP/3 authentication.
        let interface =
            InterfaceWatch::new(meow_common::outbound_iface::outbound_interface_changes())?;
        connect_addr_watched(cfg, server_addr, server_name, interface).await
    }
    #[cfg(not(target_os = "windows"))]
    connect_addr_inner(cfg, server_addr, server_name).await
}

#[cfg(any(target_os = "windows", test))]
async fn connect_addr_watched(
    cfg: Arc<Config>,
    server_addr: SocketAddr,
    server_name: &str,
    interface: InterfaceWatch,
) -> Result<ClientConnection> {
    let mut waiter = interface.clone();
    let mut client = waiter
        .during(connect_addr_inner(cfg, server_addr, server_name))
        .await??;
    client.interface_driver = Some(interface.clone().close_on_change(client.connection.clone()));
    client.interface = Some(interface);
    Ok(client)
}

async fn connect_addr_inner(
    cfg: Arc<Config>,
    server_addr: SocketAddr,
    server_name: &str,
) -> Result<ClientConnection> {
    let needs_custom_socket = !cfg.obfs_password.is_empty() || !cfg.hop_ports.trim().is_empty();
    let mut endpoint = if needs_custom_socket {
        let socket = Hy2UdpSocket::bind(
            server_addr,
            &cfg.hop_ports,
            cfg.hop_interval_min_secs,
            cfg.hop_interval_max_secs,
            &cfg.obfs_password,
        )
        .await?;
        let mut endpoint_cfg = quinn::EndpointConfig::default();
        endpoint_cfg.grease_quic_bit(false);
        Endpoint::new_with_abstract_socket(
            endpoint_cfg,
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?
    } else {
        let bind_addr = if server_addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let std_sock = bind_protected_std_udp(bind_addr).await?;
        let runtime = Arc::new(quinn::TokioRuntime);
        let socket = runtime.wrap_udp_socket(std_sock)?;
        let mut endpoint_cfg = quinn::EndpointConfig::default();
        endpoint_cfg.grease_quic_bit(false);
        Endpoint::new_with_abstract_socket(endpoint_cfg, None, socket, runtime)?
    };
    let client_cfg = tls::build_client_config(&cfg)?;
    endpoint.set_default_client_config(client_cfg);
    let connecting = endpoint
        .connect(server_addr, server_name)
        .map_err(|e| Error::Quic(format!("connect start: {e}")))?;
    let connection = timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| Error::Quic(format!("connect timeout after {CONNECT_TIMEOUT:?}")))?
        .map_err(|e| Error::Quic(format!("connect: {e}")))?;
    #[cfg(any(target_os = "windows", test))]
    let mut setup = ConnectionSetup::new(connection.clone());

    let (h3_conn, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|e| Error::Http3(e.to_string()))?;
    let h3_driver = tokio::spawn(async move {
        // Keep the HTTP/3 session alive for the lifetime of the QUIC connection.
        // Driving `poll_close` here would tear down the connection and break
        // proxied TCP/UDP streams opened via `open_bi`.
        let _ = h3_conn;
        pending::<()>().await;
    });
    #[cfg(any(target_os = "windows", test))]
    setup.drivers.push(h3_driver.abort_handle());

    let udp_enabled = match authenticate(&cfg, &mut send_request).await {
        Ok(udp_enabled) => udp_enabled,
        Err(e) => {
            connection.close(0u32.into(), b"auth failed");
            h3_driver.abort();
            return Err(e);
        }
    };

    let udp_router = Arc::new(UdpRouter::new());
    let udp_driver =
        udp_enabled.then(|| udp::spawn_receiver(connection.clone(), Arc::clone(&udp_router)));
    #[cfg(any(target_os = "windows", test))]
    if let Some(driver) = &udp_driver {
        setup.drivers.push(driver.abort_handle());
    }

    let client = ClientConnection {
        connection,
        _endpoint: endpoint,
        h3_driver,
        udp_driver,
        udp_enabled,
        udp_router,
        next_session_id: std::sync::atomic::AtomicU32::new(0),
        next_packet_id: AtomicU16::new(0),
        #[cfg(any(target_os = "windows", test))]
        interface: None,
        #[cfg(any(target_os = "windows", test))]
        interface_driver: None,
    };
    #[cfg(any(target_os = "windows", test))]
    setup.commit();
    Ok(client)
}

/// Windows setup cancellation must close QUIC and abort its keep-alive tasks;
/// dropping a JoinHandle alone detaches it. Tests exercise this with real QUIC.
#[cfg(any(target_os = "windows", test))]
struct ConnectionSetup {
    connection: Option<Connection>,
    drivers: Vec<tokio::task::AbortHandle>,
}

#[cfg(any(target_os = "windows", test))]
impl ConnectionSetup {
    fn new(connection: Connection) -> Self {
        Self {
            connection: Some(connection),
            drivers: Vec::new(),
        }
    }

    fn commit(mut self) {
        self.connection = None;
        self.drivers.clear();
    }
}

#[cfg(any(target_os = "windows", test))]
impl Drop for ConnectionSetup {
    fn drop(&mut self) {
        if let Some(connection) = &self.connection {
            connection.close(0u32.into(), b"connection setup cancelled");
        }
        for driver in &self.drivers {
            driver.abort();
        }
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone)]
struct InterfaceWatch {
    receiver: Option<tokio::sync::watch::Receiver<std::result::Result<u64, Arc<str>>>>,
    generation: u64,
}

#[cfg(any(target_os = "windows", test))]
impl InterfaceWatch {
    fn new(
        receiver: Option<tokio::sync::watch::Receiver<std::result::Result<u64, Arc<str>>>>,
    ) -> Result<Self> {
        let generation = match receiver.as_ref().map(|receiver| receiver.borrow().clone()) {
            Some(Ok(generation)) => generation,
            Some(Err(error)) => return Err(Error::Io(std::io::Error::other(error.to_string()))),
            None => 0,
        };
        let watch = Self {
            receiver,
            generation,
        };
        watch.check()?;
        Ok(watch)
    }

    fn check(&self) -> Result<()> {
        let Some(receiver) = &self.receiver else {
            return Ok(());
        };
        let message = if receiver.has_changed().is_err() {
            Some("physical interface installation ended".to_string())
        } else {
            match &*receiver.borrow() {
                Ok(generation) if *generation == self.generation => None,
                Ok(_) => Some("physical interface changed".to_string()),
                Err(error) => Some(error.to_string()),
            }
        };
        match message {
            Some(message) => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                message,
            ))),
            None => Ok(()),
        }
    }

    async fn changed(&mut self) -> Error {
        loop {
            if let Err(error) = self.check() {
                return error;
            }
            let Some(receiver) = &mut self.receiver else {
                return pending().await;
            };
            // A closed sender also invalidates the installation. Check it on
            // the next loop, without treating channel shutdown as a new link.
            let _ = receiver.changed().await;
        }
    }

    async fn during<F: std::future::Future>(&mut self, future: F) -> Result<F::Output> {
        self.check()?;
        let result = tokio::select! {
            biased;
            error = self.changed() => return Err(error),
            result = future => result,
        };
        // Reject a completion racing the notification before it can be cached.
        self.check()?;
        Ok(result)
    }

    fn close_on_change(mut self, connection: Connection) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            tokio::select! {
                error = self.changed() => {
                    tracing::debug!("hysteria2 invalidating transport: {error}");
                    // TCP streams and UDP sessions retain connection references;
                    // removing a pool entry alone does not close those users.
                    connection.close(0u32.into(), b"physical interface changed");
                }
                _ = connection.closed() => {}
            }
        })
    }
}

async fn authenticate(
    cfg: &Config,
    send_request: &mut SendRequest<OpenStreams, bytes::Bytes>,
) -> Result<bool> {
    let padding = super::proto::auth_request_padding();
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header(http::header::HOST, "hysteria")
        .header("Hysteria-Auth", cfg.auth.as_str())
        .header("Hysteria-CC-RX", cfg.rx_bps.to_string())
        .header("Hysteria-Padding", padding)
        .body(())
        .map_err(|e| Error::Http3(format!("auth request build: {e}")))?;

    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| Error::Http3(format!("auth send: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| Error::Http3(format!("auth finish: {e}")))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|e| Error::Http3(format!("auth response: {e}")))?;
    if response.status().as_u16() != 233 {
        return Err(Error::Auth(format!(
            "authentication failed, status code: {}",
            response.status()
        )));
    }

    let udp_enabled = response
        .headers()
        .get("Hysteria-UDP")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("true") || value == "1" || value.eq_ignore_ascii_case("yes")
        });

    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| Error::Http3(format!("auth body: {e}")))?
    {
        chunk.advance(chunk.remaining());
    }

    Ok(udp_enabled)
}

struct ServerTarget {
    host: String,
    port: u16,
}

impl ServerTarget {
    fn parse(addr: &str) -> Result<Self> {
        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            return Ok(Self {
                host: socket_addr.ip().to_string(),
                port: socket_addr.port(),
            });
        }

        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| Error::config(format!("server address has no port: {addr}")))?;
        if host.is_empty() || host.contains(':') {
            return Err(Error::config(format!(
                "invalid server address, bracket IPv6 literals: {addr}"
            )));
        }
        let port = port
            .parse::<u16>()
            .map_err(|e| Error::config(format!("invalid server port in '{addr}': {e}")))?;
        if port == 0 {
            return Err(Error::config("server port must be non-zero"));
        }

        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{oneshot, watch};

    fn quic_server() -> Endpoint {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
            )
            .unwrap();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        ));
        Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
    }

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            insecure: true,
            auth: "underlay-test".into(),
            ..Default::default()
        })
    }

    async fn quic_pair() -> (Endpoint, Connection, Endpoint, Connection) {
        let server = quic_server();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(tls::build_client_config(&test_config()).unwrap());
        let (client_connection, server_connection) = timeout(Duration::from_secs(3), async {
            tokio::join!(
                client
                    .connect(server.local_addr().unwrap(), "localhost")
                    .unwrap(),
                async { server.accept().await.unwrap().await },
            )
        })
        .await
        .unwrap();
        (
            client,
            client_connection.unwrap(),
            server,
            server_connection.unwrap(),
        )
    }

    #[tokio::test]
    async fn interface_watch_rejects_late_success_after_same_interface_down_up() {
        let (changes, receiver) = watch::channel(Ok(1));
        let mut interface = InterfaceWatch::new(Some(receiver)).unwrap();
        let result = interface
            .during(async {
                let _ = changes.send_replace(Err(Arc::from("same LUID disconnected")));
                let _ = changes.send_replace(Ok(3));
                // The link is back before this future returns. This result still
                // belongs to the old socket epoch and must not enter the pool.
                42
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn interface_failure_or_registration_end_does_not_poll_setup() {
        use std::sync::atomic::{AtomicBool, Ordering};
        for close_channel in [false, true] {
            let (changes, receiver) = watch::channel(Ok(1));
            let mut interface = InterfaceWatch::new(Some(receiver)).unwrap();
            let _keep_sender = if close_channel {
                drop(changes);
                None
            } else {
                let _ = changes.send_replace(Err(Arc::from("GetIpInterfaceEntry failed: 1168")));
                Some(changes)
            };
            let polled = AtomicBool::new(false);
            let error = interface
                .during(async { polled.store(true, Ordering::SeqCst) })
                .await
                .unwrap_err();
            assert!(error.to_string().contains(if close_channel {
                "installation ended"
            } else {
                "GetIpInterfaceEntry failed: 1168"
            }));
            assert!(!polled.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn interface_change_cancels_pending_quic_handshake() {
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = blackhole.local_addr().unwrap();
        let (changes, receiver) = watch::channel(Ok(1));
        let connecting = tokio::spawn(connect_addr_watched(
            test_config(),
            address,
            "localhost",
            InterfaceWatch::new(Some(receiver)).unwrap(),
        ));
        let mut packet = [0u8; 2048];
        timeout(Duration::from_secs(3), blackhole.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        let _ = changes.send_replace(Ok(2));
        let result = timeout(Duration::from_secs(3), connecting)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "must not wait for the normal 10 second handshake timeout"
        );
    }

    #[tokio::test]
    async fn interface_change_cancels_pending_auth_and_closes_peer() {
        let server = quic_server();
        let (changes, receiver) = watch::channel(Ok(1));
        let connecting = tokio::spawn(connect_addr_watched(
            test_config(),
            server.local_addr().unwrap(),
            "localhost",
            InterfaceWatch::new(Some(receiver)).unwrap(),
        ));
        let peer = timeout(Duration::from_secs(3), async {
            server.accept().await.unwrap().await
        })
        .await
        .unwrap()
        .unwrap();
        // Seeing the request's first byte proves QUIC and h3 setup completed,
        // with the auth response still pending and its driver already spawned.
        let (_send, mut receive) = timeout(Duration::from_secs(3), peer.accept_bi())
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        timeout(Duration::from_secs(3), receive.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        let _ = changes.send_replace(Ok(2));
        assert!(timeout(Duration::from_secs(3), connecting)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        let closed = timeout(Duration::from_secs(3), peer.closed())
            .await
            .unwrap();
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(_)),
            "{closed}"
        );
    }

    #[tokio::test]
    async fn unchanged_transport_works_then_change_closes_retained_streams() {
        let (_client_endpoint, client, _server_endpoint, peer) = quic_pair().await;
        let (changes, receiver) = watch::channel(Ok(1));
        let interface = InterfaceWatch::new(Some(receiver)).unwrap();
        let driver = interface.clone().close_on_change(client.clone());
        let retained = client.clone();
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        send.write_all(b"request").await.unwrap();
        let (mut reply, mut request) = peer.accept_bi().await.unwrap();
        let mut data = [0; 7];
        request.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"request");
        reply.write_all(b"reply").await.unwrap();
        let mut data = [0; 5];
        recv.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"reply");
        assert!(interface.check().is_ok());
        assert!(client.close_reason().is_none());
        assert!(!driver.is_finished());

        let _ = changes.send_replace(Err(Arc::from("same LUID down")));
        let _ = changes.send_replace(Ok(3));
        timeout(Duration::from_secs(3), driver)
            .await
            .unwrap()
            .unwrap();
        assert!(retained.close_reason().is_some());
        assert!(recv.read(&mut data).await.is_err());
        assert!(send.write_all(b"next").await.is_err());
    }

    #[tokio::test]
    async fn interface_change_closes_udp_session_retaining_entire_client() {
        let (endpoint, connection, _server_endpoint, peer) = quic_pair().await;
        let (changes, receiver) = watch::channel(Ok(1));
        let interface = InterfaceWatch::new(Some(receiver)).unwrap();
        let router = Arc::new(UdpRouter::new());
        let client = Arc::new(ClientConnection {
            interface_driver: Some(interface.clone().close_on_change(connection.clone())),
            udp_driver: Some(udp::spawn_receiver(connection.clone(), Arc::clone(&router))),
            connection,
            _endpoint: endpoint,
            h3_driver: tokio::spawn(pending()),
            udp_enabled: true,
            udp_router: router,
            next_session_id: std::sync::atomic::AtomicU32::new(0),
            next_packet_id: AtomicU16::new(0),
            interface: Some(interface),
        });
        let lifetime = Arc::downgrade(&client);
        let mut session = UdpSession::new(client).unwrap();
        session.send(b"datagram", "127.0.0.1:53").unwrap();
        let datagram = timeout(Duration::from_secs(3), peer.read_datagram())
            .await
            .unwrap()
            .unwrap();
        peer.send_datagram(datagram).unwrap();
        let (data, destination) = timeout(Duration::from_secs(3), session.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data, b"datagram");
        assert_eq!(destination, "127.0.0.1:53");

        let _ = changes.send_replace(Ok(2));
        assert!(matches!(
            timeout(Duration::from_secs(3), session.recv())
                .await
                .unwrap(),
            Err(Error::Closed)
        ));
        assert!(session.send(b"next", "127.0.0.1:53").is_err());
        assert!(lifetime.upgrade().is_some());
        drop(session);
        assert!(lifetime.upgrade().is_none());
    }

    #[tokio::test]
    async fn setup_rollback_aborts_driver_and_commit_preserves_connection() {
        let (_client_endpoint, client, _server_endpoint, _peer) = quic_pair().await;
        ConnectionSetup::new(client.clone()).commit();
        assert!(client.close_reason().is_none());
        let (started_tx, started_rx) = oneshot::channel();
        let driver = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            pending::<()>().await;
        });
        started_rx.await.unwrap();
        let mut setup = ConnectionSetup::new(client.clone());
        setup.drivers.push(driver.abort_handle());
        drop(setup);
        assert!(timeout(Duration::from_secs(3), driver)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled());
        assert!(client.close_reason().is_some());
    }

    #[test]
    fn parses_domain_server_target() {
        let target = ServerTarget::parse("example.com:443").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parses_bracketed_ipv6_server_target() {
        let target = ServerTarget::parse("[::1]:443").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
    }
}

#[cfg(all(test, target_os = "android"))]
mod android_tests {
    use super::*;
    use crate::hysteria2::socket::android_protector_tests;

    #[tokio::test]
    async fn plain_endpoint_propagates_android_protector_rejection_before_connect() {
        let (protector, _guard) = android_protector_tests::SpyProtector::install(true);
        let cfg = Arc::new(Config {
            server_addr: "127.0.0.1:443".into(),
            server_name: "localhost".into(),
            auth: "secret".into(),
            insecure: true,
            ..Default::default()
        });
        let server_addr = "127.0.0.1:443".parse().unwrap();

        let err = match connect_addr(cfg, server_addr, "localhost").await {
            Ok(_) => panic!("protector rejection should stop plain HY2 endpoint setup"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("android protect denied"));
        assert_eq!(protector.calls(), 1);
    }
}
