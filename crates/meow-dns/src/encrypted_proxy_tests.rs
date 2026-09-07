//! Loopback-only TLS fixtures. This private test key is not a deployment credential.
use super::*;
use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn,
};
use parking_lot::Mutex;
use tokio::net::TcpListener;

const CERT: &str = "308201973082013ea00302010202146e7b31d2ffc225ed12ab05ee5455641eb49b24dc300a06082a8648ce3d04030230163114301206035504030c0b646e732e6578616d706c653020170d3236303930373033343432395a180f32313236303831343033343432395a30163114301206035504030c0b646e732e6578616d706c653059301306072a8648ce3d020106082a8648ce3d03010703420004e81f600592bcceb0847eeb7c5bd091868324410bc2b00398467b31fa637749c4e027958fb80734ddddd2ddc3cb65347795be9dfe098494d90b8672fb755eb35ea3683066301d0603551d0e04160414af7294a19d7356e959fa02f46e9197788e4ae0be301f0603551d23041830168014af7294a19d7356e959fa02f46e9197788e4ae0be30160603551d11040f300d820b646e732e6578616d706c65300c0603551d130101ff04023000300a06082a8648ce3d0403020347003044022033eb26ea03798a5860cb230dcba671b9faa8049670786d2db9951ef2f3a83b4c02206c96f1eda63c7e3f29373aaf6a14d3447a0751b845409566d7a8f226fbdc52cb";
const KEY: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420f624cde3ed29c53ac1f0053eb11e45efbdada3aae40cadc0e1bea22bacddd7b6a14403420004e81f600592bcceb0847eeb7c5bd091868324410bc2b00398467b31fa637749c4e027958fb80734ddddd2ddc3cb65347795be9dfe098494d90b8672fb755eb35e";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn tls_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let cert = rustls::pki_types::CertificateDer::from(unhex(CERT));
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(unhex(KEY));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(client), Arc::new(server))
}

struct RecordingProxy {
    endpoint: SocketAddr,
    dialed: Arc<Mutex<Vec<SocketAddr>>>,
    fail: bool,
}

#[async_trait]
impl ProxyAdapter for RecordingProxy {
    fn name(&self) -> &str {
        "Korea"
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> meow_common::Result<Box<dyn ProxyConn>> {
        self.dialed
            .lock()
            .push(SocketAddr::new(metadata.dst_ip.unwrap(), metadata.dst_port));
        if self.fail {
            return Err(io::Error::other("test proxy unavailable").into());
        }
        Ok(Box::new(TcpStream::connect(self.endpoint).await?))
    }
    async fn dial_udp(&self, _: &Metadata) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
        panic!("encrypted DNS must not use UDP")
    }
    fn health(&self) -> &ProxyHealth {
        static HEALTH: OnceLock<ProxyHealth> = OnceLock::new();
        HEALTH.get_or_init(ProxyHealth::new)
    }
}
impl Proxy for RecordingProxy {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        vec![]
    }
}

fn encrypted_client(
    https: bool,
    addr: SocketAddr,
    sni: &str,
    tls: Arc<rustls::ClientConfig>,
) -> DnsClient {
    let mut client = if https {
        DnsClient::doh(addr, sni, "/dns-query?token=a%2Bb")
    } else {
        DnsClient::dot(addr, sni)
    };
    match &mut client.transport {
        Transport::Dot { tls: config, .. } | Transport::Doh { tls: config, .. } => *config = tls,
        _ => unreachable!(),
    }
    client.with_timeout(Duration::from_secs(3))
}

async fn encrypted_roundtrip(https: bool, sni: &str, trust_fixture: bool) {
    let (client_tls, server_tls) = tls_configs();
    let client_tls = if trust_fixture {
        client_tls
    } else {
        tls_client_config(if https { "doh" } else { "dot" })
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(server_tls)
            .accept(tcp)
            .await
        else {
            return;
        };
        let wire = if https {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            let head = String::from_utf8(head).unwrap();
            assert!(head.starts_with("POST /dns-query?token=a%2Bb HTTP/1.1\r\n"));
            assert!(head.contains("Host: dns.example\r\n"));
            assert!(head.contains("Content-Type: application/dns-message\r\n"));
            let len: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0; len];
            stream.read_exact(&mut body).await.unwrap();
            body
        } else {
            read_lp(&mut stream).await.unwrap()
        };
        let request = Message::from_bytes(&wire).unwrap();
        let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
        response.add_queries(request.queries);
        let wire = response.to_bytes().unwrap();
        if https {
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", wire.len()).as_bytes()).await.unwrap();
            stream.write_all(&wire).await.unwrap();
        } else {
            write_lp(&mut stream, &wire).await.unwrap();
        }
        stream.shutdown().await.unwrap();
    });
    let dialed = Arc::new(Mutex::new(Vec::new()));
    // This documentation-only destination cannot serve the response directly;
    // the mock proxy alone maps it to our loopback TLS fixture.
    let destination: SocketAddr = if https {
        "192.0.2.1:443"
    } else {
        "192.0.2.1:853"
    }
    .parse()
    .unwrap();
    let client = encrypted_client(https, destination, sni, client_tls).with_proxy(Arc::new(
        RecordingProxy {
            endpoint,
            dialed: Arc::clone(&dialed),
            fail: false,
        },
    ));
    let result = client.query("example.com", RecordType::A).await;
    assert_eq!(*dialed.lock(), vec![destination]);
    if sni == "dns.example" && trust_fixture {
        assert!(result.is_ok(), "{result:?}");
    } else {
        assert!(matches!(result, Err(ClientError::Tls(_))), "{result:?}");
    }
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn encrypted_proxy_preserves_tls_and_https() {
    encrypted_roundtrip(false, "dns.example", true).await;
    encrypted_roundtrip(true, "dns.example", true).await;
}

#[tokio::test]
async fn encrypted_proxy_rejects_wrong_certificate_name() {
    encrypted_roundtrip(false, "wrong.example", true).await;
    encrypted_roundtrip(true, "wrong.example", true).await;
}

#[tokio::test]
async fn encrypted_proxy_rejects_untrusted_certificate() {
    encrypted_roundtrip(false, "dns.example", false).await;
    encrypted_roundtrip(true, "dns.example", false).await;
}

#[tokio::test]
async fn encrypted_proxy_failure_never_falls_back_direct() {
    for https in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let dialed = Arc::new(Mutex::new(Vec::new()));
        let client = encrypted_client(https, endpoint, "dns.example", tls_configs().0).with_proxy(
            Arc::new(RecordingProxy {
                endpoint,
                dialed: Arc::clone(&dialed),
                fail: true,
            }),
        );
        assert!(matches!(
            client.query("example.com", RecordType::A).await,
            Err(ClientError::Io(_))
        ));
        assert_eq!(*dialed.lock(), vec![endpoint]);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn encrypted_proxy_resolver_validates_and_wires_registry() {
    use crate::resolver::{BootstrapError, Resolver};
    use crate::upstream::NameServerEntry;
    use meow_common::DnsMode;
    use meow_trie::DomainTrie;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    for scheme in ["tls", "https"] {
        let entry =
            NameServerEntry::parse(&format!("{scheme}://{endpoint}?proxy=Korea#dns.example"))
                .unwrap();
        for slot in 0..3 {
            let mut lists = [vec![], vec![], vec![]];
            lists[slot].push(entry.clone());
            let [main, fallback, default] = lists;
            let result = Resolver::new_with_bootstrap_with_proxies(
                main,
                fallback,
                default,
                DnsMode::Normal,
                DomainTrie::new(),
                true,
                None,
                None,
                &HashMap::new(),
            )
            .await;
            assert!(matches!(result, Err(BootstrapError::UnknownProxy { .. })));
        }
        let dialed = Arc::new(Mutex::new(Vec::new()));
        let proxy: DnsProxy = Arc::new(RecordingProxy {
            endpoint,
            dialed: Arc::clone(&dialed),
            fail: true,
        });
        let registry = HashMap::from([(smol_str::SmolStr::new("Korea"), proxy)]);
        let resolver = Resolver::new_with_bootstrap_with_proxies(
            vec![entry],
            vec![],
            vec![],
            DnsMode::Normal,
            DomainTrie::new(),
            true,
            None,
            None,
            &registry,
        )
        .await
        .unwrap();
        assert!(resolver.lookup_ipv4("example.com").await.is_none());
        // Address resolution requests A and AAAA in parallel.
        assert_eq!(*dialed.lock(), vec![endpoint, endpoint]);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn explicit_proxy_policy_failure_does_not_query_global_nameservers() {
    use crate::resolver::{NameserverPolicy, PolicyEntry, Resolver};
    use crate::upstream::NameServerEntry;
    use meow_common::DnsMode;
    use meow_trie::DomainTrie;

    let endpoint: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let policy_dials = Arc::new(Mutex::new(Vec::new()));
    let global_dials = Arc::new(Mutex::new(Vec::new()));
    let policy_proxy: DnsProxy = Arc::new(RecordingProxy {
        endpoint,
        dialed: Arc::clone(&policy_dials),
        fail: true,
    });
    let global_proxy: DnsProxy = Arc::new(RecordingProxy {
        endpoint,
        dialed: Arc::clone(&global_dials),
        fail: true,
    });
    let mut policy = NameserverPolicy::new();
    policy.insert_exact(
        "example.com".to_string(),
        PolicyEntry {
            nameservers: vec![Arc::new(
                DnsClient::doh(endpoint, "dns.example", "/dns-query").with_proxy(policy_proxy),
            )],
        },
    );
    let registry = HashMap::from([(smol_str::SmolStr::new("Korea"), global_proxy)]);
    let resolver = Resolver::new_with_bootstrap_with_proxies(
        vec![NameServerEntry::parse("https://127.0.0.1:9?proxy=Korea").unwrap()],
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        Some(policy),
        None,
        &registry,
    )
    .await
    .unwrap();
    assert!(resolver.lookup_ipv4("example.com").await.is_none());
    assert!(resolver
        .forward_generic("example.com", RecordType::TXT)
        .await
        .is_none());
    assert_eq!(policy_dials.lock().len(), 3);
    assert!(
        global_dials.lock().is_empty(),
        "explicit policy failures must not leak to global DNS"
    );
}
