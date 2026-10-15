//! Mux client: bounded pool of mux sessions over one adapter dial path.
//!
//! Mirrors metacubex/sing-mux client.go: each session is a physical proxy
//! connection (dialed to the reserved mux destination); streams are opened
//! on the session with the fewest streams, new sessions are dialed only when
//! the configured connection/stream bounds are reached.

use super::control::ControlTask;
use super::h2mux;
use super::muxcool;
use super::packet::MuxPacketConn;
use super::request::Request;
use super::smux;
use super::stream::MuxStreamConn;
use super::yamux;
use super::{address, Protocol};
use meow_common::atomic::{AtomicU, Uint};
use meow_common::{MeowError, Metadata, ProxyConn, ProxyPacketConn, Result};
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;

/// Idle sessions (zero streams) are closed after this long.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum time spent establishing one physical mux session while the pool
/// lock serializes new connections, matching sing-mux's TCPTimeout.
const SESSION_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Dialer producing one fresh physical connection to the proxy node.  The
/// connection must already carry the protocol handshake (VLESS/Trojan first
/// request) targeting the reserved mux destination.
pub type DialFn =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Box<dyn ProxyConn>>> + Send>> + Send + Sync>;

/// Mux options, defaults aligned with mihomo's documented values.
#[derive(Debug, Clone)]
pub struct MuxOptions {
    pub protocol: Protocol,
    pub padding: bool,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    /// Route UDP through the plain proxy path instead of mux streams
    /// (mihomo SingMuxOption.OnlyTcp).
    pub only_tcp: bool,
    /// 안심 세션 제어 스트림(`mux::control`)을 sing-mux 세션마다 연다. YAML `smux` 블록의
    /// `ansim-session-control: true`. 안심 노드의 strict carrier에만 켠다.
    pub session_control: bool,
}

impl Default for MuxOptions {
    fn default() -> Self {
        // h2mux is mihomo's default protocol (empty `protocol` maps to it).
        Self {
            protocol: Protocol::H2Mux,
            padding: false,
            max_connections: 4,
            min_streams: 4,
            max_streams: 4,
            only_tcp: false,
            session_control: false,
        }
    }
}

/// Monotonic millis since process start (not wall-clock: immune to clock
/// steps, which a `SystemTime`-based clock would let defer idle eviction —
/// see issue #421). On mips32 (no 64-bit atomics) this wraps every ~49.7
/// days; comparisons must stay in the truncated domain via `wrapping_sub`
/// (see [`MuxClient::offer`] below and `UdpSession::idle_for`).
fn now_ms() -> Uint {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_millis() as Uint
}

/// One protocol session multiplexing streams over one physical connection.
#[derive(Clone)]
pub(crate) enum SessionKind {
    Smux(Arc<smux::Session>),
    Yamux(Arc<yamux::Session>),
    H2Mux(Arc<h2mux::Session>),
    MuxCool(Arc<muxcool::MuxCoolSession>),
}

/// Write the sing-mux per-stream request prefix (flags + Socksaddr
/// destination).  Mux.Cool has no prefix — its New frame already carries
/// the destination.
async fn write_request_prefix<S: AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    port: u16,
    udp: bool,
) -> io::Result<()> {
    stream
        .write_all(&address::encode_stream_request_with_flags(
            host,
            port,
            u16::from(udp),
        )?)
        .await?;
    stream.flush().await
}

impl SessionKind {
    /// Open one stream to host:port.  sing-mux sessions write their
    /// per-stream request prefix here; Mux.Cool encodes the destination
    /// into the stream's New frame instead.
    pub(crate) async fn open_stream(
        &self,
        host: &str,
        port: u16,
        udp: bool,
    ) -> io::Result<MuxStream> {
        match self {
            SessionKind::Smux(session) => {
                let mut stream =
                    MuxStream::new(session.open_stream().await.map(MuxStreamKind::Smux)?);
                write_request_prefix(&mut stream, host, port, udp).await?;
                Ok(stream)
            }
            SessionKind::Yamux(session) => {
                let mut stream =
                    MuxStream::new(session.open_stream().await.map(MuxStreamKind::Yamux)?);
                write_request_prefix(&mut stream, host, port, udp).await?;
                Ok(stream)
            }
            SessionKind::H2Mux(session) => {
                let mut stream =
                    MuxStream::new(session.open_stream().await.map(MuxStreamKind::H2Mux)?);
                write_request_prefix(&mut stream, host, port, udp).await?;
                Ok(stream)
            }
            SessionKind::MuxCool(session) => session
                .open_stream(host, port, udp)
                .await
                .map(MuxStreamKind::MuxCool)
                .map(MuxStream::new),
        }
    }

    /// True when the pool must stop offering this session for new streams
    /// (physical connection dead, or - Mux.Cool only - its stream id space
    /// retired). Named `is_unusable`, not `is_dead`: a retired Mux.Cool
    /// session is still fully alive for the streams it already opened, so
    /// "dead" would mislead.
    pub(crate) fn is_unusable(&self) -> bool {
        match self {
            SessionKind::Smux(session) => session.is_dead(),
            SessionKind::Yamux(session) => session.is_dead(),
            SessionKind::H2Mux(session) => session.is_dead(),
            SessionKind::MuxCool(session) => session.unavailable(),
        }
    }
}

/// A stream on either mux protocol, exposed with tokio IO traits.
///
/// Carries the sing-mux per-stream response preamble: the server prefixes
/// its first write on every stream with a status byte (0 = success,
/// 1 = error + varbin message) — mirroring sing-mux's
/// `clientConn.readResponse`.
pub(crate) struct MuxStream {
    kind: MuxStreamKind,
    response_pending: bool,
    /// Sticky: set once the per-stream response status reported a remote
    /// error; subsequent polls repeat the error instead of reading stray
    /// varbin message bytes as data.
    response_failed: bool,
}

pub(crate) enum MuxStreamKind {
    Smux(smux::SmuxStream),
    Yamux(yamux::Stream),
    H2Mux(h2mux::Stream),
    MuxCool(muxcool::Stream),
}

impl MuxStreamKind {
    /// sing-mux prefixes every stream with a response status byte;
    /// Mux.Cool has no per-stream preamble (server Keep frames are data).
    fn requires_response(&self) -> bool {
        !matches!(self, MuxStreamKind::MuxCool(_))
    }
}

impl AsyncRead for MuxStreamKind {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MuxStreamKind::Smux(stream) => Pin::new(stream).poll_read(cx, buf),
            MuxStreamKind::Yamux(stream) => Pin::new(stream).poll_read(cx, buf),
            MuxStreamKind::H2Mux(stream) => Pin::new(stream).poll_read(cx, buf),
            MuxStreamKind::MuxCool(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl MuxStream {
    pub(crate) fn new(kind: MuxStreamKind) -> Self {
        Self {
            response_pending: kind.requires_response(),
            kind,
            response_failed: false,
        }
    }

    /// Consume the per-stream response status byte on first read.
    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.response_failed {
            return Poll::Ready(Err(io::Error::other("mux: remote stream error")));
        }
        if !self.response_pending {
            return Poll::Ready(Ok(()));
        }
        let mut byte = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.kind).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                if read_buf.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "mux: stream closed before response status",
                    )));
                }
                self.response_pending = false;
                if byte[0] == 0x00 {
                    Poll::Ready(Ok(()))
                } else {
                    // Remote error: a varbin message follows, but the stream
                    // is dead either way — surface the failure immediately
                    // and stick to it so the stray message bytes are never
                    // read as data.
                    self.response_failed = true;
                    Poll::Ready(Err(io::Error::other("mux: remote stream error")))
                }
            }
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_response(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.kind).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().kind {
            MuxStreamKind::Smux(stream) => Pin::new(stream).poll_write(cx, buf),
            MuxStreamKind::Yamux(stream) => Pin::new(stream).poll_write(cx, buf),
            MuxStreamKind::H2Mux(stream) => Pin::new(stream).poll_write(cx, buf),
            MuxStreamKind::MuxCool(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().kind {
            MuxStreamKind::Smux(stream) => Pin::new(stream).poll_flush(cx),
            MuxStreamKind::Yamux(stream) => Pin::new(stream).poll_flush(cx),
            MuxStreamKind::H2Mux(stream) => Pin::new(stream).poll_flush(cx),
            MuxStreamKind::MuxCool(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().kind {
            MuxStreamKind::Smux(stream) => Pin::new(stream).poll_shutdown(cx),
            MuxStreamKind::Yamux(stream) => Pin::new(stream).poll_shutdown(cx),
            MuxStreamKind::H2Mux(stream) => Pin::new(stream).poll_shutdown(cx),
            MuxStreamKind::MuxCool(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) struct MuxSession {
    pub(crate) kind: SessionKind,
    /// Unified slot counter: each value represents one stream slot held
    /// by this session — either an in-flight open (reserved by `offer()`
    /// via CAS, released by `Reservation::drop` on failure/cancel) or an
    /// established stream (released by `MuxStreamConn::drop`).
    ///
    /// A single counter eliminates the read-read race that two separate
    /// `streams` + `pending` atomics had: `offer()` can check-and-reserve
    /// with one `compare_exchange`, so the load assessment and the
    /// increment are one atomic step.
    pub(crate) streams: AtomicUsize,
    pub(crate) last_used_ms: AtomicU,
    /// 이 세션의 제어 작업(`session_control`일 때만). 필드라서 `MuxSession`이 버려지면
    /// `ControlTask::drop`이 작업을 끊는다. 작업은 `MuxSession`을 잡지 않는다.
    pub(crate) control: Option<ControlTask>,
}

impl MuxSession {
    /// 풀에서 빠진다. 다른 핸들(packet conn 등)이 아직 이 세션을 잡고 있어도 제어 작업은
    /// 여기서 끝낸다 — 정리된 carrier에 늦게 온 사유를 이 엔진의 인계로 읽지 않는다.
    fn retire(&self) {
        if let Some(control) = &self.control {
            control.retire();
        }
    }

    /// 물리 연결이 끊긴 세션: 이미 도착한 인계 사유를 읽을 시간을 준 뒤 뺀다.
    async fn settle_and_retire(&self) {
        if let Some(control) = &self.control {
            control.settle(CONTROL_SETTLE).await;
        }
        self.retire();
    }
}

/// 끊긴 세션의 제어 스트림이 이미 받은 사유를 처리할 시간 상한.
const CONTROL_SETTLE: Duration = Duration::from_millis(300);

/// Releases a [`MuxSession`] slot when dropped — the cancellation-safe
/// counterpart of the reservation `offer()` made via CAS on `streams`.
struct Reservation(Option<Arc<MuxSession>>);

impl Reservation {
    /// 예약한 슬롯이 성립한 스트림이 됐다. 슬롯은 스트림이 닫힐 때(`MuxStreamConn::drop`)
    /// 돌려준다. 여기서는 세션 참조만 놓는다 — `mem::forget`으로 버리면 그 `Arc`가 새어
    /// 풀에서 빠진 세션(과 물리 carrier)이 영영 닫히지 않는다.
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(session) = self.0.take() {
            session.streams.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Shared mux client used by an adapter's dial path.
pub struct MuxClient {
    dial: DialFn,
    options: MuxOptions,
    sessions: Mutex<VecDeque<Arc<MuxSession>>>,
    /// 이 풀을 만든 엔진 세대(`crate::supersession`). 인계 사유는 이 세대에만 올린다.
    generation: u64,
}

impl MuxClient {
    pub fn new(dial: DialFn, options: MuxOptions) -> Arc<Self> {
        Arc::new(Self {
            dial,
            options,
            sessions: Mutex::new(VecDeque::new()),
            generation: crate::supersession::current_generation(),
        })
    }

    /// Whether UDP should use mux rather than the adapter's plain UDP path.
    pub(crate) fn supports_udp(&self) -> bool {
        !self.options.only_tcp
    }

    fn metadata_host(metadata: &Metadata, adapter: &str) -> Result<String> {
        if !metadata.host.is_empty() {
            Ok(metadata.host.to_string())
        } else if let Some(ip) = metadata.dst_ip {
            Ok(ip.to_string())
        } else {
            Err(MeowError::Proxy(format!(
                "{adapter} mux: metadata has no destination host"
            )))
        }
    }

    /// Shared adapter hook for a muxed TCP dial.
    pub(crate) async fn open_stream_for(
        self: &Arc<Self>,
        metadata: &Metadata,
        adapter: &str,
    ) -> Result<MuxStreamConn> {
        let host = Self::metadata_host(metadata, adapter)?;
        self.open_stream(&host, metadata.dst_port).await
    }

    /// Shared adapter hook for UDP.  `None` means `only-tcp` selected the
    /// adapter's existing plain UDP path.
    pub(crate) async fn open_packet_stream_for(
        self: &Arc<Self>,
        metadata: &Metadata,
        adapter: &str,
    ) -> Result<Option<Box<dyn ProxyPacketConn>>> {
        if !self.supports_udp() {
            return Ok(None);
        }
        let host = Self::metadata_host(metadata, adapter)?;
        self.open_packet_stream(&host, metadata.dst_port)
            .await
            .map(Some)
    }

    /// Open one multiplexed TCP stream to host:port.  sing-mux writes the
    /// stream request (flags + Socksaddr destination) before returning;
    /// Mux.Cool encodes the destination into the stream's New frame.
    pub async fn open_stream(self: &Arc<Self>, host: &str, port: u16) -> Result<MuxStreamConn> {
        let (stream, session) = self.open_stream_flags(host, port, false).await?;
        Ok(MuxStreamConn::new(stream, session))
    }

    /// Open one multiplexed UDP flow to host:port.  sing-mux carries
    /// flagUDP and frames datagrams as `[len u16 BE][data]`; Mux.Cool carries
    /// a per-datagram destination in the frame meta.
    pub async fn open_packet_stream(
        self: &Arc<Self>,
        host: &str,
        port: u16,
    ) -> Result<Box<dyn ProxyPacketConn>> {
        let (stream, session) = self.open_stream_flags(host, port, true).await?;
        // The conn is bound to the stream request's destination; reads
        // report it as the datagram source.  Non-IP hosts (domains) get a
        // placeholder — same convention as the plain VLESS UDP path.
        let destination = host.parse::<std::net::IpAddr>().ok().map_or_else(
            || "0.0.0.0:0".parse().expect("static placeholder"),
            |ip| SocketAddr::new(ip, port),
        );
        match stream.kind {
            MuxStreamKind::MuxCool(stream) => {
                let muxcool::Stream { parts, .. } = stream;
                Ok(Box::new(muxcool::PacketConn::new(
                    parts,
                    session,
                    destination,
                )))
            }
            kind => Ok(Box::new(MuxPacketConn::new(
                MuxStream::new(kind),
                session,
                destination,
            ))),
        }
    }

    /// Open a stream (writing its per-stream request: sing-mux prefix or
    /// Mux.Cool New frame), retrying once on a dead session — the shared
    /// core of the TCP and UDP open paths.
    async fn open_stream_flags(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        udp: bool,
    ) -> Result<(MuxStream, Arc<MuxSession>)> {
        let mut last_err = None;
        for _ in 0..2 {
            let session = match self.offer().await {
                Ok(session) => session,
                Err(e) => return Err(e),
            };
            // offer() reserved one slot on `streams` via CAS.  The
            // guard releases it if the open future is cancelled or the
            // session rejects the stream.
            let reservation = Reservation(Some(Arc::clone(&session)));
            match session.kind.open_stream(host, port, udp).await {
                Ok(stream) => {
                    // The slot reserved by offer() is now an established
                    // stream.  Keep the slot (no decrement here) —
                    // MuxStreamConn::drop will do that when the stream is
                    // eventually closed.
                    reservation.keep();
                    // Idle eviction is measured from the last successful open
                    // (not the last activity): conservative — a long-lived
                    // stream keeps its session alive via the streams count,
                    // and zero-stream sessions idle past IDLE_TIMEOUT are
                    // evicted on the next offer.
                    session.last_used_ms.store(now_ms(), Ordering::SeqCst);
                    return Ok((stream, session));
                }
                Err(e) => {
                    // reservation drops here → slot released
                    last_err = Some(MeowError::Io(e));
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or(MeowError::Proxy("mux: failed to open stream".into())))
    }

    /// Pick an existing session that can take a new request, or dial a new
    /// one.  Unusable sessions are pruned (`is_unusable`: dead transports,
    /// but also retired-yet-alive Mux.Cool sessions that must not take new
    /// streams) and zero-stream sessions idle past `IDLE_TIMEOUT` are
    /// evicted.  The returned session has one slot
    /// reserved for the caller via a CAS on `streams` — the check and the
    /// increment are a single atomic step, so concurrent offers can never
    /// overshoot max-streams.
    async fn offer(self: &Arc<Self>) -> Result<Arc<MuxSession>> {
        // 같은 기기의 새 연결이 이 엔진의 carrier를 이어받았다. 새 세션·스트림을 열면 그
        // 연결을 도로 밀어내므로 엔진이 멈출 때까지 아무것도 열지 않는다(새 dial 금지).
        // 안심 strict carrier(`session_control`)에만 적용한다 — 그 밖의 mux 풀 동작은 그대로다.
        if self.options.session_control && crate::supersession::superseded_in(self.generation) {
            return Err(MeowError::Proxy(
                "mux: carrier superseded by the same device elsewhere".into(),
            ));
        }
        let mut sessions = self.sessions.lock().await;
        let now = now_ms();
        let mut dead = Vec::new();
        sessions.retain(|s| {
            if s.kind.is_unusable() {
                // 끊긴 carrier는 사유를 읽힌 뒤 뺀다(아래). 노드가 사유를 쓰고 닫은 직후에
                // 이 요청이 오면, 사유보다 먼저 새 carrier를 열어 도로 이어받으면 안 된다.
                dead.push(Arc::clone(s));
                return false;
            }
            // Truncated-domain comparison (never widen to u64 first): on
            // mips32 `Uint` is u32 and wraps every ~49.7 days, so a plain
            // subtraction must use `wrapping_sub`, matching
            // `UdpSession::idle_for`.
            let idle = now.wrapping_sub(s.last_used_ms.load(Ordering::SeqCst));
            let keep =
                s.streams.load(Ordering::SeqCst) > 0 || idle < IDLE_TIMEOUT.as_millis() as Uint;
            if !keep {
                s.retire();
            }
            keep
        });
        for session in dead {
            session.settle_and_retire().await;
        }
        // 잠금을 기다리는 사이나 위 정리 중에 인계 사유가 처리됐을 수 있다.
        if self.options.session_control && crate::supersession::superseded_in(self.generation) {
            return Err(MeowError::Proxy(
                "mux: carrier superseded by the same device elsewhere".into(),
            ));
        }
        let options = &self.options;
        let best = sessions
            .iter()
            .min_by_key(|s| s.streams.load(Ordering::SeqCst));
        if let Some(session) = best {
            // CAS loop: atomically check the current load and reserve a
            // slot.  If another thread modifies `streams` between our
            // load and the CAS, we retry with the updated value.  This
            // eliminates the read-read race that separate `streams` +
            // `pending` atomics had — the assessment and the increment
            // are now one atomic step.
            loop {
                let load = session.streams.load(Ordering::SeqCst);
                let reuse = if load == 0 {
                    // An idle session always takes the next stream — never
                    // dial a fresh connection while one is free.
                    true
                } else if options.max_connections > 0 {
                    sessions.len() >= options.max_connections || load < options.min_streams
                } else {
                    // max-connections=0: honor min-streams first (sing-mux
                    // checks minStreams before maxStreams in this branch),
                    // then fall back to max-streams.  max-streams=0 with
                    // min-streams=0 keeps the mihomo semantics: one physical
                    // connection per stream.
                    load < options.min_streams
                        || (options.max_streams > 0 && load < options.max_streams)
                };
                if !reuse {
                    break;
                }
                match session.streams.compare_exchange(
                    load,
                    load + 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => return Ok(Arc::clone(session)),
                    Err(_) => continue,
                }
            }
        }
        // Bounds reached: dial a fresh session while still holding the
        // sessions lock so concurrent offers serialize behind this dial and
        // cannot overshoot max-connections (sing-mux holds its mutex across
        // offerNew the same way).
        self.offer_new_locked(&mut sessions).await
    }

    /// Dial a fresh physical connection and start a new session.  sing-mux
    /// sessions write the mux request header on top; Mux.Cool needs none —
    /// the dialer's VLESS CommandMux request already marks the connection.
    /// Callers must hold the sessions lock.
    async fn offer_new_locked(
        self: &Arc<Self>,
        sessions: &mut VecDeque<Arc<MuxSession>>,
    ) -> Result<Arc<MuxSession>> {
        let kind = tokio::time::timeout(SESSION_SETUP_TIMEOUT, self.create_session())
            .await
            .map_err(|_| {
                MeowError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mux: session setup timed out",
                ))
            })??;
        // 제어 스트림은 `streams` 슬롯에 넣지 않는다 — 유휴 정리·용량 판단을 바꾸면 안 된다.
        let control = if self.options.session_control {
            ControlTask::spawn(&kind, self.generation)
        } else {
            None
        };
        let session = Arc::new(MuxSession {
            kind,
            // Start at 1: the caller's reservation.  The pool lock is
            // held, so no concurrent offer can see this session before
            // the slot is reserved.
            streams: AtomicUsize::new(1),
            last_used_ms: AtomicU::new(now_ms()),
            control,
        });
        sessions.push_back(Arc::clone(&session));
        Ok(session)
    }

    async fn create_session(&self) -> Result<SessionKind> {
        let mut conn = (self.dial)().await?;
        match self.options.protocol {
            Protocol::Smux | Protocol::Yamux | Protocol::H2Mux => {
                let header = Request::new(
                    if self.options.padding { 1 } else { 0 },
                    self.options.protocol as u8,
                    self.options.padding,
                )
                .encode();
                conn.write_all(&header).await.map_err(MeowError::Io)?;
                conn.flush().await.map_err(MeowError::Io)?;
                Ok(match self.options.protocol {
                    Protocol::Smux => SessionKind::Smux(Arc::new(
                        smux::Session::client(conn).map_err(MeowError::Io)?,
                    )),
                    Protocol::Yamux => SessionKind::Yamux(Arc::new(
                        yamux::Session::client(conn).map_err(MeowError::Io)?,
                    )),
                    Protocol::H2Mux => SessionKind::H2Mux(Arc::new(
                        h2mux::Session::client(conn).await.map_err(MeowError::Io)?,
                    )),
                    Protocol::MuxCool => unreachable!("handled above"),
                })
            }
            Protocol::MuxCool => Ok(SessionKind::MuxCool(
                muxcool::MuxCoolSession::client(conn)
                    .await
                    .map_err(MeowError::Io)?,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::task::Poll;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

    /// Minimal AsyncRead+AsyncWrite+ProxyConn newtype over a duplex half.
    struct TestConn(tokio::io::DuplexStream);

    impl ProxyConn for TestConn {}

    impl AsyncRead for TestConn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestConn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    /// Mock dialer: each dial yields a duplex half whose far end swallows
    /// bytes (a minimal mux data sink).
    async fn mock_mux_client(dials: Arc<AtomicUsize>) -> Arc<MuxClient> {
        // The mock sink speaks smux frames — pin the protocol explicitly.
        mock_mux_client_with(
            dials,
            MuxOptions {
                protocol: Protocol::Smux,
                ..MuxOptions::default()
            },
        )
        .await
    }

    async fn mock_mux_client_with(dials: Arc<AtomicUsize>, options: MuxOptions) -> Arc<MuxClient> {
        let dial: DialFn = Arc::new(move || {
            let dials = Arc::clone(&dials);
            Box::pin(async move {
                dials.fetch_add(1, Ordering::SeqCst);
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    // Drain frames without parsing: the previous version read a
                    // 10-byte header and extracted a u32 BE "length" from bytes
                    // 2–5, but smux frames are 8 bytes (u16 LE length at 2–3)
                    // and yamux frames are 12 bytes.  On a misaligned read the
                    // u32 can be enormous (e.g. 0x01000000 = 16 MiB when the
                    // smux version byte 0x01 lands at header[2]), causing a
                    // huge heap allocation that crashes the Windows runner.
                    // A fixed-size read-and-discard loop is all a data sink
                    // needs.
                    let mut io = server_io;
                    let mut buf = [0u8; 4096];
                    loop {
                        match io.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
                Ok(Box::new(TestConn(client_io)) as Box<dyn ProxyConn>)
            })
        });
        MuxClient::new(dial, options)
    }

    #[tokio::test]
    async fn streams_pack_into_one_connection_until_bounds() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = mock_mux_client(Arc::clone(&dials)).await;
        // Default bounds: max-connections=4, min/max-streams=4 — streams
        // accumulate on the first connection until it reaches max_streams.
        let mut streams = Vec::new();
        for _ in 0..4 {
            streams.push(client.open_stream("a.example", 80).await.unwrap());
        }
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        // Fifth stream exceeds max_streams → second connection.
        streams.push(client.open_stream("a.example", 80).await.unwrap());
        assert_eq!(dials.load(Ordering::SeqCst), 2);
    }

    /// max-connections=0 with max-streams=0 and min-streams=0 keeps the
    /// mihomo semantics: every stream dials its own physical connection.
    #[tokio::test]
    async fn zero_bounds_dial_one_connection_per_stream() {
        let dials = Arc::new(AtomicUsize::new(0));
        let options = MuxOptions {
            protocol: Protocol::Smux,
            max_connections: 0,
            min_streams: 0,
            max_streams: 0,
            ..MuxOptions::default()
        };
        let client = mock_mux_client_with(Arc::clone(&dials), options).await;
        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(client.open_stream("a.example", 80).await.unwrap());
        }
        assert_eq!(
            dials.load(Ordering::SeqCst),
            3,
            "max-connections=0 + max-streams=0 must dial one connection per stream"
        );
        drop(streams);
    }

    /// Concurrent opens reserve their slots under the pool lock, so the
    /// per-session stream cap is never overshot by racing offers.
    #[tokio::test]
    async fn concurrent_opens_respect_max_streams() {
        let dials = Arc::new(AtomicUsize::new(0));
        let options = MuxOptions {
            protocol: Protocol::Smux,
            max_connections: 0,
            min_streams: 4,
            max_streams: 4,
            ..MuxOptions::default()
        };
        let client = mock_mux_client_with(Arc::clone(&dials), options).await;
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    client
                        .open_stream(format!("h{i}.example").as_str(), 80)
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut streams = Vec::new();
        for handle in handles {
            streams.push(handle.await.unwrap());
        }
        let sessions = client.sessions.lock().await;
        assert_eq!(
            sessions.len(),
            2,
            "8 concurrent streams at max-streams=4 need 2 sessions"
        );
        for session in sessions.iter() {
            assert_eq!(session.streams.load(Ordering::SeqCst), 4);
        }
        drop(streams);
    }

    /// Stress test for the max-streams overshoot race: with max-streams=1
    /// every session must end with at most one stream slot.  The original
    /// design used separate `streams` + `pending` atomics whose sum was
    /// read with two independent loads — a concurrent open could transition
    /// between them and make the load appear falsely 0.  The unified
    /// `streams` counter with CAS-based reservation makes the check-and-
    /// increment one atomic step, so the overshoot is structurally
    /// impossible.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn stress_concurrent_opens_never_overshoot_max_streams_one() {
        for round in 0..200 {
            let dials = Arc::new(AtomicUsize::new(0));
            let options = MuxOptions {
                protocol: Protocol::Smux,
                max_connections: 0,
                min_streams: 1,
                max_streams: 1,
                ..MuxOptions::default()
            };
            let client = mock_mux_client_with(Arc::clone(&dials), options).await;
            let handles: Vec<_> = (0..16)
                .map(|i| {
                    let client = Arc::clone(&client);
                    tokio::spawn(async move {
                        client
                            .open_stream(format!("h{i}.example").as_str(), 80)
                            .await
                            .unwrap()
                    })
                })
                .collect();
            let mut streams = Vec::new();
            for handle in handles {
                streams.push(handle.await.unwrap());
            }
            let sessions = client.sessions.lock().await;
            for session in sessions.iter() {
                let streams = session.streams.load(Ordering::SeqCst);
                assert!(
                    streams <= 1,
                    "round {round}: session overshot max-streams=1 with {streams} streams"
                );
            }
            drop(streams);
        }
    }

    #[tokio::test]
    async fn yamux_protocol_pools_streams() {
        let dials = Arc::new(AtomicUsize::new(0));
        let options = MuxOptions {
            protocol: Protocol::Yamux,
            ..MuxOptions::default()
        };
        let client = mock_mux_client_with(Arc::clone(&dials), options).await;
        let _s1 = client.open_stream("a.example", 80).await.unwrap();
        let _s2 = client.open_stream("b.example", 80).await.unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn idle_sessions_are_evicted() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = mock_mux_client(Arc::clone(&dials)).await;
        let s = client.open_stream("a.example", 80).await.unwrap();
        drop(s);
        // The zero-stream session stays reusable within IDLE_TIMEOUT.
        let _s2 = client.open_stream("b.example", 81).await.unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), 1);
    }

    /// Regression test for issue #421: `offer()`'s idle check must compare
    /// `last_used_ms` in the truncated `Uint` domain with `wrapping_sub`,
    /// never widen to `u64` first. `last_used_ms` can end up numerically
    /// *ahead* of a freshly-read `now_ms()` two ways: a `Uint = u32`
    /// millisecond clock rolling over on a 32-bit-atomic target (mips32),
    /// or a monotonic clock read racing itself. A `saturating_sub`-based
    /// comparison computes `now.saturating_sub(last) == 0` in that case and
    /// treats the session as freshly used forever, so it can never be
    /// evicted. `wrapping_sub` recovers the true elapsed distance
    /// regardless of which side is numerically larger, so a session whose
    /// stamp reads far in the "future" is still pruned as idle.
    #[tokio::test]
    async fn idle_sessions_are_evicted_across_a_wrapped_clock_reading() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = mock_mux_client(Arc::clone(&dials)).await;
        let s = client.open_stream("a.example", 80).await.unwrap();
        drop(s);
        assert_eq!(dials.load(Ordering::SeqCst), 1);

        // Force the session's last-used stamp to read as if the millisecond
        // clock had wrapped past `now`, simulating the mips32 `AtomicU32`
        // rollover this fix targets.
        {
            let sessions = client.sessions.lock().await;
            assert_eq!(sessions.len(), 1);
            let wrapped = now_ms().wrapping_add(IDLE_TIMEOUT.as_millis() as Uint * 10);
            sessions[0].last_used_ms.store(wrapped, Ordering::SeqCst);
        }

        // offer() runs its retain() pass on the next open: the wrapped
        // session must still be recognized as idle-past-timeout and pruned,
        // forcing a second dial.
        let _s2 = client.open_stream("b.example", 81).await.unwrap();
        assert_eq!(
            dials.load(Ordering::SeqCst),
            2,
            "a session whose last-used stamp reads ahead of `now` (wrapped clock) \
             must still be evicted as idle, not kept alive forever"
        );
    }

    #[tokio::test]
    async fn write_error_on_dead_session_falls_back_to_new_dial() {
        let dials = Arc::new(AtomicUsize::new(0));
        let client = mock_mux_client(Arc::clone(&dials)).await;
        let mut s = client.open_stream("a.example", 80).await.unwrap();
        // Kill the underlying session by shutting the far side: drop the
        // server task happens implicitly — instead, just verify a second
        // stream still works after the first session dies.
        s.shutdown().await.ok();
        let _s2 = client.open_stream("b.example", 81).await.unwrap();
        assert!(dials.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn concurrent_opens_do_not_overshoot_max_connections() {
        let dials = Arc::new(AtomicUsize::new(0));
        let options = MuxOptions {
            protocol: Protocol::Smux,
            max_connections: 2,
            min_streams: 1,
            max_streams: 1,
            ..MuxOptions::default()
        };
        let client = mock_mux_client_with(Arc::clone(&dials), options).await;
        // Every stream saturates its session, so a racy pool would dial
        // once per open; holding the lock across the dial must serialize
        // them onto at most `max_connections` physical connections.
        let opens = (0..8)
            .map(|i| {
                let client = Arc::clone(&client);
                async move { (i, client.open_stream("a.example", 80).await.unwrap()) }
            })
            .collect::<Vec<_>>();
        let streams = futures::future::join_all(opens).await;
        assert_eq!(streams.len(), 8);
        assert_eq!(dials.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn session_setup_timeout_bounds_a_stalled_dial() {
        let dial: DialFn =
            Arc::new(|| Box::pin(std::future::pending::<Result<Box<dyn ProxyConn>>>()));
        let client = MuxClient::new(
            dial,
            MuxOptions {
                protocol: Protocol::Smux,
                ..MuxOptions::default()
            },
        );

        let Err(error) = client.open_stream("a.example", 80).await else {
            panic!("a stalled dial must time out");
        };
        assert!(
            error.to_string().contains("session setup timed out"),
            "unexpected error: {error}"
        );
    }

    // ─── 안심 세션 제어 스트림 ────────────────────────────────────────────────

    /// 안심 노드를 흉내 내는 smux 서버(sagernet v1 프레임). 제어 목적지로 열린 스트림을
    /// 알아보고, 시험이 넘긴 바이트를 그 스트림에 쓴다. 물리 연결이 닫히면 `closed`를 세운다.
    struct FakeCarrier {
        control: tokio::sync::watch::Receiver<Option<u32>>,
        syns: Arc<AtomicUsize>,
        out: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        closed: tokio::sync::watch::Receiver<bool>,
    }

    const SMUX_FIN: u8 = 1;
    const SMUX_PSH: u8 = 2;

    fn smux_frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![1, cmd];
        frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
        frame.extend_from_slice(&sid.to_le_bytes());
        frame.extend_from_slice(data);
        frame
    }

    impl FakeCarrier {
        fn spawn(server_io: tokio::io::DuplexStream) -> Self {
            let (mut reader, mut writer) = tokio::io::split(server_io);
            let (control_tx, control) = tokio::sync::watch::channel(None);
            let (closed_tx, closed) = tokio::sync::watch::channel(false);
            let (out, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            let syns = Arc::new(AtomicUsize::new(0));
            let reader_syns = Arc::clone(&syns);
            tokio::spawn(async move {
                // sing-mux 요청 헤더(version 0, protocol): padding 없음 → 2바이트.
                let mut request = [0u8; 2];
                if reader.read_exact(&mut request).await.is_ok() {
                    let mut header = [0u8; 8];
                    while reader.read_exact(&mut header).await.is_ok() {
                        let len = u16::from_le_bytes([header[2], header[3]]) as usize;
                        let sid = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
                        let mut payload = vec![0u8; len];
                        if reader.read_exact(&mut payload).await.is_err() {
                            break;
                        }
                        match header[1] {
                            0 => {
                                reader_syns.fetch_add(1, Ordering::SeqCst);
                            }
                            SMUX_PSH => {
                                let host = super::super::control::SESSION_CONTROL_HOST.as_bytes();
                                if payload.windows(host.len()).any(|w| w == host) {
                                    let _ = control_tx.send(Some(sid));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                let _ = closed_tx.send(true);
            });
            tokio::spawn(async move {
                while let Some(bytes) = out_rx.recv().await {
                    // 빈 묶음은 "노드가 부모 carrier를 닫는다"는 뜻이다(앞서 보낸 프레임 뒤에).
                    if bytes.is_empty() {
                        let _ = writer.shutdown().await;
                        return;
                    }
                    if writer.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
            });
            Self {
                control,
                syns,
                out,
                closed,
            }
        }

        async fn control_stream(&self) -> u32 {
            let mut control = self.control.clone();
            let sid = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                control.wait_for(Option::is_some),
            )
            .await
            .expect("the client must open the session control stream")
            .unwrap();
            sid.expect("checked")
        }

        /// 제어 스트림에 노드가 쓰는 바이트(맨 앞은 sing-mux per-stream status).
        fn send(&self, sid: u32, data: &[u8]) {
            let _ = self.out.send(smux_frame(SMUX_PSH, sid, data));
        }

        /// 노드가 부모 carrier를 닫는다(앞서 보낸 사유 프레임 뒤에).
        fn close_parent(&self) {
            let _ = self.out.send(Vec::new());
        }

        fn fin(&self, sid: u32) {
            let _ = self.out.send(smux_frame(SMUX_FIN, sid, &[]));
        }

        async fn wait_closed(&self) -> bool {
            let mut closed = self.closed.clone();
            let result =
                tokio::time::timeout(std::time::Duration::from_secs(2), closed.wait_for(|c| *c))
                    .await;
            result.is_ok()
        }
    }

    type Carriers = Arc<std::sync::Mutex<Vec<Arc<FakeCarrier>>>>;

    fn ansim_options() -> MuxOptions {
        // ansim-config가 strict 계정에 넣는 값과 같다.
        MuxOptions {
            protocol: Protocol::Smux,
            max_connections: 1,
            min_streams: 0,
            max_streams: 0,
            session_control: true,
            ..MuxOptions::default()
        }
    }

    fn fake_node_client(options: MuxOptions) -> (Arc<MuxClient>, Arc<AtomicUsize>, Carriers) {
        let dials = Arc::new(AtomicUsize::new(0));
        let carriers: Carriers = Arc::default();
        let dial_count = Arc::clone(&dials);
        let dial_carriers = Arc::clone(&carriers);
        let dial: DialFn = Arc::new(move || {
            let dials = Arc::clone(&dial_count);
            let carriers = Arc::clone(&dial_carriers);
            Box::pin(async move {
                dials.fetch_add(1, Ordering::SeqCst);
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                carriers
                    .lock()
                    .unwrap()
                    .push(Arc::new(FakeCarrier::spawn(server_io)));
                Ok(Box::new(TestConn(client_io)) as Box<dyn ProxyConn>)
            })
        });
        (MuxClient::new(dial, options), dials, carriers)
    }

    fn carrier(carriers: &Carriers, index: usize) -> Arc<FakeCarrier> {
        Arc::clone(&carriers.lock().unwrap()[index])
    }

    /// 풀에 남은 첫 세션의 제어 작업이 끝날 때까지 기다린다(사유 처리 완료).
    async fn wait_control_finished(client: &Arc<MuxClient>) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                {
                    let sessions = client.sessions.lock().await;
                    let control = sessions[0].control.as_ref().expect("session control on");
                    if control.is_finished() {
                        return;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the control task must finish after the node closes its stream");
    }

    async fn wait_superseded() -> bool {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !crate::supersession::session_superseded() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok()
    }

    /// (a)+(e) 현재 세션의 제어 스트림에 `superseded\n`이 오면 엔진 표지가 서고, 그 뒤의
    /// open은 dial 없이(기존 세션도 쓰지 않고) 실패한다. 제어 스트림은 슬롯에 들지 않는다.
    #[tokio::test]
    async fn superseded_reason_marks_engine_and_blocks_new_opens() {
        let _serial = crate::supersession::TEST_LOCK.lock().await;
        crate::supersession::clear_session_superseded();
        let (client, dials, carriers) = fake_node_client(ansim_options());

        let user = client.open_stream("a.example", 80).await.unwrap();
        let node = carrier(&carriers, 0);
        let sid = node.control_stream().await;
        assert_eq!(
            client.sessions.lock().await[0]
                .streams
                .load(Ordering::SeqCst),
            1,
            "the control stream must not take a pool slot"
        );

        node.send(sid, b"\x00superseded\n");
        assert!(
            wait_superseded().await,
            "superseded\\n must mark the engine"
        );

        let Err(error) = client.open_stream("b.example", 80).await else {
            panic!("a superseded engine must not open new streams");
        };
        assert!(error.to_string().contains("superseded"), "{error}");
        assert!(client.open_packet_stream("1.1.1.1", 53).await.is_err());
        assert_eq!(
            dials.load(Ordering::SeqCst),
            1,
            "no redial after a takeover"
        );
        drop(user);
        crate::supersession::clear_session_superseded();
    }

    /// 풀의 첫 세션이 끊긴 것으로 보일 때까지 기다린다(사유 처리는 기다리지 않는다).
    async fn wait_unusable(client: &Arc<MuxClient>) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if client.sessions.lock().await[0].kind.is_unusable() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the parent close must make the session unusable");
    }

    /// Codex 반례(msg_866ca1875860): 노드가 사유를 쓰고 부모를 닫은 직후, 제어 작업이 그
    /// 사유를 읽기 **전에** 다른 데이터 요청이 온다. 끊긴 세션을 정리하며 제어 작업을 끊고
    /// 새 carrier를 열면 이미 도착한 인계를 버리고 도로 이어받는다. 정리 전에 사유를 읽을
    /// 시간을 주므로 새 dial 없이 실패해야 한다. 표지를 기다린 뒤 요청하지 않는다.
    #[tokio::test]
    async fn a_queued_reason_is_not_dropped_by_a_concurrent_open() {
        let _serial = crate::supersession::TEST_LOCK.lock().await;
        crate::supersession::clear_session_superseded();
        let gate = super::super::control::test_gate::arm();
        let (client, dials, carriers) = fake_node_client(ansim_options());
        let user = client.open_stream("a.example", 80).await.unwrap();
        let node = carrier(&carriers, 0);
        let sid = node.control_stream().await;
        node.send(sid, b"\x00superseded\n");
        node.close_parent();
        wait_unusable(&client).await;
        assert!(
            !crate::supersession::session_superseded(),
            "gate must hold the reason"
        );
        let opener = Arc::clone(&client);
        let open = tokio::spawn(async move { opener.open_stream("b.example", 80).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        gate.add_permits(1);
        let result = open.await.unwrap();
        super::super::control::test_gate::disarm();
        assert!(
            result.is_err(),
            "a delivered takeover must not be reclaimed"
        );
        assert!(crate::supersession::session_superseded());
        assert_eq!(
            dials.load(Ordering::SeqCst),
            1,
            "no new carrier after a takeover"
        );
        drop(user);
        crate::supersession::clear_session_superseded();
    }

    /// 사유 없는 일반 끊김(EOF)은 지금처럼 곧바로 새 carrier로 다시 연결한다.
    #[tokio::test]
    async fn a_plain_parent_close_still_reconnects() {
        let _serial = crate::supersession::TEST_LOCK.lock().await;
        crate::supersession::clear_session_superseded();
        let (client, dials, carriers) = fake_node_client(ansim_options());
        let user = client.open_stream("a.example", 80).await.unwrap();
        let node = carrier(&carriers, 0);
        node.control_stream().await;
        node.close_parent();
        wait_unusable(&client).await;
        let started = std::time::Instant::now();
        let again = client.open_stream("b.example", 80).await;
        assert!(again.is_ok(), "an ordinary close must reconnect");
        assert!(
            started.elapsed() < CONTROL_SETTLE,
            "plain EOF must not wait for the settle bound"
        );
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        assert!(!crate::supersession::session_superseded());
        drop(user);
        drop(again);
    }

    /// Codex 반례(msg_2596a2116835): 제어 작업이 "아직 풀에 묶여 있다"를 확인한 뒤 멈춘
    /// 사이 세션이 풀에서 빠지면(retire), 늦은 표지가 그 뒤의 새 carrier를 끊는다. 빼기와
    /// 표지 세우기를 한 잠금으로 묶었으므로 retire는 표지 기록이 끝날 때까지 기다리고, 그 뒤
    /// 풀은 새 carrier를 열지 않는다.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retire_cannot_slip_between_the_check_and_the_mark() {
        let _serial = crate::supersession::TEST_LOCK.lock().await;
        crate::supersession::clear_session_superseded();
        let (client, dials, carriers) = fake_node_client(ansim_options());
        let user = client.open_stream("a.example", 80).await.unwrap();
        let session = Arc::clone(&client.sessions.lock().await[0]);
        let node = carrier(&carriers, 0);
        let sid = node.control_stream().await;
        let (paused_tx, paused_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
        let resume_rx = std::sync::Mutex::new(resume_rx);
        crate::supersession::test_hook::set(Some(Box::new(move |_| {
            let _ = paused_tx.send(());
            let _ = resume_rx
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5));
        })));
        node.send(sid, b"\x00superseded\n");
        tokio::task::spawn_blocking(move || {
            paused_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        })
        .await
        .unwrap();
        let retiring = tokio::task::spawn_blocking(move || session.retire());
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !retiring.is_finished(),
            "retire slipped between the bound check and the mark"
        );
        resume_tx.send(()).unwrap();
        retiring.await.unwrap();
        assert!(crate::supersession::session_superseded());
        assert!(client.open_stream("b.example", 80).await.is_err());
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        drop(user);
        crate::supersession::clear_session_superseded();
    }

    /// (b) 다른 내용·오류 status(옛 노드)·EOF·개행 없는 사유는 표지를 세우지 않는다.
    #[tokio::test]
    async fn other_control_outcomes_do_not_mark_the_engine() {
        let _serial = crate::supersession::TEST_LOCK.lock().await;
        crate::supersession::clear_session_superseded();
        let cases: [(&str, &[u8], bool); 5] = [
            ("unknown reason", b"\x00expired\n", false),
            (
                "superseded with trailing text",
                b"\x00superseded now\n",
                false,
            ),
            ("no newline before EOF", b"\x00superseded", true),
            // 옛 노드(ansim.6): 목적지 라우팅 실패 → status 1 + varbin 메시지.
            ("remote error status", b"\x01\x0esuperseded\nxxx", true),
            ("bare EOF", b"", true),
        ];
        for (name, bytes, fin) in cases {
            let (client, _dials, carriers) = fake_node_client(ansim_options());
            let _user = client.open_stream("a.example", 80).await.unwrap();
            let node = carrier(&carriers, 0);
            let sid = node.control_stream().await;
            if !bytes.is_empty() {
                node.send(sid, bytes);
            }
            if fin {
                node.fin(sid);
            }
            wait_control_finished(&client).await;
            assert!(!crate::supersession::session_superseded(), "{name}");
            assert!(client.open_stream("b.example", 80).await.is_ok(), "{name}");
        }
    }

    /// (c) 엔진이 다시 시작된 뒤(세대 변경) 이전 세션에 온 사유는 무시한다.
    #[tokio::test]
    async fn reason_from_a_previous_engine_generation_is_ignored() {
        let _serial = crate::supersession::TEST_LOCK.lock().await;
        crate::supersession::clear_session_superseded();
        let old_generation = crate::supersession::current_generation();
        let (client, _dials, carriers) = fake_node_client(ansim_options());
        let _user = client.open_stream("a.example", 80).await.unwrap();
        let node = carrier(&carriers, 0);
        let sid = node.control_stream().await;

        crate::supersession::clear_session_superseded();
        node.send(sid, b"\x00superseded\n");
        wait_control_finished(&client).await;
        assert!(!crate::supersession::session_superseded());
        assert!(!crate::supersession::superseded_in(old_generation));
        let (fresh, _fresh_dials, _fresh_carriers) = fake_node_client(ansim_options());
        assert!(fresh.open_stream("a.example", 80).await.is_ok());
    }

    /// (d) 유휴 축출된 세션: 제어 작업이 끊겨 물리 연결이 닫히고, 그 carrier에 늦게 온
    /// 사유는 무시된다. 제어 스트림은 `Arc<smux::Session>`을 잡으므로 끊지 않으면 옛
    /// carrier가 노드에 살아 남아 새 carrier가 그것을 revoke한다(자기 자신을 인계로 오인).
    #[tokio::test]
    async fn evicted_session_closes_its_carrier_and_ignores_a_late_reason() {
        let _serial = crate::supersession::TEST_LOCK.lock().await;
        crate::supersession::clear_session_superseded();
        let (client, dials, carriers) = fake_node_client(ansim_options());
        let user = client.open_stream("a.example", 80).await.unwrap();
        let old = carrier(&carriers, 0);
        let old_sid = old.control_stream().await;
        drop(user);
        {
            let sessions = client.sessions.lock().await;
            let stale = now_ms().wrapping_sub(IDLE_TIMEOUT.as_millis() as Uint * 2);
            sessions[0].last_used_ms.store(stale, Ordering::SeqCst);
        }

        // 다음 open이 옛 세션을 축출하고 새 carrier를 연다. 제어 스트림이 유휴 판단을 막지 않는다.
        let _user = client.open_stream("b.example", 80).await.unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        carrier(&carriers, 1).control_stream().await;

        // 노드가 새 carrier를 보고 옛 carrier를 revoke한다.
        old.send(old_sid, b"\x00superseded\n");
        assert!(
            old.wait_closed().await,
            "an evicted session must release its physical carrier"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !crate::supersession::session_superseded(),
            "a reason on our own evicted carrier is not a takeover"
        );
    }

    /// (d') 풀 자체가 버려지면(엔진 정지) 사유가 오기 전에 carrier가 닫힌다.
    #[tokio::test]
    async fn dropping_the_pool_closes_carriers_and_ignores_a_late_reason() {
        let _serial = crate::supersession::TEST_LOCK.lock().await;
        crate::supersession::clear_session_superseded();
        let (client, _dials, carriers) = fake_node_client(ansim_options());
        drop(client.open_stream("a.example", 80).await.unwrap());
        let node = carrier(&carriers, 0);
        let sid = node.control_stream().await;
        drop(client);
        // 사유가 오기 전에 닫혀야 한다: 열린 제어 스트림이 `Arc<smux::Session>`을 잡고 있어도
        // 세션이 버려지면 그 참조를 놓는다.
        assert!(
            node.wait_closed().await,
            "a dropped pool must close its carriers"
        );
        node.send(sid, b"\x00superseded\n");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!crate::supersession::session_superseded());
    }

    /// (f) session_control이 꺼져 있으면 제어 스트림을 열지 않는다.
    #[tokio::test]
    async fn session_control_off_opens_no_control_stream() {
        let (client, _dials, carriers) = fake_node_client(MuxOptions {
            session_control: false,
            ..ansim_options()
        });
        let mut user = client.open_stream("a.example", 80).await.unwrap();
        user.write_all(b"ping").await.unwrap();
        user.flush().await.unwrap();
        let node = carrier(&carriers, 0);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(node.syns.load(Ordering::SeqCst), 1, "only the user stream");
        assert!(node.control.borrow().is_none());
        assert!(client.sessions.lock().await[0].control.is_none());
    }

    /// 성립한 스트림의 슬롯 예약이 세션 `Arc`를 새게 하지 않는다: 유휴 축출된 세션은
    /// 제어 스트림이 없어도 물리 carrier를 닫는다(`mem::forget(Reservation)` 회귀).
    #[tokio::test]
    async fn evicted_idle_session_releases_its_carrier() {
        let (client, dials, carriers) = fake_node_client(MuxOptions {
            session_control: false,
            ..ansim_options()
        });
        drop(client.open_stream("a.example", 80).await.unwrap());
        {
            let sessions = client.sessions.lock().await;
            let stale = now_ms().wrapping_sub(IDLE_TIMEOUT.as_millis() as Uint * 2);
            sessions[0].last_used_ms.store(stale, Ordering::SeqCst);
        }
        let _user = client.open_stream("b.example", 80).await.unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        assert!(
            carrier(&carriers, 0).wait_closed().await,
            "an evicted idle session must close its physical carrier"
        );
    }
}
