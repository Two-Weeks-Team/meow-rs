use super::*;
use quinn::udp::EcnCodepoint;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicUsize, Ordering},
    task::Waker,
};

#[derive(Debug)]
struct ReceiveFixture {
    frames: Mutex<VecDeque<(Vec<u8>, RecvMeta)>>,
    polls: AtomicUsize,
}

impl AsyncUdpSocket for ReceiveFixture {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        unreachable!("receive-only fixture")
    }

    fn try_send(&self, _: &Transmit<'_>) -> io::Result<()> {
        unreachable!("receive-only fixture")
    }

    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let Some((bytes, received)) = self.frames.lock().unwrap().pop_front() else {
            return Poll::Pending;
        };
        assert!(
            bytes.len() <= bufs[0].len(),
            "inner receive buffer truncated GRO: {} > {}",
            bytes.len(),
            bufs[0].len()
        );
        bufs[0][..bytes.len()].copy_from_slice(&bytes);
        meta[0] = received;
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:12345".parse().unwrap())
    }

    fn max_receive_segments(&self) -> usize {
        64
    }
}

fn encode(payload: &[u8]) -> Vec<u8> {
    let salt = [0x5a; SALAMANDER_SALT_LEN];
    let key = Salamander::new(b"secret").key(&salt);
    salt.into_iter()
        .chain(
            payload
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ key[i % key.len()]),
        )
        .collect()
}

fn frame(bytes: Vec<u8>, stride: usize) -> (Vec<u8>, RecvMeta) {
    let received = RecvMeta {
        addr: "192.0.2.1:8443".parse().unwrap(),
        len: bytes.len(),
        stride,
        ecn: Some(EcnCodepoint::Ect0),
        dst_ip: Some("192.0.2.2".parse().unwrap()),
    };
    (bytes, received)
}

fn socket(frames: Vec<(Vec<u8>, RecvMeta)>) -> (Hy2UdpSocket, Arc<ReceiveFixture>) {
    let inner = Arc::new(ReceiveFixture {
        frames: Mutex::new(frames.into()),
        polls: AtomicUsize::new(0),
    });
    let socket = Hy2UdpSocket {
        inner: Arc::clone(&inner) as Arc<dyn AsyncUdpSocket>,
        server_addr: "192.0.2.1:443".parse().unwrap(),
        hop: HopState::new("8443", 5, 5).unwrap().map(Mutex::new),
        obfs: Some(Salamander::new(b"secret")),
        recv: Mutex::new(ObfsRecvState::default()),
    };
    (socket, inner)
}

fn next_datagram(socket: &Hy2UdpSocket, capacity: usize) -> Vec<u8> {
    let mut storage = vec![0u8; capacity];
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [RecvMeta::default()];
    let mut cx = Context::from_waker(Waker::noop());
    let result = socket.poll_recv(&mut cx, &mut bufs, &mut meta);
    assert!(matches!(result, Poll::Ready(Ok(1))), "{result:?}");
    let received = meta[0];
    assert_eq!(received.addr, socket.server_addr);
    assert_eq!(received.ecn, Some(EcnCodepoint::Ect0));
    assert_eq!(received.dst_ip, Some("192.0.2.2".parse().unwrap()));
    assert_eq!(received.stride, received.len);
    storage[..received.len].to_vec()
}

#[test]
fn gro_datagrams_survive_separate_receive_polls() {
    let payloads = [vec![0xc1; 1200], vec![0xa1; 1200], vec![0x55; 900]];
    let encrypted = payloads.iter().flat_map(|p| encode(p)).collect();
    let (socket, inner) = socket(vec![frame(encrypted, 1200 + SALAMANDER_SALT_LEN)]);
    assert_eq!(socket.max_receive_segments(), 1);
    for payload in &payloads {
        assert_eq!(&next_datagram(&socket, 1472), payload);
        assert_eq!(inner.polls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn small_gro_datagrams_are_not_merged_or_corrupted() {
    let payloads = [vec![1; 12], vec![2; 12], vec![3; 5]];
    let encrypted = payloads.iter().flat_map(|p| encode(p)).collect();
    let (socket, _) = socket(vec![frame(encrypted, 12 + SALAMANDER_SALT_LEN)]);
    for payload in &payloads {
        assert_eq!(&next_datagram(&socket, 128), payload);
    }
}

#[test]
fn oversized_and_short_datagrams_do_not_kill_the_endpoint() {
    let oversized = encode(&[7; 1600]);
    let payload = vec![3; 1200];
    let valid = encode(&payload);
    let (socket, _) = socket(vec![
        frame(oversized.clone(), oversized.len()),
        frame(vec![0; SALAMANDER_SALT_LEN], SALAMANDER_SALT_LEN),
        frame(valid.clone(), valid.len()),
    ]);
    assert_eq!(next_datagram(&socket, 1472), payload);
}

#[test]
fn malformed_gro_tail_does_not_drop_the_next_receive() {
    let payloads = [vec![1; 12], vec![2; 12]];
    let mut encrypted = payloads.iter().flat_map(|p| encode(p)).collect::<Vec<_>>();
    encrypted.extend_from_slice(&[0; SALAMANDER_SALT_LEN]);
    let following = encode(b"next");
    let (socket, _) = socket(vec![
        frame(encrypted, 12 + SALAMANDER_SALT_LEN),
        frame(following.clone(), following.len()),
    ]);
    for payload in &payloads {
        assert_eq!(&next_datagram(&socket, 128), payload);
    }
    assert_eq!(next_datagram(&socket, 128), b"next");
}

#[test]
fn receive_buffer_holds_all_64_gro_segments() {
    let payloads = (0..64).map(|i| vec![i; 1450]).collect::<Vec<_>>();
    let encrypted = payloads.iter().flat_map(|p| encode(p)).collect();
    let (socket, inner) = socket(vec![frame(encrypted, 1450 + SALAMANDER_SALT_LEN)]);
    for payload in &payloads {
        assert_eq!(&next_datagram(&socket, 1472), payload);
        assert_eq!(inner.polls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn rejected_packet_flood_yields_and_can_resume() {
    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let mut frames = vec![frame(vec![0; SALAMANDER_SALT_LEN], SALAMANDER_SALT_LEN); 65];
    let following = encode(b"next");
    frames.push(frame(following.clone(), following.len()));
    let (socket, inner) = socket(frames);
    let wake_count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wake_count));
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0u8; 1472];
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [RecvMeta::default()];
    assert!(socket.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
    assert_eq!(inner.polls.load(Ordering::SeqCst), 64);
    assert_eq!(wake_count.0.load(Ordering::SeqCst), 1);
    assert_eq!(next_datagram(&socket, 1472), b"next");
}
