//! 안심 세션 제어 스트림: sing-mux carrier가 같은 기기 인계로 닫히는지 듣는다.
//!
//! sing-mux 부모 연결에는 종료 사유 필드가 없다. 그래서 같은 carrier 안에 일반 sing-mux
//! 스트림 하나를 예약 목적지(`session-control.ansim.invalid:1`, RFC 6761 `.invalid` — 절대
//! 해석·라우팅되지 않는다)로 열어 둔다. 안심 노드는 허가된 strict carrier의 이 스트림만
//! carrier에 등록하고, 같은 기기의 새 carrier가 이어받을 때(revoke)만 정확히 `superseded\n`을
//! 쓰고 부모 carrier를 닫는다. 만료·장애·일반 종료에는 아무것도 쓰지 않는다. 이 목적지를
//! 모르는 옛 노드는 라우팅에 실패해 스트림을 닫는다(오류 status 또는 EOF) — 표지를 세우지
//! 않는다.
//!
//! 수명: 제어 작업은 그 세션의 수명에만 묶인다. 작업은 `MuxSession`을 잡지 않는다(잡으면
//! 유휴 정리된 세션이 노드에 살아 남고, 새 carrier가 그 옛 carrier를 revoke해 이 앱이 자기
//! 자신을 "인계"로 오인한다). smux 스트림은 `Arc<smux::Session>`을 잡아 물리 연결을 살려
//! 두므로, `MuxSession`이 풀에서 빠지거나 버려질 때 [`ControlTask::retire`]가 작업을 끊어
//! 그 참조를 놓는다.

use super::client::SessionKind;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::watch;
use tokio::task::AbortHandle;

/// 노드와 맞춘 예약 목적지(고정값).
pub(crate) const SESSION_CONTROL_HOST: &str = "session-control.ansim.invalid";
pub(crate) const SESSION_CONTROL_PORT: u16 = 1;
/// 개행까지 읽는 최대 길이. 노드는 `superseded\n` 한 줄만 쓴다.
const REASON_LIMIT: usize = 64;
const SUPERSEDED: &[u8] = b"superseded";

/// 한 세션의 제어 작업. 버려지면 작업을 끊는다.
pub(crate) struct ControlTask {
    abort: AbortHandle,
    /// 세션이 풀에서 빠졌다. 끊기 직전에 이미 읽힌 사유도 무시하게 한다. 표지와 같은 잠금
    /// 안에서만 세운다(`retire`) — 사유 처리(`mark_superseded_if`)와 어느 한쪽이 먼저 끝난다.
    retired: Arc<AtomicBool>,
    /// 작업이 사유 처리까지 끝났다(사유·EOF·오류·abort 무엇이든).
    settled: watch::Receiver<bool>,
}

impl ControlTask {
    /// sing-mux 세션(Smux/Yamux/H2Mux)에 제어 스트림을 연다. Mux.Cool은 sing-mux가 아니다.
    pub(crate) fn spawn(kind: &SessionKind, generation: u64) -> Option<Self> {
        if matches!(kind, SessionKind::MuxCool(_)) {
            return None;
        }
        let kind = kind.clone();
        let retired = Arc::new(AtomicBool::new(false));
        let task_retired = Arc::clone(&retired);
        let (settled_tx, settled) = watch::channel(false);
        let handle = tokio::spawn(async move {
            // 어느 경로로 끝나든(반환·abort) 끝났다고 알린다.
            let _settled = SettledOnDrop(settled_tx);
            let mut stream = match kind
                .open_stream(SESSION_CONTROL_HOST, SESSION_CONTROL_PORT, false)
                .await
            {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::debug!("mux session control: open failed: {e}");
                    return;
                }
            };
            // 스트림이 필요한 만큼만 세션을 잡게 한다(이 복제본을 들고 기다리지 않는다).
            drop(kind);
            #[cfg(test)]
            test_gate::wait().await;
            match read_reason(&mut stream).await {
                Ok(line) if line == SUPERSEDED => {
                    // 세대 비교와 "아직 풀에 묶인 carrier인가"를 표지 잠금 하나 안에서 본다.
                    crate::supersession::mark_superseded_if(generation, "vless", || {
                        !task_retired.load(Ordering::SeqCst)
                    });
                }
                Ok(line) => tracing::debug!(
                    "mux session control: ignoring unknown reason {:?}",
                    String::from_utf8_lossy(&line)
                ),
                Err(e) => tracing::debug!("mux session control: closed without a reason: {e}"),
            }
        });
        Some(Self {
            abort: handle.abort_handle(),
            retired,
            settled,
        })
    }

    /// 세션이 풀에서 빠졌다. 이후 도착하는 사유를 무시하고 제어 스트림(과 그 스트림이 잡은
    /// 물리 연결 참조)을 놓는다.
    pub(crate) fn retire(&self) {
        // 표지 잠금 안에서 표시한다. 이 뒤에 끝나는 사유 처리는 무시된다.
        crate::supersession::with_state_lock(|| self.retired.store(true, Ordering::SeqCst));
        self.abort.abort();
    }

    /// 물리 연결이 끊긴 세션을 정리하기 전에, 이미 도착한 사유를 읽을 시간을 준다.
    /// 노드는 사유를 쓴 뒤 부모를 닫으므로 세션이 죽은 것으로 보일 때 사유는 이미 스트림
    /// 버퍼에 있다. 일반 EOF·옛 노드는 곧바로 끝난다. `limit`을 넘기면 포기한다.
    pub(crate) async fn settle(&self, limit: Duration) {
        let mut settled = self.settled.clone();
        let _ = tokio::time::timeout(limit, settled.wait_for(|done| *done)).await;
    }
}

/// 시험용: 제어 작업이 사유를 읽기 직전에 멈춘다(작업 순서를 강제한다).
#[cfg(test)]
pub(crate) mod test_gate {
    use std::sync::{Arc, Mutex};
    use tokio::sync::Semaphore;

    static GATE: Mutex<Option<Arc<Semaphore>>> = Mutex::new(None);

    /// 닫힌 문을 건다. 돌려준 세마포어에 허가를 더하면 연다.
    pub(crate) fn arm() -> Arc<Semaphore> {
        let gate = Arc::new(Semaphore::new(0));
        *GATE.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }

    pub(crate) fn disarm() {
        *GATE.lock().unwrap() = None;
    }

    pub(super) async fn wait() {
        let gate = GATE.lock().unwrap().clone();
        if let Some(gate) = gate {
            let _ = gate.acquire().await;
        }
    }
}

struct SettledOnDrop(watch::Sender<bool>);

impl Drop for SettledOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

#[cfg(test)]
impl ControlTask {
    /// 제어 작업이 사유를 처리하고 끝났는가(시험용).
    pub(crate) fn is_finished(&self) -> bool {
        self.abort.is_finished()
    }
}

impl Drop for ControlTask {
    fn drop(&mut self) {
        self.retire();
    }
}

/// 개행까지 최대 [`REASON_LIMIT`]바이트를 읽는다. 개행 없는 EOF·초과·오류는 사유가 아니다.
async fn read_reason<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(16);
    let mut byte = [0u8; 1];
    while line.len() < REASON_LIMIT {
        if reader.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "control stream closed before a newline",
            ));
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
        line.push(byte[0]);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "control reason exceeds the line limit",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reason_line_requires_a_newline_within_the_limit() {
        let mut exact: &[u8] = b"superseded\n";
        assert_eq!(read_reason(&mut exact).await.unwrap(), SUPERSEDED);
        let mut no_newline: &[u8] = b"superseded";
        assert!(read_reason(&mut no_newline).await.is_err());
        let long = [b'a'; REASON_LIMIT + 1];
        let mut too_long: &[u8] = &long;
        assert!(read_reason(&mut too_long).await.is_err());
    }
}
