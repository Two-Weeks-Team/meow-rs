//! 같은 기기 인계 종료 사유.
//!
//! 안심 노드는 같은 기기 UUID의 새 연결이 이어받을 때만 이전 연결을 application error code
//! `SUPERSEDED_ERROR_CODE`로 닫는다(노드 `quic-session-gate.patch`). 만료·장애·일반 종료는
//! 이 코드를 쓰지 않는다. 그래서 이 코드를 받은 엔진만 "다른 곳에서 같은 기기 정보로 접속"을
//! 안내하면 되고, 서버 상태나 기기 시계로 추론할 필요가 없다.
//!
//! 엔진은 프로세스에 하나지만 순서대로 여러 번 뜬다(Android는 같은 프로세스에서 재시작한다).
//! 그래서 표지를 **엔진 세대**에 묶는다. 엔진을 시작할 때 `clear_superseded`가 세대를 올리고,
//! HY2 클라이언트는 만들어질 때의 세대를 붙잡는다. 이전 세대의 연결이 늦게 닫히며 인계 코드를
//! 받아도 지금 엔진은 멈추지 않는다. 네이티브 계층은 `superseded`로 현재 세대만 읽는다.

use quinn::{Connection, ConnectionError};
use std::sync::atomic::{AtomicU64, Ordering};

/// 노드 sing-quic `hysteria2.SupersededErrorCode`와 같은 값이다.
pub const SUPERSEDED_ERROR_CODE: u64 = 0x4153_0001;

/// 현재 엔진 세대. 0은 쓰지 않는다(아래 SUPERSEDED의 "없음").
static GENERATION: AtomicU64 = AtomicU64::new(1);
/// 인계로 닫힌 세대. 0이면 없음.
static SUPERSEDED: AtomicU64 = AtomicU64::new(0);

/// 현재 엔진의 HY2 연결이 같은 기기의 새 연결에 넘겨져 닫혔는가.
pub fn superseded() -> bool {
    superseded_in(GENERATION.load(Ordering::SeqCst))
}

/// 엔진을 새로 시작할 때 부른다. 세대를 올려 이전 엔진의 연결이 남긴(또는 늦게 남길) 표지를
/// 지금 엔진과 끊는다.
pub fn clear_superseded() {
    GENERATION.fetch_add(1, Ordering::SeqCst);
}

pub(crate) fn current_generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}

/// 그 세대가 인계로 닫혔고, 그 세대가 아직 현재인가.
pub(crate) fn superseded_in(generation: u64) -> bool {
    generation == GENERATION.load(Ordering::SeqCst)
        && SUPERSEDED.load(Ordering::SeqCst) == generation
}

/// 서버가 인계 코드로 닫았고 그 연결의 세대가 현재 세대면 표지를 세운다. 다른 종료와
/// 이전 세대의 늦은 종료는 무시한다.
pub(crate) fn note_close(reason: &ConnectionError, generation: u64) -> bool {
    let superseded = matches!(
        reason,
        ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == SUPERSEDED_ERROR_CODE
    );
    if !superseded {
        return false;
    }
    // 세대 비교와 기록 사이에 엔진이 다시 시작돼도 새 세대를 오염시키지 않는다:
    // 기록하는 값이 이 연결의 세대라서, 세대가 이미 올랐으면 superseded()가 거짓이다.
    if generation != GENERATION.load(Ordering::SeqCst) {
        tracing::debug!("ignoring a takeover close from a previous engine generation");
        return false;
    }
    tracing::warn!("hysteria2 connection superseded by the same device elsewhere");
    SUPERSEDED.store(generation, Ordering::SeqCst);
    true
}

pub(crate) fn spawn_watch(connection: Connection, generation: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let reason = connection.closed().await;
        note_close(&reason, generation);
    })
}
