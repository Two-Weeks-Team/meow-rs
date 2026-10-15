//! 같은 기기 인계 종료 사유.
//!
//! 안심 노드는 같은 기기 UUID의 새 연결이 이어받을 때만 이전 연결을 application error code
//! `SUPERSEDED_ERROR_CODE`로 닫는다(노드 `quic-session-gate.patch`). 만료·장애·일반 종료는
//! 이 코드를 쓰지 않는다. 그래서 이 코드를 받은 엔진만 "다른 곳에서 같은 기기 정보로 접속"을
//! 안내하면 되고, 서버 상태나 기기 시계로 추론할 필요가 없다.
//!
//! 엔진은 프로세스에 하나라서 표지도 프로세스 전역이다. 엔진을 시작할 때 `clear_superseded`로
//! 지우고, 네이티브 계층이 `superseded`로 읽어 터널을 멈추고 앱에 사유를 넘긴다.

use quinn::{Connection, ConnectionError};
use std::sync::atomic::{AtomicBool, Ordering};

/// 노드 sing-quic `hysteria2.SupersededErrorCode`와 같은 값이다.
pub const SUPERSEDED_ERROR_CODE: u64 = 0x4153_0001;

static SUPERSEDED: AtomicBool = AtomicBool::new(false);

/// 이 엔진의 HY2 연결이 같은 기기의 새 연결에 넘겨져 닫혔는가.
pub fn superseded() -> bool {
    SUPERSEDED.load(Ordering::SeqCst)
}

/// 엔진을 새로 시작할 때 이전 실행의 표지를 지운다.
pub fn clear_superseded() {
    SUPERSEDED.store(false, Ordering::SeqCst);
}

/// 서버가 인계 코드로 닫았으면 표지를 세운다. 다른 종료는 무시한다.
pub(crate) fn note_close(reason: &ConnectionError) -> bool {
    let superseded = matches!(
        reason,
        ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == SUPERSEDED_ERROR_CODE
    );
    if superseded {
        tracing::warn!("hysteria2 connection superseded by the same device elsewhere");
        SUPERSEDED.store(true, Ordering::SeqCst);
    }
    superseded
}

pub(crate) fn spawn_watch(connection: Connection) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let reason = connection.closed().await;
        note_close(&reason);
    })
}
