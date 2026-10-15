//! HY2 인계 종료 사유: 노드가 같은 기기 인계로 닫는 QUIC 연결의 application error code.
//! 표지 자체는 엔진 세대에 묶인 `crate::supersession`이 가진다.

use crate::supersession::mark_superseded;
use quinn::{Connection, ConnectionError};

/// 노드 sing-quic `hysteria2.SupersededErrorCode`와 같은 값이다.
pub const SUPERSEDED_ERROR_CODE: u64 = 0x4153_0001;

/// 서버가 인계 코드로 닫았으면 그 연결의 세대에 표지를 세운다. 다른 종료는 무시한다.
pub(crate) fn note_close(reason: &ConnectionError, generation: u64) -> bool {
    let superseded = matches!(
        reason,
        ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == SUPERSEDED_ERROR_CODE
    );
    superseded && mark_superseded(generation, "hysteria2")
}

pub(crate) fn spawn_watch(connection: Connection, generation: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let reason = connection.closed().await;
        note_close(&reason, generation);
    })
}
