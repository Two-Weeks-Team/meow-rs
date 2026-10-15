//! 같은 기기 인계 표지(엔진 세대 결속).
//!
//! 안심 노드는 같은 기기 UUID의 새 연결이 이어받을 때만 이전 carrier에 인계 사유를 보낸다.
//! HY2는 QUIC application close code로(`hysteria2::SUPERSEDED_ERROR_CODE`), VLESS sing-mux는
//! 같은 carrier의 제어 스트림으로(`mux::control`) 받는다. 만료·장애·일반 종료에는 사유가 없다.
//! 그래서 이 표지가 선 엔진만 "다른 곳에서 같은 기기 정보로 접속"을 안내하면 되고, 서버
//! 상태나 기기 시계로 추론할 필요가 없다.
//!
//! 엔진은 프로세스에 하나지만 순서대로 여러 번 뜬다(Android는 같은 프로세스에서 재시작한다).
//! 그래서 표지를 **엔진 세대**에 묶는다. 엔진을 시작할 때 `clear_session_superseded`가 세대를
//! 올리고, 각 클라이언트(HY2 연결 관리자·mux 풀)는 만들어질 때의 세대를 붙잡는다. 이전 세대의
//! 연결이 늦게 사유를 받아도 지금 엔진은 멈추지 않는다.

use std::sync::atomic::{AtomicU64, Ordering};

/// 현재 엔진 세대. 0은 쓰지 않는다(아래 SUPERSEDED의 "없음").
static GENERATION: AtomicU64 = AtomicU64::new(1);
/// 인계로 닫힌 세대. 0이면 없음.
static SUPERSEDED: AtomicU64 = AtomicU64::new(0);

/// 현재 엔진의 carrier가 같은 기기의 새 연결에 넘겨져 닫혔는가.
pub fn session_superseded() -> bool {
    superseded_in(GENERATION.load(Ordering::SeqCst))
}

/// 엔진을 새로 시작할 때(어댑터를 만들기 전에) 부른다. 세대를 올려 이전 엔진의 연결이
/// 남긴(또는 늦게 남길) 표지를 지금 엔진과 끊는다.
pub fn clear_session_superseded() {
    GENERATION.fetch_add(1, Ordering::SeqCst);
}

#[cfg_attr(not(any(feature = "hysteria2", feature = "mux")), allow(dead_code))]
pub(crate) fn current_generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}

/// 그 세대가 인계로 닫혔고, 그 세대가 아직 현재인가.
pub(crate) fn superseded_in(generation: u64) -> bool {
    generation == GENERATION.load(Ordering::SeqCst)
        && SUPERSEDED.load(Ordering::SeqCst) == generation
}

/// 인증된 carrier에서 인계 사유를 받았다. 그 carrier의 세대가 현재일 때만 표지를 세운다.
/// 기록하는 값이 그 세대라서, 비교와 기록 사이에 엔진이 다시 시작돼도 새 세대는 깨끗하다.
#[cfg_attr(not(any(feature = "hysteria2", feature = "mux")), allow(dead_code))]
pub(crate) fn mark_superseded(generation: u64, carrier: &str) -> bool {
    if generation != GENERATION.load(Ordering::SeqCst) {
        tracing::debug!("{carrier}: ignoring a takeover from a previous engine generation");
        return false;
    }
    tracing::warn!("{carrier} carrier superseded by the same device elsewhere");
    SUPERSEDED.store(generation, Ordering::SeqCst);
    true
}

/// 세대·표지는 프로세스 전역이다. 그것을 바꾸거나 읽는 시험(HY2·mux)은 이 잠금 안에서 돈다.
#[cfg(all(test, any(feature = "hysteria2", feature = "mux")))]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
