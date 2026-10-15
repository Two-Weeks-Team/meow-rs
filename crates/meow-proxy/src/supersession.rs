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

use std::sync::{Mutex, MutexGuard};

/// 엔진 세대와 그 세대의 인계 표지. 한 잠금 안에서만 읽고 바꾼다 — 둘을 따로 두면
/// "이전 세대가 비교를 통과한 뒤 멈춤 → 엔진 재시작 → 새 세대 표지 → 이전 세대 기록"
/// 순서에서 이전 기록이 새 세대의 실제 인계를 지운다(Codex 원본 함수 + barrier 재현).
struct State {
    /// 현재 엔진 세대.
    generation: u64,
    /// 현재 세대가 인계로 닫혔는가. 세대가 오르면 거짓으로 시작한다.
    superseded: bool,
}

static STATE: Mutex<State> = Mutex::new(State {
    generation: 1,
    superseded: false,
});

fn state() -> MutexGuard<'static, State> {
    // 표지 갱신 중 패닉해도 세대·표지는 일관된 두 값이다. 잠금을 계속 쓴다.
    STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 현재 엔진의 carrier가 같은 기기의 새 연결에 넘겨져 닫혔는가.
pub fn session_superseded() -> bool {
    state().superseded
}

/// 엔진을 새로 시작할 때(어댑터를 만들기 전에) 부른다. 세대를 올려 이전 엔진의 연결이
/// 남긴(또는 늦게 남길) 표지를 지금 엔진과 끊는다.
pub fn clear_session_superseded() {
    let mut state = state();
    state.generation += 1;
    state.superseded = false;
}

#[cfg_attr(not(any(feature = "hysteria2", feature = "mux")), allow(dead_code))]
pub(crate) fn current_generation() -> u64 {
    state().generation
}

/// 그 세대가 인계로 닫혔고, 그 세대가 아직 현재인가.
#[cfg_attr(not(any(feature = "hysteria2", feature = "mux")), allow(dead_code))]
pub(crate) fn superseded_in(generation: u64) -> bool {
    let state = state();
    state.generation == generation && state.superseded
}

/// 인증된 carrier에서 인계 사유를 받았다. 그 carrier의 세대가 현재일 때만 표지를 세운다.
#[cfg_attr(not(feature = "hysteria2"), allow(dead_code))]
pub(crate) fn mark_superseded(generation: u64, carrier: &str) -> bool {
    mark_superseded_if(generation, carrier, || true)
}

/// [`mark_superseded`]와 같되, 같은 잠금 안에서 `still_bound`로 그 carrier가 아직 풀에 묶여
/// 있는지도 본다. carrier를 풀에서 빼는 쪽은 [`with_state_lock`] 안에서 뺀다. 그래서 "빼기"와
/// "표지 세우기"는 어느 한쪽이 먼저 끝난다.
#[cfg_attr(not(any(feature = "hysteria2", feature = "mux")), allow(dead_code))]
pub(crate) fn mark_superseded_if(
    generation: u64,
    carrier: &str,
    still_bound: impl FnOnce() -> bool,
) -> bool {
    let mut state = state();
    if state.generation != generation {
        tracing::debug!("{carrier}: ignoring a takeover from a previous engine generation");
        return false;
    }
    if !still_bound() {
        tracing::debug!("{carrier}: ignoring a takeover on a carrier already released");
        return false;
    }
    // 원본 반례의 멈춤 자리: 검사를 모두 통과한 뒤, 기록 직전.
    #[cfg(test)]
    test_hook::paused_after_compare(true);
    tracing::warn!("{carrier} carrier superseded by the same device elsewhere");
    state.superseded = true;
    true
}

/// 표지와 같은 잠금 안에서 `f`를 돈다(carrier를 풀에서 뺄 때).
#[cfg_attr(not(feature = "mux"), allow(dead_code))]
pub(crate) fn with_state_lock<R>(f: impl FnOnce() -> R) -> R {
    let _state = state();
    f()
}

#[cfg(test)]
pub(crate) mod test_hook {
    //! 비교 직후 멈춤을 주입한다(원본 반례의 barrier 자리).
    use std::sync::Mutex;

    type Hook = Box<dyn Fn(bool) + Send>;
    static HOOK: Mutex<Option<Hook>> = Mutex::new(None);

    #[cfg_attr(not(any(feature = "hysteria2", feature = "mux")), allow(dead_code))]
    pub(crate) fn set(hook: Option<Hook>) {
        *HOOK.lock().unwrap() = hook;
    }

    /// 한 번만 분다(꺼내서 부른다). 부르는 동안 다른 표지 호출은 훅 없이 지나간다.
    pub(super) fn paused_after_compare(matched: bool) {
        let hook = HOOK.lock().unwrap().take();
        if let Some(hook) = hook {
            hook(matched);
        }
    }
}

#[cfg(all(test, any(feature = "hysteria2", feature = "mux")))]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Codex 반례(원본 함수 + barrier): 이전 세대 표지가 비교를 통과한 뒤 멈춘 사이 엔진이
    /// 다시 시작하고 새 세대가 실제 인계를 받는다. 이전 쪽이 재개돼도 새 세대 표지는 남아야
    /// 한다. 잠금 하나로 묶었으므로 새 쪽은 이전 쪽이 끝날 때까지 기다린다.
    #[test]
    fn a_paused_stale_mark_never_erases_the_current_takeover() {
        let _serial = TEST_LOCK.blocking_lock();
        let old = current_generation();
        let (paused_tx, paused_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel::<()>();
        let resume_rx = Mutex::new(resume_rx);
        test_hook::set(Some(Box::new(move |_| {
            let _ = paused_tx.send(());
            let _ = resume_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5));
        })));
        let stale = std::thread::spawn(move || mark_superseded(old, "test-old"));
        paused_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (fresh_tx, fresh_rx) = mpsc::channel();
        let fresh = std::thread::spawn(move || {
            clear_session_superseded();
            let marked = mark_superseded(current_generation(), "test-new");
            let _ = fresh_tx.send(());
            marked
        });
        // 이전 쪽이 멈춘 동안 새 쪽(재시작·새 표지)은 끝나지 못한다.
        assert!(fresh_rx.recv_timeout(Duration::from_millis(200)).is_err());
        resume_tx.send(()).unwrap();
        stale.join().unwrap();
        assert!(fresh.join().unwrap());
        assert!(
            session_superseded(),
            "stale store erased current generation takeover"
        );
        clear_session_superseded();
    }
}

/// 세대·표지는 프로세스 전역이다. 그것을 바꾸거나 읽는 시험(HY2·mux)은 이 잠금 안에서 돈다.
#[cfg(all(test, any(feature = "hysteria2", feature = "mux")))]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
