//! Proposed pure state machine. No socket, Docker, PID or signalling side effect.
use std::sync::{Arc,Mutex};

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Phase { Created, Starting, Started, Unknown, NeverStarted }
pub struct Lifecycle(Mutex<Phase>);
impl Lifecycle {
    pub fn new()->Arc<Self>{Arc::new(Self(Mutex::new(Phase::Created)))}
    fn lock(&self)->std::sync::MutexGuard<'_,Phase>{self.0.lock().unwrap_or_else(|e|e.into_inner())}
    pub fn phase(&self)->Phase{*self.lock()}
    /// Called while holding the cancellation registry's gate. Once Starting,
    /// sending may already be committed; cancellation cannot prove otherwise.
    pub fn begin(self:&Arc<Self>)->Result<Attempt,String>{
        let mut phase=self.lock();
        if *phase!=Phase::Created{return Err("exec start is not in Created state".into());}
        *phase=Phase::Starting;Ok(Attempt{state:self.clone()})
    }
    /// Same outer gate as begin(): after this wins, no start request may be sent.
    pub fn cancel_before_start(&self){let mut p=self.lock();if *p==Phase::Created{*p=Phase::NeverStarted;}}
    pub fn observe_running(&self){let mut p=self.lock();if matches!(*p,Phase::Starting|Phase::Unknown){*p=Phase::Started;}}
    pub fn terminal_without_running(&self,exit_code:Option<i64>)->bool{
        self.never_started() || (self.phase()!=Phase::Created && exit_code.is_some())
    }
    pub fn never_started(&self)->bool{self.phase()==Phase::NeverStarted}
}
pub struct Attempt {state:Arc<Lifecycle>}
impl Attempt {
    /// Caller has not issued the first transport write. This is a positive
    /// local no-post witness, never inferred from a socket timeout/cancel flag.
    pub(crate) fn abort_before_post(self) {
        let mut phase=self.state.lock();
        if matches!(*phase,Phase::Starting|Phase::Unknown) { *phase=Phase::NeverStarted; }
    }
}
impl Drop for Attempt {
    fn drop(&mut self){let mut p=self.state.lock();if *p==Phase::Starting{*p=Phase::Unknown;}}
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn pending_false_and_lost_ack_never_mean_finished(){
        let s=Lifecycle::new();let attempt=s.begin().unwrap();
        assert!(!s.terminal_without_running(None));drop(attempt);
        assert_eq!(s.phase(),Phase::Unknown);assert!(!s.terminal_without_running(None));
        s.observe_running();assert!(!s.terminal_without_running(None));
        assert!(s.terminal_without_running(Some(0)));
    }
    #[test] fn cancelled_created_cannot_later_start(){
        let s=Lifecycle::new();s.cancel_before_start();
        assert!(s.begin().is_err());assert!(s.never_started());
    }
    #[test] fn explicit_prewrite_abort_is_never_started_not_unknown() {
        let state=Lifecycle::new();let attempt=state.begin().unwrap();
        attempt.abort_before_post();assert!(state.never_started());
        assert!(state.begin().is_err());
    }
    #[test] fn numeric_exit_code_allows_silent_short_command_completion(){
        let s=Lifecycle::new();drop(s.begin().unwrap());
        assert_eq!(s.phase(),Phase::Unknown);assert!(s.terminal_without_running(Some(0)));
    }
    #[test] fn lost_worker_cannot_downgrade_an_observed_running_process(){
        let s=Lifecycle::new();let attempt=s.begin().unwrap();s.observe_running();drop(attempt);
        assert_eq!(s.phase(),Phase::Started);
    }
}
