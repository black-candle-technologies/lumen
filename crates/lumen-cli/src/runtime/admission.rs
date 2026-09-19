use std::{
    collections::BTreeSet,
    future::Future,
    sync::{Arc, Mutex},
};

use lumen_core::action::RunId;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::task::TaskTracker;

#[derive(Default)]
struct GateState {
    sealed: bool,
    handles: Vec<AbortHandle>,
    owned_runs: BTreeSet<RunId>,
}

#[derive(Clone, Default)]
pub(super) struct AdmissionGate {
    state: Arc<Mutex<GateState>>,
    tasks: TaskTracker,
}

#[derive(Debug)]
pub(super) struct AdmissionClosed;

impl AdmissionGate {
    pub fn submit<F>(&self, work: F) -> Result<JoinHandle<F::Output>, AdmissionClosed>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let mut state = self.state.lock().map_err(|_| AdmissionClosed)?;
        if state.sealed {
            return Err(AdmissionClosed);
        }
        Ok(self.spawn_locked(&mut state, work))
    }

    pub fn submit_owned<F>(
        &self,
        run_id: RunId,
        work: F,
    ) -> Result<JoinHandle<F::Output>, AdmissionClosed>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let mut state = self.state.lock().map_err(|_| AdmissionClosed)?;
        if state.sealed || !state.owned_runs.contains(&run_id) {
            return Err(AdmissionClosed);
        }
        Ok(self.spawn_locked(&mut state, work))
    }

    fn spawn_locked<F>(&self, state: &mut GateState, work: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        state.handles.retain(|handle| !handle.is_finished());
        let task = self.tasks.spawn(work);
        state.handles.push(task.abort_handle());
        task
    }

    pub fn register_owned(&self, run_id: RunId) -> Result<(), AdmissionClosed> {
        let mut state = self.state.lock().map_err(|_| AdmissionClosed)?;
        if state.sealed {
            return Err(AdmissionClosed);
        }
        state.owned_runs.insert(run_id);
        Ok(())
    }

    pub fn finish_owned(&self, run_id: RunId) {
        if let Ok(mut state) = self.state.lock() {
            state.owned_runs.remove(&run_id);
        }
    }

    pub fn seal(&self) -> Result<bool, AdmissionClosed> {
        let mut state = self.state.lock().map_err(|_| AdmissionClosed)?;
        let first = !state.sealed;
        state.sealed = true;
        Ok(first)
    }

    pub fn is_sealed(&self) -> bool {
        self.state.lock().map_or(true, |state| state.sealed)
    }

    pub fn abort_tracked(&self) -> Result<(), AdmissionClosed> {
        let state = self.state.lock().map_err(|_| AdmissionClosed)?;
        for handle in &state.handles {
            handle.abort();
        }
        Ok(())
    }

    pub fn active_count(&self) -> usize {
        self.state.lock().map_or(0, |state| {
            state
                .handles
                .iter()
                .filter(|handle| !handle.is_finished())
                .count()
        })
    }

    pub fn close_tracker(&self) {
        self.tasks.close();
    }

    pub async fn wait(&self) {
        self.tasks.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::AdmissionGate;

    #[tokio::test]
    async fn sealing_and_submission_share_one_registration_barrier() {
        let gate = AdmissionGate::default();
        let first = gate.submit(async { 7 }).expect("first task admitted");
        assert!(gate.seal().expect("sealed"));
        assert!(gate.submit(async { 8 }).is_err());
        assert_eq!(first.await.expect("first task"), 7);
        gate.close_tracker();
        gate.wait().await;
    }
}
