use std::{
    collections::VecDeque,
    convert::Infallible,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use axum::response::sse::Event;
use futures_util::{Stream, stream};
use lumen_core::{
    action::{CanonicalValue, RunId},
    identity::WorkspaceId,
};
use thiserror::Error;
use tokio::sync::{broadcast, watch};

#[derive(Clone)]
pub struct EventBroker {
    inner: Arc<EventBrokerInner>,
}

impl EventBroker {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let (sender, _) = broadcast::channel(capacity);
        let (shutdown, _) = watch::channel(false);
        Self {
            inner: Arc::new(EventBrokerInner {
                capacity,
                next_id: AtomicU64::new(1),
                events: RwLock::new(VecDeque::with_capacity(capacity)),
                sender,
                shutdown,
            }),
        }
    }

    pub fn close(&self) {
        let _ = self.inner.shutdown.send(true);
    }

    pub fn publish(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
        kind: impl Into<String>,
        payload: CanonicalValue,
    ) -> Result<RunEvent, EventBrokerError> {
        let kind = kind.into();
        if kind.is_empty()
            || kind.len() > 128
            || !kind.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
        {
            return Err(EventBrokerError::InvalidEventKind);
        }
        let event = RunEvent {
            id: self.inner.next_id.fetch_add(1, Ordering::Relaxed),
            workspace_id,
            run_id,
            kind,
            payload,
        };
        {
            let mut events = self.inner.events.write().expect("event replay lock");
            if events.len() == self.inner.capacity {
                events.pop_front();
            }
            events.push_back(event.clone());
        }
        let _ = self.inner.sender.send(event.clone());
        Ok(event)
    }

    pub(crate) fn subscribe(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
        after: u64,
    ) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static + use<> {
        let receiver = self.inner.sender.subscribe();
        let pending = self.replay(workspace_id, run_id, after);
        let state = Subscription {
            broker: self.clone(),
            workspace_id,
            run_id,
            cursor: after,
            pending,
            receiver,
            shutdown: self.inner.shutdown.subscribe(),
        };
        stream::unfold(state, |mut state| async move {
            loop {
                if *state.shutdown.borrow() {
                    return None;
                }
                if let Some(event) = state.pending.pop_front() {
                    if event.id <= state.cursor {
                        continue;
                    }
                    state.cursor = event.id;
                    return Some((Ok(event.into_sse()), state));
                }
                let received = tokio::select! {
                    biased;
                    changed = state.shutdown.changed() => {
                        if changed.is_err() || *state.shutdown.borrow() {
                            return None;
                        }
                        continue;
                    }
                    received = state.receiver.recv() => received,
                };
                match received {
                    Ok(event)
                        if event.workspace_id == state.workspace_id
                            && event.run_id == state.run_id
                            && event.id > state.cursor =>
                    {
                        state.cursor = event.id;
                        return Some((Ok(event.into_sse()), state));
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        state.pending =
                            state
                                .broker
                                .replay(state.workspace_id, state.run_id, state.cursor);
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        })
    }

    fn replay(&self, workspace_id: WorkspaceId, run_id: RunId, after: u64) -> VecDeque<RunEvent> {
        self.inner
            .events
            .read()
            .expect("event replay lock")
            .iter()
            .filter(|event| {
                event.workspace_id == workspace_id && event.run_id == run_id && event.id > after
            })
            .cloned()
            .collect()
    }
}

struct EventBrokerInner {
    capacity: usize,
    next_id: AtomicU64,
    events: RwLock<VecDeque<RunEvent>>,
    sender: broadcast::Sender<RunEvent>,
    shutdown: watch::Sender<bool>,
}

struct Subscription {
    broker: EventBroker,
    workspace_id: WorkspaceId,
    run_id: RunId,
    cursor: u64,
    pending: VecDeque<RunEvent>,
    receiver: broadcast::Receiver<RunEvent>,
    shutdown: watch::Receiver<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunEvent {
    id: u64,
    workspace_id: WorkspaceId,
    run_id: RunId,
    kind: String,
    payload: CanonicalValue,
}

impl RunEvent {
    fn into_sse(self) -> Event {
        Event::default()
            .id(self.id.to_string())
            .event(self.kind)
            .json_data(self.payload)
            .expect("canonical event payload serialization cannot fail")
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EventBrokerError {
    #[error("event kind must be a bounded lowercase ASCII identifier")]
    InvalidEventKind,
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;

    #[tokio::test]
    async fn close_ends_existing_and_future_subscriptions() {
        let broker = EventBroker::new(4);
        let workspace_id = WorkspaceId::new();
        let run_id = RunId::new();
        let existing = broker.subscribe(workspace_id, run_id, 0);
        tokio::pin!(existing);

        broker.close();

        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), existing.next())
                .await
                .expect("existing subscription closed")
                .is_none()
        );
        let future = broker.subscribe(workspace_id, run_id, 0);
        tokio::pin!(future);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), future.next())
                .await
                .expect("future subscription closed")
                .is_none()
        );
    }
}
