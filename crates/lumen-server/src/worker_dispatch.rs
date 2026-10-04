//! Server-owned durable worker polling. Policy and admission remain in the driver.
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use lumen_core::approval::TimestampMillis;
use tokio::{task::JoinHandle, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::ServiceError;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchTick {
    pub launched: usize,
}
pub type WorkerDispatchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DispatchTick, ServiceError>> + Send + 'a>>;
pub trait WorkerDispatchDriver: Send + Sync {
    fn stop_dispatches(&self) {}
    fn dispatch_tick<'a>(
        &'a self,
        now: TimestampMillis,
        stop: &'a CancellationToken,
    ) -> WorkerDispatchFuture<'a>;
}
pub struct WorkerDispatchLoop {
    driver: Arc<dyn WorkerDispatchDriver>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl WorkerDispatchLoop {
    pub fn spawn(
        driver: Arc<dyn WorkerDispatchDriver>,
        poll_every: Duration,
    ) -> Result<Self, ServiceError> {
        if !(Duration::from_millis(50)..=Duration::from_secs(60)).contains(&poll_every) {
            return Err(ServiceError::Internal(
                "invalid worker dispatch polling interval".into(),
            ));
        }
        let stop = CancellationToken::new();
        let task_stop = stop.clone();
        let task_driver = driver.clone();
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll_every);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    () = task_stop.cancelled() => break,
                    _ = ticker.tick() => {
                        if task_stop.is_cancelled() { break; }
                        // Finish a short admission tick cooperatively. Dropping it
                        // between reservation and admission could strand capacity.
                        if task_driver.dispatch_tick(TimestampMillis::new(u64::try_from(crate::now_ms()).unwrap_or(0)), &task_stop).await.is_err() {
                            eprintln!("event=worker_dispatch_tick_failed diagnostic=dispatch_failed");
                        }
                    }
                }
            }
        });
        Ok(Self {
            driver,
            stop,
            task: Some(task),
        })
    }
    pub fn request_stop(&self) {
        // Fence admission before making cancellation visible to the poller.
        self.driver.stop_dispatches();
        self.stop.cancel();
    }
    pub async fn join(mut self) {
        self.request_stop();
        if let Some(task) = self.task.take()
            && task.await.is_err()
        {
            eprintln!("event=worker_dispatch_loop_failed diagnostic=join_failed");
        }
    }
}
impl Drop for WorkerDispatchLoop {
    fn drop(&mut self) {
        self.request_stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Driver {
        ticks: AtomicUsize,
        seen: tokio::sync::Notify,
    }
    impl WorkerDispatchDriver for Driver {
        fn dispatch_tick<'a>(
            &'a self,
            _: TimestampMillis,
            stop: &'a CancellationToken,
        ) -> WorkerDispatchFuture<'a> {
            Box::pin(async move {
                assert!(!stop.is_cancelled());
                let tick = self.ticks.fetch_add(1, Ordering::SeqCst);
                self.seen.notify_one();
                if tick == 0 {
                    Err(ServiceError::Internal("injected".into()))
                } else {
                    Ok(DispatchTick::default())
                }
            })
        }
    }
    #[tokio::test]
    async fn polling_survives_failure_and_stops_before_join_returns() {
        let driver = Arc::new(Driver {
            ticks: AtomicUsize::new(0),
            seen: tokio::sync::Notify::new(),
        });
        let poller = WorkerDispatchLoop::spawn(driver.clone(), Duration::from_millis(50)).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while driver.ticks.load(Ordering::SeqCst) < 3 {
                driver.seen.notified().await;
            }
        })
        .await
        .unwrap();
        poller.request_stop();
        poller.join().await;
        let count = driver.ticks.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(driver.ticks.load(Ordering::SeqCst), count);
    }
    #[tokio::test]
    async fn polling_interval_is_bounded() {
        let driver = Arc::new(Driver {
            ticks: AtomicUsize::new(0),
            seen: tokio::sync::Notify::new(),
        });
        assert!(WorkerDispatchLoop::spawn(driver.clone(), Duration::from_millis(1)).is_err());
        assert!(WorkerDispatchLoop::spawn(driver, Duration::from_secs(61)).is_err());
    }
}
