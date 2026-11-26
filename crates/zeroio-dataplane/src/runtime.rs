//! Interface validation, thread-per-core worker planning, and dataplane lifecycle management.

use crate::umem::UmemConfig;
use crate::{InterfaceConfig, XdpAttachMode, XdpInterfaceMode};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

/// Validation error produced by [`InterfaceConfig::validate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    EmptyInterfaceName,
    InvalidFrameSize,
    EmptyQueueList,
    InvalidUmem(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInterfaceName => f.write_str("interface name cannot be empty"),
            Self::InvalidFrameSize => {
                f.write_str("frame size must be a power of two >= 2048 bytes")
            }
            Self::EmptyQueueList => f.write_str("at least one NIC queue id must be configured"),
            Self::InvalidUmem(msg) => write!(f, "invalid UMEM configuration: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Execution plan for a single per-core queue worker thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerPlan {
    pub interface: String,
    pub queue_id: u32,
    pub cpu: Option<usize>,
    pub mode: XdpInterfaceMode,
    pub attach_mode: XdpAttachMode,
    pub frame_size: u32,
    pub prefer_zerocopy: bool,
}

impl InterfaceConfig {
    /// Validate interface settings and queue layout.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::EmptyInterfaceName);
        }
        if self.frame_size < 2048 || !self.frame_size.is_power_of_two() {
            return Err(ConfigError::InvalidFrameSize);
        }
        if self.queues.is_empty() {
            return Err(ConfigError::EmptyQueueList);
        }
        Ok(())
    }

    /// Build deterministic per-queue [`WorkerPlan`] assignments paired round-robin with `cpus`.
    pub fn worker_plans(&self) -> Result<Vec<WorkerPlan>, ConfigError> {
        self.validate()?;
        let mut plans = Vec::with_capacity(self.queues.len());
        for (idx, &queue_id) in self.queues.iter().enumerate() {
            let cpu = if self.cpus.is_empty() {
                None
            } else {
                Some(self.cpus[idx % self.cpus.len()])
            };
            plans.push(WorkerPlan {
                interface: self.name.clone(),
                queue_id,
                cpu,
                mode: self.mode,
                attach_mode: self.attach_mode,
                frame_size: self.frame_size,
                prefer_zerocopy: self.prefer_zerocopy,
            });
        }
        Ok(plans)
    }
}

/// Cooperative handle controlling spawned thread-per-core workers.
pub struct DataplaneHandle {
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl DataplaneHandle {
    /// Signal all worker threads to exit their event loops.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Check whether shutdown has been requested.
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Clone the cooperative stop flag for external coordination.
    pub fn stop_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Number of spawned worker threads.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Request stop and join all worker threads.
    pub fn shutdown(self) -> thread::Result<()> {
        self.request_stop();
        self.join_all()
    }

    /// Join all worker threads without forcing stop first.
    pub fn join_all(self) -> thread::Result<()> {
        for handle in self.workers {
            handle.join()?;
        }
        Ok(())
    }
}

/// Orchestrator that validates configuration and spawns pinned per-queue worker threads.
pub struct DataplaneManager {
    interface: InterfaceConfig,
    umem: UmemConfig,
    plans: Vec<WorkerPlan>,
}

impl DataplaneManager {
    /// Validate interface and UMEM configuration and construct a [`DataplaneManager`].
    pub fn new(interface: InterfaceConfig, umem: UmemConfig) -> Result<Self, ConfigError> {
        umem.validate().map_err(ConfigError::InvalidUmem)?;
        let plans = interface.worker_plans()?;
        Ok(Self {
            interface,
            umem,
            plans,
        })
    }

    pub fn interface(&self) -> &InterfaceConfig {
        &self.interface
    }

    pub fn umem(&self) -> UmemConfig {
        self.umem
    }

    pub fn worker_plans(&self) -> &[WorkerPlan] {
        &self.plans
    }

    /// Spawn one OS thread per queue plan, pinning CPUs on Linux when configured.
    pub fn spawn_workers<F>(&self, worker_fn: F) -> std::io::Result<DataplaneHandle>
    where
        F: Fn(WorkerPlan, UmemConfig, Arc<AtomicBool>) + Send + Sync + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let shared_fn = Arc::new(worker_fn);
        let mut workers = Vec::with_capacity(self.plans.len());

        for plan in &self.plans {
            let thread_plan = plan.clone();
            let umem = self.umem;
            let stop_flag = Arc::clone(&stop);
            let run = Arc::clone(&shared_fn);
            let name = format!("zeroio-{}-q{}", thread_plan.interface, thread_plan.queue_id);
            let handle = thread::Builder::new().name(name).spawn(move || {
                #[cfg(target_os = "linux")]
                if let Some(cpu) = thread_plan.cpu {
                    let _ = crate::linux::pin_current_thread_to_cpu(cpu);
                }
                run(thread_plan, umem, stop_flag);
            })?;
            workers.push(handle);
        }

        Ok(DataplaneHandle { stop, workers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_builds_plans_and_runs_workers() {
        let mut cfg = InterfaceConfig::protect("eth0");
        cfg.queues = vec![0, 1];
        cfg.cpus = vec![2, 3];
        let mgr = DataplaneManager::new(cfg, UmemConfig::default()).unwrap();
        assert_eq!(mgr.worker_plans().len(), 2);
        assert_eq!(mgr.worker_plans()[0].cpu, Some(2));
        assert_eq!(mgr.worker_plans()[1].cpu, Some(3));

        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen_clone = Arc::clone(&seen);
        let handle = mgr
            .spawn_workers(move |_plan, _umem, stop| {
                seen_clone.fetch_add(1, Ordering::Relaxed);
                while !stop.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            })
            .unwrap();
        assert_eq!(handle.worker_count(), 2);
        while seen.load(Ordering::Relaxed) < 2 {
            std::thread::yield_now();
        }
        handle.shutdown().unwrap();
    }
}
