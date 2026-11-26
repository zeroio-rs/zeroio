//! Linux-native AF_XDP zero-copy socket driver, aya eBPF controller, and CPU affinity pinning.

pub mod af_xdp;
pub mod ebpf;

pub use af_xdp::{AfXdpConfig, AfXdpDevice};
pub use ebpf::{XdpAttachment, XdpController};

use std::fmt;
use std::io;
use std::mem;

/// Errors returned by Linux AF_XDP and eBPF dataplane operations.
#[derive(Debug)]
pub enum DataplaneError {
    Io(io::Error),
    InvalidConfig(&'static str),
    Ebpf(aya::EbpfError),
    Map(aya::maps::MapError),
    Program(aya::programs::ProgramError),
    UnsupportedBindMode,
}

impl fmt::Display for DataplaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "dataplane I/O error: {err}"),
            Self::InvalidConfig(msg) => write!(f, "invalid dataplane configuration: {msg}"),
            Self::Ebpf(err) => write!(f, "eBPF loader error: {err}"),
            Self::Map(err) => write!(f, "eBPF map error: {err}"),
            Self::Program(err) => write!(f, "eBPF program error: {err}"),
            Self::UnsupportedBindMode => {
                f.write_str("AF_XDP socket bind failed in requested zero-copy/copy modes")
            }
        }
    }
}

impl std::error::Error for DataplaneError {}

impl From<io::Error> for DataplaneError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<aya::EbpfError> for DataplaneError {
    fn from(value: aya::EbpfError) -> Self {
        Self::Ebpf(value)
    }
}

impl From<aya::maps::MapError> for DataplaneError {
    fn from(value: aya::maps::MapError) -> Self {
        Self::Map(value)
    }
}

impl From<aya::programs::ProgramError> for DataplaneError {
    fn from(value: aya::programs::ProgramError) -> Self {
        Self::Program(value)
    }
}

/// Pin the calling OS thread to CPU core index `cpu` via `sched_setaffinity`.
pub fn pin_current_thread_to_cpu(cpu: usize) -> io::Result<()> {
    if cpu >= libc::CPU_SETSIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cpu index exceeds CPU_SETSIZE",
        ));
    }

    // SAFETY: `cpu_set_t` is plain integer bitmask storage; `CPU_ZERO` initializes every bit
    // and `CPU_SET` sets the validated in-range `cpu` bit before `sched_setaffinity(0, ...)`.
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let rc = libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &set);
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
