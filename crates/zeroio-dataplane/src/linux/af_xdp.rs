//! Linux `AF_XDP` 4-ring (`Fill`, `RX`, `TX`, `Completion`) UMEM socket driver
//! implementing [`XskDevice`] with explicit zero-copy -> copy bind fallback.

use crate::XskBindMode;
use crate::device::{TxSubmitError, XskDevice};
use crate::linux::DataplaneError;
use crate::umem::{UmemConfig, UmemFrameToken};
use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Configuration for opening an [`AfXdpDevice`] bound to a specific interface and NIC queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AfXdpConfig {
    pub interface: String,
    pub queue_id: u32,
    pub umem: UmemConfig,
    pub prefer_zerocopy: bool,
    pub allow_copy_fallback: bool,
    pub need_wakeup: bool,
}

impl AfXdpConfig {
    /// Construct a default configuration for `interface` and `queue_id`.
    pub fn new(interface: impl Into<String>, queue_id: u32, umem: UmemConfig) -> Self {
        Self {
            interface: interface.into(),
            queue_id,
            umem,
            prefer_zerocopy: true,
            allow_copy_fallback: true,
            need_wakeup: true,
        }
    }
}

struct MmapRegion {
    ptr: NonNull<libc::c_void>,
    len: usize,
}

impl MmapRegion {
    fn map_anonymous_umem(len: usize) -> io::Result<Self> {
        // SAFETY: `mmap(MAP_PRIVATE | MAP_ANONYMOUS)` with `ptr::null_mut()` and `fd = -1`
        // allocates a fresh page-aligned region of `len` bytes managed solely by `MmapRegion`.
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(raw)
            .ok_or_else(|| io::Error::other("anonymous mmap returned null pointer"))?;
        Ok(Self { ptr, len })
    }

    fn map_shared_fd(fd: RawFd, len: usize, offset: libc::off_t) -> io::Result<Self> {
        // SAFETY: `fd` is a live `AF_XDP` socket descriptor whose kernel ring offsets were
        // retrieved from `getsockopt(SOL_XDP, XDP_MMAP_OFFSETS)`; `len` covers descriptor arrays.
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                offset,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(raw)
            .ok_or_else(|| io::Error::other("socket mmap returned null pointer"))?;
        Ok(Self { ptr, len })
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr().cast::<u8>()
    }
}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` and `self.len` come from a successful `libc::mmap` call.
        unsafe {
            let _ = libc::munmap(self.ptr.as_ptr(), self.len);
        }
    }
}

// SAFETY: Ownership of `MmapRegion` permits moving the queue-private UMEM and ring maps across threads
// before pinning onto the destination CPU core.
unsafe impl Send for MmapRegion {}

struct XdpRing {
    _mmap: MmapRegion,
    producer: *mut u32,
    consumer: *mut u32,
    flags: *mut u32,
    desc: *mut u8,
    size: u32,
    mask: u32,
    cached_prod: u32,
    cached_cons: u32,
}

// SAFETY: `XdpRing` raw pointers index exclusively into its owned `MmapRegion`.
unsafe impl Send for XdpRing {}

impl XdpRing {
    fn new(
        fd: RawFd,
        ring_entries: u32,
        entry_size: usize,
        pgoff: libc::off_t,
        offsets: &libc::xdp_ring_offset,
    ) -> io::Result<Self> {
        let map_len = offsets.desc as usize + (ring_entries as usize) * entry_size;
        let mmap = MmapRegion::map_shared_fd(fd, map_len, pgoff)?;
        let base = mmap.as_ptr();
        // SAFETY: Kernel guarantees `offsets.{producer,consumer,flags,desc}` lie within `map_len`.
        let (producer, consumer, flags, desc) = unsafe {
            (
                base.add(offsets.producer as usize).cast::<u32>(),
                base.add(offsets.consumer as usize).cast::<u32>(),
                base.add(offsets.flags as usize).cast::<u32>(),
                base.add(offsets.desc as usize),
            )
        };
        // SAFETY: Kernel initializes producer/consumer counters inside the mapped ring header.
        let (prod, cons) = unsafe {
            (
                AtomicU32::from_ptr(producer).load(Ordering::Acquire),
                AtomicU32::from_ptr(consumer).load(Ordering::Acquire),
            )
        };
        Ok(Self {
            _mmap: mmap,
            producer,
            consumer,
            flags,
            desc,
            size: ring_entries,
            mask: ring_entries - 1,
            cached_prod: prod,
            cached_cons: cons,
        })
    }

    fn needs_wakeup(&self) -> bool {
        // SAFETY: `self.flags` points inside `self._mmap` and is `u32`-aligned in XDP ABI.
        let f = unsafe { AtomicU32::from_ptr(self.flags).load(Ordering::Relaxed) };
        (f & libc::XDP_RING_NEED_WAKEUP) != 0
    }

    fn producer_free(&mut self, nb: u32) -> u32 {
        let free = self.size - self.cached_prod.wrapping_sub(self.cached_cons);
        if free >= nb {
            return free;
        }
        // SAFETY: `self.consumer` is kernel-owned shared atomic index inside `_mmap`.
        self.cached_cons = unsafe { AtomicU32::from_ptr(self.consumer).load(Ordering::Acquire) };
        self.size - self.cached_prod.wrapping_sub(self.cached_cons)
    }

    fn consumer_avail(&mut self, nb: u32) -> u32 {
        let avail = self.cached_prod.wrapping_sub(self.cached_cons);
        if avail >= nb {
            return avail;
        }
        // SAFETY: `self.producer` is kernel-owned shared atomic index inside `_mmap`.
        self.cached_prod = unsafe { AtomicU32::from_ptr(self.producer).load(Ordering::Acquire) };
        self.cached_prod.wrapping_sub(self.cached_cons)
    }

    fn publish_producer(&self, new_prod: u32) {
        // SAFETY: `self.producer` is shared between userspace writer and kernel reader;
        // `Release` orders descriptor writes before kernel observation.
        unsafe {
            AtomicU32::from_ptr(self.producer).store(new_prod, Ordering::Release);
        }
    }

    fn publish_consumer(&self, new_cons: u32) {
        // SAFETY: `self.consumer` is shared between kernel writer and userspace reader;
        // `Release` frees consumed descriptor slots for kernel reuse.
        unsafe {
            AtomicU32::from_ptr(self.consumer).store(new_cons, Ordering::Release);
        }
    }

    fn write_u64(&mut self, idx: u32, val: u64) {
        let slot = (idx & self.mask) as usize;
        // SAFETY: `slot < self.size`, and Fill/Completion rings store `u64` UMEM addresses.
        unsafe {
            self.desc.cast::<u64>().add(slot).write(val);
        }
    }

    fn read_u64(&self, idx: u32) -> u64 {
        let slot = (idx & self.mask) as usize;
        // SAFETY: `slot < self.size`, and kernel populated the `u64` slot prior to `Acquire` read.
        unsafe { self.desc.cast::<u64>().add(slot).read() }
    }

    fn write_desc(&mut self, idx: u32, desc: libc::xdp_desc) {
        let slot = (idx & self.mask) as usize;
        // SAFETY: `slot < self.size`, and TX/RX rings store `libc::xdp_desc` structs.
        unsafe {
            self.desc.cast::<libc::xdp_desc>().add(slot).write(desc);
        }
    }

    fn read_desc(&self, idx: u32) -> libc::xdp_desc {
        let slot = (idx & self.mask) as usize;
        // SAFETY: `slot < self.size`, and kernel populated `xdp_desc` prior to `Acquire` read.
        unsafe { self.desc.cast::<libc::xdp_desc>().add(slot).read() }
    }
}

/// Linux `AF_XDP` queue-bound socket owning UMEM + 4 mapped rings (`Fill`, `RX`, `TX`, `Completion`).
pub struct AfXdpDevice {
    fd: OwnedFd,
    queue_id: u32,
    bind_mode: XskBindMode,
    umem_cfg: UmemConfig,
    umem_region: MmapRegion,
    free_frames: VecDeque<u64>,
    fill_ring: XdpRing,
    rx_ring: XdpRing,
    tx_ring: XdpRing,
    comp_ring: XdpRing,
}

impl AfXdpDevice {
    /// Open and bind a Linux `AF_XDP` socket with explicit `XDP_ZEROCOPY -> XDP_COPY` fallback.
    pub fn open(config: &AfXdpConfig) -> Result<Self, DataplaneError> {
        config
            .umem
            .validate()
            .map_err(DataplaneError::InvalidConfig)?;
        let ifindex = interface_index(&config.interface)?;

        // SAFETY: Creating an `AF_XDP` raw datagram socket via kernel syscall.
        let raw_fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: `raw_fd` was just returned as a valid owned file descriptor from `libc::socket`.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let sock_fd = fd.as_raw_fd();

        let umem_len = config.umem.total_bytes();
        let umem_region = MmapRegion::map_anonymous_umem(umem_len)?;

        let reg = libc::xdp_umem_reg {
            addr: umem_region.as_ptr() as u64,
            len: umem_len as u64,
            chunk_size: config.umem.frame_size,
            headroom: config.umem.headroom,
            flags: 0,
            tx_metadata_len: 0,
        };
        set_sockopt(sock_fd, libc::XDP_UMEM_REG, &reg)?;
        set_sockopt(
            sock_fd,
            libc::XDP_UMEM_FILL_RING,
            &config.umem.fill_ring_size,
        )?;
        set_sockopt(
            sock_fd,
            libc::XDP_UMEM_COMPLETION_RING,
            &config.umem.comp_ring_size,
        )?;
        set_sockopt(sock_fd, libc::XDP_RX_RING, &config.umem.rx_ring_size)?;
        set_sockopt(sock_fd, libc::XDP_TX_RING, &config.umem.tx_ring_size)?;

        let offsets = get_mmap_offsets(sock_fd)?;
        let mut fill_ring = XdpRing::new(
            sock_fd,
            config.umem.fill_ring_size,
            mem::size_of::<u64>(),
            libc::XDP_UMEM_PGOFF_FILL_RING as libc::off_t,
            &offsets.fr,
        )?;
        let rx_ring = XdpRing::new(
            sock_fd,
            config.umem.rx_ring_size,
            mem::size_of::<libc::xdp_desc>(),
            libc::XDP_PGOFF_RX_RING,
            &offsets.rx,
        )?;
        let tx_ring = XdpRing::new(
            sock_fd,
            config.umem.tx_ring_size,
            mem::size_of::<libc::xdp_desc>(),
            libc::XDP_PGOFF_TX_RING,
            &offsets.tx,
        )?;
        let comp_ring = XdpRing::new(
            sock_fd,
            config.umem.comp_ring_size,
            mem::size_of::<u64>(),
            libc::XDP_UMEM_PGOFF_COMPLETION_RING as libc::off_t,
            &offsets.cr,
        )?;

        let bind_mode = bind_xsk(
            sock_fd,
            ifindex,
            config.queue_id,
            config.prefer_zerocopy,
            config.allow_copy_fallback,
            config.need_wakeup,
        )?;

        let mut free_frames = VecDeque::with_capacity(config.umem.frame_count as usize);
        let fill_target = (config.umem.frame_count / 2).min(config.umem.fill_ring_size);
        let fsize = u64::from(config.umem.frame_size);

        let avail = fill_ring.producer_free(fill_target).min(fill_target);
        for i in 0..avail {
            fill_ring.write_u64(fill_ring.cached_prod.wrapping_add(i), u64::from(i) * fsize);
        }
        fill_ring.cached_prod = fill_ring.cached_prod.wrapping_add(avail);
        fill_ring.publish_producer(fill_ring.cached_prod);

        for i in avail..config.umem.frame_count {
            free_frames.push_back(u64::from(i) * fsize);
        }

        Ok(Self {
            fd,
            queue_id: config.queue_id,
            bind_mode,
            umem_cfg: config.umem,
            umem_region,
            free_frames,
            fill_ring,
            rx_ring,
            tx_ring,
            comp_ring,
        })
    }

    fn base_addr(&self, addr: u64) -> u64 {
        let fsize = u64::from(self.umem_cfg.frame_size);
        (addr / fsize) * fsize
    }
}

impl XskDevice for AfXdpDevice {
    fn queue_id(&self) -> u32 {
        self.queue_id
    }

    fn bind_mode(&self) -> XskBindMode {
        self.bind_mode
    }

    fn fd(&self) -> Option<i32> {
        Some(self.fd.as_raw_fd())
    }

    fn recv_batch(&mut self, max: usize, out: &mut Vec<UmemFrameToken>) -> usize {
        let req = u32::try_from(max).unwrap_or(u32::MAX);
        let avail = self.rx_ring.consumer_avail(req).min(req);
        if avail == 0 {
            return 0;
        }
        let cons = self.rx_ring.cached_cons;
        for i in 0..avail {
            let desc = self.rx_ring.read_desc(cons.wrapping_add(i));
            out.push(UmemFrameToken {
                queue: self.queue_id,
                addr: desc.addr,
                len: desc.len,
            });
        }
        self.rx_ring.cached_cons = cons.wrapping_add(avail);
        self.rx_ring.publish_consumer(self.rx_ring.cached_cons);
        avail as usize
    }

    fn frame_data(&self, token: UmemFrameToken) -> Option<&[u8]> {
        let start = usize::try_from(token.addr).ok()?;
        let len = token.len as usize;
        let end = start.checked_add(len)?;
        if end > self.umem_region.len {
            return None;
        }
        // SAFETY: `[start..end)` is bounds-checked inside `self.umem_region` and not concurrently
        // mutated once delivered on RX ring until recycled back onto Fill ring.
        Some(unsafe { slice::from_raw_parts(self.umem_region.as_ptr().add(start), len) })
    }

    fn alloc_tx_frame(&mut self) -> Option<UmemFrameToken> {
        let addr = self.free_frames.pop_front()?;
        Some(UmemFrameToken {
            queue: self.queue_id,
            addr,
            len: 0,
        })
    }

    fn frame_buf_mut(&mut self, addr: u64) -> Option<&mut [u8]> {
        let base = usize::try_from(self.base_addr(addr)).ok()?;
        let start = base.checked_add(self.umem_cfg.headroom as usize)?;
        let cap = self.umem_cfg.max_payload_bytes();
        let end = start.checked_add(cap)?;
        if end > self.umem_region.len {
            return None;
        }
        // SAFETY: `base` was removed from `free_frames` so only userspace owns `[start..end)`.
        Some(unsafe { slice::from_raw_parts_mut(self.umem_region.as_ptr().add(start), cap) })
    }

    fn submit_tx(&mut self, token: UmemFrameToken) -> Result<(), TxSubmitError> {
        if token.len as usize > self.umem_cfg.max_payload_bytes() {
            return Err(TxSubmitError::FrameTooLarge);
        }
        if self.tx_ring.producer_free(1) == 0 {
            return Err(TxSubmitError::RingFull);
        }
        let data_addr = self.base_addr(token.addr) + u64::from(self.umem_cfg.headroom);
        let desc = libc::xdp_desc {
            addr: data_addr,
            len: token.len,
            options: 0,
        };
        let prod = self.tx_ring.cached_prod;
        self.tx_ring.write_desc(prod, desc);
        self.tx_ring.cached_prod = prod.wrapping_add(1);
        self.tx_ring.publish_producer(self.tx_ring.cached_prod);
        Ok(())
    }

    fn kick_tx(&mut self) -> Result<(), TxSubmitError> {
        if self.tx_ring.needs_wakeup() {
            // SAFETY: Waking up kernel TX NAPI processing via `sendto(MSG_DONTWAIT)` on `AF_XDP` fd.
            let rc = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    ptr::null(),
                    0,
                    libc::MSG_DONTWAIT,
                    ptr::null(),
                    0,
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENOBUFS | libc::EAGAIN | libc::EBUSY) => return Ok(()),
                    Some(code) => return Err(TxSubmitError::DeviceError(code)),
                    None => return Err(TxSubmitError::DeviceError(libc::EIO)),
                }
            }
        }
        Ok(())
    }

    fn recycle_rx(&mut self, token: UmemFrameToken) {
        let base = self.base_addr(token.addr);
        if self.fill_ring.producer_free(1) == 0 {
            self.free_frames.push_back(base);
            return;
        }
        let prod = self.fill_ring.cached_prod;
        self.fill_ring.write_u64(prod, base);
        self.fill_ring.cached_prod = prod.wrapping_add(1);
        self.fill_ring.publish_producer(self.fill_ring.cached_prod);
        if self.fill_ring.needs_wakeup() {
            // SAFETY: Nudge kernel RX fill ring when `XDP_RING_NEED_WAKEUP` is set.
            unsafe {
                let mut pfd = libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let _ = libc::poll(&mut pfd, 1, 0);
            }
        }
    }

    fn reclaim_completions(&mut self, max: usize) -> usize {
        let req = u32::try_from(max).unwrap_or(u32::MAX);
        let avail = self.comp_ring.consumer_avail(req).min(req);
        if avail == 0 {
            return 0;
        }
        let cons = self.comp_ring.cached_cons;
        for i in 0..avail {
            let addr = self.comp_ring.read_u64(cons.wrapping_add(i));
            self.free_frames.push_back(self.base_addr(addr));
        }
        self.comp_ring.cached_cons = cons.wrapping_add(avail);
        self.comp_ring.publish_consumer(self.comp_ring.cached_cons);
        avail as usize
    }

    fn poll_wait(&mut self, timeout: Duration) {
        let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: `pfd` points to stack-allocated `pollfd` polling readable events on `self.fd`.
        unsafe {
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let _ = libc::poll(&mut pfd, 1, timeout_ms);
        }
    }
}

fn interface_index(name: &str) -> Result<u32, DataplaneError> {
    let c_name =
        CString::new(name).map_err(|_| DataplaneError::InvalidConfig("interior NUL in name"))?;
    // SAFETY: `c_name` is a valid NUL-terminated string passed to `if_nametoindex`.
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(idx)
}

fn set_sockopt<T>(fd: RawFd, optname: libc::c_int, val: &T) -> io::Result<()> {
    let optlen = u32::try_from(mem::size_of::<T>()).unwrap_or(u32::MAX);
    // SAFETY: `val` points to `optlen` initialized bytes for `setsockopt(SOL_XDP, optname)`.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_XDP,
            optname,
            ptr::from_ref(val).cast::<libc::c_void>(),
            optlen,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_mmap_offsets(fd: RawFd) -> io::Result<libc::xdp_mmap_offsets> {
    let mut offsets = MaybeUninit::<libc::xdp_mmap_offsets>::zeroed();
    let mut len = mem::size_of::<libc::xdp_mmap_offsets>() as libc::socklen_t;
    // SAFETY: `offsets` provides `len` writable bytes for `getsockopt(SOL_XDP, XDP_MMAP_OFFSETS)`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_XDP,
            libc::XDP_MMAP_OFFSETS,
            offsets.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Kernel initialized the `xdp_mmap_offsets` structure on `rc == 0`.
    Ok(unsafe { offsets.assume_init() })
}

fn bind_xsk(
    fd: RawFd,
    ifindex: u32,
    queue_id: u32,
    prefer_zerocopy: bool,
    allow_copy_fallback: bool,
    need_wakeup: bool,
) -> Result<XskBindMode, DataplaneError> {
    let wakeup_flag = if need_wakeup {
        libc::XDP_USE_NEED_WAKEUP
    } else {
        0
    };

    if prefer_zerocopy {
        let sa_zc = libc::sockaddr_xdp {
            sxdp_family: libc::AF_XDP as u16,
            sxdp_flags: libc::XDP_ZEROCOPY | wakeup_flag,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        if try_bind_sockaddr(fd, &sa_zc).is_ok() {
            return Ok(XskBindMode::ZeroCopy);
        }
        if !allow_copy_fallback {
            return Err(DataplaneError::UnsupportedBindMode);
        }
    }

    let sa_copy = libc::sockaddr_xdp {
        sxdp_family: libc::AF_XDP as u16,
        sxdp_flags: libc::XDP_COPY | wakeup_flag,
        sxdp_ifindex: ifindex,
        sxdp_queue_id: queue_id,
        sxdp_shared_umem_fd: 0,
    };
    if try_bind_sockaddr(fd, &sa_copy).is_ok() {
        return Ok(XskBindMode::Copy);
    }
    Err(DataplaneError::UnsupportedBindMode)
}

fn try_bind_sockaddr(fd: RawFd, sa: &libc::sockaddr_xdp) -> io::Result<()> {
    let len = u32::try_from(mem::size_of::<libc::sockaddr_xdp>()).unwrap_or(u32::MAX);
    // SAFETY: `sa` is a valid initialized `sockaddr_xdp` of exact size `len`.
    let rc = unsafe { libc::bind(fd, ptr::from_ref(sa).cast::<libc::sockaddr>(), len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
