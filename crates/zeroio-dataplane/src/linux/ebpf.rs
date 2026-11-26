//! Userspace `aya` loader, attachment manager, and typed map controller for `zeroio-xdp-ebpf`.

use crate::XdpAttachMode;
use crate::linux::DataplaneError;
use aya::maps::{Array, HashMap as BpfHashMap, LpmTrie, PerCpuArray, XskMap, lpm_trie};
use aya::programs::{Xdp, XdpMode, xdp::XdpLinkId};
use aya::{Ebpf, Pod};
use std::os::fd::AsRawFd;
use std::path::Path;
use zeroio_xdp_common::{
    XdpAclRule, XdpCounters, XdpFlowKey, XdpIpV4, XdpIpV6, XdpPortKey, XdpPortRule,
    XdpRuntimeConfig, XdpSpliceTarget,
};

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PodRuntimeConfig(XdpRuntimeConfig);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PodIpV4(XdpIpV4);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PodIpV6(XdpIpV6);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PodAclRule(XdpAclRule);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PodPortKey(XdpPortKey);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PodPortRule(XdpPortRule);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PodFlowKey(XdpFlowKey);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PodSpliceTarget(XdpSpliceTarget);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PodCounters(XdpCounters);

// SAFETY: Every wrapper above has `#[repr(transparent)]` over a `#[repr(C)]` `Copy + 'static`
// ABI struct from `zeroio-xdp-common` whose padding fields are explicit and safely readable as POD.
unsafe impl Pod for PodRuntimeConfig {}
// SAFETY: Transparent POD wrapper over `#[repr(C)]` `XdpIpV4`.
unsafe impl Pod for PodIpV4 {}
// SAFETY: Transparent POD wrapper over `#[repr(C)]` `XdpIpV6`.
unsafe impl Pod for PodIpV6 {}
// SAFETY: Transparent POD wrapper over `#[repr(C)]` `XdpAclRule`.
unsafe impl Pod for PodAclRule {}
// SAFETY: Transparent POD wrapper over `#[repr(C)]` `XdpPortKey`.
unsafe impl Pod for PodPortKey {}
// SAFETY: Transparent POD wrapper over `#[repr(C)]` `XdpPortRule`.
unsafe impl Pod for PodPortRule {}
// SAFETY: Transparent POD wrapper over `#[repr(C)]` `XdpFlowKey`.
unsafe impl Pod for PodFlowKey {}
// SAFETY: Transparent POD wrapper over `#[repr(C)]` `XdpSpliceTarget`.
unsafe impl Pod for PodSpliceTarget {}
// SAFETY: Transparent POD wrapper over `#[repr(C)]` `XdpCounters`.
unsafe impl Pod for PodCounters {}

/// Active attachment record returned by [`XdpController::attach`].
#[derive(Debug)]
pub struct XdpAttachment {
    pub interface: String,
    pub link_id: XdpLinkId,
    pub mode: XdpMode,
}

/// Controller for loading, attaching, and configuring the `zeroio_xdp` eBPF program and maps.
pub struct XdpController {
    bpf: Ebpf,
    program_name: String,
    loaded: bool,
}

impl XdpController {
    /// Load an eBPF ELF object directly from an in-memory slice (e.g. `include_bytes_aligned!`).
    pub fn from_bytes(data: &[u8]) -> Result<Self, DataplaneError> {
        let bpf = Ebpf::load(data)?;
        Ok(Self {
            bpf,
            program_name: "zeroio_xdp".to_string(),
            loaded: false,
        })
    }

    /// Load an eBPF ELF object from a file path on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, DataplaneError> {
        let bpf = Ebpf::load_file(path)?;
        Ok(Self {
            bpf,
            program_name: "zeroio_xdp".to_string(),
            loaded: false,
        })
    }

    /// Ensure the `zeroio_xdp` program is loaded into the kernel.
    pub fn load_program(&mut self) -> Result<(), DataplaneError> {
        if self.loaded {
            return Ok(());
        }
        let prog: &mut Xdp = self
            .bpf
            .program_mut(&self.program_name)
            .ok_or(DataplaneError::InvalidConfig("missing zeroio_xdp program"))?
            .try_into()?;
        prog.load()?;
        self.loaded = true;
        Ok(())
    }

    /// Attach `zeroio_xdp` to `interface` according to [`XdpAttachMode`].
    pub fn attach(
        &mut self,
        interface: &str,
        mode: XdpAttachMode,
    ) -> Result<XdpAttachment, DataplaneError> {
        self.load_program()?;
        let prog: &mut Xdp = self
            .bpf
            .program_mut(&self.program_name)
            .ok_or(DataplaneError::InvalidConfig("missing zeroio_xdp program"))?
            .try_into()?;

        match mode {
            XdpAttachMode::Native => {
                let link_id = prog.attach(interface, XdpMode::Driver)?;
                Ok(XdpAttachment {
                    interface: interface.to_string(),
                    link_id,
                    mode: XdpMode::Driver,
                })
            }
            XdpAttachMode::Generic => {
                let link_id = prog.attach(interface, XdpMode::Skb)?;
                Ok(XdpAttachment {
                    interface: interface.to_string(),
                    link_id,
                    mode: XdpMode::Skb,
                })
            }
            XdpAttachMode::Auto => match prog.attach(interface, XdpMode::Driver) {
                Ok(link_id) => Ok(XdpAttachment {
                    interface: interface.to_string(),
                    link_id,
                    mode: XdpMode::Driver,
                }),
                Err(_) => {
                    let link_id = prog.attach(interface, XdpMode::Skb)?;
                    Ok(XdpAttachment {
                        interface: interface.to_string(),
                        link_id,
                        mode: XdpMode::Skb,
                    })
                }
            },
        }
    }

    /// Update runtime policy stored in `ZEROIO_CONFIG` slot `0`.
    pub fn set_config(&mut self, config: XdpRuntimeConfig) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_CONFIG")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_CONFIG map"))?;
        let mut arr = Array::<_, PodRuntimeConfig>::try_from(map)?;
        arr.set(0, PodRuntimeConfig(config), 0)?;
        Ok(())
    }

    /// Insert or update an IPv4 CIDR ACL rule inside `ZEROIO_ACL_V4`.
    pub fn set_acl_v4(
        &mut self,
        prefix_len: u32,
        ip: XdpIpV4,
        rule: XdpAclRule,
    ) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_ACL_V4")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_ACL_V4 map"))?;
        let mut trie = LpmTrie::<_, PodIpV4, PodAclRule>::try_from(map)?;
        let key = lpm_trie::Key::new(prefix_len, PodIpV4(ip));
        trie.insert(&key, PodAclRule(rule), 0)?;
        Ok(())
    }

    /// Remove an IPv4 CIDR ACL rule from `ZEROIO_ACL_V4`.
    pub fn remove_acl_v4(&mut self, prefix_len: u32, ip: XdpIpV4) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_ACL_V4")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_ACL_V4 map"))?;
        let mut trie = LpmTrie::<_, PodIpV4, PodAclRule>::try_from(map)?;
        let key = lpm_trie::Key::new(prefix_len, PodIpV4(ip));
        trie.remove(&key)?;
        Ok(())
    }

    /// Insert or update an IPv6 CIDR ACL rule inside `ZEROIO_ACL_V6`.
    pub fn set_acl_v6(
        &mut self,
        prefix_len: u32,
        ip: XdpIpV6,
        rule: XdpAclRule,
    ) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_ACL_V6")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_ACL_V6 map"))?;
        let mut trie = LpmTrie::<_, PodIpV6, PodAclRule>::try_from(map)?;
        let key = lpm_trie::Key::new(prefix_len, PodIpV6(ip));
        trie.insert(&key, PodAclRule(rule), 0)?;
        Ok(())
    }

    /// Set a port routing rule inside `ZEROIO_PORTS`.
    pub fn set_port_rule(
        &mut self,
        key: XdpPortKey,
        rule: XdpPortRule,
    ) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_PORTS")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_PORTS map"))?;
        let mut table = BpfHashMap::<_, PodPortKey, PodPortRule>::try_from(map)?;
        table.insert(PodPortKey(key), PodPortRule(rule), 0)?;
        Ok(())
    }

    /// Remove a port routing rule from `ZEROIO_PORTS`.
    pub fn remove_port_rule(&mut self, key: XdpPortKey) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_PORTS")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_PORTS map"))?;
        let mut table = BpfHashMap::<_, PodPortKey, PodPortRule>::try_from(map)?;
        table.remove(&PodPortKey(key))?;
        Ok(())
    }

    /// Register or update an L4 splice/NAT forwarding entry in `ZEROIO_SPLICE`.
    pub fn set_splice(
        &mut self,
        key: XdpFlowKey,
        target: XdpSpliceTarget,
    ) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_SPLICE")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_SPLICE map"))?;
        let mut table = BpfHashMap::<_, PodFlowKey, PodSpliceTarget>::try_from(map)?;
        table.insert(PodFlowKey(key), PodSpliceTarget(target), 0)?;
        Ok(())
    }

    /// Remove an L4 splice entry from `ZEROIO_SPLICE`.
    pub fn remove_splice(&mut self, key: XdpFlowKey) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_SPLICE")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_SPLICE map"))?;
        let mut table = BpfHashMap::<_, PodFlowKey, PodSpliceTarget>::try_from(map)?;
        table.remove(&PodFlowKey(key))?;
        Ok(())
    }

    /// Bind an AF_XDP socket file descriptor into `ZEROIO_XSKS[queue_id]`.
    pub fn register_xsk(
        &mut self,
        queue_id: u32,
        socket_fd: impl AsRawFd,
    ) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_XSKS")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_XSKS map"))?;
        let mut xsks = XskMap::try_from(map)?;
        xsks.set(queue_id, socket_fd, 0)?;
        Ok(())
    }

    /// Unbind `ZEROIO_XSKS[queue_id]`.
    pub fn unregister_xsk(&mut self, queue_id: u32) -> Result<(), DataplaneError> {
        let map = self
            .bpf
            .map_mut("ZEROIO_XSKS")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_XSKS map"))?;
        let mut xsks = XskMap::try_from(map)?;
        xsks.unset(queue_id)?;
        Ok(())
    }

    /// Read and sum per-CPU XDP counters from `ZEROIO_COUNTERS`.
    pub fn read_counters(&self) -> Result<XdpCounters, DataplaneError> {
        let map = self
            .bpf
            .map("ZEROIO_COUNTERS")
            .ok_or(DataplaneError::InvalidConfig("missing ZEROIO_COUNTERS map"))?;
        let arr = PerCpuArray::<_, PodCounters>::try_from(map)?;
        let values = arr.get(&0, 0)?;
        let mut total = XdpCounters::default();
        for cpu_val in values.iter() {
            let c = cpu_val.0;
            total.packets = total.packets.saturating_add(c.packets);
            total.passed = total.passed.saturating_add(c.passed);
            total.dropped = total.dropped.saturating_add(c.dropped);
            total.redirected = total.redirected.saturating_add(c.redirected);
            total.parse_errors = total.parse_errors.saturating_add(c.parse_errors);
            total.xsk_drops = total.xsk_drops.saturating_add(c.xsk_drops);
            total.rate_limited = total.rate_limited.saturating_add(c.rate_limited);
            total.spliced = total.spliced.saturating_add(c.spliced);
            total.acl_dropped = total.acl_dropped.saturating_add(c.acl_dropped);
            total.syn_rate_limited = total.syn_rate_limited.saturating_add(c.syn_rate_limited);
        }
        Ok(total)
    }
}
