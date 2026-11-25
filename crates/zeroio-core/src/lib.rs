#![forbid(unsafe_code)]

//! zeroio-core — pure, `#![forbid(unsafe_code)]`, sans-I/O networking and
//! transport algorithms for the Zeroio dataplane.
//!
//! - [`TransportInstant`]: monotonic microsecond instant type shared across modules.
//! - [`rate_sample`]: per-segment [`TxRecord`] bookkeeping and [`RateSample`] generation.
//! - [`rtt`]: RFC 6298 RTT estimator plus running min-RTT.
//! - [`cc`]: [`CongestionController`] trait, [`CcSnapshot`], reusable building blocks
//!   (`parts`: PRR, HyStart++), and reference controllers (`CubicRef`, `Bbr3Ref`, `NewRenoRef`).
//! - [`edgecc`]: Adaptive [`EdgeCc`] congestion controller.
//! - [`model`], [`inference`], [`envelope`], [`aggregate`], [`path_table`]: path estimation,
//!   shared-bottleneck inference, safety envelope, and path-prior sharing.
//! - [`packet`]: zero-copy L2/VLAN/IPv4/IPv6/TCP/UDP header parser, RFC 1071 checksums,
//!   TCP option codecs, and zero-allocation frame encoders.
//! - [`inspect`]: zero-copy TLS `ClientHello` SNI extraction and QUIC header/DCID inspection.
//! - [`tcp`]: O(1) generation-checked connection slab, stateless SYN cookies, bounded
//!   RX/TX reassembly and SACK scoreboards, and full sans-I/O [`TcpStack`].
//! - [`udp`]: O(1) bounded UDP session flow table ([`UdpTable`]).
//! - [`sched`], [`codel`]: DRR pacing scheduler, [`TimingWheel`], and CoDel AQM.
//! - [`sim`]: deterministic multi-flow event-driven network simulator.

pub mod accecn;
pub mod aggregate;
pub mod cc;
pub mod codel;
pub mod edgecc;
pub mod envelope;
pub mod inference;
pub mod inspect;
pub mod instant;
pub mod model;
pub mod packet;
pub mod path_table;
pub mod rate_sample;
pub mod rtt;
pub mod sched;
pub mod sim;
pub mod tcp;
pub mod udp;

pub use accecn::{AccEcn, EcnMode, Flags as AccEcnFlags};
pub use aggregate::{Aggregate, AggregateStats};
pub use cc::{CcSnapshot, CongestionController};
pub use codel::{Codel, CodelAction};
pub use edgecc::{AggregateLease, EdgeCc, PathPrior, Tier};
pub use envelope::Envelope;
pub use inference::{Inference, SbdStats, SharedBottleneckJudge};
pub use inspect::{QuicHeader, TlsSniResult, extract_tls_sni, inspect_quic_header};
pub use instant::TransportInstant;
pub use model::PathModel;
pub use packet::{
    AccEcnOption, FrameEncodeError, PacketView, SackBlock, TcpFrameSpec, TcpHeaderView, TcpOptions,
    UdpFrameSpec, encode_tcp_frame, encode_tcp_frame_parts, encode_udp_frame, internet_checksum,
    l4_pseudo_checksum,
};
pub use path_table::{PathKey, PathSample, PathTable};
pub use rate_sample::{RateSample, RateSampler, TxRecord};
pub use rtt::RttState;
pub use sched::{Admit, Lease, Scheduler, TimingWheel};
pub use tcp::{
    CcKind, ConnHandle, ConnSlab, SeqNum, SynCookieKey, TcpConfig, TcpConn, TcpConnSnapshot,
    TcpError, TcpFourTuple, TcpStack, TcpState,
};
pub use udp::{UdpFlowKey, UdpSession, UdpTable};
