// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network syscall decoding while a Linux tracee is stopped.
//!
//! Identity is the protocol plus the address and port from the syscall
//! sockaddr. A hostname is never substituted for that address. Remote reads
//! stay inside [`MAX_REMOTE_READ`](crate::MAX_REMOTE_READ) and events do not
//! keep socket payloads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use drifti_observer::Outcome;

use crate::memory::MAX_REMOTE_READ;

/// Largest socket table this decoder keeps for one execution.
const MAX_SOCKETS: usize = 4096;

/// x86_64 Linux syscall numbers. Other architectures have no network table.
const X86_64_CLOSE: u64 = 3;
const X86_64_DUP: u64 = 32;
const X86_64_DUP2: u64 = 33;
const X86_64_SOCKET: u64 = 41;
const X86_64_CONNECT: u64 = 42;
const X86_64_BIND: u64 = 49;
const X86_64_LISTEN: u64 = 50;
const X86_64_DUP3: u64 = 292;

/// An address obtained directly from an AF_INET or AF_INET6 sockaddr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Endpoint {
    address: IpAddr,
    port: u16,
}

/// A network syscall could not be represented safely.
#[derive(Debug)]
pub(crate) enum NetworkDecodeError {
    /// This build has no x86_64 network syscall table.
    ///
    /// `Ok` with an empty fact list is not this condition.
    UnsupportedAbi,
    /// The sockaddr or the resulting endpoint is not authoritative.
    InvalidEndpoint,
    /// A remote sockaddr read failed. The bytes are not retained.
    #[cfg(target_os = "linux")]
    Remote(crate::memory::RemoteReadError),
    /// Entry and exit for one thread did not pair.
    #[cfg(target_os = "linux")]
    PhaseMismatch { tid: u32 },
    /// The pending-syscall or socket table is full.
    #[cfg(target_os = "linux")]
    Capacity,
    /// `/proc` did not yield a socket inode or assigned port.
    #[cfg(target_os = "linux")]
    Proc { errno: i32 },
}

impl std::fmt::Display for NetworkDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedAbi => {
                formatter.write_str("network syscall numbers are not decoded for this architecture")
            }
            Self::InvalidEndpoint => {
                formatter.write_str("socket address is not an authoritative endpoint")
            }
            #[cfg(target_os = "linux")]
            Self::Remote(error) => write!(formatter, "socket address read: {error}"),
            #[cfg(target_os = "linux")]
            Self::PhaseMismatch { tid } => {
                write!(formatter, "network syscall phase mismatch on tid {tid}")
            }
            #[cfg(target_os = "linux")]
            Self::Capacity => formatter.write_str("network socket table capacity exceeded"),
            #[cfg(target_os = "linux")]
            Self::Proc { errno } => {
                write!(formatter, "network socket table read failed: errno {errno}")
            }
        }
    }
}

impl std::error::Error for NetworkDecodeError {}

/// Syscalls that can change IP socket identity on x86_64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetSyscall {
    Close,
    Dup,
    Dup2,
    Dup3,
    Socket,
    Connect,
    Bind,
    Listen,
}

/// `Ok(None)` means the number is outside the x86_64 network table.
/// A missing table is [`NetworkDecodeError::UnsupportedAbi`], never `Ok(None)`.
fn recognize(x86_64: bool, number: u64) -> Result<Option<NetSyscall>, NetworkDecodeError> {
    if !x86_64 {
        return Err(NetworkDecodeError::UnsupportedAbi);
    }
    Ok(match number {
        X86_64_CLOSE => Some(NetSyscall::Close),
        X86_64_DUP => Some(NetSyscall::Dup),
        X86_64_DUP2 => Some(NetSyscall::Dup2),
        X86_64_DUP3 => Some(NetSyscall::Dup3),
        X86_64_SOCKET => Some(NetSyscall::Socket),
        X86_64_CONNECT => Some(NetSyscall::Connect),
        X86_64_BIND => Some(NetSyscall::Bind),
        X86_64_LISTEN => Some(NetSyscall::Listen),
        _ => None,
    })
}

/// Minimum bytes of an AF_INET or AF_INET6 sockaddr. Other families are absent.
fn sockaddr_len(family: u16) -> Option<usize> {
    match family {
        2 => Some(16),
        10 => Some(28),
        _ => None,
    }
}

fn parse_sockaddr(bytes: &[u8]) -> Option<Endpoint> {
    let family = u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?);
    let need = sockaddr_len(family)?;
    if bytes.len() < need {
        return None;
    }
    let port = u16::from_be_bytes(bytes[2..4].try_into().ok()?);
    let address = match family {
        2 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[4..8]).ok()?)),
        10 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
        _ => return None,
    };
    Some(Endpoint { address, port })
}

/// Numeric form of `address`. This is not a reverse-DNS name.
fn canonical_host(address: IpAddr) -> String {
    address.to_string()
}

/// Keeps the bind address and fills only an ephemeral port.
fn listen_endpoint(bound: Endpoint, assigned_port: u16) -> Endpoint {
    if bound.port == 0 {
        Endpoint {
            address: bound.address,
            port: assigned_port,
        }
    } else {
        bound
    }
}

/// Rejects a socklen before any remote read. The accepted length is not a payload size.
fn bounded_socklen(supplied: u64) -> Result<usize, NetworkDecodeError> {
    let supplied = usize::try_from(supplied).map_err(|_| NetworkDecodeError::InvalidEndpoint)?;
    if !(2..=MAX_REMOTE_READ).contains(&supplied) {
        return Err(NetworkDecodeError::InvalidEndpoint);
    }
    Ok(supplied)
}

/// Bytes to read from a sockaddr. This is the address struct, never `supplied` when it is larger.
fn sockaddr_read_len(supplied: usize, family: u16) -> Result<usize, NetworkDecodeError> {
    let need = sockaddr_len(family).ok_or(NetworkDecodeError::InvalidEndpoint)?;
    if supplied < need {
        return Err(NetworkDecodeError::InvalidEndpoint);
    }
    Ok(need)
}

/// Port from a `/proc/net/tcp` or `tcp6` table. The local address column is not parsed.
fn parse_proc_net_port(text: &str, inode: &str) -> Option<u16> {
    for line in text.lines().skip(1) {
        let columns: Vec<_> = line.split_ascii_whitespace().collect();
        if columns.len() > 9 && columns[9] == inode {
            let port = columns[1].rsplit_once(':')?.1;
            return u16::from_str_radix(port, 16).ok();
        }
    }
    None
}

fn syscall_outcome(return_value: i64, is_error: bool) -> Outcome {
    if is_error {
        Outcome::failure(i32::try_from(-return_value).ok(), None)
    } else {
        Outcome::success()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::io::Read;

    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{
        bounded_socklen, canonical_host, listen_endpoint, parse_proc_net_port, parse_sockaddr,
        recognize, sockaddr_read_len, syscall_outcome, Endpoint, NetSyscall, NetworkDecodeError,
        MAX_SOCKETS,
    };
    use crate::lineage::{SpawnStop, ThreadLineage};
    use crate::memory::read_remote_memory;
    use crate::syscall::{ObservedSyscall, SyscallStop};
    use drifti_observer::{NetworkProtocol, ObservedResource, Operation, Outcome};

    #[derive(Debug, Clone, Copy)]
    struct SocketState {
        protocol: NetworkProtocol,
        ipv6: bool,
        bound: Option<Endpoint>,
    }

    #[derive(Debug)]
    enum Pending {
        Ignored,
        Socket {
            domain: u64,
            kind: u64,
            protocol: u64,
        },
        Connect {
            fd: i32,
            endpoint: Endpoint,
        },
        Bind {
            fd: i32,
            endpoint: Endpoint,
        },
        Listen {
            fd: i32,
        },
        Close {
            fd: i32,
        },
        Dup {
            old: i32,
            new: Option<i32>,
        },
    }

    struct Inflight {
        number: u64,
        body: Pending,
    }

    /// A network fact ready for the execution-wide event emitter.
    ///
    /// The resource is an endpoint identity. It does not contain a payload.
    #[derive(Debug)]
    pub(crate) struct NetworkFact {
        pub(crate) tid: u32,
        pub(crate) operation: Operation,
        pub(crate) resource: ObservedResource,
        pub(crate) outcome: Outcome,
    }

    /// Decodes IP connect and listen facts from accepted syscall pairs.
    ///
    /// Feed every syscall stop in order. [`NetworkDecodeError::UnsupportedAbi`]
    /// degrades the Network domain. Any other error fails observation. Neither
    /// path is an empty success, and neither declares coverage `COMPLETE`.
    pub(crate) struct NetworkDecoder {
        pending: BTreeMap<u32, Inflight>,
        sockets: BTreeMap<(u32, i32), SocketState>,
        max_threads: usize,
    }

    impl NetworkDecoder {
        pub(crate) fn new(max_threads: usize) -> Self {
            Self {
                pending: BTreeMap::new(),
                sockets: BTreeMap::new(),
                max_threads,
            }
        }

        pub(crate) fn on_syscall(
            &mut self,
            stop: &SyscallStop,
            lineage: &ThreadLineage,
        ) -> Result<Vec<NetworkFact>, NetworkDecodeError> {
            match stop.observed() {
                ObservedSyscall::Entry => self.entry(stop, lineage),
                ObservedSyscall::Exit => self.exit(stop, lineage),
            }
        }

        /// Whether `tid` has a network syscall waiting for its exit.
        pub(crate) fn has_pending(&self, tid: u32) -> bool {
            self.pending.contains_key(&tid)
        }

        /// Drops an in-flight entry after the caller has already failed the gap closed.
        pub(crate) fn on_gap(&mut self, tid: u32) {
            self.pending.remove(&tid);
        }

        /// Copies IP sockets into a forked child.
        ///
        /// The spawn stop arrives before the child's tgid is read from `/proc`.
        /// A forked child's tid is that thread-group id. A clone thread shares
        /// the parent's table, which stays keyed by the parent tgid.
        pub(crate) fn on_spawn(
            &mut self,
            spawn: &SpawnStop,
            lineage: &ThreadLineage,
        ) -> Result<(), NetworkDecodeError> {
            let parent = group(lineage, spawn.parent);
            let child = group(lineage, spawn.child);
            if parent == child {
                return Ok(());
            }
            let inherited: Vec<_> = self
                .sockets
                .iter()
                .filter(|((id, _), _)| *id == parent)
                .map(|((_, fd), state)| (*fd, *state))
                .collect();
            for (fd, state) in inherited {
                self.insert_socket(child, fd, state)?;
            }
            Ok(())
        }

        fn entry(
            &mut self,
            stop: &SyscallStop,
            lineage: &ThreadLineage,
        ) -> Result<Vec<NetworkFact>, NetworkDecodeError> {
            let tid = stop.tid();
            let number = stop
                .number()
                .ok_or(NetworkDecodeError::PhaseMismatch { tid })?;
            let Some(kind) = recognize(cfg!(target_arch = "x86_64"), number)? else {
                return Ok(Vec::new());
            };
            if self.pending.contains_key(&tid) {
                return Err(NetworkDecodeError::PhaseMismatch { tid });
            }
            if self.pending.len() >= self.max_threads {
                return Err(NetworkDecodeError::Capacity);
            }
            let args = stop.args();
            let body = match kind {
                NetSyscall::Socket => Pending::Socket {
                    domain: args[0],
                    kind: args[1],
                    protocol: args[2],
                },
                NetSyscall::Connect | NetSyscall::Bind => {
                    self.address_pending(lineage, tid, args, kind)?
                }
                NetSyscall::Listen => Pending::Listen {
                    fd: fd_arg(args[0]),
                },
                NetSyscall::Close => Pending::Close {
                    fd: fd_arg(args[0]),
                },
                NetSyscall::Dup => Pending::Dup {
                    old: fd_arg(args[0]),
                    new: None,
                },
                NetSyscall::Dup2 | NetSyscall::Dup3 => Pending::Dup {
                    old: fd_arg(args[0]),
                    new: Some(fd_arg(args[1])),
                },
            };
            self.pending.insert(tid, Inflight { number, body });
            Ok(Vec::new())
        }

        fn address_pending(
            &mut self,
            lineage: &ThreadLineage,
            tid: u32,
            args: [u64; 6],
            kind: NetSyscall,
        ) -> Result<Pending, NetworkDecodeError> {
            let fd = fd_arg(args[0]);
            let tracked = self.sockets.contains_key(&(group(lineage, tid), fd));
            if !tracked {
                return Ok(Pending::Ignored);
            }
            let supplied = bounded_socklen(args[2])?;
            let family_bytes = read_remote_memory(group(lineage, tid), args[1], 2)
                .map_err(NetworkDecodeError::Remote)?;
            let family = u16::from_ne_bytes([family_bytes[0], family_bytes[1]]);
            let need = sockaddr_read_len(supplied, family)?;
            let bytes = read_remote_memory(group(lineage, tid), args[1], need)
                .map_err(NetworkDecodeError::Remote)?;
            let endpoint = parse_sockaddr(&bytes).ok_or(NetworkDecodeError::InvalidEndpoint)?;
            Ok(match kind {
                NetSyscall::Connect => Pending::Connect { fd, endpoint },
                _ => Pending::Bind { fd, endpoint },
            })
        }

        fn exit(
            &mut self,
            stop: &SyscallStop,
            lineage: &ThreadLineage,
        ) -> Result<Vec<NetworkFact>, NetworkDecodeError> {
            let tid = stop.tid();
            let number = stop.number().unwrap_or(0);
            let kind = recognize(cfg!(target_arch = "x86_64"), number)?;
            let Some(pending) = self.pending.remove(&tid) else {
                return match kind {
                    Some(_) => Err(NetworkDecodeError::PhaseMismatch { tid }),
                    None => Ok(Vec::new()),
                };
            };
            if stop.number() != Some(pending.number) {
                return Err(NetworkDecodeError::PhaseMismatch { tid });
            }
            let return_value = stop
                .return_value()
                .ok_or(NetworkDecodeError::PhaseMismatch { tid })?;
            let is_error = stop.is_error();
            let id = group(lineage, tid);
            match pending.body {
                Pending::Ignored => Ok(Vec::new()),
                Pending::Socket {
                    domain,
                    kind,
                    protocol,
                } => {
                    self.finish_socket(id, domain, kind, protocol, return_value, is_error)?;
                    Ok(Vec::new())
                }
                Pending::Connect { fd, endpoint } => {
                    let Some(state) = self.sockets.get(&(id, fd)) else {
                        return Ok(Vec::new());
                    };
                    Ok(vec![fact(
                        tid,
                        Operation::NetworkConnect,
                        state.protocol,
                        endpoint,
                        return_value,
                        is_error,
                    )?])
                }
                Pending::Bind { fd, endpoint } => {
                    if is_error {
                        return Ok(Vec::new());
                    }
                    if let Some(state) = self.sockets.get_mut(&(id, fd)) {
                        state.bound = Some(endpoint);
                    }
                    Ok(Vec::new())
                }
                Pending::Listen { fd } => self.finish_listen(tid, id, fd, return_value, is_error),
                Pending::Close { fd } => {
                    if !is_error {
                        self.sockets.remove(&(id, fd));
                    }
                    Ok(Vec::new())
                }
                Pending::Dup { old, new } => {
                    self.finish_dup(id, old, new, return_value, is_error)?;
                    Ok(Vec::new())
                }
            }
        }

        fn finish_socket(
            &mut self,
            group_id: u32,
            domain: u64,
            kind: u64,
            protocol: u64,
            return_value: i64,
            is_error: bool,
        ) -> Result<(), NetworkDecodeError> {
            if is_error {
                return Ok(());
            }
            let fd =
                i32::try_from(return_value).map_err(|_| NetworkDecodeError::InvalidEndpoint)?;
            let ipv6 = domain == libc::AF_INET6 as u64;
            let ip = domain == libc::AF_INET as u64 || ipv6;
            let transport = if ip { transport(kind, protocol) } else { None };
            if let Some(protocol) = transport {
                self.insert_socket(
                    group_id,
                    fd,
                    SocketState {
                        protocol,
                        ipv6,
                        bound: None,
                    },
                )?;
            } else {
                self.sockets.remove(&(group_id, fd));
            }
            Ok(())
        }

        fn finish_listen(
            &mut self,
            tid: u32,
            group_id: u32,
            fd: i32,
            return_value: i64,
            is_error: bool,
        ) -> Result<Vec<NetworkFact>, NetworkDecodeError> {
            let Some(state) = self.sockets.get(&(group_id, fd)).copied() else {
                return Ok(Vec::new());
            };
            if state.protocol != NetworkProtocol::Tcp {
                return Ok(Vec::new());
            }
            let endpoint = match state.bound {
                Some(bound) if bound.port == 0 && !is_error => {
                    listen_endpoint(bound, kernel_listen_port(group_id, fd, state.ipv6)?)
                }
                Some(bound) if bound.port != 0 => bound,
                None if !is_error => Endpoint {
                    address: if state.ipv6 {
                        Ipv6Addr::UNSPECIFIED.into()
                    } else {
                        Ipv4Addr::UNSPECIFIED.into()
                    },
                    port: kernel_listen_port(group_id, fd, state.ipv6)?,
                },
                _ => return Err(NetworkDecodeError::InvalidEndpoint),
            };
            if endpoint.port == 0 {
                return Err(NetworkDecodeError::InvalidEndpoint);
            }
            Ok(vec![fact(
                tid,
                Operation::NetworkListen,
                state.protocol,
                endpoint,
                return_value,
                is_error,
            )?])
        }

        fn finish_dup(
            &mut self,
            group_id: u32,
            old: i32,
            new: Option<i32>,
            return_value: i64,
            is_error: bool,
        ) -> Result<(), NetworkDecodeError> {
            if is_error {
                return Ok(());
            }
            let target = match new {
                Some(fd) => fd,
                None => {
                    i32::try_from(return_value).map_err(|_| NetworkDecodeError::InvalidEndpoint)?
                }
            };
            if old == target {
                return Ok(());
            }
            if new.is_some() {
                self.sockets.remove(&(group_id, target));
            }
            if let Some(state) = self.sockets.get(&(group_id, old)).copied() {
                self.insert_socket(group_id, target, state)?;
            }
            Ok(())
        }

        fn insert_socket(
            &mut self,
            group_id: u32,
            fd: i32,
            state: SocketState,
        ) -> Result<(), NetworkDecodeError> {
            let key = (group_id, fd);
            if !self.sockets.contains_key(&key) && self.sockets.len() >= MAX_SOCKETS {
                return Err(NetworkDecodeError::Capacity);
            }
            self.sockets.insert(key, state);
            Ok(())
        }
    }

    fn group(lineage: &ThreadLineage, tid: u32) -> u32 {
        lineage
            .record(tid)
            .and_then(|record| record.tgid())
            .unwrap_or(tid)
    }

    fn fd_arg(raw: u64) -> i32 {
        raw as i32
    }

    fn transport(kind: u64, protocol: u64) -> Option<NetworkProtocol> {
        let kind = kind & 0xf;
        match (kind, protocol) {
            (value, 0) if value == libc::SOCK_STREAM as u64 => Some(NetworkProtocol::Tcp),
            (value, 0) if value == libc::SOCK_DGRAM as u64 => Some(NetworkProtocol::Udp),
            (value, proto)
                if value == libc::SOCK_STREAM as u64 && proto == libc::IPPROTO_TCP as u64 =>
            {
                Some(NetworkProtocol::Tcp)
            }
            (value, proto)
                if value == libc::SOCK_DGRAM as u64 && proto == libc::IPPROTO_UDP as u64 =>
            {
                Some(NetworkProtocol::Udp)
            }
            _ => None,
        }
    }

    fn fact(
        tid: u32,
        operation: Operation,
        protocol: NetworkProtocol,
        endpoint: Endpoint,
        return_value: i64,
        is_error: bool,
    ) -> Result<NetworkFact, NetworkDecodeError> {
        let resource = ObservedResource::network_with_protocol(
            protocol,
            canonical_host(endpoint.address),
            endpoint.port,
        )
        .map_err(|_| NetworkDecodeError::InvalidEndpoint)?;
        Ok(NetworkFact {
            tid,
            operation,
            resource,
            outcome: syscall_outcome(return_value, is_error),
        })
    }

    fn kernel_listen_port(group_id: u32, fd: i32, ipv6: bool) -> Result<u16, NetworkDecodeError> {
        let link = std::fs::read_link(format!("/proc/{group_id}/fd/{fd}")).map_err(proc_error)?;
        let name = link.to_str().ok_or(NetworkDecodeError::InvalidEndpoint)?;
        let inode = name
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
            .ok_or(NetworkDecodeError::InvalidEndpoint)?;
        let table = if ipv6 { "tcp6" } else { "tcp" };
        let file =
            std::fs::File::open(format!("/proc/{group_id}/net/{table}")).map_err(proc_error)?;
        const MAX_PROC_NET: u64 = 1_048_576;
        let mut bytes = Vec::new();
        file.take(MAX_PROC_NET + 1)
            .read_to_end(&mut bytes)
            .map_err(proc_error)?;
        if bytes.len() as u64 > MAX_PROC_NET {
            return Err(NetworkDecodeError::InvalidEndpoint);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| NetworkDecodeError::InvalidEndpoint)?;
        parse_proc_net_port(text, inode).ok_or(NetworkDecodeError::InvalidEndpoint)
    }

    fn proc_error(error: std::io::Error) -> NetworkDecodeError {
        NetworkDecodeError::Proc {
            errno: error.raw_os_error().unwrap_or(0),
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::NetworkDecoder;

#[cfg(test)]
mod tests {
    use super::{
        bounded_socklen, canonical_host, listen_endpoint, parse_proc_net_port, parse_sockaddr,
        recognize, sockaddr_len, sockaddr_read_len, syscall_outcome, Endpoint, NetSyscall,
        NetworkDecodeError, MAX_REMOTE_READ, X86_64_CONNECT, X86_64_LISTEN,
    };
    use drifti_observer::{
        EvidenceMeta, ExecutionId, MonotonicTimestamp, NetworkProtocol, ObservedEvent,
        ObservedResource, Operation, Outcome, ProcessIdentity,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn decode_ipv4_and_ipv6_without_hostname_guessing() {
        let v4 = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let parsed = parse_sockaddr(&v4).unwrap();
        assert_eq!(parsed.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(parsed.port, 8080);
        assert_eq!(canonical_host(parsed.address), "127.0.0.1");
        assert_ne!(canonical_host(parsed.address), "localhost");
        let mut v6 = [0u8; 28];
        v6[0] = 10;
        v6[3] = 53;
        v6[23] = 1;
        let parsed = parse_sockaddr(&v6).unwrap();
        assert_eq!(parsed.address, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(parsed.port, 53);
        assert_eq!(canonical_host(parsed.address), "::1");
        assert_ne!(canonical_host(parsed.address), "localhost");
        assert_eq!(sockaddr_len(1), None);
        assert_eq!(parse_sockaddr(&v4[..8]), None);
    }

    #[test]
    fn sockaddr_identity_is_protocol_address_and_port() {
        let endpoint =
            parse_sockaddr(&[2, 0, 0x00, 0x50, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let host = canonical_host(endpoint.address);
        let resource =
            ObservedResource::network_with_protocol(NetworkProtocol::Tcp, host, endpoint.port)
                .unwrap();
        match resource {
            ObservedResource::Network {
                protocol: Some(NetworkProtocol::Tcp),
                host,
                port,
            } => {
                assert_eq!(host, "1.2.3.4");
                assert_eq!(port, 80);
                assert_ne!(host, "localhost");
            }
            other => panic!("unexpected resource {other:?}"),
        }
    }

    #[test]
    fn listen_keeps_the_bind_address_when_the_port_is_assigned() {
        let bound = Endpoint {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
        };
        let endpoint = listen_endpoint(bound, 8080);
        assert_eq!(canonical_host(endpoint.address), "127.0.0.1");
        assert_eq!(endpoint.port, 8080);
        let explicit = listen_endpoint(
            Endpoint {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: 9,
            },
            8080,
        );
        assert_eq!(canonical_host(explicit.address), "10.0.0.1");
        assert_eq!(explicit.port, 9);
    }

    #[test]
    fn proc_net_supplies_a_port_and_not_a_hostname() {
        let text = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
";
        assert_eq!(parse_proc_net_port(text, "12345"), Some(8080));
        assert_eq!(parse_proc_net_port(text, "999"), None);
    }

    #[test]
    fn oversized_socklen_is_rejected_before_a_remote_read() {
        assert!(bounded_socklen(0).is_err());
        assert!(bounded_socklen(1).is_err());
        assert_eq!(bounded_socklen(16).unwrap(), 16);
        assert_eq!(
            bounded_socklen(MAX_REMOTE_READ as u64).unwrap(),
            MAX_REMOTE_READ
        );
        assert!(bounded_socklen((MAX_REMOTE_READ as u64) + 1).is_err());
        assert_eq!(sockaddr_read_len(128, 2).unwrap(), 16);
        assert_eq!(sockaddr_read_len(128, 10).unwrap(), 28);
        assert!(sockaddr_read_len(8, 2).is_err());
        assert!(sockaddr_read_len(16, 1).is_err());
    }

    #[test]
    fn non_x86_64_network_table_is_not_an_empty_success() {
        let error = recognize(false, X86_64_CONNECT).unwrap_err();
        assert!(matches!(error, NetworkDecodeError::UnsupportedAbi));
        let text = error.to_string();
        assert!(!text.to_ascii_lowercase().contains("complete"));
        assert!(!text.contains("localhost"));
        assert_eq!(
            recognize(true, X86_64_CONNECT).unwrap(),
            Some(NetSyscall::Connect)
        );
        assert_eq!(
            recognize(true, X86_64_LISTEN).unwrap(),
            Some(NetSyscall::Listen)
        );
        assert!(recognize(true, 1).unwrap().is_none());
    }

    #[test]
    fn failed_connect_outcome_is_attempted_and_not_exercised() {
        let outcome = syscall_outcome(-111, true);
        let resource =
            ObservedResource::network_with_protocol(NetworkProtocol::Tcp, "127.0.0.1", 0).unwrap();
        let event = ObservedEvent::new(
            ExecutionId::from_raw(50),
            0,
            MonotonicTimestamp::from_nanos(0),
            ProcessIdentity::new(Some(1), Some(1)),
            None,
            Operation::NetworkConnect,
            resource,
            outcome,
            EvidenceMeta::empty(),
        );
        assert!(event.was_attempted());
        assert!(!event.was_exercised());
        assert_eq!(event.evidence().byte_length(), None);
        assert!(matches!(
            event.outcome(),
            Outcome::Failure {
                errno: Some(111),
                ..
            }
        ));
        assert_eq!(syscall_outcome(0, false), Outcome::success());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn network_exit_without_entry_is_a_decode_error() {
        use super::{NetworkDecoder, X86_64_CLOSE};
        use crate::lineage::ThreadLineage;
        use crate::syscall::SyscallStop;

        let mut decoder = NetworkDecoder::new(4);
        let lineage = ThreadLineage::new(ExecutionId::from_raw(1), 4, 4);
        let close = SyscallStop::exit(7, Some(X86_64_CLOSE), 0, false);
        let error = decoder.on_syscall(&close, &lineage).unwrap_err();
        assert!(matches!(
            error,
            NetworkDecodeError::PhaseMismatch { tid: 7 }
        ));
        let write = SyscallStop::exit(7, Some(1), 0, false);
        assert!(decoder.on_syscall(&write, &lineage).unwrap().is_empty());
    }

    #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
    #[test]
    fn decoder_rejects_non_x86_64_instead_of_empty_success() {
        use super::NetworkDecoder;
        use crate::lineage::ThreadLineage;
        use crate::syscall::SyscallStop;

        let mut decoder = NetworkDecoder::new(4);
        let lineage = ThreadLineage::new(ExecutionId::from_raw(1), 4, 4);
        let stop = SyscallStop::exit(7, Some(X86_64_CONNECT), -1, true);
        let error = decoder.on_syscall(&stop, &lineage).unwrap_err();
        assert!(matches!(error, NetworkDecodeError::UnsupportedAbi));
    }
}
