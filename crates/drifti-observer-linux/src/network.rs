// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network syscall decoder. Socket state is execution scoped; sockaddr bytes
//! are read only while the tracee is stopped and never retained in an event.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address obtained directly from an AF_INET or AF_INET6 sockaddr.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    address: IpAddr,
    port: u16,
}

/// Minimum bytes needed after reading the two-byte address family.
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

#[cfg(target_os = "linux")]
mod linux {
    use drifti_observer::{NetworkProtocol, ObservedResource, Operation, Outcome};
    use std::collections::BTreeMap;
    use std::io::Read;

    use super::{parse_sockaddr, sockaddr_len, Endpoint};
    use crate::{read_remote_memory, ObservedSyscall, ThreadLineage, TraceError, TraceStop};

    #[derive(Debug, Clone)]
    struct SocketState {
        protocol: NetworkProtocol,
        ipv6: bool,
        bound: Option<Endpoint>,
    }

    #[derive(Debug)]
    enum Pending {
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

    /// A network fact ready for the execution-wide event emitter.
    pub(crate) struct NetworkFact {
        pub(crate) tid: u32,
        pub(crate) operation: Operation,
        pub(crate) resource: ObservedResource,
        pub(crate) outcome: Outcome,
    }

    /// Decodes authoritative IP network facts from accepted syscall pairs.
    /// Unsupported socket families and protocols remain outside advertised
    /// complete coverage. A failed required read aborts observation.
    #[derive(Default)]
    pub(crate) struct NetworkDecoder {
        pending: BTreeMap<u32, Pending>,
        sockets: BTreeMap<(u32, i32), SocketState>,
    }

    impl NetworkDecoder {
        fn kernel_listen_port(group: u32, fd: i32, ipv6: bool) -> Result<u16, TraceError> {
            let link = std::fs::read_link(format!("/proc/{group}/fd/{fd}"))
                .map_err(|_| TraceError::Visitor)?;
            let name = link.to_str().ok_or(TraceError::Visitor)?;
            let inode = name
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .ok_or(TraceError::Visitor)?;
            let table = if ipv6 { "tcp6" } else { "tcp" };
            let file = std::fs::File::open(format!("/proc/{group}/net/{table}"))
                .map_err(|_| TraceError::Visitor)?;
            // A fixed cap prevents an unbounded /proc read. An oversized table
            // fails observation instead of silently losing this listener.
            const MAX_PROC_NET: u64 = 1_048_576;
            let mut bytes = Vec::new();
            file.take(MAX_PROC_NET + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| TraceError::Visitor)?;
            if bytes.len() as u64 > MAX_PROC_NET {
                return Err(TraceError::Visitor);
            }
            let text = std::str::from_utf8(&bytes).map_err(|_| TraceError::Visitor)?;
            for line in text.lines().skip(1) {
                let columns: Vec<_> = line.split_ascii_whitespace().collect();
                // /proc/net/tcp: local_address is column 1, inode is 9.
                if columns.len() > 9 && columns[9] == inode {
                    let port = columns[1].rsplit_once(':').ok_or(TraceError::Visitor)?.1;
                    return u16::from_str_radix(port, 16).map_err(|_| TraceError::Visitor);
                }
            }
            Err(TraceError::Visitor)
        }

        fn group(lineage: &ThreadLineage, tid: u32) -> u32 {
            lineage.record(tid).and_then(|r| r.tgid()).unwrap_or(tid)
        }

        fn enter(
            &mut self,
            tid: u32,
            number: u64,
            args: [u64; 6],
            lineage: &ThreadLineage,
        ) -> Result<(), TraceError> {
            let group = Self::group(lineage, tid);
            let fd = args[0] as i32;
            let pending = if number == libc::SYS_socket as u64 {
                Some(Pending::Socket {
                    domain: args[0],
                    kind: args[1],
                    protocol: args[2],
                })
            } else if number == libc::SYS_connect as u64 || number == libc::SYS_bind as u64 {
                if !self.sockets.contains_key(&(group, fd)) {
                    return Ok(());
                }
                // Reject a forged or enormous socklen before remote access.
                let supplied = usize::try_from(args[2]).map_err(|_| TraceError::Visitor)?;
                if !(2..=crate::MAX_REMOTE_READ).contains(&supplied) {
                    return Err(TraceError::Visitor);
                }
                let family_bytes =
                    read_remote_memory(group, args[1], 2).map_err(|_| TraceError::Visitor)?;
                let family = u16::from_ne_bytes([family_bytes[0], family_bytes[1]]);
                let Some(need) = sockaddr_len(family) else {
                    return Ok(());
                };
                if supplied < need {
                    return Err(TraceError::Visitor);
                }
                let bytes =
                    read_remote_memory(group, args[1], need).map_err(|_| TraceError::Visitor)?;
                let endpoint = parse_sockaddr(&bytes).ok_or(TraceError::Visitor)?;
                if number == libc::SYS_connect as u64 {
                    Some(Pending::Connect { fd, endpoint })
                } else {
                    Some(Pending::Bind { fd, endpoint })
                }
            } else if number == libc::SYS_listen as u64 {
                Some(Pending::Listen { fd })
            } else if number == libc::SYS_close as u64 {
                Some(Pending::Close { fd })
            } else if number == libc::SYS_dup as u64 {
                Some(Pending::Dup { old: fd, new: None })
            } else if number == libc::SYS_dup2 as u64 || number == libc::SYS_dup3 as u64 {
                Some(Pending::Dup {
                    old: fd,
                    new: Some(args[1] as i32),
                })
            } else {
                None
            };
            if let Some(pending) = pending {
                self.pending.insert(tid, pending);
            }
            Ok(())
        }

        fn exit(
            &mut self,
            tid: u32,
            return_value: i64,
            is_error: bool,
            lineage: &ThreadLineage,
        ) -> Result<Option<NetworkFact>, TraceError> {
            let Some(pending) = self.pending.remove(&tid) else {
                return Ok(None);
            };
            let group = Self::group(lineage, tid);
            match pending {
                Pending::Socket {
                    domain,
                    kind,
                    protocol,
                } => {
                    if !is_error
                        && (domain == libc::AF_INET as u64 || domain == libc::AF_INET6 as u64)
                    {
                        let transport = match (kind & 0xf, protocol) {
                            (x, 0) if x == libc::SOCK_STREAM as u64 => Some(NetworkProtocol::Tcp),
                            (x, 0) if x == libc::SOCK_DGRAM as u64 => Some(NetworkProtocol::Udp),
                            (x, y)
                                if x == libc::SOCK_STREAM as u64
                                    && y == libc::IPPROTO_TCP as u64 =>
                            {
                                Some(NetworkProtocol::Tcp)
                            }
                            (x, y)
                                if x == libc::SOCK_DGRAM as u64
                                    && y == libc::IPPROTO_UDP as u64 =>
                            {
                                Some(NetworkProtocol::Udp)
                            }
                            _ => None,
                        };
                        if let Some(protocol) = transport {
                            let fd =
                                i32::try_from(return_value).map_err(|_| TraceError::Visitor)?;
                            self.sockets.insert(
                                (group, fd),
                                SocketState {
                                    protocol,
                                    ipv6: domain == libc::AF_INET6 as u64,
                                    bound: None,
                                },
                            );
                        }
                    }
                }
                Pending::Connect { fd, endpoint } => {
                    if let Some(state) = self.sockets.get(&(group, fd)) {
                        return Self::fact(
                            tid,
                            Operation::NetworkConnect,
                            state.protocol,
                            endpoint,
                            return_value,
                            is_error,
                        )
                        .map(Some);
                    }
                }
                Pending::Bind { fd, endpoint } => {
                    if !is_error {
                        if let Some(state) = self.sockets.get_mut(&(group, fd)) {
                            state.bound = Some(endpoint);
                        }
                    }
                }
                Pending::Listen { fd } => {
                    if let Some(state) = self.sockets.get(&(group, fd)) {
                        if state.protocol == NetworkProtocol::Tcp {
                            let protocol = state.protocol;
                            let mut endpoint = match &state.bound {
                                Some(bound) => bound.clone(),
                                None if !is_error => Endpoint {
                                    address: if state.ipv6 {
                                        std::net::Ipv6Addr::UNSPECIFIED.into()
                                    } else {
                                        std::net::Ipv4Addr::UNSPECIFIED.into()
                                    },
                                    port: 0,
                                },
                                None => return Err(TraceError::Visitor),
                            };
                            if endpoint.port == 0 && !is_error {
                                // For an ephemeral bind, read the socket's
                                // actual local port by inode from procfs.
                                endpoint.port = Self::kernel_listen_port(group, fd, state.ipv6)?;
                            }
                            if endpoint.port == 0 {
                                return Err(TraceError::Visitor);
                            }
                            return Self::fact(
                                tid,
                                Operation::NetworkListen,
                                protocol,
                                endpoint,
                                return_value,
                                is_error,
                            )
                            .map(Some);
                        }
                    }
                }
                Pending::Close { fd } => {
                    if !is_error {
                        self.sockets.remove(&(group, fd));
                    }
                }
                Pending::Dup { old, new } => {
                    if !is_error {
                        let target = new.unwrap_or(
                            i32::try_from(return_value).map_err(|_| TraceError::Visitor)?,
                        );
                        if let Some(state) = self.sockets.get(&(group, old)).cloned() {
                            self.sockets.insert((group, target), state);
                        }
                    }
                }
            }
            Ok(None)
        }

        fn fact(
            tid: u32,
            operation: Operation,
            protocol: NetworkProtocol,
            endpoint: Endpoint,
            return_value: i64,
            is_error: bool,
        ) -> Result<NetworkFact, TraceError> {
            let resource = ObservedResource::network_with_protocol(
                protocol,
                endpoint.address.to_string(),
                endpoint.port,
            )
            .map_err(|_| TraceError::Visitor)?;
            let outcome = if is_error {
                Outcome::failure(i32::try_from(-return_value).ok(), None)
            } else {
                Outcome::success()
            };
            Ok(NetworkFact {
                tid,
                operation,
                resource,
                outcome,
            })
        }
        pub(crate) fn on_stop(
            &mut self,
            stop: &TraceStop,
            lineage: &ThreadLineage,
        ) -> Result<Option<NetworkFact>, TraceError> {
            match stop {
                TraceStop::Syscall(call) => match call.observed() {
                    ObservedSyscall::Entry => {
                        self.enter(
                            call.tid(),
                            call.number().ok_or(TraceError::Visitor)?,
                            call.args(),
                            lineage,
                        )?;
                        Ok(None)
                    }
                    ObservedSyscall::Exit => self.exit(
                        call.tid(),
                        call.return_value().ok_or(TraceError::Visitor)?,
                        call.is_error(),
                        lineage,
                    ),
                },
                TraceStop::Spawn(spawn) => {
                    let parent = Self::group(lineage, spawn.parent);
                    let child = Self::group(lineage, spawn.child);
                    if parent != child {
                        let inherited: Vec<_> = self
                            .sockets
                            .iter()
                            .filter(|((group, _), _)| *group == parent)
                            .map(|((_, fd), state)| (*fd, state.clone()))
                            .collect();
                        for (fd, state) in inherited {
                            self.sockets.insert((child, fd), state);
                        }
                    }
                    Ok(None)
                }
                TraceStop::ProcessExited { tid, .. } | TraceStop::ProcessSignaled { tid, .. } => {
                    self.pending.remove(tid);
                    Ok(None)
                }
                _ => Ok(None),
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::NetworkDecoder;

#[cfg(test)]
mod tests {
    use super::{parse_sockaddr, sockaddr_len};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn decode_ipv4_and_ipv6_without_hostname_guessing() {
        let v4 = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_sockaddr(&v4).unwrap().address,
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(parse_sockaddr(&v4).unwrap().port, 8080);
        let mut v6 = [0u8; 28];
        v6[0] = 10;
        v6[3] = 53;
        v6[23] = 1;
        assert_eq!(
            parse_sockaddr(&v6).unwrap().address,
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(parse_sockaddr(&v6).unwrap().port, 53);
        assert_eq!(sockaddr_len(1), None);
        assert_eq!(parse_sockaddr(&v4[..8]), None);
    }
}
