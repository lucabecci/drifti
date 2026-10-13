// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Controlled loopback networking fixture for ptrace integration tests.

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};

fn main() {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let address = listener.local_addr().expect("local address");
    let stream = TcpStream::connect(address).expect("connect");
    let (accepted, _) = listener.accept().expect("accept");
    drop((accepted, stream));
    // Port zero is an invalid destination on Linux. This attempted connection
    // must remain an attempted, not an exercised, network capability.
    assert!(TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).is_err());
}
