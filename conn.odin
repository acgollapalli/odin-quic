package quic

import "core:sync"

Connection_Id :: union {
    uuid.UUID,
    []u8
}

Connection_State :: enum {
    New,
    Address_Validation,
    Address_Valid,
    Handshake,
    Secured
}

// FIXME: You should be able to configure these
// somehow, maybe in your make_conn method
Conn :: struct {
    socket: net.Any_Socket // This is probably not right
    send_limit: u64, // number of bytes allowed through
    receive_limit: u64, // number of bytes allowed through
    data_received: u64, // number of bytes gone through
    data_sent: u64, // number of bytes gone through
    authenticated_packets_sent: u64,
    crypto_packets_sent: u64, // THESE ARE SUPPOSED TO BE DIFFERENT PACKET NUMBER SPACES
    datagram_packets_sent: u64,
    initial_packets_sent: u64,
    handshake_packets_sent: u64,
    retry_token: [16]byte
    version: Supported_Version,
    role: Role,
    streams: []Stream,     // Does conn-level limit aapply to datagram streams too? (RFC9000.4.1)
    flow_enabled: bool,
    spin_enabled: bool, // enables latency tracking in 1-rtt streams
    source_conn_ids: []Connection_Id, 
    destination_conn_ids: []Connection_Id,
    lock: sync.Mutex // FIXME: I think we could use a futex here? or atomics
    encryption: Encryption_Context
}

// TODO: 
Conn_Config :: struct {
}

Unmatched_Packet :: struct {
    packet: []byte,
    conn_id: []byte
    timestamp: time.Time
}

