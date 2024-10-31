package quic

import "core:uuid"

Connection_Id :: uuid.UUID

// FIXME: You should be able to configure these
// somehow, maybe in your make_conn method
Conn :: struct {
    socket: net.Any_Socket // This is probably not right
    limit: int,
    streams: []Stream,     // Does conn-level limit aapply to datagram streams too? (RFC9000.4.1)
    flows: []Flow,
    flow_enabled: bool,
    spin_enabled: bool, // enables latency tracking in 1-rtt streams
    source_conn_ids: []Connection_Id, 
    destination_conn_ids: []Connection_Id,
}

// TODO: 
Conn_Config :: struct {
}


