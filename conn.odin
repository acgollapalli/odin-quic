/*
 * SDG                                                                         JJ
 */

package quic

import "core:encoding/uuid"
import "core:net"
import "core:sync"
import "core:time"

Connection_Id :: []u8

Connection_Id_St :: struct {
	value:           Connection_Id,
	sequence_number: u64,
	valid:           bool,
	used:            bool,
}

Connection_State :: enum {
	New,
	Address_Validation,
	Address_Valid,
	Handshake,
	Secured,
}

Connection_Ids :: #soa[]Connection_Id_St

// FIXME: You should be able to configure these
// somehow, maybe in your make_conn method
Conn :: struct {
	socket:                     net.Any_Socket, // This is probably not right
	send_limit:                 u64, // number of bytes allowed through
	receive_limit:              u64, // number of bytes allowed through
	data_received:              u64, // number of bytes gone through
	data_sent:                  u64, // number of bytes gone through
	authenticated_packets_sent: u64,
	crypto_packets_sent:        u64, // THESE ARE SUPPOSED TO BE DIFFERENT PACKET NUMBER SPACES
	datagram_packets_sent:      u64,
	initial_packets_sent:       u64,
	handshake_packets_sent:     u64,
	retry_token:                [16]byte,
	version:                    Supported_Version,
	role:                       Role,
	streams:                    []Stream, // Does conn-level limit aapply to datagram streams too? (RFC9000.4.1)
	flow_enabled:               bool,
	spin_enabled:               bool, // enables latency tracking in 1-rtt streams
	source_conn_ids:            Connection_Ids,
	dest_conn_ids:              Connection_Ids,
	lock:                       sync.Mutex, // FIXME: I think we could use a futex here? or atomics
	encryption:                 Encryption_Context,
}

// TODO: 
Conn_Config :: struct {
	send_limit:    u64, // number of bytes allowed through
	receive_limit: u64, // number of bytes allowed through
	version:       Supported_Version,
	role:          Role,
	flow_enabled:  bool,
	spin_enabled:  bool, // enables latency tracking in 1-rtt streams
}

Unmatched_Packet :: struct {
	packet:    []byte,
	conn_id:   []byte,
	timestamp: time.Time,
}
