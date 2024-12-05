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
	Closing,
	Draining,
}

Connection_Ids :: #soa[]Connection_Id_St

Packet_Number_Space_State :: struct {} // TODO implement maybe

// FIXME: You should be able to configure these
// somehow, maybe in your make_conn method
Conn :: struct {
	//socket:                     net.Any_Socket, // This is probably not right
	send_max_data:                 u64, // number of bytes allowed through
	receive_max_data:              u64, // number of bytes allowed through
	data_received:                 u64, // number of bytes gone through
	data_sent:                     u64, // number of bytes gone through
	initial_packets_sent:          u64,
	handshake_packets_sent:        u64,
	application_packets_sent:      u64,
	version:                       Supported_Version,
	role:                          Role,
	locally_initiated_streams_uni: [dynamic]Stream,
	remote_initiated_streams_uni:  [dynamic]Stream,
	locally_initiated_streams_bi:  [dynamic]Stream,
	remote_initiated_streams_bi:   [dynamic]Stream,
	max_local_streams_limit_uni:   u64,
	max_remote_streams_limit_uni:  u64,
	max_local_streams_limit_bi:    u64,
	max_remote_streams_limit_bi:   u64,
	retry_received:                bool,
	flow_enabled:                  bool,
	spin_enabled:                  bool, // enables latency tracking in 1-rtt streams
	source_conn_ids:               Connection_Ids,
	dest_conn_ids:                 Connection_Ids,
	lock:                          sync.Mutex, // FIXME: I think we could use a futex here? or atomics
	encryption:                    Encryption_Context,
	state:                         Connection_State,
	path_challenge:                [dynamic]u64,
	send_queue:                    [dynamic]Frame,
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
