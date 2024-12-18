/*

 SDG                                                                           JJ

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

Path_Validation_State :: enum {
	Validating,
	Valid,
}

/*
  Connection Parameters

  Not every parameter will be supported for each role.
  FIXME: Add documentation for each of the parameters
*/
Connection_Params :: struct {
	original_destination_connection_id:  Connection_Id,
	max_idle_timeout:                    time.Duration,
	stateless_reset_token:               u128,
	max_udp_payload_size:                u64,
	initial_max_data:                    u64,
	initial_max_stream_data_bidi_local:  u64,
	initial_max_stream_data_bidi_remote: u64,
	initial_max_stream_data_uni:         u64,
	initial_max_streams_bidi:            u64,
	initial_max_streams_uni:             u64,
	ack_delay_exponent:                  u64,
	max_ack_delay:                       time.Duration,
	disable_active_migration:            bool,
	preferred_address:                   net.Endpoint,
	active_connection_id_limit:          u64,
	initial_source_connection_id:        Connection_Id,
	retry_source_connection_id:          Connection_Id,
	version_information:                 Supported_Version,
	max_datagram_frame_size:             u64,
	grease_quic_bit:                     bool,
}

/*
  We can retain Congestion Control state when the address stays the
  same, however we still need to do path validation when the port
  changes.

  On Reconnect, only the Address needs to be validated, not the port.
  TODO: Should we add a timer here, or manage timers separately?

  Laytan kindly included some timer utils in his http package,
  but IDK if we should use those. There's a path timer on the path 
  as well
*/
Path :: struct {
	endpoint: net.Endpoint,
	rtt:      ^RTT_State,
	ecc:      ^ECC_State,
	timeout:  ^Timer_State,
	valid:    Path_Validation_State,
}

Paths :: map[net.Endpoint]Path


// FIXME: You should be able to configure these
// somehow, maybe in your make_conn method
Conn :: struct {
	//generation: u32,
	// These should be replaced with tracking on connection_params
	send_max_data:                 u64, // number of bytes allowed through
	receive_max_data:              u64, // number of bytes allowed through
	host_params:                   Connection_Params,
	peer_params:                   Connection_Params,
	data_received:                 u64, // number of bytes gone through
	data_sent:                     u64, // number of bytes gone through
	initial_packets_sent:          u64,
	handshake_packets_sent:        u64,
	application_packets_sent:      u64,
	version:                       Supported_Version,
	role:                          Role,
	flow_enabled:                  bool,
	spin_enabled:                  bool, // latency tracking in 1-rtt streams
	retry_received:                bool,
	source_conn_ids:               Connection_Ids,
	dest_conn_ids:                 Connection_Ids,
	state:                         Connection_State,
	path_challenge:                [dynamic]u64,

	// Begin Stream State
	// Need to move these to their own struct
	locally_initiated_streams_uni: [dynamic]Stream,
	remote_initiated_streams_uni:  [dynamic]Stream,
	locally_initiated_streams_bi:  [dynamic]Stream,
	remote_initiated_streams_bi:   [dynamic]Stream,
	max_local_streams_limit_uni:   u64,
	max_remote_streams_limit_uni:  u64,
	max_local_streams_limit_bi:    u64,
	max_remote_streams_limit_bi:   u64,
	// end stream state
	lock:                          sync.RW_Mutex,
	encryption:                    Encryption_Context,
	paths:                         Paths,
	acks:                          Ack_State,
	send:                          Send_State,
	endpoint:                      net.Endpoint,
}

Send_State :: [Packet_Number_Space]struct {
	lock:          sync.Mutex,
	queue:         [dynamic]^Frame, // TODO: swap for ring buffer
	crypto:        [4096]u8,
	ack:           [dynamic]u64,
	ack_elicited:  bool,
	crypto_len:    uint,
	crypto_flush:  bool,
	packet_number: u64,
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

// TODO implement connection_close that free's all RTT and ECC state
