/*
 * SDG                                                                         JJ
 */

package quic

import "core:sync"

Stream_Id :: distinct u64

Stream :: union {
	Sending_Stream,
	Receiving_Stream,
	Bidirectional_Stream,
}

Sending_Stream :: struct {
	id:            u64,
	max_data:      u64,
	sending_state: Sending_Stream_State,
	bytes_sent:    u64,
	buffer:        []u8,
	err:           u64,
}

Receiving_Stream :: struct {
	id:              u64,
	max_data:        u64, // FIXME: Version 1 only allows limits in a 62 bit uu64
	receiving_state: Receiving_Stream_State,
	bytes_received:  u64,
	bytes_read:      u64,
	buffer:          []u8,
	err:             u64,
}

Unidirectional_Stream :: struct {}

Bidirectional_Stream :: struct {
	id:               u64,
	send_max_data:    u64,
	receive_max_data: u64,
	sending_state:    Sending_Stream_State,
	receiving_state:  Receiving_Stream_State,
	bytes_read:       u64,
	bytes_written:    u64,
	receive_buffer:   []u8,
	send_buffer:      []u8,
	err:              u64,
}

Flow: union {
	Datagram_flow,
}

Datagram_flow :: struct {
	id: u64,
}

Stream_Type :: enum {
	Bidirectional,
	Unidirectional,
}

// from suggestion in RFC 9000.3.1
Sending_Stream_State :: enum {
	Ready,
	Send,
	Data_Sent,
	Reset_Sent,
	Data_Received,
	Reset_Received,
}

// from suggestion in RFC 9000.3.2
Receiving_Stream_State :: enum {
	Receiving,
	Size_Known,
	Data_Received,
	Reset_Received,
	Data_Read,
	Reset_Read,
}


stream_id_bits :: proc(
	stream_type: Stream_Type,
	stream_initiator: Role,
) -> int {
	return (int(stream_type) << 1) | int(stream_initiator)
}

//create_stream :: proc(id: int, stream_type: Stream_Type, stream_initiator: Stream_Initiator) -> Stream 
//
//accept_stream :: proc() -> Stream
//close_stream :: proc()
//read_stream :: proc()
//write_stream :: proc()
//reset_stream :: proc()
//
//
///*
// * A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames 
// * that do not increase flow control limits.
// */
//adjust_limits :: proc() // Senders cannot have their limits lowered, only raised RFC9000.4.2
//
///*
// * A receiver MUST close the connection with an error of type
// * FLOW_CONTROL_ERROR if the sender violates the advertised connection 
// * or stream data limits; see Section 11 for details on error handling.
// */
//check_overage :: proc() -> Transport_Error // receivers must close stream with error FLOW_CONTROL_ERROR RFC9000.4.2 
//
///*
// * If a sender has sent data up to the limit, it will be unable to 
// * send new data and is considered blocked. A sender SHOULD send a 
// * STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the 
// * receiver that it has data to write but is blocked by flow control 
// * limits. If a sender is blocked for a period longer than the idle 
// * timeout (Section 10.1), the receiver might close the connection 
// * even when the sender has data that is available for transmission. 
// * To keep the connection from closing, a sender that is flow control 
// * limited SHOULD periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED 
// * frame when it has no ack-eliciting packets in flight
//*/
//handle_blocked :: proc(stream: Stream)

// will initialize streams as requested by remote, provided that they are within configured limits
// will NOT initialize streams for locally initiated streams, but will instead return nil and a
// Transport Error.
get_stream :: proc(conn: ^Conn, stream_id: u64) -> (^Stream, Transport_Error) {
	if stream_id > (u64(2) << 62 - 1) do return nil, .STREAM_STATE_ERROR

	// TODO: make sure this is a-ok, since we're outside of this function
	// FIXME: Actually, add guards to the callers of this function
	sync.guard(&conn.lock)

	last_bit := stream_id & 0x01
	initiator: Role
	if last_bit == 0 do initiator = .Client
	else do initiator = .Server

	dir_bit := stream_id & 0x02
	stream_type: Stream_Type
	if dir_bit == 0 do stream_type = .Bidirectional
	else do stream_type = .Unidirectional

	stream_index := stream_id >> 2

	if initiator == conn.role {
		s: ^[dynamic]Stream

		switch stream_type {
		case .Bidirectional:
			s = &conn.locally_initiated_streams_bi
		case .Unidirectional:
			s = &conn.locally_initiated_streams_uni
		}

		if u64(len(s)) <= stream_index do return nil, .STREAM_STATE_ERROR
		else do return &s[stream_index], nil
	} else {
		s: ^[dynamic]Stream
		max: u64
		switch stream_type {
		case .Bidirectional:
			s = &conn.remote_initiated_streams_bi
			max = conn.max_remote_streams_limit_bi
		case .Unidirectional:
			s = &conn.remote_initiated_streams_uni
			max = conn.max_remote_streams_limit_uni
		}

		if stream_index > max do return nil, .STREAM_STATE_ERROR

		if u64(len(s)) <= stream_index {
			if err := reserve(s, int(stream_id >> 2 - 1)); err == nil {
				return &s[stream_index], nil
			} else {
				return nil, .STREAM_LIMIT_ERROR
			}
		} else do return &s[stream_index], nil
	}

}

init_stream :: proc(
	conn: ^Conn,
	bidirectional: bool,
) -> (
	stream_id: Stream_Id,
	ok: bool,
) {
	s: ^[dynamic]Stream
	ms: ^u64

	if bidirectional {
		s = &conn.locally_initiated_streams_bi
		ms = &conn.max_local_streams_limit_bi
	} else {
		s = &conn.locally_initiated_streams_uni
		ms = &conn.max_local_streams_limit_uni
	}

	can_add: bool
	{
		sync.shared_guard(&conn.lock)
		// FIXME: we can't just have an array of max(u64) streams
		// that WILL break
		can_add = len(s) < int(ms^)
	}

	can_add or_return

	b: Stream = bidirectional ? Bidirectional_Stream{} : Sending_Stream{}
	{
		sync.guard(&conn.lock)
		append(s, b)
		stream_id = Stream_Id(len(s))
	}
	stream_id <<= 2
	stream_id &= 1
	if !bidirectional do stream_id &= 2
	return

}
