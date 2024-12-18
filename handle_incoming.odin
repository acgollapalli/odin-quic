/*

SDG                                                                           JJ

 */

package quic

import ssl "../ssl"
import "core:net"

// not implemented yet
VALIDATE_PATHS :: false // #config(VALIDATE_PATHS, true)

handle_incoming_packet :: proc(
	conn: Maybe(^Conn),
	packet: Packet,
	len_dg: int,
	peer: net.Endpoint,
) {
	if conn == nil {
		handle_new_state(conn, packet, len_dg, peer)

	} else if conn, ok := conn.?; ok {
		ack_eliciting: bool
		err: Transport_Error
		switch conn.state {
		case .New:
			// we only ever get here from the client side
			handle_new_state(conn, packet, len_dg, peer)
			return
		case .Address_Validation:
			conn.state = .Address_Valid
			fallthrough
		case .Address_Valid:
			switch p in packet {
			case Initial_Packet:
				ack_eliciting, err = handle_initial(conn, p, peer)
			case Handshake_Packet:
				ack_eliciting, err = handle_handshake(conn, p, peer)
			case Version_Negotiation_Packet:
				return // TODO: handle version negotiation
			case Retry_Packet:
				if conn.role == .Client && !conn.retry_received {
					handle_retry(conn, p, peer)
				}
				return
			case One_RTT_Packet:
				return
			case Zero_RTT_Packet:
				ack_eliciting, err = handle_zero_rtt(conn, p, peer)
			}
		case .Handshake:
			switch p in packet {
			case Initial_Packet:
				return
			case Handshake_Packet:
				ack_eliciting, err = handle_handshake(conn, p, peer)
			case Version_Negotiation_Packet:
				return
			case Retry_Packet:
				if conn.role == .Client && !conn.retry_received {
					err = handle_retry(conn, p, peer)
				}
			case One_RTT_Packet:
				return
			case Zero_RTT_Packet:
				ack_eliciting, err = handle_zero_rtt(conn, p, peer)
			}
		case .Secured:
			#partial switch p in packet {
			case One_RTT_Packet:
				ack_eliciting, err = handle_one_rtt(conn, p, peer)
			case:
				return
			}
		case .Closing:
			queue_close_conn(conn, nil)
		case .Draining:
			return
		}

		if err != nil {
			queue_ack(conn, packet, ack_eliciting)
		} else {
			handle_transport_error(conn, err)
		}
	}
}

handle_new_state :: proc(
	conn: Maybe(^Conn),
	packet: Packet,
	len_dg: int,
	peer: net.Endpoint,
) -> (
	ack_eliciting: bool,
	err: Transport_Error,
) {
	#partial switch p in packet {
	case Initial_Packet:
		c: ^Conn
		if conn, ok := conn.?; ok {
			c = conn
		} else if len_dg >= 1200 {
			c = create_conn(p, peer)
		}
		ack_eliciting, err := handle_initial(c, p, peer)
		if err != nil {
			close_conn(c, err) // maybe swap with handle_transport_error?
		} else {
			queue_ack(c, p, ack_eliciting)
		}

	case:
		// if a packet isn't an initial
		// and we don't have a connection for it
		// then jusd drop the packet
		return
	}
	return
}


handle_transport_error :: proc(conn: Maybe(^Conn), error: Transport_Error) {
	if conn, ok := conn.?; ok {
		close_conn(conn, error)
	}
}


queue_ack :: proc(conn: ^Conn, packet: Packet, ack_eliciting: bool) {
	assert(conn != nil, "Received nil conn")

	pkt_number: u32
	pn_space: Packet_Number_Space

	#partial switch p in packet {
	case Initial_Packet:
		pkt_number = p.packet_number
		pn_space = .Initial
	case Handshake_Packet:
		pkt_number = p.packet_number
		pn_space = .Handshake
	case Zero_RTT_Packet:
	// we don't get here unless we were able to actually decrypt
	// the packet.
	// and in THIS version we don't buffer it if we can't
	// decrypt it or we don't have keys
		pkt_number = p.packet_number
		pn_space = .Application
	case One_RTT_Packet:
		pkt_number = p.packet_number
		pn_space = .Application
		case:
		unreachable()

	}

}

queue_reset_stream :: proc(conn: ^Conn, stream_id: u64) {
	assert(false, "not implemented")
}

store_token :: proc(conn: ^Conn, token: []byte) {
	assert(false, "not implemented")
}

// add stream data to buffer for application to read
// data should go in index offset - bytes_read
// if len(stream_data) + offset - bytes_read  > len(stream_buffer)
buffer_stream :: proc(
	conn: ^Conn,
	stream: ^Stream, // FIXME: Make sure we have a lock when we get here
	offset: u64,
	stream_data: []byte,
) -> Transport_Error {
	#partial switch s in stream {
	case Receiving_Stream:
		stream_index := offset - s.bytes_read
		if stream_index + u64(len(stream_data)) > u64(len(s.buffer)) {
			return .STREAM_LIMIT_ERROR
		} else {
			for b, i in stream_data {
				s.buffer[stream_index + u64(i)] = b
			}
		}
	case Bidirectional_Stream:
		stream_index := offset - s.bytes_read
		if stream_index + u64(len(stream_data)) > u64(len(s.receive_buffer)) {
			return .STREAM_LIMIT_ERROR
		} else {
			for b, i in stream_data {
				s.receive_buffer[stream_index + u64(i)] = b
			}
		}
	}
	return nil
}

// remove all connection Ids from the connection Id array that
// that have a secquence number less than retire_prior_to
retire_connection_ids :: proc(
	conn: ^Conn,
	retire_prior_to: u64,
) -> Transport_Error {
	assert(false, "not implemented")
	return nil
}

// use the sequence number to check that the id isn't already added
// to the conn object. If it isn't, add the new connection_id, along
// with the statless reset token
// MAY also enqueue retire_connection_id frames
add_connection_id :: proc(
	conn: ^Conn,
	connection_id: []u8,
	stateless_reset_token: ^[16]u8,
) -> Transport_Error {
	assert(false, "not implemented")
	return nil

}

// checks that the sequence number is less than than the current
// seq number and that the conn_id for dest is greater than 0
remove_connection_ids :: proc(
	conn: ^Conn,
	seq_number: u64,
) -> Transport_Error {
	assert(false, "not implemented")
	return nil
}

queue_path_response :: proc(conn: ^Conn, data: u64) {
	assert(false, "not implemented")
}

handle_ack :: proc(
	conn: ^Conn,
	frame: ^Ack_Frame,
	packet_number_space: Packet_Number_Space,
) -> Transport_Error {
	assert(false, "handle_ack is not implemented")
	return nil
}

handle_initial :: proc(
	conn: ^Conn,
	packet: Initial_Packet,
	peer: net.Endpoint,
) -> (
	ack_eliciting: bool,
	err: Transport_Error,
) {
	for frame in packet.packet_payload {
		#partial switch f in frame.variant {
		case ^Padding_Frame:
			continue
		case ^Ping_Frame:
			ack_eliciting = true
		case ^Ack_Frame:
			err = handle_ack(conn, f, .Initial)
			if err != nil do return
		case ^Crypto_Frame:
			read_crypto_frame_data(conn, .Initial_Encryption, f)
			ack_eliciting = true
		case ^Connection_Close_Frame:
			conn.state = .Draining
			return
		case:
			err = .PROTOCOL_VIOLATION
			return
		}
	}
	return
}

handle_handshake :: proc(
	conn: ^Conn,
	packet: Handshake_Packet,
	peer: net.Endpoint,
) -> (
	ack_eliciting: bool,
	err: Transport_Error,
) {
	for frame in packet.packet_payload {
		#partial switch f in frame.variant {
		case ^Padding_Frame:
			continue
		case ^Ping_Frame:
			ack_eliciting = true
		case ^Ack_Frame:
			err = handle_ack(conn, f, .Handshake)
			if err != nil do return
		case ^Crypto_Frame:
			read_crypto_frame_data(conn, .Handshake_Encryption, f)
			ack_eliciting = true
		case ^Connection_Close_Frame:
			conn.state = .Draining
			return
		case:
			err = .PROTOCOL_VIOLATION
			return
		}
	}
	return
}

// client only 
handle_retry :: proc(
	conn: ^Conn,
	packet: Retry_Packet,
	peer: net.Endpoint,
) -> Transport_Error {
	assert(false, "not implemented")
	return nil

}

handle_zero_rtt :: proc(
	conn: ^Conn,
	packet: Zero_RTT_Packet,
	peer: net.Endpoint,
) -> (
	ack_eliciting: bool,
	err: Transport_Error,
) {
	for frame in packet.packet_payload {
		#partial switch f in frame.variant {
		case ^Ack_Frame,
		     ^Crypto_Frame,
		     ^New_Token_Frame,
		     ^Path_Response_Frame,
		     ^Handshake_Done_Frame:
			err = .PROTOCOL_VIOLATION
			return
		case:
			ack_eliciting ||= handle_app_level(conn, frame^, peer) or_return
		}
	}
	return
}

handle_one_rtt :: proc(
	conn: ^Conn,
	packet: One_RTT_Packet,
	peer: net.Endpoint,
) -> (
	ack_eliciting: bool,
	err: Transport_Error,
) {
	for frame in packet.packet_payload {
		ack_eliciting ||= handle_app_level(conn, frame^, peer) or_return
	}
	return
}

handle_app_level :: proc(
	conn: ^Conn,
	frame: Frame,
	peer: net.Endpoint,
) -> (
	ack_eliciting: bool,
	err: Transport_Error,
) {
	switch f in frame.variant {
	case ^Padding_Frame:
		return
	case ^Ping_Frame:
		ack_eliciting = true
	case ^Ack_Frame:
		err = handle_ack(conn, f, .Application)
		if err != nil do return
	case ^Reset_Stream_Frame:
		stream := get_stream(conn, f.stream_id) or_return
		switch &s in stream {
		case Sending_Stream:
			err = .STREAM_STATE_ERROR
			s.err = f.app_error_code
			return
		case Receiving_Stream:
			if s.receiving_state != .Reset_Received {
				s.receiving_state = .Reset_Received
				s.err = f.app_error_code
			}
		case Bidirectional_Stream:
			if s.receiving_state != .Reset_Received {
				s.receiving_state = .Reset_Received
				s.err = f.app_error_code
			}
		}
	case ^Stop_Sending_Frame:
		stream := get_stream(conn, f.stream_id) or_return
		switch &s in stream {
		case Sending_Stream:
			if s.sending_state != .Reset_Sent {
				s.err = f.app_error_code
				queue_reset_stream(conn, f.stream_id)
			}
		case Receiving_Stream:
			err = .STREAM_STATE_ERROR
			s.err = f.app_error_code
			return
		case Bidirectional_Stream:
			if s.sending_state != .Reset_Sent {
				s.err = f.app_error_code
				queue_reset_stream(conn, f.stream_id)
			}
		}
	case ^Crypto_Frame:
		read_crypto_frame_data(conn, .Handshake_Encryption, f)
		ack_eliciting = true
	case ^New_Token_Frame:
		if conn.role == .Client {
			store_token(conn, f.token)
		} else {
			err = .PROTOCOL_VIOLATION
			return
		}
		ack_eliciting = true
	case ^Stream_Frame:
		stream := get_stream(conn, f.stream_id) or_return

		offset: u64
		if f.has_offset {
			if offset > u64(2 << 62) - 1 {
				err = .FRAME_ENCODING_ERROR
				return
			}
			offset = f.offset
		} else do offset = 0

		err = buffer_stream(conn, stream, f.offset, f.stream_data)

		ack_eliciting = true
	case ^Max_Data_Frame:
		if f.max_data > conn.send_max_data {
			conn.send_max_data = f.max_data
		}
		ack_eliciting = true
	case ^Max_Stream_Data_Frame:
		stream := get_stream(conn, f.stream_id) or_return

		switch &s in stream {
		case Sending_Stream:
			if f.max_stream_data > s.max_data {
				s.max_data = f.max_stream_data
			}
		case Bidirectional_Stream:
			if f.max_stream_data > s.send_max_data {
				s.send_max_data = f.max_stream_data
			}
		case Receiving_Stream:
			err = .STREAM_STATE_ERROR
			return
		}
		ack_eliciting = true

	case ^Max_Streams_Frame:
		if f.one_way {
			if f.max_streams > conn.max_local_streams_limit_uni {
				conn.max_local_streams_limit_uni = f.max_streams
			}
		} else {
			if f.max_streams > conn.max_local_streams_limit_bi {
				conn.max_local_streams_limit_bi = f.max_streams
			}
		}
		ack_eliciting = true
	case ^Data_Blocked_Frame:
		// if we see this frame we have screwed up
		// handling of send_limits should be handled by the packet writer
		// which iterates over its subset of the connections
		ack_eliciting = true
	case ^Stream_Data_Blocked_Frame:
		// same thing as with Data_Blocked, this is not something we should
		// see unless we've got something running really really slowly

		// however, the error check here is a MUST in the RFC
		stream := get_stream(conn, f.stream_id) or_return
		#partial switch s in stream {
		case Sending_Stream:
			err = .STREAM_STATE_ERROR
			return
		}
		ack_eliciting = true

	case ^Streams_Blocked_Frame:
		if f.max_streams > 2 << 60 {
			err = .STREAM_LIMIT_ERROR
			return
		}
		ack_eliciting = true
	case ^New_Connection_Id_Frame:
		if len(conn.dest_conn_ids) == 0 ||
		   len(f.connection_id) < 1 ||
		   len(f.connection_id) > 20 {
			err = .PROTOCOL_VIOLATION
			return
		} else {
			retire_connection_ids(conn, f.retire_prior_to) or_return
			add_connection_id(
				conn,
				f.connection_id,
				f.stateless_reset_token,
			) or_return

		}

		ack_eliciting = true
	case ^Retire_Connection_Id_Frame:
		remove_connection_ids(conn, f.sequence_num)
		ack_eliciting = true
	case ^Path_Challenge_Frame:
		queue_path_response(conn, f.data)
	case ^Path_Response_Frame:
		matches := false
		for x in conn.path_challenge {
			if x == f.data {
				matches = true
				break
			}
		}
		// TODO: implement path migragtion
		// and path validation logic here
		if !matches {
			err = .PROTOCOL_VIOLATION
			return
		}
		ack_eliciting = true
	case ^Connection_Close_Frame:
		conn.state = .Draining
		return
	case ^Handshake_Done_Frame:
		conn.state = .Secured
	case ^Datagram_Frame:
		handle_datagram_frame(conn, f^, peer)
		ack_eliciting = true
	case:
		err = .PROTOCOL_VIOLATION
		return
	}
	return
}

handle_datagram_frame :: proc(
	conn: ^Conn,
	frame: Frame,
	peer: net.Endpoint,
) -> (
	ack_eliciting: bool,
	err: Transport_Error,
) {
	cb, ok := Global_Context.callbacks.datagram_frame_callback.?
	cb(conn, frame.variant.(^Datagram_Frame).data)
	return
}
