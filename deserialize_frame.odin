/*
 * SDG                                                                         JJ
 */

package quic

import "base:runtime"

import "core:fmt"


read_frames :: proc(buf_payload: []u8) -> (out: []^Frame, err: Transport_Error) {
	payload := buf_payload

	// FIXME: This is hard to track the lifetime of
	frames := make([dynamic]^Frame)

	l_init := len(payload)

	for len(payload) > 0 {
		frame := read_frame(&payload) or_return
		//fmt.println("We've read this many frames: ", len(frames))
		#partial switch _ in frame.variant {
		case ^Padding_Frame:
			continue
		case:
			append(&frames, frame)
		}
		//fmt.printfln("frames: %v", frames[0].variant)
	}
	out = frames[:]
	return
}

read_frame :: proc(payload: ^[]u8) -> (^Frame, Transport_Error) {
	frame: ^Frame

	switch payload[0] {
	case 0x01:
		frame = new_frame(Padding_Frame)
	case 0x02:
		frame = new_frame(Ping_Frame)
	case 0x02 ..= 0x03:
		frame = new_frame(Ack_Frame)
	case 0x04:
		frame = new_frame(Reset_Stream_Frame)
	case 0x05:
		frame = new_frame(Stop_Sending_Frame)
	case 0x06:
		frame = new_frame(Crypto_Frame)
	case 0x07:
		frame = new_frame(New_Token_Frame)
	case 0x08 ..= 0x0f:
		frame = new_frame(Stream_Frame)
	case 0x10:
		frame = new_frame(Max_Data_Frame)
	case 0x11:
		frame = new_frame(Max_Stream_Data_Frame)
	case 0x12 ..= 0x13:
		frame = new_frame(Max_Streams_Frame)
	case 0x14:
		frame = new_frame(Data_Blocked_Frame)
	case 0x15:
		frame = new_frame(Stream_Data_Blocked_Frame)
	case 0x16 ..= 0x17:
		frame = new_frame(Streams_Blocked_Frame)
	case 0x18:
		frame = new_frame(New_Connection_Id_Frame)
	case 0x19:
		frame = new_frame(Retire_Connection_Id_Frame)
	case 0x1a:
		frame = new_frame(Path_Challenge_Frame)
	case 0x1b:
		frame = new_frame(Path_Response_Frame)
	case 0x1c ..= 0x1d:
		frame = new_frame(Connection_Close_Frame)
	case 0x1e:
		frame = new_frame(Handshake_Done_Frame)
	case 0x30 ..= 0x31:
		frame = new_frame(Datagram_Frame)
	}

	err := _read_frame(frame, payload)

	return frame, err
}

_read_frame :: proc(frame: ^Frame, payload: ^[]u8) -> Transport_Error {
	fmt.println(frame.variant)
	switch f in frame.variant {
	case ^Padding_Frame:
		return read_padding(f, payload)
	case ^Ping_Frame:
		return read_ping(f, payload)
	case ^Ack_Frame:
		return read_ack(f, payload)
	case ^Reset_Stream_Frame:
		return read_reset_stream(f, payload)
	case ^Stop_Sending_Frame:
		return read_stop_sending(f, payload)
	case ^Crypto_Frame:
		return read_crypto(f, payload)
	case ^New_Token_Frame:
		return read_new_token(f, payload)
	case ^Stream_Frame:
		return read_stream(f, payload)
	case ^Max_Data_Frame:
		return read_max_data(f, payload)
	case ^Max_Stream_Data_Frame:
		return read_max_stream_data(f, payload)
	case ^Max_Streams_Frame:
		return read_max_streams(f, payload)
	case ^Data_Blocked_Frame:
		return read_data_blocked(f, payload)
	case ^Stream_Data_Blocked_Frame:
		return read_stream_data_blocked(f, payload)
	case ^Streams_Blocked_Frame:
		return read_streams_blocked(f, payload)
	case ^New_Connection_Id_Frame:
		return read_new_connection_id(f, payload)
	case ^Retire_Connection_Id_Frame:
		return read_retire_connection_id(f, payload)
	case ^Path_Challenge_Frame:
		return read_path_challenge(f, payload)
	case ^Path_Response_Frame:
		return read_path_response(f, payload)
	case ^Connection_Close_Frame:
		return read_connection_close(f, payload)
	case ^Handshake_Done_Frame:
		return read_handshake_done(f, payload)
	case ^Datagram_Frame:
		return read_datagram(f, payload)
	}
	return nil
}

read_padding :: proc(
	frame: ^Padding_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]
	return nil
}

read_ping :: proc(
	frame: ^Ping_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]
	return nil
}


// FIXME: write test for the sanity checks in this function
read_ack :: proc(frame: ^Ack_Frame, payload: ^[]u8) -> (err: Transport_Error) {
	frame.has_ecn_counts = payload[0] == 0x03
	payload^ = payload[1:]

	frame.largest_ack = read_variable_length_int(payload) or_return
	frame.ack_delay = read_variable_length_int(payload) or_return
	ack_range_count := read_variable_length_int(payload) or_return
	frame.first_ack_range = read_variable_length_int(payload) or_return

	// FIXME: Is this how we should handle messed up packets?
	if len(payload) < int(ack_range_count * 2) {
		return .PROTOCOL_VIOLATION
	}

	// the QUIC protocol expects us to ensure that the ack ranges are all above
	// 0, and to return a protocol error

	ack_ranges := make([]u64, ack_range_count * 2)

	// we check to make sure that each packet number is sane
	if frame.first_ack_range > frame.largest_ack {
		return .FRAME_ENCODING_ERROR
	}

	smallest := frame.largest_ack - frame.first_ack_range
	largest: u64
	for i := 0; i < int(ack_range_count * 2); i += 2 {
		gap := read_variable_length_int(payload) or_return
		ack_range_length := read_variable_length_int(payload) or_return

		// see rfc 9000 19.3.1, we're checking for negative packet numbers
		if gap + 2 > smallest {
			return .FRAME_ENCODING_ERROR
		} else {
			largest = smallest - gap - 2
		}

		if ack_range_length > largest {
			return .FRAME_ENCODING_ERROR
		} else {
			smallest = largest - ack_range_length
		}
		ack_ranges[i] = gap
		ack_ranges[i + 1] = ack_range_length
	}

	if frame.has_ecn_counts {
		frame.ecn_counts.ect0_count = read_variable_length_int(payload) or_return
		frame.ecn_counts.ect1_count = read_variable_length_int(payload) or_return
		frame.ecn_counts.ecn_ce_count = read_variable_length_int(payload) or_return
	}
	return
}

read_reset_stream :: proc(
	frame: ^Reset_Stream_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.stream_id = read_variable_length_int(payload) or_return
	frame.app_error_code = read_variable_length_int(payload) or_return
	frame.final_size = read_variable_length_int(payload) or_return
	return
}

read_stop_sending :: proc(
	frame: ^Stop_Sending_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.stream_id = read_variable_length_int(payload) or_return
	frame.app_error_code = read_variable_length_int(payload) or_return
	return
}

read_crypto :: proc(
	frame: ^Crypto_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.offset = read_variable_length_int(payload) or_return
	length := read_variable_length_int(payload) or_return

	frame.crypto_data = read_bytes(payload, length) or_return
	return
}

read_new_token :: proc(
	frame: ^New_Token_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	token_length := read_variable_length_int(payload) or_return
	frame.token = read_bytes(payload, token_length) or_return
	return
}

read_stream :: proc(
	frame: ^Stream_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	first_byte := payload[0]
	frame.has_offset = (first_byte & 0x04) != 0
	frame.has_len = (first_byte & 0x02) != 0
	frame.fin_bit = (first_byte & 0x01) != 0
	payload^ = payload[1:]

	frame.stream_id = read_variable_length_int(payload) or_return
	if frame.has_offset {
		frame.offset = read_variable_length_int(payload) or_return
	}
	if frame.has_len {
		length := read_variable_length_int(payload) or_return
		frame.stream_data = read_bytes(payload, length) or_return
	} else {
		frame.stream_data = read_bytes(payload) or_return
	}
	return
}

read_max_data :: proc(
	frame: ^Max_Data_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.max_data = read_variable_length_int(payload) or_return
	return
}

read_max_stream_data :: proc(
	frame: ^Max_Stream_Data_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.stream_id = read_variable_length_int(payload) or_return
	frame.max_stream_data = read_variable_length_int(payload) or_return
	return
}

read_max_streams :: proc(
	frame: ^Max_Streams_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	frame.one_way = payload[0] == 0x13
	payload^ = payload[1:]

	frame.max_streams = read_variable_length_int(payload) or_return
	return
}

read_data_blocked :: proc(
	frame: ^Data_Blocked_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.max_data = read_variable_length_int(payload) or_return
	return
}

read_stream_data_blocked :: proc(
	frame: ^Stream_Data_Blocked_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.stream_id = read_variable_length_int(payload) or_return
	frame.max_data = read_variable_length_int(payload) or_return

	return
}

read_streams_blocked :: proc(
	frame: ^Streams_Blocked_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	frame.one_way = payload[0] == 0x16
	payload^ = payload[1:]

	frame.max_streams = read_variable_length_int(payload) or_return
	return
}

read_new_connection_id :: proc(
	frame: ^New_Connection_Id_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]
	frame.sequence_num = read_variable_length_int(payload) or_return
	frame.retire_prior_to = read_variable_length_int(payload) or_return
	id_len := read_variable_length_int(payload) or_return // its an 8 bit int, but should work with this proc
	frame.connection_id = read_bytes(payload, id_len) or_return

	if len(payload) < 16 do return .PROTOCOL_VIOLATION // MAYBE: should be a FRAME_ENCODING error?
	persistent_token := new([16]u8, runtime.default_allocator()) // This should not get freed with the rest of this stuff
	for &b, i in persistent_token {
		b = payload[i]
	}
	payload^ = payload[16:]

	return
}

read_retire_connection_id :: proc(
	frame: ^Retire_Connection_Id_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.sequence_num = read_variable_length_int(payload) or_return
	return
}

read_path_challenge :: proc(
	frame: ^Path_Challenge_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.data = read_variable_length_int(payload) or_return
	return
}

read_path_response :: proc(
	frame: ^Path_Response_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]

	frame.data = read_variable_length_int(payload) or_return
	return
}

read_connection_close :: proc(
	frame: ^Connection_Close_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	frame.is_app_error = payload[0] == 0x1d
	payload^ = payload[1:]

	frame.error_code = read_variable_length_int(payload) or_return

	if !frame.is_app_error {
		frame.frame_type = read_variable_length_int(payload) or_return
	}

	length := read_variable_length_int(payload) or_return
	reason_phrase := read_bytes(payload, length) or_return
	frame.reason_phrase = transmute(string)reason_phrase

	return
}

read_handshake_done :: proc(
	frame: ^Handshake_Done_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	payload^ = payload[1:]
	return
}

read_datagram :: proc(
	frame: ^Datagram_Frame,
	payload: ^[]u8,
) -> (
	err: Transport_Error,
) {
	frame.has_len = payload[0] == 0x31
	payload^ = payload[1:]

	length: u64
	if frame.has_len {
		length = read_variable_length_int(payload) or_return
	}
	frame.data = read_bytes(payload, length) or_return
	return
}

// FIXME: replace get_variable_length_int in deserialize.odin with
// this, because this one has length checking and will return an
// error if there is an error
read_variable_length_int :: proc(payload: ^[]u8) -> (u64, Transport_Error) {
	if len(payload) == 0 do return 0, .PROTOCOL_VIOLATION
	two_msb := payload[0] >> 6
	n := u64(payload[0]) &~ 0xc0

	num_len: int
	switch two_msb {
	case 0x00:
		num_len = 1
	case 0x01:
		num_len = 2
	case 0x02:
		num_len = 4
	case 0x03:
		num_len = 8
	}

	fmt.printfln("num_len %v", num_len)
	fmt.printfln("bytes %x", payload[:num_len])

	if len(payload) < num_len do return 0, .PROTOCOL_VIOLATION

	for i := 1; i < num_len; i += 1 {
		n = u64(payload[i]) + (n << 8)
	}
	payload^ = payload[num_len:]
	return n, nil
}

// WARNING: Do not deallocate the original datagram buffer before handling
// the received frames or you will deallocate the read-in data on the frames
// MAYBE: we should just allocate a new slice here?
read_bytes :: proc(
	payload: ^[]u8,
	#any_int length := 0,
) -> (
	[]u8,
	Transport_Error,
) {
	length := length > 0 ? length : len(payload)
	if length > len(payload) do return nil, .PROTOCOL_VIOLATION
	out := make([]u8, length) // out[:length] 

	for b, i in payload[:length] {
		out[i] = b
	}

	payload^ = payload[length:]
	return out, nil
}
