package quic
import "core:fmt"

Frame_Reader :: #type proc(payload: ^[]u8) -> (^Frame, Transport_Error)

read_packets :: proc(payload: []u8) -> (out: []^Frame, err: Transport_Error) {
	payload := payload

	frames := make([dynamic]^Frame)
	fmt.println(len(frames))

	reader : Frame_Reader

	for len(payload) > 0 {
		reader = find_reader(payload[0])
		frame := reader(&payload) or_return 
		#partial switch _ in frame.variant {
		case ^Padding_Frame:
			continue
		case:
			append(&frames, frame)
		}
		reader = nil
	}
	out = frames[:]
	return
}

find_reader :: proc(first_byte: u8) -> Frame_Reader {
	switch first_byte {
	case 0x01:
		return read_padding
	case 0x02:
		return read_ping
	case 0x02..=0x03:
		return read_ack
	//case 0x04:
	//	return read_reset_stream
	//case 0x05:
	//	return read_stop_sending
	//case 0x06:
	//	return read_crypto
	//case 0x07:
	//	return read_new_token
	//case 0x08..=0x0f:
	//	return read_stream
	//case 0x10:
	//	return read_max_data
	//case 0x11:
	//	return read_max_data
	//case 0x12..=0x13:
	//	return read_max_streams
	//case 0x14:
	//	return read_data_blocked
	//case 0x15:
	//	return read_streams_data_blocked
	//case 0x16..=0x17:
	//	return read_streams_blocked
	//case 0x18:
	//	return read_new_connection_id
	//case 0x19:
	//	return read_retire_connection_id
	//case 0x1a:
	//	return read_path_challenge
	//case 0x1b:
	//	return read_path_response
	//case 0x1c..=0x1d:
	//	return read_connection_close
	//case 0x1e:
	//	return read_handshake_done
	//case 0x30..=0x31:
	//	return read_datagram_frame
	}
	return nil
}

read_padding :: proc(payload: ^[]u8) -> (^Frame, Transport_Error) {
	payload^ = payload[1:]
	return new_frame(Padding_Frame), nil
}

read_ping :: proc(payload: ^[]u8) -> (^Frame, Transport_Error) {
	payload^ = payload[1:]
	return new_frame(Ping_Frame), nil
}


// FIXME: write test for the sanity checks in this function
read_ack :: proc(payload: ^[]u8) -> (frame: ^Frame, err: Transport_Error) {
	has_ecn_counts := payload[0] == 0x03
	if has_ecn_counts {
		frame = new_frame(Ack_Frame_With_Counts)
	} else {
		frame = new_frame(Ack_Frame)
	}

	largest_ack :=  read_variable_length_int(payload) or_return
	ack_delay :=  read_variable_length_int(payload) or_return
	ack_range_count := read_variable_length_int(payload) or_return
	first_ack_range := read_variable_length_int(payload) or_return

	// FIXME: Is this how we should handle messed up packets?
	if len(payload) < int(ack_range_count * 2) {
		return frame, .PROTOCOL_VIOLATION
	}

	// the QUIC protocol expects us to ensure that the ack ranges are all above
	// 0, and to return a protocol error

	ack_ranges := make([]u64, ack_range_count * 2)

	// we check to make sure that each packet number is sane
	if first_ack_range > largest_ack {
		return frame, .FRAME_ENCODING_ERROR
	}

	smallest := largest_ack - first_ack_range
	largest : u64
	for i := 0; i < int(ack_range_count * 2); i += 2 {
		gap := read_variable_length_int(payload) or_return
		ack_range_length := read_variable_length_int(payload) or_return

		// see rfc 9000 19.3.1, we're checking for negative packet numbers
		if gap + 2 > smallest {
			return frame, .FRAME_ENCODING_ERROR
		} else {
			largest = smallest - gap - 2
		}

		if ack_range_length > largest {
			return frame, .FRAME_ENCODING_ERROR
		} else {
			smallest = largest - ack_range_length
		}
		ack_ranges[i] = gap
		ack_ranges[i+1] = ack_range_length
	}


	#partial switch f in frame.variant {
	case ^Ack_Frame_With_Counts:
		f.largest_ack = largest_ack
		f.ack_delay = ack_delay
		f.first_ack_range = first_ack_range
		f.ack_ranges = ack_ranges

		f.ecn_counts.ect0_count = read_variable_length_int(payload) or_return
		f.ecn_counts.ect1_count = read_variable_length_int(payload) or_return
		f.ecn_counts.ecn_ce_count = read_variable_length_int(payload) or_return
			
	case ^Ack_Frame: 
		f.largest_ack = largest_ack
		f.ack_delay = ack_delay
		f.first_ack_range = first_ack_range
		f.ack_ranges = ack_ranges
	}
	return
}


// FIXME: replace get_variable_length_int in deserialize.odin with
// this, because this one has length checking and will return an
// error if there is an error
read_variable_length_int :: proc(payload: ^[]u8) -> (u64, Transport_Error) {
	if len(payload) == 0 do return 0, .PROTOCOL_VIOLATION
	two_msb := payload[0] >> 6
	n := u64(payload[0]) &~ (2 << 6)

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

	if len(payload) < num_len do return 0, .PROTOCOL_VIOLATION

	for i := 1; i < num_len; i += 1 {
		n = u64(payload[i]) + (n << 8)
	}
	payload^ = payload[num_len:]
	return n, nil
}
