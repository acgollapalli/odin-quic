/*
 * SDG                                                                         JJ
 */

package quic

Frame :: struct {
	variant: union {
		^Padding_Frame,
		^Ping_Frame,
		^Ack_Frame,
		^Reset_Stream_Frame,
		^Stop_Sending_Frame,
		^Crypto_Frame,
		^New_Token_Frame,
		^Stream_Frame,
		^Max_Data_Frame,
		^Max_Stream_Data_Frame,
		^Max_Streams_Frame,
		^Data_Blocked_Frame,
		^Stream_Data_Blocked_Frame,
		^Streams_Blocked_Frame,
		^New_Connection_Id_Frame,
		^Retire_Connection_Id_Frame,
		^Path_Challenge_Frame,
		^Path_Response_Frame,
		^Connection_Close_Frame,
		^Handshake_Done_Frame,
		^Datagram_Frame,
	},
}

new_frame :: proc($T: typeid) -> ^T {
	f := new(T)
	f.variant = f
	return f
}


// FIXME: This is probably unnecessary and overcomplicated
// but it helps me to see it here. 
//Frame_Type_Codes :: [Frame_Type][]? {
//	.Padding                  = { 0x00 },
//	.Ping                     = { 0x01 },
//	.Ack                      = { 0x02, 0x03 },
//	.Reset_Stream             = { 0x04 },
//	.Stop_Sending             = { 0x05 },
//	.Crypto                   = { 0x06 },
//	.New_Token                = { 0x07 },
//	.Stream                   = { 0x08, 0x0f },
//	.Max_Data                 = { 0x10 },
//	.Max_Stream_Data          = { 0x11 },
//	.Max_Streams              = { 0x12, 0x13 },
//	.Data_Blocked             = { 0x14 },
//	.Stream_Data_Blocked      = { 0x15 },
//	.Streams_Blocked          = { 0x16, 0x17 },
//	.New_Connection_Id        = { 0x18 },
//	.Retire_Connection_Id     = { 0x19 },
//	.Path_Challenge           = { 0x1a },
//	.Path_Response            = { 0x1b },
//	.Connection_Close         = { 0x1c, 0x1d },
//	.Handshake_Done           = { 0x1e },
//	.Datagram                 = { 0x30, 0x31 },
//}


Padding_Frame :: struct {
	using frame: Frame,
} //type: int = 0 `serialize:"variable_length_int"`,


add_padding_frame :: proc(payload: ^[]u8, _: Padding_Frame) {
	add_variable_length_int(payload, 0x00)
}

Ping_Frame :: struct {
	using frame: Frame,
} //type: int = 1 `serialize:"variable_length_int"`,


add_ping_frame :: proc(payload: ^[]u8, _: Ping_Frame) {
	add_variable_length_int(payload, 0x01)
}

// MAYBE: we MIGHT want to do some polymorphism here...
// but we also might not
Ack_Frame :: struct {
	//type: u64 = 3 `serialize:"variable_length_int"`, // really this is u8
	has_ecn_counts:  bool,
	largest_ack:     u64 `serialize:"variable_length_int"`,
	ack_delay:       u64 `serialize:"variable_length_int"`,
	//ack_range_count: u64 `serialize:"variable_length_int"`,
	first_ack_range: u64 `serialize:"variable_length_int"`,
	ack_ranges:      []u64 `serialize:"[]variable_length_int"`, // see RFC9000.19.3.1
	ecn_counts:      struct {
		ect0_count:   u64 `serialize:"[]variable_length_int"`,
		ect1_count:   u64 `serialize:"[]variable_length_int"`,
		ecn_ce_count: u64 `serialize:"[]variable_length_int"`,
	},
	using frame:     Frame,
}

add_ack_frame_with_counts :: proc(payload: ^[]u8, frame: Ack_Frame) {
	add_variable_length_int(payload, 0x03) // frame type
	add_variable_length_int(payload, frame.largest_ack)
	add_variable_length_int(payload, frame.ack_delay)
	add_variable_length_int(payload, len(frame.ack_ranges) / 2) // ack_range_count
	add_variable_length_int(payload, frame.first_ack_range)
	for i in frame.ack_ranges do add_variable_length_int(payload, i)

	if frame.has_ecn_counts {
		add_variable_length_int(payload, frame.ecn_counts.ect0_count)
		add_variable_length_int(payload, frame.ecn_counts.ect1_count)
		add_variable_length_int(payload, frame.ecn_counts.ecn_ce_count)
	}
}

Reset_Stream_Frame :: struct {
	//type: int = 4 `serialize:"variable_length_int"`, // really this is u8
	stream_id:      u64 `serialize:"variable_length_int"`,
	app_error_code: u64 `serialize:"variable_length_int"`,
	final_size:     u64 `serialize:"variable_length_int"`,
	using frame:    Frame,
}

add_reset_stream_frame :: proc(payload: ^[]u8, frame: Reset_Stream_Frame) {
	add_variable_length_int(payload, 0x04) // frame type
	add_variable_length_int(payload, frame.stream_id)
	add_variable_length_int(payload, frame.app_error_code)
	add_variable_length_int(payload, frame.final_size)
}

Stop_Sending_Frame :: struct {
	//type: int = 5 `serialize:"variable_length_int"`, // really this is u8
	stream_id:      u64 `serialize:"variable_length_int"`,
	app_error_code: u64 `serialize:"variable_length_int"`,
	using frame:    Frame,
}

add_stop_sending_frame :: proc(payload: ^[]u8, frame: Stop_Sending_Frame) {
	add_variable_length_int(payload, 0x05) // frame type
	add_variable_length_int(payload, frame.stream_id)
	add_variable_length_int(payload, frame.app_error_code)
}

Crypto_Frame :: struct {
	//type: int = 6 `serialize:"variable_length_int"`, // really this is u8
	offset:      u64 `serialize:"variable_length_int"`,
	//length:      int `serialize:"variable_length_int"`,
	crypto_data: []byte,
	using frame: Frame,
}

add_crypto_frame :: proc(payload: ^[]u8, frame: Crypto_Frame) {
	add_variable_length_int(payload, 0x06) // frame type
	add_variable_length_int(payload, frame.offset)
	add_variable_length_int(payload, len(frame.crypto_data))
	add_bytes(payload, frame.crypto_data)
}

// server only
New_Token_Frame :: struct {
	//type: int = 7 `serialize:"variable_length_int"`, // really this is u8
	//token_length: int `serialize:"variable_length_int"`,
	token:       []byte, // REMINDER: must be of len > 0
	using frame: Frame,
}

add_new_token_frame :: proc(payload: ^[]u8, frame: New_Token_Frame) {
	add_variable_length_int(payload, 0x07) // frame type
	add_variable_length_int(payload, len(frame.token)) // token length
	add_bytes(payload, frame.token)
}

// the type on this has bit fields
Stream_Frame :: struct {
	has_offset:  bool `serialize:"bit_flip(type, 0x04), include_field(offset)"`,
	has_len:     bool `serialize:"bit_flip(type, 0x02), include_field(length)"`,
	fin_bit:     bool `serialize:"bit_flip(type, 0x01)"`,
	//type: int = 8 `serialize:"variable_length_int"`,
	stream_id:   u64 `serialize:"variable_length_int"`,
	offset:      u64 `serialize:"variable_length_int"`,
	//length:      int `serialize:"variable_length_int"`,
	stream_data: []byte,
	using frame: Frame,
}

add_stream_frame :: proc(payload: ^[]u8, frame: Stream_Frame) {
	type := 0x08

	if frame.has_offset do type |= 0x04
	if frame.has_len do type |= 0x02
	if frame.fin_bit do type |= 0x01

	add_variable_length_int(payload, type)
	add_variable_length_int(payload, frame.stream_id)
	add_variable_length_int(payload, frame.offset)
	if frame.has_len do add_variable_length_int(payload, len(frame.stream_data))
	add_bytes(payload, frame.stream_data)
}

Max_Data_Frame :: struct {
	//type: int = 0x10 `serialize:"variable_length_int"`,
	max_data:    u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_max_data_frame :: proc(payload: ^[]u8, frame: Max_Data_Frame) {
	add_variable_length_int(payload, 0x10) // frame type
	add_variable_length_int(payload, frame.max_data)
}

Max_Stream_Data_Frame :: struct {
	//type: int = 0x11 `serialize:"variable_length_int"`,
	stream_id:       u64 `serialize:"variable_length_int"`,
	max_stream_data: u64 `serialize:"variable_length_int"`,
	using frame:     Frame,
}

add_max_stream_data_frame :: proc(
	payload: ^[]u8,
	frame: Max_Stream_Data_Frame,
) {
	add_variable_length_int(payload, 0x11) // frame type
	add_variable_length_int(payload, frame.stream_id)
	add_variable_length_int(payload, frame.max_stream_data)
}


Max_Streams_Frame :: struct {
	//type: int = 0x12 `serialize:"variable_length_int"`,
	one_way:     bool, // set type to 0x13
	max_streams: u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_max_streams_frame :: proc(payload: ^[]u8, frame: Max_Streams_Frame) {
	type := 0x12
	if frame.one_way do type += 1
	add_variable_length_int(payload, type)
	add_variable_length_int(payload, frame.max_streams)
}

Data_Blocked_Frame :: struct {
	//type: int = 0x14 `serialize:"variable_length_int"`,
	max_data:    u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_data_blocked_frame :: proc(payload: ^[]u8, frame: Data_Blocked_Frame) {
	add_variable_length_int(payload, 0x14) // frame type
	add_variable_length_int(payload, frame.max_data)
}

Stream_Data_Blocked_Frame :: struct {
	//type: int = 0x15 `serialize:"variable_length_int"`,
	stream_id:   u64 `serialize:"variable_length_int"`,
	max_data:    u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_stream_data_blocked_frame :: proc(
	payload: ^[]u8,
	frame: Stream_Data_Blocked_Frame,
) {
	add_variable_length_int(payload, 0x15) // frame type
	add_variable_length_int(payload, frame.stream_id)
	add_variable_length_int(payload, frame.max_data)
}

Streams_Blocked_Frame :: struct {
	//type: int = 0x16 `serialize:"variable_length_int"`,
	one_way:     bool, // set type to 0x16
	max_streams: u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_streams_blocked_frame :: proc(
	payload: ^[]u8,
	frame: Streams_Blocked_Frame,
) {
	type := 0x16
	if frame.one_way do type += 1
	add_variable_length_int(payload, type)
	add_variable_length_int(payload, frame.max_streams)
}

New_Connection_Id_Frame :: struct {
	//type: int = 0x18 `serialize:"variable_length_int"`,
	sequence_num:          u64 `serialize:"variable_length_int"`, // see RFC9000.5.1.1
	retire_prior_to:       u64 `serialize:"variable_length_int"`, // see RFC9000.5.1.2
	//length:                u8, // FIXME: must be 0 < length =< 20
	connection_id:         []byte,
	stateless_reset_token: ^[16]byte, // see RFC9000.10.3
	using frame:           Frame,
}

add_new_connection_id_frame :: proc(
	payload: ^[]u8,
	frame: New_Connection_Id_Frame,
) {
	add_variable_length_int(payload, 0x18) // frame type
	add_variable_length_int(payload, frame.sequence_num)
	add_variable_length_int(payload, frame.retire_prior_to)
	add_variable_length_int(payload, len(frame.connection_id)) // length of conn_id
	add_bytes(payload, frame.connection_id)
	token := frame.stateless_reset_token[:]
	add_bytes(payload, token)
}

Retire_Connection_Id_Frame :: struct {
	//type: int = 0x19 `serialize:"variable_length_int"`,
	sequence_num: u64 `serialize:"variable_length_int"`, // see RFC9000.5.1.2
	using frame:  Frame,
}

add_retire_connection_id_frame :: proc(
	payload: ^[]u8,
	frame: Retire_Connection_Id_Frame,
) {
	add_variable_length_int(payload, 0x19) // frame_type
	add_variable_length_int(payload, frame.sequence_num)
}

Path_Challenge_Frame :: struct {
	//type: int = 0x1a `serialize:"variable_length_int"`,
	data:        u64, // FIXME: Should these just be byte arrays?
	using frame: Frame,
}

add_path_challenge_frame :: proc(payload: ^[]u8, frame: Path_Challenge_Frame) {
	add_variable_length_int(payload, 0x1a) // frame type
	len_payload := len(payload)

	// add entropy
	increment_payload(payload, 8)
	for i := 0; i < 8; i += 1 {
		payload^[len_payload + i] = u8(frame.data >> u64((7 - i) * 8))
	}
}

Path_Response_Frame :: struct {
	//type: int = 0x1b `serialize:"variable_length_int"`,
	data:        u64, // don't FIXME: no, we just have to check match
	using frame: Frame,
}

add_path_response_frame :: proc(payload: ^[]u8, frame: Path_Response_Frame) {
	add_variable_length_int(payload, 0x1b) // frame type
	len_payload := len(payload)

	// add entropy
	increment_payload(payload, 8)
	for i := 0; i < 8; i += 1 {
		payload^[len_payload + i] = u8(frame.data >> u64((7 - i) * 8))
	}
}

Connection_Close_Frame :: struct {
	//type: int = 0x1c `serialize:"variable_length_int"`,
	is_app_error:  bool,
	error_code:    u64 `serialize:"variable_length_int"`,
	frame_type:    u64 `serialize:"variable_length_int"`,
	//reason_phrase_len: u64 `serialize:"variable_length_int"`,
	reason_phrase: string, // RFC9000.19.19 requires utf8 (odin default)
	using frame:   Frame,
}

add_connection_close_frame :: proc(
	payload: ^[]u8,
	frame: Connection_Close_Frame,
) {
	type := 0x1c
	if frame.is_app_error do type += 1
	add_variable_length_int(payload, type)
	if frame.is_app_error do add_variable_length_int(payload, frame.error_code)
	add_variable_length_int(payload, frame.frame_type)
	add_variable_length_int(payload, len(frame.reason_phrase))
	add_bytes(payload, transmute([]u8)frame.reason_phrase)
}

Handshake_Done_Frame :: struct {
	using frame: Frame,
} //type: int = 0x1e `serialize:"variable_length_int"`,

add_handshake_done_frame :: proc(payload: ^[]u8, frame: Handshake_Done_Frame) {
	add_variable_length_int(payload, 0x1e)
}
Datagram_Frame :: struct {
	//type: int = 0x30 `serialize:"variable_length_int"`,
	has_len:     bool, // make type 0x31
	data:        []byte,
	using frame: Frame,
}

add_datagram_frame :: proc(payload: ^[]u8, frame: Datagram_Frame) {
	type := 0x30
	if frame.has_len do type += 1
	add_variable_length_int(payload, type)

	if frame.has_len do add_variable_length_int(payload, len(frame.data))
	add_bytes(payload, frame.data)
}
