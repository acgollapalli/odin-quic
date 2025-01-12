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

Frame_Tag :: enum {
	Padding,
	Ping,
	Ack,
	Reset_Stream,
	Stop_Sending,
	Crypto,
	New_Token,
	Stream,
	Max_Data,
	Max_Stream_Data,
	Max_Streams,
	Data_Blocked,
	Stream_Data_Blocked,
	Streams_Blocked,
	New_Connection_Id,
	Retire_Connection_Id,
	Path_Challenge,
	Path_Response,
	Connection_Close,
	Handshake_Done,
	Datagram,
}

Non_Ack_Eliciting_Frames: bit_set[Frame_Tag] = {
	.Ack,
	.Padding,
	.Connection_Close,
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


add_padding_frame :: proc(_: Padding_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x00, cursor)
}

Ping_Frame :: struct {
	using frame: Frame,
} //type: int = 1 `serialize:"variable_length_int"`,


add_ping_frame :: proc(_: Ping_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x01, cursor)
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

add_ack_frame :: proc(frame: Ack_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x03, cursor) // frame type
	encode_and_cursor_append_int(frame.largest_ack, cursor)
	encode_and_cursor_append_int(frame.ack_delay, cursor)
	encode_and_cursor_append_int(len(frame.ack_ranges) / 2, cursor) // ack_range_count
	encode_and_cursor_append_int(frame.first_ack_range, cursor)
	for i in frame.ack_ranges do encode_and_cursor_append_int(i, cursor)

	if frame.has_ecn_counts {
		encode_and_cursor_append_int(frame.ecn_counts.ect0_count, cursor)
		encode_and_cursor_append_int(frame.ecn_counts.ect1_count, cursor)
		encode_and_cursor_append_int(frame.ecn_counts.ecn_ce_count, cursor)
	}
}

Reset_Stream_Frame :: struct {
	//type: int = 4 `serialize:"variable_length_int"`, // really this is u8
	stream_id:      u64 `serialize:"variable_length_int"`,
	app_error_code: u64 `serialize:"variable_length_int"`,
	final_size:     u64 `serialize:"variable_length_int"`,
	using frame:    Frame,
}

add_reset_stream_frame :: proc(frame: Reset_Stream_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x04, cursor) // frame type
	encode_and_cursor_append_int(frame.stream_id, cursor)
	encode_and_cursor_append_int(frame.app_error_code, cursor)
	encode_and_cursor_append_int(frame.final_size, cursor)
}

Stop_Sending_Frame :: struct {
	//type: int = 5 `serialize:"variable_length_int"`, // really this is u8
	stream_id:      u64 `serialize:"variable_length_int"`,
	app_error_code: u64 `serialize:"variable_length_int"`,
	using frame:    Frame,
}

add_stop_sending_frame :: proc(frame: Stop_Sending_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x05, cursor) // frame type
	encode_and_cursor_append_int(frame.stream_id, cursor)
	encode_and_cursor_append_int(frame.app_error_code, cursor)
}

Crypto_Frame :: struct {
	//type: int = 6 `serialize:"variable_length_int"`, // really this is u8
	offset:      u64 `serialize:"variable_length_int"`,
	//length:      int `serialize:"variable_length_int"`,
	crypto_data: []byte,
	using frame: Frame,
}

add_crypto_frame :: proc(frame: Crypto_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x06, cursor) // frame type
	encode_and_cursor_append_int(frame.offset, cursor)
	encode_and_cursor_append_int(len(frame.crypto_data), cursor)
	cursor_append(frame.crypto_data, cursor)
}

// server only
New_Token_Frame :: struct {
	//type: int = 7 `serialize:"variable_length_int"`, // really this is u8
	//token_length: int `serialize:"variable_length_int"`,
	token:       []byte, // REMINDER: must be of len > 0
	using frame: Frame,
}

add_new_token_frame :: proc(frame: New_Token_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x07, cursor) // frame type
	encode_and_cursor_append_int(len(frame.token), cursor) // token length
	cursor_append(frame.token, cursor)
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

add_stream_frame :: proc(frame: Stream_Frame, cursor: ^[]u8) {
	type := 0x08

	if frame.has_offset do type |= 0x04
	if frame.has_len do type |= 0x02
	if frame.fin_bit do type |= 0x01

	encode_and_cursor_append_int(type, cursor)
	encode_and_cursor_append_int(frame.stream_id, cursor)
	encode_and_cursor_append_int(frame.offset, cursor)
	if frame.has_len do encode_and_cursor_append_int(len(frame.stream_data), cursor)
	cursor_append(frame.stream_data, cursor)
}

Max_Data_Frame :: struct {
	//type: int = 0x10 `serialize:"variable_length_int"`,
	max_data:    u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_max_data_frame :: proc(frame: Max_Data_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x10, cursor) // frame type
	encode_and_cursor_append_int(frame.max_data, cursor)
}

Max_Stream_Data_Frame :: struct {
	//type: int = 0x11 `serialize:"variable_length_int"`,
	stream_id:       u64 `serialize:"variable_length_int"`,
	max_stream_data: u64 `serialize:"variable_length_int"`,
	using frame:     Frame,
}

add_max_stream_data_frame :: proc(
	frame: Max_Stream_Data_Frame,
	cursor: ^[]u8,
) {
	encode_and_cursor_append_int(0x11, cursor) // frame type
	encode_and_cursor_append_int(frame.stream_id, cursor)
	encode_and_cursor_append_int(frame.max_stream_data, cursor)
}


Max_Streams_Frame :: struct {
	//type: int = 0x12 `serialize:"variable_length_int"`,
	one_way:     bool, // set type to 0x13
	max_streams: u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_max_streams_frame :: proc(frame: Max_Streams_Frame, cursor: ^[]u8) {
	type := 0x12
	if frame.one_way do type += 1
	encode_and_cursor_append_int(type, cursor)
	encode_and_cursor_append_int(frame.max_streams, cursor)
}

Data_Blocked_Frame :: struct {
	//type: int = 0x14 `serialize:"variable_length_int"`,
	max_data:    u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_data_blocked_frame :: proc(frame: Data_Blocked_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x14, cursor) // frame type
	encode_and_cursor_append_int(frame.max_data, cursor)
}

Stream_Data_Blocked_Frame :: struct {
	//type: int = 0x15 `serialize:"variable_length_int"`,
	stream_id:   u64 `serialize:"variable_length_int"`,
	max_data:    u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_stream_data_blocked_frame :: proc(
	frame: Stream_Data_Blocked_Frame,
	cursor: ^[]u8,
) {
	encode_and_cursor_append_int(0x15, cursor) // frame type
	encode_and_cursor_append_int(frame.stream_id, cursor)
	encode_and_cursor_append_int(frame.max_data, cursor)
}

Streams_Blocked_Frame :: struct {
	//type: int = 0x16 `serialize:"variable_length_int"`,
	one_way:     bool, // set type to 0x16
	max_streams: u64 `serialize:"variable_length_int"`,
	using frame: Frame,
}

add_streams_blocked_frame :: proc(
	frame: Streams_Blocked_Frame,
	cursor: ^[]u8,
) {
	type := 0x16
	if frame.one_way do type += 1
	encode_and_cursor_append_int(type, cursor)
	encode_and_cursor_append_int(frame.max_streams, cursor)
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
	frame: New_Connection_Id_Frame,
	cursor: ^[]u8,
) {
	encode_and_cursor_append_int(0x18, cursor) // frame type
	encode_and_cursor_append_int(frame.sequence_num, cursor)
	encode_and_cursor_append_int(frame.retire_prior_to, cursor)
	encode_and_cursor_append_int(len(frame.connection_id), cursor) // length of conn_id
	cursor_append(frame.connection_id, cursor)
	token := frame.stateless_reset_token[:]
	cursor_append(token, cursor)
}

Retire_Connection_Id_Frame :: struct {
	//type: int = 0x19 `serialize:"variable_length_int"`,
	sequence_num: u64 `serialize:"variable_length_int"`, // see RFC9000.5.1.2
	using frame:  Frame,
}

add_retire_connection_id_frame :: proc(
	frame: Retire_Connection_Id_Frame,
	cursor: ^[]u8,
) {
	encode_and_cursor_append_int(0x19, cursor) // frame_type
	encode_and_cursor_append_int(frame.sequence_num, cursor)
}

Path_Challenge_Frame :: struct {
	//type: int = 0x1a `serialize:"variable_length_int"`,
	data:        u64, // FIXME: Should these just be byte arrays?
	using frame: Frame,
}

add_path_challenge_frame :: proc(frame: Path_Challenge_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x1a, cursor) // frame type

	// add entropy
	entropy_array := transmute([8]u8)frame.data
	cursor_append(entropy_array[:], cursor)
}

Path_Response_Frame :: struct {
	//type: int = 0x1b `serialize:"variable_length_int"`,
	data:        u64, // don't FIXME: no, we just have to check match
	using frame: Frame,
}

add_path_response_frame :: proc(frame: Path_Response_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x1b, cursor) // frame type

	// add entropy
	entropy_array := transmute([8]u8)frame.data
	cursor_append(entropy_array[:], cursor)
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
	frame: Connection_Close_Frame,
	cursor: ^[]u8,
) {
	type := 0x1c
	if frame.is_app_error do type += 1
	encode_and_cursor_append_int(type, cursor)
	if frame.is_app_error do encode_and_cursor_append_int(frame.error_code, cursor)
	encode_and_cursor_append_int(frame.frame_type, cursor)
	encode_and_cursor_append_int(len(frame.reason_phrase), cursor)
	cursor_append(transmute([]u8)(frame.reason_phrase), cursor)
}

Handshake_Done_Frame :: struct {
	using frame: Frame,
} //type: int = 0x1e `serialize:"variable_length_int"`,

add_handshake_done_frame :: proc(frame: Handshake_Done_Frame, cursor: ^[]u8) {
	encode_and_cursor_append_int(0x1e, cursor)
}
Datagram_Frame :: struct {
	//type: int = 0x30 `serialize:"variable_length_int"`,
	has_len:     bool, // make type 0x31
	data:        []byte,
	using frame: Frame,
}

add_datagram_frame :: proc(frame: Datagram_Frame, cursor: ^[]u8) {
	type := 0x30
	if frame.has_len do type += 1
	encode_and_cursor_append_int(type, cursor)

	if frame.has_len do encode_and_cursor_append_int(len(frame.data), cursor)
	cursor_append(frame.data, cursor)
}
