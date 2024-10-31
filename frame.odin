package quic

Padding_Frame :: struct {
    type: int = 0 `serialize:"variable_length_int"`,
}

Ping_Frame :: struct {
    type: int = 1 `serialize:"variable_length_int"`,
}

Ack_Frame :: struct {
    type: int = 2 `serialize:"variable_length_int"`, // OPTIMIZE: really this is u8
    largest_ack: int `serialize:"variable_length_int"`,
    ack_delay: int `serialize:"variable_length_int"`,
    ack_range_count: int `serialize:"variable_length_int"`,
    first_ack_range: int `serialize:"variable_length_int"`,
    ack_ranges: []int `serialize:"variable_length_int"`,// see RFC9000.19.3.1
}

Ack_Frame_With_Counts :: struct {
    type: int = 3 `serialize:"variable_length_int"`, // really this is u8
    largest_ack: int `serialize:"variable_length_int"`,
    ack_delay: int `serialize:"variable_length_int"`,
    ack_range_count: int `serialize:"variable_length_int"`,
    first_ack_range: int `serialize:"variable_length_int"`,
    ack_ranges: []int `serialize:"[]variable_length_int"`, // see RFC9000.19.3.1
    ecn_counts: []int `serialize:"[]variable_length_int"`,
}

Reset_Stream_Frame :: struct {
    type: int = 4 `serialize:"variable_length_int"`, // really this is u8
    stream_id: int `serialize:"variable_length_int"`,
    application_protocol_error_code: int `serialize:"variable_length_int"`,
    final_size: int `serialize:"variable_length_int"`,
}

Stop_Sending_Frame :: struct {
    type: int = 5 `serialize:"variable_length_int"`, // really this is u8
    stream_id: int `serialize:"variable_length_int"`,
    application_protocol_error_code: int `serialize:"variable_length_int"`,
}

Crypto_Frame :: struct {
    type: int = 6 `serialize:"variable_length_int"`, // really this is u8
    offset: int `serialize:"variable_length_int"`,
    length: int `serialize:"variable_length_int"`,
    crypto_data: []byte,
}

// server only
New_Token_Frame :: struct {
    type: int = 7 `serialize:"variable_length_int"`, // really this is u8
    token_length: int `serialize:"variable_length_int"`,
    token: []byte,
}

// the type on this has bit fields
Stream_Frame :: struct {
    has_offset: bool `serialize:"bit_flip(type, 0x04), include_field(offset)"`,
    has_len: bool `serialize:"bit_flip(type, 0x02), include_field(length)"`,
    fin_bit: bool `serialize:"bit_flip(type, 0x01)"`,
    type: int = 8 `serialize:"variable_length_int"`,
    stream_id: int `serialize:"variable_length_int"`,
    offset: int `serialize:"variable_length_int"`,
    length: int `serialize:"variable_length_int"`,
    stream_data: []byte,
}

Max_Data_Frame :: struct {
    type: int = 0x10 `serialize:"variable_length_int"`,
    max_data: int `serialize:"variable_length_int"`,
}

Max_Stream_Data_Frame :: struct {
    type: int = 0x11 `serialize:"variable_length_int"`,
    stream_id: int `serialize:"variable_length_int"`,
    max_stream_data: int `serialize:"variable_length_int"`,
}

// we could combine these two into one using a bitflip
// but that can wait
Max_Streams_Frame_Bidirectional :: struct {
    type: int = 0x12 `serialize:"variable_length_int"`,
    max_streams: int `serialize:"variable_length_int"`
}
Max_Streams_Frame_Unidirectional :: struct {
    type: int = 0x13 `serialize:"variable_length_int"`,
    max_streams: int `serialize:"variable_length_int"`
}

Max_Streams_Frame :: union { // there, they're now a union type
    Max_Streams_Frame_Bidirectional,
    Max_Streams_Frame_Unidirectional
}

Data_Blocked_Frame :: struct {
    type: int = 0x14 `serialize:"variable_length_int"`,
    max_data: int `serialize:"variable_length_int"`,
}

Stream_Data_Blocked_Frame :: struct {
    type: int = 0x15 `serialize:"variable_length_int"`,
    max_data: int `serialize:"variable_length_int"`,
}

Streams_Blocked_Bidirectional_Frame :: struct {
    type: int = 0x16 `serialize:"variable_length_int"`,
    max_streams: int `serialize:"variable_length_int"`,
}

Streams_Blocked_Unidirectional_Frame :: struct {
    type: int = 0x17 `serialize:"variable_length_int"`,
    max_streams: int `serialize:"variable_length_int"`,
}

Streams_Blocked_Frame :: union { // there, they're now a union type
    Streams_Blocked_Frame_Bidirectional,
    Streams_Blocked_Frame_Unidirectional
}   

New_Connection_Id_Frame :: struct {
    type: int = 0x18 `serialize:"variable_length_int"`,
    sequence_num: int `serialize:"variable_length_int"`,     // see RFC9000.5.1.1
    retire_prior_to: int `serialize:"variable_length_int"`,  // see RFC9000.5.1.2
    length: u8,                                              // FIXME: must be 0 < length =< 20
    connection_id: []byte,
    stateless_reset_token: u128,                             // see RFC9000.10.3
}

Retire_Connection_Id_Frame :: struct {
    type: int = 0x19 `serialize:"variable_length_int"`,
    sequence_num: int `serialize:"variable_length_int"`,     // see RFC9000.5.1.2
}

Path_Challenge_Frame :: struct {
    type: int = 0x1a `serialize:"variable_length_int"`,
    data: u64,                                               // FIXME: Should these just be byte arrays?
}

Path_Response_Frame :: struct {
    type: int = 0x1b `serialize:"variable_length_int"`,
    data: u64,                                               // don't FIXME: no, we just have to check match
}

Connection_Close_Quic_Error_Frame :: struct {
    type: int = 0x1c `serialize:"variable_length_int"`,
    error_code: int `serialize:"variable_length_int"`,
    frame_type: int `serialize:"variable_length_int"`,
    reason_phrase_len: int `serialize:"variable_length_int"`,
    reason_phrase: string,                                   // RFC9000.19.19 requires utf8 (odin default)
}

Connection_Close_App_Error_Frame :: struct {
    type: int = 0x1d `serialize:"variable_length_int"`,
    error_code: int `serialize:"variable_length_int"`,
    reason_phrase_len: int `serialize:"variable_length_int"`,
    reason_phrase: string,                                   // FIXME: but allocations? utf8 lib? string -> runes
}

Connection_Close_Frame :: union {
    Connection_Close_Quic_Error_Frame,
    Connection_Close_App_Error_Frame,
}

Handshake_Done_Frame :: struct {
    type: int = 0x1e `serialize:"variable_length_int"`,
}
