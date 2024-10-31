package quic

Packet :: union {
    Version_Negotiation_Packet,
    Initial_Packet,
    Zero_RTT_Packet,
    Handshake_Packet,
    Retry_Packet,
    One_RTT_Packet,
}

// NOT sure how we're going to ensure this get's
// serialized in the format we're sending it int
// but... maybe the #packed thing will be enough
//
// UPDATE: bit fields MAY be the answer, but I am
// not sure that they are compatible. Evidently
// They are least-significant bit and network
// packets must be big-endian... I know these words
Version_Negotiation_Packet :: struct #packed {
    first_byte: u8,
    version: u32, // version is 0 in case of negotiation
    dest_conn_id_length: u64,
    dest_conn_id: []u64,
    source_conn_id_length: u64,
    source_conn_id: []u64,
    type-specific-payload: []u8
    supported_version: u32
}

Initial_Packet :: struct #packed {
    first_byte: u8,
    version: u32,
    dest_conn_id_length: u64,
    dest_conn_id: []u64,
    source_conn_id_length: u64,
    source_conn_id: []u64,
    token_length: u64,             // variable length
    token: []u8,
    length: u64,                   // variable length
    packet_number: u32,
    packet_payload: []u8
}

Zero_RTT_Packet :: struct #packed {
    first_byte: u8,
    version: u32, // version is 0 in case of negotiation
    dest_conn_id_length: u64,
    dest_conn_id: []u64,
    source_conn_id_length: u64,
    source_conn_id: []u64,
    type-specific-payload: []u8
    length: u64,                   // variable length
    packet_number: u32,
    packet_payload: []u8
}

Handshake_Packet :: struct #packed {
    first_byte: u8,
    version: u32, // version is 0 in case of negotiation
    dest_conn_id_length: u64,
    dest_conn_id: []u64,
    source_conn_id_length: u64,
    source_conn_id: []u64,
    type-specific-payload: []u8,
    length: u64,                   // variable length
    packet_number: u32,
    packet_payload: []u8
}


/* #packed may not be necessary, as there will
   need to be some work to serialize this anyway */
Retry_Packet :: struct #packed {
    first_byte: u8,
    version: u32,
    dest_conn_id_length: u64,
    dest_conn_id: []u64,
    source_conn_id_length: u64,
    source_conn_id: []u64,
    type-specific-payload: []u8,
    length: u64,                  // variable length
    retry_token: []u8,
    retry_integrity_tag: u128
}


// SPIN BIT HAS SUPERPOWERS
One_RTT_Packet :: struct #packed {
    first_byte: u8,
    dest_conn_id: []u64,
    packet_number: u32,
    packet_payload: []u8
}


// FIXME: This function is used to CONSTRUCT the packet
// structs. Unless we want to remove the first byte arg
// entirely and just use this in serialization ... that might
// actually be better

/* we could optimize this by inlining/hardcoding instead
   of having this be a whole procedure */
get_first_byte :: proc(packet: Packet, spin: bool, key_phase: bool) -> u8 {
    header_form := 1 << 7
    fixed_bit := 1 << 6

    /* packet number lengths are hardcoded to three
       although I could probably make them smaller 
       now that we have the make_variable_length_int */
    packet_number_length := 0x03

    switch _ in packet {
    case Version_Negotiation_Packet:
	return header_form
    case Initial_Packet:
	return header_form | fixed_bit | packet_number_length 
    case Zero_RTT_Packet:
	return header_form | fixed_bit | 0x01 << 4 | packet_number_length
    case Handshake_Packet:
	return header_form | fixed_bit | 0x02 << 4 | packet_number_length
    case Retry_Packet:
	return header_form | fixed_bit | 0x03 << 4
    case :
	spin_bit := spin ? 1 << 5 : 0
	key_phase := key_phase ? 1 << 2 : 0 // 0x04
	return fixed_bit | spin_bit | key_phase | packet_number_length
    }
}

