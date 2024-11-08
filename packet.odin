package quic

Packet :: union {
    Version_Negotiation_Packet,
    Initial_Packet,
    Zero_RTT_Packet,
    Handshake_Packet,
    Retry_Packet,
    One_RTT_Packet,
}

Packet_Type :: enum {
    Version_Negotiation,
    Initial,
    Zero_RTT,
    Handshake,
    Retry,
    One_RTT,
}

//Allowed_Frames :: [Packet_Type]bit_set[Frame_type]

// NOT sure how we're going to ensure this get's
// serialized in the format we're sending it int
// but... maybe the thing will be enough
//
// UPDATE: bit fields MAY be the answer, but I am
// not sure that they are compatible. Evidently
// They are least-significant bit and network
// packets must be big-endian... I know these words
Version_Negotiation_Packet :: struct {
    dest_conn_id: Connection_Id,
    source_conn_id: Connection_Id,
    supported_versions: []u32,
}

Initial_Packet :: struct {
    version: u32,
    dest_conn_id: Connection_Id,
    source_conn_id: Connection_Id,
    token: []u8,
    packet_number: u32,
    packet_payload: []u8,
}

Zero_RTT_Packet :: struct {
    version: u32, // version is 0 in case of negotiation
    dest_conn_id: Connection_Id,
    source_conn_id: Connection_Id,
    packet_number: u32,
    packet_payload: []u8,
}

Handshake_Packet :: struct {
    version: u32, // version is 0 in case of negotiation
    dest_conn_id: Connection_Id,
    source_conn_id: Connection_Id,
    packet_number: u32,
    packet_payload: []u8,
}


/* may not be necessary, as there will
   need to be some work to serialize this anyway */
Retry_Packet :: struct {
    version: u32,
    dest_conn_id: Connection_Id,
    source_conn_id: Connection_Id,
    retry_token: []u8,
    retry_integrity_tag: []u8, // 16 bytes
}


// SPIN BIT HAS SUPERPOWERS
One_RTT_Packet :: struct {
    spin_bit: bool,
    key_phase: bool,
    dest_conn_id: Connection_Id,
    packet_number: u32,
    packet_payload: []u8,
}


Long_Header_Packet :: union {
    Version_Negotiation_Packet,
    Initial_Packet,
    Zero_RTT_Packet,
    Handshake_Packet,
    Retry_Packet,
}

get_dest_conn_id :: proc(packet: Packet) -> Connection_Id{
    switch p in packet {
    case Version_Negotiation_Packet:
	return p.dest_conn_id
    case Initial_Packet:
	return p.dest_conn_id
    case Zero_RTT_Packet:
	return p.dest_conn_id
    case Handshake_Packet:
	return p.dest_conn_id
    case Retry_Packet:
	return p.dest_conn_id
    case One_RTT_Packet:
	return p.dest_conn_id
    }
    return nil
}
