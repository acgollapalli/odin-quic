package quic

import ssl "../odin-ssl"

serialize_packet :: proc(conn: ^Conn, packet: Packet) -> []u8 {
    out: [dynamic]u8
    append(&out, 0) // placeholder first byte
    append(&out, ..serialize_header(packet))
    payload, pkt_number_index, pkt_number_length := serialize_payload
    append(&out, ..payload)

    out[0] = make_first_byte(packet, u8(pkt_number_length))

    apply_header_protection(&conn, &out, pkt_number_index, pkt_number_length)
    
    
    // FIXME: at the end, we need to add the retry integrity tag!

}

// header
// includes version, destination connection id + length source id + length
serialize_header :: proc(packet: Packet) -> []u8 {
    header := make([]u8, 46)

    switch p in packet { // FIXME: Holy code duplication batman!
    case One_RTT_Packet:
	for b in p.dest_conn_id do append(&out, b)
	header = header[0:len(dest_conn_id) + 1]
    case Version_Negotiation_Packet:
	append(&out, ..[]u8{0,0,0,0})
	append(&out, len(p.dest_conn_id))
	for b in p.dest_conn_id do append(&out, b)
	append(&out, len(p.source_conn_id))
	for b in p.source_conn_id do append(&out, b)
	len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
	header = header[0:len]
    case Initial_Packet:
	for b in make_version(p.version) do append(&out, b)
	append(&out, len(p.dest_conn_id))
	for b in p.dest_conn_id do append(&out, b)
	append(&out, len(p.source_conn_id))
	for b in p.source_conn_id do append(&out, b)
	len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
	header = header[0:len]
    case Zero_RTT_Packet:
	for b in make_version(p.version) do append(&out, b)
	append(&out, len(p.dest_conn_id))
	for b in p.dest_conn_id do append(&out, b)
	append(&out, len(p.source_conn_id))
	for b in p.source_conn_id do append(&out, b)
	len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
	header = header[0:len]
    case Handshake_Packet:
	for b in make_version(p.version) do append(&out, b)
	append(&out, len(p.dest_conn_id))
	for b in p.dest_conn_id do append(&out, b)
	append(&out, len(p.source_conn_id))
	for b in p.source_conn_id do append(&out, b)
	len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
	header = header[0:len]
    case Retry_Packet:
	for b in make_version(p.version) do append(&out, b)
	append(&out, len(p.dest_conn_id))
	for b in p.dest_conn_id do append(&out, b)
	append(&out, len(p.source_conn_id))
	for b in p.source_conn_id do append(&out, b)
	len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
	header = header[0:len]
    }
    return header
}

serialize_payload :: proc(packet: Packet) -> ([]u8, int, int) {
    switch p in packet {
    case One_RTT_Packet:
	return protect_payload(p.payload), nil
    case Version_Negotiation_Packet:
	outLen := len(p.supported_versions) * 4
	out = make([]u8, outLen)
	for v, i in p.supported_versions {
	    idx := i*4
	    make_version(v, out[idx:idx+4])
	}
	return out, nil, nil
    case Initial_Packet:
	token_len := make_variable_length_int(len(p.token))
	payload_len := make_variable_length_int(len(payload))
	packet_number := make_packet_number(p.packet_number)

	out : [dynamic]u8
	pkt_number_idx := len(token_len) + len(p.token) + len(payload_len)

	append(&out, ..token_len)
	append(&out, ..p.token)
	append(&out, ..payload_len)
	append(&out, ..packet_number)
	append(&out, ..protect_payload(p.payload))

	return out[:], pkt_number_idx, len(packet_number)
    case Zero_RTT_Packet:
	packet_number := make_packet_number(p.packet_number)
	payload_len := make_variable_length_int(p.payload_length)
	payload := protect_payload(p.payload)

	out : [dynamic]u8

	append(&out, ..payload_len)
	append(&out, ..packet_number)
	append(&out, ..payload)
	return out[:], len(payload_len), len(packet_number)
    case Handshake_Packet:
	packet_number := make_packet_number(p.packet_number)
	payload_len := make_variable_length_int(p.payload_length)
	payload := protect_payload(p.payload)

	out : [dynamic]u8

	append(&out, ..payload_len)
	append(&out, ..packet_number)
	append(&out, ..payload)
	return out[:], len(payload_len), len(packet_number)
    case Retry_Packet:
	return p.retry_token
	// retry integrity tag needs to be appended after everything else
    }
    return nil // will nver hit this, but the compiler complains
}



protect_payload :: proc(conn: ^Conn, packet: Packet) -> []u8 {
    return packet.payload // FIXME: implement properly

}

make_version :: proc(version: u32, out: ^[]u8) {
    for i:uint = 0; i < 4; i += 1 {
	out[3-i] = u8(version >> 8*i)
    }
}   

// FIXME: This function is used to CONSTRUCT the packet
// structs. Unless we want to remove the first byte arg
// entirely and just use this in serialization ... that might
// actually be better

/* we could optimize this by inlining/hardcoding instead
   of having this be a whole procedure */
make_first_byte :: proc(packet_untyped: Packet, packet_number_length: u8) -> u8 {
    header_form : u8 = 1 << 7
    fixed_bit : u8 = 1 << 6

    /* packet number lengths are hardcoded to three
       although I could probably make them smaller 
       now that we have the make_variable_length_int */

    switch packet in packet_untyped {
    case Version_Negotiation_Packet:
	return header_form
    case Initial_Packet:
	return header_form | fixed_bit | (packet_number_length - 1) 
    case Zero_RTT_Packet:
	return header_form | fixed_bit | 0x01 << 4 | (packet_number_length - 1)
    case Handshake_Packet:
	return header_form | fixed_bit | 0x02 << 4 | (packet_number_length - 1)
    case Retry_Packet:
	return header_form | fixed_bit | 0x03 << 4
    case One_RTT_Packet:
	spin_bit := packet.spin_bit ? 1 << 5 : 0
	key_phase := packet.key_phase ? 1 << 2 : 0 // 0x04
	return fixed_bit | spin_bit | key_phase | (packet_number_length - 1)
    }
}


apply_header_protection :: proc(conn: ^Conn, packet: ^[dynamic]u8, pkt_number_index: int, pkt_number_length: int) {
    encryption_level : ssl.QUIC_Encryption_Level
    #partial switch p in packet {
	case Initial_Packet:
	encryption_level = .ssl_encryption_initial
	case Zero_RTT_Packet:
	encryption_level = .ssl_encryption_early_data
	case Handshake_Packet:
	encryption_level = .ssl_encryption_handshake
	case One_RTT_Packet:
	encryption_level = .ssl_encryption_application
	case:
	return
    }

    hp_key := get_hp_key(conn, encryption_level)
    mask: = get_header_mask(hp_key, packet[pkt_number_index + 4 : pkt_number_index + 20], conn.encryption.ssl)

    packet_number_bytes := &packet[pkt_number_index : pkt_number_index + pkt_number_length]

	&packet[0], packet_number_bytes = add_header_protection(packet[0], packet_number_bytes, mask)

}
