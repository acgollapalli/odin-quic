package quic

import ssl "../odin-ssl"

serialize_packet :: proc(conn: ^Conn, packet: Packet) -> []u8 {
	out: [dynamic]u8
	append(&out, 0) // placeholder first byte
	append(&out, ..serialize_header(packet))
	payload, pkt_number_index, pkt_number_length := serialize_payload(conn, packet)
	append(&out, ..payload)

	out[0] = make_first_byte(packet, u8(pkt_number_length))

	apply_header_protection(conn, &out, packet, pkt_number_index, pkt_number_length)


	// FIXME: at the end, we need to add the retry integrity tag!


	return out[:]
}

// header
// includes version, destination connection id + length source id + length
serialize_header :: proc(packet: Packet) -> []u8 {
	header: [dynamic]u8

	switch p in packet { 	// FIXME: Holy code duplication batman!
	case One_RTT_Packet:
		for b in p.dest_conn_id do append(&header, b)
		return header[0:len(p.dest_conn_id) + 1]
	case Version_Negotiation_Packet:
		append(&header, ..[]u8{0, 0, 0, 0})
		append(&header, u8(len(p.dest_conn_id)))
		for b in p.dest_conn_id do append(&header, b)
		append(&header, u8(len(p.source_conn_id)))
		for b in p.source_conn_id do append(&header, b)
		len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
		return header[0:len]
	case Initial_Packet:
		for b in make_version(p.version) do append(&header, b)
		append(&header, u8(len(p.dest_conn_id)))
		for b in p.dest_conn_id do append(&header, b)
		append(&header, u8(len(p.source_conn_id)))
		for b in p.source_conn_id do append(&header, b)
		len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
		return header[0:len]
	case Zero_RTT_Packet:
		for b in make_version(p.version) do append(&header, b)
		append(&header, u8(len(p.dest_conn_id)))
		for b in p.dest_conn_id do append(&header, b)
		append(&header, u8(len(p.source_conn_id)))
		for b in p.source_conn_id do append(&header, b)
		len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
		return header[0:len]
	case Handshake_Packet:
		for b in make_version(p.version) do append(&header, b)
		append(&header, u8(len(p.dest_conn_id)))
		for b in p.dest_conn_id do append(&header, b)
		append(&header, u8(len(p.source_conn_id)))
		for b in p.source_conn_id do append(&header, b)
		len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
		return header[0:len]
	case Retry_Packet:
		for b in make_version(p.version) do append(&header, b)
		append(&header, u8(len(p.dest_conn_id)))
		for b in p.dest_conn_id do append(&header, b)
		append(&header, u8(len(p.source_conn_id)))
		for b in p.source_conn_id do append(&header, b)
		len := 3 + len(p.dest_conn_id) + len(p.source_conn_id)
		return header[0:len]
	}
	return header[:]
}

serialize_payload :: proc(conn: ^Conn, packet: Packet) -> ([]u8, int, int) {
	switch p in packet {
	case One_RTT_Packet:
		return protect_payload(conn, p), 0, 0
	case Version_Negotiation_Packet:
		outLen := len(p.supported_versions) * 4
		out := make([]u8, outLen)
		for v, i in p.supported_versions {
			idx := i * 4
			version := out[idx:idx + 4]
			make_version_bytes(v, &version)
		}
		return out, 0, 0
	case Initial_Packet:
		token_len := make_variable_length_int(len(p.token))
		payload_len := make_variable_length_int(len(p.packet_payload))
		packet_number := make_packet_number(p.packet_number)

		out: [dynamic]u8
		pkt_number_idx := len(token_len) + len(p.token) + len(payload_len)

		append(&out, ..token_len)
		append(&out, ..p.token)
		append(&out, ..payload_len)
		append(&out, ..packet_number)
		append(&out, ..protect_payload(conn, p))

		return out[:], pkt_number_idx, len(packet_number)
	case Zero_RTT_Packet:
		packet_number := make_packet_number(p.packet_number)
		payload_len := make_variable_length_int(len(p.packet_payload))
		payload := protect_payload(conn, p)

		out: [dynamic]u8

		append(&out, ..payload_len)
		append(&out, ..packet_number)
		append(&out, ..payload)
		return out[:], len(payload_len), len(packet_number)
	case Handshake_Packet:
		packet_number := make_packet_number(p.packet_number)
		payload_len := make_variable_length_int(len(p.packet_payload))
		payload := protect_payload(conn, p)

		out: [dynamic]u8

		append(&out, ..payload_len)
		append(&out, ..packet_number)
		append(&out, ..payload)
		return out[:], len(payload_len), len(packet_number)
	case Retry_Packet:
		return p.retry_token, 0, 0
	// retry integrity tag needs to be appended after everything else
	}
	return nil, 0, 0 // will nver hit this, but the compiler complains
}


protect_payload :: proc(conn: ^Conn, packet: Packet) -> []u8 {
	//return packet.payload // FIXME: implement properly

}

make_version_bytes :: proc(version: u32, out: ^[]u8) {
	for i: u32 = 0; i < 4; i += 1 {
		out[3 - i] = u8(version >> 8 * i)
	}
}


// FIXME: when we write the zero-copy version, this should go away
make_version :: proc(version: u32) -> []u8 {
	out := make([]u8, 4)
	make_version_bytes(version, &out)
	return out
}

make_packet_number :: make_version


// FIXME: This function is used to CONSTRUCT the packet
// structs. Unless we want to remove the first byte arg
// entirely and just use this in serialization ... that might
// actually be better

/* we could optimize this by inlining/hardcoding instead
   of having this be a whole procedure */
make_first_byte :: proc(packet_untyped: Packet, packet_number_length: u8) -> u8 {
	header_form: u8 = 1 << 7
	fixed_bit: u8 = 1 << 6

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
		spin_bit: u8 = packet.spin_bit ? 1 << 5 : 0
		key_phase: u8 = packet.key_phase ? 1 << 2 : 0 // 0x04
		return fixed_bit | spin_bit | key_phase | (packet_number_length - 1)
	}
	return 0 // unreachable (but compiler)
}

make_variable_length_int :: proc(#any_int i: u64) -> ([]u8, bool) #optional_ok {
	out_a := make([]u8, 8)

	//n : u64
	for k: u8 = 0; k < 8; k += 1 {
		out_a[7 - k] = (u8)(i >> (8 * k))
	}

	switch {
	case i < 64:
		return out_a[7:], true
	case i < 16384:
		out_a[6] = out_a[6] | (1 << 6)
		return out_a[6:], true
	case i < 1073741824:
		out_a[4] = out_a[4] | (2 << 6)
		return out_a[4:], true
	case i < 4611686018427387904:
		out_a[0] = out_a[0] | (3 << 6)
		return out_a[:], true
	case:
		return nil, false
	}
}

apply_header_protection :: proc(
	conn: ^Conn,
	packet: ^[dynamic]u8,
	pkt_obj: Packet,
	pkt_number_index: int,
	pkt_number_length: int,
) {
	encryption_level: ssl.QUIC_Encryption_Level
	#partial switch p in pkt_obj {
	case Initial_Packet:
		encryption_level = .Initial_Encryption
	case Zero_RTT_Packet:
		encryption_level = .Early_Data_Encryption
	case Handshake_Packet:
		encryption_level = .Handshake_Encryption
	case One_RTT_Packet:
		encryption_level = .Application_Encryption
	case:
		return
	}

	hp_key := get_hp_key(conn, encryption_level)
	mask := get_header_mask(
		packet[pkt_number_index + 4:pkt_number_index + 20],
		conn,
		encryption_level,
	)

	packet_number_bytes := packet[pkt_number_index:pkt_number_index + pkt_number_length]

	packet[0], packet_number_bytes = add_header_protection(packet[0], packet_number_bytes, mask)

}
