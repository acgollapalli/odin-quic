/*
 * SDG                                                                         JJ
 */

package quic

import ssl "../ssl"

serialize_packet :: proc(conn: ^Conn, packet: Packet) -> []u8 {
	out: [dynamic]u8
	append(&out, 0) // placeholder first byte
	append(&out, ..serialize_header(packet))
	out[0] = make_first_byte(packet)

	pkt_number_index := serialize_payload(conn, packet, &out)

	apply_header_protection(conn, &out, packet, pkt_number_index)


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

serialize_payload :: proc(
	conn: ^Conn,
	packet: Packet,
	out: ^[dynamic]u8,
) -> int {
	payload_buf := make([]u8, 600) // FIXME: we shouldn't be using dynamics or doing this
	payload_buf = payload_buf[:0]
	defer delete(payload_buf)
	switch p in packet {
	case One_RTT_Packet:
		payload, tag := protect_payload(
			conn,
			p,
			out[:],
			serialize_frames(&payload_buf, p.packet_payload),
		)
		append(out, ..payload)
		append(out, ..tag)
		return 0
	case Version_Negotiation_Packet:
		for v, i in p.supported_versions {
			idx := i * 4
			version := out[idx:idx + 4]
			make_version_bytes(v, &version)
			append(out, ..version)
		}
		return 0
	case Initial_Packet:
		token_len := make_variable_length_int(len(p.token))
		payload_len := make_variable_length_int(len(p.packet_payload))
		packet_number := make_packet_number(p.packet_number)

		append(out, ..token_len)
		append(out, ..p.token)
		append(out, ..payload_len)

		pkt_number_idx := len(out)
		append(out, ..packet_number)

		payload, tag := protect_payload(
			conn,
			p,
			out[:],
			serialize_frames(&payload_buf, p.packet_payload),
		)
		append(out, ..payload)
		append(out, ..tag)

		return pkt_number_idx
	case Zero_RTT_Packet:
		packet_number := make_packet_number(p.packet_number)
		payload_len := make_variable_length_int(len(p.packet_payload))

		append(out, ..payload_len)

		pkt_number_idx := len(out)
		append(out, ..packet_number)

		payload, tag := protect_payload(
			conn,
			p,
			out[:],
			serialize_frames(&payload_buf, p.packet_payload),
		)
		append(out, ..payload)
		append(out, ..tag)

		return pkt_number_idx
	case Handshake_Packet:
		packet_number := make_packet_number(p.packet_number)
		payload_len := make_variable_length_int(len(p.packet_payload))

		append(out, ..payload_len)
		pkt_number_idx := len(out)

		append(out, ..packet_number)
		payload, tag := protect_payload(
			conn,
			p,
			out[:],
			serialize_frames(&payload_buf, p.packet_payload),
		)

		append(out, ..payload)
		append(out, ..tag)
		return pkt_number_idx
	case Retry_Packet:
		append(out, ..p.retry_token)

		// constructing pseudo packet
		pseudo_packet := make([dynamic]u8)
		append(&pseudo_packet, u8(len(p.original_dest_conn_id)))
		append(&pseudo_packet, ..p.original_dest_conn_id)

		// getting the retry integrity tag
		_, tag := protect_payload(conn, p, pseudo_packet[:], payload_buf)

		delete(pseudo_packet) // cleanup

		append(out, ..tag)

		return 0
	}
	return 0 // will nver hit this, but the compiler complains
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
make_first_byte :: proc(packet_untyped: Packet) -> u8 {
	header_form: u8 = 1 << 7
	fixed_bit: u8 = 1 << 6

	/* packet number lengths are hardcoded to three
       although I could probably make them smaller 
       now that we have the make_variable_length_int */

	switch packet in packet_untyped {
	case Version_Negotiation_Packet:
		return header_form
	case Initial_Packet:
		// FIXME: This is ugly
		packet_number_length := u8(len(make_packet_number(packet.packet_number)))
		return header_form | fixed_bit | (packet_number_length - 1)
	case Zero_RTT_Packet:
		packet_number_length := u8(len(make_packet_number(packet.packet_number)))
		return header_form | fixed_bit | 0x01 << 4 | (packet_number_length - 1)
	case Handshake_Packet:
		packet_number_length := u8(len(make_packet_number(packet.packet_number)))
		return header_form | fixed_bit | 0x02 << 4 | (packet_number_length - 1)
	case Retry_Packet:
		return header_form | fixed_bit | 0x03 << 4
	case One_RTT_Packet:
		spin_bit: u8 = packet.spin_bit ? 1 << 5 : 0
		key_phase: u8 = packet.key_phase ? 1 << 2 : 0 // 0x04
		packet_number_length := u8(len(make_packet_number(packet.packet_number)))
		return fixed_bit | spin_bit | key_phase | (packet_number_length - 1)
	}
	return 0 // unreachable (but compiler)
}

make_variable_length_int :: proc(
	#any_int i: u64,
) -> (
	[]u8,
	bool,
) #optional_ok {
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
) {
	packet_number_length: int
	switch packet[0] | 0x03 {
	case 0x00:
		packet_number_length = 1
	case 0x01:
		packet_number_length = 2
	case 0x02:
		packet_number_length = 4
	case 0x03:
		packet_number_length = 8
	}
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

	hp_key := get_hp_key(conn, encryption_level, .Write)
	mask := get_header_mask(
		packet[pkt_number_index + 4:pkt_number_index + 20],
		conn,
		encryption_level,
		Secret_Role.Write,
	)

	packet_number_bytes := packet[pkt_number_index:pkt_number_index +
	packet_number_length]

	packet[0], packet_number_bytes = add_header_protection(
		packet[0],
		packet_number_bytes,
		mask,
	)
}

/*
 *  explicit mutation of payload slice for the sake of convenience 
 *  when serializing frames
 */
increment_payload :: proc(payload: ^[]u8, #any_int increment: int) {
	payload^ = payload[0:len(payload) + increment]
}


/*
 *  A way to do a variable length int that implies a single buffer
 *  we skip an allocation this way, but if you use an arena, it may not
 *  be any faster.
 */
add_variable_length_int :: proc(out: ^[]u8, #any_int i: u64) -> bool {
	k: u8
	mask: u8

	// find length and mask of variable length int
	switch {
	case i < 64:
		k = 1
	case i < 16384:
		k = 2
		mask = (1 << 6)
	case i < 1073741824:
		k = 4
		mask = (2 << 6)
	case i < 4611686018427387904:
		k = 8
		mask = (3 << 6)
	case:
		return false

	}

	// make space for it in the payload slice
	increment_payload(out, k)

	// add the variable to the slice
	for j: u8 = 1; k <= j; j += 1 {
		out^[len(out) - int(j)] = u8(i >> (8 * (j - 1)))
	}

	// add the mask to the first byte of our variable length int
	out^[len(out) - int(k)] |= mask
	return true
}

add_bytes :: proc(payload: ^[]u8, bytes: []u8) {
	idx := len(payload)
	increment_payload(payload, len(bytes))

	for b, i in bytes { 	// FIXME: Is this the kind of thing you can do with SIMD?
		payload^[idx + i] = b
	}
}
