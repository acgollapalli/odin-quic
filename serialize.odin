/*

SDG                                                                           JJ

                                  Packet Serialization

*/

package quic

import ssl "../ssl"
import "core:fmt"
import "core:sync"

// expects two byte arrays currently, one for the header and one for the payload
// it's expressed as a slice of slices for abi purposes
serialize_packet :: proc(
	conn: ^Conn,// TODO: Datagrams need to be padded for initial datagrams
	packet: Packet,
	out: [][]u8,
	arena_alloc := context.temp_allocator,
) -> (
	bytes_written: int,
) {
	defer free_all(arena_alloc) // we use temp allocator or other arena and free at the end

	header_cursor, payload_cursor := out[0][1:], out[1][:]

	payload_len := serialize_payload(packet, &payload_cursor)
	header_len, pn_len := serialize_header(
		conn,
		packet,
		payload_len,
		&header_cursor,
	)

	out[0][0] = make_first_byte(packet, pn_len) // packet_number length is in first byte
	header_len += 1 // include first_byte in header_len

	header, payload := out[0][:header_len], out[1][:payload_len]

	apply_packet_protection(conn, header, payload, packet, &payload_cursor)
	apply_header_protection(conn, header, payload, pn_len, packet)

	header_written := len(out[0]) - len(header_cursor)
	out[0] = out[0][:header_written]

	payload_written := len(out[1]) - len(payload_cursor)
	out[1] = out[1][:payload_written]

	return header_written + payload_written
}

// do this first so you can get the payload length
serialize_payload :: proc(
	packet: Packet,
	cursor: ^[]u8,
) -> (
	bytes_written: int,
) {
	bytes_written = len(cursor)
	
	// odinfmt:disable
	switch p in packet {
	case Initial_Packet:    serialize_frames(p.packet_payload, cursor)
	case Zero_RTT_Packet:   serialize_frames(p.packet_payload, cursor)
	case Handshake_Packet:  serialize_frames(p.packet_payload, cursor)
	case Retry_Packet: 		cursor_append(p.retry_token, cursor)
	case One_RTT_Packet:    serialize_frames(p.packet_payload, cursor)
	case Version_Negotiation_Packet:
		for v, i in p.supported_versions {
			idx := i * 4
			make_version_bytes(v, cursor)
			cursor^ = cursor[4:] // versions are always 4 bytes
		}
	}
	// odinfmt:enable

	bytes_written -= len(cursor)
	return
}

// header
// everything up to and including the packet_number
serialize_header :: proc(
	conn: ^Conn,
	packet: Packet,
	payload_len: int,
	cursor: ^[]u8,
) -> (
	bytes_written: int,
	pn_len: int,
) {
	bytes_written = len(cursor)

	
	// odinfmt:disable
	switch p in packet { 	// FIXME: Holy code duplication batman!
	case Version_Negotiation_Packet:
		cursor_append				 	([]u8{0, 0, 0, 0}, cursor)
		cursor_append_one			 	(u8(len(p.dest_conn_id)), cursor)
		cursor_append				 	(p.dest_conn_id, cursor)
		cursor_append_one			 	(u8(len(p.source_conn_id)), cursor)
		cursor_append				 	(p.source_conn_id, cursor)
	case Initial_Packet:
		packet_number_bytes := encode_pn_from_conn(conn, p.packet_number, .Initial)
		pn_len = len(packet_number_bytes)
		payload_len := payload_len + pn_len + 16 // includes packet_number and aead tag

		cursor_append				 	(make_version(p.version), cursor)
		cursor_append_one			 	(u8(len(p.dest_conn_id)), cursor)
		cursor_append				 	(p.dest_conn_id, cursor)
		cursor_append_one			 	(u8(len(p.source_conn_id)), cursor)
		cursor_append				 	(p.source_conn_id, cursor)
		encode_and_cursor_append_int 	(len(p.token), cursor)
		cursor_append                	(p.token, cursor)
		encode_and_cursor_append_int 	(payload_len, cursor)
		cursor_append					(packet_number_bytes, cursor)
		
	case Handshake_Packet:
		packet_number_bytes := encode_pn_from_conn(conn, p.packet_number, .Handshake)
		pn_len = len(packet_number_bytes)
		payload_len := payload_len + pn_len + 16 // includes packet_number and aead tag

		cursor_append 				 	(make_version(p.version), cursor)
		cursor_append_one 			 	(u8(len(p.dest_conn_id)), cursor)
		cursor_append 				 	(p.dest_conn_id, cursor)
		cursor_append_one 			 	(u8(len(p.source_conn_id)), cursor)
		cursor_append 				 	(p.source_conn_id, cursor)
		encode_and_cursor_append_int 	(payload_len, cursor)
		cursor_append					(packet_number_bytes, cursor)

	case Zero_RTT_Packet:
		packet_number_bytes := encode_pn_from_conn(conn, p.packet_number, .Application)
		pn_len = len(packet_number_bytes)
		payload_len := payload_len + pn_len + 16 // includes packet_number and aead tag

		cursor_append 				 	(make_version(p.version), cursor)
		cursor_append_one 			 	(u8(len(p.dest_conn_id)), cursor)
		cursor_append 				 	(p.dest_conn_id, cursor)
		cursor_append_one 			 	(u8(len(p.source_conn_id)), cursor)
		cursor_append 				 	(p.source_conn_id, cursor)
		encode_and_cursor_append_int 	(payload_len, cursor)
		cursor_append					(packet_number_bytes, cursor)

	case One_RTT_Packet:
		packet_number_bytes := encode_pn_from_conn(conn, p.packet_number, .Application)
		pn_len = len(packet_number_bytes)
		payload_len := payload_len + pn_len + 16 // includes packet_number and aead tag

		cursor_append				 	(p.dest_conn_id, cursor)
		cursor_append					(packet_number_bytes, cursor)

	case Retry_Packet:
		cursor_append 					(make_version(p.version), cursor)
		cursor_append_one 				(u8(len(p.dest_conn_id)), cursor)
		cursor_append 					(p.dest_conn_id, cursor)
		cursor_append_one 				(u8(len(p.source_conn_id)), cursor)
		cursor_append 					(p.source_conn_id, cursor)
	}
	// odinfmt:enable

	bytes_written -= len(cursor)
	return
}

apply_packet_protection :: proc(
	conn: ^Conn,
	header: []u8,
	payload: []u8,
	packet: Packet,
	cursor: ^[]u8,
) {
	_, is_version_negotiation := packet.(Version_Negotiation_Packet)
	if !is_version_negotiation {
		aead_tag := cursor[:16]
		cursor^ = cursor[16:] // decrement cursor for encryption tag

		// odinfmt:disable
		#partial switch p in packet {
			case Initial_Packet:   protect_payload(conn, packet, header, payload, aead_tag)
			case Handshake_Packet: protect_payload(conn, packet, header, payload, aead_tag) 
			case Zero_RTT_Packet:  protect_payload(conn, packet, header, payload, aead_tag) 
			case One_RTT_Packet:   protect_payload(conn, packet, header, payload, aead_tag) 
			case Retry_Packet:
			pseud := make_retry_pseudo_packet(p, header, payload, context.temp_allocator)[:]
				protect_payload(conn, packet, pseud, nil, aead_tag)
		}
		// odinfmt:enable
	}
}

get_encryption_level :: proc(
	packet: Packet,
) -> (
	level: ssl.QUIC_Encryption_Level,
	ok: bool,
) {
	// odinfmt:disable
	#partial switch p in packet {
	case Initial_Packet: 	level = .Initial_Encryption
	case Zero_RTT_Packet: 	level = .Early_Data_Encryption
	case Handshake_Packet: 	level = .Handshake_Encryption
	case One_RTT_Packet: 	level = .Application_Encryption
	case: 					return
	}
	// odinfmt:enable

	ok = true
	return
}

apply_header_protection :: proc(
	conn: ^Conn,
	header: []u8,
	payload: []u8,
	pn_len: int,
	packet: Packet,
) {
	level, has_level := get_encryption_level(packet)
	if !has_level do return

	hp_key := get_hp_key(conn, level, .Write)

	sample_offset := 4 - pn_len
	sample := payload[sample_offset:][:16]
	mask, m_ok := get_header_mask(sample, conn, level, .Write)
	assert(m_ok, "could not get header mask when serializing")

	packet_number_bytes := header[len(header) - pn_len:]
	assert(len(packet_number_bytes) == pn_len, "bad packet_number offset")

	header[0], packet_number_bytes = add_header_protection(
		header[0],
		packet_number_bytes,
		mask,
	)
}

make_version_bytes :: proc(version: u32, out: ^[]u8) {
	for i: u32 = 0; i < 4; i += 1 {
		out[3 - i] = u8(version >> (8 * i))
	}
}


// FIXME: when we write the zero-copy version, this should go away
make_version :: proc(version: u32) -> []u8 {
	out := make([]u8, 4, context.temp_allocator)
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
make_first_byte :: proc(packet_untyped: Packet, #any_int pn_len: u64) -> u8 {
	header_form: u8 = 1 << 7
	fixed_bit: u8 = 1 << 6

	/* packet number lengths are hardcoded to three
       although I could probably make them smaller 
       now that we have the make_variable_length_int */
	packet_number_length := u8(pn_len)

	switch packet in packet_untyped {
	case Version_Negotiation_Packet:
		return header_form
	case Initial_Packet:
		// FIXME: This is ugly
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
	return 0
}

make_variable_length_int :: proc(
	#any_int i: u64,
) -> (
	[]u8,
	bool,
) #optional_ok {
	out_a := make([]u8, 8, context.temp_allocator)

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

encode_pn_from_conn :: proc(
	conn: ^Conn,
	packet_number: u64,
	pn_space: Packet_Number_Space,
) -> (
	packet_number_bytes: []u8,
) {
	largest_acked := pn_largest_acked(conn, pn_space)
	packet_number_bytes = encode_packet_number(packet_number, largest_acked)
	return
}

encode_and_cursor_append_int :: proc(
	#any_int n: u64,
	cursor: ^[]u8,
) -> (
	bytes_written: int,
) {
	n_encoded := make_variable_length_int(n)
	return cursor_append(n_encoded, cursor)
}
