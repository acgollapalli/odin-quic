package quic


// handle incoming packet
// FIXME: we should be using core:bytes reader here
// FIXME: I THINK we have the Endpoint of the peer from UDP
// MAYBE we should use that in matching via context
// FIXME: We need to handle the case of MULTIPLE packets in a single datagram. ALL of them need to have the same dest_id
handle_incoming_packet :: proc(packet: []byte) ->  (Packet, []byte, Transport_Error) {
    // what kind of thing are we working with
    packet_type, err = what_kind_of_packet(packet) or_return
    dest_conn_id_len : u8
    src_conn_id_len: u8
    dest_conn_id : Connection_Id // maybe we --- this?
    src_conn_id : Connection_Id

    if packet_type == .One_RTT {
	// we always return conn_ids as uuids
	// uuid's are encoded in 16 bytes
	dest_conn_id_len = 16
	Connection_Id, err = uuid.read(string(packet[1:17]))
	if err {
	    // we couldn't read the ID, which means
	    // that they're using an ID we didn't issue
	    // in what SHOULD be an authenticated packet
	    // FIXME: This might be the wrong error
	    // MAYBE: we should just drop the packet
	    // UPDATE: We should only see this if a packet
	    // is in the same datagram as an initial packet
	    // which should create a conn in the address
	    // validation state or similar.
	    return nil, nil, .PROTOCOL_VIOLATION // just drop the packet... although error frames require an error message. We may need to do better than this
	}
    } else {
	// get the length of the connection id
	dest_conn_id_len = packet[5]

	// for v1 of QUIC, dest_conn_ids must be < 20
	if dest_conn_id_len > 20 && packet_type != .Version_Negotiation {
	    return nil, nil, .VERSION_NEGOTIATION_ERROR
	} else {
	    idx := 6+dest_conn_id_len
	    dest_conn_id = packet[6:idx]

	    src_conn_id_ln = packet[idx]
	    if src_conn_id_len > 20 && packet_type != .Version_Negotiation {
		// ONLY holds for version 1 and 2 at the moment
		return nil, nil, .PROTOCOL_VIOLATION
	    }
	    idx += 1
	    src_conn_id = packet[idx: idx + src_conn_id_ln]
	}
    }


    packet := packet // let's mutate the slice as we iterate

    switch packet_type {
    case .Initial:
	packet_number_length := packet[0] & 0x03 // last two bits

	packet = packet[1:]
	version := get_version(packet)
	packet = packet[4:]

	// we know the dest_conn_id and src_conn_id
	conn_idx := 1 + conn_id_len + 1 + src_conn_id_len
	packet = packet[conn_idx:]

	token_length, offset := get_variable_length_int(packet)
	packet = packet[offset:]
	
	token := packet[:token_length]
	packet = packet[token_length:]

	payload_length, offset := get_variable_length_int(packet)
	packet = packet[offset:] // FIXME: Maybe the function can do this part?

	packet_number: u32
	pkt_idx := ln_idx + length
	for b in packet[pkt_idx, pkt_idx + packet_number_length] {
	    packet_number = (u32)b + (packet_number << 8)
	}
	packet = packet[packet_number_length:]

	packet_payload := packet[:payload_length]
	packet = packet[packet_payload_length:]

	return Initial_Packet{
	    version: version,
	    dest_conn_id: dest_conn_id,
	    source_conn_id: src_conn_id,
	    packet_number: packet_number,
	    token: token,
	    packet_payload: packet_payload,
	}, packet, nil

    case .Handshake:
	packet_number_length := packet[0] & 0x03 // last two bits
	packet = packet[1:]

	version := get_version(packet)
	packet = packet[4:]

	// we know the dest_conn_id and src_conn_id
	conn_idx := 1 + conn_id_len + 1 + src_conn_id_len
	packet = packet[conn_idx:]

	length, offset := get_variable_length_int(packet)
	packet = packet[offset:]

	packet_number: u32
	pkt_idx := ln_idx + length
	for b in packet[pkt_idx, pkt_idx + packet_number_length] {
	    packet_number = (u32)b + (packet_number << 8)
	}
	packet = packet[packet_number_length:]

	packet_payload := packet[:packet_payload_length]
	packet = packet[packet_payload_length:]

	return Handshake_Packet{
	    version: version,
	    dest_conn_id: dest_conn_id,
	    source_conn_id: src_conn_id,
	    packet_number: packet_number,
	    packet_payload: packet_payload
	}, packet, nil
    case .Retry:
	tk_idx := 13 + conn_id_len + 8 + src_conn_id_len
	tk_end := len(packet) - 16  // integrity tag is 128 bits
	return Retry_Packet{
	    version: version,
	    dest_conn_id: dest_conn_id,
	    source_conn_id: src_conn_id,
	    retry_token: packet[tk_idx : tk_end],
	    retry_integrity_tag: packet[tk_end:],
	}, nil, nil
    case .Version_Negotiation:
	packet = packet[1:]

	version := get_version(packet)
	packet = packet[4:]

	// we know the dest_conn_id and src_conn_id
	conn_idx := 1 + conn_id_len + 1 + src_conn_id_len
	packet = packet[conn_idx:]

	versions: [dynamic]u32
	for len(packet) >= 8 {
	    append(versions, packet[:8])
	    packet = packet[8:]
	}

	return Version_Negotiation_Packet{
	    version: version,
	    dest_conn_id: dest_conn_id,
	    source_conn_id: src_conn_id,
	    supported_versions: versions
	}, nil, nil
    case .Zero_RTT:
	packet = packet[1:]

	version := get_version(packet)
	packet = packet[4:]

	// we know the dest_conn_id and src_conn_id
	conn_idx := 1 + conn_id_len + 1 + src_conn_id_len
	packet = packet[conn_idx:]

	payload_length, offset := get_variable_length_int(packet)
	packet = packet[offset:] // FIXME: Maybe the function can do this part?

	packet_number: u32
	pkt_idx := ln_idx + length
	for b in packet[pkt_idx, pkt_idx + packet_number_length] {
	    packet_number = (u32)b + (packet_number << 8)
	}
	packet = packet[packet_number_length:]

	packet_payload := packet[:payload_length]
	packet = packet[packet_payload_length:]

	return Zero_RTT_Packet{
	    version: version,
	    dest_conn_id: dest_conn_id,
	    source_conn_id: src_conn_id,
	    packet_number: packet_number,
	    packet_payload: packet_payload,
	}, packet, nil
    case One_RTT:
	spin_bit = packet[0] & (1 << 5)
	key_phase = packet[0] & (1 << 2)

	packet = packet[1:]

	// we know the dest_conn_id and src_conn_id
	conn_idx := 1 + conn_id_len + 1 + src_conn_id_len
	packet = packet[conn_idx:]

	payload_length, offset := get_variable_length_int(packet)
	packet = packet[offset:] // FIXME: Maybe the function can do this part?

	packet_number: u32
	pkt_idx := ln_idx + length
	for b in packet[pkt_idx, pkt_idx + packet_number_length] {
	    packet_number = (u32)b + (packet_number << 8)
	}
	packet = packet[packet_number_length:]

	packet_payload := packet[:payload_length]
	packet = packet[packet_payload_length:]

	return One_RTT_Packet{
	    spin_bit: spin_bit,
	    key_phase: key_phase,
	    dest_conn_id: dest_conn_id,
	    packet_number: packet_number
	}, packet, nil
    }
}

get_version :: proc(version_bytes: []byte) -> u32 {
    version: u32
	for b in version_bytes {
	    version = (u32)b + (version << 8)
	}
    return version
}

get_variable_length_int :: proc(packet: []byte) -> (n: int, len: int) {
    2msb := packet[0] >> 6
    n = packet[0] & ~(2 << 6)

    switch 2msb {
    case 0x00:
	len = 1
	return
    case 0x01:
	len = 2
    case 0x02:
	len = 4
    case 0x03:
	len = 8
    }

    for i := 1; i < len; i += 1 {
	n = packet[i] + (n << 8)
    }
    return
}

what_kind_of_packet :: proc(packet: []byte) -> (Packet_Type, Transport_Error) {
    first_byte := packet[0]
    is_long_header := first_byte & (1 << 7) // first bit
    is_fixed_bit := first_byte & (1 << 6)    // second bit
    version : u32 // only one version right now, we're just getting it out of the way
    conn_id_length : u64a

    // getting the conn_id_length (see packet.odin)
    if is_long_header {
	if is_fixed_bit {
	    return handle_version_negotiation(packet)
	} else {
	    return handle_long_header(packet)
	}
	
    } else {
	return .One_RTT, nil
    }
}

// FIXME: Only version 1 of QUIC is supported at the moment
handle_version_negotiation ::proc (packet: []byte) {
    version := get_version(packet[1:5])

    if version != 0 {
	fmt.println("version was not 0 on version negotiation packet")
	return nil, .PROTOCOL_ERROR
    } else {
	return .Version_Negotiation, nil
    }
}

handle_long_header :: proc (packet: []byte) {
    first_byte := packet[0]
    first_byte = first_byte << 2
    first_byte = first_byte >> 6

    // first byte now only has bits 5 and 6
    // long header packets are 0x01 through 0x03
    // and are enumerated in Packet_Type as 1-4
    return first_byte + 1, nil
}
