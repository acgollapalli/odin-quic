package quic

Partial_Packet :: struct {
    first_byte: byte,
    version: u32,
    dest_conn_id: Connection_id,
    src_conn_id: Connection_Id,
}


handle_datagram :: proc(dg: []byte, ctx: Context) {
    if len(dg) < 1280 {
	return
    }

// by default the context has default values for its parameters which is decided in the parser
    packets := [dynamic]Packet
    defer delete(packets)
    dg := dg

    dest_conn_id : Connection_id

    for len(dg) > 0 { // FIXME: how do we handle cases where we don't have enough for a full packet?
	packet, dg, err := process_incoming_packet(db, ctx) or_return // FIXME: we're just passing the error up

	if dest_conn_id == nil {
	    dest_conn_id = packet.dest_conn_id
	    append(&packets, packet)
	} else if dest_conn_id == packet.dest_conn_id  {
	    append(&packets, packet) // FIXME: instead of appending to a dynamic array, we should just handle the packet
	}
    }
}


// handle incoming packet
// FIXME: we should be using core:bytes reader here
process_incoming_packet :: proc(packet: []byte, ctx: Context) ->  (Packet, []byte, Transport_Error) {
    packet := packet // let's mutate the slice as we iterate

    /* This is under header protection
       and we can't read the latter half of it yet
       however we can find out what kind of thing we're working with */
    first_byte := packet[0] 
    packet_type = what_kind_of_packet(first_byte)
    packet = packet[1:]
    version : u32 // 1-RTT packets don't have this, so we don't know if this is defined
    
    dest_conn_id_len : u8
    src_conn_id_len: u8
    dest_conn_id : Connection_Id // maybe we --- this?
    src_conn_id : Connection_Id

    if packet_type == .One_RTT {
	// we always return conn_ids as uuids
	// uuid's are encoded in 16 bytes
	dest_conn_id_len = 16
	Connection_Id, packet[0:16]
	packet = packet[16:]
    } else {
	// get version
	for b in packet[0:4] {
	    version = (u32)b + (version << 8)
	}
	packet = packet[4:]

	// get the length of the connection id
	dest_conn_id_len = packet[0]
	packet = packet[1:]

	// for v1 of QUIC, dest_conn_ids must be < 20
	if dest_conn_id_len > 20 && packet_type != .Version_Negotiation {
	    return nil, nil, .VERSION_NEGOTIATION_ERROR
	} else {
	    dest_conn_id = packet[0:dest_conn_id_len]
	    packet = packet[dest_conn_id_len:]

	    if src_conn_id_len > 20 && packet_type != .Version_Negotiation {
		// ONLY holds for version 1 and 2 at the moment
		return nil, nil, .PROTOCOL_VIOLATION
	    }
	    src_conn_id = packet[0: src_conn_id_len]
	    packet = packet[src_conn_id_len:]
	}
    }

    /*
     * We've about reached the point where we can read anything that's unprotected
     * and common to all the packet types. The way we decrypt packet types is unique
     * to each packet type, so we've got handlers for each one.
     */

    partial_packet = Partial_Packet{
	first_byte = first_byte,
	version = version,
	dest_conn_id = Connection_Id,
	src_conn_id = Connection_Id,
    }

    switch packet_type {
    case .Initial:
	return process_initial(partial_packet, packet)
    case .Handshake:
	return process_handshake(partial_packet, packet, ctx)
    case .Retry:
	return process_retry(partial_packet, packet, ctx)
    case .Version_Negotiation:
	return process_version_negotiation(partial_packet, packet, ctx)
    case .Zero_RTT:
	return process_zero_rtt(partial_packet, packet, ctx)
    case One_RTT:
	return process_one_rtt(partial_packet, packet, ctx)
    }
}

get_variable_length_int :: proc(packet: []byte) -> (n: u64, len: int) {
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

what_kind_of_packet :: proc(first_byte: byte) -> Packet_Type {
    is_long_header := first_byte & (1 << 7) // first bit
    is_fixed_bit := first_byte & (1 << 6)    // second bit

    // getting the conn_id_length (see packet.odin)
    if is_long_header {
	if is_fixed_bit {
	    return .Version_Negotiation
	} else {
            first_byte := first_byte
	    first_byte = first_byte << 2
            first_byte = first_byte >> 6

            // first byte now only has bits 5 and 6
            // long header packets are 0x01 through 0x03
            // and are enumerated in Packet_Type as 1-4
            return (Packet_Type)(first_byte + 1)
	}
    } else {
	return .One_RTT
    }
}


// retrieve the conn object
retrieve_conn :: proc(ctx: Context, packet: []byte) -> Conn {
    

}

process_initial :: proc(using partial: Partial_Packet, packet: []u8) -> (Packet, []u8, Transport_Error) {

    // REMINDER: keys are determined by the FIRST initial packet. Any subsequent ones that aren't determined
    // by a retry use the same keys. On a retry. The keys should be marked INVALID.
    role: Role
    hp_key: []byte
    if conn := findConn(dest_conn_id); conn != nil { // FIXME: REPLACE WITH ZII
	sync.mutex_guard(conn.lock)
	secrets := conn.secrets[.ssl_encryption_initial]
	role = conn.role
	if role != .Server {
	    hp_key = secrets.client_hp  // I THINK this is right
	} else {
	    hp_key = secrets.server_hp // FIXME: Use examples in RFC to PROVE this is right
	}
    } else {
	// FIXME: we should CONSIDER adding the conn here (BUT... it's based off the dest id, so do we NEED TO? maybe it should be handled by the frame handler, not down here)
	secrets := determine_initial_secret(dest_conn_id)
	hp_key = secrets.client_hp
    }


    // FIXME: Should we be decrypting packet protection here?
    packet := packet
    token_length, offset := get_variable_length_int(packet)
    packet = packet[offset:]
    
    token := packet[:token_length]
    packet = packet[token_length:]
    
    payload_length, offset := get_variable_length_int(packet)
    packet = packet[offset:] // FIXME: Maybe the function can do this part?


    mask := get_header_mask(hp_key, packet[4:20], .AEAD_AES_128_GCM)
    first_byte, packet_number, packet := remove_header_protection(first_byte, packet)
    
    packet_payload := packet[:payload_length]
    packet = packet[packet_payload_length:]
    
    return Initial_Packet{
	version = version,
	dest_conn_id = dest_conn_id,
	source_conn_id = src_conn_id,
	packet_number = packet_number,
	token = token,
	packet_payload = packet_payload,
    }, packet, nil
}

process_handshake :: proc(using partial: Partial_Packet, packet: []u8, ctx: Context) -> (Packet, []u8, Transport_Error) {
    hp_key: []byte
    if conn := findConn(dest_conn_id); conn != nil { // FIXME: REPLACE WITH ZII
	sync.mutex_guard(conn.lock)
	secrets := conn.secrets[.ssl_encryption_handshake]
	hp_key := secrets.hp
    } else {
	return nil, nil, .Protocol_Error // We can't find the conn object for the handshake so... nah
    }

    // FIXME: Remove packet protection HERE
    // FIXME: Should we be decrypting packet protection here?
    length, offset := get_variable_length_int(packet)
    packet = packet[offset:]
    
    mask := get_header_mask(hp_key, packet[4:20], conn.encryption.ssl)
    first_byte, packet_number, packet := remove_header_protection(first_byte, packet)
    
    packet_payload := packet[:packet_payload_length]
    packet = packet[packet_payload_length:]
    
    return Handshake_Packet{
	version: version,
	dest_conn_id: dest_conn_id,
	source_conn_id: src_conn_id,
	packet_number: packet_number,
	packet_payload: packet_payload
    }, packet, nil
}

process_retry :: proc(using partial: Partial_Packet, packet: []u8, ctx: Context) -> (Packet, []u8, Transport_Error) {
    // FIXME: Verify there isn't any header protection on retry
    // FIXME: Verify packet protection on  retry
    tk_end := len(packet) - 16  // integrity tag is 128 bits
    return Retry_Packet{
	version: version,
	dest_conn_id: dest_conn_id,
	source_conn_id: src_conn_id,
	retry_token: packet[0 : tk_end],
	retry_integrity_tag: packet[tk_end:],
    }, nil, nil // retry ends the datagram
}


process_version_negotiation :: proc(using partial: Partial_Packet, packet: []u8, ctx: Context) -> (Packet, []u8, Transport_Error) {
    // FIXME: Verify there isn't any header protection on version negotiation
    // FIXME: Verify packet protection on version negotiation

    if (version != 0) {
	return nil, nil, .VERSION_NEGOTIATION_ERROR
    }

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
    }, nil, nil // version negotiation ends the datagam
}

process_zero_rtt :: proc(using partial: Partial_Packet, packet: []u8, ctx: Context) -> (Packet, []u8, Transport_Error) {
    hp_key: []byte
    if conn := findConn(dest_conn_id); conn != nil { // FIXME: REPLACE WITH ZII
	sync.mutex_guard(conn.lock)
	secrets := conn.secrets[.ssl_encryption_early_data]
	hp_key := secrets.hp
    } else {
	return nil, nil, .Protocol_Error // We can't find the conn object for the handshake so... nah
    }
    
    payload_length, offset := get_variable_length_int(packet)
    packet = packet[offset:] // FIXME: Maybe the function can do this part?
    
    mask := get_header_mask(hp_key, packet[4:20], conn.encryption.ssl)
    first_byte, packet_number, packet := remove_header_protection(first_byte, packet)
    
    packet_payload := packet[:payload_length]
    packet = packet[packet_payload_length:]
    
    return Zero_RTT_Packet{
	version: version,
	dest_conn_id: dest_conn_id,
	source_conn_id: src_conn_id,
	packet_number: packet_number,
	packet_payload: packet_payload,
    }, packet, nil
}

process_one_rtt :: proc(using partial: Partial_Packet, packet: []u8, ctx: Context) -> (Packet, []u8, Transport_Error) 
{
    // let's get our UUID conn id, since it's one we know we issued
    dest_conn_id, err := uuid.read(string(dest_conn_id))
    if err {
	/*
         * since we can't read the connection id, we can't tell how long
         * the packet is supposed to be, which means we're done reading
         * the whole datagram, because we can't tell where any additional
         * packets are supposed to start 
         */
	return nil, nil, .PROTOCOL_VIOLATION
    }

    hp_key: []byte
    if conn := findConn(dest_conn_id); conn != nil { // FIXME: REPLACE WITH ZII
	sync.mutex_guard(conn.lock)
	secrets := conn.secrets[.ssl_encryption_application]
	hp_key := secrets.hp
    } else {
	return nil, nil, .Protocol_Error // We can't find the conn object for the handshake so... nah
    }

    // FIXME: Remove packet protection HERE
    // FIXME: Should we be decrypting packet protection here?

    spin_bit = first_byte & (1 << 5)
    key_phase = first_byte & (1 << 2)
    
    packet = packet[1:]
    
    // we know the dest_conn_id and src_conn_id
    conn_idx := 1 + conn_id_len + 1 + src_conn_id_len
    packet = packet[conn_idx:]
    
    payload_length, offset := get_variable_length_int(packet)
    packet = packet[offset:] // FIXME: Maybe the function can do this part?
    
    mask := get_header_mask(hp_key, packet[4:20], conn.encryption.ssl)
    first_byte, packet_number, packet := remove_header_protection(first_byte, packet)
    
    packet_payload := packet[:payload_length]
    packet = packet[packet_payload_length:]
    
    return One_RTT_Packet{
	spin_bit: spin_bit,
	key_phase: key_phase,
	dest_conn_id: dest_conn_id,
	packet_number: packet_number
    }, packet, nil
}
