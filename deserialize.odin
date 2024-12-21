/*

SDG                                                                            JJ

 */

package quic

import ssl "../ssl"
import "core:net"
import "core:sync"
import "core:fmt"

Partial_Packet :: struct {
	first_byte:   byte,
	version:      u32,
	dest_conn_id: []u8,
	src_conn_id:  []u8,
}


handle_datagram :: proc(dg: []byte, peer: net.Endpoint) {
	dest_conn_id: Connection_Id
	conn: Maybe(^Conn) // we don't know the connn til we have the dest_conn_id

	len_dg := len(dg)

	for dg := dg; len(dg) > 0; {
		//fmt.println("current dg:", dg)
		packet, dg, err := process_incoming_packet(dg) // FIXME: pass conn here

		fmt.printfln("Getting dest_conn_id: %v from packet", get_dest_conn_id(packet))
		fmt.println("Recieved this packet: ", packet)

		// establish our baselines
		if dest_conn_id == nil do dest_conn_id = get_dest_conn_id(packet)
		if conn == nil do conn, _ = find_conn(dest_conn_id)

		if err != nil {
			handle_transport_error(conn, err)
			return
		} else if string(dest_conn_id) == string(get_dest_conn_id(packet)) &&
			packet != nil {
				fmt.println("Recieved this packet: ", packet)
			// TODO: This should MAYBE put the packet on thread specific queue
			//handle_incoming_packet(conn, packet, len_dg, peer)
		}
	}
}


// FIXME: pass in conn here
// handle incoming packet
process_incoming_packet :: proc(
	packet: []byte,
) -> (
	Packet,
	[]byte,
	Transport_Error,
) {
	packet := packet // let's mutate the slice as we iterate

	/* This is under header protection
       and we can't read the latter half of it yet
       however we can find out what kind of thing we're working with */
	first_byte := packet[0]
	packet_type := what_kind_of_packet(first_byte)
	packet = packet[1:]

	version: u32 
	dest_conn_id_len: u8
	src_conn_id_len: u8
	dest_conn_id: []u8 // maybe we --- this?
	src_conn_id: []u8

	if packet_type == .One_RTT {
		// we always return conn_ids as uuids
		// uuid's are encoded in 16 bytes
		dest_conn_id_len = 16
		dest_conn_id = packet[0:16]
		packet = packet[16:]
	} else {
		// get version
		for b in packet[0:4] {
			version = (u32)(b) + (version << 8)
		}
		if version == 0{
			packet_type = .Version_Negotiation
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

			src_conn_id_len = packet[0]
			packet = packet[1:]

			if src_conn_id_len > 20 && packet_type != .Version_Negotiation {
				// ONLY holds for version 1 and 2 at the moment
				return nil, nil, .PROTOCOL_VIOLATION
			}
			src_conn_id = packet[0:src_conn_id_len]
			packet = packet[src_conn_id_len:]
		}
	}

	//fmt.printfln("We've received a packet type of %v, of version %v, with dest_conn_id: %v, and src_conn_id: %v", packet_type, version, dest_conn_id, src_conn_id)

	/*
     * We've about reached the point where we can read anything that's unprotected
     * and common to all the packet types. The way we decrypt packet types is unique
     * to each packet type, so we've got handlers for each one.
     */

	partial_packet := Partial_Packet {
		first_byte   = first_byte,
		version      = version,
		dest_conn_id = dest_conn_id,
		src_conn_id  = src_conn_id,
	}

	switch packet_type {
	case .Initial:
		return process_initial(partial_packet, packet)
	case .Handshake:
		return process_handshake(partial_packet, packet)
	case .Retry:
		return process_retry(partial_packet, packet)
	case .Version_Negotiation:
		return process_version_negotiation(partial_packet, packet)
	case .Zero_RTT:
		return process_zero_rtt(partial_packet, packet)
	case .One_RTT:
		return process_one_rtt(partial_packet, packet)
	}

	return nil, nil, nil // THIS WILL NEVER RUN, BUT THE BUGGY COMPILER THINKS DIFFERENT
}

get_variable_length_int :: proc(packet: []byte) -> (n: u64, len: int) {
	two_msb := packet[0] >> 6
	n = u64(packet[0] &~ 0xc0)

	switch two_msb {
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
		n = u64(packet[i]) + (n << 8)
	}

	fmt.printfln("variable length int %v from bytes:%v",n, packet[0:len])
	return
}

what_kind_of_packet :: proc(first_byte: byte) -> Packet_Type {
	is_long_header := first_byte & 0x80 != 0 // first bit
	is_fixed_bit := first_byte & 0x40 != 0 // second bit


	// getting the conn_id_length (see packet.odin)
	if is_long_header {
		if !is_fixed_bit {
			return .Version_Negotiation
		} else {
			first_byte := first_byte
			first_byte &~= 0xcf // clear first two and last four bits
			first_byte = first_byte >> 4

			// first byte now only has bits 5 and 6
			// long header packets are 0x01 through 0x03
			// and are enumerated in Packet_Type as 1-4
			return (Packet_Type)(first_byte + 1)
		}
	} else {
		return .One_RTT
	}
}

process_initial :: proc(
	using partial: Partial_Packet,
	packet: []u8,
) -> (
	pkt: Packet,
	remaining: []u8,
	err: Transport_Error,
) {
	packet := packet

	// REMINDER: keys are determined by the FIRST initial packet. Any subsequent ones that aren't determined
	// by a retry use the same keys. On a retry. The keys should be marked INVALID.
	role: Role
	hp_key: []byte
	if conn, c_ok := find_conn(dest_conn_id); c_ok {
		sync.shared_guard(&conn.encryption.lock)
		assert(
			conn.encryption.secrets[.Initial_Encryption][.Read].valid,
			"invalid secret",
		)
		hp_key := conn.encryption.secrets[.Initial_Encryption][.Read].hp
	} else {
		// FIXME: we should CONSIDER adding the conn here (BUT...
		// it's based off the dest id, so do we NEED TO? maybe
		// it should be handled by the frame handler, not down here)

		//fmt.println("received initial packet with no associated conn")
		secrets := determine_initial_secret(dest_conn_id)
		hp_key = secrets[.Read].hp
		fmt.printfln("header protection key: %x", hp_key)
	}

	// FIXME: Should we be decrypting packet protection here?
	token_length, tk_offset := get_variable_length_int(packet)
	packet = packet[tk_offset:]

	token := packet[:token_length]
	packet = packet[token_length:]

	payload_length, pl_offset := get_variable_length_int(packet)
	packet = packet[pl_offset:] // FIXME: Maybe the function can do this part?


	fmt.println("getting header mask: ")
	mask := get_header_mask(
		hp_key,
		packet[4:20],
		Packet_Protection_Algorithm.AEAD_AES_128_GCM,
	)
	fmt.println("header mask: ", mask)
	packet_number: u32
	_, packet_number, packet = remove_header_protection(first_byte, packet, mask)

	fmt.println("packet_number: ", packet_number)
	fmt.println("packet: ", packet)
	fmt.println("payload_len:", payload_length, len(packet))
	
	packet_payload := packet[:payload_length]
	packet = packet[payload_length:]

	frames := read_frames(packet_payload) or_return

	return Initial_Packet {
			version = version,
			dest_conn_id = dest_conn_id,
			source_conn_id = src_conn_id,
			packet_number = packet_number,
			token = token,
			packet_payload = frames,
		},
		packet,
		nil
}

process_handshake :: proc(
	using partial: Partial_Packet,
	packet: []u8,
) -> (
	pktObj: Packet,
	remaining: []u8,
	err: Transport_Error,
) {
	packet := packet

	// getting the mask
	conn, conn_ok := find_conn(dest_conn_id)
	if !conn_ok { 	// FIXME: REPLACE WITH ZII
		assert(
			conn.encryption.secrets[.Handshake_Encryption][.Read].valid,
			"Dropped handshake packet",
		)
		return nil, nil, .PROTOCOL_VIOLATION // we SHOULD have keys by this point
	}
	mask, mask_ok := get_header_mask(
		packet[4:20],
		conn,
		ssl.QUIC_Encryption_Level.Handshake_Encryption,
		Secret_Role.Read,
	)
	if !mask_ok {
		return
	} // can't decrypt. We might not have keys yet. 


	// FIXME: Remove packet protection HERE
	// FIXME: Should we be decrypting packet protection here?
	payload_length, offset := get_variable_length_int(packet)
	packet = packet[offset:]

	packet_number: u32
	_, packet_number, packet = remove_header_protection(first_byte, packet, mask)


	packet_payload := packet[:payload_length]
	packet = packet[payload_length:]

	frames := read_frames(packet_payload) or_return
	return Handshake_Packet {
			version = version,
			dest_conn_id = dest_conn_id,
			source_conn_id = src_conn_id,
			packet_number = packet_number,
			packet_payload = frames,
		},
		packet,
		nil
}

process_retry :: proc(
	using partial: Partial_Packet,
	packet: []u8,
) -> (
	Packet,
	[]u8,
	Transport_Error,
) {
	// FIXME: Verify there isn't any header protection on retry
	// FIXME: Verify packet protection on  retry
	tk_end := len(packet) - 16 // integrity tag is 128 bits
	return Retry_Packet {
			version = version,
			dest_conn_id = dest_conn_id,
			source_conn_id = src_conn_id,
			retry_token = packet[0:tk_end],
			retry_integrity_tag = packet[tk_end:],
		},
		nil,
		nil // retry ends the datagram
}


process_version_negotiation :: proc(
	using partial: Partial_Packet,
	packet: []u8,
) -> (
	Packet,
	[]u8,
	Transport_Error,
) {
	packet := packet
	// FIXME: Verify there isn't any header protection on version negotiation
	// FIXME: Verify packet protection on version negotiation

	if (version != 0) {
		return nil, nil, .VERSION_NEGOTIATION_ERROR
	}

	versions: [dynamic]u32 // FIXME: replace with iteration over Supported_version in common.odin
	for len(packet) >= 8 {
		n: u32
		for b in packet[:8] do n = u32(b) + (n << 8)
		append(&versions, n)
		packet = packet[8:]
	}

	return Version_Negotiation_Packet {
			dest_conn_id = dest_conn_id,
			source_conn_id = src_conn_id,
			supported_versions = versions[:],
		},
		nil,
		nil // version negotiation ends the datagam
}

process_zero_rtt :: proc(
	using partial: Partial_Packet,
	packet: []u8,
) -> (
	pkt: Packet,
	remaining: []u8,
	err: Transport_Error,
) {
	packet := packet

	// getting the mask
	conn, conn_ok := find_conn(dest_conn_id)
	if !conn_ok {
		assert(
			conn.encryption.secrets[.Handshake_Encryption][.Read].valid,
			"Could not find conn. for Zero-RTT packet",
		)
		return nil, nil, .PROTOCOL_VIOLATION // We can't find the conn object for the handshake so... nah
	}
	mask, mask_ok := get_header_mask(
		packet[4:20],
		conn,
		ssl.QUIC_Encryption_Level.Early_Data_Encryption,
		Secret_Role.Read,
	)
	if !mask_ok {
		return
	}

	payload_length, offset := get_variable_length_int(packet)
	packet = packet[offset:] // FIXME: Maybe the function can do this part?

	packet_number: u32
	_, packet_number, packet = remove_header_protection(first_byte, packet, mask)

	packet_payload := packet[:payload_length]
	packet = packet[payload_length:]

	frames := read_frames(packet_payload) or_return

	return Zero_RTT_Packet {
			version = version,
			dest_conn_id = dest_conn_id,
			source_conn_id = src_conn_id,
			packet_number = packet_number,
			packet_payload = frames,
		},
		packet,
		nil
}

process_one_rtt :: proc(
	partial: Partial_Packet,
	packet: []u8,
) -> (
	pkt: Packet,
	remaining: []u8,
	err: Transport_Error,
) {
	packet := packet
	dest_conn_id := partial.dest_conn_id // can't shadow variables with using
	first_byte := partial.first_byte

	// getting the mask
	mask: []byte
	mask_ok: bool
	conn, conn_ok := find_conn(dest_conn_id)
	if !conn_ok { 	// FIXME: REPLACE WITH ZII
		return nil, nil, .PROTOCOL_VIOLATION // We can't find the conn object
	}
	mask, mask_ok = get_header_mask(
			packet[4:20],
			conn,
			ssl.QUIC_Encryption_Level.Application_Encryption,
			Secret_Role.Read,
	)
	if !mask_ok do return

	// removing packet protection
	decrypted_first_byte: byte
	packet_number: u32
	decrypted_first_byte, packet_number, packet = remove_header_protection(
		first_byte,
		packet,
		mask,
	)

	spin_bit := (decrypted_first_byte & (1 << 5)) != 0
	key_phase := (decrypted_first_byte & (1 << 2)) != 0

	frames := read_frames(packet) or_return

	return One_RTT_Packet {
			spin_bit = spin_bit,
			key_phase = key_phase,
			dest_conn_id = dest_conn_id,
			packet_number = packet_number,
			packet_payload = frames,
		},
		nil,
		nil
}
