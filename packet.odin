/*
 * SDG                                                                         JJ
 */

package quic

Packet :: union {
	Version_Negotiation_Packet,
	Initial_Packet,
	Zero_RTT_Packet,
	Handshake_Packet,
	Retry_Packet,
	One_RTT_Packet,
}

// TODO: Refactor for Tagged Unions so we can use a LUT instead of
// switch statements everywhere
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
	dest_conn_id:       Connection_Id,
	source_conn_id:     Connection_Id,
	supported_versions: []u32,
}

Initial_Packet :: struct {
	version:        u32,
	dest_conn_id:   Connection_Id,
	source_conn_id: Connection_Id,
	token:          []u8,
	packet_number:  u32,
	packet_payload: []^Frame,
}

Zero_RTT_Packet :: struct {
	version:        u32, // version is 0 in case of negotiation
	dest_conn_id:   Connection_Id,
	source_conn_id: Connection_Id,
	packet_number:  u32,
	packet_payload: []^Frame,
}

Handshake_Packet :: struct {
	version:        u32, // version is 0 in case of negotiation
	dest_conn_id:   Connection_Id,
	source_conn_id: Connection_Id,
	packet_number:  u32,
	packet_payload: []^Frame,
}


/* may not be necessary, as there will
   need to be some work to serialize this anyway */
Retry_Packet :: struct {
	version:               u32,
	original_dest_conn_id: Connection_Id,
	dest_conn_id:          Connection_Id,
	source_conn_id:        Connection_Id,
	retry_token:           []u8,
	retry_integrity_tag:   []u8, // 16 bytes
}


// SPIN BIT HAS SUPERPOWERS
One_RTT_Packet :: struct {
	spin_bit:       bool,
	key_phase:      bool,
	dest_conn_id:   Connection_Id,
	packet_number:  u32,
	packet_payload: []^Frame,
}


Long_Header_Packet :: union {
	Version_Negotiation_Packet,
	Initial_Packet,
	Zero_RTT_Packet,
	Handshake_Packet,
	Retry_Packet,
}

get_dest_conn_id :: proc(packet: Packet) -> Connection_Id {
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

/*
  make_packet

  general purpose packetizer

  serializes packet up to the max len of the slize provided,
  moves the frames in question from the frame queue to the pending ack struct,
  reads crypto data from the crypto queues (not implemented yet) and frames it
  in stream frames 
  reads stream data from the stream queues (not implemented yet) and frames 
  them in stream frames. 

  Don't use it for initial packets initiated as a client.
  TODO: write `make_initiating_packet` which will pad packet to 1200 bytes
*/
make_packet :: proc(
	conn: ^Conn,
	packet_number_space: Packet_Number_Space,
	dg_buf: []byte,
	alloc := context.allocator,
) -> (
	plen: int,
) {
	assert(
		false,
		"Not implemented yet, because serialization was written with bad assumptions,",
	)
	return 0
}

make_retry_pseudo_packet :: proc(p: Retry_Packet, header: []u8, payload: []u8, alloc := context.temp_allocator) -> (pseudo_packet: [dynamic]u8) {
	pseudo_packet = make([dynamic]u8, alloc)

	append(&pseudo_packet, u8(len(p.original_dest_conn_id)))
	append(&pseudo_packet, ..p.original_dest_conn_id)
	append(&pseudo_packet, ..header)
	append(&pseudo_packet, ..payload)

	return
}
