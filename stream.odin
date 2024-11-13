/*
 * SDG                                                                         JJ
 */

package quic

Stream :: union {
	Sending_Stream,
	Receiving_Stream,
	Bidirectional_Stream,
}


Sending_Stream :: struct {
	id:            u64,
	limit:         u64,
	sending_state: Sending_Stream_State,
}

Receiving_Stream :: struct {
	id:              u64,
	limit:           u64, // FIXME: Version 1 only allows limits in a 62 bit uint
	receiving_state: Receiving_Stream_State,
}

Bidirectional_Stream :: struct {
	id:              u64,
	limit:           int,
	sending_state:   Sending_Stream_State,
	receiving_State: Receiving_Stream_State,
}

Flow: union {
	Datagram_flow,
}

Datagram_flow :: struct {
	id: u64,
}

Stream_Type :: enum {
	Bidirectional,
	Unidirectional,
}

Stream_Initiator :: enum {
	Client,
	Server,
}

// from suggestion in RFC 9000.3.1
Sending_Stream_State :: enum {
	Ready,
	Send,
	Data_Sent,
	Reset_Sent,
	Data_Received,
	Reset_Received,
}

// from suggestion in RFC 9000.3.2
Receiving_Stream_State :: enum {
	Receiving,
	Size_Known,
	Data_Received,
	Reset_Received,
	Data_Read,
	Reset_Read,
}


stream_id_bits :: proc(
	stream_type: Stream_Type,
	stream_initiator: Stream_Initiator,
) -> int {
	return (int(stream_type) << 1) | int(stream_initiator)
}

//create_stream :: proc(id: int, stream_type: Stream_Type, stream_initiator: Stream_Initiator) -> Stream 
//
//accept_stream :: proc() -> Stream
//close_stream :: proc()
//read_stream :: proc()
//write_stream :: proc()
//reset_stream :: proc()
//
//
///*
// * A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames 
// * that do not increase flow control limits.
// */
//adjust_limits :: proc() // Senders cannot have their limits lowered, only raised RFC9000.4.2
//
///*
// * A receiver MUST close the connection with an error of type
// * FLOW_CONTROL_ERROR if the sender violates the advertised connection 
// * or stream data limits; see Section 11 for details on error handling.
// */
//check_overage :: proc() -> Transport_Error // receivers must close stream with error FLOW_CONTROL_ERROR RFC9000.4.2 
//
///*
// * If a sender has sent data up to the limit, it will be unable to 
// * send new data and is considered blocked. A sender SHOULD send a 
// * STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the 
// * receiver that it has data to write but is blocked by flow control 
// * limits. If a sender is blocked for a period longer than the idle 
// * timeout (Section 10.1), the receiver might close the connection 
// * even when the sender has data that is available for transmission. 
// * To keep the connection from closing, a sender that is flow control 
// * limited SHOULD periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED 
// * frame when it has no ack-eliciting packets in flight
//*/
//handle_blocked :: proc(stream: Stream)
