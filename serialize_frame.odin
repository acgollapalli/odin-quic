/*

SDG                                                                            JJ

*/

package quic

serialize_frame :: proc(payload: ^[]u8, frame: Frame) {
	switch f in frame.variant {
	case ^Padding_Frame:
		add_padding_frame(payload, f^)
	case ^Ping_Frame:
		add_ping_frame(payload, f^)
	case ^Ack_Frame:
		add_ack_frame(payload, f^)
	case ^Reset_Stream_Frame:
		add_reset_stream_frame(payload, f^)
	case ^Stop_Sending_Frame:
		add_stop_sending_frame(payload, f^)
	case ^Crypto_Frame:
		add_crypto_frame(payload, f^)
	case ^New_Token_Frame:
		add_new_token_frame(payload, f^)
	case ^Stream_Frame:
		add_stream_frame(payload, f^)
	case ^Max_Data_Frame:
		add_max_data_frame(payload, f^)
	case ^Max_Stream_Data_Frame:
		add_max_stream_data_frame(payload, f^)
	case ^Max_Streams_Frame:
		add_max_streams_frame(payload, f^)
	case ^Data_Blocked_Frame:
		add_data_blocked_frame(payload, f^)
	case ^Stream_Data_Blocked_Frame:
		add_stream_data_blocked_frame(payload, f^)
	case ^Streams_Blocked_Frame:
		add_streams_blocked_frame(payload, f^)
	case ^New_Connection_Id_Frame:
		add_new_connection_id_frame(payload, f^)
	case ^Retire_Connection_Id_Frame:
		add_retire_connection_id_frame(payload, f^)
	case ^Path_Challenge_Frame:
		add_path_challenge_frame(payload, f^)
	case ^Path_Response_Frame:
		add_path_response_frame(payload, f^)
	case ^Connection_Close_Frame:
		add_connection_close_frame(payload, f^)
	case ^Handshake_Done_Frame:
		add_handshake_done_frame(payload, f^)
	case ^Datagram_Frame:
		add_datagram_frame(payload, f^)
	}
}

// FIXME: what if the payload doesn't have enough capacity?
serialize_frames :: proc(payload: ^[]u8, frames: []^Frame) -> []u8 {
	for frame in frames {
		serialize_frame(payload, frame^)
	}
	return payload^
}
