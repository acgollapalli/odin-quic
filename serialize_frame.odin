/*

SDG                                                                           JJ

*/

package quic

serialize_frame :: proc(frame: ^Frame, cursor: ^[]u8, ) {
	switch f in frame.variant {
	case ^Padding_Frame:
		add_padding_frame(f^, cursor)
	case ^Ping_Frame:
		add_ping_frame(f^, cursor)
	case ^Ack_Frame:
		add_ack_frame(f^, cursor)
	case ^Reset_Stream_Frame:
		add_reset_stream_frame(f^, cursor)
	case ^Stop_Sending_Frame:
		add_stop_sending_frame(f^, cursor)
	case ^Crypto_Frame:
		add_crypto_frame(f^, cursor)
	case ^New_Token_Frame:
		add_new_token_frame(f^, cursor)
	case ^Stream_Frame:
		add_stream_frame(f^, cursor)
	case ^Max_Data_Frame:
		add_max_data_frame(f^, cursor)
	case ^Max_Stream_Data_Frame:
		add_max_stream_data_frame(f^, cursor)
	case ^Max_Streams_Frame:
		add_max_streams_frame(f^, cursor)
	case ^Data_Blocked_Frame:
		add_data_blocked_frame(f^, cursor)
	case ^Stream_Data_Blocked_Frame:
		add_stream_data_blocked_frame(f^, cursor)
	case ^Streams_Blocked_Frame:
		add_streams_blocked_frame(f^, cursor)
	case ^New_Connection_Id_Frame:
		add_new_connection_id_frame(f^, cursor)
	case ^Retire_Connection_Id_Frame:
		add_retire_connection_id_frame(f^, cursor)
	case ^Path_Challenge_Frame:
		add_path_challenge_frame(f^, cursor)
	case ^Path_Response_Frame:
		add_path_response_frame(f^, cursor)
	case ^Connection_Close_Frame:
		add_connection_close_frame(f^, cursor)
	case ^Handshake_Done_Frame:
		add_handshake_done_frame(f^, cursor)
	case ^Datagram_Frame:
		add_datagram_frame(f^, cursor)
	}
}

// FIXME: what if the payload doesn't have enough capacity?
serialize_frames :: proc(frames: []^Frame, cursor: ^[]u8) {
	for frame in frames {
		serialize_frame(frame, cursor)
	}
	return
}
