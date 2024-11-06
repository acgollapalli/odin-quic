package quic

Transport_Param :: enum {
    original_destination_connection_id,
    max_idle_timeout,
    stateless_reset_token,
    max_udp_payload_size,
    initial_max_data,
    initial_max_stream_data_bidi_local,
    initial_max_stream_data_bidi_remote,
    initial_max_stream_data_uni,  
    initial_max_streams_bidi,
    initial_max_streams_uni,
    ack_delay_exponent,
    max_ack_delay,
    disable_active_migration,
    preferred_address,
    active_connection_id_limit,
    initial_source_connection_id,
    retry_source_connection_id,
    version_information,
    max_datagram_frame_size,
    grease_quic_bit,
}

Transport_Param_Codes :: [Transport_Param]i32 {
	.original_destination_connection_id     = 0x00,
	.max_idle_timeout                       = 0x01,
	.stateless_reset_token                  = 0x02,
	.max_udp_payload_size                   = 0x03,
	.initial_max_data                       = 0x04,
	.initial_max_stream_data_bidi_local     = 0x05,
	.initial_max_stream_data_bidi_remote    = 0x06,
	.initial_max_stream_data_uni            = 0x07,
	.initial_max_streams_bidi               = 0x08,
	.initial_max_streams_uni                = 0x09,
	.ack_delay_exponent                     = 0x0a,
	.max_ack_delay                          = 0x0b,
	.disable_active_migration               = 0x0c,
	.preferred_address                      = 0x0d,
	.active_connection_id_limit             = 0x0e,
	.initial_source_connection_id           = 0x0f,
	.retry_source_connection_id             = 0x10,
	.version_information                    = 0x11,
	.max_datagram_frame_size                = 0x20,
	.grease_quic_bit                        = 0x26ab,
}


