/*
 * SDG                                                                         JJ
 */

package quic

Transport_Error :: enum {
	NO_ERROR,
	INTERNAL_ERROR,
	CONNECTION_REFUSED,
	FLOW_CONTROL_ERROR,
	STREAM_LIMIT_ERROR,
	STREAM_STATE_ERROR,
	FINAL_SIZE_ERROR,
	FRAME_ENCODING_ERROR,
	TRANSPORT_PARAMETER_ERROR,
	CONNECTION_ID_LIMIT_ERROR,
	PROTOCOL_VIOLATION,
	INVALID_TOKEN,
	APPLICATION_ERROR,
	CRYPTO_BUFFER_EXCEEDED,
	KEY_UPDATE_ERROR,
	AEAD_LIMIT_REACHED,
	NO_VIABLE_PATH,
	VERSION_NEGOTIATION_ERROR,
	CRYPTO_ERROR,
}

Transport_Error_Codes :: [Transport_Error][]i32 {
	.NO_ERROR                  = {0x00},
	.INTERNAL_ERROR            = {0x01},
	.CONNECTION_REFUSED        = {0x02},
	.FLOW_CONTROL_ERROR        = {0x03},
	.STREAM_LIMIT_ERROR        = {0x04},
	.STREAM_STATE_ERROR        = {0x05},
	.FINAL_SIZE_ERROR          = {0x06},
	.FRAME_ENCODING_ERROR      = {0x07},
	.TRANSPORT_PARAMETER_ERROR = {0x08},
	.CONNECTION_ID_LIMIT_ERROR = {0x09},
	.PROTOCOL_VIOLATION        = {0x0a},
	.INVALID_TOKEN             = {0x0b},
	.APPLICATION_ERROR         = {0x0c},
	.CRYPTO_BUFFER_EXCEEDED    = {0x0d},
	.KEY_UPDATE_ERROR          = {0x0e},
	.AEAD_LIMIT_REACHED        = {0x0f},
	.NO_VIABLE_PATH            = {0x10},
	.VERSION_NEGOTIATION_ERROR = {0x11},
	.CRYPTO_ERROR              = {0x0100, 0x01ff},
}

Application_Write_Error :: enum {
	None,
	Stream_Not_Found,
	Stream_Data_Blocked,
	Stream_Buffer_Full,
	Stream_Closed,
}

Application_Read_Error :: enum {
	None,
	Stream_Not_Found,
	Stream_Buffer_Empty,
	Stream_Closed,
}
