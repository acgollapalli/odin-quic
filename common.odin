/*
 * SDG                                                                         JJ
 */

package quic

import "core:encoding/uuid"
import "core:fmt"
import "core:net"
import "core:time"

MAX_STREAM_DATA :: #config(MAX_STREAM_DATA, 4096)

Role :: enum {
	Server,
	Client,
}

Supported_Version :: enum {
	QUICv1 = 0x01,
	// QUICv2 = 0x6b3343cf
}

Packet_Number_Space :: enum {
	Initial,
	Handshake,
	Application,
}
