/*
 * SDG                                                                         JJ
 */

package quic

import "core:encoding/uuid"
import "core:fmt"
import "core:net"
import "core:time"

Role :: enum {
	Server,
	Client,
}

Supported_Version :: enum {
	QUICv1 = 0x01,
	// QUICv2 = 0x6b3343cf
}
