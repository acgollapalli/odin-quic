/* MOVE THESE SOMEWHERE ELSE */
package quic
import "core:sys/posix"

//_unwrap_os_addr :: proc "contextless" (endpoint: net.Endpoint)->(linux.Sock_Addr_Any) {
//	switch address in endpoint.address {
//	case net.IP4_Address:
//		return {
//			ipv4 = {
//				sin_family = .INET,
//				sin_port = u16be(endpoint.port),
//				sin_addr = ([4]u8)(endpoint.address.(IP4_Address)),
//			},
//		}
//	case net.IP6_Address:
//		return {
//			ipv6 = {
//				sin6_port = u16be(endpoint.port),
//				sin6_addr = transmute([16]u8)endpoint.address.(IP6_Address),
//				sin6_family = .INET6,
//			},
//		}
//	case:
//		unreachable()
//	}
//}
//
//_wrap_os_addr :: proc "contextless" (addr: linux.Sock_Addr_Any)->(net.Endpoint) {
//	#partial switch addr.family {
//	case .INET:
//		return {
//			address = cast(net.IP4_Address) addr.sin_addr,
//			port = cast(int) addr.sin_port,
//		}
//	case .INET6:
//		return {
//			port = cast(int) addr.sin6_port,
//			address = transmute(net.IP6_Address) addr.sin6_addr,
//		}
//	case:
//		unreachable()
//	}
//}
/*
	Address family for the socket.
	Typically there's one address family for every protocol family.
*/

when ODIN_OS == .Darwin {
	Pfam_Len :: u8
} else when ODIN_OS == .Linux {
	Pfam_Len :: u16
}

Protocol_Family :: enum Pfam_Len {
	UNSPEC       = 0,
	LOCAL        = 1,
	UNIX         = LOCAL,
	FILE         = LOCAL,
	INET         = 2,
	AX25         = 3,
	IPX          = 4,
	APPLETALK    = 5,
	NETROM       = 6,
	BRIDGE       = 7,
	ATMPVC       = 8,
	X25          = 9,
	INET6        = 10,
	ROSE         = 11,
	DECnet       = 12,
	NETBEUI      = 13,
	SECURITY     = 14,
	KEY          = 15,
	NETLINK      = 16,
	ROUTE        = NETLINK,
	PACKET       = 17,
	ASH          = 18,
	ECONET       = 19,
	ATMSVC       = 20,
	RDS          = 21,
	SNA          = 22,
	IRDA         = 23,
	PPPOX        = 24,
	WANPIPE      = 25,
	LLC          = 26,
	IB           = 27,
	MPLS         = 28,
	CAN          = 29,
	TIPC         = 30,
	BLUETOOTH    = 31,
	IUCV         = 32,
	RXRPC        = 33,
	ISDN         = 34,
	PHONET       = 35,
	IEEE802154   = 36,
	CAIF         = 37,
	ALG          = 38,
	NFC          = 39,
	VSOCK        = 40,
	KCM          = 41,
	QIPCRTR      = 42,
	SMC          = 43,
	XDP          = 44,
	MCTP         = 45,
}

/*
	Bits for Socket_Msg
*/
Socket_Msg_Bits :: enum {
	OOB             = 0,
	PEEK            = 1,
	DONTROUTE       = 2,
	TRYHARD         = DONTROUTE,
	CTRUNC          = 3,
	PROXY           = 4,
	TRUNC           = 5,
	DONTWAIT        = 6,
	EOR             = 7,
	WAITALL         = 8,
	FIN             = 9,
	SYN             = 10,
	CONFIRM         = 11,
	RST             = 12,
	ERRQUEUE        = 13,
	NOSIGNAL        = 14,
	MORE            = 15,
	WAITFORONE      = 16,
	BATCH           = 18,
	ZEROCOPY        = 22,
	FASTOPEN        = 29,
	CMSG_CLOEXEC    = 30,
}


Address_Family :: distinct Protocol_Family

/*
	Flags for the socket for send/recv calls.
*/
Socket_Msg :: bit_set[Socket_Msg_Bits; i32]

/*
	Struct representing IPv4 socket address.
*/
Sock_Addr_In :: struct #packed {
	sin_family: Address_Family,
	sin_port:   u16be,
	sin_addr:   [4]u8,
}

/*
	Struct representing IPv6 socket address.
*/
Sock_Addr_In6 :: struct #packed {
	sin6_family:   Address_Family,
	sin6_port:     u16be,
	sin6_flowinfo: u32,
	sin6_addr:     [16]u8,
	sin6_scope_id: u32,
}

/*
	Struct representing Unix Domain Socket address
*/
Sock_Addr_Un :: struct #packed {
	sun_family: Address_Family,
	sun_path:   [108]u8,
}

/*
	Struct representing an arbitrary socket address.
*/
Sock_Addr_Any :: struct #raw_union {
	using _: struct {
		family: Address_Family,
		port:   u16be,
	},
	using ipv4: Sock_Addr_In,
	using ipv6: Sock_Addr_In6,
	using uds: Sock_Addr_Un,
}
