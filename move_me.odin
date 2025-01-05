/* MOVE THESE SOMEWHERE ELSE */
package quic
import "core:fmt"
import "core:net"
import "core:sys/posix"

//_unwrap_os_addr :: proc "contextless" (endpoint: net.Endpoint)->(linux.Sock_Addr_Any) {
//	switch address in endpoint.address {
//	case net.IP4_Address:
//		return {
//			ipv4 = {
//				sin_family = .INET,
//				sin_port = u16be(endpoint.port),
//				sin_addr = ([4]u8)(endpoint.address.(IP4_Address)), //			}, //		}
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

sockaddr :: union {
	posix.sockaddr,
	posix.sockaddr_in,
	posix.sockaddr_in6,
}

unwrap_sock_addr :: proc(addr: sockaddr) -> (endpoint: net.Endpoint) {
	//	fmt.println("raw_data", transmute([110]u8)addr)
	#partial switch addr.(posix.sockaddr).sa_family {
	case .INET, .UNIX:
		in_addr := addr.(posix.sockaddr_in)
		return {
			address = transmute(net.IP4_Address)(in_addr.sin_addr),
			port = cast(int)in_addr.sin_port,
		}
	case .INET6:
		in6_addr := addr.(posix.sockaddr_in6)
		return {
			port = cast(int)in6_addr.sin6_port,
			address = transmute(net.IP6_Address)(in6_addr.sin6_addr),
		}
	}
	return
}
