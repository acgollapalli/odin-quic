/*

SDG                                                                           JJ

                           Deserialization Tests

  These are tests for deserializing packets.

*/
package tests

import "core:encoding/hex"
import "core:fmt"
import "core:net"
import "core:testing"
import "net:quic"

@(test)
test_init_conn :: proc(t: ^testing.T) {
	ctx := &quic.Global_Context

	quic.init_quic_context({}, {send_limit = 2})
	secrets: [quic.Secret_Role]quic.TLS_Secret
	quic.create_conn(secrets, net.Endpoint{})
	testing.expectf(t, len(ctx.connections) != 0, "Connection was not created")
	testing.expect(
		t,
		ctx.connections[0].encryption.ssl != nil,
		"SSL_Connection was not initialized",
	)
	conn_actual := ctx.connections[0]
	conn_ssl, conn_ok := quic.find_conn(ctx.connections[0].encryption.ssl)

	testing.expect(t, conn_ok, "Could not find Connection from SSL")
	testing.expectf(
		t,
		conn_ssl == conn_actual,
		"Conn pointers do not match %x vs %x",
		conn_ssl,
		conn_actual,
	)
}
