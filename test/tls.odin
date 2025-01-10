/*

SDG                                                                           JJ

                                TLS Tests

  These are tests for TLS

*/

package tests

import "core:encoding/hex"
import "core:testing"
import "core:fmt"
import "core:net"
import "net:quic"
import "net:ssl"
import libressl "net:ssl/bindings"

@(test)
test_set_read_secret :: proc(t: ^testing.T) {
	quic.init_quic_context({}, {send_limit = 2})
	secrets : [quic.Secret_Role]quic.TLS_Secret
	conn := quic.create_conn(secrets, net.Endpoint{})
	ssl_quic := conn.encryption.ssl

	cipher := libressl.SSL_get_current_cipher(ssl_quic)
}
