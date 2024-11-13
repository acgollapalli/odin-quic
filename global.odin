/*
 * SDG                                                                         JJ
 */

package quic

import ssl "../odin-ssl"
import libressl "../odin-ssl/bindings"
import "core:math/rand"
import "core:sync"

/*
 * Glolbal Context Lives in this file
 * 
 * Use init to initialize it
 */

Context_Type :: struct {
	connections:            #soa[dynamic]Conn,
	ssl_context:            ssl.SSL_Context,
	stateless_reset_tokens: map[[16]byte]Connection_Id,
	lock:                   sync.Mutex,
}

Global_Context: Context_Type
Cert_Path :: #config(Cert_Path, ".")
Pkey_Path :: #config(Pkey_Path, ".")
Cert_Type :: #config(Cert_Type, 2)
Pkey_Type :: #config(Pkey_Type, 1)

init_quic_context :: proc() {
	Global_Context = Context_Type { 	// do we even need this? it should init most of it to empty by default, right?
		make(#soa[dynamic]Conn),
		ssl.create_ctx(
			Cert_Path,
			Pkey_Path,
			ssl.Certificate(Cert_Type),
			ssl.Certificate(Pkey_Type),
		), // FIXME: We need to be able to get certs out of some kind of config
		map[[16]byte]Connection_Id{},
		sync.Mutex{},
	}
}

open_conn_server :: proc(
	config: Conn_Config,
	initial_secrets: Encryption_Level_Secrets,
	early_data_secrets: Encryption_Level_Secrets = nil,
) {
	sync.mutex_guard(&Global_Context.lock) // acquire lock and release it when done


	// add it to Global_Context
	conn := Conn {
		send_limit = config.send_limit,
		receive_limit = config.receive_limit,
		version = .QUICv1,
		role = config.role,
		flow_enabled = true,
		spin_enabled = rand.uint64() % 8 != 0,
		lock = sync.Mutex{},
		source_conn_ids = make(Connection_Ids, 100), // just overwrite them as you go and issue valid until for that conn_id
		dest_conn_ids = make(Connection_Ids, 100),
		encryption = Encryption_Context {
			secrets = [ssl.QUIC_Encryption_Level]Encryption_Level_Secrets {
				.Initial_Encryption = initial_secrets,
				.Early_Data_Encryption = early_data_secrets,
				.Handshake_Encryption = nil,
				.Application_Encryption = nil,
			},
			ssl = libressl.SSL_new(Global_Context.ssl_context),
			lock = sync.Mutex{},
		},
	}

	append(&Global_Context.connections, conn)
}

// FIXME: write this function
close_conn :: proc(conn: ^Conn) {
	// remove  it from Global_Context

}

// FIXME: write this function
find_conn_by_dest_conn_id :: proc(id: Connection_Id) -> ^Conn {
	// FIXME: Don't forget the guard
	for &conn in Global_Context.connections {
		for c_id in conn.dest_conn_ids {
			if c_id.valid && string(c_id.value) == string(id) {
				return &conn
			}
		}
	}
	return nil
}

// FIXME: write this function
find_conn_by_ssl :: proc(ssl: ssl.SSL_Connection) -> ^Conn {
	// FIXME: Don't forget the guard
	for &conn in Global_Context.connections {
		if conn.encryption.ssl == ssl {
			return &conn
		}
	}
	return nil
}

find_conn :: proc {
	find_conn_by_dest_conn_id,
	find_conn_by_ssl,
}
