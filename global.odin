package quic

import "core:math/rand"
import "ssl"
import "ssl/libressl"

/*
 * Glolbal Context Lives in this file
 * 
 * Use init to initialize it
 */

Context_Type : struct {
    connections: #soa[dynamic]^Conn,
    ssl_context: ssl.SSL_Context,
    lock: sync.Mutex,
}

Global_Context : Context_Type ---

init_quic_context :: proc() {
    Global_Context = Context_Type{
	make([dynamic]^Conn),
	ssl.create_context(), // FIXME: We need to be able to get certs out of some kind of config
	lock: sync.Mutex{}
    }
}

open_conn_server(config: Conn_Config, initial_secrets: Encryption_Level_Secrets) {
    sync.mutex_guard(Global_Context.lock) // acquire lock and release it when done

    // add it to Global_Context
    conn := Conn{
	send_limit = config.send_limit,
	receive_limit = config.receive_limit,
	version = .QUICv1,
	role = config.role,
	flow_enabled = true,
	spin_enabled = rand.uint64() % 8 != 0,
	lock = sync.Mutex{},
	source_conn_ids: [100]Connection_id, // just overwrite them as you go and issue valid until for that conn_id
	dest_conn_ids: [100]Connection_id,
	encryption = Encryption_Context{
	    secrets = [ssl_encryption_level_t]Encryption_level_Secrets{
		    .ssl_encryption_initial = initial_secrets
	    },
	    ssl = libressl.SSL_new(Global_Context.ssl_context),
	    lock = sync.Mutex{}
	}
    }

    append(Global_Context.connections, conn)
}

// FIXME: write this function
close_conn(conn: ^Conn) {
    // remove  it from Global_Context

}
   
// FIXME: write this function
find_conn_by_dest_conn_id :: proc(id: Connection_Id) -> ^Conn {
    // FIXME: Don't forget the guard

}

// FIXME: write this function
find_conn_by_ssl :: proc(ssl: SSL_Connection) -> ^Conn {
    // FIXME: Don't forget the guard

}

find_conn ::proc{
    find_conn_by_dest_conn_id,
    find_conn_by_ssl,
}
