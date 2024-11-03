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
    connections: [dynamic]^Conn,
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

close_conn(conn: ^Conn) {
    // remove  it from Global_Context

}
   
