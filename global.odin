/*

SDG                                                                           JJ

                                       Global

  This file holds the global context for QUIC state.

  The global state includes a dynamic SOA array of Conn objects, as well as a
  hash map of Connection_Id's to Connection Object Pointers, for matching incoming
  packets Dest_Conn_Id to the relevant connection.

  Each Conn object has a pointer to its handle, although this is null until
  a handle is actually allocated, when the Conn object is added to the global
  state.

  Conn initialization and destruction procedures also live in this file, for 
  now, due to how dependent they are on this context.

  TODO: Improve handling of the lifecycle
  TODO: Improve handling of Conn's

  Receiving workflow:
    Receive Datagram.
    Get Conn for Datagram from DestConnId of first packet: 
      Read DestConnId 
      Check dest_conn_ids
      Check Handle

    
   
*/

package quic

import ssl "../ssl"
import libressl "../ssl/bindings"
import "core:math/rand"
import "core:sync"
import "core:net"
//import ds "./data_structs"

/*
 * Global Context Lives in this file
 * 
 * Use init to initialize it
 */

Context_Type :: struct {
	connections:            [dynamic]^Conn,
	ssl_context:            ssl.SSL_Context,
	thread_state:           Thread_State,
	stateless_reset_tokens: map[string]Connection_Id,
	path_validation_tokens: map[string]Connection_Id,
	conn_ids:               map[string]^Conn,
	callbacks:              Callbacks,
	lock:                   sync.RW_Mutex,
}

Thread_State :: enum {
	Go,
	Pause,
	Stop,
}

Global_Context: Context_Type
Cert_Path :: #config(Cert_Path, ".")
Pkey_Path :: #config(Pkey_Path, ".")
Cert_Type :: #config(Cert_Type, 2)
Pkey_Type :: #config(Pkey_Type, 1)

init_quic_context :: proc(callbacks: Callbacks) {
	Global_Context.ssl_context = ssl.create_ctx(
		Cert_Path,
		Pkey_Path,
		ssl.Certificate(Cert_Type),
		ssl.Certificate(Pkey_Type),
	) // FIXME: We need to be able to get certs out of some kind of config

	Global_Context.callbacks = callbacks
	Global_Context.thread_state = .Go
}

// TODO Refactor things so they don't need a pointer to Conn, but a handle.
// Iterating Over an array of pointers is most likely very inefficient.
open_conn_server :: proc(
	config: Conn_Config,
	initial_secrets: [Secret_Role]TLS_Secret,
) -> ^Conn {
	sync.guard(&Global_Context.lock) // acquire lock and release it when done

	// add it to Global_Context
	conn := new(Conn)
	conn.send_max_data = config.send_limit
	conn.receive_max_data = config.receive_limit
	conn.version = .QUICv1
	conn.role = config.role
	conn.flow_enabled = true
	conn.spin_enabled = rand.uint64() % 8 != 0

	conn.encryption.secrets[.Initial_Encryption] = initial_secrets
	conn.encryption.ssl = ssl.create_conn(Global_Context.ssl_context, rawptr(conn))

	append(&Global_Context.connections, conn)
	return conn
}

create_conn :: proc(p: Initial_Packet, peer: net.Endpoint) -> ^Conn {
	// TODO figure out a way to avoid recomputing this.
	// This the second time we compute this for this packet.
	secret := determine_initial_secret(p.dest_conn_id)
	config: Conn_Config
	assert(config.send_limit > 0, "Implement Conn_Config")
	conn := open_conn_server(config, secret)
	conn.paths[peer] = Path {
		endpoint = peer,
		rtt      = new(RTT_State), // TODO add proper initializers for all of these
		ecc      = new(ECC_State),
		timeout  = new(Timer_State),
	}
	return conn
}

// FIXME: IMPLEMENT
// Here we set the connection to closing
// Any subsequent packets are dropped.
// nothing else is added to the queue
close_conn :: proc(conn: ^Conn, error: Transport_Error) {
	defer destroy_conn(conn)

	assert(false, "not implemented")
}

queue_close_conn :: proc(conn: ^Conn, error: Transport_Error) {

	assert(false, "not implemented")
}

// FIXME: replace with hashmap
find_conn_by_dest_conn_id :: proc(id: Connection_Id) -> (conn: ^Conn, ok: bool) {
	// FIXME: Don't forget the guard
	sync.shared_guard(&Global_Context.lock)
	c, k := Global_Context.conn_ids[transmute(string)id]
	return c, k
}

// FIXME: write this function
find_conn_by_ssl :: proc "contextless" (
	ssl_conn: ssl.SSL_Connection,
) -> (conn: ^Conn, ok: bool) {
	conn = transmute(^Conn)ssl.get_app_data(ssl_conn)
	ok = conn != nil
	return
}

find_conn :: proc {
	find_conn_by_dest_conn_id,
	find_conn_by_ssl,
}


destroy_conn :: proc(conn: ^Conn) {
	destroy_encryption(conn)
}
