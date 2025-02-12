/*

SDG                                                                           JJ

                                   Runtime

  This package can use one or several threads, depending on the users 
  it is designed to be scaled according to the users needs, and to scale up
  and down in accordance with the load at any point.

  In the future we may go purely even driven depending on how things go.
  This is for the posix compliant implementation using sendmsg and recvmsg
  on the sockets.

 */

#+build windows

package quic

import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:sync"
import "core:sys/windows"
import "core:thread"

import "net:http/nbio"
import "net:http/nbio/poly"

import data_structs "net:quic/data_structs"

MIN_READ_THREADS, MAX_READ_THREADS ::
#config(MIN_READ_THREADS, 1), #config(MAX_READ_THREADS, 64)

MIN_WRITE_THREADS, MAX_WRITE_THREADS ::
#config(MIN_WRITE_THREADS, 1), #config(MAX_WRITE_THREADSS, 64)

PORT :: #config(PORT, 8443)
ADDRESS :: #config(ADDRESS, "127.0.0.1")

MAX_DGRAM_SIZE :: #config(MAX_DGRAM_SIZE, 4096)
INIT_RECV_BUFS :: #config(INIT_RECV_BUFS, 100)
IO_BUFS_LENGTH :: 100 // subject to change
PACKETS_LENGTH :: 100

/*
  TODO: Document
*/
init_with_server_defaults :: proc(alloc := context.allocator) {
	context.allocator = alloc
}

init_with_client_defaults :: proc(alloc := context.allocator) {
	context.allocator = alloc
}

init_runtime :: proc(callbacks: Callbacks, address := ADDRESS, port := PORT) {
	address := net.parse_address(ADDRESS)
        fmt.assertf(address != nil, "Error parsing connection params: %v", ADDRESS)
        
        endpoint := net.Endpoint{address, PORT}
    
	config : Conn_Config
        
        init_quic_context(callbacks, config)
        
        receive_thread := thread.create_and_start_with_poly_data(
                                                                 &endpoint,
                                                                 receive_thread_task,
                                                                 )
        send_thread := thread.create_and_start_with_poly_data(
                                                              &endpoint,
                                                              send_thread_task,
                                                              )
        for !thread.is_done(receive_thread) && !thread.is_done(send_thread) {
		
	}
}

receive_thread_task :: proc(endpoint: ^net.Endpoint) {
}
send_thread_task :: proc(endpoint: ^net.Endpoint) {
}
