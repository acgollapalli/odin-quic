/*

SDG                                                                           JJ

                                   Runtime

  This package can use one or several threads, depending on the users 
  it is designed to be scaled according to the users needs, and to scale up
  and down in accordance with the load at any point.


 */
package quic

// std library declarations
import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:sync"
import "core:thread"

// in engine declarations
import "net:http/nbio"
import "net:http/nbio/poly"

import data_structs "net:quic/data_structs"

/*
  TODO: Document
*/
MIN_READ_THREADS, MAX_READ_THREADS ::
	#config(MIN_READ_THREADS, 1), #config(MAX_READ_THREADS, 64)

/*
  TODO: Document
*/
MIN_WRITE_THREADS, MAX_WRITE_THREADS ::
	#config(MIN_WRITE_THREADS, 1), #config(MAX_WRITE_THREADSS, 64)

/*
  TODO: Document
  These should be cheap.
  TODO: make acks run in batches and queues so those are cheap.
*/
MIN_TIMER_THREADS, MAX_TIMER_THREADS ::
	#config(MIN_TIMER_THREADS, 1), #config(MAX_TIMER_THREADS, 4)

PORT :: #config(PORT, 8443)
ADDRESS :: #config(ADDRESS, "127.0.0.1")

MAX_DATAGRAM_SIZE :: #config(MAX_DGRAM_SIZE, 4096)
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

init_runtime :: proc(address := ADDRESS, port := PORT) {
	address := net.parse_address(ADDRESS)
	fmt.assertf(address != nil, "Error parsing connection params: %v", ADDRESS)

	address_family := net.family_from_address(address)
	endpoint := net.Endpoint{address, PORT}

	sock, err := nbio.open_socket(&server.io, address_family, .UDP)
	socket := sock.(net.UDP_Socket)

	// bind socket
	if err = net.bind(socket, endpoint); err != nil {
		net.close(socket)
		return
	}

	fmt.assertf(err == nil, "Error opening socket: %v", err)
	server.sock = socket


	init_quic_context()

}

/* Thread Contexts */
/* I/O */

/* Receiving Datagrams */

Recvmsg_Ctx :: struct {
	io:      net.io,
	name:    [80]byte, // should
	io_vecs: [1][MAX_DATAGAM_SIZE]byte,
	sock:    net.UDP_Socket,
}

receive_thread_task :: proc(sock: net.UDP_Socket) {
	ctx: Recvmsg_Ctx
	ctx.sock = sock

	nbio.init(&ctx.io)
	defer nbio.destroy(&ctx.io)

	io_err: os.Errno

	read_datagram(&ctx, sock, alloc)

	for go := Global_Context.thread_state;
	    go != .Stop && io_err == os.ERROR_NONE; {
		if go == .Pause do continue

		nbio.tick()
	}
}

/*
TODO: Add support to our fork of NBIO to allow for cmsghdr so we can set and 
read ECN codepoints for congestion control (Yup, we get to read more man pages)s
TODO: Refactor our changes in NBIO to allow us to just pass the danged msgheader
in, instead of expecting NBIO to do it. That way we can just reuse the IO_Vecs per
thread, or put it in a pool to be reused or something.
*/
on_recvmsg :: proc(
	ctx: rawptr,
	name_len: int,
	received: int,
	err: net.Network_Error,
) {
	ctx := transmute(^UDP_Ctx)ctx
	name := string(ctx.name[:name_len])
	peer, parse_ok := net.parse_endpoint(name)

	if err == nil && parse_ok {
		handle_datagram(ctx.buf[:received], peer)
	} else {
		if err do fmt.printfln("Error receiving from client: %v", err)
		if !parse_ok do fmt.printfln("Error reading peer path: %v", name)
	}

	nbio.recvmsg(&ctx.io, ctx.name[:], ctx.io_vecs[:], &ctx, on_recvmsg)
}

/* Sending Datagrams */
Sendmsg_Ctx :: struct {
	io:      net.io,
	io_vecs: [1][MAX_DATAGAM_SIZE]byte,
	sock:    net.UDP_Socket,
}
send_thread_task :: proc(sock: net.UDP_Socket) {
	ctx: Sendmsg_Ctx
	ctx.sock = sock

	nbio.init(&ctx.io)
	defer nbio.destroy(&ctx.io)

	io_err: os.Errno

	for go := Global_Context.thread_state;
	    go != .Stop && io_err == os.ERROR_NONE; {
		if go == .Pause do continue

		// NOTE: This is temporary.
		// Connections can be partitioned % num_send_threads
		// But... I need to get core logic implemented and actually get this in a
		// debugging session and a profiler first to see where the hiccups are.
		for &c in Global_Context.connections {
			dglen: int
			for pn_space in c.send_queue { 	// TODO: is there syntax to force unroll?
				pkt, plen := make_packet(c, pn_space, ctx.io_vecs[0][dglen:])
			}
			if dglen > 0 {
				nbio.sendmsg(
					&ctx.io,
					ctx.sock,
					transmute([]u8)net.endpoint_to_string(c.endpoint),
					ctx.io_vecs[:],
					&ctx,
					on_sendmsg,
				)
			}
		}
		nbio.tick()
	}
}

on_sendmsg :: proc(user: rawptr, sent: int, err: net.Network_Error) {
	// I don't actually know what to do here. All the state updates should be
	// handled in make_packet, unless we want to pass a list of all the frames
	// in the callback.
	// send failures will be treated as lost packets and retransmitted.
	// that may be slow, and it may be better to handle it here.
	// I guess we'll just have to use this to handle errors
}
