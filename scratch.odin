/*

SDG                                                                           JJ

                                   Scratch

This is the scratch file. It's useful for testing out specific procs and
building some intuition about the package as a whole.

To use it, just uncomment out main, and then run `odin run . -collection...`

You want to use it more like a repl, to try different things and double check
how they work.

Remember the words of Alec Baldwin: A.B.C., Always Be Compiling.

*/

package quic

import "core:fmt"
import "core:net"

main :: proc() {
	fmt.println("Your drill is the drill that creates the heavens!")

	callbacks := Callbacks {
		proc(peer: net.Endpoint, conn: ^Conn) {fmt.printfln(
				"new connection from %v: %v",
				peer,
				conn,
			)},
		proc(conn: ^Conn, stream_id: Stream_Id, err: Transport_Error) {
			fmt.printfln(
				"new data available on stream: %v, for conn %v, with err: %v",
				stream_id,
				conn,
				err,
			)
		},
		proc(
			conn: ^Conn,
			//	callback: proc(ctx: rawptr),
			//	callback_ctx: rawptr,
			data: []u8,
		) {fmt.println("new datagram received: %v, on conn: %v", data, conn)},
	}

	init(.Server, callbacks)
}
