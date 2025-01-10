/*

SDG                                                                           JJ

                               Client/Server API

  This package exposes several API's. These API's are handled asynchronously. 
  These include stream-send API's, realtime, unreliable-send API's, stream-read
  API's realtime, unreliable-read API's and error-handling API's, both to 
  receive errors from the peer or the transport (this library), and to send 
  errors to the peer and to handle error states.

  It is important to note thaat streams inherently involve some buffering, due
  to their ordered nature, and that for realtime applications, such as video
  game state, using the unreliable-read API's are better. Users in this space
  should use the unreliable-read/send API's for game-state and use the stream
  API's for assets and logging for which order matters more than latency.

  As such, streams api's offer slices to read from and write too, along with
  callbacks  whenever the transport either receives or sends stream data. 
  Users should not cache the adddresses of these slices, as they are reused, in
  addition, there are API's to create, prioritize, and close those streams.

  Realtime, unreliable data is transferred in an event-driven manner using
  callbacks, and, on linux, data is written directly to the IO_Vecs which
  are used for sending. Datagram frames, are not included in the same
  packets or UDP datagrams as any other type of frame, except for padding
  frames, in order to facilitate their prioritization and handling.

  Client and Server API's are not divided because the same instance of quic
  may be client for one connection and server for another. However, you can
  select a Role in the initialization function which will provide some
  sensible defaults.

  Please note that the quic context is global. Please don't forget to shut
 */
package quic

import "core:net"
import ds "./data_structs"

/*
  quic.Connect_Callback

  Callback parameter type for the callbacks struct in the `init` procedure.

  This callback is called whenever a client connects to QUIC. The endpoint
  is included in-case the application must block certain IP's or regions, for
  compliance purposes.

  If this parameter is left null, incoming packets from unknown peers are
  ignored.
*/
Connect_Callback :: #type proc(peer: net.Endpoint, conn: ^Conn)

/*
  quic.Stream_Callback

  Callback parameter type for the callbacks struct in the `init` procedure.

  This callback is called whenever a stream is initiated by the peer, when new
  data is available on the stream, or when it is closed.

  This parameter is required.
*/
Stream_Callback :: #type proc(
	conn: ^Conn,
	stream_id: Stream_Id,
	err: Transport_Error,
)

/*
  quic.Datagram_Frame_Callback

  Callback parameter type for the callbacks struct in the `init` procedure.

  This callback is called whenever a Datagram_Frame is called. Please ensure
  That this is non-blocking. 
 
  The callback must be called with the context parameter, when you are done
  reading the application data.
  
  If you do not specify this, the datagram extension will be disabled.
*/
Datagram_Frame_Callback :: #type proc(
	conn: ^Conn,
//	callback: proc(ctx: rawptr),
	//	callback_ctx: rawptr,
	data: []u8
)

/*
  quic.Callbacks

  Struct of callbacks provided to the global QUIC context.

  connect_callback is optional for clients which only use QUIC to connect to
  servers. 

  stream_callback is required unless MAX_STREAMS is 0 and QUIC is being used
  exclusively for datagrams. No supported protocol does this, AFAIK, so this
  field is required.
*/
Callbacks :: struct {
	connect_callback:        Maybe(Connect_Callback),
	stream_callback:         Maybe(Stream_Callback),
	datagram_frame_callback: Maybe(Datagram_Frame_Callback),
}

/*
  quic.init

  Initializes the QUIC state and and starts listening for connections. This
  applies even in the client role, however, in the client role, connection
  attempts from unknown sources will be ignored.
*/
init :: proc(role: Role, callbacks: Callbacks) {
	// TODO figure out client defaults
	init_runtime(callbacks)
}

/*
  On_Connection

  Accepts a tuple of a ^Conn and a Transport_Error.
  This is called on either a successful path validation or
  otherwise when it is possible to start sending application
  data.
*/
On_Connection :: #type proc(conn: ^Conn, err: Transport_Error)

/*
  quic.create_connection

  Creates a connection for a peer for quic connection, but does not send
  the first packet. This is to allow the application to include early data
  before sending. Early data is treated the same as every other type of data,
  and there are no separate early data apis.
 */
create_connection :: proc(peer: net.Endpoint, callback: On_Connection) {
	assert(false, "Not Implemented Yet")
}

/*
  quic.open_connection

  Initiates a connection with the peer specified by calling create_connection.
  Initiates the sending of the Initial packet as well as any queued up Early Data.

  Please note, that Early Data is not guaranteed to be accepted, however, any 
  unacknowledged Early Data provided will be resent. 

  WARNING: Early Data, while encrypted, may be replayed by an attacker. This 
  means that data submitted in early data, before `open_connection` is called,  
  should not include any changes which may change the state of the application 
  if sent repeatedly. The best use for Early Data is to initialize streams, and 
  let the server know to load cached user data before the application client 
  starts sending stateful updates.
*/
open_connection :: proc(conn: ^Conn) {
	assert(false, "Not Implemented Yet")
}

/*
  quic.create_stream

  Initializes a stream and returns a stream id and a transport error.

  If bidirectional is set to true, initializes a bidirectional stream,
  otherwise initializes a send-only stream.

  In order to write to this stream, use `write_stream`
*/
create_stream :: proc(
	conn: ^Conn,
	bidirectional: bool,
) -> (
	stream_id: Stream_Id,
	ok: bool,
) {
	return init_stream(conn, bidirectional)
}

/*
  quic.get_stream_writable

  This gets a slice to write data into. After writing to the slice, call 
  `quic.write_stream_writable` with that slice of data as a param. The 
  procedure will notreturn a slice smaller than requested by the `len` 
  param, but will instead return a Stream_Buffer_Full error.

  This procedure uses atomics, and should have consistent memory ordering, 
  meaning it is safe to use multithreaded.
*/
get_stream_writable :: proc(
	conn: ^Conn,
	stream_id: Stream_Id,
	len: uint,
) -> (
	[]byte,
	Application_Write_Error,
) {
	assert(false, "Not Implemented Yet")
	return nil, nil
}

/*
  quic.write_stream_writable

  After calling `get_stream_writable`, and writing into the returned
  slice, call this to enqueue the data. Please ensure that the buf
  provided to this callback is the same one provided by 
  `get_stream_writable`
  TODO: fix this. It is an ugly API, even if conducive to IO_Vecs
*/
write_stream_writable :: proc(
	conn: ^Conn,
	stream_id: Stream_Id,
	buf: []byte,
) -> Application_Write_Error {
	assert(false, "Not Implemented Yet")
	return nil
}

/*
  quic.get_stream_readable

  Get a slice of data from the stream. While it is safe to transform the data
  in the slice, please call `read_stream_readabler` to signal that you are done
  with the data in the slice or else you will slow down reading of successive 
  data.
*/
get_stream_readable :: proc(
	conn: ^Conn,
	stream_id: Stream_Id,
	max_len: uint,
) -> (
	[]byte,
	Application_Read_Error,
) {
	assert(false, "Not Implemented Yet")
	return nil, nil
}

/*
  quic.read_stream_readable

  Signal completion of reading the slice provided by `quic.get_stream_readable`
  by the application. The slice provided to the callback must be the same one
  provided by `get_stream_readable`
*/
read_stream_readable :: proc(
	conn: ^Conn,
	stream_id: Stream_Id,
	buf: []byte,
) -> Application_Read_Error {
	assert(false, "Not Implemented Yet")
	return nil
}

/*
  quic.stream_finish

  Signal completion of data on a stream. This does not close the connection,
  just the stream. Use this when you want to tell the application on the other
  end that you have sent everything that you intended to for that stream.

  You have 2^60 -1 streams, of the sending, receiving, and bidirectional sort,
  so use them freely.
*/
stream_finish :: proc(conn: ^Conn, stream_id: Stream_Id) {
	assert(false, "Not Implemented Yet")
}

/*
  quic.close_stream

  Closes the specified stream by sending a Reset_Stream frame, if the stream
  is a sending stream, and a Stop_Sending frame if the stream is a receiving
  stream.

  If the stream is bidirectional, it closes both ends.
*/
close_stream :: proc(conn: ^Conn, stream_id: Stream_Id) {
	assert(false, "Not Implemented Yet")
}

/* 
  quic.close_connection

  Closes the connection with a Connection_Close frame.
  The error_code param is application specific, as is the reason phrase
*/
close_connection :: proc(
	conn: ^Conn,
	error_code: u32,
	reason_phrase: string,
) {
	assert(false, "Not Implemented Yet")
}
