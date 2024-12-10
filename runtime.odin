/*

SDG                                                                           JJ

                                   Runtime

  This package can use one or several threads, depending on the users 
  it is designed to be scaled according to the users needs, and to scale up
  and down in accordance with the load at any point.


 */
package quic

import "core:sync"
import "core:thread"

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

/*
  TODO: Document
*/
init_with_server_defaults :: proc(alloc := context.allocator) {
	context.allocator = alloc
}

init_with_client_defaults :: proc(alloc := context.allocator) {
	context.allocator = alloc
}
