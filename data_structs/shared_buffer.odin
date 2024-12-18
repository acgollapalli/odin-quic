/*

SDG                                                                           JJ
                                  
                                 Shared Buffer

  Simple Shared Buffer for passing around IO Vecs from Buffer Pools

  Generate all slices before sharing them.
  Don't overlap the slices when sharing them.
  Don't share the same slice acoss multiple threads (and if you do, don't 
  free them from from multiple threads... it's not a shared pointer)

  When providing a shared slice, also provide a pointer to the shared_buffer
  Make sure to free the buffer when done.

*/

package data_structs

Shared_Buffer :: struct ($T: typeid, $N: int) {
	pool : ^Queue(T, $buf_len), // ATM Pool's are just queues
	buf: ^[N]T,
	slices: map[[]T]bool
}

free_shared_slice :: proc(sb: ^Shared_Buffer($T, $N), s: []T) -> (freed: bool) {
	sb.slices[s] = false // Does this need to be atomic?

	for k,v in sb.slices {
		freed &&= !v
		if !freed do break
	}

	if freed {
		write(buf.pool, buf) or_else free(buf)
		// NOTE: This does NOT free the shared_buffer struct.
		// The shared_buffer could very well be an automatic
		// variable, defined on the stack.
	}
	return
}


