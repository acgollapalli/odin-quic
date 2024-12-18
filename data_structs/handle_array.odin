/*

SDG                                                                           JJ

                                SOA Handle Array

  This is the simplest handle array solution I could come up with.

  Implementing partly because I didn't understand Bill's: 
    https://gist.github.com/gingerBill/7282ff54744838c52cc80c559f697051

  And... I didn't want to try and understand Jakub's either:
    https://github.com/jakubtomsu/sds/blob/main/pool.odin

  We don't provide a getter, because values is SOA.

  We don't resize, because we're assuming a fairly constant usage pattern.
  I probably should have just copied Bill's or Jakub's, but I'm no copy-paste
  coder.

  TODO: We could probably do a dynamic array of pages instead to avoid some of 
  the copying behavior of the regular dynamic.
*/

package data_structs

import "core:sync"

Handle_Array :: struct($T: typeid) {
	values:    #soa[dynamic]T,
	free_stack: [dynamic]u32,
	free_len:  u32,
}

Handle :: struct {
	index: u32,
	gen:   u32,
}

ha_insert :: proc(ha: ^Handle_Array($T), val: T) -> (handle: Handle) {
	sync.guard(&ha.lock)

	assert(len(ha.values) < max(u32), "overflow of handle array")

	if ha.free_len > 0 {
		ha.free_len -= 1
		handle.index = ha.free_stack[ha.free_len]

		assert(idx <= len(ha.values), "free_stack idx >= len handle_array")

		handle.gen = ha.values[handle.index].gen + 1
		ha.values[handle.index] = val
	} else {
		handle.index = len(ha.values)
		append(&ha.values, val)
	}

	return
}


ha_check :: proc(ha: ^Handle_Array($T), handle: Handle) -> (val: T, ok: bool) {
	sync.shared_guard(&ha.lock)

	val = ha.values[handle.index]
	return val, val.gen == handle.gen
}

ha_free :: proc(ha: ^Handle_Array($T), handle: Handle) {
	sync.guard(&ha.lock)

	assert(ha.free_len + 1 < max(u32), "free list overflow or handle array is destroyed")

	if len(ha.free_stack) < ha.free_len {
		ha.free_stack[ha.free_len] = ha.index
	} else {
		append(&ha.free_stack, ha.index)
	}
	ha.free_len += 1
}

ha_destroy :: proc(ha: ^Handle_Array($T)) {
	sync.guard(&ha.lock)
	clear(&ha.values)
	clear(&ha.free_stack)
	ha.free_len = max(u32)
}
