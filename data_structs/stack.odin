/*

SDG                                                                           JJ
                                  
                           Thread-Safe Stack

  Implements a lock-free, thread-safe-stack based on the Atomic Ring-Buffer
  defined in ring.odin. It's important to note that this stack is not
  resizeable by design.

*/
package data_structs

import "core:sync"

/*
  Stack

  A Thread-Safe (I think) Stack. Stores pointers to the specified type.

  Initialize like so:
  q := Stack(some_type, some_len){}

  Or more_easily: `make_stack(some_type, some_len)`

  Use `push` to add to the Stack. 
  Use `pop` to consume the Stack. 

  Do not initialize the values of the struct. The procedures below 
  expect them to be intiialized to zero.
*/
Stack :: struct($T: typeid, $buf_len: int) {
	buf:   [buf_len]^T,
	len:   int,
}

/*
  make_stack

  Initialize the stack.
*/
make_stack :: proc($T: typeid, $buf_len: int) -> Queue(^T, buf_len) {
	return Stack(^T, buf_len){}
}

/*
  push

  Add to the Stack
*/
push :: proc(q: ^Stack(^$T, $buf_len), val: ^T) -> (ok: bool) {
	if idx := sync.atomic_add(&q.len, 1); idx <= buf_len {
		sync.atomic_store(&q.buf[idx], val)
		ok = true
	} else {
		sync.atomic_sub(&q.len, 1)
	}
	return
}

/*
  pop

  Remove from the Stack
*/
pop :: proc(q: ^Stack(^$T, $buf_len)) -> (ptr: ^T, ok: bool) {
	if idx := sync.atomic_sub(&q.len, 1); idx >= 0 {
		ptr = sync.atomic_exchange(&stack.buf[idx], nil)
		if ok = ptr != nil; !ok {
			sync.atomic_add(&q.len, 1)
		}
	} else {
		sync.atomic_add(&q.len, 1)
	}
	return
}
