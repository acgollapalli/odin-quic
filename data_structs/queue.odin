/*

SDG                                                                           JJ
                                  
                           Thread-Safe Queue

  Implements a lock-free, thread-safe-queue based on the Atomic Ring-Buffer
  defined in ring.odin. It's important to note that this queue is not
  resizeable by design.

*/
package data_structs

import "core:sync"

/*
  Queue

  A Thread-Safe (I think) Queue. Stores pointers to the specified type.

  Initialize like so:
  q := Queue(some_type, some_len){}

  Or more_easily: `make_queue(some_type, some_len)`

  Use `push` to add to the Queue. 
  Use `pop` to consume the Queue. 

  Do not initialize the values of the struct. The procedures below 
  expect them to be intiialized to zero.
*/
Queue :: struct($T: typeid, $buf_len: int) {
	buf:   [buf_len]^T,
	read:  int,
	write: int,
	len:   int,
}

/*
  make_queue

  Initialize the queue.
*/
make_queue :: proc($T: typeid, $buf_len: int) -> Queue(^T, buf_len) {
	return Queue(^T, buf_len){read = 0, write = 1}
}

/*
  push

  Add to the Queue
*/
push :: proc(q: ^Queue(^$T, $buf_len), val: ^T) -> (ok: bool) {
	if sync.atomic_load(&q.len) < buf_len {
		sync.atomic_add(&queue.len, 1)
		idx := _inc_rem(&queue.write, 1, buf_len)
		q.buf[idx] = val
		return true
	} else {
		return false
	}
}

/*
  pop

  Remove from the Queue
*/
pop :: proc(q: ^Queue(^$T, $buf_len)) -> (ptr: ^T, ok: bool) {
	if sync.atomic_load(&q.len) > 0 {
		sync.atomic_sub(&queue.len, 1)
		idx := _dec_rem(&queue.write, 1, buf_len)
	}
}

/*
  _inc_rem
  
  Atomic increment remainder (%%) the modulus.

  Returns the value PRIOR to the operation
*/
_inc_rem :: proc(addr: ^$T, rem: int) -> T {
	old := sync.atomic_add(addr, 1)
	if new := old + 1; new >= rem {
		sync.compare_exchange_strong(addr, new, new %% rem)
	}
	return old %% rem
}

/*
  _dec_rem
  
  Atomic decrement remainder (%%) the modulus.

  Returns the value PRIOR to the operation
*/
_dec_rem :: proc(addr: ^$T, rem: int) -> T {
	old := sync.atomic_sub(addr, 1)
	if new := old - 1; new <= 0 {
		sync.compare_exchange_strong(addr, new, new %% rem)
	}
	return old %% rem
}
