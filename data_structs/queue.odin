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

  Use `write` to add to the Queue. 
  Use `read` to consume the Queue. 

  Do not initialize the values of the struct. The procedures below 
  expect them to be intiialized to zero.

  Or just use the the Make_Queue procedure.
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
	return Queue(^T, buf_len){}
}

/*
  write

  Add to the Queue
*/
write :: proc(q: ^Queue(^$T, $buf_len), val: ^T) -> (ok: bool) {
	defer if !ok do sync.atomic_sub(&q.len, 1)
	(sync.atomic_add(&q.len, 1) <= buf_len) or_return
	
	idx := _inc_rem(&queue.write, buf_len)
	sync.atomic_store(&q.buf[idx], val)
	return true
}

/*
  read

  Remove from the Queue
*/
read :: proc(q: ^Queue(^$T, $buf_len)) -> (ptr: ^T, ok: bool) {
	defer if !ok do sync.atomic_add(&q.len, 1)
	(sync.atomic_sub(&q.len, 1) >= 0) or_return

	defer if !ok do _dec_rem(&queue.read, buf_len)
	idx := _inc_rem(&queue.read, buf_len)

	ptr = sync.atomic_exchange(&queue.buf[idx], nil)
	return ptr, ptr != nil
}



/*
  _inc_rem
  
  Atomic increment remainder (%%) the modulus.

  Returns the value PRIOR to the operation %% the length of the queue
  Does a CAS whenever the updated value would go out of bounds of the queue.
  The returned values are always in bounds, and the underlying values are eventually 
  in bounds.
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

  Returns the value PRIOR to the operation %% the length of the queue
  Does a CAS whenever the updated value would go out of bounds of the queue
  The returned values are always in bounds, and the underlying values are eventually
  in bounds.
*/
_dec_rem :: proc(addr: ^$T, rem: int) -> T {
	old := sync.atomic_sub(addr, 1)

	if new := old - 1; new <= 0 {
		sync.compare_exchange_strong(addr, new, new %% rem)
	}

	return old %% rem
}
