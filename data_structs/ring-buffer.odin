/*

SDG                                                                           JJ
                                  
                               Atomic Ring Buffer

  Implements a lock-free ring buffer for reading and writing from streams. 
  Uses atomics to manage incrementing and decrementing of the ring buffer.

  We may end up using a queue of buffers instead, or just sticking with 
  returning slices of a dynamic array. The benchmarks will determine what we
  need to do.
  
  But I thought it was worthwhile to implement this as it seemed a very 
  obvious solution.

  TODO: Read the Lock-Free Queue Kernel Code for ideas
  NOTE: I'm worried about a fast reader reading a buffer that has been marked
  written without actually being fully written. Maybe a circular queue of 
  pointers to buffers may be better, or else some way to track marked-for-read 
  vs allowed for read, but this is more like a memory allocator than a queue at 
  that point.

  WARNING: if your writer is slow, or blocks, don't use this. Actually, just 
  don't use this. If this is in the remote repo, it is only so that that I can
  look at it later and fix it.
*/
package data_structs

import "base:builtin"
import "core:sync"

Atomic_Ring_Buffer :: struct($T: typeid, $buf_len: int) {
	buf:   [buf_len]T,
	read:  int,
	write: int,
}

Write_Error :: enum {
	None,
	Not_Enough_Space,
}

ARing_Slice :: struct($T: typeid) {
	head: []T,
	tail: []T,
}

get_read_slice :: proc(
	ring: ^Atomic_Ring_Buffer($T, $buf_len),
	read_len: int,
) -> (
	s: ARing_Slice(T),
	ret_len: int,
) {
	assert(read_len > 0 && read_len < buf_len, "read_len must be a positive int < buf_len")

	read := sync.atomic_load(&ring.read)
	write := sync.atomic_load(&ring.write)

	written_space := (write - read) %% buf_len

	ret_len = min(read_len, written_space)
	read = sync.atomic_add(&ring.read, ret_len)

	if read + ret_len < buf_len {
		s = ARing_Slice(T){ring.buf[read:][:ret_len], nil}
	} else {
		sync.atomic_compare_exchange_strong(&ring.read, read, read % buf_len)
		s = ARing_Slice(T){ring.buf[read:], ring.buf[:(read + ret_len) % buf_len]}
	}
	return
}

get_write_slice :: proc(
	ring: ^Atomic_Ring_Buffer($T, $buf_len),
	write_len: int,
) -> (
	ARing_Slice(T),
	Write_Error,
) {
	read := sync.atomic_load(&ring.read)
	write := sync.atomic_load(&ring.write)

	available := (read - write) %% buf_len if read != write else buf_len
	if write_len > available - 1 do return {}, .Not_Enough_Space
	write = sync.atomic_add(&ring.write, write_len)
	fmt.println("new_write", write)

	if write + write_len < buf_len {
		return ARing_Slice(T){ring.buf[write:][:write_len], nil}, nil
	} else {
		sync.atomic_compare_exchange_strong(&ring.write, write, write % buf_len)
		return ARing_Slice(T){ring.buf[write:], ring.buf[:(write + write_len) % buf_len]}, nil
	}
}

index :: proc(s: ^ARing_Slice($T), i: int) -> ^T {
	return &s.head[i] if i < builtin.len(s.head) else &s.tail[i - builtin.len(s.head)]
}

Iterator :: struct($T: typeid) {
	s: ^ARing_Slice(T),
	i: int,
}

iter :: proc(s: ^ARing_Slice($T)) -> Iterator(T) {
	return Iterator(T){s, 0}
}

len :: proc(s: ^ARing_Slice($T)) -> int {
	return builtin.len(s.head) + builtin.len(s.tail)
}

// TODO: Decide if we actually want to make it iterable in this way.
next :: proc(it: ^Iterator($T)) -> (^T, bool) {
	if it.i < len(it.s) {
		i := it.i
		it.i += 1
		return index(it.s, i), i < len(it.s)
	} else {
		return nil, false
	}
}
