/*

SDG                                                                           JJ

                                  Utils

  Functions for serialization and deserialization

*/
package quic

import "core:fmt"
import "core:sync"

cursor_append :: proc(data: []$T, cursor: ^[]T) -> (bytes_written: int) {
	assert(len(data) <= len(cursor))

	bytes_written = len(data)
	for b, i in data {
		cursor[i] = b
	}
	cursor^ = cursor[bytes_written:]
	return
}

cursor_append_one :: proc(data: $T, cursor: ^[]T) {
	assert(len(cursor) > 0)
	cursor[0] = data
	cursor^ = cursor[1:]
}

log2 :: proc(n: u64) -> (i: int) {
	for n := n; n > 1; n >>= 1 {
		i += 1
	}
	return
}

encode_packet_number :: proc(
	full_pn: u64,
	largest_acked: u64,
	alloc := context.temp_allocator
) -> (
	truncated_pn: []u8,
) {
	num_unacked := full_pn - largest_acked
	min_bits := log2(num_unacked) + 1
	num_bytes := (min_bits >> 3) + 1

	// stack allocate our return value
	truncated_pn = make([]u8, num_bytes, alloc)

	full_pn_arr := transmute([8]u8)full_pn
	for i := 0; i < num_bytes; i += 1 {
		truncated_pn[(num_bytes - 1) - i] = full_pn_arr[i]
	}

	return truncated_pn
}

pn_largest_acked :: proc(conn: ^Conn, pn_space: Packet_Number_Space) -> (largest_acked: u64) {
	{
		sync.guard(&conn.acks[pn_space].lock)
		largest_acked = conn.acks[pn_space].largest_acked
	}
	return
}

decode_packet_number :: proc(
	largest_pn: u64,
	truncated_pn: u32,
	pn_len: int,
) -> (
	full_pn: u64,
) {
	pn_nbits := u8(pn_len * 8)
	expected_pn := largest_pn + 1
	pn_win : u64 = 1 << pn_nbits
	pn_hwin := pn_win / 2
	pn_mask := pn_win - 1
	candidate_pn := (expected_pn &~ pn_mask) | u64(truncated_pn)
	if candidate_pn <= (expected_pn - pn_hwin) &&
	   candidate_pn < (1 << 62) - pn_win {
		return candidate_pn + pn_win
	} else if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
		return candidate_pn - pn_win
	}
	return candidate_pn
}
