/*
 * SDG                                                                         JJ
 */


package quic

import "core:encoding/uuid"
import "core:time"

generate_connection_id :: proc(counter: u16) -> []u8 {
	id := uuid.generate_v7_with_counter(counter, time.now())
	bytes := new([16]u8)
	bytes^ = ([16]u8)(id) // TESTME: this seems like it shouldn't work... I should test this.
	return bytes[:]
}
