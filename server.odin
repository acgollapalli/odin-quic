/*
 * SDG                                                                         JJ
 */

package quic

import "core:time"

// listen for incoming connections
server_listen :: proc()

// embed early data
embed_in_tls_resumption_ticket :: proc()

// retrieve early data (0-RTT)
retrieve_from_tls_resumption_ticket :: proc()

NUM_THREADS :: int

Conn_Handler_Thread :: struct {
	id:                   int,
	iteration_time_start: time.Time,
	last_iteration_time:  time.Duration,
	queue:                []^[]Packet,
}
