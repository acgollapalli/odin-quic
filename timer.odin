/*

SDG                                                                            JJ

                                 Timers

  Timer utilities and type definitions live in this file.

  Timers are iterated over in an event loop.
  When the current tick is greater than the timeout value,
  then the timer is considered timed out.

  Please note that timers are stored as pointers and must be freed upon 
  atomic exchange (swap)


*/
package quic

import "core:net"
import "core:sync"
import "core:time"


/* ---------------------------------- TYPES ---------------------------------- */

/*
  Timer_Tag

  tag for the timer class to switch on at runtime
*/
Timer_Tag :: enum {
	Packet_Loss,
	Probe_Timeout,
}

/*
  Timer

  Timers are iterated over in an event loop.
  When the current tick is greater than the timeout value,
  then the timer is considered timed out.
*/
Timer :: struct {
	tag:     Timer_Tag,
	timeout: time.Tick,
	variant: union {
		^Packet_Loss_Timer,
		^Probe_Timeout_Timer,
	},
}

/*
  Packet_Loss_Timer

  Packet Loss Timers are set whenever a newly acknowledged packet is received
  and  
*/
Packet_Loss_Timer :: struct {
	using timer:   Timer,
	packet_number: u64,
}

Probe_Timeout_Timer :: struct {
	using timer: Timer,
}

Timer_State :: struct {
	pto_backoff:   uint,
	idle_duration: i64,
	timers:        [Packet_Number_Space]^Timer,
}

/* ---------------------------- PUBLIC PROCEDURES ---------------------------- */

/* set_loss_timer

  Sets a timer to check for loss if the packet is still pending

*/
set_loss_timer :: proc(
	conn: ^Conn,
	path: net.Endpoint,
	packet_number_space: Packet_Number_Space,
	packet_number: u64,
	timeout: time.Tick,
) {
	timer := make_packet_loss_timer(timeout, packet_number)
	sync.atomic_exchange(
		&conn.paths[path].timeout.timers[packet_number_space],
		timer,
	)
}

/*
  reset_pto_timer

  Resets the Probe Timeout (PTO) timer, the idle duration and, when appropriate, 
  the PTO backoff. 

  When an ack-eliciting packet is sent or received a PTO timer is set as well. 
    + PTO is reset whenever an ack-eliciting packet is sent or received.
    + When packets are in flight in multiple packet number spaces, PTO is the
      earlier of either the Handshake or Initial packet number space PTO
    + Application level PTO's are not started until the handshake is confirmed
    + PTO should be reset whenever the Initial or Handshake keys are discarded.

  When it is called on receiving acknowledgement, then reset_pto_backoff should
  be called as well. When receiving acknowledgement either this function XOR 
  set_loss_timer should be called. If a loss timer is set, then this function
  will not set a PTO timer.

  When the caller is of Client role and the packet number space is initial, then 
  the PTO backoff is not reset.
*/
reset_pto_timer :: proc(
	conn: ^Conn,
	path: net.Endpoint,
	packet_number_space: Packet_Number_Space,
) {
	pto_duration := calculate_pto_duration(conn, path, packet_number_space)
	set_pto_timer(conn, path, packet_number_space, pto_duration)
	reset_pto_backoff(conn, path, packet_number_space)
}

/*
  timeout_pto

  Handle when a PTO timer runs out.
  Increments the idle duration for the path and updates the PTO timer. Returns
  true if the idle timeout is less than the max idle timeout.

  If this is the case, then the 

    + PTO timer expiry MUST NOT trigger retransmission of packets.
  
*/
timeout_pto :: proc(
	conn: ^Conn,
	path: net.Endpoint,
	packet_number_space: Packet_Number_Space,
) -> bool {
	pto_duration := calculate_pto_duration(conn, path, packet_number_space)

	new_timeout_duration := sync.atomic_add(
		&conn.paths[path].timeout.idle_duration,
		i64(pto_duration),
	)

	if time.Duration(new_timeout_duration) <
	   conn.peer_params.max_idle_timeout { 	// FIXME: This should be tracked on the main conn object as the min of both peer and host
		set_pto_timer(conn, path, packet_number_space, pto_duration)
		sync.atomic_add(&conn.paths[path].timeout.pto_backoff, 1)
		return true
	} else {
		return false
	}
}

/* --------------------------- PRIVATE PROCEDURES ---------------------------- */

/*
  calculate_pto

  Calculates the timer that our timeout event needs to fire for a PTO
  
  If the packet_number space is Initial or Handshake, then the max_ack_delay
  is disregarded, as these packets are not supposed to be delayed by the peer.

  Every time that a PTO timer has fired off, the PTO duration is doubled. This 
  is PTO backoff. This occurs until we receive an Ack frame from the peer.
  The PTO backoff factor applies globally to all packet number spaces.
  
 */
@(private = "file")
calculate_pto_duration :: proc(
	conn: ^Conn,
	path: net.Endpoint,
	packet_number_space: Packet_Number_Space,
) -> time.Duration {
	pto_backoff := sync.atomic_load(&conn.paths[path].timeout.pto_backoff)
	rtt := conn.paths[path].rtt

	sync.guard(&rtt.lock)

	pto_duration: time.Duration
	switch packet_number_space {
	case .Initial, .Handshake:
		// discard max_ack_delay
		pto_duration = rtt.smoothed + max(4 * rtt.var, K_GRANULARITY)
	case .Application:
		pto_duration =
			rtt.smoothed +
			max(4 * rtt.var, K_GRANULARITY) +
			conn.peer_params.max_ack_delay
	}

	// double pto_duration to account for PTO backoff
	pto_duration *= 1 << pto_backoff

	return pto_duration
}

/* 
  make_packet_loss_timer
  
  Creats an instance of the packet_loss timer.

  Note that this is an allocation
*/
@(private = "file")
make_packet_loss_timer :: proc(
	timeout: time.Tick,
	packet_number: u64,
	alloc := context.allocator,
) -> ^Timer {
	t := new(Packet_Loss_Timer, alloc)
	t.variant = t
	t.timeout = timeout
	t.packet_number = packet_number
	return t
}

/* 
  make_pto_timer
  
  Creats an instance of the probe timeout timer.

  Note that this is an allocation
*/
@(private = "file")
make_pto_timer :: proc(
	timeout: time.Tick,
	alloc := context.allocator,
) -> ^Timer {
	t := new(Probe_Timeout_Timer, alloc)
	t.variant = t
	t.timeout = timeout
	return t
}

/*
  set_pto_timer

  Don't call this directly. Call either reset_pto_timer or handle_pto_timeout

  Sets the Probe Timeout (PTO) timer. When an ack-eliciting packet is sent or
  received a PTO timer is set as well. 
    + PTO is reset whenever an ack-eliciting packet is sent or received.
    + When packets are in flight in multiple packet number spaces, PTO is the
      earlier of either the Handshake or Initial packet number space PTO
    + Application level PTO's are not started until the handshake is confirmed
    + PTO should be reset whenever the Initial or Handshake keys are discarded.

  When it is called on receiving acknowledgement, then reset_pto_backoff should
  be called as well. When receiving acknowledgement either this function XOR 
  set_loss_timer should be called. If a loss timer is set, then this function
  should not be set.

*/
@(private = "file")
set_pto_timer :: proc(
	conn: ^Conn,
	path: net.Endpoint,
	packet_number_space: Packet_Number_Space,
	pto_duration: time.Duration,
	alloc := context.allocator,
) {
	sync.shared_guard(&conn.lock) // possibly unnecessary
	idle_duration := sync.atomic_load(&conn.paths[path].timeout.idle_duration)
	timer := sync.atomic_load(
		&conn.paths[path].timeout.timers[packet_number_space],
	)
	if time.Duration(idle_duration) < conn.peer_params.max_idle_timeout &&
	   timer.tag != .Packet_Loss {

		event_time := time.tick_now() // maybe should be packet receipt time
		pto_next_tick := time.Tick{event_time._nsec + i64(pto_duration)}
		pto_timer := make_pto_timer(pto_next_tick, alloc)

		old_timer, ok := sync.atomic_compare_exchange_strong(
			&conn.paths[path].timeout.timers[packet_number_space],
			timer,
			pto_timer,
		)
		if old_timer != nil {
			free(old_timer, alloc) // swapping in a new timer everytime may not be great
		} // FIXME: Figure out if this is as safe as I thought
	}
}

/*
  reset_pto_backoff

  Resets the Probe Timeout backoff factor and the idle duration

  This is only reset when receiving an acknowledgement from the peer.
  It does not reset for the Initial packet number space, because the client
  does not know whether the server considers its address valid.
*/
@(private = "file")
reset_pto_backoff :: proc(
	conn: ^Conn,
	path: net.Endpoint,
	packet_number_space: Packet_Number_Space,
) {
	if packet_number_space != .Initial && conn.role != .Client {
		sync.atomic_exchange(&conn.paths[path].timeout.pto_backoff, 0)
	}
	sync.atomic_exchange(&conn.paths[path].timeout.idle_duration, 0)
}
