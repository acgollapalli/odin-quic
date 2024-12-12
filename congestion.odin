/*

SDG                                                                            JJ

                  Electronic Congestion Control

  Electronic Congestion Control dictates how a QUIC endpoint handles congestion.
  It allows for a back off in sending rate whenever the network is congested,
  and prevents a sender from overloading the network.
    
  Currently, only New Reno server-side congestion control is implemented.

*/


package quic

import "core:net"
import "core:sync"
import "core:time"

K_PERSISTENT_CONGESTION_THRESHOLD :: 3

K_NEW_RENO_PACER_NUM, K_NEW_RENO_PACER_DENOM :: 5, 4

ECC_State :: union {
	New_Reno_State,
}

ECC_Algorithm :: enum {
	New_Reno,
	//Cubic, // NOT YET IMPLEMENTED
}


/*
  New_Reno_State

  In the New Reno Congestion control algorithm the congestion window is tracked in 
  bytes.

  The Congestion Control Window adapts to changing network conditions, shrinking the
  amount of data allowed in-flight at any point. 

  The Congestion Control Window must not fall below the min_window
*/
New_Reno_State :: struct {
	state:           New_Reno_CC_State,
	min_window:      u64,
	recovery_start:  i64, // time.Tick
	threshold:       u64,
	window:          u64,
	bytes_in_flight: u64,
	last_send:       i64, //time.Tick,
}

New_Reno_CC_State :: enum {
	Slow_Start,
	Recovery_Period,
	Congestion_Avoidance,
}

/*
  new_reno_calc_min_window

  Calculates the minimum congestion window for the New Reno Congestion
  Control Algorithm. 

  This is calculated every time the congestion window changes
*/
new_reno_calc_min_window :: proc(max_dg_size: u64) -> u64 {
	return max(14_720, 2 * max_dg_size)
}

/*
  new_reno_handle_ack

  Event handler for an incoming ack frame for the New Reno
  Congestion Control Algorithm. 

  Updates the Congestion Window. May update the state.
  
*/
new_reno_update_state :: proc(
	conn: ^Conn,
	ecc: ^New_Reno_State,
	ack: ^Pending_Ack,
) {
	switch ecc.state {
	case .Slow_Start:
		new_reno_handle_start(conn, ecc, ack)
	case .Recovery_Period:
		new_reno_handle_recovery(conn, ecc, ack)
	case .Congestion_Avoidance:
		new_reno_handle_congestion(conn, ecc, ack)
	}
}

/*
  Handles receiving an ack frame in the Slow Start state.

  All connections start off in Slow Start state.

  While a sender is in slow start, the congestion window increases 
  by the number of bytes acknowledged.
*/
new_reno_handle_start :: proc(
	_: ^Conn,
	ecc: ^New_Reno_State,
	ack: ^Pending_Ack,
) {
	if ack.in_flight {
		sync.atomic_add(&ecc.window, ack.sent_bytes)
	}
}

/*
  Handles receiving an ack frame in the Handle Recovery state.

  A NewReno sender enters a recovery period when it detects the loss o
  a packet or when the ECN-CE count reported by its peer increases.  

  The recovery period aims to limit congestion window reduction to once
  per round trip.  Therefore, during a recovery period, the congestion
  window does not change in response to new losses or increases in the
  ECN-CE count.

  A recovery period ends and the sender enters congestion avoidance
  when a packet sent during the recovery period is acknowledged.  
*/
new_reno_handle_recovery :: proc(
	_: ^Conn,
	ecc: ^New_Reno_State,
	ack: ^Pending_Ack,
) {
	recovery_start := sync.atomic_load(&ecc.recovery_start)

	if (ack.time_sent._nsec > recovery_start) {
		sync.atomic_exchange(&ecc.state, .Congestion_Avoidance)
	}
}

/*
  A NewReno sender is in congestion avoidance any time the congestion
  window is at or above the slow start threshold and not in a recovery
  period.

  A sender in congestion avoidance uses an Additive Increase
  Multiplicative Decrease (AIMD) approach that MUST limit the increase
  to the congestion window to at most one maximum datagram size for
  each congestion window that is acknowledged.

  The sender exits congestion avoidance and enters a recovery period
  when a packet is lost or when the ECN-CE count reported by its peer
  increases.

  A sender reenters slow start any time the congestion window is less
  than the slow start threshold, which only occurs after persistent
  congestion is declared.

*/
new_reno_handle_congestion :: proc(
	conn: ^Conn,
	ecc: ^New_Reno_State,
	ack: ^Pending_Ack,
) {
	window := sync.atomic_load(&ecc.window)

	max_dg_size: u64
	{
		sync.shared_guard(&conn.lock) // possibly unnecessary
		max_dg_size := min(
			conn.peer_params.max_datagram_frame_size,
			conn.host_params.max_datagram_frame_size,
		)
	}

	new_window := max_dg_size * ack.sent_bytes / window

	if old_window, ok := sync.atomic_compare_exchange_strong(
		&ecc.window,
		window,
		new_window,
	); ok {
		// do something
	} else {
		// maybe try again?
	}

	threshold := sync.atomic_load(&ecc.threshold)

	if new_window <= threshold {
		sync.atomic_exchange(&ecc.state, .Slow_Start)
	}
}

/*
  new_reno_on_packet_loss

  Handles the change to congestion window based on the state of acks.

  If there is a contiguous window of lost packets across all packet number
  number spaces st. the time period is greater than the persistent
  congestion threshold, then this procedure declares persistent congestion,
  otherwise it enters the recovery period.
*/
new_reno_on_packet_loss :: proc(ecc: ^New_Reno_State, ack_state: ^Ack_State) {
	#assert(false, "not implemented")
}

/*
  Enter the recovery period for the New Reno Congestion Controller.
  Sets the slow start threshold and the congestion window to the 

  On entering a recovery period, a sender MUST set the slow start
  threshold to half the value of the congestion window when loss is
  detected (or the minimum congestion window)
*/
new_reno_enter_recovery :: proc(ecc: ^New_Reno_State) {
	min_window := sync.atomic_load(&ecc.min_window)
	window := max(sync.atomic_load(&ecc.window) / 2, min_window)
	sync.atomic_store(&ecc.threshold, window)
	sync.atomic_store(&ecc.window, window)
}

/*
  handle_persistent_congestion

   A sender establishes persistent congestion after the receipt of an
   acknowledgment if two packets that are ack-eliciting are declared
   lost, and:

   *  across all packet number spaces, none of the packets sent between
      the send times of these two packets are acknowledged;

   *  the duration between the send times of these two packets exceeds
      the persistent congestion duration (Section 7.6.1); and

   *  a prior RTT sample existed when these two packets were sent.

   When persistent congestion is declared, the sender's congestion
   window MUST be reduced to the minimum congestion window
   (kMinimumWindow)
*/
handle_persistent_congestion :: proc(ecc: ^New_Reno_State) {
	min_window := sync.atomic_load(&ecc.min_window)
	sync.atomic_store(&ecc.threshold, min_window)
	sync.atomic_store(&ecc.window, min_window)
}

// TODO: See if this approach to sending is fast enough
//  We are assuming our send loop can iterate over every single connection object
//  to read, packetize, and send all objects in the realtime queue at 144hz. This
//  may be partitioned for threading as appropriate.
//
//  It may be better to not have a queue at all, and to simply provide a function
//  and callback for the application to send realtime data instead of queueing it.

/*
  For our purposes, which is supporting realtime games, the pacer only
  applies to data which is put in the send queue. The pacer is called by the
  the send loop, which expects the number of bytes it is allowed to send and
  a boolean for whether it is allowed to send on this tick of the send loop.

  Realtime data, which includes realtime game state sent in Datagram frames,
  and Probe packets must be sent immediately. They are placed in the realtime
  send_queue on the conn object. As such, they are (at this point) not subject
  to this pacer, though they stil count toward bytes in flight. The reader of the
  realtime queue DOES NOT call this function.
*/
new_reno_pacer :: proc(
	ecc: ^New_Reno_State,
	rtt: ^RTT_State,
	max_dg_size: u64,
) -> (
	u64,
	bool,
) {
	rtt_smoothed: time.Duration
	{
		sync.guard(&rtt.lock)
		rtt_smoothed = rtt.smoothed
	}
	last_send := time.Tick {
		_nsec = sync.atomic_load(&ecc.last_send),
	}
	window := sync.atomic_load(&ecc.window)
	bytes_in_flight := sync.atomic_load(&ecc.bytes_in_flight)
	num_bytes: u64 =
		u64(time.tick_diff(last_send, time.tick_now())) *
		K_NEW_RENO_PACER_NUM *
		window /
		u64(rtt_smoothed * K_NEW_RENO_PACER_DENOM)
	num_bytes = min(num_bytes, max_dg_size)
	num_bytes = min(num_bytes, window - bytes_in_flight)
	ok := num_bytes > 0

	defer if ok do sync.atomic_store(&ecc.last_send, time.tick_now()._nsec)

	return num_bytes, ok
}
