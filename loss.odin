/*

SDG                                                                           JJ

                               Loss Recovery

  + Long Header packets that contain Crypto Frames must be acknowledged quickly
  + Packets that contain anything besides Ack of Connection Close count for 
    bytes in flight
  + Packets that do not newly acknowledge the largest acknowledged packet
    [largest packet number] and also acknowledge at least one ack-elicting
    packet are not used to update the RTT Estimates
  + Packets are marked as acked exactly once, and removed from the ack state
    object when they are acked.

 */

// NOTE to future me: Ensuring RTT estimates retain sufficient history is,
// per RFC9002, an open research question. That means I (meaning YOU, future
// me) should research it.
// FIXME: Research the topic, find and prove a solution, and remove the above.

package quic

import "core:net"
import "core:sync"
import "core:time"

/*
    kPacketThreshold:  Maximum reordering in packets before packet
      threshold loss detection considers a packet lost.  The value
      recommended in RFC9002 Section 6.1.1 is 3.
*/
K_PACKET_THRESHOLD :: #config(K_PACKET_THRESHOLD, 3)

/*
   kTimeThreshold:  Maximum reordering in time before time threshold
      loss detection considers a packet lost.  Specified as an RTT
      multiplier.  The value recommended in RFC9002 Section 6.1.2 is 9/8.
*/
K_TIME_THRESHOLD :: 9.0 / 8.0

/*
   kGranularity:  Timer granularity.  This is a system-dependent value,
      and RFC9002 Section 6.1.2 recommends a value of 1 ms.
*/
K_GRANULARITY :: #config(K_GRANULARITY, 1_000_000)

// NOTE: We are NOT ACTUALLY expecting THREE HUNDRED AND THIRTY THREE
// *MILLISECONDS*. Anything above 15 is bad, and above 30 utterly
// unacceptable. But we'll follow the defaults for now.
/*
   kGranularity:  Timer granularity.  This is a system-dependent value,
      and RFC9000 Section 6.1.2 recommends a value of 1 ms.
*/
K_INITIAL_RTT :: #config(K_INITIAL_RTT, 333) * K_GRANULARITY

/*
   Round Trip Time State Tracking
   
   min is the sender's estimate of the minimum RTT observed for a
   given network path over a period of time.  In this document, min_rtt
   is used by loss detection to reject implausibly small RTT samples.
     + MUST be set to the latest_rtt on the first RTT sample.
     + MUST be set to the lesser of min_rtt and latest_rtt
     + SHOULD set the min_rtt to the newest RTT sample after
       persistent congestion is established.
     + MAY reestablish the min_rtt at other times in the
       connection, such as when traffic volume is low and an 
       acknowledgment is received with a low acknowledgment delay.
     + SHOULD NOT refresh the min_rtt value too often 
       since the actual minimum RTT of the path is not frequently observable.

   smoothed is an exponentially weighted moving average of an
   endpoint's RTT samples, and rttvar estimates the variation in the RTT
   samples using a mean variation.
   The calculation of smoothed_rtt uses RTT samples after adjusting them
   for acknowledgment delays.  These delays are decoded from the ACK
   Delay field of ACK frames
     + MAY ignore the acknowledgment delay for Initial packets, since
       these acknowledgments are not delayed by the peer
     + SHOULD ignore the peer's max_ack_delay until the handshake is  
	   confirmed;
     + MUST use the lesser of the acknowledgment delay and the peer's
	   max_ack_delay after the handshake is confirmed 
     + MUST NOT subtract the acknowledgment delay from the RTT sample if
       the resulting value is smaller than the min_rtt.  This limits the
       underestimation of the smoothed_rtt due to a misreporting peer
     + MAY ignore RTT samples if adjusting the RTT sample for acknowledgment
       delay causes the sample to be less than the min_rtt
    When a packet is received it is timestamped immediately, even though
    the Ack's may not be processed until after decryption. This is to avoid
    including local delays in RTT estimates. 

    All values are stored as Durations. Durations are essentially semantic
    representations of 64 bit integers. Meaning we are able to retain some
    semantic quality of time, and associated parsing for logs without losing
    performance.

*/
RTT_State :: struct {
	min:                  time.Duration,
	smoothed:             time.Duration,
	var:                  time.Duration,
	loss_detection_timer: time.Duration, // maybe
	lock:                 sync.Mutex,
}

/*
   Pending_Ack stores the state of previously packed frames.

   The full, 64 bit packet number is stored, along with an array of the frames 
   packed into the packet, sans any padding frames, along with whether the packet
   was ack_eliciting, whether it counted towards bytes in flight, how many bytes
   were sent, and the time that the packet was sent.

   The time is stored as a tick, because it conveniently provides a means to obtain
   duration quickly, diff it monotonically, and exposes its nanosecond value easily.
*/
Pending_Ack :: struct {
	packet_number: u64,
	frames:        []Frame,
	ack_eliciting: bool,
	in_flight:     bool,
	sent_bytes:    int,
	time_sent:     time.Tick,
}

// OPTIMIZE: partition read and write threads via conn_id % thread_count
// for both read and write threads and then remove the lock.
// This object is mutated at least twice for EVERY SINGLE PACKET
// Even assuming peer consolidates acks, the lock is stil acquired
// more than once for datagram sent. This is one of those structs
// that would really benefit from being lock-free.
/*
  Pending_Acks

  Map of packet_numbers to Pending_Acks.

  Has a lock so that multiple threads don't try to delete or
  write to it at the same time.
*/
Pending_Acks :: struct {
	acks: map[u64]^Pending_Ack,
	lock: sync.Mutex,
}

/*
  Initialize Round-Trip Time (RTT) state for loss detection and congestion
  control.

  Because RTT and ECC State may be shared after connection migration, if 
  the adddress of the peer stays the same, with only a change in port, rtt
  is returned as a pointer. As such, it must be freed upon connection close.
*/
init_rtt :: proc(allocator := context.allocator) -> ^RTT_State {
	rtt := new(RTT_State, allocator)

	rtt.smoothed = K_INITIAL_RTT
	rtt.var = rtt.smoothed / 2

	return rtt
}

/*
  update_rtt

  Updates Round-Trip Time (RTT) state for loss detection and congestion control

  This function acquires a read-lock (shared-lock) on the connection object
  and a mutex on the actual RTT state object. 

  It updates the min RTT to the minimum of the latest RTT and the stored min RTT
  It also updates the smoothed RTT and the RTT variance 
*/
update_rtt :: proc(
	conn: ^Conn,
	path: net.Endpoint,
	latest_rtt: time.Duration,
	#any_int encoded_ack_delay: int,
) -> (
	ok: bool,
) {
	// OPTIMIZE: If we queue these up st. we can move to the next
	// one and come back to it, then we can use try_rw_mutex_shared_lock
	// and avoid blocking here.
	sync.shared_guard(&conn.lock)

	max_ack_delay := conn.peer_params.max_ack_delay


	if path_state, path_ok := conn.paths[path]; path_ok {
		if rtt := path_state.rtt; rtt != nil {
			sync.guard(&rtt.lock)

			rtt.min = min(rtt.min, latest_rtt)

			adjusted_rtt: time.Duration
			ack_delay := decode_ack_delay(conn, encoded_ack_delay)

			if conn.state == .Secured {
				ack_delay = time.Duration(min(ack_delay, max_ack_delay))
				adjusted_rtt = latest_rtt
			}

			if (latest_rtt >= rtt.min + ack_delay) {
				adjusted_rtt -= ack_delay
			}
			rtt.smoothed = time.Duration(
				0.875 * f64(rtt.smoothed) + 0.125 * f64(adjusted_rtt),
			)

			rtt_var_sample := abs(rtt.smoothed - adjusted_rtt)
			rtt.var = time.Duration(0.75 * f64(rtt.var) + 0.25 * f64(rtt_var_sample))

			return true
		}
	}
	return false // if path state or rtt state is not initialized
}

/*
  decode ack_delay from Ack_Frame

  Acknowledgement Delay is the recorded time from the sender-side between
  receiving a packet, and sending the acknowledgement.

  It is sent as a variable-length integer, which is to be multiplied by the
  2^ack_delay_exponent to return a value in microseconds. ack_delay_exponent 
  is set in the connection parameters negotiated during the handshake. 

  Until the connection is at least past the initial phase, and until connection
  params are actually available, this function should not be called. This is
  because large ack_delays may be ignored prior to handshake confirmation and 
  ack_delays may be ignored on initial packets
*/
decode_ack_delay :: proc(
	conn: ^Conn,
	#any_int ack_delay: int,
) -> time.Duration {
	ack_delay_us := ack_delay * (2 << conn.peer_params.ack_delay_exponent)
	return time.Duration(ack_delay_us * 1000)
}

/*
  encode_ack_delay 

  Acknowledgement Delay is the recorded time from the sender-side between
  receiving a packet, and sending the acknowledgement.

  It is sent as a variable-length integer, which is to be multiplied by the
  2^ack_delay_exponent to return a value in microseconds. ack_delay_exponent 
  is set in the connection parameters negotiated during the handshake. 
*/
encode_ack_delay :: proc(conn: ^Conn, delay: time.Duration) -> u32 {
	delay_us := int(delay) / 1000
	delay_exp := conn.host_params.ack_delay_exponent
	return u32(delay_us / (2 << delay_exp))
}
