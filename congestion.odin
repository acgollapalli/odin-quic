/*

SDG                                                                           JJ

                  Electronic Congestion Control

  + Long Header packets that contain Crypto Frames must be acknowledged quicly
  + Packets that contain anything besides Ack of Connection Close count for 
    bytes in flight

  The ECC State lives in the Conn object under the Paths property:
    {
      ..
      paths : Path[map]ECC_State
      ...
    }
  Where the Path is the network path of the peer, and the ECC_State
  is as defined below.

 */


package quic

ECC_State :: struct {}
