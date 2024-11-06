package quic

// Open a connection
open :: proc(conn: struct {}, early_data: bool)

// listen to a connection
listen :: proc(conn: struct {})

// handle early data reject or accept
handle_early_data :: proc()

