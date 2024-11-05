package quic

make_variable_length_int :: proc(i: u64) -> ([]u8, bool){
    out_a := make([]u8, 8)

    //n : u64
    for k : u8 = 0; k < 8; k += 1{
	out_a[7-k] = (u8)(i >> (8 * k))
    }

    switch {
    case i < 64:
	return out_a[7:], true
    case i < 16384:
	out_a[6] = out_a[6] | (1 << 6)
	return out_a[6:], true
    case i < 1073741824:
	out_a[4] = out_a[4] | (2 << 6)
	return out_a[4:], true
    case i < 4611686018427387904:
	out_a[0] = out_a[0] | (3 << 6)
	return out_a[:], true
    case:
	return nil, false
    }
}
