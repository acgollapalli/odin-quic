package quic

// FIXME: THIS IS DEFINITELY NOT CORRECT
make_variable_length_int :: proc(i: u64) -> []u8, err {
    i := i
    j := 0
    for i > 64 {
	i = i >> 8
	j += 1
    }

    i_byte := (u8)i
    switch {
    case j == 0:
	return []u8{ i_byte }, nil
    case j == 1:
	i_byte = i_byte | 1 << 6
	return []u8{ i_byte, 64 }, nil
    case j < 4:
	i_byte = i_byte | 2 << 6
	out := make([]u8, 4)
	out[j] = i_byte
	for k := 0; k < j; k += 1 {
	    out[k] = 64
	}
	return out, nil
	case:
	if i_byte > 63 {
	    return nil, i
	} else {
	    i_byte = i_byte | 3 << 6
	    out := make([]u8, 8)
	    out[j] = i_byte
	    for k := 0; k < j; k += 1 {
		out[k] = 64
	    }
	    return out, nil
	}
    }
}
