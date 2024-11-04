package quic

import "core:crypto/aes"
import "core:crypto/chacha"
import "core:crypto/hkdf"
import "ssl"

// constants
Initial_v1_Salt :: 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a

// Encryption Algorithms
Packet_Protection_Algorithm :: enum {
    AEAD_AES_128_GCM,
    AEAD_AES_128_CCM,
    AEAD_AES_256_GCM,
    AEAD_CHACHA20_POLY1305,
}

get_packet_protection_algorithm :: proc(ssl: ssl.SSL_Connection) -> Packet_Protection_Algorithm {
    // FIXME implement this
}

TLS_Secret :: struct {
    secret: []byte,
    key: []byte,
    iv: []byte,
    hp: []byte,
    ku: []byte,
    valid: bool
}

Initial_Secret :: struct {
    secret: []byte,
    client_secret: []byte,
    server_secret: []byte,
    client_hp: []byte,
    server_hp: []byte,
    valid: bool
}

Encryption_Level_Secrets :: union {
    Initial_Secret,
    TLS_Secret,
}
    

/*
 *  ssl_encryption_level_t comes from "ssl"
 *
 *  This context has an Encryption_Level_Secrets object
 *  for each level
 */
Encryption_Context :: struct {
    secrets: [ssl_encryption_level_t]Encryption_Level_Secrets,
    ssl: ssl.SSL_Connection,
    lock: sync.Mutex,
}
    


    


// derive key for initial packets and retry packets



// header protection

/*
 * Gets a 16 byte sample of the payload from a
 * protected packet. Returns a mask to decrypt
 * header protection
 * Takes a specific algorithm for encryption
 */
get_header_mask :: proc{
    get_header_mask_proper,
    get_header_mask_w_ssl,
}

get_header_mask_proper :: proc(hp_key, sample: []u8, algo: Packet_Protection_Algorithm) -> []byte {
    switch algo {
    case .AEAD_AES_128_GCM:
	return aes_ecb(hp_key, sample)
    case .AEAD_AES_128_CCM:
	return aes_ecb(hp_key, sample)
    case .AEAD_AES_256_GCM:
	return aes_ecb(hp_key, sample)
    case .AEAD_CHACHA20_POLY1305:
	return chacha_header_mask(hp_key, sample)
    }
}

get_header_mask_w_ssl :: proc(hp_key, sample: []u8, ssl: ssl.SSL_Connection) -> []byte {
    algo := get_packet_protection_algorithm(ssl)
    return get_header_mask_proper(hp_key, sample, algo)
}

/* 
 * This SHOULD chose 128 or 256 aes_ecb based on key size
 */ 

aes_ecb_header_mask :: proc(hp_key: []byte, sample: []byte) -> []byte {
    ctx := aes.Context_ECB
    defer(reset_ecb(ctx))
    aes.init_ecb(&ctx, hp_key)
    dst : make([]byte, 5) // FIXME: maybe a temp allocator here?
    aes.decrypt_ecb(&ctx, dst, sample)
    return dst
}

chacha_header_mask :: proc(hp_key: []byte, sample: []byte) -> []byte {
    ctx := chacha.Context
    defer(reset(ctx))
    chacha.init(ctx, hp_key, sample[:4], sample[4:])
    dst : make([]byte, 5) // FIXME: maybe a temp allocator here?
    chacha.keystream_bytes(ctx, dst)
    return dst
}

// FIXME: Do we need a decryption error here?
remove_header_protection :: proc(first_byte: byte, packet: []byte, mask: []byte) -> (byte, u32, []byte) {
    first_byte := first_byte
    packet := packet

    // remove the proection on the first byte
    if (first_byte & 0x80) == 0x80 {
	// long header
	first_byte = first_byte ~ (mask[0] & 0x0f)
    } else {
	// short header
	first_byte = first_byte ~ (mask[0] & 0x1f)
    }

    packet_number_length := first_byte & 0x03 // will index off this?

    packet_number_bytes := packet[:packet_number_length]
    packet = packet[packet_number_length:]

    // remove the protection on the packet number
    packet_number_bytes = packet_number_bytes ~ mask[1 : packet_number_length + 1]

    packet_number : u32
    
    for b in packet_number_bytes {
	packet_number = b + (packet_number << 8)
    }

    return first_byte, packet_number, packet
}


add_header_protection :: proc(first_byte: byte, packet_number_bytes: []byte, mask: []byte) -> (byte, []byte) {
    first_byte := first_byte
    packet_number_bytes := packet_number_bytes

    // add the protection on the first byte
    if (first_byte & 0x80) == 0x80 {
	// long header
	first_byte = first_byte ~ (mask[0] & 0x0f)
    } else {
	// short header
	first_byte = first_byte ~ (mask[0] & 0x1f)
    }

    packet_number_length := first_byte & 0x03 // will index off this?

    packet_number_bytes := packet[:packet_number_length]
    packet = packet[packet_number_length:]

    // add the protection on the packet number
    packet_number_bytes = packet_number_bytes ~ mask[1 : packet_number_length + 1]

    return first_byte, packet_number_bytes
}

determine_initial_secret :: proc(salt := Initial_v1_Salt, dest_conn_id: []byte) -> Initial_Secret {
    // can you allocate multiple values at once this way?
    initial_secret, client, server, client_hp, server_hp := make([]byte) // FIXME: figure out alloc strat

    hkdf.extract(salt, dest_conn_id, initial_secret)

    hkdf.expand(initial_secret, "client in", client)
    hkdf.expand(initial_secret, "server in", server)
    hkdf.expand(client, "quic hp", client_hp)
    hkdf.expand(server, "quic hp", server_hp)

    #assert(initial_secret^ != client_hp^)

    return Initial_Secret{
	initial_Secret,
	client,
	server,
	client_hp,
	server_hp,
	true
    }
}
