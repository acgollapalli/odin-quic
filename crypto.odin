/*
 * SDG                                                                         JJ
 */

package quic

import ssl "../ssl"
import "core:crypto/aes"
import chacha "core:crypto/chacha20"
import chacha_poly1305 "core:crypto/chacha20poly1305"
import "core:crypto/hash"
import "core:crypto/hkdf"
import "core:encoding/hex"
import "core:sync"
import "core:time"

hex_decode_const :: proc(str: string) -> []u8 {
	out, err := hex.decode(raw_data(str)[:len(str)])
	return out
}


// constants
Initial_v1_Salt := hex_decode_const("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

Retry_v1_Key := hex_decode_const("be0c690b9f66575a1d766b54e368c84e")
Retry_v1_Nonce := hex_decode_const("461599d35d632bf2239825bb")

// FIXME: We should have a way to get the hash
// part of the cipher suite as well, or else this will
// bite us in the tail
// Encryption Algorithms
Packet_Protection_Algorithm :: enum {
	AEAD_AES_128_GCM,
	AEAD_AES_256_GCM,
	AEAD_CHACHA20_POLY1305,
}

TLS_Secret :: struct {
	secret: []byte,
	key:    []byte,
	iv:     []byte,
	hp:     []byte,
	ku:     []byte,
	valid:  bool,
	cipher: Packet_Protection_Algorithm,
}

Initial_Secret :: struct {
	secret:        []byte,
	client_secret: []byte,
	server_secret: []byte,
	client_hp:     []byte,
	server_hp:     []byte,
	valid:         bool,
	cipher:        Packet_Protection_Algorithm,
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
	secrets: [ssl.QUIC_Encryption_Level]Encryption_Level_Secrets,
	ssl:     ssl.SSL_Connection,
	lock:    sync.RW_Mutex,
}


get_hp_key :: proc(conn: ^Conn, level: ssl.QUIC_Encryption_Level) -> []byte {
	hp_key: []byte

	// We don't read anything that can change throughout the lifetime of the
	// connection here, so we don't really NEED to get a reader-lock on the
	// conn object
	//sync.shared_guard(&conn.lock)

	// however we DO read mutable state from the encryption context,
	// and need to acquire that lock 
	sync.shared_guard(&conn.encryption.lock)

	secrets := conn.encryption.secrets[level]
	switch s in secrets {
	case Initial_Secret:
		if conn.role == .Client {
			hp_key = s.server_hp
		} else {
			hp_key = s.client_hp
		}
	case TLS_Secret:
		hp_key = s.hp
	}
	return hp_key
}

get_hp_key_and_algo :: proc(
	conn: ^Conn,
	level: ssl.QUIC_Encryption_Level,
) -> (
	[]byte,
	Packet_Protection_Algorithm,
) {
	hp_key: []byte
	sync.shared_guard(&conn.encryption.lock)
	secrets := conn.encryption.secrets[level]
	cipher: Packet_Protection_Algorithm
	switch s in secrets {
	case Initial_Secret:
		if conn.role == .Client {
			hp_key = s.server_hp
		} else {
			hp_key = s.client_hp
		}
		cipher = s.cipher
	case TLS_Secret:
		hp_key = s.hp
		cipher = s.cipher
	}
	return hp_key, cipher
}

get_secret_iv_and_algo :: proc(
	conn: ^Conn,
	level: ssl.QUIC_Encryption_Level,
) -> (
	[]byte,
	[]byte,
	Packet_Protection_Algorithm,
) {
	hp_key: []byte
	sync.shared_guard(&conn.encryption.lock)
	secrets := conn.encryption.secrets[level]
	cipher: Packet_Protection_Algorithm
	switch s in secrets {
	case Initial_Secret:
		secret: []u8
		if conn.role == .Client {
			secret = s.client_secret
		} else {
			secret = s.server_secret
		}
		key := tlsv13_expand_label(secret, "quic key")
		iv := tlsv13_expand_label(secret, "quic iv")
		return key, iv, s.cipher
	case TLS_Secret:
		return s.key, s.iv, s.cipher
	}
	return nil, nil, nil
}

// header protection

/*
 * Gets a 16 byte sample of the payload from a
 * protected packet. Returns a mask to decrypt
 * header protection
 * Takes a specific algorithm for encryption
 */
get_header_mask :: proc {
	get_header_mask_proper,
	get_header_mask_w_ssl,
}

get_header_mask_proper :: proc(
	hp_key, sample: []u8,
	algo: Packet_Protection_Algorithm,
) -> []byte {
	mask: []byte
	switch algo {
	case .AEAD_AES_128_GCM:
		mask = aes_ecb_header_mask(hp_key, sample)
	case .AEAD_AES_256_GCM:
		mask = aes_ecb_header_mask(hp_key, sample)
	case .AEAD_CHACHA20_POLY1305:
		mask = chacha_header_mask(hp_key, sample)
	}
	return mask
}

get_header_mask_w_ssl :: proc(
	sample: []u8,
	conn: ^Conn,
	encryption_level: ssl.QUIC_Encryption_Level,
) -> []byte {
	hp_key, algo := get_hp_key_and_algo(conn, encryption_level)
	return get_header_mask_proper(hp_key, sample, algo)
}

/* 
 * This SHOULD chose 128 or 256 aes_ecb based on key size
 */

aes_ecb_header_mask :: proc(hp_key: []byte, sample: []byte) -> []byte {
	ctx: aes.Context_ECB
	defer (aes.reset_ecb(&ctx))
	aes.init_ecb(&ctx, hp_key)
	dst := make([]byte, 5) // FIXME: maybe a temp allocator here?
	aes.decrypt_ecb(&ctx, dst, sample)
	return dst
}

chacha_header_mask :: proc(hp_key: []byte, sample: []byte) -> []byte {
	ctx: chacha.Context
	defer (chacha.reset(&ctx))
	chacha.init(&ctx, hp_key, sample[4:]) // FIXME: not sure what to do here
	counter: u64
	for b, i in sample[0:4] do counter += u64(b) << 8 * u64(i)
	chacha.seek(&ctx, counter)
	dst := make([]byte, 5) // FIXME: maybe a temp allocator here?
	chacha.keystream_bytes(&ctx, dst)
	return dst
}

// FIXME: Do we need a decryption error here?
remove_header_protection :: proc(
	first_byte: byte,
	packet: []byte,
	mask: []byte,
) -> (
	byte,
	u32,
	[]byte,
) {
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
	packet_number: u32
	for i := 0; i < len(packet_number_bytes); i += 1 {
		unmasked_byte := packet_number_bytes[i] ~ mask[i + 1]
		packet_number = u32(unmasked_byte) + (packet_number << 8)
	}

	return first_byte, packet_number, packet
}


add_header_protection :: proc(
	first_byte: byte,
	packet_number_bytes: []byte,
	mask: []byte,
) -> (
	byte,
	[]byte,
) {
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

	// add the protection on the packet number
	for i := 0; i < len(packet_number_bytes); i += 1 {
		packet_number_bytes[i] = packet_number_bytes[i] ~ mask[i + 1]
	}

	return first_byte, packet_number_bytes
}

// FIXME: Make SURE that we're using an allocator that isn't trying to grab
// each of these individually! BUT we only ever do it on key changes, so it's
// probably not a huge deal
tlsv13_expand_label :: proc(
	key: []u8,
	$label: string,
	algo: hash.Algorithm = hash.Algorithm.SHA256,
) -> []byte {
	out := make([]byte, 256)
	hkdf_label: [len(label) + 9]u8 // these DO NOT have the null terminating byte
	prefix: string = "tlsv13 "

	hkdf_label[1] = u8(len(label))
	for b, i in prefix {
		hkdf_label[i + 2] = u8(b)
	}
	for b, i in label {
		hkdf_label[i + 9] = u8(b)
	}

	hkdf.expand(algo, key, hkdf_label[:], out)
	return out
}

// FIXME: we may want to just have an Encyrption Secrets object passsed in so
// we can reuse the key buffers.
// NOTE: Only call this if you are NOT sending a Retry, or AFTER path-validation
// is completed via the Retry packet
determine_initial_secret :: proc(
	dest_conn_id: []byte,
	salt := Initial_v1_Salt,
) -> Initial_Secret {
	// can you allocate multiple values at once this way?
	initial_secret := make([]u8, 256)
	hkdf.extract(hash.Algorithm.SHA256, salt, dest_conn_id, initial_secret)

	client := tlsv13_expand_label(initial_secret, "client in")
	server := tlsv13_expand_label(initial_secret, "server in")
	client_hp := tlsv13_expand_label(client, "quic hp")
	server_hp := tlsv13_expand_label(server, "quic hp")

	return Initial_Secret {
		initial_secret,
		client,
		server,
		client_hp,
		server_hp,
		true,
		.AEAD_AES_128_GCM,
	}
}


/*
 *  Apply packet proection. see RFC9001.5
 *  returns the encrypted payload and the tag
 */
protect_payload :: proc(
	conn: ^Conn,
	packet: Packet,
	header: []u8,
	payload: []u8,
) -> (
	[]u8,
	[]u8,
) {

	// helper function to get the nonce
	get_nonce :: proc(iv: []u8, packet_number: u32) -> []u8 {
		nonce := make([]u8, len(iv))
		for i: u8 = 0; i < 4; i += 1 {
			nonce[len(iv) - 1 - int(i)] = u8(packet_number >> i * 8) // nonce is padded w/ zeroes 
		}
		for &b, i in nonce {
			b ~= iv[i] // bitwise xor with iv
		}
		return nonce
	}

	// getting the key and iv
	key: []u8
	iv: []u8
	nonce: []u8
	algo: Packet_Protection_Algorithm
	payload: []u8
	#partial switch p in packet {
	case Initial_Packet:
		key, iv, algo := get_secret_iv_and_algo(conn, .Initial_Encryption)
		nonce = get_nonce(iv, p.packet_number)
	case Zero_RTT_Packet:
		key, iv, algo := get_secret_iv_and_algo(conn, .Early_Data_Encryption)
		nonce = get_nonce(iv, p.packet_number)
	case Handshake_Packet:
		key, iv, algo := get_secret_iv_and_algo(conn, .Handshake_Encryption)
		nonce = get_nonce(iv, p.packet_number)
	case One_RTT_Packet:
		key, iv, algo := get_secret_iv_and_algo(conn, .Application_Encryption)
		nonce = get_nonce(iv, p.packet_number)
	case Retry_Packet:
		key = Retry_v1_Key
		nonce = Retry_v1_Nonce
	case:
		return nil, nil
	}

	// FIXME: we should just encrypt in place
	cipher_text := make([]u8, len(payload))
	tag := make([]u8, len(iv))

	// let's encrypt!
	encrypt_payload(key, iv, nonce, header, payload, algo, cipher_text, tag)

	return cipher_text, tag
}

encrypt_payload :: proc(
	key, iv, nonce, associated_data, payload: []u8,
	algo: Packet_Protection_Algorithm,
	cipher_text, tag: []u8,
) {
	switch algo {
	case .AEAD_AES_128_GCM, .AEAD_AES_256_GCM:
		ctx: aes.Context_GCM
		aes.init_gcm(&ctx, key)
		aes.seal_gcm(&ctx, cipher_text, tag, iv, associated_data, payload)
	case .AEAD_CHACHA20_POLY1305:
		ctx: chacha_poly1305.Context
		chacha_poly1305.init(&ctx, key)
		chacha_poly1305.seal(&ctx, cipher_text, tag, iv, associated_data, payload)
	}
}

// TODO 
generate_retry_token :: proc(dest_conn_id: []byte) {}

// TODO
validate_rety_token :: proc(
	dest_conn_id: []byte,
	token: []byte,
) -> bool {return false}

read_crypto_frame_data :: proc(
	conn: ^Conn,
	level: ssl.QUIC_Encryption_Level,
	frame: ^Crypto_Frame, // FIXME: Should we be passing a ptr if we're not modifying
) {
	ssl.provide_quic_data(conn.encryption.ssl, level, frame.crypto_data)
}
