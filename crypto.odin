/*
 * SDG                                                                         JJ
 */

package quic

import "base:runtime"
import "core:crypto/aes"
import chacha "core:crypto/chacha20"
import chacha_poly1305 "core:crypto/chacha20poly1305"
import "core:crypto/hash"
import "core:crypto/hkdf"
import "core:encoding/hex"
import "core:fmt"
import "core:strings"
import "core:sync"
import "core:time"
import "net:ssl"
import libressl "net:ssl/bindings"

hex_decode_const :: proc(str: string) -> []u8 {
	out, ok := hex.decode(raw_data(str)[:len(str)])
	assert(ok, "Error decoding salts!")
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

get_cipher :: proc "c" (
	cipher: ssl.SSL_CIPHER,
) -> Packet_Protection_Algorithm {
	cipher_name := ssl.cipher_name(cipher)
	switch cipher_name {
	case "TLS_AES_128_GCM_SHA256":
		return .AEAD_AES_128_GCM
	case "TLS_AES_256_GCM_SHA384":
		return .AEAD_AES_256_GCM
	case "TLS_CHACHA20_POLY1305_SHA256":
		return .AEAD_CHACHA20_POLY1305
	}
	return nil
}

Key_Len := [Packet_Protection_Algorithm]int {
	.AEAD_AES_128_GCM       = 16,
	.AEAD_AES_256_GCM       = 32,
	.AEAD_CHACHA20_POLY1305 = 32,
}

Hash_Algo := [Packet_Protection_Algorithm]hash.Algorithm {
	.AEAD_AES_128_GCM       = .SHA256,
	.AEAD_AES_256_GCM       = .SHA384,
	.AEAD_CHACHA20_POLY1305 = .SHA256,
}

TLS_Secret :: struct {
	//	secret: []byte,
	key:    []byte,
	iv:     []byte,
	hp:     []byte,
	ku:     []byte,
	valid:  bool, // soft "discarding of keys" ?
	cipher: Packet_Protection_Algorithm,
}

Secret_Role :: enum {
	Read,
	Write,
}

PN_Spaces := [ssl.QUIC_Encryption_Level]Packet_Number_Space {
	.Initial_Encryption     = .Initial,
	.Handshake_Encryption   = .Handshake,
	.Early_Data_Encryption  = .Application,
	.Application_Encryption = .Application,
}


/*
 *  This context has an Encryption_Level_Secrets object
 *  for each level
 */
Encryption_Context :: struct {
	secrets: [ssl.QUIC_Encryption_Level][Secret_Role]TLS_Secret,
	ssl:     ssl.SSL_Connection,
	lock:    sync.RW_Mutex,
}


get_hp_key :: proc(
	conn: ^Conn,
	level: ssl.QUIC_Encryption_Level,
	role: Secret_Role,
) -> []byte {
	hp_key: []byte

	// We don't read anything that can change throughout the lifetime of the
	// connection here, so we don't really NEED to get a reader-lock on the
	// conn object
	//sync.shared_guard(&conn.lock)

	// however we DO read mutable state from the encryption context,
	// and need to acquire that lock 
	sync.shared_guard(&conn.encryption.lock)
	s := conn.encryption.secrets[level][role]
	assert(s.valid, "invalid secret!")
	return s.hp
}

get_hp_key_and_algo :: proc(
	conn: ^Conn,
	level: ssl.QUIC_Encryption_Level,
	role: Secret_Role,
) -> (
	[]byte,
	Packet_Protection_Algorithm,
) {
	sync.shared_guard(&conn.encryption.lock)
	s := conn.encryption.secrets[level][role]
	assert(s.valid, "invalid secret!")
	return s.hp, s.cipher
}

get_secret_iv_and_algo :: proc(
	conn: ^Conn,
	level: ssl.QUIC_Encryption_Level,
	role: Secret_Role,
) -> (
	[]byte,
	[]byte,
	Packet_Protection_Algorithm,
) {
	hp_key: []byte
	sync.shared_guard(&conn.encryption.lock)
	s := conn.encryption.secrets[level][role]
	assert(s.valid, "invalid secret!")
	return s.key, s.iv, s.cipher
}

// header protection


_get_header_mask :: proc(
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

/*
 * Gets a 16 byte sample of the payload from a
 * protected packet. Returns a mask to decrypt
 * header protection
 * Takes a specific algorithm for encryption
 */
get_header_mask:: proc(
	sample: []u8,
	conn: ^Conn,
	encryption_level: ssl.QUIC_Encryption_Level,
	role: Secret_Role,
) -> (
	val: []byte,
	ok: bool,
) {
	has_valid_secret(conn, encryption_level, role) or_return
	hp_key, algo := get_hp_key_and_algo(conn, encryption_level, role)
	return _get_header_mask(hp_key, sample, algo), true
}

has_valid_secret :: proc(
	conn: ^Conn,
	level: ssl.QUIC_Encryption_Level,
	role: Secret_Role,
) -> (
	ok: bool,
) {
	sync.shared_guard(&conn.encryption.lock)
	return conn.encryption.secrets[level][role].valid
}

/* 
 * This SHOULD chose 128 or 256 aes_ecb based on key size
 */

aes_ecb_header_mask :: proc(hp_key: []byte, sample: []byte) -> []byte {
	ctx: aes.Context_ECB
	defer (aes.reset_ecb(&ctx))
	aes.init_ecb(&ctx, hp_key)
	dst := make([]byte, 16) // FIXME: maybe a temp allocator here?
	aes.encrypt_ecb(&ctx, dst, sample) // Simple XOR of the same value that is 
	return dst[0:5]
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
remove_header_protection :: proc {
	remove_header_protection_deprecated,
	remove_header_protection_with_pn_len,
}
// FIXME: remove and make this NOT a procedure groupe
remove_header_protection_deprecated :: proc(
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
		first_byte ~= (mask[0] & 0x0f)
	} else {
		// short header
		first_byte = first_byte ~ (mask[0] & 0x1f)
	}

	packet_number_length := first_byte & 0x03 + 1 // will index off this?

	packet_number_bytes := packet[:packet_number_length]
	packet = packet[packet_number_length:]

	// remove the protection on the packet number
	packet_number: u32
	for i := 0; i < len(packet_number_bytes); i += 1 {
		packet_number_bytes[i] ~= mask[i + 1]
		packet_number = u32(packet_number_bytes[i]) + (packet_number << 8)
	}

	return first_byte, packet_number, packet
}

// FIXME: remove and make this NOT a procedure groupe
remove_header_protection_with_pn_len :: proc(
	first_byte: byte,
	packet: []byte,
	mask: []byte,
	_: bool
) -> (
	byte,
	u32,
	int,
	[]byte,
) {
	first_byte := first_byte
	packet := packet

	// remove the proection on the first byte
	if (first_byte & 0x80) == 0x80 {
		// long header
		first_byte ~= (mask[0] & 0x0f)
	} else {
		// short header
		first_byte = first_byte ~ (mask[0] & 0x1f)
	}

	packet_number_length := first_byte & 0x03 + 1 // will index off this?

	packet_number_bytes := packet[:packet_number_length]
	packet = packet[packet_number_length:]

	// remove the protection on the packet number
	packet_number: u32
	for i := 0; i < len(packet_number_bytes); i += 1 {
		packet_number_bytes[i] ~= mask[i + 1]
		packet_number = u32(packet_number_bytes[i]) + (packet_number << 8)
	}

	return first_byte, packet_number, int(packet_number_length), packet
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
/*
  tlsv13_expand_label

  As defined in RFC 8446
       HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)

       Where HkdfLabel is specified as:

       struct {
           uint16 length = Length;
           opaque label<7..255> = "tls13 " + Label;
           opaque context<0..255> = Context;
       } HkdfLabel;

Some notes. 
  The Length param corresponds to the length of the output (k_len).
  The label value in the label struct BEGINS with a 1 byte length parameter,
   containing the length of the string.
  The context is always zero.
  The struct itself is null terminated.
*/
tlsv13_expand_label :: proc(
	key: []u8,
	$label: string,
	algo: hash.Algorithm = hash.Algorithm.SHA256,
	k_len: int,
) -> []byte {
	out := make([]byte, k_len) // FIXME: Should provide this as a param
	prefix :: "tls13 "

	// building the HkdfLabel struct as a byte array

	/*
	 First we need to know how long the array should be.
	 What do each of these numbers represent?
	 
	 2 : uint16 Length param
	 1 : uint8 size of label
	 len(prefix): length of the prefix above. Every hkdf
	   expansion in tls1.3 starts with this prefix)
	 len(label) : length of the string we actually
	   use in the HKDF-Expand function
	 1: null char at the end of the HkdfLabel
    */
	label_length :: 2 + 1 + len(prefix) + len(label) + 1
	hkdf_label: [label_length]u8

	// let's generate the HkdfLabel
	hkdf_label[0] = u8(u16(k_len) >> 8)
	hkdf_label[1] = u8(k_len)
	hkdf_label[2] = u8(len(prefix) + len(label))
	for b, i in prefix {
		hkdf_label[i + 2 + 1] = u8(b)
	}
	for b, i in label {
		hkdf_label[i + len(prefix) + 3] = u8(b)
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
	role := Role.Server,
	salt := Initial_v1_Salt,
) -> [Secret_Role]TLS_Secret {
	// can you allocate multiple values at once this way?
	initial_secret: [32]u8
	hkdf.extract(hash.Algorithm.SHA256, salt, dest_conn_id, initial_secret[:])

	client := tlsv13_expand_label(initial_secret[:], "client in", .SHA256, 32)
	defer delete(client)
	client_key := tlsv13_expand_label(client, "quic key", .SHA256, 16)
	client_iv := tlsv13_expand_label(client, "quic iv", .SHA256, 12)
	client_hp := tlsv13_expand_label(client, "quic hp", .SHA256, 16)

	server := tlsv13_expand_label(initial_secret[:], "server in", .SHA256, 32)
	defer delete(server)
	server_key := tlsv13_expand_label(server, "quic key", .SHA256, 16)
	server_iv := tlsv13_expand_label(server, "quic iv", .SHA256, 12)
	server_hp := tlsv13_expand_label(server, "quic hp", .SHA256, 16)

	secret: [Secret_Role]TLS_Secret

	// only connections in the server role ever call this function
	// so we know that .Read is the client secret
	client_st := TLS_Secret{
		key = client_key,
		hp = client_hp,
		iv = client_iv,
		valid = true, // maybe need to deprecate
		cipher = .AEAD_AES_128_GCM // always this for initial
	}

	server_st := TLS_Secret{
		key = server_key,
		hp = server_hp,
		iv = server_iv,
		valid = true, // maybe need to deprecate
		cipher = .AEAD_AES_128_GCM, // always this for initial
	}

	switch role {
	case .Server:
		secret[.Read] = client_st
		secret[.Write] = server_st
	case .Client:
		secret[.Read] = server_st
		secret[.Write] = client_st
	}

	return secret
}

destroy_secret :: proc(secret: ^TLS_Secret) {
	d_if := proc(s: []byte) {
		if s != nil {
			delete(s)
		}
	}

	d_if(secret.key)
	d_if(secret.hp)
	d_if(secret.iv)
	d_if(secret.ku)
	secret.valid = false
}

destroy_encryption :: proc(conn: ^Conn) {
	// delete all keys
	// delete ssl connection
	sync.guard(&conn.encryption.lock)
	for &p in conn.encryption.secrets {
		for &s in p {
			destroy_secret(&s)
		}
	}
	ssl.free_conn(conn.encryption.ssl)
	conn.encryption.ssl = nil
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
	tag: []u8,
) {

	// helper function to get the nonce
	get_nonce :: proc(iv: []u8, packet_number: u64) -> []u8 {
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
	#partial switch p in packet {
	case Initial_Packet:
		key, iv, algo = get_secret_iv_and_algo(conn, .Initial_Encryption, .Write)
		nonce = get_nonce(iv, p.packet_number)
	case Zero_RTT_Packet:
		key, iv, algo = get_secret_iv_and_algo(
			conn,
			.Early_Data_Encryption,
			.Write,
		)
		nonce = get_nonce(iv, p.packet_number)
	case Handshake_Packet:
		key, iv, algo = get_secret_iv_and_algo(
			conn,
			.Handshake_Encryption,
			.Write,
		)
		nonce = get_nonce(iv, p.packet_number)
	case One_RTT_Packet:
		key, iv, algo = get_secret_iv_and_algo(
			conn,
			.Application_Encryption,
			.Write,
		)
		nonce = get_nonce(iv, p.packet_number)
	case Retry_Packet:
		key = Retry_v1_Key
		nonce = Retry_v1_Nonce
	}

	// let's encrypt!
	encrypt_payload(key, iv, nonce, header, payload, algo, payload, tag)
}

encrypt_payload :: proc(
	key, iv, nonce, associated_data, payload: []u8,
	algo: Packet_Protection_Algorithm,
	cipher_text, tag: []u8,
) {
	// TODO: XOR IV and NONCE HERE

	switch algo {
	case .AEAD_AES_128_GCM, .AEAD_AES_256_GCM:
		ctx: aes.Context_GCM
		aes.init_gcm(&ctx, key)
		aes.seal_gcm(&ctx, cipher_text, tag, nonce, associated_data, payload)
	case .AEAD_CHACHA20_POLY1305:
		ctx: chacha_poly1305.Context
		chacha_poly1305.init(&ctx, key)
		chacha_poly1305.seal(&ctx, cipher_text, tag, nonce, associated_data, payload)
	}
}

decrypt_payload :: proc {
	decrypt_payload_with_conn,
	decrypt_payload_with_secrets,
}

decrypt_payload_with_conn :: proc() {
	assert(false, "not implemented")
}

// helper function to get the nonce
get_nonce :: proc(iv: []u8, packet_number: u64, out: []u8) {
	for i: u8 = 0; i < 8; i += 1 {
		// nonce is padded w/ zeroes 
		out[len(iv) - 1 - int(i)] = u8(packet_number >> i * 8) 
	}
	for &b, i in out {
		b ~= iv[i] // bitwise xor with iv
	}
	return
}

decrypt_payload_with_secrets :: proc(
	payload: []u8,
	header: []u8,
	packet_number: u64,
	secrets: [Secret_Role]TLS_Secret,
) -> (
	ok: bool,
) {
	s := secrets[.Read]
	nonce := make([]u8, len(s.iv)) // FIXME: Maybe use temp allocator here
	defer delete(nonce)

	get_nonce(s.iv, packet_number, nonce)

	switch s.cipher {
	case .AEAD_AES_128_GCM, .AEAD_AES_256_GCM:
		dst := payload[:len(payload) - 16]
		tag := payload[len(payload) - 16:]

		ctx: aes.Context_GCM
		aes.init_gcm(&ctx, s.key)
		ok = aes.open_gcm(&ctx, dst, nonce, header, dst, tag)
	case .AEAD_CHACHA20_POLY1305:
		dst := payload[:len(payload) - 16]
		tag := payload[len(payload) - 16:]

		ctx: chacha_poly1305.Context
		chacha_poly1305.init(&ctx, s.key)
		ok = chacha_poly1305.open(&ctx, dst, nonce, header, dst, tag)
	}
	return
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

/* Quic method struct for ssl */
add_handshake_data :: proc "c" (
	ssl_conn: ssl.SSL_Connection,
	level: libressl.ssl_encryption_level_t,
	data: [^]byte,
	dlen: uint,
) -> i32 {
	context = runtime.default_context()
	conn, _ := find_conn(ssl_conn) // TODO: make SSL init fn w/ a ptr to conn
	l := transmute(ssl.QUIC_Encryption_Level)level

	q := conn.send[PN_Spaces[l]]
	sync.guard(&q.lock)

	for i := 0; i < int(dlen); i += 1 do q.crypto[q.crypto_len + uint(i)] = data[i]
	q.crypto_len += dlen
	return 1
}

flush_flight :: proc "c" (ssl_conn: ssl.SSL_Connection) -> i32 {
	context = runtime.default_context()
	conn, conn_ok := find_conn(ssl_conn) // TODO: make SSL init fn w/ a ptr to conn
	assert(conn_ok, "was not able to find conn in flush flight")
	pns := conn.send
	for &q in pns {
		sync.guard(&q.lock)
		q.crypto_flush = true // TODO: consider refactoring Send_State
	}
	return 1
}

send_alert :: proc "c" (
	ssl_conn: ssl.SSL_Connection,
	level: libressl.ssl_encryption_level_t,
	alert: u8,
) -> i32 {
	context = runtime.default_context()
	conn, conn_ok := find_conn(ssl_conn) // TODO: make SSL init fn w/ a ptr to conn
	assert(conn_ok, "send alert failed to find conn")
	context = runtime.default_context()
	close_conn(conn, transmute(Transport_Error)int(alert))

	return 1
}

set_secret :: proc ( conn: ^Conn, level: ssl.QUIC_Encryption_Level, role: Secret_Role, cipher: Packet_Protection_Algorithm, secret: []u8) {
	e := &conn.encryption.secrets[level][.Read]
	key_len := Key_Len[e.cipher]
	algo := Hash_Algo[e.cipher]

	sync.guard(&conn.encryption.lock)
	e.key = tlsv13_expand_label(secret, "quic key", algo, key_len)
	e.iv = tlsv13_expand_label(secret, "quic iv", algo, 12)
	e.hp = tlsv13_expand_label(secret, "quic hp", algo, key_len)
	e.ku = tlsv13_expand_label(secret, "quic ku", algo, key_len)
	e.cipher = cipher
	e.valid = true
}

set_read_secret :: proc "c" (
	ssl_conn: ssl.SSL_Connection,
	level: libressl.ssl_encryption_level_t,
	cipher: ssl.SSL_CIPHER,
	secret: [^]u8,
	slen: uint,
) -> i32 {
	context = runtime.default_context()
	conn, _ := find_conn(ssl_conn)
	level := transmute(ssl.QUIC_Encryption_Level)level
	cipher := get_cipher(cipher)

	set_secret(conn, level, .Read, cipher, secret[:slen])
	
	return 1
}

set_write_secret :: proc "c" (
	ssl_conn: ssl.SSL_Connection,
	level: libressl.ssl_encryption_level_t,
	cipher: ssl.SSL_CIPHER,
	secret: [^]u8,
	slen: uint,
) -> i32 {
	context = runtime.default_context()
	conn, _ := find_conn(ssl_conn) // TODO: make SSL init fn w/ a ptr to conn
	level := transmute(ssl.QUIC_Encryption_Level)level
	cipher := get_cipher(cipher)

	set_secret(conn, level, .Write, cipher, secret[:slen])

	return 1
}

Quic_Method :: ssl.SSL_QUIC_METHOD {
	add_handshake_data = add_handshake_data,
	flush_flight       = flush_flight,
	send_alert         = send_alert,
	set_read_secret    = set_read_secret,
	set_write_secret   = set_write_secret,
}
