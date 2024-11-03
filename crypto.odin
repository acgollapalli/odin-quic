package quic

import "core:crypto/aes"
import "core:crypto/chacha"
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

Encryption_Level_Secrets :: struct {
    secret: []byte,
    key: []byte,
    iv: []byte,
    hp: []byte,
    ku: []byte,
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
get_header_mask :: proc(hp_key, sample: []u8, algo: Packet_Protection_Algorithm) -> ? {
    switch algo {
    case .AEAD_AES_128_GCM:
	return aes_ecb(hp_key, sample)
    case .AEAD_AES_128_CCM:
	return aes_ecb(hp_key, sample)
    case .AEAD_AES_256_GCM:
	return aes_ecb(hp_key, sample)
    case .AEAD_CHACHA20_POLY1305:
	return 
	
    }

}

/* 
 * This SHOULD chose 128 or 256 aes_ecb based on key size
 */ 

aes_ecb :: proc(hp_key: []byte, sample: []byte) -> []byte {
    ctx := aes.Context_ECB
    aes.init_ecb(&ctx, hp_key)
    dst : []byte
    aes.decrypt_ecb(&ctx, dst, sample)
    return dst
}
