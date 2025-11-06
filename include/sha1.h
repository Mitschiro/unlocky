#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>  // For uint32_t, uint64_t (fixed-size ints, no platform weirdness)
#include <stddef.h>  // For size_t (lengths, like strlen return)


// RFC 3174 implementation of sha1, as SHA1 is slowly faded out (libsodium for example) due to it's security risks,
// i decided to implement SHA1 as TOTP still depends on it and will for a while.
// The risk of adding another lib or switching to another lib altogether, just for SHA1 getting depreiated is too high of a risk.

// High-level function: Hash input bytes to 20-byte SHA1 digest
// Usage: unsigned char hash[20]; sha1_hash(input, input_len, hash);
int sha1_hash(const unsigned char *input, size_t input_len, unsigned char *output);

void sha1_compress(uint32_t *h, const unsigned char *block);

// Internal streaming functions (for large input or incremental hash)
// State = internal struct (80 bytes: hash words + buffer + len)
typedef struct {
  uint32_t h[5];  // 5 32-bit hash values (160 bits total, the "current digest")
  uint64_t len;   // Total bytes processed (64-bit, for final pad calc)
  unsigned char block[64];  // Current 512-bit block buffer (64 bytes)
  int count;  // Bytes in current block (0-63, for partial updates)
} sha1_state;

// Init: Reset state to initial values (call once before updates)
void sha1_init(sha1_state *state);

// Update: Process input bytes (can call multiple times for streaming)
void sha1_update(sha1_state *state, const unsigned char *input, size_t input_len);

// Final: Pad last block, compute digest, copy to output (20 bytes)
void sha1_final(sha1_state *state, unsigned char *output);

void hmac_sha1(const unsigned char *key, size_t key_len, const unsigned char *msg, size_t msg_len, unsigned char *output);


// Constants from RFC 3174 (Section 5: Initial Hash Values and K Words)
// H init: 5 32-bit words (hex from spec, little-endian byte order in memory)
#define H0 0x67452301  // Initial hash word 0 (first 32 bits of digest)
#define H1 0xefcdab89  // Word 1
#define H2 0x98badcfe  // Word 2
#define H3 0x10325476  // Word 3
#define H4 0xc3d2e1f0  // Word 4

// K words: 4 constant words each repeating 20 times (80 total), for compression function (Section 5)
#define K1 0x5a827999  // Round 1 (0-19): +5a827999 to f func
#define K2 0x6ed9eba1  // Round 2 (20-39): +6ed9eba1
#define K3 0x8f1bbcdc  // Round 3 (40-59): +8f1bbcdc
#define K4 0xca62c1d6  // Round 4 (60-79): +ca62c1d6

#define ROTL_B 5
#define ROTL_W 1

// Block size (512 bits = 64 bytes, RFC Section 3)
#define BLOCK_SIZE 64

#endif  // CRYPTO_H