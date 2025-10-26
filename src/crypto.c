#include "crypto.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

uint32_t rotl(uint32_t x, int n) {
  n &= 31;
  return (x << n) | (x >> (32 - n));
}

void sha1_init(sha1_state *state ) {
  if (state == NULL) {
      return;
  }

  //set initial hash
  state->h[0] = H0;
  state->h[1] = H1;
  state->h[2] = H2;
  state->h[3] = H3;
  state->h[4] = H4;

  //reset state len to 0
  state->len = 0;

  // zero current block buffer
  memset(state->block, 0, BLOCK_SIZE);

  //reset byte count
  state->count = 0;
}

void sha1_compress(uint32_t *h, const unsigned char *block) {
  uint32_t a = h[0];
  uint32_t b = h[1];
  uint32_t c = h[2];
  uint32_t d = h[3];
  uint32_t e = h[4];

  uint32_t w[80];
  int i;
  for (i = 0; i < 16; i++) {
    w[i] = (block[i*4] << 24) | (block[i*4 + 1] << 16) | (block[i*4 + 2] << 8) | block[i*4 + 3];
  }
  for (; i < 80; i++) {
    uint32_t temp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
    w[i] = rotl(temp, ROTL_W);  // ROTL_W = 1
  }

  for (i = 0; i < 80; i++) {
    uint32_t f;
    uint32_t k;

    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = K1;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = K2;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = K3;
    } else {
      f = b ^ c ^ d;
      k = K4;
    }

    uint32_t temp = rotl(a, ROTL_B) + f + e + k + w[i];

    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = temp;
  }

  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
}

void sha1_update(sha1_state *state, const unsigned char *input, size_t input_len) {
  if (state == NULL || input == NULL || input_len == 0) {
    return;
  }

  //track total bytes
  state->len += input_len;

  const unsigned char *ptr = input;
  size_t bytes_left = input_len;

  while (bytes_left > 0) {
    size_t space_left = BLOCK_SIZE - state->count;

    if (bytes_left < space_left) {
      // input fits in current block
      memcpy(state->block + state->count, ptr, bytes_left);
      state->count += bytes_left;
      bytes_left = 0;
    } else {
      //input fills current block
      memcpy(state->block + state->count, ptr, space_left);
      ptr += space_left;
      bytes_left -= space_left;

      //hash 64 byte block
      sha1_compress(state->h, state->block);
      
      //reset block
      state->count = 0;
    }
  }
}

void sha1_final(sha1_state *state, unsigned char *output) {
  if (state == NULL || output == NULL) {
    return;
  }

  //append 1 bit to message
  state->block[state->count] = 0x80; // 0x80 = 1000 0000
  state->count++;

  // Zero-pad to 56 bytes mod 64 (448 bits, room for 64-bit len)
  if (state->count > 56) {
    // Current block full—zero to end, compress, start new block for pad
    memset(state->block + state->count, 0, state->count);
    sha1_compress(state->h, state->block);
    state->count = 0;
  }
  memset(state->block + state->count, 0, 56 - state->count);

  // Append 64-bit message length in bits (big-endian, low 64 bits of len*8)
  uint64_t bit_len = state->len * 8;  // Bytes to bits (shift left 3)
  state->block[56] = (bit_len >> 56) & 0xff;  // High byte
  state->block[57] = (bit_len >> 48) & 0xff;
  state->block[58] = (bit_len >> 40) & 0xff;
  state->block[59] = (bit_len >> 32) & 0xff;
  state->block[60] = (bit_len >> 24) & 0xff;
  state->block[61] = (bit_len >> 16) & 0xff;
  state->block[62] = (bit_len >> 8) & 0xff;
  state->block[63] = bit_len & 0xff;  // Low byte

  // Hash the padded block (final compress)
  sha1_compress(state->h, state->block);

  // Copy final digest to output (20 bytes, big-endian byte order)
  for (int i = 0; i < 5; i++) {
    output[i*4] = (state->h[i] >> 24) & 0xff;  // High byte first
    output[i*4 + 1] = (state->h[i] >> 16) & 0xff;
    output[i*4 + 2] = (state->h[i] >> 8) & 0xff;
    output[i*4 + 3] = state->h[i] & 0xff;  // Low byte
  }
}

int sha1_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
  // Guard against bad pointers or empty input
  if (input == NULL || output == NULL || input_len == 0) {
    return -1;  // Err—caller check rc == 0
  }

  sha1_state state;
  sha1_init(&state);  // Set initial state

  sha1_update(&state, input, input_len);  // Process input bytes

  sha1_final(&state, output);  // Pad, hash last block, copy digest

  return 0;  // Success
}

// HMAC-SHA1 (key = seed bytes, msg = input bytes, output 20-byte digest)
void hmac_sha1(const unsigned char *key, size_t key_len, const unsigned char *msg, size_t msg_len, unsigned char *output) {
  unsigned char ipad[64] = {0};  // Pad buffer (512 bits = 64 bytes)
  unsigned char opad[64] = {0};

  // Pad key to 64 bytes (if key >64, hash it first—rare for seed)
  if (key_len > 64) {
    unsigned char key_hash[20];
    sha1_hash(key, key_len, key_hash);  // Hash long key to 20 bytes
    memcpy(ipad, key_hash, 20);
    memcpy(opad, key_hash, 20);
    key_len = 20;
  } else {
    memcpy(ipad, key, key_len);
    memcpy(opad, key, key_len);
  }

  // XOR with ipad (0x36 repeated)
  for (int i = 0; i < 64; i++) {
    ipad[i] ^= 0x36;
  }

  // XOR with opad (0x5c repeated)
  for (int i = 0; i < 64; i++) {
    opad[i] ^= 0x5c;
  }

  // Inner hash: ipad + msg
  sha1_state inner_state;
  sha1_init(&inner_state);
  sha1_update(&inner_state, ipad, 64);
  sha1_update(&inner_state, msg, msg_len);
  unsigned char inner_hash[20];
  sha1_final(&inner_state, inner_hash);

  // Outer hash: opad + inner_hash
  sha1_state outer_state;
  sha1_init(&outer_state);
  sha1_update(&outer_state, opad, 64);
  sha1_update(&outer_state, inner_hash, 20);
  sha1_final(&outer_state, output);  // 20-byte HMAC digest
}