#include "crypto.h"
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
  //local copy of state h
  uint32_t a = h[0];
  uint32_t b = h[1];
  uint32_t c = h[2];
  uint32_t d = h[3];
  uint32_t e = h[4];

  //Expand block to 80 words
  uint32_t w[80];
  int i;
  for (i = 0; i < 16; i++) {
    w[i] = (block[i*4] << 24) | (block[i*4 + 1] << 16) | (block[i*4 +2] << 8) | block[i*4 + 3];
  }
  for (; i < 80; i++) {
    uint32_t temp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
    w[i] = rotl(temp, 1); // rotate left by 1
  }

  for (i = 0; i < 80; i++) {
    uint32_t f;
    uint32_t k;

    if (i < 20) {
      // Round 1: f = (b AND c) OR ((NOT b) AND d), K = K1
      f = (b & c) | ((~b) & d);
      k = K1;
    } else if (i < 40) {
      // Round 2: f = b XOR c XOR d, K = K2
      f = b ^ c ^ d;
      k = K2;
    } else if (i < 60) {
      // Round 3: f = (b AND c) OR (b AND d) OR (c AND d), K = K3
      f = (b & c) | (b & d) | (c & d);
      k = K3;
    } else {
      // Round 4: f = b XOR c XOR d, K = K4
      f = b ^ c ^ d;
      k = K4;
    }

    // temp = a + ROTL(b, 5) + f + k + w[i]
    uint32_t temp = a + rotl(b, ROTL_B) + f + k + w[i];

    // Cycle: a = e, e = d, d = ROTL(c, 30), c = b, b = temp
    a = e;
    e = d;
    d = rotl(c, 30);
    c = b;
    b = temp;
  }

  // Add to original h (final h = old h + working a/b/c/d/e)
  h[0] += a;  // h[0] = h[0] + a
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
}

void sha1_update(sha1_state *state, const unsigned char *input, size_t input_len) {
  
}