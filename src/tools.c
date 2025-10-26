#include "tools.h"
#include "crypto.h"
#include "unlocky.h"
#include <sodium/crypto_auth_hmacsha256.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int replace_in_string(char *dest_str, const char *search_val,
                      const char *replace_value, size_t replace_value_len) {
  char tmp_str[MAX_CMD_LEN] = {0};
  char *search_val_pos = strstr(dest_str, search_val);
  if (search_val_pos) {

    memcpy(tmp_str, dest_str, search_val_pos - dest_str);
    memcpy(tmp_str + strlen(tmp_str), replace_value, replace_value_len);

    memcpy(tmp_str + strlen(tmp_str), search_val_pos + strlen(search_val),
           strlen(search_val_pos) - strlen(search_val));

    tmp_str[strlen(tmp_str) + 1] = '\0';
    strcpy(dest_str, tmp_str);
  }
  return 1;
}

int generate_totp(const char *seed, unsigned long long *totp_code,
                  int *seconds_left, int totp_hash, int totp_digit) {
  if (seed == NULL || totp_code == NULL || seconds_left == NULL ||
      strlen(seed) == 0) {
    return -1;
  }

  // Decode base32 seed to raw key bytes (TOTP standard, RFC 6030)
  unsigned char key[20];  // Room for decode (max 16 chars base32 = 10 bytes)
  size_t key_len;
  if (crypto_decode_base32(key, &key_len, (const unsigned char *)seed, strlen(seed)) != 0) {
    return -1;  // Invalid base32
  }

  // get current counter
  time_t now = time(NULL);
  uint64_t counter = now / TOTP_STEP;

  // Split uint64 counter into 8 blocks of each block holding 8 bits = 1 byte.
  // As the crypto algo requires the number to be in the correct order (Big
  // Edian) and depending on the plattform the order can be little edian, the
  // output would be garbage. So we pass the counter as an array holding each
  // byte in the correct order. 0xff is to ensure we ignore everything left of
  // the last 8 bits.
  unsigned char counter_bytes[8];
  counter_bytes[0] = (counter >> 56) & 0xff;
  counter_bytes[1] = (counter >> 48) & 0xff;
  counter_bytes[2] = (counter >> 40) & 0xff;
  counter_bytes[3] = (counter >> 32) & 0xff;
  counter_bytes[4] = (counter >> 24) & 0xff;
  counter_bytes[5] = (counter >> 16) & 0xff;
  counter_bytes[6] = (counter >> 8) & 0xff;
  counter_bytes[7] = counter & 0xff;

  unsigned char hash[HMAC_SHA256_BYTES];
  switch (totp_hash) {
    case TOTP_HASH_SHA256:
      crypto_auth_hmacsha256_state state;
      crypto_auth_hmacsha256_init(&state, (unsigned char *)seed, strlen(seed));
      crypto_auth_hmacsha256_update(&state, counter_bytes, 8);
      crypto_auth_hmacsha256_final(&state, hash);
      break;
    case TOTP_HASH_DEFAULT:
    default:
      // sha1_state state_sha1;
      // sha1_init(&state_sha1);
      // sha1_update(&state_sha1, (unsigned char*)seed, strlen(seed));
      // sha1_final(&state_sha1, hash);
      hmac_sha1((unsigned char *)seed, strlen(seed), counter_bytes, 8, hash);  // HMAC-SHA1 (key=seed, msg=counter)
      break;
  }

  int offset = hash[totp_hash == TOTP_HASH_SHA256 ? 31 : 19] & 0xf;
  uint32_t code = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) |
                  (hash[offset + 2] << 8) | hash[offset + 3];

  if (totp_digit == TOTP_DIGITS_8) {
    *totp_code = code % 100000000;
  } else {
    *totp_code = code % 1000000;
  }

  *seconds_left = TOTP_STEP - (now % TOTP_STEP);

  return 0;
}
