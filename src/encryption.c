#include "encryption.h"
#include <sodium/crypto_aead_aes256gcm.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/randombytes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

unsigned long long encrypt_value(char *value, const char *master_key) {
  if (value == NULL || master_key == NULL || strlen(value) == 0 ||
      strlen(master_key) == 0) {
    fprintf(stderr, "Malformated parameters for encrypt_value!\n");
    return 0;
  }

  size_t plainvalue_len = strlen(value);
  unsigned char key[32];
  unsigned char salt[16];
  randombytes_buf(salt, sizeof(salt));
  if (crypto_pwhash(key, sizeof(key), master_key, strlen(master_key), salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    fprintf(stderr, "Key deriv failed.\n");
    return 0;
  }

  // Debug key as hex (remove in prod)
  printf("Derived key (hex): ");
  for (int j = 0; j < sizeof(key); j++) {
    printf("%02x", key[j]);
  }
  printf("\n");

  unsigned char nonce[12];
  randombytes_buf(nonce, sizeof(nonce));

  memmove(value + 28, value, plainvalue_len);
  memcpy(value, salt, 16);
  memcpy(value + 16, nonce, 12);

  unsigned long long cipher_len;
  crypto_aead_aes256gcm_encrypt((unsigned char *)(value + 28), &cipher_len,
                                (unsigned char *)value, plainvalue_len, NULL, 0,
                                NULL, (unsigned char *)(value + 16), key);

  return 28 + cipher_len;
}
