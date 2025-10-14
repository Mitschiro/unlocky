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
  unsigned char key[KEY_LEN];
  unsigned char salt[SALT_LEN];
  randombytes_buf(salt, sizeof(salt));
  if (crypto_pwhash(key, sizeof(key), master_key, strlen(master_key), salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    fprintf(stderr, "Key deriv failed.\n");
    return 0;
  }

  unsigned char nonce[NONCE_LEN];
  randombytes_buf(nonce, sizeof(nonce));

  memmove(value + SALT_LEN + NONCE_LEN, value, plainvalue_len);
  memcpy(value, salt, SALT_LEN);
  memcpy(value + SALT_LEN, nonce, NONCE_LEN);

  unsigned long long cipher_len;
  crypto_aead_aes256gcm_encrypt((unsigned char *)(value + SALT_LEN + NONCE_LEN),
                                &cipher_len, (unsigned char *)value,
                                plainvalue_len, NULL, 0, NULL,
                                (unsigned char *)(value + SALT_LEN), key);

  return SALT_LEN + NONCE_LEN + cipher_len;
}

unsigned long long decrypt_value(char *cipher, const char *master_key) {
  if (cipher == NULL || master_key == NULL || strlen(cipher) == 0 ||
      strlen(master_key) == 0) {
    fprintf(stderr, "Malformated parameters for decryption.\n");
    return 0;
  }

  size_t cipher_total_len = strlen(cipher);
  if (cipher_total_len < (SALT_LEN + NONCE_LEN + TAG_LEN)) {
    fprintf(stderr, "Encrypted pw is too short for decryption.\n");
    return 0;
  }

  unsigned char salt[SALT_LEN];
  memcpy(salt, cipher, SALT_LEN);

  unsigned char nonce[NONCE_LEN];
  memcpy(nonce, cipher + SALT_LEN, NONCE_LEN);

  unsigned char key[KEY_LEN];
  if (crypto_pwhash(key, sizeof(key), master_key, strlen(master_key), salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    fprintf(stderr, "Incorrect Master Password for key deriv.");
    return 0;
  }

  unsigned long long plain_len;
  unsigned long long cipher_text_len = cipher_total_len - SALT_LEN - NONCE_LEN;
  if (crypto_aead_aes256gcm_decrypt(
          (unsigned char *)(cipher + SALT_LEN + NONCE_LEN), &plain_len, NULL,
          (unsigned char *)(cipher + SALT_LEN + NONCE_LEN), cipher_text_len,
          NULL, 0, (unsigned char *)(cipher + SALT_LEN), key) != 0) {
    fprintf(stderr, "Decryption failed, wrong password or comprimised?\n");
    return 0;
  }

  cipher[SALT_LEN + NONCE_LEN + plain_len] = '\0';

  return plain_len;
}
