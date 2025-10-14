#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <sodium.h>

#define SALT_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32
#define TAG_LEN 16

unsigned long long encrypt_value(char *value, const char *master_key);
unsigned long long decrypt_value(char *cipher, const char *master_key);

#endif // ENCRYPTION_H
