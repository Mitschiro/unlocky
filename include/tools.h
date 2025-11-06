#include <stddef.h>
#ifndef TOOLS_H
#include <sodium.h>
#include <time.h>

#define TOTP_DIGITS 6
#define TOTP_STEP 30
#define HMAC_SHA256_BYTES 32

int replace_in_string(char *dest_str, const char *search_val,
                      const char *replace_value, size_t replace_value_len);

/*
Generates a TOTP code from a given seed.
This function handles both SHA1 and SHA256, which can be changed with totp_hash.
This function can generate a 6 or 8 digit code, depending on the totp_digit config.
By default this function expects a base32 encoded seed unless totp_base32 specifies otherwise.
*/
int generate_totp(const char *seed, unsigned long long *totp_code,
                  int *seconds_left, int totp_hash, int totp_digit, int totp_base32);

#endif // TOOLS_H
