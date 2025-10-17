#include <stddef.h>
#ifndef TOOLS_H
#include <sodium.h>
#include <time.h>

#define TOTP_DIGITS 6
#define TOTP_STEP 30
#define HMAC_SHA256_BYTES 32

int replace_in_string(char *dest_str, const char *search_val,
                      const char *replace_value, size_t replace_value_len);

int generate_totp(const char *seed, unsigned long long *totp_code,
                  int *seconds_left);

#endif // TOOLS_H
