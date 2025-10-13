#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <sodium.h>

unsigned long long encrypt_value(char *value, const char *master_key);

#endif // ENCRYPTION_H
