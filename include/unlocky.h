#ifndef UNLOCKY_H
#define UNLOCKY_H
#include <sqlite3.h>
#include <stddef.h>

typedef enum {
  SUBCMD_INVALID = 0,
  SUBCMD_ADD,
  SUBCMD_LIST,
  SUBCMD_GET,
  SUBCMD_MODIFY,
  SUBCMD_DELETE,
  SUBCMD_SETUP
} subcmd_t;

typedef struct {
  const char *name;
  subcmd_t value;
} subcmd_entry_t;

static const subcmd_entry_t SUBCMD_TABLE[] = {
    {"add", SUBCMD_ADD},       {"list", SUBCMD_LIST},
    {"get", SUBCMD_GET},       {"modify", SUBCMD_MODIFY},
    {"delete", SUBCMD_DELETE}, {"setup", SUBCMD_SETUP},
    {NULL, SUBCMD_INVALID}};

// Definition of flags
#define FLAG_HELP "-h"
#define FLAG_NAME "-n"
#define FLAG_LOGIN "-l"
#define FLAG_PW "-p"
#define FLAG_SECRET "-s"
#define FLAG_CMD "-c"
#define FLAG_TOTP "-o"
#define FLAG_TOTP_HASH "-oh"
#define FLAG_TOTP_DIGIT "-od"
#define FLAG_ALL "-a"

#define MAX_NAME_LEN 50
#define MAX_LOGIN_LEN 100
#define MAX_PW_LEN 100
#define MAX_CMD_LEN 512
#define MAX_SECRET_LEN 1024

#define VERSION 1

#define TOTP_HASH_DEFAULT 1
#define TOTP_HASH_SHA256 256
#define TOTP_DIGITS_DEFAULT 6
#define TOTP_DIGITS_8 8

#define SEARCH_VALUE_LOGIN "%login%"
#define SEARCH_VALUE_PASSWORD "%password%"
#define SEARCH_VALUE_TOTP "%totp%"
#define SEARCH_VALUE_SECRET "%secret%"

typedef struct {
  char name[MAX_NAME_LEN];
  char login[MAX_LOGIN_LEN];
  char pw[MAX_PW_LEN];
  char cmd[MAX_CMD_LEN];
  char secret[MAX_SECRET_LEN];
  char created_at[20];
  char updated_at[20];
  char totp_seed[MAX_PW_LEN];
  int totp_hash;
  int totp_digit;
  unsigned long long totp_code;
  int totp_time;
} data_entry_t;

#endif // UNLOCKY_H
