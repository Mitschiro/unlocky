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
#define FLAG_CMD "-c"
#define FLAG_TOTP "-o"
#define FLAG_ALL "-a"

#define MAX_NAME_LEN 50
#define MAX_LOGIN_LEN 100
#define MAX_PW_LEN 100
#define MAX_CMD_LEN 512

#define VERSION 1

#define SEARCH_VALUE_LOGIN "%login%"
#define SEARCH_VALUE_PASSWORD "%password%"
#define SEARCH_VALUE_TOTP "%totp%"
// #define SEARCH_VALUE_TOTP_VALUE "%totp_value%"

typedef struct {
  char name[MAX_NAME_LEN];
  char login[MAX_LOGIN_LEN];
  char pw[MAX_PW_LEN];
  char cmd[MAX_CMD_LEN];
  char created_at[20];
  char updated_at[20];
  char totp_seed[MAX_PW_LEN];
  unsigned long long totp_code;
  int totp_time;
} data_entry_t;

#endif // UNLOCKY_H
