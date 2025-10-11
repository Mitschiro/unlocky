#include "db.h"
#include "unlocky.h"
#include <stdio.h>
#include <string.h>
void processAdd(char *name, char *login, char *pw, char *cmd);

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("No command has been invoked.\n");
    return 0;
  }

  char *subcmd_str = argv[1];
  subcmd_t subcmd = SUBCMD_INVALID;

  for (int i = 0; SUBCMD_TABLE[i].name != NULL; i++) {
    if (strcmp(subcmd_str, SUBCMD_TABLE[i].name) == 0) {
      subcmd = SUBCMD_TABLE[i].value;
      break;
    }
  }
  const char *db_path = "unlocky.db";

  int db_init = init_db(db_path);

  if (db_init != 0) {
    return -1;
  }

  switch (subcmd) {
  case SUBCMD_INVALID:
    return -1;
  case SUBCMD_ADD:
    printf("ADD\n");
    break;
  case SUBCMD_LIST:
    printf("LIST\n");
    break;
  case SUBCMD_GET:
    printf("GET\n");
    break;
  case SUBCMD_MODIFY:
    printf("MODIFY\n");
    break;
  case SUBCMD_DELETE:
    printf("DELETE\n");
    break;
  case SUBCMD_SETUP:
    printf("SETUP\n");
    break;
  }

  return 1;
}
