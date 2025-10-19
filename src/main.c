#include "db.h"
#include "unlocky.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
int getMasterPw(char *master_pw);

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

  int db_init = init_db();

  if (db_init != 0) {
    return -1;
  }
  char master_pw[100] = {0};
  
  switch (subcmd) {
    case SUBCMD_INVALID:
      return -1;
    case SUBCMD_ADD:
      if (getMasterPw(master_pw) != 0) {
        fprintf(stderr, "No master pw provided, aborting");
        return -1;
      }
      data_entry_t entry = {0};
      if (argv[2][0] != '-') {
        printf("Wrong format, after the add cmd a flag has to follow\n");
        return -1;
      }
      int flag_check = 0;
      for (int i = 2; i < argc;) {
        if (argv[i][0] == '-' && argv[i + 1][0] != '-') {
          if (strcmp(argv[i], FLAG_NAME) == 0) {
            strncpy(entry.name, argv[i + 1], MAX_NAME_LEN - 1);
            i += 2;
            flag_check += 1;
          } else if (strcmp(argv[i], FLAG_LOGIN) == 0) {
            strncpy(entry.login, argv[i + 1], MAX_LOGIN_LEN - 1);
            i += 2;
          } else if (strcmp(argv[i], FLAG_PW) == 0) {
            strncpy(entry.pw, argv[i + 1], MAX_PW_LEN - 1);
            i += 2;
            flag_check += 1;
          } else if (strcmp(argv[i], FLAG_CMD) == 0) {
            strncpy(entry.cmd, argv[i + 1], MAX_CMD_LEN - 1);
            i += 2;
          } else if (strcmp(argv[i], FLAG_TOTP) == 0) {
            strncpy(entry.totp_seed, argv[i + 1], MAX_PW_LEN - 1);
            i += 2;
          } else {
            i += 1;
          }
        } else {
          i++;
        }
      }

      if (flag_check < 2) {
        fprintf(stderr, "Name (-n) and Password (-p) are mandatory!\n");
        return -1;
      }

      printf("ADD: -n %s -l %s -p %s -c %s -o %s\n", entry.name, entry.login,
            entry.pw, entry.cmd, entry.totp_seed);

      time_t now = time(NULL);
      struct tm *tm_info = localtime(&now);
      strftime(entry.created_at, sizeof(entry.created_at), "%Y/%m/%d %H:%M:%S",
              tm_info);
      strncpy(entry.updated_at, entry.created_at, sizeof(entry.updated_at) - 1);
      entry.updated_at[sizeof(entry.updated_at) - 1] = '\0';

      if (add_entry(&entry, master_pw) == -1) {
        fprintf(stderr, "Failed operation, aborting.\n");
      }

      break;
    case SUBCMD_LIST:
      list_entries();
      break;
    case SUBCMD_GET:
      if (getMasterPw(master_pw) != 0) {
        fprintf(stderr, "No master pw provided, aborting");
        return -1;
      }
      data_entry_t get_entry_d = {0};
      
      if (get_entry(argv[2], &get_entry_d, master_pw) == 0) {
        printf("- Name: %s\n- Login: %s\n- Password: %s\n- Command: %s\n- created_at: %s\n- "
              "updated_at: %s\n- totp_seed: %s\n- totp_code: %06llu with %d seconds left\n",
              get_entry_d.name, get_entry_d.login, get_entry_d.pw, get_entry_d.cmd,
              get_entry_d.created_at, get_entry_d.updated_at,
              get_entry_d.totp_seed, get_entry_d.totp_code, get_entry_d.totp_time);
      }
      break;
    case SUBCMD_MODIFY:
      printf("MODIFY\n");
      break;
    case SUBCMD_DELETE:
      printf("DELETE\n");
      if (getMasterPw(master_pw) != 0) {
        fprintf(stderr, "No master pw provided, aborting");
        return -1;
      }
      delete_entry(argv[2], master_pw);
      break;
    case SUBCMD_SETUP:
      printf("SETUP\n");
      break;
  }

  return 0;
}

int getMasterPw(char *master_pw) {
  printf("Enter master password: ");
  fflush(stdout);
  if (fgets(master_pw, 100, stdin) == NULL) {
    printf("Input failed.\n");
    return -1;
  }
  master_pw[strcspn(master_pw, "\n")] = '\0';
  if (strlen(master_pw) == 0) {
    return -1;
  }
  return 0;
}
