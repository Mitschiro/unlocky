#include "db.h"
#include "unlocky.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>

int getMasterPw(char *master_pw);

void setup_unlocky();

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
          } else if (strcmp(argv[i], FLAG_SECRET) == 0) {
            strncpy(entry.secret, argv[i + 1], MAX_SECRET_LEN - 1);
            i += 2;
          }else if (strcmp(argv[i], FLAG_CMD) == 0) {
            strncpy(entry.cmd, argv[i + 1], MAX_CMD_LEN - 1);
            i += 2;
          } else if (strcmp(argv[i], FLAG_TOTP) == 0) {
            strncpy(entry.totp_seed, argv[i + 1], MAX_PW_LEN - 1);
            entry.totp_hash = TOTP_HASH_DEFAULT;
            entry.totp_digit = TOTP_DIGITS_DEFAULT;
            entry.totp_base32 = TOTP_BASE32_DEFAULT;
            i += 2;
          } else if(strcmp(argv[i], FLAG_TOTP_HASH)) {
            entry.totp_hash = atoi(argv[i + 1]) == TOTP_HASH_SHA256 ? TOTP_HASH_SHA256 : TOTP_HASH_DEFAULT;
            i += 2;
          } else if(strcmp(argv[i], FLAG_TOTP_DIGIT)) {
            entry.totp_digit = atoi(argv[i + 1]) == TOTP_DIGITS_8 ? TOTP_DIGITS_8 : TOTP_DIGITS_DEFAULT;
            i += 2;
          }else if (strcmp(argv[i], FLAG_TOTP_BASE32) == 0) {
            entry.totp_base32 = atoi(argv[i + 1]) == TOTP_BASE_INACTIVE ? TOTP_BASE_INACTIVE : TOTP_BASE32_DEFAULT;
            i += 2;
          }else {
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
        printf("- Name: %s\n- Login: %s\n- Password: %s\n- Secret: %s\n- Command: %s\n- created_at: %s\n- "
              "updated_at: %s\n- totp_seed: %s\n- totp_code: %06llu with %d seconds left\n- TOTP Config: SHA=%d, Digits=%d, Base32=%s\n",
              get_entry_d.name, get_entry_d.login, get_entry_d.pw, get_entry_d.secret, get_entry_d.cmd,
              get_entry_d.created_at, get_entry_d.updated_at,
              get_entry_d.totp_seed, get_entry_d.totp_code, get_entry_d.totp_time, get_entry_d.totp_hash, get_entry_d.totp_digit, get_entry_d.totp_base32 == TOTP_BASE32_ACTIVE ? "true" : "false");
      }
      break;
    case SUBCMD_MODIFY:
      if (getMasterPw(master_pw) != 0) {
        fprintf(stderr, "No master pw provided, aborting");
        return -1;
      }

      if (argv[2][0] == '-') {
        fprintf(stderr, "First argument after 'modify' has to be the name of the entry to be updated.\n");
        return -1;
      }

      if (argc < 3) {
        fprintf(stderr, "No flag+param provided for update.\n");
      }

      data_entry_t update_entry = {0};
      strncpy(update_entry.name, argv[2], MAX_NAME_LEN - 1);
      for (int i = 3; i < argc;) {
        if (argv[i][0] == '-' && argv[i + 1][0] != '-') {
          if (strcmp(argv[i], FLAG_LOGIN) == 0) {
            strncpy(update_entry.login, argv[i + 1], MAX_LOGIN_LEN - 1);
            i += 2;
          } else if (strcmp(argv[i], FLAG_PW) == 0) {
            strncpy(update_entry.pw, argv[i + 1], MAX_PW_LEN - 1);
            i += 2;
            flag_check += 1;
          } else if (strcmp(argv[i], FLAG_SECRET) == 0) {
            strncpy(update_entry.secret, argv[i + 1], MAX_SECRET_LEN - 1);
            i += 2;
          }else if (strcmp(argv[i], FLAG_CMD) == 0) {
            strncpy(update_entry.cmd, argv[i + 1], MAX_CMD_LEN - 1);
            i += 2;
          } else if (strcmp(argv[i], FLAG_TOTP) == 0) {
            strncpy(update_entry.totp_seed, argv[i + 1], MAX_PW_LEN - 1);
            i += 2;
          } else if (strcmp(argv[i], FLAG_TOTP_HASH) == 0) {
            update_entry.totp_hash = atoi(argv[i + 1]) == TOTP_HASH_SHA256 ? TOTP_HASH_SHA256 : TOTP_HASH_DEFAULT;
            i += 2;
          }else if (strcmp(argv[i], FLAG_TOTP_DIGIT) == 0) {
            update_entry.totp_digit = atoi(argv[i + 1]) == TOTP_DIGITS_8 ? TOTP_DIGITS_8 : TOTP_DIGITS_DEFAULT;
            printf("Update digit: %d\n", update_entry.totp_digit);
            i += 2;
          }else if (strcmp(argv[i], FLAG_TOTP_BASE32) == 0) {
            update_entry.totp_base32 = atoi(argv[i + 1]) == TOTP_BASE_INACTIVE ? TOTP_BASE_INACTIVE : TOTP_BASE32_DEFAULT;
            i += 2;
          }else {
            i += 1;
          }
        } else {
          i++;
        }
      }

      modify_entry(&update_entry, master_pw);
      break;
    case SUBCMD_DELETE:
      if (getMasterPw(master_pw) != 0) {
        fprintf(stderr, "No master pw provided, aborting");
        return -1;
      }
      if (argv[2][0] == '-') {
        fprintf(stderr, "First argument after 'delete' has to be the name of the entry to be deleted.\n");
        return -1;
      }
      delete_entry(argv[2], master_pw);
      break;
    case SUBCMD_SETUP:
      printf("SETUP\n");
      setup_unlocky();
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

void setup_unlocky() {
  struct passwd *pw = getpwnam("unlocky");
  uid_t unlocky_uid = 0;
  gid_t unlocky_gid = 0;
  if (pw == NULL) {
    if (system("sudo useradd -r -s /bin/false unlocky") != 0) {
      printf("Failed to set unlocky user. Try again or set the 'unlocky' user manually.\n");
      return;
    }
    pw = getpwnam("unlocky");
    if (pw == NULL) {
      fprintf(stderr, "Something went wrong, failed to fetch user details");
      return;
    }
  }
  unlocky_uid = pw->pw_uid;
  unlocky_gid = pw->pw_gid;
  printf("uid: %d, gid: %d\n", pw->pw_uid, pw->pw_gid);
  if (chown(DB_PATH, unlocky_uid, unlocky_gid) != 0) {
    fprintf(stderr, "chmod failed: %s\n", strerror(errno));
    return;
  }

  if (chmod(DB_PATH, S_IRUSR | S_IWUSR) != 0) {
    fprintf(stderr, "chmod failed: %s", strerror(errno));
    return;
  }

  if (chmod("./build/unlocky", S_IRUSR | S_IWUSR | S_IXUSR | S_IXGRP | S_IXOTH | S_ISUID) != 0) {
    fprintf(stderr, "setuid chmod failed: %s\n", strerror(errno));
    return;
  }
  return;
}
