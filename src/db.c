#include "db.h"
#include "tools.h"
#include "unlocky.h"
#include <encryption.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
// static sqlite3 *g_db = NULL;

static const char *CREATE_SQL_TABLE = "CREATE TABLE IF NOT EXISTS unlocky ("
                                      "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                      "name TEXT UNIQUE NOT NULL, "
                                      "login TEXT, "
                                      "password BLOB NOT NULL, "
                                      "cmd TEXT, "
                                      "created_at DATE, "
                                      "updated_at DATE, "
                                      "totp_seed BLOB, "
                                      "version INTEGER"
                                      ");";

int init_db() {
  sqlite3 *db = NULL;
  int rc = sqlite3_open(DB_PATH, &db);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQlite open failed: %s\n", sqlite3_errmsg(db));
    if (db) {
      sqlite3_close(db);
    }
    return -1;
  }

  char *err_msg = NULL;
  rc = sqlite3_exec(db, CREATE_SQL_TABLE, NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Table creation failed: %s\n", err_msg);
    sqlite3_free(err_msg);
    sqlite3_close(db);
    return -1;
  }

  printf("DB has been initialized: %s\n", DB_PATH);
  sqlite3_close(db);
  return 0;
}

int add_entry(data_entry_t *entry, char *master_pw) {
  //
  if (entry == NULL || master_pw == 0 || strlen(master_pw) == 0 ||
      strlen(entry->name) == 0 || strlen(entry->pw) == 0) {
    fprintf(stderr, "Invalid params for add_entry.\n");
    return -1;
  }

  sqlite3 *db = NULL;
  int rc = sqlite3_open(DB_PATH, &db);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQlite open failed: %s\n", sqlite3_errmsg(db));
    if (db) {
      sqlite3_close(db);
    }
    return -1;
  }

  unsigned long long pw_cipher_len = encrypt_value(entry->pw, master_pw);
  if (pw_cipher_len == 0) {
    fprintf(stderr, "Pw encryption failed.\n");
    return -1;
  }

  unsigned long long totp_cipher_len = 0;
  if (strlen(entry->totp_seed) > 0) {
    totp_cipher_len = encrypt_value(entry->totp_seed, master_pw);
    if (totp_cipher_len == 0) {
      fprintf(stderr, "TOTP encryption failed.\n");
      return -1;
    }
  }

  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "INSERT INTO unlocky (name, login, password, cmd, created_at, "
      "updated_at, totp_seed, version) Values (?, ?, ?, ?, ?, ?, ?, ?);";
  rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL prepare failed: %s.\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return -1;
  }

  sqlite3_bind_text(stmt, 1, entry->name, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, entry->login, -1, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, entry->pw, pw_cipher_len, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 4, entry->cmd, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 5, entry->created_at, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 6, entry->updated_at, -1, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 7, entry->totp_seed, totp_cipher_len, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 8, VERSION);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  sqlite3_close(db);

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "Insert failed: %s\n", sqlite3_errmsg(db));
    return -1;
  }

  printf("Added entry for '%s'.", entry->name);

  return 0;
}

int get_entry(const char *name, data_entry_t *entry, const char *master_pw,
              const bool all, const bool login, const bool password,
              const bool cmd, const bool totp) {
  if (name == NULL || strlen(name) == 0 || entry == NULL || master_pw == NULL ||
      strlen(master_pw) == 0) {
    return -1;
  }
  // debug
  printf("Master pw: %s\n", master_pw);
  sqlite3 *db = NULL;
  int rc = sqlite3_open(DB_PATH, &db);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQlite open failed: %s\n", sqlite3_errmsg(db));
    if (db) {
      sqlite3_close(db);
    }
    return -1;
  }

  char sql[512] = {0};
  int login_pos = 2;
  int cmd_pos = 2;
  int totp_pos = 2;
  if (all == true) {
    strcat(sql, "SELECT name, password, login, cmd, created_at, updated_at, "
                "totp_seed FROM unlocky WHERE name = ?;");
    cmd_pos = 3;
    totp_pos = 6;
  } else {
    strcat(sql, "SELECT name, password");
    if (login) {
      strcat(sql, ", login");
      cmd_pos += 1;
      totp_pos += 1;
    }
    if (cmd) {
      strcat(sql, ", cmd");
      totp_pos += 1;
    }
    if (totp) {
      strcat(sql, ", totp_seed");
    }
    strcat(sql, " WHERE name = ?;");
  }

  if (strlen(sql) == 0) {
    fprintf(stderr, "Couldn't fetch entry, missing flags.\n");
    return -1;
  }

  sqlite3_stmt *stmt = NULL;
  rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    if (stmt != NULL) {
      sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return -1;
  }

  sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *pw_blob = sqlite3_column_blob(stmt, 1);
    int pw_len = sqlite3_column_bytes(stmt, 1);

    if (pw_blob && pw_len > 0) {
      memcpy(entry->pw, pw_blob, pw_len < MAX_PW_LEN ? pw_len : MAX_PW_LEN - 1);
      entry->pw[MAX_PW_LEN - 1] = '\0';
      // debug
      printf("PW len: %d, PW Blob: %02x\n", pw_len,
             (unsigned char)entry->pw[0]);

      unsigned long long plain_pw_len =
          decrypt_value(entry->pw, master_pw, (size_t)pw_len);
      if (plain_pw_len == 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
      }
    }

    if (totp || all) {
      const unsigned char *totp_blob = sqlite3_column_blob(stmt, totp_pos);
      int totp_len = sqlite3_column_bytes(stmt, totp_pos);
      if (totp_blob && totp_len > 0) {
        memcpy(entry->totp_seed, totp_blob,
               totp_len < MAX_PW_LEN ? totp_len : MAX_PW_LEN - 1);
        entry->totp_seed[MAX_PW_LEN - 1] = '\0';
        unsigned long long plain_totp_len =
            decrypt_value(entry->totp_seed, master_pw, (size_t)totp_len);
        if (plain_totp_len == 0) {
          sqlite3_finalize(stmt);
          sqlite3_close(db);
          return -1;
        }
      }
    }

    const char *col_name = (const char *)sqlite3_column_text(stmt, 0);
    strncpy(entry->name, col_name ? col_name : "", MAX_NAME_LEN - 1);
    entry->name[MAX_NAME_LEN - 1] = '\0';

    if (all || login) {
      const char *col_login =
          (const char *)sqlite3_column_text(stmt, login_pos);
      strncpy(entry->login, col_login ? col_login : "", MAX_LOGIN_LEN - 1);
      entry->login[MAX_NAME_LEN - 1] = '\0';
    }

    if (all || cmd) {
      const char *col_cmd = (const char *)sqlite3_column_text(stmt, cmd_pos);
      strncpy(entry->cmd, col_cmd ? col_cmd : "", MAX_CMD_LEN - 1);
      printf("-------- CMD DEBUG -----------\n");
      printf("CMD before replace: %s\n", entry->cmd);
      // replace_in_string(entry->cmd, SEARCH_VALUE_LOGIN, entry->login,
      //                   strlen(entry->login));
      // printf("New CMD after login replace: %s\n", entry->cmd);

      replace_in_string(entry->cmd, SEARCH_VALUE_PASSWORD, entry->pw,
                        strlen(entry->pw));
      printf("New CMD after password replace: %s\n", entry->cmd);
      printf("-------- CMD DEBUG END --------\n");
      entry->cmd[MAX_CMD_LEN - 1] = '\0';
    }

    if (all) {
      const char *col_created = (const char *)sqlite3_column_text(stmt, 4);
      strncpy(entry->created_at, col_created ? col_created : "",
              sizeof(entry->created_at) - 1);
      entry->created_at[sizeof(entry->created_at) - 1] = '\0';

      const char *col_updated = (const char *)sqlite3_column_text(stmt, 5);
      strncpy(entry->updated_at, col_updated ? col_updated : "",
              sizeof(entry->updated_at) - 1);
      entry->updated_at[sizeof(entry->updated_at) - 1] = '\0';
    }
  } else {
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return -1;
  }

  sqlite3_finalize(stmt);
  sqlite3_close(db);

  return 0;
}
