#include "db.h"
#include "unlocky.h"
#include <encryption.h>
#include <sqlite3.h>
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
                                      "totp_seed BLOB"
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
      "updated_at, totp_seed) Values (?, ?, ?, ?, ?, ?, ?);";
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
