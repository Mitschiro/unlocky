#include "db.h"
#include "unlocky.h"
#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static sqlite3 *g_db = NULL;

static const char *CREATE_SQL_TABLE = "CREATE TABLE IF NOT EXISTS unlocky ("
                                      "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                      "name TEXT UNIQUE NOT NULL, "
                                      "login TEXT, "
                                      "encrypted_pw BLOB NOT NULL, "
                                      "cmd TEXT, "
                                      "created_at DATE, "
                                      "updated_at DATE, "
                                      "totp_seed BLOB"
                                      ");";

int init_db(const char *db_path) {
  sqlite3 *db = NULL;
  int rc = sqlite3_open(db_path, &db);
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

  printf("DB has been initialized: %s\n", db_path);
  sqlite3_close(db);
  return 0;
}

int add_entry(data_entry_t *entry, char *master_pw) {
  //

  close_db();
  return 1;
}

void close_db(void) {
  if (g_db != NULL) {
    sqlite3_close(g_db);
    g_db = NULL;
  }
}
