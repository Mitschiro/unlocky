#include "./../include/db.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static const char *CREATE_SQL_TABLE = "CREATE TABLE IF NOT EXISTS unlocky ("
                                      "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                      "name TEXT UNIQUE NOT NULL, "
                                      "login TEXT, "
                                      "encrypted_pw TEXT NOT NULL, "
                                      "cmd TEXT, "
                                      "created_at DATE, "
                                      "updated_at DATE, "
                                      "totp_seed TEXT"
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
