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

int list_callback(void*,int,char**,char**);

static const char *CREATE_SQL_TABLE = "CREATE TABLE IF NOT EXISTS unlocky ("
                                      "name TEXT PRIMARY KEY UNIQUE NOT NULL, "
                                      "login BLOB, "
                                      "password BLOB NOT NULL, "
                                      "secret BLOB, "
                                      "cmd BLOB, "
                                      "totp_seed BLOB, "
                                      "totp_hash INT NOT NULL, "
                                      "totp_digit INT NOT NULL, "
                                      "totp_base32 INT NOT NULL, "
                                      "created_at DATE, "
                                      "updated_at DATE, "
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

int add_entry(data_entry_t *entry, const char *master_pw) {
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

  unsigned long long secret_cipher_len = 0;
  if (strlen(entry->secret) > 0) {
    secret_cipher_len = encrypt_value(entry->secret, master_pw);
    printf("Secret encrypt len %llu", secret_cipher_len);
    if (secret_cipher_len == 0) {
      fprintf(stderr, "Secret encryption failed.\n");
      return -1;
    }
  }

  unsigned long long totp_cipher_len = 0;
  if (strlen(entry->totp_seed) > 0) {
    totp_cipher_len = encrypt_value(entry->totp_seed, master_pw);
    if (totp_cipher_len == 0) {
      fprintf(stderr, "TOTP encryption failed.\n");
      return -1;
    }
  }

  unsigned long long login_cipher_len = 0;
  if (strlen(entry->login) > 0) {
    login_cipher_len = encrypt_value(entry->login, master_pw);
    if (login_cipher_len == 0) {
      fprintf(stderr, "Login encryption failed.\n");
      return -1;
    }
  }

  unsigned long long cmd_cipher_len = 0;
  if (strlen(entry->cmd) > 0) {
    cmd_cipher_len = encrypt_value(entry->cmd, master_pw);
    if (cmd_cipher_len == 0) {
      fprintf(stderr, "Command encryption failed.\n");
      return -1;
    }
  }

  sqlite3_stmt *stmt = NULL;
  const char *sql =
      "INSERT INTO unlocky (name, login, password, secret, cmd, totp_seed, totp_hash, totp_digit, totp_base32,"
      " created_at, updated_at, version) Values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
  rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL prepare failed: %s.\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return -1;
  }

  sqlite3_bind_text(stmt, 1, entry->name, -1, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, entry->login, login_cipher_len, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, entry->pw, pw_cipher_len, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 4, entry->secret, secret_cipher_len, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 5, entry->cmd, cmd_cipher_len, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 6, entry->totp_seed, totp_cipher_len, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 7, entry->totp_hash);
  sqlite3_bind_int(stmt, 8, entry->totp_digit);
  sqlite3_bind_int(stmt, 9, entry->totp_base32);
  sqlite3_bind_text(stmt, 10, entry->created_at, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 11, entry->updated_at, -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 12, VERSION);

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    fprintf(stderr, "Insert failed: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return -1;
  }

  printf("Added entry for '%s'.\n", entry->name);
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return 0;
}

int get_entry(const char *name, data_entry_t *entry, const char *master_pw) {
  if (name == NULL || strlen(name) == 0 || entry == NULL || master_pw == NULL ||
      strlen(master_pw) == 0) {
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

  const char *sql = "SELECT name, password, login, cmd, created_at, updated_at, "
                "totp_seed, totp_hash, totp_digit, totp_base32, secret FROM unlocky WHERE name = ?;";
  

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

      unsigned long long plain_pw_len = decrypt_value(entry->pw, master_pw, (size_t)pw_len);
      if (plain_pw_len == 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
      }
    }

    const unsigned char *secret_blob = sqlite3_column_blob(stmt, 10);
    int secret_len = sqlite3_column_bytes(stmt, 10);
    if (secret_blob && secret_len > 0) {
      memcpy(entry->secret, secret_blob, secret_len < MAX_SECRET_LEN ? secret_len : MAX_SECRET_LEN - 1);
      entry->secret[MAX_SECRET_LEN - 1] = '\0';

      unsigned long long plain_secret_len = decrypt_value(entry->secret, master_pw, (size_t)secret_len);
      if (plain_secret_len == 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
      }
    }

    const unsigned char *login_blob = sqlite3_column_blob(stmt, 2);
    int login_len = sqlite3_column_bytes(stmt, 2);
    if (login_blob && login_len > 0) {
      memcpy(entry->login, login_blob, login_len < MAX_LOGIN_LEN ? login_len : MAX_LOGIN_LEN - 1);
      entry->login[MAX_LOGIN_LEN - 1] = '\0';

      unsigned long long plain_login_len = decrypt_value(entry->login, master_pw, (size_t)login_len);
      if (plain_login_len == 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
      }
    }

    const unsigned char *cmd_blob = sqlite3_column_blob(stmt, 3);
    int cmd_len = sqlite3_column_bytes(stmt, 3);
    if (cmd_blob && cmd_len > 0) {
      memcpy(entry->cmd, cmd_blob, cmd_len < MAX_CMD_LEN ? cmd_len : MAX_CMD_LEN - 1);
      entry->cmd[MAX_CMD_LEN - 1] = '\0';

      unsigned long long plain_cmd_len = decrypt_value(entry->cmd, master_pw, (size_t)cmd_len);
      if (plain_cmd_len == 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
      }
    }

    const unsigned char *totp_blob = sqlite3_column_blob(stmt, 6);
    int totp_len = sqlite3_column_bytes(stmt, 6);
    int totp_hash = sqlite3_column_int(stmt, 7);
    int totp_digit = sqlite3_column_int(stmt, 8);
    int totp_base32 = sqlite3_column_int(stmt, 9);
    if (totp_blob && totp_len > 0) {
      entry->totp_hash = totp_hash;
      entry->totp_digit = totp_digit;
      entry->totp_base32 = totp_base32;
      memcpy(entry->totp_seed, totp_blob,
             totp_len < MAX_PW_LEN ? totp_len : MAX_PW_LEN - 1);
      entry->totp_seed[MAX_PW_LEN - 1] = '\0';
      unsigned long long plain_totp_len =
          decrypt_value(entry->totp_seed, master_pw, (size_t)totp_len);

      if (generate_totp(entry->totp_seed, &entry->totp_code, &entry->totp_time, entry->totp_hash, entry->totp_digit, entry->totp_base32) != 0) {
        fprintf(stderr, "TOTP generation failed.\n");
        return -1;
      }
      
      if (plain_totp_len == 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
      }
    }

    const char *col_name = (const char *)sqlite3_column_text(stmt, 0);
    strncpy(entry->name, col_name ? col_name : "", MAX_NAME_LEN - 1);
    entry->name[MAX_NAME_LEN - 1] = '\0';

    if (strlen(entry->cmd) > 0) {
      
      replace_in_string(entry->cmd, SEARCH_VALUE_LOGIN, entry->login,
                        strlen(entry->login));
  
      replace_in_string(entry->cmd, SEARCH_VALUE_PASSWORD, entry->pw,
                        strlen(entry->pw));
      replace_in_string(entry->cmd, SEARCH_VALUE_SECRET, entry->secret,
                        strlen(entry->secret));
      char totp_str[20] = {0};
      sprintf(totp_str, "%06llu", entry->totp_code);
      replace_in_string(entry->cmd, SEARCH_VALUE_TOTP, totp_str,
                        strlen(totp_str));
  
      entry->cmd[MAX_CMD_LEN - 1] = '\0';
    }

    const char *col_created = (const char *)sqlite3_column_text(stmt, 4);
    strncpy(entry->created_at, col_created ? col_created : "",
            sizeof(entry->created_at) - 1);
    entry->created_at[sizeof(entry->created_at) - 1] = '\0';

    const char *col_updated = (const char *)sqlite3_column_text(stmt, 5);
    strncpy(entry->updated_at, col_updated ? col_updated : "",
            sizeof(entry->updated_at) - 1);
    entry->updated_at[sizeof(entry->updated_at) - 1] = '\0';
    
  } else {
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return -1;
  }

  sqlite3_finalize(stmt);
  sqlite3_close(db);

  return 0;
}

int list_entries() {
  sqlite3 *db = NULL;
  int rc = sqlite3_open(DB_PATH, &db);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQlite open failed: %s\n", sqlite3_errmsg(db));
    if (db) {
      sqlite3_close(db);
    }
    return -1;
  }

  const char *sql_count = "SELECT COUNT(*) FROM unlocky;";
  sqlite3_stmt *stmt_count = NULL;
  rc = sqlite3_prepare_v2(db, sql_count, -1, &stmt_count, NULL);
  if (rc != SQLITE_OK) {
    if (stmt_count != NULL) {
      sqlite3_finalize(stmt_count);
    }
    sqlite3_close(db);
    return -1;
  }
  
  int counter = 0;
  if (sqlite3_step(stmt_count) == SQLITE_ROW) {
    counter = sqlite3_column_int(stmt_count, counter);
    printf("Found %d enrtries.\n", counter);
  }

  sqlite3_finalize(stmt_count);

  const char *sql_list = "SELECT name, created_at, updated_at FROM unlocky;";
  sqlite3_stmt *stmt_list = NULL;
  char *sql_err = NULL;
  rc = sqlite3_exec(db, sql_list, list_callback, NULL, &sql_err);
  if (rc != SQLITE_OK) {
    if (stmt_list != NULL) {
      sqlite3_finalize(stmt_list);
    }
    sqlite3_free(sql_err);
    sqlite3_close(db);
    return -1;
  }


  sqlite3_close(db);
  return 0;
}

int delete_entry(const char *name, const char *master_pw) {
  if (name == NULL || master_pw == NULL || strlen(name) == 0 || strlen(master_pw) == 0) {
    fprintf(stderr, "Missing or malformated parameters.\n");
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

  const char *sql = "SELECT name, password FROM unlocky where name = ?;";
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
    char pw[MAX_PW_LEN] = {0};
    if (pw_blob && pw_len > 0) {
      memcpy(pw, pw_blob, pw_len < MAX_PW_LEN ? pw_len : MAX_PW_LEN - 1);
      //pw[MAX_PW_LEN - 1] = '\0';

      unsigned long long plain_pw_len =
          decrypt_value(pw, master_pw, (size_t)pw_len);
      if (plain_pw_len == 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
      }
    }

  }else {
    return -1;
  }

  const char *sql_delete = "DELETE FROM unlocky WHERE name = ?;";
  stmt = NULL;
  rc = sqlite3_prepare_v2(db, sql_delete, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    if (stmt != NULL) {
      sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return -1;
  }
  sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) == SQLITE_DONE) {
    printf("Sucessfully deleted entry.\n");
  }

  // Vacuum to reclaim space (defrag after delete, no pw blob fragments)
  char *err_msg = NULL;
  rc = sqlite3_exec(db, "PRAGMA vacuum;", NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Vacuum failed: %s\n", err_msg);
    sqlite3_free(err_msg);
  }

  sqlite3_close(db);
  return 0;
}

int modify_entry(data_entry_t *entry, const char *master_pw) {
  if (entry == NULL || master_pw == NULL || strlen(master_pw) == 0 || strlen(entry->name) == 0) {
    fprintf(stderr, "Missing or invalid parameters.\n");
    return -1;
  }

  sqlite3 *db = NULL;
  int rc = sqlite3_open(DB_PATH, &db);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to open DB.\n");
    if (db) {
      sqlite3_close(db);
    }
    return -1;
  }

  sqlite3_stmt *stmt = NULL;
  const char *sql_get = "SELECT name, password FROM unlocky WHERE name = ?;";
  rc = sqlite3_prepare_v2(db, sql_get, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Sqlite stmt prep failed.\n");
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return -1;
  }

  sqlite3_bind_text(stmt, 1, entry->name, -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *pw_blob = sqlite3_column_blob(stmt, 1);
    int pw_len = sqlite3_column_bytes(stmt, 1);
    char tmp_pw[MAX_PW_LEN] = {0};
    if (pw_blob && pw_len > 0) {
      memcpy(tmp_pw, pw_blob, pw_len < MAX_PW_LEN ? pw_len : MAX_PW_LEN - 1);
      // entry->pw[MAX_PW_LEN - 1] = '\0';
      unsigned long long plain_pw_len = decrypt_value(tmp_pw, master_pw, (size_t)pw_len);
      
      if (plain_pw_len == 0) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
      }
    }
  }

  bool login = strlen(entry->login) > 0;
  bool password = strlen(entry->pw) > 0;
  bool secret = strlen(entry->secret) > 0;
  bool cmd = strlen(entry->cmd) > 0;
  bool totp = strlen(entry->totp_seed) > 0;
  bool totp_hash = entry->totp_hash == TOTP_HASH_DEFAULT || entry->totp_hash == TOTP_HASH_SHA256;
  bool totp_digit = entry->totp_digit == TOTP_DIGITS_DEFAULT || entry->totp_digit == TOTP_DIGITS_8;
  bool totp_base32 = entry->totp_base32 == TOTP_BASE32_ACTIVE || entry->totp_base32 == TOTP_BASE_INACTIVE;
  int name_pos = 2;
  int login_pos = 2;
  int password_pos = 2;
  int secret_pos = 2;
  int cmd_pos = 2;
  int totp_pos = 2;
  int totp_hash_pos = 2;
  int totp_digit_pos = 2;
  int totp_base32_pos = 2;

  char sql_update[100] = {0};
  strcat(sql_update, "UPDATE unlocky SET updated_at = ?,");
  int steps = 0;
  if (login) {
    strcat(sql_update, " login = ?,");
    steps += 1;
    password_pos += 1;
    secret_pos += 1;
    cmd_pos += 1;
    totp_pos += 1;
    name_pos += 1;
    totp_hash_pos += 1;
    totp_digit_pos += 1;
    totp_base32_pos += 1;
  }
  if (password) {
    strcat(sql_update, " password = ?,");
    steps += 1;
    secret_pos += 1;
    cmd_pos += 1;
    totp_pos += 1;
    name_pos += 1;
    totp_hash_pos += 1;
    totp_digit_pos += 1;
    totp_base32_pos += 1;
  }
  if (cmd) {
    strcat(sql_update, " cmd = ?,");
    steps += 1;
    secret_pos += 1;
    totp_pos += 1;
    name_pos += 1;
    totp_hash_pos += 1;
    totp_digit_pos += 1;
    totp_base32_pos += 1;
  }
  if (totp) {
    strcat(sql_update, " totp_seed = ?,");
    steps += 1;
    secret_pos += 1;
    name_pos += 1;
    totp_hash_pos += 1;
    totp_digit_pos += 1;
    totp_base32_pos += 1;
  }
  if (secret) {
    strcat(sql_update, " secret = ?,");
    steps += 1;
    name_pos += 1;
    totp_hash_pos += 1;
    totp_digit_pos += 1;
    totp_base32_pos += 1;
  }
  if (totp_hash) {
    strcat(sql_update, " totp_hash = ?,");
    totp_digit_pos += 1;
    totp_base32_pos += 1;
    steps += 1;
    name_pos += 1;
  }
  if (totp_digit) {
    strcat(sql_update, " totp_digit = ?,");
    totp_base32_pos += 1;
    steps += 1;
    name_pos += 1;
  }
  if (totp_base32) {
    strcat(sql_update, " totp_base32 = ?,");
    steps += 1;
    name_pos += 1;
  }

  printf("SQL: %s\n", sql_update);
  if (steps > 0) {
    strcat(sql_update, " WHERE name = ?;");
    char *tr = strrchr(sql_update, ',');
    memmove(tr, tr + 1, strlen(tr ));
    rc = sqlite3_prepare_v2(db, sql_update, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Sqlite stmt prep failed.\n");
      sqlite3_finalize(stmt);
      sqlite3_close(db);
      return -1;
    }
    
    sqlite3_bind_text(stmt, name_pos, entry->name, -1, SQLITE_STATIC);

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(entry->updated_at, sizeof(entry->updated_at), "%Y/%m/%d %H:%M:%S",
              tm_info);
    sqlite3_bind_text(stmt, 1, entry->updated_at, -1, SQLITE_STATIC);

    if (login) {
      unsigned long long login_cipher_len = 0;
      login_cipher_len = encrypt_value(entry->login, master_pw);
      if (login_cipher_len == 0) {
        fprintf(stderr, "Login encryption failed.\n");
        return -1;
      }
      sqlite3_bind_blob(stmt, login_pos, entry->login, login_cipher_len, SQLITE_STATIC);
    }
    if (password) {
      unsigned long long password_cipher_len = 0;
      password_cipher_len = encrypt_value(entry->pw, master_pw);
      if (password_cipher_len == 0) {
        fprintf(stderr, "Password encryption failed.\n");
        return -1;
      }
      sqlite3_bind_blob(stmt, password_pos, entry->pw, password_cipher_len, SQLITE_STATIC);
    }
    if (secret) {
      unsigned long long secret_cipher_len = 0;
      secret_cipher_len = encrypt_value(entry->secret, master_pw);
      if (secret_cipher_len == 0) {
        fprintf(stderr, "Password encryption failed.\n");
        return -1;
      }
      sqlite3_bind_blob(stmt, secret_pos, entry->secret, secret_cipher_len, SQLITE_STATIC);
    }
    if (cmd) {
      unsigned long long cmd_cipher_len = 0;
      cmd_cipher_len = encrypt_value(entry->cmd, master_pw);
      if (cmd_cipher_len == 0) {
        fprintf(stderr, "Command encryption failed.\n");
        return -1;
      }
      sqlite3_bind_blob(stmt, cmd_pos, entry->cmd, cmd_cipher_len, SQLITE_STATIC);
    }
    if (totp) {
      unsigned long long totp_cipher_len = 0;
      totp_cipher_len = encrypt_value(entry->totp_seed, master_pw);
      if (totp_cipher_len == 0) {
        fprintf(stderr, "Totp encryption failed.\n");
        return -1;
      }
      sqlite3_bind_blob(stmt, totp_pos, entry->totp_seed, totp_cipher_len, SQLITE_STATIC);
    }
    if (totp_hash) {
      sqlite3_bind_int(stmt, totp_hash_pos, entry->totp_hash);
    }
    if (totp_digit) {
      printf("Before db: %d\n", entry->totp_digit);
      sqlite3_bind_int(stmt, totp_digit_pos, entry->totp_digit);
    }
    if (totp_base32) {
      sqlite3_bind_int(stmt, totp_base32_pos, entry->totp_base32);
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
      fprintf(stderr, "Update failed: %s\n", sqlite3_errmsg(db));
      sqlite3_finalize(stmt);
      sqlite3_close(db);
      return -1;
    }
  }

  printf("Updated entry for '%s'.\n", entry->name);
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return 0;
}

int list_callback(void *data, int argc, char **argv, char **col_name) {
  (void)data;
  for (int i = 0; i < argc; i++) {
    printf("%s = %s%s", col_name[i], argv[i] ? argv[i] : "NULL", 
           i < argc - 1 ? " | " : "\n");
  }
  return 0;
}

int setup_db() {

  init_db();
  
  sqlite3 *db = NULL;
  int rc = sqlite3_open(DB_PATH, &db);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQlite open failed: %s\n", sqlite3_errmsg(db));
    if (db) {
      sqlite3_close(db);
    }
    return -1;
  }

  // Set SQLite configs for security/performance
  const char *configs[] = {
    "PRAGMA secure_delete = ON;", //override deleted rows with 0s to avoid disk leaks.
    "PRAGMA synchronous = OFF;", // faster writes
    "PRAGMA journal_mode = MEMORY;", // exec once program, in memory is fine
    "PRAGMA threads = 1;" // no multi-thread needed
  };

  char *err_msg = NULL;
  for (int i = 0; i < 4; i++) {
    rc = sqlite3_exec(db, configs[i], NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Config %s failed: %s\n", configs[i], err_msg);
      sqlite3_free(err_msg);
      sqlite3_close(db);
      return -1;
    }
  }
  return 0;
}