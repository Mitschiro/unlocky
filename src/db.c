#include "./../include/db.h"
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
