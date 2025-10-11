#ifndef DB_H
#define DB_H

#include "unlocky.h"
#include <sqlite3.h>
#include <stdio.h>

// #define db_path = "./../db/unlocky.db"

int init_db(const char *db_path);
int add_entry(sqlite3 *db, data_entry_t *entry);
int modify_entry(sqlite3 *db, data_entry_t *entry);
int delete_entry(sqlite3 *db, const char *name);
int list_entries(sqlite3 *db);
void close_db(sqlite3 *db);

#endif // DB_H
