#ifndef DB_H
#define DB_H

#include "unlocky.h"
#include <sqlite3.h>
#include <stdbool.h>
// #include <stdio.h>

#define DB_PATH "unlocky.db"

int init_db();
int add_entry(data_entry_t *entry, const char *master_pw);
int get_entry(const char *name, data_entry_t *entry, const char *master_pw);
int modify_entry(data_entry_t *entry, const char *master_pw);
int delete_entry(const char *name, const char *master_pw);
int list_entries();
void close_db(void);

#endif // DB_H
