#ifndef DB_H
#define DB_H

#include "unlocky.h"
#include <sqlite3.h>
// #include <stdio.h>

#define DB_PATH "unlocky.db"

int init_db();
int add_entry(data_entry_t *entry, char *master_pw);
int modify_entry(data_entry_t *entry);
int delete_entry(const char *name);
int list_entries();
void close_db(void);

#endif // DB_H
