#include "unlocky.h"
#include <stdio.h>
#include <string.h>

int replace_in_string(char *dest_str, const char *search_val,
                      const char *replace_value, size_t replace_value_len) {
  // printf("replace_in_string dest_str: %s, search_val: %s, replace_value: %s,
  // "
  //        "replace_value_len: %td\n",
  //        dest_str, search_val, replace_value, replace_value_len);
  char tmp_str[MAX_CMD_LEN];
  char *search_val_pos = strstr(dest_str, search_val);
  // printf("Size of dest_str: %td\n", strlen(dest_str));
  // printf("search_val_pos: %s | %td\n", search_val_pos,
  //       search_val_pos - dest_str);
  if (search_val_pos) {
    //
    memcpy(tmp_str, dest_str, search_val_pos - dest_str);
    printf("After first memcpy: %s\n", tmp_str);
    memcpy(tmp_str + strlen(tmp_str), replace_value, replace_value_len);
    // memmove(tmp_str + strlen(tmp_str), replace_value, replace_value_len);
    printf("After second memcpy: %s\n", tmp_str);

    memcpy(tmp_str + strlen(tmp_str), search_val_pos + strlen(search_val),
           strlen(search_val_pos) - strlen(search_val));
    printf("After third memcpy: %s\n", tmp_str);

    tmp_str[strlen(tmp_str) + 1] = '\0';
    strcpy(dest_str, tmp_str);
    // printf("tmp_str: %s\n", tmp_str);
    //  printf("New search_val_pos: %s\n", search_val_pos);
    printf("New string: %s\n", dest_str);
  }
  return 1;
}
