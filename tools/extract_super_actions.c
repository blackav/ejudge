/* Copyright (C) 2024 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ejudge/super_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "lib/super_proto.c"

char *xstrdup(const char *s)
{
    return strdup(s);
}

int main(void)
{
    unsigned char action_buf[128];
    __attribute__((unused)) int _;

    printf("// TRIE_STRINGS_BEGIN\n");
    for (int i = 0; i < SSERV_CMD_LAST; ++i) {
        if (super_proto_cmd_names[i]) {
            _ = snprintf(action_buf, sizeof(action_buf), "%s", super_proto_cmd_names[i]);
        } else {
            _ = snprintf(action_buf, sizeof(action_buf), "action_%d", i);
        }
        for (unsigned char *s = action_buf; *s; ++s) {
            if (*s == '_') {
                *s = '-';
            } else {
                *s = tolower(*s);
            }
        }
        printf("\"%s\",\n", action_buf);
    }
    printf("// TRIE_STRINGS_END\n");
}
