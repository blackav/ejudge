/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/trie.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

static const char *progname = "";

static void die(const char *format, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: fatal: %s\n", progname, buf);
  exit(1);
}

int
main(int argc, char *argv[])
{
    if (!argc) return 0;
    progname = argv[0];

    if (argc != 3) die("wrong number of arguments");

    const char *input_name = argv[1];
    const char *table_prefix = argv[2];

    FILE *fin = fopen(input_name, "r");
    if (!fin) die("cannot open input file '%s': %s", input_name, strerror(errno));

    unsigned char **strs = NULL;
    size_t stra = 0, stru = 0;
    size_t bufz = 0;
    char *bufs = NULL;
    int state = 0;
    while (1) {
        ssize_t res = getline(&bufs, &bufz, fin);
        if (res < 0) {
            if (!state) die("no string table");
            if (state == 1) die("unexpected EOF");
            break;
        }
        if (res > 0) {
            while (res > 0 && isspace((unsigned char) bufs[res - 1])) --res;
            bufs[res] = 0;
        }
        if (strstr(bufs, "TRIE_STRINGS_BEGIN") != NULL) {
            state = 1;
        } else if (strstr(bufs, "TRIE_STRINGS_END") != NULL) {
            state = 2;
        } else if (state == 1) {
            char *c1 = strchr(bufs, '"');
            if (c1) {
                char *c2 = strchr(c1 + 1, '"');
                if (c2) {
                    if (stru == stra) {
                        if (!(stra *= 2)) stra = 32;
                        strs = realloc(strs, stra * sizeof(strs[0]));
                    }
                    int len = c2 - c1 - 1;
                    unsigned char *s = malloc(len + 1);
                    memcpy(s, c1 + 1, len);
                    s[len] = 0;
                    strs[stru++] = s;
                }
            }
        }
    }

    struct trie_data *trie = trie_compile_16(stru, strs);
    if (!trie) die("trie_compile_16 failed");

    trie_generate_c_16(trie, table_prefix, stdout);
}
