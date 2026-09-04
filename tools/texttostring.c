/* -*- mode: c -*- */

/* Copyright (C) 2026 Alexander Chernov <cher@ejudge.ru> */

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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

static const char *program_name = NULL;

#define DIE(msg, ...) do { fprintf(stderr, "%s:%s:%d:" msg, program_name, __PRETTY_FUNCTION__, __LINE__, ## __VA_ARGS__); exit(1); } while (0)

int
main(int argc, char *argv[])
{
    int argi = 1;
    const char *var_name = NULL;

    program_name = argv[0];
    while (argi < argc) {
        if (!strcmp(argv[argi], "-i")) {
            // ignore
            ++argi;
        } else if (!strcmp(argv[argi], "-n")) {
            if (argi + 1 >= argc) {
                DIE("argument expected for -i");
            }
            var_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--")) {
            ++argi;
            break;
        } else if (argv[argi][0] == '-') {
            DIE("invalid option '%s'", argv[argi]);
        } else {
            break;
        }
    }
    FILE *in_f = NULL;
    if (argi == argc) {
        in_f = stdin;
    } else {
        if (argi + 1 != argc) {
            DIE("extra command line arguments");
        }
        in_f = fopen(argv[argi], "r");
        if (!in_f) {
            DIE("cannot open '%s': %s", argv[argi], strerror(errno));
        }
    }
    if (!var_name) var_name = "text";

    char *txt_s = NULL;
    size_t txt_z = 0;
    FILE *txt_f = open_memstream(&txt_s, &txt_z);
    int c;
    while ((c = getc_unlocked(in_f)) != EOF) {
        putc_unlocked(c, txt_f);
    }
    fclose(txt_f); txt_f = NULL;
    if (in_f != stdin) fclose(in_f);
    in_f = NULL;

    printf("static unsigned int %s_len = %zu;\n", var_name, txt_z);
    printf("static const unsigned char %s[] = \n", var_name);
    int need_quote = 1;
    for (size_t i = 0; i < txt_z; ++i) {
        if (need_quote) {
            putchar_unlocked('\"');
            need_quote = 0;
        }
        switch ((unsigned char)txt_s[i]) {
        case '\t':
            printf("\\t");
            break;
        case '\n':
            printf("\\n\"\n");
            need_quote = 1;
            break;
        case '\r':
            printf("\\r");
            break;
        case '\'':
            printf("\\\'");
            break;
        case '\"':
            printf("\\\"");
            break;
        case '\\':
            printf("\\\\");
            break;
        case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
        case 8: case 11: case 12: case 14: case 15:
        case 16: case 17: case 18: case 19: case 20: case 21: case 22: case 23:
        case 24: case 25: case 26: case 27: case 28: case 29: case 30: case 31:
        case 127:
            printf("\\%02x", txt_s[i]);
            break;
        default:
            putchar_unlocked(txt_s[i]);
            break;
        }
    }
    if (!need_quote) putchar_unlocked('\"');
    printf(";\n");
}
