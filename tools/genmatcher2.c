/* Copyright (C) 2020-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static char *
fix_for_c_enum_str(char *s)
{
    for (int i = 0; s[i]; ++i) {
    }
    return s;
}

static int
sort_func(const void *p1, const void *p2)
{
    return strcmp(*(const char**) p1, *(const char **) p2);
}

static void
separate(int low, int high, char **strs, int pos, char **enums, int gen_else, const char *indent, const char *endstr, int after_else)
{
    __attribute__((unused)) int _;
    //fprintf(stderr, "separate(%d, %d, strs, %d, enums, %d, \"%s\", \"%s\")\n", low, high, pos, gen_else, indent, endstr);
    if (high - low <= 0) abort();
    if (high - low == 1) {
        if (!strs[low][pos]) {
            if (after_else) {
                printf(" else ");
            } else {
                printf("%s", indent);
            }
            printf("if (!s[%d]) {\n%s    return %s;\n%s}", pos, indent, enums[low], indent);
            if (gen_else) {
                printf(" else {\n%sreturn 0;\n%s }%s", indent, indent, endstr);
            } else {
                printf("%s", endstr);
            }
        } else {
            if (after_else) {
                printf(" else ");
            } else {
                printf("%s", indent);
            }
            printf("if (");
            while (strs[low][pos]) {
                printf("s[%d] == '%c' && ", pos, strs[low][pos]);
                ++pos;
            }
            printf("!s[%d]) {\n%s    return %s;\n%s}", pos, indent, enums[low], indent);
            if (gen_else) {
                printf(" else {\n%sreturn 0;\n%s }%s", indent, indent, endstr);
            } else {
                printf("%s", endstr);
            }
        }
    } else {
        char *subindent = NULL;
        _ = asprintf(&subindent, "%s    ", indent);
        int need_else = 0;
        while (low < high) {
            int cur = low + 1;
            while (cur < high && strs[cur][pos] == strs[low][pos]) {
                ++cur;
            }
            if (cur - low == 1) {
                separate(low, cur, strs, pos, enums, 0, indent, "", need_else);
            } else {
                int pos2 = pos + 1;
                while (1) {
                    int ind;
                    for (ind = low; ind < cur; ++ind) {
                        if (strs[low][pos2] != strs[ind][pos2])
                            break;
                    }
                    if (ind < cur) break;
                    ++pos2;
                }
                if (pos2 - pos == 1) {
                    if (need_else) printf(" else ");
                    else printf("%s", indent);
                    printf("if (s[%d] == '%c') {\n", pos, strs[low][pos]);
                    separate(low, cur, strs, pos2, enums, 0, subindent, endstr, 0);
                    printf("%s}", indent);
                } else {
                    if (need_else) printf(" else ");
                    else printf("%s", indent);
                    printf("if (");
                    int pos3 = pos;
                    printf("s[%d] == '%c'", pos3, strs[low][pos3]);
                    ++pos3;
                    for (; pos3 < pos2; ++pos3) {
                        printf("&& s[%d] == '%c'", pos3, strs[low][pos3]);
                    }
                    printf(") {\n");
                    separate(low, cur, strs, pos2, enums, 0, subindent, endstr, 0);
                    printf("%s}", indent);
                }
            }
            low = cur;
            need_else = 1;
        }
        printf(" else {\n%s    return 0;\n%s}%s", indent, indent, endstr);
        free(subindent);
    }
}

int
main(int argc, char *argv[])
{
    char *str = NULL;
    size_t strz = 0;
    ssize_t ret;

    char **strs = NULL;
    size_t strsu = 0, strsa = 0;
    char **sorted_strs = NULL;
    char **enums = NULL;

    char *enum_prefix = NULL;
    char *function_name = NULL;
    char *table_name = NULL;
    __attribute__((unused)) int _;

    if (argc > 0) {
        enum_prefix = argv[1];
    }
    if (argc > 1) {
        function_name = argv[2];
    }
    if (argc > 2) {
      table_name = argv[3];
    }
    if (!enum_prefix) enum_prefix = "Tag_";
    if (!function_name) function_name = "match";
    if (!table_name) table_name = "tag_table";

    while ((ret = getline(&str, &strz, stdin)) > 0) {
        while (ret > 0 && isspace((unsigned char) str[ret - 1])) --ret;
        str[ret] = 0;
        if (ret <= 0) {
            str = NULL;
            strz = 0;
            continue;
        }
        if (strlen(str) != ret) {
            fprintf(stderr, "entry has embedded NUL byte\n");
            return 1;
        }

        if (strsu == strsa) {
            if (!(strsa *= 2)) strsa = 16;
            strs = realloc(strs, strsa * sizeof(strs[0]));
        }
        strs[strsu++] = str;

        str = NULL;
        strz = 0;
    }

    if (strsu <= 0) {
        exit(0);
    }

    sorted_strs = calloc(strsu, sizeof(sorted_strs[0]));
    memcpy(sorted_strs, strs, strsu * sizeof(sorted_strs[0]));
    qsort(sorted_strs, strsu, sizeof(strs[0]), sort_func);
    enums = calloc(strsu, sizeof(enums[0]));

    for (int i = 1; i < strsu; ++i) {
        if (!strcmp(sorted_strs[i - 1], sorted_strs[i])) {
            fprintf(stderr, "duplicated entry '%s'\n", sorted_strs[i]);
            return 1;
        }
    }

    // generate enum
    printf("/* This is auto-generated file */\n");
    printf("enum\n"
           "{\n");
    for (int i = 0; i < strsu; ++i) {
        char *fixstr = strdup(strs[i]);
        _ = asprintf(&enums[i], "%s%s", enum_prefix, fix_for_c_enum_str(fixstr));
        free(fixstr);
        printf("    %s", enums[i]);
        if (!i) {
            printf(" = 1");
        }
        if (i != strsu - 1) {
            printf(",");
        }
        printf("\n");
    }
    printf("};\n");
    printf("static __attribute__((unused)) const char * const %s[] =\n"
           "{\n"
           "    0,\n", table_name);
    for (int i = 0; i < strsu; ++i) {
        printf("    \"%s\",\n", strs[i]);
    }
    printf("};\n");
    qsort(enums, strsu, sizeof(strs[0]), sort_func);
    printf("static __attribute__((unused)) int\n"
           "%s(const char *s)\n"
           "{\n", function_name);
    separate(0, strsu, sorted_strs, 0, enums, 1, "    ", "\n", 0);
    printf("    return 0;\n"
           "}\n\n");
}
