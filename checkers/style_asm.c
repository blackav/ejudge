/* -*- mode: c -*- */

/* Copyright (C) 2018 Alexander Chernov <cher@ejudge.ru> */

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
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

static const unsigned char *program_name;

static void
die(const char *format, ...)
  __attribute__((noreturn,format(printf, 1, 2)));
static void
die(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", program_name, buf);
  exit(1);
}

static const unsigned char *current_file_path = 0;
static int lineno = 0;
static int errcount = 0;

static void
err(const char *format, ...)
  __attribute__((format(printf, 1, 2)));
static void
err(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  ++errcount;

  if (!current_file_path) {
    fprintf(stderr, "%s: %s\n", program_name, buf);
  } else if (lineno <= 0) {
    fprintf(stderr, "%s: %s\n", current_file_path, buf);
  } else {
    fprintf(stderr, "%s:%d: %s\n", current_file_path, lineno, buf);
  }
}

static void
remove_comments(unsigned char *text)
{
    unsigned char *s = text;
    while (*s) {
        if (*s == '\'' || *s == '\"') {
            int endchar = *s;
            ++s;
            while (1) {
                if (!*s) {
                    err("unexpected EOF in character literal or string");
                    break;
                } else if (*s == '\n') {
                    err("newline inside character literal or string");
                    *s = ' ';
                    ++s;
                } else if (*s == endchar) {
                    ++s;
                    break;
                } else if (*s == '\\') {
                    if (!s[1]) {
                        err("backslash at end of file");
                        ++s;
                    } else if (s[1] == '\n') {
                        err("backslash at end of line");
                        *s = ' ';
                        ++s;
                    } else {
                        *s++ = ' ';
                        *s++ = ' ';
                    }
                } else {
                    *s++ = ' ';
                }
            }
        } else if (*s == '/' && s[1] == '/') {
            while (*s && *s != '\n') {
                *s++ = ' ';
            }
            if (*s == '\n') ++lineno;
        } else if (*s == '/' && s[1] == '*') {
            *s++ = ' ';
            *s++ = ' ';
            while (1) {
                if (!*s) {
                    err("comment close '*/' expected, buf EOF reached");
                    break;
                } else if (*s == '*' && s[1] == '/') {
                    *s++ = ' ';
                    *s++ = ' ';
                    break;
                } else if (*s == '\n') {
                    ++lineno;
                    ++s;
                } else {
                    *s++ = ' ';
                }
            }
        } else {
            ++s;
        }
    }
}

static int
count_lines(const unsigned char *text)
{
    const unsigned char *s = text;
    int count = 0;

    if (!*s) return 0;
    for (; *s; ++s) {
        count += (*s == '\n');
    }
    count += (s[-1] != '\n');
    return count;
}

static unsigned char **
split_for_lines(int line_count, const unsigned char *text)
{
    unsigned char **lines = calloc(line_count, sizeof(lines[0]));
    const unsigned char *s = text;
    int cur = 0;
    while (*s) {
        const unsigned char *q = s;
        while (*q && *q != '\n') {
            ++q;
        }
        if (*q == '\n') ++q;
        if (cur >= line_count) {
            abort();
        }
        int len = q - s;
        lines[cur] = malloc((len + 1) * sizeof(lines[cur][0]));
        memcpy(lines[cur], s, len);
        lines[cur][len] = 0;
        s = q;
        ++cur;
    }
    return lines;
}

static int
trim_lines(int line_count, unsigned char **lines)
{
    for (int i = 0; i < line_count; ++i) {
        unsigned char *s = lines[i];
        int len = strlen(s);
        while (len > 0 && isspace(s[len - 1])) --len;
        s[len] = 0;
    }
    while (line_count > 0 && !lines[line_count - 1][0]) {
        --line_count;
        free(lines[line_count]);
        lines[line_count] = NULL;
    }
    return line_count;
}

static int
isidchar(int c)
{
    return isalnum(c) || c == '$' || c == '_' || c == '.' || c == '@' || c == '?' || c == '(' || c == ')' || c == ',';
}

static void
process_line(const unsigned char *line)
{
    int len = strlen(line);
    if (!len) return;

    if (len > 80) {
        err("line is too long. max. 80 chars allowed");
    }
    int column = 0;
    const unsigned char *s = line;
    while (isspace(*s)) {
        if (*s == '\t') {
            column = (column + 8) & ~7;
            ++s;
        } else if (*s < ' ') {
            err("invalid character with code %d", *s);
            ++s;
        } else {
            ++column;
            ++s;
        }
    }
    if (*s == '#') {
        // do no process preprocessor directives
        return;
    }
    int saved_col = column;
    if (!isidchar(*s)) {
        // something strange, do not process
        return;
    }

    const unsigned char *q = s;
    while (isidchar(*q)) {
        ++q;
        ++column;
    }

    const unsigned char *qq = q;
    while (isspace(*qq)) {
        if (*qq == '\t') {
            column = (column + 8) & ~7;
            ++qq;
        } else if (*qq < ' ') {
            ++qq;
            err("invalid character with code %d", *qq);
        } else {
            ++column;
            ++qq;
        }
    }

    if (*qq == ':') {
        // yes, label
        if (saved_col != 0) {
            err("LABEL must be at column 0");
        }
        if (*qq != *q) {
            err("There must be no whitespace between LABEL and :");
        }
        if (q - s > 6) {
            if (qq[1]) {
                err("LABEL is long, it must be on its own line of code, whithout instruction");
            }
        } else {
        }
        ++column;
        ++qq;
        while (isspace(*qq)) {
            if (*qq == '\t') {
                column = (column + 8) & ~7;
                ++qq;
            } else if (*qq < ' ') {
                err("invalid character with code %d", *qq);
                ++qq;
            } else {
                ++column;
                ++qq;
            }
        }
        s = qq;
        saved_col = column;
    }

    column = saved_col;
    if (!isidchar(*s)) {
        // something strange, do not process
        return;
    }

    q = s;
    while (isidchar(*q)) {
        ++q;
        ++column;
    }

    if (saved_col != 8) {
        err("assembler instruction must start at column 8");
    }
    s = q;
    while (isspace(*s)) {
        if (*s == '\t') {
            column = (column + 8) & ~7;
            ++s;
        } else if (*s < ' ') {
            err("invalid character with code %d", *s);
            ++s;
        } else {
            ++column;
            ++s;
        }
    }
    if (*s) {
        if (column != 16 && column != 24) {
            err("instruction arguments must start at column 16 or 24 (but starts at %d)", column);
        }
    }
}

static int
process_file(const unsigned char *path)
{
    FILE *fin = NULL;
    int retval = 0;
    char *ts = NULL;
    size_t tz = 0;
    unsigned char **lines;

    if (!(fin = fopen(path, "r"))) {
        fprintf(stderr, "cannot open input file '%s': %s\n", path, strerror(errno));
        retval = -1;
        goto cleanup;
    }
    FILE *tf = open_memstream(&ts, &tz);
    int c;
    while ((c = getc_unlocked(fin)) != EOF) {
        putc_unlocked(c, tf);
    }
    fclose(tf); tf = NULL;

    errcount = 0;
    current_file_path = path;
    lineno = 1;

    remove_comments(ts);
    int line_count = count_lines(ts);
    if (!line_count) goto cleanup;
    lines = split_for_lines(line_count, ts);
    line_count = trim_lines(line_count, lines);
    for (int i = 0; i < line_count; ++i) {
        lineno = i + 1;
        process_line(lines[i]);
    }

    if (errcount > 0) retval = -1;

cleanup:
    if (fin) fclose(fin);
    free(ts);
    return retval;
}

int
main(int argc, char *argv[])
{
    int i = 1;
    int retval = 0;

    program_name = argv[0];

  /*
  parse_int_env("EJ_MAX_LINE_LENGTH", &max_line_length);
  parse_int_env("EJ_DISABLE_TABS", &disable_tabs);
  parse_int_env("EJ_BASE_INDENT", &base_indent);
  */

    if (i >= argc) die("no files to check");

    for (; i < argc; ++i) {
      if (process_file(argv[i]) < 0) retval = 1;
    }

    return retval;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
