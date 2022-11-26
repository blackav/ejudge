/* -*- mode: c -*- */

/* Copyright (C) 2011-2022 Alexander Chernov <cher@ejudge.ru> */

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
#include <ctype.h>
#include <errno.h>
#include <string.h>

static const unsigned char *program_name;
static unsigned char *current_file_path = 0;
static int lineno = -1;

static int disable_tabs = 1;
static int base_indent = 4;
static int max_line_length = 120;

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

  if (!current_file_path) {
    fprintf(stderr, "%s: %s\n", program_name, buf);
  } else if (lineno <= 0) {
    fprintf(stderr, "%s: %s\n", current_file_path, buf);
  } else {
    fprintf(stderr, "%s:%d: %s\n", current_file_path, lineno, buf);
  }
}

static unsigned char *line_buf = 0;
static int line_buf_a = 0;
static int line_buf_u = 0;

static unsigned char *file_buf = 0;
static int file_buf_a = 0;
static int file_buf_u = 0;

enum
{
  STATE_NORMAL = 0,
  STATE_COMMENT = 1,
  STATE_LINE_COMMENT = 2,
  STATE_STRING = 3,
  STATE_CHAR = 4
};

static unsigned char *
get_last_name(const unsigned char *str)
{
  if (!str) return 0;
  char *p = strrchr(str, '/');
  if (!p) return strdup(str);
  return strdup(p + 1);
}

static int
read_line(FILE *in, int *p_err_count)
{
  int c;

  line_buf_u = 0;
  while ((c = getc(in)) != EOF && c != '\n') {
    if (!c) {
      err("line contains \\0 character");
      if (p_err_count) ++*p_err_count;
      c = ' ';
    }
    if (line_buf_u >= line_buf_a) {
      if (line_buf_a <= 0) line_buf_a = 256;
      else line_buf_a *= 2;
      line_buf = (unsigned char*) realloc(line_buf, line_buf_a);
      if (!line_buf) die("out of memory");
    }
    line_buf[line_buf_u++] = c;
  }
  if (c == EOF && !line_buf_u) return -1;
  if (line_buf_u >= line_buf_a) {
    if (line_buf_a <= 0) line_buf_a = 256;
    else line_buf_a *= 2;
    line_buf = (unsigned char*) realloc(line_buf, line_buf_a);
    if (!line_buf) die("out of memory");
  }
  line_buf[line_buf_u] = 0;
  return line_buf_u;
}

static int
valid_space(int c)
{
  if (c == ' ' || c == '\n' || c == '\r') return 1;
  if (!disable_tabs && c == '\t') return 1;
  return 0;
}

static void
try_line_directive(const unsigned char *buf)
{
  const unsigned char *p = buf;
  unsigned char *new_file_path = NULL;

  while (isspace(*p)) ++p;
  if (!*p) return;

  if (*p != '#') return;
  ++p;

  while (isspace(*p)) ++p;
  if (!*p) return;

  if (p[0] != 'l' || p[1] != 'i' || p[2] != 'n' || p[3] != 'e') return;
  p += 4;

  while (isspace(*p)) ++p;
  if (!*p) return;

  if (!isdigit(*p)) return;
  int num = 0;
  char *eptr = NULL;
  errno = 0;
  num = strtol(p, &eptr, 10);
  if (errno || num < 0) return;
  p = (const unsigned char *) eptr;
  if (*p && !isspace(*p)) return;

  while (isspace(*p)) ++p;
  if (!*p) return;

  if (*p != '"') return;
  ++p;
  const unsigned char *q = p;
  while (*p && *p != '"') ++p;
  if (!*p) return;
  int new_len = (int)(p - q);
  new_file_path = malloc(new_len + 1);
  memcpy(new_file_path, q, new_len);
  new_file_path[new_len] = 0;
  ++p;

  while (isspace(*p) && *p != '\n') ++p;
  if (*p && *p != '\n') goto done;

  current_file_path = new_file_path; new_file_path = NULL;
  lineno = num - 1;

done:
  free(new_file_path);
}

static int
process_file(const unsigned char *path)
{
  FILE *in = 0;
  int err_count = 0;
  int i, is_first, col, state;

  if (current_file_path) {
    free(current_file_path);
  }
  current_file_path = get_last_name(path);
  lineno = -1;
  in = fopen(path, "r");
  if (!in) {
    err("failed to open file");
    return -1;
  }

  file_buf_u = 0;

  lineno = 0;
  while (read_line(in, &err_count) >= 0) {
    ++lineno;
    //if (line_buf_u <= 0) continue;
    while (line_buf_u > 0 && valid_space(line_buf[line_buf_u - 1])) {
      --line_buf_u;
    }
    line_buf[line_buf_u] = 0;
    //if (line_buf_u <= 0) continue;
    if (line_buf_u > 0 && line_buf[line_buf_u - 1] == '\t') {
      err("invalid TAB character at the end of line");
      ++err_count;
    } else if (line_buf_u > 0 && line_buf[line_buf_u - 1] < ' ') {
      err("invalid control character at the end of line");
      ++err_count;
    }
    while (line_buf_u > 0 && line_buf[line_buf_u - 1] <= ' ') {
      --line_buf_u;
    }
    line_buf[line_buf_u] = 0;
    //if (line_buf_u <= 0) continue;
    if (line_buf_u > max_line_length) {
      err("line length exceeds %d characters", max_line_length);
      ++err_count;
    }

    try_line_directive(line_buf);

    for (i = 0; i < line_buf_u; ++i) {
      if (disable_tabs && line_buf[i] == '\t') {
        err("invalid TAB character");
        ++err_count;
      } else if (line_buf[i] < ' ' && line_buf[i] != '\t') {
        err("invalid control character");
        ++err_count;
        line_buf[i] = ' ';
      }
    }

    if (file_buf_u + line_buf_u + 2 > file_buf_a) {
      if (file_buf_a <= 0) file_buf_a = 4096;
      while (file_buf_u + line_buf_u + 2 > file_buf_a) {
        file_buf_a *= 2;
      }
      file_buf = (unsigned char*) realloc(file_buf, file_buf_a);
      if (!file_buf) die("out of memory");
    }
    memcpy(file_buf + file_buf_u, line_buf, line_buf_u);
    file_buf_u += line_buf_u;
    file_buf[file_buf_u++] = '\n';
    file_buf[file_buf_u] = 0;

    /*
    pos = 0;
    i = 0;
    while (line_buf[i] && line_buf[i] <= ' ') {
      if (line_buf[i] == '\t') {
        ++i;
        // default tab is 8 characters
        pos = (pos + 8) & ~7;
      } else {
        ++i;
        ++pos;
      }
    }
    */
  }

  // check for stray backslash at the end of line
  lineno = 1;
  for (i = 0; i < file_buf_u; ++i) {
    if (i >= 2 && file_buf[i] == '\n' && file_buf[i - 1] == '\\' && file_buf[i - 2] == '\\') {
      file_buf[i - 2] = ' ';
      file_buf[i - 1] = ' ';
      file_buf[i] = ' ';
      err("\\\\ at the end of line");
      ++err_count;
      ++lineno;
    } else if (i >= 1 && file_buf[i] == '\n' && file_buf[i - 1] == '\\') {
      file_buf[i - 1] = ' ';
      err("stray \\ at the end of line");
      ++err_count;
      ++lineno;
    } else if (file_buf[i] == '\n') {
      ++lineno;
    }
  }

  if (current_file_path) {
    free(current_file_path);
  }
  current_file_path = get_last_name(path);
  lineno = 1;
  is_first = 1;
  col = 0;
  state = STATE_NORMAL;
  for (i = 0; i < file_buf_u; ++i) {
    if (!col) try_line_directive(file_buf + i);
    if (file_buf[i] == '\n') {
      ++lineno;
      is_first = 1;
      col = 0;
      if (state == STATE_LINE_COMMENT) {
        state = STATE_NORMAL;
      } else if (state == STATE_STRING) {
        err("invalid \\n character inside a string");
        ++err_count;
      } else if (state == STATE_CHAR) {
        err("invalid \\n character inside a character");
        ++err_count;
      }
    } else if (file_buf[i] == '\t') {
      col = (col + 8) & ~7;
    } else if (file_buf[i] <= ' ') {
      ++col;
    } else {
      if (state == STATE_NORMAL && is_first && col % base_indent != 0) {
        err("invalid indentation (%d)", col);
        ++err_count;
      }
      is_first = 0;
      if (file_buf[i] == '\\') {
        if (!file_buf[i + 1]) {
          err("stray \\ at the end of file");
          ++err_count;
          ++col;
        } else {
          ++i;
          col += 2;
        }
      } else if (state == STATE_NORMAL && file_buf[i] == '/' && file_buf[i + 1] == '/') {
        state = STATE_LINE_COMMENT;
        col += 2;
        ++i;
      } else if (state == STATE_NORMAL && file_buf[i] == '/' && file_buf[i + 1] == '*') {
        state = STATE_COMMENT;
        col += 2;
        ++i;
      } else if (state == STATE_COMMENT && file_buf[i] == '*' && file_buf[i + 1] == '/') {
        state = STATE_NORMAL;
        col += 2;
        ++i;
      } else if (state == STATE_NORMAL && file_buf[i] == '\'') {
        state = STATE_CHAR;
        ++col;
      } else if (state == STATE_CHAR && file_buf[i] == '\'') {
        state = STATE_NORMAL;
        ++col;
      } else if (state == STATE_NORMAL && file_buf[i] == '\"') {
        state = STATE_STRING;
        ++col;
      } else if (state == STATE_STRING && file_buf[i] == '\"') {
        state = STATE_NORMAL;
        ++col;
      } else {
        ++col;
      }
    }
  }

  //fprintf(stdout, ">>%s<<\n", file_buf);

  fclose(in); in = 0;
  return -err_count;
}

static void
parse_int_env(const unsigned char *env_name, int *p_var)
{
  const unsigned char *s;
  int i;
  char *eptr = 0;

  if (!(s = getenv(env_name))) return;
  for (i = 0; s[i] && isspace(s[i]); ++i) {}
  if (!s[i]) die("invalid value of environment '%s'", env_name);
  errno = 0;
  i = strtol(s, &eptr, 10);
  if (errno != 0 || *eptr) die("invalid value of environment '%s'", env_name);
  if (i < 0) die("invalid value of environment '%s'", env_name);
  *p_var = i;
}

int
main(int argc, char *argv[])
{
  int i = 1;
  int retval = 0;

  program_name = argv[0];

  parse_int_env("EJ_MAX_LINE_LENGTH", &max_line_length);
  parse_int_env("EJ_DISABLE_TABS", &disable_tabs);
  parse_int_env("EJ_BASE_INDENT", &base_indent);

  if (i >= argc) die("no files to check");

  for (; i < argc; ++i) {
    if (process_file(argv[i]) < 0) retval = 1;
  }

  return retval;
}
