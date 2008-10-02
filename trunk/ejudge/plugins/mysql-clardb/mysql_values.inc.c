/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

static int
parse_int(const unsigned char *str, int *p_val)
{
  char *eptr;
  int val;

  if (!str || !*str) return -1;
  errno = 0;
  val = strtol(str, &eptr, 10);
  if (*eptr || errno) return -1;
  *p_val = val;
  return 0;
}

static void
write_escaped_string(
        FILE *f,
        struct cldb_mysql_state *state,
        const unsigned char *pfx,
        const unsigned char *str)
{
  size_t len1, len2;
  unsigned char *str2;

  if (!pfx) pfx = "";
  if (!str) {
    fprintf(f, "%sNULL", pfx);
    return;
  }

  len1 = strlen(str);
  len2 = 2 * len1 + 1;
  str2 = (unsigned char*) alloca(len2);
  mysql_real_escape_string(state->conn, str2, str, len1);
  fprintf(f, "%s'%s'", pfx, str2);
}

static void
write_timestamp(
        FILE *f,
        struct cldb_mysql_state *state,
        const unsigned char *pfx,
        time_t time)
{
  struct tm *ptm;

  if (!pfx) pfx = "";
  if (time <= 0) {
    fprintf(f, "%sDEFAULT", pfx);
    return;
  }

  ptm = localtime(&time);
  fprintf(f, "%s'%04d-%02d-%02d %02d:%02d:%02d'",
          pfx, ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
          ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}

static void
write_date(
        FILE *f,
        struct cldb_mysql_state *state,
        const unsigned char *pfx,
        time_t time)
{
  struct tm *ptm;

  if (!pfx) pfx = "";
  if (time <= 0) {
    fprintf(f, "%sDEFAULT", pfx);
    return;
  }

  ptm = localtime(&time);
  fprintf(f, "%s'%04d-%02d-%02d'",
          pfx, ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);
}

struct mysql_parse_spec
{
  unsigned char null_allowed;
  unsigned char format;
  const unsigned char *name;
  size_t offset;
  int (*handle_func)();
};

static int
handle_parse_spec(
        int field_count,
        char **row,
        unsigned long *lengths,
        int spec_num,
        const struct mysql_parse_spec *specs,
        void *data, ...)
{
  int i, x, n, d_year, d_mon, d_day, d_hour, d_min, d_sec;
  va_list args;
  int *p_int;
  unsigned char **p_str;
  struct tm tt;
  time_t t;
  time_t *p_time;
  char *eptr;
  unsigned long long uq;
  unsigned long long *p_uq;
  ej_ip_t *p_ip;

  if (field_count != spec_num) {
    err("wrong field_count (%d instead of %d). invalid table format?",
        field_count, spec_num);
    return -1;
  }

  // check non-null and binary data
  for (i = 0; i < spec_num; i++) {
    if (!specs[i].null_allowed && !row[i]) {
      err("column %d (%s) cannot be NULL", i, specs[i].name);
      return -1;
    }
    if (row[i] && strlen(row[i]) != lengths[i]) {
      err("column %d (%s) cannot be binary", i, specs[i].name);
      return -1;
    }
  }

  // parse data
  va_start(args, data);
  for (i = 0; i < spec_num; i++) {
    switch (specs[i].format) {
    case 0: break;
    case 'q':
      errno = 0;
      eptr = 0;
      uq = strtoull(row[i], &eptr, 16);
      if (errno || *eptr) goto invalid_format;
      p_uq = XPDEREF(unsigned long long, data, specs[i].offset);
      *p_uq = uq;
      break;
      
    case 'd':
    case 'e':
      errno = 0;
      eptr = 0;
      x = strtol(row[i], &eptr, 10);
      if (errno || *eptr) goto invalid_format;
      p_int = XPDEREF(int, data, specs[i].offset);
      *p_int = x;
      break;
    case 'D':
      errno = 0;
      eptr = 0;
      x = strtol(row[i], &eptr, 10);
      if (errno || *eptr) goto invalid_format;
      p_int = va_arg(args, int*);
      *p_int = x;
      break;
    case 'b':
      if (sscanf(row[i], "%d%n", &x, &n) != 1 || row[i][n])
        goto invalid_format;
      if (x != 0 && x != 1) goto invalid_format;
      p_int = XPDEREF(int, data, specs[i].offset);
      *p_int = x;
      break;
    case 'B':
      if (sscanf(row[i], "%d%n", &x, &n) != 1 || row[i][n])
        goto invalid_format;
      if (x != 0 && x != 1) goto invalid_format;
      p_int = va_arg(args, int*);
      *p_int = x;
      break;
    case 's':
      p_str = XPDEREF(unsigned char *, data, specs[i].offset);
      if (row[i]) {
        *p_str = xstrdup(row[i]);
      } else {
        *p_str = 0;
      }
      break;
    case 'S':
      p_str = va_arg(args, unsigned char **);
      if (row[i]) {
        *p_str = xstrdup(row[i]);
      } else {
        *p_str = 0;
      }
      break;
    case 't':
      if (!row[i]) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      // special handling for '0' case
      if (sscanf(row[i], "%d%n", &x, &n) == 1 && !row[i][n]
          && !x) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      // 'YYYY-MM-DD hh:mm:ss'
      if (sscanf(row[i], "%d-%d-%d %d:%d:%d%n",
                 &d_year, &d_mon, &d_day, &d_hour, &d_min, &d_sec, &n) != 6
          || row[i][n])
        goto invalid_format;
      if (!d_year && !d_mon && !d_day && !d_hour && !d_min && !d_sec) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      memset(&tt, 0, sizeof(tt));
      tt.tm_year = d_year - 1900;
      tt.tm_mon = d_mon - 1;
      tt.tm_mday = d_day;
      tt.tm_hour = d_hour;
      tt.tm_min = d_min;
      tt.tm_sec = d_sec;
      tt.tm_isdst = -1;
      if ((t = mktime(&tt)) == (time_t) -1) goto invalid_format;
      if (t < 0) t = 0;
      p_time = XPDEREF(time_t, data, specs[i].offset);
      *p_time = t;
      break;
    case 'a':
      if (!row[i]) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      // special handling for '0' case
      if (sscanf(row[i], "%d%n", &x, &n) == 1 && !row[i][n]
          && !x) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      // 'YYYY-MM-DD hh:mm:ss'
      if (sscanf(row[i], "%d-%d-%d%n", &d_year, &d_mon, &d_day, &n) != 3
          || row[i][n])
        goto invalid_format;
      if (!d_year && !d_mon && !d_day) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      memset(&tt, 0, sizeof(tt));
      tt.tm_year = d_year - 1900;
      tt.tm_mon = d_mon - 1;
      tt.tm_mday = d_day;
      tt.tm_hour = 12;
      tt.tm_isdst = -1;
      if ((t = mktime(&tt)) == (time_t) -1) goto invalid_format;
      if (t < 0) t = 0;
      p_time = XPDEREF(time_t, data, specs[i].offset);
      *p_time = t;
      break;
    case 'i':
      p_ip = XPDEREF(ej_ip_t, data, specs[i].offset);
      if (xml_parse_ip(0, 0, 0, row[i], p_ip) < 0) goto invalid_format;
      break;

    default:
      err("unhandled format %d", specs[i].format);
      abort();

    invalid_format:
      err("column %d (%s) format is invalid", i, specs[i].name);
      va_end(args);
      return -1;
    }
  }
  va_end(args);
  return 0;
}

static void
handle_unparse_spec(
        struct cldb_mysql_state *state,
        FILE *fout,
        int spec_num,
        const struct mysql_parse_spec *specs,
        const void *data,
        ...)
{
  int i, val;
  va_list args;
  const unsigned char *sep = "";
  const unsigned char *str;
  unsigned char **p_str;
  const time_t *p_time;
  const int *p_int;
  const unsigned long long *p_uq;
  unsigned long long uq;
  ej_ip_t *p_ip;

  va_start(args, data);
  for (i = 0; i < spec_num; ++i) {
    switch (specs[i].format) {
    case 0: break;
    case 'q':
      p_uq = XPDEREF(unsigned long long, data, specs[i].offset);
      uq = *p_uq;
      fprintf(fout, "%s'%016llx'", sep, uq);
      break;

    case 'e':
      p_int = XPDEREF(int, data, specs[i].offset);
      val = *p_int;
      if (val == -1) {
        fprintf(fout, "%sDEFAULT", sep);
      } else {
        fprintf(fout, "%s%d", sep, val);
      }
      break;

    case 'd':
      p_int = XPDEREF(int, data, specs[i].offset);
      val = *p_int;
      fprintf(fout, "%s%d", sep, val);
      break;

    case 'D':
      val = va_arg(args, int);
      fprintf(fout, "%s%d", sep, val);
      break;

    case 'b':
      p_int = XPDEREF(int, data, specs[i].offset);
      val = *p_int;
      if (val) val = 1;
      fprintf(fout, "%s%d", sep, val);
      break;

    case 'B':
      val = va_arg(args, int);
      if (val) val = 1;
      fprintf(fout, "%s%d", sep, val);
      break;

    case 's':
      p_str = XPDEREF(unsigned char *, data, specs[i].offset);
      write_escaped_string(fout, state, sep, *p_str);
      break;

    case 'S':
      str = va_arg(args, const unsigned char *);
      write_escaped_string(fout, state, sep, str);
      break;

    case 't':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_timestamp(fout, state, sep, *p_time);
      break;

    case 'a':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_date(fout, state, sep, *p_time);
      break;

    case 'i':
      p_ip = XPDEREF(ej_ip_t, data, specs[i].offset);
      fprintf(fout, "%s'%s'", sep, xml_unparse_ip(*p_ip));
      break;

    default:
      err("unhandled format %d", specs[i].format);
      abort();
    }
    sep = ", ";
  }
  va_end(args);
}
