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

#include "config.h"
#include "ej_limits.h"
#include "common_mysql.h"
#include "xml_utils.h"
#include "pathutl.h"
#include "errlog.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <ctype.h>
#include <mysql.h>
#include <errmsg.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *);
static int
prepare_func(
        struct common_plugin_data *,
        struct ejudge_cfg *,
        struct xml_tree *);
static int
connect_func(struct common_mysql_state *state);
static void
free_res_func(struct common_mysql_state *state);
static int
simple_query_func(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen);
static int
simple_fquery_func(
        struct common_mysql_state *state,
        const char *format,
        ...);
static int
query_func(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum);
static int
fquery_func(
        struct common_mysql_state *state,
        int colnum,
        const char *format,
        ...);
static int
query_one_row_func(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum);
static int
next_row_func(struct common_mysql_state *state);
static int
int_val_func(struct common_mysql_state *state,
        int *p_int,
        int min_val);

static int error_func(struct common_mysql_state *state);
static int error_field_count_func(struct common_mysql_state *state, int cnt);
static int error_no_data_func(struct common_mysql_state *state);
static int error_inv_value_func(struct common_mysql_state *state, const char *field);

static int
parse_spec_func(
        struct common_mysql_state *state,
        int field_count,
        char **row,
        unsigned long *lengths,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
        void *data,
        ...);
static void
unparse_spec_func(
        struct common_mysql_state *state,
        FILE *fout,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
        const void *data,
        ...);

static void
write_escaped_string_func(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        const unsigned char *str);
static void
write_timestamp_func(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        time_t time);
static void
write_date_func(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        time_t time);
static int
parse_int_func(
        struct common_mysql_state *state,
        const unsigned char *str,
        int *p_val);

/* plugin entry point */
struct common_mysql_iface plugin_common_mysql =
{
  {
    {
      sizeof (struct common_mysql_iface),
      EJUDGE_PLUGIN_IFACE_VERSION,
      "common",
      "mysql",
    },
    COMMON_PLUGIN_IFACE_VERSION,
    init_func,
    finish_func,
    prepare_func,
  },
  COMMON_MYSQL_PLUGIN_IFACE_VERSION,

  connect_func,
  free_res_func,

  simple_query_func,
  simple_fquery_func,
  query_func,
  fquery_func,
  query_one_row_func,
  next_row_func,
  int_val_func,

  error_func,
  error_field_count_func,
  error_no_data_func,
  error_inv_value_func,

  parse_spec_func,
  unparse_spec_func,

  write_escaped_string_func,
  write_timestamp_func,
  write_date_func,
  parse_int_func,
};

static struct common_plugin_data *
init_func(void)
{
  struct common_mysql_state *state = 0;
  XCALLOC(state, 1);
  state->i = &plugin_common_mysql;
  state->show_queries = 1;
  return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  return 0;
}

static const unsigned char *charset_mappings[][2] =
{
  { "utf-8", "utf8" },
  { "koi8-r", "koi8r" },

  { 0, 0 },
};

static int
parse_passwd_file(
        struct common_mysql_state *state,
        const unsigned char *path)
{
  FILE *f = 0;
  const unsigned char *fname = __FUNCTION__;
  unsigned char buser[1024];
  unsigned char bpwd[1024];
  int len, c;

  if (!(f = fopen(path, "r"))) {
    err("%s: cannot open password file %s", fname, path);
    goto cleanup;
  }
  if (!fgets(buser, sizeof(buser), f)) {
    err("%s: cannot read the user line from %s", fname, path);
    goto cleanup;
  }
  if ((len = strlen(buser)) > sizeof(buser) - 24) {
    err("%s: user is too long in %s", fname, path);
    goto cleanup;
  }
  while (len > 0 && isspace(buser[--len]));
  buser[++len] = 0;

  if (!fgets(bpwd, sizeof(bpwd), f)) {
    err("%s: cannot read the password line from %s", fname, path);
    goto cleanup;
  }
  if ((len = strlen(bpwd)) > sizeof(bpwd) - 24) {
    err("%s: password is too long in %s", fname, path);
    goto cleanup;
  }
  while (len > 0 && isspace(bpwd[--len]));
  bpwd[++len] = 0;
  while ((c = getc(f)) && isspace(c));
  if (c != EOF) {
    err("%s: garbage in %s", fname, path);
    goto cleanup;
  }
  fclose(f); f = 0;
  state->user = xstrdup(buser);
  state->password = xstrdup(bpwd);

  // debug
  //fprintf(stderr, "login: %s\npassword: %s\n", state->user, state->password);
  return 0;

 cleanup:
  if (f) fclose(f);
  return -1;
}

static int
prepare_func(
        struct common_plugin_data *data,
        struct ejudge_cfg *config,
        struct xml_tree *tree)
{
  struct common_mysql_state *state = (struct common_mysql_state*) data;
  const struct xml_parse_spec *spec = ejudge_cfg_get_spec();
  const struct xml_attr *a = 0;
  struct xml_tree *p = 0;
  const unsigned char *cs = 0;
  int i;
  path_t ppath;

  (void) spec;
  ASSERT(tree->tag == spec->default_elem);
  ASSERT(!strcmp(tree->name[0], "config"));

  if (xml_empty_text_c(tree) < 0) return -1;

  for (a = tree->first; a; a = a->next) {
    ASSERT(a->tag == spec->default_attr);
    if (!strcmp(a->name[0], "show_queries")) {
      if (xml_attr_bool(a, &state->show_queries) < 0) return -1;
    } else {
      return xml_err_attr_not_allowed(p, a);
    }
  }

  for (p = tree->first_down; p; p = p->right) {
    ASSERT(p->tag == spec->default_elem);
    if (!strcmp(p->name[0], "user")) {
      if (xml_leaf_elem(p, &state->user, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "password")) {
      if (xml_leaf_elem(p, &state->password, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "database")) {
      if (xml_leaf_elem(p, &state->database, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "host")) {
      if (xml_leaf_elem(p, &state->host, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "socket")) {
      if (xml_leaf_elem(p, &state->socket, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "table_prefix")) {
      if (xml_leaf_elem(p, &state->table_prefix, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "schema_path")) {
      if (xml_leaf_elem(p, &state->schema_path, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "password_file")) {
      if (xml_leaf_elem(p, &state->password_file, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "port")) {
      if (p->first) return xml_err_attrs(p);
      if (p->first_down) return xml_err_nested_elems(p);
      if (state->port > 0) return xml_err_elem_redefined(p);
      if (xml_parse_int("", p->line, p->column, p->text,
                        &state->port) < 0) return -1;
    } else if (!strcmp(p->name[0], "charset")) {
      if (xml_leaf_elem(p, &state->charset, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "collation")) {
      if (xml_leaf_elem(p, &state->collation, 1, 0) < 0) return -1;
    } else {
      return xml_err_elem_not_allowed(p);
    }
  }

  if (state->password_file) {
    ppath[0] = 0;
    if (os_IsAbsolutePath(state->password_file)) {
      snprintf(ppath, sizeof(ppath), "%s", state->password_file);
    }
#if defined EJUDGE_CONF_DIR
    if (!ppath[0]) {
      snprintf(ppath, sizeof(ppath), "%s/%s", EJUDGE_CONF_DIR,
               state->password_file);
    }
#endif
    if (!ppath[0]) {
      snprintf(ppath, sizeof(ppath), "%s", state->password_file);
    }
    if (parse_passwd_file(state, ppath) < 0) return -1;
  }

  if (!state->user) return xml_err_elem_undefined_s(tree, "user");
  if (!state->password) return xml_err_elem_undefined_s(tree, "password");
  if (!state->database) return xml_err_elem_undefined_s(tree, "database");
  if (!state->table_prefix) state->table_prefix = xstrdup("");
  if (!state->charset) {
    if (config) cs = config->charset;
#if defined EJUDGE_CHARSET
    if (!cs) cs = EJUDGE_CHARSET;
#endif /* EJUDGE_CHARSET */
    // remap charset, since mysql has different charset names
    if (cs) {
      for (i = 0; charset_mappings[i][0]; i++) {
        if (!strcasecmp(charset_mappings[i][0], cs))
          state->charset = xstrdup(charset_mappings[i][1]);
      }
    }
  }

  return 0;
}

static int
connect_func(struct common_mysql_state *state)
{
  unsigned char buf[1024];
  int buflen;

  if (state->conn) return 0;

  if (!(state->conn = mysql_init(0))) {
    err("mysql_init failed");
    return -1;
  }
  if (!mysql_real_connect(state->conn,
                          state->host, state->user, state->password,
                          state->database, state->port, state->socket, 0))
    return state->i->error(state);
  if (state->charset) {
    snprintf(buf, sizeof(buf), "SET NAMES '%s' ;", state->charset);
    buflen = strlen(buf);
    if (mysql_real_query(state->conn, buf, buflen))
      db_error_fail(state);
  }
  return 0;

 fail:
  return -1;
}

static void
free_res_func(struct common_mysql_state *state)
{
  if (state->res) mysql_free_result(state->res);
  state->res = 0;
}

static int
do_query(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen)
{
  int sleep_time = 0;
  int r;
  unsigned char buf[1024];
  int buflen;

  if (!mysql_real_query(state->conn, cmd, cmdlen)) return 0;
  if (mysql_errno(state->conn) != CR_SERVER_GONE_ERROR) db_error_fail(state);

  // try to reconnect
  while (sleep_time != 8) {
    if (state->conn) mysql_close(state->conn);
    state->conn = 0;
    if (sleep_time) {
      sleep(sleep_time);
      sleep_time *= 2;
    } else {
      sleep_time = 1;
    }

    if (!(state->conn = mysql_init(0))) {
      err("mysql_init failed");
      return -1;
    }
    if (mysql_real_connect(state->conn,
                           state->host, state->user, state->password,
                           state->database, state->port, state->socket, 0))
      break;
    r = mysql_errno(state->conn);
    if (r != CR_CONNECTION_ERROR && r != CR_CONN_HOST_ERROR
        && r != CR_SERVER_GONE_ERROR && r != CR_SERVER_LOST)
      db_error_fail(state);
  }

  // reconnected
  info("reconnected to MySQL daemon");
  if (state->charset) {
    snprintf(buf, sizeof(buf), "SET NAMES '%s' ;", state->charset);
    buflen = strlen(buf);
    if (mysql_real_query(state->conn, buf, buflen))
      db_error_fail(state);
  }

  // reissue the query
  if (mysql_real_query(state->conn, cmd, cmdlen))
    db_error_fail(state);
  return 0;

 fail:
  return -1;
}

static int
simple_query_func(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen)
{
  if (state->show_queries) {
    fprintf(stderr, "mysql: %s\n", cmd);
  }
  return do_query(state, cmd, cmdlen);
}

static int
simple_fquery_func(
        struct common_mysql_state *state,
        const char *format,
        ...)
{
  unsigned char cmdbuf[2024];
  size_t cmdlen;
  va_list args;

  va_start(args, format);
  vsnprintf(cmdbuf, sizeof(cmdbuf), format, args);
  va_end(args);
  cmdlen = strlen(cmdbuf);
  return state->i->simple_query(state, cmdbuf, cmdlen);
}

static int
query_func(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum)
{
  if (state->show_queries) {
    fprintf(stderr, "mysql: %s\n", cmd);
  }
  if (do_query(state->conn, cmd, cmdlen)) db_error_fail(state);
  if((state->field_count = mysql_field_count(state->conn)) != colnum)
    db_error_field_count_fail(state, colnum);
  if (!(state->res = mysql_store_result(state->conn))) db_error_fail(state);
  if ((state->row_count = mysql_num_rows(state->res)) < 0) goto fail;
  return state->row_count;

 fail:
  state->i->free_res(state);
  return -1;
}

static int
fquery_func(
        struct common_mysql_state *state,
        int colnum,
        const char *format,
        ...)
{
  unsigned char cmdbuf[2024];
  size_t cmdlen;
  va_list args;

  va_start(args, format);
  vsnprintf(cmdbuf, sizeof(cmdbuf), format, args);
  va_end(args);
  cmdlen = strlen(cmdbuf);
  return state->i->query(state, cmdbuf, cmdlen, colnum);
}

static int
query_one_row_func(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum)
{
  int i;

  if (state->show_queries) {
    fprintf(stderr, "mysql: %s\n", cmd);
  }
  if (do_query(state->conn, cmd, cmdlen))
    db_error_fail(state);
  if((state->field_count = mysql_field_count(state->conn)) != colnum)
    db_error_field_count_fail(state, colnum);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  if ((state->row_count = mysql_num_rows(state->res)) != 1)
    goto fail;
    //db_wrong_row_count_fail(state, 1);
  if (!(state->row = mysql_fetch_row(state->res)))
    db_error_no_data_fail(state);
  state->lengths = mysql_fetch_lengths(state->res);
  // extra check...
  for (i = 0; i < state->field_count; i++)
    if (state->row[i] && strlen(state->row[i]) != state->lengths[i])
      db_error_inv_value_fail(state, "field");
  return 0;

 fail:
  state->i->free_res(state);
  return -1;
}

static int
next_row_func(struct common_mysql_state *state)
{
  int i;

  if (!(state->row = mysql_fetch_row(state->res)))
    db_error_no_data_fail(state);
  state->lengths = mysql_fetch_lengths(state->res);

  // extra check...
  for (i = 0; i < state->field_count; i++)
    if (state->row[i] && strlen(state->row[i]) != state->lengths[i])
      db_error_inv_value_fail(state, "in my_row");
  return 0;

 fail:
  state->i->free_res(state);
  return -1;
}

static int
int_val_func(struct common_mysql_state *state,
        int *p_int,
        int min_val)
{
  if (state->i->next_row(state) < 0) goto fail;
  if (!state->lengths[0]) db_error_inv_value_fail(state, "int_val");
  if (state->i->parse_int(state, state->row[0], p_int) < 0 || *p_int < min_val)
    db_error_inv_value_fail(state, "int_val");
  return 0;

 fail:
  state->i->free_res(state);
  return -1;
}

static int
error_func(struct common_mysql_state *state)
{
  err("database error: %s", mysql_error(state->conn));
  return -1;
}

static int
error_field_count_func(struct common_mysql_state *state, int cnt)
{
  err("wrong database format: field_count == %d, must be %d",
      state->field_count, cnt);
  return -1;
}

static int
error_no_data_func(struct common_mysql_state *state)
{
  err("database error: no data");
  return -1;
}

static int
error_inv_value_func(struct common_mysql_state *state, const char *field)
{
  err("database error: invalid value of field %s", field);
  return -1;
}

static int
parse_spec_func(
        struct common_mysql_state *state,
        int field_count,
        char **row,
        unsigned long *lengths,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
        void *data,
        ...)
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
      // 'YYYY-MM-DD'
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
      //tt.tm_hour = 12;
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
unparse_spec_func(
        struct common_mysql_state *state,
        FILE *fout,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
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
      write_escaped_string_func(state, fout, sep, *p_str);
      break;

    case 'S':
      str = va_arg(args, const unsigned char *);
      write_escaped_string_func(state, fout, sep, str);
      break;

    case 't':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_timestamp_func(state, fout, sep, *p_time);
      break;

    case 'a':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_date_func(state, fout, sep, *p_time);
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

static void
write_escaped_string_func(
        struct common_mysql_state *state,
        FILE *f,
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
write_timestamp_func(
        struct common_mysql_state *state,
        FILE *f,
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
write_date_func(
        struct common_mysql_state *state,
        FILE *f,
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

static int
parse_int_func(
        struct common_mysql_state *state,
        const unsigned char *str,
        int *p_val)
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

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
