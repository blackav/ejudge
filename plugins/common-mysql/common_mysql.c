/* -*- mode: c -*- */

/* Copyright (C) 2008-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "common_mysql.h"
#include "ejudge/xml_utils.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/base64.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <ctype.h>
#include <mysql.h>
#include <errmsg.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *);
static int
prepare_func(
        struct common_plugin_data *,
        const struct ejudge_cfg *,
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
static void
escape_string_func(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *str);
static void
write_datetime_func(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        const struct timeval *ptv);
static int
parse_int64_func(
        struct common_mysql_state *state,
        int index,
        long long *p_val);
static void
unparse_spec_2_func(
        struct common_mysql_state *state,
        FILE *fout,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
        unsigned long long skip_mask,
        const void *data,
        ...);
static void
unparse_spec_3_func(
        struct common_mysql_state *state,
        FILE *fout,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
        unsigned long long skip_mask,
        const void *data,
        ...);
static void
write_escaped_bin_func(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        const struct common_mysql_binary *bin);
static int
simple_query_bin_func(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen);
static void
lock_func(
        struct common_mysql_state *state);
static void
unlock_func(
        struct common_mysql_state *state);

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

  escape_string_func,
  write_datetime_func,
  parse_int64_func,
  unparse_spec_2_func,
  unparse_spec_3_func,
  write_escaped_bin_func,

  simple_query_bin_func,
  lock_func,
  unlock_func,
};

static struct common_plugin_data *
init_func(void)
{
  struct common_mysql_state *state = 0;
  XCALLOC(state, 1);
  state->i = &plugin_common_mysql;
  state->show_queries = 1;
  pthread_mutex_init(&state->m, NULL);
  return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  return 0;
}

static const unsigned char *charset_mappings[][2] =
{
  { "utf-8", "utf8mb4" },
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
  unsigned char bdatabase[1024];
  unsigned char bhost[1024];
  unsigned char bport[1024];
  int vport = 0;
  int len, c;

  bdatabase[0] = 0;
  bhost[0] = 0;
  bport[0] = 0;

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
  while (len > 0 && isspace(buser[len - 1])) { --len; }
  buser[len] = 0;

  if (!fgets(bpwd, sizeof(bpwd), f)) {
    err("%s: cannot read the password line from %s", fname, path);
    goto cleanup;
  }
  if ((len = strlen(bpwd)) > sizeof(bpwd) - 24) {
    err("%s: password is too long in %s", fname, path);
    goto cleanup;
  }
  while (len > 0 && isspace(bpwd[len - 1])) { --len; }
  bpwd[len] = 0;
  if (state->password_file_mode == 1) {
    if (fgets(bdatabase, sizeof(bdatabase), f)) {
      if ((len = strlen(bdatabase)) > sizeof(bdatabase) - 24) {
        err("%s: database is too long in %s", fname, path);
        goto cleanup;
      }
      while (len > 0 && isspace(bdatabase[len - 1])) { --len; }
      bdatabase[len] = 0;
      if (fgets(bhost, sizeof(bhost), f)) {
        if ((len = strlen(bhost)) > sizeof(bhost) - 24) {
          err("%s: host is too long in %s", fname, path);
          goto cleanup;
        }
        while (len > 0 && isspace(bhost[len - 1])) { --len; }
        bhost[len] = 0;
        if (fgets(bport, sizeof(bport), f)) {
          if ((len = strlen(bport)) > sizeof(bport) - 24) {
            err("%s: port is too long in %s", fname, path);
            goto cleanup;
          }
          while (len > 0 && isspace(bport[len - 1])) { --len; }
          bport[len] = 0;
          if (bport[0]) {
            errno = 0;
            char *eptr = NULL;
            long v = strtol(bport, &eptr, 10);
            if (errno || *eptr || (char*) bport == eptr || v < 0 || v >= 65536) {
              err("%s: invalid port value in %s", fname, path);
              goto cleanup;
            }
            vport = v;
          }
        }
      }
    }
  }
  while ((c = getc(f)) && isspace(c));
  if (c != EOF) {
    err("%s: garbage in %s", fname, path);
    goto cleanup;
  }
  fclose(f); f = 0;
  state->user = xstrdup(buser);
  state->password = xstrdup(bpwd);
  if (bdatabase[0]) {
    state->database = xstrdup(bdatabase);
  }
  if (bhost[0]) {
    state->host = xstrdup(bhost);
  }
  if (vport > 0) {
    state->port = vport;
  }

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
        const struct ejudge_cfg *config,
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
      if (xml_parse_int(NULL, "", p->line, p->column, p->text,
                        &state->port) < 0) return -1;
    } else if (!strcmp(p->name[0], "password_file_mode")) {
      if (p->first) return xml_err_attrs(p);
      if (p->first_down) return xml_err_nested_elems(p);
      if (state->port > 0) return xml_err_elem_redefined(p);
      if (xml_parse_int(NULL, "", p->line, p->column, p->text,
                        &state->password_file_mode) < 0) return -1;
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
  if (state->conn) return 0;

  const char *charset = state->charset;
  if (!charset || !*charset) {
    charset = "utf8mb4";
  }
  static unsigned char names_buf[256];
  snprintf(names_buf, sizeof(names_buf), "SET NAMES '%s' ;", charset);

  if (!(state->conn = mysql_init(0))) {
    err("mysql_init failed");
    return -1;
  }
  if (mysql_options(state->conn, MYSQL_INIT_COMMAND, names_buf) < 0) {
    err("mysql_options failed");
    return -1;
  }
  //my_bool flag = 1;
  char flag = 1;
  if (mysql_options(state->conn, MYSQL_OPT_RECONNECT, &flag) < 0) {
    err("mysql_options failed");
    return -1;
  }
  if (!mysql_real_connect(state->conn,
                          state->host, state->user, state->password,
                          state->database, state->port, state->socket, 0))
    return state->i->error(state);
  return 0;
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
  free_res_func(state);
  return do_query(state, cmd, cmdlen);
}

static int
simple_fquery_func(
        struct common_mysql_state *state,
        const char *format,
        ...)
{
  va_list args;
  char *cmd = NULL;
  int cmdlen;
  int ret;

  va_start(args, format);
  cmdlen = vasprintf(&cmd, format, args);
  va_end(args);

  ret = state->i->simple_query(state, cmd, cmdlen);
  free(cmd);
  return ret;
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
  free_res_func(state);
  if (do_query(state, cmd, cmdlen)) db_error_fail(state);
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
  int cmdlen;
  va_list args;
  char *cmd = NULL;
  int ret;

  va_start(args, format);
  cmdlen = vasprintf(&cmd, format, args);
  va_end(args);

  ret = state->i->query(state, cmd, cmdlen, colnum);
  free(cmd);
  return ret;
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
  free_res_func(state);
  if (do_query(state, cmd, cmdlen))
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
  if (!(state->row = mysql_fetch_row(state->res)))
    db_error_no_data_fail(state);
  state->lengths = mysql_fetch_lengths(state->res);

  /*
  // extra check...
  for (int i = 0; i < state->field_count; i++)
    if (state->row[i] && strlen(state->row[i]) != state->lengths[i])
      db_error_inv_value_fail(state, "in my_row");
  */
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

#define DEFAULT_IP "127.0.0.127"

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
  ej_ip4_t *p_ip;
  ej_ip_t *p_ipv6;

  if (field_count >= 0 && field_count != spec_num) {
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
    if (specs[i].format != 'x' && row[i] && strlen(row[i]) != lengths[i]) {
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

    case 'l': {
      long long llv = 0;
      if (row[i]) {
        errno = 0;
        eptr = NULL;
        llv = strtoll(row[i], &eptr, 10);
        if (errno || *eptr) goto invalid_format;
      }
      long long *p_llv = XPDEREF(long long, data, specs[i].offset);
      *p_llv = llv;
      break;
    }

    case 'd':
    case 'e':
      errno = 0;
      eptr = 0;
      x = -1;
      if (row[i]) {
        x = strtol(row[i], &eptr, 10);
        if (errno || *eptr) goto invalid_format;
      }
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
    case 'T': {
      struct timeval *ptv = NULL;
      const char *str = row[i];
      int us = 0;
      ptv = XPDEREF(struct timeval, data, specs[i].offset);
      ptv->tv_sec = 0; ptv->tv_usec = 0;
      if (!str) break;
      // special handling for '0' case
      if (sscanf(str, "%d%n", &x, &n) == 1 && !str[n] && !x) break;
      // 'YYYY-MM-DD hh:mm:ss[.uuuuuu]'
      if (sscanf(str, "%d-%d-%d %d:%d:%d%n",
                 &d_year, &d_mon, &d_day, &d_hour, &d_min, &d_sec, &n) != 6)
        goto invalid_format;
      if (str[n] == '.') {
        str += n + 1; n = 0;
        if (sscanf(str, "%d%n", &us, &n) != 1) goto invalid_format;
      }
      if (str[n]) goto invalid_format;
      if (!d_year && !d_mon && !d_day && !d_hour && !d_min && !d_sec && !us)
        break;
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
      ptv->tv_sec = t;
      ptv->tv_usec = us;
      break;
    }
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
      p_ip = XPDEREF(ej_ip4_t, data, specs[i].offset);
      if (!row[i]) {
        xml_parse_ip(NULL, 0, 0, 0, DEFAULT_IP, p_ip);
      } else if (xml_parse_ip(NULL, 0, 0, 0, row[i], p_ip) < 0) {
        xml_parse_ip(NULL, 0, 0, 0, DEFAULT_IP, p_ip);
      }
      break;
    case 'I':
      p_ipv6 = XPDEREF(ej_ip_t, data, specs[i].offset);
      if (!row[i]) {
        xml_parse_ipv6_2(DEFAULT_IP, p_ipv6);
      } else if (xml_parse_ipv6_2(row[i], p_ipv6) < 0) {
        xml_parse_ipv6_2(DEFAULT_IP, p_ipv6);
      }
      break;
    case 'u': // 128-bit
      p_uq = XPDEREF(ej_cookie_t, data, specs[i].offset);
      if (xml_parse_full_cookie(row[i], p_uq, p_uq + 1) < 0)
        goto invalid_format;
      break;
    case 'U': { // base64u-encoded 256 bit
      char *dst_ptr = XPDEREF(char, data, specs[i].offset);
      if (!row[i] || !lengths[i]) {
        memset(dst_ptr, 0, 32);
      } else if (lengths[i] >= 43) {
        // exact 256 bits or more
        int err_flag = 0;
        base64u_decode(row[i], 43, dst_ptr, &err_flag);
        if (err_flag) goto invalid_format;
      } else {
        memset(dst_ptr, 0, 32);
        int err_flag = 0;
        base64u_decode(row[i], lengths[i], dst_ptr, &err_flag);
        if (err_flag) goto invalid_format;
      }
      break;
    }
    case 'g': {
      ej_uuid_t *dst_ptr = XPDEREF(ej_uuid_t, data, specs[i].offset);
      if (!row[i] || !lengths[i]) {
        memset(dst_ptr, 0, sizeof(*dst_ptr));
      } else {
        if (ej_uuid_parse(row[i], dst_ptr) < 0) goto invalid_format;
      }
      break;
    }

    case 'x': {
      struct common_mysql_binary *bin = XPDEREF(struct common_mysql_binary, data, specs[i].offset);
      if (!row[i]) {
        bin->size = 0;
        bin->data = NULL;
      } else {
        bin->size = lengths[i];
        bin->data = xmemdup(row[i], lengths[i]);
      }
      break;
    }

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
  ej_ip4_t *p_ip;
  ej_ip_t *p_ipv6;
  unsigned char u_buf[64];

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

    case 'l': {
      long long *p_llv = XPDEREF(long long, data, specs[i].offset);
      fprintf(fout, "%s%lld", sep, *p_llv);
      break;
    }

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

    case 'T': {
      const struct timeval *ptv = XPDEREF(struct timeval, data, specs[i].offset);
      write_datetime_func(state, fout, sep, ptv);
      break;
    }
    case 'a':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_date_func(state, fout, sep, *p_time);
      break;

    case 'i':
      p_ip = XPDEREF(ej_ip4_t, data, specs[i].offset);
      fprintf(fout, "%s'%s'", sep, xml_unparse_ip(*p_ip));
      break;

    case 'I':
      p_ipv6 = XPDEREF(ej_ip_t, data, specs[i].offset);
      fprintf(fout, "%s'%s'", sep, xml_unparse_ipv6(p_ipv6));
      break;

    case 'u': // 128-bit
      p_uq = XPDEREF(ej_cookie_t, data, specs[i].offset);
      fprintf(fout, "%s'%s'", sep,
              xml_unparse_full_cookie(u_buf, sizeof(u_buf), p_uq, p_uq + 1));
      break;

    case 'g': {
      ej_uuid_t *p_uuid = XPDEREF(ej_uuid_t, data, specs[i].offset);
      char uuid_str[40];
      if (!ej_uuid_is_nonempty(*p_uuid) && specs[i].null_allowed) {
        fprintf(fout, "%sNULL", sep);
      } else {
        ej_uuid_unparse_r(uuid_str, sizeof(uuid_str), p_uuid, NULL);
        fprintf(fout, "%s'%s'", sep, uuid_str);
      }
      break;
    }

    case 'x': {
      const struct common_mysql_binary *bin = XPDEREF(struct common_mysql_binary, data, specs[i].offset);
      write_escaped_bin_func(state, fout, sep, bin);
      break;
    }

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
escape_string_func(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *str)
{
  size_t len1, len2;
  unsigned char *str2;

  len1 = strlen(str);
  len2 = 2 * len1 + 1;
  str2 = (unsigned char*) alloca(len2);
  mysql_real_escape_string(state->conn, str2, str, len1);
  fprintf(f, "%s", str2);
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

static void
write_datetime_func(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        const struct timeval *ptv)
{
  if (!pfx) pfx = "";

  if (!ptv) {
    fprintf(f, "%sNULL", pfx);
    return;
  }
  if (ptv->tv_sec <= 0) {
    fprintf(f, "%sDEFAULT", pfx);
    return;
  }

  struct tm ttm = {};
  localtime_r(&ptv->tv_sec, &ttm);
  fprintf(f, "%s'%04d-%02d-%02d %02d:%02d:%02d",
          pfx, ttm.tm_year + 1900, ttm.tm_mon + 1, ttm.tm_mday,
          ttm.tm_hour, ttm.tm_min, ttm.tm_sec);
  if (ptv->tv_usec > 0) {
    fprintf(f, ".%06d", (int) ptv->tv_usec);
  }
  fprintf(f, "'");
}

static int
parse_int64_func(
        struct common_mysql_state *state,
        int index,
        long long *p_val)
{
  if (index >= state->field_count) {
    return -1;
  }
  const char *s = state->row[index];
  if (!s) {
    return -1;
  }
  char *eptr = NULL;
  errno = 0;
  long long val = strtoll(s, &eptr, 10);
  if (*eptr || errno || s == eptr) {
    return -1;
  }
  *p_val = val;
  return 0;
}

static void
unparse_spec_2_func(
        struct common_mysql_state *state,
        FILE *fout,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
        unsigned long long skip_mask,
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
  ej_ip4_t *p_ip;
  ej_ip_t *p_ipv6;
  unsigned char u_buf[64];

  va_start(args, data);
  for (i = 0; i < spec_num; ++i) {
    if ((skip_mask & (1ULL << i)) != 0) continue;

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

    case 'l': {
      long long *p_llv = XPDEREF(long long, data, specs[i].offset);
      fprintf(fout, "%s%lld", sep, *p_llv);
      break;
    }

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

    case 'T': {
      const struct timeval *ptv = XPDEREF(struct timeval, data, specs[i].offset);
      write_datetime_func(state, fout, sep, ptv);
      break;
    }
    case 'a':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_date_func(state, fout, sep, *p_time);
      break;

    case 'i':
      p_ip = XPDEREF(ej_ip4_t, data, specs[i].offset);
      fprintf(fout, "%s'%s'", sep, xml_unparse_ip(*p_ip));
      break;

    case 'I':
      p_ipv6 = XPDEREF(ej_ip_t, data, specs[i].offset);
      fprintf(fout, "%s'%s'", sep, xml_unparse_ipv6(p_ipv6));
      break;

    case 'u': // 128-bit
      p_uq = XPDEREF(ej_cookie_t, data, specs[i].offset);
      fprintf(fout, "%s'%s'", sep,
              xml_unparse_full_cookie(u_buf, sizeof(u_buf), p_uq, p_uq + 1));
      break;

    case 'g': {
      ej_uuid_t *p_uuid = XPDEREF(ej_uuid_t, data, specs[i].offset);
      char uuid_str[40];
      if (!ej_uuid_is_nonempty(*p_uuid) && specs[i].null_allowed) {
        fprintf(fout, "%sNULL", sep);
      } else {
        ej_uuid_unparse_r(uuid_str, sizeof(uuid_str), p_uuid, NULL);
        fprintf(fout, "%s'%s'", sep, uuid_str);
      }
      break;
    }

    case 'x': {
      const struct common_mysql_binary *bin = XPDEREF(struct common_mysql_binary, data, specs[i].offset);
      write_escaped_bin_func(state, fout, sep, bin);
      break;
    }

    default:
      err("unhandled format %d", specs[i].format);
      abort();
    }
    sep = ", ";
  }
  va_end(args);
}

static void
unparse_spec_3_func(
        struct common_mysql_state *state,
        FILE *fout,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
        unsigned long long skip_mask,
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
  ej_ip4_t *p_ip;
  ej_ip_t *p_ipv6;
  unsigned char u_buf[64];

  va_start(args, data);
  for (i = 0; i < spec_num; ++i) {
    if ((skip_mask & (1ULL << i)) != 0) continue;

    if (specs[i].format) {
      fprintf(fout, "%s%s = ", sep, specs[i].name);
    }
    switch (specs[i].format) {
    case 0: break;
    case 'q':
      p_uq = XPDEREF(unsigned long long, data, specs[i].offset);
      uq = *p_uq;
      fprintf(fout, "'%016llx'", uq);
      break;

    case 'e':
      p_int = XPDEREF(int, data, specs[i].offset);
      val = *p_int;
      if (val == -1) {
        fprintf(fout, "DEFAULT");
      } else {
        fprintf(fout, "%d", val);
      }
      break;

    case 'l': {
      long long *p_llv = XPDEREF(long long, data, specs[i].offset);
      fprintf(fout, "%lld", *p_llv);
      break;
    }

    case 'd':
      p_int = XPDEREF(int, data, specs[i].offset);
      val = *p_int;
      fprintf(fout, "%d", val);
      break;

    case 'D':
      val = va_arg(args, int);
      fprintf(fout, "%d", val);
      break;

    case 'b':
      p_int = XPDEREF(int, data, specs[i].offset);
      val = *p_int;
      if (val) val = 1;
      fprintf(fout, "%d", val);
      break;

    case 'B':
      val = va_arg(args, int);
      if (val) val = 1;
      fprintf(fout, "%d", val);
      break;

    case 's':
      p_str = XPDEREF(unsigned char *, data, specs[i].offset);
      write_escaped_string_func(state, fout, "", *p_str);
      break;

    case 'S':
      str = va_arg(args, const unsigned char *);
      write_escaped_string_func(state, fout, "", str);
      break;

    case 't':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_timestamp_func(state, fout, "", *p_time);
      break;

    case 'T': {
      const struct timeval *ptv = XPDEREF(struct timeval, data, specs[i].offset);
      write_datetime_func(state, fout, "", ptv);
      break;
    }
    case 'a':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_date_func(state, fout, "", *p_time);
      break;

    case 'i':
      p_ip = XPDEREF(ej_ip4_t, data, specs[i].offset);
      fprintf(fout, "'%s'", xml_unparse_ip(*p_ip));
      break;

    case 'I':
      p_ipv6 = XPDEREF(ej_ip_t, data, specs[i].offset);
      fprintf(fout, "'%s'", xml_unparse_ipv6(p_ipv6));
      break;

    case 'u': // 128-bit
      p_uq = XPDEREF(ej_cookie_t, data, specs[i].offset);
      fprintf(fout, "'%s'",
              xml_unparse_full_cookie(u_buf, sizeof(u_buf), p_uq, p_uq + 1));
      break;

    case 'g': {
      ej_uuid_t *p_uuid = XPDEREF(ej_uuid_t, data, specs[i].offset);
      char uuid_str[40];
      if (!ej_uuid_is_nonempty(*p_uuid) && specs[i].null_allowed) {
        fprintf(fout, "NULL");
      } else {
        ej_uuid_unparse_r(uuid_str, sizeof(uuid_str), p_uuid, NULL);
        fprintf(fout, "'%s'", uuid_str);
      }
      break;
    }

    case 'x': {
      const struct common_mysql_binary *bin = XPDEREF(struct common_mysql_binary, data, specs[i].offset);
      write_escaped_bin_func(state, fout, "", bin);
      break;
    }

    default:
      err("unhandled format %d", specs[i].format);
      abort();
    }
    sep = ", ";
  }
  va_end(args);
}

static void
write_escaped_bin_func(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        const struct common_mysql_binary *bin)
{
  size_t len2;
  unsigned char *str2;

  if (!pfx) pfx = "";
  if (!bin || !bin->data) {
    fprintf(f, "%sNULL", pfx);
    return;
  }

  if (bin->size < 128000) {
    len2 = 2 * bin->size + 1;
    str2 = (unsigned char *) alloca(len2);
    mysql_real_escape_string(state->conn, str2, bin->data, bin->size);
    fprintf(f, "%s'%s'", pfx, str2);
    return;
  }

  len2 = 2 * bin->size + 1;
  str2 = (unsigned char*) malloc(len2);
  mysql_real_escape_string(state->conn, str2, bin->data, bin->size);
  fprintf(f, "%s'%s'", pfx, str2);
  free(str2);
}

static int
simple_query_bin_func(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen)
{
  /*
  if (state->show_queries) {
    fprintf(stderr, "mysql: %s\n", cmd);
  }
  */
  free_res_func(state);
  return do_query(state, cmd, cmdlen);
}

static void
lock_func(
        struct common_mysql_state *state)
{
  pthread_mutex_lock(&state->m);
}

static void
unlock_func(
        struct common_mysql_state *state)
{
  pthread_mutex_unlock(&state->m);
}
