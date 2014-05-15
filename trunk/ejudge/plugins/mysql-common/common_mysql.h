/* -*- c -*- */
/* $Id$ */

#ifndef __COMMON_MYSQL_H__
#define __COMMON_MYSQL_H__

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ejudge_plugin.h"
#include "ejudge/common_plugin.h"

struct common_mysql_iface;
struct common_mysql_state;

#ifndef EJUDGE_SKIP_MYSQL

#include <mysql.h>

struct common_mysql_state
{
  struct common_mysql_iface *i;

  // configuration settings
  int port;
  int show_queries;

  unsigned char *user;
  unsigned char *password;
  unsigned char *database;
  unsigned char *host;
  unsigned char *socket;
  unsigned char *table_prefix;
  unsigned char *charset;
  unsigned char *collation;
  unsigned char *password_file;
  unsigned char *schema_path;

  // MYSQL connection
  MYSQL *conn;
  MYSQL_RES *res;
  MYSQL_ROW row;
  unsigned long *lengths;
  int row_count;
  int field_count;
};

#endif /* EJUDGE_SKIP_MYSQL */

struct common_mysql_parse_spec
{
  unsigned char null_allowed;
  unsigned char format;
  const unsigned char *name;
  size_t offset;
  int (*handle_func)();
};

#define COMMON_MYSQL_PLUGIN_IFACE_VERSION 1

struct common_mysql_iface
{
  struct common_plugin_iface b;
  int common_mysql_version;

  int (*connect)(struct common_mysql_state *state);
  void (*free_res)(struct common_mysql_state *state);
  int (*simple_query)(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen);
  int (*simple_fquery)(
        struct common_mysql_state *state,
        const char *format,
        ...)
    __attribute__((format(printf, 2, 3)));
  int (*query)(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum);
  int (*fquery)(
        struct common_mysql_state *state,
        int colnum,
        const char *format,
        ...)
    __attribute__((format(printf, 3, 4)));
  int (*query_one_row)(
        struct common_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum);
  int (*next_row)(struct common_mysql_state *state);
  int (*int_val)(struct common_mysql_state *state,
        int *p_int,
        int min_val);

  int (*error)(struct common_mysql_state *state);
  int (*error_field_count)(struct common_mysql_state *state, int cnt);
  int (*error_no_data)(struct common_mysql_state *state);
  int (*error_inv_value)(struct common_mysql_state *state, const char *field);

  int (*parse_spec)(
        struct common_mysql_state *state,
        int field_count,
        char **row,
        unsigned long *lengths,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
        void *data,
        ...);
  void (*unparse_spec)(
        struct common_mysql_state *state,
        FILE *fout,
        int spec_num,
        const struct common_mysql_parse_spec *specs,
        const void *data,
        ...);

  void (*write_escaped_string)(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        const unsigned char *str);
  void (*write_timestamp)(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        time_t time);
  void (*write_date)(
        struct common_mysql_state *state,
        FILE *f,
        const unsigned char *pfx,
        time_t time);

  int (*parse_int)(
        struct common_mysql_state *state,
        const unsigned char *str,
        int *p_val);
};

#define db_error_fail(s) do { s->i->error(s); goto fail; } while (0)
#define db_error_field_count_fail(s, c) do { s->i->error_field_count(s, c); goto fail; } while (0)
#define db_error_no_data_fail(s) do { s->i->error_no_data(s); goto fail; } while (0)
#define db_error_inv_value_fail(s, f) do { s->i->error_inv_value(s, f); goto fail; } while (0)

#endif /* __COMMON_MYSQL_H__ */
