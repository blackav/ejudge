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
db_error(struct rldb_mysql_state *state)
{
  err("database error: %s", mysql_error(state->conn));
  return -1;
}
#define db_error_fail(s) do { db_error(s); goto fail; } while (0)

static void
db_wrong_field_count(struct rldb_mysql_state *state, int cnt)
{
  err("wrong database format: field_count == %d, must be %d",
      state->field_count, cnt);
}
#define db_wrong_field_count_fail(s, c) do { db_wrong_field_count(s, c); goto fail; } while (0)

static void
db_no_data(void)
{
  err("database error: no data");
}
#define db_no_data_fail() do { db_no_data(); goto fail; } while (0)

static void
db_inv_value(const char *field)
{
  err("database error: invalid value of field %s", field);
}
#define db_inv_value_fail(s) do { db_inv_value(s); goto fail; } while (0)

static void
my_free_res(struct rldb_mysql_state *state)
{
  if (state->res) mysql_free_result(state->res);
  state->res = 0;
}

static int
my_simple_query(
        struct rldb_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen)
  __attribute__((unused));
static int
my_simple_query(
        struct rldb_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen)
{
  if (state->show_queries) {
    fprintf(stderr, "mysql: %s\n", cmd);
  }
  if (mysql_real_query(state->conn, cmd, cmdlen)) db_error_fail(state);
  return 0;

 fail:
  return -1;
}

static int
my_simple_fquery(
        struct rldb_mysql_state *state,
        const char *format,
        ...)
  __attribute__((format(printf, 2, 3), unused));
static int
my_simple_fquery(
        struct rldb_mysql_state *state,
        const char *format,
        ...)
{
  unsigned char cmdbuf[1024];
  size_t cmdlen;
  va_list args;

  va_start(args, format);
  vsnprintf(cmdbuf, sizeof(cmdbuf), format, args);
  va_end(args);
  cmdlen = strlen(cmdbuf);
  return my_simple_query(state, cmdbuf, cmdlen);
}

static int
my_query(
        struct rldb_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum)
{
  if (state->show_queries) {
    fprintf(stderr, "mysql: %s\n", cmd);
  }
  if (mysql_real_query(state->conn, cmd, cmdlen)) db_error_fail(state);
  if((state->field_count = mysql_field_count(state->conn)) != colnum)
    db_wrong_field_count_fail(state, colnum);
  if (!(state->res = mysql_store_result(state->conn))) db_error_fail(state);
  if ((state->row_count = mysql_num_rows(state->res)) < 0) goto fail;
  return state->row_count;

 fail:
  my_free_res(state);
  return -1;
}
static int
my_fquery(
        struct rldb_mysql_state *state,
        int colnum,
        const char *format,
        ...)
  __attribute__((format(printf, 3, 4), unused));
static int
my_fquery(
        struct rldb_mysql_state *state,
        int colnum,
        const char *format,
        ...)
{
  unsigned char cmdbuf[1024];
  size_t cmdlen;
  va_list args;

  va_start(args, format);
  vsnprintf(cmdbuf, sizeof(cmdbuf), format, args);
  va_end(args);
  cmdlen = strlen(cmdbuf);
  return my_query(state, cmdbuf, cmdlen, colnum);
}

static int
my_row(struct rldb_mysql_state *state)
  __attribute__((unused));
static int
my_row(struct rldb_mysql_state *state)
{
  int i;

  if (!(state->row = mysql_fetch_row(state->res)))
    db_no_data_fail();
  state->lengths = mysql_fetch_lengths(state->res);

  // extra check...
  for (i = 0; i < state->field_count; i++)
    if (state->row[i] && strlen(state->row[i]) != state->lengths[i])
      db_inv_value_fail("in my_row");
  return 0;

 fail:
  my_free_res(state);
  return -1;
}
