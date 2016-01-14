/* -*- mode: c -*- */

/* Copyright (C) 2008-2016 Alexander Chernov <cher@ejudge.ru> */

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

static struct userlist_cookie *
get_cookie_from_pool(
        struct uldb_mysql_state *state,
        unsigned long long val)
  __attribute__((unused));
static int
fetch_cookie(
        struct uldb_mysql_state *state,
        ej_cookie_t val,
        ej_cookie_t client_key,
        struct userlist_cookie **p_c);
static void
unparse_cookie(
        struct uldb_mysql_state *state,
        FILE *fout,
        const struct userlist_cookie *c)
  __attribute__((unused));
static void
remove_cookie_from_pool(
        struct uldb_mysql_state *state,
        unsigned long long val);
static void
remove_cookie_from_pool_by_uid(
        struct uldb_mysql_state *state,
        int user_id);
static void
remove_cookie_from_pool_by_expire(
        struct uldb_mysql_state *state,
        time_t expire);

static struct userlist_contest *
get_cntsreg_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
  __attribute__((unused));
static int
fetch_cntsreg(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        struct userlist_contest **p_c)
  __attribute__((unused));
static void
unparse_cntsreg(
        struct uldb_mysql_state *state,
        FILE *fout,
        int user_id,
        const struct userlist_contest *c)
  __attribute__((unused));
static void
remove_cntsreg_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id);
static void
remove_cntsreg_from_pool_by_uid(
        struct uldb_mysql_state *state,
        int user_id);

static struct userlist_user *
get_login_from_pool(
        struct uldb_mysql_state *state,
        int user_id)
  __attribute__((unused));
static int
fetch_login(
        struct uldb_mysql_state *state,
        int user_id,
        struct userlist_user **p_user)
  __attribute__((unused));
static void
unparse_login(
        struct uldb_mysql_state *state,
        FILE *fout,
        const struct userlist_user *u)
  __attribute__((unused));
static void
remove_login_from_pool(
        struct uldb_mysql_state *state,
        int user_id)
  __attribute__((unused));

static struct userlist_user_info *
get_user_info_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
  __attribute__((unused));
static int
fetch_user_info(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        struct userlist_user_info **p_ui)
  __attribute__((unused));
static void
unparse_user_info(
        struct uldb_mysql_state *state,
        FILE *fout,
        int user_id,
        const struct userlist_user_info *ui)
  __attribute__((unused));
static void
remove_user_info_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id);
static void
remove_user_info_from_pool_by_uid(
        struct uldb_mysql_state *state,
        int user_id);

static struct userlist_members *
get_member_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
  __attribute__((unused));
static int
fetch_member(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        struct userlist_members **p_mm)
  __attribute__((unused));
static void
unparse_member(
        struct uldb_mysql_state *state,
        FILE *fout,
        int user_id,
        int contest_id,
        const struct userlist_member *m)
  __attribute__((unused));
static void
remove_member_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id);
static void
remove_member_from_pool_by_uid(
        struct uldb_mysql_state *state,
        int user_id);
