/* -*- c -*- */
/* $Id$ */

#ifndef __ULDB_PLUGIN_H__
#define __ULDB_PLUGIN_H__

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

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

#include "ejudge_plugin.h"
#include "ej_types.h"

struct xml_tree;
struct xml_parse_spec;
struct ejudge_cfg;
struct userlist_user;
struct userlist_cookie;
struct userlist_user_info;
struct userlist_contest;

struct int_iterator;
typedef struct int_iterator *int_iterator_t;
struct int_iterator
{
  int (*has_next)(int_iterator_t);
  int (*get)(int_iterator_t);
  void (*next)(int_iterator_t);
  void (*destroy)(int_iterator_t);
};

struct ptr_iterator;
typedef struct ptr_iterator *ptr_iterator_t;
struct ptr_iterator
{
  int (*has_next)(ptr_iterator_t);
  const void *(*get)(ptr_iterator_t);
  void (*next)(ptr_iterator_t);
  void (*destroy)(ptr_iterator_t);
};

/* version of the plugin interface structure */
#define ULDB_PLUGIN_IFACE_VERSION 1

struct uldb_plugin_iface
{
  struct ejudge_plugin_iface b;
  int uldb_version;

  // initialize the plugin
  void *(*init)(const struct ejudge_cfg*);
  // parse the configuration settings
  int (*parse)(const struct ejudge_cfg *, struct xml_tree *, void *);
  // open the database
  int (*open)(void *);
  // close the database flushing all the data, if necessary
  int (*close)(void *);
  // check the database, probably upgrading it to the current version
  int (*check)(void *);
  // create a new database
  int (*create)(void*);
  // insert a whole user record
  int (*insert)(void *, const struct userlist_user *);
  // get the full user info (may be expensive!)
  int (*get_user_full)(void *, int, const struct userlist_user **);
  // get the user_id iterator
  int_iterator_t (*get_user_id_iterator)(void *);
  // get the user_id by login
  int (*get_user_by_login)(void *, const unsigned char *);
  // mark the database for syncing, if necessary
  void (*sync)(void *);
  // force syncing
  void (*forced_sync)(void *);
  // get login by the user_id, login allocated on heap
  unsigned char *(*get_login)(void *, int);
  // create a new user
  int (*new_user)(void *, const unsigned char *login,
                  const unsigned char *email,
                  const unsigned char *reg_passwd,
                  int simple_reg_flag);
  // remove a user
  int (*remove_user)(void *, int);
  // find a cookie
  int (*get_cookie)(void *, ej_cookie_t, const struct userlist_cookie **);
  // create a new cookie
  int (*new_cookie)(void *, int user_id,
                    ej_ip_t ip, int ssl_flag,
                    ej_cookie_t cookie, time_t,
                    int contest_id,
                    int locale_id,
                    int priv_level,
                    const struct userlist_cookie **);
  // remove a cookie
  int (*remove_cookie)(void *, const struct userlist_cookie *);
  // remove all user's cookies
  int (*remove_user_cookies)(void *, int);
  // remove expired cookies
  int (*remove_expired_cookies)(void *, time_t);
  // get an iterator over the user's contests
  ptr_iterator_t (*get_user_contest_iterator)(void *, int);
  // remove expired users
  int (*remove_expired_users)(void *, time_t);
  // get the login user info
  int (*get_user_info_1)(void *, int, const struct userlist_user **);
  // get the login and basic contest-specific user info
  int (*get_user_info_2)(void *, int, int, const struct userlist_user **, const struct userlist_user_info **);
  // set the login time
  int (*touch_login_time)(void *, int, time_t);
  // get the login, basic contest-specific user info, and registration
  int (*get_user_info_3)(void *, int, int, const struct userlist_user **, const struct userlist_user_info **, const struct userlist_contest **);
  // change the contest_id for the cookie
  int (*set_cookie_contest)(void *, const struct userlist_cookie *, int);
  // change the locale of the cookie
  int (*set_cookie_locale)(void *, const struct userlist_cookie *, int);
  // change the privilege level of the cookie
  int (*set_cookie_priv_level)(void *, const struct userlist_cookie *, int);
  // get the login, basic contest-specific user info, and registration
  // merged into one structure for further retrieval by unparse
  int (*get_user_info_4)(void *, int, int, const struct userlist_user **);
  // get the all the information about a user for privileged
  // get user information
  int (*get_user_info_5)(void *, int, int, const struct userlist_user **);
  // get an iterator for extracting brief user info (general or contest)
  // iterator iterates over all users
  ptr_iterator_t (*get_brief_list_iterator)(void *, int);
  // get an iterator for standings XML userlist
  ptr_iterator_t (*get_standings_list_iterator)(void *, int);
  // check, that user exists (0 - yes, -1 - no)
  int (*check_user)(void *, int);
  // set the registration password
  int (*set_reg_passwd)(void *, int, int, const unsigned char *, time_t);
  // set the team password
  int (*set_team_passwd)(void *, int, int, int, const unsigned char *, time_t, int *);
  // register a user for contest
  int (*register_contest)(void *, int, int, int, time_t, const struct userlist_contest**);
  // remove a particular member from a user
  int (*remove_member)(void *, int, int, int, time_t, int *);
  // check if the user is read-only
  int (*is_read_only)(void *, int, int);
  // get the user iterator for HTML user info requests
  // userlist_user, userlist_user_info, userlist_member, userlist_contest
  // fields are filled up
  ptr_iterator_t (*get_info_list_iterator)(void *, int, unsigned int);
  // clear the team password
  int (*clear_team_passwd)(void *, int, int, int *);
  // remove a contest registration
  int (*remove_registration)(void *, int, int);
  // set the registration status
  int (*set_reg_status)(void *, int, int, int);
  // set the registration flags
  int (*set_reg_flags)(void *, int, int, int, unsigned int);
  // remove user contest-specific info
  int (*remove_user_contest_info)(void *, int, int);
  // clear the main user info field
  int (*clear_user_field)(void *, int, int, time_t);
  // clear the user_info field
  int (*clear_user_info_field)(void *, int, int, int, time_t, int *);
  // clear the member field
  int (*clear_user_member_field)(void *, int, int, int, int, time_t, int *);
  // set the main user info field
  int (*set_user_field)(void *, int, int, const unsigned char *, time_t);
  // set the user contest-specific info field
  int (*set_user_info_field)(void *, int, int, int, const unsigned char *, time_t, int *);
  // set the user member field
  int (*set_user_member_field)(void *, int, int, int, int, const unsigned char *, time_t, int *);
  // create new member
  int (*new_member)(void *, int, int, int, time_t, int *);
  // maintenance operations
  int (*maintenance)(void *, time_t);
  // change the role of the existing member
  int (*change_member_role)(void *, int, int, int, int, time_t, int *);
  // set the user fields by its XML
  int (*set_user_xml)(void *, int, int, struct userlist_user *,
                      time_t, int *);
};

/* default plugin: compiled into userlist-server */
extern struct uldb_plugin_iface uldb_plugin_xml;

#endif /* __ULDB_PLUGIN_H__ */
