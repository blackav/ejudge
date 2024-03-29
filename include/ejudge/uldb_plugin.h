/* -*- c -*- */

#ifndef __ULDB_PLUGIN_H__
#define __ULDB_PLUGIN_H__

/* Copyright (C) 2006-2022 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/iterators.h"

#include <time.h>

struct xml_tree;
struct xml_parse_spec;
struct ejudge_cfg;
struct userlist_user;
struct userlist_cookie;
struct userlist_user_info;
struct userlist_contest;
struct contest_desc;
struct userlist_members;
struct userlist_api_key;

/* version of the plugin interface structure */
#define ULDB_PLUGIN_IFACE_VERSION 3

struct uldb_plugin_iface
{
  struct common_plugin_iface b;
  int uldb_version;

  /*
  // initialize the plugin
  void *(*init)(void);
  // clean-up the plugin
  int (*finish)(void *);
  // parse the configuration settings
  int (*prepare)(void *, struct ejudge_cfg *, struct xml_tree *);
  */
  // open the database
  int (*open)(void *);
  // close the database flushing all the data, if necessary
  int (*close)(void *);
  // check the database, probably upgrading it to the current version
  int (*check)(void *);
  // create a new database
  int (*create)(void*);
  // insert a whole user record
  int (*insert)(void *, const struct userlist_user *, int *);
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
  int (*new_user)(void *,
                  const unsigned char *login,
                  const unsigned char *email,
                  int passwd_method,
                  const unsigned char *reg_passwd,
                  int is_privileged,
                  int is_invisible,
                  int is_banned,
                  int is_locked,
                  int show_login,
                  int show_email,
                  int read_only,
                  int never_clean,
                  int simple_registration);
  // remove a user
  int (*remove_user)(void *, int);
  // find a cookie
  int (*get_cookie)(void *,
                    ej_cookie_t,
                    ej_cookie_t,
                    const struct userlist_cookie **);
  // create a new cookie
  int (*new_cookie)(void *, int user_id,
                    const ej_ip_t *pip, int ssl_flag,
                    ej_cookie_t cookie,
                    time_t,
                    int contest_id,
                    int locale_id,
                    int priv_level,
                    int role, int recovery, int team_login,
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
  int (*touch_login_time)(void *, int, int, time_t);
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
  int (*register_contest)(void *, int, int, int, int, time_t, const struct userlist_contest**);
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
  // set the user fields by its XML
  int (*set_user_xml)(void *, int, int, struct userlist_user *,
                      time_t, int *);
  // copy contest-specific user info to another contest
  int (*copy_user_info)(void *, int, int, int, int, time_t,
                        const struct contest_desc *);
  int (*check_user_reg_data)(void *, int, int);
  // move a particular member to a different role
  int (*move_member)(void *, int, int, int, int, time_t, int *);
  // change the team_login flag of the cookie
  int (*set_cookie_team_login)(void *, const struct userlist_cookie *, int);
  // get the login, basic contest-specific user info, registration
  // and member information
  int (*get_user_info_6)(void *, int, int, const struct userlist_user **, const struct userlist_user_info **, const struct userlist_contest **, const struct userlist_members **);
  // get the login, basic contest-specific user info, and member info
  int (*get_user_info_7)(void *, int, int, const struct userlist_user **, const struct userlist_user_info **, const struct userlist_members **);
  // get the member serial number
  int (*get_member_serial)(void *);
  // set the member serial number
  int (*set_member_serial)(void *, int);
  // unlock the complete user information structure
  void (*unlock_user)(void *, const struct userlist_user *);
  // get the contest registration information
  const struct userlist_contest * (*get_contest_reg)(void *, int, int);
  // drop the cache
  void (*drop_cache)(void *);
  // disable caching
  void (*disable_cache)(void *);
  // enable caching
  void (*enable_cache)(void *);
  // pick up a new login by a template
  int (*try_new_login)(void *, unsigned char *, size_t, const char *, int, int);
  // set the simple_registration flag
  int (*set_simple_reg)(void *, int, int, time_t);
  // get the group iterator
  ptr_iterator_t (*get_group_iterator)(void *);
  // get the group by the group name
  const struct userlist_group*(*get_group_by_name)(void *,const unsigned char*);
  // pick up a new group name by a template
  int (*try_new_group_name)(void *, unsigned char *, size_t, const char *, int, int);
  // create a new group
  int (*create_group)(void *, const unsigned char *, int created_by);
  // remove a group
  int (*remove_group)(void *, int);
  // edit a group field
  int (*edit_group_field)(void *, int, int, const unsigned char *value);
  // clear a group field
  int (*clear_group_field)(void *, int, int);
  // get the group by the group id
  const struct userlist_group *(*get_group)(void *, int);
  // get the group users iterator
  ptr_iterator_t (*get_group_user_iterator)(void *, int);
  // get the group groupmember iterator
  ptr_iterator_t (*get_group_member_iterator)(void *, int);
  // create a group member
  int (*create_group_member)(void *, int group_id, int user_id);
  // remove a group member
  int (*remove_group_member)(void *, int group_id, int user_id);
  // list users
  ptr_iterator_t (*get_brief_list_iterator_2)(
        void *,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int offset,
        int count,
        int page,
        int sort_field,
        int sort_order,
        int filter_field,
        int filter_op);
  // get the total count of users for the given filter
  int (*get_user_count)(
        void *,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int filter_field,
        int filter_op,
        int new_mode,
        long long *p_count);
  // get the group iterator
  ptr_iterator_t (*get_group_iterator_2)(void *, const unsigned char *filter, int offset, int count);
  // get the total number of groups to display
  int (*get_group_count)(void *, const unsigned char *filter, long long *p_count);
  // get the previous user
  int (*get_prev_user_id)(void *, int contest_id, int group_id, int user_id, const unsigned char *filter, int *p_user_id);
  // get the next user
  int (*get_next_user_id)(void *, int contest_id, int group_id, int user_id, const unsigned char *filter, int *p_user_id);
  // create a new 128-bit cookie
  int (*new_cookie_2)(
        void *,
        int user_id,
        const ej_ip_t *pip,
        int ssl_flag,
        ej_cookie_t cookie,
        ej_cookie_t client_key,
        time_t expire,
        int contest_id,
        int locale_id,
        int priv_level,
        int role,
        int recovery,
        int team_login,
        int is_ws,
        int is_job,
        const struct userlist_cookie **);
  // find a client key, returns any cookie which matches the given client_key
  int (*get_client_key)(void *,
                        ej_cookie_t,
                        const struct userlist_cookie **);
  // create a new API key
  int (*new_api_key)(
        void *,
        struct userlist_api_key *,
        const struct userlist_api_key **);
  // get an existing API key
  int (*get_api_key)(
        void *,
        const char *token,
        const struct userlist_api_key **);
  // get an existing API key by secret part
  int (*get_api_key_secret)(
        void *,
        const char *secret,
        const struct userlist_api_key **);
  // get the count of the user API keys
  int (*get_api_keys_count)(
        void *,
        int user_id);
  // get API keys for a user
  int (*get_api_keys_for_user)(
        void *,
        int user_id,
        const struct userlist_api_key ***);
  // remove API key
  int (*remove_api_key)(
        void *,
        int user_id,
        const char *token);
};

/* default plugin: compiled into userlist-server */
extern struct uldb_plugin_iface uldb_plugin_xml;

#endif /* __ULDB_PLUGIN_H__ */
