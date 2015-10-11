/* -*- c -*- */

#ifndef __EJUDGE_CFG_H__
#define __EJUDGE_CFG_H__ 1

/* Copyright (C) 2002-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/expat_iface.h"
#include "ejudge/opcaps.h"

#include <stdio.h>
#include <time.h>

struct ejudge_plugin
{
  struct xml_tree b;

  unsigned char *name;
  unsigned char *type;
  int load_flag;
  int default_flag;
  unsigned char *path;
  struct xml_tree *data;
};

struct ejudge_cfg_user_map
{
  struct xml_tree b;

  int system_uid;
  unsigned char *system_user_str;
  unsigned char *local_user_str;
};

struct ejudge_cfg;
struct ejudge_cfg_caps_file
{
  unsigned char *base_path;
  unsigned char *path;
  int error_flag;
  struct ejudge_cfg *root;
  time_t last_caps_file_check;
  time_t last_caps_file_mtime;
};

struct ejudge_cfg
{
  struct xml_tree b;

  int l10n;
  int serialization_key;
  int disable_cookie_ip_check; // ignored since 2.3.29
  int enable_cookie_ip_check;  // supported since 2.3.29
  int enable_contest_select;
  int disable_new_users;

  // these strings actually point into other strings in XML tree
  unsigned char *socket_path;
  unsigned char *db_path;
  unsigned char *contests_dir;
  unsigned char *email_program;
  unsigned char *register_url;
  unsigned char *register_email;
  unsigned char *server_name;
  unsigned char *server_name_en;
  unsigned char *server_main_url;
  unsigned char *admin_email;
  unsigned char *l10n_dir;
  unsigned char *run_path;
  unsigned char *charset;
  unsigned char *config_dir;
  unsigned char *contests_home_dir;
  unsigned char *full_cgi_data_dir;
  unsigned char *compile_home_dir;
  unsigned char *testing_work_dir;
  unsigned char *script_dir;
  unsigned char *plugin_dir;
  unsigned char *var_dir;
  unsigned char *userlist_log;
  unsigned char *super_serve_log;
  unsigned char *job_server_log;
  unsigned char *compile_log;
  unsigned char *super_serve_socket;
  unsigned char *super_serve_user;
  unsigned char *super_serve_group;
  unsigned char *userlist_user;
  unsigned char *userlist_group;
  unsigned char *job_server_spool;
  unsigned char *job_server_work;
  unsigned char *new_server_socket;
  unsigned char *new_server_log;
  unsigned char *default_clardb_plugin;
  unsigned char *default_rundb_plugin;
  unsigned char *default_xuser_plugin;
  unsigned char *caps_file;
  struct xml_tree *user_map;
  struct xml_tree *compile_servers;

  opcaplist_t capabilities;
  struct xml_tree *caps_node;

  struct xml_tree *plugin_list;
  struct xml_tree *hosts_options;

  struct ejudge_cfg_caps_file *caps_file_info;
  unsigned char *ejudge_xml_path;
};

struct ejudge_cfg *ejudge_cfg_parse(char const *, int no_system_lookup);
struct ejudge_cfg *ejudge_cfg_free(struct ejudge_cfg *);
struct xml_tree   *ejudge_cfg_free_subtree(struct xml_tree *p);
void ejudge_cfg_unparse(struct ejudge_cfg *, FILE *);
void ejudge_cfg_unparse_plugins(struct ejudge_cfg *cfg, FILE *f);
const struct xml_parse_spec *ejudge_cfg_get_spec(void);
struct xml_tree *
ejudge_cfg_get_plugin_config(
        const struct ejudge_cfg *cfg,
        const unsigned char *type,
        const unsigned char *name);

const unsigned char *
ejudge_cfg_get_host_option(
        const struct ejudge_cfg *cfg,
        unsigned char **host_names,
        const unsigned char *option_name);
int
ejudge_cfg_get_host_option_int(
        const struct ejudge_cfg *cfg,
        unsigned char **host_names,
        const unsigned char *option_name,
        int default_value,
        int error_value);

void
ejudge_cfg_refresh_caps_file(const struct ejudge_cfg *cfg, int force_flag);
struct ejudge_cfg_caps_file *
ejudge_cfg_create_caps_file(const unsigned char *base_path);
struct ejudge_cfg_caps_file *
ejudge_cfg_free_caps_file(struct ejudge_cfg_caps_file *info);

int
ejudge_cfg_opcaps_find(
        const struct ejudge_cfg *cfg,
        const unsigned char *login_str, 
        opcap_t *p_caps);
const unsigned char *
ejudge_cfg_user_map_find(
        const struct ejudge_cfg *cfg,
        const unsigned char *system_user_str);
const unsigned char *
ejudge_cfg_user_map_find_uid(
        const struct ejudge_cfg *cfg,
        int system_user_id);
const unsigned char *
ejudge_cfg_user_map_find_simple(
        const struct ejudge_cfg *cfg,
        const unsigned char *system_user_str);

void
ejudge_cfg_user_map_add(
        struct ejudge_cfg *cfg,
        const unsigned char *unix_login,
        const unsigned char *ejudge_login);
void
ejudge_cfg_caps_add(
        struct ejudge_cfg *cfg,
        const unsigned char *login,
        opcap_t caps);

#endif /* __EJUDGE_CFG_H__ */
