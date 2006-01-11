/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_CFG_H__
#define __USERLIST_CFG_H__ 1

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ispras.ru> */

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

#include "expat_iface.h"
#include "opcaps.h"

#include <stdio.h>

struct userlist_cfg_user_map
{
  struct xml_tree b;

  int system_uid;
  unsigned char *system_user_str;
  unsigned char *local_user_str;
};

struct userlist_cfg
{
  struct xml_tree b;

  int l10n;
  int serialization_key;

  // these strings actually point into another strings in XML tree
  unsigned char *socket_path;
  unsigned char *db_path;
  unsigned char *contests_dir;
  unsigned char *email_program;
  unsigned char *register_url;
  unsigned char *register_email;
  unsigned char *admin_email;
  unsigned char *l10n_dir;
  unsigned char *serve_path;
  unsigned char *run_path;
  unsigned char *charset;
  unsigned char *config_dir;
  unsigned char *contests_home_dir;
  unsigned char *full_cgi_data_dir;
  unsigned char *compile_home_dir;
  unsigned char *testing_work_dir;
  unsigned char *script_dir;
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
  struct xml_tree *user_map;

  opcaplist_t capabilities;
};

struct userlist_cfg *userlist_cfg_parse(char const *);
struct userlist_cfg *userlist_cfg_free(struct userlist_cfg *);
void userlist_cfg_unparse(struct userlist_cfg *, FILE *);

#endif /* __USERLIST_CFG_H__ */
