/* -*- c -*- */
/* $Id$ */

#ifndef __CONTESTS_H__
#define __CONTESTS_H__

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "ej_types.h"
#include "expat_iface.h"
#include "opcaps.h"

#include <stdlib.h>
#include <time.h>

enum
  {
    CONTEST_CONTESTS = 1,
    CONTEST_CONTEST,
    CONTEST_REGISTER_ACCESS,
    CONTEST_USERS_ACCESS,
    CONTEST_MASTER_ACCESS,
    CONTEST_JUDGE_ACCESS,
    CONTEST_TEAM_ACCESS,
    CONTEST_SERVE_CONTROL_ACCESS,
    CONTEST_IP,
    CONTEST_FIELD,
    CONTEST_NAME,
    CONTEST_NAME_EN,
    CONTEST_MAIN_URL,
    CONTEST_CONTESTANTS,
    CONTEST_RESERVES,
    CONTEST_COACHES,
    CONTEST_ADVISORS,
    CONTEST_GUESTS,
    CONTEST_USERS_HEADER_FILE,
    CONTEST_USERS_FOOTER_FILE,
    CONTEST_REGISTER_EMAIL,
    CONTEST_REGISTER_URL,
    CONTEST_LOGIN_TEMPLATE,
    CONTEST_TEAM_URL,
    CONTEST_REGISTRATION_DEADLINE,
    CONTEST_CAP,
    CONTEST_CAPS,
    CONTEST_ROOT_DIR,
    CONTEST_STANDINGS_URL,
    CONTEST_PROBLEMS_URL,
    CONTEST_CLIENT_FLAGS,
    CONTEST_SERVE_USER,
    CONTEST_SERVE_GROUP,
    CONTEST_REGISTER_HEADER_FILE,
    CONTEST_REGISTER_FOOTER_FILE,
    CONTEST_TEAM_HEADER_FILE,
    CONTEST_TEAM_FOOTER_FILE,
    CONTEST_USERS_HEAD_STYLE,
    CONTEST_USERS_PAR_STYLE,
    CONTEST_USERS_TABLE_STYLE,
    CONTEST_USERS_VERB_STYLE,
    CONTEST_USERS_TABLE_FORMAT,
    CONTEST_USERS_TABLE_FORMAT_EN,
    CONTEST_USERS_TABLE_LEGEND,
    CONTEST_USERS_TABLE_LEGEND_EN,
    CONTEST_REGISTER_HEAD_STYLE,
    CONTEST_REGISTER_PAR_STYLE,
    CONTEST_REGISTER_TABLE_STYLE,
    CONTEST_TEAM_HEAD_STYLE,
    CONTEST_TEAM_PAR_STYLE,
    CONTEST_CONF_DIR,
    CONTEST_RUN_USER,
    CONTEST_RUN_GROUP,
    CONTEST_REGISTER_EMAIL_FILE,
    CONTEST_USER_NAME_COMMENT,
    CONTEST_ALLOWED_LANGUAGES,
    CONTEST_CF_NOTIFY_EMAIL,
    CONTEST_CLAR_NOTIFY_EMAIL,
    CONTEST_DAILY_STAT_EMAIL,
    CONTEST_PRIV_HEADER_FILE,
    CONTEST_PRIV_FOOTER_FILE,
    CONTEST_ALLOWED_REGIONS,
    CONTEST_LOGIN_TEMPLATE_OPTIONS,

    CONTEST_LAST_TAG
  };
enum
  {
    CONTEST_A_ID = 1,
    CONTEST_A_DEFAULT,
    CONTEST_A_ALLOW,
    CONTEST_A_DENY,
    CONTEST_A_MANDATORY,
    CONTEST_A_OPTIONAL,
    CONTEST_A_MIN,
    CONTEST_A_MAX,
    CONTEST_A_AUTOREGISTER,
    CONTEST_A_INITIAL,
    CONTEST_A_DISABLE_TEAM_PASSWORD,
    CONTEST_A_LOGIN,
    CONTEST_A_MANAGED,
    CONTEST_A_NEW_MANAGED,
    CONTEST_A_CLEAN_USERS,
    CONTEST_A_RUN_MANAGED,
    CONTEST_A_CLOSED,
    CONTEST_A_INVISIBLE,
    CONTEST_A_SSL,
    CONTEST_A_SIMPLE_REGISTRATION,
    CONTEST_A_SEND_PASSWD_EMAIL,
    CONTEST_A_ASSIGN_LOGINS,
    CONTEST_A_FORCE_REGISTRATION,
    CONTEST_A_DISABLE_NAME,

    CONTEST_LAST_ATTR
  };
enum
  {
    CONTEST_FIRST_FIELD = 1,
    CONTEST_F_HOMEPAGE = CONTEST_FIRST_FIELD,
    CONTEST_F_PHONE,
    CONTEST_F_INST,
    CONTEST_F_INST_EN,
    CONTEST_F_INSTSHORT,
    CONTEST_F_INSTSHORT_EN,
    CONTEST_F_FAC,
    CONTEST_F_FAC_EN,
    CONTEST_F_FACSHORT,
    CONTEST_F_FACSHORT_EN,
    CONTEST_F_CITY,
    CONTEST_F_CITY_EN,
    CONTEST_F_COUNTRY,
    CONTEST_F_COUNTRY_EN,
    CONTEST_F_REGION,
    CONTEST_F_LANGUAGES,

    CONTEST_LAST_FIELD
  };
enum
  {
    CONTEST_M_CONTESTANT,
    CONTEST_M_RESERVE,
    CONTEST_M_COACH,
    CONTEST_M_ADVISOR,
    CONTEST_M_GUEST,
    CONTEST_LAST_MEMBER
  };
enum
  {
    CONTEST_MF_SERIAL = 0,
    CONTEST_MF_FIRSTNAME = 1,
    CONTEST_MF_FIRSTNAME_EN,
    CONTEST_MF_MIDDLENAME,
    CONTEST_MF_MIDDLENAME_EN,
    CONTEST_MF_SURNAME,
    CONTEST_MF_SURNAME_EN,
    CONTEST_MF_STATUS,
    CONTEST_MF_GRADE,
    CONTEST_MF_GROUP,
    CONTEST_MF_GROUP_EN,
    CONTEST_MF_EMAIL,
    CONTEST_MF_HOMEPAGE,
    CONTEST_MF_PHONE,
    CONTEST_MF_INST,
    CONTEST_MF_INST_EN,
    CONTEST_MF_INSTSHORT,
    CONTEST_MF_INSTSHORT_EN,
    CONTEST_MF_FAC,
    CONTEST_MF_FAC_EN,
    CONTEST_MF_FACSHORT,
    CONTEST_MF_FACSHORT_EN,
    CONTEST_MF_OCCUPATION,
    CONTEST_MF_OCCUPATION_EN,
    CONTEST_LAST_MEMBER_FIELD
  };

struct contest_field
{
  struct xml_tree b;
  int mandatory;
  int id;
};

struct contest_ip
{
  struct xml_tree b;
  int allow;
  int ssl;
  unsigned int addr;
  unsigned int mask;
};

struct contest_access
{
  struct xml_tree b;
  int default_is_allow;
};

struct contest_member
{
  struct xml_tree b;
  int min_count;
  int max_count;
  int init_count;
  struct contest_field *fields[CONTEST_LAST_MEMBER_FIELD];
};

struct contest_desc
{
  struct xml_tree b;
  int id;
  unsigned char autoregister;
  unsigned char disable_team_password;
  unsigned char managed;
  unsigned char new_managed;
  unsigned char run_managed;
  unsigned char clean_users;
  unsigned char closed;
  unsigned char invisible;
  unsigned char simple_registration;
  unsigned char send_passwd_email;
  unsigned char assign_logins;
  unsigned char force_registration;
  unsigned char disable_name;

  time_t         reg_deadline;
  unsigned char *name;
  unsigned char *name_en;
  unsigned char *main_url;
  unsigned char *users_header_file;
  unsigned char *users_footer_file;
  unsigned char *register_header_file;
  unsigned char *register_footer_file;
  unsigned char *team_header_file;
  unsigned char *team_footer_file;
  unsigned char *priv_header_file;
  unsigned char *priv_footer_file;
  unsigned char *register_email;
  unsigned char *register_url;
  unsigned char *team_url;
  unsigned char *login_template;
  unsigned char *login_template_options;
  unsigned char *root_dir;
  unsigned char *conf_dir;
  unsigned char *standings_url;
  unsigned char *problems_url;
  unsigned char *serve_user;
  unsigned char *serve_group;
  unsigned char *run_user;
  unsigned char *run_group;
  unsigned char *register_email_file;
  struct contest_access *register_access;
  struct contest_access *users_access;
  struct contest_access *master_access;
  struct contest_access *judge_access;
  struct contest_access *team_access;
  struct contest_access *serve_control_access;
  struct contest_field *fields[CONTEST_LAST_FIELD];
  struct contest_member *members[CONTEST_LAST_MEMBER];
  struct xml_tree *caps_node;
  opcaplist_t capabilities;
  unsigned char *users_head_style;
  unsigned char *users_par_style;
  unsigned char *users_table_style;
  unsigned char *users_verb_style;
  unsigned char *users_table_format;
  unsigned char *users_table_format_en;
  unsigned char *users_table_legend;
  unsigned char *users_table_legend_en;
  unsigned char *register_head_style;
  unsigned char *register_par_style;
  unsigned char *register_table_style;
  unsigned char *team_head_style;
  unsigned char *team_par_style;
  unsigned char *cf_notify_email;
  unsigned char *clar_notify_email;
  unsigned char *daily_stat_email;

  unsigned char *user_name_comment;
  unsigned char *allowed_languages;
  unsigned char *allowed_regions;

  unsigned char client_ignore_time_skew;
  unsigned char client_disable_team;
  unsigned char disable_member_delete;

  time_t last_check_time;
  time_t last_file_time;
};

struct contest_list
{
  struct xml_tree b;

  int id_map_size;
  struct contest_desc **id_map;
};

/* error codes */
enum
{
  CONTEST_ERR_OK = 0,
  CONTEST_ERR_BAD_DIR,
  CONTEST_ERR_BAD_ID,
  CONTEST_ERR_NO_CONTEST,
  CONTEST_ERR_BAD_XML,
  CONTEST_ERR_ID_NOT_MATCH,
  CONTEST_ERR_REMOVED,
  CONTEST_ERR_FILE_CREATION_ERROR,
  CONTEST_ERR_IO_ERROR,
  CONTEST_ERR_LAST
};

int contests_set_directory(unsigned char const *);
int contests_make_path(unsigned char *buf, size_t sz, int num);
int contests_get_list(unsigned char **);
int contests_get(int, const struct contest_desc **);
int contests_load(int number, struct contest_desc **p_cnts);
struct contest_desc *contests_free(struct contest_desc *cnts);
void contests_free_2(struct xml_tree *t);
struct xml_tree *contests_new_node(int tag);

const unsigned char *contests_strerror(int);

/* if the contest has disappeared, use old copy */
int contests_lock(int);
int contests_unlock(int);

int contests_check_ip(int, int, ej_ip_t, int);
int contests_check_register_ip(int, ej_ip_t, int);
int contests_check_register_ip_2(const struct contest_desc *, ej_ip_t, int);
int contests_check_users_ip(int, ej_ip_t, int);
int contests_check_users_ip_2(const struct contest_desc *, ej_ip_t, int);
int contests_check_master_ip(int, ej_ip_t, int);
int contests_check_master_ip_2(const struct contest_desc *, ej_ip_t, int);
int contests_check_judge_ip(int, ej_ip_t, int);
int contests_check_judge_ip_2(const struct contest_desc *, ej_ip_t, int);
int contests_check_team_ip(int, ej_ip_t, int);
int contests_check_team_ip_2(const struct contest_desc *, ej_ip_t, int);
int contests_check_serve_control_ip(int num, ej_ip_t ip, int ssl);
int contests_check_serve_control_ip_2(const struct contest_desc *, ej_ip_t, int);

void contests_set_load_callback(void (*f)(const struct contest_desc *));
void contests_set_unload_callback(void (*f)(const struct contest_desc *));

void contests_write_header(FILE *f, const struct contest_desc *cnts);
int contests_save_xml(struct contest_desc *cnts,
                      const unsigned char *txt1,
                      const unsigned char *txt2,
                      const unsigned char *txt3);
int contests_unparse_and_save(struct contest_desc *cnts,
                              const unsigned char *header,
                              const unsigned char *footer,
                              const unsigned char *add_footer,
                              unsigned char *(*diff_func)(const unsigned char *,
                                                          const unsigned char *),
                              unsigned char **p_diff_txt);

#endif /* __CONTESTS_H__ */
