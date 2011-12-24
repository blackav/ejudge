/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_PROTO_H__
#define __USERLIST_PROTO_H__

/* Copyright (C) 2002-2011 Alexander Chernov <cher@ejudge.ru> */

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

/* server requests codes */
enum
  {
    ULS_PASS_FD = 1,
    ULS_STOP,
    ULS_RESTART,
    ULS_REGISTER_NEW,
    ULS_DO_LOGIN,
    ULS_CHECK_COOKIE,
    ULS_DO_LOGOUT,
    ULS_GET_USER_INFO,
    ULS_SET_USER_INFO,
    ULS_SET_PASSWD,
    ULS_GET_USER_CONTESTS,
    ULS_REGISTER_CONTEST,
    ULS_DELETE_MEMBER,
    ULS_LIST_USERS,
    ULS_MAP_CONTEST,
    ULS_ADMIN_PROCESS,
    ULS_GENERATE_TEAM_PASSWORDS,
    ULS_TEAM_LOGIN,
    ULS_TEAM_CHECK_COOKIE,
    ULS_GET_CONTEST_NAME,
    ULS_TEAM_SET_PASSWD,
    ULS_LIST_ALL_USERS,
    ULS_EDIT_REGISTRATION,
    ULS_EDIT_FIELD,
    ULS_DELETE_FIELD,
    ULS_ADD_FIELD,
    ULS_GET_UID_BY_PID,
    ULS_PRIV_LOGIN,
    ULS_PRIV_CHECK_COOKIE,
    ULS_DUMP_DATABASE,
    ULS_PRIV_GET_USER_INFO,
    ULS_PRIV_SET_USER_INFO,
    ULS_PRIV_REGISTER_CONTEST,
    ULS_GENERATE_PASSWORDS,
    ULS_CLEAR_TEAM_PASSWORDS,
    ULS_LIST_STANDINGS_USERS,
    ULS_GET_UID_BY_PID_2,
    ULS_IS_VALID_COOKIE,
    ULS_DUMP_WHOLE_DATABASE,
    ULS_RANDOM_PASSWD,
    ULS_RANDOM_TEAM_PASSWD,
    ULS_COPY_TO_TEAM,
    ULS_COPY_TO_REGISTER,
    ULS_FIX_PASSWORD,
    ULS_LOOKUP_USER,
    ULS_REGISTER_NEW_2,
    ULS_DELETE_USER,
    ULS_DELETE_COOKIE,
    ULS_DELETE_USER_INFO,
    ULS_CREATE_USER,
    ULS_CREATE_MEMBER,
    ULS_PRIV_DELETE_MEMBER,
    ULS_PRIV_CHECK_USER,
    ULS_PRIV_GET_COOKIE,
    ULS_LOOKUP_USER_ID,
    ULS_TEAM_CHECK_USER,
    ULS_TEAM_GET_COOKIE,
    ULS_ADD_NOTIFY,
    ULS_DEL_NOTIFY,
    ULS_SET_COOKIE_LOCALE,
    ULS_PRIV_SET_REG_PASSWD,
    ULS_PRIV_SET_TEAM_PASSWD,
    ULS_GENERATE_TEAM_PASSWORDS_2,
    ULS_GENERATE_PASSWORDS_2,
    ULS_GET_DATABASE,
    ULS_COPY_USER_INFO,
    ULS_RECOVER_PASSWORD_1,
    ULS_RECOVER_PASSWORD_2,
    ULS_PRIV_COOKIE_LOGIN,
    ULS_CHECK_USER,
    ULS_REGISTER_CONTEST_2,
    ULS_GET_COOKIE,
    ULS_EDIT_FIELD_SEQ,
    ULS_MOVE_MEMBER,
    ULS_IMPORT_CSV_USERS,
    ULS_FETCH_COOKIE,
    ULS_LIST_ALL_GROUPS,
    ULS_CREATE_GROUP,
    ULS_DELETE_GROUP,
    ULS_EDIT_GROUP_FIELD,
    ULS_DELETE_GROUP_FIELD,
    ULS_LIST_GROUP_USERS,
    ULS_CREATE_GROUP_MEMBER,
    ULS_DELETE_GROUP_MEMBER,
    ULS_GET_GROUPS,
    ULS_LIST_ALL_USERS_2,
    ULS_GET_USER_COUNT,
    ULS_LIST_ALL_GROUPS_2,
    ULS_GET_GROUP_COUNT,
    ULS_PRIV_SET_REG_PASSWD_PLAIN,
    ULS_PRIV_SET_REG_PASSWD_SHA1,
    ULS_PRIV_SET_CNTS_PASSWD_PLAIN,
    ULS_PRIV_SET_CNTS_PASSWD_SHA1,
    ULS_CREATE_USER_2,
    ULS_PREV_USER,
    ULS_NEXT_USER,
    ULS_LIST_ALL_USERS_3,
    ULS_LIST_ALL_USERS_4,
    ULS_GET_GROUP_INFO,
    ULS_PRIV_CHECK_PASSWORD,

    ULS_LAST_CMD
  };

/* server reply codes (each corresponds to a different packet) */
enum
  {
    ULS_OK = 0,
    ULS_LOGIN_OK,
    ULS_LOGIN_COOKIE,
    ULS_XML_DATA,
    ULS_CONTEST_MAPPED,
    ULS_UID,
    ULS_UID_2,
    ULS_PASSWORD,
    ULS_CLONED,
    ULS_NOTIFICATION,
    ULS_TEXT_DATA,
    ULS_NEW_PASSWORD,
    ULS_TEXT_DATA_FAILURE,
    ULS_COUNT,
  };

/* various error codes */
enum
  {
    ULS_ERR_1 = 1,              /* reserved to return -1 */
    ULS_ERR_LOGIN_USED,
    ULS_ERR_INVALID_LOGIN,
    ULS_ERR_INVALID_PASSWORD,
    ULS_ERR_NO_COOKIE,
    ULS_ERR_BAD_UID,
    ULS_ERR_NO_PERMS,
    ULS_ERR_SEND_FAILED,
    ULS_ERR_OUT_OF_MEM,
    ULS_ERR_RECEIVE_FAILED,
    ULS_ERR_PROTOCOL,
    ULS_ERR_NO_CONNECT,
    ULS_ERR_WRITE_ERROR,
    ULS_ERR_READ_ERROR,
    ULS_ERR_UNEXPECTED_EOF,
    ULS_ERR_XML_PARSE,
    ULS_ERR_NOT_IMPLEMENTED,
    ULS_ERR_INVALID_SIZE,
    ULS_ERR_BAD_CONTEST_ID,
    ULS_ERR_BAD_MEMBER,
    ULS_ERR_IPC_FAILURE,
    ULS_ERR_IP_NOT_ALLOWED,
    ULS_ERR_CANNOT_PARTICIPATE,
    ULS_ERR_NOT_REGISTERED,
    ULS_ERR_CANNOT_DELETE,
    ULS_ERR_CANNOT_CHANGE,
    ULS_ERR_DEADLINE,
    ULS_ERR_DISCONNECT,
    ULS_ERR_EMAIL_FAILED,
    ULS_ERR_INCOMPLETE_REG,
    ULS_ERR_BAD_FIELD,
    ULS_ERR_TRANSITIVE_SHARING,
    ULS_ERR_UNSPECIFIED_ERROR,
    ULS_ERR_DB_ERROR,
    ULS_ERR_SIMPLE_REGISTERED,
    ULS_ERR_GROUP_NAME_USED,
    ULS_ERR_BAD_GROUP_ID,

    ULS_ERR_LAST
  };

unsigned char const *userlist_strerror(int code);
int userlist_str_to_request(const unsigned char *reqs);

struct userlist_table
{
  unsigned int vintage;
};

/* a generic packet structure */
struct userlist_packet
{
  short id;
  char  bytes[0];
};

/* client->server requests packet */
struct userlist_pk_register_new
{
  short         request_id;
  ej_ip_t       origin_ip;
  int           ssl;
  int           contest_id;
  signed char   locale_id;
  int           action;
  int           login_length;
  int           email_length;
  int           self_url_length;
  unsigned char data[3];
};

struct userlist_pk_do_login
{
  short         request_id;
  ej_ip_t       origin_ip;
  int           ssl;
  int           contest_id;
  signed char   locale_id;
  unsigned char priv_level;
  int           role;
  unsigned char login_length;
  unsigned char password_length;
  unsigned char data[2];
};

struct userlist_pk_check_cookie
{
  short              request_id;
  ej_ip_t            origin_ip;
  int                ssl;
  int                contest_id;
  ej_cookie_t        cookie;
  int                priv_level;
  int                role;
};

struct userlist_pk_cookie_login
{
  short              request_id;
  ej_ip_t            origin_ip;
  int                ssl;
  int                contest_id;
  int                locale_id;
  ej_cookie_t        cookie;
  int                role;
};

struct userlist_pk_do_logout
{
  short              request_id;
  ej_ip_t            origin_ip;
  int                ssl;
  ej_cookie_t        cookie;
};

struct userlist_pk_get_user_info
{
  short         request_id;
  int           user_id;
  int           contest_id;
};

struct userlist_pk_set_user_info
{
  short          request_id;
  int            user_id;
  int            contest_id;
  unsigned short info_len;
  unsigned char  data[1];
};

struct userlist_pk_set_password
{
  short         request_id;
  int           user_id;
  int           contest_id;
  unsigned char old_len;
  unsigned char new_len;
  unsigned char data[2];
};

struct userlist_pk_register_contest
{
  short   request_id;
  int     user_id;
  int     contest_id;
  ej_ip_t ip;
  int     ssl_flag;
};

struct userlist_pk_delete_info
{
  short request_id;
  int   user_id;
  int   contest_id;
  int   serial;
};

struct userlist_pk_move_info
{
  short request_id;
  int   user_id;
  int   contest_id;
  int   serial;
  int   new_role;
};

struct userlist_pk_list_users
{
  short         request_id;
  ej_ip_t       origin_ip;
  int           ssl;
  int           contest_id;
  int           user_id;
  unsigned long flags;
  signed char   locale_id;
  unsigned char url_len;
  unsigned char srch_len;
  unsigned char data[2];
};

struct userlist_pk_map_contest
{
  short request_id;
  int   contest_id;
};

struct userlist_pk_edit_registration
{
  short          request_id;
  int            user_id;
  int            contest_id;
  int            new_status;    /* -1 - no change, -2 - delete */
  int            flags_cmd; /* 0 - no change, 1 - set, 2 - clear, 3 - toggle */
  unsigned int   new_flags;
};

struct userlist_pk_edit_field
{
  short request_id;
  int   user_id;
  int   contest_id;
  int   serial;
  int   field;
  ej_cookie_t cookie;
  int   value_len;
  unsigned char data[1];
};

struct userlist_pk_edit_field_seq
{
  short request_id;
  int   user_id;
  int   contest_id;
  int   serial;
  int   deleted_num;
  int   edited_num;
  int   data[0];
  // int deleted_field_ids[deleted_num];
  // int edited_field_ids[edited_num];
  // int edited_field_lens[edited_num];
  // char stringdata[...];
};

struct userlist_pk_get_uid_by_pid
{
  short request_id;
  int   system_uid;
  int   system_gid;
  int   system_pid;
  int   contest_id;
};

struct userlist_pk_dump_database
{
  short request_id;
  int   contest_id;
  int   html_flag;
};

struct userlist_pk_list_users_2
{
  short request_id;
  int   contest_id;
  int   group_id;
  int   user_id;
  int   filter_len;
  int   offset;
  int   count;
  unsigned char data[1];
};

struct userlist_pk_create_user_2
{
  short request_id;
  int login_len;
  int email_len;
  int send_email_flag;
  int confirm_email_flag;
  int random_password_flag;
  int reg_password_len;
  int use_sha1_flag;
  int is_privileged_flag;
  int is_invisible_flag;
  int is_banned_flag;
  int is_locked_flag;
  int show_login_flag;
  int show_email_flag;
  int read_only_flag;
  int never_clean_flag;
  int simple_registration_flag;
  int contest_id;
  int cnts_status;
  int cnts_is_invisible_flag;
  int cnts_is_banned_flag;
  int cnts_is_locked_flag;
  int cnts_is_incomplete_flag;
  int cnts_is_disqualified_flag;
  int cnts_use_reg_passwd_flag;
  int cnts_set_null_passwd_flag;
  int cnts_random_password_flag;
  int cnts_password_len;
  int cnts_use_sha1_flag;
  int cnts_name_len;
  int group_id;
  unsigned char data[5];
};

/* server->client replies */
struct userlist_pk_login_ok
{
  short              reply_id;
  int                user_id;
  ej_cookie_t        cookie;
  int                contest_id;
  signed char        locale_id;
  unsigned char      priv_level;
  int                role;
  int                team_login;
  int                reg_status;
  int                reg_flags;
  unsigned char      login_len;
  unsigned char      name_len;
  char               data[2];
};

struct userlist_pk_xml_data
{
  short          reply_id;
  unsigned int   info_len;
  unsigned char  data[1];
};

struct userlist_pk_contest_mapped
{
  short reply_id;
  int   sem_key;
  int   shm_key;
};

struct userlist_pk_uid
{
  short reply_id;
  int   uid;
  int   priv_level;
  ej_cookie_t cookie;
  ej_ip_t ip;
  int ssl;
};

struct userlist_pk_uid_2
{
  short reply_id;
  int uid;
  int priv_level;
  ej_ip_t ip;
  int ssl;
  int login_len;
  int name_len;
  ej_cookie_t cookie;
  unsigned char data[2];
};

struct userlist_pk_notification
{
  short reply_id;
  int contest_id;
};

struct userlist_pk_new_password
{
  short       reply_id;
  int         user_id;
  int         regstatus;
  int         login_len;
  int         name_len;
  int         passwd_len;
  char        data[3];
};

struct userlist_pk_count
{
  short reply_id;
  long long count;
};

#endif /* __USERLIST_PROTO_H__ */
