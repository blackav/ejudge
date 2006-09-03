/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_PROTO_H__
#define __USERLIST_PROTO_H__

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

/* server requests codes */
enum
  {
    ULS_REGISTER_NEW = 1,
    ULS_DO_LOGIN,
    ULS_CHECK_COOKIE,
    ULS_DO_LOGOUT,
    ULS_GET_USER_INFO,
    ULS_SET_USER_INFO,
    ULS_SET_PASSWD,
    ULS_GET_USER_CONTESTS,
    ULS_REGISTER_CONTEST,
    ULS_DELETE_MEMBER,
    ULS_PASS_FD,
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
    ULS_ERR_UNSPECIFIED_ERROR,

    ULS_ERR_LAST
  };

unsigned char const *userlist_strerror(int code);

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
  unsigned char login_length;
  unsigned char email_length;
  unsigned char data[2];
};

struct userlist_pk_do_login
{
  short         request_id;
  ej_ip_t       origin_ip;
  int           ssl;
  int           contest_id;
  signed char   locale_id;
  unsigned char priv_level;
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
  signed char        locale_id;
  unsigned char      priv_level;
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
  short request_id;
  int   user_id;
  int   contest_id;
};

struct userlist_pk_delete_info
{
  short request_id;
  int   user_id;
  int   contest_id;
  int   serial;
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

/* server->client replies */
struct userlist_pk_login_ok
{
  short              reply_id;
  int                user_id;
  ej_cookie_t        cookie;
  int                contest_id;
  signed char        locale_id;
  unsigned char      priv_level;
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

#endif /* __USERLIST_PROTO_H__ */
