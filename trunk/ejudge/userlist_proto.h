/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_PROTO_H__
#define __USERLIST_PROTO_H__

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

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
    ULS_REMOVE_MEMBER,
    ULS_PASS_FD,
  };

/* server reply codes (each corresponds to a different packet) */
enum
  {
    ULS_OK = 0,
    ULS_LOGIN_OK,
    ULS_LOGIN_COOKIE,
    ULS_XML_DATA,
  };

/* various error codes */
enum
  {
    ULS_ERR_LOGIN_USED = 1,
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

    ULS_ERR_LAST
  };

unsigned char const *userlist_strerror(int code);

/* a generic packet structure */
struct userlist_packet __attribute__((packed,aligned(1)));
struct userlist_packet
{
  short id;
  char  bytes[0];
};

/* client->server requests packet */
struct userlist_pk_register_new __attribute__((packed,aligned(1)));
struct userlist_pk_register_new
{
  short         request_id;
  unsigned long origin_ip;
  long          contest_id;
  signed char   locale_id;
  signed char   use_cookies;
  unsigned char login_length;
  unsigned char email_length;
  unsigned char data[0];
};

struct userlist_pk_do_login __attribute__((packed,aligned(1)));
struct userlist_pk_do_login
{
  short         request_id;
  unsigned long origin_ip;
  long          contest_id;
  signed char   locale_id;
  signed char   use_cookies;
  unsigned char login_length;
  unsigned char password_length;
  unsigned char data[0];
};

struct userlist_pk_check_cookie __attribute__((packed,aligned(1)));
struct userlist_pk_check_cookie
{
  short              request_id;
  unsigned long      origin_ip;
  long               contest_id;
  unsigned long long cookie;
  signed char        locale_id;
};

struct userlist_pk_do_logout __attribute__((packed,aligned(1)));
struct userlist_pk_do_logout
{
  short              request_id;
  unsigned long      origin_ip;
  long               contest_id;
  unsigned long long cookie;
  long               user_id;
};

struct userlist_pk_get_user_info __attribute__((packed,aligned(1)));
struct userlist_pk_get_user_info
{
  short         request_id;
  unsigned long user_id;       /* which user_info we want */
};

struct userlist_pk_set_user_info __attribute__((packed,aligned(1)));
struct userlist_pk_set_user_info
{
  short          request_id;
  unsigned long  user_id;
  unsigned short info_len;
  unsigned char  data[0];
};

struct userlist_pk_set_password __attribute__((packed,aligned(1)));
struct userlist_pk_set_password
{
  short         request_id;
  int           user_id;
  unsigned char old_len;
  unsigned char new_len;
  unsigned char data[0];
};

struct userlist_pk_register_contest __attribute__((packed,aligned(1)));
struct userlist_pk_register_contest
{
  short request_id;
  int   user_id;
  int   contest_id;
};

struct userlist_pk_remove_member __attribute__((packed,aligned(1)));
struct userlist_pk_remove_member
{
  short request_id;
  int   user_id;
  int   role_id;
  int   pers_id;
  int   serial;
};

/* server->client replies */
struct userlist_pk_login_ok __attribute__((packed,aligned(1)));
struct userlist_pk_login_ok
{
  short              reply_id;
  long               user_id;
  unsigned long long cookie;
  signed char        locale_id;
  unsigned char      login_len;
  unsigned char      name_len;
  char               data[0];
};

struct userlist_pk_xml_data __attribute__((packed,aligned(1)));
struct userlist_pk_xml_data
{
  short          reply_id;
  unsigned short info_len;
  unsigned char  data[0];
};

#endif /* __USERLIST_PROTO_H__ */
