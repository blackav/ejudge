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
  };

/* server reply codes */
enum
  {
    ULS_OK = 0,
    ULS_LOGIN_USED,
  };

struct userlist_packet __attribute__((packed));
struct userlist_packet
{
  unsigned short id;
  char bytes[0];
};

struct userlist_pk_register_new __attribute__((packed));
struct userlist_pk_register_new
{
  unsigned short id;
  unsigned long origin_ip;
  int contest_id;
  unsigned char locale_id;
  unsigned char use_cookies;
  unsigned char login_length;
  unsigned char email_length;
  unsigned char data[0];
};

#endif /* __USERLIST_PROTO_H__ */
