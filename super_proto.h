/* -*- c -*- */
/* $Id$ */

#ifndef __SUPER_PROTO_H__
#define __SUPER_PROTO_H__

/* Copyright (C) 2004-2005 Alexander Chernov <cher@ispras.ru> */

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

#define PROT_SUPER_PACKET_MAGIC (0xf249)
struct prot_super_packet
{
  unsigned short magic;
  short id;
};

/* client-server requests */
enum
{
  SSERV_CMD_PASS_FD = 1,
  SSERV_CMD_MAIN_PAGE,
  SSERV_CMD_CONTEST_PAGE,
  SSERV_CMD_VIEW_SERVE_LOG,
  SSERV_CMD_VIEW_RUN_LOG,
  SSERV_CMD_VIEW_CONTEST_XML,
  SSERV_CMD_VIEW_SERVE_CFG,
  SSERV_CMD_OPEN_CONTEST,
  SSERV_CMD_CLOSE_CONTEST,
  SSERV_CMD_INVISIBLE_CONTEST,
  SSERV_CMD_VISIBLE_CONTEST,

  SSERV_CMD_LAST,
};

/* replies */
enum
{
  SSERV_RPL_OK = 0,

  SSERV_RPL_LAST,
};

/* error codes */
enum
{
  SSERV_ERR_NO_ERROR = 0,
  SSERV_ERR_1,                  /* to reserve -1 */
  SSERV_ERR_NOT_CONNECTED,
  SSERV_ERR_INVALID_FD,
  SSERV_ERR_WRITE_TO_SERVER,
  SSERV_ERR_BAD_SOCKET_NAME,
  SSERV_ERR_SYSTEM_ERROR,
  SSERV_ERR_CONNECT_FAILED,
  SSERV_ERR_READ_FROM_SERVER,
  SSERV_ERR_EOF_FROM_SERVER,
  SSERV_ERR_PROTOCOL_ERROR,
  SSERV_ERR_USERLIST_DOWN,
  SSERV_ERR_PERMISSION_DENIED,
  SSERV_ERR_INVALID_CONTEST,
  SSERV_ERR_BANNED_IP,
  SSERV_ERR_ROOT_DIR_NOT_SET,
  SSERV_ERR_FILE_NOT_EXIST,
  SSERV_ERR_LOG_IS_DEV_NULL,
  SSERV_ERR_FILE_READ_ERROR,
  SSERV_ERR_FILE_FORMAT_INVALID,
  SSERV_ERR_UNEXPECTED_USERLIST_ERROR,

  SSERV_UNKNOWN_ERROR,
  SSERV_ERR_LAST,
};

unsigned char const *super_proto_strerror(int n);

enum
{
  SSERV_VIEW_INVISIBLE = 1,
};

struct prot_super_pkt_main_page
{
  struct prot_super_packet b;

  int locale_id;
  int contest_id;               /* for viewing contest details */
  unsigned int flags;           /* view flags */
  int self_url_len;
  int hidden_vars_len;
  int extra_args_len;
  unsigned char data[3];
};

struct prot_super_pkt_simple_cmd
{
  struct prot_super_packet b;

  int contest_id;
};

#endif /* __SUPER_PROTO_H__ */
