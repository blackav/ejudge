/* -*- c -*- */
/* $Id$ */

#ifndef __NEW_SERVER_PROTO_H__
#define __NEW_SERVER_PROTO_H__

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <time.h>

#define NEW_SERVER_PROT_PACKET_MAGIC (0xe352)
struct new_server_prot_packet
{
  unsigned short magic;
  short id;
};

// client->serve requests
enum
{
  NEW_SRV_CMD_PASS_FD = 1,
  NEW_SRV_CMD_HTTP_REQUEST,

  NEW_SRV_CMD_LAST,
};

// serve->client replies
enum
{
  NEW_SRV_RPL_OK = 0,

  NEW_SRV_RPL_LAST,
};

// serve error message codes
enum
{
  NEW_SRV_ERR_NO_ERROR = 0,
  NEW_SRV_ERR_UNKNOWN_ERROR,
  NEW_SRV_ERR_BAD_SOCKET_NAME,
  NEW_SRV_ERR_SYSTEM_ERROR,
  NEW_SRV_ERR_CONNECT_FAILED,
  NEW_SRV_ERR_WRITE_ERROR,
  NEW_SRV_ERR_NOT_CONNECTED,
  NEW_SRV_ERR_READ_ERROR,
  NEW_SRV_ERR_UNEXPECTED_EOF,
  NEW_SRV_ERR_PACKET_TOO_BIG,
  NEW_SRV_ERR_PACKET_TOO_SMALL,
  NEW_SRV_ERR_PROTOCOL_ERROR,
  NEW_SRV_ERR_PARAM_OUT_OF_RANGE,

  NEW_SRV_ERR_INVALID_USER_ID,

  NEW_SRV_ERR_LAST,
};

struct new_server_prot_http_request
{
  struct new_server_prot_packet b;
  int arg_num;
  int env_num;
  int param_num;
};

const unsigned char *new_server_proto_strerror(int n);
void new_serve_error(FILE *log_f, int code, ...);

#endif /* __NEW_SERVER_PROTO_H__ */
