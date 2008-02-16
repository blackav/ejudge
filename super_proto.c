/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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

#include "super_proto.h"

#include <reuse/xalloc.h>

#include <stdio.h>

static unsigned char const * const error_map[] =
{
  "no error",
  "error code 1",
  "not connected",
  "invalid file descriptors",
  "write to server failed",
  "invalid socket name",
  "system call failed",
  "connection refused",
  "read from server failed",
  "unexpected EOF from server",
  "protocol error",
  "userlist-server is down",
  "permission denied",
  "invalid contest",
  "IP-address is banned",
  "contest root_dir is not set",
  "file does not exist",
  "log file is redirected to /dev/null",
  "read error",
  "file format is invalid",
  "unexpected userlist-server error",
  "contest is already used",
  "another contest is edited in this session",
  "not implemented yet",
  "invalid parameter",
  "no contest is edited",
  "duplicated login name",
  "such problem already exists",
  "this problem is used as base problem",
  "parameter is out of range",

  "unknown error",
};

unsigned char const *
super_proto_strerror(int n)
{
  if (n < 0) n = -n;
  if (n >= SSERV_ERR_LAST) {
    // this is error anyway, so leak some memory
    unsigned char buf[64];

    snprintf(buf, sizeof(buf), "unknown error %d", n);
    return xstrdup(buf);
  }
  return error_map[n];
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
