/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "new_server_clnt/new_server_clnt_priv.h"
#include "ejudge/new_server_proto.h"

#include "ejudge/xalloc.h"

#include <unistd.h>

new_server_conn_t
new_server_clnt_close(new_server_conn_t conn)
{
  if (!conn) return 0;

  close(conn->fd); conn->fd = -1;
  xfree(conn);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
