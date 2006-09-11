/* -*- mode: c -*- */
/* $Id$ */

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

#include "userlist_clnt/private.h"
#include "errlog.h"

#include <sys/ioctl.h>
#include <linux/sockios.h>

int
userlist_clnt_bytes_available(struct userlist_clnt *clnt)
{
  int sz = 0;

  if (ioctl(clnt->fd, SIOCINQ, &sz) < 0) {
    err("userlist_clnt_has_data: ioctl failed: %s", os_ErrorMsg());
    return -ULS_ERR_READ_ERROR;
  } else {
    return sz;
  }
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
