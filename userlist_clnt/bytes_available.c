/* -*- mode: c -*- */

/* Copyright (C) 2006-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "userlist_clnt/private.h"
#include "ejudge/errlog.h"

#include <sys/ioctl.h>
#ifdef __linux__
#include <linux/sockios.h>
#endif

int
userlist_clnt_bytes_available(struct userlist_clnt *clnt)
{
#if HAVE_SIOCINQ - 0 == 1
  int sz = 0;

  if (ioctl(clnt->fd, SIOCINQ, &sz) < 0) {
    err("%s: ioctl failed: %s", __FUNCTION__, os_ErrorMsg());
    return -ULS_ERR_READ_ERROR;
  } else {
    return sz;
  }
#else
  err("%s: not implemented", __FUNCTION__);
  return -1;
#endif
}
