/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

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
 */

#include "userlist_clnt/private.h"

#include <errno.h>

int
userlist_clnt_send_packet(struct userlist_clnt *clnt,
                          size_t size, void const *buf)
{
  unsigned char *b;
  int w, n;

  ASSERT(clnt);
  ASSERT(size > 0);
  ASSERT(clnt->fd >= 0);

  b = (unsigned char*) alloca(size + 4);
  memcpy(b, &size, 4);          /* FIXME: non-portable */
  memcpy(b + 4, buf, size);
  w = size + 4;

  while (w > 0) {
    n = write(clnt->fd, b, w);
    if (n <= 0) {
      n = errno;
      err("write() to userlist-server failed: %s", os_ErrorMsg());
      close(clnt->fd);
      clnt->fd = -1;
      if (n == EPIPE) return -ULS_ERR_DISCONNECT;
      return -ULS_ERR_WRITE_ERROR;
    }
    w -= n; b += n;
  }
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
