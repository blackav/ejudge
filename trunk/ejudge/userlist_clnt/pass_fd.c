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

int
userlist_clnt_pass_fd(struct userlist_clnt *clnt, int nfd, int *fds)
{
  struct userlist_packet *out = 0;
  int out_size = 0;
  int r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  out->id = ULS_PASS_FD;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  return userlist_clnt_do_pass_fd(clnt, nfd, fds);
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
