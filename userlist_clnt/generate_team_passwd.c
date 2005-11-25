/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

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

int
userlist_clnt_generate_team_passwd(struct userlist_clnt *clnt,
                                   int cmd,
                                   int contest_id, int out_fd)
{
  struct userlist_pk_map_contest *out = 0;
  struct userlist_packet *in = 0;
  int r;
  size_t out_size, in_size = 0;
  int pfd[2], pp[2];
  char b;

  if (cmd != ULS_GENERATE_TEAM_PASSWORDS && cmd != ULS_GENERATE_PASSWORDS) {
    return -ULS_ERR_PROTOCOL;
  }

  if (pipe(pp) < 0) {
    err("pipe() failed: %s", os_ErrorMsg());
    return -ULS_ERR_WRITE_ERROR;
  }
  pfd[0] = out_fd;
  pfd[1] = pp[1];

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = cmd;
  out->contest_id = contest_id;
  if ((r = userlist_clnt_pass_fd(clnt, 2, pfd)) < 0) return r;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_recv_packet(clnt, &in_size, (void*) &in)) < 0)
    return r;
  r = in->id;
  xfree(in);
  if (r < 0) return r;

  close(pfd[1]);
  r = read(pp[0], &b, 1);
  if (r > 0) return -ULS_ERR_PROTOCOL;
  if (r < 0) return -ULS_ERR_READ_ERROR;
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
