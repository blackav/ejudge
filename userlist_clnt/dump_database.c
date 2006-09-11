/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ejudge.ru> */

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
userlist_clnt_dump_database(struct userlist_clnt *clnt, int cmd,
                            int contest_id, int out_fd,
                            int html_flag)
{
  struct userlist_pk_dump_database *out = 0;
  struct userlist_packet *in = 0;
  int w1, w2, r;
  size_t out_size, in_size = 0;
  int pfd[2], pp[2] = { -1, -1 };

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
  out->html_flag = html_flag;
  if ((r = userlist_clnt_pass_fd(clnt, 2, pfd)) < 0) goto _cleanup;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) goto _cleanup;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, (void*) &in)) < 0)
    goto _cleanup;
  if (in_size != sizeof(*in) || in->id > 0) {
    r = -ULS_ERR_PROTOCOL;
    goto _cleanup;
  }
  r = in->id;
  if (r < 0) goto _cleanup;

  close(pp[1]); pp[1] = -1;
  w1 = read(pp[0], &w2, 1);
  if (w1 != 0) {
    r = -ULS_ERR_PROTOCOL;
    goto _cleanup;
  }

 _cleanup:
  xfree(in);
  if (pp[0] > 0) close(pp[0]);
  if (pp[1] > 0) close(pp[1]);
  return r;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
