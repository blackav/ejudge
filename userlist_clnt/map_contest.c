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

int
userlist_clnt_map_contest(struct userlist_clnt *clnt,
                          int contest_id,
                          int *p_sem_key,
                          int *p_shm_key)
{
  struct userlist_pk_map_contest *out = 0;
  struct userlist_pk_contest_mapped *in = 0;
  int r;
  size_t out_size, in_size = 0;

  /* FIXME: check args? */

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_MAP_CONTEST;
  out->contest_id = contest_id;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_recv_packet(clnt, &in_size, (void*) &in)) < 0)
    return r;
  if (in->reply_id != ULS_CONTEST_MAPPED) {
    r = in->reply_id;
    xfree(in);
    return r;
  }
  if (p_sem_key) *p_sem_key = in->sem_key;
  if (p_shm_key) *p_shm_key = in->shm_key;
  r = in->reply_id;
  xfree(in);
  return r;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
