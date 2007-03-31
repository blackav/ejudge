/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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
userlist_clnt_edit_field_seq(
	struct userlist_clnt *clnt,
        int cmd,
        int user_id,
        int contest_id,
        int serial,
        int deleted_num,
        int edited_num,
        int deleted_ids[],
        int edited_ids[],
        const unsigned char **edited_strs)
{
  int r, i;
  struct userlist_pk_edit_field_seq *out = 0;
  struct userlist_packet *in = 0;
  size_t out_size = 0, in_size = 0;
  int *edited_lens = 0;
  unsigned char *pktptr;

  if (cmd <= 0) cmd = ULS_EDIT_FIELD_SEQ;
  if (edited_num > 0) {
    XALLOCAZ(edited_lens, edited_num);
  }
  out_size = sizeof(*out);
  out_size += deleted_num * sizeof(deleted_ids[0]);
  out_size += edited_num * sizeof(edited_ids[0]);
  out_size += edited_num * sizeof(edited_lens[0]);
  for (i = 0; i < edited_num; i++) {
    edited_lens[i] = strlen(edited_strs[i]);
    out_size += edited_lens[i] + 1;
  }
  // FIXME: check, that out_size is reasonable
  out = (struct userlist_pk_edit_field_seq*) alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = cmd;
  out->user_id = user_id;
  out->contest_id = contest_id;
  out->serial = serial;
  out->deleted_num = deleted_num;
  out->edited_num = edited_num;
  pktptr = (unsigned char *) out->data;
  if (deleted_num > 0) {
    memcpy(pktptr, deleted_ids, deleted_num * sizeof(deleted_ids[0]));
    pktptr += deleted_num * sizeof(deleted_ids[0]);
  }
  if (edited_num > 0) {
    memcpy(pktptr, edited_ids, edited_num * sizeof(edited_ids[0]));
    pktptr += edited_num * sizeof(edited_ids[0]);
    memcpy(pktptr, edited_lens, edited_num * sizeof(edited_lens[0]));
    pktptr += edited_num * sizeof(edited_lens[0]);
  }
  for (i = 0; i < edited_num; i++) {
    memcpy(pktptr, edited_strs[i], edited_lens[i] + 1);
    pktptr += edited_lens[i] + 1;
  }

  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, (void*) &in)) < 0)
    return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
