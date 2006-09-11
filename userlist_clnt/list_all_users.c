/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ejudge.ru> */

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
userlist_clnt_list_all_users(struct userlist_clnt *clnt,
                             int cmd,
                             int contest_id,
                             unsigned char **p_info)
{
  struct userlist_pk_map_contest *out = 0;
  struct userlist_pk_xml_data *in = 0;
  int r;
  size_t out_size, in_size = 0;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  if (cmd != ULS_LIST_ALL_USERS && cmd != ULS_LIST_STANDINGS_USERS) {
    return -ULS_ERR_PROTOCOL;
  }
  out->request_id = cmd;
  out->contest_id = contest_id;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, (void*) &in)) < 0)
    return r;
  if (in_size < sizeof(struct userlist_packet)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  if (in->reply_id != ULS_XML_DATA) {
    r = in->reply_id;
    xfree(in);
    return r;
  }
  if (in_size < sizeof(struct userlist_pk_xml_data)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  if (strlen(in->data) != in->info_len) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  *p_info = xstrdup(in->data);
  xfree(in);
  return ULS_XML_DATA;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
