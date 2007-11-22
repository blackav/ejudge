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
userlist_clnt_import_csv_users(
	struct userlist_clnt *clnt,
        int cmd,
        int contest_id,
        int separator,
        int flags,
        const unsigned char *csv_text,
        unsigned char **p_log)
{
  struct userlist_pk_edit_field *out = 0;
  struct userlist_packet *in_dflt = 0;
  struct userlist_pk_xml_data *in = 0;
  size_t text_len, out_size, in_size = 0, log_len;
  void *in_void = 0;
  int r;

#if !defined PYTHON
  ASSERT(clnt);
  ASSERT(clnt->fd >= 0);
#endif

  if (!csv_text) csv_text = "";
  text_len = strlen(csv_text);
  if (text_len >= 1024 * 1024 * 1024) return -ULS_ERR_PROTOCOL;
  out_size = sizeof(*out) + text_len;
  out = (struct userlist_pk_edit_field*) alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = cmd;
  out->contest_id = contest_id;
  out->serial = flags;
  out->field = separator;
  out->value_len = text_len;
  memcpy(out->data, csv_text, text_len + 1);
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &in_void)) < 0)
    return r;
  if (in_size < sizeof(*in_dflt)) {
    xfree(in_void);
    return -ULS_ERR_PROTOCOL;
  }
  in_dflt = (struct userlist_packet*) in_void;
  if (in_dflt->id < 0) {
    r = in_dflt->id;
    xfree(in_void);
    return r;
  }
  if (in_dflt->id != ULS_TEXT_DATA && in_dflt->id != ULS_TEXT_DATA_FAILURE) {
    xfree(in_void);
    return -ULS_ERR_PROTOCOL;
  }
  if (in_size < sizeof(*in)) {
    xfree(in_void);
    return -ULS_ERR_PROTOCOL;
  }
  in = (struct userlist_pk_xml_data*) in_void;
  log_len = strlen(in->data);
  if (log_len != in->info_len) {
    xfree(in_void);
    return -ULS_ERR_PROTOCOL;
  }
  if (sizeof(*in) + log_len != in_size) {
    xfree(in_void);
    return -ULS_ERR_PROTOCOL;
  }
  if (p_log) *p_log = xstrdup(in->data);
  r = in->reply_id;
  xfree(in_void);
  return r;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
