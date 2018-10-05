/* -*- mode: c -*- */

/* Copyright (C) 2010-2016 Alexander Chernov <cher@ejudge.ru> */

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
userlist_clnt_get_xml_by_text(
        struct userlist_clnt *clnt,
        int cmd,
        const unsigned char *request_text,
        unsigned char **reply_text)
{
  size_t request_len, out_size, xml_len, in_size = 0;
  struct userlist_pk_set_user_info *out;
  void *in_void = 0;
  struct userlist_packet *in_gen = 0;
  struct userlist_pk_xml_data *in = 0;
  int r;

  if (!request_text) request_text = "";
  request_len = strlen(request_text);
  out_size = sizeof(*out) + request_len;
  out = (typeof(out)) alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = cmd;
  out->info_len = request_len;
  memcpy(out->data, request_text, request_len + 1);
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &in_void)) < 0)
    return r;

  r = -ULS_ERR_PROTOCOL;
  in_gen = (struct userlist_packet*) in_void;
  if (!in_gen || in_size < sizeof(*in_gen)) goto cleanup;
  if (in_gen->id < 0) {
    r = in_gen->id;
    goto cleanup;
  }
  if (in_gen->id != ULS_XML_DATA) goto cleanup;
  if (in_size < sizeof(*in)) goto cleanup;

  in = (struct userlist_pk_xml_data*) in_gen;
  xml_len = strlen(in->data);
  if (xml_len != in->info_len) goto cleanup;
  if (in_size != sizeof(*in) + xml_len) goto cleanup;

  if (reply_text) {
    *reply_text = xstrdup(in->data);
  }
  r = ULS_XML_DATA;

cleanup:
  xfree(in_void);
  return r;
}
