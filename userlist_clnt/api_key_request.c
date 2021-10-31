/* -*- mode: c -*- */

/* Copyright (C) 2020-2021 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/userlist.h"

int
userlist_clnt_api_key_request(
        struct userlist_clnt *clnt,
        int cmd,
        int in_count,
        const struct userlist_api_key *in_api_keys,
        int *p_out_count,
        struct userlist_api_key **p_out_api_keys,
        struct userlist_contest_info *p_cnts_info)
{
  int string_pool_size = 1;
  int out_size = sizeof(struct userlist_pk_api_key_data);

  if (in_count > 0) {
    for (int i = 0; i < in_count; ++i) {
      const struct userlist_api_key *k = &in_api_keys[i];
      if (k->payload) {
        string_pool_size += strlen(k->payload) + 1;
      }
      if (k->origin) {
        string_pool_size += strlen(k->origin) + 1;
      }
    }
    out_size += sizeof(struct userlist_pk_api_key) * in_count;
    out_size += string_pool_size;
  }
  if (p_cnts_info) {
    // p_cnts_info is not copied
    out_size += sizeof(struct userlist_pk_contest_info);
    memset(p_cnts_info, 0, sizeof(*p_cnts_info));
  }

  void *out_data = malloc(out_size);
  memset(out_data, 0, out_size);
  struct userlist_pk_api_key_data *out_pkt = out_data;
  if (in_count > 0) {
    char *out_pool = (char*) out_pkt->api_keys + sizeof(struct userlist_pk_api_key) * in_count + sizeof(struct userlist_pk_contest_info) * (p_cnts_info != NULL);
    int out_offset = 1;
    for (int i = 0; i < in_count; ++i) {
      const struct userlist_api_key *in_k = &in_api_keys[i];
      struct userlist_pk_api_key *out_k = &out_pkt->api_keys[i];
      memcpy(out_k->token, in_k->token, sizeof(out_k->token));
      memcpy(out_k->secret, in_k->secret, sizeof(out_k->secret));
      out_k->create_time = in_k->create_time;
      out_k->expiry_time = in_k->expiry_time;
      out_k->user_id = in_k->user_id;
      out_k->contest_id = in_k->contest_id;
      out_k->all_contests = in_k->all_contests;
      out_k->role = in_k->role;
      if (in_k->payload) {
        out_k->payload_offset = out_offset;
        int len = strlen(in_k->payload);
        memcpy(out_pool + out_offset, in_k->payload, len);
        out_offset += len + 1;
      }
      if (in_k->origin) {
        out_k->origin_offset = out_offset;
        int len = strlen(in_k->origin);
        memcpy(out_pool + out_offset, in_k->origin, len);
        out_offset += len + 1;
      }
    }
  }

  out_pkt->request_id = cmd;
  out_pkt->api_key_count = in_count;
  out_pkt->contest_info_count = (p_cnts_info != NULL);
  out_pkt->string_pool_size = string_pool_size;

  int r = userlist_clnt_send_packet(clnt, out_size, out_data);
  xfree(out_data); out_data = NULL;
  if (r < 0) return r;

  size_t in_size = 0;
  void *in_data = NULL;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &in_data)) < 0) {
    return r;
  }
  if (in_size < 2) {
    xfree(in_data);
    return -ULS_ERR_PROTOCOL;
  }
  short reply_code = *(short *) in_data;
  if (reply_code < 0) {
    xfree(in_data);
    return reply_code;
  }
  if (reply_code == ULS_OK) {
    xfree(in_data);
    return 0;
  }
  if (reply_code != ULS_API_KEY_DATA) {
    xfree(in_data);
    return -ULS_ERR_PROTOCOL;
  }
  if (in_size < sizeof(struct userlist_pk_api_key_data)) {
    xfree(in_data);
    return -ULS_ERR_PROTOCOL;
  }
  struct userlist_pk_api_key_data *in_pkt = in_data;
  if (in_pkt->api_key_count < 0 || in_pkt->api_key_count > 100000) {
    xfree(in_data);
    return -ULS_ERR_PROTOCOL;
  }
  if (in_pkt->api_key_count == 0) {
    if (in_pkt->string_pool_size) {
      xfree(in_data);
      return -ULS_ERR_PROTOCOL;
    }
    if (in_size != sizeof(struct userlist_pk_api_key_data)) {
      xfree(in_data);
      return -ULS_ERR_PROTOCOL;
    }
    *p_out_count = 0;
    *p_out_api_keys = NULL;
    xfree(in_data);
    return 0;
  }

  if (in_pkt->string_pool_size <= 0 || in_pkt->string_pool_size > 1000000) {
    xfree(in_data);
    return -ULS_ERR_PROTOCOL;
  }
  if (sizeof(struct userlist_pk_api_key_data) + in_pkt->api_key_count * sizeof(struct userlist_pk_api_key) + in_pkt->contest_info_count * sizeof(struct userlist_pk_contest_info) + in_pkt->string_pool_size != in_size) {
    xfree(in_data);
    return -ULS_ERR_PROTOCOL;
  }
  const char *in_pool = (const char*) in_pkt->api_keys + in_pkt->api_key_count * sizeof(struct userlist_pk_api_key) + in_pkt->contest_info_count * sizeof(struct userlist_pk_contest_info);

  struct userlist_api_key *out_api_keys = calloc(in_pkt->api_key_count, sizeof(out_api_keys[0]));
  for (int i = 0; i < in_pkt->api_key_count; ++i) {
    const struct userlist_pk_api_key *in_k = &in_pkt->api_keys[i];
    struct userlist_api_key *out_k = &out_api_keys[i];
    memcpy(out_k->token, in_k->token, sizeof(out_k->token));
    memcpy(out_k->secret, in_k->secret, sizeof(out_k->secret));
    out_k->create_time = in_k->create_time;
    out_k->expiry_time = in_k->expiry_time;
    out_k->user_id = in_k->user_id;
    out_k->contest_id = in_k->contest_id;
    out_k->all_contests = in_k->all_contests;
    out_k->role = in_k->role;
    if (in_k->payload_offset) {
      out_k->payload = xstrdup(in_pool + in_k->payload_offset);
    }
    if (in_k->origin_offset) {
      out_k->origin = xstrdup(in_pool + in_k->origin_offset);
    }
  }

  if (p_cnts_info && in_pkt->contest_info_count > 0) {
    const struct userlist_pk_contest_info *in_cnts_info = (const struct userlist_pk_contest_info *)((const char*) in_pkt->api_keys + in_pkt->api_key_count * sizeof(struct userlist_pk_api_key));
    p_cnts_info->user_id = in_cnts_info->user_id;
    p_cnts_info->contest_id = in_cnts_info->contest_id;
    p_cnts_info->login = xstrdup(in_pool + in_cnts_info->login_offset);
    p_cnts_info->name = xstrdup(in_pool + in_cnts_info->name_offset);
    p_cnts_info->reg_status = in_cnts_info->reg_status;
    p_cnts_info->reg_flags = in_cnts_info->reg_flags;
  }

  *p_out_count = in_pkt->api_key_count;
  *p_out_api_keys = out_api_keys;
  xfree(in_data);
  return *p_out_count;
}
