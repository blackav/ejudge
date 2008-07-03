/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "ej_types.h"
#include "ej_limits.h"
#include "ej_byteorder.h"

#include "compile_packet.h"
#include "compile_packet_priv.h"
#include "pathutl.h"
#include "errlog.h"
#include "prepare.h"
#include "runlog.h"

#include <reuse/integral.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdlib.h>
#include <string.h>

#define FAIL_IF(c) if (c)do { errcode = __LINE__; goto failed; } while (0)

int
compile_request_packet_write(const struct compile_request_packet *in_data,
                             size_t *p_out_size, void **p_out_data)
{
  int errcode, i, out_size, env_num;
  rint32_t *str_lens, *str_lens_out;
  struct compile_request_bin_packet *out_data = 0;
  unsigned char *out_ptr;

  FAIL_IF(in_data->judge_id < 0 || in_data->judge_id > EJ_MAX_JUDGE_ID);
  FAIL_IF(in_data->contest_id < 0 || in_data->contest_id > EJ_MAX_CONTEST_ID);
  FAIL_IF(in_data->run_id < 0 || in_data->run_id > EJ_MAX_RUN_ID);
  FAIL_IF(in_data->lang_id < 0 || in_data->lang_id > EJ_MAX_LANG_ID);
  FAIL_IF(in_data->locale_id < 0 || in_data->locale_id > EJ_MAX_LOCALE_ID);
  FAIL_IF(in_data->output_only < 0 || in_data->output_only > 1);
  FAIL_IF(in_data->ts1_us < 0 || in_data->ts1_us > USEC_MAX);
  FAIL_IF(in_data->run_block_len < 0 || in_data->run_block_len > EJ_MAX_COMPILE_RUN_BLOCK_LEN);
  env_num = in_data->env_num;
  if (env_num == -1) {
    env_num =0;
    if (in_data->env_vars) {
      for (i = 0; in_data->env_vars[i]; i++);
      env_num = i;
    }
  }
  FAIL_IF(env_num < 0 || env_num > EJ_MAX_COMPILE_ENV_NUM);
  XALLOCA(str_lens, env_num);
  XALLOCA(str_lens_out, env_num);
  for (i = 0; i < env_num; i++) {
    str_lens[i] = strlen(in_data->env_vars[i]);
    FAIL_IF(str_lens[i] < 0 || str_lens[i] > EJ_MAX_COMPILE_ENV_LEN);
    str_lens_out[i] = cvt_host_to_bin_32(str_lens[i]);
  }

  out_size = sizeof(*out_data);
  out_size += pkt_bin_align(in_data->run_block_len);
  out_size += pkt_bin_align(env_num * sizeof(rint32_t));
  for (i = 0; i < env_num; i++) {
    out_size += str_lens[i];
  }
  out_size = pkt_bin_align(out_size);
  FAIL_IF(out_size < sizeof(*out_data)||out_size > EJ_MAX_COMPILE_PACKET_SIZE);

  out_data = xcalloc(1, out_size);
  out_ptr = (unsigned char *) out_data + sizeof(*out_data);

  out_data->packet_len = cvt_host_to_bin_32(out_size);
  out_data->version = cvt_host_to_bin_32(1);
  out_data->judge_id = cvt_host_to_bin_32(in_data->judge_id);
  out_data->contest_id = cvt_host_to_bin_32(in_data->contest_id);
  out_data->run_id = cvt_host_to_bin_32(in_data->run_id);
  out_data->lang_id = cvt_host_to_bin_32(in_data->lang_id);
  out_data->locale_id = cvt_host_to_bin_32(in_data->locale_id);
  out_data->output_only = cvt_host_to_bin_32(in_data->output_only);
  out_data->ts1 = cvt_host_to_bin_32(in_data->ts1);
  out_data->ts1_us = cvt_host_to_bin_32(in_data->ts1_us);
  out_data->run_block_len = cvt_host_to_bin_32(in_data->run_block_len);
  out_data->env_num = cvt_host_to_bin_32(env_num);
  if (in_data->run_block_len) {
    memcpy(out_ptr, in_data->run_block, in_data->run_block_len);
    out_ptr += in_data->run_block_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (env_num) {
    memcpy(out_ptr, str_lens_out, env_num * sizeof(rint32_t));
    out_ptr += env_num * sizeof(rint32_t);
    pkt_bin_align_addr(out_ptr, out_data);
    for (i = 0; i < env_num; i++) {
      memcpy(out_ptr, in_data->env_vars[i], str_lens[i]);
      out_ptr += str_lens[i];
    }
  }

  *p_out_size = (size_t) out_size;
  *p_out_data = out_data;
  return 0;

 failed:
  err("compile_request_packet_write: error %s, %d", "$Revision$", errcode);
  xfree(out_data);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
