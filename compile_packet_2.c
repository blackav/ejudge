/* -*- c -*- */

/* Copyright (C) 2005-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/ej_byteorder.h"
#include "ejudge/compile_packet.h"
#include "ejudge/compile_packet_priv.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/prepare.h"
#include "ejudge/runlog.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/integral.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define FAIL_IF(c) if (c)do { errcode = __LINE__; goto failed; } while (0)

int
compile_request_packet_write(
        const struct compile_request_packet *in_data,
        size_t *p_out_size,
        void **p_out_data)
{
  int errcode, i, out_size, env_num, sc_env_num;
  rint32_t *str_lens, *str_lens_out, *sc_str_lens, *sc_str_lens_out;
  struct compile_request_bin_packet *out_data = 0;
  unsigned char *out_ptr;
  int style_checker_len = 0;
  int src_sfx_len = 0;

  if (in_data->style_checker) {
    style_checker_len = strlen(in_data->style_checker);
  }
  if (in_data->src_sfx) {
    src_sfx_len = strlen(in_data->src_sfx);
  }

  FAIL_IF(in_data->judge_id < 0 || in_data->judge_id > EJ_MAX_JUDGE_ID);
  FAIL_IF(in_data->contest_id < 0 || in_data->contest_id > EJ_MAX_CONTEST_ID);
  FAIL_IF(in_data->run_id < 0 || in_data->run_id > EJ_MAX_RUN_ID);
  FAIL_IF(in_data->lang_id < 0 || in_data->lang_id > EJ_MAX_LANG_ID);
  FAIL_IF(in_data->locale_id < 0 || in_data->locale_id > EJ_MAX_LOCALE_ID);
  FAIL_IF(in_data->output_only < 0 || in_data->output_only > 1);
  FAIL_IF(in_data->style_check_only < 0 || in_data->style_check_only > 1);
  FAIL_IF(in_data->ts1_us < 0 || in_data->ts1_us > USEC_MAX);
  FAIL_IF(style_checker_len < 0 || style_checker_len > PATH_MAX);
  FAIL_IF(src_sfx_len < 0 || src_sfx_len > PATH_MAX);
  FAIL_IF(in_data->run_block_len < 0 || in_data->run_block_len > EJ_MAX_COMPILE_RUN_BLOCK_LEN);
  env_num = in_data->env_num;
  if (env_num == -1) {
    env_num = 0;
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

  sc_env_num = in_data->sc_env_num;
  if (sc_env_num == -1) {
    sc_env_num = 0;
    if (in_data->sc_env_vars) {
      for (i = 0; in_data->sc_env_vars[i]; ++i);
      sc_env_num = i;
    }
  }
  FAIL_IF(sc_env_num < 0 || sc_env_num > EJ_MAX_COMPILE_ENV_NUM);
  XALLOCA(sc_str_lens, sc_env_num);
  XALLOCA(sc_str_lens_out, sc_env_num);
  for (i = 0; i < sc_env_num; ++i) {
    sc_str_lens[i] = strlen(in_data->sc_env_vars[i]);
    FAIL_IF(sc_str_lens[i] < 0 || sc_str_lens[i] > EJ_MAX_COMPILE_ENV_LEN);
    sc_str_lens_out[i] = cvt_host_to_bin_32(sc_str_lens[i]);
  }

  out_size = sizeof(*out_data);
  if (style_checker_len > 0) {
    out_size += pkt_bin_align(style_checker_len);
  }
  if (src_sfx_len > 0) {
    out_size += pkt_bin_align(src_sfx_len);
  }
  out_size += pkt_bin_align(in_data->run_block_len);
  out_size += pkt_bin_align(env_num * sizeof(rint32_t));
  for (i = 0; i < env_num; i++) {
    out_size += str_lens[i];
  }
  out_size = pkt_bin_align(out_size);
  out_size += pkt_bin_align(sc_env_num * sizeof(rint32_t));
  for (i = 0; i < sc_env_num; ++i) {
    out_size += sc_str_lens[i];
  }
  out_size = pkt_bin_align(out_size);
  FAIL_IF(out_size < sizeof(*out_data)||out_size > EJ_MAX_COMPILE_PACKET_SIZE);

  out_data = xcalloc(1, out_size);
  out_ptr = (unsigned char *) out_data + sizeof(*out_data);

  out_data->packet_len = cvt_host_to_bin_32(out_size);
  out_data->version = cvt_host_to_bin_32(EJ_COMPILE_PACKET_VERSION);
  out_data->judge_id = cvt_host_to_bin_32(in_data->judge_id);
  out_data->contest_id = cvt_host_to_bin_32(in_data->contest_id);
  out_data->run_id = cvt_host_to_bin_32(in_data->run_id);
  out_data->lang_id = cvt_host_to_bin_32(in_data->lang_id);
  out_data->locale_id = cvt_host_to_bin_32(in_data->locale_id);
  out_data->output_only = cvt_host_to_bin_32(in_data->output_only);
  out_data->style_check_only = cvt_host_to_bin_32(in_data->style_check_only);
  out_data->ts1 = cvt_host_to_bin_32(in_data->ts1);
  out_data->ts1_us = cvt_host_to_bin_32(in_data->ts1_us);
  out_data->max_vm_size = cvt_host_to_bin_64(in_data->max_vm_size);
  out_data->max_stack_size = cvt_host_to_bin_64(in_data->max_stack_size);
  out_data->max_file_size = cvt_host_to_bin_64(in_data->max_file_size);
  out_data->use_uuid = cvt_host_to_bin_32(in_data->use_uuid);
  out_data->uuid.v[0] = cvt_host_to_bin_32(in_data->uuid.v[0]);
  out_data->uuid.v[1] = cvt_host_to_bin_32(in_data->uuid.v[1]);
  out_data->uuid.v[2] = cvt_host_to_bin_32(in_data->uuid.v[2]);
  out_data->uuid.v[3] = cvt_host_to_bin_32(in_data->uuid.v[3]);
  out_data->style_checker_len = cvt_host_to_bin_32(style_checker_len);
  out_data->src_sfx_len = cvt_host_to_bin_32(src_sfx_len);
  out_data->run_block_len = cvt_host_to_bin_32(in_data->run_block_len);
  out_data->env_num = cvt_host_to_bin_32(env_num);
  out_data->sc_env_num = cvt_host_to_bin_32(sc_env_num);
  if (style_checker_len > 0) {
    memcpy(out_ptr, in_data->style_checker, style_checker_len);
    out_ptr += style_checker_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (src_sfx_len > 0) {
    memcpy(out_ptr, in_data->src_sfx, src_sfx_len);
    out_ptr += src_sfx_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
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
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (sc_env_num) {
    memcpy(out_ptr, sc_str_lens_out, sc_env_num * sizeof(rint32_t));
    out_ptr += sc_env_num * sizeof(rint32_t);
    pkt_bin_align_addr(out_ptr, out_data);
    for (i = 0; i < sc_env_num; i++) {
      memcpy(out_ptr, in_data->sc_env_vars[i], sc_str_lens[i]);
      out_ptr += sc_str_lens[i];
    }
    pkt_bin_align_addr(out_ptr, out_data);
  }

  *p_out_size = (size_t) out_size;
  *p_out_data = out_data;
  return 0;

 failed:
  err("compile_request_packet_write: error %s, %d", "$Revision$", errcode);
  xfree(out_data);
  return -1;
}

