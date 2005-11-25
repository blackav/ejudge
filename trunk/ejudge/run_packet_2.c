/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

#include "run_packet.h"
#include "run_packet_priv.h"
#include "pathutl.h"
#include "errlog.h"
#include "prepare.h"
#include "runlog.h"

#include <reuse/integral.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdlib.h>
#include <string.h>

int
run_request_packet_write(const struct run_request_packet *in_data,
                         size_t *p_out_size, void **p_out_data)
{
  size_t out_size = sizeof(struct run_request_bin_packet);
  struct run_request_bin_packet *out_data = 0;
  int errcode = 0;
  size_t exe_sfx_len = 0, arch_len = 0, user_spelling_len = 0, prob_spelling_len = 0;
  unsigned char *out_ptr;
  unsigned int flags = 0;

  /* calculate the size of the output packet */
  if (in_data->exe_sfx) out_size += (exe_sfx_len = strlen(in_data->exe_sfx));
  if (in_data->arch) out_size += (arch_len = strlen(in_data->arch));
  if (in_data->user_spelling)
    out_size += (user_spelling_len = strlen(in_data->user_spelling));
  if (in_data->prob_spelling)
    out_size += (prob_spelling_len = strlen(in_data->prob_spelling));
  out_size = pkt_bin_align(out_size);
  if (out_size < sizeof(*out_data) || out_size > MAX_PACKET_SIZE) {
    errcode = 1;
    goto failed;
  }
  out_data = (typeof(out_data)) xcalloc(1, out_size);
  out_ptr = (unsigned char*) out_data + sizeof(*out_data);

  out_data->packet_len = cvt_host_to_bin_32(out_size);
  out_data->version = cvt_host_to_bin_32(1);
  if (in_data->contest_id <= 0 || in_data->contest_id > MAX_CONTEST_ID) {
    errcode = 2;
    goto failed;
  }
  out_data->contest_id = cvt_host_to_bin_32(in_data->contest_id);
  if (in_data->run_id < 0 || in_data->run_id > EJ_MAX_RUN_ID) {
    errcode = 3;
    goto failed;
  }
  out_data->run_id = cvt_host_to_bin_32(in_data->run_id);
  if (in_data->problem_id <= 0 || in_data->problem_id > MAX_PROB_ID) {
    errcode = 4;
    goto failed;
  }
  out_data->problem_id = cvt_host_to_bin_32(in_data->problem_id);
  if (in_data->user_id <= 0 || in_data->user_id > EJ_MAX_USER_ID) {
    errcode = 5;
    goto failed;
  }
  out_data->user_id = cvt_host_to_bin_32(in_data->user_id);
  if (in_data->time_limit_adj < 0 || in_data->time_limit_adj > MAX_TIME_LIMIT_ADJ) {
    errcode = 6;
    goto failed;
  }
  out_data->time_limit_adj = cvt_host_to_bin_32(in_data->time_limit_adj);

  if (in_data->scoring_system < 0 || in_data->scoring_system >= SCORE_TOTAL) {
    errcode = 7;
    goto failed;
  }
  flags |= FLAGS_PUT_SCORING_SYSTEM(in_data->scoring_system);
  if (in_data->accepting_mode) flags |= FLAGS_ACCEPTING_MODE;
  if (in_data->accept_partial) flags |= FLAGS_ACCEPT_PARTIAL;
  if (in_data->disable_sound) flags |= FLAGS_DISABLE_SOUND;
  if (in_data->full_archive) flags |= FLAGS_FULL_ARCHIVE;
  if (in_data->memory_limit) flags |= FLAGS_MEMORY_LIMIT;
  out_data->flags = cvt_host_to_bin_32(flags);

  /* copy timestamps without care */
  out_data->ts1 = cvt_host_to_bin_32(in_data->ts1);
  out_data->ts1_us = cvt_host_to_bin_32(in_data->ts1_us);
  out_data->ts2 = cvt_host_to_bin_32(in_data->ts2);
  out_data->ts2_us = cvt_host_to_bin_32(in_data->ts2_us);
  out_data->ts3 = cvt_host_to_bin_32(in_data->ts3);
  out_data->ts3_us = cvt_host_to_bin_32(in_data->ts3_us);
  out_data->ts4 = cvt_host_to_bin_32(in_data->ts4);
  out_data->ts4_us = cvt_host_to_bin_32(in_data->ts4_us);

  if (in_data->judge_id < 0 || in_data->judge_id > MAX_JUDGE_ID) {
    errcode = 8;
    goto failed;
  }
  out_data->judge_id = cvt_host_to_bin_16(in_data->judge_id);
  if (user_spelling_len > MAX_USER_SPELLING_LEN) {
    errcode = 9;
    goto failed;
  }
  out_data->user_spelling_len = cvt_host_to_bin_16(user_spelling_len);
  if (prob_spelling_len > MAX_PROB_SPELLING_LEN) {
    errcode = 10;
    goto failed;
  }
  out_data->prob_spelling_len = cvt_host_to_bin_16(prob_spelling_len);
  if (exe_sfx_len > MAX_EXE_SFX_LEN) {
    errcode = 11;
    goto failed;
  }
  out_data->exe_sfx_len = exe_sfx_len;
  if (arch_len > MAX_ARCH_LEN) {
    errcode = 12;
    goto failed;
  }
  out_data->arch_len = arch_len;
  if (in_data->variant < 0 || in_data->variant > MAX_VARIANT) {
    errcode = 13;
    goto failed;
  }
  out_data->variant = in_data->variant;

  if (exe_sfx_len > 0) {
    memcpy(out_ptr, in_data->exe_sfx, exe_sfx_len);
    out_ptr += exe_sfx_len;
  }
  if (arch_len > 0) {
    memcpy(out_ptr, in_data->arch, arch_len);
    out_ptr += arch_len;
  }
  if (user_spelling_len > 0) {
    memcpy(out_ptr, in_data->user_spelling, user_spelling_len);
    out_ptr += user_spelling_len;
  }
  if (prob_spelling_len > 0) {
    memcpy(out_ptr, in_data->prob_spelling, prob_spelling_len);
    out_ptr += prob_spelling_len;
  }

  *p_out_size = out_size;
  *p_out_data = out_data;
  return 0;

 failed:
  err("run_request_packet_write: error %d", errcode);
  xfree(out_data);
  return -1;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
