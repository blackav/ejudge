/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2011 Alexander Chernov <cher@ejudge.ru> */

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

#include "run_packet.h"
#include "run_packet_priv.h"
#include "pathutl.h"
#include "errlog.h"
#include "prepare.h"
#include "runlog.h"

#include "reuse_xalloc.h"
#include "reuse_logger.h"
#include "reuse_integral.h"

#include <stdlib.h>
#include <string.h>

#define FAIL_IF(c) if (c)do { errcode = __LINE__; goto failed; } while (0)

int
run_request_packet_write(
        const struct run_request_packet *in_data,
        size_t *p_out_size,
        void **p_out_data)
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
  FAIL_IF(out_size < sizeof(*out_data) || out_size > EJ_MAX_RUN_PACKET_SIZE);
  out_data = (typeof(out_data)) xcalloc(1, out_size);
  out_ptr = (unsigned char*) out_data + sizeof(*out_data);

  out_data->packet_len = cvt_host_to_bin_32(out_size);
  out_data->version = cvt_host_to_bin_32(RUN_REQUEST_PACKET_VERSION);
  FAIL_IF(in_data->contest_id <= 0 || in_data->contest_id > EJ_MAX_CONTEST_ID);
  out_data->contest_id = cvt_host_to_bin_32(in_data->contest_id);
  FAIL_IF(in_data->run_id < 0 || in_data->run_id > EJ_MAX_RUN_ID);
  out_data->run_id = cvt_host_to_bin_32(in_data->run_id);
  FAIL_IF(in_data->problem_id <= 0 || in_data->problem_id > EJ_MAX_PROB_ID);
  out_data->problem_id = cvt_host_to_bin_32(in_data->problem_id);
  FAIL_IF(in_data->user_id <= 0 || in_data->user_id > EJ_MAX_USER_ID);
  out_data->user_id = cvt_host_to_bin_32(in_data->user_id);
  FAIL_IF(in_data->time_limit_adj < 0 || in_data->time_limit_adj > EJ_MAX_TIME_LIMIT_ADJ);
  out_data->time_limit_adj = cvt_host_to_bin_32(in_data->time_limit_adj);
  FAIL_IF(in_data->time_limit_adj_millis < 0 || in_data->time_limit_adj_millis > EJ_MAX_TIME_LIMIT_ADJ_MILLIS);
  out_data->time_limit_adj_millis = cvt_host_to_bin_32(in_data->time_limit_adj_millis);
  out_data->mime_type = cvt_host_to_bin_32(in_data->mime_type);

  FAIL_IF(in_data->scoring_system < 0||in_data->scoring_system >= SCORE_TOTAL);
  flags |= FLAGS_PUT_SCORING_SYSTEM(in_data->scoring_system);
  if (in_data->accepting_mode) flags |= FLAGS_ACCEPTING_MODE;
  if (in_data->accept_partial) flags |= FLAGS_ACCEPT_PARTIAL;
  if (in_data->disable_sound) flags |= FLAGS_DISABLE_SOUND;
  if (in_data->full_archive) flags |= FLAGS_FULL_ARCHIVE;
  if (in_data->memory_limit) flags |= FLAGS_MEMORY_LIMIT;
  if (in_data->secure_run) flags |= FLAGS_SECURE_RUN;
  if (in_data->security_violation) flags |= FLAGS_SECURITY_VIOLATION;
  if (in_data->notify_flag) flags |= FLAGS_NOTIFY;
  if (in_data->advanced_layout) flags |= FLAGS_ADVANCED_LAYOUT;
  if (in_data->separate_user_score) flags |= FLAGS_SEPARATE_USER_SCORE;
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

  FAIL_IF(in_data->judge_id < 0 || in_data->judge_id > EJ_MAX_JUDGE_ID);
  out_data->judge_id = cvt_host_to_bin_16(in_data->judge_id);
  FAIL_IF(user_spelling_len > EJ_MAX_USER_SPELLING_LEN);
  out_data->user_spelling_len = cvt_host_to_bin_16(user_spelling_len);
  FAIL_IF(prob_spelling_len > EJ_MAX_PROB_SPELLING_LEN);
  out_data->prob_spelling_len = cvt_host_to_bin_16(prob_spelling_len);
  FAIL_IF(exe_sfx_len > EJ_MAX_EXE_SFX_LEN);
  out_data->exe_sfx_len = exe_sfx_len;
  FAIL_IF(arch_len > EJ_MAX_ARCH_LEN);
  out_data->arch_len = arch_len;
  FAIL_IF(in_data->variant < 0 || in_data->variant > EJ_MAX_VARIANT);
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
  err("run_request_packet_write: error %s, %d", "$Revision$", errcode);
  xfree(out_data);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
