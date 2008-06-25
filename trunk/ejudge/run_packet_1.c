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

#define FAIL_IF(c) if (c)do { errcode = __LINE__; goto failed; } while (0)

int
run_request_packet_read(size_t in_size, const void *in_data,
                        struct run_request_packet **p_out_data)
{
  struct run_request_packet *pout = 0;
  const struct run_request_bin_packet*pin=(const struct run_request_bin_packet*)in_data;
  int errcode = 0, version;
  size_t packet_len, user_spelling_len, prob_spelling_len, exe_sfx_len, arch_len;
  unsigned int flags;
  const unsigned char *inptr;

  FAIL_IF(in_size < sizeof(*pin));
  FAIL_IF(pkt_bin_align(in_size) != in_size);
  packet_len = cvt_bin_to_host_32(pin->packet_len);
  FAIL_IF(packet_len != in_size);
  version = cvt_bin_to_host_32(pin->version);
  FAIL_IF(version != 1);

  XCALLOC(pout, 1);

  pout->contest_id = cvt_bin_to_host_32(pin->contest_id);
  if (pout->contest_id == -1) {
    /* this is "Forced Quit" packet */
    *p_out_data = pout;
    return 0;
  }
  FAIL_IF(pout->contest_id <= 0 || pout->contest_id > EJ_MAX_CONTEST_ID);
  pout->run_id = cvt_bin_to_host_32(pin->run_id);
  FAIL_IF(pout->run_id < 0 || pout->run_id > EJ_MAX_RUN_ID);
  pout->problem_id = cvt_bin_to_host_32(pin->problem_id);
  FAIL_IF(pout->problem_id <= 0 || pout->problem_id > EJ_MAX_PROB_ID);
  pout->user_id = cvt_bin_to_host_32(pin->user_id);
  FAIL_IF(pout->user_id <= 0 || pout->user_id > EJ_MAX_USER_ID);
  pout->time_limit_adj = cvt_bin_to_host_32(pin->time_limit_adj);
  FAIL_IF(pout->time_limit_adj < 0 || pout->time_limit_adj > EJ_MAX_TIME_LIMIT_ADJ);
  pout->time_limit_adj_millis = cvt_bin_to_host_32(pin->time_limit_adj_millis);
  FAIL_IF(pout->time_limit_adj_millis < 0 || pout->time_limit_adj_millis > EJ_MAX_TIME_LIMIT_ADJ_MILLIS);

  flags = cvt_bin_to_host_32(pin->flags);
  FAIL_IF(flags != (flags & FLAGS_ALL_MASK));
  pout->scoring_system = FLAGS_GET_SCORING_SYSTEM(flags);
  FAIL_IF(pout->scoring_system < 0 || pout->scoring_system >= SCORE_TOTAL);
  if ((flags & FLAGS_ACCEPTING_MODE)) pout->accepting_mode = 1;
  if ((flags & FLAGS_ACCEPT_PARTIAL)) pout->accept_partial = 1;
  if ((flags & FLAGS_DISABLE_SOUND)) pout->disable_sound = 1;
  if ((flags & FLAGS_FULL_ARCHIVE)) pout->full_archive = 1;
  if ((flags & FLAGS_MEMORY_LIMIT)) pout->memory_limit = 1;
  if ((flags & FLAGS_SECURE_RUN)) pout->secure_run = 1;
  if ((flags & FLAGS_SECURITY_VIOLATION)) pout->security_violation = 1;

  pout->ts1 = cvt_bin_to_host_32(pin->ts1);
  pout->ts1_us = cvt_bin_to_host_32(pin->ts1_us);
  pout->ts2 = cvt_bin_to_host_32(pin->ts2);
  pout->ts2_us = cvt_bin_to_host_32(pin->ts2_us);
  pout->ts3 = cvt_bin_to_host_32(pin->ts3);
  pout->ts3_us = cvt_bin_to_host_32(pin->ts3_us);
  pout->ts4 = cvt_bin_to_host_32(pin->ts4);
  pout->ts4_us = cvt_bin_to_host_32(pin->ts4_us);

  pout->judge_id = cvt_bin_to_host_16(pin->judge_id);
  FAIL_IF(pout->judge_id < 0 || pout->judge_id > EJ_MAX_JUDGE_ID);
  user_spelling_len = cvt_bin_to_host_16(pin->user_spelling_len);
  FAIL_IF(user_spelling_len > EJ_MAX_USER_SPELLING_LEN);
  prob_spelling_len = cvt_bin_to_host_16(pin->prob_spelling_len);
  FAIL_IF(prob_spelling_len > EJ_MAX_PROB_SPELLING_LEN);
  exe_sfx_len = pin->exe_sfx_len;
  FAIL_IF(exe_sfx_len > EJ_MAX_EXE_SFX_LEN);
  arch_len = pin->arch_len;
  FAIL_IF(arch_len > EJ_MAX_ARCH_LEN);
  pout->variant = pin->variant;
  FAIL_IF(pout->variant < 0 || pout->variant > EJ_MAX_VARIANT);

  packet_len = pkt_bin_align(sizeof(*pin) + user_spelling_len + prob_spelling_len
                             + exe_sfx_len + arch_len);
  FAIL_IF(packet_len != pin->packet_len);
  inptr = (const unsigned char*) pin + sizeof(*pin);

  pout->exe_sfx = xmalloc(exe_sfx_len + 1);
  if (exe_sfx_len > 0) memcpy(pout->exe_sfx, inptr, exe_sfx_len);
  pout->exe_sfx[exe_sfx_len] = 0;
  inptr += exe_sfx_len;

  pout->arch = xmalloc(arch_len + 1);
  if (arch_len > 0) memcpy(pout->arch, inptr, arch_len);
  pout->arch[arch_len] = 0;
  inptr += arch_len;

  pout->user_spelling = xmalloc(user_spelling_len + 1);
  if (user_spelling_len > 0) memcpy(pout->user_spelling, inptr, user_spelling_len);
  pout->user_spelling[user_spelling_len] = 0;
  inptr += user_spelling_len;

  pout->prob_spelling = xmalloc(prob_spelling_len + 1);
  if (prob_spelling_len > 0) memcpy(pout->prob_spelling, inptr, prob_spelling_len);
  pout->prob_spelling[prob_spelling_len] = 0;
  inptr += prob_spelling_len;

  *p_out_data = pout;
  return 0;

 failed:
  err("run_request_packet_read: error %s, %d", "$Revision$", errcode);
  run_request_packet_free(pout);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
