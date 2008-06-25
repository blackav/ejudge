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
#include "serve_state.h"

#include <reuse/integral.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdlib.h>
#include <string.h>

#define FAIL_IF(c) if (c)do { errcode = __LINE__; goto failed; } while (0)

int
compile_request_packet_read(const serve_state_t state,
                            size_t in_size, const void *in_data,
                            struct compile_request_packet **p_out_data)
{
  const struct compile_request_bin_packet *pin = in_data;
  const unsigned char *pin_ptr, *end_ptr;
  struct compile_request_packet *pout = 0;
  int pkt_size, pkt_version, errcode = 0, i;
  rint32_t *str_lens;

  FAIL_IF(in_size < sizeof(struct compile_request_bin_packet));
  pkt_size = cvt_bin_to_host_32(pin->packet_len);
  FAIL_IF(pkt_size != in_size);
  FAIL_IF(pkt_size < 0 || pkt_size > EJ_MAX_COMPILE_PACKET_SIZE);
  /* unaligned packet size */
  FAIL_IF((pkt_size & 0xf));
  pkt_version = cvt_bin_to_host_32(pin->version);
  FAIL_IF(pkt_version != 1);
  XCALLOC(pout, 1);
  pout->judge_id = cvt_bin_to_host_32(pin->judge_id);
  FAIL_IF(pout->judge_id < 0 || pout->judge_id > EJ_MAX_JUDGE_ID);
  pout->contest_id = cvt_bin_to_host_32(pin->contest_id);
  FAIL_IF(pout->contest_id < 0 || pout->contest_id > EJ_MAX_CONTEST_ID);

  /* from now on the contest id is available */
  pout->run_id = cvt_bin_to_host_32(pin->run_id);
  FAIL_IF(pout->run_id < 0 || pout->run_id > EJ_MAX_RUN_ID);
  pout->lang_id = cvt_bin_to_host_32(pin->lang_id);
  if (pout->contest_id > 0) {
    FAIL_IF(pout->lang_id < 0 || pout->lang_id > state->max_lang || !state->langs[pout->lang_id]);
  }
  pout->locale_id = cvt_bin_to_host_32(pin->locale_id);
  FAIL_IF(pout->locale_id < 0 || pout->locale_id > EJ_MAX_LOCALE_ID);
  pout->output_only = cvt_bin_to_host_32(pin->output_only);
  FAIL_IF(pout->output_only < 0 || pout->output_only > 1);
  pout->ts1 = cvt_bin_to_host_32(pin->ts1);
  pout->ts1_us = cvt_bin_to_host_32(pin->ts1_us);
  FAIL_IF(pout->ts1_us < 0 || pout->ts1_us > 999999);

  /* extract the additional data */
  // set up the additional data pointer
  pin_ptr = (const unsigned char*) in_data + sizeof(*pin);
  // set up the packet end pointer
  end_ptr = (const unsigned char*) in_data + pkt_size;

  pout->run_block_len = cvt_bin_to_host_32(pin->run_block_len);
  FAIL_IF(pout->run_block_len < 0 || pout->run_block_len > EJ_MAX_COMPILE_RUN_BLOCK_LEN);
  FAIL_IF(pin_ptr + pout->run_block_len > end_ptr);
  if (pout->run_block_len > 0) {
    pout->run_block = xmalloc(pout->run_block_len);
    memcpy(pout->run_block, pin_ptr, pout->run_block_len);
    pin_ptr += pkt_bin_align(pout->run_block_len);
  }

  pout->env_num = cvt_bin_to_host_32(pin->env_num);
  FAIL_IF(pout->env_num < 0 || pout->env_num > EJ_MAX_COMPILE_ENV_NUM);
  FAIL_IF(pin_ptr + pout->env_num * sizeof(rint32_t) > end_ptr);
  if (pout->env_num > 0) {
    XCALLOC(pout->env_vars, pout->env_num + 1);
    str_lens = (rint32_t*) alloca(pout->env_num * sizeof(rint32_t));
    memcpy(str_lens, pin_ptr, pout->env_num * sizeof(rint32_t));
    for (i = 0; i < pout->env_num; i++) {
      str_lens[i] = cvt_bin_to_host_32(str_lens[i]);
      FAIL_IF(str_lens[i] < 0 || str_lens[i] > EJ_MAX_COMPILE_ENV_LEN);
      pout->env_vars[i] = xmalloc(str_lens[i] + 1);
    }
    pin_ptr += pkt_bin_align(pout->env_num * sizeof(rint32_t));

    for (i = 0; i < pout->env_num; i++) {
      FAIL_IF(pin_ptr + str_lens[i] > end_ptr);
      memcpy(pout->env_vars[i], pin_ptr, str_lens[i]);
      pout->env_vars[i][str_lens[i]] = 0;
      pin_ptr += str_lens[i];
    }
  }

  // align the address at the 16-byte boundary
  pkt_bin_align_addr(pin_ptr, in_data);
  FAIL_IF(pin_ptr != end_ptr);

#if 0
  /* debugging */
  fprintf(stderr,
          "the compile request packet\n"
          "  judge_id:      %d\n"
          "  contest_id:    %d\n"
          "  run_id:        %d\n"
          "  lang_id:       %d\n"
          "  locale_id:     %d\n"
          "  ts1:           %d\n"
          "  ts1_us:        %d\n"
          "  run_block_len: %d\n"
          "  env_num:       %d\n",
          pout->judge_id, pout->contest_id, pout->run_id, pout->lang_id,
          pout->locale_id, pout->ts1, pout->ts1_us, pout->run_block_len,pout->env_num);
  for (i = 0; i < pout->env_num; i++) {
    fprintf(stderr, "    env[%d]: <%s>\n", i, pout->env_vars[i]);
  }
#endif

  *p_out_data = pout;
  return 1;

 failed:
  /* even the contest id is not available */
  err("compile_request_packet_read: error %s, %d", "$Revision$", errcode);
  compile_request_packet_free(pout);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
