/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005,2006 Alexander Chernov <cher@ispras.ru> */

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

#include "compile_packet.h"
#include "compile_packet_priv.h"
#include "pathutl.h"
#include "errlog.h"
#include "prepare.h"
#include "prepare_vars.h"
#include "runlog.h"

#include <reuse/integral.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdlib.h>
#include <string.h>

int
compile_request_packet_read(size_t in_size, const void *in_data,
                            struct compile_request_packet **p_out_data)
{
  const struct compile_request_bin_packet *pin = in_data;
  const unsigned char *pin_ptr, *end_ptr;
  struct compile_request_packet *pout = 0;
  int pkt_size, pkt_version, errcode = 0, i;
  rint32_t *str_lens;

  if (in_size < sizeof(struct compile_request_bin_packet)) {
    errcode = 1;
    goto failed_badly;
  }
  pkt_size = cvt_bin_to_host(pin->packet_len);
  if (pkt_size != in_size) {
    errcode = 2;
    goto failed_badly;
  }
  if (pkt_size < 0 || pkt_size > MAX_PACKET_SIZE) {
    errcode = 3;
    goto failed_badly;
  }
  if ((pkt_size & 0xf)) {
    /* unaligned packet size */
    errcode = 4;
    goto failed_badly;
  }
  pkt_version = cvt_bin_to_host(pin->version);
  if (pkt_version != 1) {
    errcode = 5;
    goto failed_badly;
  }
  XCALLOC(pout, 1);
  pout->judge_id = cvt_bin_to_host(pin->judge_id);
  if (pout->judge_id < 0 || pout->judge_id > MAX_JUDGE_ID) {
    errcode = 6;
    goto failed_badly;
  }
  pout->contest_id = cvt_bin_to_host(pin->contest_id);
  if (pout->contest_id <= 0 || pout->contest_id > MAX_CONTEST_ID) {
    errcode = 7;
    goto failed_badly;
  }

  /* from now on the contest id is available */
  pout->run_id = cvt_bin_to_host(pin->run_id);
  if (pout->run_id < 0 || pout->run_id > EJ_MAX_RUN_ID) {
    errcode = 8;
    goto failed_badly;
  }
  pout->lang_id = cvt_bin_to_host(pin->lang_id);
  if (pout->lang_id < 0 || pout->lang_id > max_lang || !langs[pout->lang_id]) {
    errcode = 9;
    goto failed_badly;
  }
  pout->locale_id = cvt_bin_to_host(pin->locale_id);
  if (pout->locale_id < 0 || pout->locale_id > 127) {
    errcode = 10;
    goto failed_badly;
  }
  pout->output_only = cvt_bin_to_host(pin->output_only);
  if (pout->output_only < 0 || pout->output_only > 1) {
    errcode = 11;
    goto failed_badly;
  }
  pout->ts1 = cvt_bin_to_host(pin->ts1);
  pout->ts1_us = cvt_bin_to_host(pin->ts1_us);
  if (pout->ts1_us < 0 || pout->ts1_us > 999999) {
    errcode = 12;
    goto failed_badly;
  }

  /* extract the additional data */
  // set up the additional data pointer
  pin_ptr = (const unsigned char*) in_data + sizeof(*pin);
  // set up the packet end pointer
  end_ptr = (const unsigned char*) in_data + pkt_size;

  pout->run_block_len = cvt_bin_to_host(pin->run_block_len);
  if (pout->run_block_len < 0 || pout->run_block_len > MAX_RUN_BLOCK_LEN) {
    errcode = 13;
    goto failed_badly;
  }
  if (pin_ptr + pout->run_block_len > end_ptr) {
    errcode = 14;
    goto failed_badly;
  }
  if (pout->run_block_len > 0) {
    pout->run_block = xmalloc(pout->run_block_len);
    memcpy(pout->run_block, pin_ptr, pout->run_block_len);
    pin_ptr += pkt_bin_align(pout->run_block_len);
  }

  pout->env_num = cvt_bin_to_host(pin->env_num);
  if (pout->env_num < 0 || pout->env_num > MAX_ENV_NUM) {
    errcode = 15;
    goto failed_badly;
  }
  if (pin_ptr + pout->env_num * sizeof(rint32_t) > end_ptr) {
    errcode = 16;
    goto failed_badly;
  }
  if (pout->env_num > 0) {
    XCALLOC(pout->env_vars, pout->env_num + 1);
    str_lens = (rint32_t*) alloca(pout->env_num * sizeof(rint32_t));
    memcpy(str_lens, pin_ptr, pout->env_num * sizeof(rint32_t));
    for (i = 0; i < pout->env_num; i++) {
      str_lens[i] = cvt_bin_to_host(str_lens[i]);
      if (str_lens[i] < 0 || str_lens[i] > MAX_ENV_LEN) {
        errcode = 17;
        goto failed_badly;
      }
      pout->env_vars[i] = xmalloc(str_lens[i] + 1);
    }
    pin_ptr += pkt_bin_align(pout->env_num * sizeof(rint32_t));

    for (i = 0; i < pout->env_num; i++) {
      if (pin_ptr + str_lens[i] > end_ptr) {
        errcode = 18;
        goto failed_badly;
      }
      memcpy(pout->env_vars[i], pin_ptr, str_lens[i]);
      pout->env_vars[i][str_lens[i]] = 0;
      pin_ptr += str_lens[i];
    }
  }

  // align the address at the 16-byte boundary
  pkt_bin_align_addr(pin_ptr, in_data);
  if (pin_ptr != end_ptr) {
    errcode = 19;
    goto failed_badly;
  }

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

#if 0
 failed:
  /* reading failed, but the contest id is available */
  err("compile_request_packet_read: error %d", errcode);
  compile_request_packet_free(pout);
  if (p_contest_id) *p_contest_id = contest_id;
  return 0;
#endif

 failed_badly:
  /* even the contest id is not available */
  err("compile_request_packet_read: error %d", errcode);
  compile_request_packet_free(pout);
  return -1;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
