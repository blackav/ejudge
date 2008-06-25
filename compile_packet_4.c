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
compile_reply_packet_read(size_t in_size, const void *in_data,
                          struct compile_reply_packet **p_out_data)
{
  struct compile_reply_packet *pout = 0;
  const struct compile_reply_bin_packet *pin = in_data;
  int errcode = 0, pkt_size, pkt_version;
  const unsigned char *in_ptr, *end_ptr;

  FAIL_IF(in_size < sizeof(*pin));
  pkt_size = cvt_bin_to_host_32(pin->packet_len);
  FAIL_IF(pkt_size != in_size);
  FAIL_IF(pkt_size < 0 || pkt_size > EJ_MAX_COMPILE_PACKET_SIZE);
  FAIL_IF((pkt_size & 0xf));
  pkt_version = cvt_bin_to_host_32(pin->version);
  FAIL_IF(pkt_version != 1);
  XCALLOC(pout, 1);
  pout->judge_id = cvt_bin_to_host_32(pin->judge_id);
  FAIL_IF(pout->judge_id < 0 || pout->judge_id > EJ_MAX_JUDGE_ID);
  pout->contest_id = cvt_bin_to_host_32(pin->contest_id);
  FAIL_IF(pout->contest_id <= 0 || pout->contest_id > EJ_MAX_CONTEST_ID);
  pout->run_id = cvt_bin_to_host_32(pin->run_id);
  FAIL_IF(pout->run_id < 0 || pout->run_id > EJ_MAX_RUN_ID);
  // OK, COMPILE_ERR, CHECK_FAILED are allowed
  pout->status = cvt_bin_to_host_32(pin->status);
  FAIL_IF(pout->status != RUN_OK && pout->status != RUN_COMPILE_ERR && pout->status != RUN_CHECK_FAILED);
  pout->ts1 = cvt_bin_to_host_32(pin->ts1);
  pout->ts1_us = cvt_bin_to_host_32(pin->ts1_us);
  FAIL_IF(pout->ts1_us < 0 || pout->ts1_us > 999999);
  pout->ts2 = cvt_bin_to_host_32(pin->ts2);
  pout->ts2_us = cvt_bin_to_host_32(pin->ts2_us);
  FAIL_IF(pout->ts2_us < 0 || pout->ts2_us > 999999);
  pout->ts3 = cvt_bin_to_host_32(pin->ts3);
  pout->ts3_us = cvt_bin_to_host_32(pin->ts3_us);
  FAIL_IF(pout->ts3_us < 0 || pout->ts3_us > 999999);

  in_ptr = (const unsigned char*) pin + sizeof(*pin);
  end_ptr = (const unsigned char*) pin + pkt_size;

  pout->run_block_len = cvt_bin_to_host_32(pin->run_block_len);
  FAIL_IF(pout->run_block_len < 0 || pout->run_block_len > EJ_MAX_COMPILE_RUN_BLOCK_LEN);
  if (pout->run_block_len > 0) {
    FAIL_IF(in_ptr + pout->run_block_len > end_ptr);
    pout->run_block = xmalloc(pout->run_block_len);
    memcpy(pout->run_block, in_ptr, pout->run_block_len);
    in_ptr += pout->run_block_len;
  }

  pkt_bin_align_addr(in_ptr, pin);
  FAIL_IF(in_ptr != end_ptr);

#if 0
  /* debug */
  fprintf(stderr, 
          "compile reply packet:\n"
          "  judge_id:      %d\n"
          "  contest_id:    %d\n"
          "  run_id:        %d\n"
          "  status:        %d\n"
          "  ts1:           %d\n"
          "  ts1_us:        %d\n"
          "  ts2:           %d\n"
          "  ts2_us:        %d\n"
          "  ts3:           %d\n"
          "  ts3_us:        %d\n"
          "  run_block_len: %d\n",
          pout->judge_id, pout->contest_id, pout->run_id, pout->status,
          pout->ts1, pout->ts1_us, pout->ts2, pout->ts2_us, pout->ts3, pout->ts3_us,
          pout->run_block_len);
#endif

  *p_out_data = pout;
  return 0;

 failed:
  err("compile_reply_packet_read: error %s, %d", "$Revision$", errcode);
  compile_reply_packet_free(pout);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
