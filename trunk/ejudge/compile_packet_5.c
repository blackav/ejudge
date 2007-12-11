/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "runlog.h"

#include <reuse/integral.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdlib.h>
#include <string.h>

int
compile_reply_packet_write(const struct compile_reply_packet *in_data,
                           size_t *p_out_size, void **p_out_data)
{
  struct compile_reply_bin_packet *out_data = 0;
  unsigned char *out_ptr;
  int errcode = 0, out_size;

  if (in_data->judge_id < 0 || in_data->judge_id > MAX_JUDGE_ID) {
    errcode = 1;
    goto failed;
  }
  if (in_data->contest_id <= 0 || in_data->contest_id > EJ_MAX_CONTEST_ID) {
    errcode = 2;
    goto failed;
  }
  if (in_data->run_id < 0 || in_data->run_id > EJ_MAX_RUN_ID) {
    errcode = 3;
    goto failed;
  }
  if (in_data->status != RUN_OK && in_data->status != RUN_COMPILE_ERR
      && in_data->status != RUN_CHECK_FAILED) {
    errcode = 4;
    goto failed;
  }
  if (in_data->ts1_us < 0 || in_data->ts1_us > 999999) {
    errcode = 5;
    goto failed;
  }
  if (in_data->ts2_us < 0 || in_data->ts2_us > 999999) {
    errcode = 6;
    goto failed;
  }
  if (in_data->ts3_us < 0 || in_data->ts3_us > 999999) {
    errcode = 7;
    goto failed;
  }
  if (in_data->run_block_len < 0 || in_data->run_block_len>MAX_RUN_BLOCK_LEN) {
    errcode = 8;
    goto failed;
  }

  out_size = sizeof(*out_data);
  out_size += pkt_bin_align(in_data->run_block_len);
  if (out_size < 0 || out_size > MAX_PACKET_SIZE) {
    errcode = 9;
    goto failed;
  }

  out_data = xcalloc(1, out_size);
  out_ptr = (unsigned char*) out_data + sizeof(*out_data);

  out_data->packet_len = cvt_host_to_bin(out_size);
  out_data->version = cvt_host_to_bin(1);
  out_data->judge_id = cvt_host_to_bin(in_data->judge_id);
  out_data->contest_id = cvt_host_to_bin(in_data->contest_id);
  out_data->run_id = cvt_host_to_bin(in_data->run_id);
  out_data->status = cvt_host_to_bin(in_data->status);
  out_data->ts1 = cvt_host_to_bin(in_data->ts1);
  out_data->ts1_us = cvt_host_to_bin(in_data->ts1_us);
  out_data->ts2 = cvt_host_to_bin(in_data->ts2);
  out_data->ts2_us = cvt_host_to_bin(in_data->ts2_us);
  out_data->ts3 = cvt_host_to_bin(in_data->ts3);
  out_data->ts3_us = cvt_host_to_bin(in_data->ts3_us);
  out_data->run_block_len = cvt_host_to_bin(in_data->run_block_len);
  if (in_data->run_block_len) {
    memcpy(out_ptr, in_data->run_block, in_data->run_block_len);
  }

  *p_out_size = (size_t) out_size;
  *p_out_data = out_data;
  return 0;

 failed:
  err("compile_reply_packet_write: error %d", errcode);
  xfree(out_data);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
