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
#include "prepare.h"
#include "runlog.h"

#include <reuse/integral.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdlib.h>
#include <string.h>

int
run_reply_packet_write(const struct run_reply_packet *in_data,
                       size_t *p_out_size, void **p_out_data)
{
  struct run_reply_bin_packet *out_data = 0;
  size_t out_size = sizeof(*out_data);
  int errcode = 0;

  if (out_size < sizeof(*out_data) || out_size > MAX_PACKET_SIZE) {
    errcode = 1;
    goto failed;
  }

  out_data = (typeof(out_data)) xcalloc(1, out_size);

  out_data->packet_len = cvt_host_to_bin_32(out_size);
  out_data->version = cvt_host_to_bin_32(1);
  if (in_data->judge_id < 0 || in_data->judge_id > MAX_JUDGE_ID) {
    errcode = 2;
    goto failed;
  }
  out_data->judge_id = cvt_host_to_bin_32(in_data->judge_id);
  if (in_data->contest_id <= 0 || in_data->contest_id > MAX_CONTEST_ID) {
    errcode = 3;
    goto failed;
  }
  out_data->contest_id = cvt_host_to_bin_32(in_data->contest_id);
  if (in_data->run_id < 0 || in_data->run_id > EJ_MAX_RUN_ID) {
    errcode = 4;
    goto failed;
  }
  out_data->run_id = cvt_host_to_bin_32(in_data->run_id);
  if (in_data->status < 0 || in_data->status > RUN_MAX_STATUS) {
    errcode = 5;
    goto failed;
  }
  out_data->status = cvt_host_to_bin_32(in_data->status);
  if (in_data->failed_test < -1 || in_data->failed_test > MAX_FAILED_TEST) {
    errcode = 6;
    goto failed;
  }
  out_data->failed_test = cvt_host_to_bin_32(in_data->failed_test);
  if (in_data->score < -1 || in_data->score > MAX_SCORE) {
    errcode = 7;
    goto failed;
  }
  out_data->score = cvt_host_to_bin_32(in_data->score);

  out_data->ts1 = cvt_host_to_bin_32(in_data->ts1);
  out_data->ts1_us = cvt_host_to_bin_32(in_data->ts1_us);
  out_data->ts2 = cvt_host_to_bin_32(in_data->ts2);
  out_data->ts2_us = cvt_host_to_bin_32(in_data->ts2_us);
  out_data->ts3 = cvt_host_to_bin_32(in_data->ts3);
  out_data->ts3_us = cvt_host_to_bin_32(in_data->ts3_us);
  out_data->ts4 = cvt_host_to_bin_32(in_data->ts4);
  out_data->ts4_us = cvt_host_to_bin_32(in_data->ts4_us);
  out_data->ts5 = cvt_host_to_bin_32(in_data->ts5);
  out_data->ts5_us = cvt_host_to_bin_32(in_data->ts5_us);
  out_data->ts6 = cvt_host_to_bin_32(in_data->ts6);
  out_data->ts6_us = cvt_host_to_bin_32(in_data->ts6_us);
  out_data->ts7 = cvt_host_to_bin_32(in_data->ts7);
  out_data->ts7_us = cvt_host_to_bin_32(in_data->ts7_us);

  *p_out_size = out_size;
  *p_out_data = out_data;
  return 0;

 failed:
  err("run_reply_packet_write: error %d", errcode);
  xfree(out_data);
  return -1;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
