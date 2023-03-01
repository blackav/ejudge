/* -*- c -*- */

/* Copyright (C) 2005-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/run_packet.h"
#include "ejudge/run_packet_priv.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/prepare.h"
#include "ejudge/runlog.h"
#include "ejudge/xml_utils.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/integral.h"

#include <stdlib.h>
#include <string.h>

#define FAIL_IF(c) if (c)do { errcode = __LINE__; goto failed; } while (0)

int
run_reply_packet_write(
        const struct run_reply_packet *in_data,
        size_t *p_out_size,
        void **p_out_data)
{
  struct run_reply_bin_packet *out_data = 0;
  size_t out_size = sizeof(*out_data);
  int errcode = 0, flags = 0;

  FAIL_IF(out_size < sizeof(*out_data) || out_size > EJ_MAX_RUN_PACKET_SIZE);

  out_data = (typeof(out_data)) xcalloc(1, out_size);

  out_data->packet_len = cvt_host_to_bin_32(out_size);
  out_data->version = cvt_host_to_bin_32(1);
  FAIL_IF(in_data->judge_id < 0 || in_data->judge_id > EJ_MAX_JUDGE_ID);
  out_data->judge_id = cvt_host_to_bin_32(in_data->judge_id);
  FAIL_IF(in_data->contest_id <= 0 || in_data->contest_id > EJ_MAX_CONTEST_ID);
  out_data->contest_id = cvt_host_to_bin_32(in_data->contest_id);
  FAIL_IF(in_data->run_id < 0 || in_data->run_id > EJ_MAX_RUN_ID);
  out_data->run_id = cvt_host_to_bin_32(in_data->run_id);
  FAIL_IF(!run_is_normal_status(in_data->status));
  out_data->status = cvt_host_to_bin_32(in_data->status);
  FAIL_IF(in_data->failed_test < -1 || in_data->failed_test > EJ_MAX_TEST_NUM);
  out_data->failed_test = cvt_host_to_bin_32(in_data->failed_test);
  FAIL_IF(in_data->tests_passed < -1 || in_data->tests_passed > EJ_MAX_TEST_NUM);
  out_data->tests_passed = cvt_host_to_bin_32(in_data->tests_passed);
  FAIL_IF(in_data->score < -1 || in_data->score > EJ_MAX_SCORE);
  out_data->score = cvt_host_to_bin_32(in_data->score);
  out_data->user_status = cvt_host_to_bin_32(in_data->user_status);
  out_data->user_tests_passed = cvt_host_to_bin_32(in_data->user_tests_passed);
  out_data->user_score = cvt_host_to_bin_32(in_data->user_score);
  out_data->submit_id = cvt_host_to_bin_64(in_data->submit_id);

  if (in_data->notify_flag) flags |= FLAGS_NOTIFY;
  if (in_data->marked_flag) flags |= FLAGS_MARKED;
  if (in_data->has_user_score) flags |= FLAGS_HAS_USER_SCORE;
  if (in_data->bson_flag) flags |= FLAGS_BSON;
  out_data->flags = cvt_host_to_bin_32(flags);
  out_data->verdict_bits = cvt_host_to_bin_32(in_data->verdict_bits);

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

  out_data->uuid = in_data->uuid;
  out_data->judge_uuid = in_data->judge_uuid;
  /*
  out_data->uuid.v[0] = cvt_host_to_bin_32(in_data->uuid.v[0]);
  out_data->uuid.v[1] = cvt_host_to_bin_32(in_data->uuid.v[1]);
  out_data->uuid.v[2] = cvt_host_to_bin_32(in_data->uuid.v[2]);
  out_data->uuid.v[3] = cvt_host_to_bin_32(in_data->uuid.v[3]);
  */

  *p_out_size = out_size;
  *p_out_data = out_data;
  return 0;

 failed:
  err("run_reply_packet_write: error %s, %d", "$Revision$", errcode);
  xfree(out_data);
  return -1;
}

void
run_reply_packet_dump(
        const struct run_reply_packet *in_data)
{
  fprintf(stderr, "=== packet dump ===\n");
  fprintf(stderr, "judge_id = %d\n", in_data->judge_id);
  fprintf(stderr, "contest_id = %d\n", in_data->contest_id);
  fprintf(stderr, "status = %d\n", in_data->status);
  fprintf(stderr, "failed_test = %d\n", in_data->failed_test);
  fprintf(stderr, "tests_passed = %d\n", in_data->tests_passed);
  fprintf(stderr, "score = %d\n", in_data->score);
  fprintf(stderr, "notify_flag = %d\n", in_data->notify_flag);
  fprintf(stderr, "marked_flag = %d\n", in_data->marked_flag);
  fprintf(stderr, "has_user_score = %d\n", in_data->has_user_score);
  fprintf(stderr, "user_status = %d\n", in_data->user_status);
  fprintf(stderr, "user_tests_passed = %d\n", in_data->user_tests_passed);
  fprintf(stderr, "user_score = %d\n", in_data->user_score);
  fprintf(stderr, "ts1 = \"%s.%06d\"\n", xml_unparse_date(in_data->ts1), in_data->ts1_us);
  fprintf(stderr, "ts2 = \"%s.%06d\"\n", xml_unparse_date(in_data->ts2), in_data->ts2_us);
  fprintf(stderr, "ts3 = \"%s.%06d\"\n", xml_unparse_date(in_data->ts3), in_data->ts3_us);
  fprintf(stderr, "ts4 = \"%s.%06d\"\n", xml_unparse_date(in_data->ts4), in_data->ts4_us);
  fprintf(stderr, "ts5 = \"%s.%06d\"\n", xml_unparse_date(in_data->ts5), in_data->ts5_us);
  fprintf(stderr, "ts6 = \"%s.%06d\"\n", xml_unparse_date(in_data->ts6), in_data->ts6_us);
  fprintf(stderr, "ts7 = \"%s.%06d\"\n", xml_unparse_date(in_data->ts7), in_data->ts7_us);
  fprintf(stderr, "uuid = \"%s\"\n", ej_uuid_unparse(&in_data->uuid, "NULL"));
}
