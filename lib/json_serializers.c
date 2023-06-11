/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/json_serializers.h"
#include "ejudge/cJSON.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/submit_plugin.h"
#include "ejudge/runlog.h"

cJSON *
json_serialize_submit(
        const struct submit_entry *se,
        const struct testing_report_xml *tr)
{
  cJSON *jrr = cJSON_CreateObject();
  cJSON_AddNumberToObject(jrr, "submit_id", se->serial_id);
  cJSON_AddNumberToObject(jrr, "contest_id", se->contest_id);
  cJSON_AddNumberToObject(jrr, "user_id", se->user_id);
  cJSON_AddNumberToObject(jrr, "prob_id", se->prob_id);
  cJSON_AddNumberToObject(jrr, "lang_id", se->lang_id);
  cJSON_AddNumberToObject(jrr, "status", se->status);
  cJSON_AddStringToObject(jrr, "status_str",
                          run_status_str(se->status, NULL, 0, 0, 0));
  if (se->ext_user_kind > 0 && se->ext_user_kind < MIXED_ID_LAST) {
    unsigned char buf[64];
    cJSON_AddStringToObject(jrr, "ext_user_kind",
                            mixed_id_unparse_kind(se->ext_user_kind));
    cJSON_AddStringToObject(jrr, "ext_user",
                            mixed_id_marshall(buf, se->ext_user_kind,
                                              &se->ext_user));
  }
  if (se->notify_driver > 0
      && se->notify_kind > 0 && se->notify_kind < MIXED_ID_LAST) {
    unsigned char buf[64];
    cJSON_AddNumberToObject(jrr, "notify_driver", se->notify_driver);
    cJSON_AddStringToObject(jrr, "notify_kind",
                            mixed_id_unparse_kind(se->notify_kind));
    cJSON_AddStringToObject(jrr, "notify_queue",
                            mixed_id_marshall(buf, se->notify_kind,
                                              &se->notify_queue));
  }
  if (tr) {
    if (tr->compiler_output && *tr->compiler_output) {
      cJSON_AddStringToObject(jrr, "compiler_output", tr->compiler_output);
    }
    if (tr->run_tests > 0) {
      if (tr->tests && tr->tests[0]) {
        struct testing_report_test *ttr = tr->tests[0];
        if (ttr) {
          cJSON_AddNumberToObject(jrr, "time", ttr->time);
          if (ttr->real_time > 0) {
            cJSON_AddNumberToObject(jrr, "real_time", ttr->real_time);
          }
          if (ttr->exit_code >= 0) {
            cJSON_AddNumberToObject(jrr, "exit_code", ttr->exit_code);
          }
          if (ttr->term_signal > 0) {
            cJSON_AddNumberToObject(jrr, "term_signal", ttr->term_signal);
          }
          if (ttr->max_memory_used > 0) {
            cJSON_AddNumberToObject(jrr, "max_memory_used", ttr->max_memory_used);
          }
          if (ttr->max_rss > 0) {
            cJSON_AddNumberToObject(jrr, "max_rss", ttr->max_rss);
          }
          if (ttr->input.size > 0) {
            cJSON_AddStringToObject(jrr, "input", ttr->input.data);
          }
          if (ttr->output.size > 0) {
            cJSON_AddStringToObject(jrr, "output", ttr->output.data);
          }
          if (ttr->error.size > 0) {
            cJSON_AddStringToObject(jrr, "error", ttr->error.data);
          }
          if (ttr->test_checker.size > 0) {
            cJSON_AddStringToObject(jrr, "test_checker", ttr->test_checker.data);
          }
        }
      }
    }
  }

  return jrr;
}
