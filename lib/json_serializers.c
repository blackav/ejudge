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
#include "ejudge/teamdb.h"
#include "ejudge/prepare.h"
#include "ejudge/xml_utils.h"
#include "ejudge/misctext.h"
#include "ejudge/sha256.h"
#include "ejudge/mime_type.h"

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
                          run_status_short_str(se->status));
  cJSON_AddStringToObject(jrr, "status_desc",
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

cJSON *
json_serialize_run(
        serve_state_t cs,
        const struct run_entry *re)
{
    cJSON *jr = cJSON_CreateObject();
    const unsigned char *s;

    if (re->status == RUN_EMPTY) {
        cJSON_AddNumberToObject(jr, "run_id", re->run_id);
        cJSON_AddNumberToObject(jr, "contest_id", cs->contest_id);
        cJSON_AddNumberToObject(jr, "status", re->status);
        cJSON_AddStringToObject(jr, "status_str",
                                run_status_short_str(re->status));
        cJSON_AddStringToObject(jr, "status_desc",
                                run_status_str(re->status, NULL, 0, 0, 0));
        return jr;
    }

    if (re->status == RUN_VIRTUAL_START || re->status == RUN_VIRTUAL_STOP) {
        cJSON_AddNumberToObject(jr, "run_id", re->run_id);
        cJSON_AddNumberToObject(jr, "contest_id", cs->contest_id);
        cJSON_AddNumberToObject(jr, "status", re->status);
        cJSON_AddStringToObject(jr, "status_str",
                                run_status_short_str(re->status));
        cJSON_AddNumberToObject(jr, "run_time", (double) re->time);
        cJSON_AddNumberToObject(jr, "nsec", (double) re->nsec);
        cJSON_AddNumberToObject(jr, "run_time_us",
                                (double) (re->time * 1000000LL + re->nsec / 1000));
        cJSON_AddNumberToObject(jr, "user_id", re->user_id);
        s = teamdb_get_login(cs->teamdb_state, re->user_id);
        if (s && *s) {
            cJSON_AddStringToObject(jr, "user_login", s);
        }
        s = teamdb_get_name(cs->teamdb_state, re->user_id);
        if (s && *s) {
            cJSON_AddStringToObject(jr, "user_name", s);
        }
        if (re->is_checked) {
            cJSON_AddTrueToObject(jr, "is_checked");
        }
        return jr;
    }

    if (re->status > RUN_TRANSIENT_LAST
        || (re->status > RUN_LOW_LAST && re->status < RUN_RUNNING)) {
        cJSON_AddNumberToObject(jr, "run_id", re->run_id);
        cJSON_AddNumberToObject(jr, "contest_id", cs->contest_id);
        cJSON_AddNumberToObject(jr, "status", re->status);
        return jr;
    }

    cJSON_AddNumberToObject(jr, "run_id", re->run_id);
    if (ej_uuid_is_nonempty(re->run_uuid)) {
        cJSON_AddStringToObject(jr, "run_uuid", ej_uuid_unparse(&re->run_uuid, ""));
    }
    cJSON_AddNumberToObject(jr, "contest_id", cs->contest_id);
    if (re->serial_id > 0) {
        cJSON_AddNumberToObject(jr, "serial_id", re->serial_id);
    }
    cJSON_AddNumberToObject(jr, "status", re->status);
    cJSON_AddStringToObject(jr, "status_str",
                            run_status_short_str(re->status));
    cJSON_AddStringToObject(jr, "status_desc",
                            run_status_str(re->status, NULL, 0, 0, 0));
    cJSON_AddNumberToObject(jr, "run_time", (double) re->time);
    cJSON_AddNumberToObject(jr, "nsec", (double) re->nsec);
    cJSON_AddNumberToObject(jr, "run_time_us",
                            (double) (re->time * 1000000LL + re->nsec / 1000));
    cJSON_AddNumberToObject(jr, "user_id", re->user_id);
    s = teamdb_get_login(cs->teamdb_state, re->user_id);
    if (s && *s) {
        cJSON_AddStringToObject(jr, "user_login", s);
    }
    s = teamdb_get_name(cs->teamdb_state, re->user_id);
    if (s && *s) {
        cJSON_AddStringToObject(jr, "user_name", s);
    }
    if (re->ext_user_kind > 0 && re->ext_user_kind < MIXED_ID_LAST) {
        unsigned char mbuf[64];
        cJSON_AddStringToObject(jr, "ext_user_kind",
                                mixed_id_unparse_kind(re->ext_user_kind));
        cJSON_AddStringToObject(jr, "ext_user",
                                mixed_id_marshall(mbuf, re->ext_user_kind,
                                                  &re->ext_user));
    }

    cJSON_AddNumberToObject(jr, "prob_id", re->prob_id);
    const struct section_problem_data *prob = NULL;
    if (re->prob_id > 0 && re->prob_id <= cs->max_prob) {
        prob = cs->probs[re->prob_id];
    }
    if (prob && prob->short_name[0]) {
        cJSON_AddStringToObject(jr, "prob_name", prob->short_name);
    }
    if (prob && prob->internal_name && prob->internal_name[0]) {
        cJSON_AddStringToObject(jr, "prob_internal_name", prob->internal_name);
    }
    if (ej_uuid_is_nonempty(re->prob_uuid)) {
        cJSON_AddStringToObject(jr, "prob_uuid",
                                ej_uuid_unparse(&re->prob_uuid, ""));
    } else if (prob && prob->uuid && prob->uuid[0]) {
        cJSON_AddStringToObject(jr, "prob_uuid", prob->uuid);
    }
    if (prob && prob->variant_num > 0) {
        if (re->variant > 0) {
            cJSON_AddNumberToObject(jr, "raw_variant", re->variant);
            cJSON_AddNumberToObject(jr, "variant", re->variant);
        } else {
            int variant = find_variant(cs, re->user_id, re->prob_id, 0);
            if (variant > 0) {
                cJSON_AddNumberToObject(jr, "variant", variant);
            }
        }
    }
    cJSON_AddNumberToObject(jr, "lang_id", re->lang_id);
    const struct section_language_data *lang = NULL;
    if (re->lang_id > 0 && re->lang_id <= cs->max_lang) {
        lang = cs->langs[re->lang_id];
    }
    if (lang && lang->short_name[0]) {
        cJSON_AddStringToObject(jr, "lang_name", lang->short_name);
    }
    cJSON_AddNumberToObject(jr, "size", re->size);

    if (re->ipv6_flag) {
        cJSON_AddTrueToObject(jr, "ipv6_flag");
        ej_ip_t tmp_ip = {};
        tmp_ip.ipv6_flag = 1;
        memcpy(tmp_ip.u.v6.addr, re->a.ipv6, 16);
        cJSON_AddStringToObject(jr, "ip", xml_unparse_ipv6(&tmp_ip));
    } else {
        cJSON_AddStringToObject(jr, "ip", xml_unparse_ip(re->a.ip));
    }
    if (re->ssl_flag) {
        cJSON_AddTrueToObject(jr, "ssl_flag");
    }
    if (re->sha256_flag) {
        cJSON_AddStringToObject(jr, "sha256", unparse_sha256(re->h.sha256));
    } else {
        cJSON_AddStringToObject(jr, "sha1", unparse_sha1(re->h.sha1));
    }
    if (re->locale_id > 0) {
        cJSON_AddNumberToObject(jr, "locale_id", re->locale_id);
    }
    if (re->eoln_type > 0) {
        cJSON_AddNumberToObject(jr, "eoln_type", re->eoln_type);
    }
    if (re->mime_type) {
        cJSON_AddStringToObject(jr, "mime_type",
                                mime_type_get_type(re->mime_type));
    }
    if (re->store_flags) {
        cJSON_AddNumberToObject(jr, "store_flags", re->store_flags);
    }
    if (re->is_imported) {
        cJSON_AddTrueToObject(jr, "is_imported");
    }
    if (re->is_hidden) {
        cJSON_AddTrueToObject(jr, "is_hidden");
    }
    if (re->is_readonly) {
        cJSON_AddTrueToObject(jr, "is_readonly");
    }
    if (re->passed_mode > 0) {
        cJSON_AddTrueToObject(jr, "passed_mode");
    } else if (!re->passed_mode) {
        cJSON_AddFalseToObject(jr, "passed_mode");
    }
    if (re->score >= 0) {
        cJSON_AddNumberToObject(jr, "raw_score", re->score);
    }
    if (re->test >= 0) {
        cJSON_AddNumberToObject(jr, "raw_test", re->test);
    }
    if (re->is_marked) {
        cJSON_AddTrueToObject(jr, "is_marked");
    }
    if (re->score_adj != 0) {
        cJSON_AddNumberToObject(jr, "score_adj", re->score_adj);
    }
    if (re->judge_uuid_flag) {
        if (ej_uuid_is_nonempty(re->j.judge_uuid)) {
            cJSON_AddStringToObject(jr, "judge_uuid",
                                    ej_uuid_unparse(&re->j.judge_uuid, ""));
        }
    } else if (re->j.judge_id) {
        cJSON_AddNumberToObject(jr, "judge_id", re->j.judge_id);
    }
    if (re->pages) {
        cJSON_AddNumberToObject(jr, "pages", re->pages);
    }
    if (re->token_flags) {
        cJSON_AddNumberToObject(jr, "token_flags", re->token_flags);
    }
    if (re->token_count) {
        cJSON_AddNumberToObject(jr, "token_count", re->token_count);
    }
    if (re->is_saved) {
        cJSON_AddTrueToObject(jr, "is_saved");
        cJSON_AddNumberToObject(jr, "saved_status", re->saved_status);
        cJSON_AddStringToObject(jr, "saved_status_str",
                                run_status_short_str(re->saved_status));
        if (re->saved_score >= 0) {
            cJSON_AddNumberToObject(jr, "saved_score", re->saved_score);
        }
        if (re->saved_test >= 0) {
            cJSON_AddNumberToObject(jr, "saved_test", re->saved_test);
        }
    }
    if (re->is_checked) {
        cJSON_AddTrueToObject(jr, "is_checked");
    }
    if (re->is_vcs) {
        cJSON_AddTrueToObject(jr, "is_vcs");
    }
    if (re->verdict_bits) {
        cJSON_AddNumberToObject(jr, "verdict_bits", re->verdict_bits);
    }
    if (re->last_change_us > 0) {
        cJSON_AddNumberToObject(jr, "last_change_us", re->last_change_us);
    }
    if (re->notify_driver > 0
        && re->notify_kind > 0 && re->notify_kind < MIXED_ID_LAST) {
        unsigned char mbuf[64];
        cJSON_AddNumberToObject(jr, "notify_driver", re->notify_driver);
        cJSON_AddStringToObject(jr, "notify_kind",
                                mixed_id_unparse_kind(re->notify_kind));
        cJSON_AddStringToObject(jr, "notify_queue",
                                mixed_id_marshall(mbuf, re->notify_kind,
                                                  &re->notify_queue));
    }

    return jr;
}
