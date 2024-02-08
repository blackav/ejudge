/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023-2024 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/userlist.h"

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

cJSON *
json_serialize_userlist_member(int user_id, int contest_id, const struct userlist_member *m)
{
    cJSON *jr = cJSON_CreateObject();

    if (user_id > 0) cJSON_AddNumberToObject(jr, "user_id", user_id);
    if (contest_id > 0) cJSON_AddNumberToObject(jr, "contest_id", contest_id);
    cJSON_AddNumberToObject(jr, "team_role", m->team_role);
    cJSON_AddNumberToObject(jr, "serial", m->serial);
    if (m->copied_from > 0) cJSON_AddNumberToObject(jr, "copied_from", m->copied_from);
    if (m->status > 0) cJSON_AddNumberToObject(jr, "status", m->status);
    if (m->gender > 0) cJSON_AddNumberToObject(jr, "gender", m->gender);
    if (m->grade >= 0) cJSON_AddNumberToObject(jr, "grade", m->grade);
    if (m->firstname) cJSON_AddStringToObject(jr, "firstname", m->firstname);
    if (m->firstname_en) cJSON_AddStringToObject(jr, "firstname_en", m->firstname_en);
    if (m->middlename) cJSON_AddStringToObject(jr, "middlename", m->middlename);
    if (m->middlename_en) cJSON_AddStringToObject(jr, "middlename_en", m->middlename_en);
    if (m->surname) cJSON_AddStringToObject(jr, "surname", m->surname);
    if (m->surname_en) cJSON_AddStringToObject(jr, "surname_en", m->surname_en);
    if (m->group) cJSON_AddStringToObject(jr, "group", m->group);
    if (m->group_en) cJSON_AddStringToObject(jr, "group_en", m->group_en);
    if (m->email) cJSON_AddStringToObject(jr, "email", m->email);
    if (m->homepage) cJSON_AddStringToObject(jr, "homepage", m->homepage);
    if (m->occupation) cJSON_AddStringToObject(jr, "occupation", m->occupation);
    if (m->occupation_en) cJSON_AddStringToObject(jr, "occupation_en", m->occupation_en);
    if (m->discipline) cJSON_AddStringToObject(jr, "discipline", m->discipline);
    if (m->inst) cJSON_AddStringToObject(jr, "inst", m->inst);
    if (m->inst_en) cJSON_AddStringToObject(jr, "inst_en", m->inst_en);
    if (m->instshort) cJSON_AddStringToObject(jr, "instshort", m->instshort);
    if (m->instshort_en) cJSON_AddStringToObject(jr, "instshort_en", m->instshort_en);
    if (m->fac) cJSON_AddStringToObject(jr, "fac", m->fac);
    if (m->fac_en) cJSON_AddStringToObject(jr, "fac_en", m->fac_en);
    if (m->facshort) cJSON_AddStringToObject(jr, "facshort", m->facshort);
    if (m->facshort_en) cJSON_AddStringToObject(jr, "facshort_en", m->facshort_en);
    if (m->phone) cJSON_AddStringToObject(jr, "phone", m->phone);
    if (m->birth_date != 0) cJSON_AddNumberToObject(jr, "birth_date", m->birth_date);
    if (m->entry_date != 0) cJSON_AddNumberToObject(jr, "entry_date", m->entry_date);
    if (m->graduation_date != 0) cJSON_AddNumberToObject(jr, "graduation_date", m->graduation_date);
    if (m->create_time > 0) cJSON_AddNumberToObject(jr, "create_time", m->create_time);
    if (m->last_change_time > 0) cJSON_AddNumberToObject(jr, "last_change_time", m->last_change_time);
    if (m->last_access_time > 0) cJSON_AddNumberToObject(jr, "last_access_time", m->last_access_time);

    return jr;
}

cJSON *
json_serialize_userlist_user_info(int user_id, const struct userlist_user_info *ui)
{
    cJSON *jr = cJSON_CreateObject();

    if (user_id > 0) cJSON_AddNumberToObject(jr, "user_id", user_id);
    if (ui->contest_id > 0) cJSON_AddNumberToObject(jr, "contest_id", ui->contest_id);
    if (ui->cnts_read_only > 0) cJSON_AddTrueToObject(jr, "cnts_read_only");
    if (ui->instnum > 0) cJSON_AddNumberToObject(jr, "instnum", ui->instnum);
    cJSON_AddNumberToObject(jr, "team_passwd_method", ui->team_passwd_method);
    if (ui->inst) cJSON_AddStringToObject(jr, "inst", ui->inst);
    if (ui->inst_en) cJSON_AddStringToObject(jr, "inst_en", ui->inst_en);
    if (ui->instshort) cJSON_AddStringToObject(jr, "instshort", ui->instshort);
    if (ui->instshort_en) cJSON_AddStringToObject(jr, "instshort_en", ui->instshort_en);
    if (ui->fac) cJSON_AddStringToObject(jr, "fac", ui->fac);
    if (ui->fac_en) cJSON_AddStringToObject(jr, "fac_en", ui->fac_en);
    if (ui->facshort) cJSON_AddStringToObject(jr, "facshort", ui->facshort);
    if (ui->facshort_en) cJSON_AddStringToObject(jr, "facshort_en", ui->facshort_en);
    if (ui->homepage) cJSON_AddStringToObject(jr, "homepage", ui->homepage);
    if (ui->city) cJSON_AddStringToObject(jr, "city", ui->city);
    if (ui->city_en) cJSON_AddStringToObject(jr, "city_en", ui->city_en);
    if (ui->country) cJSON_AddStringToObject(jr, "country", ui->country);
    if (ui->country_en) cJSON_AddStringToObject(jr, "country_en", ui->country_en);
    if (ui->region) cJSON_AddStringToObject(jr, "region", ui->region);
    if (ui->area) cJSON_AddStringToObject(jr, "area", ui->area);
    if (ui->zip) cJSON_AddStringToObject(jr, "zip", ui->zip);
    if (ui->street) cJSON_AddStringToObject(jr, "street", ui->street);
    if (ui->location) cJSON_AddStringToObject(jr, "location", ui->location);
    if (ui->spelling) cJSON_AddStringToObject(jr, "spelling", ui->spelling);
    if (ui->printer_name) cJSON_AddStringToObject(jr, "printer_name", ui->printer_name);
    if (ui->exam_id) cJSON_AddStringToObject(jr, "exam_id", ui->exam_id);
    if (ui->exam_cypher) cJSON_AddStringToObject(jr, "exam_cypher", ui->exam_cypher);
    if (ui->languages) cJSON_AddStringToObject(jr, "languages", ui->languages);
    if (ui->phone) cJSON_AddStringToObject(jr, "phone", ui->phone);
    if (ui->field0) cJSON_AddStringToObject(jr, "field0", ui->field0);
    if (ui->field1) cJSON_AddStringToObject(jr, "field1", ui->field1);
    if (ui->field2) cJSON_AddStringToObject(jr, "field2", ui->field2);
    if (ui->field3) cJSON_AddStringToObject(jr, "field3", ui->field3);
    if (ui->field4) cJSON_AddStringToObject(jr, "field4", ui->field4);
    if (ui->field5) cJSON_AddStringToObject(jr, "field5", ui->field5);
    if (ui->field6) cJSON_AddStringToObject(jr, "field6", ui->field6);
    if (ui->field7) cJSON_AddStringToObject(jr, "field7", ui->field7);
    if (ui->field8) cJSON_AddStringToObject(jr, "field8", ui->field8);
    if (ui->field9) cJSON_AddStringToObject(jr, "field9", ui->field9);
    if (ui->avatar_store) cJSON_AddStringToObject(jr, "avatar_store", ui->avatar_store);
    if (ui->avatar_id) cJSON_AddStringToObject(jr, "avatar_id", ui->avatar_id);
    if (ui->avatar_suffix) cJSON_AddStringToObject(jr, "avatar_suffix", ui->avatar_suffix);
    if (ui->create_time > 0) cJSON_AddNumberToObject(jr, "create_time", ui->create_time);
    if (ui->last_login_time > 0) cJSON_AddNumberToObject(jr, "last_login_time", ui->last_login_time);
    if (ui->last_change_time > 0) cJSON_AddNumberToObject(jr, "last_change_time", ui->last_change_time);
    if (ui->last_access_time > 0) cJSON_AddNumberToObject(jr, "last_access_time", ui->last_access_time);
    if (ui->last_pwdchange_time > 0) cJSON_AddNumberToObject(jr, "last_pwdchange_time", ui->last_pwdchange_time);

    if (ui->members && ui->members->a > 0) {
        cJSON *jms = cJSON_CreateArray();
        for (int i = 0; i < ui->members->a; ++i) {
            if (ui->members->m[i]) {
                cJSON *jm = json_serialize_userlist_member(user_id, ui->contest_id, ui->members->m[i]);
                cJSON_AddItemToArray(jms, jm);
            }
        }
        cJSON_AddItemToObject(jr, "members", jms);
    }

    return jr;
}

cJSON *
json_serialize_userlist_contest(int user_id, const struct userlist_contest *uc)
{
    cJSON *jr = cJSON_CreateObject();

    if (user_id > 0) cJSON_AddNumberToObject(jr, "user_id", user_id);
    if (uc->id > 0) cJSON_AddNumberToObject(jr, "contest_id", uc->id);
    cJSON_AddNumberToObject(jr, "status", uc->status);
    if (uc->create_time > 0) cJSON_AddNumberToObject(jr, "create_time", uc->create_time);
    if (uc->last_change_time > 0) cJSON_AddNumberToObject(jr, "last_change_time", uc->last_change_time);
    if ((uc->flags & USERLIST_UC_INVISIBLE) != 0) cJSON_AddTrueToObject(jr, "is_invisible");
    if ((uc->flags & USERLIST_UC_BANNED) != 0) cJSON_AddTrueToObject(jr, "is_banned");
    if ((uc->flags & USERLIST_UC_LOCKED) != 0) cJSON_AddTrueToObject(jr, "is_locked");
    if ((uc->flags & USERLIST_UC_INCOMPLETE) != 0) cJSON_AddTrueToObject(jr, "is_incomplete");
    if ((uc->flags & USERLIST_UC_DISQUALIFIED) != 0) cJSON_AddTrueToObject(jr, "is_disqualified");
    if ((uc->flags & USERLIST_UC_PRIVILEGED) != 0) cJSON_AddTrueToObject(jr, "is_privileged");
    if ((uc->flags & USERLIST_UC_REG_READONLY) != 0) cJSON_AddTrueToObject(jr, "is_reg_readonly");

    return jr;
}

cJSON *
json_serialize_userlist_user(
        const struct userlist_user *u,
        const struct userlist_user_info *ui,
        const struct userlist_contest *uc)
{
    cJSON *jr = cJSON_CreateObject();

    cJSON_AddNumberToObject(jr, "user_id", u->id);
    if (u->is_privileged > 0) cJSON_AddTrueToObject(jr, "is_privileged");
    if (u->is_invisible > 0) cJSON_AddTrueToObject(jr, "is_invisible");
    if (u->is_banned > 0) cJSON_AddTrueToObject(jr, "is_banned");
    if (u->is_locked > 0) cJSON_AddTrueToObject(jr, "is_locked");
    if (u->show_login > 0) cJSON_AddTrueToObject(jr, "show_login");
    if (u->show_email > 0) cJSON_AddTrueToObject(jr, "show_email");
    if (u->read_only > 0) cJSON_AddTrueToObject(jr, "read_only");
    if (u->never_clean > 0) cJSON_AddTrueToObject(jr, "never_clean");
    if (u->simple_registration > 0) cJSON_AddTrueToObject(jr, "simple_registration");
    if (u->login && u->login[0]) cJSON_AddStringToObject(jr, "user_login", u->login);
    if (u->email && u->email[0]) cJSON_AddStringToObject(jr, "email", u->email);
    if (u->passwd_method > 0) cJSON_AddNumberToObject(jr, "passwd_method", u->passwd_method);
    if (u->extra1) cJSON_AddStringToObject(jr, "extra1", u->extra1);
    if (u->registration_time > 0) cJSON_AddNumberToObject(jr, "registration_time", u->registration_time);
    if (u->last_login_time > 0) cJSON_AddNumberToObject(jr, "last_login_time", u->last_login_time);
    if (u->last_minor_change_time > 0) cJSON_AddNumberToObject(jr, "last_minor_change_time",u->last_minor_change_time);
    if (u->last_change_time > 0) cJSON_AddNumberToObject(jr, "last_change_time", u->last_change_time);
    if (u->last_access_time > 0) cJSON_AddNumberToObject(jr, "last_access_time", u->last_access_time);
    if (u->last_pwdchange_time > 0) cJSON_AddNumberToObject(jr, "last_pwdchange_time", u->last_pwdchange_time);

    if (u->contests && u->contests->first_down) {
        cJSON *jcs = cJSON_CreateArray();
        for (const struct xml_tree *p = u->contests->first_down; p; p = p->right) {
            const struct userlist_contest *uc = (const struct userlist_contest*) p;
            cJSON *jc = json_serialize_userlist_contest(u->id, uc);
            cJSON_AddItemToArray(jcs, jc);
        }
        cJSON_AddItemToObject(jr, "contests", jcs);
    }

    //struct xml_tree *cookies;

    if (u->cis_a > 0) {
        cJSON *juis = cJSON_CreateArray();
        for (int i = 0; i < u->cis_a; ++i) {
            cJSON *jui = json_serialize_userlist_user_info(u->id, u->cis[i]);
            cJSON_AddItemToArray(juis, jui);
        }
        cJSON_AddItemToObject(jr, "infos", juis);
    }

    return jr;
}
