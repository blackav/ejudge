/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023-2025 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/contests.h"
#include "ejudge/expat_iface.h"
#include "ejudge/meta/contests_meta.h"
#include "ejudge/ej_types.h"
#include "ejudge/json_serializers.h"
#include "ejudge/cJSON.h"
#include "ejudge/meta_generic.h"
#include "ejudge/opcaps.h"
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
#include "ejudge/xalloc.h"
#include "ejudge/base64.h"
#include "ejudge/meta/prepare_meta.h"

#include <stdio.h>
#include <time.h>

void
json_serialize_file_content(
                            cJSON *jd, // target json
                            const unsigned char *attr_name,
                            const unsigned char *orig_attr_name,
                            const struct testing_report_file_content *fc)
{
    if (fc->size <= 0) return;
    if (fc->is_too_big <= 0 && fc->is_base64 <= 0 && fc->is_bzip2 <= 0) {
        cJSON_AddStringToObject(jd, attr_name, fc->data);
        return;
    }
    cJSON *jfc = cJSON_CreateObject();
    if (fc->size > 0) {
        cJSON_AddNumberToObject(jfc, "size", fc->size);
    }
    if (fc->orig_size > 0) {
        cJSON_AddNumberToObject(jfc, "orig_size", fc->orig_size);
    }
    if (fc->data) {
        cJSON_AddStringToObject(jfc, "data", fc->data);
    }
    if (fc->is_too_big > 0) {
        cJSON_AddTrueToObject(jfc, "is_too_big");
    }
    if (fc->is_base64 > 0) {
        cJSON_AddTrueToObject(jfc, "is_base64");
    }
    if (fc->is_bzip2 > 0) {
        cJSON_AddTrueToObject(jfc, "is_bzip2");
    }
    cJSON_AddItemToObject(jd, orig_attr_name, jfc);
    if (fc->is_bzip2 > 0) {
        cJSON_AddStringToObject(jd, attr_name, "[data format is not supported]");
        return;
    }
    if (fc->is_too_big > 0) {
        cJSON_AddStringToObject(jd, attr_name, "[data is too big]");
        return;
    }
    size_t in_len = strlen(fc->data);
    unsigned char *out_buf = xmalloc(in_len + 16);
    int error_flag = 0;
    int out_len = base64_decode(fc->data, in_len, out_buf, &error_flag);
    if (error_flag) {
        cJSON_AddStringToObject(jd, attr_name, "[data is invalid]");
        xfree(out_buf);
        return;
    }
    out_buf[out_len] = 0;
    if (strlen(out_buf) == out_len) {
        cJSON_AddStringToObject(jd, attr_name, out_buf);
        xfree(out_buf);
        return;
    }
    // count the number of zero bytes
    int zero_cnt = 0;
    for (int i = 0; i < out_len; ++i) {
        if (!out_buf[i]) {
            ++zero_cnt;
        }
    }
    unsigned char *w_buf = xmalloc(out_len + 1 + zero_cnt * 2);
    unsigned char *w_ptr = w_buf;
    for (int i = 0; i < out_len; ++i) {
        if (!out_buf[i]) {
            *w_ptr++ = 0xe2;
            *w_ptr++ = 0x90;
            *w_ptr++ = 0x80;
        } else {
            *w_ptr++ = out_buf[i];
        }
    }
    *w_ptr = 0;
    xfree(out_buf);
    cJSON_AddStringToObject(jd, attr_name, w_buf);
    xfree(w_buf);
}

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
                    json_serialize_file_content(jrr, "input", "input_orig", &ttr->input);
                    json_serialize_file_content(jrr, "output", "output_orig", &ttr->output);
                    json_serialize_file_content(jrr, "error", "error_orig", &ttr->error);
                    json_serialize_file_content(jrr, "test_checker", "test_checker_orig", &ttr->test_checker);
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
    if (ui->name && ui->name[0]) {
        cJSON_AddStringToObject(jr, "user_name", ui->name);
    }
    if (ui->cnts_read_only > 0) cJSON_AddTrueToObject(jr, "cnts_read_only");
    if (ui->instnum > 0) cJSON_AddNumberToObject(jr, "instnum", ui->instnum);
    if (ui->team_passwd && ui->team_passwd[0]) {
        cJSON_AddNumberToObject(jr, "team_passwd_method", ui->team_passwd_method);
    }
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

    if (uc) {
        cJSON *jcs = cJSON_CreateArray();
        cJSON *jc = json_serialize_userlist_contest(u->id, uc);
        cJSON_AddItemToArray(jcs, jc);
        cJSON_AddItemToObject(jr, "contests", jcs);
    } else {
        if (u->contests && u->contests->first_down) {
            cJSON *jcs = cJSON_CreateArray();
            for (const struct xml_tree *p = u->contests->first_down; p; p = p->right) {
                const struct userlist_contest *uc = (const struct userlist_contest*) p;
                cJSON *jc = json_serialize_userlist_contest(u->id, uc);
                cJSON_AddItemToArray(jcs, jc);
            }
            cJSON_AddItemToObject(jr, "contests", jcs);
        }
    }

    //struct xml_tree *cookies;

    if (ui) {
        cJSON *juis = cJSON_CreateArray();
        cJSON *jui = json_serialize_userlist_user_info(u->id, ui);
        cJSON_AddItemToArray(juis, jui);
        cJSON_AddItemToObject(jr, "infos", juis);
    } else {
        if (u->cis_a > 0) {
            cJSON *juis = cJSON_CreateArray();
            for (int i = 0; i < u->cis_a; ++i) {
                cJSON *jui = json_serialize_userlist_user_info(u->id, u->cis[i]);
                cJSON_AddItemToArray(juis, jui);
            }
            cJSON_AddItemToObject(jr, "infos", juis);
        }
    }

    return jr;
}

cJSON *
json_serialize_language(const struct section_language_data *lang, int final_mode)
{
    cJSON *jr = cJSON_CreateObject();

    cJSON_AddNumberToObject(jr, "id", (double) lang->id);
    if (lang->compile_id > 0 && lang->compile_id != lang->id) {
        cJSON_AddNumberToObject(jr, "compile_id", (double) lang->compile_id);
    }
    if (lang->disabled > 0) {
        cJSON_AddTrueToObject(jr, "disabled");
    } else if (!lang->disabled && !final_mode) {
        cJSON_AddFalseToObject(jr, "disabled");
    }
    if (lang->compile_real_time_limit > 0) {
        cJSON_AddNumberToObject(jr, "compile_real_time_limit", (double) lang->compile_real_time_limit);
    }
    if (lang->binary > 0) {
        cJSON_AddTrueToObject(jr, "binary");
    } else if (!lang->binary && !final_mode) {
        cJSON_AddFalseToObject(jr, "binary");
    }
    if (lang->priority_adjustment != 0) {
        cJSON_AddNumberToObject(jr, "priority_adjustment", (double) lang->priority_adjustment);
    }
    if (lang->insecure > 0) {
        cJSON_AddTrueToObject(jr, "insecure");
    } else if (!lang->insecure && !final_mode) {
        cJSON_AddFalseToObject(jr, "insecure");
    }
    if (lang->disable_security > 0) {
        cJSON_AddTrueToObject(jr, "disable_security");
    } else if (!lang->disable_security && !final_mode) {
        cJSON_AddFalseToObject(jr, "disable_security");
    }
    if (lang->enable_suid_run > 0) {
        cJSON_AddTrueToObject(jr, "enable_suid_run");
    } else if (!lang->enable_suid_run && !final_mode) {
        cJSON_AddFalseToObject(jr, "enable_suid_run");
    }
    if (lang->is_dos > 0) {
        cJSON_AddTrueToObject(jr, "is_dos");
    } else if (!lang->is_dos && !final_mode) {
        cJSON_AddFalseToObject(jr, "is_dos");
    }
    cJSON_AddStringToObject(jr, "short_name", lang->short_name);
    if (lang->long_name) {
        cJSON_AddStringToObject(jr, "long_name", lang->long_name);
    }
    if (lang->key && (!final_mode || lang->key[0])) {
        cJSON_AddStringToObject(jr, "key", lang->key);
    }
    if (lang->arch && (!final_mode || lang->arch[0])) {
        cJSON_AddStringToObject(jr, "arch", lang->arch);
    }
    cJSON_AddStringToObject(jr, "src_sfx", lang->src_sfx);
    cJSON_AddStringToObject(jr, "exe_sfx", lang->exe_sfx);
    if (lang->content_type && (!final_mode || lang->content_type[0])) {
        cJSON_AddStringToObject(jr, "content_type", lang->content_type);
    }
    if (lang->cmd && (!final_mode || lang->cmd[0])) {
        cJSON_AddStringToObject(jr, "cmd", lang->cmd);
    }
    if (lang->style_checker_cmd && (!final_mode || lang->style_checker_cmd[0])) {
        cJSON_AddStringToObject(jr, "style_checker_cmd", lang->style_checker_cmd);
    }
    if (lang->style_checker_env && (!final_mode || lang->style_checker_env[0])) {
        cJSON *ja = cJSON_CreateArray();
        for (int i = 0; lang->style_checker_env[i]; ++i) {
            cJSON *js = cJSON_CreateString(lang->style_checker_env[i]);
            cJSON_AddItemToArray(ja, js);
        }
        cJSON_AddItemToObject(jr, "style_checker_env", ja);
    }
    if (lang->extid && (!final_mode || lang->extid[0])) {
        cJSON_AddStringToObject(jr, "extid", lang->extid);
    }
    if (lang->super_run_dir && (!final_mode || lang->super_run_dir[0])) {
        cJSON_AddStringToObject(jr, "super_run_dir", lang->super_run_dir);
    }
    if (lang->disable_auto_testing > 0) {
        cJSON_AddTrueToObject(jr, "disable_auto_testing");
    } else if (!lang->disable_auto_testing && !final_mode) {
        cJSON_AddFalseToObject(jr, "disable_auto_testing");
    }
    if (lang->disable_testing > 0) {
        cJSON_AddTrueToObject(jr, "disable_testing");
    } else if (!lang->disable_testing && !final_mode) {
        cJSON_AddFalseToObject(jr, "disable_testing");
    }
    if (lang->enable_custom > 0) {
        cJSON_AddTrueToObject(jr, "enable_custom");
    } else if (!lang->enable_custom && !final_mode) {
        cJSON_AddFalseToObject(jr, "enable_custom");
    }
    if (lang->enable_ejudge_env > 0) {
        cJSON_AddTrueToObject(jr, "enable_ejudge_env");
    } else if (!lang->enable_ejudge_env && !final_mode) {
        cJSON_AddFalseToObject(jr, "enable_ejudge_env");
    }
    if (lang->enable_network > 0) {
        cJSON_AddTrueToObject(jr, "enable_network");
    } else if (!lang->enable_network && !final_mode) {
        cJSON_AddFalseToObject(jr, "enable_network");
    }
    if (lang->enable_remote_cache > 0) {
        cJSON_AddTrueToObject(jr, "enable_remote_cache");
    } else if (!lang->enable_remote_cache && !final_mode) {
        cJSON_AddFalseToObject(jr, "enable_remote_cache");
    }
    if (lang->preserve_line_numbers > 0) {
        cJSON_AddTrueToObject(jr, "preserve_line_numbers");
    } else if (!lang->preserve_line_numbers && !final_mode) {
        cJSON_AddFalseToObject(jr, "preserve_line_numbers");
    }
    if (lang->default_disabled > 0) {
        cJSON_AddTrueToObject(jr, "default_disabled");
    } else if (!lang->default_disabled && !final_mode) {
        cJSON_AddFalseToObject(jr, "default_disabled");
    }
    if (lang->enabled > 0) {
        cJSON_AddTrueToObject(jr, "enabled");
    } else if (!lang->enabled && !final_mode) {
        cJSON_AddFalseToObject(jr, "enabled");
    }
    if (lang->disable_auto_update > 0) {
        cJSON_AddTrueToObject(jr, "disable_auto_update");
    } else if (!lang->disable_auto_update && !final_mode) {
        cJSON_AddFalseToObject(jr, "disable_auto_update");
    }
    if (lang->max_vm_size > 0) {
        cJSON_AddNumberToObject(jr, "max_vm_size", (double) lang->max_vm_size);
    }
    if (lang->max_stack_size > 0) {
        cJSON_AddNumberToObject(jr, "max_stack_size", (double) lang->max_stack_size);
    }
    if (lang->max_file_size > 0) {
        cJSON_AddNumberToObject(jr, "max_file_size", (double) lang->max_file_size);
    }
    if (lang->max_rss_size > 0) {
        cJSON_AddNumberToObject(jr, "max_rss_size", (double) lang->max_rss_size);
    }
    if (lang->run_max_stack_size > 0) {
        cJSON_AddNumberToObject(jr, "run_max_stack_size", (double) lang->run_max_stack_size);
    }
    if (lang->run_max_vm_size > 0) {
        cJSON_AddNumberToObject(jr, "run_max_vm_size", (double) lang->run_max_vm_size);
    }
    if (lang->run_max_rss_size > 0) {
        cJSON_AddNumberToObject(jr, "run_max_rss_size", (double) lang->run_max_rss_size);
    }
    if (lang->run_max_file_size > 0) {
        cJSON_AddNumberToObject(jr, "run_max_file_size", (double) lang->run_max_file_size);
    }

    if (lang->compiler_env && (!final_mode || lang->compiler_env[0])) {
        cJSON *ja = cJSON_CreateArray();
        for (int i = 0; lang->compiler_env[i]; ++i) {
            cJSON *js = cJSON_CreateString(lang->compiler_env[i]);
            cJSON_AddItemToArray(ja, js);
        }
        cJSON_AddItemToObject(jr, "compiler_env", ja);
    }
    if (lang->compile_server_id && (!final_mode || lang->compile_server_id[0])) {
        cJSON_AddStringToObject(jr, "compile_server_id", lang->compile_server_id);
    }
    if (lang->multi_header_suffix && (!final_mode || lang->multi_header_suffix[0])) {
        cJSON_AddStringToObject(jr, "multi_header_suffix", lang->multi_header_suffix);
    }
    if (lang->container_options && (!final_mode || lang->container_options[0])) {
        cJSON_AddStringToObject(jr, "container_options", lang->container_options);
    }
    if (lang->compiler_container_options && (!final_mode || lang->compiler_container_options[0])) {
        cJSON_AddStringToObject(jr, "compiler_container_options", lang->compiler_container_options);
    }
    if (lang->clean_up_cmd && (!final_mode || lang->clean_up_cmd[0])) {
        cJSON_AddStringToObject(jr, "clean_up_cmd", lang->clean_up_cmd);
    }
    if (lang->run_env_file && (!final_mode || lang->run_env_file[0])) {
        cJSON_AddStringToObject(jr, "run_env_file", lang->run_env_file);
    }
    if (lang->clean_up_env_file && (!final_mode || lang->clean_up_env_file[0])) {
        cJSON_AddStringToObject(jr, "clean_up_env_file", lang->clean_up_env_file);
    }
    if (lang->version && (!final_mode || lang->version[0])) {
        cJSON_AddStringToObject(jr, "version", lang->version);
    }
    if (lang->unhandled_vars && !final_mode) {
        cJSON_AddStringToObject(jr, "unhandled_vars", lang->unhandled_vars);
    }

    return jr;
}

cJSON *
json_serialize_userlist_cookie(const struct userlist_cookie *c)
{
    cJSON *jr = cJSON_CreateObject();
    unsigned char buf[64];

    if (!ipv6_is_empty(&c->ip)) {
        cJSON_AddStringToObject(jr, "ip", xml_unparse_ipv6(&c->ip));
    }
    snprintf(buf, sizeof(buf), "%016llx", c->cookie);
    cJSON_AddStringToObject(jr, "cookie", buf);
    snprintf(buf, sizeof(buf), "%016llx", c->client_key);
    cJSON_AddStringToObject(jr, "client_key", buf);
    if (c->expire > 0) {
        cJSON_AddNumberToObject(jr, "expire", c->expire);
    }
    if (c->user_id > 0) {
        cJSON_AddNumberToObject(jr, "user_id", c->user_id);
    }
    if (c->ssl > 0) {
        cJSON_AddTrueToObject(jr, "ssl");
    }
    if (c->contest_id > 0) {
        cJSON_AddNumberToObject(jr, "contest_id", c->contest_id);
    }
    if (c->locale_id > 0) {
        cJSON_AddNumberToObject(jr, "locale_id", c->locale_id);
    }
    if (c->priv_level > 0) {
        cJSON_AddNumberToObject(jr, "priv_level", c->priv_level);
    }
    if (c->role > 0) {
        cJSON_AddNumberToObject(jr, "role", c->role);
    }
    if (c->recovery > 0) {
        cJSON_AddTrueToObject(jr, "recovery");
    }
    if (c->team_login > 0) {
        cJSON_AddTrueToObject(jr, "team_login");
    }
    if (c->is_ws > 0) {
        cJSON_AddTrueToObject(jr, "is_ws");
    }
    if (c->is_job > 0) {
        cJSON_AddTrueToObject(jr, "is_job");
    }

    return jr;
}

static const unsigned char *
unparse_date_iso(unsigned char *buf, size_t size, time_t t)
{
    struct tm tt;
    gmtime_r(&t, &tt);
    snprintf(buf, size, "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tt.tm_year + 1900, tt.tm_mon + 1, tt.tm_mday, tt.tm_hour, tt.tm_min, tt.tm_sec);
    return buf;
}

static const unsigned char * const field_names[] =
{
    [1] = "homepage", "phone", "inst",
    "inst_en", "instshort", "instshort_en", "instnum",
    "fac", "fac_en", "facshort", "facshort_en",
    "city", "city_en", "country", "country_en",
    "region", "area", "zip", "street",
    "languages", "field0", "field1", "field2",
    "field3", "field4", "field5", "field6",
    "field7", "field8", "field9",
};

static const unsigned char * const member_names[] =
{
    "contestant", "reserve", "coach", "advisor",
    "guest",
};

static const unsigned char * const member_field_names[] =
{
    "serial", "firstname", "firstname_en", "middlename",
    "middlename_en", "surname", "surname_en", "status",
    "gender", "grade", "group", "group_en",
    "email", "homepage", "phone", "inst",
    "inst_en", "instshort", "instshort_en", "fac",
    "fac_en", "facshort", "facshort_en", "occupation",
    "occupation_en", "discipline", "birth_date", "entry_date",
    "graduation_date",
};

cJSON *
json_serialize_contest_access(const struct contest_access *ac)
{
    cJSON *jr = cJSON_CreateObject();
    if (ac && ac->default_is_allow > 0) {
        cJSON_AddTrueToObject(jr, "default_is_allow");
        if (ac->b.first_down) {
            cJSON *jrs = cJSON_CreateArray();
            for (struct xml_tree *p = ac->b.first_down; p; p = p->right) {
                struct contest_ip *pp = (struct contest_ip *) p;
                cJSON *ja = cJSON_CreateObject();
                if (pp->allow) {
                    cJSON_AddTrueToObject(ja, "allow");
                }
                if (pp->ssl) {
                    cJSON_AddTrueToObject(ja, "ssl");
                }
                cJSON_AddStringToObject(ja, "addr", xml_unparse_ipv6_mask(&pp->addr, &pp->mask));
                cJSON_AddItemToArray(jrs, ja);
            }
            cJSON_AddItemToObject(jr, "rules", jrs);
        }
    }
    return jr;
}

static cJSON*
serialize_contest_field(const struct contest_field *f)
{
    cJSON *jf = cJSON_CreateObject();
    if (f->mandatory > 0) {
        cJSON_AddTrueToObject(jf, "mandatory");
    }
    if (f->legend) {
        cJSON_AddStringToObject(jf, "legend", f->legend);
    }
    if (f->separator) {
        cJSON_AddStringToObject(jf, "separator", f->separator);
    }
    if (f->options) {
        cJSON_AddStringToObject(jf, "options", f->options);
    }
    if (f->checkbox > 0) {
        cJSON_AddTrueToObject(jf, "checkbox");
    }
    if (f->is_password > 0) {
        cJSON_AddTrueToObject(jf, "is_password");
    }
    return jf;
}

cJSON *
json_serialize_contest_xml_full(const struct contest_desc *cnts, int date_mode)
{
    cJSON *jr = cJSON_CreateObject();

    if (cnts->id > 0) {
        cJSON_AddNumberToObject(jr, "id", cnts->id);
    }

    const static int bool_fields[] =
    {
        CNTS_autoregister, CNTS_disable_team_password, CNTS_managed, CNTS_run_managed,
        CNTS_clean_users, CNTS_closed, CNTS_invisible, CNTS_simple_registration,
        CNTS_send_passwd_email, CNTS_assign_logins, CNTS_force_registration, CNTS_disable_name,
        CNTS_enable_password_recovery, CNTS_exam_mode, CNTS_disable_password_change, CNTS_disable_locale_change,
        CNTS_personal, CNTS_allow_reg_data_edit, CNTS_disable_member_delete, CNTS_ready,
        CNTS_force_password_change, CNTS_enable_user_telegram, CNTS_enable_avatar, CNTS_enable_local_pages,
        CNTS_read_only_name, CNTS_enable_oauth, CNTS_enable_reminders, CNTS_disable_standalone_reg,
        CNTS_enable_telegram_registration, CNTS_enable_special_flow, CNTS_enable_user_finish, CNTS_disable_user_finish,
    };
    for (int i = 0; i < sizeof(bool_fields) / sizeof(bool_fields[0]); ++i) {
        const ejbytebool_t *ptr = (const ejbytebool_t *) contest_desc_get_ptr(cnts, bool_fields[i]);
        const unsigned char *name = contest_desc_get_name(bool_fields[i]);
        if (*ptr > 0) {
            cJSON_AddTrueToObject(jr, name);
        }
    }

    const static int time_fields[] =
    {
        CNTS_reg_deadline, CNTS_sched_time, CNTS_open_time, CNTS_close_time,
        CNTS_update_time,
    };
    for (int i = 0; i < sizeof(time_fields)/sizeof(time_fields[0]); ++i) {
        const time_t *ptr = (const time_t *) contest_desc_get_ptr(cnts, time_fields[i]);
        const unsigned char *name = contest_desc_get_name(time_fields[i]);
        if (*ptr > 0) {
            if (date_mode == 1) {
                unsigned char buf[64];
                cJSON_AddStringToObject(jr, name, unparse_date_iso(buf, sizeof(buf), *ptr));
            } else if (date_mode == 2) {
                cJSON_AddNumberToObject(jr, name, (double) *ptr);
            } else {
                cJSON_AddStringToObject(jr, name, xml_unparse_date(*ptr));
            }
        }
    }

    const static int string_fields[] =
    {
        CNTS_name, CNTS_name_en, CNTS_main_url, CNTS_keywords,
        CNTS_comment, CNTS_users_header_file, CNTS_users_footer_file, CNTS_register_header_file,
        CNTS_register_footer_file, CNTS_team_header_file, CNTS_team_menu_1_file, CNTS_team_menu_2_file,
        CNTS_team_menu_3_file, CNTS_team_separator_file, CNTS_team_footer_file, CNTS_priv_header_file,
        CNTS_priv_footer_file, CNTS_copyright_file, CNTS_register_email, CNTS_register_url,
        CNTS_team_url, CNTS_login_template, CNTS_login_template_options, CNTS_root_dir,
        CNTS_conf_dir, CNTS_standings_url, CNTS_problems_url, CNTS_analytics_url,
        CNTS_analytics_key, CNTS_serve_user, CNTS_serve_group, CNTS_run_user,
        CNTS_run_group, CNTS_register_email_file, CNTS_register_subject, CNTS_register_subject_en,
        CNTS_users_head_style, CNTS_users_par_style, CNTS_users_table_style, CNTS_users_verb_style,
        CNTS_users_table_format, CNTS_users_table_format_en, CNTS_users_table_legend, CNTS_users_table_legend_en,
        CNTS_register_head_style, CNTS_register_par_style, CNTS_register_table_style, CNTS_team_head_style,
        CNTS_team_par_style, CNTS_cf_notify_email, CNTS_clar_notify_email, CNTS_daily_stat_email,
        CNTS_user_name_comment, CNTS_allowed_languages, CNTS_allowed_regions, CNTS_dir_mode,
        CNTS_dir_group, CNTS_file_mode, CNTS_file_group, CNTS_welcome_file,
        CNTS_reg_welcome_file, CNTS_logo_url, CNTS_css_url, CNTS_ext_id,
        CNTS_problem_count, CNTS_telegram_bot_id, CNTS_telegram_admin_chat_id, CNTS_telegram_user_chat_id,
        CNTS_avatar_plugin, CNTS_content_plugin, CNTS_content_url_prefix, CNTS_special_flow_options,
    };
    for (int i = 0; i < sizeof(string_fields)/sizeof(string_fields[0]); ++i) {
        unsigned char **ptr = (unsigned char **) contest_desc_get_ptr(cnts, string_fields[i]);
        const unsigned char *name = contest_desc_get_name(string_fields[i]);
        if (*ptr) {
            cJSON_AddStringToObject(jr, name, *ptr);
        }
    }
    if (cnts->user_contest_num > 0) {
        cJSON_AddNumberToObject(jr, "user_contest", cnts->user_contest_num);
    }
    if (cnts->default_locale_num > 0) {
        cJSON_AddNumberToObject(jr, "default_locale", cnts->default_locale_num);
    }
    if (cnts->register_access) {
        cJSON_AddItemToObject(jr, "register_access", json_serialize_contest_access(cnts->register_access));
    }
    if (cnts->users_access) {
        cJSON_AddItemToObject(jr, "users_access", json_serialize_contest_access(cnts->users_access));
    }
    if (cnts->master_access) {
        cJSON_AddItemToObject(jr, "master_access", json_serialize_contest_access(cnts->master_access));
    }
    if (cnts->judge_access) {
        cJSON_AddItemToObject(jr, "judge_access", json_serialize_contest_access(cnts->judge_access));
    }
    if (cnts->team_access) {
        cJSON_AddItemToObject(jr, "team_access", json_serialize_contest_access(cnts->team_access));
    }
    if (cnts->serve_control_access) {
        cJSON_AddItemToObject(jr, "serve_control_access", json_serialize_contest_access(cnts->serve_control_access));
    }
    if (cnts->capabilities.first) {
        cJSON *jcs = cJSON_CreateArray();
        for (struct opcap_list_item *p = cnts->capabilities.first; p; p = (struct opcap_list_item *) p->b.right) {
            cJSON *jc = cJSON_CreateObject();
            cJSON_AddStringToObject(jc, "login", p->login);
            unsigned char *s = opcaps_unparse(0, 1024, p->caps);
            cJSON_AddStringToObject(jc, "caps", s);
            xfree(s);
            cJSON_AddItemToArray(jcs, jc);
        }
        cJSON_AddItemToObject(jr, "capabilities", jcs);
    }
    if (cnts->oauth_rules) {
        cJSON *ors = cJSON_CreateArray();
        for (const struct xml_tree *p1 = cnts->oauth_rules->first_down; p1; p1 = p1->right) {
            if (p1->tag == CONTEST_OAUTH_RULE) {
                cJSON *or = cJSON_CreateObject();
                for (const struct xml_attr *a = p1->first; a; a = a->next) {
                    switch (a->tag) {
                    case CONTEST_A_DOMAIN:
                        cJSON_AddStringToObject(or, "domain", a->text);
                        break;
                    case CONTEST_A_ALLOW: {
                        int val = 0;
                        xml_parse_bool(NULL, NULL, 0, 0, a->text, &val);
                        if (val > 0) {
                            cJSON_AddTrueToObject(or, "allow");
                        }
                        break;
                    }
                    case CONTEST_A_DENY: {
                        int val = 0;
                        xml_parse_bool(NULL, NULL, 0, 0, a->text, &val);
                        if (val > 0) {
                            cJSON_AddTrueToObject(or, "deny");
                        }
                        break;
                    }
                    case CONTEST_A_STRIP_DOMAIN: {
                        int val = 0;
                        xml_parse_bool(NULL, NULL, 0, 0, a->text, &val);
                        if (val > 0) {
                            cJSON_AddTrueToObject(or, "strip_domain");
                        }
                        break;
                    }
                    case CONTEST_A_DISABLE_EMAIL_CHECK: {
                        int val = 0;
                        xml_parse_bool(NULL, NULL, 0, 0, a->text, &val);
                        if (val > 0) {
                            cJSON_AddTrueToObject(or, "disable_email_check");
                        }
                        break;
                    }
                    }
                }
                cJSON_AddItemToArray(ors, or);
            }
        }
        cJSON_AddItemToObject(jr, "oauth_rules", ors);
    }

    int need_fields = 0;
    for (int i = 0; i < CONTEST_LAST_FIELD; ++i) {
        if (cnts->fields[i]) {
            need_fields = 1;
            break;
        }
    }
    if (need_fields) {
        cJSON *jfs = cJSON_CreateObject();
        for (int i = 0; i < CONTEST_LAST_FIELD; ++i) {
            struct contest_field *f = cnts->fields[i];
            if (f) {
                cJSON_AddItemToObject(jfs, field_names[i], serialize_contest_field(f));
            }
        }
        cJSON_AddItemToObject(jr, "fields", jfs);
    }
    int need_members = 0;
    for (int i = 0; i < CONTEST_LAST_MEMBER; ++i) {
        if (cnts->members[i]) {
            need_members = 1;
            break;
        }
    }
    if (need_members) {
        cJSON *jms = cJSON_CreateObject();
        for (int i = 0; i < CONTEST_LAST_MEMBER; ++i) {
            struct contest_member *m = cnts->members[i];
            if (m) {
                cJSON *jm = cJSON_CreateObject();
                if (m->min_count > 0) {
                    cJSON_AddNumberToObject(jm, "min_count", m->min_count);
                }
                if (m->max_count > 0) {
                    cJSON_AddNumberToObject(jm, "max_count", m->max_count);
                }
                if (m->init_count > 0) {
                    cJSON_AddNumberToObject(jm, "init_count", m->init_count);
                }
                int need_fields = 0;
                for (int j = 0; j < CONTEST_LAST_MEMBER_FIELD; ++j) {
                    if (m->fields[j]) {
                        need_fields = 1;
                        break;
                    }
                }
                if (need_fields) {
                    cJSON *jmfs = cJSON_CreateObject();
                    for (int j = 0; j < CONTEST_LAST_MEMBER_FIELD; ++j) {
                        struct contest_field *f = m->fields[j];
                        if (f) {
                            cJSON_AddItemToObject(jmfs, member_field_names[j], serialize_contest_field(f));
                        }
                    }
                    cJSON_AddItemToObject(jm, "fields", jmfs);
                }
                cJSON_AddItemToObject(jms, member_names[i], jm);
            }
        }
        cJSON_AddItemToObject(jr, "members", jms);
    }

    return jr;
}

static void
json_serialize_meta_field(
        cJSON *j,
        const void *ptr,
        const struct meta_methods *meta,
        int field,
        int date_mode,
        int size_mode)
{
    struct meta_info_item *item = &meta->items[field];
    switch (item->type) {
    case 'i': {
        int value = *(int *) meta->get_ptr(ptr, field);
        if (value >= 0) {
            cJSON_AddNumberToObject(j, item->name, value);
        }
        break;
    }
    case 'z': {
        ejintsize_t value = *(ejintsize_t *) meta->get_ptr(ptr, field);
        if (value > 0) {
            if (size_mode == 1) {
                cJSON_AddNumberToObject(j, item->name, value);
            } else {
                unsigned char buf[128];
                num_to_size_str(buf, sizeof(buf), value);
                cJSON_AddStringToObject(j, item->name, buf);
            }
        }
        break;
    }
    case 'B': {
        ejintbool_t value = *(ejintbool_t *) meta->get_ptr(ptr, field);
        if (value > 0) {
            cJSON_AddTrueToObject(j, item->name);
        } else if (!value) {
            cJSON_AddFalseToObject(j, item->name);
        }
        break;
    }
    case 't': {
        time_t value = *(time_t *) meta->get_ptr(ptr, field);
        if (value > 0) {
            if (date_mode == 1) {
                unsigned char buf[64];
                cJSON_AddStringToObject(j, item->name, unparse_date_iso(buf, sizeof(buf), value));
            } else if (date_mode == 2) {
                cJSON_AddNumberToObject(j, item->name, (double) value);
            } else {
                cJSON_AddStringToObject(j, item->name, xml_unparse_date(value));
            }
        }
        break;
    }
    case 's': {
        const unsigned char *value = *(const unsigned char **) meta->get_ptr(ptr, field);
        if (value) {
            cJSON_AddStringToObject(j, item->name, value);
        }
        break;
    }
    case 'x': {
        char **value = *(char ***) meta->get_ptr(ptr, field);
        if (value) {
            cJSON *ja = cJSON_CreateArray();
            for (int i = 0; value[i]; ++i) {
                cJSON_AddItemToArray(ja, cJSON_CreateString(value[i]));
            }
            cJSON_AddItemToObject(j, item->name, ja);
        }
        break;
    }
    case 'E': {
        ej_size64_t value = *(ej_size64_t *) meta->get_ptr(ptr, field);
        if (value > 0) {
            if (size_mode == 1) {
                cJSON_AddNumberToObject(j, item->name, value);
            } else {
                unsigned char buf[128];
                ll_to_size_str(buf, sizeof(buf), value);
                cJSON_AddStringToObject(j, item->name, buf);
            }
        }
        break;
    }
    }
}

cJSON *
json_serialize_global(const struct section_global_data *g, int date_mode, int size_mode, const unsigned char *ignored_fields)
{
    cJSON *jg = cJSON_CreateObject();
    for (int field = 1; field < CNTSGLOB_LAST_FIELD; ++field) {
        if (ignored_fields[field]) {
            continue;
        }
        switch (field) {
        case CNTSGLOB_priority_adjustment:
            if (g->priority_adjustment != 0) {
                cJSON_AddNumberToObject(jg, "priority_adjustment", g->priority_adjustment);
            }
            break;
        case CNTSGLOB_score_system:
            if (g->score_system >= 0 && g->score_system < SCORE_TOTAL) {
                cJSON_AddStringToObject(jg, "score_system", prepare_unparse_score_system(g->score_system));
            }
            break;
        case CNTSGLOB_rounding_mode:
            if (g->rounding_mode >= 0 && g->rounding_mode <= 2) {
                cJSON_AddStringToObject(jg, "rounding_mode", prepare_unparse_rounding_mode(g->rounding_mode));
            }
            break;
        default:
            json_serialize_meta_field(jg, g, &cntsglob_methods, field, date_mode, size_mode);
        }
    }
    return jg;
}
