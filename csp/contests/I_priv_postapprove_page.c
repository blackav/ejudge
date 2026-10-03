/* -*- c -*- */

/* Copyright (C) 2026 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/misctext.h"
#include "ejudge/new-server.h"
#include "ejudge/new_server_pi.h"
#include "ejudge/contests.h"
#include "ejudge/opcaps.h"
#include "ejudge/random.h"
#include "ejudge/prepare.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/runlog.h"
#include "ejudge/xml_utils.h"
#include "ejudge/fileutl.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

extern int
csp_view_priv_postapprove_page(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);

static void
destroy_func(
        PageInterface *ps)
{
    PrivPostapprovePage *pg = (PrivPostapprovePage *) ps;

    free(pg->err_id_str);
    free(pg->err_msg);
    free(pg->pre);
    if (pg->prr) {
        run_review_free(pg->prr);
        free(pg->prr);
    }
    free(pg->run_text);
    free(pg->statement_text);
}

static int
execute_func(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
#define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)
    PrivPostapprovePage *pg = (PrivPostapprovePage *) ps;
    unsigned err_id = random_u32();
    __attribute__((unused)) int _;
    long long serial_id = -1;
    struct contest_extra *extra = phr->extra;
    serve_state_t cs = extra->serve_state;
    struct run_review review = {};
    int r;
    const struct contest_desc *review_cnts = NULL;
    opcap_t review_cap = 0;
    struct contest_extra *review_extra = NULL;
    serve_state_t review_cs = NULL;
    struct run_entry re = {};
    const struct section_problem_data *prob = NULL;
    char *run_text = NULL;
    size_t run_size = 0;
    unsigned char *statement_text = NULL;

    uint64_t field_mask = RER_SERIAL_ID | RER_CREATION_TIME | RER_LAST_UPDATE_TIME |
        RER_MODERATION_TIME | RER_REVIEW_START_TIME | RER_REVIEW_FINISH_TIME |
        RER_REVIEW_UUID | RER_OPTIONS | RER_CUSTOM_PROMPT | RER_REVIEW_AGENT |
        RER_REVIEW_RESULT | RER_REVIEW_JUDGE_RESULT | RER_REVIEW_STATISTICS |
        RER_REVIEW_LOG | RER_MODEL | RER_CONTEST_ID | RER_RUN_ID |
        RER_REQUEST_USER_ID | RER_MODERATOR_USER_ID | RER_REVIEWER_USER_ID |
        RER_INPUT_TOKENS | RER_CACHED_INPUT_TOKENS | RER_OUPUT_TOKENS |
        RER_REASONING_TOKENS | RER_TOTAL_TOKENS | RER_GENERATION |
        RER_STATUS | RER_PURPOSE | RER_REVIEW_RECOMMENDED_STATUS | RER_AI_GENERATION_SCORE;

    hr_cgi_param_long_long_opt(phr, "serial_id", &serial_id, -1);
    if (serial_id < 0) {
        ERR("serial_id is invalid or undefined");
        _ = asprintf(&pg->err_msg, "serial_id is undefined or invalid");
        goto fail;
    }
    r = run_review_fetch_by_serial_id(cs->runlog_state, serial_id, field_mask, &review);
    if (!r) {
        ERR("review with serial_id %lld does not exist", serial_id);
        _ = asprintf(&pg->err_msg, "review with serial_id %lld does not exist", (long long) serial_id);
        goto fail;
    }
    if (r < 0) {
        ERR("database error on fetching review");
        _ = asprintf(&pg->err_msg, "database error");
        goto fail;
    }

    // load the contest specified in review
    if (contests_get(review.contest_id, &review_cnts) < 0 || !review_cnts) {
        ERR("invalid contest %d in review %lld", review.contest_id, serial_id);
        _ = asprintf(&pg->err_msg, "invalid contest");
        goto fail;
    }
    if (opcaps_find(&review_cnts->capabilities, phr->login, &review_cap) < 0 ||
        opcaps_check(review_cap, OPCAP_COMMENT_RUN) < 0) {
        ERR("user %s has no COMENT_RUN cap on contest %d for review %lld", phr->login, review.contest_id, (long long) serial_id);
        _ = asprintf(&pg->err_msg, "permission denied");
        goto fail;
    }
    if (phr->load_contest(phr->config, phr->fw_state, phr->userlist_clnt, review.contest_id) < 0) {
        ERR("failed to load contest %d for review %lld", review.contest_id, serial_id);
        _ = asprintf(&pg->err_msg, "failed to load contest");
        goto fail;
    }
    review_extra = ns_get_contest_extra(review_cnts, phr->config);
    ASSERT(review_extra);
    review_cs = review_extra->serve_state;
    ASSERT(review_cs);

    if (review.run_id < 0 || review.run_id >= run_get_total(review_cs->runlog_state)) {
        ERR("invalid run_id %d for review %lld, contest_id %d", review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "invalid run");
        goto fail;
    }
    if (run_get_entry(review_cs->runlog_state, review.run_id, &re) < 0) {
        ERR("failed to load run_id %d for review %lld, contest_id %d", review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "invalid run");
        goto fail;
    }
    if (!(re.status <= RUN_NORMAL_LAST || re.status == RUN_SUMMONED)) {
        ERR("invalid run status %d in run_id %d for review %lld, contest_id %d", re.status, review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "invalid run");
        goto fail;
    }
    if (re.prob_id <= 0 || re.prob_id > review_cs->max_prob || !(prob = review_cs->probs[re.prob_id])) {
        ERR("invalid problem %d in run_id %d for review %lld, contest_id %d", re.prob_id, review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "invalid problem");
        goto fail;
    }
    if (prob->enable_external_review <= 0) {
        ERR("external review disabled for problem %d in run_id %d for review %lld, contest_id %d", re.prob_id, review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "invalid problem");
        goto fail;
    }
    if (!prob->md_file || !prob->md_file[0]) {
        ERR("no md_file for problem %d in run_id %d for review %lld, contest_id %d", re.prob_id, review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "invalid problem");
        goto fail;
    }
    if (review_cs->global->advanced_layout <= 0) {
        ERR("advanced_layout required for problem %d in run_id %d for review %lld, contest_id %d", re.prob_id, review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "invalid problem");
        goto fail;
    }
    unsigned char src_path[PATH_MAX];
    src_path[0] = 0;
    int src_flags = serve_make_source_read_path(review_cs, src_path, sizeof(src_path), &re);
    if (src_flags < 0) {
        ERR("no source available for run_id %d for review %lld, contest_id %d", review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "run source not available");
        goto fail;
    }
    if (generic_read_file(&run_text, 0, &run_size, src_flags, NULL, src_path, NULL) < 0) {
        ERR("source failed for run_id %d for review %lld, contest_id %d", review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "run source not available");
        goto fail;
    }
    utf8_fix_buf_2(&run_text, &run_size, 1, 1);
    pg->source_language = ns_get_language_name(re.lang_id);
    int variant = re.variant;
    if (prob->variant_num > 0) {
        if (variant <= 0) variant = find_variant(review_cs, re.user_id, re.prob_id, NULL);
        if (variant <= 0) {
            ERR("invalid variant for run_id %d for review %lld, contest_id %d", review.run_id, serial_id, review.contest_id);
            _ = asprintf(&pg->err_msg, "invalid variant");
            goto fail;
        }
    } else {
        variant = 0;
    }

    unsigned char prob_path[PATH_MAX];
    prob_path[0] = 0;
    get_advanced_layout_path(prob_path, sizeof(prob_path), review_cs->global, prob, NULL, variant);
    statement_text = ns_safe_read_utf8_text_file(prob_path, prob->md_file, err_id, 0);
    if (!statement_text) {
        ERR("no md statement for problem %d in run_id %d for review %lld, contest_id %d", re.prob_id, review.run_id, serial_id, review.contest_id);
        _ = asprintf(&pg->err_msg, "problem statement not available");
        goto fail;
    }

    pg->serial_id = serial_id;
    pg->review_cnts = review_cnts;
    pg->review_cs = review_cs;
    XCALLOC(pg->pre, 1);
    XMEMCPY(pg->pre, &re, 1);
    XCALLOC(pg->prr, 1);
    XMEMCPY(pg->prr, &review, 1);
    XMEMZERO(&review, 1);
    pg->run_text = run_text; run_text = NULL;
    pg->statement_text = statement_text; statement_text = NULL;
    pg->variant = variant;

done:;
    run_review_free(&review);
    free(run_text);
    free(statement_text);
    return 0;

fail:;
    _ = asprintf(&pg->err_id_str, "%08x", err_id);
    goto done;
#undef ERR
}

static struct PageInterfaceOps ops =
{
    destroy_func,
    execute_func,
    csp_view_priv_postapprove_page,
};

PageInterface *
csp_get_priv_postapprove_page(void)
{
    PrivPostapprovePage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
}
