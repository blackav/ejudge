/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/super_serve_pi.h"
#include "ejudge/contests.h"
#include "ejudge/http_request.h"
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"
#include "ejudge/super_proto.h"

#include "ejudge/xalloc.h"

#include <string.h>

extern int
csp_view_check_tests_page(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);

static void
destroy_func(
        PageInterface *ps)
{
    CspCheckTestsPage *pp = (CspCheckTestsPage *) ps;
    if (!pp) return;
    xfree(pp->log_txt);
    memset(pp, 0, sizeof(*pp));
    xfree(pp);
}

static int
execute_func(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    CspCheckTestsPage *pp = (CspCheckTestsPage *) ps;
    if (!pp) return 0;

    const struct contest_desc *cnts = 0;
    if (contests_get(phr->contest_id, &cnts) < 0 || !cnts) return -SSERV_ERR_INVALID_CONTEST;
    if (phr->ss->edited_cnts) return -SSERV_ERR_CONTEST_EDITED;
    if (phr->priv_level != PRIV_LEVEL_ADMIN) return -SSERV_ERR_PERMISSION_DENIED;

    opcap_t caps = 0;
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0) return -SSERV_ERR_PERMISSION_DENIED;
    if (opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) return -SSERV_ERR_PERMISSION_DENIED;

    struct contest_desc *rw_cnts = 0;
    if (contests_load(phr->contest_id, &rw_cnts) < 0 || !rw_cnts) return -SSERV_ERR_INVALID_CONTEST;
    phr->ss->edited_cnts = rw_cnts;
    super_html_load_serve_cfg(rw_cnts, phr->config, phr->ss);

    char *log_t = 0;
    size_t log_z = 0;
    FILE *log_ff = open_memstream(&log_t, &log_z);
    pp->status = super_html_new_check_tests(log_ff, phr->config, phr->ss);
    fclose(log_ff); log_ff = 0;
    pp->log_txt = log_t; log_t = 0;
    log_z = 0;
    super_serve_clear_edited_contest(phr->ss);

    return 0;
}

static struct PageInterfaceOps ops =
{
    destroy_func,
    execute_func,
    csp_view_check_tests_page,
};

PageInterface *
csp_get_check_tests_page(void)
{
    CspCheckTestsPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
