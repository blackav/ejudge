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

#include "reuse/xalloc.h"

extern int
csp_view_new_main_page(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);

static void
destroy_func(
        PageInterface *ps)
{
    CspNewMainPage *pp = (CspNewMainPage *) ps;
    xfree(pp);
}

static int
execute_func(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    CspNewMainPage *pp = (CspNewMainPage *) ps;
    (void) pp;
    return 0;
}

static struct PageInterfaceOps ops =
{
    destroy_func,
    execute_func,
    csp_view_new_main_page,
};

PageInterface *
csp_get_new_main_page(void)
{
    CspNewMainPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
