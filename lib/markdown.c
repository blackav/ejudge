/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/markdown.h"
#include "ejudge/xalloc.h"

#include "md4c/md4c-html.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void output_func(
        const MD_CHAR* data,
        MD_SIZE size,
        void *user)
{
    fwrite_unlocked(data, 1, size, (FILE *) user);
}

int
markdown_parse(
        const unsigned char *path,
        struct md_content *res)
{
    int retval = -1;
    FILE *fin = NULL;
    FILE *fmem = NULL;
    char *bmem = NULL;
    size_t zmem = 0;
    FILE *fhtml = 0;
    char *bhtml = 0;
    size_t zhtml = 0;
    int c;

    memset(res, 0, sizeof(*res));

    fin = fopen(path, "r");
    if (!fin) goto done;
    fmem = open_memstream(&bmem, &zmem);
    if (!fmem) goto done;
    while ((c = getc_unlocked(fin)) != EOF) {
        putc_unlocked(c, fmem);
    }
    fclose(fin); fin = NULL;
    fclose(fmem); fmem = NULL;

    fhtml = open_memstream(&bhtml, &zhtml);
    if (!fhtml) goto done;
    unsigned parser_flags = MD_FLAG_LATEXMATHSPANS;
    unsigned renderer_flags = MD_HTML_FLAG_SKIP_UTF8_BOM;
    if (md_html(bmem, zmem, output_func, fhtml, parser_flags, renderer_flags) < 0) {
        goto done;
    }
    fclose(fhtml); fhtml = NULL;

    res->path = xstrdup(path);
    res->data = bhtml; bhtml = NULL;
    res->size = zhtml; zhtml = 0;
    retval = 0;

done:;
    if (fin) fclose(fin);
    if (fmem) fclose(fmem);
    free(bmem);
    if (fhtml) fclose(fhtml);
    free(bhtml);
    return retval;
}
