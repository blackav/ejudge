/* -*- mode:c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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

#include "tex_dom.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <string.h>

static const unsigned char * const node_names[] =
{
  [TEX__DOC] "_DOC",
  [TEX__PAR] "_PAR",
  [TEX__WORD] "_WORD",
  [TEX__SPACE] "_SPACE",
  [TEX__BLOCK] "_BLOCK",
  [TEX_BEGIN] "\\begin",
  [TEX_END] "\\end",
  [TEX_IT] "\\it",
  [TEX_ENV_CENTER] "\\begin{center}",
};

const unsigned char *
tex_dom_get_node_name(int kind)
{
  static unsigned char tmpbuf[64];

  if (kind < 0 || kind >= sizeof(node_names) / sizeof(node_names[0])
      || !node_names[kind]) {
    snprintf(tmpbuf, sizeof(tmpbuf), "NODE_%d", kind);
    return tmpbuf;
  }
  return node_names[kind];
}

static void
do_tex_dom_print(FILE *f, tex_dom_t node, const unsigned char *margin)
{
  tex_dom_t p;
  unsigned char *new_marg;

  if (!node) return;
  ASSERT(node->tag >= 1 && node->tag < TEX__LAST);
  ASSERT(node_names[node->tag]);
  switch (node->tag) {
  case TEX__WORD:
    ASSERT(!node->first);
    ASSERT(!node->n);
    ASSERT(!node->refs);
    ASSERT(node->txt);
    fprintf(f, "%s%s: <%s>\n", margin, node_names[node->tag], node->txt);
    break;
  case TEX__SPACE:
    ASSERT(!node->first);
    ASSERT(!node->n);
    ASSERT(!node->refs);
    ASSERT(!node->txt);
    fprintf(f, "%s%s\n", margin, node_names[node->tag]);
    break;
  default:
    ASSERT(!node->txt);
    fprintf(f, "%s%s\n", margin, node_names[node->tag]);
    new_marg = alloca(strlen(margin) + 3);
    sprintf(new_marg, "  %s", margin);
    for (p = node->first; p; p = p->next)
      do_tex_dom_print(f, p, new_marg);
    break;
  }
}

void
tex_dom_print(FILE *f, tex_dom_t node)
{
  do_tex_dom_print(f, node, "");
}

tex_dom_t
tex_dom_free(tex_dom_t node)
{
  tex_dom_t p, q;

  if (!node) return 0;
  xfree(node->txt);
  xfree(node->refs);
  p = node->first;
  while (p) {
    q = p->next;
    tex_dom_free(p);
    p = q;
  }
  xfree(node);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "gcc -Wall -g -I/home/cher/reuse/include -I/home/cher/reuse/include/ix86-linux -L/home/cher/reuse/lib/ix86-linux tex_dom.c tex_dom_parse.c tex_dom_render.c tex_dom_doc.c tex_dom_test.c -o tex_dom -lreuse -lm"
 * End:
 */
