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

static void
create_new_paragraph(tex_doc_t pdoc, tex_align_t align)
{
  tex_par_t ppar;

  ASSERT(align >= 0 && align < TEX_ALIGN_MAX);

  XCALLOC(ppar, 1);
  ppar->align = align;
  if (pdoc->u == pdoc->a) {
    if (!pdoc->a) {
      pdoc->a = 8;
      XCALLOC(pdoc->pars, pdoc->a);
    } else {
      pdoc->a *= 2;
      XREALLOC(pdoc->pars, pdoc->a);
    }
  }
  if (tex_dom_get_render_func_ptr) {
    ppar->render_func = (*tex_dom_get_render_func_ptr)(align);
  }
  pdoc->pars[pdoc->u++] = ppar;
}

static void
create_new_word(tex_doc_t pdoc)
{
  tex_par_t ppar;
  tex_word_t pword;

  ASSERT(pdoc->u > 0);
  ppar = pdoc->pars[pdoc->u - 1];
  XCALLOC(pword, 1);
  if (ppar->u == ppar->a) {
    if (!ppar->a) {
      ppar->a = 16;
      XCALLOC(ppar->words, ppar->a);
    } else {
      ppar->a *= 2;
      XREALLOC(ppar->words, ppar->a);
    }
  }
  ppar->words[ppar->u++] = pword;
}

static void
append_to_word(tex_doc_t pdoc, const unsigned char *pstr, tex_font_t font,
               unsigned char is_italic, unsigned char is_slanted,
               unsigned char is_bold, unsigned char is_underlined)
{
  tex_par_t ppar;
  tex_word_t pword;
  tex_char_t pchar;
  size_t len;
  const unsigned char *pp;

  ASSERT(pdoc);
  ASSERT(pdoc->u > 0);
  ppar = pdoc->pars[pdoc->u - 1];
  ASSERT(ppar->u > 0);
  pword = ppar->words[ppar->u - 1];
  len = strlen(pstr);

  if (pword->u + len > pword->a) {
    if (!pword->a) pword->a = 16;
    while (pword->u + len > pword->a) pword->a *= 2;
    XREALLOC(pword->chars, pword->a);
  }

  for (pp = pstr; *pp; pp++) {
    XCALLOC(pchar, 1);
    pchar->c = *pp;
    pchar->font = font;
    pchar->is_italic = is_italic;
    pchar->is_slanted = is_slanted;
    pchar->is_bold = is_bold;
    pchar->is_underlined = is_underlined;
    pword->chars[pword->u++] = pchar;
  }
}

typedef struct attr_struct
{
  tex_align_t par_align;
  tex_font_t font;
  unsigned char is_italic;
  unsigned char is_slanted;
  unsigned char is_bold;
  unsigned char is_underlined;
  unsigned char is_new_word;
} tex_attr_t;

static void
do_build_doc(tex_dom_t node, tex_doc_t pdoc, tex_attr_t *pattr)
{
  tex_attr_t locattr;

  if (!node) return;
  locattr = *pattr;
  switch (node->tag) {
  case TEX__DOC:
    do_build_doc(node->first, pdoc, pattr);
    break;
  case TEX__PAR:
    create_new_paragraph(pdoc, pattr->par_align);
    locattr.is_new_word = 1;
    do_build_doc(node->first, pdoc, &locattr);
    do_build_doc(node->next, pdoc, pattr);
    break;
  case TEX__BLOCK:
    do_build_doc(node->first, pdoc, pattr);
    do_build_doc(node->next, pdoc, pattr);
    break;
  case TEX__WORD:
    if (pattr->is_new_word) create_new_word(pdoc);
    locattr.is_new_word = 0;
    append_to_word(pdoc, node->txt, pattr->font, pattr->is_italic,
                   pattr->is_slanted, pattr->is_bold, pattr->is_underlined);
    do_build_doc(node->next, pdoc, &locattr);
    break;
  case TEX__SPACE:
    locattr.is_new_word = 1;
    do_build_doc(node->next, pdoc, &locattr);
    break;
  case TEX_ENV_CENTER:
    locattr.par_align = TEX_ALIGN_CENTER;
    do_build_doc(node->first, pdoc, &locattr);
    do_build_doc(node->next, pdoc, pattr);
    break;
  default:
    SWERR(("do_build_doc: unhandled node %d (%s)", node->tag,
           tex_dom_get_node_name(node->tag)));
  }
}

tex_doc_t
tex_dom_build_doc(tex_dom_t dom)
{
  tex_attr_t locattr;
  tex_doc_t pdoc;

  XMEMZERO(&locattr, 1);
  XCALLOC(pdoc, 1);
  do_build_doc(dom, pdoc, &locattr);
  return pdoc;
}

static int
get_par_width(tex_par_t ppar)
{
  int i;
  int width = 0;

  /* FIXME: must consider indent and margins */
  if (ppar->u > 1) width = ppar->u - 1;
  for (i = 0; i < ppar->u; i++) {
    width += ppar->words[i]->u;
  }
  return width;
}

int
tex_dom_get_doc_width(tex_doc_t pdoc)
{
  int i;
  int maxwidth = 0, width;

  for (i = 0; i < pdoc->u; i++) {
    width = get_par_width(pdoc->pars[i]);
    if (width > maxwidth) maxwidth = width;
  }
  return maxwidth;
}

tex_char_t
tex_dom_free_char(tex_char_t pchar)
{
  xfree(pchar);
  return 0;
}

tex_word_t
tex_dom_free_word(tex_word_t pword)
{
  int i;

  if (!pword) return 0;
  for (i = 0; i < pword->u; i++)
    tex_dom_free_char(pword->chars[i]);
  xfree(pword->chars);
  xfree(pword);
  return 0;
}

tex_par_t
tex_dom_free_par(tex_par_t ppar)
{
  int i;

  if (!ppar) return 0;
  for (i = 0; i < ppar->u; i++)
    tex_dom_free_word(ppar->words[i]);
  xfree(ppar->words);
  xfree(ppar);
  return 0;
}

tex_doc_t
tex_dom_free_doc(tex_doc_t pdoc)
{
  int i;

  if (!pdoc) return 0;
  for (i = 0; i < pdoc->u; i++)
    tex_dom_free_par(pdoc->pars[i]);
  xfree(pdoc->pars);
  xfree(pdoc);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "gcc -Wall -g -I/home/cher/reuse/include -I/home/cher/reuse/include/ix86-linux -L/home/cher/reuse/lib/ix86-linux tex_dom.c tex_dom_parse.c tex_dom_render.c tex_dom_doc.c tex_dom_test.c -o tex_dom -lreuse -lm"
 * End:
 */
