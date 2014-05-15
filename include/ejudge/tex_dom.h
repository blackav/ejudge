/* -*- c -*- */
/* $Id$ */

#ifndef __TEX_DOM_H__
#define __TEX_DOM_H__

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

/* a simple DOM structures for subset of LaTeX commands used
 * in the ejudge documentation
 */

#include <stdlib.h>
#include <stdio.h>

/* tex commands */
enum
{
  TEX__DOC = 1,
  TEX__PAR,
  TEX__WORD,
  TEX__SPACE,
  TEX__BLOCK,
  TEX_BEGIN,
  TEX_END,
  TEX_IT,

  TEX_ENV_CENTER,

  TEX__LAST,
};

struct tex_dom_struct
{
  int tag;
  struct tex_dom_struct *next;
  struct tex_dom_struct *first;
  int n;                        /* number of subnodes */
  struct tex_dom_struct **refs; /* subnodes */
  unsigned char *txt;           /* text for leaf nodes */
};
typedef struct tex_dom_struct *tex_dom_t;

struct tex_dom_result_struct
{
  unsigned char *errlog;
  int errcnt;
  tex_dom_t tree;
};
typedef struct tex_dom_result_struct *tex_dom_result_t;

const unsigned char *tex_dom_get_node_name(int kind);
tex_dom_result_t tex_dom_parse(const unsigned char *str);
void tex_dom_print(FILE *f, tex_dom_t node);
tex_dom_result_t tex_dom_free_result(tex_dom_result_t res);
tex_dom_t tex_dom_free(tex_dom_t node);

/* various supported fonts */
typedef enum tex_font_flags
{
  TEX_FONT_RM = 0,
  TEX_FONT_SF,
  TEX_FONT_TT,
  TEX_FONT_SC,
} tex_font_t;

/* paragraph alignments */
typedef enum tex_align_enum
{
  TEX_ALIGN_FILLED = 0,
  TEX_ALIGN_CENTER,
  TEX_ALIGN_LEFT,
  TEX_ALIGN_RIGHT,
  TEX_ALIGN_MAX,
} tex_align_t;

/* character attributes */
typedef struct tex_char_struct
{
  unsigned char c;
  tex_font_t font;
  unsigned char is_italic;
  unsigned char is_slanted;
  unsigned char is_bold;
  unsigned char is_underlined;
} *tex_char_t;

/* word attributes */
typedef struct tex_word_struct
{
  size_t a, u;
  tex_char_t *chars;
} *tex_word_t;

/* paragraph attributes */
struct tex_doc_struct;
struct tex_buffer_struct;
typedef struct tex_par_struct
{
  size_t a, u;
  tex_word_t *words;
  tex_align_t align;
  int indent, left_margin, right_margin;
  int (*render_func)(struct tex_par_struct *, struct tex_buffer_struct *, int);
} *tex_par_t;

/* document attributes */
typedef struct tex_doc_struct
{
  size_t a, u;
  tex_par_t *pars;
} *tex_doc_t;

tex_doc_t tex_dom_build_doc(tex_dom_t dom);
int tex_dom_get_doc_width(tex_doc_t pdoc);
tex_char_t tex_dom_free_char(tex_char_t pchar);
tex_doc_t tex_dom_free_doc(tex_doc_t pdoc);

/* rendering buffer */
typedef struct tex_buffer_struct
{
  size_t lines, lines_a;
  size_t cols;
  tex_char_t **buf;
} *tex_buffer_t;

int (*tex_dom_get_render_func(int rend_type))(tex_par_t,tex_buffer_t,int);
tex_buffer_t tex_dom_render(int cols, tex_doc_t doc);
void tex_dom_dump_buffer(FILE *out, tex_buffer_t buf);
int tex_dom_get_width(tex_buffer_t pbuf);
int tex_dom_get_height(tex_buffer_t pbuf);
tex_buffer_t tex_dom_free_buffer(tex_buffer_t pbuf);

/* not extern intentionally! */
int (*(*tex_dom_get_render_func_ptr)(int))(tex_par_t,tex_buffer_t,int);


#endif /* __TEX_DOM_H__ */

/**
 * Local variables:
 *  compile-command: "make"
 * End:
 */
