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

int (*(*tex_dom_get_render_func_ptr)(int))(tex_par_t,tex_buffer_t,int) = tex_dom_get_render_func;

static int centered_par_render_func(tex_par_t, tex_buffer_t, int);
static int justified_par_render_func(tex_par_t, tex_buffer_t, int);
static int left_par_render_func(tex_par_t, tex_buffer_t, int);
static int right_par_render_func(tex_par_t, tex_buffer_t, int);

static int (*align_render_funcs[TEX_ALIGN_MAX])(tex_par_t,tex_buffer_t, int) =
{
  [TEX_ALIGN_FILLED] = justified_par_render_func,
  [TEX_ALIGN_CENTER] = centered_par_render_func,
  [TEX_ALIGN_LEFT]   = left_par_render_func,
  [TEX_ALIGN_RIGHT]  = right_par_render_func,
};

int (*tex_dom_get_render_func(int rend_type))(tex_par_t, tex_buffer_t, int)
{
  ASSERT(rend_type >= 0 && rend_type < TEX_ALIGN_MAX);
  return align_render_funcs[rend_type];
}

static void
render_tex_char_t(tex_buffer_t pbuf, int line, int col, const tex_char_t pc)
     __attribute__((unused));
static void
render_tex_char_t(tex_buffer_t pbuf, int line, int col, const tex_char_t pc)
{
  size_t old_lines;

  ASSERT(col >= 0 && col < pbuf->cols);
  ASSERT(line >= 0);

  if (line >= pbuf->lines_a) {
    old_lines = pbuf->lines_a;
    if (!pbuf->lines_a) pbuf->lines_a = 8;
    while (line >= pbuf->lines_a) pbuf->lines_a *= 2;
    XREALLOC(pbuf->buf, pbuf->lines_a);
    memset(&pbuf->buf[old_lines], 0,
           sizeof(pbuf->buf[0]) * (pbuf->lines_a-old_lines));
  }
  if (line >= pbuf->lines) pbuf->lines = line + 1;
  if (!pbuf->buf[line]) {
    XCALLOC(pbuf->buf[line], pbuf->cols);
  }
  if (!pbuf->buf[line][col]) {
    XCALLOC(pbuf->buf[line][col], 1);
  }
  *(pbuf->buf[line][col]) = *pc;
}

static void
render_char(tex_buffer_t pbuf, int line, int col, int c, tex_font_t font,
            unsigned char is_italic, unsigned char is_slanted,
            unsigned char is_bold, unsigned char is_underlined)
{
  size_t old_lines;
  tex_char_t new_pc;

  ASSERT(col >= 0 && col < pbuf->cols);
  ASSERT(line >= 0);

  if (line >= pbuf->lines_a) {
    old_lines = pbuf->lines_a;
    if (!pbuf->lines_a) pbuf->lines_a = 8;
    while (line >= pbuf->lines_a) pbuf->lines_a *= 2;
    XREALLOC(pbuf->buf, pbuf->lines_a);
    memset(&pbuf->buf[old_lines], 0,
           sizeof(pbuf->buf[0]) * (pbuf->lines_a-old_lines));
  }
  if (line >= pbuf->lines) pbuf->lines = line + 1;
  if (!pbuf->buf[line]) {
    XCALLOC(pbuf->buf[line], pbuf->cols);
  }
  if (!pbuf->buf[line][col]) {
    XCALLOC(pbuf->buf[line][col], 1);
  }
  new_pc = pbuf->buf[line][col];
  new_pc->c = c;
  new_pc->font = font;
  new_pc->is_italic = is_italic;
  new_pc->is_slanted = is_slanted;
  new_pc->is_bold = is_bold;
  new_pc->is_underlined = is_underlined;
}

static void
render_tex_char_ts(tex_buffer_t pbuf, int line, int col, tex_char_t *pc, int n)
{
  size_t old_lines;
  int i;

  ASSERT(col >= 0 && col < pbuf->cols);
  ASSERT(line >= 0);
  ASSERT(n >= 0);
  ASSERT(col + n <= pbuf->cols);
  if (!n) return;

  if (line >= pbuf->lines_a) {
    old_lines = pbuf->lines_a;
    if (!pbuf->lines_a) pbuf->lines_a = 8;
    while (line >= pbuf->lines_a) pbuf->lines_a *= 2;
    XREALLOC(pbuf->buf, pbuf->lines_a);
    memset(&pbuf->buf[old_lines], 0,
           sizeof(pbuf->buf[0]) * (pbuf->lines_a-old_lines));
  }
  if (line >= pbuf->lines) pbuf->lines = line + 1;
  if (!pbuf->buf[line]) {
    XCALLOC(pbuf->buf[line], pbuf->cols);
  }
  for (i = 0; n; n--, col++, i++) {
    if (!pbuf->buf[line][col]) {
      XCALLOC(pbuf->buf[line][col], 1);
    }
    *(pbuf->buf[line][col]) = *(pc[i]);
  }
}

static int
centered_par_render_func(tex_par_t ppar, tex_buffer_t pbuf, int curline)
{
  int wfirst = 0, wlast;
  int cfirst;
  tex_word_t curw;
  int curwidth;

  if (!ppar->u) return curline;

  while (wfirst < ppar->u) {
    // find the range of words to fit into one line
    if (ppar->words[wfirst]->u > pbuf->cols) {
      // the word is too long to fit into one line
      curw = ppar->words[wfirst];
      cfirst = 0;
      while (cfirst + pbuf->cols - 1 < curw->u) {
        if (cfirst + pbuf->cols == curw->u) break;
        render_tex_char_ts(pbuf, curline, 0, &curw->chars[cfirst],
                           pbuf->cols - 1);
        render_char(pbuf, curline, pbuf->cols - 1, '\\', 0, 0, 0, 0, 0);
        curline++;
        cfirst += pbuf->cols - 1;
      }
      render_tex_char_ts(pbuf, curline, 0, &curw->chars[cfirst],
                         curw->u - cfirst);
      curline++;
      wfirst++;
      continue;
    }
    if (ppar->words[wfirst]->u == pbuf->cols) {
      // the word is exactly of line width
      curw = ppar->words[wfirst];
      render_tex_char_ts(pbuf, curline, 0, curw->chars, curw->u);
      curline++;
      wfirst++;
      continue;
    }
    wlast = wfirst + 1;
    curwidth = ppar->words[wfirst]->u;
    while (wlast < ppar->u) {
      if (curwidth + ppar->words[wlast]->u + 1 > pbuf->cols) break;
      curwidth += ppar->words[wlast]->u + 1;
      wlast++;
    }
    wlast--;
    cfirst = (pbuf->cols - curwidth) / 2;
    while (wfirst <= wlast) {
      curw = ppar->words[wfirst];
      render_tex_char_ts(pbuf, curline, cfirst, curw->chars, curw->u);
      cfirst += curw->u + 1;
      wfirst++;
    }
    curline++;
  }
  return curline;
}

static int
justified_par_render_func(tex_par_t ppar, tex_buffer_t pbuf, int curline)
{
  int indent, left_margin, right_margin, width, cur_left;
  int wfirst = 0, wlast, cfirst, ws, rems, i, curwidth;
  tex_word_t curw;

  if (!ppar->u) return curline;

  indent = ppar->indent;
  left_margin = ppar->left_margin;
  right_margin = ppar->right_margin;

  if (left_margin < 0) left_margin = 0;
  if (right_margin < 0) right_margin = 0;
  if (left_margin + 2 > pbuf->cols - right_margin) right_margin = 0;
  if (left_margin + 2 > pbuf->cols - right_margin) left_margin = 0;
  if (left_margin + indent < 0) indent = 0;
  if (left_margin + indent + 2 > pbuf->cols - right_margin) indent=left_margin;

  width = pbuf->cols - (left_margin + indent) - right_margin;
  cur_left = left_margin + indent;

  while (wfirst < ppar->u) {
    curw = ppar->words[wfirst];
    if (curw->u > width) {
      cfirst = 0;
      render_tex_char_ts(pbuf, curline, cur_left, &curw->chars[cfirst],
                         width - 1);
      render_char(pbuf, curline, left_margin + width - 1, '\\', 0, 0, 0, 0, 0);
      curline++;
      cfirst += width - 1;
      width = pbuf->cols - left_margin - right_margin;
      cur_left = left_margin;

      while (cfirst + width - 1 < curw->u) {
        if (cfirst + width == curw->u) break;
        render_tex_char_ts(pbuf, curline, cur_left, &curw->chars[cfirst],
                           width - 1);
        render_char(pbuf, curline, left_margin + width - 1, '\\', 0, 0,0,0,0);
        curline++;
        cfirst += width - 1;
      }
      render_tex_char_ts(pbuf, curline, cur_left, &curw->chars[cfirst],
                         curw->u - cfirst);
      curline++;
      wfirst++;
    } else if (curw->u == width) {
      render_tex_char_ts(pbuf, curline, cur_left, curw->chars, curw->u);
      width = pbuf->cols - left_margin - right_margin;
      cur_left = left_margin;
      curline++;
      wfirst++;
    } else {
      wlast = wfirst + 1;
      curwidth = ppar->words[wfirst]->u;
      while (wlast < ppar->u) {
        if (curwidth + ppar->words[wlast]->u + 1 > width) break;
        curwidth += ppar->words[wlast]->u + 1;
        wlast++;
      }
      wlast--;

      if (wlast + 1 == ppar->u) {
        cfirst = cur_left;
        while (wfirst <= wlast) {
          curw = ppar->words[wfirst];
          render_tex_char_ts(pbuf, curline, cfirst, curw->chars, curw->u);
          cfirst += curw->u + 1;
          wfirst++;
        }
        curline++;
        return curline;
      }
      if (wfirst == wlast) {
        render_tex_char_ts(pbuf, curline, cur_left, curw->chars, curw->u);
        width = pbuf->cols - left_margin - right_margin;
        cur_left = left_margin;
        wfirst++;
        curline++;
      } else {
        cfirst = cur_left;
        rems = width;
        for (i = wfirst; i <= wlast; i++)
          rems -= ppar->words[i]->u;
        while (wfirst <= wlast) {
          curw = ppar->words[wfirst];
          render_tex_char_ts(pbuf, curline, cfirst, curw->chars, curw->u);
          cfirst += curw->u;
          if (wfirst < wlast) {
            ws = rems / (wlast - wfirst);
            if ((rems % (wlast - wfirst))) ws++;
            cfirst += ws;
            rems -= ws;
          }
          wfirst++;
        }
        curline++;
        width = pbuf->cols - left_margin - right_margin;
        cur_left = left_margin;
      }
    }
  }

  return curline;
}

static int
left_par_render_func(tex_par_t ppar, tex_buffer_t pbuf, int curline)
{
  SWERR(("not implemented"));
}

static int
right_par_render_func(tex_par_t ppar, tex_buffer_t pbuf, int curline)
{
  SWERR(("not implemented"));
}

tex_buffer_t
tex_dom_render(int cols, tex_doc_t pdoc)
{
  tex_buffer_t pbuf;
  int i, curl = 0;

  ASSERT(cols > 1);

  XCALLOC(pbuf, 1);
  pbuf->cols = cols;
  for (i = 0; i < pdoc->u; i++)
    curl = (*pdoc->pars[i]->render_func)(pdoc->pars[i], pbuf, curl);

  return pbuf;
}

void
tex_dom_dump_buffer(FILE *out, tex_buffer_t pbuf)
{
  int line, width, col;

  for (line = 0; line < pbuf->lines; line++) {
    if (!pbuf->buf[line]) {
      fprintf(out, "\n");
      continue;
    }
    width = pbuf->cols;
    while (width > 0 && !pbuf->buf[line][width - 1]) width--;
    if (!width) {
      fprintf(out, "\n");
      continue;
    }
    for (col = 0; col < width; col++) {
      if (!pbuf->buf[line][col]) {
        putc(' ', out);
      } else {
        putc(pbuf->buf[line][col]->c, out);
      }
    }
    fprintf(out, "\n");
  }
}

int
tex_dom_get_width(tex_buffer_t pbuf)
{
  return pbuf->cols;
}

int
tex_dom_get_height(tex_buffer_t pbuf)
{
  return pbuf->lines;
}

tex_buffer_t
tex_dom_free_buffer(tex_buffer_t pbuf)
{
  int line, col;

  if (!pbuf) return 0;

  for (line = 0; line < pbuf->lines; line++) {
    if (!pbuf->buf[line]) continue;
    for (col = 0; col < pbuf->cols; col++)
      tex_dom_free_char(pbuf->buf[line][col]);
    xfree(pbuf->buf[line]);
  }
  xfree(pbuf->buf);
  xfree(pbuf);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "gcc -Wall -g -I/home/cher/reuse/include -I/home/cher/reuse/include/ix86-linux -L/home/cher/reuse/lib/ix86-linux tex_dom.c tex_dom_parse.c tex_dom_render.c tex_dom_doc.c tex_dom_test.c -o tex_dom -lreuse -lm"
 * End:
 */
