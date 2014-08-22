/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2010-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/t3_packets.h"
#include "ejudge/expat_iface.h"
#include "ejudge/xml_utils.h"
#include "ejudge/mime_type.h"
#include "ejudge/misctext.h"

#include "ejudge/xalloc.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define MAX_UQ_COUNT (128*1024*1024)

enum
{
  TG_EXAMCHECK = 1,
  TG_UQ,
  TG_UQXFILE,
  TG_ANSWER,

  TG_LAST_TAG
};
enum
{
  AT_E = 1,
  AT_Q,
  AT_U,
  AT_TYPE,
  AT_FILENAME,
  AT_Q_EXTID,
  AT_GZIPPED,
  AT_NAME,
  AT_SORTID,
  AT_GUID,

  AT_LAST_ATTR,
};

static const char * const elem_map[] =
{
  [TG_EXAMCHECK] = "examcheck",
  [TG_UQ]        = "uq",
  [TG_UQXFILE]   = "uqxfile",
  [TG_ANSWER]    = "answer",

  [TG_LAST_TAG] = 0,
};
static const char * const attr_map[] =
{
  [AT_E]           = "e",
  [AT_Q]           = "q",
  [AT_U]           = "u",
  [AT_TYPE]        = "type",
  [AT_FILENAME]    = "filename",
  [AT_Q_EXTID]     = "q_extid",
  [AT_GZIPPED]     = "gzipped",
  [AT_NAME]        = "name",
  [AT_SORTID]      = "sortid",
  [AT_GUID]        = "guid",

  [AT_LAST_ATTR] = 0,
};

static struct xml_parse_spec examcheck_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = NULL,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = NULL,
  .attr_free = NULL,
};

#define logerr(txt,...) flogerr(log, __FUNCTION__, txt,## __VA_ARGS__)
static int
flogerr(FILE *log, const char *function, const char *format, ...)
  __attribute__((format(printf, 3, 4)));
static int
flogerr(FILE *log, const char *function, const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(log, "%s: %s\n", function, buf);
  return -1;
}

static int
ends_with(
        const unsigned char *str,
        int len,
        const unsigned char *sfx,
        int sfxlen)
{
  return (len >= sfxlen && !strcmp(str + len - sfxlen, sfx));
}

static int
t3_parse_xml(
        FILE *log,
        struct xml_tree *t,
        struct t3_in_packet *r)
{
  struct xml_attr *a;
  struct xml_tree *uq, *uqx;
  int submit_count = 0, uqx_count = 0, i;
  struct t3_in_submit *rs;
  unsigned char *a_type = 0;
  unsigned char *slash = 0;

  if (!t) return 0;

  if (t->tag != TG_EXAMCHECK) {
    logerr("root element must be <examcheck>");
    return -1;
  }
  for (a = t->first; a; a = a->next) {
    if (a->tag == AT_E) {
      r->exam_guid = a->text; a->text = 0;
    }
  }

  for (uq = t->first_down; uq; uq = uq->right) {
    if (uq->tag == TG_UQ) ++submit_count;
  }
  if (!submit_count) return 0;
  if (submit_count > MAX_UQ_COUNT || submit_count < 0) {
    logerr("too many (%d) <uq> elements", submit_count);
    return -1;
  }

  r->submit_count = submit_count;
  XCALLOC(r->submits, submit_count);

  for (uq = t->first_down, i = -1; uq; uq = uq->right) {
    if (uq->tag != TG_UQ) continue;
    rs = &r->submits[++i];
    a_type = 0;
    for (a = uq->first; a; a = a->next) {
      switch (a->tag) {
      case AT_Q:
        rs->prob_guid = a->text; a->text = 0;
        break;
      case AT_U:
        rs->user_guid = a->text; a->text = 0;
        break;
      case AT_TYPE:
        a_type = a->text;
        break;
      case AT_Q_EXTID:
        rs->prob_extid = a->text; a->text = 0;
        break;
      }
    }
    if (!rs->prob_guid) {
      xml_err_attr_undefined(uq, AT_Q);
      return -1;
    }
    if (!rs->user_guid) {
      xml_err_attr_undefined(uq, AT_U);
      return -1;
    }

    uqx_count = 0;
    for (uqx = uq->first_down; uqx; uqx = uqx->right) {
      if (uqx->tag == TG_UQXFILE) ++uqx_count;
    }
    if (!uqx_count) {
      rs->skip_flag = 1;
      continue;
      //xml_err_elem_undefined(uq, TG_UQXFILE);
      //return -1;
    }
    if (uqx_count != 1) {
      xml_err(uq, "only one element <uqxfile> is allowed");
      //return -1;
    }
    for (uqx = uq->first_down; uqx && uqx->tag != TG_UQXFILE; uqx = uqx->right);

    rs->gzipped = -1;
    for (a = uqx->first; a; a = a->next) {
      switch (a->tag) {
      case AT_FILENAME:
        rs->filename = a->text; a->text = 0;
        break;
      case AT_GZIPPED:
        if (xml_attr_bool(a, &rs->gzipped) < 0)
          return -1;
        break;
      case AT_TYPE:
        a_type = a->text;
        break;
      }
    }
    if (!a_type) {
      xml_err_attr_undefined(uqx, AT_TYPE);
      return -1;
    }
    if (!rs->filename) {
      xml_err_attr_undefined(uqx, AT_FILENAME);
      return -1;
    }

    // type="LANG/CHARSET"
    if (!(slash = strchr(a_type, '/'))) {
      rs->prog_lang = xstrdup(a_type);
    } else {
      rs->prog_lang = xmemdup(a_type, slash - a_type);
      rs->prog_charset = xstrdup(slash + 1);
    }

    if (rs->gzipped == -1) {
      // check for some well-known suffixes
      int len = strlen(rs->filename);
      if (ends_with(rs->filename, len, ".gz", 3)) {
        rs->gzipped = 1;
      } else {
        rs->gzipped = 0;
      }
    }
  }

  return 0;
}

struct t3_in_packet *
t3_in_packet_parse_str(
        FILE *log,
        const unsigned char *str)
{
  struct xml_tree *t = 0;
  struct t3_in_packet *r = 0;

  t = xml_build_tree_str(NULL, str, &examcheck_parse_spec);
  if (!t) goto failure;

  xml_err_path = "<string>";
  xml_err_spec = &examcheck_parse_spec;
  XCALLOC(r, 1);
  if (t3_parse_xml(log, t, r) < 0) goto failure;
  xml_tree_free(t, &examcheck_parse_spec);

  return r;

 failure:
  if (t) xml_tree_free(t, &examcheck_parse_spec);
  return 0;
}

struct t3_in_packet *
t3_in_packet_free(struct t3_in_packet *p)
{
  int i;

  if (!p) return 0;

  if (p->submit_count > 0) {
    for (i = 0; i < p->submit_count; ++i) {
      struct t3_in_submit *q = &p->submits[i];

      xfree(q->prob_guid);
      xfree(q->prob_extid);
      xfree(q->user_guid);
      xfree(q->prog_lang);
      xfree(q->prog_charset);
      xfree(q->filename);
    }
    memset(p->submits, 0, p->submit_count * sizeof(*p));
  }

  xfree(p->submits);

  xfree(p->exam_guid);

  memset(p, 0, sizeof(*p));
  xfree(p);
  return 0;
}

struct t3_out_packet *
t3_out_packet_make_from_in(struct t3_in_packet *p)
{
  struct t3_out_packet *out = 0;
  int i;

  if (!p) return 0;

  XCALLOC(out, 1);
  if (p->exam_guid) {
    out->exam_guid = xstrdup(p->exam_guid);
  }
  out->submit_count = p->submit_count;

  if (out->submit_count > 0) {
    XCALLOC(out->submits, out->submit_count);
    for (i = 0; i < out->submit_count; ++i) {
      struct t3_in_submit *ins = &p->submits[i];
      struct t3_out_submit *outs = &out->submits[i];
      if (ins->prob_guid) {
        outs->prob_guid = xstrdup(ins->prob_guid);
      }
      if (ins->user_guid) {
        outs->user_guid = xstrdup(ins->user_guid);
      }
      outs->status = -1;
    }
  }

  return out;
}

void
t3_out_packet_write(FILE *out, struct t3_out_packet *p)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int i;

  if (!p) return;

  fprintf(out, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
  fprintf(out, "<examresults e=\"%s\">\n",
          html_armor_buf(&ab, p->exam_guid));
  for (i = 0; i < p->submit_count; ++i) {
    struct t3_out_submit *ps = &p->submits[i];
    if (ps->skip_flag) continue;
    if (ps->mark || ps->data) {
      fprintf(out, "  <um");
      fprintf(out, " m=\"%d\"", ps->score * 100);
      if (ps->prob_guid) {
        fprintf(out, " q=\"%s\"", html_armor_buf(&ab, ps->prob_guid));
      }
      if (ps->user_guid) {
        fprintf(out, " u=\"%s\"", html_armor_buf(&ab, ps->user_guid));
      }
      fprintf(out, ">\n");
      if (ps->mark || ps->data) {
        fprintf(out, "    <uacomment");
        if (ps->mark) {
          fprintf(out, " mark=\"%s\"", html_armor_buf(&ab, ps->mark));
        }
        if (ps->data) {
          fprintf(out, " data=\"%s\"", html_armor_buf(&ab, ps->data));
        }
        fprintf(out, "/>\n");
      }
      fprintf(out, "  </um>\n");
    }
  }
  fprintf(out, "</examresults>\n");

  html_armor_free(&ab);
}

struct t3_out_packet *
t3_out_packet_free(struct t3_out_packet *p)
{
  int i;

  if (!p) return 0;

  if (p->submit_count > 0) {
    for (i = 0; i < p->submit_count; ++i) {
      struct t3_out_submit *q = &p->submits[i];

      xfree(q->prob_guid);
      xfree(q->user_guid);
    }
    memset(p->submits, 0, p->submit_count * sizeof(*p));
  }

  xfree(p->submits);
  xfree(p->exam_guid);

  memset(p, 0, sizeof(*p));
  xfree(p);
  return 0;
}
