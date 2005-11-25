/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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

#include "config.h"
#include "settings.h"

#include "team_extra.h"
#include "expat_iface.h"
#include "pathutl.h"
#include "errlog.h"
#include "xml_utils.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <ctype.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

#define RUNLOG_MAX_TEAM_ID 100000
#define CLARLOG_MAX_CLAR_ID 100000
#define BPE (CHAR_BIT * sizeof(((struct team_extra*)0)->clar_map[0]))

/* elements */
enum
{
  TE_T_TEAM_EXTRA = 1,
  TE_T_VIEWED_CLARS,
  TE_T_WARNINGS,
  TE_T_WARNING,
  TE_T_TEXT,
  TE_T_COMMENT,
  TE_T_STATUS,

  TE_T_LAST_TAG,
};
/* attributes */
enum
{
  TE_A_USER_ID = 1,
  TE_A_ISSUER_ID,
  TE_A_ISSUER_IP,
  TE_A_DATE,

  TE_A_LAST_ATTR,
};
static const char * const elem_map[] =
{
  [TE_T_TEAM_EXTRA]   "team_extra",
  [TE_T_VIEWED_CLARS] "viewed_clars",
  [TE_T_WARNINGS]     "warnings",
  [TE_T_WARNING]      "warning",
  [TE_T_TEXT]         "text",
  [TE_T_COMMENT]      "comment",
  [TE_T_STATUS]       "status",
  [TE_T_LAST_TAG]     0,
};
static const char * const attr_map[] =
{
  [TE_A_USER_ID]   "user_id",
  [TE_A_ISSUER_ID] "issuer_id",
  [TE_A_ISSUER_IP] "issuer_ip",
  [TE_A_DATE]      "date",
  [TE_A_LAST_ATTR] 0,
};
static const size_t elem_sizes[TE_T_LAST_TAG];
static const size_t attr_sizes[TE_A_LAST_ATTR];

static void *
elem_alloc(int tag)
{
  size_t sz;
  ASSERT(tag >= 1 && tag < TE_T_LAST_TAG);
  if (!(sz = elem_sizes[tag])) sz = sizeof(struct xml_tree);
  return xcalloc(1, sz);
}
static void *
attr_alloc(int tag)
{
  size_t sz;

  ASSERT(tag >= 1 && tag < TE_A_LAST_ATTR);
  if (!(sz = attr_sizes[tag])) sz = sizeof(struct xml_attn);
  return xcalloc(1, sz);
}
static void
elem_free(struct xml_tree *t)
{
}
static void
attr_free(struct xml_attn *a)
{
}

static int
check_empty_text(struct xml_tree *xt)
{
  const unsigned char *s;

  if (!xt) return 0;
  if (!xt->text) return 0;
  s = xt->text;
  while (*s && isspace(*s)) s++;
  if (!*s) return 0;
  return -1;
}

static int
parse_viewed_clars(struct xml_tree *t, struct team_extra *te, int *pv_flag)
{
  int n, x, max_x, r;
  unsigned char *s;

  if (*pv_flag) {
    err("%d:%d: duplicated element <%s>", t->line, t->column,elem_map[t->tag]);
    return -1;
  }
  *pv_flag = 1;

  if (t->first) {
    err("%d:%d: element <%s> do not have attributes",
        t->line, t->column, elem_map[t->tag]);
    return -1;
  }
  if (t->first_down) {
    err("%d:%d: element <%s> do not have nested elements",
        t->line, t->column, elem_map[t->tag]);
    return -1;
  }
  if (!t->text) t->text = xstrdup("");

  max_x = -1;
  s = t->text;
  while (1) {
    x = n = 0;
    r = sscanf(s, "%d%n", &x, &n);
    if (r == EOF) break;
    if (r != 1 || x < 0 || x > CLARLOG_MAX_CLAR_ID) {
      err("%d:%d: value of element <%s> is invalid",
          t->line, t->column, elem_map[t->tag]);
      return -1;
    }
    s += n;
    if (x > max_x) max_x = x;
  }
  if (max_x == -1) return 0;

  te->clar_map_alloc = 16;
  te->clar_map_size = 8 * sizeof(te->clar_map[0]) * te->clar_map_alloc;
  XCALLOC(te->clar_map, te->clar_map_alloc);

  s = t->text;
  while (1) {
    x = n = 0;
    if (sscanf(s, "%d%n", &x, &n) != 1) break;
    s += n;
    ASSERT(x >= 0 && x < te->clar_map_size);
    if (te->clar_map[x / BPE] & (1UL << x % BPE)) {
      err("%d:%d: duplicated clar %d in element <%s>",
          t->line, t->column, x, elem_map[t->tag]);
      return -1;
    }
    te->clar_map[x / BPE] |= (1UL << x % BPE);
  }

  return 0;
}

/*
<warnings>
  <warning issuer_id="ID" issuer_ip="IP" date="DATE">
    <text>TEXT</text>
    <comment>COMMENT</comment>
  </warnings>
</warnings>
 */
static int
parse_warnings(struct xml_tree *t, struct team_extra *te, int *pw_flag)
{
  struct xml_tree *wt, *tt;
  struct xml_attn *a;
  struct team_warning *cur_warn;
  unsigned char **ptxt;
  int x;

  if (*pw_flag) {
    err("%d:%d: duplicated element <%s>", t->line, t->column,elem_map[t->tag]);
    return -1;
  }
  *pw_flag = 1;

  if (!te->warn_a) {
    te->warn_a = 8;
    XCALLOC(te->warns, te->warn_a);
  }

  if (t->first) {
    err("%d:%d: element <%s> do not have attributes",
        t->line, t->column, elem_map[t->tag]);
    return -1;
  }
  if (check_empty_text(t) < 0) {
    err("%d:%d: element <%s> must not have text",
        t->line, t->column, elem_map[t->tag]);
    return -1;
  }

  for (wt = t->first_down; wt; wt = wt->right) {
    if (wt->tag != TE_T_WARNING) {
      err("%d:%d: element <%s> is invalid in element <%s>",
          wt->line, wt->column, elem_map[wt->tag], elem_map[t->tag]);
      return -1;
    }
    if (check_empty_text(wt) < 0) {
      err("%d:%d: element <%s> must not have text",
          wt->line, wt->column, elem_map[wt->tag]);
      return -1;
    }

    if (te->warn_u == te->warn_a) {
      te->warn_a *= 2;
      if (!te->warn_a) te->warn_a = 8;
      XREALLOC(te->warns, te->warn_a);
    }
    XCALLOC(cur_warn, 1);
    te->warns[te->warn_u++] = cur_warn;

    for (a = wt->first; a; a = a->next) {
      switch (a->tag) {
      case TE_A_ISSUER_ID:
        if (xml_parse_int(0, a->line, a->column, a->text, &x) < 0) return -1;
        if (x <= 0 || x > RUNLOG_MAX_TEAM_ID) {
          err("%d:%d: value of attribute \"%s\" is invalid",
              a->line, a->column, attr_map[a->tag]);
          return -1;
        }
        cur_warn->issuer_id = x;
        break;
      case TE_A_ISSUER_IP:
        if (xml_parse_ip(0, a->line, a->column, a->text,
                         &cur_warn->issuer_ip) < 0) return -1;
        break;
      case TE_A_DATE:
        if (xml_parse_date(0, a->line, a->column, a->text,
                           &cur_warn->date) < 0) return -1;
        break;
      default:
        err("%d:%d: attribute \"%s\" is invalid in element <%s>",
            a->line, a->column, attr_map[a->tag], elem_map[wt->tag]);
        return -1;
      }
    }

    if (!cur_warn->issuer_id) {
      err("%d:%d: attribute \"%s\" is not specified",
          wt->line, wt->column, attr_map[TE_A_ISSUER_ID]);
      return -1;
    }
    if (!cur_warn->issuer_ip) {
      err("%d:%d: attribute \"%s\" is not specified",
          wt->line, wt->column, attr_map[TE_A_ISSUER_IP]);
      return -1;
    }
    if (!cur_warn->date) {
      err("%d:%d: attribute \"%s\" is not specified",
          wt->line, wt->column, attr_map[TE_A_DATE]);
      return -1;
    }

    for (tt = wt->first_down; tt; tt = tt->right) {
      switch (tt->tag) {
      case TE_T_TEXT:
      case TE_T_COMMENT:
        ptxt = 0;
        switch (tt->tag) {
        case TE_T_TEXT:    ptxt = &cur_warn->text;    break;
        case TE_T_COMMENT: ptxt = &cur_warn->comment; break;
        }
        if (tt->first) {
          err("%d:%d: element <%s> cannot have attributes",
              tt->line, tt->column, elem_map[tt->tag]);
          return -1;
        }
        if (tt->first_down) {
          err("%d:%d: element <%s> cannot have nested elements",
              tt->line, tt->column, elem_map[tt->tag]);
          return -1;
        }
        if (*ptxt) {
          err("%d:%d: element <%s> cannot be used several times",
              tt->line, tt->column, elem_map[tt->tag]);
          return -1;
        }
        *ptxt = tt->text;
        tt->text = 0;
        break;
      default:
        err("%d:%d: element <%s> is invalid in element <%s>",
            tt->line, tt->column, elem_map[tt->tag], elem_map[wt->tag]);
        return -1;
      }
    }

    if (!cur_warn->text) cur_warn->text = xstrdup("");
    if (!cur_warn->comment) cur_warn->comment = xstrdup("");
  }

  return 0;
}

int
parse_status(struct xml_tree *t, struct team_extra *te, int *ps_flag)
{
  if (*ps_flag) {
    err("%d:%d: duplicated element <%s>", t->line, t->column,elem_map[t->tag]);
    return -1;
  }
  *ps_flag = 1;

  if (t->first) {
    err("%d:%d: element <%s> do not have attributes",
        t->line, t->column, elem_map[t->tag]);
    return -1;
  }
  if (t->first_down) {
    err("%d:%d: element <%s> cannot have nested elements",
        t->line, t->column, elem_map[t->tag]);
    return -1;
  }
  if (!t->text) t->text = xstrdup("");
  if (xml_parse_int(0, t->line, t->column, t->text, &te->status) < 0)
    return -1;
  if (te->status < 0) {
    err("%d:%d: invalid value of element <%s>",
        t->line, t->column, elem_map[t->tag]);
    return -1;
  }
  return 0;
}

int
team_extra_parse_xml(const unsigned char *path, struct team_extra **pte)
{
  struct xml_tree *t = 0, *t2 = 0;
  struct team_extra *te = 0;
  struct xml_attn *a = 0;
  int user_id = -1, x, n, v_flag = 0, w_flag = 0, s_flag = 0;

  t = xml_build_tree(path, elem_map, attr_map, elem_alloc, attr_alloc);
  if (!t) return -1;
  XCALLOC(te, 1);
  if (t->tag != TE_T_TEAM_EXTRA) {
    err("%d:%d: top-level element must be <%s>",
        t->line, t->column, elem_map[TE_T_TEAM_EXTRA]);
    goto cleanup;
  }
  if (check_empty_text(t) < 0) {
    err("%d:%d: element <%s> cannot contain text",
        t->line, t->column, elem_map[TE_T_TEAM_EXTRA]);
    goto cleanup;
  }
  for (a = t->first; a; a = a->next) {
    switch (a->tag) {
    case TE_A_USER_ID:
      if (user_id != -1) {
        err("%d:%d: duplicated attribute \"%s\"",
            a->line, a->column, attr_map[a->tag]);
        goto cleanup;
      }
      if (!a->text) a->text = xstrdup("");
      x = n = 0;
      if (sscanf(a->text, "%d%n", &x, &n) != 1 || a->text[n]
          || x <= 0 || x > RUNLOG_MAX_TEAM_ID) {
        err("%d:%d: value of attribute \"%s\" is invalid",
            a->line, a->column, attr_map[a->tag]);
        goto cleanup;
      }
      user_id = x;
      break;
    default:
      err("%d:%d: attribute \"%s\" is invalid in element <%s>",
          a->line, a->column, attr_map[a->tag], elem_map[TE_T_TEAM_EXTRA]);
      goto cleanup;
    }
  }
  if (user_id == -1) {
    err("%d:%d: attribute \"%s\" must be specified",
        t->line, t->column, attr_map[TE_A_USER_ID]);
    goto cleanup;
  }
  te->user_id = user_id;

  for (t2 = t->first_down; t2; t2 = t2->right) {
    switch (t2->tag) {
    case TE_T_VIEWED_CLARS:
      if (parse_viewed_clars(t2, te, &v_flag) < 0) goto cleanup;
      break;
    case TE_T_WARNINGS:
      if (parse_warnings(t2, te, &w_flag) < 0) goto cleanup;
      break;
    case TE_T_STATUS:
      if (parse_status(t2, te, &s_flag) < 0) goto cleanup;
      break;
    default:
      err("%d:%d: element <%s> is invalid in element <%s>",
          t2->line, t2->column, elem_map[t2->tag], elem_map[t->tag]);
      goto cleanup;
    }
  }

  if (pte) *pte = te;
  xml_tree_free(t, elem_free, attr_free);
  return 0;

 cleanup:
  if (t) xml_tree_free(t, elem_free, attr_free);
  if (te && te->clar_map) xfree(te->clar_map);
  if (te) xfree(te);
  return -1;
}

int
team_extra_unparse_xml(FILE *f, struct team_extra *te)
{
  int i, j;

  ASSERT(f);
  ASSERT(te);
  ASSERT(te->user_id > 0);

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\"?>\n", EJUDGE_CHARSET);
  fprintf(f, "<%s %s=\"%d\">\n", elem_map[TE_T_TEAM_EXTRA],
          attr_map[TE_A_USER_ID], te->user_id);
  fprintf(f, "  <%s>", elem_map[TE_T_VIEWED_CLARS]);
  for (i = 0, j = 0; i < te->clar_map_size; i++) {
    if (te->clar_map[i / BPE] & (1UL << i % BPE)) {
      if (j) putc(' ', f);
      fprintf(f, "%d", i);
      j++;
    }
  }
  fprintf(f, "  </%s>\n", elem_map[TE_T_VIEWED_CLARS]);
  if (te->status > 0) {
    fprintf(f, "  <%s>%d</%s>\n", elem_map[TE_T_STATUS],
            te->status, elem_map[TE_T_STATUS]);
  }
  if (te->warn_u > 0) {
    fprintf(f, "  <%s>\n", elem_map[TE_T_WARNINGS]);
    for (i = 0; i < te->warn_u; i++) {
      fprintf(f, "    <%s %s=\"%d\" %s=\"%s\" %s=\"%s\">\n",
              elem_map[TE_T_WARNING],
              attr_map[TE_A_ISSUER_ID], te->warns[i]->issuer_id,
              attr_map[TE_A_ISSUER_IP],xml_unparse_ip(te->warns[i]->issuer_ip),
              attr_map[TE_A_DATE], xml_unparse_date(te->warns[i]->date));
      xml_unparse_text(f, elem_map[TE_T_TEXT], te->warns[i]->text, "      ");
      xml_unparse_text(f, elem_map[TE_T_COMMENT],
                       te->warns[i]->comment, "      ");
      fprintf(f, "    </%s>\n", elem_map[TE_T_WARNING]);
    }
    fprintf(f, "  </%s>\n", elem_map[TE_T_WARNINGS]);
  }
  fprintf(f, "</%s>\n", elem_map[TE_T_TEAM_EXTRA]);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
