/* -*- c -*- */

/* Copyright (C) 2004-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/team_extra.h"
#include "ejudge/expat_iface.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/xml_utils.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <ctype.h>
#include <errno.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJ_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

#define RUNLOG_MAX_TEAM_ID 10000000
#define CLARLOG_MAX_CLAR_ID 10000000
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
  TE_T_DISQ_COMMENT,
  TE_T_RUN_FIELDS,
  TE_T_UUID,
  TE_T_CLAR_UUIDS,
  TE_T_PROBLEM_DIR_PREFIX,

  TE_T_LAST_TAG,
};
/* attributes */
enum
{
  TE_A_USER_ID = 1,
  TE_A_ISSUER_ID,
  TE_A_ISSUER_IP,
  TE_A_DATE,
  TE_A_CONTEST_ID,

  TE_A_LAST_ATTR,
};
static const char * const elem_map[] =
{
  [TE_T_TEAM_EXTRA]   = "team_extra",
  [TE_T_VIEWED_CLARS] = "viewed_clars",
  [TE_T_WARNINGS]     = "warnings",
  [TE_T_WARNING]      = "warning",
  [TE_T_TEXT]         = "text",
  [TE_T_COMMENT]      = "comment",
  [TE_T_STATUS]       = "status",
  [TE_T_DISQ_COMMENT] = "disq_comment",
  [TE_T_RUN_FIELDS]   = "run_fields",
  [TE_T_UUID]         = "uuid",
  [TE_T_CLAR_UUIDS]   = "clar_uuids",
  [TE_T_PROBLEM_DIR_PREFIX] = "problem_dir_prefix",
  [TE_T_LAST_TAG]     = 0,
};
static const char * const attr_map[] =
{
  [TE_A_USER_ID]   = "user_id",
  [TE_A_ISSUER_ID] = "issuer_id",
  [TE_A_ISSUER_IP] = "issuer_ip",
  [TE_A_DATE]      = "date",
  [TE_A_CONTEST_ID]= "contest_id",
  [TE_A_LAST_ATTR] = 0,
};

static struct xml_parse_spec team_extra_parse_spec =
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

static int
parse_viewed_clars(struct xml_tree *t, struct team_extra *te, int *pv_flag)
{
  int n, x, max_x, r;
  unsigned char *s;

  if (*pv_flag) return xml_err_elem_redefined(t);
  *pv_flag = 1;

  if (t->first) return xml_err_attrs(t);
  if (t->first_down) return xml_err_nested_elems(t);
  if (!t->text) t->text = xstrdup("");

  max_x = -1;
  s = t->text;
  while (1) {
    x = n = 0;
    r = sscanf(s, "%d%n", &x, &n);
    if (r == EOF) break;
    if (r != 1 || x < 0 || x > CLARLOG_MAX_CLAR_ID)
      return xml_err_elem_invalid(t);
    s += n;
    if (x > max_x) max_x = x;
  }
  if (max_x == -1) return 0;

  te->clar_map_size = 128;
  while (te->clar_map_size <= max_x) te->clar_map_size *= 2;
  te->clar_map_alloc = te->clar_map_size / BPE;
  XCALLOC(te->clar_map, te->clar_map_alloc);

  s = t->text;
  while (1) {
    x = n = 0;
    if (sscanf(s, "%d%n", &x, &n) != 1) break;
    s += n;
    ASSERT(x >= 0 && x < te->clar_map_size);
    if (te->clar_map[x / BPE] & (1UL << x % BPE)) {
      xml_err(t, "duplicated clar %d in element <%s>", x, elem_map[t->tag]);
      return -1;
    }
    te->clar_map[x / BPE] |= (1UL << x % BPE);
  }

  return 0;
}

static int
parse_clar_uuids(struct xml_tree *t, struct team_extra *te, int *pu_flag)
{
  if (*pu_flag) return xml_err_elem_redefined(t);
  *pu_flag = 1;

  if (t->first) return xml_err_attrs(t);
  if (xml_empty_text(t) < 0) return -1;

  for (struct xml_tree *wt = t->first_down; wt; wt = wt->right) {
    if (wt->tag != TE_T_UUID) return xml_err_elem_not_allowed(wt);
    if (wt->first) return xml_err_attrs(t);
    if (wt->first_down) return xml_err_nested_elems(wt);
    ej_uuid_t uuid = {};
    if (ej_uuid_parse(wt->text, &uuid) < 0) return xml_err_elem_invalid(wt);
    team_extra_add_clar_uuid(te, &uuid);
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
  struct xml_attr *a;
  struct team_warning *cur_warn;
  unsigned char **ptxt;
  int x;

  if (*pw_flag) return xml_err_elem_redefined(t);
  *pw_flag = 1;

  if (!te->warn_a) {
    te->warn_a = 8;
    XCALLOC(te->warns, te->warn_a);
  }

  if (t->first) return xml_err_attrs(t);
  if (xml_empty_text(t) < 0) return -1;

  for (wt = t->first_down; wt; wt = wt->right) {
    if (wt->tag != TE_T_WARNING) return xml_err_elem_not_allowed(wt);
    if (xml_empty_text(wt) < 0) return -1;

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
        if (xml_parse_int(NULL, 0, a->line, a->column, a->text, &x) < 0) return -1;
        if (x <= 0 || x > RUNLOG_MAX_TEAM_ID)
          return xml_err_attr_invalid(a);
        cur_warn->issuer_id = x;
        break;
      case TE_A_ISSUER_IP:
        if (xml_parse_ipv6(NULL, 0, a->line, a->column, a->text,
                           &cur_warn->issuer_ip) < 0) return -1;
        break;
      case TE_A_DATE:
        if (xml_parse_date(NULL, 0, a->line, a->column, a->text,
                           &cur_warn->date) < 0) return -1;
        break;
      default:
        return xml_err_attr_not_allowed(wt, a);
      }
    }

    if (!cur_warn->issuer_id)
      return xml_err_attr_undefined(wt, TE_A_ISSUER_ID);
    /*
    if (!cur_warn->issuer_ip)
      return xml_err_attr_undefined(wt, TE_A_ISSUER_IP);
    */
    if (!cur_warn->date)
      return xml_err_attr_undefined(wt, TE_A_DATE);

    for (tt = wt->first_down; tt; tt = tt->right) {
      switch (tt->tag) {
      case TE_T_TEXT:
      case TE_T_COMMENT:
        ptxt = 0;
        switch (tt->tag) {
        case TE_T_TEXT:    ptxt = &cur_warn->text;    break;
        case TE_T_COMMENT: ptxt = &cur_warn->comment; break;
        }
        if (tt->first) return xml_err_attrs(tt);
        if (tt->first_down) return xml_err_nested_elems(tt);
        if (*ptxt) return xml_err_elem_redefined(tt);
        *ptxt = tt->text;
        tt->text = 0;
        break;
      default:
        return xml_err_elem_not_allowed(tt);
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
  if (*ps_flag) return xml_err_elem_redefined(t);
  *ps_flag = 1;

  if (t->first) return xml_err_attrs(t);
  if (t->first_down) return xml_err_nested_elems(t);
  if (!t->text) t->text = xstrdup("");
  if (xml_parse_int(NULL, 0, t->line, t->column, t->text, &te->status) < 0)
    return -1;
  if (te->status < 0) return xml_err_elem_invalid(t);
  return 0;
}

int
parse_run_felds(struct xml_tree *t, struct team_extra *te)
{
  if (!t) return 0;
  if (t->first) return xml_err_attrs(t);
  if (t->first_down) return xml_err_nested_elems(t);
  if (!t->text) return 0;
  long long flags = 0;
  char *eptr = 0;
  errno = 0;
  flags = strtoll(t->text, &eptr, 16);
  if (errno || *eptr || flags <= 0) return 0;
  te->run_fields = flags;
  return 0;
}

int
team_extra_parse_xml(const unsigned char *path, struct team_extra **pte)
{
  struct xml_tree *t = 0, *t2 = 0;
  struct team_extra *te = 0;
  struct xml_attr *a = 0;
  int user_id = -1, x, n, v_flag = 0, w_flag = 0, s_flag = 0, u_flag = 0;

  xml_err_path = path;
  xml_err_spec = &team_extra_parse_spec;

  t = xml_build_tree(NULL, path, &team_extra_parse_spec);
  if (!t) return -1;
  XCALLOC(te, 1);
  if (t->tag != TE_T_TEAM_EXTRA) {
    xml_err_top_level(t, TE_T_TEAM_EXTRA);
    goto cleanup;
  }
  if (xml_empty_text(t) < 0) goto cleanup;
  for (a = t->first; a; a = a->next) {
    switch (a->tag) {
    case TE_A_USER_ID:
      if (!a->text) a->text = xstrdup("");
      x = n = 0;
      if (sscanf(a->text, "%d%n", &x, &n) != 1 || a->text[n]
          || x <= 0 || x > RUNLOG_MAX_TEAM_ID) {
        xml_err_attr_invalid(a);
        goto cleanup;
      }
      user_id = x;
      break;
    case TE_A_CONTEST_ID:
      if (xml_attr_int(a, &te->contest_id) < 0) goto cleanup;
      break;
    default:
      xml_err_attr_not_allowed(t, a);
      goto cleanup;
    }
  }
  if (user_id == -1) {
    xml_err_attr_undefined(t, TE_A_USER_ID);
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
    case TE_T_DISQ_COMMENT:
      if (t2->first) return xml_err_attrs(t2);
      if (t2->first_down) return xml_err_nested_elems(t2);
      if (te->disq_comment) return xml_err_elem_redefined(t2);
      te->disq_comment = t2->text;
      t2->text = 0;
      break;
    case TE_T_PROBLEM_DIR_PREFIX:
      if (t2->first) return xml_err_attrs(t2);
      if (t2->first_down) return xml_err_nested_elems(t2);
      if (te->problem_dir_prefix) return xml_err_elem_redefined(t2);
      te->problem_dir_prefix = t2->text;
      t2->text = 0;
      break;
    case TE_T_RUN_FIELDS:
      if (parse_run_felds(t2, te) < 0) goto cleanup;
      break;
    case TE_T_UUID:
      if (ej_uuid_parse(t2->text, &te->uuid) < 0) {
        xml_err_elem_invalid(t2);
        goto cleanup;
      }
      break;
    case TE_T_CLAR_UUIDS:
      if (parse_clar_uuids(t2, te, &u_flag) < 0) goto cleanup;
      break;
    default:
      xml_err_elem_not_allowed(t2);
      goto cleanup;
    }
  }

  if (pte) *pte = te;
  xml_tree_free(t, &team_extra_parse_spec);
  return 0;

 cleanup:
  if (t) xml_tree_free(t, &team_extra_parse_spec);
  if (te && te->clar_map) xfree(te->clar_map);
  if (te) xfree(te);
  return -1;
}

int
team_extra_unparse_xml(FILE *f, const struct team_extra *te)
{
  int i, j;

  ASSERT(f);
  ASSERT(te);
  ASSERT(te->user_id > 0);

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\"?>\n", EJUDGE_CHARSET);
  fprintf(f, "<%s %s=\"%d\"", elem_map[TE_T_TEAM_EXTRA],
          attr_map[TE_A_USER_ID], te->user_id);
  if (te->contest_id > 0) {
    fprintf(f, " %s=\"%d\"", attr_map[TE_A_CONTEST_ID], te->contest_id);
  }
  fprintf(f, ">\n");
  if (ej_uuid_is_nonempty(te->uuid)) {
    fprintf(f, "  <%s>%s</%s>\n", elem_map[TE_T_UUID],
            ej_uuid_unparse(&te->uuid, NULL),
            elem_map[TE_T_UUID]);
  }
  if (te->clar_map_size > 0) {
    fprintf(f, "  <%s>", elem_map[TE_T_VIEWED_CLARS]);
    for (i = 0, j = 0; i < te->clar_map_size; i++) {
      if (te->clar_map[i / BPE] & (1UL << i % BPE)) {
        if (j) putc(' ', f);
        fprintf(f, "%d", i);
        j++;
      }
    }
    fprintf(f, "  </%s>\n", elem_map[TE_T_VIEWED_CLARS]);
  }
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
              attr_map[TE_A_ISSUER_IP],
              xml_unparse_ipv6(&te->warns[i]->issuer_ip),
              attr_map[TE_A_DATE], xml_unparse_date(te->warns[i]->date));
      xml_unparse_text(f, elem_map[TE_T_TEXT], te->warns[i]->text, "      ");
      xml_unparse_text(f, elem_map[TE_T_COMMENT],
                       te->warns[i]->comment, "      ");
      fprintf(f, "    </%s>\n", elem_map[TE_T_WARNING]);
    }
    fprintf(f, "  </%s>\n", elem_map[TE_T_WARNINGS]);
  }
  if (te->clar_uuids_size > 0) {
    fprintf(f, "  <%s>\n", elem_map[TE_T_CLAR_UUIDS]);
    for (i = 0; i < te->clar_uuids_size; ++i) {
      fprintf(f, "    <%s>%s</%s>\n", elem_map[TE_T_UUID],
              ej_uuid_unparse(&te->clar_uuids[i], NULL), elem_map[TE_T_UUID]);
    }
    fprintf(f, "  </%s>\n", elem_map[TE_T_CLAR_UUIDS]);
  }
  if (te->disq_comment) {
    xml_unparse_text(f, elem_map[TE_T_DISQ_COMMENT], te->disq_comment, "  ");
  }
  if (te->problem_dir_prefix) {
    xml_unparse_text(f, elem_map[TE_T_PROBLEM_DIR_PREFIX], te->problem_dir_prefix, "  ");
  }
  if (te->run_fields > 0) {
    fprintf(f, "  <%s>%llx</%s>\n", elem_map[TE_T_RUN_FIELDS], te->run_fields, elem_map[TE_T_RUN_FIELDS]);
  }
  fprintf(f, "</%s>\n", elem_map[TE_T_TEAM_EXTRA]);
  return 0;
}
