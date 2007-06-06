/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "problem_xml.h"
#include "xml_utils.h"

#include <reuse/xalloc.h>

#include <string.h>
#include <errno.h>
#include <limits.h>

static char const * const elem_map[] =
{
  0,
  "problem",
  "statement",
  "title",
  "description",
  "input_format",
  "output_format",
  "examples",
  "example",
  "input",
  "output",
  "time_limits",
  "time_limit",
  "answer_variants",
  0,
  "_default",
  "_text",
  0,
};

static char const * const attr_map[] =
{
  0,
  "id",
  "type",
  "language",
  "cpu",
  "wordsize",
  "frequency",
  "bogomips",
  0,
  "_default",

  0,
};

static size_t const elem_sizes[PROB_LAST_TAG] =
{
  [PROB_T_PROBLEM] = sizeof(struct problem_desc),
  [PROB_T_STATEMENT] = sizeof(struct problem_stmt),
  [PROB_T_TIME_LIMIT] = sizeof(struct problem_time_limit),
};

static const unsigned char verbatim_flags[PROB_LAST_TAG] =
{
  [PROB_T_PROBLEM] = 1,
};

static void node_free(struct xml_tree *t);

static struct xml_parse_spec problem_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = NULL,
  .attr_sizes = NULL,
  .default_elem = PROB_T__DEFAULT,
  .default_attr = PROB_A__DEFAULT,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = node_free,
  .attr_free = NULL,
  .verbatim_flags = verbatim_flags,
  .text_elem = PROB_T__TEXT,
  .unparse_entity = 1,
};

static void
node_free(struct xml_tree *t)
{
  switch (t->tag) {
  case PROB_T_TIME_LIMIT:
    {
      struct problem_time_limit *pt = (struct problem_time_limit*) t;

      xfree(pt->cpu);
    }
    break;
  case PROB_T_PROBLEM:
    {
      problem_xml_t pt = (problem_xml_t) t;

      xfree(pt->id);
    }
    break;
  case PROB_T_STATEMENT:
    {
      struct problem_stmt *pt = (struct problem_stmt*) t;

      xfree(pt->lang);
    }
    break;
  }
}

problem_xml_t
problem_xml_free(problem_xml_t tree)
{
  xml_tree_free(&tree->b, &problem_parse_spec);
  return 0;
}

static int
num_suffix(const unsigned char *str)
{
  if (!str[0]) return 1;
  if (str[1]) return 0; 
  if (str[0] == 'k' || str[0] == 'K') return 1024;
  if (str[0] == 'm' || str[0] == 'M') return 1024 * 1024;
  if (str[0] == 'g' || str[0] == 'G') return 1024 * 1024 * 1024;
  return 0;
}

static int
parse_size(const unsigned char *str, size_t *sz)
{
  long long val;
  char *eptr = 0;
  int sfx;

  if (!str || !*str) return -1;
  if (!strcasecmp(str, "unlimited")) {
    *sz = (size_t) -1;
    return 0;
  }
  if (!strcasecmp(str, "default")) {
    *sz = 0;
    return 0;
  }
  errno = 0;
  val = strtoll(str, &eptr, 10);
  if (errno || val <= 0 || (sfx = num_suffix(eptr)) <= 0) return -1;
  if (val > LONG_LONG_MAX / sfx) return -1;
  val *= sfx;
  if (val >= 2147483648LL) return -1;
  *sz = val;
  return 0;
}

static int
parse_statement(problem_xml_t prb, struct xml_tree *pstmt)
{
  struct problem_stmt *stmt = (struct problem_stmt*) pstmt;
  struct xml_attr *a;
  struct xml_tree *p1;

  stmt->next_stmt = prb->stmts;
  prb->stmts = stmt;

  for (a = stmt->b.first; a; a = a->next) {
    switch (a->tag) {
    case PROB_A_LANG:
      stmt->lang = a->text; a->text = 0;
      break;
    default:
      return xml_err_attr_not_allowed(pstmt, a);
    }
  }

  for (p1 = stmt->b.first_down; p1; p1 = p1->right) {
    switch (p1->tag) {
    case PROB_T_TITLE:
      if (stmt->title) return xml_err_elem_redefined(p1);
      stmt->title = p1;
      break;
    case PROB_T_DESCRIPTION:
      if (stmt->desc) return xml_err_elem_redefined(p1);
      stmt->desc = p1;
      break;
    case PROB_T_INPUT_FORMAT:
      if (stmt->input_format) return xml_err_elem_redefined(p1);
      stmt->input_format = p1;
      break;
    case PROB_T_OUTPUT_FORMAT:
      if (stmt->output_format) return xml_err_elem_redefined(p1);
      stmt->output_format = p1;
      break;
    default:
      return xml_err_elem_not_allowed(p1);
    }
  }

  return 0;
}

static int
parse_time_limits(problem_xml_t prb, struct xml_tree *tree)
{
  struct xml_tree *p;
  struct xml_attr *a;
  struct problem_time_limit *ptl;
  int t, n;
  double v;

  for (p = tree->first_down; p; p = p->right) {
    if (p->tag != PROB_T_TIME_LIMIT) return xml_err_elem_not_allowed(p);
    ptl = (struct problem_time_limit*) p;
    ptl->next_tl = prb->tls;
    prb->tls = ptl;
    if (p->first_down) return xml_err_nested_elems(p);
    for (a = p->first; a; a = a->next) {
      switch (a->tag) {
      case PROB_A_CPU:
        ptl->cpu = a->text; a->text = 0;
        break;
      case PROB_A_WORDSIZE:
        if (sscanf(a->text, "%d%n", &t, &n) != 1 || a->text[n])
          return xml_err_attr_invalid(a);
        if (t != 16 && t != 32 && t != 64)
          return xml_err_attr_invalid(a);
        ptl->wordsize = t;
        break;
      case PROB_A_FREQ:
        if (sscanf(a->text, "%lf%n", &v, &n) != 1)
          return xml_err_attr_invalid(a);
        if (!a->text[n]) {
          ptl->freq = (long long) v;
        } else if (!strcasecmp(a->text + n, "GHz")) {
          ptl->freq = (long long) (v * 1000000000.0);
        } else if (!strcasecmp(a->text + n, "MHz")) {
          ptl->freq = (long long) (v * 1000000.0);
        } else if (!strcasecmp(a->text + n, "KHz")) {
          ptl->freq = (long long) (v * 1000.0);
        } else if (!strcasecmp(a->text + n, "Hz")) {
          ptl->freq = (long long) v;
        } else {
          return xml_err_attr_invalid(a);
        }
        if (ptl->freq < 0) xml_err_attr_invalid(a);
        break;
      case PROB_A_BOGOMIPS:
        if (sscanf(a->text, "%lf%n", &v, &n) != 1 || a->text[n] || v <= 0)
          return xml_err_attr_invalid(a);
        ptl->bogomips = v;
        break;
      default:
        return xml_err_attr_not_allowed(p, a);
      }
    }
    if (sscanf(p->text, "%d%n", &t, &n) != 1) return xml_err_elem_invalid(p);
    if (t <= 0 || t > 1000000) return xml_err_elem_invalid(p);
    if (!p->text[n]) {
      t *= 1000;
    } else if (!strcasecmp(p->text + n, "s")) {
      t *= 1000;
    } else if (!strcasecmp(p->text + n, "ms")) {
    } else {
      return xml_err_elem_invalid(p);
    }
    xfree(p->text); p->text = 0;
    ptl->time_limit_ms = t;
  }

  return 0;
}

static int
parse_answer_variants(problem_xml_t prb, struct xml_tree *tree)
{
  struct xml_tree *p, *q;
  struct xml_attr *a;

  for (p = tree->first_down; p; p = p->right) {
    if (p->tag != PROB_T_ANSWER) return xml_err_elem_not_allowed(p);
  }

  return 0;
}

static int
parse_tree(problem_xml_t tree)
{
  struct xml_tree *pt = &tree->b;
  struct xml_attr *a;
  struct xml_tree *p1;

  if (tree->b.tag != PROB_T_PROBLEM)
    return xml_err_top_level(pt, PROB_T_PROBLEM);

  // handle attributes
  for (a = tree->b.first; a; a = a->next) {
    switch (a->tag) {
    case PROB_A_ID:
      tree->id = a->text; a->text = 0;
      break;
    case PROB_A_TYPE:
      if ((tree->type = problem_parse_type(a->text)) < 0)
        return xml_err_attr_invalid(a);
      break;
    default:
      return xml_err_attr_not_allowed(&tree->b, a);
    }
  }

  for (p1 = tree->b.first_down; p1; p1 = p1->right) {
    switch (p1->tag) {
    case PROB_T_STATEMENT:
      if (parse_statement(tree, p1) < 0)
        return -1;
      break;
    case PROB_T_EXAMPLES:
      tree->examples = p1;
      break;
    case PROB_T_MAX_VM_SIZE:
      if (tree->max_vm_size) return xml_err_elem_redefined(p1);
      if (parse_size(p1->text, &tree->max_vm_size) < 0)
        return xml_err_elem_invalid(p1);
      break;
    case PROB_T_MAX_STACK_SIZE:
      if (tree->max_stack_size) return xml_err_elem_redefined(p1);
      if (parse_size(p1->text, &tree->max_stack_size) < 0)
        return xml_err_elem_invalid(p1);
      break;
    case PROB_T_TIME_LIMITS:
      if (parse_time_limits(tree, p1) < 0) return -1;
      break;
    case PROB_T_ANSWER_VARIANTS:
      if (parse_answer_variants(tree, p1) < 0) return -1;
      break;
    default:
      return xml_err_elem_not_allowed(p1);
    }
  }

  return 0;
}

problem_xml_t
problem_xml_parse(const unsigned char *path)
{
  struct xml_tree *tree = 0;
  problem_xml_t px = 0;

  xml_err_path = path;
  xml_err_spec = &problem_parse_spec;

  tree = xml_build_tree(path, &problem_parse_spec);
  if (!tree) goto failed;
  px = (problem_xml_t) tree;
  if (parse_tree(px) < 0) goto failed;
  return px;

 failed:
  problem_xml_free((problem_xml_t) tree);
  return 0;
}

problem_xml_t
problem_xml_parse_string(const unsigned char *path, const unsigned char *str)
{
  struct xml_tree *tree = 0;
  problem_xml_t px = 0;

  xml_err_path = path;
  xml_err_spec = &problem_parse_spec;

  tree = xml_build_tree_str(str, &problem_parse_spec);
  if (!tree) goto failed;
  px = (problem_xml_t) tree;
  if (parse_tree(px) < 0) goto failed;
  return px;

 failed:
  problem_xml_free((problem_xml_t) tree);
  return 0;
}

problem_xml_t
problem_xml_parse_stream(const unsigned char *path, FILE *f)
{
  struct xml_tree *tree = 0;
  problem_xml_t px = 0;

  xml_err_path = path;
  xml_err_spec = &problem_parse_spec;

  tree = xml_build_tree_file(f, &problem_parse_spec);
  if (!tree) goto failed;
  px = (problem_xml_t) tree;
  if (parse_tree(px) < 0) goto failed;
  return px;

 failed:
  problem_xml_free((problem_xml_t) tree);
  return 0;
}

struct problem_stmt *
problem_xml_unparse_elem(
	FILE *fout,
        problem_xml_t p,
        int elem,                  /* STATEMENT, INPUT_FORMAT, etc */
        const unsigned char *lang, /* 0 - default language */
        struct problem_stmt *stmt) /* previously found element */
{
  struct xml_tree *t = 0;

  if (!stmt && lang) {
    // try to find the exact language
    for (stmt = p->stmts; stmt; stmt = stmt->next_stmt) {
      if (stmt->lang && !strcasecmp(stmt->lang, lang))
        break;
    }
  }
  if (!stmt) {
    // try to find the default language
    // FIXME: add and handle "default" attribute
    for (stmt = p->stmts; stmt; stmt = stmt->next_stmt) {
      if (!stmt->lang)
        break;
    }
  }
  if (!stmt) {
    // get the first language
    stmt = p->stmts;
  }
  if (!stmt) return 0;

  switch (elem) {
  case PROB_T_TITLE:         t = stmt->title;         break;
  case PROB_T_DESCRIPTION:   t = stmt->desc;          break;
  case PROB_T_INPUT_FORMAT:  t = stmt->input_format;  break; 
  case PROB_T_OUTPUT_FORMAT: t = stmt->output_format; break;
  default:
    return stmt;
  }

  xml_unparse_raw_tree(fout, t, &problem_parse_spec);

  return stmt;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
