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
  "lang",
  0,
  "_default",

  0,
};

static size_t const elem_sizes[PROB_LAST_TAG] =
{
  [PROB_T_PROBLEM] = sizeof(struct problem_desc),
  [PROB_T_STATEMENT] = sizeof(struct problem_stmt),
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
