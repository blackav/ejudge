/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2011-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/problem_xml.h"
#include "ejudge/misctext.h"

#define ARMOR(s)  html_armor_buf(&ab, (s))

static void
unparse_statement(FILE *out_f, const struct xml_parse_spec *spec, const struct problem_stmt *stmt)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  if (!stmt) return;

  fprintf(out_f, "  <%s", spec->elem_map[PROB_T_STATEMENT]);
  if (stmt->lang) {
    fprintf(out_f, " %s=\"%s\"", spec->attr_map[PROB_A_LANG], ARMOR(stmt->lang));
  }
  fprintf(out_f, ">\n");
  if (stmt->title) {
    fprintf(out_f, "    <%s>", spec->elem_map[PROB_T_TITLE]);
    xml_unparse_raw_tree(out_f, stmt->title, spec);
    fprintf(out_f, "</%s>\n", spec->elem_map[PROB_T_TITLE]);
  }
  if (stmt->desc) {
    fprintf(out_f, "    <%s>", spec->elem_map[PROB_T_DESCRIPTION]);
    xml_unparse_raw_tree(out_f, stmt->desc, spec);
    fprintf(out_f, "</%s>\n", spec->elem_map[PROB_T_DESCRIPTION]);
  }
  if (stmt->input_format) {
    fprintf(out_f, "    <%s>", spec->elem_map[PROB_T_INPUT_FORMAT]);
    xml_unparse_raw_tree(out_f, stmt->input_format, spec);
    fprintf(out_f, "</%s>\n", spec->elem_map[PROB_T_INPUT_FORMAT]);
  }
  if (stmt->output_format) {
    fprintf(out_f, "    <%s>", spec->elem_map[PROB_T_OUTPUT_FORMAT]);
    xml_unparse_raw_tree(out_f, stmt->output_format, spec);
    fprintf(out_f, "</%s>\n", spec->elem_map[PROB_T_OUTPUT_FORMAT]);
  }
  if (stmt->notes) {
    fprintf(out_f, "    <%s>", spec->elem_map[PROB_T_NOTES]);
    xml_unparse_raw_tree(out_f, stmt->notes, spec);
    fprintf(out_f, "</%s>\n", spec->elem_map[PROB_T_NOTES]);
  }
  fprintf(out_f, "  </%s>\n", spec->elem_map[PROB_T_STATEMENT]);
  html_armor_free(&ab);
}

void
problem_xml_unparse(FILE *out_f, const problem_xml_t prob_xml)
{
  const struct xml_parse_spec *spec = problem_xml_get_parse_spec();
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const struct problem_stmt *stmt = NULL;
  const struct xml_tree *p, *q;

  if (!prob_xml) return;

  fprintf(out_f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", EJUDGE_CHARSET);
  fprintf(out_f, "<%s", spec->elem_map[PROB_T_PROBLEM]);
  if (prob_xml->package) {
    fprintf(out_f, "\n        %s=\"%s\"", spec->attr_map[PROB_A_PACKAGE], ARMOR(prob_xml->package));
  }
  if (prob_xml->id) {
    fprintf(out_f, "\n        %s=\"%s\"", spec->attr_map[PROB_A_ID], ARMOR(prob_xml->id));
  }
  if (prob_xml->type >= 0 && prob_xml->type < PROB_TYPE_LAST) {
    fprintf(out_f, "\n        %s=\"%s\"", spec->attr_map[PROB_A_TYPE], problem_unparse_type(prob_xml->type));
  }
  fprintf(out_f, ">\n");

  for (stmt = prob_xml->stmts; stmt; stmt = stmt->next_stmt) {
    unparse_statement(out_f, spec, stmt);
  }
  if (prob_xml->examples) {
    fprintf(out_f, "  <%s>\n", spec->elem_map[PROB_T_EXAMPLES]);
    for (p = prob_xml->examples->first_down; p; p = p->right) {
      if (p->tag != PROB_T_EXAMPLE) continue;
      fprintf(out_f, "    <%s>\n", spec->elem_map[PROB_T_EXAMPLE]);
      for (q = p->first_down; q && q->tag != PROB_T_INPUT; q = q->right);
      if (q && q->tag == PROB_T_INPUT) {
        fprintf(out_f, "      <%s>", spec->elem_map[PROB_T_INPUT]);
        xml_unparse_raw_tree(out_f, q, spec);
        fprintf(out_f, "</%s>\n", spec->elem_map[PROB_T_INPUT]);
      }
      for (q = p->first_down; q && q->tag != PROB_T_OUTPUT; q = q->right);
      if (q && q->tag == PROB_T_OUTPUT) {
        fprintf(out_f, "      <%s>", spec->elem_map[PROB_T_OUTPUT]);
        xml_unparse_raw_tree(out_f, q, spec);
        fprintf(out_f, "</%s>\n", spec->elem_map[PROB_T_OUTPUT]);
      }
      fprintf(out_f, "    </%s>\n", spec->elem_map[PROB_T_EXAMPLE]);
    }
    fprintf(out_f, "  </%s>\n", spec->elem_map[PROB_T_EXAMPLES]);
  }
  fprintf(out_f, "</%s>\n", spec->elem_map[PROB_T_PROBLEM]);

  html_armor_free(&ab);
}
