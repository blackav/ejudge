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

static char const * const elem_map[] =
{
  0,
  "problem",
  0,
  "_default",
  "_text",
  0,
};

static char const * const attr_map[] =
{
  0,
  0,
  "_default",

  0,
};

static const unsigned char verbatim_flags[PROB_LAST_TAG] =
{
  [PROB_T_PROBLEM] = 1,
};

static struct xml_parse_spec ejudge_config_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = NULL,
  .attr_sizes = NULL,
  .default_elem = PROB_T__DEFAULT,
  .default_attr = PROB_A__DEFAULT,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = NULL,
  .attr_free = NULL,
  .verbatim_flags = verbatim_flags,
  .text_elem = PROB_T__TEXT,
  .unparse_entity = 1,
};

problem_xml_t
problem_xml_parse(const unsigned char *path)
{
  struct xml_tree *tree = 0;

  xml_err_path = path;
  xml_err_spec = &contests_parse_spec;

  tree = xml_build_tree(path, &contests_parse_spec);
  if (!tree) goto failed;

 failed:
  problem_
}

problem_xml_t
problem_xml_parse_string(const unsigned char *path, const unsigned char *str)
{
}

problem_xml_t
problem_xml_parse_stream(const unsigned char *path, FILE *f)
{
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
