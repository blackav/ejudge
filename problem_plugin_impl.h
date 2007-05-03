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

#include "problem_plugin.h"

#include <reuse/xalloc.h>

#include <ctype.h>
#include <string.h>

#if !defined INIT_FUNC_NAME
#define INIT_FUNC_NAME init_func
static void *
init_func(void)
{
  return 0;
}
#endif /* INIT_FUNC_NAME */

#if !defined FINI_FUNC_NAME
#define FINI_FUNC_NAME finalize_func
static void
finalize_func(void *data)
{
}
#endif /* FINI_FUNC_NAME */

struct http_request_info;
struct contest_desc;
struct contest_extra;

int
ns_cgi_param(
	const struct http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value);
int
ns_cgi_param_bin(
	const struct http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value,
        size_t *p_size);
int
ns_cgi_param_int(
	struct http_request_info *phr,
        const unsigned char *name,
        int *p_val);

unsigned char *
text_input_process_string(const unsigned char *s,
                          int sep, int sep_repl);
unsigned char *
text_area_process_string(const unsigned char *s,
                         int sep, int sep_repl);

#define PLUGIN_STRINGIFY(x) #x
#define PLUGIN_STRINGIFY_2(x) PLUGIN_STRINGIFY(x)
#define PLUGIN_CONCAT(x,y) x##y
#define PLUGIN_STRUCT_NAME(x) PLUGIN_CONCAT(plugin_problem_, x)
#define PLUGIN_STRING(x) PLUGIN_STRINGIFY_2(PLUGIN_CONCAT(problem_, x))

static int
parse_form(
	FILE *fout, 
        FILE *flog,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);

static unsigned char *
parse_form_func(
	void *data, 
        FILE *flog,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  char *out_s = 0;
  size_t out_z = 0;
  FILE *fout = open_memstream(&out_s, &out_z);
  int r;

  r = parse_form(fout, flog, phr, cnts, extra);
  if (r == -2) goto invalid_characters;
  if (r < 0) goto fail;

  fclose(fout);
  return (unsigned char*) out_s;

 invalid_characters:
  fprintf(flog, "Invalid characters in the form\n");
  goto fail;

 fail:
  if (fout) fclose(fout);
  xfree(out_s);
  return 0;
}

struct problem_plugin_iface PLUGIN_STRUCT_NAME(PLUGIN_NAME) =
{
  {
    sizeof (struct problem_plugin_iface),
    EJUDGE_PLUGIN_IFACE_VERSION,
    "problem",
    PLUGIN_STRING(PLUGIN_NAME),
  },

  PROBLEM_PLUGIN_IFACE_VERSION,
  INIT_FUNC_NAME,
  FINI_FUNC_NAME,
  parse_form_func,
  0,
};
