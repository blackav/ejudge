/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000,2001 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "parsecfg.h"
#include "xalloc.h"
#include "pathutl.h"

#include <stdio.h>
#include <ctype.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

static int lineno = 1;

static int
read_first_char(FILE *f)
{
  int c;

  c = getc(f);
  while (c >= 0 && c <= ' ') {
    if (c == '\n') lineno++;
    c = getc(f);
  }
  if (c != EOF) ungetc(c, f);
  return c;
}

static int
read_section_name(FILE *f, char *name, int nlen)
{
  int c, i;

  c = getc(f);
  while (c >= 0 && c <= ' ') {
    if (c == '\n') lineno++;
    c = getc(f);
  }
  if (c != '[') {
    fprintf(stderr, _("%d: [ expected\n"), lineno);
    return -1;
  }

  c = getc(f);
  for (i = 0; i < nlen - 1 && (isalnum(c) || c == '_'); i++, c = getc(f))
    name[i] = c;
  name[i] = 0;
  if (i >= nlen - 1 && (isalnum(c) || c == '_')) {
    fprintf(stderr, _("%d: section name is too long\n"), lineno);
    return -1;
  }
  if (c != ']') {
    fprintf(stderr, _("%d: ] expected\n"), lineno);
    return -1;
  }

  c = getc(f);
  while (c != EOF && c != '\n') {
    if (c > ' ') {
      fprintf(stderr, _("%d: garbage after variable value\n"), lineno);
      return -1;
    }
    c = getc(f);
  }
  lineno++;
  return 0;
}

static int
read_variable(FILE *f, char *name, int nlen, char *val, int vlen)
{
  int   c;
  int  i;

  c = getc(f);
  while (c >= 0 && c <= ' ') {
    if (c == '\n') lineno++;
    c = getc(f);
  }
  for (i = 0; i < nlen - 1 && (isalnum(c) || c == '_'); i++, c = getc(f))
    name[i] = c;
  name[i] = 0;
  if (i >= nlen - 1 && (isalnum(c) || c == '_')) {
    fprintf(stderr, _("%d: variable name is too long\n"), lineno);
    return -1;
  }

  while (c >= 0 && c <= ' ' && c != '\n') c = getc(f);
  if (c != '=') {
    fprintf(stderr, _("%d: '=' expected after variable name\n"), lineno);
    return -1;
  }

  c = getc(f);
  while (c >= 0 && c <= ' ' && c != '\n') c = getc(f);

  i = 0;
  val[0] = 0;
  if (c == '\"') {
    c = getc(f);
    for (i = 0; i < vlen - 1 && c != EOF && c != '\"' && c != '\n';
         i++, c = getc(f))
      val[i] = c;
    val[i] = 0;
    if (i >= vlen - 1 && c != EOF && c != '\"' && c != '\n') {
      fprintf(stderr, _("%d: variable value is too long\n"), lineno);
      return -1;
    }
    if (c != '\"') {
      fprintf(stderr, _("%d: \" expected\n"), lineno);
      return -1;
    }
    c = getc(f);
  } else if (c > ' ') {
    for (i = 0; i < vlen - 1 && c > ' '; i++, c = getc(f))
      val[i] = c;
    val[i] = 0;
    if (i >= vlen - 1 && c > ' ') {
      fprintf(stderr, _("%d: variable value is too long\n"), lineno);
      return -1;
    }
  }

  while (c != '\n' && c != EOF) {
    if (c > ' ') {
      fprintf(stderr, _("%d: garbage after variable value\n"), lineno);
      return -1;
    }
    c = getc(f);
  }
  lineno++;
  return 0;
}

static int
read_comment(FILE *f)
{
  int c;

  c = getc(f);
  while (c != EOF && c != '\n') c =getc(f);
  lineno++;
  return 0;
}

static int
copy_param(void *cfg, struct config_parse_info *params,
           char *varname, char *varvalue)
{
  int i;

  for (i = 0; params[i].name; i++)
    if (!strcmp(params[i].name, varname)) break;
  if (!params[i].name) {
    fprintf(stderr, _("%d: unknown parameter '%s'\n"),
            lineno - 1, varname);
    return -1;
  }

  if (!strcmp(params[i].type, "d")) {
    int  n, v;
    int *ptr;

    if (sscanf(varvalue, "%d%n", &v, &n) != 1 || varvalue[n]) {
      fprintf(stderr, _("%d: numeric parameter expected for '%s'\n"),
              lineno - 1, varname);
      return -1;
    }
    ptr = (int *) ((char*) cfg + params[i].offset);
    *ptr = v;
  } else if (!strcmp(params[i].type, "s")) {
    char *ptr;

    if (params[i].size == 0) params[i].size = PATH_MAX;
    if (strlen(varvalue) > params[i].size - 1) {
      fprintf(stderr, _("%d: parameter '%s' is too long\n"), lineno - 1,
              varname);
      return -1;
    }
    ptr = (char*) cfg + params[i].offset;
    strcpy(ptr, varvalue);
  }
  return 0;
}

struct generic_section_config *
parse_param(char const *path,
            void *vf,
            struct config_section_info *params,
            int quiet_flag)
{
  struct generic_section_config  *cfg = NULL;
  struct generic_section_config **psect, *sect;
  struct config_parse_info       *sinfo;

  char           sectname[32];
  char           varname[32];
  char           varvalue[1024];
  int            c, sindex;
  FILE          *f = (FILE *) vf;

  /* found the global section description */
  for (sindex = 0; params[sindex].name; sindex++) {
    if (!strcmp(params[sindex].name, "global")) break;
  }
  if (!params[sindex].name) {
    fprintf(stderr, _("Cannot find description of section [global]\n"));
    goto cleanup;
  }
  sinfo = params[sindex].info;

  if (!f && !(f = fopen(path, "r"))) {
    fprintf(stderr, _("Cannot open configuration file %s\n"), path);
    goto cleanup;
  }

  cfg = (struct generic_section_config*) xcalloc(1, params[sindex].size);
  psect = &cfg->next;
  sect = NULL;

  while (1) {
    c = read_first_char(f);
    if (c == EOF || c == '[') break;
    if (c == '#') {
      read_comment(f);
      continue;
    }
    if (read_variable(f, varname, sizeof(varname),
                      varvalue, sizeof(varvalue)) < 0) goto cleanup;
    if (!quiet_flag) {
      printf(_("%d: Value: %s = %s\n"), lineno - 1, varname, varvalue);
    }
    if (copy_param(cfg, sinfo, varname, varvalue) < 0) goto cleanup;
  }

  while (c != EOF) {
    if (read_section_name(f, sectname, sizeof(sectname)) < 0) goto cleanup;
    if (!quiet_flag) {
      printf(_("%d: New section %s\n"), lineno - 1, sectname);
    }
    if (!strcmp(sectname, "global")) {
      fprintf(stderr, _("Section global cannot be specified explicitly\n"));
      goto cleanup;
    }
    for (sindex = 0; params[sindex].name; sindex++) {
      if (!strcmp(params[sindex].name, sectname)) break;
    }
    if (!params[sindex].name) {
      fprintf(stderr, _("Cannot find description of section [%s]\n"),
              sectname);
      goto cleanup;
    }
    sinfo = params[sindex].info;
    if (params[sindex].pcounter) (*params[sindex].pcounter)++;

    sect = (struct generic_section_config*) xcalloc(1, params[sindex].size);
    strcpy(sect->name, sectname);
    *psect = sect;
    psect = &sect->next;

    while (1) {
      c = read_first_char(f);
      if (c == EOF || c == '[') break;
      if (c == '#') {
        read_comment(f);
        continue;
      }
      if (read_variable(f, varname, sizeof(varname),
                        varvalue, sizeof(varvalue)) < 0) goto cleanup;
      if (!quiet_flag) {
        printf(_("%d: Value: %s = %s\n"), lineno - 1, varname, varvalue);
      }
      if (copy_param(sect, sinfo, varname, varvalue) < 0) goto cleanup;
    }
  }

  if (vf) fclose(f);
  return cfg;

 cleanup:
  xfree(cfg);
  if (vf && f) fclose(f);
  return NULL;
}

