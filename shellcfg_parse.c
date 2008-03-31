/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "shellcfg_parse.h"

#include <reuse/xalloc.h>

#include <string.h>
#include <ctype.h>

static int
next_char(FILE *f)
{
  int c = getc(f);
  if (c == '#') {
    while (c != EOF && c != '\n') c = getc(f);
  }
  return c;
}

shellconfig_t
shellconfig_parse(FILE *log_f, FILE *f, const unsigned char *path)
{
  shellconfig_t cfg = 0;
  int lineno = 1;
  int errcount = 0;
  int c, endc;
  unsigned char varname[1024], varval[1024];
  int namei, vali, i;

  XCALLOC(cfg, 1);
  c = next_char(f);
  while (c != EOF) {
    if (c == '\n') {
      c = next_char(f);
      lineno++;
      continue;
    }
    if (isspace(c)) {
      c = next_char(f);
      continue;
    }
    if (c < ' ') {
      fprintf(log_f, "%s: %d: invalid control character %d\n",path, lineno, c);
      errcount++;
      c = next_char(f);
      continue;
    }
    if (!isalpha(c)) {
      fprintf(log_f, "%s: %d: variable name expected\n", path, lineno);
      goto failure;
    }
    namei = 0;
    while ((isalnum(c) || c == '_') && namei < sizeof(varname) - 2) {
      varname[namei++] = c;
      c = next_char(f);
    }
    if (namei >= sizeof(varname) - 2) {
      fprintf(log_f, "%s: %d: variable name is too long\n", path, lineno);
      goto failure;
    }
    varname[namei] = 0;
    if (c != '=') {
      fprintf(log_f, "%s: %d: `=' expected\n", path, lineno);
      goto failure;
    }
    c = next_char(f);
    vali = 0;
    while (c != EOF && !isspace(c) && vali < sizeof(varval) - 2) {
      if (c < ' ') {
        fprintf(log_f, "%s: %d: invalid control character %d\n",path,lineno,c);
        errcount++;
        c = next_char(f);
        continue;
      } else if (c == '\'' || c == '\"') {
        endc = c;
        c = next_char(f);
        while (c != EOF && c != '\n' && c != endc) {
          if (c < ' ' && !isspace(c)) {
            fprintf(log_f, "%s: %d: invalid control character %d\n",
                    path, lineno, c);
            errcount++;
            c = next_char(f);
            continue;
          }
          varval[vali++] = c;
          c = next_char(f);
        }
        if (c != endc) {
          fprintf(log_f, "%s: %d: `\\%c' expected\n", path, lineno, c);
          goto failure;
        }
        c = next_char(f);
      } else {
        varval[vali++] = c;
        c = next_char(f);
      }
    }
    varval[vali] = 0;
    for (i = 0; i < cfg->usage; i++)
      if (!strcmp(varname, cfg->names[i]))
        break;
    if (i == cfg->usage) {
      if (cfg->usage == cfg->size) {
        if (!(cfg->size *= 2)) cfg->size = 16;
        XREALLOC(cfg->names, cfg->size);
        XREALLOC(cfg->lengths, cfg->size);
        XREALLOC(cfg->values, cfg->size);
      }
      cfg->names[i] = xstrdup(varname);
      cfg->lengths[i] = vali;
      cfg->values[i] = xmemdup(varval, vali + 1);
      cfg->usage++;
    } else {
      xfree(cfg->values[i]);
      cfg->lengths[i] = vali;
      cfg->values[i] = xmemdup(varval, vali + 1);
    }

    while (c != EOF && c != '\n') {
      if (!isspace(c)) {
        fprintf(log_f, "%s: %d: garbage after variable value\n", path, lineno);
        goto failure;
      }
      c = next_char(f);
    }
  }

  if (errcount > 0) goto failure;
  goto cleanup;

 failure:
  cfg = shellconfig_free(cfg);

 cleanup:
  return cfg;
}

shellconfig_t
shellconfig_free(shellconfig_t cfg)
{
  size_t i;

  if (!cfg) return 0;

  for (i = 0; i < cfg->usage; i++) {
    xfree(cfg->names[i]);
    xfree(cfg->values[i]);
  }
  xfree(cfg->names);
  xfree(cfg->lengths);
  xfree(cfg->values);
  memset(cfg, 0, sizeof(*cfg));
  xfree(cfg);
  return 0;
}

int
shellconfig_find_by_prefix(
	shellconfig_t cfg,
        const unsigned char *pfx,
        size_t pfxlen)
{
  int i;

  if (!cfg) return -1;
  for (i = 0; i < cfg->usage; i++)
    if (!strncmp(cfg->names[i], pfx, pfxlen))
      break;
  if (i == cfg->usage) i = -1;
  return i;
}

const unsigned char *
shellconfig_get_name_by_num(
	shellconfig_t cfg,
        int num)
{
  if (!cfg || num < 0 || num >= cfg->usage) return 0;
  return cfg->names[num];
}

const unsigned char *
shellconfig_get_value_by_num(
	shellconfig_t cfg,
        int num)
{
  if (!cfg || num < 0 || num >= cfg->usage) return 0;
  if (strlen(cfg->values[num]) != cfg->lengths[num]) return 0;
  return cfg->values[num];
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

