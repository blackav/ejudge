/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2004 Alexander Chernov <cher@ispras.ru> */

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

#include "parsecfg.h"
#include "pathutl.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>

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
    fprintf(stderr, "%d: [ expected\n", lineno);
    return -1;
  }

  c = getc(f);
  for (i = 0; i < nlen - 1 && (isalnum(c) || c == '_'); i++, c = getc(f))
    name[i] = c;
  name[i] = 0;
  if (i >= nlen - 1 && (isalnum(c) || c == '_')) {
    fprintf(stderr, "%d: section name is too long\n", lineno);
    return -1;
  }
  if (c != ']') {
    fprintf(stderr, "%d: ] expected\n", lineno);
    return -1;
  }

  c = getc(f);
  while (c != EOF && c != '\n') {
    if (c > ' ') {
      fprintf(stderr, "%d: garbage after variable value\n", lineno);
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
  unsigned char *lbuf = 0, *tmp, *p, *q;
  size_t lbuf_size = 0;
  size_t lbuf_used = 0, tmp_len;
  int quot_char = 0;
  unsigned char nb[4];

  c = getc(f);
  while (c >= 0 && c <= ' ') {
    if (c == '\n') lineno++;
    c = getc(f);
  }
  for (i = 0; i < nlen - 1 && (isalnum(c) || c == '_'); i++, c = getc(f))
    name[i] = c;
  name[i] = 0;
  if (i >= nlen - 1 && (isalnum(c) || c == '_')) {
    fprintf(stderr, "%d: variable name is too long\n", lineno);
    return -1;
  }

  while (c >= 0 && c <= ' ' && c != '\n') c = getc(f);
  if (c == '\n') {
    // FIXME: may we assumpt, that vlen >= 2?
    strcpy(val, "1");
    lineno++;
    return 0;
  }
  if (c != '=') {
    fprintf(stderr, "%d: '=' expected after variable name\n", lineno);
    return -1;
  }

  lbuf_size = 128;
  lbuf = alloca(128);
  lbuf_used = 0;
  while (1) {
    c = getc(f);
    if (c == EOF) break;
    if (lbuf_used + 1 == lbuf_size) {
      tmp = alloca(lbuf_size *= 2);
      memcpy(tmp, lbuf, lbuf_used);
      lbuf = tmp;
    }
    lbuf[lbuf_used++] = c;
    if (c == '\n') break;
  }
  while (lbuf_used > 0 && isspace(lbuf[lbuf_used - 1])) lbuf_used--;
  lbuf[lbuf_used] = 0;

  q = tmp = alloca(lbuf_size);
  p = lbuf;
  while (*p && isspace(*p)) p++;
  while (1) {
    if (!*p) break;
    if (!quot_char && (*p == '#' || *p == ';')) break;
    if (!quot_char && isspace(*p)) break;
    if (*p < ' ') {
      fprintf(stderr, "%d: invalid control code %d\n", lineno, *p);
      return -1;
    }
    if (*p == '\"' || *p == '\'') {
      if (!quot_char) {
        quot_char = *p++;
      } else if (quot_char == *p) {
        quot_char = 0;
        p++;
      } else {
        *q++ = *p++;
      }
      continue;
    }
    if (quot_char) {
      *q++ = *p++;
      continue;
    }
    if (*p == '\\') {
      switch (p[1]) {
      case 0:
        *q++ = '\\';
        p++;
        break;
      case 'x': case 'X':
        if (!isxdigit(p[2])) {
          fprintf(stderr, "%d: invalid escape sequence\n", lineno);
          return -1;
        }
        p += 2;
        memset(nb, 0, sizeof(nb));
        nb[0] = *p++;
        if (isxdigit(*p)) nb[1] = *p++;
        *q++ = strtol(nb, 0, 16);
        break;
      case '0': case '1': case '2': case '3':
        p++;
        memset(nb, 0, sizeof(nb));
        nb[0] = *p++;
        if (*p >= '0' && *p <= '7') nb[1] = *p++;
        if (*p >= '0' && *p <= '7') nb[2] = *p++;
        *q++ = strtol(nb, 0, 8);
        break;
      case '4': case '5': case '6': case '7':
        p++;
        memset(nb, 0, sizeof(nb));
        nb[0] = *p++;
        if (*p >= '0' && *p <= '7') nb[1] = *p++;
        *q++ = strtol(nb, 0, 8);
        break;
      case 'a': *q++ = '\a'; p += 2; break;
      case 'b': *q++ = '\b'; p += 2; break;
      case 'f': *q++ = '\f'; p += 2; break;
      case 'n': *q++ = '\n'; p += 2; break;
      case 'r': *q++ = '\r'; p += 2; break;
      case 't': *q++ = '\t'; p += 2; break;
      case 'v': *q++ = '\v'; p += 2; break;
      default:
        p++;
        *q++ = *p++;
        break;
      }
      continue;
    }
    *q++ = *p++;
  }

  while (*p && isspace(*p)) p++;
  if (quot_char) {
    fprintf(stderr, "%d: unclosed quote character <%c>\n", lineno, quot_char);
    return -1;
  }
  if (*p && *p != '#' && *p != ';') {
    fprintf(stderr, "%d: garbage after variable value\n", lineno);
    return -1;
  }
  *q = 0;
  tmp_len = strlen(tmp);
  if (tmp_len >= vlen) {
    fprintf(stderr, "%d: variable value is too long\n", lineno);
    return -1;
  }
  strcpy(val, tmp);
  lineno++;
  return 0;

  /*
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
      fprintf(stderr, "%d: variable value is too long\n", lineno);
      return -1;
    }
    if (c != '\"') {
      fprintf(stderr, "%d: \" expected\n", lineno);
      return -1;
    }
    c = getc(f);
  } else if (c > ' ') {
    for (i = 0; i < vlen - 1 && c > ' '; i++, c = getc(f))
      val[i] = c;
    val[i] = 0;
    if (i >= vlen - 1 && c > ' ') {
      fprintf(stderr, "%d: variable value is too long\n", lineno);
      return -1;
    }
  }

  while (c != '\n' && c != EOF) {
    if (c > ' ') {
      fprintf(stderr, "%d: garbage after variable value\n", lineno);
      return -1;
    }
    c = getc(f);
  }
  lineno++;
  return 0;
  */
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
    fprintf(stderr, "%d: unknown parameter '%s'\n",
            lineno - 1, varname);
    return -1;
  }

  if (!strcmp(params[i].type, "d")) {
    int  n, v;
    int *ptr;

    if (sscanf(varvalue, "%d%n", &v, &n) != 1 || varvalue[n]) {
      fprintf(stderr, "%d: numeric parameter expected for '%s'\n",
              lineno - 1, varname);
      return -1;
    }
    ptr = (int *) ((char*) cfg + params[i].offset);
    *ptr = v;
  } else if (!strcmp(params[i].type, "s")) {
    char *ptr;

    if (params[i].size == 0) params[i].size = PATH_MAX;
    if (strlen(varvalue) > params[i].size - 1) {
      fprintf(stderr, "%d: parameter '%s' is too long\n", lineno - 1,
              varname);
      return -1;
    }
    ptr = (char*) cfg + params[i].offset;
    strcpy(ptr, varvalue);
  } else if (!strcmp(params[i].type, "x")) {
    char ***ppptr = 0;
    char **pptr = 0;
    int    j;

    ppptr = (char***) ((char*) cfg + params[i].offset);
    if (!*ppptr) {
      *ppptr = (char**) xcalloc(16, sizeof(char*));
      (*ppptr)[15] = (char*) 1;
    }
    pptr = *ppptr;
    for (j = 0; pptr[j]; j++) {
    }
    if (pptr[j + 1] == (char*) 1) {
      int newsize = (j + 2) * 2;
      char **newptr = (char**) xcalloc(newsize, sizeof(char*));
      newptr[newsize - 1] = (char*) 1;
      memcpy(newptr, pptr, j * sizeof(char*));
      xfree(pptr);
      pptr = newptr;
      *ppptr = newptr;
    }
    pptr[j] = xstrdup(varvalue);
    pptr[j + 1] = 0;
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
    fprintf(stderr, "Cannot find description of section [global]\n");
    goto cleanup;
  }
  sinfo = params[sindex].info;

  if (!f && !(f = fopen(path, "r"))) {
    fprintf(stderr, "Cannot open configuration file %s\n", path);
    goto cleanup;
  }

  cfg = (struct generic_section_config*) xcalloc(1, params[sindex].size);
  if (params[sindex].init_func)
    params[sindex].init_func(cfg);
  cfg->next = 0;
  psect = &cfg->next;
  sect = NULL;

  while (1) {
    c = read_first_char(f);
    if (c == EOF || c == '[') break;
    if (c == '#' || c== '%' || c == ';') {
      read_comment(f);
      continue;
    }
    if (read_variable(f, varname, sizeof(varname),
                      varvalue, sizeof(varvalue)) < 0) goto cleanup;
    if (!quiet_flag) {
      printf("%d: Value: %s = %s\n", lineno - 1, varname, varvalue);
    }
    if (copy_param(cfg, sinfo, varname, varvalue) < 0) goto cleanup;
  }

  while (c != EOF) {
    if (read_section_name(f, sectname, sizeof(sectname)) < 0) goto cleanup;
    if (!quiet_flag) {
      printf("%d: New section %s\n", lineno - 1, sectname);
    }
    if (!strcmp(sectname, "global")) {
      fprintf(stderr, "Section global cannot be specified explicitly\n");
      goto cleanup;
    }
    for (sindex = 0; params[sindex].name; sindex++) {
      if (!strcmp(params[sindex].name, sectname)) break;
    }
    if (!params[sindex].name) {
      fprintf(stderr, "Cannot find description of section [%s]\n",
              sectname);
      goto cleanup;
    }
    sinfo = params[sindex].info;
    if (params[sindex].pcounter) (*params[sindex].pcounter)++;

    sect = (struct generic_section_config*) xcalloc(1, params[sindex].size);
    strcpy(sect->name, sectname);
    if (params[sindex].init_func)
      params[sindex].init_func(sect);
    sect->next = 0;
    *psect = sect;
    psect = &sect->next;

    while (1) {
      c = read_first_char(f);
      if (c == EOF || c == '[') break;
      if (c == '#' || c == '%' || c == ';') {
        read_comment(f);
        continue;
      }
      if (read_variable(f, varname, sizeof(varname),
                        varvalue, sizeof(varvalue)) < 0) goto cleanup;
      if (!quiet_flag) {
        printf("%d: Value: %s = %s\n", lineno - 1, varname, varvalue);
      }
      if (copy_param(sect, sinfo, varname, varvalue) < 0) goto cleanup;
    }
  }

  fflush(stdout);

  if (f) fclose(f);
  return cfg;

 cleanup:
  xfree(cfg);
  if (vf && f) fclose(f);
  return NULL;
}

struct generic_section_config *
param_make_global_section(struct config_section_info *params)
{
  int sindex;
  struct config_parse_info *sinfo;
  struct generic_section_config *cfg;

  for (sindex = 0; params[sindex].name; sindex++) {
    if (!strcmp(params[sindex].name, "global")) break;
  }
  if (!params[sindex].name) {
    fprintf(stderr, "Cannot find description of section [global]\n");
    return 0;
  }
  sinfo = params[sindex].info;

  cfg = (struct generic_section_config*) xcalloc(1, params[sindex].size);
  if (params[sindex].init_func) params[sindex].init_func(cfg);
  return cfg;
}


int sarray_len(char **a)
{
  int i;

  if (!a) return 0;
  for (i = 0; a[i]; i++);
  return i;
}

char **sarray_free(char **a)
{
  int i;

  if (!a) return 0;
  for (i = 0; a[i]; i++) xfree(a[i]);
  xfree(a);
  return 0;
}

char **sarray_merge_pf(char **a1, char **a2)
{
  int newlen = 0;
  char **pptr = 0;
  int i, j = 0;

  if (!a1 || !a1[0]) return a2;
  newlen = sarray_len(a1) + sarray_len(a2);
  pptr = (char**) xcalloc(newlen + 2, sizeof(char*));
  pptr[newlen + 1] = (char*) 1;
  if (a1) {
    for (i = 0; a1[i]; i++) {
      // FIXME: should we share strings???
      pptr[j++] = xstrdup(a1[i]);
    }
  }
  if (a2) {
    for (i = 0; a2[i]; i++) {
      pptr[j++] = a2[i];
    }
  }
  xfree(a2);
  return pptr;
}

char **sarray_merge_arr(int n, char ***pa)
{
  int newlen = 0, i, j, k;
  char **pptr;

  if (!n || !pa) return 0;
  for (i = 0; i < n; i++)
    newlen += sarray_len(pa[i]);
  if (!newlen) return 0;
  pptr = (char**) xcalloc(newlen + 2, sizeof(char*));
  pptr[newlen + 1] = (char*) 1;
  k = 0;
  for (i = 0; i < n; i++) {
    if (!pa[i]) continue;
    for (j = 0; pa[i][j]; j++) {
      pptr[k++] = xstrdup(pa[i][j]);
    }
  }
  return pptr;
}
