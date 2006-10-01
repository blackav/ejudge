/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "testinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

struct line_buf
{
  size_t a, u;
  unsigned char *v;
};

struct cmdline_buf
{
  size_t a, u;
  unsigned char **v;
};

static int
read_line(FILE *fin, struct line_buf *pbuf)
{
  unsigned char *old_v;
  int c;

  if (!pbuf->a || !pbuf->v) {
    pbuf->a = 512;
    if (!(pbuf->v = (unsigned char*) malloc(pbuf->a))) goto failure;
  }
  pbuf->u = 0;
  pbuf->v[0] = 0;

  while (1) {
    c = getc(fin);
    if (c == EOF) break;
    if (pbuf->u + 1 >= pbuf->a) {
      pbuf->a *= 2;
      old_v = pbuf->v;
      if (!(pbuf->v = (unsigned char*) realloc(pbuf->v, pbuf->a))) {
        pbuf->v = old_v;
        goto failure;
      }
    }
    pbuf->v[pbuf->u++] = c;
    if (c == '\n') break;
  }

  if (!pbuf->u) {
    if (ferror(fin)) return -TINF_E_IO_ERROR;
    return -TINF_E_EOF;
  }
  pbuf->v[pbuf->u] = 0;
  while (pbuf->u > 0 && isspace(pbuf->v[pbuf->u - 1]))
    pbuf->v[--pbuf->u] = 0;
  return pbuf->u;

 failure:
  if (pbuf->v) free(pbuf->v);
  memset(pbuf, 0, sizeof(*pbuf));
  return -TINF_E_NO_MEMORY;
}

static int
parse_cmdline(const unsigned char *str, struct cmdline_buf *pcmd)
{
  unsigned char *locbuf, *q, *qq, **old_v;
  const unsigned char *p = str;
  unsigned char nb[4];
  int q_char = 0;
  int code, i;

  memset(pcmd, 0, sizeof(*pcmd));
  pcmd->a = 16;
  if (!(pcmd->v = (unsigned char**) malloc(pcmd->a * sizeof(pcmd->v[0])))) {
    code = -TINF_E_NO_MEMORY;
    goto failure;
  }
  pcmd->u = 0;
  pcmd->v[0] = 0;
  if (!(q = locbuf = (unsigned char*) alloca(strlen(str) + 16))) {
    code = -TINF_E_NO_MEMORY;
    goto failure;
  }
  while (isspace(*p)) p++;
  if (*p && *p != '#') {
    while (1) {
      if (!*p || (*p == '#' && !q_char)) {
        if (q_char) {
          code = -TINF_E_UNCLOSED_QUOTE;
          goto failure;
        }
        *q = 0;
        if (pcmd->u + 1 >= pcmd->a) {
          pcmd->a *= 2;
          old_v = pcmd->v;
          pcmd->v=(unsigned char**)realloc(pcmd->v,pcmd->a*sizeof(pcmd->v[0]));
          if (!pcmd->v) {
            pcmd->v = old_v;
            code = -TINF_E_NO_MEMORY;
            goto failure;
          }
        }
        if (!(qq = strdup(locbuf))) {
          code = -TINF_E_NO_MEMORY;
          goto failure;
        }
        pcmd->v[pcmd->u++] = qq;
        pcmd->v[pcmd->u] = 0;
        break;
      } else if (*p == '\"') {
        if (!q_char) {
          q_char = *p++;
        } else if (q_char == '\"') {
          q_char = 0;
          p++;
        } else {
          *q++ = *p++;
        }
      } else if (*p == '\'') {
        if (!q_char) {
          q_char = *p++;
        } else if (q_char == '\'') {
          q_char = 0;
          p++;
        } else {
          *q++ = *p++;
        }
      } else if (*p == '\\') {
        if (q_char == '\'') {
          *q++ = *p++;
        } else {
          switch (p[1]) {
          case 0:
            *q++ = '\\';
            p++;
            break;
          case 'x': case 'X':
            if (!isxdigit(p[2])) {
              code = -TINF_E_INVALID_ESCAPE;
              goto failure;
              p++;
              break;
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
        }
      } else if (isspace(*p)) {
        if (q_char) {
          *q++ = *p++;
        } else {
          *q = 0;
          if (pcmd->u + 1 >= pcmd->a) {
            pcmd->a *= 2;
            old_v = pcmd->v;
            pcmd->v=(unsigned char**)realloc(pcmd->v,
                                             pcmd->a*sizeof(pcmd->v[0]));
            if (!pcmd->v) {
              pcmd->v = old_v;
              code = -TINF_E_NO_MEMORY;
              goto failure;
            }
          }
          if (!(qq = strdup(locbuf))) {
            code = -TINF_E_NO_MEMORY;
            goto failure;
          }
          pcmd->v[pcmd->u++] = qq;
          pcmd->v[pcmd->u] = 0;
          while (isspace(*p)) p++;
          if (!*p) break;
          q = locbuf;
        }
      } else if (*p < ' ') {
        code = -TINF_E_STRAY_CONTROL_CHAR;
        goto failure;
        *q++ = ' ';
      } else {
        *q++ = *p++;
      }
    }
  }
  return 0;

 failure:
  if (pcmd->v) {
    for (i = 0; i < pcmd->u; i++)
      if (pcmd->v[i]) free(pcmd->v[i]);
    free(pcmd->v);
  }
  memset(pcmd, 0, sizeof(*pcmd));
  return code;
}

static void
free_cmdline(struct cmdline_buf *pcmd)
{
  int i;

  if (pcmd->v) {
    for (i = 0; i < pcmd->u; i++)
      if (pcmd->v[i]) free(pcmd->v[i]);
    free(pcmd->v);
  }
  memset(pcmd, 0, sizeof(*pcmd));
}

static inline int
is_ident_char(int c)
{
  return isalnum(c) || c == '_';
}

#define FAIL(code) do { retval = -code; goto fail; } while (0)

static int
parse_line(const unsigned char *str, size_t len, testinfo_t *pt)
{
  const unsigned char *s = str;
  unsigned char *name_buf = 0, *p;
  unsigned char *val_buf = 0;
  unsigned char **ppval;
  size_t len2;
  struct cmdline_buf cmd;
  int retval = 0, x, n;

  memset(&cmd, 0, sizeof(cmd));
  if (!(name_buf = (unsigned char *) alloca(len + 1))) FAIL(TINF_E_NO_MEMORY);
  if (!(val_buf = (unsigned char *) alloca(len + 2))) FAIL(TINF_E_NO_MEMORY);

  while (isspace(*s)) s++;
  p = name_buf;
  if (!is_ident_char(*s)) FAIL(TINF_E_IDENT_EXPECTED);
  while (is_ident_char(*s)) *p++ = *s++;
  *p = 0;
  while (isspace(*s)) s++;
  if (!*s) {
    /* implicit "1" */
    strcpy(val_buf, "1");
  } else if (*s != '=') {
    FAIL(TINF_E_EQUAL_EXPECTED);
  } else {
    s++;
    while (isspace(*s)) s++;
    strcpy(val_buf, s);
    len2 = strlen(val_buf);
    while (len2 > 0 && isspace(val_buf[len2 - 1])) len2--;
  }
  if ((retval = parse_cmdline(val_buf, &cmd)) < 0) {
    free_cmdline(&cmd);
    return retval;
  }

  if (!strcmp(name_buf, "params")) {
    if (pt->cmd_argc >= 0) FAIL(TINF_E_VAR_REDEFINED);
    pt->cmd_argc = cmd.u;
    pt->cmd_argv = cmd.v;
    memset(&cmd, 0, sizeof(cmd));
  } else if (!strcmp(name_buf, "comment")
             || !strcmp(name_buf, "team_comment")) {
    if (!strcmp(name_buf, "comment")) {
      ppval = &pt->comment;
    } else {
      ppval = &pt->team_comment;
    }
    if (*ppval) FAIL(TINF_E_VAR_REDEFINED);
    if (cmd.u < 1) FAIL(TINF_E_EMPTY_VALUE);
    if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
    *ppval = cmd.v[0];
    cmd.v[0] = 0;
  } else if (!strcmp(name_buf, "exit_code")) {
    if (cmd.u < 1) FAIL(TINF_E_EMPTY_VALUE);
    if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
    if (sscanf(cmd.v[0], "%d%n", &x, &n) != 1 || cmd.v[0][n]
        || x < 0 || x > 127)
      FAIL(TINF_E_INVALID_VALUE);
    pt->exit_code = x;
  } else if (!strcmp(name_buf, "check_stderr")) {
    if (cmd.u < 1) {
      x = 1;
    } else {
      if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
      if (sscanf(cmd.v[0], "%d%n", &x, &n) != 1 || cmd.v[0][n]
          || x < 0 || x > 1)
        FAIL(TINF_E_INVALID_VALUE);
    }
    pt->check_stderr = x;
  } else {
    FAIL(TINF_E_INVALID_VAR_NAME);
  }
  free_cmdline(&cmd);
  return 0;

 fail:
  free_cmdline(&cmd);
  return retval;
}

static int
parse_file(FILE *fin, testinfo_t *pt)
{
  struct line_buf buf;
  int retval;

  memset(&buf, 0, sizeof(buf));
  while (read_line(fin, &buf) >= 0) {
    /*
    if ((t = strchr(buf.v, '#'))) {
      *t = 0;
      buf.u = t - buf.v;
    }
    */
    while (buf.u > 0 && isspace(buf.v[buf.u - 1]))
      buf.v[--buf.u] = 0;
    if (!buf.u) continue;

    if ((retval = parse_line(buf.v, buf.u, pt))) {
      if (buf.v) free(buf.v);
      return retval;
    }
  }
  if (buf.v) free(buf.v);
  return 0;
}

int
testinfo_parse(const unsigned char *path, testinfo_t *pt)
{
  FILE *fin = 0;
  int retval;

  memset(pt, 0, sizeof(*pt));
  pt->cmd_argc = -1;
  if (!(fin = fopen(path, "r"))) {
    memset(pt, 0, sizeof(*pt));
    return -TINF_E_CANNOT_OPEN;
  }
  if ((retval = parse_file(fin, pt)) < 0) {
    fclose(fin);
    memset(pt, 0, sizeof(*pt));
    return retval;
  }
  fclose(fin);
  return 0;
}

void
testinfo_free(testinfo_t *pt)
{
  int i;

  if (pt->cmd_argc > 0 && pt->cmd_argv) {
    for (i = 0; i < pt->cmd_argc; i++)
      if (pt->cmd_argv[i]) free(pt->cmd_argv[i]);
    free(pt->cmd_argv);
  }
  if (pt->comment) free(pt->comment);
  if (pt->team_comment) free(pt->team_comment);
  memset(pt, 0, sizeof(*pt));
}

static const unsigned char * const error_codes[] =
{
  [TINF_E_OK] "OK - no error",
  [TINF_E_EOF] "EOF",
  [TINF_E_IO_ERROR] "IO error",
  [TINF_E_NO_MEMORY] "memory exhausted",
  [TINF_E_UNCLOSED_QUOTE] "unclosed quote",
  [TINF_E_STRAY_CONTROL_CHAR] "stray control character",
  [TINF_E_INVALID_ESCAPE] "invalid escape sequence",
  [TINF_E_IDENT_EXPECTED] "variable name expected",
  [TINF_E_EQUAL_EXPECTED] "'=' expected",
  [TINF_E_CANNOT_OPEN] "cannot open input file",
  [TINF_E_INVALID_VAR_NAME] "invalid variable name",
  [TINF_E_VAR_REDEFINED] "variable is redefined",
  [TINF_E_EMPTY_VALUE] "variable value is empty",
  [TINF_E_MULTIPLE_VALUE] "variable value is multiple",
  [TINF_E_INVALID_VALUE] = "variable value is invalid",
};
const unsigned char *
testinfo_strerror(int err)
{
  if (err < 0) err = -err;
  if (err >= TINF_E_LAST || !error_codes[err]) {
    /* note, that heap memory almost surely will be leaked in this
     * case, however, if the error code is invalid, the program
     * is already working not as expected
     */
    unsigned char *str = (unsigned char*) malloc(128);
    if (!str) {
      return "Unknown testinfo error code, and malloc failed";
    } else {
      snprintf(str, 128, "Unknown testinfo error code %d", err);
      return str;
    }
  }
  return error_codes[err];
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
