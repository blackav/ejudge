/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2005 Alexander Chernov <cher@ispras.ru> */

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

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

static int lineno = 1;

typedef struct bufstring_struct
{
  size_t a, u;
  unsigned char *s;
} bufstring_t;

static bufstring_t raw;
static int raw_i;
static int ncond_var;
static cfg_cond_var_t *cond_vars;

enum
{
  CV_VOID = PARSECFG_T_VOID,
  CV_LONG = PARSECFG_T_LONG,
  CV_STRING = PARSECFG_T_STRING,
};

struct cond_stack
{
  struct cond_stack *next;
  int was_true;
  int was_else;
  int output_enabled;
};
static struct cond_stack *cond_stack;
static int output_enabled = 1;

static int
convert_to_bool(cfg_cond_value_t *pv)
{
  switch (pv->tag) {
  case CV_LONG:
    return !!pv->l.val;
  case CV_STRING:
    return !!pv->s.str[0];
  }
  abort();
}
static void
set_bool_value(cfg_cond_value_t *pv, int val)
{
  XMEMZERO(pv, 1);
  pv->tag = CV_LONG;
  pv->l.val = !!val;
}
static void
free_value(cfg_cond_value_t *pv)
{
  if (pv->tag == CV_STRING)
    xfree(pv->s.str);
  pv->s.str = 0;
}
static void
copy_value(cfg_cond_value_t *pdst, cfg_cond_value_t *psrc)
{
  *pdst = *psrc;
  if (pdst->tag == CV_STRING) pdst->s.str = xstrdup(pdst->s.str);
}

#if 0
static void
print_value(cfg_cond_value_t *pv)
{
  if (!pv) {
    fprintf(stderr, "(null)\n");
  } else {
    switch (pv->tag) {
    case CV_VOID: fprintf(stderr, "(void)\n"); break;
    case CV_LONG: fprintf(stderr, "%lld\n", pv->l.val); break;
    case CV_STRING: fprintf(stderr, ">%s<\n", pv->s.str); break;
    default:
      abort();
    }
  }
}
#endif

static int parse_conditional_expr(int need_eval, cfg_cond_value_t *pv);
static int parse_logical_OR_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_logical_AND_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_OR_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_XOR_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_AND_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_equality_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_relational_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_shift_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_additive_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_multiplicative_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_unary_expr(int need_eval, cfg_cond_value_t *prv);
static int parse_primary_expr(int need_eval, cfg_cond_value_t *prv);

static int
parse_expr(int need_eval, cfg_cond_value_t *prv)
{
  int b = 0;

  if (parse_conditional_expr(need_eval, prv) < 0) return -1;
  while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
  if (raw.s[raw_i]) {
    fprintf(stderr, "%d: syntax error\n", lineno);
    if (need_eval) free_value(prv);
    return -1;
  }
  if (need_eval) b = convert_to_bool(prv);
  return b;
}

static int
parse_conditional_expr(int need_eval, cfg_cond_value_t *prv)
{
  return parse_logical_OR_expr(need_eval, prv);
}

static int
parse_logical_OR_expr(int need_eval, cfg_cond_value_t *prv)
{
  cfg_cond_value_t v1, v2;
  int b = 0, r;

  if ((r = parse_logical_AND_expr(need_eval, &v1)) < 0) return -1;
  if (need_eval) {
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (raw.s[raw_i] != '|' || raw.s[raw_i + 1] != '|') {
      *prv = v1;
      return r;
    }
    if (convert_to_bool(&v1)) {
      set_bool_value(prv, 1);
      b = 1;
      need_eval = 0;
      free_value(&v1);
    }
  }
  while (1) {
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (raw.s[raw_i] != '|' || raw.s[raw_i + 1] != '|') break;
    raw_i += 2;
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (parse_logical_AND_expr(need_eval, &v2) < 0) return -1;
    if (need_eval && convert_to_bool(&v2)) {
      set_bool_value(prv, 1);
      b = 1;
      need_eval = 0;
      free_value(&v2);
    }
  }
  if (need_eval) {
    set_bool_value(prv, 0);
    b = 0;
  }
  return b;
}

static int
parse_logical_AND_expr(int need_eval, cfg_cond_value_t *prv)
{
  cfg_cond_value_t v1, v2;
  int b = 0, r;

  if ((r = parse_OR_expr(need_eval, &v1)) < 0) return -1;
  if (need_eval) {
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (raw.s[raw_i] != '&' || raw.s[raw_i + 1] != '&') {
      *prv = v1;
      return r;
    }
    if (!convert_to_bool(&v1)) {
      set_bool_value(prv, 0);
      b = 0;
      need_eval = 0;
      free_value(&v1);
    }
  }
  while (1) {
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (raw.s[raw_i] != '&' || raw.s[raw_i + 1] != '&') break;
    raw_i += 2;
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (parse_OR_expr(need_eval, &v2) < 0) return -1;
    if (need_eval && !convert_to_bool(&v2)) {
      set_bool_value(prv, 0);
      b = 0;
      need_eval = 0;
      free_value(&v2);
    }
  }
  if (need_eval) {
    set_bool_value(prv, 1);
    b = 1;
  }
  return b;
}

static int
parse_OR_expr(int need_eval, cfg_cond_value_t *prv)
{
  return parse_XOR_expr(need_eval, prv);
}

static int
parse_XOR_expr(int need_eval, cfg_cond_value_t *prv)
{
  return parse_AND_expr(need_eval, prv);
}

static int
parse_AND_expr(int need_eval, cfg_cond_value_t *prv)
{
  return parse_equality_expr(need_eval, prv);
}

static int
parse_equality_expr(int need_eval, cfg_cond_value_t *prv)
{
  cfg_cond_value_t v1, v2;
  int op;

  if (parse_relational_expr(need_eval, &v1) < 0) return -1;
  if (need_eval) *prv = v1;
  while (1) {
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if ((raw.s[raw_i] != '=' && raw.s[raw_i] != '!')
        || raw.s[raw_i + 1] != '=')
      break;
    if (raw.s[raw_i] == '=') op = 0;
    else op = 1;
    raw_i += 2;
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (parse_relational_expr(need_eval, &v2) < 0) {
      if (need_eval) free_value(prv);
      return -1;
    }
    if (need_eval) {
      if (prv->tag != v2.tag) {
        fprintf(stderr, "%d: type mismatch in expression\n", lineno);
        free_value(prv);
        free_value(&v2);
        return -1;
      }
      XMEMZERO(&v1, 1);
      v1.tag = CV_LONG;
      if (prv->tag == CV_LONG) {
        switch (op) {
        case 0: v1.l.val = (prv->l.val == v2.l.val); break;
        case 1: v1.l.val = (prv->l.val != v2.l.val); break;
        default:
          abort();
        }
      } else if (prv->tag == CV_STRING) {
        switch (op) {
        case 0: v1.l.val = (strcmp(prv->s.str, v2.s.str) == 0); break;
        case 1: v1.l.val = (strcmp(prv->s.str, v2.s.str) != 0); break;
        default:
          abort();
        }
      } else {
        fprintf(stderr, "%d: invalid type in expression\n", lineno);
        free_value(prv);
        free_value(&v2);
        return -1;
      }
      free_value(prv);
      free_value(&v2);
      *prv = v1;
    }
  }
  return 0;
}

static int
parse_relational_expr(int need_eval, cfg_cond_value_t *prv)
{
  cfg_cond_value_t v1, v2;
  int op = -1;

  if (parse_shift_expr(need_eval, &v1) < 0) return -1;
  if (need_eval) *prv = v1;
  while (1) {
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (raw.s[raw_i] == '<' && raw.s[raw_i + 1] == '=') {
      op = 0;
      raw_i += 2;
    } else if (raw.s[raw_i] == '>' && raw.s[raw_i + 1] == '=') {
      op = 1;
      raw_i += 2;
    } else if (raw.s[raw_i] == '<') {
      op = 2;
      raw_i += 1;
    } else if (raw.s[raw_i] == '>') {
      op = 3;
      raw_i += 1;
    } else {
      break;
    }
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (parse_shift_expr(need_eval, &v2) < 0) {
      if (need_eval) free_value(prv);
      return -1;
    }
    if (need_eval) {
      if (prv->tag != v2.tag) {
        fprintf(stderr, "%d: type mismatch in expression\n", lineno);
        free_value(prv);
        free_value(&v2);
        return -1;
      }
      XMEMZERO(&v1, 1);
      v1.tag = CV_LONG;
      if (prv->tag == CV_LONG) {
        switch (op) {
        case 0: v1.l.val = (prv->l.val <= v2.l.val); break;
        case 1: v1.l.val = (prv->l.val >= v2.l.val); break;
        case 2: v1.l.val = (prv->l.val < v2.l.val); break;
        case 3: v1.l.val = (prv->l.val > v2.l.val); break;
        default:
          abort();
        }
      } else if (prv->tag == CV_STRING) {
        switch (op) {
        case 0: v1.l.val = (strcmp(prv->s.str, v2.s.str) <= 0); break;
        case 1: v1.l.val = (strcmp(prv->s.str, v2.s.str) >= 0); break;
        case 2: v1.l.val = (strcmp(prv->s.str, v2.s.str) < 0); break;
        case 3: v1.l.val = (strcmp(prv->s.str, v2.s.str) > 0); break;
        default:
          abort();
        }
      } else {
        fprintf(stderr, "%d: invalid type in expression\n", lineno);
        free_value(prv);
        free_value(&v2);
        return -1;
      }
      free_value(prv);
      free_value(&v2);
      *prv = v1;
    }
  }
  return 0;
}

static int
parse_shift_expr(int need_eval, cfg_cond_value_t *prv)
{
  return parse_additive_expr(need_eval, prv);
}

static int
parse_additive_expr(int need_eval, cfg_cond_value_t *prv)
{
  return parse_multiplicative_expr(need_eval, prv);
}

static int
parse_multiplicative_expr(int need_eval, cfg_cond_value_t *prv)
{
  return parse_unary_expr(need_eval, prv);
}

static int
parse_unary_expr(int need_eval, cfg_cond_value_t *prv)
{
  return parse_primary_expr(need_eval, prv);
}

static int
parse_string(int need_eval, cfg_cond_value_t *prv)
{
  int j;
  unsigned char *p, *q;
  unsigned char nb[16];

  j = raw_i + 1;
  while (raw.s[j] && raw.s[j] != '\"') {
    if (raw.s[j] == '\\' && !raw.s[j + 1]) {
      fprintf(stderr, "%d: '\\' at the end of line\n", lineno);
      return -1;
    }
    if (raw.s[j] == '\\') j += 2;
    else j++;
  }
  if (!raw.s[j]) {
    fprintf(stderr, "%d: unterminated string\n", lineno);
    return -1;
  }
  j++;
  if (!need_eval) {
    raw_i = j++;
    return 0;
  }

  XMEMZERO(prv, 1);
  prv->tag = CV_STRING;
  q = prv->s.str = (unsigned char*) xmalloc(j - raw_i);
  p = raw.s + raw_i + 1;
  while (*p && *p != '\"') {
    if (*p != '\\') {
      *q++ = *p++;
      continue;
    }

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
  }
  *q = 0;
  raw_i = j;
  return 0;
}

static int
parse_number(int need_eval, cfg_cond_value_t *prv)
{
  int j;
  unsigned char *buf;

  j = raw_i;
  while (isdigit(raw.s[j])) j++;
  if (!need_eval) {
    raw_i = j;
    return 0;
  }

  XALLOCAZ(buf, j - raw_i + 2);
  memcpy(buf, raw.s + raw_i, j - raw_i);
  raw_i = j;
  XMEMZERO(prv, 1);
  prv->tag = CV_LONG;
  errno = 0;
  prv->l.val = strtoll(buf, 0, 10);
  if (errno) {
    fprintf(stderr, "%d: value is too large\n", lineno);
    return -1;
  }
  return 0;
}

static int
parse_ident(int need_eval, cfg_cond_value_t *prv)
{
  int j = raw_i, i;
  unsigned char *idbuf = 0;

  while (isalnum(raw.s[j]) || raw.s[j] == '_') j++;
  XALLOCAZ(idbuf, j - raw_i + 2);
  memcpy(idbuf, raw.s + raw_i, j - raw_i);
  raw_i = j;

  if (!need_eval) return 0;
  for (i = 0; i < ncond_var; i++) {
    if (!strcmp(idbuf, cond_vars[i].name)) break;
  }
  if (i >= ncond_var) {
    fprintf(stderr, "%d: variable `%s' does not exist\n", lineno, idbuf);
    return -1;
  }
  copy_value(prv, &cond_vars[i].val);
  return 0;
}

static int
parse_primary_expr(int need_eval, cfg_cond_value_t *prv)
{
  int r;

  while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
  if (raw.s[raw_i] == '(') {
    raw_i++;
    if ((r = parse_conditional_expr(need_eval, prv)) < 0) return -1;
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (raw.s[raw_i] != ')') {
      fprintf(stderr, "%d: ')' expected\n", lineno);
      if (need_eval) free_value(prv);
      return -1;
    }
    raw_i++;
    return r;
  } else if (raw.s[raw_i] == '\"') {
    return parse_string(need_eval, prv);
  } else if (isalpha(raw.s[raw_i]) || raw.s[raw_i] == '_') {
    return parse_ident(need_eval, prv);
  } else if (isdigit(raw.s[raw_i])) {
    return parse_number(need_eval, prv);
  }
  fprintf(stderr, "%d: primary expression expected\n", lineno);
  return -1;
}

static int
handle_conditional(FILE *f)
{
  int c;
  unsigned char *cmd, *p;
  struct cond_stack *new_item = 0;
  cfg_cond_value_t val;

  // initialize the raw buffer
  raw.u = 0;
  if (!raw.a) {
    raw.a = 1024;
    XCALLOC(raw.s, raw.a);
  }
  raw.s[raw.u] = 0;

  // read the line into the buffer
  while ((c = fgetc(f)) != EOF && c != '\n') {
    if (!c) continue;
    if (raw.u >= raw.a) {
      raw.a *= 2;
      XREALLOC(raw.s, raw.a);
    }
    raw.s[raw.u++] = c;
  }
  if (raw.u >= raw.a) {
    raw.a *= 2;
    XREALLOC(raw.s, raw.a);
  }
  raw.s[raw.u] = 0;

  while (raw.u > 0 && isspace(raw.s[raw.u - 1])) raw.s[--raw.u] = 0;
  raw_i = 0;
  while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;

  //fprintf(stderr, ">>%s\n", raw.s + raw_i);
  if (raw.s[raw_i] != '@') {
    fprintf(stderr, "%d: invalid conditional directive\n", lineno);
    goto failure;
  }
  raw_i++;
  while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;

  XALLOCA(cmd, raw.u + 1);
  p = cmd;
  while (isalnum(raw.s[raw_i]) || raw.s[raw_i] == '_') *p++ = raw.s[raw_i++];
  *p = 0;

  if (!strcmp(cmd, "if")) {
    XCALLOC(new_item, 1);
    new_item->next = cond_stack;
    cond_stack = new_item;
    if (parse_expr(1, &val) < 0) goto failure;
    //print_value(&val);
    if (!output_enabled) {
      cond_stack->was_true = 1;
      output_enabled = cond_stack->output_enabled = 0;
    } else if (convert_to_bool(&val)) {
      cond_stack->was_true = 1;
      output_enabled = cond_stack->output_enabled = 1;
    } else {
      output_enabled = cond_stack->output_enabled = 0;
    }
    free_value(&val);
  } else if (!strcmp(cmd, "elif")) {
    if (!cond_stack) {
      fprintf(stderr, "%d: dangling elif\n", lineno);
      goto failure;
    }
    if (cond_stack->was_else) {
      fprintf(stderr, "%d: elif after else\n", lineno);
      goto failure;
    }
    if (parse_expr(1, &val) < 0) goto failure;
    if (!cond_stack->was_true && convert_to_bool(&val)) {
      cond_stack->was_true = 1;
      output_enabled = cond_stack->output_enabled = 1;
    } else {
      output_enabled = cond_stack->output_enabled = 0;
    }
    free_value(&val);
  } else if (!strcmp(cmd, "else")) {
    if (!cond_stack) {
      fprintf(stderr, "%d: dangling else\n", lineno);
      goto failure;
    }
    if (cond_stack->was_else) {
      fprintf(stderr, "%d: else after else\n", lineno);
      goto failure;
    }
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (raw.s[raw_i]) {
      fprintf(stderr, "%d: garbage after else\n", lineno);
      goto failure;
    }
    cond_stack->was_else = 1;
    if (!cond_stack->was_true) {
      cond_stack->was_true = 1;
      output_enabled = cond_stack->output_enabled = 1;
    } else {
      output_enabled = cond_stack->output_enabled = 0;
    }
  } else if (!strcmp(cmd, "endif")) {
    if (!cond_stack) {
      fprintf(stderr, "%d: dangling endif\n", lineno);
      goto failure;
    }
    while (raw.s[raw_i] > 0 && raw.s[raw_i] <= ' ') raw_i++;
    if (raw.s[raw_i]) {
      fprintf(stderr, "%d: garbage after endif\n", lineno);
      goto failure;
    }
    new_item = cond_stack;
    cond_stack = cond_stack->next;
    if (!cond_stack) output_enabled = 1;
    else output_enabled = cond_stack->output_enabled;
    xfree(new_item);
  } else {
    fprintf(stderr, "%d: invalid conditional compilation directive\n", lineno);
    goto failure;
  }

  lineno++;
  return 0;

 failure:
  lineno++;
  return -1;
}

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
    if (quot_char == '\'') {
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

  if (!strcmp(params[i].type, "z")) {
    int n, m;
    size_t v, *ptr;

    if (sscanf(varvalue, "%zu%n", &v, &n) != 1
        || !(m = num_suffix(varvalue + n))) {
      fprintf(stderr, "%d: size parameter expected for '%s'\n",
              lineno - 1, varname);
      return -1;
    }
    // FIXME: check for overflow 
    v *= m;
    ptr = (size_t*) ((char*) cfg + params[i].offset);
    *ptr = v;
  } else if (!strcmp(params[i].type, "d")) {
    int  n, v, m;
    int *ptr;

    if (sscanf(varvalue, "%d%n", &v, &n) != 1
        || !(m = num_suffix(varvalue + n))) {
      fprintf(stderr, "%d: numeric parameter expected for '%s'\n",
              lineno - 1, varname);
      return -1;
    }
    // FIXME: check for overflow 
    v *= m;
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
            FILE *f,
            struct config_section_info *params,
            int quiet_flag,
            int _ncond_var,
            cfg_cond_var_t *_cond_vars,
            int *p_cond_count)
{
  struct generic_section_config  *cfg = NULL;
  struct generic_section_config **psect, *sect;
  struct config_parse_info       *sinfo;

  char           sectname[32];
  char           varname[32];
  char           varvalue[1024];
  int            c, sindex;

  ncond_var = _ncond_var;
  cond_vars = _cond_vars;
  cond_stack = 0;
  output_enabled = 1;
  if (p_cond_count) *p_cond_count = 0;

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
    if (c == '@') {
      if (handle_conditional(f) < 0) goto cleanup;
      if (p_cond_count) (*p_cond_count)++;
      continue;
    }
    if (!output_enabled) {
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
      if (c == '@') {
        if (handle_conditional(f) < 0) goto cleanup;
        if (p_cond_count) (*p_cond_count)++;
        continue;
      }
      if (!output_enabled) {
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

  if (cond_stack) {
    fprintf(stderr, "%d: unclosed conditional compilation\n", lineno);
    goto cleanup;
  }

  fflush(stdout);

  if (f) fclose(f);
  return cfg;

 cleanup:
  xfree(cfg);
  if (f) fclose(f);
  return NULL;
}

struct generic_section_config *
param_make_global_section(struct config_section_info *params)
{
  int sindex;
  struct config_parse_info *sinfo;
  struct generic_section_config *cfg;

  ncond_var = 0;
  cond_vars = 0;
  output_enabled = 1;

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

struct generic_section_config *
param_free(struct generic_section_config *cfg,
           const struct config_section_info *params)
{
  struct generic_section_config *p, *q;
  int i;
  unsigned char *name;

  for (p = cfg; p; p = q) {
    q = p->next;

    name = p->name;
    if (!name[0]) name = "global";
    for (i = 0; params[i].name; i++)
      if (!strcmp(name, params[i].name))
        break;
    ASSERT(params[i].name);

    if (params[i].free_func) (*params[i].free_func)(p);
    else {
      memset(p, 0, params[i].size);
      xfree(p);
    }
  }

  return 0;
}

struct generic_section_config *
param_alloc_section(const unsigned char *name,
                    const struct config_section_info *params)
{
  int i;
  struct generic_section_config *p;

  for (i = 0; params[i].name; i++)
    if (!strcmp(name, params[i].name))
      break;
  ASSERT(params[i].name);

  p = (typeof(p)) xcalloc(1, params[i].size);
  snprintf(p->name, sizeof(p->name), "%s", name);
  return p;
}

struct generic_section_config *
param_merge(struct generic_section_config *s1,
            struct generic_section_config *s2)
{
  struct generic_section_config **ps = &s1;

  for (; *ps; ps = &(*ps)->next);
  *ps = s2;
  return s1;
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

char *
sarray_unparse(char **a)
{
  char *out_txt = 0;
  unsigned char *s, *q;
  size_t out_len = 0;
  FILE *out;
  int i;

  out = open_memstream(&out_txt, &out_len);
  if (a) {
    for (i = 0; a[i]; i++) {
      // VAR[=[value]]
      if (i > 0) fprintf(out, " ");
      s = a[i];
      while (*s && (isalnum(*s) || *s == '_')) s++;
      if (*s && *s != '=') {
        // invalid variable name
        fprintf(out, "invalid_variable_name=");
        s = a[i];
      } else if (*s == '=' && (char*) s == a[i]) {
        fprintf(out, "empty_variable_name=");
        s++;
      } else {
        s = a[i];
        while (*s && *s != '=') putc_unlocked(*s++, out);
        if (*s == '=') putc_unlocked(*s++, out);
      }
      q = s;
      while (*q && *q > ' ' && *q < 127 && *q != '\"' && *q != '\\') q++;
      if (*q) {
        putc_unlocked('\"', out);
        for (; *s; s++) {
          if (*s < ' ') {
            fprintf(out, "\\%03o", *s);
          } else if (*s == '\"') {
            fputs("\\\"", out);
          } else if (*s == '\\') {
            fputs("\\\\", out);
          } else {
            putc_unlocked(*s, out);
          }
        }
        putc_unlocked('\"', out);
      } else {
        while (*s) putc_unlocked(*s++, out);
      }
    }
  }
  fclose(out);
  return out_txt;
}

char *
sarray_unparse_2(char **a)
{
  char *out_txt = 0;
  unsigned char *s, *q;
  size_t out_len = 0;
  FILE *out;
  int i;

  out = open_memstream(&out_txt, &out_len);
  if (a) {
    for (i = 0; a[i]; i++) {
      // VAR[=[value]]
      if (i > 0) fprintf(out, " ");
      s = a[i];
      q = s;
      while (*q && *q > ' ' && *q < 127 && *q != '\"' && *q != '\\') q++;
      if (*q) {
        putc_unlocked('\"', out);
        for (; *s; s++) {
          if (*s < ' ') {
            fprintf(out, "\\%03o", *s);
          } else if (*s == '\"') {
            fputs("\\\"", out);
          } else if (*s == '\\') {
            fputs("\\\\", out);
          } else {
            putc_unlocked(*s, out);
          }
        }
        putc_unlocked('\"', out);
      } else {
        while (*s) putc_unlocked(*s++, out);
      }
    }
  }
  fclose(out);
  return out_txt;
}

int
sarray_parse(const unsigned char *str, char ***p_a)
{
  char **a = 0;
  int nvars = 0, i;
  const unsigned char *s = str;
  unsigned char *q;
  size_t str_len;
  unsigned char nb[8];

  if (!str) {
    *p_a = 0;
    return 0;
  }

  str_len = strlen(str);
  // check syntax and count variables
  while (*s) {
    while (*s && isspace(*s)) s++;
    if (!*s) break;
    if (!isalnum(*s) && *s != '_') return -1;
    nvars++;
    while (*s && (isalnum(*s) || *s == '_')) s++;
    if (!*s) break;
    if (isspace(*s)) continue;
    if (*s != '=') return -1;
    s++;
    if (*s == '\"') {
      s++;
      while (*s && *s != '\"') {
        if (*s == '\\') {
          if (!s[1]) return -1;
          s += 2;
        } else {
          s++;
        }
      }
      if (!*s) return -1;
      s++;
      if (*s && !isspace(*s)) return -1;
    } else {
      while (*s && !isspace(*s) && *s != '\"' && *s != '\\') s++;
      if (*s == '\\' || *s == '\"') return -1;
    }
  }

  if (!nvars) {
    *p_a = 0;
    return 0;
  }
  XCALLOC(a, nvars + 1);
  for (i = 0; i < nvars; i++) {
    a[i] = (char*) malloc(str_len + 1);
    a[i][0] = 0;
  }

  // parse the string
  s = str; i = -1; q = 0;
  while (*s) {
    i++;
    if (q) *q = 0;
    q = a[i];

    while (*s && isspace(*s)) s++;
    if (!*s) break;
    while (*s && (isalnum(*s) || *s == '_')) *q++ = *s++;
    if (!*s) break;
    if (isspace(*s)) continue;
    *q++ = *s++;
    if (!*s) break;
    if (isspace(*s)) continue;
    if (*s == '\"') {
      s++;
      while (*s != '\"') {
        if (*s == '\\') {
          switch (s[1]) {
          case 0:
            *q++ = '\\';
            s++;
            break;
          case 'x': case 'X':
            if (!isxdigit(s[2])) {
              *q++ = s[1];
              s += 2;
              break;
            }
            s += 2;
            memset(nb, 0, sizeof(nb));
            nb[0] = *s++;
            if (isxdigit(*s)) nb[1] = *s++;
            *q++ = strtol(nb, 0, 16);
            break;
          case '0': case '1': case '2': case '3':
            s++;
            memset(nb, 0, sizeof(nb));
            nb[0] = *s++;
            if (*s >= '0' && *s <= '7') nb[1] = *s++;
            if (*s >= '0' && *s <= '7') nb[2] = *s++;
            *q++ = strtol(nb, 0, 8);
            break;
          case '4': case '5': case '6': case '7':
            s++;
            memset(nb, 0, sizeof(nb));
            nb[0] = *s++;
            if (*s >= '0' && *s <= '7') nb[1] = *s++;
            *q++ = strtol(nb, 0, 8);
            break;
          case 'a': *q++ = '\a'; s += 2; break;
          case 'b': *q++ = '\b'; s += 2; break;
          case 'f': *q++ = '\f'; s += 2; break;
          case 'n': *q++ = '\n'; s += 2; break;
          case 'r': *q++ = '\r'; s += 2; break;
          case 't': *q++ = '\t'; s += 2; break;
          case 'v': *q++ = '\v'; s += 2; break;
          default:
            s++;
            *q++ = *s++;
            break;
          }
        } else {
          *q++ = *s++;
        }
      }
      s++;      
    } else {
      while (*s && !isspace(*s)) *q++ = *s++;
    }
  }
  if (q) *q = 0;

  *p_a = a;
  return nvars;
}

int
sarray_parse_2(const unsigned char *str, char ***p_a)
{
  char **a = 0;
  int nvars = 0, i;
  const unsigned char *s = str;
  unsigned char *q;
  size_t str_len;
  unsigned char nb[8];

  if (!str) {
    *p_a = 0;
    return 0;
  }

  str_len = strlen(str);
  // check syntax and count variables
  while (*s) {
    while (*s && isspace(*s)) s++;
    if (!*s) break;
    nvars++;
    if (*s == '\"') {
      s++;
      while (*s && *s != '\"') {
        if (*s == '\\') {
          if (!s[1]) return -1;
          s += 2;
        } else {
          s++;
        }
      }
      if (!*s) return -1;
      s++;
      if (*s && !isspace(*s)) return -1;
    } else {
      while (*s && !isspace(*s) && *s != '\"' && *s != '\\') s++;
      if (*s == '\\' || *s == '\"') return -1;
    }
  }

  if (!nvars) {
    *p_a = 0;
    return 0;
  }
  XCALLOC(a, nvars + 1);
  for (i = 0; i < nvars; i++) {
    a[i] = (char*) malloc(str_len + 1);
    a[i][0] = 0;
  }

  // parse the string
  s = str; i = -1; q = 0;
  while (*s) {
    i++;
    if (q) *q = 0;
    q = a[i];

    while (*s && isspace(*s)) s++;
    if (!*s) break;
    if (*s == '\"') {
      s++;
      while (*s != '\"') {
        if (*s == '\\') {
          switch (s[1]) {
          case 0:
            *q++ = '\\';
            s++;
            break;
          case 'x': case 'X':
            if (!isxdigit(s[2])) {
              *q++ = s[1];
              s += 2;
              break;
            }
            s += 2;
            memset(nb, 0, sizeof(nb));
            nb[0] = *s++;
            if (isxdigit(*s)) nb[1] = *s++;
            *q++ = strtol(nb, 0, 16);
            break;
          case '0': case '1': case '2': case '3':
            s++;
            memset(nb, 0, sizeof(nb));
            nb[0] = *s++;
            if (*s >= '0' && *s <= '7') nb[1] = *s++;
            if (*s >= '0' && *s <= '7') nb[2] = *s++;
            *q++ = strtol(nb, 0, 8);
            break;
          case '4': case '5': case '6': case '7':
            s++;
            memset(nb, 0, sizeof(nb));
            nb[0] = *s++;
            if (*s >= '0' && *s <= '7') nb[1] = *s++;
            *q++ = strtol(nb, 0, 8);
            break;
          case 'a': *q++ = '\a'; s += 2; break;
          case 'b': *q++ = '\b'; s += 2; break;
          case 'f': *q++ = '\f'; s += 2; break;
          case 'n': *q++ = '\n'; s += 2; break;
          case 'r': *q++ = '\r'; s += 2; break;
          case 't': *q++ = '\t'; s += 2; break;
          case 'v': *q++ = '\v'; s += 2; break;
          default:
            s++;
            *q++ = *s++;
            break;
          }
        } else {
          *q++ = *s++;
        }
      }
      s++;      
    } else {
      while (*s && !isspace(*s)) *q++ = *s++;
    }
  }
  if (q) *q = 0;

  *p_a = a;
  return nvars;
}
