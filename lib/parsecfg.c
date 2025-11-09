/* -*- c -*- */

/* Copyright (C) 2000-2025 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/parsecfg.h"
#include "ejudge/charsets.h"
#include "ejudge/xml_utils.h"
#include "ejudge/misctext.h"
#include "ejudge/meta_generic.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/prepare.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

typedef struct bufstring_struct
{
  size_t a, u;
  unsigned char *s;
} bufstring_t;

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

struct parsecfg_file
{
  struct parsecfg_file *next;
  FILE *f;
  unsigned char *path;
  int lineno;
};

struct parsecfg_state
{
  bufstring_t raw;
  int raw_i;
  int ncond_var;
  cfg_cond_var_t *cond_vars;
  struct cond_stack *cond_stack;
  struct parsecfg_file *f_stack;
  int output_enabled;
  int charset_id;
};

static void
sync_problem_dir_from_variants(struct section_problem_data *prob)
{
  if (!prob) return;

  unsigned char *first = NULL;
  if (prob->variant_problem_dirs && prob->variant_problem_dirs[0]) {
    first = prob->variant_problem_dirs[0];
  }

  if (!first) {
    if (prob->problem_dir) {
      xfree(prob->problem_dir);
      prob->problem_dir = NULL;
    }
    return;
  }

  if (prob->problem_dir == first) {
    prob->problem_dir = xstrdup(first);
    return;
  }

  if (prob->problem_dir
      && strcmp((const char*) prob->problem_dir, (const char*) first) == 0) {
    return;
  }

  xfree(prob->problem_dir);
  prob->problem_dir = xstrdup(first);
}

static void
append_problem_dir_entry(struct section_problem_data *prob,
                         const unsigned char *value)
{
  if (!prob || !value) return;

  char **old_entries = (char**) prob->variant_problem_dirs;
  char **new_entries = sarray_append(old_entries, value);
  if (old_entries && old_entries != new_entries) {
    xfree(old_entries);
  }
  prob->variant_problem_dirs = (unsigned char **) new_entries;

  sync_problem_dir_from_variants(prob);
}

static int
ps_getc(struct parsecfg_state *ps)
{
  if (!ps || !ps->f_stack || !ps->f_stack->f) return EOF;
  while (1) {
    int c = getc(ps->f_stack->f);
    if (c != EOF) return c;
    if (!ps->f_stack->next) return c;
    struct parsecfg_file *pf = ps->f_stack;
    ps->f_stack = pf->next;
    fclose(pf->f);
    xfree(pf->path);
    memset(pf, 0, sizeof(*pf));
    xfree(pf);
  }
}

static void
ps_ungetc(int c, struct parsecfg_state *ps)
{
  ungetc(c, ps->f_stack->f);
}

static char *
ps_gets(char *buf, size_t size, struct parsecfg_state *ps)
{
  if (!ps || !ps->f_stack || !ps->f_stack->f) return NULL;
  while (1) {
    char *s = fgets(buf, size, ps->f_stack->f);
    if (s) return s;
    if (!ps->f_stack->next) return s;
    struct parsecfg_file *pf = ps->f_stack;
    ps->f_stack = pf->next;
    fclose(pf->f);
    xfree(pf->path);
    memset(pf, 0, sizeof(*pf));
    xfree(pf);
  }
}

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

static int parse_conditional_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *pv);
static int parse_logical_OR_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_logical_AND_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_OR_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_XOR_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_AND_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_equality_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_relational_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_shift_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_additive_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_multiplicative_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_unary_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);
static int parse_primary_expr(struct parsecfg_state *ps, int need_eval, cfg_cond_value_t *prv);

static int
parse_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  int b = 0;

  if (parse_conditional_expr(ps, need_eval, prv) < 0) return -1;
  while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
  if (ps->raw.s[ps->raw_i]) {
    fprintf(stderr, "%d: syntax error\n", ps->f_stack->lineno);
    if (need_eval) free_value(prv);
    return -1;
  }
  if (need_eval) b = convert_to_bool(prv);
  return b;
}

static int
parse_conditional_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  return parse_logical_OR_expr(ps, need_eval, prv);
}

static int
parse_logical_OR_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  cfg_cond_value_t v1, v2;
  int b = 0, r;

  if ((r = parse_logical_AND_expr(ps, need_eval, &v1)) < 0) return -1;
  if (need_eval) {
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (ps->raw.s[ps->raw_i] != '|' || ps->raw.s[ps->raw_i + 1] != '|') {
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
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (ps->raw.s[ps->raw_i] != '|' || ps->raw.s[ps->raw_i + 1] != '|') break;
    ps->raw_i += 2;
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (parse_logical_AND_expr(ps, need_eval, &v2) < 0) return -1;
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
parse_logical_AND_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  cfg_cond_value_t v1, v2;
  int b = 0, r;

  if ((r = parse_OR_expr(ps, need_eval, &v1)) < 0) return -1;
  if (need_eval) {
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (ps->raw.s[ps->raw_i] != '&' || ps->raw.s[ps->raw_i + 1] != '&') {
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
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (ps->raw.s[ps->raw_i] != '&' || ps->raw.s[ps->raw_i + 1] != '&') break;
    ps->raw_i += 2;
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (parse_OR_expr(ps, need_eval, &v2) < 0) return -1;
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
parse_OR_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  return parse_XOR_expr(ps, need_eval, prv);
}

static int
parse_XOR_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  return parse_AND_expr(ps, need_eval, prv);
}

static int
parse_AND_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  return parse_equality_expr(ps, need_eval, prv);
}

static int
parse_equality_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  cfg_cond_value_t v1, v2;
  int op;

  if (parse_relational_expr(ps, need_eval, &v1) < 0) return -1;
  if (need_eval) *prv = v1;
  while (1) {
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if ((ps->raw.s[ps->raw_i] != '=' && ps->raw.s[ps->raw_i] != '!')
        || ps->raw.s[ps->raw_i + 1] != '=')
      break;
    if (ps->raw.s[ps->raw_i] == '=') op = 0;
    else op = 1;
    ps->raw_i += 2;
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (parse_relational_expr(ps, need_eval, &v2) < 0) {
      if (need_eval) free_value(prv);
      return -1;
    }
    if (need_eval) {
      if (prv->tag != v2.tag) {
        fprintf(stderr, "%d: type mismatch in expression\n", ps->f_stack->lineno);
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
        fprintf(stderr, "%d: invalid type in expression\n", ps->f_stack->lineno);
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
parse_relational_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  cfg_cond_value_t v1, v2;
  int op = -1;

  if (parse_shift_expr(ps, need_eval, &v1) < 0) return -1;
  if (need_eval) *prv = v1;
  while (1) {
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (ps->raw.s[ps->raw_i] == '<' && ps->raw.s[ps->raw_i + 1] == '=') {
      op = 0;
      ps->raw_i += 2;
    } else if (ps->raw.s[ps->raw_i] == '>' && ps->raw.s[ps->raw_i + 1] == '=') {
      op = 1;
      ps->raw_i += 2;
    } else if (ps->raw.s[ps->raw_i] == '<') {
      op = 2;
      ps->raw_i += 1;
    } else if (ps->raw.s[ps->raw_i] == '>') {
      op = 3;
      ps->raw_i += 1;
    } else {
      break;
    }
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (parse_shift_expr(ps, need_eval, &v2) < 0) {
      if (need_eval) free_value(prv);
      return -1;
    }
    if (need_eval) {
      if (prv->tag != v2.tag) {
        fprintf(stderr, "%d: type mismatch in expression\n", ps->f_stack->lineno);
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
        fprintf(stderr, "%d: invalid type in expression\n", ps->f_stack->lineno);
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
parse_shift_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  return parse_additive_expr(ps, need_eval, prv);
}

static int
parse_additive_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  return parse_multiplicative_expr(ps, need_eval, prv);
}

static int
parse_multiplicative_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  return parse_unary_expr(ps, need_eval, prv);
}

static int
parse_unary_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  return parse_primary_expr(ps, need_eval, prv);
}

static int
parse_string(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  int j;
  unsigned char *p, *q;
  unsigned char nb[16];

  j = ps->raw_i + 1;
  while (ps->raw.s[j] && ps->raw.s[j] != '\"') {
    if (ps->raw.s[j] == '\\' && !ps->raw.s[j + 1]) {
      fprintf(stderr, "%d: '\\' at the end of line\n", ps->f_stack->lineno);
      return -1;
    }
    if (ps->raw.s[j] == '\\') j += 2;
    else j++;
  }
  if (!ps->raw.s[j]) {
    fprintf(stderr, "%d: unterminated string\n", ps->f_stack->lineno);
    return -1;
  }
  j++;
  if (!need_eval) {
    ps->raw_i = j++;
    return 0;
  }

  XMEMZERO(prv, 1);
  prv->tag = CV_STRING;
  q = prv->s.str = (unsigned char*) xmalloc(j - ps->raw_i);
  p = ps->raw.s + ps->raw_i + 1;
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
        fprintf(stderr, "%d: invalid escape sequence\n", ps->f_stack->lineno);
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
  ps->raw_i = j;
  return 0;
}

static int
parse_number(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  int j;
  unsigned char *buf;

  j = ps->raw_i;
  while (isdigit(ps->raw.s[j])) j++;
  if (!need_eval) {
    ps->raw_i = j;
    return 0;
  }

  XALLOCAZ(buf, j - ps->raw_i + 2);
  memcpy(buf, ps->raw.s + ps->raw_i, j - ps->raw_i);
  ps->raw_i = j;
  XMEMZERO(prv, 1);
  prv->tag = CV_LONG;
  errno = 0;
  prv->l.val = strtoll(buf, 0, 10);
  if (errno) {
    fprintf(stderr, "%d: value is too large\n", ps->f_stack->lineno);
    return -1;
  }
  return 0;
}

static int
parse_ident(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  int j = ps->raw_i, i;
  unsigned char *idbuf = 0;

  while (isalnum(ps->raw.s[j]) || ps->raw.s[j] == '_') j++;
  XALLOCAZ(idbuf, j - ps->raw_i + 2);
  memcpy(idbuf, ps->raw.s + ps->raw_i, j - ps->raw_i);
  ps->raw_i = j;

  if (!need_eval) return 0;
  for (i = 0; i < ps->ncond_var; i++) {
    if (!strcmp(idbuf, ps->cond_vars[i].name)) break;
  }
  if (i >= ps->ncond_var) {
    fprintf(stderr, "%d: variable `%s' does not exist\n", ps->f_stack->lineno, idbuf);
    return -1;
  }
  copy_value(prv, &ps->cond_vars[i].val);
  return 0;
}

static int
parse_primary_expr(
        struct parsecfg_state *ps,
        int need_eval,
        cfg_cond_value_t *prv)
{
  int r;

  while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
  if (ps->raw.s[ps->raw_i] == '(') {
    ps->raw_i++;
    if ((r = parse_conditional_expr(ps, need_eval, prv)) < 0) return -1;
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (ps->raw.s[ps->raw_i] != ')') {
      fprintf(stderr, "%d: ')' expected\n", ps->f_stack->lineno);
      if (need_eval) free_value(prv);
      return -1;
    }
    ps->raw_i++;
    return r;
  } else if (ps->raw.s[ps->raw_i] == '\"') {
    return parse_string(ps, need_eval, prv);
  } else if (isalpha(ps->raw.s[ps->raw_i]) || ps->raw.s[ps->raw_i] == '_') {
    return parse_ident(ps, need_eval, prv);
  } else if (isdigit(ps->raw.s[ps->raw_i])) {
    return parse_number(ps, need_eval, prv);
  }
  fprintf(stderr, "%d: primary expression expected\n", ps->f_stack->lineno);
  return -1;
}

static int
handle_conditional(struct parsecfg_state *ps)
{
  int c;
  unsigned char *cmd, *p;
  struct cond_stack *new_item = 0;
  cfg_cond_value_t val;

  // initialize the ps->raw buffer
  ps->raw.u = 0;
  if (!ps->raw.a) {
    ps->raw.a = 1024;
    XCALLOC(ps->raw.s, ps->raw.a);
  }
  ps->raw.s[ps->raw.u] = 0;

  // read the line into the buffer
  while ((c = ps_getc(ps)) != EOF && c != '\n') {
    if (!c) continue;
    if (ps->raw.u >= ps->raw.a) {
      ps->raw.a *= 2;
      XREALLOC(ps->raw.s, ps->raw.a);
    }
    ps->raw.s[ps->raw.u++] = c;
  }
  if (ps->raw.u >= ps->raw.a) {
    ps->raw.a *= 2;
    XREALLOC(ps->raw.s, ps->raw.a);
  }
  ps->raw.s[ps->raw.u] = 0;

  while (ps->raw.u > 0 && isspace(ps->raw.s[ps->raw.u - 1])) ps->raw.s[--ps->raw.u] = 0;
  ps->raw_i = 0;
  while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;

  //fprintf(stderr, ">>%s\n", ps->raw.s + ps->raw_i);
  if (ps->raw.s[ps->raw_i] != '@') {
    fprintf(stderr, "%d: invalid conditional directive\n", ps->f_stack->lineno);
    goto failure;
  }
  ps->raw_i++;
  while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;

  XALLOCA(cmd, ps->raw.u + 1);
  p = cmd;
  while (isalnum(ps->raw.s[ps->raw_i]) || ps->raw.s[ps->raw_i] == '_') *p++ = ps->raw.s[ps->raw_i++];
  *p = 0;

  if (!strcmp(cmd, "include")) {
    unsigned char file_path[PATH_MAX];
    while (ps->raw_i < ps->raw.u && isspace(ps->raw.s[ps->raw_i])) ++ps->raw_i;
    if (ps->raw_i == ps->raw.u) {
      fprintf(stderr, "%d: no file specified\n", ps->f_stack->lineno);
      goto failure;
    }
    if (ps->raw.s[ps->raw_i] == '/') {
      // absolute path
      snprintf(file_path, sizeof(file_path), "%s", ps->raw.s + ps->raw_i);
    } else if (!ps->f_stack->path || !*ps->f_stack->path) {
      // relative to the current working dir, that's no good
      snprintf(file_path, sizeof(file_path), "%s", ps->raw.s + ps->raw_i);
    } else {
      unsigned char *rs = strrchr(ps->f_stack->path, '/');
      if (!rs || rs == ps->f_stack->path) {
        // no good
        snprintf(file_path, sizeof(file_path), "%s", ps->raw.s + ps->raw_i);
      } else {
        snprintf(file_path, sizeof(file_path), "%.*s%s", (int) (rs - ps->f_stack->path + 1), ps->f_stack->path, ps->raw.s + ps->raw_i);
      }
    }
    //fprintf(stderr, "include file: %s\n", file_path);
    FILE *inc_f = fopen(file_path, "r");
    if (!inc_f) {
      fprintf(stderr, "%d: cannot open file '%s'\n", ps->f_stack->lineno, file_path);
      goto failure;
    }
    struct parsecfg_file *inc = NULL;
    XCALLOC(inc, 1);
    inc->next = ps->f_stack;
    inc->f = inc_f;
    inc->path = xstrdup(file_path);
    inc->lineno = 0;
    ps->f_stack = inc;
  } else if (!strcmp(cmd, "if")) {
    XCALLOC(new_item, 1);
    new_item->next = ps->cond_stack;
    ps->cond_stack = new_item;
    if (parse_expr(ps, 1, &val) < 0) goto failure;
    //print_value(&val);
    if (!ps->output_enabled) {
      ps->cond_stack->was_true = 1;
      ps->output_enabled = ps->cond_stack->output_enabled = 0;
    } else if (convert_to_bool(&val)) {
      ps->cond_stack->was_true = 1;
      ps->output_enabled = ps->cond_stack->output_enabled = 1;
    } else {
      ps->output_enabled = ps->cond_stack->output_enabled = 0;
    }
    free_value(&val);
  } else if (!strcmp(cmd, "elif")) {
    if (!ps->cond_stack) {
      fprintf(stderr, "%d: dangling elif\n", ps->f_stack->lineno);
      goto failure;
    }
    if (ps->cond_stack->was_else) {
      fprintf(stderr, "%d: elif after else\n", ps->f_stack->lineno);
      goto failure;
    }
    if (parse_expr(ps, 1, &val) < 0) goto failure;
    if (!ps->cond_stack->was_true && convert_to_bool(&val)) {
      ps->cond_stack->was_true = 1;
      ps->output_enabled = ps->cond_stack->output_enabled = 1;
    } else {
      ps->output_enabled = ps->cond_stack->output_enabled = 0;
    }
    free_value(&val);
  } else if (!strcmp(cmd, "else")) {
    if (!ps->cond_stack) {
      fprintf(stderr, "%d: dangling else\n", ps->f_stack->lineno);
      goto failure;
    }
    if (ps->cond_stack->was_else) {
      fprintf(stderr, "%d: else after else\n", ps->f_stack->lineno);
      goto failure;
    }
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (ps->raw.s[ps->raw_i]) {
      fprintf(stderr, "%d: garbage after else\n", ps->f_stack->lineno);
      goto failure;
    }
    ps->cond_stack->was_else = 1;
    if (!ps->cond_stack->was_true) {
      ps->cond_stack->was_true = 1;
      ps->output_enabled = ps->cond_stack->output_enabled = 1;
    } else {
      ps->output_enabled = ps->cond_stack->output_enabled = 0;
    }
  } else if (!strcmp(cmd, "endif")) {
    if (!ps->cond_stack) {
      fprintf(stderr, "%d: dangling endif\n", ps->f_stack->lineno);
      goto failure;
    }
    while (ps->raw.s[ps->raw_i] > 0 && ps->raw.s[ps->raw_i] <= ' ') ps->raw_i++;
    if (ps->raw.s[ps->raw_i]) {
      fprintf(stderr, "%d: garbage after endif\n", ps->f_stack->lineno);
      goto failure;
    }
    new_item = ps->cond_stack;
    ps->cond_stack = ps->cond_stack->next;
    if (!ps->cond_stack) ps->output_enabled = 1;
    else ps->output_enabled = ps->cond_stack->output_enabled;
    xfree(new_item);
  } else {
    fprintf(stderr, "%d: invalid conditional compilation directive\n", ps->f_stack->lineno);
    goto failure;
  }

  ps->f_stack->lineno++;
  return 0;

 failure:
  ps->f_stack->lineno++;
  return -1;
}

static int
read_first_char(struct parsecfg_state *ps)
{
  int c;

  c = ps_getc(ps);
  while (c >= 0 && c <= ' ') {
    if (c == '\n') ps->f_stack->lineno++;
    c = ps_getc(ps);
  }
  if (c != EOF) ps_ungetc(c, ps);
  return c;
}

static int
read_section_name(struct parsecfg_state *ps, char *name, int nlen)
{
  int c, i;

  c = ps_getc(ps);
  while (c >= 0 && c <= ' ') {
    if (c == '\n') ps->f_stack->lineno++;
    c = ps_getc(ps);
  }
  if (c != '[') {
    fprintf(stderr, "%d: [ expected\n", ps->f_stack->lineno);
    return -1;
  }

  c = ps_getc(ps);
  for (i = 0; i < nlen - 1 && (isalnum(c) || c == '_'); i++, c = ps_getc(ps))
    name[i] = c;
  name[i] = 0;
  if (i >= nlen - 1 && (isalnum(c) || c == '_')) {
    fprintf(stderr, "%d: section name is too long\n", ps->f_stack->lineno);
    return -1;
  }
  if (c != ']') {
    fprintf(stderr, "%d: ] expected\n", ps->f_stack->lineno);
    return -1;
  }

  c = ps_getc(ps);
  while (c != EOF && c != '\n') {
    if (c > ' ') {
      fprintf(stderr, "%d: garbage after variable value\n", ps->f_stack->lineno);
      return -1;
    }
    c = ps_getc(ps);
  }
  ps->f_stack->lineno++;
  return 0;
}

static int
read_variable(struct parsecfg_state *ps, char *name, int nlen, char *val, int vlen)
{
  int   c;
  int  i;
  unsigned char *lbuf = 0, *tmp, *p, *q;
  size_t lbuf_size = 0;
  size_t lbuf_used = 0, tmp_len;
  int quot_char = 0;
  unsigned char nb[4];

  c = ps_getc(ps);
  while (c >= 0 && c <= ' ') {
    if (c == '\n') ps->f_stack->lineno++;
    c = ps_getc(ps);
  }
  for (i = 0; i < nlen - 1 && (isalnum(c) || c == '_'); i++, c = ps_getc(ps))
    name[i] = c;
  name[i] = 0;
  if (i >= nlen - 1 && (isalnum(c) || c == '_')) {
    fprintf(stderr, "%d: variable name is too long\n", ps->f_stack->lineno);
    return -1;
  }

  while (c >= 0 && c <= ' ' && c != '\n') c = ps_getc(ps);
  if (c == '\n') {
    // FIXME: may we assumpt, that vlen >= 2?
    strcpy(val, "1");
    ps->f_stack->lineno++;
    return 0;
  }
  if (c != '=') {
    fprintf(stderr, "%d: '=' expected after variable name\n", ps->f_stack->lineno);
    return -1;
  }

  lbuf_size = 128;
  lbuf = alloca(128);
  lbuf_used = 0;
  while (1) {
    c = ps_getc(ps);
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
      fprintf(stderr, "%d: invalid control code %d\n", ps->f_stack->lineno, *p);
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
          fprintf(stderr, "%d: invalid escape sequence\n", ps->f_stack->lineno);
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
    fprintf(stderr, "%d: unclosed quote character <%c>\n", ps->f_stack->lineno, quot_char);
    return -1;
  }
  if (*p && *p != '#' && *p != ';') {
    fprintf(stderr, "%d: garbage after variable value\n", ps->f_stack->lineno);
    return -1;
  }
  *q = 0;
  tmp_len = strlen(tmp);
  if (tmp_len >= vlen) {
    fprintf(stderr, "%d: variable value is too long\n", ps->f_stack->lineno);
    return -1;
  }
  strcpy(val, tmp);
  ps->f_stack->lineno++;
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
      fprintf(stderr, "%d: variable value is too long\n", ps->lineno);
      return -1;
    }
    if (c != '\"') {
      fprintf(stderr, "%d: \" expected\n", ps->lineno);
      return -1;
    }
    c = getc(f);
  } else if (c > ' ') {
    for (i = 0; i < vlen - 1 && c > ' '; i++, c = getc(f))
      val[i] = c;
    val[i] = 0;
    if (i >= vlen - 1 && c > ' ') {
      fprintf(stderr, "%d: variable value is too long\n", ps->lineno);
      return -1;
    }
  }

  while (c != '\n' && c != EOF) {
    if (c > ' ') {
      fprintf(stderr, "%d: garbage after variable value\n", ps->lineno);
      return -1;
    }
    c = getc(f);
  }
  ps->lineno++;
  return 0;
  */
}

/* check for "-*- coding: CHARSET -*-" stuff */
static int
read_first_line(struct parsecfg_state *ps)
{
  unsigned char buf[1024];
  unsigned char buf2[1024];
  unsigned char *p;
  size_t buflen;
  int n;

  if (!ps_gets(buf, sizeof(buf), ps)) return 0;
  if ((buflen = strlen(buf)) == sizeof(buf) - 1) {
    ps->f_stack->lineno++;
    return 0;
  }
  ps->f_stack->lineno++;
  while (buflen > 0 && isspace(buf[buflen - 1])) buflen--;
  buf[buflen] = 0;
  if (buflen <= 3) return 0;
  if (buf[buflen - 3]!='-' || buf[buflen - 2]!='*' || buf[buflen - 1]!='-')
    return 0;
  buflen -= 3;
  while (buflen > 0 && isspace(buf[buflen - 1])) buflen--;
  buf[buflen] = 0;
  if (buflen <= 3) return 0;

  p = buf;
  if (*p == '#' || *p == ';' || *p == '%') p++;
  while (isspace(*p)) p++;
  if (p[0] != '-' || p[1] != '*' || p[2] != '-') return 0;
  p += 3;
  while (isspace(*p)) p++;
  if (sscanf(p, "%s%n", buf2, &n) != 1) return 0;
  if (strcasecmp(buf2, "coding:") != 0) return 0;
  p += n;
  if (sscanf(p, "%s%n", buf2, &n) != 1) return 0;
  p += n;
  if (*p) return 0;

  ps->charset_id = charset_get_id(buf2);
  /*
  fprintf(stderr, "detected charset: %s (%d)\n", buf2,
          ps->charset_id);
  */
  return 0;
}

static int
read_comment(struct parsecfg_state *ps)
{
  int c;

  if (ps->f_stack->lineno == 1) return read_first_line(ps);
  c = ps_getc(ps);
  while (c != EOF && c != '\n') c = ps_getc(ps);
  ps->f_stack->lineno++;
  return 0;
}

static int
copy_param(
        struct parsecfg_state *ps,
        void *cfg,
        const struct config_section_info *sinfo,
        char *varname,
        char *varvalue)
{
  int i;
  size_t param_size = 0;
  const struct config_parse_info *params = sinfo->info;

  if (sinfo->mm) {
    // new metainfo handling code
    int field_id = sinfo->mm->lookup_field(varname);
    if (field_id <= 0) {
      fprintf(stderr, "%d: unknown parameter '%s'\n", ps->f_stack->lineno - 1, varname);
      return -1;
    }
    if (sinfo->mm == &cntsprob_methods && !strcmp(varname, "problem_dir")) {
      struct section_problem_data *prob = (struct section_problem_data *) cfg;
      unsigned char *decoded = NULL;

      if (ps->charset_id > 0) {
        decoded = charset_decode_to_heap(ps->charset_id, varvalue);
      } else {
        decoded = xstrdup(varvalue);
      }
      if (decoded) {
        append_problem_dir_entry(prob, decoded);
        xfree(decoded);
      }
      return 0;
    }

    if (meta_parse_string(stderr, ps->f_stack->lineno - 1, cfg, field_id, sinfo->mm,
                          varname, varvalue, ps->charset_id) < 0) {
      return -1;
    }

    return 0;
  }

  // old config_parse_info manipulation code
  for (i = 0; params[i].name; i++)
    if (!strcmp(params[i].name, varname)) break;
  if (!params[i].name) {
    fprintf(stderr, "%d: unknown parameter '%s'\n", ps->f_stack->lineno - 1, varname);
    return -1;
  }

  if (!strcmp(sinfo->name, "problem") && !strcmp(varname, "problem_dir")) {
    struct section_problem_data *prob = (struct section_problem_data *) cfg;
    unsigned char *decoded = NULL;

    if (ps->charset_id > 0) {
      decoded = charset_decode_to_heap(ps->charset_id, varvalue);
    } else {
      decoded = xstrdup(varvalue);
    }
    if (decoded) {
      append_problem_dir_entry(prob, decoded);
      xfree(decoded);
    }
    return 0;
  }

  if (!strcmp(params[i].type, "f")) {
    void *ptr = (void*) ((char*) cfg + params[i].offset);
    if (params[i].parse_func(varvalue, ptr, params[i].size) < 0) {
      fprintf(stderr, "%d: invalid parameter value for '%s'\n", ps->f_stack->lineno - 1, varname);
      return -1;
    }
  } else if (!strcmp(params[i].type, "t")) {
    time_t v = -1, *ptr;
    if (xml_parse_date(NULL, 0, 0, 0, varvalue, &v) < 0) {
      fprintf(stderr, "%d: date parameter expected for '%s'\n", ps->f_stack->lineno - 1, varname);
      return -1;
    }
    if (v < 0) v = 0;
    ptr = (time_t*) ((char*) cfg + params[i].offset);
    *ptr = v;
  } else if (!strcmp(params[i].type, "E")) {
    ej_size64_t v = 0, *ptr = 0;
    if (size_str_to_size64_t(varvalue, &v) < 0) {
      fprintf(stderr, "%d: invalid value of size64 parameter for '%s'\n", ps->f_stack->lineno - 1, varname);
      return -1;
    }
    ptr = (ej_size64_t *) ((char*) cfg + params[i].offset);
    *ptr = v;
  } else if (!strcmp(params[i].type, "z")) {
    size_t v = 0, *ptr = 0;

    if (size_str_to_size_t(varvalue, &v) < 0) {
      fprintf(stderr, "%d: invalid value of size parameter for '%s'\n", ps->f_stack->lineno - 1, varname);
      return -1;
    }
    ptr = (size_t*) ((char*) cfg + params[i].offset);
    *ptr = v;
  } else if (!strcmp(params[i].type, "d")) {
    int v = 0, *ptr = 0;
    if (size_str_to_num(varvalue, &v) < 0) {
      fprintf(stderr, "%d: invalid value of numeric parameter for '%s'\n", ps->f_stack->lineno - 1, varname);
      return -1;
    }
    ptr = (int *) ((char*) cfg + params[i].offset);
    *ptr = v;
  } else if (params[i].type[0] == 'L') {
    int v = 0;
    if (size_str_to_num(varvalue, &v) < 0) {
      fprintf(stderr, "%d: invalid value of numeric parameter for '%s'\n", ps->f_stack->lineno - 1, varname);
      return -1;
    }
    if (v < 0) v = -1;
    if (v > 0) v = 1;
    signed char *ptr = (signed char *)((char*) cfg + params[i].offset);
    *ptr = v;
  } else if (!strcmp(params[i].type, "s")) {
    char *ptr;

    param_size = params[i].size;
    if (!param_size) param_size = PATH_MAX;
    if (strlen(varvalue) > param_size - 1) {
      fprintf(stderr, "%d: parameter '%s' is too long\n", ps->f_stack->lineno - 1, varname);
      return -1;
    }
    ptr = (char*) cfg + params[i].offset;
    strcpy(ptr, varvalue);
    if (ps->charset_id > 0) {
      charset_decode_buf(ps->charset_id, ptr, param_size);
    }
  } else if (!strcmp(params[i].type, "S")) {
    // string allocated on heap
    char **pptr;

    pptr = (char**) ((char*) cfg + params[i].offset);
    if (ps->charset_id > 0) {
      *pptr = charset_decode_to_heap(ps->charset_id, varvalue);
    } else {
      *pptr = xstrdup(varvalue);
    }
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
    if (ps->charset_id > 0) {
      pptr[j] = charset_decode_to_heap(ps->charset_id, varvalue);
    } else {
      pptr[j] = xstrdup(varvalue);
    }
    pptr[j + 1] = 0;
  }
  return 0;
}

struct generic_section_config *
parse_param(char const *path,
            FILE *f,
            const struct config_section_info *params,
            int quiet_flag,
            int ncond_var,
            cfg_cond_var_t *cond_vars,
            int *p_cond_count)
{
  struct generic_section_config  *cfg = NULL;
  struct generic_section_config **psect = &cfg, *sect = NULL;
  const struct config_section_info *cur_info = NULL;
  struct parsecfg_file *ff = NULL;

  char           sectname[32];
  char           varname[32];
  char           varvalue[1024];
  int            c, sindex;

  struct parsecfg_state cfgstate;
  memset(&cfgstate, 0, sizeof(cfgstate));
  struct parsecfg_state *ps = &cfgstate;

  ps->ncond_var = ncond_var;
  ps->cond_vars = cond_vars;
  ps->cond_stack = 0;
  ps->output_enabled = 1;
  if (p_cond_count) *p_cond_count = 0;

  /*
struct parsecfg_file
{
  struct parsecfg_file *next;
  FILE *f;
  unsigned char *path;
  int lineno;
};
   */

  /* found the global section description */
  for (sindex = 0; params[sindex].name; sindex++) {
    if (!strcmp(params[sindex].name, "global")) {
      cur_info = &params[sindex];
      break;
    }
  }
  /*
  if (!cur_info) {
    fprintf(stderr, "Cannot find description of section [global]\n");
    goto cleanup;
  }
  */

  if (!f && !(f = fopen(path, "r"))) {
    fprintf(stderr, "Cannot open configuration file %s\n", path);
    goto cleanup;
  }

  XCALLOC(ff, 1);
  ps->f_stack = ff;
  ff->lineno = 1;
  ff->path = xstrdup(path);
  ff->f = f;
  ff = NULL;
  f = NULL;

  if (cur_info) {
    cfg = (struct generic_section_config*) xcalloc(1, cur_info->size);
    if (cur_info->init_func) cur_info->init_func(cfg);
    cfg->next = NULL;
    psect = &cfg->next;
  }

  while (1) {
    c = read_first_char(ps);
    if (c == EOF || c == '[') break;
    if (c == '#' || c== '%' || c == ';') {
      read_comment(ps);
      continue;
    }
    if (c == '@') {
      if (handle_conditional(ps) < 0) goto cleanup;
      if (p_cond_count) (*p_cond_count)++;
      continue;
    }
    if (!ps->output_enabled) {
      read_comment(ps);
      continue;
    }
    if (read_variable(ps, varname, sizeof(varname), varvalue, sizeof(varvalue)) < 0) goto cleanup;
    if (!quiet_flag) {
      printf("%d: Value: %s = %s\n", ps->f_stack->lineno - 1, varname, varvalue);
    }
    if (!cur_info) {
      fprintf(stderr, "Cannot find description of section [global]\n");
      goto cleanup;
    }
    if (copy_param(ps, cfg, cur_info, varname, varvalue) < 0) goto cleanup;
  }

  while (c != EOF) {
    if (read_section_name(ps, sectname, sizeof(sectname)) < 0) goto cleanup;
    if (!quiet_flag) {
      printf("%d: New section %s\n", ps->f_stack->lineno - 1, sectname);
    }
    if (!strcmp(sectname, "global")) {
      fprintf(stderr, "Section global cannot be specified explicitly\n");
      goto cleanup;
    }
    for (sindex = 0; params[sindex].name; sindex++) {
      if (!strcmp(params[sindex].name, sectname)) {
        cur_info = &params[sindex];
        break;
      }
    }
    if (!cur_info) {
      fprintf(stderr, "Cannot find description of section [%s]\n", sectname);
      goto cleanup;
    }
    if (cur_info->pcounter) (*cur_info->pcounter)++;

    sect = (struct generic_section_config*) xcalloc(1, cur_info->size);
    strcpy(sect->name, sectname);
    if (cur_info->init_func) cur_info->init_func(sect);
    sect->next = NULL;
    *psect = sect;
    psect = &sect->next;

    while (1) {
      c = read_first_char(ps);
      if (c == EOF || c == '[') break;
      if (c == '#' || c == '%' || c == ';') {
        read_comment(ps);
        continue;
      }
      if (c == '@') {
        if (handle_conditional(ps) < 0) goto cleanup;
        if (p_cond_count) (*p_cond_count)++;
        continue;
      }
      if (!ps->output_enabled) {
        read_comment(ps);
        continue;
      }
      if (read_variable(ps, varname, sizeof(varname), varvalue, sizeof(varvalue)) < 0) goto cleanup;
      if (!quiet_flag) {
        printf("%d: Value: %s = %s\n", ps->f_stack->lineno - 1, varname, varvalue);
      }
      if (copy_param(ps, sect, cur_info, varname, varvalue) < 0) goto cleanup;
    }
  }

  if (ps->cond_stack) {
    fprintf(stderr, "%d: unclosed conditional compilation\n", ps->f_stack->lineno);
    goto cleanup;
  }

  fflush(stdout);

  if (f) fclose(f);
  if (ps && ps->f_stack) {
    if (ps->f_stack) fclose(ps->f_stack->f);
    xfree(ps->f_stack->path);
    xfree(ps->f_stack);
  }
  if (ps) {
    xfree(ps->raw.s);
  }
  return cfg;

 cleanup:
  if (cfg) {
    param_free(cfg, params);
  }
  if (f) fclose(f);
  if (ff) {
    if (ff->f) fclose(ff->f);
    xfree(ff->path);
    xfree(ff);
  }
  if (ps && ps->f_stack) {
    if (ps->f_stack) fclose(ps->f_stack->f);
    xfree(ps->f_stack->path);
    xfree(ps->f_stack);
  }
  if (ps) {
    xfree(ps->raw.s);
  }
  return NULL;
}

struct generic_section_config *
param_make_global_section(struct config_section_info *params)
{
  int sindex;
  struct generic_section_config *cfg;

  for (sindex = 0; params[sindex].name; sindex++) {
    if (!strcmp(params[sindex].name, "global")) break;
  }
  if (!params[sindex].name) {
    fprintf(stderr, "Cannot find description of section [global]\n");
    return 0;
  }
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
    if (params[i].name) {
      if (params[i].free_func) {
        (*params[i].free_func)(p);
      } else {
        memset(p, 0, params[i].size);
        xfree(p);
      }
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

char **
sarray_merge_pp(char **a1, char **a2)
{
  int newlen = 0, i = 0, j;
  char **aa = 0;

  newlen = sarray_len(a1) + sarray_len(a2);
  XCALLOC(aa, newlen + 1);
  if (a1) {
    for (j = 0; a1[j]; ++j)
      aa[i++] = xstrdup(a1[j]);
  }
  if (a2) {
    for (j = 0; a2[j]; ++j)
      aa[i++] = xstrdup(a2[j]);
  }
  return aa;
}

char **
sarray_merge_arr(int n, char ***pa)
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

char **
sarray_append(char **a1, const unsigned char *str)
{
  char **res = 0;
  int len, i;

  if (!str) return a1;
  if (!a1) {
    XCALLOC(res, 2);
    res[0] = xstrdup(str);
    return res;
  }

  len = sarray_len(a1);
  XCALLOC(res, len + 2);
  for (i = 0; i < len; ++i)
    res[i] = a1[i];
  res[i] = xstrdup(str);
  return res;
}

static int
is_prefix(const unsigned char *patt, const unsigned char *str)
{
  const unsigned char *p = patt;
  const unsigned char *s = str;

  while (*p && *p == *s) {
    ++p; ++s;
  }
  if (!*p) return (int) (p - patt);
  return -1;
}

void
param_subst(
        unsigned char *buf,
        size_t size,
        const unsigned char **subst_src,
        const unsigned char **subst_dst)
{
  int i, len;
  unsigned char tmp_buf[4096];

  if (!subst_src || !subst_dst) return;
  for (i = 0; subst_src[i]; ++i) {
    if ((len = is_prefix(subst_src[i], buf)) >= 0) {
      snprintf(tmp_buf, sizeof(tmp_buf), "%s%s", subst_dst[i], buf + len);
      snprintf(buf, size, "%s", tmp_buf);
      return;
    }
  }
}

void
param_subst_2(
        unsigned char **pbuf,
        const unsigned char **subst_src,
        const unsigned char **subst_dst)
{
  int i, len;
  unsigned char tmp_buf[4096];

  if (!*pbuf) return;
  if (!subst_src || !subst_dst) return;

  for (i = 0; subst_src[i]; ++i) {
    if ((len = is_prefix(subst_src[i], *pbuf)) >= 0) {
      snprintf(tmp_buf, sizeof(tmp_buf), "%s%s", subst_dst[i], *pbuf + len);
      xfree(*pbuf);
      *pbuf = xstrdup(*pbuf);
      return;
    }
  }
}

char **
sarray_copy(char **a1)
{
  int newlen = 0, i = 0, j;
  char **aa = 0;

  if (!a1 || !a1[0]) return NULL;

  newlen = sarray_len(a1);
  XCALLOC(aa, newlen + 1);
  if (a1) {
    for (j = 0; a1[j]; ++j)
      aa[i++] = xstrdup(a1[j]);
  }
  return aa;
}

int
sarray_cmp(char **a1, char **a2)
{
  if (!a1 && !a2) return 0;
  if (!a1) return -1;
  if (!a2) return 1;
  int i = 0;
  while (1) {
    if (!a1[i] && !a2[i]) return 0;
    if (!a1[i]) return -1;
    if (!a2[i]) return 1;
    int r = strcmp(a1[i], a2[i]);
    if (r != 0) return r;
  }
  return 0;
}
