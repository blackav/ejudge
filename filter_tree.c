/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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

#include "filter_tree.h"
#include "filter_expr.h"

#include <reuse/MemPage.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <errno.h>
#include <limits.h>

struct filter_tree_mem
{
  tPageDesc *pages;
};

struct filter_tree_mem *
filter_tree_new(void)
{
  struct filter_tree_mem *mem = 0;

  XCALLOC(mem, 1);
  mem->pages = pgCreate(32768);
  return mem;
}

struct filter_tree_mem *
filter_tree_delete(struct filter_tree_mem *mem)
{
  ASSERT(mem);

  pgDestroy(mem->pages);
  mem->pages = 0;
  xfree(mem);
  return 0;
}

void
filter_tree_stats(struct filter_tree_mem *mem, FILE *out)
{
  ASSERT(mem);

  pgPageStatistics(mem->pages, out);

}

static struct filter_tree *
getnode(struct filter_tree_mem *mem)
{
  struct filter_tree *node;
  node = (struct filter_tree*) pgCalloc(mem->pages, 1, sizeof(*node));
  return node;
}

struct filter_tree *
filter_tree_new_node(struct filter_tree_mem *mem,
                     int kind, int type,
                     struct filter_tree *left, struct filter_tree *right)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = kind;
  p->type = type;
  p->v.t[0] = left;
  p->v.t[1] = right;
  return p;
}

struct filter_tree *
filter_tree_new_buf(struct filter_tree_mem *mem,
                    unsigned char const *buf, size_t len)
{
  struct filter_tree *p;
  unsigned char *s;

  ASSERT(mem);
  p = getnode(mem);
  s = (unsigned char*) pgCalloc(mem->pages, 1, len + 1);
  if (len > 0) memcpy(s, buf, len);
  p->kind = TOK_STRING_L;
  p->type = FILTER_TYPE_STRING;
  p->v.s = s;
  return p;
}

struct filter_tree *
filter_tree_new_string(struct filter_tree_mem *mem,
                       unsigned char const *str)
{
  struct filter_tree *p;
  unsigned char *s;
  size_t len;

  ASSERT(mem);
  len = strlen(str);
  p = getnode(mem);
  s = (unsigned char*) pgCalloc(mem->pages, 1, len + 1);
  if (len > 0) memcpy(s, str, len);
  p->kind = TOK_STRING_L;
  p->type = FILTER_TYPE_STRING;
  p->v.s = s;
  return p;
}

struct filter_tree *
filter_tree_new_int(struct filter_tree_mem *mem, int val)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = TOK_INT_L;
  p->type = FILTER_TYPE_INT;
  p->v.i = val;
  return p;
}

struct filter_tree *
filter_tree_new_bool(struct filter_tree_mem *mem, int val)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = TOK_BOOL_L;
  p->type = FILTER_TYPE_BOOL;
  p->v.i = !!val;
  return p;
}

struct filter_tree *
filter_tree_new_dur(struct filter_tree_mem *mem, time_t val)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = TOK_DUR_L;
  p->type = FILTER_TYPE_DUR;
  p->v.u = val;
  return p;
}

static unsigned char const * const type_str[] =
  {
    "unknown",
    "int",
    "string",
    "boolean",
    "date_t",
    "dur_t",
    "size_t",
    "result_t",
    "hash_t"
  };

unsigned char const *
filter_tree_type_to_str(int type)
{
  ASSERT(type >= 0 && type < FILTER_TYPE_LAST);
  return type_str[type];
}

static unsigned char*
kind_to_string(int kind)
{
  switch (kind) {
  case '*': return "*";
  case '/': return "/";
  case '%': return "%";
  case '~': return "~";
  case '!': return "!";
  case '(': return "(";
  case ')': return ")";
  case '+': return "+";
  case '-': return "-";
  case '>': return ">";
  case '<': return "<";

  case TOK_LOGOR: return "||";
  case TOK_LOGAND: return "&&";
  case TOK_EQ: return "==";
  case TOK_NE: return "!=";
  case TOK_LE: return "<=";
  case TOK_GE: return ">=";
  case TOK_ASL: return "<<";
  case TOK_ASR: return ">>";
  case TOK_ID: return "id";
  case TOK_TIME: return "atime";
  case TOK_CURTIME: return "curatime";
  case TOK_DUR: return "dur";
  case TOK_CURDUR: return "curdur";
  case TOK_SIZE: return "size";
  case TOK_CURSIZE: return "cursize";
  case TOK_HASH: return "hash";
  case TOK_CURHASH: return "curhash";
  case TOK_PROB: return "prob";
  case TOK_CURPROB: return "curprob";
  case TOK_UID: return "uid";
  case TOK_CURUID: return "curuid";
  case TOK_LOGIN: return "login";
  case TOK_CURLOGIN: return "curlogin";
  case TOK_LANG: return "lang";
  case TOK_CURLANG: return "curlang";
  case TOK_RESULT: return "result";
  case TOK_CURRESULT: return "curresult";
  case TOK_SCORE: return "score";
  case TOK_CURSCORE: return "curscore";
  case TOK_TEST: return "test";
  case TOK_CURTEST: return "curtest";
  case TOK_INT: return "int";
  case TOK_STRING: return "string";
  case TOK_BOOL: return "bool";
  case TOK_DATE_T: return "date_t";
  case TOK_DUR_T: return "dur_t";
  case TOK_SIZE_T: return "size_t";
  case TOK_RESULT_T: return "result_t";
  case TOK_HASH_T: return "hash_t";
  case TOK_INT_L: return "INT_L";
  case TOK_STRING_L: return "STRING_L";
  case TOK_BOOL_L: return "BOOL_L";
  case TOK_DATE_L: return "DATE_L";
  case TOK_DUR_L: return "DUR_L";
  case TOK_SIZE_L: return "SIZE_L";
  case TOK_RESULT_L: return "RESULT_L";
  case TOK_HASH_L: return "HASH_L";
  case TOK_UN_MINUS: return "UN_MINUS";

  default:
    SWERR(("unhandled kind: %d", kind));
  }
}

void
filter_tree_print(struct filter_tree *p, FILE *out, unsigned char const *ind)
{
  unsigned char *newind = 0;
  size_t indlen;
  unsigned char buf[128];

  fprintf(out, "%s%s %s", ind, kind_to_string(p->kind),
          filter_tree_type_to_str(p->type));
  indlen = strlen(ind);
  newind = alloca(indlen + 3);
  strcpy(newind, ind);
  newind[indlen] = ' ';
  newind[indlen + 1] = ' ';
  newind[indlen + 2] = 0;
  memset(buf, 0, sizeof(buf));

  switch (p->kind) {
    /* binary */
  case '*':
  case '/':
  case '%':
  case '+':
  case '-':
  case '>':
  case '<':
  case TOK_LOGOR:
  case TOK_LOGAND:
  case TOK_EQ:
  case TOK_NE:
  case TOK_LE:
  case TOK_GE:
  case TOK_ASL:
  case TOK_ASR:
    fprintf(out, "\n");
    filter_tree_print(p->v.t[0], out, newind);
    filter_tree_print(p->v.t[1], out, newind);
    break;

    /* unary */
  case '~':
  case '!':
  case TOK_TIME:
  case TOK_DUR:
  case TOK_SIZE:
  case TOK_HASH:
  case TOK_PROB:
  case TOK_UID:
  case TOK_LOGIN:
  case TOK_LANG:
  case TOK_RESULT:
  case TOK_SCORE:
  case TOK_TEST:
  case TOK_INT:
  case TOK_STRING:
  case TOK_BOOL:
  case TOK_DATE_T:
  case TOK_DUR_T:
  case TOK_SIZE_T:
  case TOK_RESULT_T:
  case TOK_HASH_T:
  case TOK_UN_MINUS:
    fprintf(out, "\n");
    filter_tree_print(p->v.t[0], out, newind);
    break;

    /* variables */
  case '(':
  case ')':
  case TOK_ID:
  case TOK_CURTIME:
  case TOK_CURDUR:
  case TOK_CURSIZE:
  case TOK_CURHASH:
  case TOK_CURPROB:
  case TOK_CURUID:
  case TOK_CURLOGIN:
  case TOK_CURLANG:
  case TOK_CURRESULT:
  case TOK_CURSCORE:
  case TOK_CURTEST:
    fprintf(out, "\n");
    break;

  case TOK_INT_L:
    filter_tree_int_str(buf, sizeof(buf), p->v.i);
    fprintf(out, " %s\n", buf);
    break;
  case TOK_STRING_L:
    fprintf(out, " %s\n", p->v.s);
    break;
  case TOK_BOOL_L:
    filter_tree_bool_str(buf, sizeof(buf), p->v.b);
    fprintf(out, " %s\n", buf);
    break;
  case TOK_DATE_L:
    filter_tree_date_str(buf, sizeof(buf), p->v.a);
    fprintf(out, " %s\n", buf);
    break;
  case TOK_DUR_L:
    filter_tree_dur_str(buf, sizeof(buf), p->v.u);
    fprintf(out, " %s\n", buf);
    break;
  case TOK_SIZE_L:
    filter_tree_size_str(buf, sizeof(buf), p->v.z);
    fprintf(out, " %s\n", buf);
    break;
  case TOK_RESULT_L:
    filter_tree_result_str(buf, sizeof(buf), p->v.r);
    fprintf(out, " %s\n", buf);
    break;
  case TOK_HASH_L:
    filter_tree_hash_str(buf, sizeof(buf), p->v.h);
    fprintf(out, " %s\n", buf);
    break;

  default:
    SWERR(("unhandled kind: %d", p->kind));
  }
}

int
filter_tree_int_str(unsigned char *buf, size_t size, int val)
{
  return snprintf(buf, size, "%d", val);
}

int
filter_tree_bool_str(unsigned char *buf, size_t size, int val)
{
  if (val) return snprintf(buf, size, "true");
  return snprintf(buf, size, "false");
}

int
filter_tree_date_str(unsigned char *buf, size_t size, time_t val)
{
  struct tm *ptm;

  ptm = localtime(&val);
  return snprintf(buf, size, "%04d/%02d/%02d %02d:%02d:%02d",
                  ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
                  ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}

int
filter_tree_dur_str(unsigned char *buf, size_t size, time_t val)
{
  time_t hour, min, sec;

  sec = val % 60;
  min = val / 60;
  hour = min / 60;
  min = min % 60;
  return snprintf(buf, size, "%lu:%02lu:%02lu", hour, min, sec);
}

int
filter_tree_size_str(unsigned char *buf, size_t size, size_t val)
{
  return snprintf(buf, size, "%zu", val);
}

int
filter_tree_result_str(unsigned char *buf, size_t size, int val)
{
  unsigned char tmp[32];

  switch (val) {
  case 0:                     /* RUN_OK */
    strcpy(tmp, "OK"); break;
  case 1:                     /* RUN_COMPILE_ERR */
    strcpy(tmp, "CE"); break;
  case 2:                     /* RUN_RUN_TIME_ERR */
    strcpy(tmp, "RT"); break;
  case 3:                     /* RUN_TIME_LIMIT_ERR */
    strcpy(tmp, "TL"); break;
  case 4:                     /* RUN_PRESENTATION_ERR */
    strcpy(tmp, "PE"); break;
  case 5:                     /* RUN_WRONG_ANSWER_ERR */
    strcpy(tmp, "WA"); break;
  case 6:                     /* RUN_CHECK_FAILED */
    strcpy(tmp, "CF"); break;
  case 7:                     /* RUN_PARTIAL */
    strcpy(tmp, "PT"); break;
  case 8:                     /* RUN_ACCEPTED */
    strcpy(tmp, "AC"); break;
  case 9:                     /* RUN_IGNORED */
    strcpy(tmp, "IG"); break;
  case 96:                    /* RUN_RUNNING */
    strcpy(tmp, "running"); break;
  case 97:                    /* RUN_COMPILED */
    strcpy(tmp, "compiled"); break;
  case 98:                    /* RUN_COMPILING */
    strcpy(tmp, "compiling"); break;
  case 99:                    /* RUN_AVAILABLE */
    strcpy(tmp, "available"); break;
  default:
    snprintf(tmp, sizeof(tmp), "result_%d", val);
    break;
  }
  return snprintf(buf, size, "%s", tmp);
}

int
filter_tree_hash_str(unsigned char *buf, size_t size, unsigned long *val)
{
  unsigned char tmp[64];
  unsigned char *out = tmp;
  int i;
  unsigned char *in = (unsigned char*) val;

  for (i = 0; i < 20; i++)
    out += sprintf(out, "%02x", *in++);
  *out = 0;
  return snprintf(buf, size, "%s", tmp);
}

static int
str_to_int(const unsigned char *str, int *p_int)
{
  char *eptr;
  int val;

  *p_int = 0;
  errno = 0;
  val = strtol(str, &eptr, 0);
  if (*eptr) return -FILTER_ERR_INT_CVT;
  if (errno) return -FILTER_ERR_INT_OVF;
  *p_int = val;
  return 0;
}

int
filter_tree_eval_node(int kind, struct filter_tree *res,
                      struct filter_tree *p1, struct filter_tree *p2)
{
  memset(res, 0, sizeof(*res));

  switch (kind) {

    /* cast to dur_t */
  case TOK_DUR_T:
    res->kind = TOK_DUR_L;
    res->type = FILTER_TYPE_DUR;
    switch (p1->kind) {
    case TOK_INT_L:
      res->v.u = p1->v.i;
      break;
    case TOK_STRING_L:
      {
        int n, h = 0, m = 0, s = 0, l;
        unsigned char *th, *tm, *ts;
        long long tmp;

        l = strlen(p1->v.s);
        th = alloca(l + 10);
        tm = alloca(l + 10);
        ts = alloca(l + 10);
        if (sscanf(p1->v.s, "%[^:] : %[^:] : %[^:] %n", th, tm, ts, &n) == 3
            && !p1->v.s[n]) {
        } else if (sscanf(p1->v.s, "%[^:] : %[^:] %n", tm, ts, &n) == 2
                   && !p1->v.s[n]) {
          *th = 0;
        } else if (sscanf(p1->v.s, "%s %n", ts, &n) == 1 && !p1->v.s[n]) {
          *th = 0;
          *tm = 0;
        } else {
          return FILTER_ERR_DUR_CVT;
        }
        if (*th && (n = str_to_int(th, &h)) < 0) return n;
        if (*tm && (n = str_to_int(tm, &m)) < 0) return n;
        if (*ts && (n = str_to_int(ts, &s)) < 0) return n;
        if ((h || m) && (s < 0)) return FILTER_ERR_DUR_CVT;
        if (h && m < 0) return FILTER_ERR_DUR_CVT;
        tmp = (long long) h * 3600 + (long long) m * 60 + s;
        if (tmp < INT_MIN || tmp > INT_MAX) return FILTER_ERR_INT_OVF;
        res->v.u = tmp;
        break;
      }
    case TOK_DUR_L:
      res->v.u = p1->v.u;
      break;
    default:
      SWERR(("unhandled node %d", kind));
    }
    break;

  default:
    SWERR(("unhandled node %d", kind));
  }
  return 0;
}

#define _(x) x
static unsigned char const * const errmsg[] =
{
  _("no error"),
  _("unknown error"),
  _("integer overflow"),
  _("division by zero"),
  _("conversion from string to int failed"),
  _("conversion from string to dur_t failed"),
};
#undef _
unsigned char const *
filter_strerror(int n)
{
  if (n < 0) n = -n;

  if (n >= FILTER_ERR_LAST) {
    /* FIXME: this is bug anyway */
    char buf[128];
    snprintf(buf, sizeof(buf), "unknown error %d", n);
    return xstrdup(buf);
  }
  return errmsg[n];
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "tPageDesc")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
