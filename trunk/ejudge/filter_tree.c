/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

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

#define YYSTYPE struct filter_tree *

#include "filter_tree.h"
#include "filter_expr.h"
#include "runlog.h"

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
  if (!mem) return 0;

  /*
  filter_tree_stats(mem, stderr);
  */
  pgDestroy(mem->pages);
  mem->pages = 0;
  xfree(mem);
  return 0;
}

void
filter_tree_clear(struct filter_tree_mem *mem)
{
  ASSERT(mem);

  // FIXME: implement!!!
  abort();
}

void
filter_tree_stats(struct filter_tree_mem *mem, FILE *out)
{
  ASSERT(mem);

  pgPageStatistics(mem->pages, out);

}

void *
filter_tree_alloc(struct filter_tree_mem *mem, size_t size)
{
  return pgCalloc(mem->pages, 1, size);
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

struct filter_tree*
filter_tree_dup(struct filter_tree_mem *mem,
                struct filter_tree *p)
{
  struct filter_tree *q;

  ASSERT(mem);
  ASSERT(p);
  q = getnode(mem);
  memcpy(q, p, sizeof(*p));
  return q;
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
filter_tree_new_string2(struct filter_tree_mem *mem,
                        unsigned char *str)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = TOK_STRING_L;
  p->type = FILTER_TYPE_STRING;
  p->v.s = str;
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

struct filter_tree *
filter_tree_new_time(struct filter_tree_mem *mem, time_t val)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = TOK_TIME_L;
  p->type = FILTER_TYPE_TIME;
  p->v.a = val;
  return p;
}

struct filter_tree *
filter_tree_new_size(struct filter_tree_mem *mem, size_t val)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = TOK_SIZE_L;
  p->type = FILTER_TYPE_SIZE;
  p->v.z = val;
  return p;
}

struct filter_tree *
filter_tree_new_result(struct filter_tree_mem *mem, int val)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = TOK_RESULT_L;
  p->type = FILTER_TYPE_RESULT;
  p->v.r = val;
  return p;
}

struct filter_tree *
filter_tree_new_hash(struct filter_tree_mem *mem, ruint32_t *val)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = TOK_HASH_L;
  p->type = FILTER_TYPE_HASH;
  if (val) {
    memcpy(p->v.h, val, sizeof(p->v.h));
  }
  return p;
}

struct filter_tree *
filter_tree_new_ip(struct filter_tree_mem *mem, ej_ip_t val)
{
  struct filter_tree *p;

  ASSERT(mem);
  p = getnode(mem);
  p->kind = TOK_IP_L;
  p->type = FILTER_TYPE_IP;
  p->v.p = val;
  return p;
}

#define _(x) x
static unsigned char const * const errmsg[] =
{
  _("no error"),
  _("unknown error"),
  _("integer overflow"),
  _("division by zero"),
  _("conversion from string to int failed"),
  _("conversion from string to bool failed"),
  _("conversion from string to dur_t failed"),
  _("conversion from string to time_t failed"),
  _("conversion from string to result_t failed"),
  _("conversion from string to hash_t failed"),
  _("conversion from string to ip_t failed"),
  _("range error"),
  _("invalid argument"),
  _("invalid argument type"),
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

static unsigned char const * const type_str[] =
  {
    "unknown",
    "int",
    "string",
    "boolean",
    "time_t",
    "dur_t",
    "size_t",
    "result_t",
    "hash_t",
    "ip_t",
  };

unsigned char const *
filter_tree_type_to_str(int type)
{
  ASSERT(type >= 0 && type < FILTER_TYPE_LAST);
  return type_str[type];
}

unsigned char const*
filter_tree_kind_to_str(int kind)
{
  switch (kind) {
  case '^': return "^";
  case '|': return "|";
  case '&': return "&";
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
  case TOK_TIME: return "time";
  case TOK_CURTIME: return "curtime";
  case TOK_DUR: return "dur";
  case TOK_CURDUR: return "curdur";
  case TOK_SIZE: return "size";
  case TOK_CURSIZE: return "cursize";
  case TOK_HASH: return "hash";
  case TOK_CURHASH: return "curhash";
  case TOK_IP: return "ip";
  case TOK_CURIP: return "curip";
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
  case TOK_NOW: return "now";
  case TOK_START: return "start";
  case TOK_FINISH: return "finish";
  case TOK_TOTAL: return "total";
  case TOK_INT: return "int";
  case TOK_STRING: return "string";
  case TOK_BOOL: return "bool";
  case TOK_TIME_T: return "time_t";
  case TOK_DUR_T: return "dur_t";
  case TOK_SIZE_T: return "size_t";
  case TOK_RESULT_T: return "result_t";
  case TOK_HASH_T: return "hash_t";
  case TOK_IP_T: return "ip_t";
  case TOK_INT_L: return "INT_L";
  case TOK_STRING_L: return "STRING_L";
  case TOK_BOOL_L: return "BOOL_L";
  case TOK_TIME_L: return "TIME_L";
  case TOK_DUR_L: return "DUR_L";
  case TOK_SIZE_L: return "SIZE_L";
  case TOK_RESULT_L: return "RESULT_L";
  case TOK_HASH_L: return "HASH_L";
  case TOK_IP_L: return "IP_L";
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

  fprintf(out, "%s%s %s", ind, filter_tree_kind_to_str(p->kind),
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
  case '^':
  case '|':
  case '&':
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
  case TOK_IP:
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
  case TOK_TIME_T:
  case TOK_DUR_T:
  case TOK_SIZE_T:
  case TOK_RESULT_T:
  case TOK_HASH_T:
  case TOK_IP_T:
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
  case TOK_CURIP:
  case TOK_CURPROB:
  case TOK_CURUID:
  case TOK_CURLOGIN:
  case TOK_CURLANG:
  case TOK_CURRESULT:
  case TOK_CURSCORE:
  case TOK_CURTEST:
  case TOK_NOW:
  case TOK_START:
  case TOK_FINISH:
  case TOK_TOTAL:
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
  case TOK_TIME_L:
    filter_tree_time_str(buf, sizeof(buf), p->v.a);
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
    run_status_to_str_short(buf, sizeof(buf), p->v.r);
    fprintf(out, " %s\n", buf);
    break;
  case TOK_HASH_L:
    filter_tree_hash_str(buf, sizeof(buf), p->v.h);
    fprintf(out, " %s\n", buf);
    break;
  case TOK_IP_L:
    filter_tree_ip_str(buf, sizeof(buf), p->v.p);
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
filter_tree_time_str(unsigned char *buf, size_t size, time_t val)
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
  unsigned char const *sgn = "";

  if (val < 0) {
    sgn = "-";
    val = -val;
  }
  sec = val % 60;
  min = val / 60;
  hour = min / 60;
  min = min % 60;
  return snprintf(buf, size, "%s%ld:%02ld:%02ld", sgn, hour, min, sec);
}

int
filter_tree_size_str(unsigned char *buf, size_t size, size_t val)
{
  return snprintf(buf, size, "%zu", val);
}

int
filter_tree_hash_str(unsigned char *buf, size_t size, ruint32_t *val)
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

int
filter_tree_ip_str(unsigned char *buf, size_t size, ej_ip_t val)
{
  return snprintf(buf, size, "%u.%u.%u.%u",
                  val >> 24, (val >> 16) & 0xff,
                  (val >> 8) & 0xff, val & 0xff);
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

static unsigned int
str_to_uint(const unsigned char *str, unsigned int *p_int)
{
  char *eptr;
  unsigned int val;

  *p_int = 0;
  errno = 0;
  val = strtoul(str, &eptr, 0);
  if (*eptr) return -FILTER_ERR_INT_CVT;
  if (errno) return -FILTER_ERR_INT_OVF;
  *p_int = val;
  return 0;
}

static int const add_table[FILTER_TYPE_LAST][FILTER_TYPE_LAST] =
{
  /*          -  i  s  b  a  u  z  r  h  p */
  /* - */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  /* i */  {  0, 1, 0, 0, 5, 6, 7, 0, 0, 0 },
  /* s */  {  0, 0, 2, 0, 0, 0, 0, 0, 0, 0 },
  /* b */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  /* a */  {  0, 8, 0, 0, 0, 9, 0, 0, 0, 0 },
  /* u */  {  0,10, 0, 0,11, 3, 0, 0, 0, 0 },
  /* z */  {  0,12, 0, 0, 0, 0, 4, 0, 0, 0 },
  /* r */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  /* h */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  /* p */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

static int const sub_table[FILTER_TYPE_LAST][FILTER_TYPE_LAST] =
{
  /*          -  i  s  b  a  u  z  r  h  p */
  /* - */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  /* i */  {  0, 1, 0, 0, 0, 2, 0, 0, 0, 0 },
  /* s */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  /* b */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  /* a */  {  0, 3, 0, 0, 4, 5, 0, 0, 0, 0 },
  /* u */  {  0, 6, 0, 0, 0, 7, 0, 0, 0, 0 },
  /* z */  {  0, 8, 0, 0, 0, 0, 9, 0, 0, 0 },
  /* r */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  /* h */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  /* p */  {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

int
filter_tree_eval_node(struct filter_tree_mem *mem,
                      int kind, struct filter_tree *res,
                      struct filter_tree *p1, struct filter_tree *p2)
{
  memset(res, 0, sizeof(*res));

  switch (kind) {

  case '+':
    {
      long long t;

      ASSERT(p1);
      ASSERT(p2);
      ASSERT(p1->type > 0 && p1->type < FILTER_TYPE_LAST);
      ASSERT(p2->type > 0 && p2->type < FILTER_TYPE_LAST);

      switch (add_table[p1->type][p2->type]) {
      case 0:
        return -FILTER_ERR_INV_TYPES;
      case 1:                     /* int + int */
        res->kind = TOK_INT_L;
        res->type = FILTER_TYPE_INT;
        t = (long long) p1->v.i + (long long) p2->v.i;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.i = t;
        break;
      case 2:                     /* string + string */
        {
          int l1, l2;
          unsigned char *s;

          res->kind = TOK_STRING_L;
          res->type = FILTER_TYPE_STRING;
          ASSERT(p1->v.s);
          ASSERT(p2->v.s);
          l1 = strlen(p1->v.s);
          l2 = strlen(p2->v.s);
          s = (unsigned char*) pgCalloc(mem->pages, 1, l1 + l2 + 1);
          if (l1 > 0) memcpy(s, p1->v.s, l1);
          if (l2 > 0) memcpy(s + l1, p2->v.s, l2);
          res->v.s = s;
        }
        break;
      case 3:                     /* dur_t + dur_t */
        res->kind = TOK_DUR_L;
        res->type = FILTER_TYPE_DUR;
        t = (long long) p1->v.u + (long long) p2->v.u;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.u = t;
        break;
      case 4:                     /* size_t + size_t */
        res->kind = TOK_SIZE_L;
        res->type = FILTER_TYPE_SIZE;
        t = (long long) p1->v.z + (long long) p2->v.z;
        if (t < 0 || t > UINT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.z = t;
        break;
      case 5:                     /* int + time_t */
        res->kind = TOK_TIME_L;
        res->type = FILTER_TYPE_TIME;
        t = (long long) p1->v.i + (long long) p2->v.a;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.a = t;
        break;
      case 6:                     /* int + dur_t */
        res->kind = TOK_DUR_L;
        res->type = FILTER_TYPE_DUR;
        t = (long long) p1->v.i + (long long) p2->v.u;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.u = t;
        break;
      case 7:                     /* int + size_t */
        res->kind = TOK_SIZE_L;
        res->type = FILTER_TYPE_SIZE;
        t = (long long) p1->v.i + (long long) p2->v.z;
        if (t < 0 || t > UINT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.z = t;
        break;
      case 8:                     /* time_t + int */
        res->kind = TOK_TIME_L;
        res->type = FILTER_TYPE_TIME;
        t = (long long) p1->v.a + (long long) p2->v.i;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.a = t;
        break;
      case 9:                     /* time_t + dur_t */
        res->kind = TOK_TIME_L;
        res->type = FILTER_TYPE_TIME;
        t = (long long) p1->v.a + (long long) p2->v.u;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.a = t;
        break;
      case 10:                    /* dur_t + int */
        res->kind = TOK_DUR_L;
        res->type = FILTER_TYPE_DUR;
        t = (long long) p1->v.u + (long long) p2->v.i;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.u = t;
        break;
      case 11:                    /* dur_t + time_t */
        res->kind = TOK_TIME_L;
        res->type = FILTER_TYPE_TIME;
        t = (long long) p1->v.u + (long long) p2->v.a;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.a = t;
        break;
      case 12:                    /* size_t + int */
        res->kind = TOK_SIZE_L;
        res->type = FILTER_TYPE_SIZE;
        t = (long long) p1->v.z + (long long) p2->v.i;
        if (t < 0 || t > UINT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.z = t;
        break;
      default:
        SWERR(("unhandled add action %d", add_table[p1->type][p2->type]));
      }
    }
    break;

  case '-':
    {
      long long t;

      ASSERT(p1);
      ASSERT(p2);
      ASSERT(p1->type > 0 && p1->type < FILTER_TYPE_LAST);
      ASSERT(p2->type > 0 && p2->type < FILTER_TYPE_LAST);

      switch (sub_table[p1->type][p2->type]) {
      case 0:
        return -FILTER_ERR_INV_TYPES;
      case 1:                     /* int - int */
        res->kind = TOK_INT_L;
        res->type = FILTER_TYPE_INT;
        t = (long long) p1->v.i - (long long) p2->v.i;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.i = t;
        break;
      case 2:                     /* int - dur_t */
        res->kind = TOK_DUR_L;
        res->type = FILTER_TYPE_DUR;
        t = (long long) p1->v.i - (long long) p2->v.u;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.u = t;
        break;
      case 3:                     /* time_t - int */
        res->kind = TOK_TIME_L;
        res->type = FILTER_TYPE_TIME;
        t = (long long) p1->v.a - (long long) p2->v.i;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.a = t;
        break;
      case 4:                     /* time_t - time_t */
        res->kind = TOK_DUR_L;
        res->type = FILTER_TYPE_DUR;
        t = (long long) p1->v.a - (long long) p2->v.a;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.u = t;
        break;
      case 5:                     /* time_t - dur_t */
        res->kind = TOK_TIME_L;
        res->type = FILTER_TYPE_TIME;
        t = (long long) p1->v.a - (long long) p2->v.u;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.a = t;
        break;
      case 6:                     /* dur_t - int */
        res->kind = TOK_DUR_L;
        res->type = FILTER_TYPE_DUR;
        t = (long long) p1->v.u - (long long) p2->v.i;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.u = t;
        break;
      case 7:                     /* dur_t - dur_t */
        res->kind = TOK_DUR_L;
        res->type = FILTER_TYPE_DUR;
        t = (long long) p1->v.u - (long long) p2->v.u;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.u = t;
        break;
      case 8:                     /* size_t - int */
        res->kind = TOK_SIZE_L;
        res->type = FILTER_TYPE_SIZE;
        t = (long long) p1->v.z - (long long) p2->v.i;
        if (t < 0 || t > UINT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.z = t;
        break;
      case 9:                     /* size_t - size_t */
        res->kind = TOK_INT_L;
        res->type = FILTER_TYPE_INT;
        t = (long long) p1->v.z - (long long) p2->v.z;
        if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
        res->v.i = t;
        break;
      default:
        SWERR(("unhandled sub action %d", sub_table[p1->type][p2->type]));
      }
    }
    break;

  case '^':
    ASSERT(p1->type == FILTER_TYPE_INT);
    ASSERT(p2->type == FILTER_TYPE_INT);
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = p1->v.i ^ p2->v.i;
    break;

  case '&':
    ASSERT(p1->type == FILTER_TYPE_INT);
    ASSERT(p2->type == FILTER_TYPE_INT);
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = p1->v.i & p2->v.i;
    break;

  case '|':
    ASSERT(p1->type == FILTER_TYPE_INT);
    ASSERT(p2->type == FILTER_TYPE_INT);
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = p1->v.i | p2->v.i;
    break;

  case TOK_ASL:
    ASSERT(p1->type == FILTER_TYPE_INT);
    ASSERT(p2->type == FILTER_TYPE_INT);
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    if (p2->v.i < 0 || p2->v.i > 32) return -FILTER_ERR_INV_ARG;
    res->v.i = p1->v.i << p2->v.i;
    break;

  case TOK_ASR:
    ASSERT(p1->type == FILTER_TYPE_INT);
    ASSERT(p2->type == FILTER_TYPE_INT);
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    if (p2->v.i < 0 || p2->v.i > 32) return -FILTER_ERR_INV_ARG;
    res->v.i = (unsigned) p1->v.i >> p2->v.i;
    break;

  case TOK_EQ:
    ASSERT(p1->type == p2->type);
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    switch (p1->kind) {
    case TOK_INT_L:    res->v.b = (p1->v.i == p2->v.i); break;
    case TOK_STRING_L: res->v.b = !strcmp(p1->v.s, p2->v.s); break;
    case TOK_BOOL_L:   res->v.b = (p1->v.b == p2->v.b); break;
    case TOK_TIME_L:   res->v.b = (p1->v.a == p2->v.a); break;
    case TOK_DUR_L:    res->v.b = (p1->v.u == p2->v.u); break;
    case TOK_SIZE_L:   res->v.b = (p1->v.z == p2->v.z); break;
    case TOK_RESULT_L: res->v.b = (p1->v.r == p2->v.r); break;
    case TOK_HASH_L:   res->v.b = !memcmp(p1->v.h, p2->v.h, 20); break;
    case TOK_IP_L:     res->v.b = (p1->v.p == p2->v.p); break;
    default:
      SWERR(("unhandled node %d", p1->kind));
    }
    break;

  case TOK_NE:
    ASSERT(p1->type == p2->type);
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    switch (p1->kind) {
    case TOK_INT_L:    res->v.b = (p1->v.i != p2->v.i); break;
    case TOK_STRING_L: res->v.b = (strcmp(p1->v.s, p2->v.s) != 0); break;
    case TOK_BOOL_L:   res->v.b = (p1->v.b != p2->v.b); break;
    case TOK_TIME_L:   res->v.b = (p1->v.a != p2->v.a); break;
    case TOK_DUR_L:    res->v.b = (p1->v.u != p2->v.u); break;
    case TOK_SIZE_L:   res->v.b = (p1->v.z != p2->v.z); break;
    case TOK_RESULT_L: res->v.b = (p1->v.r != p2->v.r); break;
    case TOK_HASH_L:   res->v.b = (memcmp(p1->v.h, p2->v.h, 20) != 0); break;
    case TOK_IP_L:     res->v.b = (p1->v.p != p2->v.p); break;
    default:
      SWERR(("unhandled node %d", p1->kind));
    }
    break;

  case '<':
    ASSERT(p1->type == p2->type);
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    switch (p1->kind) {
    case TOK_INT_L:    res->v.b = (p1->v.i < p2->v.i); break;
    case TOK_STRING_L: res->v.b = (strcmp(p1->v.s, p2->v.s) < 0); break;
    case TOK_BOOL_L:   res->v.b = (p1->v.b < p2->v.b); break;
    case TOK_TIME_L:   res->v.b = (p1->v.a < p2->v.a); break;
    case TOK_DUR_L:    res->v.b = (p1->v.u < p2->v.u); break;
    case TOK_SIZE_L:   res->v.b = (p1->v.z < p2->v.z); break;
    default:
      SWERR(("unhandled node %d", p1->kind));
    }
    break;

  case TOK_LE:
    ASSERT(p1->type == p2->type);
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    switch (p1->kind) {
    case TOK_INT_L:    res->v.b = (p1->v.i <= p2->v.i); break;
    case TOK_STRING_L: res->v.b = (strcmp(p1->v.s, p2->v.s) <= 0); break;
    case TOK_BOOL_L:   res->v.b = (p1->v.b <= p2->v.b); break;
    case TOK_TIME_L:   res->v.b = (p1->v.a <= p2->v.a); break;
    case TOK_DUR_L:    res->v.b = (p1->v.u <= p2->v.u); break;
    case TOK_SIZE_L:   res->v.b = (p1->v.z <= p2->v.z); break;
    default:
      SWERR(("unhandled node %d", p1->kind));
    }
    break;

  case '>':
    ASSERT(p1->type == p2->type);
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    switch (p1->kind) {
    case TOK_INT_L:    res->v.b = (p1->v.i > p2->v.i); break;
    case TOK_STRING_L: res->v.b = (strcmp(p1->v.s, p2->v.s) > 0); break;
    case TOK_BOOL_L:   res->v.b = (p1->v.b > p2->v.b); break;
    case TOK_TIME_L:   res->v.b = (p1->v.a > p2->v.a); break;
    case TOK_DUR_L:    res->v.b = (p1->v.u > p2->v.u); break;
    case TOK_SIZE_L:   res->v.b = (p1->v.z > p2->v.z); break;
    default:
      SWERR(("unhandled node %d", p1->kind));
    }
    break;

  case TOK_GE:
    ASSERT(p1->type == p2->type);
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    switch (p1->kind) {
    case TOK_INT_L:    res->v.b = (p1->v.i >= p2->v.i); break;
    case TOK_STRING_L: res->v.b = (strcmp(p1->v.s, p2->v.s) >= 0); break;
    case TOK_BOOL_L:   res->v.b = (p1->v.b >= p2->v.b); break;
    case TOK_TIME_L:   res->v.b = (p1->v.a >= p2->v.a); break;
    case TOK_DUR_L:    res->v.b = (p1->v.u >= p2->v.u); break;
    case TOK_SIZE_L:   res->v.b = (p1->v.z >= p2->v.z); break;
    default:
      SWERR(("unhandled node %d", p1->kind));
    }
    break;

  case '*':
    if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_INT) {
      long long t = (long long) p1->v.i * (long long) p2->v.i;
      if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.i = t;
    } else if (p1->type == FILTER_TYPE_DUR && p2->type == FILTER_TYPE_INT) {
      long long t = (long long) p1->v.u * (long long) p2->v.i;
      if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_DUR_L;
      res->type = FILTER_TYPE_DUR;
      res->v.u = t;
    } else if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_DUR) {
      long long t = (long long) p2->v.u * (long long) p1->v.i;
      if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_DUR_L;
      res->type = FILTER_TYPE_DUR;
      res->v.u = t;
    } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_INT) {
      unsigned long long t;
      if (p2->v.i < 0) return -FILTER_ERR_INV_ARG;
      t = (unsigned long long) p1->v.z * p2->v.i;
      if (t > UINT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_SIZE_L;
      res->type = FILTER_TYPE_SIZE;
      res->v.z = t;
    } else if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_SIZE) {
      unsigned long long t;
      if (p1->v.i < 0) return -FILTER_ERR_INV_ARG;
      t = (unsigned long long) p2->v.z * p1->v.i;
      if (t > UINT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_SIZE_L;
      res->type = FILTER_TYPE_SIZE;
      res->v.z = t;
    } else {
      SWERR(("unhandled argument types for %"));
    }
    break;

  case '%':
    if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_INT) {
      if (p2->v.i < 0) return -FILTER_ERR_INV_ARG;
      if (p2->v.i == 0) return -FILTER_ERR_DIV0;
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.i = p1->v.i % p2->v.i;
    } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_SIZE) {
      size_t tmp;
      if (p2->v.z == 0) return -FILTER_ERR_DIV0;
      tmp = p1->v.z % p2->v.z;
      if (tmp > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.i = tmp;
    } else if (p1->type == FILTER_TYPE_DUR && p2->type == FILTER_TYPE_DUR) {
      if (p2->v.u < 0) return -FILTER_ERR_INV_ARG;
      if (p2->v.u == 0) return -FILTER_ERR_DIV0;
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.i = p1->v.u % p2->v.u;
    } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_INT) {
      size_t tmp;
      if (p2->v.i < 0) return -FILTER_ERR_INV_ARG;
      if (p2->v.i == 0) return -FILTER_ERR_DIV0;
      tmp = p1->v.z % p2->v.i;
      if (tmp > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_SIZE_L;
      res->type = FILTER_TYPE_SIZE;
      res->v.z = tmp;
    } else if (p1->type == FILTER_TYPE_DUR && p2->type == FILTER_TYPE_INT) {
      if (p2->v.i < 0) return -FILTER_ERR_INV_ARG;
      if (p2->v.i == 0) return -FILTER_ERR_DIV0;
      res->kind = TOK_DUR_L;
      res->type = FILTER_TYPE_DUR;
      res->v.u = p1->v.u % p2->v.i;
    } else {
      SWERR(("unhandled argument types for %"));
    }
    break;

  case '/':
    if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_INT) {
      long long t;
      if (p2->v.i == 0) return -FILTER_ERR_DIV0;
      t = (long long) p1->v.i / (long long) p2->v.i;
      if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.i = t;
    } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_SIZE) {
      size_t t;
      if (p2->v.z == 0) return -FILTER_ERR_DIV0;
      t = p1->v.z / p2->v.z;
      if (t > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.i = t;
    } else if (p1->type == FILTER_TYPE_DUR && p2->type == FILTER_TYPE_DUR) {
      long long t;
      if (p2->v.u == 0) return -FILTER_ERR_DIV0;
      t = (long long) p1->v.u / (long long) p2->v.u;
      if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.u = t;
    } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_INT) {
      if (p2->v.i == 0) return -FILTER_ERR_DIV0;
      if (p2->v.i < 0) return -FILTER_ERR_INV_ARG;
      res->kind = TOK_SIZE_L;
      res->type = FILTER_TYPE_SIZE;
      res->v.z = p1->v.z / (size_t) p2->v.i;
    } else if (p1->type == FILTER_TYPE_DUR && p2->type == FILTER_TYPE_INT) {
      long long t;
      if (p2->v.i == 0) return -FILTER_ERR_DIV0;
      t = (long long) p1->v.u / (long long) p2->v.i;
      if (t < INT_MIN || t > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->kind = TOK_DUR_L;
      res->type = FILTER_TYPE_DUR;
      res->v.u = t;
    } else {
      SWERR(("unhandled argument types for /"));
    }
    break;

  case '!':
    ASSERT(p1->type == FILTER_TYPE_BOOL);
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    res->v.b = !p1->v.b;
    break;

  case '~':
    ASSERT(p1->type == FILTER_TYPE_INT);
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = ~p1->v.i;
    break;

  case TOK_UN_MINUS:
    ASSERT(p1->type == FILTER_TYPE_INT);
    if (p1->v.i == INT_MIN) return -FILTER_ERR_INT_OVF;
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = -p1->v.i;
    break;

    /* cast to int */
  case TOK_INT:
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    switch (p1->kind) {
    case TOK_INT_L:
      res->v.i = p1->v.i;
      break;
    case TOK_STRING_L:
      {
        int r, val;

        if ((r = str_to_int(p1->v.s, &val)) < 0) return r;
        res->v.i = val;
      }
      break;
    case TOK_BOOL_L:
      res->v.i = p1->v.b;
      break;
    case TOK_TIME_L:
      res->v.i = p1->v.a;
      break;
    case TOK_DUR_L:
      res->v.i = p1->v.u;
      break;
    case TOK_SIZE_L:
      if (p1->v.z > INT_MAX) return -FILTER_ERR_INT_OVF;
      res->v.i = p1->v.z;
      break;
    case TOK_RESULT_L:
      res->v.i = p1->v.r;
      break;
    case TOK_HASH_L:
      res->v.i = p1->v.h[0];
      break;
    case TOK_IP_L:
      res->v.i = p1->v.p;
      break;
    default:
      SWERR(("unhandled node %d", kind));
    }
    break;

  case TOK_STRING:
    {
      unsigned char val[128], *pval = val, *s;
      int len;

      res->kind = TOK_STRING_L;
      res->type = FILTER_TYPE_STRING;
      memset(val, 0, sizeof(val));
      switch (p1->kind) {
      case TOK_INT_L:
        filter_tree_int_str(val, sizeof(val), p1->v.i);
        break;
      case TOK_STRING_L:
        pval = p1->v.s;
        break;
      case TOK_BOOL_L:
        filter_tree_bool_str(val, sizeof(val), p1->v.b);
        break;
      case TOK_TIME_L:
        filter_tree_time_str(val, sizeof(val), p1->v.a);
        break;
      case TOK_DUR_L:
        filter_tree_time_str(val, sizeof(val), p1->v.u);
        break;
      case TOK_SIZE_L:
        filter_tree_size_str(val, sizeof(val), p1->v.z);
        break;
      case TOK_RESULT_L:
        run_status_to_str_short(val, sizeof(val), p1->v.r);
        break;
      case TOK_HASH_L:
        filter_tree_hash_str(val, sizeof(val), p1->v.h);
        break;
      case TOK_IP_L:
        filter_tree_ip_str(val, sizeof(val), p1->v.p);
      default:
        SWERR(("unhandled node %d", kind));
      }

      len = strlen(val);
      s = (unsigned char*) pgCalloc(mem->pages, 1, len + 1);
      if (len > 0) memcpy(s, val, len);
      res->v.s = s;
    }
    break;

  case TOK_BOOL:
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    switch (p1->kind) {
    case TOK_INT_L:
      res->v.b = !!p1->v.i;
      break;
    case TOK_STRING_L:
      if (!strcasecmp(p1->v.s, "true")) {
        res->v.b = 1;
      } else if (!strcasecmp(p1->v.s, "false")) {
        res->v.b = 0;
      } else {
        return -FILTER_ERR_BOOL_CVT;
      }
      break;
    case TOK_BOOL_L:
      res->v.b = p1->v.b;
      break;
    case TOK_TIME_L:
      res->v.b = !!p1->v.a;
      break;
    case TOK_DUR_L:
      res->v.b = !!p1->v.u;
      break;
    case TOK_SIZE_L:
      res->v.b = !!p1->v.z;
      break;
    case TOK_RESULT_L:
      res->v.b = !p1->v.r;
      break;
    case TOK_HASH_L:
      res->v.b = p1->v.h[0]||p1->v.h[1]||p1->v.h[2]||p1->v.h[3]||p1->v.h[4];
      break;
    case TOK_IP_L:
      res->v.b = !!p1->v.p;
      break;
    default:
      SWERR(("unhandled node %d", kind));
    }
    break;

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
          return -FILTER_ERR_DUR_CVT;
        }
        if (*th && (n = str_to_int(th, &h)) < 0) return n;
        if (*tm && (n = str_to_int(tm, &m)) < 0) return n;
        if (*ts && (n = str_to_int(ts, &s)) < 0) return n;
        if ((h || m) && (s < 0)) return FILTER_ERR_DUR_CVT;
        if (h && m < 0) return FILTER_ERR_DUR_CVT;
        if (h < 0) {
          tmp = (long long) h * 3600 - (long long) m * 60 - s;
        } else if (m < 0) {
          tmp = (long long) m * 60 - s;
        } else if (s < 0) {
          tmp = s;
        } else {
          tmp = (long long) h * 3600 + (long long) m * 60 + s;
        }
        if (tmp < INT_MIN || tmp > INT_MAX) return -FILTER_ERR_INT_OVF;
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

  case TOK_TIME_T:
    res->kind = TOK_TIME_L;
    res->type = FILTER_TYPE_TIME;
    switch (p1->kind) {
    case TOK_INT_L:
      res->v.a = p1->v.i;
      break;
    case TOK_STRING_L:
      {
        int l, y, m, d, h, mm, ss, n;
        unsigned char *ty, *tm, *td, *th, *tmm, *ts, *s;
        time_t tmp;
        struct tm tt;

        s = p1->v.s;
        l = strlen(s);
        memset(&tt, 0, sizeof(tt));
        tt.tm_isdst = -1;
        ty = alloca(l + 10); memset(ty, 0, l + 10);
        tm = alloca(l + 10); memset(tm, 0, l + 10);
        td = alloca(l + 10); memset(td, 0, l + 10);
        th = alloca(l + 10); memset(td, 0, l + 10);
        tmm = alloca(l + 10); memset(tmm, 0, l + 10);
        ts = alloca(l + 10); memset(ts, 0, l + 10);

        if (strchr(s, '/')) {
          if (sscanf(s, "%[^/] / %[^/] / %s %n", ty, tm, td, &n) != 3) {
            return -FILTER_ERR_TIME_CVT;
          }
          s += n;
          if ((n = str_to_int(ty, &y)) < 0) return n;
          if ((n = str_to_int(tm, &m)) < 0) return n;
          if ((n = str_to_int(td, &d)) < 0) return n;
          if (y < 1900 || y > 2100) return -FILTER_ERR_TIME_CVT;
          if (m < 1 || m > 12) return -FILTER_ERR_TIME_CVT;
          if (d < 1 || d > 31) return -FILTER_ERR_TIME_CVT;
          tt.tm_year = y - 1900;
          tt.tm_mon = m - 1;
          tt.tm_mday = d;
        } else {
          // current day, parse just time
          tmp = time(0);
          tt = *localtime(&tmp);
          tt.tm_hour = 0;
          tt.tm_min = 0;
          tt.tm_sec = 0;
        }

        h = mm = ss = 0;
        n = 0;
        if (sscanf(s, "%[^:] : %[^:] : %[^:] %n", th, tmm, ts, &n) == 3
            && !s[n]) {
          if ((n = str_to_int(th, &h)) < 0) return n;
          if ((n = str_to_int(tmm, &mm)) < 0) return n;
          if ((n = str_to_int(ts, &ss)) < 0) return n;
        } else if (sscanf(s, "%[^:] : %[^:] %n", th, tm, &n) == 2
                   && !s[n]) {
          if ((n = str_to_int(th, &h)) < 0) return n;
          if ((n = str_to_int(tmm, &mm)) < 0) return n;
        } else if (sscanf(s, "%s %n", th, &n) == 1 && !s[n]) {
          if ((n = str_to_int(th, &h)) < 0) return n;
        } else if (sscanf(s, " %n", &n) == 0 && !s[n]) {
        } else {
          return -FILTER_ERR_TIME_CVT;
        }
        if (h < 0 || h > 23) return -FILTER_ERR_TIME_CVT;
        if (mm < 0 || mm > 59) return -FILTER_ERR_TIME_CVT;
        if (ss < 0 || ss > 60) return -FILTER_ERR_TIME_CVT;
        tt.tm_hour = h;
        tt.tm_min = mm;
        tt.tm_sec = ss;
        if ((tmp = mktime(&tt)) == (time_t) -1) return -FILTER_ERR_TIME_CVT;
        res->v.a = tmp;
      }
      break;
    case TOK_TIME_L:
      res->v.a = p1->v.a;
      break;
    default:
      SWERR(("unhandled node %d", kind));
    }
    break;

  case TOK_SIZE_T:
    res->kind = TOK_SIZE_L;
    res->type = FILTER_TYPE_SIZE;
    switch (p1->kind) {
    case TOK_INT_L:
      if (p1->v.i < 0) return -FILTER_ERR_INT_OVF;
      res->v.z = p1->v.i;
      break;
    case TOK_STRING_L:
      {
        unsigned int tmp = 0;
        int n;

        if ((n = str_to_uint(p1->v.s, &tmp)) < 0) return n;
        res->v.z = tmp;
      }
      break;
    case TOK_SIZE_L:
      res->v.z = p1->v.z;
      break;
    default:
      SWERR(("unhandled node %d", kind));
    }
    break;

  case TOK_RESULT_T:
    res->kind = TOK_RESULT_L;
    res->type = FILTER_TYPE_RESULT;
    switch (p1->kind) {
    case TOK_INT_L:
      switch (p1->v.i) {
      case RUN_OK:
      case RUN_COMPILE_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_PARTIAL:
      case RUN_ACCEPTED:
      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
      case RUN_PENDING:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_FULL_REJUDGE:
      case RUN_RUNNING:
      case RUN_COMPILED:
      case RUN_COMPILING:
      case RUN_AVAILABLE:
        res->v.r = p1->v.i;
        break;
      default:
        return -FILTER_ERR_RANGE;
      }
      break;
    case TOK_STRING_L:
      if (run_str_short_to_status(p1->v.s, &res->v.r) < 0)
        return -FILTER_ERR_RESULT_CVT;
      break;
    case TOK_RESULT_L:
      res->v.r = p1->v.r;
      break;
    default:
      SWERR(("unhandled node %d", kind));
    }
    break;

  case TOK_HASH_T:
    res->kind = TOK_HASH_L;
    res->type = FILTER_TYPE_HASH;
    switch (p1->kind) {
    case TOK_STRING_L:
      {
        unsigned char *s;
        unsigned char *out;
        unsigned char tmp[4];
        int l, n, i;

        l = strlen(p1->v.s);
        s = alloca(l + 10);
        memset(s, 0, l + 10);
        if (sscanf(p1->v.s, "%[0-9a-fA-F] %n", s, &n) != 1 || p1->v.s[n])
          return -FILTER_ERR_HASH_CVT;
        if (strlen(s) != 40) return -FILTER_ERR_HASH_CVT;
        out = (unsigned char *) res->v.h;
        for (i = 0; i < 20; i++) {
          tmp[0] = *s++;
          tmp[1] = *s++;
          tmp[2] = 0;
          n = strtol(tmp, 0, 16);
          *out++ = n;
        }
      }
      break;
    case TOK_HASH_L:
      memcpy(res->v.h, p1->v.h, sizeof(res->v.h));
      break;
    default:
      SWERR(("unhandled node %d", kind));
    }
    break;

  case TOK_IP_T:
    res->kind = TOK_IP_L;
    res->type = FILTER_TYPE_IP;
    switch (p1->kind) {
    case TOK_INT_L:
      res->v.p = p1->v.i;
      break;
    case TOK_STRING_L:
      {
        unsigned int b1, b2, b3, b4;
        int n = 0;
        unsigned long tmp;

        if (sscanf(p1->v.s, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
            || p1->v.s[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
          return -FILTER_ERR_IP_CVT;
        }
        tmp = b1 << 24 | b2 << 16 | b3 << 8 | b4;
        res->v.p = tmp;
      }
      break;
    case TOK_IP_L:
      res->v.p = p1->v.p;
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

int
filter_tree_is_value_node(struct filter_tree *p)
{
  ASSERT(p);
  switch(p->kind) {
  case TOK_INT_L:
  case TOK_STRING_L:
  case TOK_BOOL_L:
  case TOK_TIME_L:
  case TOK_DUR_L:
  case TOK_SIZE_L:
  case TOK_RESULT_L:
  case TOK_HASH_L:
  case TOK_IP_L:
    return 1;
  }
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "tPageDesc")
 * End:
 */
