/* -*- mode: c; coding: koi8-r -*- */
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
 */

%{
#include "filter_tree.h"

#include <reuse/logger.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>

static struct filter_tree_mem *tree_mem;

/* for local use */
typedef struct filter_tree *tree_t;
#define MKINT(i) filter_tree_new_int(tree_mem, i)
#define MKSTRING(s) filter_tree_new_string(tree_mem, s)
#define MKBOOL(b) filter_tree_new_bool(tree_mem, b)
#define MKDUR(u) filter_tree_new_dur(tree_mem, u)

static tree_t check_int(tree_t p);
static tree_t check_bool(tree_t p);

static tree_t do_int_cast(tree_t q, tree_t p);
static tree_t do_string_cast(tree_t, tree_t);
static tree_t do_bool_cast(tree_t, tree_t);
static tree_t do_dur_cast(tree_t, tree_t);

static tree_t do_un_bitnot(tree_t, tree_t);
static tree_t do_un_lognot(tree_t, tree_t);
static tree_t do_un_minus(tree_t, tree_t);
static tree_t do_un_plus(tree_t, tree_t);

static tree_t do_multiply(tree_t, tree_t, tree_t);
static tree_t do_divmod(tree_t, tree_t, tree_t);

static void yyerror(unsigned char const *);
static void do_error(unsigned char const *format, ...);

#define YYSTYPE struct filter_tree *
//#define YYDEBUG 1
%}
%token TOK_LOGOR     "||"
%token TOK_LOGAND    "&&"
%token TOK_EQ        "=="
%token TOK_NE        "!="
%token TOK_LE        "<="
%token TOK_GE        ">="
%token TOK_ASL       "<<"
%token TOK_ASR       ">>"
%token TOK_ID        "id"
%token TOK_TIME      "time"
%token TOK_CURTIME   "curtime"
%token TOK_DUR       "dur"
%token TOK_CURDUR    "curdur"
%token TOK_SIZE      "size"
%token TOK_CURSIZE   "cursize"
%token TOK_HASH      "hash"
%token TOK_CURHASH   "curhash"
%token TOK_PROB      "prob"
%token TOK_CURPROB   "curprob"
%token TOK_UID       "uid"
%token TOK_CURUID    "curuid"
%token TOK_LOGIN     "login"
%token TOK_CURLOGIN  "curlogin"
%token TOK_LANG      "lang"
%token TOK_CURLANG   "curlang"
%token TOK_RESULT    "result"
%token TOK_CURRESULT "curresult"
%token TOK_SCORE     "score"
%token TOK_CURSCORE  "curscore"
%token TOK_TEST      "test"
%token TOK_CURTEST   "curtest"
%token TOK_INT       "int"
%token TOK_STRING    "string"
%token TOK_BOOL      "bool"
%token TOK_DATE_T    "date_t"
%token TOK_DUR_T     "dur_t"
%token TOK_SIZE_T    "size_t"
%token TOK_RESULT_T  "result_t"
%token TOK_HASH_T    "hash_t"
%token TOK_INT_L
%token TOK_STRING_L
%token TOK_BOOL_L
%token TOK_DATE_L
%token TOK_DUR_L
%token TOK_SIZE_L
%token TOK_RESULT_L
%token TOK_HASH_L
%token TOK_UN_MINUS
%%

filter_expr :
  expr0 { yylval = $1; }
;

expr0 :
  expr1 { $$ = $1; }
| expr0 "||" expr1 { abort(); }
;

expr1 :
  expr2 { $$ = $1; }
| expr1 "&&" expr2 { abort(); }
;

expr2 :
  expr3 { $$ = $1; }
| expr2 '|' expr3 { abort(); }
;

expr3 :
  expr4 { $$ = $1; }
| expr3 '^' expr4 { abort(); }
;

expr4 :
  expr5 { $$ = $1; }
| expr4 '&' expr5 { abort(); }
;

expr5 :
  expr6 { $$ = $1; }
| expr5 "==" expr6 { abort(); }
| expr5 "!=" expr6 { abort(); }
| expr5 '<'  expr6 { abort(); }
| expr5 "<=" expr6 { abort(); }
| expr5 '>'  expr6 { abort(); }
| expr5 ">=" expr6 { abort(); }
;

expr6 :
  expr7 { $$ = $1; }
| expr6 "<<" expr7 { abort(); }
| expr6 ">>" expr7 { abort(); }
;

expr7 :
  expr8 { $$ = $1; }
| expr7 '+' expr8 { abort(); }
| expr7 '-' expr8 { abort(); }
;

expr8 :
  expr9 { $$ = $1; }
| expr8 '*' expr9 { $$ = do_multiply($2, $1, $3); }
| expr8 '/' expr9 { $$ = do_divmod($2, $1, $3); }
| expr8 '%' expr9 { $$ = do_divmod($2, $1, $3); }
;

expr9 :
  exprA { $$ = $1; }
| '~' exprA { $$ = do_un_bitnot($1, $2); }
| '!' exprA { $$ = do_un_lognot($1, $2); }
| '-' exprA { $$ = do_un_minus($1, $2); }
| '+' exprA { $$ = do_un_plus($1, $2); }
;

exprA :
  '(' expr0 ')' { $$ = $2; }
| TOK_STRING_L { $$ = $1; }
| TOK_INT_L { $$ = $1; }
| TOK_BOOL_L { $$ = $1; }
| "id" { $$ = $1; }
| "time" { $1->kind = TOK_CURTIME; $$ = $1; }
| "time" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curtime" { $$ = $1; }
| "dur" { $1->kind = TOK_CURDUR; $$ = $1; }
| "dur" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curdur" { $$ = $1; }
| "size" { $1->kind = TOK_CURSIZE; $$ = $1; }
| "size" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "cursize" { $$ = $1; }
| "hash" { $1->kind = TOK_CURHASH; $$ = $1; }
| "hash" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curhash" { $$ = $1; }
| "uid" { $1->kind = TOK_CURUID; $$ = $1; }
| "uid" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curuid" { $$ = $1; }
| "login" { $1->kind = TOK_CURLOGIN; $$ = $1; }
| "login" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curlogin" { $$ = $1; }
| "lang" { $1->kind = TOK_CURLANG; $$ = $1; }
| "lang" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curlang" { $$ = $1; }
| "prob" { $1->kind = TOK_CURPROB; $$ = $1; }
| "prob" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curprob" { $$ = $1; }
| "result" { $1->kind = TOK_CURRESULT; $$ = $1; }
| "result" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curresult" { $$ = $1; }
| "score" { $1->kind = TOK_CURSCORE; $$ = $1; }
| "score" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curscore" { $$ = $1; }
| "test" { $1->kind = TOK_CURTEST; $$ = $1; }
| "test" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curtest" { $$ = $1; }
| "int" '(' expr0 ')' { $$ = do_int_cast($1, $3); }
| "string" '(' expr0 ')' { $$ = do_string_cast($1, $3); }
| "bool" '(' expr0 ')' { $$ = do_bool_cast($1, $3); }
| "date_t" '(' expr0 ')' { abort(); }
| "dur_t" '(' expr0 ')' { $$ = do_dur_cast($1, $3); }
| "size_t" '(' expr0 ')' { abort(); }
| "result_t" '(' expr0 ')' { abort(); }
| "hash_t" '(' expr0 ')' { abort(); }
;

%%

static void
do_error(const unsigned char *format, ...)
{
  va_list args;
  fprintf(stderr, "filter_expr: ");
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  yynerrs++;
}

static int
str_to_int(const unsigned char *str, int *p_int, unsigned char const *msg)
{
  char *eptr;
  int val;

  *p_int = 0;
  errno = 0;
  val = strtol(str, &eptr, 0);
  if (*eptr) {
    do_error("cannot convert string to %s", msg);
    return -1;
  }
  if (errno) {
    do_error("%s is out of range", msg);
    return -1;
  }
  *p_int = val;
  return 0;
}

static unsigned int
str_to_uint(const unsigned char *str,
            unsigned int *p_int, unsigned char const *msg)
{
  char *eptr;
  unsigned int val;

  *p_int = 0;
  errno = 0;
  val = strtoul(str, &eptr, 0);
  if (*eptr) {
    do_error("cannot convert string to %s", msg);
    return -1;
  }
  if (errno) {
    do_error("%s is out of range", msg);
    return -1;
  }
  *p_int = val;
  return 0;
}

static tree_t
check_int(tree_t p)
{
  ASSERT(p);
  if (p->type != FILTER_TYPE_INT) {
    do_error("`int' expression expected");
    yynerrs++;
    return MKINT(0);
  }
  return p;
}
static tree_t
check_bool(tree_t p)
{
  ASSERT(p);
  if (p->type != FILTER_TYPE_BOOL) {
    do_error("`bool' expression expected");
    yynerrs++;
    return MKBOOL(0);
  }
  return p;
}

static tree_t
do_un_plus(tree_t op, tree_t p)
{
  p = check_int(p);
  return p;
}
static tree_t
do_un_minus(tree_t op, tree_t p)
{
  p = check_int(p);
  if (p->kind == TOK_INT_L) {
    p->v.i = -p->v.i;
    return p;
  }
  op->kind = TOK_UN_MINUS;
  op->type = FILTER_TYPE_INT;
  op->v.t[0] = p;
  return op;
}
static tree_t
do_un_bitnot(tree_t op, tree_t p)
{
  p = check_int(p);
  if (p->kind == TOK_INT_L) {
    p->v.i = ~p->v.i;
    return p;
  }
  op->kind = '~';
  op->type = FILTER_TYPE_INT;
  op->v.t[0] = p;
  return op;
}
static tree_t
do_un_lognot(tree_t op, tree_t p)
{
  p = check_bool(p);
  if (p->kind == TOK_BOOL_L) {
    p->v.b = !p->v.b;
    return p;
  }
  op->kind = '!';
  op->type = FILTER_TYPE_BOOL;
  op->v.t[0] = p;
  return op;
}
static tree_t
do_divmod(tree_t op, tree_t p1, tree_t p2)
{
  ASSERT(op);
  ASSERT(p1);
  ASSERT(p2);

  if (p1->type == FILTER_TYPE_STRING || p1->type == FILTER_TYPE_BOOL
      || p1->type == FILTER_TYPE_RESULT || p1->type == FILTER_TYPE_HASH
      || p1->type == FILTER_TYPE_DATE) {
    do_error("%c is undefined for type %s", op->kind,
             filter_tree_type_to_str(p1->type));
    return MKINT(0);
  }
  if (p2->type == FILTER_TYPE_STRING || p2->type == FILTER_TYPE_BOOL
      || p2->type == FILTER_TYPE_RESULT || p2->type == FILTER_TYPE_HASH
      || p2->type == FILTER_TYPE_DATE) {
    do_error("%c is undefined for type %s", op->kind,
             filter_tree_type_to_str(p2->type));
    return MKINT(0);
  }
  if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_INT) {
    if (p1->kind == TOK_INT_L && p2->kind == TOK_INT_L) {
      long long res = 0;
      if (!p2->v.i) {
        do_error("division by zero");
        return MKINT(0);
      }
      if (op->kind == '%') {
        res = (long long) p1->v.i % (long long) p2->v.i;
      } else if (op->kind == '/') {
        res = (long long) p1->v.i / (long long) p2->v.i;
      } else {
        SWERR(("unhandled operation: %d", op->kind));
      }
      if (res < INT_MIN || res > INT_MAX) {
        do_error("integer overflow on *");
        return MKINT(0);
      }
      return MKINT((int) res);
    }
    op->type = FILTER_TYPE_INT;
    op->v.t[0] = p1;
    op->v.t[1] = p2;
    return op;
  }
  if (p1->type == FILTER_TYPE_INT) {
    do_error("cannot divide int by %s",
             filter_tree_type_to_str(p1->type));
    return MKINT(0);
  }
  if (p1->type == p2->type) {
    op->type = FILTER_TYPE_INT;
    op->v.t[0] = p1;
    op->v.t[1] = p2;
    return op;
  }
  if (p2->type != FILTER_TYPE_INT) {
    do_error("invalid types for %c", op->kind);
    return MKINT(0);
  }
  op->type = p1->type;
  op->v.t[0] = p1;
  op->v.t[1] = p2;
  return op;
}
static tree_t
do_multiply(tree_t op, tree_t p1, tree_t p2)
{
  ASSERT(op);
  ASSERT(p1);
  ASSERT(p2);

  if (p1->type == FILTER_TYPE_STRING || p1->type == FILTER_TYPE_BOOL
      || p1->type == FILTER_TYPE_RESULT || p1->type == FILTER_TYPE_HASH
      || p1->type == FILTER_TYPE_DATE) {
    do_error("* is undefined for type %s",
             filter_tree_type_to_str(p1->type));
    return MKINT(0);
  }
  if (p2->type == FILTER_TYPE_STRING || p2->type == FILTER_TYPE_BOOL
      || p2->type == FILTER_TYPE_RESULT || p2->type == FILTER_TYPE_HASH
      || p2->type == FILTER_TYPE_DATE) {
    do_error("* is undefined for type %s",
             filter_tree_type_to_str(p2->type));
    return MKINT(0);
  }
  if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_INT) {
    if (p1->kind == TOK_INT_L && p2->kind == TOK_INT_L) {
      long long res = (long long) p1->v.i * (long long) p2->v.i;
      if (res < INT_MIN || res > INT_MAX) {
        do_error("integer overflow on *");
        return MKINT(0);
      }
      return MKINT((int) res);
    }
    op->kind = '*';
    op->type = FILTER_TYPE_INT;
    op->v.t[0] = p1;
    op->v.t[1] = p2;
    return op;
  } else if (p1->type == FILTER_TYPE_INT) {
    tree_t tmp = p1;
    p1 = p2;
    p2 = tmp;
  } else if (p2->type == FILTER_TYPE_INT) {
  } else {
    do_error("one argument of * must be of type int");
    return MKINT(0);
  }

  ASSERT(p1->type == TOK_DUR_L || p1->type == TOK_SIZE_L);
  if (p2->kind == TOK_INT_L) {
  }
  op->kind = '*';
  op->type = p1->type;
  op->v.t[0] = p1;
  op->v.t[1] = p2;
  return op;
}

static tree_t
do_int_cast(tree_t q, tree_t p)
{
  int x;

  ASSERT(p);
  switch (p->kind) {
  case TOK_INT_L:
    return p;
  case TOK_STRING_L:
    str_to_int(p->v.s, &x, "int");
    return MKINT(x);
  case TOK_BOOL_L:
    return MKINT(p->v.b);
  case TOK_DATE_L:
    return MKINT(p->v.a);
  case TOK_DUR_L:
    return MKINT(p->v.u);
  case TOK_SIZE_L:
    return MKINT(p->v.z);
  case TOK_RESULT_L:
    return MKINT(p->v.r);
  case TOK_HASH_L:
    return MKINT(p->v.h[0]);
  }
  q->v.t[0] = p;
  q->kind = TOK_INT;
  q->type = FILTER_TYPE_INT;
  return q;
}

static tree_t
do_bool_cast(tree_t q, tree_t p)
{
  ASSERT(p);

  switch (p->kind) {
  case TOK_INT_L:
    return MKBOOL(!!p->v.i);
  case TOK_STRING_L:
    if (!strcasecmp(p->v.s, "true")) {
      return MKBOOL(1);
    } else if (!strcasecmp(p->v.s, "false")) {
      return MKBOOL(0);
    }
    do_error("cannot convert string to bool");
    return MKBOOL(0);
  case TOK_BOOL_L:
    return p;
  case TOK_DATE_L:
    return MKBOOL(!!p->v.a);
  case TOK_DUR_L:
    return MKBOOL(!!p->v.u);
  case TOK_SIZE_L:
    return MKBOOL(!!p->v.z);
  case TOK_RESULT_L:
    return MKBOOL(!p->v.r);
  case TOK_HASH_L:
    return MKBOOL(p->v.h[0]||p->v.h[1]||p->v.h[2]||p->v.h[3]||p->v.h[4]);
  }

  q->v.t[0] = p;
  q->kind = TOK_BOOL;
  q->type = FILTER_TYPE_BOOL;
  return q;
}

static tree_t
do_string_cast(tree_t q, tree_t p)
{
  unsigned char val[128];

  ASSERT(p);
  memset(val, 0, sizeof(val));
  switch (p->kind) {
  case TOK_INT_L:
    filter_tree_int_str(val, sizeof(val), p->v.i);
    break;
  case TOK_STRING_L:
    return p;
  case TOK_BOOL_L:
    filter_tree_bool_str(val, sizeof(val), p->v.b);
    break;
  case TOK_DATE_L:
    filter_tree_date_str(val, sizeof(val), p->v.a);
    break;
  case TOK_DUR_L:
    filter_tree_date_str(val, sizeof(val), p->v.u);
    break;
  case TOK_SIZE_L:
    filter_tree_size_str(val, sizeof(val), p->v.z);
    break;
  case TOK_RESULT_L:
    filter_tree_result_str(val, sizeof(val), p->v.r);
  break;
  case TOK_HASH_L:
    filter_tree_hash_str(val, sizeof(val), p->v.h);
    break;
  }
  if (val[0]) {
    return MKSTRING(val);
  }
  q->v.t[0] = p;
  q->kind = TOK_STRING;
  q->type = FILTER_TYPE_STRING;
  return q;
}

static tree_t
do_dur_cast(tree_t q, tree_t p)
{
  int r;

  if (p->type == FILTER_TYPE_DUR) {
    return p;
  }
  if (p->kind == TOK_INT_L || p->kind == TOK_STRING_L) {
    struct filter_tree res;

    if ((r = filter_tree_eval_node(TOK_DUR_T, &res, p, 0)) < 0) {
      do_error("%s", filter_strerror(-r));
      return MKDUR(0);
    }
    return MKDUR(res.v.u);
  }
  if (p->type != FILTER_TYPE_INT
      && p->type != FILTER_TYPE_STRING) {
    do_error("expression of type %s cannot be converted to dur_t",
             filter_tree_type_to_str(p->type));
    return MKDUR(0);
  }
  q->v.t[0] = p;
  q->kind = TOK_DUR;
  q->type = FILTER_TYPE_DUR;
  return q;
}

static void
yyerror(unsigned char const *msg)
{
  do_error("%s", msg);
}

void
filter_expr_init_parser(struct filter_tree_mem *mem)
{
  tree_mem = mem;
  //yydebug = 1;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "jmp_buf")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
