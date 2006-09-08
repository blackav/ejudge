/* -*- mode: fundamental; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ejudge.ru> */

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

/* for local use */
typedef struct filter_tree *tree_t;
#define MKINT(i) filter_tree_new_int(filter_expr_tree_mem, i)
#define MKSTRING(s) filter_tree_new_string(filter_expr_tree_mem, s)
#define MKSTRING2(s) filter_tree_new_string2(filter_expr_tree_mem, s)
#define MKBOOL(b) filter_tree_new_bool(filter_expr_tree_mem, b)
#define MKDUR(u) filter_tree_new_dur(filter_expr_tree_mem, u)
#define MKTIME(a) filter_tree_new_time(filter_expr_tree_mem, a)
#define MKSIZE(z) filter_tree_new_size(filter_expr_tree_mem, z)
#define MKRESULT(r) filter_tree_new_result(filter_expr_tree_mem, r)
#define MKHASH(h) filter_tree_new_hash(filter_expr_tree_mem, h)
#define MKIP(p) filter_tree_new_ip(filter_expr_tree_mem, p)
#define MKCOPY(c) filter_tree_dup(filter_expr_tree_mem, c)

static tree_t check_int(tree_t p);
static tree_t check_bool(tree_t p);

static tree_t do_int_cast(tree_t q, tree_t p);
static tree_t do_string_cast(tree_t, tree_t);
static tree_t do_bool_cast(tree_t, tree_t);
static tree_t do_dur_cast(tree_t, tree_t);
static tree_t do_time_cast(tree_t, tree_t);
static tree_t do_size_cast(tree_t, tree_t);
static tree_t do_result_cast(tree_t, tree_t);
static tree_t do_hash_cast(tree_t, tree_t);
static tree_t do_ip_cast(tree_t, tree_t);

static tree_t do_un_bitnot(tree_t, tree_t);
static tree_t do_un_lognot(tree_t, tree_t);
static tree_t do_un_minus(tree_t, tree_t);
static tree_t do_un_plus(tree_t, tree_t);

static tree_t do_logop(tree_t, tree_t, tree_t);
static tree_t do_equality(tree_t, tree_t, tree_t);
static tree_t do_relation(tree_t, tree_t, tree_t);
static tree_t do_multiply(tree_t, tree_t, tree_t);
static tree_t do_divmod(tree_t, tree_t, tree_t);
static tree_t do_bitop(tree_t, tree_t, tree_t);
static tree_t do_add(tree_t, tree_t, tree_t);
static tree_t do_sub(tree_t, tree_t, tree_t);

static void yyerror(unsigned char const *);
static void do_error(void *, unsigned char const *format, ...);

/*
 * FIXME: filter_expr parser uses lots of static variables internally,
 *        so, it should be used with care!
 */
static struct filter_tree_mem *filter_expr_tree_mem;
static void (*filter_expr_parse_err)(void *, unsigned char const *, ...);
static void *filter_expr_user_data;

#define YYSTYPE struct filter_tree *
#define YYERROR_VERBOSE
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
%token TOK_IP        "ip"
%token TOK_CURIP     "curip"
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
%token TOK_NOW       "now"
%token TOK_START     "begin"
%token TOK_FINISH    "finish"
%token TOK_TOTAL     "total"
%token TOK_IMPORTED  "imported"
%token TOK_CURIMPORTED "curimported"
%token TOK_HIDDEN    "hidden"
%token TOK_CURHIDDEN "curhidden"
%token TOK_READONLY  "readonly"
%token TOK_CURREADONLY "curreadonly"
%token TOK_VARIANT   "variant"
%token TOK_CURVARIANT "curvariant"
%token TOK_RAWVARIANT "rawvariant"
%token TOK_CURRAWVARIANT "currawvariant"
%token TOK_USERINVISIBLE "userinvisible"
%token TOK_CURUSERINVISIBLE "curuserinvisible"
%token TOK_USERBANNED "userbanned"
%token TOK_CURUSERBANNED "curuserbanned"
%token TOK_USERLOCKED "userlocked"
%token TOK_CURUSERLOCKED "curuserlocked"
%token TOK_LATEST    "latest"
%token TOK_CURLATEST "curlatest"
%token TOK_AFTEROK   "afterok"
%token TOK_CURAFTEROK "curafterok"
%token TOK_INT       "int"
%token TOK_STRING    "string"
%token TOK_BOOL      "bool"
%token TOK_TIME_T    "time_t"
%token TOK_DUR_T     "dur_t"
%token TOK_SIZE_T    "size_t"
%token TOK_RESULT_T  "result_t"
%token TOK_HASH_T    "hash_t"
%token TOK_IP_T      "ip_t"
%token TOK_INT_L
%token TOK_STRING_L
%token TOK_BOOL_L
%token TOK_TIME_L
%token TOK_DUR_L
%token TOK_SIZE_L
%token TOK_RESULT_L
%token TOK_HASH_L
%token TOK_IP_L
%token TOK_UN_MINUS
%%

filter_expr :
  expr0 { yylval = $1; }
| { yylval = 0; }
;

expr0 :
  expr1 { $$ = $1; }
| expr0 "||" expr1 { $$ = do_logop($2, $1, $3); }
;

expr1 :
  expr2 { $$ = $1; }
| expr1 "&&" expr2 { $$ = do_logop($2, $1, $3); }
;

expr2 :
  expr3 { $$ = $1; }
| expr2 '|' expr3 { $$ = do_bitop($2, $1, $3); }
;

expr3 :
  expr4 { $$ = $1; }
| expr3 '^' expr4 { $$ = do_bitop($2, $1, $3); }
;

expr4 :
  expr5 { $$ = $1; }
| expr4 '&' expr5 { $$ = do_bitop($2, $1, $3); }
;

expr5 :
  expr6 { $$ = $1; }
| expr5 "==" expr6 { $$ = do_equality($2, $1, $3); }
| expr5 "!=" expr6 { $$ = do_equality($2, $1, $3); }
| expr5 '<'  expr6 { $$ = do_relation($2, $1, $3); }
| expr5 "<=" expr6 { $$ = do_relation($2, $1, $3); }
| expr5 '>'  expr6 { $$ = do_relation($2, $1, $3); }
| expr5 ">=" expr6 { $$ = do_relation($2, $1, $3); }
;

expr6 :
  expr7 { $$ = $1; }
| expr6 "<<" expr7 { $$ = do_bitop($2, $1, $3); }
| expr6 ">>" expr7 { $$ = do_bitop($2, $1, $3); }
;

expr7 :
  expr8 { $$ = $1; }
| expr7 '+' expr8 { $$ = do_add($2, $1, $3); }
| expr7 '-' expr8 { $$ = do_sub($2, $1, $3); }
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
| TOK_RESULT_L { $$ = $1; }
| "id" { $$ = $1; }
| "now" { $$ = $1; }
| "start" { $$ = $1; }
| "finish" { $$ = $1; }
| "total" { $$ = $1; }
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
| "ip" { $1->kind = TOK_CURIP; $$ = $1; }
| "ip" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curip" { $$ = $1; }
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
| "imported" { $1->kind = TOK_CURIMPORTED; $$ = $1; }
| "imported" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curimported" { $$ = $1; }
| "hidden" { $1->kind = TOK_CURHIDDEN; $$ = $1; }
| "hidden" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curhidden" { $$ = $1; }
| "readonly" { $1->kind = TOK_CURREADONLY; $$ = $1; }
| "readonly" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curreadonly" { $$ = $1; }
| "variant" { $1->kind = TOK_CURVARIANT; $$ = $1; }
| "variant" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "curvariant" { $$ = $1; }
| "rawvariant" { $1->kind = TOK_CURRAWVARIANT; $$ = $1; }
| "rawvariant" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "currawvariant" { $$ = $1; }
| "userinvisible" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "userinvisible" { $1->kind = TOK_CURUSERINVISIBLE; $$ = $1; }
| "curuserinvisible" { $$ = $1; }
| "userbanned" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "userbanned" { $1->kind = TOK_CURUSERBANNED; $$ = $1; }
| "curuserbanned" { $$ = $1; }
| "userlocked" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "userlocked" { $1->kind = TOK_CURUSERLOCKED; $$ = $1; }
| "curuserlocked" { $$ = $1; }
| "latest" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "latest" { $1->kind = TOK_CURLATEST; $$ = $1; }
| "curlatest" { $$ = $1; }
| "afterok" '(' expr0 ')' { $1->v.t[0] = check_int($3); $$ = $1; }
| "afterok" { $1->kind = TOK_CURAFTEROK; $$ = $1; }
| "curafterok" { $$ = $1; }
| "int" '(' expr0 ')' { $$ = do_int_cast($1, $3); }
| "string" '(' expr0 ')' { $$ = do_string_cast($1, $3); }
| "bool" '(' expr0 ')' { $$ = do_bool_cast($1, $3); }
| "time_t" '(' expr0 ')' { $$ = do_time_cast($1, $3); }
| "dur_t" '(' expr0 ')' { $$ = do_dur_cast($1, $3); }
| "size_t" '(' expr0 ')' { $$ = do_size_cast($1, $3); }
| "result_t" '(' expr0 ')' { $$ = do_result_cast($1, $3); }
| "hash_t" '(' expr0 ')' { $$ = do_hash_cast($1, $3); }
| "ip_t" '(' expr0 ')' { $$ = do_ip_cast($1, $3); }
;

%%

static void
do_error(void *data, const unsigned char *format, ...)
{
  va_list args;
  //fprintf(stderr, "filter_expr: ");
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  yynerrs++;
}

static tree_t
check_int(tree_t p)
{
  ASSERT(p);
  if (p->type != FILTER_TYPE_INT) {
    (*filter_expr_parse_err)(filter_expr_user_data, "`int' expression expected");
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
    (*filter_expr_parse_err)(filter_expr_user_data, "`bool' expression expected");
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
    tree_t res = MKINT(0);
    int n;

    n = filter_tree_eval_node(filter_expr_tree_mem, TOK_UN_MINUS, res, p, 0);
    if (n < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-n));
    return res;
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
    tree_t res = MKINT(0);
    int n;

    n = filter_tree_eval_node(filter_expr_tree_mem, '~', res, p, 0);
    if (n < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-n));
    return res;
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
    tree_t res = MKBOOL(0);
    int n;

    n = filter_tree_eval_node(filter_expr_tree_mem, '!', res, p, 0);
    if (n < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-n));
    return res;
  }
  op->kind = '!';
  op->type = FILTER_TYPE_BOOL;
  op->v.t[0] = p;
  return op;
}

static tree_t
do_sub(tree_t op, tree_t p1, tree_t p2)
{
  ASSERT(op);
  ASSERT(p1);
  ASSERT(p2);

  if (p1->type != FILTER_TYPE_INT && p1->type != FILTER_TYPE_TIME
      && p1->type != FILTER_TYPE_DUR && p1->type != FILTER_TYPE_SIZE) {
    goto undefined_op;
  }
  if (p2->type != FILTER_TYPE_INT && p2->type != FILTER_TYPE_TIME
      && p2->type != FILTER_TYPE_DUR && p2->type != FILTER_TYPE_SIZE) {
    goto undefined_op;
  }

  /* int dur_t time_t size_t */
  if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_SIZE) {
    op->type = FILTER_TYPE_INT;
  } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_INT) {
    op->type = FILTER_TYPE_SIZE;
  } else if (p1->type == FILTER_TYPE_SIZE || p2->type == FILTER_TYPE_SIZE) {
    goto undefined_op;
  } else if (p1->type == FILTER_TYPE_TIME && p2->type == FILTER_TYPE_TIME) {
    op->type = FILTER_TYPE_DUR;
  } else if (p2->type == FILTER_TYPE_TIME) {
    goto undefined_op;
  } else if (p1->type == FILTER_TYPE_TIME && p2->type == FILTER_TYPE_INT) {
    op->type = FILTER_TYPE_TIME;
  } else if (p1->type == FILTER_TYPE_TIME && p2->type == FILTER_TYPE_DUR) {
    op->type = FILTER_TYPE_TIME;
  } else if (p1->type == FILTER_TYPE_DUR || p2->type == FILTER_TYPE_DUR) {
    op->type = FILTER_TYPE_DUR;
  } else {
    op->type = FILTER_TYPE_INT;
  }

  if (filter_tree_is_value_node(p1) && filter_tree_is_value_node(p2)) {
    struct filter_tree *res = MKINT(0);
    int r;

    r = filter_tree_eval_node(filter_expr_tree_mem, '-', res, p1, p2);
    if (r < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
    return res;
  }

  op->v.t[0] = p1;
  op->v.t[1] = p2;
  return op;

 undefined_op:
  (*filter_expr_parse_err)(filter_expr_user_data, "operation -(%s,%s) is not defined",
           filter_tree_type_to_str(p1->type),
           filter_tree_type_to_str(p2->type));
  return MKINT(0);
}

static tree_t
do_add(tree_t op, tree_t p1, tree_t p2)
{
  ASSERT(op);
  ASSERT(p1);
  ASSERT(p2);

  if (p1->type == FILTER_TYPE_HASH || p2->type == FILTER_TYPE_HASH
      || p1->type == FILTER_TYPE_IP || p2->type == FILTER_TYPE_IP
      || p1->type == FILTER_TYPE_RESULT || p2->type == FILTER_TYPE_RESULT
      || p1->type == FILTER_TYPE_BOOL || p2->type == FILTER_TYPE_BOOL) {
    goto undefined_op;
  }
  /* int string time_t dur_t size_t*/
  if (p1->type == FILTER_TYPE_STRING && p2->type == FILTER_TYPE_STRING) {
    op->type = FILTER_TYPE_STRING;
  } else if (p1->type == FILTER_TYPE_STRING || p2->type == FILTER_TYPE_STRING){
    goto undefined_op;
  } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_SIZE) {
    op->type = FILTER_TYPE_SIZE;
  } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_INT) {
    op->type = FILTER_TYPE_SIZE;
  } else if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_SIZE) {
    op->type = FILTER_TYPE_SIZE;
  } else if (p1->type == FILTER_TYPE_SIZE || p2->type == FILTER_TYPE_SIZE) {
    goto undefined_op;
  } else if (p1->type == FILTER_TYPE_TIME && p2->type == FILTER_TYPE_TIME) {
    goto undefined_op;
  } else if (p1->type == FILTER_TYPE_TIME || p2->type == FILTER_TYPE_TIME) {
    op->type = FILTER_TYPE_TIME;
  } else if (p1->type == FILTER_TYPE_DUR || p2->type == FILTER_TYPE_DUR) {
    op->type = FILTER_TYPE_DUR;
  } else {
    op->type = FILTER_TYPE_INT;
  }

  if (filter_tree_is_value_node(p1) && filter_tree_is_value_node(p2)) {
    struct filter_tree *res = MKINT(0);
    int r;

    r = filter_tree_eval_node(filter_expr_tree_mem, '+', res, p1, p2);
    if (r < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
    return res;
  }

  op->v.t[0] = p1;
  op->v.t[1] = p2;
  return op;

 undefined_op:
  (*filter_expr_parse_err)(filter_expr_user_data, "operation +(%s,%s) is not defined",
           filter_tree_type_to_str(p1->type),
           filter_tree_type_to_str(p2->type));
  return MKINT(0);
}

static tree_t
do_logop(tree_t op, tree_t p1, tree_t p2)
{
  ASSERT(op);
  ASSERT(p1);
  ASSERT(p2);

  p1 = check_bool(p1);
  p2 = check_bool(p2);
  switch (op->kind) {
  case TOK_LOGOR:
    if (p1->kind == TOK_BOOL_L) {
      if (p1->v.b) return MKBOOL(1);
      else return p2;
    }
    break;
  case TOK_LOGAND:
    if (p1->kind == TOK_BOOL_L) {
      if (p1->v.b) return p2;
      else return MKBOOL(0);
    }
    break;
  default:
    SWERR(("unhandled node %d", op->kind));
  }

  op->type = FILTER_TYPE_BOOL;
  op->v.t[0] = p1;
  op->v.t[1] = p2;
  return op;
}

static tree_t
do_bitop(tree_t op, tree_t p1, tree_t p2)
{
  ASSERT(op);
  ASSERT(p1);
  ASSERT(p2);

  if (p1->type != FILTER_TYPE_INT || p2->type != FILTER_TYPE_INT) {
    (*filter_expr_parse_err)(filter_expr_user_data, "operation is not defined");
    return MKINT(0);
  }

  if (filter_tree_is_value_node(p1) && filter_tree_is_value_node(p2)) {
    struct filter_tree *res = MKINT(0);
    int r;

    r = filter_tree_eval_node(filter_expr_tree_mem, op->kind, res, p1, p2);
    if (r < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
    return res;
  }

  op->type = FILTER_TYPE_INT;
  op->v.t[0] = p1;
  op->v.t[1] = p2;
  return op;
}

static tree_t
do_equality(tree_t op, tree_t p1, tree_t p2)
{
  ASSERT(op);
  ASSERT(p1);
  ASSERT(p2);

  if (p1->type != p2->type) {
    (*filter_expr_parse_err)(filter_expr_user_data, "type mismatch");
    return MKBOOL(0);
  }

  if (filter_tree_is_value_node(p1) && filter_tree_is_value_node(p2)) {
    struct filter_tree *res = MKINT(0);
    int r;

    r = filter_tree_eval_node(filter_expr_tree_mem, op->kind, res, p1, p2);
    if (r < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
    return res;
  }

  op->type = FILTER_TYPE_BOOL;
  op->v.t[0] = p1;
  op->v.t[1] = p2;
  return op;
}

static tree_t
do_relation(tree_t op, tree_t p1, tree_t p2)
{
  ASSERT(op);
  ASSERT(p1);
  ASSERT(p2);

  if (p1->type == FILTER_TYPE_HASH || p1->type == FILTER_TYPE_RESULT
      || p1->type == FILTER_TYPE_IP) {
    (*filter_expr_parse_err)(filter_expr_user_data, "operation is undefined for this type");
    return MKBOOL(0);
  }
  if (p1->type != p2->type) {
    (*filter_expr_parse_err)(filter_expr_user_data, "type mismatch");
    return MKBOOL(0);
  }

  if (filter_tree_is_value_node(p1) && filter_tree_is_value_node(p2)) {
    struct filter_tree *res = MKINT(0);
    int r;

    r = filter_tree_eval_node(filter_expr_tree_mem, op->kind, res, p1, p2);
    if (r < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
    return res;
  }

  op->type = FILTER_TYPE_BOOL;
  op->v.t[0] = p1;
  op->v.t[1] = p2;
  return op;
}

static tree_t
do_divmod(tree_t op, tree_t p1, tree_t p2)
{
  ASSERT(op);
  ASSERT(p1);
  ASSERT(p2);

  if (p1->type != FILTER_TYPE_INT && p1->type != FILTER_TYPE_DUR
      && p1->type != FILTER_TYPE_SIZE) {
    (*filter_expr_parse_err)(filter_expr_user_data, "%c is undefined for type %s", op->kind,
             filter_tree_type_to_str(p1->type));
    return MKINT(0);
  }
  if (p2->type != FILTER_TYPE_INT && p2->type != FILTER_TYPE_DUR
      && p2->type != FILTER_TYPE_SIZE) {
    (*filter_expr_parse_err)(filter_expr_user_data, "%c is undefined for type %s", op->kind,
             filter_tree_type_to_str(p2->type));
    return MKINT(0);
  }
  if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_INT) {
    op->type = FILTER_TYPE_INT;
  } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_SIZE) {
    op->type = FILTER_TYPE_INT;
  } else if (p1->type == FILTER_TYPE_DUR && p2->type == FILTER_TYPE_DUR) {
    op->type = FILTER_TYPE_INT;
  } else if (p1->type == FILTER_TYPE_SIZE && p2->type == FILTER_TYPE_INT) {
    op->type = FILTER_TYPE_SIZE;
  } else if (p1->type == FILTER_TYPE_DUR && p2->type == FILTER_TYPE_INT) {
    op->type = FILTER_TYPE_DUR;
  } else {
    (*filter_expr_parse_err)(filter_expr_user_data, "invalid arguments of %c", op->kind);
    return MKINT(0);
  }

  if (filter_tree_is_value_node(p1) && filter_tree_is_value_node(p2)) {
    struct filter_tree *res = MKINT(0);
    int r;

    r = filter_tree_eval_node(filter_expr_tree_mem, op->kind, res, p1, p2);
    if (r < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
    return res;
  }

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

  if (p1->type != FILTER_TYPE_INT && p1->type != FILTER_TYPE_DUR
      && p1->type != FILTER_TYPE_SIZE) {
    (*filter_expr_parse_err)(filter_expr_user_data, "* is undefined for type %s",
             filter_tree_type_to_str(p1->type));
    return MKINT(0);
  }
  if (p2->type != FILTER_TYPE_INT && p2->type != FILTER_TYPE_DUR
      && p2->type != FILTER_TYPE_SIZE) {
    (*filter_expr_parse_err)(filter_expr_user_data, "* is undefined for type %s",
             filter_tree_type_to_str(p2->type));
    return MKINT(0);
  }
  if (p1->type == FILTER_TYPE_INT && p2->type == FILTER_TYPE_INT) {
  } else if (p1->type == FILTER_TYPE_INT) {
    tree_t tmp = p1;
    p1 = p2;
    p2 = tmp;
  } else if (p2->type == FILTER_TYPE_INT) {
  } else {
    (*filter_expr_parse_err)(filter_expr_user_data, "one argument of * must be of type int");
    return MKINT(0);
  }

  if (filter_tree_is_value_node(p1) && filter_tree_is_value_node(p2)) {
    struct filter_tree *res = MKINT(0);
    int r;

    r = filter_tree_eval_node(filter_expr_tree_mem, '*', res, p1, p2);
    if (r < 0) (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
    return res;
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
  ASSERT(p);
  if (p->kind == FILTER_TYPE_INT)
    return p;
  if (filter_tree_is_value_node(p)) {
    struct filter_tree res;
    int r;

    if ((r = filter_tree_eval_node(filter_expr_tree_mem, TOK_INT, &res, p, 0)) < 0) {
      (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
      return MKINT(0);
    }
    return MKINT(res.v.b);
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

  if (p->type == FILTER_TYPE_BOOL)
    return p;

  if (filter_tree_is_value_node(p)) {
    struct filter_tree res;
    int r;

    if ((r = filter_tree_eval_node(filter_expr_tree_mem, TOK_BOOL, &res, p, 0)) < 0) {
      (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
      return MKBOOL(0);
    }
    return MKBOOL(res.v.b);
  }

  q->v.t[0] = p;
  q->kind = TOK_BOOL;
  q->type = FILTER_TYPE_BOOL;
  return q;
}

static tree_t
do_string_cast(tree_t q, tree_t p)
{
  ASSERT(p);
  if (p->type == FILTER_TYPE_STRING)
    return p;
  if (filter_tree_is_value_node(p)) {
    struct filter_tree res;
    int r;

    if ((r = filter_tree_eval_node(filter_expr_tree_mem, TOK_STRING, &res, p, 0)) < 0) {
      (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
      return MKSTRING("");
    }
    return MKSTRING2(res.v.s);
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

    if ((r = filter_tree_eval_node(filter_expr_tree_mem, TOK_DUR_T, &res, p, 0)) < 0) {
      (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
      return MKDUR(0);
    }
    return MKDUR(res.v.u);
  }
  if (p->type != FILTER_TYPE_INT
      && p->type != FILTER_TYPE_STRING) {
    (*filter_expr_parse_err)(filter_expr_user_data, "expression of type %s cannot be converted to dur_t",
             filter_tree_type_to_str(p->type));
    return MKDUR(0);
  }
  q->v.t[0] = p;
  q->kind = TOK_DUR_T;
  q->type = FILTER_TYPE_DUR;
  return q;
}

static tree_t
do_time_cast(tree_t q, tree_t p)
{
  int r;

  if (p->type == FILTER_TYPE_TIME) {
    return p;
  }
  if (p->kind == TOK_INT_L || p->kind == TOK_STRING_L) {
    struct filter_tree res;

    if ((r = filter_tree_eval_node(filter_expr_tree_mem, TOK_TIME_T, &res, p, 0)) < 0) {
      (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
      return MKTIME(0);
    }
    return MKTIME(res.v.a);
  }
  if (p->type != FILTER_TYPE_INT
      && p->type != FILTER_TYPE_STRING) {
    (*filter_expr_parse_err)(filter_expr_user_data, "expression of type %s cannot be converted to time_t",
             filter_tree_type_to_str(p->type));
    return MKTIME(0);
  }
  q->v.t[0] = p;
  q->kind = TOK_TIME_T;
  q->type = FILTER_TYPE_TIME;
  return q;
}

static tree_t
do_size_cast(tree_t q, tree_t p)
{
  int r;

  if (p->type == FILTER_TYPE_SIZE) {
    return p;
  }
  if (p->kind == TOK_STRING_L || p->kind == TOK_INT_L) {
    struct filter_tree res;

    if ((r = filter_tree_eval_node(filter_expr_tree_mem, TOK_SIZE_T, &res, p, 0)) < 0) {
      (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
      return MKSIZE(0);
    }
    return MKSIZE(res.v.z);
  }
  if (p->type != FILTER_TYPE_STRING && p->type != FILTER_TYPE_INT) {
    (*filter_expr_parse_err)(filter_expr_user_data, "expression of type %s cannot be converted to size_t",
             filter_tree_type_to_str(p->type));
    return MKSIZE(0);
  }
  q->v.t[0] = p;
  q->kind = TOK_SIZE_T;
  q->type = FILTER_TYPE_SIZE;
  return q;
}

static tree_t
do_result_cast(tree_t q, tree_t p)
{
  int r;

  if (p->type == FILTER_TYPE_RESULT) {
    return p;
  }
  if (p->kind == TOK_STRING_L || p->kind == TOK_INT_L) {
    struct filter_tree res;

    if ((r = filter_tree_eval_node(filter_expr_tree_mem, TOK_RESULT_T, &res, p, 0)) < 0) {
      (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
      return MKRESULT(0);
    }
    return MKRESULT(res.v.r);
  }
  if (p->type != FILTER_TYPE_STRING && p->type != FILTER_TYPE_INT) {
    (*filter_expr_parse_err)(filter_expr_user_data, "expression of type %s cannot be converted to result_t",
             filter_tree_type_to_str(p->type));
    return MKRESULT(0);
  }
  q->v.t[0] = p;
  q->kind = TOK_RESULT_T;
  q->type = FILTER_TYPE_RESULT;
  return q;
}

static tree_t
do_hash_cast(tree_t q, tree_t p)
{
  int r;

  if (p->type == FILTER_TYPE_HASH) {
    return p;
  }
  if (p->kind == TOK_STRING_L) {
    struct filter_tree res;

    if ((r = filter_tree_eval_node(filter_expr_tree_mem, TOK_HASH_T, &res, p, 0)) < 0) {
      (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
      return MKHASH(0);
    }
    return MKHASH(res.v.h);
  }
  if (p->type != FILTER_TYPE_STRING) {
    (*filter_expr_parse_err)(filter_expr_user_data, "expression of type %s cannot be converted to hash_t",
             filter_tree_type_to_str(p->type));
    return MKHASH(0);
  }
  q->v.t[0] = p;
  q->kind = TOK_HASH_T;
  q->type = FILTER_TYPE_HASH;
  return q;
}

static tree_t
do_ip_cast(tree_t q, tree_t p)
{
  int r;

  if (p->type == FILTER_TYPE_IP) {
    return p;
  }
  if (p->kind == TOK_STRING_L || p->kind == TOK_INT_L) {
    struct filter_tree res;

    if ((r = filter_tree_eval_node(filter_expr_tree_mem, TOK_IP_T, &res, p, 0)) < 0) {
      (*filter_expr_parse_err)(filter_expr_user_data, "%s", filter_strerror(-r));
      return MKIP(0);
    }
    return MKIP(res.v.p);
  }
  if (p->type != FILTER_TYPE_STRING && p->type != FILTER_TYPE_INT) {
    (*filter_expr_parse_err)(filter_expr_user_data, "expression of type %s cannot be converted to ip_t",
             filter_tree_type_to_str(p->type));
    return MKIP(0);
  }
  q->v.t[0] = p;
  q->kind = TOK_IP_T;
  q->type = FILTER_TYPE_IP;
  return q;
}

static void
yyerror(unsigned char const *msg)
{
  (*filter_expr_parse_err)(filter_expr_user_data, "%s", msg);
}

void
filter_expr_init_parser(struct filter_tree_mem *mem,
                        void (*errfunc)(void *, unsigned char const *, ...),
                        void *user_data)
{
  filter_expr_tree_mem = mem;
  filter_expr_parse_err = errfunc;
  filter_expr_user_data = user_data;
  if (!filter_expr_parse_err) filter_expr_parse_err = do_error;
  //yydebug = 1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "jmp_buf")
 * End:
 */
