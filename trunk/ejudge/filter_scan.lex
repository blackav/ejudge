/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002,2003 Alexander Chernov <cher@ispras.ru> */

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
#define YYSTYPE struct filter_tree *

#include "filter_expr.h"
#include "filter_tree.h"
#include "runlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

extern int filter_expr_nerrs;

static unsigned char *scan_buf;
static size_t scan_len;
static size_t scan_read;
static void (*scan_err)(unsigned char const *, ...);

static struct filter_tree_mem *tree_mem;

#define TT(t,y) filter_expr_lval = filter_tree_new_node(tree_mem, t, y, 0, 0); return t
#define T(t) filter_expr_lval = filter_tree_new_node(tree_mem, t, 0, 0, 0); return t
#define TR(r) filter_expr_lval = filter_tree_new_result(tree_mem, r); return TOK_RESULT_L

#define YY_INPUT(buf,result,max_size) do { if (scan_read >= scan_len) result = YY_NULL; else if (scan_len - scan_read > max_size) { memcpy(buf, scan_buf + scan_read, max_size); scan_read += max_size; result = max_size; } else { memcpy(buf, scan_buf + scan_read, scan_len - scan_read); result = scan_len - scan_read; scan_read = scan_len; } } while (0)

static void handle_int(void);

%}
ws      [\000-\040]
hexd    [0-9a-fA-F]
octd    [0-7]
decd    [0-9]
%option noyywrap
%%
"||" { T(TOK_LOGOR); }
"or" { T(TOK_LOGOR); }
"&&" { T(TOK_LOGAND); }
"and" { T(TOK_LOGAND); }
"==" { T(TOK_EQ); }
"!=" { T(TOK_NE); }
"<=" { T(TOK_LE); }
">=" { T(TOK_GE); }
"<<" { T(TOK_ASL); }
">>" { T(TOK_ASR); }

"^" |
"|" |
"&" |
"*" |
"/" |
"%" |
"~" |
"!" |
"(" |
")" |
"+" |
"-" |
">" |
"<" { T(*yytext); }

"id" { TT(TOK_ID, FILTER_TYPE_INT); }
"time" { TT(TOK_TIME, FILTER_TYPE_TIME); }
"curtime" { TT(TOK_CURTIME, FILTER_TYPE_TIME); }
"dur" { TT(TOK_DUR, FILTER_TYPE_DUR); }
"curdur" { TT(TOK_CURDUR, FILTER_TYPE_DUR); }
"size" { TT(TOK_SIZE, FILTER_TYPE_SIZE); }
"cursize" { TT(TOK_CURSIZE, FILTER_TYPE_SIZE); }
"hash" { TT(TOK_HASH, FILTER_TYPE_HASH); }
"curhash" { TT(TOK_CURHASH, FILTER_TYPE_HASH); }
"ip" { TT(TOK_IP, FILTER_TYPE_IP); }
"curip" { TT(TOK_CURIP, FILTER_TYPE_IP); }
"uid" { TT(TOK_UID, FILTER_TYPE_INT); }
"curuid" { TT(TOK_CURUID, FILTER_TYPE_INT); }
"login" { TT(TOK_LOGIN, FILTER_TYPE_STRING); }
"curlogin" { TT(TOK_CURLOGIN, FILTER_TYPE_STRING); }
"lang" { TT(TOK_LANG, FILTER_TYPE_STRING); }
"curlang" { TT(TOK_CURLANG, FILTER_TYPE_STRING); }
"prob" { TT(TOK_PROB, FILTER_TYPE_STRING); }
"curprob" { TT(TOK_CURPROB, FILTER_TYPE_STRING); }
"result" { TT(TOK_RESULT, FILTER_TYPE_RESULT); }
"curresult" { TT(TOK_CURRESULT, FILTER_TYPE_RESULT); }
"status" { TT(TOK_RESULT, FILTER_TYPE_RESULT); }
"curstatus" { TT(TOK_CURRESULT, FILTER_TYPE_RESULT); }
"score" { TT(TOK_SCORE, FILTER_TYPE_INT); }
"curscore" { TT(TOK_CURSCORE, FILTER_TYPE_INT); }
"test" { TT(TOK_TEST, FILTER_TYPE_INT); }
"curtest" { TT(TOK_CURTEST, FILTER_TYPE_INT); }
"now" { TT(TOK_NOW, FILTER_TYPE_TIME); }
"start" { TT(TOK_START, FILTER_TYPE_TIME); }
"finish" { TT(TOK_FINISH, FILTER_TYPE_TIME); }
"total" { TT(TOK_TOTAL, FILTER_TYPE_INT); }
"imported" { TT(TOK_IMPORTED, FILTER_TYPE_BOOL); }
"curimported" { TT(TOK_CURIMPORTED, FILTER_TYPE_BOOL); }
"hidden" { TT(TOK_HIDDEN, FILTER_TYPE_BOOL); }
"curhidden" { TT(TOK_CURHIDDEN, FILTER_TYPE_BOOL); }
"readonly" { TT(TOK_READONLY, FILTER_TYPE_BOOL); }
"curreadonly" { TT(TOK_CURREADONLY, FILTER_TYPE_BOOL); }
"variant" { TT(TOK_VARIANT, FILTER_TYPE_INT); }
"curvariant" { TT(TOK_CURVARIANT, FILTER_TYPE_INT); }
"rawvariant" { TT(TOK_RAWVARIANT, FILTER_TYPE_INT); }
"currawvariant" { TT(TOK_CURRAWVARIANT, FILTER_TYPE_INT); }

"int" { TT(TOK_INT, FILTER_TYPE_INT); }
"string" { TT(TOK_STRING, FILTER_TYPE_STRING); }
"bool" { TT(TOK_BOOL, FILTER_TYPE_BOOL); }
"time_t" { TT(TOK_TIME_T, FILTER_TYPE_TIME); }
"dur_t" { TT(TOK_DUR_T, FILTER_TYPE_DUR); }
"size_t" { TT(TOK_SIZE_T, FILTER_TYPE_SIZE); }
"result_t" { TT(TOK_RESULT_T, FILTER_TYPE_RESULT); }
"hash_t" { TT(TOK_HASH_T, FILTER_TYPE_HASH); }
"ip_t" { TT(TOK_IP_T, FILTER_TYPE_IP); }

"true" { filter_expr_lval = filter_tree_new_bool(tree_mem, 1); return TOK_BOOL_L; }
"false" { filter_expr_lval = filter_tree_new_bool(tree_mem, 0); return TOK_BOOL_L; }

"OK" { TR(RUN_OK); }
"CE" { TR(RUN_COMPILE_ERR); }
"RT" { TR(RUN_RUN_TIME_ERR); }
"TL" { TR(RUN_TIME_LIMIT_ERR); }
"PE" { TR(RUN_PRESENTATION_ERR); }
"WA" { TR(RUN_WRONG_ANSWER_ERR); }
"CF" { TR(RUN_CHECK_FAILED); }
"PT" { TR(RUN_PARTIAL); }
"AC" { TR(RUN_ACCEPTED); }
"IG" { TR(RUN_IGNORED); }
"RU" { TR(RUN_RUNNING); }
"CD" { TR(RUN_COMPILED); }
"CG" { TR(RUN_COMPILING); }
"AV" { TR(RUN_AVAILABLE); }
"RJ" { TR(RUN_REJUDGE); }
"EM" { TR(RUN_EMPTY); }

0[xX]{hexd}+ { handle_int(); return TOK_INT_L; }
0{octd}* { handle_int(); return TOK_INT_L; }
[1-9]{decd}* { handle_int(); return TOK_INT_L; }

{ws}+ {}

\"[^\"]*\" |
\'[^\']*\' { filter_expr_lval = filter_tree_new_buf(tree_mem, yytext + 1, yyleng - 2); return TOK_STRING_L; }

. { (*scan_err)("invalid character \\%03o", (unsigned char) *yytext); }
%%

static void
handle_int(void)
{
  unsigned char *buf, *eptr;
  int val;

  buf = alloca(yyleng + 16);
  memset(buf, 0, yyleng + 16);
  memcpy(buf, yytext, yyleng);
  errno = 0;
  val = strtol(buf, (char**) &eptr, 0);
  if (errno) {
    (*scan_err)("value is out of range");
    val = 0;
  }
  filter_expr_lval = filter_tree_new_int(tree_mem, val);
}

static void
local_err_func(unsigned char const *format, ...)
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  filter_expr_nerrs++;
}

void
filter_expr_set_string(unsigned char const *str,
                       struct filter_tree_mem *mem,
                       void (*errfnc)(unsigned char const *, ...))
{
  (void) &yyunput;

  yyrestart(0);
  BEGIN(INITIAL);
  scan_buf = (unsigned char*) str;
  scan_len = strlen(str);
  scan_read = 0;
  scan_err = errfnc;
  tree_mem = mem;
  if (!scan_err) {
    scan_err = local_err_func;
  }
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
