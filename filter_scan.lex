/* -*- mode: fundamental -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/filter_expr.h"
#include "ejudge/filter_tree.h"
#include "ejudge/runlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

static int input() __attribute__((unused));

extern int filter_expr_nerrs;

/* NOTE: scanner uses lost of static variables during its operation,
 *       so, it should be used with care.
 */
static unsigned char *filter_scan_buf;
static size_t filter_scan_len;
static size_t filter_scan_read;
static void (*filter_scan_err)(void *, unsigned char const *, ...);
static struct filter_tree_mem *filter_scan_tree_mem;
static void *filter_scan_user_data;

#define TT(t,y) filter_expr_lval = filter_tree_new_node(filter_scan_tree_mem, t, y, 0, 0); return t
#define T(t) filter_expr_lval = filter_tree_new_node(filter_scan_tree_mem, t, 0, 0, 0); return t
#define TR(r) filter_expr_lval = filter_tree_new_result(filter_scan_tree_mem, r); return TOK_RESULT_L

#define YY_INPUT(buf,result,max_size) do { if (filter_scan_read >= filter_scan_len) result = YY_NULL; else if (filter_scan_len - filter_scan_read > max_size) { memcpy(buf, filter_scan_buf + filter_scan_read, max_size); filter_scan_read += max_size; result = max_size; } else { memcpy(buf, filter_scan_buf + filter_scan_read, filter_scan_len - filter_scan_read); result = filter_scan_len - filter_scan_read; filter_scan_read = filter_scan_len; } } while (0)

static void handle_int(void);

%}
ws      [\000-\040]
hexd    [0-9a-fA-F]
octd    [0-7]
decd    [0-9]
lett    [A-Za-z_]
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
"~=" { T(TOK_REGEXP); }

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
"run_id" { TT(TOK_ID, FILTER_TYPE_INT); }
"time" { TT(TOK_TIME, FILTER_TYPE_TIME); }
"curtime" { TT(TOK_CURTIME, FILTER_TYPE_TIME); }
"dur" { TT(TOK_DUR, FILTER_TYPE_DUR); }
"curdur" { TT(TOK_CURDUR, FILTER_TYPE_DUR); }
"size" { TT(TOK_SIZE, FILTER_TYPE_SIZE); }
"cursize" { TT(TOK_CURSIZE, FILTER_TYPE_SIZE); }
"hash" { TT(TOK_HASH, FILTER_TYPE_HASH); }
"curhash" { TT(TOK_CURHASH, FILTER_TYPE_HASH); }
"uuid" { TT(TOK_UUID, FILTER_TYPE_STRING); }
"curuuid" { TT(TOK_CURUUID, FILTER_TYPE_STRING); }
"ip" { TT(TOK_IP, FILTER_TYPE_IP); }
"curip" { TT(TOK_CURIP, FILTER_TYPE_IP); }
"uid" { TT(TOK_UID, FILTER_TYPE_INT); }
"user_id" { TT(TOK_UID, FILTER_TYPE_INT); }
"curuid" { TT(TOK_CURUID, FILTER_TYPE_INT); }
"curuser_id" { TT(TOK_CURUID, FILTER_TYPE_INT); }
"login" { TT(TOK_LOGIN, FILTER_TYPE_STRING); }
"curlogin" { TT(TOK_CURLOGIN, FILTER_TYPE_STRING); }
"name" { TT(TOK_NAME, FILTER_TYPE_STRING); }
"curname" { TT(TOK_CURNAME, FILTER_TYPE_STRING); }
"group" { TT(TOK_GROUP, FILTER_TYPE_STRING); }
"curgroup" { TT(TOK_CURGROUP, FILTER_TYPE_STRING); }
"lang" { TT(TOK_LANG, FILTER_TYPE_STRING); }
"lang_id" { TT(TOK_LANG, FILTER_TYPE_STRING); }
"curlang" { TT(TOK_CURLANG, FILTER_TYPE_STRING); }
"curlang_id" { TT(TOK_CURLANG, FILTER_TYPE_STRING); }
"arch" { TT(TOK_ARCH, FILTER_TYPE_STRING); }
"curarch" { TT(TOK_CURARCH, FILTER_TYPE_STRING); }
"prob" { TT(TOK_PROB, FILTER_TYPE_STRING); }
"prob_id" { TT(TOK_PROB, FILTER_TYPE_STRING); }
"curprob" { TT(TOK_CURPROB, FILTER_TYPE_STRING); }
"curprob_id" { TT(TOK_CURPROB, FILTER_TYPE_STRING); }
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
"marked" { TT(TOK_MARKED, FILTER_TYPE_BOOL); }
"curmarked" { TT(TOK_CURMARKED, FILTER_TYPE_BOOL); }
"saved" { TT(TOK_SAVED, FILTER_TYPE_BOOL); }
"cursaved" { TT(TOK_CURSAVED, FILTER_TYPE_BOOL); }
"variant" { TT(TOK_VARIANT, FILTER_TYPE_INT); }
"curvariant" { TT(TOK_CURVARIANT, FILTER_TYPE_INT); }
"rawvariant" { TT(TOK_RAWVARIANT, FILTER_TYPE_INT); }
"currawvariant" { TT(TOK_CURRAWVARIANT, FILTER_TYPE_INT); }
"userinvisible" { TT(TOK_USERINVISIBLE, FILTER_TYPE_BOOL); }
"curuserinvisible" { TT(TOK_CURUSERINVISIBLE, FILTER_TYPE_BOOL); }
"userbanned" { TT(TOK_USERBANNED, FILTER_TYPE_BOOL); }
"curuserbanned" { TT(TOK_CURUSERBANNED, FILTER_TYPE_BOOL); }
"userlocked" { TT(TOK_USERLOCKED, FILTER_TYPE_BOOL); }
"curuserlocked" { TT(TOK_CURUSERLOCKED, FILTER_TYPE_BOOL); }
"userincomplete" { TT(TOK_USERINCOMPLETE, FILTER_TYPE_BOOL); }
"curuserincomplete" { TT(TOK_CURUSERINCOMPLETE, FILTER_TYPE_BOOL); }
"userdisqualified" { TT(TOK_USERDISQUALIFIED, FILTER_TYPE_BOOL); }
"curuserdisqualified" { TT(TOK_CURUSERDISQUALIFIED, FILTER_TYPE_BOOL); }
"latest" { TT(TOK_LATEST, FILTER_TYPE_BOOL); }
"curlatest" { TT(TOK_CURLATEST, FILTER_TYPE_BOOL); }
"latestmarked" { TT(TOK_LATESTMARKED, FILTER_TYPE_BOOL); }
"curlatestmarked" { TT(TOK_CURLATESTMARKED, FILTER_TYPE_BOOL); }
"afterok" { TT(TOK_AFTEROK, FILTER_TYPE_BOOL); }
"curafterok" { TT(TOK_CURAFTEROK, FILTER_TYPE_BOOL); }
"examinable" { TT(TOK_EXAMINABLE, FILTER_TYPE_BOOL); }
"curexaminable" { TT(TOK_CUREXAMINABLE, FILTER_TYPE_BOOL); }
"examinator" { TT(TOK_EXAMINATOR, FILTER_TYPE_BOOL); }
"curexaminator" { TT(TOK_CUREXAMINATOR, FILTER_TYPE_BOOL); }
"cypher" { TT(TOK_CYPHER, FILTER_TYPE_STRING); }
"curcypher" { TT(TOK_CURCYPHER, FILTER_TYPE_STRING); }
"missingsource" { TT(TOK_MISSINGSOURCE, FILTER_TYPE_BOOL); }
"curmissingsource" { TT(TOK_CURMISSINGSOURCE, FILTER_TYPE_BOOL); }
"judge_id" { TT(TOK_JUDGE_ID, FILTER_TYPE_INT); }
"curjudge_id" { TT(TOK_CURJUDGE_ID, FILTER_TYPE_INT); }
"total_score" { TT(TOK_TOTAL_SCORE, FILTER_TYPE_INT); }
"inusergroup" { TT(TOK_INUSERGROUP, FILTER_TYPE_BOOL); }
"passed_mode" { TT(TOK_PASSED_MODE, FILTER_TYPE_BOOL); }
"curpassed_mode" { TT(TOK_CURPASSED_MODE, FILTER_TYPE_BOOL); }
"eoln_type" { TT(TOK_EOLN_TYPE, FILTER_TYPE_INT); }
"cureoln_type" { TT(TOK_CUREOLN_TYPE, FILTER_TYPE_INT); }
"store_flags" { TT(TOK_STORE_FLAGS, FILTER_TYPE_INT); }
"curstore_flags" { TT(TOK_CURSTORE_FLAGS, FILTER_TYPE_INT); }
"token_flags" { TT(TOK_TOKEN_FLAGS, FILTER_TYPE_INT); }
"curtoken_flags" { TT(TOK_CURTOKEN_FLAGS, FILTER_TYPE_INT); }
"token_count" { TT(TOK_TOKEN_COUNT, FILTER_TYPE_INT); }
"curtoken_count" { TT(TOK_CURTOKEN_COUNT, FILTER_TYPE_INT); }

"int" { TT(TOK_INT, FILTER_TYPE_INT); }
"string" { TT(TOK_STRING, FILTER_TYPE_STRING); }
"bool" { TT(TOK_BOOL, FILTER_TYPE_BOOL); }
"time_t" { TT(TOK_TIME_T, FILTER_TYPE_TIME); }
"dur_t" { TT(TOK_DUR_T, FILTER_TYPE_DUR); }
"size_t" { TT(TOK_SIZE_T, FILTER_TYPE_SIZE); }
"result_t" { TT(TOK_RESULT_T, FILTER_TYPE_RESULT); }
"hash_t" { TT(TOK_HASH_T, FILTER_TYPE_HASH); }
"ip_t" { TT(TOK_IP_T, FILTER_TYPE_IP); }

"true" { filter_expr_lval = filter_tree_new_bool(filter_scan_tree_mem, 1); return TOK_BOOL_L; }
"false" { filter_expr_lval = filter_tree_new_bool(filter_scan_tree_mem, 0); return TOK_BOOL_L; }

[Oo][Kk] { TR(RUN_OK); }
[Cc][Ee] { TR(RUN_COMPILE_ERR); }
[Rr][Tt] { TR(RUN_RUN_TIME_ERR); }
[Tt][Ll] { TR(RUN_TIME_LIMIT_ERR); }
[Pp][Ee] { TR(RUN_PRESENTATION_ERR); }
[Ww][Aa] { TR(RUN_WRONG_ANSWER_ERR); }
[Cc][Ff] { TR(RUN_CHECK_FAILED); }
[Pp][Tt] { TR(RUN_PARTIAL); }
[Aa][Cc] { TR(RUN_ACCEPTED); }
[Ii][Gg] { TR(RUN_IGNORED); }
[Dd][Qq] { TR(RUN_DISQUALIFIED); }
[Pp][Dd] { TR(RUN_PENDING); }
[Mm][Ll] { TR(RUN_MEM_LIMIT_ERR); }
[Ss][Ee] { TR(RUN_SECURITY_ERR); }
[Ss][Vv] { TR(RUN_STYLE_ERR); }
[Ww][Tt] { TR(RUN_WALL_TIME_LIMIT_ERR); }
[Rr][Jj] { TR(RUN_REJECTED); }
[Pp][Rr] { TR(RUN_PENDING_REVIEW); }
[Rr][Uu] { TR(RUN_RUNNING); }
[Cc][Dd] { TR(RUN_COMPILED); }
[Cc][Gg] { TR(RUN_COMPILING); }
[Aa][Vv] { TR(RUN_AVAILABLE); }
[Ee][Mm] { TR(RUN_EMPTY); }
[Vv][Ss] { TR(RUN_VIRTUAL_START); }
[Vv][Tt] { TR(RUN_VIRTUAL_STOP); }

0[xX]{hexd}+ { handle_int(); return TOK_INT_L; }
0{octd}* { handle_int(); return TOK_INT_L; }
[1-9]{decd}* { handle_int(); return TOK_INT_L; }

{ws}+ {}

\"[^\"]*\" |
\'[^\']*\' { filter_expr_lval = filter_tree_new_buf(filter_scan_tree_mem, yytext + 1, yyleng - 2); return TOK_STRING_L; }

{lett}+ { (*filter_scan_err)(filter_scan_user_data, "invalid keyword `%.*s'", yyleng, yytext); }
[\040-\377] { (*filter_scan_err)(filter_scan_user_data, "invalid character `%c'", *yytext); }

%%

static void
handle_int(void)
{
  unsigned char *buf;
  int val;
  char *tmpeptr = 0;

  buf = alloca(yyleng + 16);
  memset(buf, 0, yyleng + 16);
  memcpy(buf, yytext, yyleng);
  errno = 0;
  val = strtol(buf, &tmpeptr, 0);
  if (errno) {
    (*filter_scan_err)(filter_scan_user_data, "value is out of range");
    val = 0;
  }
  filter_expr_lval = filter_tree_new_int(filter_scan_tree_mem, val);
}

static void
local_err_func(void *data, unsigned char const *format, ...)
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
                       void (*errfnc)(void *, unsigned char const *, ...),
                       void *user_data)
{
  (void) &yyunput;

  yyrestart(0);
  BEGIN(INITIAL);
  filter_scan_buf = (unsigned char*) str;
  filter_scan_len = strlen(str);
  filter_scan_read = 0;
  filter_scan_err = errfnc;
  filter_scan_tree_mem = mem;
  filter_scan_user_data = user_data;
  if (!filter_scan_err) {
    filter_scan_err = local_err_func;
  }
}
