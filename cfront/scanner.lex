/* -*- mode:c -*- */

/* Copyright (C) 2003-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "tree.h"
#include "c_errors.h"
#include "typedef.h"
#include "scanner.h"

#include "ejudge/xalloc.h"
#include "ejudge/number_io.h"
#include "ejudge/logger.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <wchar.h>
#include <ctype.h>

#if defined __MINGW32__
#include <malloc.h>
#endif

  /* various flags */
enum
  {
    LT_UNSIGNED = 1,
    LT_LONG = 2,
    LT_LONGLONG = 4,
    LT_FLOAT = 8,
    LT_IMAG = 16,
  };

/* the current position */
static pos_t curpos;
/* the start position of the current token */
static pos_t stpos;

/* a temporary buffer for by-one additions */
#define IBUF_SIZE 512
static unsigned char ibuf[IBUF_SIZE];
static int ibuf_cur;

/* a temporary buffer for complex cases (strings, characters) */
static unsigned char *buf_p;
static int buf_u, buf_a;

/* what character terminates the string (', ") */
static int str_endchar;
static int str_endstate;
static int curtok;
static ident_t curid;

/* flags for # directive */
enum
  {
    HF_START = 1,
    HF_RETURN = 2,
    HF_SYSTEM = 4,
    HF_C = 8,
  };
static int hashline_flags;
static int hashline_lineno;

static void ibuf_flush(void);
static void buf_yytext_append(void);
static void handle_integral(int start, int end, int base, int flags);
static void handle_float(int start, int end, int base, int flags);

#define ibuf_add(c) do { if (ibuf_cur >= IBUF_SIZE) ibuf_flush(); ibuf[ibuf_cur++] = (c); } while (0)
#define adjust_tab() (curpos.column = ((curpos.column + 8) & ~7))

static int  hex2int(int c);
static void handle_lstring(wchar_t endchar);

static int initialized = 0;

#ifdef __MSVCRT__
/*
size_t __cdecl mbrtowc(wchar_t *a, const char *b, size_t c, mbstate_t *d)
{
  SWERR(("oops, mbrtowc is not implemented"));
} */
#endif

%}
id0     [A-Za-z_\$]
id1     [A-Za-z0-9_\$]
d0      [1-9]
dd      [0-9]
dx      [0-9a-fA-F]
d8      [0-7]
sp      [ \t]
%option noyywrap
%x STR CMT PP1 PP2 PP3 PP4 ANNOT LSTR
%%

^{sp}*"#"{sp}* {
#if 0
  {
    int i;

    /* adjust position */
    for (i = 0; i < yyleng; i++) {
      if (yytext[i] == '\t') {
        adjust_tab();
      } else {
        curpos.column++;
      }
    }
  }
#endif 
  BEGIN(PP1);
}

<PP1>"pragma" {
  /* no #pragma's are currently handled */
  BEGIN(PP2);
}
<PP1>"ident" {
  /* what is this? */
  BEGIN(PP2);
}
<PP1>{dd}+ {
  hashline_lineno = 0;
  hashline_flags = 0;
  {
    unsigned char *buf = 0;
    buf = (unsigned char*) alloca(yyleng + 1);
    memset(buf, 0, yyleng + 1);
    memcpy(buf, yytext, yyleng);
    errno = 0;
    hashline_lineno = strtol(buf, 0, 10);
    if (errno) {
      /* issue a warning */
      BEGIN(PP2);
    } else {
      BEGIN(PP3);
    }
  }
}
<PP1>{id0}{id1}* {
  /* FIXME: issue a warning? */
  BEGIN(PP2);
}
<PP1>. {
  /* FIXME: issue a warning? */
  BEGIN(PP2);
}
<PP1>\n {
  curpos.column = 0;
  curpos.line++;
  BEGIN(INITIAL);
}
<PP1><<EOF>> {
  BEGIN(INITIAL);
}

<PP2>\n {
  curpos.column = 0;
  curpos.line++;
  BEGIN(INITIAL);
}
<PP2>.+ {
}
<PP2><<EOF>> {
  BEGIN(INITIAL);
}

<PP3>\" {
  str_endchar = '\"';
  str_endstate = PP4;
  BEGIN(STR);
}
<PP3>\n {
  curpos.column = 0;
  curpos.line = hashline_lineno;
  BEGIN(INITIAL);
}
<PP3>[ \t]+ {
}
<PP3>. {
  BEGIN(PP2);
}
<PP3><<EOF>> {
  BEGIN(INITIAL);
}

<PP4>\n {
  pos_set(&curpos, buf_p, hashline_lineno, 0);
  buf_u = 0;
  *buf_p = 0;
  BEGIN(INITIAL);
}
<PP4>[ \t]+ {
}
<PP4>1 {
  hashline_flags |= HF_START;
}
<PP4>2 {
  hashline_flags |= HF_RETURN;
}
<PP4>3 {
  hashline_flags |= HF_SYSTEM;
}
<PP4>4 {
  hashline_flags |= HF_C;
}
<PP4>. {
  BEGIN(PP2);
}
<PP4><<EOF>> {
  BEGIN(INITIAL);
}

 /* line comments */
"//".*\n {
  curpos.column = 0;
  curpos.line++;
}

 /* block comments */
"/*" {
  curpos.column += 2;
  BEGIN(CMT);
}

<CMT>"*/" {
  curpos.column += 2;
  BEGIN(INITIAL);
}
<CMT>\t {
  adjust_tab();
}
<CMT>\r {
  curpos.column = 0;
}
<CMT>\n {
  curpos.column = 0;
  curpos.line++;
}
<CMT>[\040-\051\053-\377]+ {
  curpos.column += yyleng;
}
<CMT>[\0-\037] {
  curpos.column++;
}
<CMT>"*" {
  curpos.column++;
}
<CMT><<EOF>> {
  /* issue an error */
}

 /* annotation comment */
"/*LAL" {
  stpos = curpos;
  curpos.column += 5;
  BEGIN(ANNOT);
  yylval = tree_make_token(TOK___ANNOT, &stpos, &curpos);
  return TOK___ANNOT;
}

<ANNOT>"*/" {
  curpos.column += 2;
  ibuf_add(0);
  ibuf_flush();
  yylval = tree_make_string(TOK_STRING, &stpos, &curpos, buf_p, buf_u);
  buf_u = 0;
  *buf_p = 0;
  BEGIN(INITIAL);
  return TOK_STRING;
}
<ANNOT>\t {
  adjust_tab();
  ibuf_add('\t');
}
<ANNOT>\r {
  curpos.column = 0;
  ibuf_add('\r');
}
<ANNOT>\n {
  curpos.column = 0;
  curpos.line++;
  ibuf_add('\n');
}
<ANNOT>[\040-\051\053-\377]+ {
  curpos.column += yyleng;
  buf_yytext_append();
}
<ANNOT>[\0-\037] {
  curpos.column++;
  ibuf_add(*yytext);
}
<ANNOT>"*" {
  curpos.column++;
  ibuf_add(*yytext);
}
<ANNOT><<EOF>> {
  c_err(&curpos, "end-of-file inside of annotation specification");
  ibuf_add(0);
  ibuf_flush();
  yylval = tree_make_string(TOK_STRING, &stpos, &curpos, buf_p, buf_u);
  buf_u = 0;
  *buf_p = 0;
  BEGIN(INITIAL);
  return TOK_STRING;
}

 /* wide string literals */
L\" {
  stpos = curpos;
  curpos.column += 2;
  handle_lstring(L'\"');
  return TOK_LSTRING;
}

 /* wide character literals */
L\' {
  stpos = curpos;
  curpos.column += 2;
  handle_lstring(L'\'');
  return TOK_CONSTANT;
}

 /* string literals */
\" {
  str_endchar = '\"';
  str_endstate = INITIAL;
  stpos = curpos;
  curpos.column++;
  BEGIN(STR);
}

 /* character literals */
\' {
  str_endchar = '\'';
  str_endstate = INITIAL;
  stpos = curpos;
  curpos.column++;
  BEGIN(STR);
}

<STR>\" {
  if (str_endchar == '\"') {
    ibuf_add(0);
    ibuf_flush();
    if (str_endstate == INITIAL) {
      yylval = tree_make_string(TOK_STRING, &stpos, &curpos, buf_p, buf_u);
      curpos.column++;
      buf_u = 0;
      *buf_p = 0;
      BEGIN(INITIAL);
      return TOK_STRING;
    }
    BEGIN(str_endstate);
  } else {
    curpos.column++;
    ibuf_add('\"');
  }
}
<STR>\' {
  if (str_endchar == '\'') {
    yylval = tree_make_value(TOK_CONSTANT, &stpos, &curpos);
    curpos.column++;
  do_return_char:
    ibuf_flush();
    yylval->val.val.tag = C_INT;
    if (!buf_u) {
      c_err(&stpos, "empty character literal");
    } else if (buf_u > 1) {
      int i, v = 0;
      c_warn(&stpos, "multibyte character literal");
      for (i = 0; i < buf_u; i++) {
        v <<= 8;
        v += buf_p[i];
      }
      yylval->val.val.v.ct_int = v;
    } else {
      yylval->val.val.v.ct_int = buf_p[0];
    }
    buf_u = 0;
    *buf_p = 0;
    BEGIN(INITIAL);
    return TOK_CONSTANT;
  } else {
    curpos.column++;
    ibuf_add('\'');
  }
}
<STR>\t {
  adjust_tab();
  ibuf_add('\t');
}
<STR>\r {
  /* FIXME: probably issue a warning */
  curpos.column = 0;
  ibuf_add('\r');
}
<STR>\n {
  /* FIXME: probably issue a warning */
  curpos.column = 0;
  curpos.line++;
  ibuf_add('\n');
}
<STR>\\[xX]{dx}{dx} {
  curpos.column += 4;
  ibuf_add(hex2int(yytext[2]) * 16 + hex2int(yytext[3]));
}
<STR>\\[xX]{dx} {
  curpos.column += 3;
  ibuf_add(hex2int(yytext[2]));
}
<STR>\\[0-3]{d8}{d8} {
  curpos.column += 4;
  ibuf_add((yytext[1]-'0')*64 + (yytext[2]-'0')*8 + (yytext[3]-'0'));
}
<STR>\\{d8}{d8} {
  curpos.column += 3;
  ibuf_add((yytext[1]-'0')*8 + (yytext[2]-'0'));
}
<STR>\\{d8} {
  curpos.column += 2;
  ibuf_add(yytext[1] - '0');
}
<STR>\\a {
  curpos.column += 2;
  ibuf_add('\a');
}
<STR>\\b {
  curpos.column += 2;
  ibuf_add('\b');
}
<STR>\\f {
  curpos.column += 2;
  ibuf_add('\f');
}
<STR>\\n {
  curpos.column += 2;
  ibuf_add('\n');
}
<STR>\\r {
  curpos.column += 2;
  ibuf_add('\r');
}
<STR>\\t {
  curpos.column += 2;
  ibuf_add('\t');
}
<STR>\\v {
  curpos.column += 2;
  ibuf_add('\v');
}
<STR>\\\' {
  curpos.column += 2;
  ibuf_add('\'');
}
<STR>\\\" {
  curpos.column += 2;
  ibuf_add('\"');
}
<STR>\\\\ {
  curpos.column += 2;
  ibuf_add('\\');
}
<STR>\\ {
  c_warn(&curpos, "invalid escape sequence");
  curpos.column++;
  ibuf_add('\\');
}
<STR>[\0-\037] {
  c_warn(&curpos,
         "control character (\\%03o) inside character literal or string",
         *(unsigned char*) yytext);
  curpos.column++;
  ibuf_add(*yytext);
}
 /* all printable except ', ", \ */
<STR>[\040-\041\043-\046\050-\133\135-\377]+ {
  curpos.column += yyleng;
  buf_yytext_append();
}
<STR><<EOF>> {
  if (str_endchar == '\'') {
    c_err(&curpos, "end-of-file inside of character literal");
    yylval = tree_make_value(TOK_CONSTANT, &stpos, &curpos);
    goto do_return_char;
  } else {
    c_err(&curpos, "end-of-file inside of character string");
    ibuf_add(0);
    ibuf_flush();
    if (str_endstate == INITIAL) {
      yylval = tree_make_string(TOK_STRING, &stpos, &curpos, buf_p, buf_u);
      buf_u = 0;
      *buf_p = 0;
      BEGIN(INITIAL);
      return TOK_STRING;
    }
    BEGIN(str_endstate);
  }
}

 /* floating point constants */
{dd}+[eE][+-]?{dd}+ |
{dd}+"."{dd}*([eE][+-]?{dd}+)? |
"."{dd}+([eE][+-]?{dd}+)? {
  handle_float(0, yyleng, 10, 0);
  return TOK_CONSTANT;
}

{dd}+([eE][+-]?{dd}+)?[iIjJ] |
{dd}+"."{dd}*([eE][+-]?{dd}+)?[iIjJ] |
"."{dd}+([eE][+-]?{dd}+)?[iIjJ] {
  handle_float(0, yyleng - 1, 10, LT_IMAG);
  return TOK_CONSTANT;
}

{dd}+[eE][+-]?{dd}+[lL] |
{dd}+"."{dd}*([eE][+-]?{dd}+)?[lL] |
"."{dd}+([eE][+-]?{dd}+)?[lL] {
  handle_float(0, yyleng - 1, 10, LT_LONG);
  return TOK_CONSTANT;
}

{dd}+([eE][+-]?{dd}+)?[lL][iIjJ] |
{dd}+"."{dd}*([eE][+-]?{dd}+)?[lL][iIjJ] |
"."{dd}+([eE][+-]?{dd}+)?[lL][iIjJ] {
  handle_float(0, yyleng - 2, 10, LT_LONG | LT_IMAG);
  return TOK_CONSTANT;
}

{dd}+([eE][+-]?{dd}+)?[fF] |
{dd}+"."{dd}*([eE][+-]?{dd}+)?[fF] |
"."{dd}+([eE][+-]?{dd}+)?[fF] {
  handle_float(0, yyleng - 1, 10, LT_FLOAT);
  return TOK_CONSTANT;
}

{dd}+([eE][+-]?{dd}+)?[fF][iIjJ] |
{dd}+"."{dd}*([eE][+-]?{dd}+)?[fF][iIjJ] |
"."{dd}+([eE][+-]?{dd}+)?[fF][iIjJ] {
  handle_float(0, yyleng - 2, 10, LT_FLOAT | LT_IMAG);
  return TOK_CONSTANT;
}

0x{dx}+("."{dx}*)?[pP][+-]?{dd}+ {
  handle_float(0, yyleng, 16, 0);
  return TOK_CONSTANT;
}
0x{dx}+("."{dx}*)?[pP][+-]?{dd}+[iIjJ] {
  handle_float(0, yyleng - 1, 16, LT_IMAG);
  return TOK_CONSTANT;
}
0x{dx}+("."{dx}*)?[pP][+-]?{dd}+[lL] {
  handle_float(0, yyleng - 1, 16, LT_LONG);
  return TOK_CONSTANT;
}
0x{dx}+("."{dx}*)?[pP][+-]?{dd}+[lL][iIjJ] {
  handle_float(0, yyleng - 2, 16, LT_LONG | LT_IMAG);
  return TOK_CONSTANT;
}
0x{dx}+("."{dx}*)?[pP][+-]?{dd}+[fF] {
  handle_float(0, yyleng - 1, 16, LT_FLOAT);
  return TOK_CONSTANT;
}
0x{dx}+("."{dx}*)?[pP][+-]?{dd}+[fF][iIjJ] {
  handle_float(0, yyleng - 2, 16, LT_FLOAT | LT_IMAG);
  return TOK_CONSTANT;
}

 /* integral constants */
{d0}{dd}* |
00* {
  handle_integral(0, yyleng, 10, 0);
  return TOK_CONSTANT;
}
{d0}{dd}*[uU] |
00*[uU] {
  handle_integral(0, yyleng - 1, 10, LT_UNSIGNED);
  return TOK_CONSTANT;
}
{d0}{dd}*[lL] |
00*[lL] {
  handle_integral(0, yyleng - 1, 10, LT_LONG);
  return TOK_CONSTANT;
}
{d0}{dd}*[lL][lL] |
00*[lL][lL] {
  handle_integral(0, yyleng - 2, 10, LT_LONGLONG);
  return TOK_CONSTANT;
}
{d0}{dd}*[uU][lL] |
{d0}{dd}*[lL][uU] |
00*[uU][lL] | 
00*[lL][uU] {
  handle_integral(0, yyleng - 2, 10, LT_LONG | LT_UNSIGNED);
  return TOK_CONSTANT;
}
{d0}{dd}*[uU][lL][lL] |
{d0}{dd}*[lL][uU][lL] |
{d0}{dd}*[lL][lL][uU] |
00*[uU][lL][lL] |
00*[lL][uU][lL] | 
00*[lL][lL][uU] {
  handle_integral(0, yyleng - 3, 10, LT_LONGLONG | LT_UNSIGNED);
  return TOK_CONSTANT;
}

0[xX]{dx}+ {
  handle_integral(2, yyleng - 2, 16, 0 /*LT_UNSIGNED*/);
  return TOK_CONSTANT;
}
0[xX]{dx}+[uU] {
  handle_integral(2, yyleng - 3, 16, LT_UNSIGNED);
  return TOK_CONSTANT;
}
0[xX]{dx}+[lL] {
  handle_integral(2, yyleng - 3, 16, LT_LONG /*| LT_UNSIGNED*/);
  return TOK_CONSTANT;
}
0[xX]{dx}+[lL][lL] {
  handle_integral(2, yyleng - 4, 16, LT_LONGLONG /*| LT_UNSIGNED*/);
  return TOK_CONSTANT;
}
0[xX]{dx}+[uU][lL] |
0[xX]{dx}+[lL][uU] {
  handle_integral(2, yyleng - 4, 16, LT_LONG | LT_UNSIGNED);
  return TOK_CONSTANT;
}
0[xX]{dx}+[uU][lL][lL] |
0[xX]{dx}+[lL][uU][lL] |
0[xX]{dx}+[lL][lL][uU] {
  handle_integral(2, yyleng - 5, 16, LT_LONGLONG | LT_UNSIGNED);
  return TOK_CONSTANT;
}

00*[1-7]{d8}* {
  handle_integral(0, yyleng, 8, 0 /*LT_UNSIGNED*/);
  return TOK_CONSTANT;
}
00*[1-7]{d8}*[uU] {
  handle_integral(0, yyleng - 1, 8, LT_UNSIGNED);
  return TOK_CONSTANT;
}
00*[1-7]{d8}*[lL] {
  handle_integral(0, yyleng - 1, 8, LT_LONG /*| LT_UNSIGNED*/);
  return TOK_CONSTANT;
}
00*[1-7]{d8}*[lL][lL] {
  handle_integral(0, yyleng - 2, 8, LT_LONGLONG /*| LT_UNSIGNED*/);
  return TOK_CONSTANT;
}
00*[1-7]{d8}*[uU][lL] |
00*[1-7]{d8}*[lL][uU] {
  handle_integral(0, yyleng - 2, 8, LT_LONG | LT_UNSIGNED);
  return TOK_CONSTANT;
}
00*[1-7]{d8}*[uU][lL][lL] |
00*[1-7]{d8}*[lL][uU][lL] |
00*[1-7]{d8}*[lL][lL][uU] { 
  handle_integral(0, yyleng - 3, 8, LT_LONGLONG | LT_UNSIGNED);
  return TOK_CONSTANT;
}

 /* keywords */
"auto" { curtok = TOK_AUTO; goto do_return_token; }
"break" { curtok = TOK_BREAK; goto do_return_token; }
"case" { curtok = TOK_CASE; goto do_return_token; }
"char" { curtok = TOK_CHAR; goto do_return_token; }
"const" { curtok = TOK_CONST; goto do_return_token; }
"__const" { curtok = TOK_CONST; goto do_return_token; }
"continue" { curtok = TOK_CONTINUE; goto do_return_token; }
"default" { curtok = TOK_DEFAULT; goto do_return_token; }
"do" { curtok = TOK_DO; goto do_return_token; }
"double" { curtok = TOK_DOUBLE; goto do_return_token; }
"else" { curtok = TOK_ELSE; goto do_return_token; }
"enum" { curtok = TOK_ENUM; goto do_return_token; }
"extern" { curtok = TOK_EXTERN; goto do_return_token; }
"float" { curtok = TOK_FLOAT; goto do_return_token; }
"for" { curtok = TOK_FOR; goto do_return_token; }
"goto" { curtok = TOK_GOTO; goto do_return_token; }
"if" { curtok = TOK_IF; goto do_return_token; }
"inline" { curtok = TOK_INLINE; goto do_return_token; }
"int" { curtok = TOK_INT; goto do_return_token; }
"long" { curtok = TOK_LONG; goto do_return_token; }
"register" { curtok = TOK_REGISTER; goto do_return_token; }
"restrict" { curtok = TOK_RESTRICT; goto do_return_token; }
"__restrict" { curtok = TOK_RESTRICT; goto do_return_token; }
"__restrict_arr" { curtok = TOK_RESTRICT; goto do_return_token; }
"return" { curtok = TOK_RETURN; goto do_return_token; }
"short" { curtok = TOK_SHORT; goto do_return_token; }
"signed" { curtok = TOK_SIGNED; goto do_return_token; }
"sizeof" { curtok = TOK_SIZEOF; goto do_return_token; }
"static" { curtok = TOK_STATIC; goto do_return_token; }
"struct" { curtok = TOK_STRUCT; goto do_return_token; }
"switch" { curtok = TOK_SWITCH; goto do_return_token; }
"typedef" { curtok = TOK_TYPEDEF; goto do_return_token; }
"union" { curtok = TOK_UNION; goto do_return_token; }
"unsigned" { curtok = TOK_UNSIGNED; goto do_return_token; }
"void" { curtok = TOK_VOID; goto do_return_token; }
"volatile" { curtok = TOK_VOLATILE; goto do_return_token; }
"while" { curtok = TOK_WHILE; goto do_return_token; }
"_Bool" { curtok = TOK__BOOL; goto do_return_token; }
"_Complex" { curtok = TOK__COMPLEX; goto do_return_token; }
"_Imaginary" {
  curtok = TOK__IMAGINARY;
 do_return_token:
  stpos = curpos;
  curpos.column += yyleng - 1;
  yylval = tree_make_token(curtok, &stpos, &curpos);
  curpos.column++;
  return curtok;
}

 /* extension tokens */
"__builtin_va_list" { curtok = TOK_VA_LIST; goto do_return_token; }
"__builtin_va_start" { curtok = TOK_VA_START; goto do_return_token; }
"__builtin_va_arg" { curtok = TOK_VA_ARG; goto do_return_token; }
"__builtin_va_end" { curtok = TOK_VA_END; goto do_return_token; }
"__builtin_assert" { curtok = TOK_ASSERT; goto do_return_token; }
"typeof" { curtok = TOK_TYPEOF; goto do_return_token; }
"asm" { curtok = TOK_ASM; goto do_return_token; }
"__attribute__" { curtok = TOK_ATTRIBUTE; goto do_return_token; }

 /* identifier */
{id0}{id1}* {
  {
    int tt = TOK_IDENT;

    stpos = curpos;
    curpos.column += yyleng - 1;
    curid = ident_put(yytext, yyleng);
    if (typedef_is_typedef(curid)) tt = TOK_TYPENAME;
    yylval = tree_make_ident(tt, &stpos, &curpos, curid);
    curpos.column++;
    return tt;
  }
}

 /* supported multichar separators */
"++" { curtok = TOK_INCR; goto do_return_token; }
"--" { curtok = TOK_DECR; goto do_return_token; }
"<<" { curtok = TOK_LSHIFT; goto do_return_token; }
">>" { curtok = TOK_RSHIFT; goto do_return_token; }
"<=" { curtok = TOK_LEQ; goto do_return_token; }
">=" { curtok = TOK_GEQ; goto do_return_token; }
"==" { curtok = TOK_EQ; goto do_return_token; }
"!=" { curtok = TOK_NEQ; goto do_return_token; }
"&&" { curtok = TOK_LOGAND; goto do_return_token; }
"||" { curtok = TOK_LOGOR; goto do_return_token; }
"^^" { curtok = TOK_LOGXOR; goto do_return_token; }
"..." { curtok = TOK_ELLIPSIS; goto do_return_token; }
"*=" { curtok = TOK_MULASSIGN; goto do_return_token; }
"/=" { curtok = TOK_DIVASSIGN; goto do_return_token; }
"%=" { curtok = TOK_MODASSIGN; goto do_return_token; }
"+=" { curtok = TOK_ADDASSIGN; goto do_return_token; }
"-=" { curtok = TOK_SUBASSIGN; goto do_return_token; }
"<<=" { curtok = TOK_LSHASSIGN; goto do_return_token; }
">>=" { curtok = TOK_RSHASSIGN; goto do_return_token; }
"&=" { curtok = TOK_ANDASSIGN; goto do_return_token; }
"^=" { curtok = TOK_XORASSIGN; goto do_return_token; }
"|=" { curtok = TOK_ORASSIGN; goto do_return_token; }
"->" { curtok = TOK_ARROW; goto do_return_token; }

 /* supported one-char tokens */
";" |
"," |
"=" |
"{" |
"}" |
":" |
"(" |
")" |
"[" |
"]" |
"*" |
"." |
"?" |
"|" |
"^" |
"&" |
">" |
"<" |
"+" |
"-" |
"/" |
"%" |
"~" |
"!" { curtok = *yytext; goto do_return_token; }

 /* some special characters to handle */
\t {
  adjust_tab();
}
\n {
  curpos.column = 0;
  curpos.line++;
}
\r {
  curpos.column = 0;
}
[\000-\037] {
  curpos.column++;
}
" "+ {
  curpos.column += yyleng;
}
. {
  c_err(&curpos, "invalid character (\\%03o)", *(unsigned char*) yytext);
  curpos.column++;
}
<<EOF>> {
  yylval = tree_make_token(0, &curpos, &curpos);
  return 0;
}

%%

static int
hex2int(int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - ('a' - 10);
  if (c >= 'A' && c <= 'F') return c - ('A' - 10);
  return 0;
}

static void
buf_extend(int new_size)
{
  if (new_size <= buf_a) return;
  while (new_size > buf_a) {
    buf_a *= 2;
  }
  buf_p = xrealloc(buf_p, buf_a);
}

/* append the ibuf contents to the buf contents */
static void
ibuf_flush(void)
{
  if (!ibuf_cur) return;
  buf_extend(ibuf_cur + buf_u + 1);
  memcpy(buf_p + buf_u, ibuf, ibuf_cur);
  buf_u += ibuf_cur;
  buf_p[buf_u] = 0;
  ibuf_cur = 0;
}

static void
buf_yytext_append(void)
{
  if (!yyleng) return;
  ibuf_flush();
  buf_extend(yyleng + buf_u + 1);
  memcpy(buf_p + buf_u, yytext, yyleng);
  buf_u += yyleng;
  buf_p[buf_u] = 0;
}

static void
handle_integral(int start, int length, int base, int flags)
{
  unsigned char *buf = 0;

  buf = (unsigned char *) alloca(length + 1);
  memset(buf, 0, length + 1);
  memcpy(buf, yytext + start, length);
  stpos = curpos;
  curpos.column += yyleng - 1;
  yylval = tree_make_value(TOK_CONSTANT, &stpos, &curpos);
  curpos.column++;

  if (flags == 0) {
    /* plain int */
    int val = 0;
    errno = 0;
    val = strtol(buf, 0, base);
    if (errno == 0) {
      yylval->val.val.tag = C_INT;
      yylval->val.val.v.ct_int = val;
      return;
    }
  }
  if ((flags & (LT_LONGLONG | LT_LONG)) == 0) {
    /* int, unsigned int */
    unsigned int val = 0;
    errno = 0;
    val = strtoul(buf, 0, base);
    if (errno == 0) {
      yylval->val.val.tag = C_UINT;
      yylval->val.val.v.ct_uint = val;
      return;
    }
  }
  if ((flags & (LT_LONGLONG | LT_UNSIGNED)) == 0) {
    /* int, long */
    long val;
    errno = 0;
    val = strtol(buf, 0, base);
    if (errno == 0) {
      yylval->val.val.tag = C_LONG;
      yylval->val.val.v.ct_lint = val;
      return;
    }
  }
  if ((flags & LT_LONGLONG) == 0) {
    unsigned long val;
    errno = 0;
    val = strtoul(buf, 0, base);
    if (errno == 0) {
      yylval->val.val.tag = C_ULONG;
      yylval->val.val.v.ct_ulint = val;
      return;
    }
  }
  if ((flags & LT_UNSIGNED) == 0) {
    long long val;
    errno = 0;
    val = strtoll(buf, 0, base);
    if (errno == 0) {
      yylval->val.val.tag = C_LLONG;
      yylval->val.val.v.ct_llint = val;
      return;
    }
  }
  /* try unsigned long long */
  {
    unsigned long long val;
    errno = 0;
    val = strtoull(buf, 0, base);
    if (errno == 0) {
      yylval->val.val.tag = C_ULLONG;
      yylval->val.val.v.ct_ullint = val;
      return;
    }
  }
  /* issue an error */
  c_warn(&stpos, "integral literal is too large");
  yylval->val.val.tag = C_INT;
  switch (flags) {
  case LT_UNSIGNED:               yylval->val.val.tag = C_UINT;   break;
  case LT_LONG:                   yylval->val.val.tag = C_LONG;   break;
  case LT_LONG | LT_UNSIGNED:     yylval->val.val.tag = C_ULONG;  break;
  case LT_LONGLONG:               yylval->val.val.tag = C_LLONG;  break;
  case LT_LONGLONG | LT_UNSIGNED: yylval->val.val.tag = C_ULLONG; break;
  }
}

static void
handle_float(int start, int length, int base, int flags)
{
  unsigned char *buf = 0;
  unsigned char *base_type = "";
  int ret = 0;
  int (*read_func)() = 0;
  void *addr = 0;

  buf = (unsigned char *) alloca(length + 1);
  memset(buf, 0, length + 1);
  memcpy(buf, yytext + start, length);
  stpos = curpos;
  curpos.column += yyleng - 1;
  yylval = tree_make_value(TOK_CONSTANT, &stpos, &curpos);
  curpos.column++;

  switch (flags) {
  case 0:
    base_type = "double";
    yylval->val.val.tag = C_DOUBLE;
    addr = &yylval->val.val.v.ct_double;
    if (base == 16) read_func = reuse_readhd;
    else read_func = os_readdd;
    break;
  case LT_IMAG:
    base_type = "double";
    memset(&yylval->val.val, 0, sizeof(yylval->val.val));
    yylval->val.val.tag = C_DCOMPLEX;
    addr = &yylval->val.val.v.ct_dcomplex.d_im;
    if (base == 16) read_func = reuse_readhd;
    else read_func = os_readdd;
    break;
  case LT_FLOAT:
    base_type = "float";
    yylval->val.val.tag = C_FLOAT;
    addr = &yylval->val.val.v.ct_float;
    if (base == 16) read_func = reuse_readhf;
    else read_func = os_readdf;
    break;
  case LT_FLOAT | LT_IMAG:
    base_type = "float";
    memset(&yylval->val.val, 0, sizeof(yylval->val.val));
    yylval->val.val.tag = C_FCOMPLEX;
    addr = &yylval->val.val.v.ct_fcomplex.f_im;
    if (base == 16) read_func = reuse_readhf;
    else read_func = os_readdf;
    break;
  case LT_LONG:
    base_type = "long double";
    yylval->val.val.tag = C_LDOUBLE;
    addr = &yylval->val.val.v.ct_ldouble;
    if (base == 16) read_func = reuse_readhld;
    else read_func = os_readdld;
    break;
  case LT_LONG | LT_IMAG:
    base_type = "long double";
    memset(&yylval->val.val, 0, sizeof(yylval->val.val));
    yylval->val.val.tag = C_LCOMPLEX;
    addr = &yylval->val.val.v.ct_lcomplex.l_im;
    if (base == 16) read_func = reuse_readhld;
    else read_func = os_readdld;
    break;
  default:
    SWERR(("unhandled case %d", flags));
  }

  ret = (*read_func)(buf, 0, addr);
  ASSERT(ret >= 0);
  if (ret == 1) {
    c_warn(&stpos, "floating-point literal is too large for type `%s'",
           base_type);
  } else if (ret == 2) {
    c_warn(&stpos, "floating-point literal is too small for type `%s'",
           base_type);
  }
  return;
}

static void
handle_lstring(wchar_t endchar)
{
  size_t mb_a, mb_u, mb_n, ws_a, ws_u;
  unsigned char *mb_b;
  int c, i, maxulen;
  wchar_t wc_c, *ws_b;
  mbstate_t mb_s;
  const unsigned char *category = "wide character literal";
  wchar_t *tmp_wb;
  unsigned char *tmp_cb;

  memset(&mb_s, 0, sizeof(mb_s));
  mb_a = 32;
  mb_u = 0;
  mb_b = (unsigned char*) alloca(mb_a);
  ws_a = 4;
  if (endchar == L'\"') {
    category = "wide character string";
    ws_a = 16;
  }
  ws_u = 0;
  ws_b = (wchar_t*) alloca(ws_a * sizeof(ws_b[0]));

  while (1) {
    c = input();
    if (c == EOF) {
      c_err(&curpos, "end-of-file inside of %s", category);
      break;
    }
    if (c == 0) {
      wc_c = 0;
      curpos.column++;
      goto append_character;
    }

    /* append a byte character to the byte buffer */
    if (mb_u == mb_a) {
      mb_a *= 2;
      tmp_cb = (unsigned char*) alloca(mb_a);
      memcpy(tmp_cb, mb_b, mb_u);
      mb_b = tmp_cb;
    }
    ASSERT(mb_u < mb_a);
    mb_b[mb_u++] = c;

    mb_n = mbrtowc(&wc_c, mb_b, mb_u, &mb_s);
    if (mb_n == (size_t) -2) {
      // need more multibyte characters
      curpos.column++;
      continue;
    }
    if (mb_n == (size_t) -1) {
      c_err(&curpos, "invalid multibyte sequence inside of %s", category);
      memset(&mb_s, 0, sizeof(mb_s));
      curpos.column++;
      continue;
    }
    ASSERT(mb_n == mb_u);

    mb_u = 0;
    if (wc_c == endchar) {
      curpos.column++;
      break;
    }
    if (wc_c != L'\\') {
      if (wc_c == '\n') {
        curpos.column = 0;
        curpos.line++;
      } else if (wc_c == '\t') {
        curpos.column = (curpos.column + 8) & ~7;
      } else {
        curpos.column++;
      }
    append_character:
      /* append a character to the wide buffer */
      if (ws_u == ws_a) {
        ws_a *= 2;
        tmp_wb = (wchar_t*) alloca(ws_a * sizeof(ws_b[0]));
        memcpy(tmp_wb, ws_b, ws_u * sizeof(ws_b[0]));
        ws_b = tmp_wb;
      }
      ASSERT(ws_u < ws_a);
      ws_b[ws_u++] = wc_c;
      continue;
    }

    /* according to 5.2.1.2 the characters from the basic source
     * character set are one-byte
     */
    /*
    if (mbrtowc(0, 0, 0, &mb_s) == (size_t) -1) {
      c_err(&curpos, "invalid multibyte sequence inside of %s", category);
      memset(&mb_s, 0, sizeof(mb_s));
      continue;
    }
    */

    curpos.column++;            // count the '\\'
    c = input();
    if (c == EOF) {
      c_err(&curpos, "end-of-file inside of %s", category);
      break;
    }
    curpos.column++;

    switch (c) {
    case 'a':  wc_c = '\a'; goto append_character;
    case 'b':  wc_c = '\b'; goto append_character;
    case 'f':  wc_c = '\f'; goto append_character;
    case 'n':  wc_c = '\n'; goto append_character;
    case 'r':  wc_c = '\r'; goto append_character;
    case 't':  wc_c = '\t'; goto append_character;
    case 'v':  wc_c = '\v'; goto append_character;
    case '\'': wc_c = '\''; goto append_character;
    case '\"': wc_c = '\"'; goto append_character;
    case '\\': wc_c = '\\'; goto append_character;
    case 'x': case 'X':
      c = input();
      if (!isxdigit(c)) {
        c_err(&curpos, "invalid escape sequence inside of %s", category);
        yyunput(c, yytext);
        yyunput(c, yytext);
        curpos.column--;
        memset(&mb_s, 0, sizeof(mb_s));
        continue;
      }
      curpos.column++;
      memset(mb_b, 0, 4);
      mb_b[0] = c;
      c = input();
      if (isxdigit(c)) {
        curpos.column++;
        mb_b[1] = c;
      } else {
        yyunput(c, yytext);
      }
      wc_c = strtol(mb_b, 0, 16);
      goto append_character;
    case '0': case '1': case '2': case '3':
      memset(mb_b, 0, 4);
      mb_b[0] = c;
      if ((c = input()) >= '0' && c <= '7') {
        curpos.column++;
        mb_b[1] = c;
        if ((c = input()) >= '0' && c <= '7') {
          curpos.column++;
          mb_b[2] = c;
        } else {
          yyunput(c, yytext);
        }
      } else {
        yyunput(c, yytext);
      }
      wc_c = strtol(mb_b, 0, 8);
      goto append_character;
    case '4': case '5': case '6': case '7':
      memset(mb_b, 0, 4);
      mb_b[0] = c;
      if ((c = input()) >= '0' && c <= '7') {
        curpos.column++;
        mb_b[1] = c;
      } else {
        yyunput(c, yytext);
      }
      wc_c = strtol(mb_b, 0, 8);
      goto append_character;
    case 'U':
      maxulen = 8;
      goto read_unicode;
    case 'u':
      maxulen = 4;
    read_unicode:
      c = input();
      if (!isxdigit(c)) {
        c_err(&curpos, "invalid escape sequence inside of %s", category);
        yyunput(c, yytext);
        yyunput(c, yytext);
        curpos.column--;
        memset(&mb_s, 0, sizeof(mb_s));
        continue;
      }
      curpos.column++;
      i = 0;
      mb_b[i++] = c;
      for (; i < maxulen; i++) {
        c = input();
        if (!isxdigit(c)) {
          yyunput(c, yytext);
          break;
        }
        curpos.column++;
        mb_b[i] = c;
      }
      mb_b[i] = 0;
      wc_c = strtoul(mb_b, 0, 16);
      goto append_character;
    default:
      c_warn(&curpos, "invalid escape sequence inside of %s", category);
      yyunput(c, yytext);
      memset(&mb_s, 0, sizeof(mb_s));
      continue;
    }
  }

  if (endchar == L'\"') {
    /* append \0 terminator to the wide buffer */
    if (ws_u == ws_a) {
      wchar_t *tmp_b;
      
      ws_a *= 2;
      tmp_b = (wchar_t*) alloca(ws_a * sizeof(ws_b[0]));
      memcpy(tmp_b, ws_b, ws_u * sizeof(ws_b[0]));
      ws_b = tmp_b;
    }
    ASSERT(ws_u < ws_a);
    ws_b[ws_u++] = 0;

    yylval = tree_make_lstring(TOK_LSTRING, &stpos, &curpos, ws_b, ws_u);
  } else {
    if (!ws_u) {
      c_err(&curpos, "empty wide character literal");
      wc_c = 0;
    } else if (ws_u > 1) {
      c_warn(&curpos, "wide character literal is too long");
      wc_c = ws_b[0];
    } else {
      wc_c = ws_b[0];
    }
    yylval = tree_make_value(TOK_CONSTANT, &stpos, &curpos);
    // FIXME: use the host wint_t type...
    yylval->val.val.tag = C_UINT;
    yylval->val.val.v.ct_uint = (unsigned) wc_c;
  }
}

static void
initialize(void)
{
  if (initialized) return;
  initialized = 1;

  ibuf_cur = 0;
  buf_a = 256;
  buf_u = 0;
  buf_p = (unsigned char*) xcalloc(buf_a, 1);
}

void
scanner_set_input(const unsigned char *path, FILE *f)
{
  if (!initialized) initialize();

  //yyin = f;
  yyrestart(f);
  pos_set(&curpos, path, 1, 0);
}
