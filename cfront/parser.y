/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "typedef.h"
#include "scanner.h"
#include "c_errors.h"

#include "ejudge/logger.h"

static void yyerror(const unsigned char *msg);

static tree_t tree;

static int declspec_is_typedef(tree_t);
static void register_ident(tree_t, int);
static void rereg_par_scope(tree_t);
static int ds_typedef_flag;

#define YYERROR_VERBOSE 1

//#define YYDEBUG 1

%}
%token TOK_INCR       "++"
%token TOK_DECR       "--"
%token TOK_LSHIFT     "<<"
%token TOK_RSHIFT     ">>"
%token TOK_LEQ        "<="
%token TOK_GEQ        ">="
%token TOK_EQ         "=="
%token TOK_NEQ        "!="
%token TOK_LOGAND     "&&"
%token TOK_LOGOR      "||"
%token TOK_LOGXOR     "^^"
%token TOK_ELLIPSIS   "..."
%token TOK_MULASSIGN  "*="
%token TOK_DIVASSIGN  "/="
%token TOK_MODASSIGN  "%="
%token TOK_ADDASSIGN  "+="
%token TOK_SUBASSIGN  "-="
%token TOK_LSHASSIGN  "<<="
%token TOK_RSHASSIGN  ">>="
%token TOK_ANDASSIGN  "&="
%token TOK_XORASSIGN  "^="
%token TOK_ORASSIGN   "|="
%token TOK_ARROW      "->"
%token TOK_AUTO       "auto"
%token TOK_BREAK      "break"
%token TOK_CASE       "case"
%token TOK_CHAR       "char"
%token TOK_CONST      "const"
%token TOK_CONTINUE   "continue"
%token TOK_DEFAULT    "default"
%token TOK_DO         "do"
%token TOK_DOUBLE     "double"
%token TOK_ELSE       "else"
%token TOK_ENUM       "enum"
%token TOK_EXTERN     "extern"
%token TOK_FLOAT      "float"
%token TOK_FOR        "for"
%token TOK_GOTO       "goto"
%token TOK_IF         "if"
%token TOK_INLINE     "inline"
%token TOK_INT        "int"
%token TOK_LONG       "long"
%token TOK_REGISTER   "register"
%token TOK_RESTRICT   "restrict"
%token TOK_RETURN     "return"
%token TOK_SHORT      "short"
%token TOK_SIGNED     "signed"
%token TOK_SIZEOF     "sizeof"
%token TOK_STATIC     "static"
%token TOK_STRUCT     "struct"
%token TOK_SWITCH     "switch"
%token TOK_TYPEDEF    "typedef"
%token TOK_UNION      "union"
%token TOK_UNSIGNED   "unsigned"
%token TOK_VOID       "void"
%token TOK_VOLATILE   "volatile"
%token TOK_WHILE      "while"
%token TOK__BOOL      "_Bool"
%token TOK__COMPLEX   "_Complex"
%token TOK__IMAGINARY "_Imaginary"
%token TOK_IDENT      "identifier"
%token TOK_TYPENAME   "typename"
%token TOK_CONSTANT   "constant"
%token TOK_STRING     "string"
%token TOK_LSTRING    "Lstring"
/* extension tokens */
%token TOK_VA_LIST    "__builtin_va_list"
%token TOK_VA_START   "__builtin_va_start"
%token TOK_VA_ARG     "__builtin_va_arg"
%token TOK_VA_END     "__builtin_va_end"
%token TOK_TYPEOF     "typeof"
%token TOK_ASM        "asm"
%token TOK_ATTRIBUTE  "__attribute__"
%token TOK_ASSERT     "__builtin_assert"
%token TOK___ANNOT    "__annot"
%token TOK_LAST
/* expect one if/then/else shift/reduce conflict */
%expect 1
%token-table
%%

top_rule : { tree = 0; }
| translation_unit
{
  tree = tree_make_node3(NODE_ROOT, 4, $1);
}
;

/* A.2.4 External definitions */

translation_unit :
  external_declaration { $$ = $1; }
| translation_unit external_declaration
{
  $$ = tree_merge($1, 0, $2);
}
;

external_declaration :
  function_definition { $$ = $1; }
| global_declaration { $$ = $1; }
| ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, NULL, NULL, $1);
}
| "__annot" TOK_STRING
{
  $$ = tree_make_node3(NODE_ANNOT, 4, $2);
}
;

function_definition :
  declarator_reg_2 { rereg_par_scope($1); } compound_statement
{
  $$ = tree_make_node3(NODE_DECLFUNC, 7, NULL, $1, NULL, $3);
  typedef_drop_scope();
}
| declarator_reg_2 { rereg_par_scope($1); } declaration_list compound_statement
{
  $$ = tree_make_node3(NODE_DECLFUNC, 7, NULL, $1, $3, $4);
  typedef_drop_scope();
}
| declspec1 declarator_reg_2 { rereg_par_scope($2); } compound_statement
{
  $$ = tree_make_node3(NODE_DECLFUNC, 7, $1, $2, NULL, $4);
  typedef_drop_scope();
}
| declspec1 declarator_reg_2 { rereg_par_scope($2); } declaration_list compound_statement
{
  $$ = tree_make_node3(NODE_DECLFUNC, 7, $1, $2, $4, $5);
  typedef_drop_scope();
}
| declspec2 declarator_td_reg_2 { rereg_par_scope($2); } compound_statement
{
  $$ = tree_make_node3(NODE_DECLFUNC, 7, $1, $2, NULL, $4);
  typedef_drop_scope();
}
| declspec2 declarator_td_reg_2 { rereg_par_scope($2); } declaration_list compound_statement
{
  $$ = tree_make_node3(NODE_DECLFUNC, 7, $1, $2, $4, $5);
  typedef_drop_scope();
}
| declspec3 declarator_td_reg_2 { rereg_par_scope($2); } compound_statement
{
  $$ = tree_make_node3(NODE_DECLFUNC, 7, $1, $2, NULL, $4);
  typedef_drop_scope();
}
| declspec3 declarator_td_reg_2 { rereg_par_scope($2); } declaration_list compound_statement
{
  $$ = tree_make_node3(NODE_DECLFUNC, 7, $1, $2, $4, $5);
  typedef_drop_scope();
}
;

declarator_reg_2 :
  declarator
{
  $$ = $1;
  register_ident($$, 0);
}
;

declarator_td_reg_2 :
  declarator_td
{
  $$ = $1;
  register_ident($$, 0);
}
;

declaration_list :
  declaration { $$ = $1; }
| declaration_list declaration
{
  $$ = tree_merge($1, 0, $2);
}
;

/* A.2.2 Declarations */

global_declaration :
  init_declarator_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, NULL, $1, $2);
}
| init_declarator_reg ',' init_declarator_list_td_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, NULL, tree_merge($1, $2, $3), $4);
}
| declspec1 ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, NULL, $2);
}
| declspec1 init_declarator_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, $2, $3);
}
| declspec1 init_declarator_reg ',' init_declarator_list_td_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, tree_merge($2, $3, $4), $5);
}
| declspec2 ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, NULL, $2);
}
| declspec2 init_declarator_list_td_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, $2, $3);
}
| declspec3 ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, NULL, $2);
}
| declspec3 init_declarator_list_td_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, $2, $3);
}
| error ';' { $$ = 0; }
;

declaration :
  declspec1 ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, NULL, $2);
}
| declspec1 init_declarator_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, $2, $3);
}
| declspec1 init_declarator_reg ',' init_declarator_list_td_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, tree_merge($2, $3, $4), $5);
}
| declspec2 ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, NULL, $2);
}
| declspec2 init_declarator_list_td_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, $2, $3);
}
| declspec3 ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, NULL, $2);
}
| declspec3 init_declarator_list_td_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, $2, $3);
}
| error ';' { $$ = 0; }
;

declspec1 :
  declaration_specifiers_notype
{
  $$ = $1;
  ds_typedef_flag = declspec_is_typedef($$);
}
;

declspec2 :
  type_specifier declaration_specifiers_notd_opt 
{
  $$ = tree_merge($1, 0, $2);
  ds_typedef_flag = declspec_is_typedef($$);
}
;

declspec3 :
  declaration_specifiers_notype type_specifier declaration_specifiers_notd_opt
{
  $$ = tree_merge(tree_merge($1, 0, $2), 0, $3);
  ds_typedef_flag = declspec_is_typedef($$);
}
;

declaration_specifiers_notd_opt : { $$ = 0; }
| declaration_specifiers_notd { $$ = $1; }
;

declaration_specifiers_notype :
  declaration_specifier_notype { $$ = $1; }
| declaration_specifiers_notype declaration_specifier_notype
{
  $$ = tree_merge($1, 0, $2);
}
;

declaration_specifiers_notd :
  declaration_specifier_notd { $$ = $1; }
| declaration_specifiers_notd declaration_specifier_notd
{
  $$ = tree_merge($1, 0, $2);
}
;

declaration_specifier_notype :
  storage_class_specifier { $$ = $1; }
| type_qualifier { $$ = $1; }
| function_specifier { $$ = $1; }
;

declaration_specifier_notd :
  storage_class_specifier { $$ = $1; }
| type_specifier_notd { $$ = $1; }
| type_qualifier { $$ = $1; }
| function_specifier { $$ = $1; }
;

init_declarator_list_td_reg :
  init_declarator_td_reg { $$ = $1; }
| init_declarator_list_td_reg ',' init_declarator_td_reg
{
  $$ = tree_merge($1, $2, $3);
}
;

init_declarator_reg :
  declarator_reg
{
  $$ = tree_make_node3(NODE_INITDECLR, 6, $1, NULL, NULL);
}
| declarator_reg '=' initializer
{
  $$ = tree_make_node3(NODE_INITDECLR, 6, $1, $2, $3);
}
;

declarator_reg :
  declarator
{
  $$ = $1;
  register_ident($$, ds_typedef_flag);
}
;

init_declarator_td_reg :
  declarator_td_reg
{
  $$ = tree_make_node3(NODE_INITDECLR, 6, $1, NULL, NULL);
}
| declarator_td_reg '=' initializer
{
  $$ = tree_make_node3(NODE_INITDECLR, 6, $1, $2, $3);
}
;

declarator_td_reg :
  declarator_td
{
  $$ = $1;
  register_ident($$, ds_typedef_flag);
}
;

storage_class_specifier :
  storage_class_specifier_token
{
  $$ = tree_make_node3(NODE_DSSTORAGE, 4, $1);
}
;

storage_class_specifier_token :
  "typedef" { $$ = $1; }
| "extern" { $$ = $1; }
| "static" { $$ = $1; }
| "auto" { $$ = $1; }
| "register" { $$ = $1; }
;

type_specifier :
  type_specifier_token
{
  $$ = tree_make_node3(NODE_DSSTDTYPE, 4, $1);
}
| struct_or_union_specifier { $$ = $1; }
| enum_specifier { $$ = $1; }
| typeof_specifier { $$ = $1; }
| typedef_name
{
  $$ = tree_make_node3(NODE_DSTYPENAME, 4, $1);
}
;

type_specifier_notd :
  type_specifier_token
{
  $$ = tree_make_node3(NODE_DSSTDTYPE, 4, $1);
}
| struct_or_union_specifier { $$ = $1; }
| enum_specifier { $$ = $1; }
| typeof_specifier { $$ = $1; }
;

type_specifier_token :
  "void" { $$ = $1; }
| "char" { $$ = $1; }
| "short" { $$ = $1; }
| "int" { $$ = $1; }
| "long" { $$ = $1; }
| "float" { $$ = $1; }
| "double" { $$ = $1; }
| "signed" { $$ = $1; }
| "unsigned" { $$ = $1; }
| "_Bool" { $$ = $1; }
| "_Complex" { $$ = $1; }
| "_Imaginary" { $$ = $1; }
| "__builtin_va_list" { $$ = $1; }
;

typeof_specifier :
  "typeof" '(' expression ')'
{
  $$ = tree_make_node3(NODE_DSTYPEOF, 7, $1, $2, $3, $4);
}
| "typeof" '(' error ')' { $$ = 0; }
;

struct_or_union_specifier :
  struct_or_union identifier_or_typename_opt struct_opening_brace struct_declaration_list_opt '}'
{
  $$ = tree_make_node3(NODE_DSAGGREG, 8, $1, $2, $3, $4, $5);
  typedef_drop_scope();
}
| struct_or_union identifier_or_typename
{
  $$ = tree_make_node3(NODE_DSAGGREG, 8, $1, $2, NULL, NULL, NULL);
}
| struct_or_union identifier_or_typename_opt struct_opening_brace error '}'
{ 
  $$ = 0;
  typedef_drop_scope();
}
;

struct_opening_brace :
  '{'
{
  $$ = $1;
  typedef_new_scope();
}
;

struct_or_union :
  "struct" { $$ = $1; }
| "union" { $$ = $1; }
;

struct_declaration_list_opt :
{
  $$ = 0;
}
| struct_declaration_list
{
  $$ = $1;
}
;

struct_declaration_list :
  struct_declaration { $$ = $1; }
| struct_declaration_list struct_declaration
{
  $$ = tree_merge($1, 0, $2);
}
;

struct_declaration :
  qualifier_list ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, NULL, $2);
}
| qualifier_list struct_declarator_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, $2, $3);
}
| qualifier_list struct_declarator_reg ',' struct_declarator_list_td_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, tree_merge($2, $3, $4), $5);
}
| qualifier_list_opt type_specifier specifier_qualifier_list_notd_opt ';'
{
  $$ = tree_make_node3(NODE_DECL, 6,
                       tree_merge(tree_merge($1, 0, $2), 0, $3),
                       NULL, $4);
}
| qualifier_list_opt type_specifier specifier_qualifier_list_notd_opt struct_declarator_list_td_reg ';'
{
  $$ = tree_make_node3(NODE_DECL, 6,
                       tree_merge(tree_merge($1, 0, $2), 0, $3),
                       $4, $5);
}
| error ';' { $$ = 0; }
;

qualifier_list_opt : { $$ = 0; }
| qualifier_list { $$ = $1; }
;

qualifier_list :
  type_qualifier { $$ = $1; }
| qualifier_list type_qualifier
{
  $$ = tree_merge($1, 0, $2);
}
;

specifier_qualifier_list_notd_opt : { $$ = 0; }
| specifier_qualifier_list_notd { $$ = $1; }
;

specifier_qualifier_list :
  specifier_qualifier { $$ = $1; }
| specifier_qualifier_list specifier_qualifier
{
  $$ = tree_merge($1, 0, $2);
}
;

specifier_qualifier_list_notd :
  specifier_qualifier_notd { $$ = $1; }
| specifier_qualifier_list_notd specifier_qualifier_notd
{
  $$ = tree_merge($1, 0, $2);
}
;

specifier_qualifier :
  type_specifier { $$ = $1; }
| type_qualifier { $$ = $1; }
;

specifier_qualifier_notd :
  type_specifier_notd { $$ = $1; }
| type_qualifier { $$ = $1; }
;

struct_declarator_list_td_reg :
  struct_declarator_td_reg { $$ = $1; }
| struct_declarator_list_td_reg ',' struct_declarator_td_reg
{
  $$ = tree_merge($1, $2, $3);
}
;

struct_declarator_reg :
  declarator /*declarator_reg_2*/
{
  $$ = tree_make_node3(NODE_STRUCTDECLR, 6, $1, NULL, NULL);
}
| declarator /*declarator_reg_2*/ ':' constant_expression
{
  $$ = tree_make_node3(NODE_STRUCTDECLR, 6, $1, $2, $3);
}
| ':' constant_expression
{
  $$ = tree_make_node3(NODE_STRUCTDECLR, 6, NULL, $1, $2);
}
;

struct_declarator_td_reg :
  declarator_td /*declarator_td_reg_2*/
{
  $$ = tree_make_node3(NODE_STRUCTDECLR, 6, $1, NULL, NULL);
}
| declarator_td /*declarator_td_reg_2*/ ':' constant_expression
{
  $$ = tree_make_node3(NODE_STRUCTDECLR, 6, $1, $2, $3);
}
| ':' constant_expression
{
  $$ = tree_make_node3(NODE_STRUCTDECLR, 6, NULL, $1, $2);
}
;

enum_specifier :
  "enum" identifier_or_typename_opt '{' enumerator_list_opt '}'
{
  $$ = tree_make_node3(NODE_DSENUM, 9, $1, $2, $3, $4, NULL, $5);
}
| "enum" identifier_or_typename_opt '{' enumerator_list ',' '}'
{
  $$ = tree_make_node3(NODE_DSENUM, 9, $1, $2, $3, $4, $5, $6);
}
| "enum" identifier_or_typename
{
  $$ = tree_make_node3(NODE_DSENUM, 9, $1, $2, NULL, NULL, NULL, NULL);
}
| "enum" identifier_or_typename_opt '{' error '}' { $$ = 0; }
;

enumerator_list_opt :
{
  $$ = 0;
}
| enumerator_list
{
  $$ = $1;
}
;

enumerator_list :
  enumerator { $$ = $1; }
| enumerator_list ',' enumerator
{
  $$ = tree_merge($1, $2, $3);
}
;

enumerator :
  enumeration_constant
{
  $$ = tree_make_node3(NODE_ENUMERATOR, 6, $1, NULL, NULL);
}
| enumeration_constant '=' constant_expression
{
  $$ = tree_make_node3(NODE_ENUMERATOR, 6, $1, $2, $3);
}
;

enumeration_constant :
  identifier_or_typename
{
  $$ = $1;
  register_ident($$, 0);
}
;

type_qualifier :
  type_qualifier_token
{
  $$ = tree_make_node3(NODE_DSQUAL, 4, $1);
}
;

type_qualifier_token :
  "const" { $$ = $1; }
| "restrict" { $$ = $1; }
| "volatile" { $$ = $1; }
;

function_specifier :
  "inline"
{
  $$ = tree_make_node3(NODE_DSFUNCSPEC, 4, $1);
}
;

declarator :
  pointer_opt direct_declarator attribute_specification_opt
{
  $$ = tree_make_node3(NODE_DECLR, 6, $1, $2, $3);
}
;

declarator_td :
  pointer_opt direct_declarator_td attribute_specification_opt
{
  $$ = tree_make_node3(NODE_DECLR, 6, $1, $2, $3);
}
;

direct_declarator :
  TOK_IDENT
{
  $$ = tree_make_node3(NODE_DIRDECLR1, 4, $1);
}
| '(' declarator ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR2, 6, $1, $2, $3);
}
| direct_declarator '[' type_qualifier_list_opt assignment_expression_opt ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2, $3, NULL, $4, $5);
}
| direct_declarator '[' storage_class_static type_qualifier_list_opt assignment_expression ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2,
                       tree_merge($3, 0, $4), NULL, $5, $6);
}
| direct_declarator '[' type_qualifier_list storage_class_static assignment_expression ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2,
                       tree_merge($3, 0, $4), NULL, $5, $6);
}
| direct_declarator '[' type_qualifier_list_opt '*' ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2, $3, $4, NULL, $5);
}
| direct_declarator par_open_bracket parameter_type_list ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR4, 7, $1, $2, $3, $4);
  typedef_drop_scope();
}
| direct_declarator '(' identifier_list_opt ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR5, 7, $1, $2, $3, $4);
}
| direct_declarator '(' error ')' { $$ = 0; }
| direct_declarator '[' error ']' { $$ = 0; }
| '(' error ')' { $$ = 0; }
;

par_open_bracket :
  '('
{
  $$ = $1;
  typedef_new_scope();
}
;

direct_declarator_td :
  identifier_or_typename
{
  $$ = tree_make_node3(NODE_DIRDECLR1, 4, $1);
}
| '(' declarator ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR2, 6, $1, $2, $3);
}
| direct_declarator_td '[' type_qualifier_list_opt assignment_expression_opt ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2, $3, NULL, $4, $5);
}
| direct_declarator_td '[' storage_class_static type_qualifier_list_opt assignment_expression ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2,
                       tree_merge($3, 0, $4), NULL, $5, $6);
}
| direct_declarator_td '[' type_qualifier_list storage_class_static assignment_expression ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2,
                       tree_merge($3, 0, $4), NULL, $5, $6);
}
| direct_declarator_td '[' type_qualifier_list_opt '*' ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2, $3, $4, NULL, $5);
}
| direct_declarator_td par_open_bracket parameter_type_list ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR4, 7, $1, $2, $3, $4);
  typedef_drop_scope();
}
| direct_declarator_td '(' identifier_list_opt ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR5, 7, $1, $2, $3, $4);
}
| direct_declarator_td '(' error ')' { $$ = 0; }
| direct_declarator_td '[' error ']' { $$ = 0; }
| '(' error ')' { $$ = 0; }
;

storage_class_static :
  "static"
{
  $$ = tree_make_node3(NODE_DSSTORAGE, 4, $1);
}
;

pointer_opt : { $$ = 0; }
| pointer { $$ = $1; }
;

pointer :
  '*' type_qualifier_list_opt
{
  $$ = tree_make_node3(NODE_POINTER, 6, $1, $2, NULL);
}
| '*' type_qualifier_list_opt pointer
{
  $$ = tree_make_node3(NODE_POINTER, 6, $1, $2, $3);
}
;

type_qualifier_list_opt : { $$ = 0; }
| type_qualifier_list { $$ = $1; }
;

type_qualifier_list :
  type_qualifier { $$ = $1; }
| type_qualifier_list type_qualifier
{
  $$ = tree_merge($1, 0, $2);
}
;

parameter_type_list :
  parameter_list { $$ = $1; }
| "..."
{
  $$ = tree_make_node3(NODE_ELLIPSIS, 4, $1);
}
| parameter_list ',' "..."
{
  $$ = tree_merge($1, $2, tree_make_node3(NODE_ELLIPSIS, 4, $3));
}
;

parameter_list :
  parameter_declaration { $$ = $1; }
| parameter_list ',' parameter_declaration
{
  $$ = tree_merge($1, $2, $3);
}
;

parameter_declaration :
  declaration_specifiers_notype declarator
{
  $$ = tree_make_node3(NODE_DECL, 6, $1,
                       tree_make_node3(NODE_INITDECLR, 6, $2, NULL, NULL),
                       NULL);
  register_ident($2, 0);
}
| declaration_specifiers_notype
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, NULL, NULL);
}
| declaration_specifiers_notype abstract_declarator
{
  $$ = tree_make_node3(NODE_DECL, 6, $1,
                       tree_make_node3(NODE_INITDECLR, 6, $2, NULL, NULL),
                       NULL);
}
| declaration_specifiers_notype type_specifier declaration_specifiers_notd_opt declarator_td
{
  $$ = tree_make_node3(NODE_DECL, 6,
                       tree_merge(tree_merge($1, 0, $2), 0, $3),
                       tree_make_node3(NODE_INITDECLR, 6, $4, NULL, NULL),
                       NULL);
  register_ident($4, 0);
}
| declaration_specifiers_notype type_specifier declaration_specifiers_notd_opt
{
  $$ = tree_make_node3(NODE_DECL, 6,
                       tree_merge(tree_merge($1, 0, $2), 0, $3), NULL, NULL);
}
| declaration_specifiers_notype type_specifier declaration_specifiers_notd_opt abstract_declarator
{
  $$ = tree_make_node3(NODE_DECL, 6,
                       tree_merge(tree_merge($1, 0, $2), 0, $3),
                       tree_make_node3(NODE_INITDECLR, 6, $4, NULL, NULL),
                       NULL);
}
| type_specifier declaration_specifiers_notd_opt declarator_td
{
  $$ = tree_make_node3(NODE_DECL, 6,
                       tree_merge($1, 0, $2),
                       tree_make_node3(NODE_INITDECLR, 6, $3, NULL, NULL),
                       NULL);
  register_ident($3, 0);
}
| type_specifier declaration_specifiers_notd_opt
{
  $$ = tree_make_node3(NODE_DECL, 6,
                       tree_merge($1, 0, $2), NULL, NULL);
}
| type_specifier declaration_specifiers_notd_opt abstract_declarator
{
  $$ = tree_make_node3(NODE_DECL, 6,
                       tree_merge($1, 0, $2),
                       tree_make_node3(NODE_INITDECLR, 6, $3, NULL, NULL),
                       NULL);
}
;

identifier_list_opt : { $$ = 0; }
| identifier_list { $$ = $1; }
;

identifier_list :
  TOK_IDENT
{
  $$ = tree_make_node3(NODE_IDENTS, 4, $1);
}
| identifier_list ',' identifier_or_typename
{
  $$ = tree_merge($1, $2, tree_make_node3(NODE_IDENTS, 4, $3));
}
;

type_name :
  specifier_qualifier_list
{
  $$ = tree_make_node3(NODE_DECL, 6, $1, NULL, NULL);
}
| specifier_qualifier_list abstract_declarator
{
  $$ = tree_make_node3(NODE_DECL, 6, $1,
                       tree_make_node3(NODE_INITDECLR, 6, $2, NULL, NULL),
                       NULL);
}
;

abstract_declarator :
  pointer
{
  $$ = tree_make_node3(NODE_DECLR, 6, $1, NULL, NULL);
}
| pointer_opt direct_abstract_declarator
{
  $$ = tree_make_node3(NODE_DECLR, 6, $1, $2, NULL);
}
;

direct_abstract_declarator :
  '(' abstract_declarator ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR2, 6, $1, $2, $3);
}
| direct_abstract_declarator '[' assignment_expression_opt ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2, NULL, NULL, $3, $4);
}
| '[' assignment_expression_opt ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, NULL, $1, NULL, NULL, $2, $3);
}
| direct_abstract_declarator '[' '*' ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, $1, $2, NULL, $3, NULL, $4);
}
| '[' '*' ']'
{
  $$ = tree_make_node3(NODE_DIRDECLR3, 9, NULL, $1, NULL, $2, NULL, $3);
}
| direct_abstract_declarator par_open_bracket parameter_type_list ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR4, 7, $1, $2, $3, $4);
  typedef_drop_scope();
}
| direct_abstract_declarator '(' ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR5, 7, $1, $2, NULL, $3);
}
| par_open_bracket parameter_type_list ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR4, 7, NULL, $1, $2, $3);
  typedef_drop_scope();
}
| '(' ')'
{
  $$ = tree_make_node3(NODE_DIRDECLR5, 7, NULL, $1, NULL, $2);
}
;

typedef_name :
  TOK_TYPENAME { $$ = $1; }
;

initializer :
  assignment_expression
{
  $$ = tree_make_node3(NODE_INITEXPR, 6, NULL, NULL, $1);
}
| '{' '}'
{
  $$ = tree_make_node3(NODE_INITBLOCK, 9, NULL, NULL, $1, NULL, NULL, $2);
}
| '{' initializer_list '}'
{
  $$ = tree_make_node3(NODE_INITBLOCK, 9, NULL, NULL, $1, $2, NULL, $3);
}
| '{' initializer_list ',' '}'
{
  $$ = tree_make_node3(NODE_INITBLOCK, 9, NULL, NULL, $1, $2, $3, $4);
}
| '{' error '}' { $$ = 0; }
;

initializer_list :
  designated_initializer { $$ = $1; }
| initializer_list ',' designated_initializer
{
  $$ = tree_merge($1, $2, $3);
}
;

designated_initializer :
  initializer { $$ = $1; }
| designator_list '=' initializer
{
  if ($3) {
    $3->node.refs[3] = $1;
    $3->node.refs[4] = $2;
    tree_fix_pos($3, 3, $3->node.nrefs - 1);
  }
  $$ = $3;
}
| '[' constant_expression ']' initializer
{
  if ($4) {
    $4->node.refs[3] = tree_make_node3(NODE_DESARRAY, 6, $1, $2, $3);
    $4->node.refs[4] = 0;
    tree_fix_pos($4, 3, $4->node.nrefs - 1);
  }
  $$ = $4;
}
;

designator_list :
  designator { $$ = $1; }
| designator_list designator
{
  $$ = tree_merge($1, 0, $2);
}
;

designator :
  '[' constant_expression ']'
{
  $$ = tree_make_node3(NODE_DESARRAY, 6, $1, $2, $3);
}
| '.' identifier_or_typename
{
  $$ = tree_make_node3(NODE_DESFIELD, 5, $1, $2);
}
| '[' error ']' { $$ = 0; }
;

/* A.2.3 Statements */

statement :
  labeled_statement { $$ = $1; }
| compound_statement { $$ = $1; }
| expression_statement { $$ = $1; }
| empty_statement { $$ = $1; }
| selection_statement { $$ = $1; }
| iteration_statement { $$ = $1; }
| jump_statement { $$ = $1; }
;

nonempty_statement :
  labeled_statement { $$ = $1; }
| compound_statement { $$ = $1; }
| expression_statement { $$ = $1; }
| selection_statement { $$ = $1; }
| iteration_statement { $$ = $1; }
| jump_statement { $$ = $1; }
;

labeled_statement :
  direct_label statement
{
  $$ = tree_make_node3(NODE_STLABEL, 5, $1, $2);
}
;

direct_label :
  TOK_IDENT ':'
{
  $$ = tree_make_node3(NODE_LABID, 5, $1, $2);
}
| "case" constant_expression ':'
{
  $$ = tree_make_node3(NODE_LABCASE, 8, $1, $2, NULL, NULL, $3);
}
| "case" constant_expression "..." constant_expression ':'
{
  $$ = tree_make_node3(NODE_LABCASE, 8, $1, $2, $3, $4, $5);
}
| "default" ':'
{
  $$ = tree_make_node3(NODE_LABDEFAULT, 5, $1, $2);
}
| "case" error ':' { $$ = 0; }
;

compound_statement :
  compound_opening_brace block_item_list '}'
{
  $$ = tree_make_node3(NODE_STBLOCK, 6, $1, $2, $3);
  typedef_drop_scope();
}
| compound_opening_brace '}'
{
  $$ = tree_make_node3(NODE_STBLOCK, 6, $1, NULL, $2);
  typedef_drop_scope();
}
| compound_opening_brace error '}'
{
  $$ = 0;
  typedef_drop_scope();
}
;

compound_opening_brace :
  '{'
{
  $$ = $1;
  typedef_new_scope();
};

/*
block_item_list :
  block_item { $$ = $1; }
| block_item_list block_item
{
  $$ = tree_merge($1, 0, $2);
}
;

block_item :
  declaration { $$ = $1; }
| statement { $$ = $1; }
;
*/

block_item_list :
  decl_list
{
  $$ = $1;
}
| block_item_list1
{
  $$ = $1;
}
| block_item_list1 block_item_list2
{
  $$ = tree_merge($1, 0, $2);
}
| empty_stmt_list
{
  $$ = $1;
}
;

block_item_list1 :
  decl_list stmt_list
{
  $$ = tree_merge($1, 0, $2);
}
| stmt_list
{
  $$ = $1;
}
| empty_stmt_list decl_list stmt_list
{
  $$ = tree_merge(tree_merge($1, 0, $2), 0, $3);
}
| empty_stmt_list stmt_list
{
  $$ = tree_merge($1, 0, $2);
}
;

block_item_list2 :
  block_item2
{
  $$ = tree_make_node3(NODE_STSUBBLOCK, 6, NULL, $1, NULL);
}
| block_item2 block_item_list2
{
  $$ = tree_make_node3(NODE_STSUBBLOCK, 6, NULL, tree_merge($1, 0, $2), NULL);
}
;

block_item2 :
  decl_list stmt_list
{
  $$ = tree_merge($1, 0, $2);
}
;

decl_list :
  declaration
{
  $$ = $1;
}
| declaration decl_and_empty_stmt_list
{
  $$ = tree_merge($1, 0, $2);
}
;

decl_and_empty_stmt_list :
  decl_or_empty
{
  $$ = $1;
}
| decl_and_empty_stmt_list decl_or_empty
{
  $$ = tree_merge($1, 0, $2);
}
;

decl_or_empty :
  empty_statement
{
  $$ = $1;
}
| declaration
{
  $$ = $1;
}
;

stmt_list :
  nonempty_statement
{
  $$ = $1;
}
| nonempty_statement any_stmt_list
{
  $$ = tree_merge($1, 0, $2);
}
;

any_stmt_list :
  statement
{
  $$ = $1;
}
| any_stmt_list statement
{
  $$ = tree_merge($1, 0, $2);
}
;

empty_stmt_list :
  empty_statement
{
  $$ = $1;
}
| empty_stmt_list empty_statement
{
  $$ = tree_merge($1, 0, $2);
}
;

expression_statement :
  expression ';'
{
  $$ = tree_make_node3(NODE_STEXPR, 5, $1, $2);
}
;

empty_statement :
  ';'
{
  $$ = tree_make_node3(NODE_STEXPR, 5, NULL, $1);
}
;

selection_statement :
  "if" '(' expression_or_error ')' statement
{
  $$ = tree_make_node3(NODE_STIF, 10, $1, $2, $3, $4, $5, NULL, NULL);
}
| "if" '(' expression_or_error ')' statement "else" statement
{
  $$ = tree_make_node3(NODE_STIF, 10, $1, $2, $3, $4, $5, $6, $7);
}
| "switch" '(' expression_or_error ')' statement
{
  $$ = tree_make_node3(NODE_STSWITCH, 8, $1, $2, $3, $4, $5);
}
;

expression_or_error :
  expression { $$ = $1; }
| error { $$ = 0; }
;

iteration_statement :
  "while" '(' expression_or_error ')' statement
{
  $$ = tree_make_node3(NODE_STWHILE, 8, $1, $2, $3, $4, $5);
}
| "do" statement "while" '(' expression_or_error ')' ';'
{
  $$ = tree_make_node3(NODE_STDO, 10, $1, $2, $3, $4, $5, $6, $7);
}
| "for" '(' expression_opt ';' expression_opt ';' expression_opt ')' statement
{
  $$ = tree_make_node3(NODE_STFOR, 12, $1, $2, $3, $4, $5, $6, $7, $8, $9);
}
| "for" '(' declaration expression_opt ';' expression_opt ')' statement
{
  $$ = tree_make_node3(NODE_STFOR, 12, $1, $2, NULL, NULL,$4, $5, $6, $7, $8);
  $$ = tree_merge($3, 0, $$);
  $$ = tree_make_node3(NODE_STSUBBLOCK, 6, NULL, $$, NULL);
}
| "do" error "while" '(' expression_or_error ')' ';' { $$ = 0; }
| "for" '(' error ')' statement { $$ = 0; }
;

jump_statement :
  "goto" identifier_or_typename ';'
{
  $$ = tree_make_node3(NODE_STGOTO, 6, $1, $2, $3);
}
| "continue" ';'
{
  $$ = tree_make_node3(NODE_STCONTINUE, 5, $1, $2);
}
| "break" ';'
{
  $$ = tree_make_node3(NODE_STBREAK, 5, $1, $2);
}
| "return" expression_opt ';'
{
  $$ = tree_make_node3(NODE_STRETURN, 6, $1, $2, $3);
}
| "return" error ';' { $$ = 0; }
;

/* A.2.1 Expressions */

constant_expression :
  conditional_expression { $$ = $1; }
;

expression_opt : { $$ = 0; }
| expression { $$ = $1; }
;

expression :
  assignment_expression { $$ = $1; }
| expression ',' assignment_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

assignment_expression_opt : { $$ = 0; }
| assignment_expression { $$ = $1; }
;

assignment_expression :
  conditional_expression { $$ = $1; }
| unary_expression assignment_operator assignment_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

assignment_operator :
  '=' { $$ = $1; }
| "*=" { $$ = $1; }
| "/=" { $$ = $1; }
| "%=" { $$ = $1; }
| "+=" { $$ = $1; }
| "-=" { $$ = $1; }
| "<<=" { $$ = $1; }
| ">>=" { $$ = $1; }
| "&=" { $$ = $1; }
| "^=" { $$ = $1; }
| "|=" { $$ = $1; }
;

conditional_expression :
  logical_OR_expression { $$ = $1; }
| logical_OR_expression '?' expression ':' conditional_expression
{
  $$ = tree_make_node3(NODE_EXPRTERNARY, 8, $1, $2, $3, $4, $5);
}
;

logical_OR_expression :
  logical_AND_expression { $$ = $1; }
| logical_OR_expression "||" logical_AND_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

logical_AND_expression :
  inclusive_OR_expression { $$ = $1; }
| logical_AND_expression "&&" inclusive_OR_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

inclusive_OR_expression :
  exclusive_OR_expression { $$ = $1; }
| inclusive_OR_expression '|' exclusive_OR_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

exclusive_OR_expression :
  AND_expression { $$ = $1; }
| exclusive_OR_expression '^' AND_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

AND_expression :
  equality_expression { $$ = $1; }
| AND_expression '&' equality_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

equality_expression :
  relational_expression { $$ = $1; }
| equality_expression equality_operator relational_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

equality_operator :
  "==" { $$ = $1; }
| "!=" { $$ = $1; }
;

relational_expression :
  shift_expression { $$ = $1; }
| relational_expression relational_operator shift_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

relational_operator :
  '>' { $$ = $1; }
| '<' { $$ = $1; }
| "<=" { $$ = $1; }
| ">=" { $$ = $1; }
;

shift_expression :
  additive_expression { $$ = $1; }
| shift_expression shift_operator additive_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

shift_operator :
  ">>" { $$ = $1; }
| "<<" { $$ = $1; }
;

additive_expression :
  multiplicative_expression { $$ = $1; }
| additive_expression additive_operator multiplicative_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

additive_operator :
  '+' { $$ = $1; }
| '-' { $$ = $1; }
;

multiplicative_expression :
  cast_expression { $$ = $1; }
| multiplicative_expression multiplicative_operator cast_expression
{
  $$ = tree_make_node3(NODE_EXPRBINARY, 6, $1, $2, $3);
}
;

multiplicative_operator :
  '*' { $$ = $1; }
| '/' { $$ = $1; }
| '%' { $$ = $1; }
;

cast_expression :
  unary_expression { $$ = $1; }
| '(' type_name ')' cast_expression
{
  $$ = tree_make_node3(NODE_EXPRCAST, 7, $1, $2, $3, $4);
}
;

unary_expression :
  postfix_expression { $$ = $1; }
| "++" unary_expression
{
  $$ = tree_make_node3(NODE_EXPRUNARY, 5, $1, $2);
}
| "--" unary_expression
{
  $$ = tree_make_node3(NODE_EXPRUNARY, 5, $1, $2);
}
| unary_operator cast_expression
{
  $$ = tree_make_node3(NODE_EXPRUNARY, 5, $1, $2);
}
| "sizeof" unary_expression
{
  $$ = tree_make_node3(NODE_EXPRUNARY, 5, $1, $2);
}
| "sizeof" '(' type_name ')'
{
  $$ = tree_make_node3(NODE_EXPRSIZEOF, 7, $1, $2, $3, $4);
}
;

unary_operator :
  '&' { $$ = $1; }
| '*' { $$ = $1; }
| '+' { $$ = $1; }
| '-' { $$ = $1; }
| '~' { $$ = $1; }
| '!' { $$ = $1; }
;

postfix_expression :
  primary_expression { $$ = $1; }
| postfix_expression '[' expression ']'
{
  $$ = tree_make_node3(NODE_EXPRARRAY, 7, $1, $2, $3, $4);
}
| postfix_expression '[' error ']' { $$ = 0; }
| postfix_expression '(' argument_expression_list_opt ')'
{
  $$ = tree_make_node3(NODE_EXPRCALL, 7, $1, $2, $3, $4);
}
| postfix_expression '(' error ')' { $$ = 0; }
| postfix_expression '.' identifier_or_typename
{
  $$ = tree_make_node3(NODE_EXPRFIELD, 6, $1, $2, $3);
}
| postfix_expression "->" identifier_or_typename
{
  $$ = tree_make_node3(NODE_EXPRFIELD, 6, $1, $2, $3);
}
| postfix_expression "++"
{
  $$ = tree_make_node3(NODE_EXPRPOSTFIX, 5, $1, $2);
}
| postfix_expression "--"
{
  $$ = tree_make_node3(NODE_EXPRPOSTFIX, 5, $1, $2);
}
| '(' type_name ')' '{' initializer_list '}'
{
  $$ = tree_make_node3(NODE_EXPRINIT, 10, $1, $2, $3, $4, $5, NULL, $6);
}
| '(' type_name ')' '{' initializer_list ',' '}'
{
  $$ = tree_make_node3(NODE_EXPRINIT, 10, $1, $2, $3, $4, $5, $6, $7);
}
;

argument_expression_list_opt : { $$ = 0; }
| argument_expression_list { $$ = $1; }
;

argument_expression_list :
  assignment_expression { $$ = $1; }
| argument_expression_list ',' assignment_expression
{
  $$ = tree_merge($1, $2, $3);
}
;

string_concatenation :
  TOK_STRING
{
  $$ = tree_make_node3(NODE_EXPRSTRING, 5, NULL, $1);
}
| string_concatenation TOK_STRING
{
  $$ = tree_make_node3(NODE_EXPRSTRING, 5, $1, $2);
}
;

lstring_concatenation :
  TOK_LSTRING
{
  $$ = tree_make_node3(NODE_EXPRLSTRING, 5, NULL, $1);
}
| lstring_concatenation TOK_LSTRING
{
  $$ = tree_make_node3(NODE_EXPRLSTRING, 5, $1, $2);
}
;

primary_expression :
  TOK_IDENT
{
  $$ = tree_make_node3(NODE_EXPRIDENT, 4, $1);
}
| TOK_CONSTANT
{
  $$ = tree_make_node3(NODE_EXPRCONST, 4, $1);
}
| string_concatenation { $$ = $1; }
| lstring_concatenation { $$ = $1; }
| '(' expression ')'
{
  /* FIXME: maybe such a node is reduntant... */
  //$$ = tree_make_node3(NODE_EXPRBRACKETS, 6, $1, $2, $3);
  $$ = $2;
}
| '(' error ')' { $$ = 0; }
| "__builtin_va_start" '(' assignment_expression ',' assignment_expression ')'
{
  $$ = tree_make_node3(NODE_EXPRVASTART, 9, $1, $2, $3, $4, $5, $6);
}
| "__builtin_va_start" '(' error ')' { $$ = 0; }
| "__builtin_va_arg" '(' assignment_expression ',' type_name ')'
{
  $$ = tree_make_node3(NODE_EXPRVAARG, 9, $1, $2, $3, $4, $5, $6);
}
| "__builtin_va_arg" '(' error ')' { $$ = 0; }
| "__builtin_va_end" '(' assignment_expression ')'
{
  $$ = tree_make_node3(NODE_EXPRVAEND, 7, $1, $2, $3, $4);
}
| "__builtin_va_end" '(' error ')' { $$ = 0; }
| "__builtin_assert" '(' assignment_expression ')'
{
  $$ = tree_make_node3(NODE_EXPRASSERT, 7, $1, $2, $3, $4);
}
| "__builtin_assert" '(' error ')' { $$ = 0; }
| asm_specification
{
  $$ = $1;
}
| '(' compound_statement ')'
{
  $$ = tree_make_node3(NODE_EXPRSTMT, 6, $1, $2, $3);
}
;

identifier_or_typename_opt : { $$ = 0; }
| identifier_or_typename { $$ = $1; }
;

identifier_or_typename :
  TOK_IDENT    { $$ = $1; }
| TOK_TYPENAME { $$ = $1; }
;

attribute_specification_opt : { $$ = 0; }
| attribute_specification { $$ = $1; }
;

attribute_specification :
  "__attribute__" '(' '(' attribute_list ')' ')'
{
  $$ = tree_make_node3(NODE_ATTRIBUTE, 9, $1, $2, $3, $4, $5, $6);
}
;

attribute_list :
  attribute_item
{
  $$ = $1;
}
| attribute_list ',' attribute_item
{
  $$ = tree_merge($1, $2, $3);
}
;

attribute_item :
  attribute_name
{
  $$ = tree_make_node3(NODE_ATTRITEM, 7, $1, NULL, NULL, NULL);
}
| attribute_name '(' argument_expression_list ')'
{
  $$ = tree_make_node3(NODE_ATTRITEM, 7, $1, $2, $3, $4);
}
;

attribute_name :
  TOK_IDENT
{
  $$ = $1;
}
| TOK_TYPENAME
{
  $1->kind = TOK_IDENT;
  $$ = $1;
}
| "const"
{
  $$ = tree_make_ident(TOK_IDENT, &$1->tok.pos.beg, &$1->tok.pos.end,
                       ident_put("const", 5));
}
;

asm_specification :
  "asm" '(' TOK_STRING ')'
{
  $$ = tree_make_node3(NODE_EXPRASM, 13, $1, $2, $3, NULL, NULL, NULL, NULL,
                       NULL, NULL, $4);
}
| "asm" '(' TOK_STRING ':' asm_arg_list_opt ':' asm_arg_list_opt ')'
{
  $$ = tree_make_node3(NODE_EXPRASM, 13, $1, $2, $3, $4, $5, $6, $7,
                         NULL, NULL, $8);
}
| "asm" '(' TOK_STRING ':' asm_arg_list_opt ':' asm_arg_list_opt ':' asm_reg_list_opt ')'
{
  $$ = tree_make_node3(NODE_EXPRASM, 13, $1, $2, $3, $4, $5, $6, $7,$8,$9,$10);
}
;

asm_arg_list_opt :
  /* empty */
{
  $$ = 0;
}
| asm_arg_list
{
  $$ = $1;
};

asm_arg_list :
  asm_arg_spec
{
  $$ = $1;
}
| asm_arg_list ',' asm_arg_spec
{
  $$ = tree_merge($1, $2, $3);
}
;

asm_arg_spec :
  TOK_STRING '(' expression ')'
{
  $$ = tree_make_node3(NODE_ASMARG, 7, $1, $2, $3, $4);
};

asm_reg_list_opt :
  /* empty */
{
  $$ = 0;
}
| asm_reg_list
{
  $$ = $1;
};

asm_reg_list :
  asm_reg
{
  $$ = $1;
}
| asm_reg_list ',' asm_reg
{
  $$ = tree_merge($1, $2, $3);
}
;

asm_reg :
  TOK_STRING
{
  $$ = tree_make_node3(NODE_ASMARG, 7, $1, NULL, NULL, NULL);
}
;

%%

static void
yyerror(const unsigned char *msg)
{
  c_err(&yylval->gen.pos.beg, "%s", msg);
}

static int
declspec_is_typedef(tree_t ds)
{
  while (1) {
    if (!ds) return 0;
    switch (ds->kind) {
    case NODE_DSSTORAGE:
      if (ds->node.refs[3] && ds->node.refs[3]->kind == TOK_TYPEDEF)
        return 1;
      break;
    case NODE_DSSTDTYPE:
    case NODE_DSTYPENAME:
    case NODE_DSQUAL:
    case NODE_DSFUNCSPEC:
    case NODE_DSENUM:
    case NODE_DSAGGREG:
    case NODE_DSTYPEOF:
      break;
    default:
      SWERR(("invalid declspec node"));
    }
    ds = ds->node.refs[0];
  }
  return 0;
}

static void
register_ident(tree_t p, int typedef_flag)
{
  tree_t pid;

  pid = tree_get_ident_node(p);
  if (!pid) return;
  ASSERT(pid->kind == TOK_IDENT || pid->kind == TOK_TYPENAME);
  if (typedef_flag) {
    typedef_register_typedef(pid->id.id);
  } else {
    typedef_register_regular(pid->id.id);
  }
}

static void
rereg_par_scope(tree_t p)
{
  tree_t q, r;

  typedef_new_scope();

  while (1) {
    if (!p) return;
    switch (p->kind) {
    case NODE_DECLR:
      p = p->node.refs[4];
      break;
    case NODE_DIRDECLR1:
      return;
    case NODE_DIRDECLR2:
      p = p->node.refs[4];
      break;
    case NODE_DIRDECLR3:
      p = p->node.refs[3];
      break;
    case NODE_DIRDECLR4:
    case NODE_DIRDECLR5:
      if (p->node.refs[3] && p->node.refs[3]->kind == NODE_DIRDECLR1)
        goto loop_out;
      p = p->node.refs[3];
      break;
    default:
      SWERR(("rereg_par_scope: unhandled node"));
    }
  }
 loop_out:
  ;

  ASSERT(p->kind == NODE_DIRDECLR4 || p->kind == NODE_DIRDECLR5);
  ASSERT(p->node.refs[3]);
  ASSERT(p->node.refs[3]->kind == NODE_DIRDECLR1);

  if (p->kind == NODE_DIRDECLR4) {
    for (q = p->node.refs[5]; q; q = q->node.refs[0]) {
      if (q->kind == NODE_ELLIPSIS) continue;
      r = tree_get_ident_node(q->node.refs[4]);
      if (!r) continue;
      typedef_register_regular(r->id.id);
    }
  } else /* p->kind == NODE_DIRDECLR5 */ {
    for (q = p->node.refs[5]; q; q = q->node.refs[0]) {
      if (!q->node.refs[3]) continue;
      typedef_register_regular(q->node.refs[3]->id.id);
    }
  }
}

int
parser_parse(tree_t *presult)
{
  *presult = 0;
  typedef_new_scope();
  yyparse();
  typedef_free();
  if (c_err_get_count() > 0) {
    return -1;
  }
  *presult = tree;
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */

