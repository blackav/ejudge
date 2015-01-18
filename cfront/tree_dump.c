/* -*- mode: c -*- */

/* Copyright (C) 2008-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "tree.h"

#include "ejudge/number_io.h"

static unsigned char *node_names[] =
{
  [TOK_INCR] = "\"++\"",
  [TOK_DECR] = "\"--\"",
  [TOK_LSHIFT] = "\"<<\"",
  [TOK_RSHIFT] = "\">>\"",
  [TOK_LEQ] = "\"<=\"",
  [TOK_GEQ] = "\">=\"",
  [TOK_EQ] = "\"==\"",
  [TOK_NEQ] = "\"!=\"",
  [TOK_LOGAND] = "\"&&\"",
  [TOK_LOGOR] = "\"||\"",
  [TOK_LOGXOR] = "\"^^\"",
  [TOK_ELLIPSIS] = "\"...\"",
  [TOK_MULASSIGN] = "\"*=\"",
  [TOK_DIVASSIGN] = "\"/=\"",
  [TOK_MODASSIGN] = "\"%=\"",
  [TOK_ADDASSIGN] = "\"+=\"",
  [TOK_SUBASSIGN] = "\"-=\"",
  [TOK_LSHASSIGN] = "\"<<=\"",
  [TOK_RSHASSIGN] = "\">>=\"",
  [TOK_ANDASSIGN] = "\"&=\"",
  [TOK_XORASSIGN] = "\"^=\"",
  [TOK_ORASSIGN] = "\"|=\"",
  [TOK_ARROW] = "\"->\"",

  [TOK_AUTO] = "\"auto\"",
  [TOK_BREAK] = "\"break\"",
  [TOK_CASE] = "\"case\"",
  [TOK_CHAR] = "\"char\"",
  [TOK_CONST] = "\"const\"",
  [TOK_CONTINUE] = "\"continue\"",
  [TOK_DEFAULT] = "\"default\"",
  [TOK_DO] = "\"do\"",
  [TOK_DOUBLE] = "\"double\"",
  [TOK_ELSE] = "\"else\"",
  [TOK_ENUM] = "\"enum\"",
  [TOK_EXTERN] = "\"extern\"",
  [TOK_FLOAT] = "\"float\"",
  [TOK_FOR] = "\"for\"",
  [TOK_GOTO] = "\"goto\"",
  [TOK_IF] = "\"if\"",
  [TOK_INLINE] = "\"inline\"",
  [TOK_INT] = "\"int\"",
  [TOK_LONG] = "\"long\"",
  [TOK_REGISTER] = "\"register\"",
  [TOK_RESTRICT] = "\"restrict\"",
  [TOK_RETURN] = "\"return\"",
  [TOK_SHORT] = "\"short\"",
  [TOK_SIGNED] = "\"signed\"",
  [TOK_SIZEOF] = "\"sizeof\"",
  [TOK_STATIC] = "\"static\"",
  [TOK_STRUCT] = "\"struct\"",
  [TOK_SWITCH] = "\"switch\"",
  [TOK_TYPEDEF] = "\"typedef\"",
  [TOK_UNION] = "\"union\"",
  [TOK_UNSIGNED] = "\"unsigned\"",
  [TOK_VOID] = "\"void\"",
  [TOK_VOLATILE] = "\"volatile\"",
  [TOK_WHILE] = "\"while\"",
  [TOK__BOOL] = "\"_bool\"",
  [TOK__COMPLEX] = "\"_complex\"",
  [TOK__IMAGINARY] = "\"_imaginary\"",
  [TOK_VA_LIST] = "\"va_list\"",
  [TOK_VA_START] = "\"va_start\"",
  [TOK_VA_ARG] = "\"va_arg\"",
  [TOK_VA_END] = "\"va_end\"",
  [TOK_TYPEOF] = "\"typeof\"",
  [TOK_ASM] = "\"asm\"",
  [TOK_ATTRIBUTE] = "\"attribute\"",
  [TOK_ASSERT] = "\"assert\"",
  [TOK___ANNOT] = "\"__annot\"",

  [NODE_ROOT] = "ROOT",
  [NODE_DECLFUNC] = "DECLFUNC",
  [NODE_DECL] = "DECL",
  [NODE_ELLIPSIS] = "ELLIPSIS",
  [NODE_DSSTDTYPE] = "DSSTDTYPE",
  [NODE_DSTYPENAME] = "DSTYPENAME",
  [NODE_DSSTORAGE] = "DSSTORAGE",
  [NODE_DSQUAL] = "DSQUAL",
  [NODE_DSFUNCSPEC] = "DSFUNCSPEC",
  [NODE_DSENUM] = "DSENUM",
  [NODE_DSAGGREG] = "DSAGGREG",
  [NODE_DSTYPEOF] = "DSTYPEOF",
  [NODE_ENUMERATOR] = "ENUMERATOR",
  [NODE_INITDECLR] = "INITDECLR",
  [NODE_STRUCTDECLR] = "STRUCTDECLR",
  [NODE_DECLR] = "DECLR",
  [NODE_POINTER] = "POINTER",
  [NODE_DIRDECLR1] = "DIRDECLR1",
  [NODE_DIRDECLR2] = "DIRDECLR2",
  [NODE_DIRDECLR3] = "DIRDECLR3",
  [NODE_DIRDECLR4] = "DIRDECLR4",
  [NODE_DIRDECLR5] = "DIRDECLR5",
  [NODE_IDENTS] = "IDENTS",
  [NODE_INITEXPR] = "INITEXPR",
  [NODE_INITBLOCK] = "INITBLOCK",
  [NODE_DESARRAY] = "DESARRAY",
  [NODE_DESFIELD] = "DESFIELD",
  [NODE_LABID] = "LABID",
  [NODE_LABCASE] = "LABCASE",
  [NODE_LABDEFAULT] = "LABDEFAULT",
  [NODE_STLABEL] = "STLABEL",
  [NODE_STBLOCK] = "STBLOCK",
  [NODE_STSUBBLOCK] = "STSUBBLOCK",
  [NODE_STEXPR] = "STEXPR",
  [NODE_STIF] = "STIF",
  [NODE_STSWITCH] = "STSWITCH",
  [NODE_STWHILE] = "STWHILE",
  [NODE_STDO] = "STDO",
  [NODE_STFOR] = "STFOR",
  [NODE_STDECLFOR] = "STDECLFOR",
  [NODE_STGOTO] = "STGOTO",
  [NODE_STCONTINUE] = "STCONTINUE",
  [NODE_STBREAK] = "STBREAK",
  [NODE_STRETURN] = "STRETURN",
  [NODE_EXPRTERNARY] = "EXPRTERNARY",
  [NODE_EXPRBINARY] = "EXPRBINARY",
  [NODE_EXPRCAST] = "EXPRCAST",
  [NODE_EXPRSIZEOF] = "EXPRSIZEOF",
  [NODE_EXPRUNARY] = "EXPRUNARY",
  [NODE_EXPRARRAY] = "EXPRARRAY",
  [NODE_EXPRCALL] = "EXPRCALL",
  [NODE_EXPRFIELD] = "EXPRFIELD",
  [NODE_EXPRPOSTFIX] = "EXPRPOSTFIX",
  [NODE_EXPRBRACKETS] = "EXPRBRACKETS",
  [NODE_EXPRIDENT] = "EXPRIDENT",
  [NODE_EXPRCONST] = "EXPRCONST",
  [NODE_EXPRSTRING] = "EXPRSTRING",
  [NODE_EXPRVASTART] = "EXPRVASTART",
  [NODE_EXPRVAARG] = "EXPRVAARG",
  [NODE_EXPRVAEND] = "EXPRVAEND",
  [NODE_EXPRINIT] = "EXPRINIT",
  [NODE_EXPRASM] = "EXPRASM",
  [NODE_EXPRASSERT] = "EXPRASSERT",
  [NODE_ASMARG] = "ASMARG",
  [NODE_ATTRIBUTE] = "ATTRIBUTE",
  [NODE_ATTRITEM] = "ATTRITEM",
  [NODE_SEMA] = "SEMA",
};

static const unsigned char *
tree_get_short_node_name(int kind)
{
  static unsigned char buf[64];

  if (kind <= 0 || kind >= (sizeof(node_names) / sizeof(node_names[0]))) {
    //snprintf(buf, sizeof(buf), "(%d)", kind);
    abort();
    return buf;
  }
  if (kind <= ' ' || (kind >= 127 && kind < 258)) {
    //snprintf(buf, sizeof(buf), "(%d)", kind);
    abort();
    return buf;
  }
  if (kind < 256) {
    snprintf(buf, sizeof(buf), "\"%c\"", kind);
    return buf;
  }
  if (!node_names[kind]) {
    //snprintf(buf, sizeof(buf), "(%d)", kind);
    abort();
    return buf;
  }
  return node_names[kind];
}

static void
dump_string(
	FILE *fout,
        const unsigned char *str,
        size_t len)
{
  size_t i;

  if (!str || !len) {
    fprintf(fout, " S(\"\")");
    return;
  }

  fprintf(fout, " S(\"");
  for (i = 0; i < len - 1; i++) {
    switch (str[i]) {
    case '\t': fputs("\\t", fout); continue;
    case '\n': fputs("\\n", fout); continue;
    case '\r': fputs("\\r", fout); continue;
    case '\'': fputs("\\\'", fout); continue;
    case '\"': fputs("\\\"", fout); continue;
    case '\\': fputs("\\\\", fout); continue;
    }
    if (str[i] < ' ' || str[i] >= 0x7f) {
      fprintf(fout, "\\x%02x", str[i]);
      continue;
    }
    putc(str[i], fout);
  }
  fprintf(fout, "\")");
}

static void
dump_value(
	FILE *fout,
        c_value_t *pval)
{
  unsigned char buf[1024];

  switch (pval->tag) {
  case C_BOOL:
    fprintf(fout, " V(%s)", pval->v.ct_bool?"true":"false");
    break;
  case C_CHAR:
  case C_SCHAR:
    fprintf(fout, " V(%dhh)", pval->v.ct_schar);
    break;
  case C_UCHAR:
    fprintf(fout, " V(%uuhh)", pval->v.ct_uchar);
    break;
  case C_SHORT:
    fprintf(fout, " V(%dh)", pval->v.ct_short);
    break;
  case C_USHORT:
    fprintf(fout, " V(%uuh)", pval->v.ct_ushort);
    break;
  case C_INT:
    fprintf(fout, " V(%d)", pval->v.ct_int);
    break;
  case C_UINT:
    fprintf(fout, " V(%uu)", pval->v.ct_uint);
    break;
  case C_LONG:
    fprintf(fout, " V(%ldl)", pval->v.ct_lint);
    break;
  case C_ULONG:
    fprintf(fout, " V(%luul)", pval->v.ct_ulint);
    break;

  case C_LLONG:
    reuse_writell(buf, sizeof(buf), &pval->v.ct_llint, 10, 0, 0);
    fprintf(fout, " V(%sll)", buf);
    break;

  case C_ULLONG:
    reuse_writeull(buf, sizeof(buf), &pval->v.ct_ullint, 10, 0, 0);
    fprintf(fout, " V(%sull)", buf);
    break;

  case C_FLOAT:
    reuse_writehf(buf, sizeof(buf), &pval->v.ct_float, 0, 0);
    fprintf(fout, " V(%sf)", buf);
    break;

  case C_DOUBLE:
    reuse_writehd(buf, sizeof(buf), &pval->v.ct_double, 0, 0);
    fprintf(fout, " V(%s)", buf);
    break;

  case C_LDOUBLE:
    reuse_writehld(buf, sizeof(buf), &pval->v.ct_ldouble, 0, 0);
    fprintf(fout, " V(%sl)", buf);
    break;

  case C_QDOUBLE:
    fprintf(fout, " QDOUBLE_VALUE");
    break;

  case C_FIMAGINARY:
    fprintf(fout, " FIMAGINARY_VALUE");
    break;

  case C_DIMAGINARY:
    fprintf(fout, " DIMAGINARY_VALUE");
    break;

  case C_LIMAGINARY:
    fprintf(fout, " LIMAGINARY_VALUE");
    break;

  case C_QIMAGINARY:
    fprintf(fout, " QIMAGINARY_VALUE");
    break;

  case C_FCOMPLEX:
    fprintf(fout, " FCOMPLEX_VALUE");
    break;

  case C_DCOMPLEX:
    fprintf(fout, " DCOMPLEX_VALUE");
    break;

  case C_LCOMPLEX:
    fprintf(fout, " LCOMPLEX_VALUE");
    break;

  case C_QCOMPLEX:
    fprintf(fout, " QCOMPLEX_VALUE");
    break;

  default:
    abort();
  }
}

static void
tree_dump_list(
	FILE *fout,
        tree_t node,
        const unsigned char *list_tag)
{
  if (!node && list_tag) {
    fprintf(fout, " null");
    return;
  }

  if (list_tag) fprintf(fout, " (%s", list_tag);
  while (node) {
    if (node->node.refs[2]) tree_dump(fout, node->node.refs[2]);
    tree_dump(fout, node);
    node = node->node.refs[0];
  }
  if (list_tag) fprintf(fout, ")");
}

void
tree_dump(
	FILE *fout,
        tree_t root)
{
  int i;

  if (!root) {
    fprintf(fout, " null");
    return;
  }

  switch (root->kind) {
  case ';':
  case ',':
  case '=':
  case '{':
  case '}':
  case ':':
  case '(':
  case ')':
  case '[':
  case ']':
  case '*':
  case '.':
  case '?':
  case '|':
  case '^':
  case '&':
  case '>':
  case '<':
  case '+':
  case '-':
  case '/':
  case '%':
  case '~':
  case '!':

  case TOK_INCR:
  case TOK_DECR:
  case TOK_LSHIFT:
  case TOK_RSHIFT:
  case TOK_LEQ:
  case TOK_GEQ:
  case TOK_EQ:
  case TOK_NEQ:
  case TOK_LOGAND:
  case TOK_LOGOR:
  case TOK_LOGXOR:
  case TOK_ELLIPSIS:
  case TOK_MULASSIGN:
  case TOK_DIVASSIGN:
  case TOK_MODASSIGN:
  case TOK_ADDASSIGN:
  case TOK_SUBASSIGN:
  case TOK_LSHASSIGN:
  case TOK_RSHASSIGN:
  case TOK_ANDASSIGN:
  case TOK_XORASSIGN:
  case TOK_ORASSIGN:
  case TOK_ARROW:
  case TOK_AUTO:
  case TOK_BREAK:
  case TOK_CASE:
  case TOK_CHAR:
  case TOK_CONST:
  case TOK_CONTINUE:
  case TOK_DEFAULT:
  case TOK_DO:
  case TOK_DOUBLE:
  case TOK_ELSE:
  case TOK_ENUM:
  case TOK_EXTERN:
  case TOK_FLOAT:
  case TOK_FOR:
  case TOK_GOTO:
  case TOK_IF:
  case TOK_INLINE:
  case TOK_INT:
  case TOK_LONG:
  case TOK_REGISTER:
  case TOK_RESTRICT:
  case TOK_RETURN:
  case TOK_SHORT:
  case TOK_SIGNED:
  case TOK_SIZEOF:
  case TOK_STATIC:
  case TOK_STRUCT:
  case TOK_SWITCH:
  case TOK_TYPEDEF:
  case TOK_UNION:
  case TOK_UNSIGNED:
  case TOK_VOID:
  case TOK_VOLATILE:
  case TOK_WHILE:
  case TOK__BOOL:
  case TOK__COMPLEX:
  case TOK__IMAGINARY:
  case TOK_VA_LIST:
  case TOK_VA_START:
  case TOK_VA_ARG:
  case TOK_VA_END:
  case TOK_TYPEOF:
  case TOK_ASM:
  case TOK_ATTRIBUTE:
  case TOK_ASSERT:
  case TOK___ANNOT:
    fprintf(fout, " %s", tree_get_short_node_name(root->kind));
  break;

  case TOK_CONSTANT:
    dump_value(fout, &root->val.val);
    break;

  case TOK_IDENT:
    fprintf(fout, " I(\"%s\")", ident_get(root->id.id));
    break;

  case TOK_TYPENAME:
    fprintf(fout, " T(\"%s\")", ident_get(root->id.id));
    break;

  case TOK_STRING:
    dump_string(fout, root->str.val, root->str.len);
    break;

  case NODE_ROOT:
    fprintf(fout, " (%s ", tree_get_short_node_name(root->kind));
    tree_dump_list(fout, root->node.refs[3], "DECLS");
    fprintf(fout, ")");
    break;
  case NODE_DECLFUNC:
    fprintf(fout, " (%s ", tree_get_short_node_name(root->kind));
    tree_dump_list(fout, root->node.refs[3], "DECLSPECS");
    tree_dump(fout, root->node.refs[4]);
    tree_dump_list(fout, root->node.refs[5], "DECLS");
    tree_dump(fout, root->node.refs[6]);
    fprintf(fout, ")");
    break;

  case NODE_DECL:
    fprintf(fout, " (%s ", tree_get_short_node_name(root->kind));
    tree_dump_list(fout, root->node.refs[3], "DECLSPECS");
    tree_dump_list(fout, root->node.refs[4], "INITDECLRS");
    tree_dump(fout, root->node.refs[5]);
    fprintf(fout, ")");
    break;

  case NODE_ELLIPSIS:
    //case NODE_ANNOT:
  case NODE_DSSTDTYPE:
  case NODE_DSTYPENAME:
  case NODE_DSSTORAGE:
  case NODE_DSQUAL:
  case NODE_DSFUNCSPEC:
    goto generic;

  case NODE_DSENUM:
    fprintf(fout, " (%s ", tree_get_short_node_name(root->kind));
    tree_dump(fout, root->node.refs[3]);
    tree_dump(fout, root->node.refs[4]);
    tree_dump(fout, root->node.refs[5]);
    tree_dump_list(fout, root->node.refs[6], "ENUMERATORS");
    tree_dump(fout, root->node.refs[8]);
    fprintf(fout, ")");
    break;

  case NODE_DSAGGREG:
    fprintf(fout, " (%s ", tree_get_short_node_name(root->kind));
    tree_dump(fout, root->node.refs[3]);
    tree_dump(fout, root->node.refs[4]);
    tree_dump(fout, root->node.refs[5]);
    tree_dump_list(fout, root->node.refs[6], "DECLS");
    tree_dump(fout, root->node.refs[7]);
    fprintf(fout, ")");
    break;

  case NODE_DSTYPEOF:
  case NODE_ENUMERATOR:
  case NODE_INITDECLR:
  case NODE_STRUCTDECLR:
  case NODE_DECLR:
  case NODE_POINTER:
  case NODE_DIRDECLR1:
  case NODE_DIRDECLR2:
  case NODE_DIRDECLR3:
    goto generic;

  case NODE_DIRDECLR4:
    fprintf(fout, " (%s ", tree_get_short_node_name(root->kind));
    tree_dump(fout, root->node.refs[3]);
    tree_dump(fout, root->node.refs[4]);
    tree_dump_list(fout, root->node.refs[5], "DECLS");
    tree_dump(fout, root->node.refs[6]);
    fprintf(fout, ")");
    break;

  case NODE_DIRDECLR5:
  case NODE_IDENTS:
  case NODE_INITEXPR:
  case NODE_INITBLOCK:
  case NODE_DESARRAY:
  case NODE_DESFIELD:
  case NODE_LABID:
  case NODE_LABCASE:
  case NODE_LABDEFAULT:
  case NODE_STLABEL:
    goto generic;

  case NODE_STBLOCK:
    fprintf(fout, " (%s ", tree_get_short_node_name(root->kind));
    tree_dump(fout, root->node.refs[3]);
    tree_dump_list(fout, root->node.refs[4], /*"STMTS"*/ 0);
    tree_dump(fout, root->node.refs[5]);
    fprintf(fout, ")");
    break;

  case NODE_STSUBBLOCK:
  case NODE_STEXPR:
  case NODE_STIF:
  case NODE_STSWITCH:
  case NODE_STWHILE:
  case NODE_STDO:
  case NODE_STFOR:
  case NODE_STDECLFOR:
  case NODE_STGOTO:
  case NODE_STCONTINUE:
  case NODE_STBREAK:
  case NODE_STRETURN:
  case NODE_EXPRTERNARY:
  case NODE_EXPRBINARY:
  case NODE_EXPRCAST:
  case NODE_EXPRSIZEOF:
  case NODE_EXPRUNARY:
  case NODE_EXPRARRAY:
    goto generic;

  case NODE_EXPRCALL:
    fprintf(fout, " (%s ", tree_get_short_node_name(root->kind));
    tree_dump(fout, root->node.refs[3]);
    tree_dump(fout, root->node.refs[4]);
    tree_dump_list(fout, root->node.refs[5], "EXPRS");
    tree_dump(fout, root->node.refs[6]);
    fprintf(fout, ")");
    break;

  case NODE_EXPRFIELD:
  case NODE_EXPRPOSTFIX:
  case NODE_EXPRBRACKETS:
  case NODE_EXPRIDENT:
  case NODE_EXPRCONST:
  case NODE_EXPRSTRING:
  case NODE_EXPRLSTRING:
  case NODE_EXPRVASTART:
  case NODE_EXPRVAARG:
  case NODE_EXPRVAEND:
  case NODE_EXPRINIT:
  case NODE_EXPRASM:
  case NODE_EXPRASSERT:
  case NODE_EXPRSTMT:
  case NODE_ASMARG:
  case NODE_ATTRIBUTE:
  case NODE_ATTRITEM:
  generic:
    fprintf(fout, " (%s ", tree_get_short_node_name(root->kind));
    for (i = 3; i < root->node.nrefs; i++)
      tree_dump(fout, root->node.refs[i]);
    fprintf(fout, ")");
    break;

  default:
    fprintf(fout, " NODE(%s)", tree_get_node_name(root->kind));
  }
}
