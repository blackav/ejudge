/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "ej_limits.h"
#include "ej_types.h"

#include "type_info.h"
#include "dwarf_parse.h"
#include "html_parse.h"
#include "xml_utils.h"

#include "reuse/osdeps.h"
#include "reuse/xalloc.h"
#include "reuse/c_value.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>

struct ProcessorState;
struct ScannerState;

static void
parser_error_2(struct ProcessorState *ps, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
static void
dump_token(struct ScannerState *ss)
    __attribute__((unused));

static unsigned char *progname = NULL;
static void
fatal(const char *format, ...)
    __attribute__((format(printf, 1, 2), noreturn));
static void
fatal(const char *format, ...)
{
    unsigned char buf[512];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "%s: %s\n", progname, buf);
    exit(2);
}
static void
report_version(void)
{
    //printf("%s: ejudge version %s compiled %s\n", progname, compile_version, compile_date);
    exit(0);
}
static void
report_help(void)
{
    //printf("%s: ejudge version %s compiled %s\n", progname, compile_version, compile_date);
    exit(0);
}

struct MemoryBuffer
{
    unsigned char *str;
    int len;
};
struct MemoryBufferArray
{
    int a, u;
    struct MemoryBuffer *v;
};
static struct MemoryBufferArray strs;

static unsigned char const * const armored_c_translate_table[256] =
{
  "\\0", "\\x01", "\\x02", "\\x03", "\\x04", "\\x05", "\\x06", "\\a", "\\b", "\\t", "\\n", "\\v", "\\f", "\\r", "\\x0e", "\\x0f", 
  "\\x10", "\\x11", "\\x12", "\\x13", "\\x14", "\\x15", "\\x16", "\\x17", "\\x18", "\\x19", "\\x1a", "\\x1b", "\\x1c", "\\x1d", "\\x1e", "\\x1f", 
  0, 0, "\\\"", 0, 0, 0, 0, "\\\'", 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "\\\\", 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "\\x7f", 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
};

static void
emit_str_literal(FILE *out_f, const unsigned char *data, int len)
{
    putc('\"', out_f);
    const unsigned char *p = data;
    int rem = len;
    for (; rem > 0; ++p, --rem) {
        if (armored_c_translate_table[*p]) {
            fputs(armored_c_translate_table[*p], out_f);
        } else {
            putc(*p, out_f);
        }
    }
    putc('\"', out_f);
}

// token types
enum
{
    TOK_EOF = 0,
    TOK_IDENT,
    TOK_STRING,
    TOK_CHAR,
    TOK_NUMBER,
    TOK_FPNUMBER,
    TOK_OPER,
};

typedef struct Position
{
    int filename_idx;
    int line;
    int column;
} Position;

static void
pos_next(Position *p, int c)
{
    if (c == '\n') {
        ++p->line;
        p->column = 0;
    } else if (c == '\t') {
        p->column = (p->column + 8) & ~7;
    } else {
        ++p->column;
    }
}
static void
pos_next_n(Position *p, int n)
{
    p->column += n;
}

typedef struct GlobalSetting
{
    TypeInfo *name;
    TypeInfo *value;
} GlobalSetting;
typedef struct GlobalSettingArray
{
    int a, u;
    GlobalSetting *v;
} GlobalSettingArray;

typedef struct HtmlElementStack
{
    struct HtmlElementStack *up;
    HtmlElement *el;
    void *extra;
} HtmlElementStack;

typedef struct NamedUrl
{
    TypeInfo *name;
    HtmlElement *value;
} NamedUrl;
typedef struct NamedUrlArray
{
    int a, u;
    NamedUrl *v;
} NamedUrlArray;

struct ProcessorState;

typedef void (*TypeHandler)(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info);

typedef struct TypeHandlerInfo
{
    TypeInfo *type_info;
    TypeHandler handler;
} TypeHandlerInfo;

typedef struct TypeHandlerArray
{
    int a, u;
    TypeHandlerInfo *v;
} TypeHandlerArray;

typedef struct ProcessorState
{
    unsigned char **filenames;
    int filename_a, filename_u;

    Position pos;
    int error_count;

    FILE *log_f;
    HtmlElementStack *el_stack;
    GlobalSettingArray settings;
    IdScope *scope_stack;
    TypeHandlerArray type_handlers;
    TypeHandlerArray array_type_handlers;
    TypeHandler default_type_handler;
    NamedUrlArray urls;
} ProcessorState;

static ProcessorState *
processor_state_init(FILE *log_f)
{
    ProcessorState *ps = NULL;
    XCALLOC(ps, 1);
    ps->filename_a = 16;
    XCALLOC(ps->filenames, ps->filename_a);
    ps->filename_u = 1;
    ps->log_f = log_f;
    return ps;
}

static void
processor_state_init_file(ProcessorState *ps, const unsigned char *filename)
{
    int i;
    for (i = 1; i < ps->filename_u; ++i) {
        if (!strcmp(ps->filenames[i], filename))
            break;
    }
    if (i == ps->filename_u) {
        if (ps->filename_u >= ps->filename_a) {
            XREALLOC(ps->filenames, ps->filename_a *= 2);
        }
        ps->filenames[ps->filename_u++] = xstrdup(filename);
    }

    ps->pos.filename_idx = i;
    ps->pos.line = 1;
    ps->pos.column = 0;
}

static TypeInfo *
processor_state_find_setting(ProcessorState *ps, TypeInfo *name)
{
    for (int i = 0; i < ps->settings.u; ++i) {
        if (ps->settings.v[i].name == name)
            return ps->settings.v[i].value;
    }
    return NULL;
}

static IdScope *
processor_state_push_scope(ProcessorState *ps, IdScope *cur)
{
    cur->up = ps->scope_stack;
    ps->scope_stack = cur;
    return cur;
}

static void
processor_state_pop_scope(ProcessorState *ps)
{
    IdScope *cur = ps->scope_stack;
    if (cur) {
        ps->scope_stack = cur->up;
        tc_scope_destroy(cur);
    }
}

static TypeInfo *
processor_state_find_in_scopes(ProcessorState *ps, TypeInfo *id)
{
    return tc_scope_find(ps->scope_stack, id);
}

static void
processor_state_add_to_scope(ProcessorState *ps, TypeInfo *def)
{
    tc_scope_add(ps->scope_stack, def);
}

static void
processor_state_invoke_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    if (type_info && type_info->kind == NODE_ARRAY_TYPE) {
        for (int i = 0; i < ps->array_type_handlers.u; ++i) {
            if (ps->array_type_handlers.v[i].type_info == type_info->n.info[1]) {
                return ps->array_type_handlers.v[i].handler(log_f, cntx, ps, txt_f, prg_f, text, elem, type_info);
            }
        }
    }

    for (int i = 0; i < ps->type_handlers.u; ++i) {
        if (ps->type_handlers.v[i].type_info == type_info) {
            return ps->type_handlers.v[i].handler(log_f, cntx, ps, txt_f, prg_f, text, elem, type_info);
        }
    }
    parser_error_2(ps, "no type handler installed");
    tc_print_2(log_f, type_info, 3);
    fprintf(log_f, "\n");
    if (!ps->default_type_handler) {
        return;
    }
    return ps->default_type_handler(log_f, cntx, ps, txt_f, prg_f, text, elem, type_info);
}

static void
add_type_handler(
        TypeHandlerArray *pa,
        TypeInfo *type_info,
        TypeHandler handler)
{
    if (!type_info) return;

    int i;
    for (i = 0; i < pa->u && pa->v[i].type_info != type_info; ++i) {}
    if (i >= pa->u) {
        if (pa->u >= pa->a) {
            if (!(pa->a *= 2)) pa->a = 32;
            XREALLOC(pa->v, pa->a);
        }
        pa->v[i].type_info = type_info;
        ++pa->u;
    }
    pa->v[i].handler = handler;
}

static void
processor_state_set_type_handler(
        ProcessorState *ps,
        TypeInfo *type_info,
        TypeHandler handler)
{
    add_type_handler(&ps->type_handlers, type_info, handler);
}

static void
processor_state_set_array_type_handler(
        ProcessorState *ps,
        TypeInfo *type_info,
        TypeHandler handler)
{
    add_type_handler(&ps->array_type_handlers, type_info, handler);
}

static void
processor_state_add_named_url(
        ProcessorState *ps,
        TypeInfo *name,
        HtmlElement *value)
{
    for (int i = 0; i < ps->urls.u; ++i) {
        if (ps->urls.v[i].name == name) {
            html_element_free(ps->urls.v[i].value);
            ps->urls.v[i].value = value;
            return;
        }
    }
    if (ps->urls.u == ps->urls.a) {
        if (!(ps->urls.a *= 2)) ps->urls.a = 32;
        XREALLOC(ps->urls.v, ps->urls.a);
    }
    ps->urls.v[ps->urls.u].name = name;
    ps->urls.v[ps->urls.u].value = value;
    ++ps->urls.u;
}

static HtmlElement *
processor_state_find_named_url(
        ProcessorState *ps,
        TypeInfo *name)
{
    for (int i = 0; i < ps->urls.u; ++i) {
        if (ps->urls.v[i].name == name) {
            return ps->urls.v[i].value;
        }
    }
    return NULL;
}

typedef struct ScannerState
{
    ProcessorState *ps;
    FILE *log_f;

    const unsigned char *buf;
    int len;

    Position pos;
    int idx;

    int error_count;
    int token;
    Position token_pos;

    int value_len;
    unsigned char *value;
    c_value_t cv;

    int raw_len;
    unsigned char *raw;
} ScannerState;

typedef struct SavedScannerState
{
    Position pos;
    int idx;

    int error_count;
    int token;
    Position token_pos;

    int value_len;
    unsigned char *value;
    c_value_t cv;

    int raw_len;
    unsigned char *raw;
} SavedScannerState;

static const unsigned char *
pos_str(unsigned char *buf, size_t size, const ScannerState *ss)
{
    snprintf(buf, size, "%s: %d: %d", ss->ps->filenames[ss->pos.filename_idx], ss->pos.line, ss->pos.column);
    return buf;

}

static const unsigned char *
pos_str_2(unsigned char *buf, size_t size, const ProcessorState *ps, const Position *pos)
{
    snprintf(buf, size, "%s: %d: %d", ps->filenames[pos->filename_idx], pos->line, pos->column);
    return buf;

}

// pre-defined C keywords
static TypeInfo *kwd_auto = NULL;
static TypeInfo *kwd_break = NULL;
static TypeInfo *kwd_case = NULL;
static TypeInfo *kwd_char = NULL;
static TypeInfo *kwd_const = NULL;
static TypeInfo *kwd_continue = NULL;
static TypeInfo *kwd_default = NULL;
static TypeInfo *kwd_do = NULL;
static TypeInfo *kwd_double = NULL;
static TypeInfo *kwd_else = NULL;
static TypeInfo *kwd_enum = NULL;
static TypeInfo *kwd_extern = NULL;
static TypeInfo *kwd_float = NULL;
static TypeInfo *kwd_for = NULL;
static TypeInfo *kwd_goto = NULL;
static TypeInfo *kwd_if = NULL;
static TypeInfo *kwd_inline = NULL;
static TypeInfo *kwd_int = NULL;
static TypeInfo *kwd_long = NULL;
static TypeInfo *kwd_register = NULL;
static TypeInfo *kwd_restrict = NULL;
static TypeInfo *kwd_return = NULL;
static TypeInfo *kwd_short = NULL;
static TypeInfo *kwd_signed = NULL;
static TypeInfo *kwd_sizeof = NULL;
static TypeInfo *kwd_static = NULL;
static TypeInfo *kwd_struct = NULL;
static TypeInfo *kwd_switch = NULL;
static TypeInfo *kwd_typedef = NULL;
static TypeInfo *kwd_union = NULL;
static TypeInfo *kwd_unsigned = NULL;
static TypeInfo *kwd_void = NULL;
static TypeInfo *kwd_volatile = NULL;
static TypeInfo *kwd_while = NULL;
static TypeInfo *kwd__Bool = NULL;
static TypeInfo *kwd__Complex = NULL;
static TypeInfo *kwd__Imaginary = NULL;

static ScannerState *
init_scanner(ProcessorState *ps, FILE *log_f, const unsigned char *buf, int len, Position pos, TypeContext *cntx)
{
    ScannerState *ss = NULL;
    XCALLOC(ss, 1);
    ss->ps = ps;
    ss->log_f = log_f;
    ss->buf = buf;
    ss->len = len;
    ss->pos = pos;

    if (!kwd_auto) {
        kwd_auto = tc_get_ident(cntx, "auto");
        kwd_break = tc_get_ident(cntx, "break");
        kwd_case = tc_get_ident(cntx, "case");
        kwd_char = tc_get_ident(cntx, "char");
        kwd_const = tc_get_ident(cntx, "const");
        kwd_continue = tc_get_ident(cntx, "continue");
        kwd_default = tc_get_ident(cntx, "default");
        kwd_do = tc_get_ident(cntx, "do");
        kwd_double = tc_get_ident(cntx, "double");
        kwd_else = tc_get_ident(cntx, "else");
        kwd_enum = tc_get_ident(cntx, "enum");
        kwd_extern = tc_get_ident(cntx, "extern");
        kwd_float = tc_get_ident(cntx, "float");
        kwd_for = tc_get_ident(cntx, "for");
        kwd_goto = tc_get_ident(cntx, "goto");
        kwd_if = tc_get_ident(cntx, "if");
        kwd_inline = tc_get_ident(cntx, "inline");
        kwd_int = tc_get_ident(cntx, "int");
        kwd_long = tc_get_ident(cntx, "long");
        kwd_register = tc_get_ident(cntx, "register");
        kwd_restrict = tc_get_ident(cntx, "restrict");
        kwd_return = tc_get_ident(cntx, "return");
        kwd_short = tc_get_ident(cntx, "short");
        kwd_signed = tc_get_ident(cntx, "signed");
        kwd_sizeof = tc_get_ident(cntx, "sizeof");
        kwd_static = tc_get_ident(cntx, "static");
        kwd_struct = tc_get_ident(cntx, "struct");
        kwd_switch = tc_get_ident(cntx, "switch");
        kwd_typedef = tc_get_ident(cntx, "typedef");
        kwd_union = tc_get_ident(cntx, "union");
        kwd_unsigned = tc_get_ident(cntx, "unsigned");
        kwd_void = tc_get_ident(cntx, "void");
        kwd_volatile = tc_get_ident(cntx, "volatile");
        kwd_while = tc_get_ident(cntx, "while");
        kwd__Bool = tc_get_ident(cntx, "_Bool");
        kwd__Complex = tc_get_ident(cntx, "_Complex");
        kwd__Imaginary = tc_get_ident(cntx, "_Imaginary");
    }
    return ss;
}

static ScannerState *
destroy_scanner(ScannerState *ss)
{
    if (ss) {
        ss->ps->error_count += ss->error_count;
        xfree(ss->value);
        xfree(ss->raw);
        xfree(ss);
    }
    return NULL;
}

static SavedScannerState *
save_scanner_state(const ScannerState *ss)
{
    SavedScannerState *sss = NULL;
    XCALLOC(sss, 1);

    sss->pos = ss->pos;
    sss->idx = ss->idx;
    sss->error_count = ss->error_count;
    sss->token = ss->token;
    sss->token_pos = ss->token_pos;
    sss->value_len = ss->value_len;
    if (ss->value) sss->value = xmemdup(ss->value, ss->value_len);
    sss->cv = ss->cv;
    sss->raw_len = ss->raw_len;
    if (ss->raw) sss->raw = xmemdup(ss->raw, ss->raw_len);
    return sss;
}

static void
restore_scanner_state(ScannerState *ss, const SavedScannerState *sss)
{
    ss->pos = sss->pos;
    ss->idx = sss->idx;
    ss->error_count = sss->error_count;
    ss->token = sss->token;
    ss->token_pos = sss->token_pos;
    ss->value_len = sss->value_len;
    xfree(ss->value); ss->value = NULL;
    if (sss->value) ss->value = xmemdup(sss->value, sss->value_len);
    ss->cv = sss->cv;
    ss->raw_len = sss->raw_len;
    xfree(ss->raw); ss->raw = NULL;
    if (sss->raw) ss->raw = xmemdup(sss->raw, sss->raw_len);
}

static SavedScannerState *
destroy_saved_state(SavedScannerState *sss)
{
    if (!sss) return NULL;

    xfree(sss->value);
    xfree(sss->raw);
    memset(sss, 0, sizeof(*sss));
    xfree(sss);
    return NULL;
}

static void
scanner_error(ScannerState *ss, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
static void
scanner_error(ScannerState *ss, const char *format, ...)
{
    va_list args;
    char buf[1024];
    unsigned char pb[1024];

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(ss->log_f, "%s: %s\n", pos_str(pb, sizeof(pb), ss), buf);
    ++ss->error_count;
}

static void
parser_error(ScannerState *ss, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
static void
parser_error(ScannerState *ss, const char *format, ...)
{
    va_list args;
    char buf[1024];
    unsigned char pb[1024];

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(ss->log_f, "%s: %s\n", pos_str_2(pb, sizeof(pb), ss->ps, &ss->token_pos), buf);
    ++ss->error_count;
}

static void
parser_error_2(ProcessorState *ps, const char *format, ...)
{
    va_list args;
    char buf[1024];
    unsigned char pb[1024];

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(ps->log_f, "%s: %s\n", pos_str_2(pb, sizeof(pb), ps, &ps->pos), buf);
    ++ps->error_count;
}

static TypeInfo *
make_value_info(ScannerState *ss, TypeContext *cntx)
{
    switch (ss->token) {
    case TOK_STRING:
        return tc_get_string(cntx, ss->value, ss->value_len);
    case TOK_CHAR:
        return tc_get_i8(cntx, ss->cv.v.ct_char);
    case TOK_NUMBER:
        switch (ss->cv.tag) {
        case C_BOOL:
            return tc_get_i1(cntx, ss->cv.v.ct_bool);
        case C_CHAR:
            return tc_get_i8(cntx, ss->cv.v.ct_char);
        case C_SCHAR:
            return tc_get_i8(cntx, ss->cv.v.ct_schar);
        case C_UCHAR:
            return tc_get_u8(cntx, ss->cv.v.ct_uchar);
        case C_SHORT:
            return tc_get_i16(cntx, ss->cv.v.ct_short);
        case C_USHORT:
            return tc_get_u16(cntx, ss->cv.v.ct_ushort);
        case C_INT:
            return tc_get_i32(cntx, ss->cv.v.ct_int);
        case C_UINT:
            return tc_get_u32(cntx, ss->cv.v.ct_uint);
        case C_LONG:
            return tc_get_i32(cntx, ss->cv.v.ct_lint);
        case C_ULONG:
            return tc_get_u32(cntx, ss->cv.v.ct_ulint);
        case C_LLONG:
            return tc_get_i64(cntx, ss->cv.v.ct_llint);
        case C_ULLONG:
            return tc_get_u64(cntx, ss->cv.v.ct_ullint);
        default:
            dump_token(ss);
            parser_error(ss, "value expected");
            return NULL;
        }
    case TOK_FPNUMBER:
        switch (ss->cv.tag) {
        case C_FLOAT:
            return tc_get_f32(cntx, ss->cv.v.ct_float);
        case C_DOUBLE:
            return tc_get_f64(cntx, ss->cv.v.ct_double);
        case C_LDOUBLE:
            return tc_get_f80(cntx, ss->cv.v.ct_ldouble);
        default:
            dump_token(ss);
            parser_error(ss, "value expected");
            return NULL;
        }
    default:
        dump_token(ss);
        parser_error(ss, "value expected");
        return NULL;
    }
    return NULL;
}

static TypeInfo *
make_value_type(ScannerState *ss, TypeContext *cntx)
{
    switch (ss->token) {
    case TOK_STRING:
        return tc_get_ptr_type(cntx, tc_get_const_type(cntx, tc_get_u8_type(cntx)));
    case TOK_CHAR:
        return tc_get_u8_type(cntx);
    case TOK_NUMBER:
        switch (ss->cv.tag) {
        case C_BOOL:
            return tc_get_i1_type(cntx);
        case C_CHAR:
            return tc_get_i8_type(cntx);
        case C_SCHAR:
            return tc_get_i8_type(cntx);
        case C_UCHAR:
            return tc_get_u8_type(cntx);
        case C_SHORT:
            return tc_get_i16_type(cntx);
        case C_USHORT:
            return tc_get_u16_type(cntx);
        case C_INT:
            return tc_get_i32_type(cntx);
        case C_UINT:
            return tc_get_u32_type(cntx);
        case C_LONG:
            return tc_get_i32_type(cntx);
        case C_ULONG:
            return tc_get_u32_type(cntx);
        case C_LLONG:
            return tc_get_i64_type(cntx);
        case C_ULLONG:
            return tc_get_u64_type(cntx);
        default:
            dump_token(ss);
            parser_error(ss, "value expected");
            return NULL;
        }
    case TOK_FPNUMBER:
        switch (ss->cv.tag) {
        case C_FLOAT:
            return tc_get_f32_type(cntx);
        case C_DOUBLE:
            return tc_get_f64_type(cntx);
        case C_LDOUBLE:
            return tc_get_f80_type(cntx);
        default:
            dump_token(ss);
            parser_error(ss, "value expected");
            return NULL;
        }
    default:
        dump_token(ss);
        parser_error(ss, "value expected");
        return NULL;
    }
    return NULL;
}

static void
next_string(ScannerState *ss)
{
    int t = ss->buf[ss->idx];
    int cur = ss->idx + 1;
    int c;
    unsigned char nb[8], *nbp;

    ss->token_pos = ss->pos;
    pos_next(&ss->pos, t);
    if (t == '\"') {
        ss->token = TOK_STRING;
    } else if (t == '\'') {
        ss->token = TOK_CHAR;
    } else {
        abort();
    }

    // calculate length
    while (1) {
        if (cur >= ss->len) {
            scanner_error(ss, "unexpected end of text in string");
            break;
        }
        if (!(c = ss->buf[cur])) {
            scanner_error(ss, "stray \\0 in string");
            pos_next(&ss->pos, c);
            ++cur;
        } else if (c < ' ' || c == 0x7f) {
            scanner_error(ss, "control character \\%03o in string", c);
            pos_next(&ss->pos, c);
            ++cur;
        } else if (c == t) {
            pos_next(&ss->pos, c);
            ++cur;
            break;
        } else if (c == '\\' && ss->buf[cur + 1]) {
            pos_next(&ss->pos, ss->buf[cur]);
            pos_next(&ss->pos, ss->buf[cur + 1]);
            cur += 2;
        } else {
            pos_next(&ss->pos, c);
            ++cur;
        }
    }

    ss->raw_len = cur - ss->idx;
    ss->raw = xmalloc(ss->raw_len + 1);
    memcpy(ss->raw, ss->buf + ss->idx, ss->raw_len);
    ss->raw[ss->raw_len] = 0;

    ss->pos = ss->token_pos;
    ss->value = xmalloc(ss->raw_len + 1); // not all length is necessarily used
    unsigned char *p = ss->value;
    cur = ss->idx + 1;
    while (1) {
        if (cur >= ss->len) break;
        c = ss->buf[cur];
        if (c == t) {
            ++cur;
            break;
        }
        if (c < ' ' || c == 0x7f) {
            *p++ = ' '; // do not pass through control characters?
            pos_next(&ss->pos, c);
            ++cur;
        } else if (c != '\\') {
            *p++ = c;
            pos_next(&ss->pos, c);
            ++cur;
        } else {
            // backslash
            pos_next(&ss->pos, c);
            ++cur;
            if (cur >= ss->len) {
                *p++ = '\\';
                break;
            }
            switch (ss->buf[cur]) {
            case 'x': case 'X':
                pos_next(&ss->pos, ss->buf[cur]);
                ++cur;
                if (cur >= ss->len || !isxdigit(ss->buf[cur])) {
                    scanner_error(ss, "invalid escape sequence");
                    *p++ = '\\';
                    *p++ = ss->buf[cur - 1];
                    break;
                }
                nbp = nb;
                pos_next_n(&ss->pos, 1);
                *nbp++ = ss->buf[cur++];
                if (cur < ss->len && isxdigit(ss->buf[cur])) {
                    pos_next_n(&ss->pos, 1);
                    *nbp++ = ss->buf[cur++];
                }
                *nbp = 0;
                *p++ = strtol(nb, NULL, 16);
                break;
            case '0': case '1': case '2': case '3':
                nbp = nb;
                pos_next_n(&ss->pos, 1);
                *nbp++ = ss->buf[cur++];
                if (cur < ss->len && ss->buf[cur] >= '0' && ss->buf[cur] <= '7') {
                    pos_next_n(&ss->pos, 1);
                    *nbp++ = ss->buf[cur++];
                }
                if (cur < ss->len && ss->buf[cur] >= '0' && ss->buf[cur] <= '7') {
                    pos_next_n(&ss->pos, 1);
                    *nbp++ = ss->buf[cur++];
                }
                *nbp = 0;
                *p++ = strtol(nb, NULL, 8);
                break;
            case '4': case '5': case '6': case '7':
                nbp = nb;
                pos_next_n(&ss->pos, 1);
                *nbp++ = ss->buf[cur++];
                if (cur < ss->len && ss->buf[cur] >= '0' && ss->buf[cur] <= '7') {
                    pos_next_n(&ss->pos, 1);
                    *nbp++ = ss->buf[cur++];
                }
                *nbp = 0;
                *p++ = strtol(nb, NULL, 8);
                break;
            case 'a':
                *p++ = '\a';
            simple_escape:
                pos_next_n(&ss->pos, 1);
                ++cur;
                break;
            case 'b':
                *p++ = '\b';
                goto simple_escape;
            case 'f':
                *p++ = '\f';
                goto simple_escape;
            case 'n':
                *p++ = '\n';
                goto simple_escape;
            case 'r':
                *p++ = '\r';
                goto simple_escape;
            case 't':
                *p++ = '\t';
                goto simple_escape;
            case 'v':
                *p++ = '\v';
                goto simple_escape;
            case '\'':
                *p++ = '\'';
                goto simple_escape;
            case '\"':
                *p++ = '\"';
                goto simple_escape;
            case '\\':
                *p++ = '\\';
                goto simple_escape;
            default:
                // report invalid escape sequence
                c = ss->buf[cur];
                if (c < ' ' || c == 0x7f) {
                    c = ' ';
                }
                *p++ = '\\';
                *p++ = c;
                break;
            }
        }
    }
    *p = 0;
    ss->value_len = (int)(p - ss->value);
    ss->idx = cur;
}

static int
isintsuffix(int c)
{
    if (c == 'u' || c == 'U') return 'u';
    if (c == 'l' || c == 'L') return 'l';
    return 0;
}

static int
isfloatsuffix(int c)
{
    if (c == 'f' || c == 'F') return 'f';
    if (c == 'l' || c == 'L') return 'l';
    return 0;
}

static void
next_int_number(ScannerState *ss, int endpos)
{
    ss->token = TOK_NUMBER;
    ss->raw_len = endpos - ss->idx;
    ss->raw = xmemdup(ss->buf + ss->idx, ss->raw_len);
    memset(&ss->cv, 0, sizeof(ss->cv));
    pos_next_n(&ss->pos, ss->raw_len);
    ss->idx = endpos;

    int u_count = 0, l_count = 0;
    const unsigned char *p = ss->raw + ss->raw_len - 1;
    int c;
    while ((c = isintsuffix(*p))) {
        if (c == 'u') {
            ++u_count;
        } else if (c == 'l') {
            ++l_count;
        } else {
            abort();
        }
        --p;
    }
    if (u_count > 1) {
        parser_error(ss, "invalid integer literal");
        u_count = 1;
    }
    if (l_count > 2) {
        parser_error(ss, "invalid integer literal");
    }
    errno = 0;
    unsigned long long val = strtoull(ss->raw, NULL, 0);
    if (errno == ERANGE) {
        parser_error(ss, "integer literal is too big");
        ss->cv.tag = C_INT; // not quite right...
        return;
    }
    if (errno != 0) {
        parser_error(ss, "invalid integer literal");
        ss->cv.tag = C_INT;
        return;
    }
    if (u_count > 0 || ss->raw[0] == '0') {
        // unsigned value
        if (l_count == 0 && val <= UINT_MAX) {
            ss->cv.tag = C_UINT;
            ss->cv.v.ct_uint = (unsigned int) val;
        } else if (l_count <= 1 && val <= ULONG_MAX) {
            ss->cv.tag = C_ULONG;
            ss->cv.v.ct_ulint = (unsigned long) val;
        } else {
            ss->cv.tag = C_ULLONG;
            ss->cv.v.ct_ullint = val;
        }
    } else {
        // signed value
        if (l_count == 0 && val <= INT_MAX) {
            ss->cv.tag = C_INT;
            ss->cv.v.ct_int = (int) val;
        } else if (l_count <= 1 && val <= LONG_MAX) {
            ss->cv.tag = C_LONG;
            ss->cv.v.ct_lint = (long) val;
        } else if (val <= LONG_LONG_MAX) {
            ss->cv.tag = C_LLONG;
            ss->cv.v.ct_llint = (long long) val;
        } else {
            ss->cv.tag = C_ULLONG;
            ss->cv.v.ct_ullint = val;
        }
    }
}

static void
next_float_number(ScannerState *ss, int endpos)
{
    ss->token = TOK_FPNUMBER;
    ss->raw_len = endpos - ss->idx;
    ss->raw = xmemdup(ss->buf + ss->idx, ss->raw_len);
    memset(&ss->cv, 0, sizeof(ss->cv));
    pos_next_n(&ss->pos, ss->raw_len);
    ss->idx = endpos;

    errno = 0;
    char *eptr = NULL;
    long double val = strtold(ss->raw, &eptr);
    if (errno == ERANGE) {
        parser_error(ss, "floating point value is out of range");
        ss->cv.tag = C_DOUBLE; // not quite right...
        ss->cv.v.ct_double = 0.0;
        return;
    }
    if (errno != 0) {
        parser_error(ss, "invalid floating point literal");
        ss->cv.tag = C_DOUBLE;
        ss->cv.v.ct_double = 0.0;
        return;
    }
    int s = isfloatsuffix(*eptr);
    if (s == 'l') {
        ss->cv.tag = C_LDOUBLE;
        ss->cv.v.ct_ldouble = val;
    } else if (s == 'f') {
        ss->cv.tag = C_FLOAT;
        ss->cv.v.ct_float = (float) val;
    } else {
        ss->cv.tag = C_DOUBLE;
        ss->cv.v.ct_double = (double) val;
    }
}

static void
next_float_number_e(ScannerState *ss, int cur)
{
    ++cur;
    if (ss->buf[cur] == '+' || ss->buf[cur] == '-') {
        ++cur;
        if (!isdigit(ss->buf[cur])) return next_float_number(ss, cur - 2);
    } else if (!isdigit(ss->buf[cur])) {
        return next_float_number(ss, cur - 1);
    }
    while (isdigit(ss->buf[cur])) ++cur;
    if (isfloatsuffix(ss->buf[cur])) ++cur;
    return next_float_number(ss, cur);
}

static void
next_op(ScannerState *ss, int len);

static void
next_number(ScannerState *ss)
{
    ss->token_pos = ss->pos;
    int cur = ss->idx + 1;

    if (ss->buf[ss->idx] == '0') {
        if (ss->buf[cur] == 'x' || ss->buf[cur] == 'X') {
            ++cur;
            if (!isxdigit(ss->buf[cur])) return next_int_number(ss, 1);
            while (isxdigit(ss->buf[cur])) ++cur;
            if (isintsuffix(ss->buf[cur])) {
                while (isintsuffix(ss->buf[cur])) ++cur;
                return next_int_number(ss, cur);
            }
            if (ss->buf[cur] == '.') {
                ++cur;
                if (!isxdigit(ss->buf[cur])) return next_int_number(ss, cur - 1);
                while (isxdigit(ss->buf[cur])) ++cur;
                if (ss->buf[cur] != 'p' && ss->buf[cur] != 'P') return next_float_number(ss, cur);
                ++cur;
                if (ss->buf[cur] == '+' || ss->buf[cur] == '-') {
                    ++cur;
                    if (!isxdigit(ss->buf[cur])) return next_float_number(ss, cur - 2);
                } else if (!isdigit(ss->buf[cur])) {
                    return next_float_number(ss, cur - 1);
                }
                while (isdigit(ss->buf[cur])) ++cur;
                if (isfloatsuffix(ss->buf[cur])) ++cur;
                return next_float_number(ss, cur);
            }
            if (ss->buf[cur] == 'p' || ss->buf[cur] == 'P') {
                ++cur;
                if (ss->buf[cur] == '+' || ss->buf[cur] == '-') {
                    ++cur;
                    if (!isxdigit(ss->buf[cur])) return next_int_number(ss, cur - 2);
                } else if (!isdigit(ss->buf[cur])) {
                    return next_int_number(ss, cur - 1);
                }
                while (isdigit(ss->buf[cur])) ++cur;
                if (isfloatsuffix(ss->buf[cur])) ++cur;
                return next_float_number(ss, cur);
            }
            return next_int_number(ss, cur);
        }
        if (ss->buf[cur] == 'b' || ss->buf[cur] == 'b') {
            ++cur;
            if (ss->buf[cur] != '0' && ss->buf[cur] != '1') return next_int_number(ss, 1);
            while (ss->buf[cur] == '0' || ss->buf[cur] == '1') ++cur;
            while (isintsuffix(ss->buf[cur])) ++cur;
            return next_int_number(ss, cur);
        }
        while (ss->buf[cur] >= '0' && ss->buf[cur] <= '7') ++cur;
        if (isintsuffix(ss->buf[cur])) {
            while (isintsuffix(ss->buf[cur])) ++cur;
            return next_int_number(ss, cur);
        }
        if (ss->buf[cur] >= '8' && ss->buf[cur] <= '9') {
            int saved_cur = cur;
            while (isdigit(ss->buf[cur])) ++cur;
            if (ss->buf[cur] == '.') {
                ++cur;
                while (isdigit(ss->buf[cur])) ++cur;
                if (ss->buf[cur] == 'e' || ss->buf[cur] == 'E') {
                    return next_float_number_e(ss, cur);
                }
                if (isfloatsuffix(ss->buf[cur])) ++cur;
                return next_float_number(ss, cur);
            }
            if (ss->buf[cur] == 'e' || ss->buf[cur] == 'E') {
                ++cur;
                if (ss->buf[cur] == '+' || ss->buf[cur] == '-') {
                    ++cur;
                    if (!isdigit(ss->buf[cur])) {
                        return next_int_number(ss, saved_cur);
                    }
                } else if (!isdigit(ss->buf[cur])) {
                    return next_int_number(ss, saved_cur);
                }
                while (isdigit(ss->buf[cur])) ++cur;
                if (isfloatsuffix(ss->buf[cur])) ++cur;
                return next_float_number(ss, cur);
            }
            return next_int_number(ss, saved_cur);
        }
        if (ss->buf[cur] == '.') {
            ++cur;
            while (isdigit(ss->buf[cur])) ++cur;
            if (ss->buf[cur] == 'e' || ss->buf[cur] == 'E') {
                return next_float_number_e(ss, cur);
            }
            if (isfloatsuffix(ss->buf[cur])) ++cur;
            return next_float_number(ss, cur);
        }
        return next_int_number(ss, cur);
    } else if (ss->buf[ss->idx] >= '1' && ss->buf[ss->idx] <= '9') {
        while (ss->buf[cur] >= '0' && ss->buf[cur] <= '9') ++cur;
        if (isintsuffix(ss->buf[cur])) {
            while (isintsuffix(ss->buf[cur])) ++cur;
            return next_int_number(ss, cur);
        }
        if (ss->buf[cur] == '.') {
            ++cur;
            while (isdigit(ss->buf[cur])) ++cur;
            if (ss->buf[cur] == 'e' || ss->buf[cur] == 'E') {
                return next_float_number_e(ss, cur);
            }
            if (isfloatsuffix(ss->buf[cur])) ++cur;
            return next_float_number(ss, cur);            
        }
        if (ss->buf[cur] == 'e' || ss->buf[cur] == 'E') {
            return next_float_number_e(ss, cur);
        }
        return next_int_number(ss, cur);
    } else if (ss->buf[ss->idx] == '.') {
        if (!isdigit(ss->buf[cur])) return next_op(ss, 1);
        while (isdigit(ss->buf[cur])) ++cur;
        if (ss->buf[cur] == 'e' || ss->buf[cur] == 'E') {
            return next_float_number_e(ss, cur);
        }
        if (isfloatsuffix(ss->buf[cur])) ++cur;
        return next_float_number(ss, cur);            
    } else {
        abort();
    }
}

static void
next_op(ScannerState *ss, int len)
{
    ss->token = TOK_OPER;
    ss->token_pos = ss->pos;
    ss->raw_len = len;
    ss->raw = xmalloc(len + 1);
    memcpy(ss->raw, ss->buf + ss->idx, len);
    ss->raw[len] = 0;
    ss->idx += len;
    pos_next_n(&ss->pos, len);
}

static void
next_token(ScannerState *ss)
{
    xfree(ss->value); ss->value = NULL; ss->value_len = 0;
    xfree(ss->raw); ss->raw = NULL; ss->raw_len = 0;
    int c;

    while (1) {
        while (isspace((c = ss->buf[ss->idx]))) {
            pos_next(&ss->pos, c);
            ++ss->idx;
        }
        if (ss->idx >= ss->len) {
            ss->token = TOK_EOF;
            return;
        }
        if (isalpha(c) || c == '_' || c == '$') {
            // ident
            ss->token_pos = ss->pos;
            int cur = ss->idx + 1;
            while (isalnum((c = ss->buf[cur])) || c == '_' || c == '$') ++cur;
            ss->value = xmalloc(cur + 1 - ss->idx);
            memcpy(ss->value, ss->buf + ss->idx, cur - ss->idx);
            ss->value[cur - ss->idx] = 0;
            pos_next_n(&ss->pos, cur - ss->idx);
            ss->raw = xstrdup(ss->value);
            ss->idx = cur;
            ss->token = TOK_IDENT;
            return;
        }
        if (c == '\"' || c == '\'') {
            return next_string(ss);
        }
        if (isdigit(c)) {
            return next_number(ss);
        }
        if (c == '/') {
            if (ss->idx + 1 < ss->len) {
                c = ss->buf[ss->idx + 1];
                if (c == '/') {
                    // line comment
                    ss->idx += 2;
                    while (ss->idx < ss->len && ss->buf[ss->idx] != '\n') ++ss->idx;
                    if (ss->idx < ss->len) ++ss->idx;
                    pos_next(&ss->pos, '\n');
                    continue;
                } else if (c == '*') {
                    // block comment
                    pos_next_n(&ss->pos, 2);
                    ss->idx += 2;
                    while (ss->idx < ss->len) {
                        if (ss->buf[ss->idx] == '*') {
                            pos_next(&ss->pos, '*');
                            ++ss->idx;
                            if (ss->idx >= ss->len) {
                                scanner_error(ss, "unexpected end of block comment");
                                break;
                            }
                            if (ss->buf[ss->idx] == '/') {
                                pos_next(&ss->pos, '/');
                                ++ss->idx;
                                break;
                            }
                        } else {
                            pos_next(&ss->pos, ss->buf[ss->idx]);
                            ++ss->idx;
                        }
                    }
                    continue;
                } else if (c == '=') {
                    // /=
                    return next_op(ss, 2);
                } else {
                    return next_op(ss, 1);
                }
            } else {
                return next_op(ss, 1);
            }
        }
        if (c == '.') {
            if (ss->idx + 1 < ss->len) {
                c = ss->buf[ss->idx + 1];
                if (isdigit(c)) {
                    return next_number(ss);
                }
                if (c == '.' && ss->idx + 2 < ss->len && ss->buf[ss->idx + 2] == '.') {
                    return next_op(ss, 3);
                } else {
                    return next_op(ss, 1);
                }
            } else {
                return next_op(ss, 1);
            }
        }
        if (c == '<') {
            if (ss->idx + 1 < ss->len) {
                if (ss->buf[ss->idx + 1] == '<') {
                    if (ss->idx + 2 < ss->len && ss->buf[ss->idx + 2] == '=') {
                        return next_op(ss, 3);
                    } else {
                        return next_op(ss, 2);
                    }
                } else if (ss->buf[ss->idx + 1] == '=') {
                        return next_op(ss, 2);
                } else {
                    return next_op(ss, 1);
                }
            } else {
                return next_op(ss, 1);
            }
        }
        if (c == '>') {
            if (ss->idx + 1 < ss->len) {
                if (ss->buf[ss->idx + 1] == '>') {
                    if (ss->idx + 2 < ss->len && ss->buf[ss->idx + 2] == '=') {
                        return next_op(ss, 3);
                    } else {
                        return next_op(ss, 2);
                    }
                } else if (ss->buf[ss->idx + 1] == '=') {
                        return next_op(ss, 2);
                } else {
                    return next_op(ss, 1);
                }
            } else {
                return next_op(ss, 1);
            }
        }
        if (c == '-') {
            if (ss->idx + 1 < ss->len) {
                c = ss->buf[ss->idx + 1];
                if (c == '-' || c == '=' || c == '>') {
                    return next_op(ss, 2);
                } else {
                    return next_op(ss, 1);
                }
            } else {
                return next_op(ss, 1);
            }
        }
        if (c == '+' || c == '&' || c == '|' || c == '=') {
            if (ss->idx + 1 < ss->len) {
                if (ss->buf[ss->idx + 1] == c || ss->buf[ss->idx + 1] == '=') {
                    return next_op(ss, 2);
                } else {
                    return next_op(ss, 1);
                }
            } else {
                return next_op(ss, 1);
            }
        }
        if (c == '*' || c== '!' || c == '%' || c == '^') {
            if (ss->idx + 1 < ss->len) {
                if (ss->buf[ss->idx + 1] == '=') {
                    return next_op(ss, 2);
                } else {
                    return next_op(ss, 1);
                }
            } else {
                return next_op(ss, 1);
            }
        }
        if (c == '#') {
            if (ss->idx + 1 < ss->len) {
                if (ss->buf[ss->idx + 1] == c) {
                    return next_op(ss, 2);
                } else {
                    return next_op(ss, 1);
                }
            } else {
                return next_op(ss, 1);
            }
        }
        if (c == ';' || c == ',' || c == '{' || c == '}' 
            || c == ':' || c == '(' || c == ')' || c == '['
            || c == ']' || c == '?' || c == '~') {
            return next_op(ss, 1);
        }
        if (ss->buf[ss->idx] < ' ' || ss->buf[ss->idx] >= 0x7f) {
            scanner_error(ss, "invalid character (code \\%03o)", ss->buf[ss->idx]);
        } else {
            scanner_error(ss, "invalid character '%c'", ss->buf[ss->idx]);
        }
        pos_next(&ss->pos, ss->buf[ss->idx]);
        ++ss->idx;
    }
}

static void
dump_token(ScannerState *ss)
{
    unsigned char buf[1024];
    fprintf(stderr, "%s: %d: <<%s>>\n", pos_str_2(buf, sizeof(buf), ss->ps, &ss->token_pos), ss->token, ss->raw);
    abort();
}

#define IS_OPER(ss, c) ((ss)->token == TOK_OPER && (ss)->raw_len == 1 && (ss)->raw[0] == (c))
#define IS_OPER_2(ss, c1, c2) ((ss)->token == TOK_OPER && (ss)->raw_len == 2 && (ss)->raw[0] == (c1) && (ss)->raw[1] == (c2))
#define IS_OPER_3(ss, c1, c2, c3) ((ss)->token == TOK_OPER && (ss)->raw_len == 3 && (ss)->raw[0] == (c1) && (ss)->raw[1] == (c2) && (ss)->raw[2] == (c3))

static int
parse_declspec(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode, // if 1, be quiet on errors
        TypeInfo **p_info)
{
    int retval = -1;

    int auto_count = 0;
    int const_count = 0;
    int extern_count = 0;
    int register_count = 0;
    int restrict_count = 0;
    int static_count = 0;
    int typedef_count = 0;
    int volatile_count = 0;

    int signed_count = 0;
    int unsigned_count = 0;
    int short_count = 0;
    int long_count = 0;
    int bool_count = 0;
    int char_count = 0;
    int int_count = 0;
    int float_count = 0;
    int double_count = 0;

    int has_base_type = 0;
    TypeInfo *type_info = NULL;

    if (ss->token != TOK_IDENT) {
        if (!quiet_mode) parser_error(ss, "type expected");
        goto cleanup;
    }
    while (1) {
        if (ss->token != TOK_IDENT) break;
        TypeInfo *kwd = tc_get_ident(cntx, ss->raw);
        if (kwd == kwd_auto) {
            ++auto_count;
            next_token(ss);
        } else if (kwd == kwd_const) {
            ++const_count;
            next_token(ss);
        } else if (kwd == kwd_extern) {
            ++extern_count;
            next_token(ss);
        } else if (kwd == kwd_register) {
            ++register_count;
            next_token(ss);
        } else if (kwd == kwd_restrict) {
            ++restrict_count;
            next_token(ss);
        } else if (kwd == kwd_static) {
            ++static_count;
            next_token(ss);
        } else if (kwd == kwd_typedef) {
            ++typedef_count;
            next_token(ss);
        } else if (kwd == kwd_volatile) {
            ++volatile_count;
            next_token(ss);
        } else if (kwd == kwd_enum) {
            if (type_info || has_base_type) goto invalid_declspec;
            next_token(ss);
            if (ss->token != TOK_IDENT) {
                if (!quiet_mode) parser_error(ss, "identifier expected after 'enum'");
                goto cleanup;
            }
            type_info = tc_find_enum_type(cntx, tc_get_ident(cntx, ss->raw));
            if (!type_info) {
                if (!quiet_mode) parser_error(ss, "enum type '%s' undefined", ss->raw);
                goto cleanup;
            }
            next_token(ss);
        } else if (kwd == kwd_struct) {
            if (type_info || has_base_type) goto invalid_declspec;
            next_token(ss);
            if (ss->token != TOK_IDENT) {
                if (!quiet_mode) parser_error(ss, "identifier expected after 'struct'");
                goto cleanup;
            }
            type_info = tc_find_struct_type(cntx, NODE_STRUCT_TYPE, tc_get_ident(cntx, ss->raw));
            if (!type_info) {
                if (!quiet_mode) parser_error(ss, "struct type '%s' undefined", ss->raw);
                goto cleanup;
            }
            next_token(ss);
        } else if (kwd == kwd_union) {
            if (type_info || has_base_type) goto invalid_declspec;
            next_token(ss);
            if (ss->token != TOK_IDENT) {
                if (!quiet_mode) parser_error(ss, "identifier expected after 'union'");
                goto cleanup;
            }
            type_info = tc_find_struct_type(cntx, NODE_UNION_TYPE, tc_get_ident(cntx, ss->raw));
            if (!type_info) {
                if (!quiet_mode) parser_error(ss, "union type '%s' undefined", ss->raw);
                goto cleanup;
            }
            next_token(ss);
        } else if (kwd == kwd_signed) {
            if (type_info) goto invalid_declspec;
            ++signed_count;
            has_base_type = 1;
            next_token(ss);
        } else if (kwd == kwd_unsigned) {
            if (type_info) goto invalid_declspec;
            ++unsigned_count;
            has_base_type = 1;
            next_token(ss);
        } else if (kwd == kwd_short) {
            if (type_info) goto invalid_declspec;
            ++short_count;
            has_base_type = 1;
            next_token(ss);
        } else if (kwd == kwd_long) {
            if (type_info) goto invalid_declspec;
            ++long_count;
            has_base_type = 1;
            next_token(ss);
        } else if (kwd == kwd__Bool) {
            if (type_info) goto invalid_declspec;
            ++bool_count;
            has_base_type = 1;
            next_token(ss);
        } else if (kwd == kwd_char) {
            if (type_info) goto invalid_declspec;
            ++char_count;
            has_base_type = 1;
            next_token(ss);
        } else if (kwd == kwd_int) {
            if (type_info) goto invalid_declspec;
            ++int_count;
            has_base_type = 1;
            next_token(ss);
        } else if (kwd == kwd_float) {
            if (type_info) goto invalid_declspec;
            ++float_count;
            has_base_type = 1;
            next_token(ss);
        } else if (kwd == kwd_double) {
            if (type_info) goto invalid_declspec;
            ++double_count;
            has_base_type = 1;
            next_token(ss);
        } else {
            if (has_base_type || type_info) break;
            type_info = tc_find_typedef_type(cntx, tc_get_ident(cntx, ss->raw));
            if (!type_info) {
                if (!quiet_mode) parser_error(ss, "typedef type '%s' undefined", ss->raw);
                goto cleanup;
            }
            next_token(ss);
        }
    }

    if (type_info && has_base_type) goto invalid_declspec;
    if (type_info) {
        *p_info = type_info;
        retval = 0;
        goto cleanup;
    }
    if (!has_base_type) goto invalid_declspec;

    if (signed_count == 0 && unsigned_count == 0 && short_count == 0 && long_count == 1
        && bool_count == 0 && char_count == 0 && int_count == 0 && float_count == 0
        && double_count == 1) {
        *p_info = tc_get_f80_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (signed_count == 0 && unsigned_count == 0 && short_count == 0 && long_count == 0
        && bool_count == 0 && char_count == 0 && int_count == 0 && float_count == 0
        && double_count == 1) {
        *p_info = tc_get_f64_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (double_count) goto invalid_declspec;
    if (signed_count == 0 && unsigned_count == 0 && short_count == 0 && long_count == 0
        && bool_count == 0 && char_count == 0 && int_count == 0 && float_count == 1) {
        *p_info = tc_get_f32_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (float_count) goto invalid_declspec;
    if (signed_count == 0 && unsigned_count == 0 && short_count == 0 && long_count == 0
        && bool_count == 1 && char_count == 0 && int_count == 0) {
        *p_info = tc_get_i1_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (bool_count) goto invalid_declspec;
    if (signed_count == 0 && unsigned_count == 0 && short_count == 0 && long_count == 0
        && char_count == 1 && int_count == 0) {
        *p_info = tc_get_i8_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (signed_count == 1 && unsigned_count == 0 && short_count == 0 && long_count == 0
        && char_count == 1 && int_count == 0) {
        *p_info = tc_get_i8_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (signed_count == 0 && unsigned_count == 1 && short_count == 0 && long_count == 0
        && char_count == 1 && int_count == 0) {
        *p_info = tc_get_u8_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (char_count) goto invalid_declspec;
    if (int_count > 1 || signed_count > 1 || unsigned_count > 1 || short_count > 1 || long_count > 2)
        goto invalid_declspec;
    if (signed_count > 0 && unsigned_count > 0) goto invalid_declspec;
    if (short_count > 0 && long_count > 0) goto invalid_declspec;
    if (long_count == 2 && unsigned_count > 0) {
        *p_info = tc_get_u64_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (long_count == 2) {
        *p_info = tc_get_i64_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (long_count > 0 && unsigned_count > 0) {
        *p_info = tc_get_u32_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (long_count > 0) {
        *p_info = tc_get_i32_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (short_count > 0 && unsigned_count > 0) {
        *p_info = tc_get_u16_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (short_count > 0) {
        *p_info = tc_get_i16_type(cntx);
        retval = 0;
        goto cleanup;
    }
    if (unsigned_count > 0) {
        *p_info = tc_get_u32_type(cntx);
        retval = 0;
        goto cleanup;
    }

    *p_info = tc_get_i32_type(cntx);
    retval = 0;

cleanup:
    return retval;

invalid_declspec:
    if (!quiet_mode) parser_error(ss, "invalid declaration specifier");
    goto cleanup;
}

// int *a : a - pointer - int
// int a[] : a - array of - int
// int *a[] : a - array of - pointer - int
// int (*a)[] : a - pointer - array of - int
// int (*a)[]() : a - pointer - array of - function - int

typedef struct DeclrHelper
{
    struct DeclrHelper *next;
    int tag;
    int count;
    TypeInfo **info;
} DeclrHelper;

static DeclrHelper *
free_declr_helper(DeclrHelper *p)
{
    DeclrHelper *q;
    while (p) {
        q = p->next;
        xfree(p->info);
        xfree(p);
        p = q;
    }
    return NULL;
}

static int
parse_param(
        ScannerState *ss,
        TypeContext *cntx,
        int anon_allowed,
        int quiet_mode,
        TypeInfo **p_info);
static int
parse_declr(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode,
        int anon_allowed,
        DeclrHelper **p_head,
        TypeInfo **p_ident);

static int
try_declr(
        ScannerState *ss,
        TypeContext *cntx)
{
    SavedScannerState *sss = save_scanner_state(ss);
    next_token(ss);
    TypeInfo *p_ident = NULL;
    int ret = parse_declr(ss, cntx, 1, 1, NULL, &p_ident);
    if (ret >= 0 && !IS_OPER(ss, ')')) ret = -1;
    restore_scanner_state(ss, sss);
    destroy_saved_state(sss);
    return ret;
}

static int
parse_function_type_params(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode,
        DeclrHelper **p_head)
{
    TypeInfo *ti = NULL;
    enum { MAX_PARAM_COUNT = 128 };
    int idx = 0;
    TypeInfo *info[MAX_PARAM_COUNT];
    DeclrHelper *cur = NULL;

    // '(' is the current token
    next_token(ss);
    if (IS_OPER(ss, ')')) {
        next_token(ss);
        if (p_head) {
            XCALLOC(cur, 1);
            cur->tag = NODE_FUNCTION_TYPE;
            cur->count = 2;
            XCALLOC(cur->info, 3);
            cur->info[idx++] = tc_get_u32(cntx, 0);
            cur->next = *p_head;
            *p_head = cur;
        }
        return 0;
    }
    info[idx++] = tc_get_u32(cntx, 0);
    info[idx++] = NULL;
    int r = parse_param(ss, cntx, quiet_mode, 0, &ti);
    if (r < 0) return r;
    info[idx++] = ti;
    while (IS_OPER(ss, ',')) {
        if (idx == MAX_PARAM_COUNT - 2) {
            if (!quiet_mode) parser_error(ss, "too many parameters");
            return -1;
        }
        next_token(ss);
        if ((r = parse_param(ss, cntx, quiet_mode, 0, &ti)) < 0) return r;
        info[idx++] = ti;
    }
    info[idx] = NULL;
    if (!IS_OPER(ss, ')')) {
        if (!quiet_mode) parser_error(ss, "')' expected");
        return -1;
    }
    next_token(ss);

    if (p_head) {
        XCALLOC(cur, 1);
        cur->tag = NODE_FUNCTION_TYPE;
        cur->count = idx;
        XCALLOC(cur->info, idx + 1);
        memcpy(cur->info, info, sizeof(info[0]) * idx);
        cur->next = *p_head;
        *p_head = cur;
    }
    return 0;
}

// parse '(' DECLR ')' construct
static int
parse_declr_2(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode, 
        int anon_allowed,
        DeclrHelper **p_head,
        TypeInfo **p_ident)
{
    if (!IS_OPER(ss, '(')) {
        if (!quiet_mode) parser_error(ss, "'(' expected");
        return -1;
    }
    next_token(ss);
    int r = parse_declr(ss, cntx, quiet_mode, anon_allowed, p_head, p_ident);
    if (r < 0) return r;
    if (!IS_OPER(ss, ')')) {
        if (!quiet_mode) parser_error(ss, "')' expected");
        return -1;
    }
    next_token(ss);
    return 0;
}

static int
parse_declr(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode, // if 1, be quiet on errors
        int anon_allowed, // if 1, anonymous declarator is allowed, but ident is OK
        DeclrHelper **p_head,
        TypeInfo **p_ident) // if NULL, identifier is not allowed, this implies anon_allowed == 1
{
    int star_count = 0;
    TypeInfo *ti = NULL;
    int r;

    while (IS_OPER(ss, '*')) {
        ++star_count;
        next_token(ss);
        while (ss->token == TOK_IDENT
               && (!strcmp(ss->raw, "const") || !strcmp(ss->raw, "volatile") || !strcmp(ss->raw, "restrict"))) {
            next_token(ss);
        }
    }

    if (!p_ident) {
        // only anonymous declarator is allowed
        if (IS_OPER(ss, '(')) {
            if ((r = try_declr(ss, cntx)) >= 0) {
                // yes, this looks like '(' DECLR ')' part
                if ((r = parse_declr_2(ss, cntx, quiet_mode, 1, p_head, NULL)) < 0) return r;
            }
        }
    } else {
        if (IS_OPER(ss, '(') && anon_allowed) {
            if ((r = try_declr(ss, cntx)) >= 0) {
                if ((r = parse_declr_2(ss, cntx, quiet_mode, 1, p_head, p_ident)) < 0) return r;
            }
        } else if (IS_OPER(ss, '(')) {
            if ((r = parse_declr_2(ss, cntx, quiet_mode, 0, p_head, p_ident)) < 0) return r;
        } else {
            if (ss->token != TOK_IDENT) {
                if (p_head) parser_error(ss, "identifier expected");
                return -1;
            }
            ti = tc_get_ident(cntx, ss->raw);
            if (tc_is_c_keyword(cntx, ti)) {
                if (p_head) parser_error(ss, "identifier expected");
                return -1;
            }
            if (p_ident) *p_ident = ti;
            next_token(ss);
        }
    }

    while (IS_OPER(ss, '(') || IS_OPER(ss, '[')) {
        if (IS_OPER(ss, '(')) {
            r = parse_function_type_params(ss, cntx, quiet_mode, p_head);
            if (r < 0) return -1;
        } else if (IS_OPER(ss, '[')) {
            next_token(ss);
            int depth = 1;
            while (1) {
                if (IS_OPER(ss, '[')) {
                    ++depth;
                    next_token(ss);
                } else if (IS_OPER(ss, '{')) {
                    ++depth;
                    next_token(ss);
                } else if (IS_OPER(ss, '(')) {
                    ++depth;
                    next_token(ss);
                } else if (IS_OPER(ss, ')')) {
                    --depth;
                    next_token(ss);
                } else if (IS_OPER(ss, '}')) {
                    --depth;
                    next_token(ss);
                } else if (IS_OPER(ss, ']')) {
                    --depth;
                    next_token(ss);
                    if (!depth) break;
                } else {
                    next_token(ss);
                }
            }
            if (p_head) {
                DeclrHelper *cur = NULL;
                XCALLOC(cur, 1);
                cur->tag = NODE_OPEN_ARRAY_TYPE;
                cur->next = *p_head;
                *p_head = cur;
            }
        } else {
            abort();
        }
    }

    if (p_head && star_count > 0) {
        for (; star_count > 0; --star_count) {
            DeclrHelper *cur = NULL;
            XCALLOC(cur, 1);
            cur->tag = NODE_POINTER_TYPE;
            cur->next = *p_head;
            *p_head = cur;
        }
    }

    return 0;
}

static int
parse_full_declr(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode,
        int anon_allowed,
        TypeInfo *ds,
        TypeInfo **p_type,
        TypeInfo **p_id)

{
    DeclrHelper *head = NULL;
    XCALLOC(head, 1);

    int r = parse_declr(ss, cntx, quiet_mode, anon_allowed, &head, p_id);
    if (r < 0) {
        free_declr_helper(head);
        return -1;
    }

    for (DeclrHelper *cur = head; cur; cur = cur->next) {
        if (cur->tag == NODE_POINTER_TYPE) {
            ds = tc_get_ptr_type(cntx, ds);
        } else if (cur->tag == NODE_OPEN_ARRAY_TYPE) {
            ds = tc_get_open_array_type(cntx, ds);
        } else if (cur->tag == NODE_FUNCTION_TYPE) {
            cur->info[0] = tc_get_u32(cntx, 0);
            cur->info[1] = ds;
            ds = tc_get_function_type(cntx, cur->info);
        }
    }

    *p_type = ds;
    free_declr_helper(head);
    return 0;
}

// if anon_allowed flag is set, param is parsed as type, param name is ignored
static int
parse_param(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode, // if 1, be quiet on errors
        int param_mode, // if 1, NODE_PARAM is created, if 0, NODE_FORMAL_PARAM is created
        TypeInfo **p_info)
{
    TypeInfo *ds = NULL;
    TypeInfo *id = NULL;
    int r = parse_declspec(ss, cntx, quiet_mode, &ds);
    if (r < 0) return -1;

    if (parse_full_declr(ss, cntx, quiet_mode, 1, ds, &ds, &id) < 0) return -1;

    if (param_mode) {
        if (!id) id = tc_get_ident(cntx, "");
        ds = tc_get_param(cntx, tc_get_i32(cntx, 0), ds, id);
    } else {
        ds = tc_get_formal_param(cntx, ds);
    }

    *p_info = ds;
    return 0;
}

static int
parse_params(ScannerState *ss, TypeContext *cntx, TypeInfo **info, int size, int idx, int quiet_mode)
{
    int r;

    if (!IS_OPER(ss, '(')) {
        if (!quiet_mode) parser_error(ss, "'(' expected");
        return -1;
    }
    next_token(ss);
    if ((r = parse_param(ss, cntx, quiet_mode, 1, &info[idx++])) < 0) return r;
    while (IS_OPER(ss, ',')) {
        if (idx == size - 1) {
            if (!quiet_mode) parser_error(ss, "too many parameters");
            return -1;
        }
        next_token(ss);
        if ((r = parse_param(ss, cntx, quiet_mode, 1, &info[idx++])) < 0) return r;
    }
    if (!IS_OPER(ss, ')')) {
        if (!quiet_mode) parser_error(ss, "')' expected");
        return -1;
    }
    next_token(ss);
    info[idx] = NULL;
    return 0;
}

static int
parse_init_declr(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode,
        int anon_allowed,
        TypeInfo *ds,
        TypeInfo **p_type,
        TypeInfo **p_id)
{
    int r = parse_full_declr(ss, cntx, quiet_mode, anon_allowed, ds, p_type, p_id);
    if (r < 0) return -1;
    if (IS_OPER(ss, '=')) {
        // ignore initializer
        next_token(ss);
        int depth = 0;
        while (1) {
            if (ss->token == TOK_EOF) {
                parser_error(ss, "unexpected end of text");
                break;
            }
            if ((IS_OPER(ss, ',') || IS_OPER(ss, ';')) && !depth) break;
            if (IS_OPER(ss, '[')) {
                ++depth;
                next_token(ss);
            } else if (IS_OPER(ss, '{')) {
                ++depth;
                next_token(ss);
            } else if (IS_OPER(ss, '(')) {
                ++depth;
                next_token(ss);
            } else if (IS_OPER(ss, ')')) {
                --depth;
                next_token(ss);
            } else if (IS_OPER(ss, '}')) {
                --depth;
                next_token(ss);
            } else if (IS_OPER(ss, ']')) {
                --depth;
                next_token(ss);
                if (!depth) break;
            } else {
                next_token(ss);
            }
        }
    }
    return 0;
}

static int
parse_cast(ScannerState *ss, TypeContext *cntx, int quiet_mode, TypeInfo **p_info)
{
    if (!IS_OPER(ss, '(')) {
        parser_error(ss, "'(' expected");
        return -1;
    }
    next_token(ss);
    TypeInfo *ds = NULL;
    int r = parse_declspec(ss, cntx, quiet_mode, &ds);
    if (r < 0) return -1;
    if ((r = parse_full_declr(ss, cntx, quiet_mode, 1, ds, &ds, NULL)) < 0) return r;
    if (!IS_OPER(ss, ')')) {
        parser_error(ss, "')' expected");
        return -1;
    }
    next_token(ss);
    if (p_info) *p_info = ds;
    return 0;
}

/*static*/ int
is_vardecl_start(ScannerState *ss, TypeContext *cntx)
{
    if (ss->token != TOK_IDENT) return 0;
    TypeInfo *id = tc_get_ident(cntx, ss->raw);
    // typedef id?
    if (tc_find_typedef_type(cntx, id)) return 1;

    return id == kwd_auto
        || id == kwd_const
        || id == kwd_extern
        || id == kwd_register
        || id == kwd_restrict
        || id == kwd_static
        || id == kwd_typedef
        || id == kwd_volatile
        || id == kwd_enum
        || id == kwd_struct
        || id == kwd_union
        || id == kwd_signed
        || id == kwd_unsigned
        || id == kwd_short
        || id == kwd_long
        || id == kwd__Bool
        || id == kwd_char
        || id == kwd_int
        || id == kwd_float
        || id == kwd_double;
}

/*static*/ int
parse_vardecl(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode)
{
    TypeInfo *ds = NULL;
    TypeInfo *id = NULL;
    TypeInfo *vartype = NULL;
    int r = parse_declspec(ss, cntx, quiet_mode, &ds);
    if (r < 0) return -1;

    r = parse_init_declr(ss, cntx, quiet_mode, 0, ds, &vartype, &id);
    if (r < 0) return -1;
    processor_state_add_to_scope(ss->ps, tc_get_local_var(cntx, tc_get_i32(cntx, 0), vartype, id, tc_get_i32(cntx, 0)));
    while (IS_OPER(ss, ',')) {
        next_token(ss);
        vartype = NULL;
        id = NULL;
        r = parse_init_declr(ss, cntx, quiet_mode, 0, ds, &vartype, &id);
        if (r < 0) return -1;
        processor_state_add_to_scope(ss->ps, tc_get_local_var(cntx, tc_get_i32(cntx, 0), vartype, id, tc_get_i32(cntx, 0)));
    }
    if (!IS_OPER(ss, ';')) {
        parser_error(ss, "';' expected");
        return -1;
    }

    next_token(ss);
    return 0;
}

static int parse_expression(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info);
static int parse_expression_1(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info);

// "str", num, (e), ({...}), (t){...}
static int
parse_expression_16(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    if (ss->token == TOK_STRING) {
        if (p_info) *p_info = make_value_type(ss, cntx);
        next_token(ss);
        while (ss->token == TOK_STRING)
            next_token(ss);
        return 0;
    } else if (ss->token == TOK_CHAR || ss->token == TOK_NUMBER || ss->token == TOK_FPNUMBER) {
        if (p_info) *p_info = make_value_type(ss, cntx);
        next_token(ss);
        return 0;
    } else if (ss->token == TOK_IDENT) {
        TypeInfo *t = processor_state_find_in_scopes(ss->ps, tc_get_ident(cntx, ss->raw));
        if (!t) {
            parser_error(ss, "identifier '%s' is undefined", ss->raw);
            return -1;
        }
        if (t->kind != NODE_PARAM && t->kind != NODE_LOCAL_VAR && t->kind != NODE_SUBROUTINE) {
            parser_error(ss, "invalid symbol type");
            return -1;
        }
        if (t->kind == NODE_PARAM || t->kind == NODE_LOCAL_VAR) {
            if (p_info) *p_info = t->n.info[2];
        } else if (t->kind == NODE_SUBROUTINE) {
            if (p_info) *p_info = t->n.info[1];
        }
        next_token(ss);
        return 0;
    } else if (IS_OPER(ss, '(')) {
        next_token(ss);
        int r = parse_expression(ss, cntx, p_info);
        if (r < 0) return r;
        if (!IS_OPER(ss, ')')) {
            parser_error(ss, "')' expected");
            return -1;
        }
        next_token(ss);
        return 0;
    } else {
        parser_error(ss, "primary expression expected");
        return -1;
    }
}

// e[], e(), e->f, e.f, e++, e--
static int
parse_expression_15(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *t = NULL;
    int r = parse_expression_16(ss, cntx, &t);
    if (r < 0) return r;
    while (1) {
        if (IS_OPER(ss, '[')) {
            next_token(ss);
            TypeInfo *t2 = NULL;
            if ((r = parse_expression(ss, cntx, &t2)) < 0) return r;
            if (!IS_OPER(ss, ']')) {
                parser_error(ss, "']' expected");
                return -1;
            }
            next_token(ss);
            t = tc_promote(cntx, t);
            if (t->kind != NODE_POINTER_TYPE) {
                parser_error(ss, "invalid argument for [] operation");
                return -1;
            }
            t = t->n.info[1];
        } else if (IS_OPER(ss, '(')) {
            next_token(ss);
            TypeInfo *et = NULL;
            if ((r = parse_expression_1(ss, cntx, &et)) < 0) return r;
            while (IS_OPER(ss, ',')) {
                next_token(ss);
                if ((r = parse_expression_1(ss, cntx, &et)) < 0) return r;
            }
            if (!IS_OPER(ss, ')')) {
                parser_error(ss, "')' expected");
                return -1;
            }
            next_token(ss);
            fprintf(stderr, "type: ");
            tc_print(stderr, t);
            t = tc_skip_tcv(t);
            if (t->kind == NODE_POINTER_TYPE) {
                t = tc_skip_tcv(t->n.info[1]);
            }
            if (t->kind != NODE_FUNCTION_TYPE) {
                parser_error(ss, "function or function pointer type expected");
                return -1;
            }
            t = t->n.info[1];
        } else if (IS_OPER_2(ss, '-', '>')) {
            next_token(ss);
            t = tc_skip_tcv(t);
            if (t->kind != NODE_POINTER_TYPE) {
                parser_error(ss, "invalid argument for -> operation");
                return -1;
            }
            t = tc_skip_tcv(t->n.info[1]);
            if (t->kind != NODE_STRUCT_TYPE && t->kind != NODE_UNION_TYPE) {
                parser_error(ss, "structure or union type expected");
                return -1;
            }
            if (ss->token != TOK_IDENT) {
                parser_error(ss, "field name expected");
                return -1;
            }

            //tc_print_2(stderr, t, 3);

            TypeInfo *f = tc_find_field(t, tc_get_ident(cntx, ss->raw));
            if (!f) {
                parser_error(ss, "field '%s' is not declared", ss->raw);
                return -1;
            }
            t = f->n.info[2];
            next_token(ss);
        } else if (IS_OPER(ss, '.')) {
            next_token(ss);
            t = tc_skip_tcv(t);
            if (t->kind == NODE_POINTER_TYPE) {
                t = tc_skip_tcv(t->n.info[1]);
            }
            if (t->kind != NODE_STRUCT_TYPE && t->kind != NODE_UNION_TYPE) {
                parser_error(ss, "structure or union type expected");
                return -1;
            }
            if (ss->token != TOK_IDENT) {
                parser_error(ss, "field name expected");
                return -1;
            }
            TypeInfo *f = tc_find_field(t, tc_get_ident(cntx, ss->raw));
            if (!f) {
                parser_error(ss, "field '%s' is not declared", ss->raw);
                return -1;
            }
            t = f->n.info[2];
            next_token(ss);
        } else if (IS_OPER_2(ss, '+', '+')) {
            next_token(ss);
        } else if (IS_OPER_2(ss, '-', '-')) {
            next_token(ss);
        } else {
            break;
        }
    }
    if (p_info) *p_info = t;
    return 0;
}

// & * + - ~ ! ++ -- sizeof
static int
parse_expression_14(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    int r;
    TypeInfo *t = NULL;
    if (IS_OPER(ss, '&')) {
        next_token(ss);
        if ((r = parse_expression_14(ss, cntx, &t)) < 0) return r;
        if (p_info) *p_info = tc_get_ptr_type(cntx, t);
        return 0;
    } else if (IS_OPER(ss, '*')) {
        next_token(ss);
        if ((r = parse_expression_14(ss, cntx, &t)) < 0) return r;
        if (t->kind != NODE_POINTER_TYPE) {
            parser_error(ss, "pointer type expected");
            return -1;
        }
        if (p_info) *p_info = t->n.info[1];
        return 0;
    } else if (IS_OPER(ss, '+')) {
        next_token(ss);
        if ((r = parse_expression_14(ss, cntx, &t)) < 0) return r;
        if (p_info) *p_info = tc_promote(cntx, t);
        return 0;
    } else if (IS_OPER(ss, '-')) {
        next_token(ss);
        if ((r = parse_expression_14(ss, cntx, &t)) < 0) return r;
        if (p_info) *p_info = tc_promote(cntx, t);
        return 0;
    } else if (IS_OPER(ss, '~')) {
        next_token(ss);
        if ((r = parse_expression_14(ss, cntx, &t)) < 0) return r;
        if (p_info) *p_info = tc_promote(cntx, t);
        return 0;
    } else if (IS_OPER(ss, '!')) {
        next_token(ss);
        if ((r = parse_expression_14(ss, cntx, &t)) < 0) return r;
        if (p_info) *p_info = tc_get_i1_type(cntx);
        return 0;
    } else if (IS_OPER_2(ss, '+', '+')) {
        next_token(ss);
        if ((r = parse_expression_14(ss, cntx, &t)) < 0) return r;
        if (p_info) *p_info = t;
        return 0;
    } else if (IS_OPER_2(ss, '-', '-')) {
        next_token(ss);
        if ((r = parse_expression_14(ss, cntx, &t)) < 0) return r;
        if (p_info) *p_info = t;
        return 0;
    } else if (ss->token == TOK_IDENT && tc_get_ident(cntx, ss->raw) == kwd_sizeof) {
        next_token(ss);
        if (IS_OPER(ss, '(') && try_declr(ss, cntx) >= 0) {
            if ((r = parse_cast(ss, cntx, 0, &t)) < 0) return r;
        } else {
            if ((r = parse_expression(ss, cntx, &t)) < 0) return r;
        }
        t = tc_find_typedef_type(cntx, tc_get_ident(cntx, "size_t"));
        if (!t) t = tc_get_u32_type(cntx);
        if (p_info) *p_info = t;
        return 0;
    } else {
        if ((r = parse_expression_15(ss, cntx, &t)) < 0) return r;
        if (p_info) *p_info = t;
        return 0;
    }
}

// (TYPE) expr
static int
parse_expression_13(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    int r = 0;
    TypeInfo *t = NULL;
    if (IS_OPER(ss, '(') && try_declr(ss, cntx) >= 0) {
        if ((r = parse_cast(ss, cntx, 0, &t)) < 0) return r;
        if ((r = parse_expression_13(ss, cntx, NULL)) < 0) return r;
        if (p_info) *p_info = t;
        return 0;
    }
    return parse_expression_14(ss, cntx, p_info);
}

// mul
static int
parse_expression_12(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL, *info1 = NULL;
    int r = parse_expression_13(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER(ss, '*') || IS_OPER(ss, '/') || IS_OPER(ss, '%')) {
        next_token(ss);
        r = parse_expression_13(ss, cntx, &info1);
        if (r < 0) return r;
        info0 = tc_balance(cntx, info0, info1);
    }
    if (p_info) *p_info = info0;
    return 0;
}

// add
static int
parse_expression_11(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL, *info1 = NULL;
    int r = parse_expression_12(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER(ss, '+') || IS_OPER(ss, '-')) {
        next_token(ss);
        r = parse_expression_12(ss, cntx, &info1);
        if (r < 0) return r;
        info0 = tc_balance(cntx, info0, info1);
    }
    if (p_info) *p_info = info0;
    return 0;
}

// shift
static int
parse_expression_10(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL, *info1 = NULL;
    int r = parse_expression_11(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER_2(ss, '<', '<')
           || IS_OPER_2(ss, '>', '>')) {
        next_token(ss);
        r = parse_expression_11(ss, cntx, &info1);
        if (r < 0) return r;
        info0 = tc_balance(cntx, info0, info1);
    }
    if (p_info) *p_info = info0;
    return 0;
}

// relation
static int
parse_expression_9(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL, *info1 = NULL;
    int r = parse_expression_10(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER_2(ss, '<', '=')
           || IS_OPER_2(ss, '>', '=')
           || IS_OPER(ss, '<')
           || IS_OPER(ss, '>')) {
        next_token(ss);
        r = parse_expression_10(ss, cntx, &info1);
        if (r < 0) return r;
        info0 = tc_get_i1_type(cntx);
    }
    if (p_info) *p_info = info0;
    return 0;
}

// equality
static int
parse_expression_8(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL, *info1 = NULL;
    int r = parse_expression_9(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER_2(ss, '=', '=') || IS_OPER_2(ss, '!', '=')) {
        next_token(ss);
        r = parse_expression_9(ss, cntx, &info1);
        if (r < 0) return r;
        info0 = tc_get_i1_type(cntx);
    }
    if (p_info) *p_info = info0;
    return 0;
}

// and
static int
parse_expression_7(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL, *info1 = NULL;
    int r = parse_expression_8(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER(ss, '&')) {
        next_token(ss);
        r = parse_expression_8(ss, cntx, &info1);
        if (r < 0) return r;
        info0 = tc_balance(cntx, info0, info1);
    }
    if (p_info) *p_info = info0;
    return 0;
}

// xor
static int
parse_expression_6(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL, *info1 = NULL;
    int r = parse_expression_7(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER(ss, '^')) {
        next_token(ss);
        r = parse_expression_7(ss, cntx, &info1);
        if (r < 0) return r;
        info0 = tc_balance(cntx, info0, info1);
    }
    if (p_info) *p_info = info0;
    return 0;
}

// or
static int
parse_expression_5(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL, *info1 = NULL;
    int r = parse_expression_6(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER(ss, '|')) {
        next_token(ss);
        r = parse_expression_6(ss, cntx, &info1);
        if (r < 0) return r;
        info0 = tc_balance(cntx, info0, info1);
    }
    if (p_info) *p_info = info0;
    return 0;
}

// logical and
static int
parse_expression_4(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL;
    int r = parse_expression_5(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER_2(ss, '&', '&')) {
        next_token(ss);
        info0 = tc_get_i1_type(cntx);
        r = parse_expression_5(ss, cntx, NULL);
        if (r < 0) return r;
    }
    if (p_info) *p_info = info0;
    return 0;
}

// logical or
static int
parse_expression_3(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL;
    int r = parse_expression_4(ss, cntx, &info0);
    if (r < 0) return r;
    while (IS_OPER_2(ss, '|', '|')) {
        next_token(ss);
        info0 = tc_get_i1_type(cntx);
        r = parse_expression_4(ss, cntx, NULL);
        if (r < 0) return r;
    }
    if (p_info) *p_info = info0;
    return 0;
}

// conditional expression
static int
parse_expression_2(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *info0 = NULL;
    int r = parse_expression_3(ss, cntx, &info0);
    if (r < 0) return r;
    if (IS_OPER(ss, '?')) {
        next_token(ss);
        info0 = NULL;
        r = parse_expression(ss, cntx, &info0);
        if (r < 0) return r;
        if (!IS_OPER(ss, ':')) {
            parser_error(ss, "':' expected");
            return -1;
        }
        next_token(ss);
        r = parse_expression_2(ss, cntx, NULL);
        if (r < 0) return r;
    }
    if (p_info) *p_info = info0;
    return 0;
}

// assignment expression
static int
parse_expression_1(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    TypeInfo *lhs_info = NULL;
    int r = parse_expression_2(ss, cntx, &lhs_info);
    if (r < 0) return r;
    if (IS_OPER(ss, '=') 
        || IS_OPER_2(ss, '*', '=')
        || IS_OPER_2(ss, '/', '=')
        || IS_OPER_2(ss, '%', '=')
        || IS_OPER_2(ss, '+', '=')
        || IS_OPER_2(ss, '-', '=')
        || IS_OPER_2(ss, '&', '=')
        || IS_OPER_2(ss, '^', '=')
        || IS_OPER_2(ss, '|', '=')
        || IS_OPER_3(ss, '>', '>', '=')
        || IS_OPER_3(ss, '<', '<', '=')) {
        next_token(ss);
        r = parse_expression_2(ss, cntx, NULL);
        if (r < 0) return r;
    }
    if (p_info) *p_info = lhs_info;
    return 0;
}

// comma expression
static int
parse_expression(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
{
    int r = parse_expression_1(ss, cntx, p_info);
    if (r < 0) return r;
    while (IS_OPER(ss, ',')) {
        next_token(ss);
        r = parse_expression_1(ss, cntx, p_info);
        if (r < 0) return r;
    }
    return 0;
}

static int
parse_c_expression(ProcessorState *ps, TypeContext *cntx, FILE *log_f, const unsigned char *str, TypeInfo **p_info, Position pos)
{
    int retval = -1;
    int len = strlen(str);
    ScannerState *ss = init_scanner(ps, log_f, str, len, pos, cntx);
    next_token(ss);
    if (parse_expression(ss, cntx, p_info) < 0) {
        goto cleanup;
    }
    if (ss->token != TOK_EOF) {
        parser_error(ss, "end of expression expected");
        goto cleanup;
    }
    retval = 0;

cleanup:
    destroy_scanner(ss);
    return retval;
}

static int
handle_directive_page(ScannerState *ss, TypeContext *cntx, FILE *out_f)
{
    int retval = -1;
    unsigned char *page_name = NULL;
    enum { MAX_PARAM_COUNT = 1024 };
    TypeInfo *info[MAX_PARAM_COUNT];
    int idx = 0;
    int start_param_pos = 0;

    next_token(ss); //dump_token(ss);
    if (ss->token != TOK_IDENT) {
        parser_error(ss, "page name (identifier) expected");
        goto cleanup;
    }
    page_name = ss->value; ss->value = NULL;
    start_param_pos = ss->idx;
    next_token(ss);

    info[idx++] = tc_get_u32(cntx, 0);
    info[idx++] = tc_get_ident(cntx, page_name);
    info[idx++] = tc_get_i32_type(cntx);
    if (parse_params(ss, cntx, info, MAX_PARAM_COUNT, idx, 0) < 0) {
        goto cleanup;
    }

    TypeInfo *f = tc_get_function(cntx, info);
    TypeInfo *empty_id = tc_get_ident(cntx, "");
    processor_state_push_scope(ss->ps, tc_scope_create());
    for (int i = 3; i < f->n.count; ++i) {
        TypeInfo *param = f->n.info[i];
        if (param->kind == NODE_PARAM && param->n.info[3] != empty_id) {
            processor_state_add_to_scope(ss->ps, param);
        }
    }
    processor_state_push_scope(ss->ps, tc_scope_create());

    if (ss->token != TOK_EOF) {
        parser_error(ss, "garbage after directive");
        goto cleanup;
    }

    fprintf(out_f, "int %s%s\n{\n", page_name, ss->buf + start_param_pos);

    retval = 0;

cleanup:
    xfree(page_name);
    return retval;
}

static int
handle_directive_set(ScannerState *ss, TypeContext *cntx, FILE *out_f)
{
    int retval = -1;
    TypeInfo *name = NULL;
    TypeInfo *value = NULL;

    next_token(ss);
    if (ss->token != TOK_IDENT) {
        parser_error(ss, "identifier expected");
        goto cleanup;
    }
    if (!(name = tc_get_ident(cntx, ss->raw))) {
        parser_error(ss, "identifier expected");
        goto cleanup;
    }
    next_token(ss);
    if (!IS_OPER(ss, '=')) {
        parser_error(ss, "'=' expected");
        goto cleanup;
    }
    next_token(ss);
    if (!(value = make_value_info(ss, cntx))) {
        parser_error(ss, "value expected");
        goto cleanup;
    }

    int i;
    for (i = 0; i < ss->ps->settings.u; ++i) {
        if (ss->ps->settings.v[i].name == name)
            break;
    }
    if (i >= ss->ps->settings.u) {
        if (ss->ps->settings.u >= ss->ps->settings.a) {
            if (!(ss->ps->settings.a *= 2)) ss->ps->settings.a = 32;
            XREALLOC(ss->ps->settings.v, ss->ps->settings.a);
        }
        ss->ps->settings.v[i].name = name;
        ++ss->ps->settings.u;
    }
    ss->ps->settings.v[i].value = value;

    retval = 0;

cleanup:
    return retval;
}

static int
handle_directive(TypeContext *cntx, ProcessorState *ps, FILE *out_f, FILE *log_f, const unsigned char *str, int len, Position pos)
{
    ScannerState *ss = init_scanner(ps, log_f, str, len, pos, cntx);
    int retval = -1;

    next_token(ss); //dump_token(ss);

    if (ss->token != TOK_IDENT) {
        parser_error(ss, "directive expected");
    } else if (!strcmp(ss->value, "page")) {
        handle_directive_page(ss, cntx, out_f);
    } else if (!strcmp(ss->value, "set")) {
        handle_directive_set(ss, cntx, out_f);
    } else {
        parser_error(ss, "invalid directive '%s'", ss->value);
    }

    ss = destroy_scanner(ss);
    return retval;
}

static int
handle_c_code(
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *out_f,
        FILE *log_f,
        const unsigned char *str,
        int len,
        Position pos)
{
    ScannerState *ss = init_scanner(ps, log_f, str, len, pos, cntx);
    int retval = -1;
    next_token(ss); //dump_token(ss);

    while (ss->token != TOK_EOF) {
        if (is_vardecl_start(ss, cntx)) {
            parse_vardecl(ss, cntx, 0);
            continue;
        }
        if (IS_OPER(ss, '{')) {
            processor_state_push_scope(ps, tc_scope_create());
            next_token(ss); //dump_token(ss);
            continue;
        }
        if (IS_OPER(ss, '}')) {
            processor_state_pop_scope(ps);
            next_token(ss); //dump_token(ss);
            continue;
        }
        if (IS_OPER(ss, ';')) {
            next_token(ss); //dump_token(ss);
            continue;
        }
        while (ss->token != TOK_EOF && !IS_OPER(ss, ';') && !IS_OPER(ss, '{') && !IS_OPER(ss, '}')) {
            next_token(ss); //dump_token(ss);
        }
    }

    ss = destroy_scanner(ss);
    return retval;
}

static int
handle_html_text(FILE *out_f, FILE *txt_f, FILE *log_f, const unsigned char *mem, int start_idx, int end_idx)
{
    int len = end_idx - start_idx;
    if (len > 0) {
        int i;
        for (i = 0; i < strs.u; ++i) {
            if (strs.v[i].len == len && !memcmp(strs.v[i].str, mem + start_idx, len))
                break;
        }
        if (i >= strs.u) {
            if (strs.u >= strs.a) {
                if (!(strs.a *= 2)) strs.a = 32;
                XREALLOC(strs.v, strs.a);
            }
            strs.v[i].len = len;
            strs.v[i].str = xmemdup(mem + start_idx, len);
            ++strs.u;

            fprintf(txt_f, "static const unsigned char csp_str%d[%d] = ", i, len + 1);
            emit_str_literal(txt_f, mem + start_idx, len);
            fprintf(txt_f, ";\n");
        }

        fprintf(out_f, "fwrite(csp_str%d, 1, %d, out_f);\n", i, len);
    }
    return 0;
}

static int
process_ac_attr(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        HtmlElement *elem,
        unsigned char *buf,
        int bufsize)
{
    HtmlAttribute *at = html_element_find_attribute(elem, "ac"); // action code
    if (!at) return 0;

    TypeInfo *ac_prefix = processor_state_find_setting(ps, tc_get_ident(cntx, "ac_prefix"));
    if (!ac_prefix) {
        parser_error_2(ps, "'ac_prefix' global parameter is undefined");
        return -1;
    }
    if (ac_prefix->kind != NODE_STRING) {
        parser_error_2(ps, "'ac_prefix' global parameter must be of type 'STRING'");
        return -1;
    }
    snprintf(buf, bufsize, "%s%s", ac_prefix->s.str, at->value);
    int len = strlen(buf);
    for (int i = 0; i < len; ++i) {
        if (buf[i] == '-') buf[i] = '_';
        buf[i] = toupper(buf[i]);
    }
    return 1;
}

static int
handle_a_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    unsigned char buf[1024];
    int r;

    HtmlAttribute *attr = html_element_find_attribute(elem, "url");
    if (attr) {
        HtmlElement *url_elem = processor_state_find_named_url(ps, tc_get_ident(cntx, attr->value));
        if (!url_elem) {
            parser_error_2(ps, "URL '%s' is undefined", attr->value);
            return -1;
        }
        r = process_ac_attr(log_f, cntx, ps, url_elem, buf, sizeof(buf));
        if (r < 0) return r;
        if (!r) {
            parser_error_2(ps, "ac attribute is undefined");
            return -1;
        }
        fprintf(prg_f, "fputs(\"<a href=\\\"\", out_f);\n");
        fprintf(prg_f, "sep = ns_url_2(out_f, phr, %s);\n", buf);
        for (HtmlElement *child = url_elem->first_child; child; child = child->next_sibling) {
            fprintf(prg_f, "fputs(sep, out_f); sep = \"&amp;\";\n");
            attr = html_element_find_attribute(child, "name");
            if (attr) {
                fprintf(prg_f, "fputs(\"%s=\", out_f);\n", attr->value);
                attr = html_element_find_attribute(child, "value");
                if (attr) {
                    TypeInfo *t = NULL;
                    r = parse_c_expression(ps, cntx, log_f, attr->value, &t, ps->pos);
                    if (r >= 0) {
                        fprintf(log_f, "Expression type: ");
                        tc_print_2(log_f, t, 2);
                        fprintf(log_f, "\n");

                        processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, attr->value, child, t);
                    }
                }
            }
        }
        fprintf(prg_f, "(void) sep;\n");
        fprintf(prg_f, "fputs(\"\\\">\", out_f);\n");
        return 0;
    }

    r = process_ac_attr(log_f, cntx, ps, elem, buf, sizeof(buf));
    if (r < 0) return r;
    if (r > 0) {
        fprintf(prg_f, "fputs(ns_aref(hbuf, sizeof(hbuf), phr, %s, 0), out_f);\n", buf);
    }
    return 0;
}

static int
handle_a_close(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        unsigned char *mem,
        int beg_i,
        int end_i)
{
    handle_html_text(prg_f, txt_f, log_f, mem, beg_i, end_i);
    fprintf(prg_f, "fputs(\"</a>\", out_f);\n");
    return 0;
}

static int
handle_form_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    const unsigned char *method = "post";
    const unsigned char *enctype = NULL;
    const unsigned char *id = NULL;

    HtmlAttribute *at = html_element_find_attribute(elem, "method");
    if (at && !strcmp(at->value, "get")) {
        method = "get";
    }
    if (!strcmp(method, "post")) {
        at = html_element_find_attribute(elem, "enctype");
        if (at && !strcmp(at->value, "multipart/form-data")) {
            enctype = at->value;
        } else {
            enctype = "application/x-www-form-urlencoded";
        }
    }
    if ((at = html_element_find_attribute(elem, "id"))) {
        id = at->value;
    }

    // FIXME: handle action, or ac
    fprintf(prg_f, "fputs(\"<form method=\\\"%s\\\"", method);
    if (enctype && *enctype) {
        fprintf(prg_f, " enctype=\\\"%s\\\"", enctype);
    }
    if (id && *id) {
        fprintf(prg_f, " id=\\\"%s\\\"", id);
    }
    fprintf(prg_f, " action=\\\"\", out_f);\n");
    fprintf(prg_f, "fputs(phr->self_url, out_f);\n");
    fprintf(prg_f, "fputs(\"\\\">\", out_f);\n");
    fprintf(prg_f, "fputs(phr->hidden_vars, out_f);\n");

    return 0;
}

static int
handle_form_close(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        unsigned char *mem,
        int beg_i,
        int end_i)
{
    handle_html_text(prg_f, txt_f, log_f, mem, beg_i, end_i);
    fprintf(prg_f, "fputs(\"</form>\", out_f);\n");
    return 0;
}

static int
handle_submit_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    unsigned char buf[1024];
    const unsigned char *value = NULL;

    if (!elem->no_body) {
        parser_error_2(ps, "<s:submit> element must not have a body");
        return -1;
    }

    HtmlAttribute *at = html_element_find_attribute(elem, "value");
    if (at) {
        value = at->value;
    } else {
        value = "NULL";
    }

    int r = process_ac_attr(log_f, cntx, ps, elem, buf, sizeof(buf));
    if (r < 0) return r;
    if (r > 0) {
        fprintf(prg_f, "fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, %s, %s), out_f);\n", buf, value);
    } else if ((at = html_element_find_attribute(elem, "action"))) {
        fprintf(prg_f, "fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, (%s), %s), out_f);\n", at->value, value);
    }

    return 0;
}

static int
handle_v_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    if (!elem->no_body) {
        parser_error_2(ps, "<s:v> element must not have a body");
        return -1;
    }

    HtmlAttribute *at = html_element_find_attribute(elem, "value");
    if (!at) {
        parser_error_2(ps, "<s:v> element requires value attribute");
        return -1;
    }

    TypeInfo *t = NULL;
    int r = parse_c_expression(ps, cntx, log_f, at->value, &t, ps->pos);
    if (r < 0) return r;

    fprintf(log_f, "Expression type: ");
    tc_print_2(log_f, t, 2);
    fprintf(log_f, "\n");

    processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, at->value, elem, t);

    return 0;
}

static int
handle_url_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    // save for future perusal
    ps->el_stack->extra = html_element_clone(elem);

    return 0;
}

static int
handle_url_close(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        unsigned char *mem,
        int beg_i,
        int end_i)
{
    HtmlElement *elem = ps->el_stack->extra;
    HtmlAttribute *at = html_element_find_attribute(elem, "name");
    if (!at) {
        parser_error_2(ps, "<s:url> element requires 'name' attribute");
        return -1;
    }
    processor_state_add_named_url(ps, tc_get_ident(cntx, at->value), elem);
    ps->el_stack->extra = NULL;
    return 0;
}

static int
handle_param_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    HtmlElement *url_elem = ps->el_stack->up->extra;

    if (!url_elem || strcmp(url_elem->name, "s:url") != 0) {
        parser_error_2(ps, "s:param must be nested to s:url");
        return -1;
    }
    if (!elem->no_body) {
        parser_error_2(ps, "<s:param> element must not have a body");
        return -1;
    }
    html_element_add_child(url_elem, html_element_clone(elem));

    return 0;
}

static int
handle_html_element_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    if (!strcmp(ps->el_stack->el->name, "s:tr")) {
        fprintf(prg_f, "fputs(_(");
    } else if (!strcmp(ps->el_stack->el->name, "s:a")) {
        handle_a_open(log_f, cntx, ps, txt_f, prg_f);
    } else if (!strcmp(ps->el_stack->el->name, "s:submit")) {
        handle_submit_open(log_f, cntx, ps, txt_f, prg_f);
    } else if (!strcmp(ps->el_stack->el->name, "s:v")) {
        handle_v_open(log_f, cntx, ps, txt_f, prg_f);
    } else if (!strcmp(ps->el_stack->el->name, "s:form")) {
        handle_form_open(log_f, cntx, ps, txt_f, prg_f);
    } else if (!strcmp(ps->el_stack->el->name, "s:url")) {
        handle_url_open(log_f, cntx, ps, txt_f, prg_f);
    } else if (!strcmp(ps->el_stack->el->name, "s:param")) {
        handle_param_open(log_f, cntx, ps, txt_f, prg_f);
    } else {
        parser_error_2(ps, "unhandled element");
    }
    return 0;
}

static int
handle_html_element_close(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        unsigned char *mem,
        int beg_i,
        int end_i)
{
    if (!strcmp(ps->el_stack->el->name, "s:tr")) {
        emit_str_literal(prg_f, mem + beg_i, end_i - beg_i);
        fprintf(prg_f, "), out_f);\n");
    } else if (!strcmp(ps->el_stack->el->name, "s:a")) {
        handle_a_close(log_f, cntx, ps, txt_f, prg_f, mem, beg_i, end_i);
    } else if (!strcmp(ps->el_stack->el->name, "s:form")) {
        handle_form_close(log_f, cntx, ps, txt_f, prg_f, mem, beg_i, end_i);
    } else if (!strcmp(ps->el_stack->el->name, "s:url")) {
        handle_url_close(log_f, cntx, ps, txt_f, prg_f, mem, beg_i, end_i);
    } else {
        parser_error_2(ps, "unhandled element");
    }
    return 0;
}

static void
string_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    int need_escape = 1;
    HtmlAttribute *at = NULL;
    if (elem) {
        at = html_element_find_attribute(elem, "escape");
    }
    if (at) {
        int v;
        if (xml_parse_bool(NULL, NULL, 0, 0, at->value, &v) >= 0) need_escape = v;
    }
    if (need_escape) {
        if (!strcmp(elem->name, "s:param")) {
            fprintf(prg_f, "url_armor_string(hbuf, sizeof(hbuf), (%s));\n", text);
            fprintf(prg_f, "fputs(hbuf, out_f);\n");
        } else {
            fprintf(prg_f, "fputs(html_armor_buf(&ab, (%s)), out_f);\n", text);
        }
    } else {
        fprintf(prg_f, "fputs((%s), out_f);\n", text);
    }
}

static void
cookie_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f, "fprintf(out_f, \"%%016llx\", (%s));\n", text);
}

static void
int_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    // handle "format"?
    fprintf(prg_f, "fprintf(out_f, \"%%d\", (int)(%s));\n", text);
}

static void
long_long_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    // handle "format"?
    fprintf(prg_f, "fprintf(out_f, \"%%lld\", (long long)(%s));\n", text);
}

static void
time_t_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f, "fputs(xml_unparse_date((%s)), out_f);\n", text);
}

static void
size_t_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    // handle "format"?
    fprintf(prg_f, "fprintf(out_f, \"%%zu\", (size_t)(%s));\n", text);
}

static int
process_file(
        FILE *log_f,
        FILE *out_f,
        const unsigned char *path,
        TypeContext *cntx,
        IdScope *global_scope)
{
    FILE *in_f = NULL;
    int result = 0;
    int cc;

    ProcessorState *ps = processor_state_init(log_f);

    processor_state_set_type_handler(ps, tc_get_ptr_type(cntx, tc_get_const_type(cntx, tc_get_u8_type(cntx))),
                                     string_type_handler);
    processor_state_set_type_handler(ps, tc_get_ptr_type(cntx, tc_get_u8_type(cntx)),
                                     string_type_handler);
    processor_state_set_type_handler(ps, tc_get_ptr_type(cntx, tc_get_const_type(cntx, tc_get_i8_type(cntx))),
                                     string_type_handler);
    processor_state_set_type_handler(ps, tc_get_ptr_type(cntx, tc_get_i8_type(cntx)),
                                     string_type_handler);
    processor_state_set_type_handler(ps, tc_get_open_array_type(cntx, tc_get_u8_type(cntx)),
                                     string_type_handler);
    processor_state_set_type_handler(ps, tc_get_open_array_type(cntx, tc_get_i8_type(cntx)),
                                     string_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ej_cookie_t")),
                                     cookie_type_handler);
    processor_state_set_type_handler(ps, tc_get_i32_type(cntx), int_type_handler);
    processor_state_set_type_handler(ps, tc_get_i64_type(cntx), long_long_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "time_t")),
                                     time_t_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "size_t")),
                                     size_t_type_handler);

    processor_state_set_array_type_handler(ps, tc_get_u8_type(cntx), string_type_handler);
    processor_state_set_array_type_handler(ps, tc_get_i8_type(cntx), string_type_handler);

    char *txt_t = NULL;
    size_t txt_z = 0;
    FILE *txt_f = open_memstream(&txt_t, &txt_z);

    char *prg_t = NULL;
    size_t prg_z = 0;
    FILE *prg_f = open_memstream(&prg_t, &prg_z);

    unsigned char *mem = NULL;
    int mem_a = 0, mem_u = 0, mem_i = 0, html_i = 0;

    if (!strcmp(path, "-")) {
        in_f = stdin;
    } else {
        in_f = fopen(path, "r");
        if (!in_f) {
            fprintf(log_f, "%s: cannot open file '%s': %s\n", progname, path, os_ErrorMsg());
            goto fail;
        }
    }
    processor_state_init_file(ps, path);
    processor_state_push_scope(ps, global_scope);

    // read the whole file to memory
    mem_a = 1024;
    mem = xmalloc(mem_a * sizeof(mem[0]));
    while ((cc = getc(in_f)) != EOF) {
        if (mem_u + 1 >= mem_a) {
            mem = xrealloc(mem, (mem_a *= 2) * sizeof(mem[0]));
        }
        mem[mem_u++] = cc;
    }
    mem[mem_u] = 0;
    if (in_f != stdin) fclose(in_f);
    in_f = NULL;

    mem_i = 0;
    html_i = 0;
    while (mem_i < mem_u) {
        if (mem[mem_i] == '<' && mem[mem_i + 1] == '%') {
            handle_html_text(prg_f, txt_f, log_f, mem, html_i, mem_i);
            pos_next(&ps->pos, '<');
            pos_next(&ps->pos, '%');
            Position start_pos = ps->pos;
            mem_i += 2;
            html_i = mem_i;
            while (mem_i < mem_u && (mem[mem_i] != '%' || mem[mem_i + 1] != '>')) {
                pos_next(&ps->pos, mem[mem_i]);
                ++mem_i;
            }
            int end_i = mem_i;
            if (mem_i < mem_u) {
                pos_next(&ps->pos, '%');
                pos_next(&ps->pos, '>');
                mem_i += 2;
            }
            mem[end_i] = 0;

            while (end_i > html_i && isspace(mem[end_i - 1])) --end_i;
            mem[end_i] = 0;
            if (end_i > html_i) {
                int t = mem[html_i];
                if (t == '@' || t == '=') {
                    pos_next(&start_pos, t);
                    ++html_i;
                } else {
                    t = '*';
                }
                while (isspace(mem[html_i])) {
                    pos_next(&start_pos, mem[html_i]);
                    ++html_i;
                }
                if (t == '@') {
                    handle_directive(cntx, ps, prg_f, log_f, mem + html_i, end_i - html_i, start_pos);
                } else if (t == '=') {
                } else {
                    // plain <% %>
                    fprintf(prg_f, "\n#line %d \"%s\"\n", start_pos.line, ps->filenames[start_pos.filename_idx]);
                    fprintf(prg_f, "%s\n", mem + html_i);
                    handle_c_code(cntx, ps, prg_f, log_f, mem + html_i, end_i - html_i, start_pos);
                }
            }
            html_i = mem_i;
        } else if (mem[mem_i] == '<' && mem[mem_i + 1] == 's' && mem[mem_i + 2] == ':') {
            handle_html_text(prg_f, txt_f, log_f, mem, html_i, mem_i);
            html_i = mem_i;

            int end_i = 0;
            HtmlElement *el = html_element_parse_start(mem, mem_i, &end_i);
            if (!el) {
                char pb[1024];
                fprintf(log_f, "%s: invalid element\n", pos_str_2(pb, sizeof(pb), ps, &ps->pos));
                pos_next(&ps->pos, mem[mem_i]);
                ++mem_i;
            } else {
                HtmlElementStack *cur = NULL;
                XCALLOC(cur, 1);
                cur->up = ps->el_stack;
                cur->el = el;
                ps->el_stack = cur;

                handle_html_element_open(log_f, cntx, ps, txt_f, prg_f);

                while (mem_i < end_i) {
                    pos_next(&ps->pos, mem[mem_i]);
                    ++mem_i;
                }
                html_i = mem_i;

                if (el->no_body) {
                    ps->el_stack = cur->up;
                    html_element_free(cur->el);
                    xfree(cur);
                }
            }
        } else if (mem[mem_i] == '<' && mem[mem_i + 1] == '/' && mem[mem_i + 2] == 's' && mem[mem_i + 3] == ':') {
            int end_i = 0;
            HtmlElement *el = html_element_parse_end(mem, mem_i, &end_i);
            if (!el) {
                parser_error_2(ps, "invalid element");
                pos_next(&ps->pos, mem[mem_i]);
                ++mem_i;
            } else {
                HtmlElementStack *cur = ps->el_stack;
                if (!cur) {
                    parser_error_2(ps, "element stack is empty");
                } else {
                    if (strcmp(el->name, cur->el->name) != 0) {
                        parser_error_2(ps, "element mismatch");
                    } else {
                        handle_html_element_close(log_f, cntx, ps, txt_f, prg_f, mem, html_i, mem_i);
                    }
                    ps->el_stack = cur->up;
                    html_element_free(cur->el);
                    xfree(cur);
                }

                el = html_element_free(el);
                while (mem_i < end_i) {
                    pos_next(&ps->pos, mem[mem_i]);
                    ++mem_i;
                }
                html_i = mem_i;
            }
        } else {
            pos_next(&ps->pos, mem[mem_i]);
            ++mem_i;
        }
    }
    handle_html_text(prg_f, txt_f, log_f, mem, html_i, mem_i);

    fprintf(out_f, "/* === string pool === */\n\n");
    fclose(txt_f); txt_f = NULL;
    fwrite(txt_t, 1, txt_z, out_f);
    free(txt_t); txt_t = NULL; txt_z = 0;
    fprintf(out_f, "\n");

    fclose(prg_f); prg_f = NULL;
    fwrite(prg_t, 1, prg_z, out_f);
    free(prg_t); prg_t = NULL; prg_z = 0;

    // FIXME: put error handling here...
    fprintf(out_f, "  return 0;\n");
    fprintf(out_f, "}\n");
    processor_state_pop_scope(ps); // local variables scope
    processor_state_pop_scope(ps); // parameter scope

cleanup:
    if (in_f && in_f != stdin) fclose(in_f);
    return result;

fail:
    result = 1;
    goto cleanup;
}

int
main(int argc, char *argv[])
{
    int argi = 1;

    progname = os_GetLastname(argv[0]);

    while (argi < argc) {
        if (!strcmp(argv[argi], "--version")) {
            report_version();
        } else if (!strcmp(argv[argi], "--help")) {
            report_help();
        } else if (!strcmp(argv[argi], "--")) {
            ++argi;
            break;
        } else if (!strcmp(argv[argi], "-")) {
            break;
        } else if (argv[argi][0] == '-') {
            fatal("invalid option '%s'", argv[argi]);
        } else {
            break;
        }
    }

    if (argi >= argc) {
        fatal("source file name is expected");
    }
    const unsigned char *source_path = argv[argi++];
    if (argi < argc) {
        fatal("too many command line arguments");
    }

    TypeContext *cntx = tc_create();
    IdScope *global_scope = tc_scope_create();
    if (dwarf_parse(stderr, argv[0], cntx, global_scope) < 0) {
        tc_dump_context(stdout, cntx);
        tc_free(cntx);
        fatal("dwarf parsing failed");
    }
    //tc_dump_context(stdout, cntx);

    int result = 0;
    result = process_file(stderr, stdout, source_path, cntx, global_scope) || result;

    tc_free(cntx);

    return result;
}

/* these are required to correctly link all object files */

int utf8_mode;
void *ul_conn;

unsigned char *ul_login;
int ul_uid;

void * /*struct contest_extra * */
get_existing_contest_extra(int num)
{
    return NULL;
}
void
super_serve_register_process(/*struct background_process *prc*/)
{
}
void * /*struct background_process * */
super_serve_find_process(const unsigned char *name)
{
    return NULL;
}
const void * /*const struct sid_state* */
super_serve_sid_state_get_test_editor(int contest_id)
{
    return NULL;
}
const void * /*struct sid_state* */
super_serve_sid_state_get_cnts_editor(int contest_id)
{
    return NULL;
}
void * /*struct sid_state**/
super_serve_sid_state_get_cnts_editor_nc(int contest_id)
{
    return NULL;
}
void
super_serve_clear_edited_contest(/*struct sid_state *p*/ void *p)
{
}
int
super_serve_sid_state_get_max_edited_cnts(void)
{
    return 0;
}
void
super_serve_move_edited_contest(void *dst, void * src /*struct sid_state *dst, struct sid_state *src*/)
{
}
void */*struct update_state * */
update_state_free(/*struct update_state *us*/ void *us)
{
    return NULL;
}
void * /*struct update_state * */
update_state_create(void)
{
    return NULL;
}

void * /*struct session_info * */
ns_get_session(
        ej_cookie_t session_id,
        ej_cookie_t client_key,
        time_t cur_time)
{
    return NULL;
}
void
ns_remove_session(ej_cookie_t session_id)
{
}
int
nsdb_check_role(int user_id, int contest_id, int role)
{
    return 0;
}
void * /*int_iterator_t*/
nsdb_get_examiner_user_id_iterator(int contest_id, int prob_id)
{
    return NULL;
}
int
nsdb_get_examiner_count(int contest_id, int prob_id)
{
    return 0;
}
int
nsdb_find_chief_examiner(int contest_id, int prob_id)
{
    return 0;
}
int
nsdb_get_priv_role_mask_by_iter(void * /*int_iterator_t*/ iter, unsigned int *p_mask)
{
    return 0;
}
void * /*int_iterator_t*/
nsdb_get_contest_user_id_iterator(int contest_id)
{
    return NULL;
}
int
nsdb_remove_examiner(int user_id, int contest_id, int prob_id)
{
    return 0;
}
int
nsdb_assign_chief_examiner(int user_id, int contest_id, int prob_id)
{
    return 0;
}
int
nsdb_assign_examiner(int user_id, int contest_id, int prob_id)
{
    return 0;
}
int
nsdb_add_role(int user_id, int contest_id, int role)
{
    return 0;
}
int
nsdb_del_role(int user_id, int contest_id, int role)
{
    return 0;
}
int
nsdb_priv_remove_user(int user_id, int contest_id)
{
    return 0;
}
void
ns_send_reply(void * /*struct client_state * */ p, int answer)
{
}
void
ns_new_autoclose(void * /*struct client_state * */ p, void *write_buf, size_t write_len)
{
}
void * /*struct client_state * */
ns_get_client_by_id(int client_id)
{
    return NULL;
}

const char compile_version[] = "?";
const char compile_date[] = "?";

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
