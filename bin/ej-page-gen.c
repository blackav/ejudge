/* -*- c -*- */

/* Copyright (C) 2014-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/ej_types.h"
#include "ejudge/type_info.h"
#include "ejudge/dwarf_parse.h"
#include "ejudge/html_parse.h"
#include "ejudge/xml_utils.h"
#include "ejudge/new_server_pi.h"
#include "ejudge/super_serve_pi.h"
#include "ejudge/internal_pages.h"

#include "ejudge/compile_heartbeat.h"

#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"
#include "ejudge/c_value.h"

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
    TOK_MACROBODY
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

typedef struct Macro
{
    TypeInfo *name;
    unsigned char *body;
    int body_len;
} Macro;
typedef struct MacroArray
{
    int a, u;
    Macro *v;
} MacroArray;

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

typedef int (*ReadTypeHandler)(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const HtmlElement *elem,
        const unsigned char *var_name,
        const unsigned char *param_name,
        TypeInfo *type_info);

typedef struct ReadTypeHandlerInfo
{
    TypeInfo *type_info;
    ReadTypeHandler handler;
} ReadTypeHandlerInfo;

typedef struct ReadTypeHandlerArray
{
    int a, u;
    ReadTypeHandlerInfo *v;
} ReadTypeHandlerArray;

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
    ReadTypeHandlerArray read_type_handlers;
    ReadTypeHandlerArray read_array_type_handlers;
    MacroArray macros;

    int is_in_function;
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
processor_state_add_to_scope(ProcessorState *ps, TypeInfo *def, TypeInfo *id)
{
    if (tc_scope_find_local(ps->scope_stack, id)) {
        parser_error_2(ps, "identifier '%s' already declared", id->s.str);
    } else {
        tc_scope_add(ps->scope_stack, def);
    }
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

static int
processor_state_invoke_read_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const HtmlElement *elem,
        const unsigned char *var_name,
        const unsigned char *param_name,
        TypeInfo *type_info)
{
    if (type_info && type_info->kind == NODE_ARRAY_TYPE) {
        for (int i = 0; i < ps->read_array_type_handlers.u; ++i) {
            if (ps->read_array_type_handlers.v[i].type_info == type_info->n.info[1]) {
                return ps->read_array_type_handlers.v[i].handler(log_f, cntx, ps, txt_f, prg_f, elem, var_name, param_name, type_info);
            }
        }
    }

    for (int i = 0; i < ps->read_type_handlers.u; ++i) {
        if (ps->read_type_handlers.v[i].type_info == type_info) {
            return ps->read_type_handlers.v[i].handler(log_f, cntx, ps, txt_f, prg_f, elem, var_name, param_name, type_info);
        }
    }
    parser_error_2(ps, "no read type handler installed");
    tc_print_2(log_f, type_info, 3);
    fprintf(log_f, "\n");
    return -1;
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
add_read_type_handler(
        ReadTypeHandlerArray *pa,
        TypeInfo *type_info,
        ReadTypeHandler handler)
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
processor_state_set_read_type_handler(
        ProcessorState *ps,
        TypeInfo *type_info,
        ReadTypeHandler handler)
    __attribute__((unused));
static void
processor_state_set_read_type_handler(
        ProcessorState *ps,
        TypeInfo *type_info,
        ReadTypeHandler handler)
{
    add_read_type_handler(&ps->read_type_handlers, type_info, handler);
}

static void
processor_state_set_read_array_type_handler(
        ProcessorState *ps,
        TypeInfo *type_info,
        ReadTypeHandler handler)
    __attribute__((unused));
static void
processor_state_set_read_array_type_handler(
        ProcessorState *ps,
        TypeInfo *type_info,
        ReadTypeHandler handler)
{
    add_read_type_handler(&ps->read_array_type_handlers, type_info, handler);
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
static TypeInfo *kwd___attribute__ = NULL;

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
        kwd___attribute__ = tc_get_ident(cntx, "__attribute__");
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
next_macro_body(ScannerState *ss)
{
    xfree(ss->value); ss->value = NULL; ss->value_len = 0;
    xfree(ss->raw); ss->raw = NULL; ss->raw_len = 0;
    int c;

    while (isspace((c = ss->buf[ss->idx]))) {
        pos_next(&ss->pos, c);
        ++ss->idx;
    }
    if (ss->idx >= ss->len) {
        ss->token = TOK_EOF;
        return;
    }
    ss->token_pos = ss->pos;
    int saved_idx = ss->idx;
    int end_idx = ss->idx;
    while (1) {
        if (ss->idx + 2 < ss->len && ss->buf[ss->idx] == '@' && ss->buf[ss->idx + 1] == '%' && ss->buf[ss->idx + 2] == '>') {
            end_idx = ss->idx;
            ss->idx += 3;
            pos_next_n(&ss->pos, 3);
            break;
        }
        if (ss->idx == ss->len) {
            end_idx = ss->idx;
            break;
        }
        pos_next(&ss->pos, ss->buf[ss->idx]);
        ++ss->idx;
    }

    //while (end_idx > saved_idx && isspace(ss->buf[end_idx - 1])) --end_idx;

    ss->value_len = end_idx - saved_idx;
    ss->raw_len = ss->value_len;
    ss->value = xmalloc(ss->value_len + 1);
    ss->raw = xmalloc(ss->value_len + 1);
    memcpy(ss->value, ss->buf + saved_idx, ss->value_len);
    memcpy(ss->raw, ss->buf + saved_idx, ss->value_len);
    ss->value[ss->value_len] = 0;
    ss->raw[ss->value_len] = 0;
    ss->token = TOK_MACROBODY;
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
parse_full_declr(
        ScannerState *ss,
        TypeContext *cntx,
        int quiet_mode,
        int anon_allowed,
        TypeInfo *ds,
        TypeInfo **p_type,
        TypeInfo **p_id);

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
try_type(
        ScannerState *ss,
        TypeContext *cntx)
{
    SavedScannerState *sss = save_scanner_state(ss);
    next_token(ss);

    TypeInfo *ds = NULL;
    TypeInfo *id = NULL;
    int ret = parse_declspec(ss, cntx, 1, &ds);
    if (ret >= 0 && !IS_OPER(ss, ')')) {
        ret = parse_full_declr(ss, cntx, 1, 1, ds, &ds, &id);
        if (ret >= 0 && !IS_OPER(ss, ')')) {
            ret = -1;
        }
    }
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

    if (ss->token == TOK_IDENT && tc_get_ident(cntx, ss->raw) == kwd___attribute__) {
        // ignore __attribute__(...)
        next_token(ss);
        int depth = 0;
        while (1) {
            if (ss->token == TOK_EOF) {
                parser_error(ss, "unexpected end of text");
                break;
            }
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
                if (!depth) break;
            } else if (IS_OPER(ss, '}')) {
                --depth;
                next_token(ss);
            } else if (IS_OPER(ss, ']')) {
                --depth;
                next_token(ss);
            } else {
                next_token(ss);
            }
        }
    }
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
                //if (!depth) break;
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
    processor_state_add_to_scope(ss->ps, tc_get_local_var(cntx, tc_get_i32(cntx, 0), vartype, id, tc_get_i32(cntx, 0)), id);
    while (IS_OPER(ss, ',')) {
        next_token(ss);
        vartype = NULL;
        id = NULL;
        r = parse_init_declr(ss, cntx, quiet_mode, 0, ds, &vartype, &id);
        if (r < 0) return -1;
        processor_state_add_to_scope(ss->ps, tc_get_local_var(cntx, tc_get_i32(cntx, 0), vartype, id, tc_get_i32(cntx, 0)), id);
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
            /*
            fprintf(stderr, "type: ");
            tc_print(stderr, t);
            */
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
        if (IS_OPER(ss, '(') && try_type(ss, cntx) >= 0) {
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
    if (IS_OPER(ss, '(') && try_type(ss, cntx) >= 0) {
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
html_attribute_get_bool(const HtmlAttribute *attr, int default_value)
{
    int v;
    if (!attr) return default_value;
    if (xml_parse_bool(NULL, NULL, 0, 0, attr->value, &v) >= 0) return v;
    return default_value;
}

static int
handle_directive_function(ScannerState *ss, TypeContext *cntx, FILE *out_f)
{
    int retval = -1;
    unsigned char *page_name = NULL;
    enum { MAX_PARAM_COUNT = 1024 };
    TypeInfo *info[MAX_PARAM_COUNT];
    int idx = 0;
    int start_param_pos = 0;

    if (ss->ps->is_in_function > 0) {
        processor_state_pop_scope(ss->ps);
        processor_state_pop_scope(ss->ps);
        fprintf(out_f, "return retval;\n}\n\n");
    }

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
            processor_state_add_to_scope(ss->ps, param, param->n.info[3]);
        }
    }
    processor_state_push_scope(ss->ps, tc_scope_create());

    if (ss->token != TOK_EOF) {
        parser_error(ss, "garbage after directive");
        goto cleanup;
    }

    ss->ps->is_in_function = 1;
    fprintf(out_f, "static int %s%s\n{\n", page_name, ss->buf + start_param_pos);

    retval = 0;

cleanup:
    xfree(page_name);
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

    if (ss->ps->is_in_function > 0) {
        processor_state_pop_scope(ss->ps);
        processor_state_pop_scope(ss->ps);
        fprintf(out_f, "return retval;\n}\n\n");
    }
    ss->ps->is_in_function = 1;

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
            processor_state_add_to_scope(ss->ps, param, param->n.info[3]);
        }
    }
    processor_state_push_scope(ss->ps, tc_scope_create());

    if (ss->token != TOK_EOF) {
        parser_error(ss, "garbage after directive");
        goto cleanup;
    }

    TypeInfo *getter_name = processor_state_find_setting(ss->ps, tc_get_ident(cntx, "getter_name"));
    if (getter_name) {
        if (getter_name->kind != NODE_STRING) {
            parser_error_2(ss->ps, "'getter_name' global parameter must be of type 'STRING'");
            return -1;
        }

        fprintf(out_f, "int %s%s;\n", page_name, ss->buf + start_param_pos);
        fprintf(out_f,
                "static PageInterfaceOps page_ops =\n"
                "{\n"
                "    NULL, // destroy\n"
                "    NULL, // execute\n"
                "    %s, // render\n"
                "};\n"
                "static PageInterface page_iface =\n"
                "{\n"
                "    &page_ops,\n"
                "};\n"
                "PageInterface *\n"
                "%s(void)\n"
                "{\n"
                "    return &page_iface;\n"
                "}\n\n",
                page_name, getter_name->s.str);
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
handle_directive_define(ScannerState *ss, TypeContext *cntx, FILE *out_f)
{
    int retval = -1;
    TypeInfo *name = NULL;

    next_token(ss);
    if (ss->token != TOK_IDENT) {
        parser_error(ss, "identifier expected");
        goto cleanup;
    }
    if (!(name = tc_get_ident(cntx, ss->raw))) {
        parser_error(ss, "identifier expected");
        goto cleanup;
    }
    next_macro_body(ss);
    if (ss->token != TOK_MACROBODY) {
        parser_error(ss, "macro body expected");
        goto cleanup;
    }

    int i;
    for (i = 0; i < ss->ps->macros.u; ++i) {
        if (ss->ps->macros.v[i].name == name)
            break;
    }
    if (i >= ss->ps->macros.u) {
        if (ss->ps->macros.u >= ss->ps->macros.a) {
            if (!(ss->ps->macros.a *= 2)) ss->ps->macros.a = 32;
            XREALLOC(ss->ps->macros.v, ss->ps->macros.a);
        }
        memset(&ss->ps->macros.v[i], 0, sizeof(ss->ps->macros.v[i]));
        ss->ps->macros.v[i].name = name;
        ++ss->ps->macros.u;
    }
    xfree(ss->ps->macros.v[i].body);
    ss->ps->macros.v[i].body = ss->value;
    ss->ps->macros.v[i].body_len = ss->value_len;
    ss->value = NULL;
    ss->value_len = 0;
    retval = 0;

cleanup:
    return retval;
}

static int
process_file(
        FILE *log_f,
        FILE *prg_f,
        FILE *txt_f,
        FILE *dep_f,
        ProcessorState *ps,
        const unsigned char *path,
        TypeContext *cntx,
        IdScope *global_scope,
        const unsigned char *file_text);

static int
handle_directive_include(
        ScannerState *ss,
        FILE *log_f,
        FILE *prg_f,
        FILE *txt_f,
        FILE *dep_f,
        TypeContext *cntx,
        IdScope *global_scope)
{
    int retval = -1;
    const unsigned char *path = NULL;
    ProcessorState *ps = ss->ps;

    next_token(ss);
    if (ss->token != TOK_STRING) {
        parser_error(ss, "file name expected");
        goto cleanup;
    }
    if (strlen(ss->value) != ss->value_len) {
        parser_error(ss, "invalid file name");
        goto cleanup;
    }
    path = ss->value;

    if (dep_f) {
        fprintf(dep_f, " %s", path);
    }

    Position saved_pos = ps->pos;
    process_file(log_f, prg_f, txt_f, dep_f, ss->ps, path, cntx, global_scope, NULL);
    ps->pos = saved_pos;

cleanup:
    retval = 0;
    return retval;
}

static int
handle_directive_expand(
        ScannerState *ss,
        FILE *log_f,
        FILE *prg_f,
        FILE *txt_f,
        FILE *dep_f,
        TypeContext *cntx,
        IdScope *global_scope)
{
    int retval = -1;
    ProcessorState *ps = ss->ps;
    TypeInfo *name = NULL;
    int arg_a = 0, arg_u = 0;
    unsigned char **args = NULL;
    int i;
    char *exp_s = NULL;
    size_t exp_z = 0;
    FILE *exp_f = NULL;
    const unsigned char *body = NULL;
    unsigned char path[1024];

    next_token(ss);
    if (ss->token != TOK_IDENT) {
        parser_error(ss, "identifier expected");
        goto cleanup;
    }
    snprintf(path, sizeof(path), "%s", ss->raw);
    if (!(name = tc_get_ident(cntx, ss->raw))) {
        parser_error(ss, "identifier expected");
        goto cleanup;
    }
    for (i = 0; i < ss->ps->macros.u; ++i) {
        if (ss->ps->macros.v[i].name == name)
            break;
    }
    if (i >= ss->ps->macros.u) {
        parser_error(ss, "macro undefined");
        goto cleanup;
    }
    while (1) {
        next_token(ss);
        if (ss->token == TOK_EOF) break;
        if (ss->token != TOK_STRING) {
            parser_error(ss, "identifier expected");
            goto cleanup;
        }
        if (arg_u == arg_a) {
            if (!(arg_a *= 2)) arg_a = 32;
            XREALLOC(args, arg_a);
        }
        args[arg_u] = ss->value;
        ss->value = NULL; ss->value_len = 0;
        ++arg_u;
    }
    if (arg_u > 9) {
        parser_error(ss, "too many args");
        goto cleanup;
    }

    exp_f = open_memstream(&exp_s, &exp_z);
    body = ss->ps->macros.v[i].body;
    if (body) {
        while (*body) {
            int n;
            if (*body == '@' && (body[1] >= '1' && body[1] <= '9') && (n = body[1] - '1') < arg_u) {
                fputs(args[n], exp_f);
                body += 2;
            } else {
                putc(*body++, exp_f);
            }
        }
    }
    fclose(exp_f); exp_f = NULL;

    if (exp_z > 0) {
        Position saved_pos = ps->pos;
        process_file(log_f, prg_f, txt_f, dep_f, ss->ps, path, cntx, global_scope, exp_s);
        ps->pos = saved_pos;
    }

cleanup:
    for (i = 0; i < arg_u; ++i) {
        xfree(args[i]);
    }
    xfree(args);
    if (exp_f) fclose(exp_f);
    xfree(exp_s);
    retval = 0;
    return retval;
}

static int
handle_directive(
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *out_f,
        FILE *txt_f,
        FILE *log_f,
        FILE *dep_f,
        const unsigned char *str,
        int len,
        Position pos,
        IdScope *global_scope)
{
    ScannerState *ss = init_scanner(ps, log_f, str, len, pos, cntx);
    int retval = -1;

    next_token(ss); //dump_token(ss);

    if (ss->token != TOK_IDENT) {
        parser_error(ss, "directive expected");
    } else if (!strcmp(ss->value, "function")) {
        handle_directive_function(ss, cntx, out_f);
    } else if (!strcmp(ss->value, "page")) {
        handle_directive_page(ss, cntx, out_f);
    } else if (!strcmp(ss->value, "set")) {
        handle_directive_set(ss, cntx, out_f);
    } else if (!strcmp(ss->value, "include")) {
        handle_directive_include(ss, log_f, out_f, txt_f, dep_f, cntx, global_scope);
    } else if (!strcmp(ss->value, "define")) {
        handle_directive_define(ss, cntx, out_f);
    } else if (!strcmp(ss->value, "expand")) {
        handle_directive_expand(ss, log_f, out_f, txt_f, dep_f, cntx, global_scope);
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

            fprintf(txt_f, "static const __attribute__((unused)) unsigned char csp_str%d[%d] = ", i, len + 1);
            emit_str_literal(txt_f, mem + start_idx, len);
            fprintf(txt_f, ";\n");
        }

        fprintf(out_f, "fwrite_unlocked(csp_str%d, 1, %d, out_f);\n", i, len);
    }
    return 0;
}

static int
handle_html_string(FILE *out_f, FILE *txt_f, FILE *log_f, const unsigned char *str)
{
    return handle_html_text(out_f, txt_f, log_f, str, 0, strlen(str));
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
    if (!at) {
        at = html_element_find_attribute(elem, "action");
        if (!at) return 0;
        snprintf(buf, bufsize, "%s", at->value);
        return 1;
    }

    TypeInfo *ac_prefix = processor_state_find_setting(ps, tc_get_ident(cntx, "ac_prefix"));
    if (!ac_prefix) {
        parser_error_2(ps, "'ac_prefix' global parameter is undefined");
        return -1;
    }
    if (ac_prefix->kind != NODE_STRING) {
        parser_error_2(ps, "'ac_prefix' global parameter must be of type 'STRING'");
        return -1;
    }
    int at_len = strlen(at->value);
    if (at_len >= 2 &&
        ((at->value[0] == '\'' && at->value[at_len - 1] == '\'')
         || (at->value[0] == '"' && at->value[at_len - 1] == '"'))) {
        snprintf(buf, bufsize, "\"%.*s\"", at_len - 2, at->value + 1);
        return 1;
    }
    snprintf(buf, bufsize, "%s%s", ac_prefix->s.str, at->value);
    int len = strlen(buf);
    for (int i = 0; i < len; ++i) {
        if (buf[i] == '-') buf[i] = '_';
        buf[i] = toupper(buf[i]);
    }
    return 1;
}

static const unsigned char *
process_err_attr(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        unsigned char *buf,
        int bufsize,
        const unsigned char *err_name)
{
    if (!err_name) err_name = "inv-param";
    const unsigned char *err_prefix = "";
    TypeInfo *err_prefix_attr = processor_state_find_setting(ps, tc_get_ident(cntx, "err_prefix"));
    if (err_prefix_attr && err_prefix_attr->kind == NODE_STRING) {
        err_prefix = err_prefix_attr->s.str;
    }
    snprintf(buf, bufsize, "%s%s", err_prefix, err_name);
    int len = strlen(buf);
    for (int i = 0; i < len; ++i) {
        if (buf[i] == '-') buf[i] = '_';
        buf[i] = toupper(buf[i]);
    }
    return buf;
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

    HtmlAttribute *script_attr = html_element_find_attribute(elem, "script");
    HtmlAttribute *class_attr = html_element_find_attribute(elem, "class");
    int nosid_flag = html_attribute_get_bool(html_element_find_attribute(elem, "nosid"), 0);
    HtmlAttribute *target_attr = html_element_find_attribute(elem, "target");
    HtmlAttribute *title_attr = html_element_find_attribute(elem, "title");

    HtmlAttribute *attr = html_element_find_attribute(elem, "url");
    if (attr) {
        HtmlElement *url_elem = processor_state_find_named_url(ps, tc_get_ident(cntx, attr->value));
        if (!url_elem) {
            parser_error_2(ps, "URL '%s' is undefined", attr->value);
            return -1;
        }
        script_attr = html_element_find_attribute(url_elem, "script");
        nosid_flag = html_attribute_get_bool(html_element_find_attribute(url_elem, "nosid"), 0);
        r = process_ac_attr(log_f, cntx, ps, url_elem, buf, sizeof(buf));
        if (r < 0) return r;
        if (!r) {
            parser_error_2(ps, "ac attribute is undefined");
            return -1;
        }
        char *str_p = 0;
        size_t str_z = 0;
        FILE *str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "<a");
        if (class_attr) {
            fprintf(str_f, " class=\"%s\"", class_attr->value);
        }
        if (target_attr) {
            fprintf(str_f, " target=\"%s\"", target_attr->value);
        }
        if (title_attr) {
            fprintf(str_f, " title=\"%s\"", title_attr->value);
        }
        fprintf(str_f, " href=\"");
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        if (script_attr) {
            fprintf(prg_f, "hr_%s_url(out_f, phr);\n", script_attr->value);
            if (nosid_flag) {
                fprintf(prg_f, "sep = hr_url_4(out_f, phr, %s);\n", buf);
            } else {
                if (buf[0] == '\"') {
                    fprintf(prg_f, "sep = hr_url_5(out_f, phr, %s);\n", buf);
                } else {
                    fprintf(prg_f, "sep = hr_url_3(out_f, phr, %s);\n", buf);
                }
            }
        } else {
            fprintf(prg_f, "sep = hr_url_2(out_f, phr, %s);\n", buf);
        }
        for (HtmlElement *child = url_elem->first_child; child; child = child->next_sibling) {
            HtmlAttribute *full_check_expr = html_element_find_attribute(child, "fullcheckexpr");
            HtmlAttribute *check_expr = html_element_find_attribute(child, "checkexpr");
            HtmlAttribute *name_attr = html_element_find_attribute(child, "name");
            HtmlAttribute *value_attr = html_element_find_attribute(child, "value");
            if (name_attr && !value_attr) {
                value_attr = name_attr;
            }
            if (check_expr && value_attr) {
                fprintf(prg_f, "if ((%s)%s) {\n", value_attr->value, check_expr->value);
            }
            if (full_check_expr) {
                fprintf(prg_f, "if (%s) {\n", full_check_expr->value);
            }
            fprintf(prg_f, "fputs(sep, out_f); sep = \"&amp;\";\n");
            if (name_attr) {
                str_p = 0;
                str_z = 0;
                str_f = open_memstream(&str_p, &str_z);
                fprintf(str_f, "%s=", name_attr->value);
                fclose(str_f); str_f = 0;
                handle_html_string(prg_f, txt_f, log_f, str_p);
                free(str_p); str_p = 0; str_z = 0;
                if (value_attr) {
                    TypeInfo *t = NULL;
                    r = parse_c_expression(ps, cntx, log_f, value_attr->value, &t, ps->pos);
                    if (r >= 0) {
                        /*
                        fprintf(log_f, "Expression type: ");
                        tc_print_2(log_f, t, 2);
                        fprintf(log_f, "\n");
                        */

                        processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, value_attr->value, child, t);
                    }
                }
            }
            if (full_check_expr) {
                fprintf(prg_f, "}\n");
            }
            if (check_expr && value_attr) {
                fprintf(prg_f, "}\n");
            }
        }
        fprintf(prg_f, "(void) sep;\n");
        handle_html_string(prg_f, txt_f, log_f, "\">");

        return 0;
    }

    r = process_ac_attr(log_f, cntx, ps, elem, buf, sizeof(buf));
    if (r < 0) return r;
    if (r > 0) {
        char *str_p = 0;
        size_t str_z = 0;
        FILE *str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "<a");
        if (class_attr) {
            fprintf(str_f, " class=\"%s\"", class_attr->value);
        }
        if (target_attr) {
            fprintf(str_f, " target=\"%s\"", target_attr->value);
        }
        if (title_attr) {
            fprintf(str_f, " title=\"%s\"", title_attr->value);
        }
        fprintf(str_f, " href=\"");
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        if (script_attr) {
            fprintf(prg_f, "hr_%s_url(out_f, phr);\n", script_attr->value);
            if (nosid_flag) {
                fprintf(prg_f, "sep = hr_url_4(out_f, phr, %s);\n", buf);
            } else {
                fprintf(prg_f, "sep = hr_url_3(out_f, phr, %s);\n", buf);
            }
        } else {
            fprintf(prg_f, "sep = hr_url_2(out_f, phr, %s);\n", buf);
        }
        handle_html_string(prg_f, txt_f, log_f, "\">");
        //fprintf(prg_f, "fputs(ns_aref(hbuf, sizeof(hbuf), phr, %s, 0), out_f);\n", buf);
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
    handle_html_string(prg_f, txt_f, log_f, "</a>");
    return 0;
}

static int
handle_redirect_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    unsigned char buf[1024];
    int r;

    HtmlAttribute *script_attr = html_element_find_attribute(elem, "script");
    int nosid_flag = html_attribute_get_bool(html_element_find_attribute(elem, "nosid"), 0);

    fprintf(prg_f, "{\n"
            "char *red_p = 0;\n"
            "size_t red_z = 0;\n"
            "FILE *sav_f = out_f;\n"
            "out_f = open_memstream(&red_p, &red_z);\n");

    HtmlAttribute *attr = html_element_find_attribute(elem, "url");
    if (attr) {
        HtmlElement *url_elem = processor_state_find_named_url(ps, tc_get_ident(cntx, attr->value));
        if (!url_elem) {
            parser_error_2(ps, "URL '%s' is undefined", attr->value);
            return -1;
        }
        script_attr = html_element_find_attribute(url_elem, "script");
        nosid_flag = html_attribute_get_bool(html_element_find_attribute(url_elem, "nosid"), 0);
        r = process_ac_attr(log_f, cntx, ps, url_elem, buf, sizeof(buf));
        if (r < 0) return r;
        if (!r) {
            parser_error_2(ps, "ac attribute is undefined");
            return -1;
        }

        if (script_attr) {
            fprintf(prg_f, "hr_%s_redirect(out_f, phr);\n", script_attr->value);
            if (nosid_flag) {
                fprintf(prg_f, "sep = hr_redirect_4(out_f, phr, %s);\n", buf);
            } else {
                if (buf[0] == '\"') {
                    fprintf(prg_f, "sep = hr_redirect_5(out_f, phr, %s);\n", buf);
                } else {
                    fprintf(prg_f, "sep = hr_redirect_3(out_f, phr, %s);\n", buf);
                }
            }
        } else {
            fprintf(prg_f, "sep = hr_redirect_2(out_f, phr, %s);\n", buf);
        }
        for (HtmlElement *child = url_elem->first_child; child; child = child->next_sibling) {
            HtmlAttribute *full_check_expr = html_element_find_attribute(child, "fullcheckexpr");
            if (full_check_expr) {
                fprintf(prg_f, "if (%s) {\n", full_check_expr->value);
            }
            fprintf(prg_f, "fputs(sep, out_f); sep = \"&\";\n");
            attr = html_element_find_attribute(child, "name");
            if (attr) {
                char *str_p = 0;
                size_t str_z = 0;
                FILE *str_f = open_memstream(&str_p, &str_z);
                fprintf(str_f, "%s=", attr->value);
                fclose(str_f); str_f = 0;
                handle_html_string(prg_f, txt_f, log_f, str_p);
                free(str_p); str_p = 0; str_z = 0;
                attr = html_element_find_attribute(child, "value");
                if (attr) {
                    TypeInfo *t = NULL;
                    r = parse_c_expression(ps, cntx, log_f, attr->value, &t, ps->pos);
                    if (r >= 0) {
                        /*
                        fprintf(log_f, "Expression type: ");
                        tc_print_2(log_f, t, 2);
                        fprintf(log_f, "\n");
                        */

                        processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, attr->value, child, t);
                    }
                }
            }
            if (full_check_expr) {
                fprintf(prg_f, "}\n");
            }
        }
        fprintf(prg_f, "(void) sep;\n");
        fprintf(prg_f, "fclose(out_f);\n"
                "out_f = sav_f;\n"
                "phr->redirect = red_p;\n"
                "red_p = 0; red_z = 0;\n"
                "}\n");

        return 0;
    }

    r = process_ac_attr(log_f, cntx, ps, elem, buf, sizeof(buf));
    if (r < 0) return r;
    if (r > 0) {
        if (script_attr) {
            fprintf(prg_f, "hr_%s_redirect(out_f, phr);\n", script_attr->value);
            if (nosid_flag) {
                fprintf(prg_f, "sep = hr_redirect_4(out_f, phr, %s);\n", buf);
            } else {
                if (buf[0] == '\"') {
                    fprintf(prg_f, "sep = hr_redirect_5(out_f, phr, %s);\n", buf);
                } else {
                    fprintf(prg_f, "sep = hr_redirect_3(out_f, phr, %s);\n", buf);
                }
            }
        } else {
            fprintf(prg_f, "sep = hr_redirect_2(out_f, phr, %s);\n", buf);
        }
        fprintf(prg_f, "fclose(out_f);\n"
                "out_f = sav_f;\n"
                "phr->redirect = red_p;\n"
                "red_p = 0; red_z = 0;\n"
                "}\n");
    }
    return 0;
}

static int
handle_th_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = open_memstream(&str_p, &str_z);
    fprintf(str_f, "<th");

    HtmlAttribute *valign_attr = html_element_find_attribute(elem, "valign");
    if (valign_attr) {
        fprintf(str_f, " valign=\"%s\"", valign_attr->value);
    }
    HtmlAttribute *onclickexpr_attr = html_element_find_attribute(elem, "onclickexpr");
    if (onclickexpr_attr) {
        fprintf(str_f, " onclick=\"");
        fclose(str_f); str_f = NULL;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = NULL; str_z = 0;
        TypeInfo *t = NULL;
        int r = parse_c_expression(ps, cntx, log_f, onclickexpr_attr->value, &t, ps->pos);
        if (r >= 0) {
            processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, onclickexpr_attr->value, elem, t);
        }
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "\"");
    }
    HtmlAttribute *onclick_attr = html_element_find_attribute(elem, "onclick");
    if (onclick_attr) {
        fprintf(str_f, " onclick=\"%s\"", onclick_attr->value);
    }
    HtmlAttribute *id_attr = html_element_find_attribute(elem, "id");
    HtmlAttribute *idsuffix_attr = html_element_find_attribute(elem, "idsuffix");
    if (id_attr && idsuffix_attr) {
        fprintf(str_f, " id=\"%s", id_attr->value);
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        TypeInfo *t = NULL;
        int r = parse_c_expression(ps, cntx, log_f, idsuffix_attr->value, &t, ps->pos);
        if (r >= 0) {
            processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, idsuffix_attr->value, elem, t);
        }
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "\"");
    } else if (id_attr) {
        fprintf(str_f, " id=\"%s\"", id_attr->value);
    }

    HtmlAttribute *hiddenexpr_attr = html_element_find_attribute(elem, "hiddenexpr");
    if (hiddenexpr_attr) {
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        fprintf(prg_f, "if (%s) {\n", hiddenexpr_attr->value);
        handle_html_string(prg_f, txt_f, log_f, " style=\"display: none;\"");
        fprintf(prg_f, "}\n");
        str_f = open_memstream(&str_p, &str_z);
    }

    HtmlAttribute *attr_attr = html_element_find_attribute(elem, "attr");
    if (attr_attr) {
        fprintf(str_f, " ");
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        fprintf(prg_f, "fputs(%s, out_f);\n", attr_attr->value);
        handle_html_string(prg_f, txt_f, log_f, ">");
    } else {
        fprintf(str_f, ">");
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
    }

    return 0;
}

static int
handle_th_close(
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
    handle_html_string(prg_f, txt_f, log_f, "</th>");
    return 0;
}

static int
handle_td_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = open_memstream(&str_p, &str_z);
    fprintf(str_f, "<td");

    HtmlAttribute *valign_attr = html_element_find_attribute(elem, "valign");
    if (valign_attr) {
        fprintf(str_f, " valign=\"%s\"", valign_attr->value);
    }
    HtmlAttribute *onclickexpr_attr = html_element_find_attribute(elem, "onclickexpr");
    if (onclickexpr_attr) {
        fprintf(str_f, " onclick=\"");
        fclose(str_f); str_f = NULL;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = NULL; str_z = 0;
        TypeInfo *t = NULL;
        int r = parse_c_expression(ps, cntx, log_f, onclickexpr_attr->value, &t, ps->pos);
        if (r >= 0) {
            processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, onclickexpr_attr->value, elem, t);
        }
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "\"");
    }
    HtmlAttribute *onclick_attr = html_element_find_attribute(elem, "onclick");
    if (onclick_attr) {
        fprintf(str_f, " onclick=\"%s\"", onclick_attr->value);
    }
    HtmlAttribute *id_attr = html_element_find_attribute(elem, "id");
    HtmlAttribute *idsuffix_attr = html_element_find_attribute(elem, "idsuffix");
    if (id_attr && idsuffix_attr) {
        fprintf(str_f, " id=\"%s", id_attr->value);
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        TypeInfo *t = NULL;
        int r = parse_c_expression(ps, cntx, log_f, idsuffix_attr->value, &t, ps->pos);
        if (r >= 0) {
            processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, idsuffix_attr->value, elem, t);
        }
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "\"");
    } else if (id_attr) {
        fprintf(str_f, " id=\"%s\"", id_attr->value);
    }

    HtmlAttribute *hiddenexpr_attr = html_element_find_attribute(elem, "hiddenexpr");
    if (hiddenexpr_attr) {
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        fprintf(prg_f, "if (%s) {\n", hiddenexpr_attr->value);
        handle_html_string(prg_f, txt_f, log_f, " style=\"display: none;\"");
        fprintf(prg_f, "}\n");
        str_f = open_memstream(&str_p, &str_z);
    }

    HtmlAttribute *attr_attr = html_element_find_attribute(elem, "attr");
    if (attr_attr) {
        fprintf(str_f, " ");
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        fprintf(prg_f, "fputs(%s, out_f);\n", attr_attr->value);
        handle_html_string(prg_f, txt_f, log_f, ">");
    } else {
        fprintf(str_f, ">");
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
    }

    return 0;
}

static int
handle_td_close(
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
    handle_html_string(prg_f, txt_f, log_f, "</td>");
    return 0;
}

static int
handle_tr_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = open_memstream(&str_p, &str_z);
    fprintf(str_f, "<tr");

    HtmlAttribute *valign_attr = html_element_find_attribute(elem, "valign");
    if (valign_attr) {
        fprintf(str_f, " valign=\"%s\"", valign_attr->value);
    }
    HtmlAttribute *onclickexpr_attr = html_element_find_attribute(elem, "onclickexpr");
    if (onclickexpr_attr) {
        fprintf(str_f, " onclick=\"");
        fclose(str_f); str_f = NULL;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = NULL; str_z = 0;
        TypeInfo *t = NULL;
        int r = parse_c_expression(ps, cntx, log_f, onclickexpr_attr->value, &t, ps->pos);
        if (r >= 0) {
            processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, onclickexpr_attr->value, elem, t);
        }
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "\"");
    }
    HtmlAttribute *onclick_attr = html_element_find_attribute(elem, "onclick");
    if (onclick_attr) {
        fprintf(str_f, " onclick=\"%s\"", onclick_attr->value);
    }
    HtmlAttribute *id_attr = html_element_find_attribute(elem, "id");
    HtmlAttribute *idsuffix_attr = html_element_find_attribute(elem, "idsuffix");
    if (id_attr && idsuffix_attr) {
        fprintf(str_f, " id=\"%s", id_attr->value);
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        TypeInfo *t = NULL;
        int r = parse_c_expression(ps, cntx, log_f, idsuffix_attr->value, &t, ps->pos);
        if (r >= 0) {
            processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, idsuffix_attr->value, elem, t);
        }
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "\"");
    } else if (id_attr) {
        fprintf(str_f, " id=\"%s\"", id_attr->value);
    }

    HtmlAttribute *hiddenexpr_attr = html_element_find_attribute(elem, "hiddenexpr");
    if (hiddenexpr_attr) {
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        fprintf(prg_f, "if (%s) {\n", hiddenexpr_attr->value);
        handle_html_string(prg_f, txt_f, log_f, " style=\"display: none;\"");
        fprintf(prg_f, "}\n");
        str_f = open_memstream(&str_p, &str_z);
    }

    HtmlAttribute *attr_attr = html_element_find_attribute(elem, "attr");
    if (attr_attr) {
        fprintf(str_f, " ");
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        fprintf(prg_f, "fputs(%s, out_f);\n", attr_attr->value);
        handle_html_string(prg_f, txt_f, log_f, ">");
    } else {
        fprintf(str_f, ">");
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
    }

    return 0;
}

static int
handle_tr_close(
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
    handle_html_string(prg_f, txt_f, log_f, "</tr>");
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
    const unsigned char *onsubmit = NULL;

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
    if ((at = html_element_find_attribute(elem, "onsubmit"))) {
        onsubmit = at->value;
    }

    // FIXME: handle action, or ac
    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = open_memstream(&str_p, &str_z);
    fprintf(str_f, "<form method=\"%s\"", method);
    if (enctype && *enctype) {
        fprintf(str_f, " enctype=\"%s\"", enctype);
    }
    if (id && *id) {
        fprintf(str_f, " id=\"%s\"", id);
    }
    if (onsubmit && *onsubmit) {
        fprintf(str_f, " onsubmit=\"%s\"", onsubmit);
    }
    fprintf(str_f, " action=\"");
    fclose(str_f); str_f = 0;
    handle_html_string(prg_f, txt_f, log_f, str_p);
    free(str_p); str_p = 0; str_z = 0;
    fprintf(prg_f, "fputs(phr->self_url, out_f);\n");
    handle_html_string(prg_f, txt_f, log_f, "\">");

    fprintf(prg_f, "if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }\n");

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
    handle_html_string(prg_f, txt_f, log_f, "</form>");

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
    unsigned char label_buf[1024];
    const unsigned char *value = NULL;

    HtmlAttribute *name_attr = html_element_find_attribute(elem, "name");
    if (name_attr != NULL) {
        HtmlAttribute *value_attr = html_element_find_attribute(elem, "value");
        if (value_attr) {
            // interpret value?
        } else {
            value_attr = html_element_find_attribute(elem, "label");
            if (value_attr) {
                char *str_p = 0;
                size_t str_z = 0;
                FILE *str_f = open_memstream(&str_p, &str_z);
                fprintf(str_f, "<input type=\"submit\" name=\"%s\" value=\"", name_attr->value);
                fclose(str_f); str_f = 0;
                handle_html_string(prg_f, txt_f, log_f, str_p);
                free(str_p); str_p = 0; str_z = 0;
                fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", value_attr->value);
                handle_html_string(prg_f, txt_f, log_f, "\" />");
            } else {
                char *str_p = 0;
                size_t str_z = 0;
                FILE *str_f = open_memstream(&str_p, &str_z);
                fprintf(str_f, "<input type=\"submit\" name=\"%s\" />", name_attr->value);
                fclose(str_f); str_f = 0;
                handle_html_string(prg_f, txt_f, log_f, str_p);
                free(str_p); str_p = 0; str_z = 0;
            }
        }
        return 0;
    }

    HtmlAttribute *at = html_element_find_attribute(elem, "value");
    if (at) {
        value = at->value;
    } else {
        at = html_element_find_attribute(elem, "text");
        if (at) {
            snprintf(label_buf, sizeof(label_buf), "\"%s\"", at->value);
            value = label_buf;
        } else {
            at = html_element_find_attribute(elem, "label");
            if (at) {
                snprintf(label_buf, sizeof(label_buf), "_(\"%s\")", at->value);
                value = label_buf;
            } else {
                value = "NULL";
            }
        }
    }

    int r = process_ac_attr(log_f, cntx, ps, elem, buf, sizeof(buf));
    if (r < 0) return r;
    if (r > 0) {
        fprintf(prg_f, "hr_submit_button(out_f, 0, %s, %s);\n", buf, value);
    } else if ((at = html_element_find_attribute(elem, "action"))) {
        fprintf(prg_f, "hr_submit_button(out_f, 0, (%s), %s);\n", at->value, value);
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

    HtmlAttribute *full_check_attr = html_element_find_attribute(elem, "fullcheckexpr");
    if (full_check_attr) {
        fprintf(prg_f, "if (%s) {\n", full_check_attr->value);
    }

    HtmlAttribute *check_attr = html_element_find_attribute(elem, "checkexpr");
    if (check_attr) {
        fprintf(prg_f, "if ((%s) %s) {\n", at->value, check_attr->value);
    }

    HtmlAttribute *sep_attr = html_element_find_attribute(elem, "sep");
    if (sep_attr) {
        handle_html_string(prg_f, txt_f, log_f, sep_attr->value);
    }

    TypeInfo *t = NULL;

    HtmlAttribute *type_attr = html_element_find_attribute(elem, "type");
    if (type_attr != NULL) {
        // some pseudo-typedefs...
        if (!strcmp(type_attr->value, "uuid")) {
            t = tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_uuid_t"));
        } else if (!strcmp(type_attr->value, "eoln_type")) {
            t = tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_eoln_type_t"));
        } else if (!strcmp(type_attr->value, "run_status")) {
            t = tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_run_status_t"));
        } else if (!strcmp(type_attr->value, "mime_type")) {
            t = tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_mime_type_t"));
        } else if (!strcmp(type_attr->value, "sha1")) {
            t = tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_sha1_t"));
        } else if (!strcmp(type_attr->value, "duration")) {
            t = tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_duration_t"));
        } else if (!strcmp(type_attr->value, "brief_time")) {
            t = tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_brief_time_t"));
        } else if (!strcmp(type_attr->value, "jsbool")) {
            t = tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_jsbool_t"));
        }
    } else {
        int r = parse_c_expression(ps, cntx, log_f, at->value, &t, ps->pos);
        if (r < 0) return r;

        /*
        fprintf(log_f, "Expression type: ");
        tc_print_2(log_f, t, 2);
        fprintf(log_f, "\n");
        */
    }

    processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, at->value, elem, t);

    if (check_attr || full_check_attr) {
        HtmlAttribute *def_attr = html_element_find_attribute(elem, "defstr");
        if (def_attr) {
            fprintf(prg_f, "} else {\n"
                    "fputs(\"%s\", out_f);\n"
                    "}\n", def_attr->value);
        } else if ((def_attr = html_element_find_attribute(elem, "deflabel"))) {
            fprintf(prg_f, "} else {\n"
                    "fputs(_(\"%s\"), out_f);\n"
                    "}\n", def_attr->value);
        } else {
            fprintf(prg_f, "}\n");
        }
    }

    return 0;
}

static int
handle_indir_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    HtmlAttribute *at = html_element_find_attribute(elem, "value");
    if (!at) {
        parser_error_2(ps, "<s:indir> element requires value attribute");
        return -1;
    }

    ps->el_stack->extra = html_element_clone(elem);

    fprintf(prg_f,
            "putc_unlocked('<', out_f);\n"
            "fputs(%s, out_f);\n"
            "putc_unlocked('>', out_f);\n", at->value);

    return 0;
}

static int
handle_indir_close(
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

    HtmlElement *elem = ps->el_stack->extra;
    HtmlAttribute *at = html_element_find_attribute(elem, "value");

    fprintf(prg_f,
            "putc_unlocked('<', out_f);\n"
            "putc_unlocked('/', out_f);\n"
            "fputs(%s, out_f);\n"
            "putc_unlocked('>', out_f);\n", at->value);
    return 0;
}

static int
handle_vb_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    HtmlAttribute *at = html_element_find_attribute(elem, "value");
    if (!at) {
        parser_error_2(ps, "<s:vb> element requires value attribute");
        return -1;
    }

    fprintf(prg_f, "if ((%s)) { fputs(_(\"Yes\"), out_f); } else { fputs(_(\"No\"), out_f); }\n",
            at->value);

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
handle_copyright_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    if (!elem->no_body) {
        parser_error_2(ps, "<s:copyright> element must not have a body");
        return -1;
    }
    fprintf(prg_f, "write_copyright_short(out_f);\n");

    return 0;
}

static int
handle_config_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    if (!elem->no_body) {
        parser_error_2(ps, "<s:config> element must not have a body");
        return -1;
    }

    HtmlAttribute *at = html_element_find_attribute(elem, "name");
    if (!at) {
        parser_error_2(ps, "<s:config> element requires 'name' attribute");
        return -1;
    }
    const unsigned char *value = NULL;
    if (!strcmp(at->value, "charset")) {
        value = EJUDGE_CHARSET;
    } else if (!strcmp(at->value, "style-prefix")) {
        value = CONF_STYLE_PREFIX;
    }
    if (value) {
        fprintf(prg_f, "fwrite_unlocked(\"%s\", 1, %zu, out_f);\n", value, strlen(value));
    }

    return 0;
}

static int
handle_textfield_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    if (!elem->no_body) {
        parser_error_2(ps, "<s:textfield> element must not have a body");
        return -1;
    }

    // supported attributes: name, value, size, escape (for string values), check, checkExpr
    HtmlAttribute *name_attr = html_element_find_attribute(elem, "name");
    if (!name_attr) {
        parser_error_2(ps, "<s:textfield> element requires 'name' attribute");
        return -1;
    }
    int skip_value = 0;
    unsigned char ac_buf[1024];
    int has_ac = process_ac_attr(log_f, cntx, ps, elem, ac_buf, sizeof(ac_buf));
    HtmlAttribute *value_attr = html_element_find_attribute(elem, "value");
    TypeInfo *value_type = NULL;
    const unsigned char *expr = NULL;
    if (has_ac > 0) {
        expr = ac_buf;
        value_type = tc_get_i32_type(cntx);
    } else if (!value_attr) {
        expr = name_attr->value;
        parse_c_expression(ps, cntx, log_f, name_attr->value, &value_type, ps->pos); // return value is ignored!
        if (!value_type) {
            skip_value = 1;
        }
    } else {
        expr = value_attr->value;
        if (!value_attr->value || !value_attr->value[0]) {
            skip_value = 1;
        } else {
            parse_c_expression(ps, cntx, log_f, value_attr->value, &value_type, ps->pos); // return value is ignored!
        }
    }

    const unsigned char *input_type = "text";
    if (!strcmp(elem->name, "s:password")) {
        input_type = "password";
    } else if (!strcmp(elem->name, "s:hidden")) {
        input_type = "hidden";
    } else if (!strcmp(elem->name, "s:radio")) {
        input_type = "radio";
    }

    /*
    if (html_element_find_attribute(elem, "disabled")) {
        parser_error_2(ps, "use disabledExpr instead of disabled");
        return -1;
    }
    */

    HtmlAttribute *disabled_attr = html_element_find_attribute(elem, "disabledexpr");

    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = open_memstream(&str_p, &str_z);
    fprintf(str_f, "<input type=\"%s\" name=\"%s\"", input_type, name_attr->value);
    HtmlAttribute *size_attr = html_element_find_attribute(elem, "size");
    if (size_attr) {
        fprintf(str_f, " size=\"%s\"", size_attr->value);
    }
    HtmlAttribute *maxlength_attr = html_element_find_attribute(elem, "maxlength");
    if (maxlength_attr) {
        fprintf(str_f, " maxlength=\"%s\"", maxlength_attr->value);
    }
    HtmlAttribute *disabled2_attr = html_element_find_attribute(elem, "disabled");
    if (disabled2_attr) {
        fprintf(str_f, " disabled=\"%s\"", disabled2_attr->value);
    }
    HtmlAttribute *readonly_attr = html_element_find_attribute(elem, "readonly");
    if (readonly_attr) {
        fprintf(str_f, " readonly=\"%s\"", readonly_attr->value);
    }
    HtmlAttribute *onclick_attr = html_element_find_attribute(elem, "onclick");
    if (onclick_attr) {
        fprintf(str_f, " onclick=\"%s\"", onclick_attr->value);
    }
    HtmlAttribute *onchange_attr = html_element_find_attribute(elem, "onchange");
    if (onchange_attr) {
        fprintf(str_f, " onchange=\"%s\"", onchange_attr->value);
    }
    HtmlAttribute *class_attr = html_element_find_attribute(elem, "class");
    if (class_attr) {
        fprintf(str_f, " class=\"%s\"", class_attr->value);
    }
    HtmlAttribute *id_attr = html_element_find_attribute(elem, "id");
    HtmlAttribute *idsuffix_attr = html_element_find_attribute(elem, "idsuffix");
    if (id_attr && idsuffix_attr) {
        fprintf(str_f, " id=\"%s", id_attr->value);
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        TypeInfo *t = NULL;
        int r = parse_c_expression(ps, cntx, log_f, idsuffix_attr->value, &t, ps->pos);
        if (r >= 0) {
            processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, idsuffix_attr->value, elem, t);
        }
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "\"");
    } else if (id_attr) {
        fprintf(str_f, " id=\"%s\"", id_attr->value);
    }
    if (skip_value) {
        if (disabled_attr) {
            fclose(str_f); str_f = 0;
            handle_html_string(prg_f, txt_f, log_f, str_p);
            free(str_p); str_p = 0; str_z = 0;
            fprintf(prg_f, "if (%s) {\n", disabled_attr->value);
            handle_html_string(prg_f, txt_f, log_f, " disabled=\"disabled\"");
            fprintf(prg_f, "}\n");
            handle_html_string(prg_f, txt_f, log_f, " />");
        } else {
            fprintf(str_f, " />");
            fclose(str_f); str_f = 0;
            handle_html_string(prg_f, txt_f, log_f, str_p);
            free(str_p); str_p = 0; str_z = 0;
        }
        return 0;
    }
    fclose(str_f); str_f = 0;
    handle_html_string(prg_f, txt_f, log_f, str_p);
    free(str_p); str_p = 0; str_z = 0;
    if (disabled_attr) {
        fprintf(prg_f, "if (%s) {\n", disabled_attr->value);
        handle_html_string(prg_f, txt_f, log_f, " disabled=\"disabled\"");
        fprintf(prg_f, "}\n");
    }

    int need_check = html_attribute_get_bool(html_element_find_attribute(elem, "check"), 1);
    if (has_ac > 0) need_check = 0;
    if (need_check) {
        HtmlAttribute *full_check_expr_attr = html_element_find_attribute(elem, "fullcheckexpr");
        if (full_check_expr_attr) {
            fprintf(prg_f, "if (%s) {\n", full_check_expr_attr->value);
        } else {
            HtmlAttribute *check_expr_attr = html_element_find_attribute(elem, "checkexpr");
            fprintf(prg_f, "if ((%s)", expr);
            if (check_expr_attr) {
                fprintf(prg_f, " %s", check_expr_attr->value);
            }
            fprintf(prg_f, ") {\n");
        }
    }
    handle_html_string(prg_f, txt_f, log_f, " value=\"");
    processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, expr, elem, value_type);
    handle_html_string(prg_f, txt_f, log_f, "\"");
    if (need_check) {
        fprintf(prg_f, "}\n");
    }
    handle_html_string(prg_f, txt_f, log_f, " />");
    int need_notset = html_attribute_get_bool(html_element_find_attribute(elem, "notset"), 0);
    if (need_notset) {
        fprintf(prg_f, "if (!(%s)) { ", expr);
        handle_html_string(prg_f, txt_f, log_f, "(<i>Not set</i>)");
        fprintf(prg_f, " }\n");
    }
    return 0;
}

static int
handle_checkbox_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    TypeInfo *value_type = NULL;

    HtmlAttribute *onchange_attr = html_element_find_attribute(elem, "onchange");
    HtmlAttribute *name_serial_attr = html_element_find_attribute(elem, "nameserial");
    if (name_serial_attr) {
        // <s:checkbox nameSerial="var" namePrefix="prefix" value="VALUE" checkedExpr="CHECKED-EXPR" disabledExpr="DISABLED-EXPR" />
        const unsigned char *name_prefix_str = "field_";
        HtmlAttribute *name_prefix_attr = html_element_find_attribute(elem, "nameprefix");
        if (name_prefix_attr) {
            name_prefix_str = name_prefix_attr->value;
        }
        HtmlAttribute *value_attr = html_element_find_attribute(elem, "value");
        const unsigned char *value_str = "1";
        if (value_attr) {
            value_str = value_attr->value;
        }
        char *str_p = 0;
        size_t str_z = 0;
        FILE *str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "<input type=\"checkbox\" name=\"%s", name_prefix_str);
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
        parse_c_expression(ps, cntx, log_f, name_serial_attr->value, &value_type, ps->pos);
        processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, name_serial_attr->value, elem, value_type);
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "\" value=\"%s\"", value_str);
        if (onchange_attr) {
            fprintf(str_f, " onchange=\"%s\"", onchange_attr->value);
        }
        fclose(str_f); str_f = NULL;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = NULL; str_z = 0;
    } else {
        // <s:checkbox name="NAME" value="VALUE" checkedExpr="CHECKED-EXPR" disabledExpr="DISABLED-EXPR" />
        HtmlAttribute *name_attr = html_element_find_attribute(elem, "name");
        if (!name_attr) {
            parser_error_2(ps, "<s:checkbox> element requires 'name' attribute");
            return -1;
        }
        HtmlAttribute *value_attr = html_element_find_attribute(elem, "value");
        const unsigned char *value_str = "1";
        if (value_attr) {
            value_str = value_attr->value;
        }

        char *str_p = 0;
        size_t str_z = 0;
        FILE *str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "<input type=\"checkbox\" name=\"%s\" value=\"%s\"", name_attr->value, value_str);
        if (onchange_attr) {
            fprintf(str_f, " onchange=\"%s\"", onchange_attr->value);
        }
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
    }

    HtmlAttribute *checked_attr = html_element_find_attribute(elem, "checkedexpr");
    if (checked_attr) {
        fprintf(prg_f, "if (%s) {\n", checked_attr->value);
        handle_html_string(prg_f, txt_f, log_f, " checked=\"checked\"");
        fprintf(prg_f, "}\n");
    }
    HtmlAttribute *disabled_attr = html_element_find_attribute(elem, "disabledexpr");
    if (disabled_attr) {
        fprintf(prg_f, "if (%s) {\n", disabled_attr->value);
        handle_html_string(prg_f, txt_f, log_f, " disabled=\"disabled\"");
        fprintf(prg_f, "}\n");
    }
    handle_html_string(prg_f, txt_f, log_f, " />");

    return 0;
}

static int
handle_gettext_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    fprintf(prg_f, "fputs(_(");
    return 0;
}

static int
handle_gettext_close(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        unsigned char *mem,
        int beg_i,
        int end_i)
{
    emit_str_literal(prg_f, mem + beg_i, end_i - beg_i);
    fprintf(prg_f, "), out_f);\n");
    return 0;
}

static int
handle_option_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    handle_html_string(prg_f, txt_f, log_f, "<option");

    HtmlAttribute *selected_attr = html_element_find_attribute(elem, "selectedexpr");
    if (selected_attr) {
        fprintf(prg_f, "if (%s) {\n", selected_attr->value);
        handle_html_string(prg_f, txt_f, log_f, " selected=\"selected\"");
        fprintf(prg_f, "}\n");
    }
    HtmlAttribute *value_attr = html_element_find_attribute(elem, "value");
    TypeInfo *value_type = NULL;
    if (value_attr) {
        handle_html_string(prg_f, txt_f, log_f, " value=\"");
        parse_c_expression(ps, cntx, log_f, value_attr->value, &value_type, ps->pos);
        processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, value_attr->value, elem, value_type);
        handle_html_string(prg_f, txt_f, log_f, "\"");
    }
    handle_html_string(prg_f, txt_f, log_f, ">");
    return 0;
}

static int
handle_option_close(
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
    handle_html_string(prg_f, txt_f, log_f, "</option>");
    return 0;
}

static int
handle_select_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    HtmlAttribute *name_attr = html_element_find_attribute(elem, "name");
    if (!name_attr) {
        parser_error_2(ps, "<s:select> element requires 'name' attribute");
        return -1;
    }
    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = open_memstream(&str_p, &str_z);
    fprintf(str_f, "<select name=\"%s\"", name_attr->value);
    fclose(str_f); str_f = 0;
    handle_html_string(prg_f, txt_f, log_f, str_p);
    free(str_p); str_p = 0; str_z = 0;

    HtmlAttribute *disabled_attr = html_element_find_attribute(elem, "disabledexpr");
    if (disabled_attr) {
        fprintf(prg_f, "if (%s) {\n", disabled_attr->value);
        handle_html_string(prg_f, txt_f, log_f, " disabled=\"disabled\"");
        fprintf(prg_f, "}\n");
    }
    handle_html_string(prg_f, txt_f, log_f, ">");
    return 0;
}

static int
handle_select_close(
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
    handle_html_string(prg_f, txt_f, log_f, "</select>");
    return 0;
}

static int
handle_yesno_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    HtmlAttribute *name_attr = html_element_find_attribute(elem, "name");
    if (!name_attr) {
        parser_error_2(ps, "<s:yesno> element requires 'name' attribute");
        return -1;
    }
    HtmlAttribute *value_attr = html_element_find_attribute(elem, "value");
    const unsigned char *no_label = "No";
    HtmlAttribute *no_attr = html_element_find_attribute(elem, "nolabel");
    if (no_attr) {
        no_label = no_attr->value;
    }
    const unsigned char *yes_label = "Yes";
    HtmlAttribute *yes_attr = html_element_find_attribute(elem, "yeslabel");
    if (yes_attr) {
        yes_label = yes_attr->value;
    }
    HtmlAttribute *id_attr = html_element_find_attribute(elem, "id");
    HtmlAttribute *idsuffix_attr = html_element_find_attribute(elem, "idsuffix");
    HtmlAttribute *disabled_attr = html_element_find_attribute(elem, "disabled");
    if (!disabled_attr) disabled_attr = html_element_find_attribute(elem, "readonly");

    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = NULL;

    if (disabled_attr) {
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "<input type=\"hidden\" name=\"%s\"", name_attr->value);
        if (id_attr && idsuffix_attr) {
            fprintf(str_f, " id=\"%s", id_attr->value);
            fclose(str_f); str_f = 0;
            handle_html_string(prg_f, txt_f, log_f, str_p);
            free(str_p); str_p = 0; str_z = 0;
            TypeInfo *t = NULL;
            int r = parse_c_expression(ps, cntx, log_f, idsuffix_attr->value, &t, ps->pos);
            if (r >= 0) {
                processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, idsuffix_attr->value, elem, t);
            }
            str_f = open_memstream(&str_p, &str_z);
            fprintf(str_f, "\"");
        } else if (id_attr) {
            fprintf(str_f, " id=\"%s\"", id_attr->value);
        }
        fprintf(str_f, " value=\"");
        fclose(str_f); str_f = NULL;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = NULL; str_z = 0;
        fprintf(prg_f, "if ((%s)) {\n", value_attr->value);
        handle_html_string(prg_f, txt_f, log_f, "1\" /><b><font color=\"lightgreen\">");
        fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", yes_label);
        handle_html_string(prg_f, txt_f, log_f, "</font></b>");
        fprintf(prg_f, "} else {\n");
        handle_html_string(prg_f, txt_f, log_f, "0\" /><b>");
        fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", no_label);
        handle_html_string(prg_f, txt_f, log_f, "</b>");
        fprintf(prg_f, "}\n");
        return 0;
    }

    fprintf(prg_f,
            "{\n"
            "  unsigned char *s1 = \"\", *s2 = \"\";\n");
    if (value_attr) {
        fprintf(prg_f,
                "if ((%s)) { s2 = \" selected=\\\"selected\\\"\"; } else { s1 = \" selected=\\\"selected\\\"\"; }\n",
                value_attr->value);
    }

    str_f = open_memstream(&str_p, &str_z);
    fprintf(str_f, "<select");
    if (id_attr) {
        fprintf(str_f, " id=\"%s\"", id_attr->value);
    }
    if (disabled_attr) {
        fprintf(str_f, " disabled=\"%s\"", disabled_attr->value);
    }
    fprintf(str_f, " name=\"%s\"><option value=\"0\"", name_attr->value);
    fclose(str_f); str_f = 0;
    handle_html_string(prg_f, txt_f, log_f, str_p);
    free(str_p); str_p = 0; str_z = 0;
    fprintf(prg_f, "fputs(s1, out_f);\n");
    handle_html_string(prg_f, txt_f, log_f, ">");
    fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", no_label);
    handle_html_string(prg_f, txt_f, log_f, "</option><option value=\"1\"");
    fprintf(prg_f, "fputs(s2, out_f);\n");
    handle_html_string(prg_f, txt_f, log_f, ">");
    fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", yes_label);
    handle_html_string(prg_f, txt_f, log_f, "</option></select>");

    fprintf(prg_f,
            "}\n");
    return 0;
}

static int
handle_yesno3_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    HtmlAttribute *name_attr = html_element_find_attribute(elem, "name");
    if (!name_attr) {
        parser_error_2(ps, "<s:yesno3> element requires 'name' attribute");
        return -1;
    }
    HtmlAttribute *value_attr = html_element_find_attribute(elem, "value");
    if (value_attr) {
        fprintf(prg_f,
                "{\n"
                "  int yesno3_value = (int)(%s);\n", value_attr->value);
    } else {
        fprintf(prg_f,
                "{\n"
                "  int yesno3_value = -1;\n");
    }
    HtmlAttribute *default_attr = html_element_find_attribute(elem, "default");
    int defaultdefault_value = html_attribute_get_bool(html_element_find_attribute(elem, "defaultdefault"), 0);

    const unsigned char *no_label = "No";
    HtmlAttribute *no_attr = html_element_find_attribute(elem, "nolabel");
    if (no_attr) {
        no_label = no_attr->value;
    }
    const unsigned char *yes_label = "Yes";
    HtmlAttribute *yes_attr = html_element_find_attribute(elem, "yeslabel");
    if (yes_attr) {
        yes_label = yes_attr->value;
    }
    const unsigned char *default_label = "Default";
    HtmlAttribute *default_label_attr = html_element_find_attribute(elem, "deflabel");
    if (default_label_attr) {
        default_label = default_label_attr->value;
    }

    HtmlAttribute *id_attr = html_element_find_attribute(elem, "id");
    HtmlAttribute *disabled_attr = html_element_find_attribute(elem, "disabled");
    if (!disabled_attr) disabled_attr = html_element_find_attribute(elem, "readonly");

    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = NULL;

    if (disabled_attr) {
        str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, "<input type=\"hidden\" name=\"%s\"", name_attr->value);
        if (id_attr) {
            fprintf(str_f, " id=\"%s\"", id_attr->value);
        }
        fprintf(str_f, " value=\"");
        fclose(str_f); str_f = NULL;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = NULL; str_z = 0;
        fprintf(prg_f, "fprintf(out_f, \"%%d\", yesno3_value);\n");
        handle_html_string(prg_f, txt_f, log_f, "\" />");

        fprintf(prg_f, "  if (yesno3_value < 0) {\n");

        fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", default_label);
        handle_html_string(prg_f, txt_f, log_f, " (");
        if (!defaultdefault_value) {
            fprintf(prg_f, "  if ((%s) <= 0) {\n", default_attr->value);
        } else {
            fprintf(prg_f, "  if (!(%s)) {\n", default_attr->value);
        }
        fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", no_label);
        fprintf(prg_f, "} else {\n");
        fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", yes_label);
        fprintf(prg_f, "}\n");
        handle_html_string(prg_f, txt_f, log_f, ")");

        fprintf(prg_f, "  } else if (!yesno3_value) {\n");

        handle_html_string(prg_f, txt_f, log_f, "<b>");
        fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", no_label);
        handle_html_string(prg_f, txt_f, log_f, "</b>");


        fprintf(prg_f, "  } else {\n");

        handle_html_string(prg_f, txt_f, log_f, "<b><font color=\"lightgreen\">");
        fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", yes_label);
        handle_html_string(prg_f, txt_f, log_f, "</font></b>");

        fprintf(prg_f, "  }\n");

        fprintf(prg_f,
                "}\n");
        return 0;
    }


    str_f = open_memstream(&str_p, &str_z);
    fprintf(str_f, "<select");
    if (id_attr) {
        fprintf(str_f, " id=\"%s\"", id_attr->value);
    }
    fprintf(str_f, " name=\"%s\"><option value=\"-1\"", name_attr->value);
    fclose(str_f); str_f = 0;
    handle_html_string(prg_f, txt_f, log_f, str_p);
    free(str_p); str_p = 0; str_z = 0;
    fprintf(prg_f, "  if (yesno3_value < 0) {\n");
    handle_html_string(prg_f, txt_f, log_f, " selected=\"selected\"");
    fprintf(prg_f, "  }\n");
    handle_html_string(prg_f, txt_f, log_f, ">");
    fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", default_label);
    handle_html_string(prg_f, txt_f, log_f, " (");
    if (!defaultdefault_value) {
        fprintf(prg_f, "  if ((%s) <= 0) {\n", default_attr->value);
    } else {
        fprintf(prg_f, "  if (!(%s)) {\n", default_attr->value);
    }
    fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", no_label);
    fprintf(prg_f, "} else {\n");
    fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", yes_label);
    fprintf(prg_f, "}\n");
    handle_html_string(prg_f, txt_f, log_f, ")</option><option value=\"0\"");
    fprintf(prg_f, "  if (yesno3_value == 0) {\n");
    handle_html_string(prg_f, txt_f, log_f, " selected=\"selected\"");
    fprintf(prg_f, "  }\n");
    handle_html_string(prg_f, txt_f, log_f, ">");
    fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", no_label);
    handle_html_string(prg_f, txt_f, log_f, "</option><option value=\"1\"");
    fprintf(prg_f, "  if (yesno3_value > 0) {\n");
    handle_html_string(prg_f, txt_f, log_f, " selected=\"selected\"");
    fprintf(prg_f, "  }\n");
    handle_html_string(prg_f, txt_f, log_f, ">");
    fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", yes_label);
    handle_html_string(prg_f, txt_f, log_f, "</option></select>");

    fprintf(prg_f,
            "}\n");
    return 0;
}

static int
html_attr_parse_int(const HtmlAttribute *attr, int *p_value)
{
    if (!attr) return 0;
    char *endp = attr->value;
    while (isspace(*endp)) ++endp;
    if (!*endp) return 0;

    endp = 0;
    errno = 0;
    int res = strtol(attr->value, &endp, 10);
    if (errno || *endp) return -1;
    *p_value = res;
    return 1;
}

static int
handle_numselect_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    HtmlAttribute *name_attr = html_element_find_attribute(elem, "name");
    if (!name_attr) {
        parser_error_2(ps, "<s:numselect> element requires 'name' attribute");
        return -1;
    }
    HtmlAttribute *value_attr = html_element_find_attribute(elem, "value");

    int low_value = 0;
    HtmlAttribute *low_attr = html_element_find_attribute(elem, "lowvalue");
    if (html_attr_parse_int(low_attr, &low_value) < 0) {
        parser_error_2(ps, "<s:numselect> 'lowValue' attribute is invalid");
        return -1;
    }

    int high_value = 0;
    HtmlAttribute *high_attr = html_element_find_attribute(elem, "highvalue");
    if (!high_attr) {
        parser_error_2(ps, "<s:numselect> element requires 'highValue' attribute");
        return -1;
    }
    if (html_attr_parse_int(high_attr, &high_value) <= 0) {
        parser_error_2(ps, "<s:numselect> 'highValue' attribute is invalid");
        return -1;
    }
    if (low_value == high_value) {
        parser_error_2(ps, "<s:numselect> empty range");
        return -1;
    }

    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = open_memstream(&str_p, &str_z);
    fprintf(str_f,"<select name=\"%s\">\n", name_attr->value);
    fclose(str_f); str_f = 0;
    handle_html_string(prg_f, txt_f, log_f, str_p);
    free(str_p); str_p = 0; str_z = 0;

    if (low_value < high_value) {
        fprintf(prg_f, "for (int numsel_i = %d; numsel_i < %d; ++numsel_i) {\n", low_value, high_value);
    } else {
        fprintf(prg_f, "for (int numsel_i = %d; numsel_i > %d; --numsel_i) {\n", high_value, low_value);
    }

    fprintf(prg_f,
            "  fprintf(out_f, \"<option value=\\\"%%d\\\"\", numsel_i);\n");
    if (value_attr) {
        fprintf(prg_f, "  if (%s == numsel_i) {\n", value_attr->value);
        handle_html_string(prg_f, txt_f, log_f, " selected=\"selected\"");
        fprintf(prg_f, "}\n");
    }
    fprintf(prg_f,
            "  fprintf(out_f, \">%%d</option>\\n\", numsel_i);\n");
    fprintf(prg_f, "}\n");
    handle_html_string(prg_f, txt_f, log_f, "</select>");

    return 0;
}

static int
handle_button_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    handle_html_string(prg_f, txt_f, log_f, "<input type=\"button\"");

    HtmlAttribute *label_attr = html_element_find_attribute(elem, "label");
    if (label_attr) {
        handle_html_string(prg_f, txt_f, log_f, " value=\"");
        fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", label_attr->value);
        handle_html_string(prg_f, txt_f, log_f, "\"");
    }
    HtmlAttribute *onclick_attr = html_element_find_attribute(elem, "onclick");
    if (onclick_attr) {
        char *str_p = 0;
        size_t str_z = 0;
        FILE *str_f = open_memstream(&str_p, &str_z);
        fprintf(str_f, " onclick=\"%s\"", onclick_attr->value);
        fclose(str_f); str_f = 0;
        handle_html_string(prg_f, txt_f, log_f, str_p);
        free(str_p); str_p = 0; str_z = 0;
    }
    handle_html_string(prg_f, txt_f, log_f, " />");

    return 0;
}

static int
handle_img_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    unsigned char buf[1024];

    handle_html_string(prg_f, txt_f, log_f, "<img src=\"");

    // url, label
    HtmlAttribute *attr = html_element_find_attribute(elem, "url");
    if (attr) {
        HtmlElement *url_elem = processor_state_find_named_url(ps, tc_get_ident(cntx, attr->value));
        if (!url_elem) {
            parser_error_2(ps, "URL '%s' is undefined", attr->value);
            return -1;
        }
        int r = process_ac_attr(log_f, cntx, ps, url_elem, buf, sizeof(buf));
        if (r < 0) return r;
        if (!r) {
            parser_error_2(ps, "ac attribute is undefined");
            return -1;
        }
        fprintf(prg_f, "sep = hr_url_2(out_f, phr, %s);\n", buf);
        for (HtmlElement *child = url_elem->first_child; child; child = child->next_sibling) {
            fprintf(prg_f, "fputs(sep, out_f); sep = \"&amp;\";\n");
            attr = html_element_find_attribute(child, "name");
            if (attr) {
                char *str_p = 0;
                size_t str_z = 0;
                FILE *str_f = open_memstream(&str_p, &str_z);
                fprintf(str_f, "%s=", attr->value);
                fclose(str_f); str_f = 0;
                handle_html_string(prg_f, txt_f, log_f, str_p);
                free(str_p); str_p = 0; str_z = 0;
                attr = html_element_find_attribute(child, "value");
                if (attr) {
                    TypeInfo *t = NULL;
                    r = parse_c_expression(ps, cntx, log_f, attr->value, &t, ps->pos);
                    if (r >= 0) {
                        /*
                        fprintf(log_f, "Expression type: ");
                        tc_print_2(log_f, t, 2);
                        fprintf(log_f, "\n");
                        */

                        processor_state_invoke_type_handler(log_f, cntx, ps, txt_f, prg_f, attr->value, child, t);
                    }
                }
            }
        }
        fprintf(prg_f, "(void) sep;\n");
    }
    handle_html_string(prg_f, txt_f, log_f, "\"");

    attr = html_element_find_attribute(elem, "label");
    if (attr) {
        handle_html_string(prg_f, txt_f, log_f, " alt=\"");
        fprintf(prg_f, "fputs(_(\"%s\"), out_f);\n", attr->value);
        handle_html_string(prg_f, txt_f, log_f, "\"");
    }

    char *str_p = 0;
    size_t str_z = 0;
    FILE *str_f = open_memstream(&str_p, &str_z);
    HtmlAttribute *id_attr = html_element_find_attribute(elem, "id");
    if (id_attr) {
        fprintf(str_f, " id=\"%s\"", id_attr->value);
    }
    HtmlAttribute *class_attr = html_element_find_attribute(elem, "class");
    if (class_attr) {
        fprintf(str_f, " class=\"%s\"", class_attr->value);
    }
    fclose(str_f); str_f = NULL;
    if (str_z > 0) {
        handle_html_string(prg_f, txt_f, log_f, str_p);
    }
    free(str_p); str_p = NULL;

    handle_html_string(prg_f, txt_f, log_f, " />");
    return 0;
}

static int
handle_ac_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    unsigned char buf[1024];

    if (process_ac_attr(log_f, cntx, ps, elem, buf, sizeof(buf)) > 0) {
        fprintf(prg_f, "fprintf(out_f, \"%%d\", %s);\n", buf);
    }
    return 0;
}

/* <s:read var="VAR" name="NAME" /> */
static int
handle_read_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;

    HtmlAttribute *var_attr = html_element_find_attribute(elem, "var");
    HtmlAttribute *name_attr = html_element_find_attribute(elem, "name");

    if (!var_attr && !name_attr) {
        parser_error_2(ps, "'var' or 'name' attributes are required for s:read");
        return -1;
    }
    if (!var_attr) var_attr = name_attr;
    if (!name_attr) name_attr = var_attr;

    TypeInfo *var_type = NULL;
    int r = parse_c_expression(ps, cntx, log_f, var_attr->value, &var_type, ps->pos);
    if (r < 0) {
        parser_error_2(ps, "failed to parse C expression for var attribute");
        return -1;
    }
    /*
    fprintf(log_f, "Read expression type: ");
    tc_print_2(log_f, var_type, 2);
    fprintf(log_f, "\n");
    */
    r = processor_state_invoke_read_type_handler(log_f, cntx, ps, txt_f, prg_f, elem, var_attr->value, name_attr->value, var_type);
    if (r < 0) {
        return -1;
    }

    return 0;
}

static int
handle_help_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    HtmlElement *elem = ps->el_stack->el;
    unsigned char buf[1024];

    HtmlAttribute *topic_attr = html_element_find_attribute(elem, "topic");
    if (topic_attr != NULL) {
        fprintf(prg_f, "hr_print_help_url_2(out_f, \"%s\");\n", topic_attr->value);
    } else {
        if (process_ac_attr(log_f, cntx, ps, elem, buf, sizeof(buf)) > 0) {
            fprintf(prg_f, "hr_print_help_url(out_f, %s);\n", buf);
        }
    }
    return 0;
}

struct ElementInfo
{
    const unsigned char *name;
    int (*open_func)(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f);
    int (*close_func)(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        unsigned char *mem,
        int beg_i,
        int end_i);
};

static const struct ElementInfo element_handlers[] =
{
    { "s:_", handle_gettext_open, handle_gettext_close },
    { "s:a", handle_a_open, handle_a_close },
    { "s:submit", handle_submit_open, NULL },
    { "s:v", handle_v_open, NULL },
    { "s:form", handle_form_open, handle_form_close },
    { "s:url", handle_url_open, handle_url_close },
    { "s:param", handle_param_open, NULL },
    { "s:copyright", handle_copyright_open, NULL },
    { "s:config", handle_config_open, NULL },
    { "s:textfield", handle_textfield_open, NULL },
    { "s:password", handle_textfield_open, NULL },
    { "s:hidden", handle_textfield_open, NULL },
    { "s:checkbox", handle_checkbox_open, NULL },
    { "s:select", handle_select_open, handle_select_close },
    { "s:option", handle_option_open, handle_option_close },
    { "s:yesno", handle_yesno_open, NULL },
    { "s:yesno3", handle_yesno3_open, NULL },
    { "s:vb", handle_vb_open, NULL },
    { "s:button", handle_button_open, NULL },
    { "s:img", handle_img_open, NULL },
    { "s:radio", handle_textfield_open, NULL },
    { "s:ac", handle_ac_open, NULL },
    { "s:read", handle_read_open, NULL },
    { "s:numselect", handle_numselect_open, NULL },
    { "s:tr", handle_tr_open, handle_tr_close },
    { "s:td", handle_td_open, handle_td_close },
    { "s:th", handle_th_open, handle_th_close },
    { "s:redirect", handle_redirect_open, NULL },
    { "s:help", handle_help_open, NULL },
    { "s:indir", handle_indir_open, handle_indir_close },

    { NULL, NULL, NULL },
};

static int
handle_html_element_open(
        FILE *log_f,
        TypeContext *cntx,
        ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f)
{
    for (int i = 0; element_handlers[i].name; ++i) {
        if (!strcmp(ps->el_stack->el->name, element_handlers[i].name)) {
            if (!element_handlers[i].close_func && !ps->el_stack->el->no_body) {
                parser_error_2(ps, "<%s> element must not have a body", element_handlers[i].name);
                return -1;
            }
            return element_handlers[i].open_func(log_f, cntx, ps, txt_f, prg_f);
        }
    }
    parser_error_2(ps, "unhandled element");
    return -1;
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
    for (int i = 0; element_handlers[i].name; ++i) {
        if (!strcmp(ps->el_stack->el->name, element_handlers[i].name)) {
            if (!element_handlers[i].close_func) {
                parser_error_2(ps, "</%s> element is not allowed", element_handlers[i].name);
                return -1;
            }
            return element_handlers[i].close_func(log_f, cntx, ps, txt_f, prg_f, mem, beg_i, end_i);
        }
    }
    parser_error_2(ps, "unhandled element");
    return -1;
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
    int need_json = 0;
    HtmlAttribute *at = NULL;
    if (elem) {
        at = html_element_find_attribute(elem, "json");
    }
    if (at) {
        int v;
        if (xml_parse_bool(NULL, NULL, 0, 0, at->value, &v) >= 0) need_json = v;
        if (need_json) need_escape = 0;
    }
    at = NULL;
    if (!need_json) {
        if (elem) {
            at = html_element_find_attribute(elem, "escape");
        }
        if (at) {
            int v;
            if (xml_parse_bool(NULL, NULL, 0, 0, at->value, &v) >= 0) need_escape = v;
        }
    }
    if (need_escape) {
        if (!strcmp(elem->name, "s:param")) {
            fprintf(prg_f, "url_armor_string(hbuf, sizeof(hbuf), (%s));\n", text);
            fprintf(prg_f, "fputs(hbuf, out_f);\n");
        } else {
            fprintf(prg_f, "fputs(html_armor_buf(&ab, (%s)), out_f);\n", text);
        }
    } else if (need_json) {
        fprintf(prg_f, "fputs(json_armor_buf(&ab, (%s)), out_f);\n", text);
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
ej_jsbool_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f, "fputs((%s)?(\"true\"):(\"false\"), out_f);\n", text);
}

static void
unsigned_type_handler(
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
    fprintf(prg_f, "fprintf(out_f, \"%%u\", (unsigned)(%s));\n", text);
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
    HtmlAttribute *at = NULL;
    if (elem) {
        at = html_element_find_attribute(elem, "format");
    }
    if (at && !strcmp(at->value, "V")) {
        fprintf(prg_f, "size_t_to_size_str_f(out_f, (size_t)(%s));\n", text);
    } else if (at) {
        fprintf(prg_f, "fprintf(out_f, \"%%%szu\", (size_t)(%s));\n", at->value, text);
    } else {
        fprintf(prg_f, "fprintf(out_f, \"%%zu\", (size_t)(%s));\n", text);
    }
}

static void
ej_size64_t_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    HtmlAttribute *at = NULL;
    if (elem) {
        at = html_element_find_attribute(elem, "format");
    }
    if (at && !strcmp(at->value, "V")) {
        fprintf(prg_f, "ll_to_size_str_f(out_f, (ej_size64_t)(%s));\n", text);
    } else if (at) {
        fprintf(prg_f, "fprintf(out_f, \"%%%slld\", (ej_size64_t)(%s));\n", at->value, text);
    } else {
        fprintf(prg_f, "fprintf(out_f, \"%%lld\", (ej_size64_t)(%s));\n", text);
    }
}

static void
ej_size_t_type_handler(
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

static void
ej_ip_t_type_handler(
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
    fprintf(prg_f, "fprintf(out_f, \"%%s\", xml_unparse_ipv6(&(%s)));\n", text);
}

static void
ej_ipv4_t_type_handler(
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
    fprintf(prg_f, "fprintf(out_f, \"%%s\", xml_unparse_ip(%s));\n", text);
}

static void
ej_uuid_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f, "fputs(ej_uuid_unparse(&(%s), \"\"), out_f);\n", text);
}

static void
ej_eoln_type_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f, "fputs(eoln_type_unparse_html((%s)), out_f);\n", text);
}

static void
ej_run_status_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f, "fputs(run_status_str((%s), 0, 0, 0, 0), out_f);\n", text);
}

static void
ej_mime_type_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f, "fputs(mime_type_get_type((%s)), out_f);\n", text);
}

static void
ej_sha1_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f, "fputs(unparse_sha1((%s)), out_f);\n", text);
}

static void
ej_duration_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f, "fputs(duration_str_2(hbuf, sizeof(hbuf), %s), out_f);\n", text);
}

static void
ej_brief_time_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const unsigned char *text,
        const HtmlElement *elem,
        TypeInfo *type_info)
{
    fprintf(prg_f,
            "{\n"
            "  struct tm *ptm = localtime(&(%s));\n"
            "  fprintf(out_f, \"%%02d:%%02d:%%02d\", ptm->tm_hour, ptm->tm_min, ptm->tm_sec);\n"
            "}\n", text);
}

static int
int_read_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const HtmlElement *elem,
        const unsigned char *var_name,
        const unsigned char *param_name,
        TypeInfo *type_info)
{
    unsigned char errcode_buf[1024];
    const unsigned char *type_str = "int";

    if (type_info == tc_find_typedef_type(cntx, tc_get_ident(cntx, "ejintbool_t"))) {
        type_str = "bool";
    } else if (type_info == tc_find_typedef_type(cntx, tc_get_ident(cntx, "ej_size64_t"))) {
        type_str = "size64";
    }

    int required = html_attribute_get_bool(html_element_find_attribute(elem, "required"), 0);
    if (required) {
        // <s:read var="VAR" name="NAME" required="yes" [ignoreerrors="BOOL"] [gotoerrors="BOOL"] [error="CODE"] [missing="CODE"] [invalid="CODE"] />
        const unsigned char *error_code = html_element_find_attribute_value(elem, "error");
        const unsigned char *missing_code = html_element_find_attribute_value(elem, "missing");
        const unsigned char *invalid_code = html_element_find_attribute_value(elem, "invalid");
        int ignoreerrors = html_attribute_get_bool(html_element_find_attribute(elem, "ignoreerrors"), 0);
        if (!missing_code) missing_code = error_code;
        if (!invalid_code) invalid_code = error_code;
        if (ignoreerrors) {
            fprintf(prg_f, "hr_cgi_param_%s_2(phr, \"%s\", &(%s));\n", type_str, param_name, var_name);
        } else {
            int gotoerrors = html_attribute_get_bool(html_element_find_attribute(elem, "gotoerrors"), 0);
            if (!missing_code) missing_code = "inv-param";
            if (!invalid_code) invalid_code = "inv-param";
            if (!strcmp(missing_code, invalid_code)) {
                if (gotoerrors) {
                    fprintf(prg_f, "if (hr_cgi_param_%s_2(phr, \"%s\", &(%s)) <= 0) {\n"
                            "  goto %s;\n"
                            "}\n",
                            type_str, param_name, var_name, invalid_code);
                } else {
                    fprintf(prg_f, "if (hr_cgi_param_%s_2(phr, \"%s\", &(%s)) <= 0) {\n"
                            "  FAIL(%s);\n"
                            "}\n",
                            type_str, param_name, var_name,
                            process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), invalid_code));
                }
            } else {
                fprintf(prg_f,
                        "{\n"
                        "  int tmp_err = hr_cgi_param_%s_2(phr, \"%s\", &(%s));\n",
                        type_str, param_name, var_name);
                if (gotoerrors) {
                    fprintf(prg_f,
                            "  if (!tmp_err) {\n"
                            "    goto %s;\n"
                            "  } else if (tmp_err < 0) {\n"
                            "    goto %s;\n"
                            "  }\n"
                            "}\n",
                            missing_code, invalid_code);
                } else {
                    fprintf(prg_f,
                            "  if (!tmp_err) {\n"
                            "    FAIL(%s);\n"
                            "  } else if (tmp_err < 0) {\n",
                            process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), missing_code));
                    fprintf(prg_f,
                            "    FAIL(%s);\n"
                            "  }\n"
                            "}\n",
                            process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), invalid_code));
                }
            }
        }
    } else {
        const unsigned char *flagvar_name = html_element_find_attribute_value(elem, "flagvar");
        if (flagvar_name) {
            // <s:read var="VAR" name="NAME" flagvar="VAR" [ignoreerrors="BOOL"] [error="CODE"] [invalid="CODE"] />
            int ignoreerrors = html_attribute_get_bool(html_element_find_attribute(elem, "ignoreerrors"), 0);
            if (ignoreerrors) {
                fprintf(prg_f, "hr_cgi_param_%s_opt_2(phr, \"%s\", &(%s), &(%s));\n", type_str, param_name, var_name, flagvar_name);
            } else {
                const unsigned char *error_code = html_element_find_attribute_value(elem, "error");
                const unsigned char *invalid_code = html_element_find_attribute_value(elem, "invalid");
                int gotoerrors = html_attribute_get_bool(html_element_find_attribute(elem, "gotoerrors"), 0);
                if (!invalid_code) invalid_code = error_code;
                if (!invalid_code) invalid_code = "inv-param";
                if(gotoerrors) {
                    fprintf(prg_f, "if (hr_cgi_param_%s_opt_2(phr, \"%s\", &(%s), &(%s)) < 0) {\n"
                            "  goto %s;\n"
                            "}\n",
                            type_str, param_name, var_name, flagvar_name, invalid_code);
                } else {
                    fprintf(prg_f, "if (hr_cgi_param_%s_opt_2(phr, \"%s\", &(%s), &(%s)) < 0) {\n"
                            "  FAIL(%s);\n"
                            "}\n",
                            type_str, param_name, var_name, flagvar_name,
                            process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), invalid_code));
                }
            }
        } else {
            // <s:read var="VAR" name="NAME" default="VALUE" [ignoreerrors="BOOL"] [error="CODE"] [invalid="CODE"] />
            int ignoreerrors = html_attribute_get_bool(html_element_find_attribute(elem, "ignoreerrors"), 0);
            const unsigned char *default_value = html_element_find_attribute_value(elem, "default");
            if (!default_value) default_value = "0";
            if (ignoreerrors) {
                fprintf(prg_f, "hr_cgi_param_%s_opt(phr, \"%s\", &(%s), %s);\n", type_str, param_name, var_name, default_value);
            } else {
                const unsigned char *error_code = html_element_find_attribute_value(elem, "error");
                const unsigned char *invalid_code = html_element_find_attribute_value(elem, "invalid");
                int gotoerrors = html_attribute_get_bool(html_element_find_attribute(elem, "gotoerrors"), 0);
                if (!invalid_code) invalid_code = error_code;
                if (!invalid_code) invalid_code = "inv-param";
                if (gotoerrors) {
                    fprintf(prg_f, "if (hr_cgi_param_%s_opt(phr, \"%s\", &(%s), %s) < 0) {\n"
                            "  goto %s;\n"
                            "}\n",
                            type_str, param_name, var_name, default_value, invalid_code);
                } else {
                    fprintf(prg_f, "if (hr_cgi_param_%s_opt(phr, \"%s\", &(%s), %s) < 0) {\n"
                            "  FAIL(%s);\n"
                            "}\n",
                            type_str, param_name, var_name, default_value,
                            process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), invalid_code));
                }
            }
        }
    }

    return 0;
}

static int
string_read_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const HtmlElement *elem,
        const unsigned char *var_name,
        const unsigned char *param_name,
        TypeInfo *type_info)
{
    unsigned char errcode_buf[1024];
    const unsigned char *getter_name = "hr_cgi_param";
    unsigned char calltail[1024];
    calltail[0] = 0;
    int normalize = html_attribute_get_bool(html_element_find_attribute(elem, "normalize"), 0);
    if (normalize) {
        if (html_attribute_get_bool(html_element_find_attribute(elem, "nonnull"), 0)) {
            getter_name = "hr_cgi_param_string_2";
        } else {
            getter_name = "hr_cgi_param_string";
        }
        const unsigned char *prepend_value = html_element_find_attribute_value(elem, "prepend");
        if (prepend_value) {
            snprintf(calltail, sizeof(calltail), ", \"%s\"", prepend_value);
        } else {
            snprintf(calltail, sizeof(calltail), ", NULL");
        }
    }
    int required = html_attribute_get_bool(html_element_find_attribute(elem, "required"), 0);
    if (required) {
        // <s:read var="VAR" name="NAME" required="yes" [ignoreerrors="BOOL"] [gotoerrors="BOOL"] [error="CODE"] [missing="CODE"] [invalid="CODE"] />
        const unsigned char *error_code = html_element_find_attribute_value(elem, "error");
        const unsigned char *missing_code = html_element_find_attribute_value(elem, "missing");
        const unsigned char *invalid_code = html_element_find_attribute_value(elem, "invalid");
        const unsigned char *error_msg = html_element_find_attribute_value(elem, "errormsg");
        const unsigned char *missing_msg = html_element_find_attribute_value(elem, "missingmsg");
        const unsigned char *invalid_msg = html_element_find_attribute_value(elem, "invalidmsg");
        int ignoreerrors = html_attribute_get_bool(html_element_find_attribute(elem, "ignoreerrors"), 0);
        if (!missing_code) missing_code = error_code;
        if (!invalid_code) invalid_code = error_code;
        if (!missing_msg) missing_msg = error_msg;
        if (!invalid_msg) invalid_msg = error_msg;
        if (ignoreerrors) {
            fprintf(prg_f, "%s(phr, \"%s\", &(%s)%s);\n", getter_name, param_name, var_name, calltail);
        } else {
            int gotoerrors = html_attribute_get_bool(html_element_find_attribute(elem, "gotoerrors"), 0);
            if (!missing_code) missing_code = "inv-param";
            if (!invalid_code) invalid_code = "inv-param";
            if (!strcmp(missing_code, invalid_code)) {
                if (gotoerrors) {
                    fprintf(prg_f, "if (%s(phr, \"%s\", &(%s)%s) <= 0) {\n"
                            "  goto %s;\n"
                            "}\n",
                            getter_name, param_name, var_name, calltail, invalid_code);
                } else {
                    fprintf(prg_f, "if (%s(phr, \"%s\", &(%s)%s) <= 0) {\n", getter_name, param_name, var_name, calltail);
                    if (error_msg) {
                        fprintf(prg_f, "  fputs(\"%s\", log_f);\n", error_msg);
                    }
                    fprintf(prg_f, "  FAIL(%s);\n"
                            "}\n",
                            process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), invalid_code));
                }
            } else {
                fprintf(prg_f,
                        "{\n"
                        "  int tmp_err = %s(phr, \"%s\", &(%s)%s);\n",
                        getter_name, param_name, var_name, calltail);
                if (gotoerrors) {
                    fprintf(prg_f,
                            "  if (!tmp_err) {\n"
                            "    goto %s;\n"
                            "  } else if (tmp_err < 0) {\n"
                            "    goto %s;\n"
                            "  }\n"
                            "}\n",
                            missing_code, invalid_code);
                } else {
                    fprintf(prg_f, "  if (!tmp_err) {\n");
                    if (missing_msg) {
                        fprintf(prg_f, "  fputs(\"%s\", log_f);\n", missing_msg);
                    }
                    fprintf(prg_f,
                            "    FAIL(%s);\n"
                            "  } else if (tmp_err < 0) {\n",
                            process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), missing_code));
                    if (invalid_msg) {
                        fprintf(prg_f, "  fputs(\"%s\", log_f);\n", invalid_msg);
                    }
                    fprintf(prg_f,
                            "    FAIL(%s);\n"
                            "  }\n"
                            "}\n",
                            process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), invalid_code));
                }
            }
        }
    } else {
        // <s:read var="VAR" name="NAME" [ignoreerrors="BOOL"] [error="CODE"] [invalid="CODE"] />
        int ignoreerrors = html_attribute_get_bool(html_element_find_attribute(elem, "ignoreerrors"), 0);
        if (ignoreerrors) {
            fprintf(prg_f, "%s(phr, \"%s\", &(%s)%s);\n", getter_name, param_name, var_name, calltail);
        } else {
            const unsigned char *error_code = html_element_find_attribute_value(elem, "error");
            const unsigned char *invalid_code = html_element_find_attribute_value(elem, "invalid");
            const unsigned char *error_msg = html_element_find_attribute_value(elem, "errormsg");
            const unsigned char *invalid_msg = html_element_find_attribute_value(elem, "invalidmsg");
            int gotoerrors = html_attribute_get_bool(html_element_find_attribute(elem, "gotoerrors"), 0);
            if (!invalid_code) invalid_code = error_code;
            if (!invalid_code) invalid_code = "inv-param";
            if (!invalid_msg) invalid_msg = error_msg;
            if (gotoerrors) {
                fprintf(prg_f, "if (%s(phr, \"%s\", &(%s)%s) < 0) {\n"
                        "  goto %s;\n"
                        "}\n",
                        getter_name, param_name, var_name, calltail, invalid_code);
            } else {
                fprintf(prg_f, "if (%s(phr, \"%s\", &(%s)%s) < 0) {\n", getter_name, param_name, var_name, calltail);
                if (invalid_msg) {
                    fprintf(prg_f, "  fputs(\"%s\", log_f);\n", invalid_msg);
                }
                fprintf(prg_f,
                        "  FAIL(%s);\n"
                        "}\n",

                        process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), invalid_code));
            }
        }
    }

    return 0;
}

static int
string_array_read_type_handler(
        FILE *log_f,
        TypeContext *cntx,
        struct ProcessorState *ps,
        FILE *txt_f,
        FILE *prg_f,
        const HtmlElement *elem,
        const unsigned char *var_name,
        const unsigned char *param_name,
        TypeInfo *type_info)
{
    // <s:read var="VAR" name="NAME" [ignoreerrors="BOOL"] [error="CODE"] [invalid="CODE"] />
    fprintf(prg_f, "{\n  const unsigned char *tmp_str = NULL;\n");

    int ignoreerrors = html_attribute_get_bool(html_element_find_attribute(elem, "ignoreerrors"), 0);
    if (ignoreerrors) {
        fprintf(prg_f, "  hr_cgi_param(phr, \"%s\", &(tmp_str));\n", param_name);
        fprintf(prg_f, "  sarray_parse_2(tmp_str, &(%s));\n", var_name);
    } else {
        unsigned char errcode_buf[1024];
        const unsigned char *error_code = html_element_find_attribute_value(elem, "error");
        const unsigned char *invalid_code = html_element_find_attribute_value(elem, "invalid");
        const unsigned char *error_msg = html_element_find_attribute_value(elem, "errormsg");
        const unsigned char *invalid_msg = html_element_find_attribute_value(elem, "invalidmsg");
        const unsigned char *stream = html_element_find_attribute_value(elem, "stream");
        int gotoerrors = html_attribute_get_bool(html_element_find_attribute(elem, "gotoerrors"), 0);
        if (!invalid_code) invalid_code = error_code;
        if (!invalid_code) invalid_code = "inv-param";
        if (!invalid_msg) invalid_msg = error_msg;
        if (!stream) stream = "log_f";
        if (gotoerrors) {
            fprintf(prg_f, "  if (hr_cgi_param(phr, \"%s\", &(tmp_str)) < 0) goto %s;\n", param_name, invalid_code);
            fprintf(prg_f, "  if (sarray_parse_2(tmp_str, &(%s)) < 0) goto %s;\n", var_name, invalid_code);
        } else {
            fprintf(prg_f, "  if (hr_cgi_param(phr, \"%s\", &(tmp_str)) < 0 || sarray_parse_2(tmp_str, &(%s)) < 0) {\n",
                    param_name, var_name);
            if (invalid_msg) {
                fprintf(prg_f, "    fputs(\"%s\", %s);\n", invalid_msg, stream);
            }
            fprintf(prg_f,
                    "    FAIL(%s);\n"
                    "  }\n",
                    process_err_attr(log_f, cntx, ps, errcode_buf, sizeof(errcode_buf), invalid_code));
        }
    }
    fprintf(prg_f, "}\n");
    return 0;
}

static int
has_non_whitespace(
        const unsigned char *txt,
        int start_idx,
        int end_idx)
{
    if (!txt || start_idx >= end_idx) return 0;
    for (; start_idx < end_idx; ++start_idx) {
        if (!isspace(txt[start_idx])) {
            return 1;
        }
    }
    return 0;
}

static int
process_file(
        FILE *log_f,
        FILE *prg_f,
        FILE *txt_f,
        FILE *dep_f,
        ProcessorState *ps,
        const unsigned char *path,
        TypeContext *cntx,
        IdScope *global_scope,
        const unsigned char *file_text)
{
    FILE *in_f = NULL;
    int result = 0;
    int cc;
    unsigned char *mem = NULL;
    int mem_a = 0, mem_u = 0, mem_i = 0, html_i = 0;

    if (file_text) {
        mem_u = strlen(file_text);
        mem_a = mem_u + 1;
        mem = xstrdup(file_text);
        processor_state_init_file(ps, path);
    } else {
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
    }

    mem_i = 0;
    html_i = 0;
    while (mem_i < mem_u) {
        if (mem[mem_i] == '<' && mem[mem_i + 1] == '%' && mem[mem_i + 2] == '#') {
            handle_html_text(prg_f, txt_f, log_f, mem, html_i, mem_i);
            pos_next(&ps->pos, '<');
            pos_next(&ps->pos, '%');
            pos_next(&ps->pos, '#');
            Position start_pos = ps->pos;
            mem_i += 3;
            html_i = mem_i;
            while (mem_i < mem_u && (mem[mem_i] != '#' || mem[mem_i + 1] != '%' || mem[mem_i + 2] != '>')) {
                pos_next(&ps->pos, mem[mem_i]);
                ++mem_i;
            }
            int end_i = mem_i;
            if (mem_i < mem_u) {
                pos_next(&ps->pos, '#');
                pos_next(&ps->pos, '%');
                pos_next(&ps->pos, '>');
                mem_i += 3;
            }
            mem[end_i] = 0;
            while (end_i > html_i && isspace(mem[end_i - 1])) --end_i;
            mem[end_i] = 0;
            handle_directive(cntx, ps, prg_f, txt_f, log_f, dep_f, mem + html_i, end_i - html_i, start_pos, global_scope);
            html_i = mem_i;
        } else if (mem[mem_i] == '<' && mem[mem_i + 1] == '%') {
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
                    handle_directive(cntx, ps, prg_f, txt_f, log_f, dep_f, mem + html_i, end_i - html_i, start_pos, global_scope);
                } else if (t == '=') {
                } else {
                    // plain <% %>
                    // FIXME: use option
                    //fprintf(prg_f, "\n#line %d \"%s\"\n", start_pos.line, ps->filenames[start_pos.filename_idx]);
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
    if (has_non_whitespace(mem, html_i, mem_i)) {
        handle_html_text(prg_f, txt_f, log_f, mem, html_i, mem_i);
    }

cleanup:
    if (in_f && in_f != stdin) fclose(in_f);
    xfree(mem);
    return result;

fail:
    result = 1;
    goto cleanup;
}

static int
process_unit(
        FILE *log_f,
        FILE *out_f,
        FILE *dep_f,
        const unsigned char *path,
        TypeContext *cntx,
        IdScope *global_scope)
{
    FILE *in_f = NULL;
    int result = 0;

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
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "path_t")),
                                     string_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ej_cookie_t")),
                                     cookie_type_handler);
    processor_state_set_type_handler(ps, tc_get_i16_type(cntx), int_type_handler);
    processor_state_set_type_handler(ps, tc_get_u16_type(cntx), int_type_handler);
    processor_state_set_type_handler(ps, tc_get_i32_type(cntx), int_type_handler);
    processor_state_set_type_handler(ps, tc_get_u32_type(cntx), unsigned_type_handler);
    processor_state_set_type_handler(ps, tc_get_i64_type(cntx), long_long_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "rint16_t")),
                                     int_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "rint32_t")),
                                     int_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ruint32_t")),
                                     unsigned_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "time_t")),
                                     time_t_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ej_time64_t")),
                                     time_t_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "size_t")),
                                     size_t_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ej_size_t")),
                                     ej_size_t_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ej_size64_t")),
                                     ej_size64_t_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ej_ip_t")),
                                     ej_ip_t_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ej_ip4_t")),
                                     ej_ipv4_t_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ejbytebool_t")),
                                     int_type_handler);
    processor_state_set_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ejintbool_t")),
                                     int_type_handler);

    processor_state_set_type_handler(ps, tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_uuid_t")),
                                     ej_uuid_type_handler);
    processor_state_set_type_handler(ps, tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_eoln_type_t")),
                                     ej_eoln_type_type_handler);
    processor_state_set_type_handler(ps, tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_run_status_t")),
                                     ej_run_status_type_handler);
    processor_state_set_type_handler(ps, tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_mime_type_t")),
                                     ej_mime_type_type_handler);
    processor_state_set_type_handler(ps, tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_sha1_t")),
                                     ej_sha1_type_handler);
    processor_state_set_type_handler(ps, tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_duration_t")),
                                     ej_duration_type_handler);
    processor_state_set_type_handler(ps, tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_brief_time_t")),
                                     ej_brief_time_type_handler);
    processor_state_set_type_handler(ps, tc_get_typedef_type(cntx, tc_get_i0_type(cntx), tc_get_ident(cntx, "__ej_jsbool_t")),
                                     ej_jsbool_type_handler);

    processor_state_set_array_type_handler(ps, tc_get_u8_type(cntx), string_type_handler);
    processor_state_set_array_type_handler(ps, tc_get_i8_type(cntx), string_type_handler);

    processor_state_set_read_type_handler(ps, tc_get_i32_type(cntx), int_read_type_handler);
    processor_state_set_read_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ejintbool_t")), int_read_type_handler);
    processor_state_set_read_type_handler(ps, tc_find_typedef_type(cntx, tc_get_ident(cntx, "ej_size64_t")), int_read_type_handler);
    processor_state_set_read_type_handler(ps, tc_get_ptr_type(cntx, tc_get_const_type(cntx, tc_get_u8_type(cntx))),
                                          string_read_type_handler);
    processor_state_set_read_type_handler(ps, tc_get_ptr_type(cntx, tc_get_const_type(cntx, tc_get_i8_type(cntx))),
                                          string_read_type_handler);
    processor_state_set_read_type_handler(ps, tc_get_ptr_type(cntx, tc_get_u8_type(cntx)), string_read_type_handler);
    processor_state_set_read_type_handler(ps, tc_get_ptr_type(cntx, tc_get_i8_type(cntx)), string_read_type_handler);
    processor_state_set_read_type_handler(ps, tc_get_ptr_type(cntx, tc_get_ptr_type(cntx, tc_get_i8_type(cntx))), string_array_read_type_handler);

    char *txt_t = NULL;
    size_t txt_z = 0;
    FILE *txt_f = open_memstream(&txt_t, &txt_z);

    char *prg_t = NULL;
    size_t prg_z = 0;
    FILE *prg_f = open_memstream(&prg_t, &prg_z);

    processor_state_push_scope(ps, global_scope);

    result = process_file(log_f, prg_f, txt_f, dep_f, ps, path, cntx, global_scope, NULL);

    fprintf(out_f, "#ifdef __clang__\n");
    fprintf(out_f, "#pragma GCC diagnostic ignored \"-Wpointer-bool-conversion\"\n");
    fprintf(out_f, "#pragma GCC diagnostic ignored \"-Wformat-security\"\n");
    fprintf(out_f, "#endif\n\n");
    fprintf(out_f, "/* === string pool === */\n\n");
    fclose(txt_f); txt_f = NULL;
    fwrite(txt_t, 1, txt_z, out_f);
    free(txt_t); txt_t = NULL; txt_z = 0;
    fprintf(out_f, "\n");

    fclose(prg_f); prg_f = NULL;
    fwrite(prg_t, 1, prg_z, out_f);
    free(prg_t); prg_t = NULL; prg_z = 0;

    // FIXME: put error handling here...
    fprintf(out_f, "  return retval;\n");
    fprintf(out_f, "}\n");
    processor_state_pop_scope(ps); // local variables scope
    processor_state_pop_scope(ps); // parameter scope

    if (in_f && in_f != stdin) fclose(in_f);
    return result;
}

int
main(int argc, char *argv[])
{
    int argi = 1;
    unsigned char *output_name = NULL;
    unsigned char *deps_name = NULL;
    unsigned char *debug_name = NULL;
    FILE *out_f = NULL;
    FILE *dep_f = NULL;

    super_serve_pi_init();

    progname = os_GetLastname(argv[0]);

    while (argi < argc) {
        if (!strcmp(argv[argi], "--version")) {
            report_version();
        } else if (!strcmp(argv[argi], "--help")) {
            report_help();
        } else if (!strcmp(argv[argi], "-o")) {
            if (++argi >= argc) fatal("option -o requires an argument (output file name)");
            output_name = argv[argi++];
        } else if (!strcmp(argv[argi], "-d")) {
            if (++argi >= argc) fatal("option -d requires an argument (deps file name)");
            deps_name = argv[argi++];
        } else if (!strcmp(argv[argi], "-x")) {
            if (++argi >= argc) fatal("option -x requires an argument (debug info file name)");
            debug_name = argv[argi++];
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

    if (debug_name && !strcmp(debug_name, "none")) debug_name = 0;
    if (!debug_name) debug_name = argv[0];

    TypeContext *cntx = tc_create();
    IdScope *global_scope = tc_scope_create();
    if (dwarf_parse(stderr, debug_name, cntx, global_scope) < 0) {
        tc_dump_context(stdout, cntx);
        tc_free(cntx);
        fatal("dwarf parsing failed");
    }
    //tc_dump_context(stdout, cntx);

    if (output_name) {
        out_f = fopen(output_name, "w");
        if (!out_f) fatal("cannot open output file '%s'", output_name);
    } else {
        out_f = stdout;
    }
    if (output_name && deps_name) {
        dep_f = fopen(deps_name, "w");
        if (!dep_f) fatal("cannot open output file '%s'", deps_name);
        unsigned char *last_name = os_GetLastname(output_name);
        fprintf(dep_f, "%s : %s", last_name, source_path);
        xfree(last_name);
    }

    int result = 0;
    result = process_unit(stderr, out_f, dep_f, source_path, cntx, global_scope) || result;

    if (output_name && out_f) {
        fclose(out_f);
    }
    out_f = NULL;
    if (dep_f) {
        fprintf(dep_f, "\n");
        fclose(dep_f);
    }
    dep_f = NULL;

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
super_serve_sid_state_clear(ej_cookie_t cookie)
{
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
ns_send_reply_2(int client_id, int answer)
{
}
void
ns_new_autoclose_2(int client_id, void *write_buf, size_t write_len)
{
}
void
ns_client_state_clear_contest_id(int client_id)
{
}
void
ns_close_client_fds(int client_id)
{
}
int
ns_is_valid_client_id(int client_id)
{
    return 0;
}

const char compile_version[] = "?";
const char compile_date[] = "?";

PrivViewPrivUsersPage dummy_pvpup;
PrivViewUserIPsPage dummy_pvuip;
PrivViewIPUsersPage dummy_pviup;
PrivViewUsersPage dummy_pvup;
UserInfoPage dummy_uip;
StandingsPage dummy_page;
LanguageStat dummy_lang_stat;
struct compile_heartbeat_vector chv;
struct compile_queues_info cqi;

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
