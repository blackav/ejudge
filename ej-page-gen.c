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
#include "version.h"

#include "type_info.h"
#include "dwarf_parse.h"

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
    printf("%s: ejudge version %s compiled %s\n", progname, compile_version, compile_date);
    exit(0);
}
static void
report_help(void)
{
    printf("%s: ejudge version %s compiled %s\n", progname, compile_version, compile_date);
    exit(0);
}

static int str_serial;

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

typedef struct ProcessorState
{
    unsigned char **filenames;
    int filename_a, filename_u;

    Position pos;
    int error_count;
} ProcessorState;

static ProcessorState *
processor_state_init(void)
{
    ProcessorState *ps = NULL;
    XCALLOC(ps, 1);
    ps->filename_a = 16;
    XCALLOC(ps->filenames, ps->filename_a);
    ps->filename_u = 1;
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

static ScannerState *
init_scanner(ProcessorState *ps, FILE *log_f, const unsigned char *buf, int len, Position pos)
{
    ScannerState *ss = NULL;
    XCALLOC(ss, 1);
    ss->ps = ps;
    ss->log_f = log_f;
    ss->buf = buf;
    ss->len = len;
    ss->pos = pos;
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
        if (c == t) break;
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
}

#define IS_OPER(ss, c) ((ss)->token == TOK_OPER && (ss)->raw_len == 1 && ss->raw[0] == (c))

/*static*/ int
parse_declspec(ScannerState *ss, TypeContext *cntx, TypeInfo **p_info)
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
        parser_error(ss, "type expected");
        goto cleanup;
    }
    while (1) {
        if (ss->token != TOK_IDENT) break;
        if (!strcmp(ss->raw, "auto")) {
            ++auto_count;
            next_token(ss);
        } else if (!strcmp(ss->raw, "const")) {
            ++const_count;
            next_token(ss);
        } else if (!strcmp(ss->raw, "extern")) {
            ++extern_count;
            next_token(ss);
        } else if (!strcmp(ss->raw, "register")) {
            ++register_count;
            next_token(ss);
        } else if (!strcmp(ss->raw, "restrict")) {
            ++restrict_count;
            next_token(ss);
        } else if (!strcmp(ss->raw, "static")) {
            ++static_count;
            next_token(ss);
        } else if (!strcmp(ss->raw, "typedef")) {
            ++typedef_count;
            next_token(ss);
        } else if (!strcmp(ss->raw, "volatile")) {
            ++volatile_count;
            next_token(ss);
        } else if (!strcmp(ss->raw, "enum")) {
            if (type_info || has_base_type) goto invalid_declspec;
            next_token(ss);
            if (ss->token != TOK_IDENT) {
                parser_error(ss, "identifier expected after 'enum'");
                goto cleanup;
            }
            type_info = tc_find_enum_type(cntx, tc_get_ident(cntx, ss->raw));
            if (!type_info) {
                parser_error(ss, "enum type '%s' undefined", ss->raw);
                goto cleanup;
            }
        } else if (!strcmp(ss->raw, "struct")) {
            if (type_info || has_base_type) goto invalid_declspec;
            next_token(ss);
            if (ss->token != TOK_IDENT) {
                parser_error(ss, "identifier expected after 'struct'");
                goto cleanup;
            }
            type_info = tc_find_struct_type(cntx, NODE_STRUCT_TYPE, tc_get_ident(cntx, ss->raw));
            if (!type_info) {
                parser_error(ss, "struct type '%s' undefined", ss->raw);
                goto cleanup;
            }
        } else if (!strcmp(ss->raw, "union")) {
            if (type_info || has_base_type) goto invalid_declspec;
            next_token(ss);
            if (ss->token != TOK_IDENT) {
                parser_error(ss, "identifier expected after 'union'");
                goto cleanup;
            }
            type_info = tc_find_struct_type(cntx, NODE_UNION_TYPE, tc_get_ident(cntx, ss->raw));
            if (!type_info) {
                parser_error(ss, "union type '%s' undefined", ss->raw);
                goto cleanup;
            }
        } else if (!strcmp(ss->raw, "signed")) {
            if (type_info) goto invalid_declspec;
            ++signed_count;
            has_base_type = 1;
            next_token(ss);
        } else if (!strcmp(ss->raw, "unsigned")) {
            if (type_info) goto invalid_declspec;
            ++unsigned_count;
            has_base_type = 1;
            next_token(ss);
        } else if (!strcmp(ss->raw, "short")) {
            if (type_info) goto invalid_declspec;
            ++short_count;
            has_base_type = 1;
            next_token(ss);
        } else if (!strcmp(ss->raw, "long")) {
            if (type_info) goto invalid_declspec;
            ++long_count;
            has_base_type = 1;
            next_token(ss);
        } else if (!strcmp(ss->raw, "_Bool")) {
            if (type_info) goto invalid_declspec;
            ++bool_count;
            has_base_type = 1;
            next_token(ss);
        } else if (!strcmp(ss->raw, "char")) {
            if (type_info) goto invalid_declspec;
            ++char_count;
            has_base_type = 1;
            next_token(ss);
        } else if (!strcmp(ss->raw, "int")) {
            if (type_info) goto invalid_declspec;
            ++int_count;
            has_base_type = 1;
            next_token(ss);
        } else if (!strcmp(ss->raw, "float")) {
            if (type_info) goto invalid_declspec;
            ++float_count;
            has_base_type = 1;
            next_token(ss);
        } else if (!strcmp(ss->raw, "double")) {
            if (type_info) goto invalid_declspec;
            ++double_count;
            has_base_type = 1;
            next_token(ss);
        } else {
            if (has_base_type || type_info) break;
            type_info = tc_find_typedef_type(cntx, tc_get_ident(cntx, ss->raw));
            if (!type_info) {
                parser_error(ss, "typedef type '%s' undefined", ss->raw);
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
    parser_error(ss, "invalid declaration specifier");
    goto cleanup;
}

static int
handle_directive_page(ScannerState *ss, FILE *out_f)
{
    int retval = -1;
    unsigned char *page_name = NULL;

    next_token(ss); dump_token(ss);
    if (ss->token != TOK_IDENT) {
        parser_error(ss, "page name (identifier) expected");
        goto cleanup;
    }
    page_name = ss->value; ss->value = NULL;

    next_token(ss); dump_token(ss);
    if (!IS_OPER(ss, '(')) {
        parser_error(ss, "'(' expected");
        goto cleanup;
    }
    next_token(ss); dump_token(ss);
    if (IS_OPER(ss, ')')) {
        // empty argument list
        next_token(ss); dump_token(ss);
    } else {
        if (ss->token != TOK_IDENT) {
            parser_error(ss, "argument type expected");
            goto cleanup;
        }
        next_token(ss); dump_token(ss);
        if (ss->token != TOK_IDENT) {
            parser_error(ss, "argument name expected");
            goto cleanup;
        }
        next_token(ss); dump_token(ss);
        while (IS_OPER(ss, ',')) {
            next_token(ss); dump_token(ss);
            if (ss->token != TOK_IDENT) {
                parser_error(ss, "argument type expected");
                goto cleanup;
            }
            next_token(ss); dump_token(ss);
            if (ss->token != TOK_IDENT) {
                parser_error(ss, "argument name expected");
                goto cleanup;
            }
            next_token(ss); dump_token(ss);
        }
        if (!IS_OPER(ss, ')')) {
            parser_error(ss, "')' expected");
            goto cleanup;
        }
        next_token(ss); dump_token(ss);
    }

    if (ss->token != TOK_EOF) {
        parser_error(ss, "garbage after directive");
        goto cleanup;
    }
    retval = 0;

cleanup:
    xfree(page_name);
    return retval;
}

static int
handle_directive(ProcessorState *ps, FILE *out_f, FILE *log_f, const unsigned char *str, int len, Position pos)
{
    ScannerState *ss = init_scanner(ps, log_f, str, len, pos);
    int retval = -1;

    next_token(ss); dump_token(ss);

    if (ss->token != TOK_IDENT) {
        parser_error(ss, "directive expected");
    } else if (!strcmp(ss->value, "page")) {
        handle_directive_page(ss, out_f);
    } else {
        parser_error(ss, "invalid directive '%s'", ss->value);
    }

    ss = destroy_scanner(ss);
    return retval;
}

static int
handle_html_text(FILE *out_f, FILE *log_f, const unsigned char *str, int len)
{
    if (len > 0) {
        fprintf(out_f, "static const unsigned char str%d[%d] = ", str_serial++, len + 1);
        emit_str_literal(out_f, str, len);
        fprintf(out_f, ";\n");

        fprintf(out_f, "fwrite(str%d, 1, %d, out_f);\n", str_serial - 1, len);
    }
    return 0;
}

#define APPEND_CHAR(c) do { if (buf_u + 1 >= buf_a) { buf = xrealloc(buf, buf_a *= 2); } buf[buf_u++] = (c); } while (0)

static int
process_file(
        const unsigned char *path,
        TypeContext *cntx)
{
    FILE *in_f = NULL;
    int result = 0;
    unsigned char *buf = NULL;
    int buf_a = 0, buf_u = 0;
    int c;

    FILE *out_f = stdout;
    ProcessorState *ps = processor_state_init();

    if (!strcmp(path, "-")) {
        in_f = stdin;
    } else {
        in_f = fopen(path, "r");
        if (!in_f) {
            fprintf(stderr, "%s: cannot open file '%s': %s\n", progname, path, os_ErrorMsg());
            goto fail;
        }
    }
    processor_state_init_file(ps, path);

    buf_a = 512;
    buf = xmalloc(buf_a);

    c = getc(in_f);
    while (c != EOF) {
        if (c == '<') {
            c = getc(in_f);
            if (c == '%') {
                // <%
                buf[buf_u] = 0;
                handle_html_text(out_f, stderr, buf, buf_u);
                buf_u = 0;
                pos_next(&ps->pos, '<');
                pos_next(&ps->pos, '%');
                Position start_pos = ps->pos;

                c = getc(in_f);
                while (c != EOF) {
                    if (c == '%') {
                        c = getc(in_f);
                        if (c == EOF) break;
                        if (c == '>') {
                            pos_next(&ps->pos, '>');
                            c = getc(in_f);
                            break;
                        }
                        APPEND_CHAR('%');
                        pos_next(&ps->pos, '%');
                    } else {
                        APPEND_CHAR(c);
                        pos_next(&ps->pos, c);
                        c = getc(in_f);
                    }
                }
                buf[buf_u] = 0;

                // handle <% ... %>
                while (buf_u > 0 && isspace(buf[buf_u - 1])) --buf_u;
                buf[buf_u] = 0;
                if (buf_u > 0) {
                    int t = buf[0];
                    int start = 0;
                    if (t == '@' || t == '=') {
                        pos_next(&start_pos, t);
                        ++start;
                    } else {
                        t = '*';
                    }
                    while (isspace(buf[start])) {
                        pos_next(&start_pos, buf[start]);
                        ++start;
                    }

                    if (t == '@') {
                        handle_directive(ps, out_f, stderr, buf + start, buf_u - start, start_pos);
                    } else if (t == '=') {
                    } else {
                        fprintf(out_f, "%s", buf + start);
                    }
                }
                buf_u = 0;
            } else {
                APPEND_CHAR('<');
                pos_next(&ps->pos, '<');
            }
        } else {
            APPEND_CHAR(c);
            pos_next(&ps->pos, c);
            c = getc(in_f);
        }
    }

    buf[buf_u] = 0;
    handle_html_text(out_f, stderr, buf, buf_u);
    buf_u = 0;

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
    if (dwarf_parse(stdout, argv[0], cntx) < 0) {
        tc_dump_context(stdout, cntx);
        tc_free(cntx);
        fatal("dwarf parsing failed");
    }
    //tc_dump_context(stdout, cntx);

    int result = 0;
    result = process_file(source_path, cntx) || result;

    tc_free(cntx);

    return result;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
