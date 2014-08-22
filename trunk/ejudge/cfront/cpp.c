/* -*- mode: c -*- */
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

//#include "version.h"

#include "ejudge/logger.h"
#include "ejudge/xalloc.h"
#include "ejudge/c_value.h"
#include "ejudge/hash.h"
#include "ejudge/number_io.h"
#include "ejudge/getopt.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>

#if defined __MINGW32__
#include <malloc.h>
#endif

/* ============= option flags ============= */
static short option_trigraph = 0;
static short option_preserve_comments = 0;
static short option_verbose = 0;

static strarray_t input_files;
static char *output_name;

static strarray_t sys_incl_dirs;
static strarray_t warn_incl_dirs;
static strarray_t incl_dirs;
static strarray_t du_options;
static strarray_t include_files;
/* ============= raw strings ============= */

typedef struct rawstring_struct
{
  size_t size;
  unsigned char *str;
} rawstring_t;

typedef struct bufstring_struct
{
  size_t a, u;
  unsigned char *str;
} bufstring_t;

/* ============= preprocessor tokens ============= */

enum token_names
{
  TOK_INCR = 258,               /* ++ */
  TOK_DECR,                     /* -- */
  TOK_LSHIFT,                   /* << */
  TOK_RSHIFT,                   /* >> */
  TOK_LEQ,                      /* <= */
  TOK_GEQ,                      /* >= */
  TOK_EQ,                       /* == */
  TOK_NEQ,                      /* != */
  TOK_LOGAND,                   /* && */
  TOK_LOGOR,                    /* || */
  TOK_LOGXOR,                   /* ^^ --- extension! */
  TOK_ELLIPSIS,                 /* ... */
  TOK_MULASSIGN,                /* *= */
  TOK_DIVASSIGN,                /* /= */
  TOK_MODASSIGN,                /* %= */
  TOK_ADDASSIGN,                /* += */
  TOK_SUBASSIGN,                /* -= */
  TOK_LSHASSIGN,                /* <<= */
  TOK_RSHASSIGN,                /* >>= */
  TOK_ANDASSIGN,                /* &= */
  TOK_XORASSIGN,                /* ^= */
  TOK_ORASSIGN,                 /* |= */
  TOK_ARROW,                    /* -> */
  TOK_PASTE,                    /* ## */
  TOK_PASTE_VA,                 /* ## */ /* for variadic macros */
  TOK_IDENT,
  TOK_CONSTANT,
  TOK_STRING,
  TOK_SPACE,
  TOK_ANNOT,
  TOK_UNKNOWN,
  TOK_NL,
  TOK_IDENT_NE,                 /* non-expandable identifier */
};
struct token_token
{
  int kind;
};
struct token_value
{
  int kind;
  rawstring_t raw;
  c_value_t val;
};
struct token_ident
{
  int kind;
  ident_t id;
};
struct token_string
{
  int kind;
  rawstring_t raw;
  rawstring_t val;
};
struct token_space
{
  int kind;
  rawstring_t raw;
};
union token
{
  int kind;
  struct token_token tok;
  struct token_value val;
  struct token_ident id;
  struct token_string str;
  struct token_space sp;
};
typedef union token token_t;

/* macroexpand stack */
struct ident_stack
{
  struct ident_stack *next;
  ident_t id;
};
typedef struct ident_stack *idstack_t;

/* ============= file stack ============= */

struct file_stack
{
  struct file_stack *next;

  FILE *file;
  unsigned char *path;
  int line;
  int spliced_nls;

  int la_stack_buf[16];
  int *la_stack;
  int la_last;
  int is_eof;

  int s2_stack[16];
  int s2_last;
};
static struct file_stack *files = 0;

static inline int
stage0_getchar(void)
{
  int c;

  if (files->la_last > 0) return files->la_stack[--files->la_last];
  if (files->is_eof) return -1;
  c = getc(files->file);
  if (c == -1) files->is_eof = 1;
  return c;
}

static inline void
stage0_pushback(int c)
{
  //ASSERT(files->la_last < 16);
  files->la_stack[files->la_last++] = c;
}

static int
stage12_getchar(void)
{
  int c1, c2, c3;

  while (1) {
    c1 = stage0_getchar();
    if (c1 == '\\') {
      c2 = stage0_getchar();
      if (c2 == '\n') {
        // unix-like \n end of line
        files->spliced_nls++;
        continue;
      }
      if (c2 == '\r') {
        c3 = stage0_getchar();
        files->spliced_nls++;
        if (c3 == '\n') {
          // dos-line \r\n end of line
          continue;
        }
        // mac-like \r end of file
        stage0_pushback(c3);
        continue;
      }
      // push back the last char
      stage0_pushback(c2);
      return c1;
    }
    if (option_trigraph && c1 == '?') {
      c2 = stage0_getchar();
      if (c2 != '?') {
        stage0_pushback(c2);
        return c1;
      }
      c3 = stage0_getchar();
      switch (c3) {
      case '=':  c1 = '#';  break;
      case '(':  c1 = '[';  break;
      case '/':  c1 = '\\'; break;
      case ')':  c1 = ']';  break;
      case '\'': c1 = '^';  break;
      case '<':  c1 = '{';  break;
      case '!':  c1 = '|';  break;
      case '>':  c1 = '}';  break;
      case '-':  c1 = '~';  break;
      default:
        stage0_pushback(c3);
        stage0_pushback(c2);
        return c1;
      }
    }
    return c1;
  }
}

static int
stage0_open_input(unsigned char *path, FILE *f)
{
  struct file_stack *p = 0;
  int r;

  p = (struct file_stack *) xcalloc(1, sizeof(*p));
  p->la_stack = p->la_stack_buf;
  if (!f) {
    f = fopen(path, "rb");
    if (!f) {
      r = errno;
      if (!r) r = 1;
      xfree(p);
      return -errno;
    }
  } 

  p->file = f;
  p->path = xstrdup(path);
  p->line = 1;
  p->next = files;
  files = p;
  return 0;
}

static void
stage0_close_input(void)
{
  struct file_stack *p = files;

  if (!p) return;
  files = files->next;
  xfree(p->path);
  xfree(p);
}

static int
stage3_getchar(void)
{
  if (files->s2_last > 0) return files->s2_stack[--files->s2_last];
  return stage12_getchar();
}
static void
stage3_pushback(int c)
{
  ASSERT(files->s2_last < 16);
  files->s2_stack[files->s2_last++] = c;
}
static void
next_line(FILE *out)
{
  int i;

  if (out && files->spliced_nls > 0) {
    for (i = 0; i < files->spliced_nls; i++)
      putc('\n', out);
  }
  files->line += files->spliced_nls + 1;
  files->spliced_nls = 0;
}

static int error_counter;

#ifdef __GNUC__
static void c_err(const char *format, ...)
  __attribute__((format(printf, 1, 2)));
#endif
static void
c_err(const char *format, ...)
{
  va_list args;

  fprintf(stderr, "%s: %d: ", files->path, files->line);
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  error_counter++;
}

#ifdef __GNUC__
static void c_err2(const unsigned char *path, int line, const char *format, ...)
  __attribute__((format(printf, 3, 4)));
#endif
static void
c_err2(const unsigned char *path, int line, const char *format, ...)
{
  va_list args;

  fprintf(stderr, "%s: %d: ", path, line);
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  error_counter++;
}

#ifdef __GNUC__
static void c_warn(const char *format, ...)
  __attribute__((format(printf, 1, 2)));
#endif
static void
c_warn(const char *format, ...)
{
  va_list args;

  fprintf(stderr, "%s: %d: warning: ", files->path, files->line);
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
}

#ifdef __GNUC__
static void c_warn2(const unsigned char *path, int line, const char *format, ...)
  __attribute__((format(printf, 3, 4)));
#endif
static void
c_warn2(const unsigned char *path, int line, const char *format, ...)
{
  va_list args;

  fprintf(stderr, "%s: %d: warning: ", path, line);
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
}

static void
init_bufstring(bufstring_t *pb)
{
  pb->a = 1024;
  pb->u = 0;
  pb->str = (unsigned char*) xcalloc(pb->a, 1);
  pb->str[0] = 0;
}

static void
bufstring_setsize(bufstring_t *pb, size_t newsz)
{
  if (newsz > pb->a) {
    while (newsz > pb->a) {
      pb->a *= 2;
    }
    pb->str = (unsigned char*) xrealloc(pb->str, pb->a);
  }
}

static void
add_to_bufstring(bufstring_t *pb, const unsigned char *str, size_t len)
{
  size_t newsz = pb->u + len + 1;

  if (newsz > pb->a) {
    while (newsz > pb->a) {
      pb->a *= 2;
    }
    pb->str = (unsigned char*) xrealloc(pb->str, pb->a);
  }
  if (len > 0) {
    memcpy(&pb->str[pb->u], str, len);
    pb->u += len;
    pb->str[pb->u] = 0;
  }
}

/* ============= line buffer ============= */

static bufstring_t line_buf;
static size_t line_buf_ind;
static int auto_getline_flag;
static int scanner_include_strings_flag;

static bufstring_t valbuf;
static bufstring_t rawbuf;
static bufstring_t spcbuf;

static token_t cur_val;

struct scanner_state
{
  bufstring_t line_buf;
  size_t line_buf_ind;
  int auto_getline_flag;
};
static struct scanner_state *saved_state;

static void
scanner_save_state(void)
{
  if (!saved_state) {
    saved_state = (struct scanner_state*) xcalloc(1, sizeof(*saved_state));
    saved_state->line_buf.a = line_buf.a;
    saved_state->line_buf.str = (unsigned char*) xcalloc(line_buf.a, 1);
  }
  if (saved_state->line_buf.a != line_buf.a) {
    xfree(saved_state->line_buf.str);
    saved_state->line_buf.a = line_buf.a;
    saved_state->line_buf.str = (unsigned char*) xcalloc(line_buf.a, 1);
  }
  saved_state->line_buf.u = line_buf.u;
  memcpy(saved_state->line_buf.str, line_buf.str, line_buf.u + 1);
  saved_state->line_buf_ind = line_buf_ind;
  saved_state->auto_getline_flag = auto_getline_flag;
}
static void
scanner_restore_state(void)
{
  line_buf.u = saved_state->line_buf.u;
  memcpy(line_buf.str, saved_state->line_buf.str, line_buf.u + 1);
  line_buf_ind = saved_state->line_buf_ind;
  auto_getline_flag = saved_state->auto_getline_flag;
}

static int
stage4_getline(void)
{
  unsigned char lbuf[512];
  int c, i;

  line_buf.u = 0;
  line_buf.str[0] = 0;
  line_buf_ind = 0;
  i = 0;
  while (1) {
    c = stage3_getchar();
    if (c < 0) {
      add_to_bufstring(&line_buf, lbuf, i);
      break;
    }
    if (c == '\n') {
      if (i >= sizeof(lbuf) - 4) {
        add_to_bufstring(&line_buf, lbuf, i);
        i = 0;
      }
      lbuf[i++] = c;
      add_to_bufstring(&line_buf, lbuf, i);
      break;
    }
    if (c == '\r') {
      if (i >= sizeof(lbuf) - 4) {
        add_to_bufstring(&line_buf, lbuf, i);
        i = 0;
      }
      lbuf[i++] = c;
      c = stage3_getchar();
      if (c == '\n') {
        lbuf[i++] = c;
      } else {
        if (c >= 0) stage3_pushback(c);
      }
      add_to_bufstring(&line_buf, lbuf, i);
      break;
    }
    if (i >= sizeof(lbuf)) {
      add_to_bufstring(&line_buf, lbuf, i);
      i = 0;
    }
    lbuf[i++] = c;
  }

  bufstring_setsize(&spcbuf, spcbuf.u + line_buf.u + 32);
  bufstring_setsize(&valbuf, valbuf.u + line_buf.u + 32);
  bufstring_setsize(&rawbuf, rawbuf.u + line_buf.u + 10);
  return line_buf.u;
}

static inline int
stage4_getchar(void)
{
  if (line_buf_ind >= line_buf.u) {
    line_buf_ind++;
    if (!auto_getline_flag) return -1;
    if (!stage4_getline()) return -1;
  }
  return line_buf.str[line_buf_ind++];
}
static inline void
stage4_pushback(void)
{
  if (line_buf_ind > line_buf.u) return;
  if (line_buf_ind > 0) line_buf_ind--;
}

static unsigned char const * const token_strings[] =
{
  [TOK_INCR]      "++",
  [TOK_DECR]      "--",
  [TOK_LSHIFT]    "<<",
  [TOK_RSHIFT]    ">>",
  [TOK_LEQ]       "<=",
  [TOK_GEQ]       ">=",
  [TOK_EQ]        "==",
  [TOK_NEQ]       "!=",
  [TOK_LOGAND]    "&&",
  [TOK_LOGOR]     "||",
  [TOK_LOGXOR]    "^^",
  [TOK_ELLIPSIS]  "...",
  [TOK_MULASSIGN] "*=",
  [TOK_DIVASSIGN] "/=",
  [TOK_MODASSIGN] "%=",
  [TOK_ADDASSIGN] "+=",
  [TOK_SUBASSIGN] "-=",
  [TOK_LSHASSIGN] "<<=",
  [TOK_RSHASSIGN] ">>=",
  [TOK_ANDASSIGN] "&=",
  [TOK_XORASSIGN] "^=",
  [TOK_ORASSIGN]  "|=",
  [TOK_ARROW]     "->",
  [TOK_PASTE]     "##",
  [TOK_PASTE_VA]  "[##]",
};

static int
hex2int(int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - ('a' - 10);
  if (c >= 'A' && c <= 'F') return c - ('A' - 10);
  return 0;
}

  /* various flags */
enum
  {
    LT_UNSIGNED = 1,
    LT_LONG = 2,
    LT_LONGLONG = 4,
    LT_FLOAT = 8,
    LT_IMAG = 16,
  };

#define add_to_raw(c) (rawbuf.str[rawbuf.u++] = (c))
#define add_to_val(c) (valbuf.str[valbuf.u++] = (c))

static int
read_int_suffix(int tok)
{
  int flags = 0;
  int u_count = 0;
  int l_count = 0;

  while (1) {
    if (tok == 'u' || tok == 'U') {
      if (u_count > 0) goto pushback_and_return;
      add_to_raw(tok);
      u_count++;
      flags |= LT_UNSIGNED;
      tok = stage4_getchar();
    } else if (tok == 'l' || tok == 'L') {
      if (l_count > 1) goto pushback_and_return;
      add_to_raw(tok);
      l_count++;
      if (l_count == 1) flags |= LT_LONG;
      else flags = (flags & ~LT_LONG) | LT_LONGLONG;
      tok = stage4_getchar();
    } else {
      goto pushback_and_return;
    }
  }
  return flags;

 pushback_and_return:
  stage4_pushback();
  return flags;
}

static int
handle_integral(int start, int length, int base, int flags)
{
  unsigned char *buf = 0;

  buf = (unsigned char *) alloca(length + 1);
  memset(buf, 0, length + 1);
  memcpy(buf, rawbuf.str + start, length);

  if (flags == 0) {
    /* plain int */
    int val = 0;
    errno = 0;
    val = strtol(buf, 0, base);
    if (errno == 0) {
      cur_val.val.val.tag = C_INT;
      cur_val.val.val.v.ct_int = val;
      return TOK_CONSTANT;
    }
  }
  if ((flags & (LT_LONGLONG | LT_LONG)) == 0) {
    /* int, unsigned int */
    unsigned int val = 0;
    errno = 0;
    val = strtoul(buf, 0, base);
    if (errno == 0) {
      cur_val.val.val.tag = C_UINT;
      cur_val.val.val.v.ct_uint = val;
      return TOK_CONSTANT;
    }
  }
  if ((flags & (LT_LONGLONG | LT_UNSIGNED)) == 0) {
    /* int, long */
    long val;
    errno = 0;
    val = strtol(buf, 0, base);
    if (errno == 0) {
      cur_val.val.val.tag = C_LONG;
      cur_val.val.val.v.ct_lint = val;
      return TOK_CONSTANT;
    }
  }
  if ((flags & LT_LONGLONG) == 0) {
    unsigned long val;
    errno = 0;
    val = strtoul(buf, 0, base);
    if (errno == 0) {
      cur_val.val.val.tag = C_ULONG;
      cur_val.val.val.v.ct_ulint = val;
      return TOK_CONSTANT;
    }
  }
  if ((flags & LT_UNSIGNED) == 0) {
    long long val;
    errno = 0;
    val = strtoll(buf, 0, base);
    if (errno == 0) {
      cur_val.val.val.tag = C_LLONG;
      cur_val.val.val.v.ct_llint = val;
      return TOK_CONSTANT;
    }
  }
  /* try unsigned long long */
  {
    unsigned long long val;
    errno = 0;
    val = strtoull(buf, 0, base);
    if (errno == 0) {
      cur_val.val.val.tag = C_ULLONG;
      cur_val.val.val.v.ct_ullint = val;
      return TOK_CONSTANT;
    }
  }
  cur_val.kind = TOK_UNKNOWN;
  return TOK_UNKNOWN;
}

static int
read_float_suffix(int tok)
{
  int flags = 0;

  if (tok == 'f' || tok == 'F') {
    add_to_raw(tok);
    flags |= LT_FLOAT;
    tok = stage4_getchar();
    if (tok == 'i' || tok == 'I' || tok == 'j' || tok == 'J') {
      add_to_raw(tok);
      flags |= LT_IMAG;
    } else {
      goto pushback_and_return;
    }
  } else if (tok == 'l' || tok == 'L') {
    add_to_raw(tok);
    flags |= LT_LONG;
    tok = stage4_getchar();
    if (tok == 'i' || tok == 'I' || tok == 'j' || tok == 'J') {
      add_to_raw(tok);
      flags |= LT_IMAG;
    } else {
      goto pushback_and_return;
    }
  } else if (tok == 'i' || tok == 'I' || tok == 'j' || tok == 'J') {
    add_to_raw(tok);
    flags |= LT_IMAG;
    tok = stage4_getchar();
    if (tok == 'f' || tok == 'F') {
      add_to_raw(tok);
      flags |= LT_FLOAT;
    } else if (tok == 'l' || tok == 'L') {
      add_to_raw(tok);
      flags |= LT_LONG;
    } else {
      goto pushback_and_return;
    }
  } else {
    goto pushback_and_return;
  }

  return flags;

 pushback_and_return:
  stage4_pushback();
  return flags;
}

static int
handle_float(int start, int length, int base, int flags)
{
  unsigned char *buf = 0;
  int ret = 0;
  int (*read_func)() = 0;
  void *addr = 0;

  buf = (unsigned char *) alloca(length + 1);
  memset(buf, 0, length + 1);
  memcpy(buf, rawbuf.str + start, length);
  memset(&cur_val.val.val, 0, sizeof(cur_val.val.val));

  switch (flags) {
  case 0:
    cur_val.val.val.tag = C_DOUBLE;
    addr = &cur_val.val.val.v.ct_double;
    if (base == 16) read_func = reuse_readhd;
    else read_func = os_readdd;
    break;
  case LT_IMAG:
    cur_val.val.val.tag = C_DCOMPLEX;
    addr = &cur_val.val.val.v.ct_dcomplex.d_im;
    if (base == 16) read_func = reuse_readhd;
    else read_func = os_readdd;
    break;
  case LT_FLOAT:
    cur_val.val.val.tag = C_FLOAT;
    addr = &cur_val.val.val.v.ct_float;
    if (base == 16) read_func = reuse_readhf;
    else read_func = os_readdf;
    break;
  case LT_FLOAT | LT_IMAG:
    cur_val.val.val.tag = C_FCOMPLEX;
    addr = &cur_val.val.val.v.ct_fcomplex.f_im;
    if (base == 16) read_func = reuse_readhf;
    else read_func = os_readdf;
    break;
  case LT_LONG:
    cur_val.val.val.tag = C_LDOUBLE;
    addr = &cur_val.val.val.v.ct_ldouble;
    if (base == 16) read_func = reuse_readhld;
    else read_func = os_readdld;
    break;
  case LT_LONG | LT_IMAG:
    cur_val.val.val.tag = C_LCOMPLEX;
    addr = &cur_val.val.val.v.ct_lcomplex.l_im;
    if (base == 16) read_func = reuse_readhld;
    else read_func = os_readdld;
    break;
  }

  ret = (*read_func)(buf, 0, addr);
  ASSERT(ret >= 0);
  cur_val.kind = TOK_CONSTANT;
  cur_val.val.raw.size = rawbuf.u;
  cur_val.val.raw.str = rawbuf.str;
  return TOK_CONSTANT;
}

static int
get_file_token(void)
{
  int tok, tok2, tok3;
  int strterm, i, val, flags;
  int annot_state;

  tok = stage4_getchar();
  valbuf.u = 0;
  valbuf.str[0] = 0;
  rawbuf.u = 0;
  rawbuf.str[0] = 0;

  switch (tok) {
  case -1:
    cur_val.kind = 0;
    return 0;
  case '\n':
    add_to_raw(tok);
    cur_val.kind = TOK_NL;
    cur_val.sp.raw.size = rawbuf.u;
    cur_val.sp.raw.str = rawbuf.str;
    return TOK_NL;
  case '\r':
    add_to_raw(tok);
    tok = stage4_getchar();
    if (tok != '\n') {
      stage4_pushback();
    } else {
      add_to_raw(tok);
    }
    cur_val.kind = TOK_NL;
    cur_val.sp.raw.size = rawbuf.u;
    cur_val.sp.raw.str = rawbuf.str;
    return TOK_NL;
  case 0 ... 9:
  case 11 ... 12:
  case 14 ... 32:
    while (tok >= 0 && tok <= ' ' && tok != '\n' && tok != '\r') {
      add_to_raw(tok);
      tok = stage4_getchar();
    }
    stage4_pushback();
    cur_val.kind = TOK_SPACE;
    cur_val.sp.raw.size = rawbuf.u;
    cur_val.sp.raw.str = rawbuf.str;
    return TOK_SPACE;

  case '/':                     /* '/', '//', '/''*', '/=' */
    tok2 = stage4_getchar();
    switch (tok2) {
    case '/':                   /* line comment */
      if (option_preserve_comments) {
        SWERR(("cannot preserve comments"));
      } else {
        while (1) {
          tok = stage4_getchar();
          if (tok == -1 || tok == '\r' || tok == '\n') break;
        }
        stage4_pushback();
        add_to_raw(' ');
        cur_val.kind = TOK_SPACE;
        cur_val.sp.raw.size = rawbuf.u;
        cur_val.sp.raw.str = rawbuf.str;
        return TOK_SPACE;
      }
    case '*':                   /* block comment */
      if (option_preserve_comments) {
        SWERR(("cannot preserve comments"));
      } else {
        annot_state = 0;
        while (1) {
          tok = stage4_getchar();
          if (annot_state == 0 && tok == 'L') annot_state = 1;
          else if (annot_state == 1 && tok == 'A') annot_state = 2;
          else if (annot_state == 2 && tok == 'L') {
            annot_state = 3;
            break;
          } else {
            annot_state = -1;
          }
          if (tok == -1) {
            // FIXME: unexpected EOF in comment
            break;
          }
          if (tok == '\n') {
            files->spliced_nls++;
          }
          if (tok == '*') {
            tok = stage4_getchar();
            if (tok == '/') break;
            stage4_pushback();
          }
        }
        if (annot_state == 3) {
          /* annotation */
          add_to_raw('/');
          add_to_raw('*');
          add_to_raw('L');
          add_to_raw('A');
          add_to_raw('L');
          while (1) {
            tok = stage4_getchar();
            if (tok == -1) {
              // FIXME: unexpected EOF in comment
              break;
            }
            if (tok == '*') {
              tok = stage4_getchar();
              if (tok == '/') break;
              stage4_pushback();
              add_to_raw('*');
            } else {
              add_to_raw(tok);
            }
          }
          add_to_raw('*');
          add_to_raw('/');
          cur_val.kind = TOK_ANNOT;
          cur_val.sp.raw.size = rawbuf.u;
          cur_val.sp.raw.str = rawbuf.str;
          return TOK_ANNOT;
        }
        add_to_raw(' ');
        cur_val.kind = TOK_SPACE;
        cur_val.sp.raw.size = rawbuf.u;
        cur_val.sp.raw.str = rawbuf.str;
        return TOK_SPACE;
      }
    case '=':
      cur_val.kind = TOK_DIVASSIGN;
      return TOK_DIVASSIGN;
    default:
      stage4_pushback();
      cur_val.kind = '/';
      return '/';
    }

  case 'a'...'z':
  case 'A'...'Z':
  case '_':
  case '$':
    while ((tok >= 'a' && tok <= 'z')
           || (tok >= 'A' && tok <= 'Z')
           || (tok >= '0' && tok <= '9')
           || tok == '$'
           || tok == '_') {
      add_to_raw(tok);
      tok = stage4_getchar();
    }
    stage4_pushback();
    cur_val.kind = TOK_IDENT;
    cur_val.id.id = ident_put(rawbuf.str, rawbuf.u);
    return TOK_IDENT;

  case '\'':
    strterm = '\'';
    scanner_include_strings_flag = 0;
    goto do_read_string;
  case '\"':
    strterm = '\"';
  do_read_string:
    add_to_raw(tok);
    while (tok) {
      tok = stage4_getchar();
      if (tok < 0) {
        // FIXME: report unexpected EOF
        break;
      }
      if (tok == strterm) {
        add_to_raw(tok);
        break;
      }
      if (tok != '\\') {
        add_to_raw(tok);
        add_to_val(tok);
        continue;
      }

      if (scanner_include_strings_flag) {
        add_to_raw(tok);
        add_to_val(tok);
        continue;
      }

      /* handle escape sequence */
      tok2 = stage4_getchar();
      if (tok2 < 0) {
        // FIXME: report unexpected EOF
        // silently ignore dangling '\\'
        add_to_raw('\\');
        continue;
      }
      switch (tok2) {
      case 'a':   tok3 = '\a'; goto read_simple_esc_seq;
      case 'b':   tok3 = '\b'; goto read_simple_esc_seq;
      case 'f':   tok3 = '\f'; goto read_simple_esc_seq;
      case 'n':   tok3 = '\n'; goto read_simple_esc_seq;
      case 'r':   tok3 = '\r'; goto read_simple_esc_seq;
      case 't':   tok3 = '\t'; goto read_simple_esc_seq;
      case 'v':   tok3 = '\v'; goto read_simple_esc_seq;
      case '\'':  tok3 = '\''; goto read_simple_esc_seq;
      case '\"':  tok3 = '\"'; goto read_simple_esc_seq;
      case '\\': 
        tok3 = '\\';
      read_simple_esc_seq:
        add_to_raw(tok);
        add_to_raw(tok2);
        add_to_val(tok3);
        continue;

      case '0'...'7':
        add_to_raw(tok);
        tok = tok2;
        tok2 = stage4_getchar();
        if (tok2 < '0' || tok2 > '7') {
          stage4_pushback();
          add_to_raw(tok);
          add_to_val(tok - '0');
          continue;
        }
        if (tok > '3') {
          add_to_raw(tok);
          add_to_raw(tok2);
          add_to_val((tok - '0') * 8 + (tok2 - '0'));
          continue;
        }
        tok3 = stage4_getchar();
        if (tok3 < '0' || tok3 > '7') {
          stage4_pushback();
          add_to_raw(tok);
          add_to_raw(tok2);
          add_to_val((tok - '0') * 8 + (tok2 - '0'));
          continue;
        }
        add_to_raw(tok);
        add_to_raw(tok2);
        add_to_raw(tok3);
        add_to_val((tok - '0') * 64 + (tok2 - '0') * 8 + (tok2 - '0'));
        continue;

      case 'x': case 'X':
        tok3 = stage4_getchar();
        if (!isxdigit(tok3)) {
          // FIXME: invalid escape sequence
          stage4_pushback();
          add_to_raw(tok);
          add_to_raw(tok2);
          add_to_val(tok2);
          continue;
        }
        tok = tok2;
        tok2 = tok3;
        tok3 = stage4_getchar();
        if (!isxdigit(tok3)) {
          stage4_pushback();
          add_to_raw('\\');
          add_to_raw(tok);
          add_to_raw(tok2);
          add_to_val(hex2int(tok2));
          continue;
        }
        add_to_raw('\\');
        add_to_raw(tok);
        add_to_raw(tok2);
        add_to_raw(tok3);
        add_to_val(hex2int(tok2) * 16 + hex2int(tok3));
        continue;

      default:
        // FIXME: invalid escape sequence
        add_to_raw(tok);
        add_to_raw(tok2);
      }
    }
    if (strterm == '\'') {
      cur_val.kind = TOK_CONSTANT;
      cur_val.val.raw.size = rawbuf.u;
      cur_val.val.raw.str = rawbuf.str;
      cur_val.val.val.tag = C_INT;
      cur_val.val.val.v.ct_int = 0;
      if (valbuf.u < 1) {
        // FIXME: empty character literal
      } else {
        if (valbuf.u > 1) {
          // FIXME: multibyte character literal
        }
        val = 0;
        for (i = 0; i < valbuf.u; i++)
          val = (val << 8) | (valbuf.str[i]);
        cur_val.val.val.v.ct_int = val;
      }
      return TOK_CONSTANT;
    }
    cur_val.kind = TOK_STRING;
    cur_val.str.val.size = valbuf.u;
    cur_val.str.val.str = valbuf.str;
    cur_val.str.raw.size = rawbuf.u;
    cur_val.str.raw.str = rawbuf.str;
    return TOK_STRING;

  case '.':
    add_to_raw(tok);
    tok = stage4_getchar();
    if (tok == '.') {
      tok = stage4_getchar();
      if (tok == '.') {
        cur_val.kind = TOK_ELLIPSIS;
        return TOK_ELLIPSIS;
      }
      stage4_pushback();
      stage4_pushback();
      cur_val.kind = '.';
      return '.';
    } else if (tok >= '0' && tok <= '9') {
      while (tok >= '0' && tok <= '9') {
        add_to_raw(tok);
        tok = stage4_getchar();
      }
      if (tok == 'e' || tok == 'E') {
        add_to_raw(tok);
        tok = stage4_getchar();
        if (tok == '+' || tok == '-') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
        if (tok < '0' || tok > '9') {
          stage4_pushback();
          cur_val.kind = TOK_UNKNOWN;
          cur_val.sp.raw.size = rawbuf.u;
          cur_val.sp.raw.str = rawbuf.str;
          return TOK_UNKNOWN;
        }
        while (tok >= '0' && tok <= '9') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
      }
      i = rawbuf.u;
      flags = read_float_suffix(tok);
      return handle_float(0, i, 10, flags);
    } else {
      stage4_pushback();
      cur_val.kind = '.';
      return '.';
    }

  case '0':
    add_to_raw(tok);
    tok = stage4_getchar();
    if (tok == 'x' || tok == 'X') {
      add_to_raw(tok);
      tok = stage4_getchar();
      if (!isxdigit(tok)) {
        stage4_pushback();
        cur_val.kind = TOK_UNKNOWN;
        cur_val.sp.raw.size = rawbuf.u;
        cur_val.sp.raw.str = rawbuf.str;
        return TOK_UNKNOWN;
      }
      while (isxdigit(tok)) {
        add_to_raw(tok);
        tok = stage4_getchar();
      }
      if (tok == '.' || tok == 'p' || tok == 'P') {
        if (tok == '.') {
          add_to_raw(tok);
          tok = stage4_getchar();
          while (isxdigit(tok)) {
            add_to_raw(tok);
            tok = stage4_getchar();
          }
          if (tok != 'p' && tok != 'P') {
            stage4_pushback();
            cur_val.kind = TOK_UNKNOWN;
            cur_val.sp.raw.size = rawbuf.u;
            cur_val.sp.raw.str = rawbuf.str;
            return TOK_UNKNOWN;
          }
        }
        add_to_raw(tok);
        tok = stage4_getchar();
        if (tok == '+' || tok == '-') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
        if (tok < '0' || tok > '9') {
          stage4_pushback();
          cur_val.kind = TOK_UNKNOWN;
          cur_val.sp.raw.size = rawbuf.u;
          cur_val.sp.raw.str = rawbuf.str;
          return TOK_UNKNOWN;
        }
        while (tok >= '0' && tok <= '9') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
        i = rawbuf.u;
        flags = read_float_suffix(tok);
        return handle_float(0, i, 16, flags);
      }
      i = rawbuf.u;
      flags = read_int_suffix(tok);
      cur_val.val.raw.size = rawbuf.u;
      cur_val.val.raw.str = rawbuf.str;
      cur_val.kind = TOK_CONSTANT;
      return handle_integral(2, i - 2, 16, flags);
    }

    // octal literal
    while (tok >= '0' && tok <= '7') {
      add_to_raw(tok);
      tok = stage4_getchar();
    }
    if (tok == '.' || tok == 'e' || tok == 'E' || tok == '8' || tok == '9'
        || tok == 'f' || tok == 'F'
        || tok == 'i' || tok == 'I' || tok == 'j' || tok == 'J') {
      while (tok >= '0' && tok <= '9') {
        add_to_raw(tok);
        tok = stage4_getchar();
      }
      if (tok != '.' && tok != 'e' && tok != 'E' && tok != 'f' && tok != 'F'
          && tok != 'l' && tok != 'L'
          && tok != 'i' && tok != 'I' && tok != 'j' && tok != 'J') {
        stage4_pushback();
        cur_val.kind = TOK_UNKNOWN;
        cur_val.sp.raw.size = rawbuf.u;
        cur_val.sp.raw.str = rawbuf.str;
        return TOK_UNKNOWN;
      }
      if (tok == '.') {
        add_to_raw(tok);
        tok = stage4_getchar();
        while (tok >= '0' && tok <= '9') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
      }
      if (tok == 'e' || tok == 'E') {
        add_to_raw(tok);
        tok = stage4_getchar();
        if (tok == '+' || tok == '-') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
        if (tok < '0' || tok > '9') {
          stage4_pushback();
          cur_val.kind = TOK_UNKNOWN;
          cur_val.sp.raw.size = rawbuf.u;
          cur_val.sp.raw.str = rawbuf.str;
          return TOK_UNKNOWN;
        }
        while (tok >= '0' && tok <= '9') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
      }
      i = rawbuf.u;
      flags = read_float_suffix(tok);
      return handle_float(0, i, 10, flags);
    }
    i = rawbuf.u;
    flags = read_int_suffix(tok);
    cur_val.val.raw.size = rawbuf.u;
    cur_val.val.raw.str = rawbuf.str;
    cur_val.kind = TOK_CONSTANT;
    return handle_integral(0, i, 8, flags);

  case '1'...'9':
    add_to_raw(tok);
    tok = stage4_getchar();
    while (tok >= '0' && tok <= '9') {
      add_to_raw(tok);
      tok = stage4_getchar();
    }
    if (tok == '.' || tok == 'e' || tok == 'E' || tok == 'f' || tok == 'F'
        || tok == 'i' || tok == 'I' || tok == 'j' || tok == 'J') {
      if (tok == '.') {
        add_to_raw(tok);
        tok = stage4_getchar();
        while (tok >= '0' && tok <= '9') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
      }
      if (tok == 'e' || tok == 'E') {
        add_to_raw(tok);
        tok = stage4_getchar();
        if (tok == '+' || tok == '-') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
        if (tok < '0' || tok > '9') {
          stage4_pushback();
          cur_val.kind = TOK_UNKNOWN;
          cur_val.sp.raw.size = rawbuf.u;
          cur_val.sp.raw.str = rawbuf.str;
          return TOK_UNKNOWN;
        }
        while (tok >= '0' && tok <= '9') {
          add_to_raw(tok);
          tok = stage4_getchar();
        }
      }
      i = rawbuf.u;
      flags = read_float_suffix(tok);
      cur_val.val.raw.size = rawbuf.u;
      cur_val.val.raw.str = rawbuf.str;
      cur_val.kind = TOK_CONSTANT;
      return handle_float(0, i, 10, flags);
    }
    i = rawbuf.u;
    flags = read_int_suffix(tok);
    cur_val.val.raw.size = rawbuf.u;
    cur_val.val.raw.str = rawbuf.str;
    cur_val.kind = TOK_CONSTANT;
    return handle_integral(0, i, 10, flags);

  case '<':
    if (scanner_include_strings_flag) {
      strterm = '>';
      goto do_read_string;
    }
    tok2 = stage4_getchar();
    if (tok2 == '=') {
      return (cur_val.kind = TOK_LEQ);
    } else if (tok2 == '<') {
      tok3 = stage4_getchar();
      if (tok3 == '=') {
        return (cur_val.kind = TOK_LSHASSIGN);
      } else {
        stage4_pushback();
        return (cur_val.kind = TOK_LSHIFT);
      }
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '>':
    tok2 = stage4_getchar();
    if (tok2 == '=') {
      return (cur_val.kind = TOK_GEQ);
    } else if (tok2 == '>') {
      tok3 = stage4_getchar();
      if (tok3 == '=') {
        return (cur_val.kind = TOK_RSHASSIGN);
      } else {
        stage4_pushback();
        return (cur_val.kind = TOK_RSHIFT);
      }
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '-':
    tok2 = stage4_getchar();
    switch (tok2) {
    case '-': return (cur_val.kind = TOK_DECR);
    case '=': return (cur_val.kind = TOK_SUBASSIGN);
    case '>': return (cur_val.kind = TOK_ARROW);
    default:
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '+':
    tok2 = stage4_getchar();
    if (tok2 == '+') {
      return (cur_val.kind = TOK_INCR);
    } else if (tok2 == '=') {
      return (cur_val.kind = TOK_ADDASSIGN);
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '&':
    tok2 = stage4_getchar();
    if (tok2 == '&') {
      return (cur_val.kind = TOK_LOGAND);
    } else if (tok2 == '=') {
      return (cur_val.kind = TOK_ANDASSIGN);
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '|':
    tok2 = stage4_getchar();
    if (tok2 == '|') {
      return (cur_val.kind = TOK_LOGOR);
    } else if (tok2 == '=') {
      return (cur_val.kind = TOK_ORASSIGN);
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '=':
    tok2 = stage4_getchar();
    if (tok2 == '=') {
      return (cur_val.kind = TOK_EQ);
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '!':
    tok2 = stage4_getchar();
    if (tok2 == '=') {
      return (cur_val.kind = TOK_NEQ);
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '*':
    tok2 = stage4_getchar();
    if (tok2 == '=') {
      return (cur_val.kind = TOK_MULASSIGN);
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '%':
    tok2 = stage4_getchar();
    if (tok2 == '=') {
      return (cur_val.kind = TOK_MODASSIGN);
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '^':
    tok2 = stage4_getchar();
    if (tok2 == '^') {
      return (cur_val.kind = TOK_LOGXOR);
    } else if (tok2 == '=') {
      return (cur_val.kind = TOK_XORASSIGN);
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case '#':
    tok2 = stage4_getchar();
    if (tok2 == '#') {
      return (cur_val.kind = TOK_PASTE);
    } else {
      stage4_pushback();
      return (cur_val.kind = tok);
    }

  case ';':
  case ',':
  case '{':
  case '}':
  case ':':
  case '(':
  case ')':
  case '[':
  case ']':
  case '?':
  case '~':
    return (cur_val.kind = tok);

    /* set unknown token type */
  default:
    add_to_raw(tok);
    cur_val.kind = TOK_UNKNOWN;
    cur_val.sp.raw.size = rawbuf.u;
    cur_val.sp.raw.str = rawbuf.str;
    return TOK_UNKNOWN;
  }
}

#if 0
static void
my_c_value_print(c_value_t *val, FILE *f)
{
  int tag = val->tag;
  ASSERT(tag >= C_FIRST_ARITH && tag <= C_LAST_ARITH);
  switch (tag)
    {
    case C_CHAR:
      fprintf(f, "(%s)%d", c_builtin_str(tag), val->v.ct_char);
      break;
    case C_SCHAR:
      fprintf(f, "(%s)%d", c_builtin_str(tag), val->v.ct_schar);
      break;
    case C_UCHAR:
      fprintf(f,"(%s)%u", c_builtin_str(tag), val->v.ct_uchar);
      break;
    case C_SHORT:
      fprintf(f, "(%s)%d", c_builtin_str(tag), val->v.ct_short);
      break;
    case C_USHORT:
      fprintf(f, "(%s)%u", c_builtin_str(tag), val->v.ct_ushort);
      break;
    case C_INT:
      fprintf(f, "(%s)%d", c_builtin_str(tag), val->v.ct_int);
      break;
    case C_UINT:
      fprintf(f, "(%s)%u", c_builtin_str(tag), val->v.ct_uint);
      break;
    case C_LONG:
      fprintf(f, "(%s)%ld", c_builtin_str(tag), val->v.ct_lint);
      break;
    case C_ULONG:
      fprintf(f, "(%s)%lu", c_builtin_str(tag), val->v.ct_ulint);
      break;
    case C_LLONG:
      fprintf(f, "(%s)%lld", c_builtin_str(tag), val->v.ct_llint);
      break;
    case C_ULLONG:
      fprintf(f, "(%s)%llu", c_builtin_str(tag), val->v.ct_ullint);
      break;
    case C_FLOAT:
      fprintf(f, "(%s)%f", c_builtin_str(tag), val->v.ct_float);
      break;
    case C_DOUBLE:
      fprintf(f, "(%s)%f", c_builtin_str(tag), val->v.ct_double);
      break;
    case C_LDOUBLE:
      fprintf(f, "(%s)%Lf", c_builtin_str(tag), val->v.ct_ldouble);
      break;
    default:
      SWERR(("bad val->tag"));
    }
}
#endif

static unsigned char *
escape_buf(const unsigned char *buf, size_t size)
{
  int out_len = 3;
  int i;
  unsigned char *out, *s;

  // estimate output buffer length
  for (i = 0; i < size; i++) {
    if (buf[i] < ' ') out_len += 4;
    else out_len += 2;
  }
  out = (unsigned char *) xmalloc(out_len + 5);
  s = out;
  *s++ = '\"';
  for (i = 0; i < size; i++) {
    switch (buf[i]) {
    case '\a': *s++ = '\\'; *s++ = 'a';  break;
    case '\b': *s++ = '\\'; *s++ = 'b';  break;
    case '\f': *s++ = '\\'; *s++ = 'f';  break;
    case '\n': *s++ = '\\'; *s++ = 'n';  break;
    case '\r': *s++ = '\\'; *s++ = 'r';  break;
    case '\t': *s++ = '\\'; *s++ = 't';  break;
    case '\v': *s++ = '\\'; *s++ = 'v';  break;
    case '\'': *s++ = '\\'; *s++ = '\''; break;
    case '\"': *s++ = '\\'; *s++ = '\"'; break;
    case '\\': *s++ = '\\'; *s++ = '\\'; break;
    case 0:    *s++ = '\\'; *s++ = '0';  break;
    default:
      if (buf[i] < ' ') {
        *s++ = '\\';
        *s++ = (buf[i] >> 6) + '0';
        *s++ = ((buf[i] & 070) >> 3) + '0';
        *s++ = (buf[i] & 07) + '0';
      } else {
        *s++ = buf[i];
      }
    }
  }
  *s++ = '\"';
  *s = 0;
  return out;
}

static unsigned char *
escape_string(const unsigned char *str)
{
  return escape_buf(str, strlen(str));
}

static void
strip_trailing_ws(bufstring_t *bs)
{
  while (bs->u > 0 && bs->str[bs->u - 1] <= ' ') {
    bs->str[--bs->u] = 0;
  }
}

static void
add_token_to_bufstring(int tok, token_t *pattr, bufstring_t *bs)
{
  char buf[1];
  unsigned char *s;

  if (tok <= 0) return;
  if (tok < 256) {
    buf[0] = tok;
    add_to_bufstring(bs, buf, 1);
    return;
  }
  if (tok >= TOK_INCR && tok <= TOK_PASTE_VA) {
    add_to_bufstring(bs, token_strings[tok], strlen(token_strings[tok]));
    return;
  }
  switch (tok) {
  case TOK_IDENT_NE:
  case TOK_IDENT:
    s = ident_get(pattr->id.id);
    add_to_bufstring(bs, s, strlen(s));
    return;
  case TOK_CONSTANT:
    add_to_bufstring(bs, pattr->val.raw.str, pattr->val.raw.size);
    return;
  case TOK_STRING:
  case TOK_ANNOT:
    add_to_bufstring(bs, pattr->str.raw.str, pattr->str.raw.size);
    return;
  case TOK_SPACE:
  case TOK_UNKNOWN:
  case TOK_NL:
    add_to_bufstring(bs, pattr->sp.raw.str, pattr->sp.raw.size);
    return;
  default:
    SWERR(("unhandled token type: %d", tok));
  }
}

static void
write_token(int tok, token_t *pattr, FILE *out)
{
  if (tok <= 0) return;
  if (tok < 256) {
    putc(tok, out);
    return;
  }
  if (tok >= TOK_INCR && tok <= TOK_PASTE_VA) {
    fputs(token_strings[tok], out);
    return;
  }
  switch (tok) {
  case TOK_IDENT_NE:
    fprintf(out, "%s", ident_get(pattr->id.id));
    return;
  case TOK_IDENT:
    fputs(ident_get(pattr->id.id), out);
    return;
  case TOK_CONSTANT:
    fwrite(pattr->val.raw.str, 1, pattr->val.raw.size, out);
    return;
  case TOK_STRING:
  case TOK_ANNOT:
    fwrite(pattr->str.raw.str, 1, pattr->str.raw.size, out);
    return;
  case TOK_SPACE:
  case TOK_UNKNOWN:
  case TOK_NL:
    fwrite(pattr->sp.raw.str, 1, pattr->sp.raw.size, out);
    return;
  default:
    SWERR(("unhandled token type: %d", tok));
  }
}

static void
dup_token(token_t *out, const token_t *in)
{
  *out = *in;
  switch (in->kind) {
  case TOK_CONSTANT:
  case TOK_ANNOT:
    out->val.raw.str = xmemdup(in->val.raw.str, in->val.raw.size + 1);
    break;
  case TOK_STRING:
    out->str.val.str = xmemdup(in->str.val.str, in->str.val.size + 1);
    out->str.raw.str = xmemdup(in->str.raw.str, in->str.raw.size + 1);
    break;
  case TOK_SPACE:
  case TOK_UNKNOWN:
  case TOK_NL:
    out->sp.raw.str = xmemdup(in->sp.raw.str, in->sp.raw.size + 1);
    break;
  }
}

static void
undup_token(token_t *tok)
{
  cur_val = *tok;
  switch (tok->kind) {
  case TOK_CONSTANT:
  case TOK_ANNOT:
    rawbuf.u = tok->val.raw.size;
    memcpy(rawbuf.str, tok->val.raw.str, rawbuf.u);
    cur_val.val.raw.str = rawbuf.str;
    break;
  case TOK_STRING:
    rawbuf.u = tok->str.raw.size;
    memcpy(rawbuf.str, tok->str.raw.str, rawbuf.u);
    cur_val.str.raw.str = rawbuf.str;
    valbuf.u = tok->str.val.size;
    memcpy(valbuf.str, tok->str.val.str, rawbuf.u);
    cur_val.str.val.str = valbuf.str;
    break;
  case TOK_SPACE:
  case TOK_UNKNOWN:
  case TOK_NL:
    rawbuf.u = tok->sp.raw.size;
    memcpy(rawbuf.str, tok->sp.raw.str, rawbuf.u);
    cur_val.sp.raw.str = rawbuf.str;
    break;
  }
}

static void
free_token(token_t *ptok)
{
  switch (ptok->kind) {
  case TOK_CONSTANT:
  case TOK_ANNOT:
    xfree(ptok->val.raw.str);
    break;
  case TOK_STRING:
    xfree(ptok->str.val.str);
    xfree(ptok->str.raw.str);
    break;
  case TOK_SPACE:
  case TOK_UNKNOWN:
  case TOK_NL:
    xfree(ptok->sp.raw.str);
    break;
  }
  memset(ptok, 0, sizeof(*ptok));
}

static int
compare_tokens(token_t *p1, token_t *p2)
{
  if (p1->kind != p2->kind) return 0;
  switch (p1->kind) {
  case TOK_IDENT:
    return (p1->id.id == p2->id.id);
  case TOK_CONSTANT:
  case TOK_ANNOT:
    return !memcmp(p1->val.raw.str, p2->val.raw.str, p2->val.raw.size);
  case TOK_STRING:
    return !memcmp(p1->str.raw.str, p2->str.raw.str, p2->str.raw.size);
  case TOK_UNKNOWN:
    return !memcmp(p1->sp.raw.str, p2->sp.raw.str, p2->sp.raw.size);
  }
  return 1;
}

enum
{
  ID_DEFINE = 1,
  ID_DEFINED,
  ID_ELIF,
  ID_ELSE,
  ID_ENDIF,
  ID_ERROR,
  ID_IDENT,
  ID_IF,
  ID_IFDEF,
  ID_IFNDEF,
  ID_INCLUDE,
  ID_LINE,
  ID_PRAGMA,
  ID_UNDEF,
  ID_WARNING,
  ID___LINE__,
  ID___FILE__,
  ID___VA_ARGS__,
  ID_DEFCONST,
};

/* whether tokens should be written to the output */
static int output_enabled;

static strarray_t file_names;
static unsigned char *
add_to_file_names(const unsigned char *path)
{
  int i;

  for (i = 0; i < file_names.u; i++)
    if (!strcmp(path, file_names.v[i]))
      break;
  if (i <  file_names.u)
    return file_names.v[i];
  xexpand(&file_names);
  return (file_names.v[file_names.u++] = xstrdup(path));
}

/* macro expansion contexts */
enum
{
  CNTX_REG = 0,
  CNTX_IF,                      /* macroexpansion inside #if */
};

typedef struct toklist_item_struct
{
  struct toklist_item_struct *next;
  int par_ind;
  token_t tok;
} toklist_item_t;

typedef struct macrodef_struct
{
  ident_t id;
  int index;
  unsigned char *def_file;
  int def_line;
  int par_num;
  int is_variadic;
  int is_predefined;
  ident_t *params;
  unsigned char *no_prescan;
  toklist_item_t *tokens;
  toklist_item_t *if_tokens;
  int (*expand_function)(struct macrodef_struct *, int, toklist_item_t **,
                         toklist_item_t **);
} macrodef_t;

static void
free_toklist(toklist_item_t *p)
{
  toklist_item_t *q;

  while (p) {
    q = p->next;
    free_token(&p->tok);
    xfree(p);
    p = q;
  }
}

static void
free_macrodef(macrodef_t *pdef)
{
  xfree(pdef->params);
  free_toklist(pdef->tokens);
  free_toklist(pdef->if_tokens);
  memset(pdef, 0, sizeof(*pdef));
  xfree(pdef);
}

static int
compare_macrodefs(macrodef_t *p1, macrodef_t *p2)
{
  int i;
  toklist_item_t *pt1, *pt2;

  if (p1->id != p2->id) return 0;
  if (p1->par_num != p2->par_num) return 0;
  if (p1->is_variadic != p2->is_variadic) return 0;
  for (i = 0; i < p1->par_num; i++)
    if (p1->params[i] != p2->params[i])
      return 0;
  for (pt1 = p1->tokens, pt2 = p2->tokens; pt1 && pt2;) {
    if (pt1->tok.kind == TOK_SPACE) {
      pt1 = pt1->next;
      continue;
    }
    if (pt2->tok.kind == TOK_SPACE) {
      pt2 = pt2->next;
      continue;
    }
    if (!compare_tokens(&pt1->tok, &pt2->tok)) return 0;
    pt1 = pt1->next;
    pt2 = pt2->next;
  }
  while (pt1 && pt1->tok.kind == TOK_SPACE) pt1 = pt1->next;
  while (pt2 && pt2->tok.kind == TOK_SPACE) pt2 = pt2->next;
  if (pt1 || pt2) return 0;
  return 1;
}

static toklist_item_t *pending_tokens;

static int get_pending_token(void)
{
  if (pending_tokens) {
    toklist_item_t *p;

    p = pending_tokens;
    pending_tokens = p->next;
    undup_token(&p->tok);
    free_token(&p->tok);
    xfree(p);
    return cur_val.kind;
  }
  return get_file_token();
}

#define HASH_OFFSET 509
static macrodef_t **define_table;
static size_t define_size;
static size_t define_thold;
static size_t define_used;

static macrodef_t *
put_to_define_table(ident_t id, macrodef_t *pdef)
{
  int i;
  macrodef_t *old_def = 0;

  if (!define_table) {
    define_size = 1024;
    define_thold = (int) (((double) define_size) * 0.7);
    define_table = (macrodef_t**)xcalloc(define_size, sizeof(define_table[0]));
  }
  if (define_used >= define_thold) {
    size_t new_size = define_size * 2;
    macrodef_t**new_table=(macrodef_t**)xcalloc(new_size,sizeof(new_table[0]));
    int j;

    for (j = 0; j < define_size; j++) {
      if (!define_table[j]) continue;
      i = define_table[j]->id % new_size;
      while (new_table[i]) i = (i + HASH_OFFSET) % new_size;
      new_table[i] = define_table[j];
      new_table[i]->index = i;
    }
    xfree(define_table);
    define_table = new_table;
    define_size = new_size;
    define_thold = (int) (((double) define_size) * 0.7);
  }

  i = id % define_size;
  while (define_table[i] && define_table[i]->id != id)
    i = (i + HASH_OFFSET) % define_size;
  if (define_table[i]) old_def = define_table[i];
  define_table[i] = pdef;
  pdef->index = i;
  define_used++;
  return old_def;
}

static macrodef_t *
remove_from_define_table(ident_t id)
{
  int i, remains, j, k;
  macrodef_t **saved_defs, *def;

  if (!define_size) return 0;
  i = id % define_size;
  while (define_table[i] && define_table[i]->id != id)
    i = (i + HASH_OFFSET) % define_size;
  if (!define_table[i]) return 0;
  def = define_table[i];

  remains = 0;
  j = id % define_size;
  while (define_table[j]) {
    if (j != i) remains++;
    j = (j + HASH_OFFSET) % define_size;
  }

  if (!remains) {
    define_table[i] = 0;
    define_used--;
    return def;
  }

  saved_defs = (macrodef_t**) alloca(remains * sizeof(saved_defs[0]));
  k = 0;
  j = id % define_size;
  while (define_table[j]) {
    if (i != j) saved_defs[k++] = define_table[j];
    define_table[j] = 0;
    j = (j + HASH_OFFSET) % define_size;
  }
  
  for (k = 0; k < remains; k++) {
    i = saved_defs[k]->id % define_size;
    while (define_table[i]) i = (i + HASH_OFFSET) % define_size;
    define_table[i] = saved_defs[k];
  }

  define_used--;
  return def;
}

static macrodef_t *
lookup_define_table(ident_t id)
{
  int i;

  if (!define_size) return 0;
  i = id % define_size;
  while (define_table[i] && define_table[i]->id != id)
    i = (i + HASH_OFFSET) % define_size;
  return define_table[i];
}

#if 0
static void
write_toklist(toklist_item_t *tok_list, FILE *out)
{
  toklist_item_t *p;

  fprintf(stderr, "toklist: ");
  for (p = tok_list; p; p = p->next) {
    fprintf(stderr, "(%d)<", p->tok.kind);
    write_token(p->tok.kind, &p->tok, stderr);
    fprintf(stderr, ">");
  }
  fprintf(stderr, "\n");
}
#endif

static toklist_item_t *
remove_space_tokens(toklist_item_t *ptok)
{
  toklist_item_t **pp = &ptok;
  toklist_item_t *p, *q = ptok;

  while (q) {
    if (q->tok.kind == TOK_SPACE) {
      p = q;
      q = p->next;
      *pp = q;
      p->next = 0;
      free_toklist(p);
    } else {
      pp = &q->next;
      q = *pp;
    }
  }
  return ptok;
}

static toklist_item_t *
read_tokens_to_list(FILE *out)
{
  toklist_item_t *tok_list = 0, **last_p = &tok_list, *new_tok;
  int c;

  while (1) {
    c = get_pending_token();
    if (!c) break;
    if (c == TOK_NL) {
      write_token(c, &cur_val, out);
      next_line(out);
      break;
    }
    new_tok = (toklist_item_t *) xcalloc(1, sizeof(*new_tok));
    dup_token(&new_tok->tok, &cur_val);
    *last_p = new_tok;
    last_p = &new_tok->next;
  }
  return tok_list;
}

static int
handle_directive_error(ident_t id, FILE *out)
{
  int c;
  bufstring_t bb;

  if (!output_enabled) return -1;

  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  init_bufstring(&bb);
  while (c != TOK_NL && c != 0) {
    add_token_to_bufstring(c, &cur_val, &bb);
    c = get_pending_token();
  }
  strip_trailing_ws(&bb);
  c_err("#error %s", bb.str);
  xfree(bb.str);
  if (c == TOK_NL) {
    write_token(c, &cur_val, out);
    next_line(out);
  }
  return 0;
}

static int
handle_directive_warning(ident_t id, FILE *out)
{
  int c;
  bufstring_t bb;

  if (!output_enabled) return -1;

  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  init_bufstring(&bb);
  while (c != TOK_NL && c != 0) {
    add_token_to_bufstring(c, &cur_val, &bb);
    c = get_pending_token();
  }
  strip_trailing_ws(&bb);
  c_warn("#warning %s", bb.str);
  xfree(bb.str);
  if (c == TOK_NL) {
    write_token(c, &cur_val, out);
    next_line(out);
  }
  return 0;
}

static int
handle_directive_pragma(ident_t direct_id, FILE *out)
{
  int c;
  bufstring_t bb;

  if (!output_enabled) return -1;

  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  init_bufstring(&bb);
  while (c != TOK_NL && c != 0) {
    add_token_to_bufstring(c, &cur_val, &bb);
    c = get_pending_token();
  }
  strip_trailing_ws(&bb);
  fprintf(out, "#%s ", ident_get(direct_id));
  fwrite(bb.str, 1, bb.u, out);
  xfree(bb.str);
  if (c == TOK_NL) {
    write_token(c, &cur_val, out);
    next_line(out);
  }
  return 0;
}

static int
handle_directive_line(ident_t id, FILE *out)
{
  unsigned char *new_path = 0;
  unsigned char *esc_str = 0;
  int new_line = 1, c;
  c_value_t line_val;

  if (!output_enabled) return -1;

  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  if (c != TOK_CONSTANT) goto invalid_line_directive;
  if (cur_val.val.val.tag<C_FIRST_INT || cur_val.val.val.tag > C_LAST_INT)
    goto invalid_line_directive;
  if (!c_value_fits(&cur_val.val.val, C_INT))
    goto invalid_line_directive;
  c_value_cast(&cur_val.val.val, C_INT, &line_val);
  new_line = line_val.v.ct_int;
  if (new_line <= 0) goto invalid_line_directive;
  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  if (c == TOK_STRING) {
    new_path = xmemdup(cur_val.str.val.str,cur_val.str.val.size);
    c = get_pending_token();
    while (c == TOK_SPACE) c = get_pending_token();
  }
  if (c != TOK_NL && c != 0) goto invalid_line_directive;
  if (!new_path) {
    new_path = xstrdup(files->path);
  }
  next_line(out);
  esc_str = escape_string(new_path);
  fprintf(out, "# %d %s\n", new_line, esc_str);
  xfree(files->path);
  xfree(esc_str);
  files->path = new_path;
  files->line = new_line;
  return 0;

 invalid_line_directive:
  c_err("invalid #line directive");
  xfree(new_path);
  return -1;
}

static int
handle_directive_define(ident_t id, FILE *out)
{
  int c, i;
  macrodef_t *pdef = 0;
  macrodef_t *old_def = 0;
  toklist_item_t **pplast;
  toklist_item_t *ptok, *prevtok, *q, *p;

  if (!output_enabled) return -1;

  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  if (c != TOK_IDENT) goto invalid_directive;

  if (cur_val.id.id == ID___VA_ARGS__) {
    c_err("macro `__VA_ARGS__' cannot be defined");
    return -1;
  }

  pdef = (macrodef_t*) xcalloc(1, sizeof(*pdef));
  pdef->id = cur_val.id.id;
  pdef->def_file = add_to_file_names(files->path);
  pdef->def_line = files->line;

  c = get_pending_token();
  if (c == '(') {
    ident_t *lpars;
    size_t lpar_a;
    size_t lpar_u;

    lpar_a = 16;
    lpar_u = 0;
    lpars = (ident_t*) alloca(lpar_a * sizeof(lpars[0]));

    while (1) {
      c = get_pending_token();
      while (c == TOK_SPACE) c = get_pending_token();
      if (c == ')' && !lpar_u) {
        break;
      } else if (c == TOK_IDENT) {
        if (cur_val.id.id == ID___VA_ARGS__) {
          c_err("identifier `__VA_ARGS__' cannot be used as macro parameter");
          return -1;
        }
        if (lpar_u >= lpar_a) {
          ident_t *new_lpars;

          new_lpars = (ident_t*) alloca((lpar_a *= 2) * sizeof(lpars[0]));
          memcpy(new_lpars, lpars, lpar_u * sizeof(lpars[0]));
          lpars = new_lpars;
        }
        lpars[lpar_u++] = cur_val.id.id;
        c = get_pending_token();
        while (c == TOK_SPACE) c = get_pending_token();
        if (c == TOK_ELLIPSIS) {
          pdef->is_variadic = 1;
          c = get_pending_token();
          while (c == TOK_SPACE) c = get_pending_token();
          if (c != ')') goto invalid_directive;
          break;
        }
        if (c == ')') break;
        if (c != ',') goto invalid_directive;
      } else if (c == TOK_ELLIPSIS) {
        pdef->is_variadic = 1;
        if (lpar_u >= lpar_a) {
          ident_t *new_lpars;

          new_lpars = (ident_t*) alloca((lpar_a *= 2) * sizeof(lpars[0]));
          memcpy(new_lpars, lpars, lpar_u * sizeof(lpars[0]));
          lpars = new_lpars;
        }
        lpars[lpar_u++] = ID___VA_ARGS__;
        c = get_pending_token();
        while (c == TOK_SPACE) c = get_pending_token();
        if (c != ')') goto invalid_directive;
        break;
      } else {
        goto invalid_directive;
      }
    }
    c = get_pending_token();

    if (lpar_u > 0) {
      pdef->par_num = lpar_u;
      pdef->params = (ident_t*) xmalloc(lpar_u * sizeof(lpars[0]));
      memcpy(pdef->params, lpars, lpar_u * sizeof(lpars[0]));
    }
  } else {
    pdef->par_num = -1;
  }

  while (c == TOK_SPACE) c = get_pending_token();

  // collect tokens
  pplast = &pdef->tokens;
  while (c != TOK_NL && c != 0) {
    ptok = (toklist_item_t*) xcalloc(1, sizeof(*ptok));
    dup_token(&ptok->tok, &cur_val);
    if (c == TOK_IDENT) {
      for (i = 0; i < pdef->par_num; i++)
        if (cur_val.id.id == pdef->params[i]) {
          ptok->par_ind = i + 1;
          break;
        }
      if (cur_val.id.id == ID___VA_ARGS__ && !pdef->is_variadic) {
        c_err("`__VA_ARGS__' can only be used in variadic macros");
      }
      if (cur_val.id.id == ID___VA_ARGS__ && !ptok->par_ind) {
        c_err("`__VA_ARGS__' can only be used in C99 variadic macros");
      }
    }
    *pplast = ptok;
    pplast = &ptok->next;
    c = get_pending_token();
  }

  // remove trailing spaces
  pplast = &pdef->tokens;
  ptok = pdef->tokens;
  while (ptok) {
    if (ptok->tok.kind != TOK_SPACE) pplast = &ptok->next;
    ptok = ptok->next;
  }
  free_toklist(*pplast);
  *pplast = 0;

  if (c == TOK_NL && out) {
    write_token(c, &cur_val, out);
    next_line(out);
  }

  old_def = put_to_define_table(pdef->id, pdef);
  if (old_def) {
    if (old_def->is_predefined) {
      c_warn2(pdef->def_file, pdef->def_line,
              "redefiniting predefined macro `%s'", ident_get(pdef->id));
    } else if (!compare_macrodefs(pdef, old_def)) {
      c_warn2(pdef->def_file, pdef->def_line,
              "macro `%s' redefined", ident_get(pdef->id));
      c_warn2(old_def->def_file, old_def->def_line,
              "this is the place of previous definition");
    }
    free_macrodef(old_def);
  }

  /* fix token paste operation for variadic parameter */
  if (pdef->is_variadic) {
    for (ptok = pdef->tokens; ptok; ptok = ptok->next) {
      if (ptok->tok.kind != ',') continue;
      for (q = ptok->next; q && q->tok.kind == TOK_SPACE; q = q->next);
      if (!q || q->tok.kind != TOK_PASTE) continue;
      for (p = q->next; p && p->tok.kind == TOK_SPACE; p = p->next);
      if (!p || p->tok.kind != TOK_IDENT || p->par_ind != pdef->par_num)
        continue;
      q->tok.kind = TOK_PASTE_VA;
    }
  }

  /* calculate prescan flags */
  if (pdef->par_num > 0) {
    pdef->no_prescan = (unsigned char *) xcalloc(pdef->par_num, 1);
    for (prevtok = 0, ptok = pdef->tokens;
         ptok;
         ptok = ptok->next) {
      if (ptok->tok.kind == TOK_SPACE) continue;
      if (ptok->tok.kind == '#') {
        for (q = ptok->next; q && q->tok.kind == TOK_SPACE; q = q->next);
        if (q && q->par_ind > 0) pdef->no_prescan[q->par_ind - 1] = 1;
      } else if (ptok->tok.kind == TOK_PASTE) {
        if (prevtok && prevtok->par_ind > 0)
          pdef->no_prescan[prevtok->par_ind - 1] = 1;
        for (q = ptok->next; q && q->tok.kind == TOK_SPACE; q = q->next);
        if (q && q->par_ind > 0) pdef->no_prescan[q->par_ind - 1] = 1;
      }
      prevtok = ptok;
    }
  }

#if 0
  fprintf(stderr, "Define information:\n");
  fprintf(stderr, "  id: %s\n", ident_get(pdef->id));
  fprintf(stderr, "  index: %d\n", pdef->index);
  fprintf(stderr, "  def_file: %s\n", pdef->def_file);
  fprintf(stderr, "  def_line: %d\n", pdef->def_line);
  fprintf(stderr, "  par_num: %d\n", pdef->par_num);
  fprintf(stderr, "  is_variadic: %d\n", pdef->is_variadic);
  for (i = 0; i < pdef->par_num; i++) {
    fprintf(stderr, "    param[%d]: %s, %d\n",
            i + 1, ident_get(pdef->params[i]), pdef->no_prescan[i]);
  }
  for (ptok = pdef->tokens; ptok; ptok = ptok->next) {
    fprintf(stderr, "    token (%d): <", ptok->par_ind);
    write_token(ptok->tok.kind, &ptok->tok, stderr);
    fprintf(stderr, ">\n");
  }
#endif

  return 0;

 invalid_directive:
  c_err("invalid #define directive");
  return -1;
}

static int
handle_directive_defconst(ident_t id, FILE *out)
{
  int c, i;
  macrodef_t *pdef = 0;
  macrodef_t *old_def = 0;
  toklist_item_t **pplast;
  toklist_item_t *ptok, *ntok;

  if (!output_enabled) return -1;

  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  if (c != TOK_IDENT) {
    c_err("invalid #defconst directive");
    return -1;
  }

  ntok = (toklist_item_t*) xcalloc(1, sizeof(*ntok));
  dup_token(&ntok->tok, &cur_val);

  if (cur_val.id.id == ID___VA_ARGS__) {
    c_err("macro `__VA_ARGS__' cannot be defined");
    return -1;
  }

  pdef = (macrodef_t*) xcalloc(1, sizeof(*pdef));
  pdef->id = cur_val.id.id;
  pdef->def_file = add_to_file_names(files->path);
  pdef->def_line = files->line;
  pdef->par_num = -1;
  pdef->tokens = ntok;

  c = get_pending_token();
  if (c == '(') {
    c_err("#defconst cannot define function macro");
    return -1;
  }

  while (c == TOK_SPACE) c = get_pending_token();

  // collect tokens
  pplast = &pdef->if_tokens;
  while (c != TOK_NL && c != 0) {
    if (c == '#') {
      c_err("# cannot be used inside #defconst");
      return -1;
    }
    if (c == TOK_PASTE) {
      c_err("## cannot be used inside #defconst");
      return -1;
    }

    ptok = (toklist_item_t*) xcalloc(1, sizeof(*ptok));
    dup_token(&ptok->tok, &cur_val);
    if (c == TOK_IDENT) {
      for (i = 0; i < pdef->par_num; i++)
        if (cur_val.id.id == pdef->params[i]) {
          ptok->par_ind = i + 1;
          break;
        }
      if (cur_val.id.id == ID___VA_ARGS__ && !pdef->is_variadic) {
        c_err("`__VA_ARGS__' can only be used in variadic macros");
      }
      if (cur_val.id.id == ID___VA_ARGS__ && !ptok->par_ind) {
        c_err("`__VA_ARGS__' can only be used in C99 variadic macros");
      }
    }
    *pplast = ptok;
    pplast = &ptok->next;
    c = get_pending_token();
  }

  // remove trailing spaces
  pplast = &pdef->if_tokens;
  ptok = pdef->if_tokens;
  while (ptok) {
    if (ptok->tok.kind != TOK_SPACE) pplast = &ptok->next;
    ptok = ptok->next;
  }
  free_toklist(*pplast);
  *pplast = 0;

  old_def = lookup_define_table(pdef->id);
  if (old_def) {
    if (old_def->is_predefined) {
      c_warn2(pdef->def_file, pdef->def_line,
              "redefiniting predefined macro `%s'", ident_get(pdef->id));
    } else if (!compare_macrodefs(pdef, old_def)) {
      c_warn2(pdef->def_file, pdef->def_line,
              "macro `%s' redefined", ident_get(pdef->id));
      c_warn2(old_def->def_file, old_def->def_line,
              "this is the place of previous definition");
    } else {
      c_warn2(pdef->def_file, pdef->def_line,
              "macro `%s' definition duplicated", ident_get(pdef->id));
      c_warn2(old_def->def_file, old_def->def_line,
              "this is the place of previous definition");
    }
    free_macrodef(pdef);
    if (c == TOK_NL && out) {
      write_token(c, &cur_val, out);
      next_line(out);
    }
    return 0;
  }
  old_def = put_to_define_table(pdef->id, pdef);
  ASSERT(!old_def);

  if (out) {
    fprintf(out, "%s = ", ident_get(pdef->id));
    for (ptok = pdef->if_tokens; ptok; ptok = ptok->next) {
      putc(' ', out);
      write_token(ptok->tok.kind, &ptok->tok, out);
    }
    fprintf(out, ",");
  }
  if (c == TOK_NL && out) {
    write_token(c, &cur_val, out);
    next_line(out);
  }

#if 0
  fprintf(stderr, "Define information:\n");
  fprintf(stderr, "  id: %s\n", ident_get(pdef->id));
  fprintf(stderr, "  index: %d\n", pdef->index);
  fprintf(stderr, "  def_file: %s\n", pdef->def_file);
  fprintf(stderr, "  def_line: %d\n", pdef->def_line);
  fprintf(stderr, "  par_num: %d\n", pdef->par_num);
  fprintf(stderr, "  is_variadic: %d\n", pdef->is_variadic);
  for (i = 0; i < pdef->par_num; i++) {
    fprintf(stderr, "    param[%d]: %s, %d\n",
            i + 1, ident_get(pdef->params[i]), pdef->no_prescan[i]);
  }
  for (ptok = pdef->if_tokens; ptok; ptok = ptok->next) {
    fprintf(stderr, "    token (%d): <", ptok->par_ind);
    write_token(ptok->tok.kind, &ptok->tok, stderr);
    fprintf(stderr, ">\n");
  }
#endif

  return 0;

}

static int
handle_directive_undef(ident_t id, FILE *out)
{
  int c;
  macrodef_t *mdef;

  if (!output_enabled) return -1;

  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  if (!c || c == TOK_NL) {
    if (c == TOK_NL && out) {
      write_token(c, &cur_val, out);
      next_line(out);
    }
    return 0;
  }
  if (c != TOK_IDENT) goto invalid_directive;

  if (cur_val.id.id == ID___VA_ARGS__) {
    c_err("macro `__VA_ARGS__' cannot be undefined");
    return -1;
  }

  mdef = remove_from_define_table(cur_val.id.id);
  if (mdef && mdef->is_predefined) {
    c_warn("undefining predefined macro `%s'", ident_get(cur_val.id.id));
  }
  if (mdef) free_macrodef(mdef);
  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  if (!c || c == TOK_NL) {
    write_token(c, &cur_val, out);
    next_line(out);
    return 0;
  }

 invalid_directive:
  c_err("invalid #undef directive");
  return -1;
}

static toklist_item_t *macroexpand_toklist(toklist_item_t *, idstack_t, int);
static void fix_path(unsigned char *);
static int process_file(unsigned char *in_path, FILE *in,
                        FILE *out, int is_system_header);

static int
handle_directive_include(ident_t id, FILE *out)
{
  int c, i, sys_flag;
  toklist_item_t *toks = 0, **last_p = &toks, *new_tok, *p;
  bufstring_t namebuf;
  bufstring_t pathbuf;
  FILE *fincl;
  unsigned char *esc_str;
  unsigned char *e_p = files->path;
  int e_l = files->line;

  if (!output_enabled) return -1;

  init_bufstring(&namebuf);
  scanner_include_strings_flag = 1;
  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  scanner_include_strings_flag = 0;
  if (!c || c == TOK_NL) goto invalid_directive;

  if (c == TOK_STRING) {
    // include <file> or include "file"
    add_token_to_bufstring(c, &cur_val, &namebuf);
    c = get_pending_token();
    while (c == TOK_SPACE) c = get_pending_token();
    if (c && c != TOK_NL) goto invalid_directive;
    if (c == TOK_NL) {
      write_token(c, &cur_val, out);
      next_line(out);
    }
    c = 0;
  } else {
    // read up to the end of line and macroexpand
    while (c && c != TOK_NL) {
      new_tok = (toklist_item_t *) xcalloc(1, sizeof(*new_tok));
      dup_token(&new_tok->tok, &cur_val);
      *last_p = new_tok;
      last_p = &new_tok->next;
      c = get_pending_token();
    }
    if (c == TOK_NL) {
      write_token(c, &cur_val, out);
      next_line(out);
    }
    c = 0;

    /* note, that the list of tokens does not contain '\n' */
    toks = macroexpand_toklist(toks, 0, 0);
    //toks = remove_enable_tokens(toks);

#if 0
    fprintf(stderr, ">>");
    for (new_tok = toks; new_tok; new_tok = new_tok->next) {
      fprintf(stderr, "<");
      write_token(new_tok->tok.kind, &new_tok->tok, stderr);
      fprintf(stderr, ">");
    }
    fprintf(stderr, "\n");
#endif

    /* check the include form and remove spaces around '<' and '>' */
    new_tok = toks;
    while (new_tok && new_tok->tok.kind == TOK_SPACE) {
      new_tok = new_tok->next;
    }
    if (!new_tok) {
      goto invalid_directive;
    } else if (new_tok->tok.kind == TOK_STRING) {
      add_token_to_bufstring(new_tok->tok.kind, &new_tok->tok, &namebuf);
      new_tok = new_tok->next;
      while (new_tok && new_tok->tok.kind == TOK_SPACE) {
        new_tok = new_tok->next;
      }
      if (new_tok) goto invalid_directive;
    } else if (new_tok->tok.kind == '<') {
      last_p = &new_tok->next;
      add_token_to_bufstring('<', &new_tok->tok, &namebuf);
      new_tok = new_tok->next;
      while (new_tok && new_tok->tok.kind == TOK_SPACE) {
        new_tok = new_tok->next;
      }
      if (new_tok && new_tok->tok.kind != '>') {
        last_p = &new_tok->next;
      }
      if (!new_tok) goto invalid_directive;
      while (1) {
        if (!new_tok) goto invalid_directive;
        if (new_tok->tok.kind == '>') break;
        if (new_tok->tok.kind != TOK_SPACE) {
          if (last_p != &new_tok->next) {
            for (p = *last_p; p != new_tok; p = p->next)
              if (p->tok.kind == TOK_SPACE)
                add_token_to_bufstring(p->tok.kind, &p->tok, &namebuf);
          }
          add_token_to_bufstring(new_tok->tok.kind, &new_tok->tok, &namebuf);
          last_p = &new_tok->next;
        }
        new_tok = new_tok->next;
      }
      add_token_to_bufstring('>', &new_tok->tok, &namebuf);
      new_tok = new_tok->next;
      while (new_tok && new_tok->tok.kind == TOK_SPACE) {
        new_tok = new_tok->next;
      }
      if (new_tok && new_tok->tok.kind != TOK_NL)
        goto invalid_directive;
    } else {
      goto invalid_directive;
    }
  }

  free_toklist(toks);
  /* namebuf contains the string to include */
  //fprintf(stderr, "#include %s\n", namebuf.str);

  ASSERT(namebuf.u >= 2);
  fix_path(namebuf.str);
  pathbuf.u = strlen(namebuf.str + 1);

  init_bufstring(&pathbuf);
  sys_flag = 0;
  fincl = 0;
  while (1) {
    if (namebuf.str[1] == '/') {
      pathbuf.str[0] = 0;
      pathbuf.u = 0;
      add_to_bufstring(&pathbuf, &namebuf.str[1], namebuf.u - 2);
      fincl = fopen(pathbuf.str, "rb");
      break;
    }
    if (namebuf.str[0] == '\"') {
      // search in the directory of the current file
      pathbuf.str[0] = 0;
      pathbuf.u = 0;
      if (strchr(files->path, '/')) {
        unsigned char *dn = os_DirName(files->path);
        add_to_bufstring(&pathbuf, dn, strlen(dn));
        add_to_bufstring(&pathbuf, "/", 1);
        xfree(dn);
      }
      add_to_bufstring(&pathbuf, &namebuf.str[1], namebuf.u - 2);
      fincl = fopen(pathbuf.str, "rb");
      if (fincl) break;
    }

    for (i = 0; i < incl_dirs.u; i++) {
      pathbuf.str[0] = 0;
      pathbuf.u = 0;
      add_to_bufstring(&pathbuf, incl_dirs.v[i], strlen(incl_dirs.v[i]));
      add_to_bufstring(&pathbuf, "/", 1);
      add_to_bufstring(&pathbuf, &namebuf.str[1], namebuf.u - 2);
      fincl = fopen(pathbuf.str, "rb");
      if (fincl) break;
    }
    if (i < incl_dirs.u) break;

    sys_flag = 1;
    for (i = 0; i < sys_incl_dirs.u; i++) {
      pathbuf.str[0] = 0;
      pathbuf.u = 0;
      add_to_bufstring(&pathbuf,
                       sys_incl_dirs.v[i], strlen(sys_incl_dirs.v[i]));
      add_to_bufstring(&pathbuf, "/", 1);
      add_to_bufstring(&pathbuf, &namebuf.str[1], namebuf.u - 2);
      fincl = fopen(pathbuf.str, "rb");
      if (fincl) break;
    }
    if (i < sys_incl_dirs.u) break;

    for (i = 0; i < warn_incl_dirs.u; i++) {
      pathbuf.str[0] = 0;
      pathbuf.u = 0;
      add_to_bufstring(&pathbuf,
                       warn_incl_dirs.v[i], strlen(warn_incl_dirs.v[i]));
      add_to_bufstring(&pathbuf, "/", 1);
      add_to_bufstring(&pathbuf, &namebuf.str[1], namebuf.u - 2);
      fincl = fopen(pathbuf.str, "rb");
      if (fincl) break;
    }
    if (fincl) {
      c_warn("including foreign header file `%s'", pathbuf.str);
    }
    break;
  }

  if (fincl) {
    process_file(pathbuf.str, fincl, out, sys_flag);
    if (fincl) fclose(fincl);
    esc_str = escape_string(files->path);
    fprintf(out, "# %d %s 2\n", files->line, esc_str);
    xfree(esc_str);
  } else {
    pathbuf.str[0] = 0;
    pathbuf.u = 0;
    add_to_bufstring(&pathbuf, &namebuf.str[1], namebuf.u - 2);
    c_err2(e_p, e_l, "%s: No such file or directory", pathbuf.str);
  }

  xfree(pathbuf.str);

  xfree(namebuf.str);
  return 0;

 invalid_directive:
  xfree(namebuf.str);
  free_toklist(toks);
  c_err2(e_p, e_l, "invalid #include directive");
  if (c == TOK_NL) {
    write_token(c, &cur_val, out);
    next_line(out);
    return 0;
  }
  return -1;
}

static toklist_item_t *expr_list;
static toklist_item_t *expr_tok;
static const unsigned char *expr_f;
static int expr_l;

static int parse_conditional_expr(int need_eval, long long *pres);
static int parse_logical_OR_expr(int need_eval, long long *pres);
static int parse_logical_AND_expr(int need_eval, long long *pres);
static int parse_OR_expr(int need_eval, long long *pres);
static int parse_XOR_expr(int need_eval, long long *pres);
static int parse_AND_expr(int need_eval, long long *pres);
static int parse_equality_expr(int need_eval, long long *pres);
static int parse_relational_expr(int need_eval, long long *pres);
static int parse_shift_expr(int need_eval, long long *pres);
static int parse_additive_expr(int need_eval, long long *pres);
static int parse_multiplicative_expr(int need_eval, long long *pres);
static int parse_unary_expr(int need_eval, long long *pres);
static int parse_primary_expr(int need_eval, long long *pres);

static int
parse_expression(toklist_item_t *tlist, int need_eval, long long *pres)
{
  expr_list = tlist;
  expr_tok = tlist;
  if (parse_conditional_expr(need_eval, pres) < 0) return -1;
  if (expr_tok) return -1;
  return 0;
}

static int
parse_conditional_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0, v3 = 0;

  if (parse_logical_OR_expr(need_eval, &v1) < 0) return -1;
  if (!expr_tok || expr_tok->tok.kind != '?') {
    if (need_eval) *pres = v1;
    return 0;
  }
  expr_tok = expr_tok->next;
  if (parse_conditional_expr(need_eval && v1, &v2) < 0) return -1;
  if (!expr_tok || expr_tok->tok.kind != ':') return -1;
  expr_tok = expr_tok->next;
  if (parse_conditional_expr(need_eval && !v1, &v3) < 0) return -1;
  if (need_eval) {
    if (v1) *pres = v2;
    else *pres = v3;
  }
  return 0;
}

static int
parse_logical_OR_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;

  if (parse_logical_AND_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok && expr_tok->tok.kind == TOK_LOGOR) {
    expr_tok = expr_tok->next;
    if (parse_logical_AND_expr(need_eval && !v1, &v2) < 0) return -1;
    if (need_eval) v1 = (v1 || v2);
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_logical_AND_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;

  if (parse_OR_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok && expr_tok->tok.kind == TOK_LOGAND) {
    expr_tok = expr_tok->next;
    if (parse_OR_expr(need_eval && v1, &v2) < 0) return -1;
    if (need_eval) v1 = (v1 && v2);
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_OR_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;

  if (parse_XOR_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok && expr_tok->tok.kind == '|') {
    expr_tok = expr_tok->next;
    if (parse_XOR_expr(need_eval, &v2) < 0) return -1;
    if (need_eval) v1 = v1 | v2;
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_XOR_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;

  if (parse_AND_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok && expr_tok->tok.kind == '^') {
    expr_tok = expr_tok->next;
    if (parse_AND_expr(need_eval, &v2) < 0) return -1;
    if (need_eval) v1 = v1 ^ v2;
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_AND_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;

  if (parse_equality_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok && expr_tok->tok.kind == '&') {
    expr_tok = expr_tok->next;
    if (parse_equality_expr(need_eval, &v2) < 0) return -1;
    if (need_eval) v1 = v1 & v2;
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_equality_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;
  int op;

  if (parse_relational_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok
         && (expr_tok->tok.kind == TOK_EQ
             || expr_tok->tok.kind == TOK_NEQ)) {
    op = expr_tok->tok.kind;
    expr_tok = expr_tok->next;
    if (parse_relational_expr(need_eval, &v2) < 0) return -1;
    if (need_eval) {
      switch (op) {
      case TOK_EQ:  v1 = (v1 == v2); break;
      case TOK_NEQ: v1 = (v1 != v2); break;
      default:
        abort();
      }
    }
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_relational_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;
  int op;

  if (parse_shift_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok
         && (expr_tok->tok.kind == TOK_LEQ
             || expr_tok->tok.kind == TOK_GEQ
             || expr_tok->tok.kind == '<'
             || expr_tok->tok.kind == '>')) {
    op = expr_tok->tok.kind;
    expr_tok = expr_tok->next;
    if (parse_shift_expr(need_eval, &v2) < 0) return -1;
    if (need_eval) {
      switch (op) {
      case TOK_LEQ: v1 = (v1 <= v2); break;
      case TOK_GEQ: v1 = (v1 >= v2); break;
      case '<':     v1 = (v1 < v2); break;
      case '>':     v1 = (v1 > v2); break;
      default:
        abort();
      }
    }
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_shift_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;
  int op;

  if (parse_additive_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok
         && (expr_tok->tok.kind == TOK_LSHIFT
             || expr_tok->tok.kind == TOK_RSHIFT)) {
    op = expr_tok->tok.kind;
    expr_tok = expr_tok->next;
    if (parse_additive_expr(need_eval, &v2) < 0) return -1;
    if (need_eval) {
      switch (op) {
      case TOK_LSHIFT: v1 = v1 << v2; break;
      case TOK_RSHIFT: v1 = v1 >> v2; break;
      default:
        abort();
      }
    }
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_additive_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;
  int op;

  if (parse_multiplicative_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok
         && (expr_tok->tok.kind == '+'
             || expr_tok->tok.kind == '-')) {
    op = expr_tok->tok.kind;
    expr_tok = expr_tok->next;
    if (parse_multiplicative_expr(need_eval, &v2) < 0) return -1;
    if (need_eval) {
      switch (op) {
      case '+': v1 = v1 + v2; break;
      case '-': v1 = v1 - v2; break;
      default:
        abort();
      }
    }
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_multiplicative_expr(int need_eval, long long *pres)
{
  long long v1 = 0, v2 = 0;
  int op;

  if (parse_unary_expr(need_eval, &v1) < 0) return -1;
  while (expr_tok
         && (expr_tok->tok.kind == '*'
             || expr_tok->tok.kind == '/'
             || expr_tok->tok.kind == '%')) {
    op = expr_tok->tok.kind;
    expr_tok = expr_tok->next;
    if (parse_unary_expr(need_eval, &v2) < 0) return -1;
    if (need_eval) {
      switch (op) {
      case '*': v1 = v1 * v2; break;
      case '/':
        if (!v2) return -1;
        v1 = v1 / v2;
        break;
      case '%':
        if (!v2) return -1;
        v1 = v1 % v2;
        break;
      default:
        abort();
      }
    }
  }
  if (need_eval) *pres = v1;
  return 0;
}

static int
parse_unary_expr(int need_eval, long long *pres)
{
  long long v1 = 0;
  int op = 0;

  if (expr_tok) {
    switch(expr_tok->tok.kind) {
    case '+':
    case '-':
    case '!':
    case '~':
      op = expr_tok->tok.kind;
      expr_tok = expr_tok->next;
      break;
    case TOK_IDENT:
    case TOK_IDENT_NE:
      if (expr_tok->tok.id.id == ID_DEFINED) {
        int nl = 0;

        expr_tok = expr_tok->next;
        while (expr_tok && expr_tok->tok.kind == '(') {
          nl++;
          expr_tok = expr_tok->next;
        }
        if (!expr_tok) return -1;
        if (expr_tok->tok.kind != TOK_IDENT
            && expr_tok->tok.kind != TOK_IDENT_NE)
          return -1;
        if (need_eval) {
          if (lookup_define_table(expr_tok->tok.id.id))
            v1 = 1;
        }
        expr_tok = expr_tok->next;
        while (nl && expr_tok && expr_tok->tok.kind == ')') {
          nl--;
          expr_tok = expr_tok->next;
        }
        if (nl) return -1;
        if (need_eval) *pres = v1;
        return 0;
      }
      break;
    }
  }
  if (!op) {
    if (!parse_primary_expr(need_eval, &v1) < 0) return -1;
    if (need_eval) *pres = v1;
    return 0;
  } else {
    if (!parse_unary_expr(need_eval, &v1) < 0) return -1;
  }
  if (need_eval) {
    switch (op) {
    case '+': v1 = +v1; break;
    case '-': v1 = -v1; break;
    case '!': v1 = !v1; break;
    case '~': v1 = ~v1; break;
    }
    *pres = v1;
  }
  return 0;
}

static int
parse_primary_expr(int need_eval, long long *pres)
{
  c_value_t res;

  if (!expr_tok) return -1;
  switch (expr_tok->tok.kind) {
  case '(':
    expr_tok = expr_tok->next;
    if (parse_conditional_expr(need_eval, pres) < 0) return -1;
    if (!expr_tok || expr_tok->tok.kind != ')') return -1;
    expr_tok = expr_tok->next;
    break;
  case TOK_IDENT:
  case TOK_IDENT_NE:
    if (need_eval) *pres = 0;
    expr_tok = expr_tok->next;
    break;
  case TOK_CONSTANT:
    ASSERT(expr_tok->tok.val.val.tag >= C_FIRST_ARITH);
    ASSERT(expr_tok->tok.val.val.tag <= C_LAST_ARITH);
    if (expr_tok->tok.val.val.tag >= C_FIRST_FLT) {
      return -1;
    }
    if (need_eval) {
      c_value_cast(&expr_tok->tok.val.val, C_LLONG, &res);
      *pres = res.v.ct_llint;
    }
    expr_tok = expr_tok->next;
    break;
  case TOK_STRING:
    return -1;
  default:
    return -1;
  }
  return 0;
}

struct cond_stack
{
  struct cond_stack *next;
  int was_true;
  int was_else;
  int output_enabled;
};
static struct cond_stack *cond_stack;

static int
handle_directive_conditional(ident_t id, FILE *out)
{
  toklist_item_t *toklist, *p, *q;
  struct cond_stack *new_stack;
  long long val = 0;
  int need_eval;

  expr_f = files->path;
  expr_l = files->line;
  toklist = read_tokens_to_list(out);

  switch (id) {
  case ID_IF:
  case ID_ELIF:
    if (id == ID_ELIF) {
      if (!cond_stack) {
        c_err2(expr_f, expr_l, "unbalanced `#elif'");
        return 0;
      }
      if (cond_stack->was_else) {
        c_err2(expr_f, expr_l, "`#elif' after `#else'");
        return 0;
      }
    }

    /* prevent macroexpansion of X in "defined X" */
    for (p = toklist; p; p = p->next) {
      if ((p->tok.kind == TOK_IDENT || p->tok.kind == TOK_IDENT_NE)
          && p->tok.id.id == ID_DEFINED) {
        p->tok.kind = TOK_IDENT_NE;
        q = p->next;
        while (q && (q->tok.kind == TOK_SPACE || q->tok.kind == '(')) {
          q = q->next;
        }
        if (q && (q->tok.kind == TOK_IDENT || q->tok.kind == TOK_IDENT_NE)) {
          q->tok.kind = TOK_IDENT_NE;
        }
      }
    }
    toklist = macroexpand_toklist(toklist, 0, CNTX_IF);
    toklist = remove_space_tokens(toklist);
    //toklist = remove_enable_tokens(toklist);

#if 0
    write_toklist(toklist, stderr);
#endif

    if (id == ID_IF) {
      need_eval = output_enabled;
    } else {
      need_eval = !cond_stack->was_true;
    }
    if (parse_expression(toklist, need_eval, &val) < 0) {
      c_err2(expr_f, expr_l, 
             "invalid expression in `#%s' directive", ident_get(id));
      val = 0;
    }

    if (id == ID_IF) {
      new_stack = (struct cond_stack*) xcalloc(1, sizeof(*new_stack));
      new_stack->next = cond_stack;
      cond_stack = new_stack;
      new_stack->was_true = val;
      new_stack->output_enabled = val;
      if (!output_enabled) {
        new_stack->was_true = 1;
        new_stack->output_enabled = 0;
      }
    } else {
      if (!cond_stack->was_true) {
        cond_stack->was_true = val;
        cond_stack->output_enabled = val;
      } else {
        cond_stack->output_enabled = 0;
      }
      new_stack = cond_stack;
    }
    output_enabled = new_stack->output_enabled;
    break;
  case ID_IFDEF:
  case ID_IFNDEF:
    toklist = remove_space_tokens(toklist);
    if (!toklist || toklist->tok.kind != TOK_IDENT || toklist->next) {
      c_err2(expr_f, expr_l, "invalid `#%s' directive", ident_get(id));
    } else {
      if (output_enabled) {
        if (lookup_define_table(toklist->tok.id.id)) val = 1;
        if (id == ID_IFNDEF) val = !val;
      }
    }
    free_toklist(toklist);

    new_stack = (struct cond_stack*) xcalloc(1, sizeof(*new_stack));
    new_stack->next = cond_stack;
    cond_stack = new_stack;
    new_stack->was_true = val;
    new_stack->output_enabled = val;
    if (!output_enabled) {
      new_stack->was_true = 1;
      new_stack->output_enabled = 0;
    }
    output_enabled = new_stack->output_enabled;
    break;

  case ID_ELSE:
    if (!cond_stack) {
      c_err2(expr_f, expr_l, "unbalanced `#else'");
      return 0;
    }
    if (cond_stack->was_else) {
      c_err2(expr_f, expr_l, "`#else' after another `#else'");
      return 0;
    }
    toklist = remove_space_tokens(toklist);
    if (toklist) {
      c_warn2(expr_f, expr_l, "garbage after `#else' directive");
    }
    free_toklist(toklist);

    cond_stack->was_else = 1;
    if (!cond_stack->was_true) {
      cond_stack->was_true = 1;
      cond_stack->output_enabled = 1;
    } else {
      cond_stack->output_enabled = 0;
    }
    output_enabled = cond_stack->output_enabled;
    break;
  case ID_ENDIF:
    if (!cond_stack) {
      c_err2(expr_f, expr_l, "unbalanced `#endif'");
      return 0;
    }
    toklist = remove_space_tokens(toklist);
    if (toklist) {
      c_warn2(expr_f, expr_l, "garbage after `#endif' directive");
    }
    free_toklist(toklist);

    new_stack = cond_stack;
    cond_stack = new_stack->next;
    if (!cond_stack) output_enabled = 1;
    else output_enabled = cond_stack->output_enabled;
    xfree(new_stack);
    break;
  }
  return 0;
}

static const unsigned char * const directive_names[] =
{
  [ID_DEFINE] "define",
  [ID_DEFINED] "defined",
  [ID_ERROR] "error",
  [ID_ENDIF] "endif",
  [ID_ELIF] "elif",
  [ID_ELSE] "else",
  [ID_IDENT] "ident",
  [ID_IF] "if",
  [ID_IFDEF] "ifdef",
  [ID_IFNDEF] "ifndef",
  [ID_INCLUDE] "include",
  [ID_LINE] "line",
  [ID_PRAGMA] "pragma",
  [ID_UNDEF] "undef",
  [ID_WARNING] "warning",
  [ID___LINE__] "__LINE__",
  [ID___FILE__] "__FILE__",
  [ID___VA_ARGS__] "__VA_ARGS__",
  [ID_DEFCONST] "defconst",
};
static int (*directive_funcs[])(ident_t id, FILE *out) =
{
  [ID_DEFINE] handle_directive_define,
  [ID_ERROR] handle_directive_error,
  [ID_ENDIF] handle_directive_conditional,
  [ID_ELIF] handle_directive_conditional,
  [ID_ELSE] handle_directive_conditional,
  [ID_IDENT] handle_directive_pragma,
  [ID_IF] handle_directive_conditional,
  [ID_IFDEF] handle_directive_conditional,
  [ID_IFNDEF] handle_directive_conditional,
  [ID_INCLUDE] handle_directive_include,
  [ID_LINE] handle_directive_line,
  [ID_PRAGMA] handle_directive_pragma,
  [ID_UNDEF] handle_directive_undef,
  [ID_WARNING] handle_directive_warning,
  [ID_DEFCONST] handle_directive_defconst,
};

static void
handle_directive(FILE *out)
{
  int c;
  ident_t direct_id;

  c = get_pending_token();
  while (c == TOK_SPACE) c = get_pending_token();
  if (c == TOK_NL) {
    write_token(c, &cur_val, out);
    next_line(out);
    return;
  }
  if (c == 0) {
    return;
  }
  if (c != TOK_IDENT) goto skip_rest_of_line;

  direct_id = cur_val.id.id;
  if (direct_id < 0) goto skip_rest_of_line;
  if (direct_id >= (sizeof(directive_funcs)/sizeof(directive_funcs[0])))
    goto skip_rest_of_line;
  if (!directive_funcs[direct_id]) goto skip_rest_of_line;

  if ((*directive_funcs[direct_id])(direct_id, out) < 0)
    goto skip_rest_of_line;
  return;

  // skip the rest of line
 skip_rest_of_line:
  c = get_pending_token();
  while (c != TOK_NL && c != 0) c = get_pending_token();
  if (c == TOK_NL) {
    write_token(c, &cur_val, out);
    next_line(out);
  }
}

static int macroexpand(macrodef_t *mdef, int par_num, toklist_item_t **params,
                       toklist_item_t **out_list, idstack_t pst, int context);

static toklist_item_t *
macroexpand_toklist(toklist_item_t *toks, idstack_t idst, int context)
{
  toklist_item_t *p, **prev_p, *q;
  macrodef_t *mdef;

  toklist_item_t *param_initial[64];
  toklist_item_t **param_v = param_initial, **last_p, *new_item, **new_par;
  toklist_item_t *expand_res;
  size_t param_a = 64, param_u;
  int br_nest;

  idstack_t curst;

 restart_scan:
  param_u = 0;
  memset(param_v, 0, param_a * sizeof(param_v[0]));

#if 0
  fprintf(stderr, "  toks: \n");
  for (p = toks; p; p = p->next) {
    fprintf(stderr, "<");
    write_token(p->tok.kind, &p->tok, stderr);
    fprintf(stderr, ">");
  }
  fprintf(stderr, "\n");
#endif

  for (p = toks, prev_p = &toks; p; prev_p = &p->next, p = *prev_p) {
    if (p->tok.kind != TOK_IDENT) {
      continue;
    }
    mdef = lookup_define_table(p->tok.id.id);
    if (!mdef) continue;
    for (curst = idst; curst && curst->id != mdef->id; curst = curst->next);
    if (curst) {
      p->tok.kind = TOK_IDENT_NE;
      continue;
    }

    if (mdef->par_num >= 0) {
      q = p->next;
      while (q && (q->tok.kind == TOK_SPACE || q->tok.kind == TOK_NL)) {
        q = q->next;
      }
      if (!q || q->tok.kind != '(') {
        continue;
        /*
        p->tok.kind = TOK_IDENT_NE;
        goto restart_scan;
        */
      }

      q = q->next;
      last_p = &param_v[0];
      param_u = 1;
      br_nest = 0;
      while (1) {
        if (!q) {
          p->tok.kind = TOK_IDENT_NE;
          goto restart_scan;
        }
        if (q->tok.kind == ')' && !br_nest) break;
        if (q->tok.kind == ',' && !br_nest
            && (!mdef->is_variadic || mdef->par_num != param_u)) {
          if (param_u == param_a) {
            param_a *= 2;
            new_par = (toklist_item_t**) alloca(param_a * sizeof(*new_par));
            memset(new_par, 0, param_a * sizeof(*new_par));
            memcpy(new_par, param_v, param_u * sizeof(*new_par));
            param_v = new_par;
          }
          last_p = &param_v[param_u++];
          q = q->next;
          continue;
        }
        if (q->tok.kind == '(') br_nest++;
        if (q->tok.kind == ')') br_nest--;

        new_item = (toklist_item_t*) xcalloc(1, sizeof(*new_item));
        dup_token(&new_item->tok, &q->tok);
        *last_p = new_item;
        last_p = &new_item->next;
        q = q->next;
      }
    } else {
      q = p;
    }

#if 0
    {
      int j, i;

      fprintf(stderr, "Parameters read for %s:\n", ident_get(mdef->id));
      for (i = 0; i < param_u; i++) {
        fprintf(stderr, "  param %d\n", i);
        for (j = 0, p = param_v[i]; p; p = p->next, j++) {
          fprintf(stderr, "    token (%d): <", j);
          write_token(p->tok.kind, &p->tok, stderr);
          fprintf(stderr, ">\n");
        }
      }
    }
#endif

    if (macroexpand(mdef, param_u, param_v, &expand_res, idst, context) < 0) {
      p->tok.kind = TOK_IDENT_NE;
      goto restart_scan;
    }

#if 0
  fprintf(stderr, "  result: \n");
  for (p = expand_res; p; p = p->next) {
    fprintf(stderr, "<");
    write_token(p->tok.kind, &p->tok, stderr);
    fprintf(stderr, ">");
  }
  fprintf(stderr, "\n");
#endif

    /* replace token list between p and q with expand_res */
    for (last_p = &expand_res; *last_p; last_p = &(*last_p)->next);
    *last_p = q->next;
    *prev_p = expand_res;
    q->next = 0;
    free_toklist(p);
    goto restart_scan;
  }

  return toks;
}

static int cur_tok = 0;

static int
expand_predefined(macrodef_t *mdef, int par_num, toklist_item_t **params,
                  toklist_item_t **out_list)
{
  toklist_item_t *ptok = 0;
  unsigned char buf[128];

  if (mdef->id == ID___LINE__) {
    ptok = (toklist_item_t*) xcalloc(1, sizeof(*ptok));
    ptok->tok.kind = TOK_CONSTANT;
    ptok->tok.val.val.tag = C_INT;
    ptok->tok.val.val.v.ct_int = files->line;
    snprintf(buf, sizeof(buf), "%d", files->line);
    ptok->tok.val.raw.str = xstrdup(buf);
    ptok->tok.val.raw.size = strlen(buf);
  } else if (mdef->id == ID___FILE__) {
    ptok = (toklist_item_t*) xcalloc(1, sizeof(*ptok));
    ptok->tok.kind = TOK_STRING;
    ptok->tok.str.val.str = xstrdup(files->path);
    ptok->tok.str.val.size = strlen(files->path);
    ptok->tok.str.raw.str = escape_string(files->path);
    ptok->tok.str.raw.size = strlen(ptok->tok.str.raw.str);
  }
  *out_list = ptok;
  return 1;
}

static int
macroexpand(macrodef_t *mdef, int par_num, toklist_item_t **params,
            toklist_item_t **out_list, idstack_t pst, int context)
{
  int tok_count = 0, i;
  toklist_item_t *outlist = 0, **plast = &outlist, *p, *newtok=0, *q, **pp, *r;
  bufstring_t strbuf;
  idstack_t newst;

  if (out_list) *out_list = 0;
  init_bufstring(&strbuf);

  if (mdef->par_num >= 0) {
    if (mdef->is_variadic) {
      if (par_num < mdef->par_num - 1) goto too_few_arguments;
    } else {
      if (mdef->par_num == 0 && par_num == 1) {
        if (params[0]) goto too_many_arguments;
        par_num = 0;
      } else {
        if (par_num > mdef->par_num) goto too_many_arguments;
        if (mdef->par_num > 1 && par_num < mdef->par_num)
          goto too_few_arguments;
      }
    }
  }

  for (i = 0; i < par_num; i++) {
    /* remove heading spaces */
    while (params[i] &&
           (params[i]->tok.kind == TOK_SPACE
            || params[i]->tok.kind == TOK_NL)) {
      p = params[i];
      params[i] = p->next;
      p->next = 0;
      free_toklist(p);
    }
    /* remove trailing spaces */
    pp = &params[i];
    p = params[i];
    for (; p; p = p->next) {
      if (p->tok.kind != TOK_SPACE && p->tok.kind != TOK_NL)
        pp = &p->next;
    }
    p = *pp;
    *pp = 0;
    free_toklist(p);
    /* collate several spaces into one */
    for (p = params[i]; p; p = p->next) {
      if (p->tok.kind != TOK_SPACE && p->tok.kind != TOK_NL)
        continue;
      p->tok.sp.raw.str[0] = ' ';
      p->tok.sp.raw.str[1] = 0;
      p->tok.sp.raw.size = 1;
      while (1) {
        q = p->next;
        if (!q || (q->tok.kind != TOK_SPACE && q->tok.kind != TOK_NL))
          break;
        p->next = q->next;
        q->next = 0;
        free_toklist(q);
      }
    }
  }

  /* prescan arguments */
  for (i = 0; i < par_num; i++)
    if (i < mdef->par_num && !mdef->no_prescan[i])
      params[i] = macroexpand_toklist(params[i], pst, context);

  // now we suppress this macro
  newst = alloca(sizeof(*newst));
  memset(newst, 0, sizeof(*newst));
  newst->next = pst;
  newst->id = mdef->id;

  if (mdef->expand_function) {
    tok_count = mdef->expand_function(mdef, par_num, params, &outlist);
    for (plast = &outlist; *plast; plast = &(*plast)->next);
  }

  p = mdef->tokens;
  if (context == CNTX_IF && mdef->if_tokens) p = mdef->if_tokens;

  for (; p; p = p->next) {
    if (p->tok.kind == '#') {
      for (q = p->next; q && q->tok.kind == TOK_SPACE; q = q->next);
      if (!q) {
        c_err("'#' at the end of macro expansion");
        break;
      }
      strbuf.str[0] = 0;
      strbuf.u = 0;
      if (!q->par_ind) {
        c_warn("'#' is not followed by a macro parameter");
        add_token_to_bufstring(q->tok.kind, &newtok->tok, &strbuf);
      } else {
        for (newtok = params[q->par_ind - 1]; newtok; newtok = newtok->next) {
          add_token_to_bufstring(newtok->tok.kind, &newtok->tok, &strbuf);
        }
      }
      newtok = (toklist_item_t*) xcalloc(1, sizeof(*newtok));
      newtok->tok.kind = TOK_STRING;
      newtok->tok.str.val.str = xstrdup(strbuf.str);
      newtok->tok.str.val.size = strlen(newtok->tok.str.val.str);
      newtok->tok.str.raw.str = escape_string(newtok->tok.str.val.str);
      newtok->tok.str.raw.size = strlen(newtok->tok.str.raw.str);
      *plast = newtok;
      plast = &newtok->next;
      p = q;
      continue;
    }
    if (!p->par_ind) {
      newtok = (toklist_item_t*) xcalloc(1, sizeof(*newtok));
      dup_token(&newtok->tok, &p->tok);
      *plast = newtok;
      plast = &newtok->next;
    } else {
      q = params[p->par_ind - 1];
      for (; q; q = q->next) {
        newtok = (toklist_item_t*) xcalloc(1, sizeof (*newtok));
        dup_token(&newtok->tok, &q->tok);
        *plast = newtok;
        plast = &newtok->next;
      }
    }
  }

  /* remove spaces preceding and succeding ## */
  pp = &outlist;
  p = outlist;
  while (p) {
    if (p->tok.kind == TOK_SPACE || p->tok.kind == TOK_NL) {
      p = p->next;
    } else if (p->tok.kind == TOK_PASTE) {
      if (*pp != p) {
        for (q = *pp; q->next != p; q = q->next);
        q->next = 0;
        q = *pp;
        *pp = p;
        free_toklist(q);
      }
      while (1) {
        q = p->next;
        if (!q) break;
        if (q->tok.kind != TOK_SPACE && q->tok.kind != TOK_NL) break;
        p->next = q->next;
        q->next = 0;
        free_toklist(q);
      }
      pp = &p->next;
      p = *pp;
    } else {
      pp = &p->next;
      p = *pp;
    }
  }

  if (outlist && outlist->tok.kind == TOK_PASTE) {
    c_err("'##' cannot appear at either end of a macro expansion");
    q = outlist;
    while (outlist && outlist->tok.kind == TOK_PASTE) {
      p = outlist;
      outlist = p->next;
      p->next = 0;
    }
    free_toklist(q);
  }

  p = outlist;
  plast = &outlist;
  while(1) {
    if (!p) break;
    if (!p->next || p->next->tok.kind != TOK_PASTE) {
      plast = &p->next;
      p = p->next;
      continue;
    }

    /* handle concatenation chains */
    /* plast points to the start of concatenation chain */
    strbuf.str[0] = 0;
    strbuf.u = 0;
    add_token_to_bufstring(p->tok.kind, &p->tok, &strbuf);
    p = p->next;
    while (p && p->tok.kind == TOK_PASTE) {
      p = p->next;
      if (!p) {
        c_err("'##' cannot appear at either end of a macro expansion");
        break;
      }
      add_token_to_bufstring(p->tok.kind, &p->tok, &strbuf);
      p = p->next;
    }

    scanner_save_state();
    line_buf.u = 0;
    line_buf.str[0] = 0;
    auto_getline_flag = 0;
    line_buf_ind = 0;
    add_to_bufstring(&line_buf, strbuf.str, strbuf.u);

    r = 0;
    pp = &r;

    cur_tok = get_file_token();
    if (!cur_tok) {
      /* FIXME: report warning */
    } else {
      while (cur_tok) {
        newtok = (toklist_item_t*) xcalloc(1, sizeof(*r));
        dup_token(&newtok->tok, &cur_val);
        *pp = newtok;
        pp = &newtok->next;
        cur_tok = get_file_token();
      }
    }
    scanner_restore_state();

    *pp = p;
    q = *plast;
    *plast = r;
    while (q != p) {
      newtok = q;
      q = q->next;
      newtok->next = 0;
      free_toklist(newtok);
    }
  }

  /* fix variadic macros */
  if (mdef->is_variadic) {
    plast = &outlist;
    p = *plast;
    while (p) {
      if (p->tok.kind == ',') {
        q = p->next;
        while (q && q->tok.kind == TOK_SPACE) {
          q = q->next;
        }
        if (q && q->tok.kind == TOK_PASTE_VA) {
          if (params[mdef->par_num - 1]) {
            // remove just ##
            newtok = q->next;
            q = p->next;
            p->next = newtok;
            p = p->next;
          } else {
            // remove , and ##
            *plast = q->next;
            q = p;
            p = *plast;
          }
          // remove tokens from q to p
          while (q != p) {
            newtok = q;
            q = q->next;
            newtok->next = 0;
            free_toklist(newtok);
          }
          continue;
        }
      }
      plast = &p->next;
      p = *plast;
    }
  }

  /* scan for the last token */
  for (plast = &outlist; *plast; plast = &(*plast)->next);

  /* add one space before and after macroexpansion */
  newtok = (toklist_item_t*) xcalloc(1, sizeof(*newtok));
  newtok->tok.kind = TOK_SPACE;
  newtok->tok.sp.raw.size = 1;
  newtok->tok.sp.raw.str = xstrdup(" ");
  newtok->next = outlist;
  outlist = newtok;

  newtok = (toklist_item_t*) xcalloc(1, sizeof(*newtok));
  newtok->tok.kind = TOK_SPACE;
  newtok->tok.sp.raw.size = 1;
  newtok->tok.sp.raw.str = xstrdup(" ");
  *plast = newtok;
  plast = &newtok->next;

  xfree(strbuf.str);

  outlist = macroexpand_toklist(outlist, newst, context);
  *out_list = outlist;
  return tok_count;

 too_many_arguments:
  c_err("macro `%s' passed %d arguments, but takes just %d",
        ident_get(mdef->id), par_num, mdef->par_num);
  xfree(strbuf.str);
  return -1;

 too_few_arguments:
  c_err("macro `%s' requires %d arguments, but only %d given",
        ident_get(mdef->id), mdef->par_num, par_num);
  xfree(strbuf.str);
  return -1;
}

void
collect_params(FILE *out, macrodef_t *mdef)
{
  int nl_num = 0;
  int spl_num = 0;
  int i;

  toklist_item_t **param_v = 0, **last_p, *expand_res, *p;
  toklist_item_t *new_par;
  size_t param_a = 0;
  size_t param_u = 0;

  size_t stack_u = 0;

  if (mdef->par_num >= 0) {
    // save all whitespace, since it's possible that the macro has no params
    // note, that we might get temporary EOF's since the input is
    // line-buffered
    p = (toklist_item_t*) xcalloc(1, sizeof(*p));
    dup_token(&p->tok, &cur_val);
    last_p = &p->next;
    while (1) {
      cur_tok = get_pending_token();
      if (!cur_tok) break;
      if (cur_tok == TOK_NL) {
        nl_num++;
        spl_num += files->spliced_nls;
      }
      new_par = (toklist_item_t*) xcalloc(1, sizeof(*new_par));
      dup_token(&new_par->tok, &cur_val);
      *last_p = new_par;
      last_p = &new_par->next;
      if (cur_tok != TOK_SPACE && cur_tok != TOK_NL) break;
    }
    if (cur_tok != '(') {
      p->tok.kind = TOK_IDENT_NE;
      *last_p = pending_tokens;
      pending_tokens = p;
      return;
    }

    free_toklist(p);
    for (i = 0; i < nl_num; i++) {
      fprintf(out, "\n");
    }
    for (i = 0; i < spl_num; i++) {
      fprintf(out, "\n");
    }
    files->line += nl_num + spl_num;

    param_a = 64;
    param_v = (toklist_item_t**) alloca(param_a * sizeof(param_v[0]));
    param_u = 1;
    memset(param_v, 0, param_a * sizeof(param_v[0]));
    last_p = &param_v[0];

    stack_u = 0;

    while (1) {
      cur_tok = get_pending_token();
      
      if (cur_tok == 0) break;
      if (cur_tok == TOK_NL) {
        fwrite(cur_val.sp.raw.str, 1, cur_val.sp.raw.size, out);
        next_line(out);
      }
      if (cur_tok == ',' && !stack_u
          && (!mdef->is_variadic || mdef->par_num != param_u)) {
        if (param_u == param_a) {
          toklist_item_t **new_v;

          param_a *= 2;
          new_v = (toklist_item_t**) alloca(param_a * sizeof(param_v[0]));
          memset(new_v, 0, param_a * sizeof(param_v[0]));
          memcpy(new_v, param_v, param_u * sizeof(param_v[0]));
          param_v = new_v;
        }
        last_p = &param_v[param_u++];
        continue;
      }
      if (cur_tok == ')' && !stack_u) {
        break;
      }
      if (cur_tok == '(') stack_u++;
      if (cur_tok == ')') stack_u--;
      new_par = (toklist_item_t *) xcalloc(1, sizeof(*new_par));
      dup_token(&new_par->tok, &cur_val);
      new_par->next = 0;
      *last_p = new_par;
      last_p = &new_par->next;
    }

    if (cur_tok == 0) {
      // unexpected EOF
      c_err("unterminated argument list invoking macro `%s'",
            ident_get(mdef->id));
      return;
    }

#if 0
    {
      int j;

      fprintf(stderr, "Parameters read:\n");
      for (i = 0; i < param_u; i++) {
        fprintf(stderr, "  param %d\n", i);
        for (j = 0, p = param_v[i]; p; p = p->next, j++) {
          fprintf(stderr, "    token (%d): <", j);
          write_token(p->tok.kind, &p->tok, stderr);
          fprintf(stderr, ">\n");
        }
      }
    }
#endif
  }

  /* macroexpand */
  i = macroexpand(mdef, param_u, param_v, &expand_res, 0, 0);

#if 0
  fprintf(stderr, "  result: \n");
  for (p = expand_res; p; p = p->next) {
    fprintf(stderr, "<");
    write_token(p->tok.kind, &p->tok, stderr);
    fprintf(stderr, ">");
  }
  fprintf(stderr, "\n");
#endif

  if (i >= 0) {
    last_p = &expand_res;
    for (p = expand_res; p; last_p = &p->next, p = *last_p);
    *last_p = pending_tokens;
    pending_tokens = expand_res;
  }

#if 0
  fprintf(stderr, "  pending: \n");
  for (p = pending_tokens; p; p = p->next) {
    fprintf(stderr, "<");
    write_token(p->tok.kind, &p->tok, stderr);
    fprintf(stderr, ">");
  }
  fprintf(stderr, "\n");
#endif
}

static int
process_file(unsigned char *in_path, FILE *in,
             FILE *out, int is_system_header)
{
  macrodef_t *mdef = 0;
  int flag_at_newline = 0;
  unsigned char *esc_str = 0;
  int need_close = 0;

  if (in) {
    if (!in_path || !*in_path || !strcmp(in_path, "-")) {
      in_path = "<stdin>";
    }
  } else {
    if (!in_path || !*in_path || !strcmp(in_path, "-")) {
      in = stdin;
      in_path = "<stdin>";
    } else {
      in = fopen(in_path, "rb");
      if (!in) {
        fprintf(stderr, "%s: %s: %s\n",
                opt_getname(), in_path, os_ErrorString());
        return -1;
      }
      need_close = 1;
    }
  }

  stage0_open_input(in_path, in);
  auto_getline_flag = 1;
  flag_at_newline = 1;
  stage4_getline();

  esc_str = escape_string(in_path);
  if (is_system_header) {
    fprintf(out, "# 1 %s 1 3\n", esc_str);
  } else {
    fprintf(out, "# 1 %s 1\n", esc_str);
  }
  xfree(esc_str);

  while (1) {
    cur_tok = get_pending_token();
    if (!cur_tok) break;
    if (cur_tok == TOK_SPACE) {
      add_token_to_bufstring(cur_tok, &cur_val, &spcbuf);
      continue;
    }
    if (cur_tok == TOK_NL) {
      spcbuf.u = 0;
      spcbuf.str[0] = 0;
      fwrite(cur_val.sp.raw.str, 1, cur_val.sp.raw.size, out);
      next_line(out);
      flag_at_newline = 1;
      continue;
    }
    if (cur_tok == '#' && flag_at_newline) {
      spcbuf.u = 0;
      spcbuf.str[0] = 0;
      handle_directive(out);
      flag_at_newline = 1;
      continue;
    }
    
    flag_at_newline = 0;
    if (spcbuf.u) {
      if (output_enabled) {
        fwrite(spcbuf.str, 1, spcbuf.u, out);
      }
      spcbuf.u = 0;
      spcbuf.str[0] = 0;
    }

    if (output_enabled) {
      if (cur_tok == TOK_IDENT
          && (mdef = lookup_define_table(cur_val.id.id))) {
        collect_params(out, mdef);
      } else {
        write_token(cur_tok, &cur_val, out);
      }
    }
  }

  if (need_close && in != stdin) {
    fclose(in);
  }

  stage0_close_input();

  return 0;
}

static void
install_directives(void)
{
  ident_t id;
  int i;

  for (i = 0; i < (sizeof(directive_names)/sizeof(directive_names[0])); i++) {
    if (!directive_names[i]) continue;
    id = ident_put(directive_names[i], strlen(directive_names[i]));
    ASSERT(id == i);
  }
};

static void
install_predefined_macros(void)
{
  unsigned char *builtin_file;
  macrodef_t *mdef;
  time_t curtime;
  struct tm *loctime;
  unsigned char buf[512], *esc_buf;
  toklist_item_t *ptok;

  builtin_file = add_to_file_names("<built-in>");
  curtime = time(0);
  loctime = localtime(&curtime);

  /* __DATE__ */
  mdef = (macrodef_t*) xcalloc(1, sizeof(*mdef));
  mdef->id = ident_put("__DATE__", 8);
  mdef->def_file = builtin_file;
  mdef->def_line = 1;
  mdef->par_num = -1;
  mdef->is_predefined = 1;
  strftime(buf, sizeof(buf), "%b %d %Y", loctime);
  esc_buf = escape_string(buf);
  ptok = (toklist_item_t*) xcalloc(1, sizeof(*ptok));
  ptok->tok.kind = TOK_STRING;
  ptok->tok.str.raw.str = esc_buf;
  ptok->tok.str.raw.size = strlen(esc_buf);
  ptok->tok.str.val.str = xstrdup(buf);
  ptok->tok.str.val.size = strlen(buf);
  mdef->tokens = ptok;
  put_to_define_table(mdef->id, mdef);

  /* __TIME__ */
  mdef = (macrodef_t*) xcalloc(1, sizeof(*mdef));
  mdef->id = ident_put("__TIME__", 8);
  mdef->def_file = builtin_file;
  mdef->def_line = 1;
  mdef->par_num = -1;
  mdef->is_predefined = 1;
  strftime(buf, sizeof(buf), "%H:%M:%S", loctime);
  esc_buf = escape_string(buf);
  ptok = (toklist_item_t*) xcalloc(1, sizeof(*ptok));
  ptok->tok.kind = TOK_STRING;
  ptok->tok.str.raw.str = esc_buf;
  ptok->tok.str.raw.size = strlen(esc_buf);
  ptok->tok.str.val.str = xstrdup(buf);
  ptok->tok.str.val.size = strlen(buf);
  mdef->tokens = ptok;
  put_to_define_table(mdef->id, mdef);

  /* __FILE__ */
  mdef = (macrodef_t*) xcalloc(1, sizeof(*mdef));
  mdef->id = ID___FILE__;
  mdef->def_file = builtin_file;
  mdef->def_line = 1;
  mdef->par_num = -1;
  mdef->is_predefined = 1;
  mdef->expand_function = expand_predefined;
  put_to_define_table(mdef->id, mdef);

  /* __LINE__ */
  mdef = (macrodef_t*) xcalloc(1, sizeof(*mdef));
  mdef->id = ID___LINE__;
  mdef->def_file = builtin_file;
  mdef->def_line = 1;
  mdef->par_num = -1;
  mdef->is_predefined = 1;
  mdef->expand_function = expand_predefined;
  put_to_define_table(mdef->id, mdef);
}

static void
fix_path(unsigned char *buf)
{
  unsigned char *s = buf, *p;
  for (; *s; s++) {
    if (*s == '\\') *s = '/';
  }
  s = buf;
  while (*s == '/') s++;
  p = s;
  while (*s) {
    if (*s == '/') {
      while (*s == '/') s++;
      if (*s) {
        *p++ = '/';
      }
    } else {
      *p++ = *s++;
    }
  }
  *p = 0;
}

static void
fix_include_dirs(void)
{
  int i;

  for (i = 0; i < incl_dirs.u; i++) {
    fix_path(incl_dirs.v[i]);
  }
  for (i = 0; i < sys_incl_dirs.u; i++) {
    fix_path(sys_incl_dirs.v[i]);
  }
}

static void
handle_command_line_defines(void)
{
  int i, j;
  unsigned char *str, *p, *q;
  size_t len;

  output_enabled = 1;
  auto_getline_flag = 0;
  files = (struct file_stack *) xcalloc(1, sizeof(*files));
  files->file = 0;
  files->is_eof = 1;
  files->path = xstrdup("<command line>");
  files->line = 1;

  for (i = 0; i < du_options.u; i++) {
    str = (unsigned char*) alloca(strlen(du_options.v[i]) + 10);
    strcpy(str, du_options.v[i]);
    for (p = str; *p; p++) {
      if (*p < ' ') *p = ' ';
    }
    for (p = q = str; *p && *p != '='; p++) {
      if (*p != ' ') *q++ = *p;
    }
    while ((*q++ = *p++));
    for (p = str; *p && *p != '='; p++);
    if (*p == '=') *p = ' ';
    else {
      *p++ = ' ';
      *p++ = '1';
      *p = 0;
    }
    len = strlen(str);
    files->la_stack = (int*) alloca(len * sizeof(files->la_stack[0]));
    memset(files->la_stack, 0, len * sizeof(files->la_stack[0]));
    for (p = str + 2, j = len - 3; *p; p++, j--)
      files->la_stack[j] = *p;
    files->la_last = len - 2;
    files->s2_last = 0;

    stage4_getline();
    if (str[1] == 'D') {
      handle_directive_define(ID_DEFINE, 0);
    } else {
      handle_directive_undef(ID_UNDEF, 0);
    }

    files->line++;
  }

  xfree(files->path);
  xfree(files);
  files = 0;
}

static int
add_du_option(char *opt1, char *opt2, int optnum)
{
  size_t len;
  char *str;

  if (!opt1) opt1 = "";
  if (!opt2) opt2 = "";
  len = strlen(opt1) + strlen(opt2) + 1;
  str = (char*) xmalloc(len);
  strcpy(str, opt1);
  strcat(str, opt2);
  xexpand(&du_options);
  du_options.v[du_options.u++] = str;
  return 0;
}

static int
add_incl_dir(char *opt, int num)
{
  /* -IXXX */
  xexpand(&incl_dirs);
  incl_dirs.v[incl_dirs.u++] = xstrdup(opt + 2);
  return 0;
}

static int
add_sys_incl_dir(char *opt, int num)
{
  /* -isystem */
  xexpand(&sys_incl_dirs);
  sys_incl_dirs.v[sys_incl_dirs.u++] = xstrdup(opt + 8);
  return 0;
}

static int
add_sys_bef_incl_dir(char *opt, int num)
{
  /* -isysbefore */
  xexpand(&sys_incl_dirs);
  sys_incl_dirs.v[sys_incl_dirs.u++] = xstrdup(opt + 11);
  return 0;
}

static int
add_warn_incl_dir(char *opt, int num)
{
  /* -iwarn */
  xexpand(&warn_incl_dirs);
  warn_incl_dirs.v[warn_incl_dirs.u++] = xstrdup(opt + 6);
  return 0;
}

static optrec_t options[] =
{
  { 1, 0, "-V", "v", (void *) 1, 
    "Display version information", 0 },
  { 1, 0, "--version", "v", (void *) 1, 
    "Display version information", 0 },
  { 1, 0, "--help", "h", (void *) 1,
    "Display help message", 0 },

  { 1, 0, "-I", "V+", &incl_dirs,
    "Add directory to include search", 0 },
  { 1, 0, "-I", "*2a", &add_incl_dir,
    "Add directory to include search", 0 },
  { 1, 0, "-isystem", "V+", &sys_incl_dirs,
    "Add a system include directory", 0 },
  { 1, 0, "-isystem", "*8a", &add_sys_incl_dir,
    "Add a system include directory", 0 },
  { 1, 0, "-isysbefore", "V+", &sys_incl_dirs,
    "Add a system include directory", 0 },
  { 1, 0, "-isysbefore", "*11a", &add_sys_bef_incl_dir,
    "Add a system include directory", 0 },
  { 1, 0, "-iwarn", "V+", &warn_incl_dirs,
    "Add a system include directory", 0 },
  { 1, 0, "-iwarn", "*6a", &add_warn_incl_dir,
    "Add a system include directory", 0 },

  { 1, 0, "-include", "V+", &include_files,
    "Add a file to include before the main file" },

  { 1, 0, "-D", "a+", &add_du_option,
    "Define a macro", 0 },
  { 1, 0, "-D", "*2V-", &du_options,
    "Define a macro", 0 },
  { 1, 0, "-U", "a+", &add_du_option,
    "Undefine a macro", 0 },
  { 1, 0, "-U", "*2V-", &du_options,
    "Undefine a macro", 0 },

  { 1, 0, "-o", "t1", &output_name,
    "Specify output file name", 0 },

  { 1, 0, "-v", "s1", &option_verbose,
    "Verbose execution", 0 },

  { 1, 0, "-", "V-", &input_files,
    "file to process", 0 },
  { 1, 0, opt_default, "V+", &input_files,
    "file to process", 0 },

  { 0, 0, NULL, NULL, NULL, NULL, NULL }
};

static char buildinfo[128];
static void
make_buildinfo(void)
{
  buildinfo[0] = 0;
  /*
  sprintf(buildinfo, "revision %s, copyright (C) 2003-2005 Alexander Chernov",
          compile_version);
  */
}

int
main(int argc, char **argv)
{
  unsigned char *in_path = 0;
  int res = 0, i;
  FILE *out;

  init_bufstring(&valbuf);
  init_bufstring(&rawbuf);
  init_bufstring(&line_buf);
  init_bufstring(&spcbuf);

  install_directives();
  install_predefined_macros();

  make_buildinfo();
  opt_setargs(options, NULL, NULL, buildinfo, NULL, argc, argv, 0);

  while (opt_get() != OPT_END);
  opt_close();

  if (input_files.u > 1) {
    err_Startup("too many input files");
  }
  fix_include_dirs();

  handle_command_line_defines();

  if (input_files.u) {
    in_path = input_files.v[0];
  }

  if (!output_name || !*output_name || !strcmp(output_name, "-")) {
    out = stdout;
  } else {
    out = fopen(output_name, "w");
    if (!out) {
      fprintf(stderr, "%s: %s: %s\n", opt_getname(), output_name,
              os_ErrorString());
      res = -1;
    }
  }
  if (out) {
    output_enabled = 1;
    for (i = 0; i < include_files.u; i++)
      process_file(include_files.v[i], 0, out, 0);
    res = process_file(in_path, 0, out, 0);
  }
  if (out && out != stdout) {
    fclose(out);
  }

  if (res < 0) {
    res = 1;
  } else if (res > 0) {
    res = 0;
  }
  if (!res && error_counter > 0) res = 1;
  return res;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
