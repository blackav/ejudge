/* -*- mode: c -*- */

/* Copyright (C) 2003-2022 Alexander Chernov <cher@ejudge.ru> */

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

#ifdef EJUDGE_CHECKER
#include "testinfo.h"
#else
#include "ejudge/testinfo.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

#define XOFFSET(type,field)       ((long) &((type*) 0)->field)
#define TESTINFO_OFFSET(f)        XOFFSET(struct testinfo_struct, f)
#define XPDEREF(type,base,offset) (((type*) (((char*) (base)) + (offset))))
static __attribute__((unused)) unsigned int tag_offsets[] =
{
  [Tag_params] = 0,
  [Tag_environ] = 0,
  [Tag_checker_env] = 0,
  [Tag_interactor_env] = 0,
  [Tag_init_env] = 0,
  [Tag_compiler_env] = 0,
  [Tag_style_checker_env] = 0,
  [Tag_ok_language] = 0,
  [Tag_comment] = TESTINFO_OFFSET(comment),
  [Tag_team_comment] = TESTINFO_OFFSET(team_comment),
  [Tag_source_stub] = TESTINFO_OFFSET(source_stub),
  [Tag_working_dir] = TESTINFO_OFFSET(working_dir),
  [Tag_program_name] = TESTINFO_OFFSET(program_name),
  [Tag_exit_code] = TESTINFO_OFFSET(exit_code),
  [Tag_max_open_file_count] = TESTINFO_OFFSET(max_open_file_count),
  [Tag_max_process_count] = TESTINFO_OFFSET(max_process_count),
  [Tag_time_limit_ms] = TESTINFO_OFFSET(time_limit_ms),
  [Tag_real_time_limit_ms] = TESTINFO_OFFSET(real_time_limit_ms),
  [Tag_max_vm_size] = TESTINFO_OFFSET(max_vm_size),
  [Tag_max_stack_size] = TESTINFO_OFFSET(max_stack_size),
  [Tag_max_file_size] = TESTINFO_OFFSET(max_file_size),
  [Tag_max_rss_size] = TESTINFO_OFFSET(max_rss_size),
  [Tag_check_stderr] = TESTINFO_OFFSET(check_stderr),
  [Tag_disable_stderr] = TESTINFO_OFFSET(disable_stderr),
  [Tag_enable_subst] = TESTINFO_OFFSET(enable_subst),
  [Tag_compiler_must_fail] = TESTINFO_OFFSET(compiler_must_fail),
  [Tag_allow_compile_error] = TESTINFO_OFFSET(allow_compile_error),
  [Tag_disable_valgrind] = TESTINFO_OFFSET(disable_valgrind),
  [Tag_ignore_exit_code] = TESTINFO_OFFSET(ignore_exit_code),
};

struct line_buf
{
  size_t a, u;
  unsigned char *v;
};

struct cmdline_buf
{
  size_t a, u;
  unsigned char **v;
};

static int
read_line(FILE *fin, struct line_buf *pbuf)
{
  unsigned char *old_v;
  int c;

  if (!pbuf->a || !pbuf->v) {
    pbuf->a = 512;
    if (!(pbuf->v = (unsigned char*) malloc(pbuf->a))) goto failure;
  }
  pbuf->u = 0;
  pbuf->v[0] = 0;

  while (1) {
    c = getc(fin);
    if (c == EOF) break;
    if (pbuf->u + 1 >= pbuf->a) {
      pbuf->a *= 2;
      old_v = pbuf->v;
      if (!(pbuf->v = (unsigned char*) realloc(pbuf->v, pbuf->a))) {
        pbuf->v = old_v;
        goto failure;
      }
    }
    pbuf->v[pbuf->u++] = c;
    if (c == '\n') break;
  }

  if (!pbuf->u) {
    if (ferror(fin)) return -TINF_E_IO_ERROR;
    return -TINF_E_EOF;
  }
  pbuf->v[pbuf->u] = 0;
  while (pbuf->u > 0 && isspace(pbuf->v[pbuf->u - 1]))
    pbuf->v[--pbuf->u] = 0;
  return pbuf->u;

 failure:
  if (pbuf->v) free(pbuf->v);
  memset(pbuf, 0, sizeof(*pbuf));
  return -TINF_E_NO_MEMORY;
}

static int
parse_cmdline(const unsigned char *str, struct cmdline_buf *pcmd)
{
  unsigned char *locbuf, *q, *qq, **old_v;
  const unsigned char *p = str;
  unsigned char nb[4];
  int q_char = 0;
  int code, i;

  memset(pcmd, 0, sizeof(*pcmd));
  pcmd->a = 16;
  if (!(pcmd->v = (unsigned char**) malloc(pcmd->a * sizeof(pcmd->v[0])))) {
    code = -TINF_E_NO_MEMORY;
    goto failure;
  }
  pcmd->u = 0;
  pcmd->v[0] = 0;
  if (!(q = locbuf = (unsigned char*) alloca(strlen(str) + 16))) {
    code = -TINF_E_NO_MEMORY;
    goto failure;
  }
  while (isspace(*p)) p++;
  if (*p && *p != '#') {
    while (1) {
      if (!*p || (*p == '#' && !q_char)) {
        if (q_char) {
          code = -TINF_E_UNCLOSED_QUOTE;
          goto failure;
        }
        *q = 0;
        if (pcmd->u + 1 >= pcmd->a) {
          pcmd->a *= 2;
          old_v = pcmd->v;
          pcmd->v=(unsigned char**)realloc(pcmd->v,pcmd->a*sizeof(pcmd->v[0]));
          if (!pcmd->v) {
            pcmd->v = old_v;
            code = -TINF_E_NO_MEMORY;
            goto failure;
          }
        }
        if (!(qq = strdup(locbuf))) {
          code = -TINF_E_NO_MEMORY;
          goto failure;
        }
        pcmd->v[pcmd->u++] = qq;
        pcmd->v[pcmd->u] = 0;
        break;
      } else if (*p == '\"') {
        if (!q_char) {
          q_char = *p++;
        } else if (q_char == '\"') {
          q_char = 0;
          p++;
        } else {
          *q++ = *p++;
        }
      } else if (*p == '\'') {
        if (!q_char) {
          q_char = *p++;
        } else if (q_char == '\'') {
          q_char = 0;
          p++;
        } else {
          *q++ = *p++;
        }
      } else if (*p == '\\') {
        if (q_char == '\'') {
          *q++ = *p++;
        } else {
          switch (p[1]) {
          case 0:
            *q++ = '\\';
            p++;
            break;
          case 'x': case 'X':
            if (!isxdigit(p[2])) {
              code = -TINF_E_INVALID_ESCAPE;
              goto failure;
              p++;
              break;
            }
            p += 2;
            memset(nb, 0, sizeof(nb));
            nb[0] = *p++;
            if (isxdigit(*p)) nb[1] = *p++;
            *q++ = strtol(nb, 0, 16);
            break;

          case '0': case '1': case '2': case '3':
            p++;
            memset(nb, 0, sizeof(nb));
            nb[0] = *p++;
            if (*p >= '0' && *p <= '7') nb[1] = *p++;
            if (*p >= '0' && *p <= '7') nb[2] = *p++;
            *q++ = strtol(nb, 0, 8);
            break;

          case '4': case '5': case '6': case '7':
            p++;
            memset(nb, 0, sizeof(nb));
            nb[0] = *p++;
            if (*p >= '0' && *p <= '7') nb[1] = *p++;
            *q++ = strtol(nb, 0, 8);
            break;

          case 'a': *q++ = '\a'; p += 2; break;
          case 'b': *q++ = '\b'; p += 2; break;
          case 'f': *q++ = '\f'; p += 2; break;
          case 'n': *q++ = '\n'; p += 2; break;
          case 'r': *q++ = '\r'; p += 2; break;
          case 't': *q++ = '\t'; p += 2; break;
          case 'v': *q++ = '\v'; p += 2; break;
          default:
            p++;
            *q++ = *p++;
            break;
          }
        }
      } else if (isspace(*p)) {
        if (q_char) {
          *q++ = *p++;
        } else {
          *q = 0;
          if (pcmd->u + 1 >= pcmd->a) {
            pcmd->a *= 2;
            old_v = pcmd->v;
            pcmd->v=(unsigned char**)realloc(pcmd->v,
                                             pcmd->a*sizeof(pcmd->v[0]));
            if (!pcmd->v) {
              pcmd->v = old_v;
              code = -TINF_E_NO_MEMORY;
              goto failure;
            }
          }
          if (!(qq = strdup(locbuf))) {
            code = -TINF_E_NO_MEMORY;
            goto failure;
          }
          pcmd->v[pcmd->u++] = qq;
          pcmd->v[pcmd->u] = 0;
          while (isspace(*p)) p++;
          if (!*p) break;
          q = locbuf;
        }
      } else if (*p < ' ') {
        code = -TINF_E_STRAY_CONTROL_CHAR;
        goto failure;
        *q++ = ' ';
      } else {
        *q++ = *p++;
      }
    }
  }
  return 0;

 failure:
  if (pcmd->v) {
    for (i = 0; i < pcmd->u; i++)
      if (pcmd->v[i]) free(pcmd->v[i]);
    free(pcmd->v);
  }
  memset(pcmd, 0, sizeof(*pcmd));
  return code;
}

static void
append_char(unsigned char **p_t, int *p_a, int *p_u, int c)
{
  if (!*p_t || !*p_a) {
    *p_a = 32;
    *p_t = (unsigned char*) malloc(*p_a);
  } else if (*p_u == *p_a) {
    *p_a *= 2;
    *p_t = (unsigned char *) realloc(*p_t, *p_a);
  }
  if (!*p_t) return;
  (*p_t)[(*p_u)++] = c;
}

static void
append_string(unsigned char **p_t, int *p_a, int *p_u, const unsigned char *s)
{
  int slen;

  if (!s || !*s) return;
  slen = strlen(s);
  if (*p_u + slen > *p_a) {
    if (*p_a <= 0) *p_a = 32;
    while (*p_u + slen > *p_a) *p_a *= 2;
    *p_t = (unsigned char *) realloc(*p_t, *p_a);
    if (!*p_t) return;
  }
  while (*s) {
    (*p_t)[(*p_u)++] = *s++;
  }
}

static int
need_quotes(const unsigned char *str)
{
  if (!str) return 0;
  for (; *str; ++str) {
    if (*str <= ' ' || *str == 0177 || *str == '\'' || *str == '\"' || *str == '\\')
      return 1;
  }
  return 0;
}

static void
append_string_quoted(unsigned char **p_t, int *p_a, int *p_u, const unsigned char *s)
{
  unsigned char buf[16];
  if (!s || !*s) return;
  for (; *s; ++s) {
    switch (*s) {
    case '\t':
      append_string(p_t, p_a, p_u, "\\t");
      break;
    case '\r':
      append_string(p_t, p_a, p_u, "\\r");
      break;
    case '\n':
      append_string(p_t, p_a, p_u, "\\n");
      break;
    case '\'':
      append_string(p_t, p_a, p_u, "\\\'");
      break;
    case '\"':
      append_string(p_t, p_a, p_u, "\\\"");
      break;
    case '\\':
      append_string(p_t, p_a, p_u, "\\\\");
      break;
    default:
      if (*s < ' ' || *s == 0177) {
        snprintf(buf, sizeof(buf), "\\%03o", *s);
        append_string(p_t, p_a, p_u, buf);
      } else {
        append_char(p_t, p_a, p_u, *s);
      }
      break;
    }
  }
}

static unsigned char *
unparse_str_array(int arr_u, char **arr_v)
{
  int i, a = 0, u = 0;
  unsigned char *t = NULL;

  if (arr_u <= 0 || !arr_v) return strdup("");
  for (i = 0; i < arr_u; ++i) {
    if (i > 0) append_char(&t, &a, &u, ' ');
    if (!arr_v[i]) {
      append_string(&t, &a, &u, "(null)");
    } else {
      if (need_quotes(arr_v[i])) {
        append_char(&t, &a, &u, '\"');
        append_string_quoted(&t, &a, &u, arr_v[i]);
        append_char(&t, &a, &u, '\"');
      } else {
        append_string(&t, &a, &u, arr_v[i]);
      }
    }
  }
  append_char(&t, &a, &u, 0);
  return t;
}

unsigned char *
testinfo_unparse_cmdline(const struct testinfo_struct *ti)
{
  return unparse_str_array(ti->cmd_argc, ti->cmd_argv);
}

unsigned char *
testinfo_unparse_environ(const struct testinfo_struct *ti)
{
  return unparse_str_array(ti->env_u, ti->env_v);
}

unsigned char *
testinfo_unparse_checker_env(const struct testinfo_struct *ti)
{
  return unparse_str_array(ti->checker_env_u, ti->checker_env_v);
}

unsigned char *
testinfo_unparse_interactor_env(const struct testinfo_struct *ti)
{
  return unparse_str_array(ti->interactor_env_u, ti->interactor_env_v);
}

unsigned char *
testinfo_unparse_init_env(const struct testinfo_struct *ti)
{
  return unparse_str_array(ti->init_env_u, ti->init_env_v);
}

unsigned char *
testinfo_unparse_compiler_env(const struct testinfo_struct *ti)
{
  return unparse_str_array(ti->compiler_env_u, ti->compiler_env_v);
}

unsigned char *
testinfo_unparse_style_checker_env(const struct testinfo_struct *ti)
{
  return unparse_str_array(ti->style_checker_env_u, ti->style_checker_env_v);
}

unsigned char *
testinfo_unparse_ok_language(const struct testinfo_struct *ti)
{
  return unparse_str_array(ti->ok_language_u, ti->ok_language_v);
}

static void
free_cmdline(struct cmdline_buf *pcmd)
{
  int i;

  if (pcmd->v) {
    for (i = 0; i < pcmd->u; i++)
      if (pcmd->v[i]) free(pcmd->v[i]);
    free(pcmd->v);
  }
  memset(pcmd, 0, sizeof(*pcmd));
}

static inline int
is_ident_char(int c)
{
  return isalnum(c) || c == '_';
}

#define FAIL(code) do { retval = -code; goto fail; } while (0)

static int
parse_size(const unsigned char *str, long long *p_value)
{
  if (!str || !*str) return -1;
  char *eptr = NULL;
  errno = 0;
  long long value = strtoll(str, &eptr, 10);
  if (errno) {
    // overflow
    return -1;
  }
  if (*eptr == 'G' || *eptr == 'g') {
    if (__builtin_mul_overflow(value, 1024LL * 1024LL * 1024LL, &value)) {
      // overflow
      return -1;
    }
    ++eptr;
  } else if (*eptr == 'M' || *eptr == 'm') {
    if (__builtin_mul_overflow(value, 1024LL * 1024LL, &value)) {
      // overflow
      return -1;
    }
    ++eptr;
  } else if (*eptr == 'K' || *eptr == 'k') {
    if (__builtin_mul_overflow(value, 1024LL, &value)) {
      // overflow
      return -1;
    }
    ++eptr;
  }
  if (value < 0) value = -1;
  if (p_value) *p_value = value;
  return 1;
}

static int
parse_line(const unsigned char *str, size_t len, testinfo_t *pt, struct testinfo_subst_handler *sh)
{
  unsigned char *subst_str = NULL;
  const unsigned char *s = str;
  unsigned char *name_buf = 0, *p;
  unsigned char *val_buf = 0;
  unsigned char **ppval;
  size_t len2;
  struct cmdline_buf cmd;
  int retval = 0, x, n;
  int tag;

  if (sh && pt->enable_subst > 0) {
    subst_str = sh->substitute(sh, str);
    str = subst_str;
    s = str;
    len = strlen(str);
  }

  memset(&cmd, 0, sizeof(cmd));
  if (!(name_buf = (unsigned char *) alloca(len + 1))) FAIL(TINF_E_NO_MEMORY);
  if (!(val_buf = (unsigned char *) alloca(len + 2))) FAIL(TINF_E_NO_MEMORY);

  while (isspace(*s)) s++;
  p = name_buf;
  if (!is_ident_char(*s)) FAIL(TINF_E_IDENT_EXPECTED);
  while (is_ident_char(*s)) *p++ = *s++;
  *p = 0;
  while (isspace(*s)) s++;
  if (!*s) {
    /* implicit "1" */
    strcpy(val_buf, "1");
  } else if (*s != '=') {
    FAIL(TINF_E_EQUAL_EXPECTED);
  } else {
    s++;
    while (isspace(*s)) s++;
    strcpy(val_buf, s);
    len2 = strlen(val_buf);
    while (len2 > 0 && isspace(val_buf[len2 - 1])) len2--;
  }
  if ((retval = parse_cmdline(val_buf, &cmd)) < 0) {
    free_cmdline(&cmd);
    free(subst_str);
    return retval;
  }

switch ((tag = match(name_buf))) {
  case Tag_params:
    if (pt->cmd_argc >= 0) FAIL(TINF_E_VAR_REDEFINED);
    pt->cmd_argc = cmd.u;
    pt->cmd_argv = (char**) cmd.v;
    memset(&cmd, 0, sizeof(cmd));
    break;
  case Tag_environ:
    if (pt->env_u > 0) FAIL(TINF_E_VAR_REDEFINED);
    pt->env_u = cmd.u;
    pt->env_v = (char**) cmd.v;
    memset(&cmd, 0, sizeof(cmd));
    break;
  case Tag_checker_env:
    if (pt->checker_env_u > 0) FAIL(TINF_E_VAR_REDEFINED);
    pt->checker_env_u = cmd.u;
    pt->checker_env_v = (char**) cmd.v;
    memset(&cmd, 0, sizeof(cmd));
    break;
  case Tag_interactor_env:
    if (pt->interactor_env_u > 0) FAIL(TINF_E_VAR_REDEFINED);
    pt->interactor_env_u = cmd.u;
    pt->interactor_env_v = (char**) cmd.v;
    memset(&cmd, 0, sizeof(cmd));
    break;
  case Tag_init_env:
    if (pt->init_env_u > 0) FAIL(TINF_E_VAR_REDEFINED);
    pt->init_env_u = cmd.u;
    pt->init_env_v = (char**) cmd.v;
    memset(&cmd, 0, sizeof(cmd));
    break;
  case Tag_compiler_env:
    if (pt->compiler_env_u > 0) FAIL(TINF_E_VAR_REDEFINED);
    pt->compiler_env_u = cmd.u;
    pt->compiler_env_v = (char**) cmd.v;
    memset(&cmd, 0, sizeof(cmd));
    break;
  case Tag_style_checker_env:
    if (pt->style_checker_env_u > 0) FAIL(TINF_E_VAR_REDEFINED);
    pt->style_checker_env_u = cmd.u;
    pt->style_checker_env_v = (char**) cmd.v;
    memset(&cmd, 0, sizeof(cmd));
    break;
  case Tag_ok_language:
    if (pt->ok_language_u > 0) FAIL(TINF_E_VAR_REDEFINED);
    pt->ok_language_u = cmd.u;
    pt->ok_language_v = (char**) cmd.v;
    memset(&cmd, 0, sizeof(cmd));
    break;
  case Tag_comment:
  case Tag_team_comment:
  case Tag_source_stub:
  case Tag_working_dir:
  case Tag_program_name:
    ppval = XPDEREF(unsigned char *, pt, tag_offsets[tag]);
    if (*ppval) FAIL(TINF_E_VAR_REDEFINED);
    if (cmd.u < 1) FAIL(TINF_E_EMPTY_VALUE);
    if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
    *ppval = cmd.v[0];
    cmd.v[0] = 0;
    break;
  case Tag_exit_code:
    if (cmd.u < 1) FAIL(TINF_E_EMPTY_VALUE);
    if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
    if (sscanf(cmd.v[0], "%d%n", &x, &n) != 1 || cmd.v[0][n]
        || x < 0 || x > 255)
      FAIL(TINF_E_INVALID_VALUE);
    pt->exit_code = x;
    break;
  case Tag_max_open_file_count:
  {
    int *pint = XPDEREF(int, pt, tag_offsets[tag]);
    if (cmd.u < 1) FAIL(TINF_E_EMPTY_VALUE);
    if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
    if (sscanf(cmd.v[0], "%d%n", &x, &n) != 1 || cmd.v[0][n] || x < 0 || x > 1024)
      FAIL(TINF_E_INVALID_VALUE);
    *pint = x;
    break;
  }
  case Tag_max_process_count:
    if (cmd.u < 1) FAIL(TINF_E_EMPTY_VALUE);
    if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
    if (sscanf(cmd.v[0], "%d%n", &x, &n) != 1 || cmd.v[0][n] || x < 0 || x > 1024)
      FAIL(TINF_E_INVALID_VALUE);
    pt->max_process_count = x;
    break;
  case Tag_time_limit_ms:
  case Tag_real_time_limit_ms:
  {
    int *pint = XPDEREF(int, pt, tag_offsets[tag]);
    if (cmd.u < 1) FAIL(TINF_E_EMPTY_VALUE);
    if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
    if (sscanf(cmd.v[0], "%d%n", &x, &n) != 1 || cmd.v[0][n] || x <= 0)
      FAIL(TINF_E_INVALID_VALUE);
    *pint = x;
    break;
  }
  case Tag_max_vm_size:
  case Tag_max_stack_size:
  case Tag_max_file_size:
  case Tag_max_rss_size:
    if (cmd.u < 1) FAIL(TINF_E_EMPTY_VALUE);
    if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
    if (parse_size(cmd.v[0], XPDEREF(long long, pt, tag_offsets[tag])) < 0) FAIL(TINF_E_INVALID_VALUE);
    break;
  case Tag_check_stderr:
  case Tag_disable_stderr:
  case Tag_enable_subst:
  case Tag_compiler_must_fail:
  case Tag_allow_compile_error:
  case Tag_disable_valgrind:
  case Tag_ignore_exit_code:
  {
    int *pint = XPDEREF(int, pt, tag_offsets[tag]);
    if (cmd.u < 1) {
      x = 1;
    } else {
      if (cmd.u > 1) FAIL(TINF_E_MULTIPLE_VALUE);
      if (sscanf(cmd.v[0], "%d%n", &x, &n) != 1 || cmd.v[0][n]
          || x < 0 || x > 1)
        FAIL(TINF_E_INVALID_VALUE);
    }
    *pint = x;
    break;
  }
  default:
    FAIL(TINF_E_INVALID_VAR_NAME);
  }

  free_cmdline(&cmd);
  free(subst_str);
  return 0;

 fail:
  free_cmdline(&cmd);
  free(subst_str);
  return retval;
}

static int
parse_file(FILE *fin, testinfo_t *pt, struct testinfo_subst_handler *sh)
{
  struct line_buf buf;
  int retval;

  memset(&buf, 0, sizeof(buf));
  while (read_line(fin, &buf) >= 0) {
    /*
    if ((t = strchr(buf.v, '#'))) {
      *t = 0;
      buf.u = t - buf.v;
    }
    */
    while (buf.u > 0 && isspace(buf.v[buf.u - 1]))
      buf.v[--buf.u] = 0;
    if (!buf.u) continue;

    if ((retval = parse_line(buf.v, buf.u, pt, sh))) {
      if (buf.v) free(buf.v);
      return retval;
    }
  }
  if (buf.v) free(buf.v);
  return 0;
}

int
testinfo_parse(const char *path, testinfo_t *pt, struct testinfo_subst_handler *sh)
{
  FILE *fin = 0;
  int retval;

  memset(pt, 0, sizeof(*pt));
  pt->cmd_argc = -1;
  pt->disable_stderr = -1;
  pt->max_open_file_count = -1;
  pt->max_process_count = -1;
  pt->max_vm_size = -1LL;
  pt->max_stack_size = -1LL;
  pt->max_file_size = -1LL;
  pt->max_rss_size = -1LL;
  pt->ignore_exit_code = -1;
  if (!(fin = fopen(path, "r"))) {
    memset(pt, 0, sizeof(*pt));
    return -TINF_E_CANNOT_OPEN;
  }
  if ((retval = parse_file(fin, pt, sh)) < 0) {
    fclose(fin);
    memset(pt, 0, sizeof(*pt));
    return retval;
  }
  fclose(fin);
  return 0;
}

void
testinfo_free(testinfo_t *pt)
{
  int i;

  if (!pt) return;

  if (pt->cmd_argc > 0 && pt->cmd_argv) {
    for (i = 0; i < pt->cmd_argc; i++)
      if (pt->cmd_argv[i]) free(pt->cmd_argv[i]);
    free(pt->cmd_argv);
  }
  if (pt->env_u > 0 && pt->env_v) {
    for (i = 0; i < pt->env_u; ++i) {
      if (pt->env_v[i]) free(pt->env_v[i]);
    }
    free(pt->env_v);
  }
  if (pt->checker_env_u > 0 && pt->checker_env_v) {
    for (i = 0; i < pt->checker_env_u; ++i) {
      if (pt->checker_env_v[i]) free(pt->checker_env_v[i]);
    }
    free(pt->checker_env_v);
  }
  if (pt->interactor_env_u > 0 && pt->interactor_env_v) {
    for (i = 0; i < pt->interactor_env_u; ++i) {
      if (pt->interactor_env_v[i]) free(pt->interactor_env_v[i]);
    }
    free(pt->interactor_env_v);
  }
  if (pt->init_env_u > 0 && pt->init_env_v) {
    for (i = 0; i < pt->init_env_u; ++i) {
      if (pt->init_env_v[i]) free(pt->init_env_v[i]);
    }
    free(pt->init_env_v);
  }
  if (pt->compiler_env_u > 0 && pt->compiler_env_v) {
    for (i = 0; i < pt->compiler_env_u; ++i) {
      if (pt->compiler_env_v[i]) free(pt->compiler_env_v[i]);
    }
    free(pt->compiler_env_v);
  }
  if (pt->style_checker_env_u > 0 && pt->style_checker_env_v) {
    for (i = 0; i < pt->style_checker_env_u; ++i) {
      if (pt->style_checker_env_v[i]) free(pt->style_checker_env_v[i]);
    }
    free(pt->style_checker_env_v);
  }
  if (pt->ok_language_u > 0 && pt->ok_language_v) {
    for (i = 0; i < pt->ok_language_u; ++i) {
      free(pt->ok_language_v[i]);
    }
    free(pt->ok_language_v);
  }
  if (pt->comment) free(pt->comment);
  if (pt->team_comment) free(pt->team_comment);
  if (pt->source_stub) free(pt->source_stub);
  free(pt->working_dir);
  free(pt->program_name);
  memset(pt, 0, sizeof(*pt));
}

static const unsigned char * const error_codes[] =
{
  [TINF_E_OK] = "OK - no error",
  [TINF_E_EOF] = "EOF",
  [TINF_E_IO_ERROR] = "IO error",
  [TINF_E_NO_MEMORY] = "memory exhausted",
  [TINF_E_UNCLOSED_QUOTE] = "unclosed quote",
  [TINF_E_STRAY_CONTROL_CHAR] = "stray control character",
  [TINF_E_INVALID_ESCAPE] = "invalid escape sequence",
  [TINF_E_IDENT_EXPECTED] = "variable name expected",
  [TINF_E_EQUAL_EXPECTED] = "'=' expected",
  [TINF_E_CANNOT_OPEN] = "cannot open input file",
  [TINF_E_INVALID_VAR_NAME] = "invalid variable name",
  [TINF_E_VAR_REDEFINED] = "variable is redefined",
  [TINF_E_EMPTY_VALUE] = "variable value is empty",
  [TINF_E_MULTIPLE_VALUE] = "variable value is multiple",
  [TINF_E_INVALID_VALUE] = "variable value is invalid",
};
const char *
testinfo_strerror(int err)
{
  if (err < 0) err = -err;
  if (err >= TINF_E_LAST || !error_codes[err]) {
    /* note, that heap memory almost surely will be leaked in this
     * case, however, if the error code is invalid, the program
     * is already working not as expected
     */
    unsigned char *str = (unsigned char*) malloc(128);
    if (!str) {
      return "Unknown testinfo error code, and malloc failed";
    } else {
      snprintf(str, 128, "Unknown testinfo error code %d", err);
      return str;
    }
  }
  return error_codes[err];
}
