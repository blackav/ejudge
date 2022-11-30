/* -*- c -*- */
#ifndef __TESTINFO_H__
#define __TESTINFO_H__

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

#ifdef __cplusplus
extern "C" {
#else
#endif /* __cplusplus */

/* error codes, actual error values are negative */
enum
{
  TINF_E_OK = 0,
  TINF_E_EOF,
  TINF_E_IO_ERROR,
  TINF_E_NO_MEMORY,
  TINF_E_UNCLOSED_QUOTE,
  TINF_E_STRAY_CONTROL_CHAR,
  TINF_E_INVALID_ESCAPE,
  TINF_E_IDENT_EXPECTED,
  TINF_E_EQUAL_EXPECTED,
  TINF_E_CANNOT_OPEN,
  TINF_E_INVALID_VAR_NAME,
  TINF_E_VAR_REDEFINED,
  TINF_E_EMPTY_VALUE,
  TINF_E_MULTIPLE_VALUE,
  TINF_E_INVALID_VALUE,

  TINF_E_LAST,
};

struct testinfo_array
{
  char **v;
  int u;
};

struct testinfo_struct
{
  struct testinfo_array cmd;
  struct testinfo_array env;
  struct testinfo_array checker_env;
  struct testinfo_array interactor_env;
  struct testinfo_array init_env;
  struct testinfo_array compiler_env;
  struct testinfo_array style_checker_env;
  struct testinfo_array ok_language;
  char *comment;
  char *team_comment;
  char *source_stub;
  char *working_dir;
  char *program_name;
  long long max_vm_size;
  long long max_stack_size;
  long long max_file_size;
  long long max_rss_size;
  int exit_code;
  int ignore_exit_code;
  int check_stderr;
  int disable_stderr;
  int enable_subst;
  int compiler_must_fail;
  int disable_valgrind;
  int max_open_file_count;
  int max_process_count;
  int time_limit_ms;
  int real_time_limit_ms;
  int allow_compile_error;
};
typedef struct testinfo_struct testinfo_t;

#if EJUDGE_COMPAT - 0 != 0
#define cmd_argc cmd.u
#define cmd_argv cmd.v
#endif

struct testinfo_subst_handler
{
  unsigned char * (*substitute)(struct testinfo_subst_handler *, const unsigned char *);
};

int testinfo_parse(const char *path, testinfo_t *pt, struct testinfo_subst_handler *sh);
void testinfo_free(testinfo_t *pt);
const char *testinfo_strerror(int errcode);
unsigned char *testinfo_unparse_cmdline(const testinfo_t *pt);
unsigned char *testinfo_unparse_environ(const struct testinfo_struct *ti);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TESTINFO_H__ */
