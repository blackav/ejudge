/* -*- c -*- */
/* $Id$ */
#ifndef __TESTINFO_H__
#define __TESTINFO_H__

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ejudge.ru> */

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
#define TESTINFO_char_t char
extern "C" {
#else
#define TESTINFO_char_t unsigned char
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

struct testinfo_struct
{
  int exit_code;
  int check_stderr;
  int cmd_argc;
  TESTINFO_char_t **cmd_argv;
  TESTINFO_char_t *comment;
  TESTINFO_char_t *team_comment;
};
typedef struct testinfo_struct testinfo_t;

int testinfo_parse(const TESTINFO_char_t *path, testinfo_t *pt);
void testinfo_free(testinfo_t *pt);
const TESTINFO_char_t *testinfo_strerror(int errcode);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#undef TESTINFO_char_t

#endif /* __TESTINFO_H__ */

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
