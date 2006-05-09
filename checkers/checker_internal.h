#ifndef __CHECKER_INTERNAL_H__
#define __CHECKER_INTERNAL_H__

/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ispras.ru> */

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
#define CHECKER_char_t char
extern "C" {
#else
#define CHECKER_char_t unsigned char
#endif /* __cplusplus */

#if defined _MSC_VER || defined __MINGW32__
#undef NEED_TGZ
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <math.h>

#if NEED_TGZ - 0 == 1
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#endif /* NEED_TGZ */

#define XCALLOC(p,s)    ((p) = (typeof(p)) xcalloc((s), sizeof((p)[0])))
#define XREALLOC(p,s)   ((p) = (typeof(p)) xrealloc((p), (s) * sizeof((p)[0])))
#define XALLOCA(p,s)    ((p) = (typeof(p)) alloca((s) * sizeof((p)[0])))
#define XALLOCAZ(p,s)   ((p) = (typeof(p)) alloca((s) * sizeof((p)[0])), memset((p), 0, (s)*sizeof(*(p))), (p))
#define XMEMMOVE(d,s,c) (memmove((d),(s),(c)*sizeof(*(d))))
#define XMEMZERO(d,c)   (memset((d),0,(c)*sizeof(*(d))))

enum
{
  RUN_OK               = 0,
  RUN_COMPILE_ERR      = 1,
  RUN_RUN_TIME_ERR     = 2,
  RUN_TIME_LIMIT_ERR   = 3,
  RUN_PRESENTATION_ERR = 4,
  RUN_WRONG_ANSWER_ERR = 5,
  RUN_CHECK_FAILED     = 6
};

extern FILE *f_in;
extern FILE *f_team;
extern FILE *f_corr;
extern FILE *f_arr[3];
extern const CHECKER_char_t * const f_arr_names[3];

#if NEED_TGZ - 0 == 1
extern DIR *dir_in;
extern DIR *dir_out;
extern CHECKER_char_t *dir_in_path;
extern CHECKER_char_t *dir_out_path;
#endif /* NEED_TGZ */

void checker_do_init(int, char **, int, int, int);

#ifdef __GNUC__
#define LIBCHECKER_ATTRIB(x) __attribute__(x)
#else
#define LIBCHECKER_ATTRIB(x)
#endif

#ifdef __GNUC__
typedef long long libchecker_i64_t;
typedef unsigned long long libchecker_u64_t;
#else
typedef __int64 libchecker_i64_t;
typedef unsigned __int64 libchecker_u64_t;
#endif

void fatal(int code, char const *format, ...)
	 LIBCHECKER_ATTRIB((noreturn, format(printf, 2, 3)));
void fatal_CF(char const *format, ...)
     LIBCHECKER_ATTRIB((noreturn, format(printf, 1, 2)));
void fatal_PE(char const *format, ...)
     LIBCHECKER_ATTRIB((noreturn, format(printf, 1, 2)));
void fatal_WA(char const *format, ...)
     LIBCHECKER_ATTRIB((noreturn, format(printf, 1, 2)));
void fatal_read(int streamno, char const *format, ...)
     LIBCHECKER_ATTRIB((noreturn, format(printf, 2, 3)));
void checker_OK(void) LIBCHECKER_ATTRIB((noreturn));

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *ptr, size_t size);
CHECKER_char_t *xstrdup(const CHECKER_char_t *str);

void checker_corr_close(void);
void checker_corr_eof(void);
void checker_in_close(void);
void checker_in_eof(void);
void checker_normalize_file(CHECKER_char_t **, size_t *);
void checker_normalize_spaces_in_file(CHECKER_char_t **, size_t *);
void checker_normalize_line(CHECKER_char_t *);
int  checker_read_buf(int, const CHECKER_char_t *, int,
                      CHECKER_char_t *,size_t);
void checker_read_file(int, CHECKER_char_t **, size_t *);
void checker_read_file_by_line(int, CHECKER_char_t ***, size_t *);
void checker_read_file_by_line_f(FILE *f, const unsigned char *,
                                 CHECKER_char_t ***, size_t *);
int  checker_read_line(int, const CHECKER_char_t *, int, CHECKER_char_t **);
int  checker_skip_eoln(int ind, int eof_error_flag);
void checker_team_close(void);
void checker_team_eof(void);

int  checker_read_int(int, const CHECKER_char_t *, int, int *);
int  checker_read_unsigned_int(int, const CHECKER_char_t *, int,
                               unsigned int *);
int  checker_read_long_long(int, const CHECKER_char_t *, int, libchecker_i64_t *);
int  checker_read_unsigned_long_long(int, const CHECKER_char_t *, int,
                                     libchecker_u64_t *);
int  checker_read_double(int, const CHECKER_char_t *, int, double *);
int  checker_read_long_double(int, const CHECKER_char_t *, int, long double *);

int  checker_read_in_int(const CHECKER_char_t *, int, int *);
int  checker_read_in_unsigned_int(const CHECKER_char_t *, int,
                                  unsigned int *);
int  checker_read_in_long_long(const CHECKER_char_t *, int, libchecker_i64_t *);
int  checker_read_in_unsigned_long_long(const CHECKER_char_t *, int,
										libchecker_u64_t *);
int  checker_read_in_double(const CHECKER_char_t *, int, double *);
int  checker_read_in_long_double(const CHECKER_char_t *, int, long double *);

int  checker_read_team_int(const CHECKER_char_t *, int, int *);
int  checker_read_team_unsigned_int(const CHECKER_char_t *, int,
                                    unsigned int *);
int  checker_read_team_long_long(const CHECKER_char_t *, int, libchecker_i64_t *);
int  checker_read_team_unsigned_long_long(const CHECKER_char_t *, int,
										  libchecker_u64_t *);
int  checker_read_team_double(const CHECKER_char_t *, int, double *);
int  checker_read_team_long_double(const CHECKER_char_t *, int, long double *);

int  checker_read_corr_int(const CHECKER_char_t *, int, int *);
int  checker_read_corr_unsigned_int(const CHECKER_char_t *, int,
                                    unsigned int *);
int  checker_read_corr_long_long(const CHECKER_char_t *, int, libchecker_i64_t *);
int  checker_read_corr_unsigned_long_long(const CHECKER_char_t *, int,
										  libchecker_u64_t *);
int  checker_read_corr_double(const CHECKER_char_t *, int, double *);
int  checker_read_corr_long_double(const CHECKER_char_t *, int, long double *);

int checker_eq_double(double v1, double v2, double eps);
int checker_eq_long_double(long double v1, long double v2, long double eps);
int checker_eq_float(float v1, float v2, float eps);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#undef CHECKER_char_t

#endif /* __CHECKER_INTERNAL_H__ */

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
