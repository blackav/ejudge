#ifndef __CHECKER_INTERNAL_H__
#define __CHECKER_INTERNAL_H__

/* $Id$ */

/* Copyright (C) 2003 Alexander Chernov <cher@ispras.ru> */

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
extern const unsigned char * const f_arr_names[3];

#if NEED_TGZ - 0 == 1
extern DIR *dir_in;
extern DIR *dir_out;
#endif /* NEED_TGZ */

void checker_do_init(int, char **, int, int, int);

void fatal(int code, char const *format, ...)
     __attribute__ ((noreturn, format(printf, 2, 3)));
void fatal_CF(char const *format, ...)
     __attribute__ ((noreturn, format(printf, 1, 2)));
void fatal_PE(char const *format, ...)
     __attribute__ ((noreturn, format(printf, 1, 2)));
void fatal_WA(char const *format, ...)
     __attribute__ ((noreturn, format(printf, 1, 2)));
void checker_OK(void) __attribute__((noreturn));

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *ptr, size_t size);
unsigned char *xstrdup(const unsigned char *str);

void checker_corr_close(void);
void checker_corr_eof(void);
void checker_in_close(void);
void checker_in_eof(void);
void checker_normalize_file(unsigned char **, size_t *);
int checker_read_buf(int, const unsigned char *, int, unsigned char *, size_t);
int checker_read_corr_int(const unsigned char *, int, int *);
int checker_read_double(int, const unsigned char *, int, double *);
void checker_read_file(int, unsigned char **, size_t *);
void checker_read_file_by_line(int, unsigned char ***, size_t *);
int checker_read_in_double(const unsigned char *, int, double *);
int checker_read_in_int(const unsigned char *, int, int *);
int checker_read_team_double(const unsigned char *, int, double *);
int checker_read_team_int(const unsigned char *, int, int *);
int checker_read_team_long_double(const unsigned char *, int, long double *);
void checker_team_close(void);
void checker_team_eof(void);

#endif /* __CHECKER_INTERNAL_H__ */

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
