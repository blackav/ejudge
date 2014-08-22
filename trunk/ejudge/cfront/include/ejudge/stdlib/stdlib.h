/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_STDLIB_H__
#define __RCC_STDLIB_H__

/* Copyright (C) 1999-2004 Alexander Chernov <cher@ispras.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <features.h>

#ifndef RCC_SIZE_T_DEFINED
#define RCC_SIZE_T_DEFINED 1
typedef unsigned long size_t;
#endif /* RCC_SIZE_T_DEFINED */

#ifndef RCC_SSIZE_T_DEFINED
#define RCC_SSIZE_T_DEFINED 1
typedef long ssize_t;
#endif /* RCC_SSIZE_T_DEFINED */

#ifndef RCC_PTRDIFF_T_DEFINED
#define RCC_PTRDIFF_T_DEFINED 1
typedef long ptrdiff_t;
#endif /* RCC_PTRDIFF_T_DEFINED */

#ifndef RCC_WCHAR_T_DEFINED
#define RCC_WCHAR_T_DEFINED 1
/* FIXME: wchar_t should be somehow built-in */
typedef long int wchar_t;
#endif /* RCC_WCHAR_T_DEFINED */

#if !defined NULL
#define NULL 0
#endif

/* These flags are also in <sys/wait.h> */
#ifndef WNOHANG
int enum
{
#defconst WNOHANG 1
#defconst WUNTRACED 2
#defconst __WALL 0x40000000
#defconst __WCLONE 0x80000000
};
#endif /* WNOHANG */

/* These macros are also in <sys/wait.h> */
#ifndef WEXITSTATUS
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#define WTERMSIG(status)    ((status) & 0x7f)
#define WSTOPSIG(status)    WEXITSTATUS(status)
#define WIFEXITED(status)   (WTERMSIG(status) == 0)
#define WIFSIGNALED(status) (!WIFSTOPPED(status) && !WIFEXITED(status))
#define WIFSTOPPED(status)  (((status) & 0xff) == 0x7f)
#define WCOREDUMP(status)   ((status) & __WCOREFLAG)
#define WCOREFLAG           0x80
#define __WCOREFLAG         WCOREFLAG
#endif /* WEXITSTATUS */

typedef struct
{
  int quot;
  int rem;
} div_t;
typedef struct
{
  long int quot;
  long int rem;
} ldiv_t;
typedef struct
{
  long long int quot;
  long long int rem;
} lldiv_t;

int enum
{
#defconst RAND_MAX 2147483647
};

#ifndef EXIT_SUCCESS
int enum
{
#defconst EXIT_SUCCESS 0
#defconst EXIT_FAILURE 1
};
#endif /* EXIT_SUCCESS */

#define MB_CUR_MAX (__ctype_get_mb_cur_max ())
size_t __ctype_get_mb_cur_max(void);

double atof(const char *);
int atoi(const char *);
long atol(const char *);
long long atoll(const char *);
long long atoq(const char *);

double strtod(const char *, char **);
float strtof(const char *, char **);
long double strtold(const char *, char **);

long strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int);
long long strtoq(const char *, char **, int);
unsigned long long strtouq(const char *, char **, int);
long long strtoll(const char *, char **, int);
unsigned long long strtoull(const char *, char **, int);

#include <xlocale.h>

long int strtol_l(const char *nptr, char **restrict endptr,
                  int base, __locale_t loc);
unsigned long int strtoul_l(const char *nptr, char **endptr,
                            int base, __locale_t loc);
long long int strtoll_l(const char *nptr, char **endptr,
                        int base, __locale_t loc);
unsigned long long int strtoull_l(const char *nptr, char **endptr,
                                  int base, __locale_t loc);

double strtod_l(const char *nptr, char **endptr, __locale_t loc);
float strtof_l(const char *nptr, char **endptr, __locale_t loc);
long double strtold_l(const char *nptr, char **endptr, __locale_t loc);

double __strtod_internal(const char * nptr, char **endptr, int group);
float __strtof_internal(const char * nptr, char **endptr, int group);
long double __strtold_internal(const char *nptr, char ** endptr, int group);
long int __strtol_internal(const char *nptr, char **endptr,
                           int base, int group);
unsigned long int strtoul_internal(const char *nptr, char **endptr,
                                   int base, int group);
long long int __strtoll_internal(const char *nptr, char **endptr,
                                 int base, int group);
unsigned long long int __strtoull_internal(const char *nptr, char **endptr,
                                           int base, int group);

char *l64a(long int n);
long int a64l(const char *s);

#include <sys/types.h>

long int random(void);
void srandom(unsigned int);
char *initstate(unsigned int, char *, size_t);
char *setstate(char *);

struct random_data
{
  int32_t *fptr;
  int32_t *rptr;
  int32_t *state;
  int rand_type;
  int rand_deg;
  int rand_sep;
  int32_t *end_ptr;
};

int random_r(struct random_data *buf, int32_t *result);
int srandom_r(unsigned int seed, struct random_data *buf);
int initstate_r(unsigned int seed, char *statebuf, size_t statelen,
                struct random_data *buf);
int setstate_r(char *statebuf, struct random_data *buf);

int rand(void);
void srand(unsigned int seed);
int rand_r(unsigned int *seedp);

double drand48(void);
double erand48(unsigned short int xsubi[3]);
long int lrand48(void);
long int nrand48(unsigned short int xsubi[3]);
long int mrand48(void);
long int jrand48(unsigned short int xsubi[3]);
void srand48(long int seedval);
unsigned short int *seed48(unsigned short int seed16v[3]);
void lcong48(unsigned short int param[7]);

struct drand48_data
{
  unsigned short int __x[3];
  unsigned short int __old_x[3];
  unsigned short int __c;
  unsigned short int __init;
  unsigned long long int __a;
};

int drand48_r(struct drand48_data *buffer, double *result);
int erand48_r(unsigned short int xsubi[3], struct drand48_data *buffer,
              double *result);
int lrand48_r(struct drand48_data *buffer, long int *result);
int nrand48_r(unsigned short int xsubi[3], struct drand48_data *buffer,
              long int *result);
int mrand48_r(struct drand48_data *buffer, long int *result);
int jrand48_r(unsigned short int xsubi[3], struct drand48_data *buffer,
              long int *result);
int srand48_r(long int seedval, struct drand48_data *buffer);
int seed48_r(unsigned short int seed16v[3], struct drand48_data *buffer);
int lcong48_r(unsigned short int param[7], struct drand48_data *buffer);

void *malloc(size_t);
void *realloc(void *, size_t);
void *calloc(size_t, size_t);
void  free(void*);
void cfree(void *);

#ifndef alloca
#define alloca(s) (__builtin_alloca(s))
#endif /* alloca */

void *valloc(size_t size);
int posix_memalign(void **memptr, size_t alignment, size_t size);

void abort(void) __attribute__((noreturn));

int atexit(void (*)(void));
int on_exit(void (*func)(int status, void *arg), void *arg);
void exit(int) __attribute__((noreturn));
void _Exit(int status) __attribute__((noreturn));

char *getenv(const char *);
char *__secure_getenv(const char *name);
int putenv(char *);
int setenv(const char *name, const char *value, int replace);
int unsetenv(const char *name);
int clearenv(void);

char *mktemp(char *template);
int mkstemp(char *template);
int mkstemp64(char *template);
char *mkdtemp(char *template);

int system(const char *);
char *canonicalize_file_name(const char *name);
char *realpath(const char *name, char *resolved);

void *bsearch(const void *key, const void *base, size_t nmemb,
              size_t size, int (*compar)(const void *, const void *));
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));

int abs(int x);
long int labs(long int x);
long long int llabs(long long int x);

div_t div(int numer, int denom);
ldiv_t ldiv(long int numer, long int denom);
lldiv_t lldiv(long long int numer, long long int denom);

char *ecvt(double value, int ndigit, int *decpt, int *sign);
char *fcvt(double value, int ndigit, int *decpt, int *sign);
char *gcvt(double value, int ndigit, char *buf);

char *qecvt(long double value, int ndigit, int *decpt, int *sign);
char *qfcvt(long double value, int ndigit, int *decpt, int *sign);
char *qgcvt(long double value, int ndigit, char *buf);

int ecvt_r(double value, int ndigit, int *decpt, int *sign, char *buf,
           size_t len);
int fcvt_r(double value, int ndigit, int *decpt, int *sign, char *buf,
           size_t len);

int qecvt_r(long double value, int ndigit, int *decpt, int *sign,
            char *buf, size_t len);
int qfcvt_r(long double value, int ndigit, int *decpt, int *sign,
            char *buf, size_t len);

int mblen(const char *s, size_t n);
int mbtowc(wchar_t *pwc, const char *s, size_t n);
int wctomb(char *s, wchar_t wchar);
size_t mbstowcs(wchar_t * pwcs, const char *s, size_t n);
size_t wcstombs(char *s, const wchar_t *pwcs, size_t n);

int rpmatch(const char *response);

int getsubopt(char **optionp, char *const *tokens, char **valuep);

void setkey(const char *key);

int posix_openpt(int oflag);

int grantpt(int fd);
int unlockpt(int fd);
char *ptsname(int fd);
int ptsname_r(int fd, char *buf, size_t buflen);
int getpt(void);

int getloadavg(double loadavg[], int nelem);

#endif /* __RCC_STDLIB_H__ */
