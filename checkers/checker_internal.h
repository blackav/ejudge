#ifndef __CHECKER_INTERNAL_H__
#define __CHECKER_INTERNAL_H__

/* Copyright (C) 2003-2017 Alexander Chernov <cher@ejudge.ru> */

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

#if defined __GNUC__
#define XCALLOC(p,s)    ((p) = (typeof(p)) xcalloc((s), sizeof((p)[0])))
#define XREALLOC(p,s)   ((p) = (typeof(p)) xrealloc((p), (s) * sizeof((p)[0])))
#define XALLOCA(p,s)    ((p) = (typeof(p)) alloca((s) * sizeof((p)[0])))
#define XALLOCAZ(p,s)   ((p) = (typeof(p)) alloca((s) * sizeof((p)[0])), memset((p), 0, (s)*sizeof(*(p))))
#else
#define XCALLOC(p,s)    ((p) = xcalloc((s), sizeof((p)[0])))
#define XREALLOC(p,s)   ((p) = xrealloc((p), (s) * sizeof((p)[0])))
#define XALLOCA(p,s)    ((p) = alloca((s) * sizeof((p)[0])))
#define XALLOCAZ(p,s)   ((p) = alloca((s) * sizeof((p)[0])), memset((p), 0, (s)*sizeof(*(p))))
#endif
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
  RUN_CHECK_FAILED     = 6,
  RUN_MEM_LIMIT_ERR    = 12,
  RUN_SECURITY_ERR     = 13,
  RUN_STYLE_ERR        = 14,
  RUN_WALL_TIME_LIMIT_ERR = 15,
  RUN_SKIPPED          = 18,

  RUN_MAX_STATUS       = 18,
};

/* S-expression types */
enum { CHECKER_SEXPR_ATOM, CHECKER_SEXPR_PAIR };
union checker_sexpr_elem;
typedef union checker_sexpr_elem *checker_sexpr_t;
struct checker_sexpr_pair
{
  int kind;
  checker_sexpr_t head;
  checker_sexpr_t tail;
};
struct checker_sexpr_atom
{
  int kind;
  unsigned char *value;
};
union checker_sexpr_elem
{
  int kind;
  struct checker_sexpr_atom a;
  struct checker_sexpr_pair p;
};

struct valuer_test_info
{
  int result;
  int score;
  int time_ms;
};

extern FILE *f_in;
extern FILE *f_out;
extern FILE *f_corr;
extern FILE *f_arr[3];
extern const char * const f_arr_names[3];

// backward compatibility
extern FILE *f_team;

#if NEED_TGZ - 0 == 1
extern DIR *dir_in;
extern DIR *dir_out;
extern char *dir_in_path;
extern char *dir_out_path;
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

typedef void (*checker_error_func_t)(char const *format, ...)
         LIBCHECKER_ATTRIB((noreturn, format(printf, 1, 2)));

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

void checker_drain(void);

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *str);

void checker_corr_close(void);
void checker_corr_eof(void);
void checker_in_close(void);
void checker_in_eof(void);
void checker_normalize_file(char **, size_t *);
void checker_normalize_spaces_in_file(char **, size_t *);
void checker_normalize_line(char *);

int  checker_read_buf(int, const char *, int,
                      char *,size_t)
        LIBCHECKER_ATTRIB((deprecated));
char *checker_read_buf_2(int ind, const char *name, int eof_error_flag,
                         char *sbuf, size_t ssz, char **pdbuf, size_t *pdsz);

void checker_in_open(const char *path);
void checker_out_open(const char *path);
void checker_corr_open(const char *path);

void checker_read_file(int, char **, size_t *);
void checker_read_file_f(FILE *, char **, size_t *);
void checker_read_file_by_line(int, char ***, size_t *);
void checker_read_file_by_line_f(FILE *f, const char *,
                                 char ***, size_t *);
int  checker_read_line(int, const char *, int, char **);
int  checker_skip_eoln(int ind, int eof_error_flag);
void checker_out_close(void);
void checker_out_eof(void);
void checker_out_eoln(int);

int  checker_read_int(int, const char *, int, int *);
int  checker_read_int_2(int, const char *, int, int, int *);
int  checker_read_unsigned_int(int, const char *, int, unsigned int *);
int  checker_read_unsigned_int_2(int, const char *, int, int, unsigned int *);
int  checker_read_long_long(int, const char *, int, libchecker_i64_t *);
int  checker_read_long_long_2(int, const char *, int, int, libchecker_i64_t *);
int  checker_read_unsigned_long_long(int, const char *, int, libchecker_u64_t*);
int  checker_read_unsigned_long_long_2(int, const char *, int, int, libchecker_u64_t*);
int  checker_read_double(int, const char *, int, double *);
int  checker_read_long_double(int, const char *, int, long double *);

int  checker_read_in_int(const char *, int, int *);
int  checker_read_in_unsigned_int(const char *, int,
                                  unsigned int *);
int  checker_read_in_long_long(const char *, int, libchecker_i64_t *);
int  checker_read_in_unsigned_long_long(const char *, int, libchecker_u64_t *);
int  checker_read_in_double(const char *, int, double *);
int  checker_read_in_long_double(const char *, int, long double *);

int  checker_read_out_int(const char *, int, int *);
int  checker_read_out_unsigned_int(const char *, int,
                                    unsigned int *);
int  checker_read_out_long_long(const char *, int, libchecker_i64_t *);
int  checker_read_out_unsigned_long_long(const char *, int,libchecker_u64_t *);
int  checker_read_out_double(const char *, int, double *);
int  checker_read_out_long_double(const char *, int, long double *);

int  checker_read_corr_int(const char *, int, int *);
int  checker_read_corr_unsigned_int(const char *, int,
                                    unsigned int *);
int  checker_read_corr_long_long(const char *, int, libchecker_i64_t *);
int  checker_read_corr_unsigned_long_long(const char *, int,libchecker_u64_t *);
int  checker_read_corr_double(const char *, int, double *);
int  checker_read_corr_long_double(const char *, int, long double *);

int checker_eq_double(double v1, double v2, double eps);
int checker_eq_double_abs(double v1, double v2, double eps);
int checker_eq_long_double(long double v1, long double v2, long double eps);
int checker_eq_long_double_abs(long double v1, long double v2, long double eps);
int checker_eq_float(float v1, float v2, float eps);
int checker_eq_float_abs(float v1, float v2, float eps);

checker_sexpr_t checker_read_sexpr(int ind);
int checker_eq_sexpr(checker_sexpr_t l_corr, checker_sexpr_t l_out);

int checker_koi8r_to_ucs4(int c);
int checker_koi8r_to_ucs4_buf(int*, const char*, size_t);
int checker_koi8r_to_ucs4_str(int*, const char*);
int checker_cp866_to_ucs4(int c);
int checker_cp866_to_ucs4_buf(int*, const char*, size_t);
int checker_cp866_to_ucs4_str(int*, const char*);
int checker_cp1251_to_ucs4(int c);
int checker_cp1251_to_ucs4_buf(int*, const char*, size_t);
int checker_cp1251_to_ucs4_str(int*, const char*, size_t);
int checker_iso_to_ucs4(int c);
int checker_iso_to_ucs4_buf(int*, const char*, size_t);
int checker_iso_to_ucs4_str(int*, const char*);
int checker_mac_to_ucs4(int c);
int checker_mac_to_ucs4_buf(int*, const char*, size_t);
int checker_mac_to_ucs4_str(int*, const char*);

int checker_utf8_to_ucs4_buf(int *, const char *, size_t);
int checker_utf8_to_ucs4_str(int *out, const char *in);

size_t checker_ucs4_to_utf8_size(const int *in);
const unsigned char *
checker_ucs4_to_utf8_str(unsigned char *buf, size_t size, const int *in);

int checker_ucs4_to_koi8r(int c);
char *checker_ucs4_to_koi8r_str(char *out, size_t size, const int *in);

int checker_ucs4_tolower(int c);
int *checker_ucs4_tolower_buf(int *buf, size_t size);

int checker_strcmp_ucs4(const int *s1, const int *s2);
int checker_eq_str_rus_ucs4(const char *s1, const int *s2);
int checker_eq_str_rus_ucs4_nocase(const char *s1, const int *s2);

int checker_is_utf8_locale(void);

// backward compatibility
#if defined __GNUC__
void checker_team_close(void)
  __attribute__((deprecated));
void checker_team_eof(void)
  __attribute__((deprecated));
void checker_team_eoln(int lineno)
  __attribute__((deprecated));
int  checker_read_team_int(const char *, int, int *)
  __attribute__((deprecated));
int  checker_read_team_unsigned_int(const char *, int, unsigned int *)
  __attribute__((deprecated));
int  checker_read_team_long_long(const char *, int, libchecker_i64_t *)
  __attribute__((deprecated));
int  checker_read_team_unsigned_long_long(const char *, int,libchecker_u64_t *)
  __attribute__((deprecated));
int  checker_read_team_double(const char *, int, double *)
  __attribute__((deprecated));
int  checker_read_team_long_double(const char *, int, long double *)
  __attribute__((deprecated));
#endif

/* new generation functions */

void
checker_eof(
        FILE *f,
        checker_error_func_t error_func,
        const char *name);

void
checker_eoln(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int lineno);

int
checker_skip_eoln_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag);

void
checker_read_file_by_line_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        char ***out_lines,
        size_t *out_lines_num);

int
checker_read_line_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag,
        char **out_str);

char *
checker_read_buf_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag,
        char *sbuf,             /* static buffer pointer */
        size_t ssz,             /* static buffer size */
        char **pdbuf,           /* dynamic pointer */
        size_t *pdsz);          /* dynamic size */

int
checker_read_int_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag,
        int *p_val);

int
checker_read_unsigned_int_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag,
        unsigned int *p_val);

int
checker_read_long_long_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag,
        long long *p_val);

int
checker_read_unsigned_long_long_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag,
        unsigned long long *p_val);

int
checker_read_double_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag,
        double *p_val);

int
checker_read_long_double_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag,
        long double *p_val);

void
valuer_parse_input(
        int *p_test_count,
        struct valuer_test_info **p_infos);

void checker_l10n_prepare(void);

int
checker_require_nl(FILE *f, int allow_fail);
void
checker_skip_bom(FILE *f);

int
checker_kill(int pid, int signal);

int
checker_stoi(const char *str, int base, int *p_int);
int
checker_stou(const char *str, int base, unsigned *p_value);
int
checker_stol(const char *str, int base, long *p_value);
int
checker_stoul(const char *str, int base, unsigned long *p_value);
int
checker_stoll(const char *str, int base, long long *p_value);
int
checker_stoull(const char *str, int base, unsigned long long *p_value);

int
checker_open_control_fd(void);

int
checker_kill_2(int socket_fd, int signal);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CHECKER_INTERNAL_H__ */
