/* -*- mode: c -*- */
/* $Id$ */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <math.h>

#ifndef NEED_CORR
#error You must define NEED_CORR macro
#endif /* NEED_CORR */

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

void fatal(int code, char const *format, ...)
     __attribute__ ((noreturn, format(printf, 2, 3)));

void fatal(int code, char const *format, ...)
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  exit(code);
}

void fatal_CF(char const *format, ...)
     __attribute__ ((noreturn, format(printf, 1, 2)));
void fatal_CF(char const *format, ...)
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  exit(RUN_CHECK_FAILED);
}

void fatal_PE(char const *format, ...)
     __attribute__ ((noreturn, format(printf, 1, 2)));
void fatal_PE(char const *format, ...)
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  exit(RUN_PRESENTATION_ERR);
}

void fatal_WA(char const *format, ...)
     __attribute__ ((noreturn, format(printf, 1, 2)));
void fatal_WA(char const *format, ...)
{
  va_list args;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  exit(RUN_WRONG_ANSWER_ERR);
}

void *xmalloc(size_t size)
{
  void *ptr = malloc(size);
  if (!ptr) fatal_CF("Out of heap memory: malloc(%zu) failed",size);
  return ptr;
}
void *xcalloc(size_t nmemb, size_t size)
{
  void *ptr = calloc(nmemb, size);
  if (!ptr) fatal_CF("Out of heap memory: calloc(%zu,%zu) failed",nmemb, size);
  return ptr;
}
void *xrealloc(void *ptr, size_t size)
{
  void *newptr = realloc(ptr, size);
  if (!newptr) fatal_CF("Out of heap memory: realloc(...,%zu) failed", size);
  return newptr;
}
unsigned char *xstrdup(const unsigned char *str)
{
  unsigned char *outstr = (unsigned char*) strdup(str);
  if (!outstr) fatal_CF("Out of heap memory: strdup(`%s') failed", str);
  return outstr;
}

FILE *f_in;
FILE *f_team;
FILE *f_corr;
FILE *f_arr[3];
const unsigned char * const f_arr_names[3] =
{
  "input",
  "team output",
  "correct output"
};

void checker_init(int argc, char **argv)
{
#if NEED_CORR != 0
  if (argc != 4)
    fatal_CF("Invalid number of arguments: %d instead of 4", argc);
#else
  if (argc != 3 && argc != 4)
    fatal_CF("Invalid number of arguments: %d instead of 3", argc);
#endif /* NEED_CORR */

  if (!(f_in = fopen(argv[1], "r")))
    fatal_CF("Cannot open input file `%s'", argv[1]);
  f_arr[0] = f_in;
  if (!(f_team = fopen(argv[2], "r")))
    fatal_PE("Cannot open team output file `%s'", argv[2]);
  f_arr[1] = f_team;
#if NEED_CORR != 0
  if (!(f_corr = fopen(argv[3], "r")))
    fatal_CF("Cannot open correct output file `%s'", argv[3]);
  f_arr[2] = f_corr;
#endif /* NEED_CORR */
}

int checker_read_team_int(const unsigned char *name,
                          int eof_error_flag,
                          int *p_val)
{
  int x = 0, n = 0;

  if ((n = fscanf(f_team, "%d", &x)) != 1) {
    if (ferror(f_team))
      fatal_CF("Input error from team output file");
    if (n == EOF) {
      if (!eof_error_flag) return -1;
      fatal_PE("Unexpected EOF while reading %s in team output file", name);
    }
    fatal_PE("Cannot read int value (%s) from team output", name);
  }
  *p_val = x;
  return 1;
}

int checker_read_in_int(const unsigned char *name,
                        int eof_error_flag,
                        int *p_val)
{
  int x = 0, n = 0;

  if ((n = fscanf(f_in, "%d", &x)) != 1) {
    if (ferror(f_in))
      fatal_CF("Input error from input file");
    if (n == EOF) {
      if (!eof_error_flag) return -1;
      fatal_CF("Unexpected EOF while reading %s in input file", name);
    }
    fatal_CF("Cannot read int value (%s) from input file", name);
  }
  *p_val = x;
  return 1;
}

int checker_read_corr_int(const unsigned char *name,
                          int eof_error_flag,
                          int *p_val)
{
  int x = 0, n = 0;

  if ((n = fscanf(f_corr, "%d", &x)) != 1) {
    if (ferror(f_corr))
      fatal_CF("Input error from correct output file");
    if (n == EOF) {
      if (!eof_error_flag) return -1;
      fatal_CF("Unexpected EOF while reading %s in correct output file", name);
    }
    fatal_CF("Cannot read int value (%s) from correct output", name);
  }
  *p_val = x;
  return 1;
}

void checker_team_eof(void)
{
  fscanf(f_team, " ");
  if (ferror(f_team))
    fatal_CF("Input error from team output file");
  if (getc(f_team) != EOF)
    fatal_PE("Garbage in team output file");
}

void checker_in_eof(void)
{
  fscanf(f_in, " ");
  if (ferror(f_in))
    fatal_CF("Input error from input file");
  if (getc(f_in) != EOF)
    fatal_CF("Garbage in input file");
}

void checker_corr_eof(void)
{
  fscanf(f_corr, " ");
  if (ferror(f_corr))
    fatal_CF("Input error from correct output file");
  if (getc(f_corr) != EOF)
    fatal_CF("Garbage in correct output file");
}

void checker_team_close(void)
{
  if (!f_team) return;
  fclose(f_team);
  f_team = f_arr[1] = 0;
}

void checker_in_close(void)
{
  if (!f_in) return;
  fclose(f_in);
  f_in = f_arr[0] = 0;
}

void checker_corr_close(void)
{
  if (!f_corr) return;
  fclose(f_corr);
  f_corr = f_arr[2] = 0;
}

void checker_OK(void) __attribute__((noreturn));
void checker_OK(void)
{
  fprintf(stderr, "OK\n");
  exit(0);
}

void checker_read_file(int ind, unsigned char **out, size_t *out_len)
{
  unsigned char read_buf[512];
  unsigned char *buf = 0;
  size_t buf_len = 0, read_len = 0;

  assert(ind >= 0 && ind <= 2);
  assert(f_arr[ind]);

  while (1) {
    read_len = fread(read_buf, 1, sizeof(read_buf), f_arr[ind]);
    if (!read_len) break;
    if (!buf_len) {
      buf = (unsigned char*) xcalloc(read_len + 1, 1);
      memcpy(buf, read_buf, read_len);
      buf_len = read_len;
    } else {
      buf = (unsigned char*) xrealloc(buf, buf_len + read_len);
      memcpy(buf + buf_len, read_buf, read_len);
      buf_len += read_len;
      buf[buf_len] = 0;
    }
  }
  if (ferror(f_arr[ind])) {
    fatal_CF("Input error from %s file", f_arr_names[ind]);
  }
  if (!buf_len) {
    buf = (unsigned char*) xmalloc(1);
    buf[0] = 0;
    buf_len = 0;
  }
  if (out) *out = buf;
  if (out_len) *out_len = buf_len;
}

int checker_read_in_double(const unsigned char *name,
                           int eof_error_flag,
                           double *p_val)
{
  double x = 0.0;
  int n;

  if (!name) name = "";
  if ((n = fscanf(f_in, "%lf", &x)) != 1) {
    if (ferror(f_in)) fatal_CF("Input error from input file");
    if (n == EOF) {
      if (!eof_error_flag) return -1;
      fatal_CF("Unexpected EOF while reading `%s'", name);
    }
    fatal_CF("Cannot parse double value `%s'", name);
  }
  *p_val = x;
  return 1;
}

int checker_read_team_double(const unsigned char *name,
                             int eof_error_flag,
                             double *p_val)
{
  double x = 0.0;
  int n;

  if (!name) name = "";
  if ((n = fscanf(f_team, "%lf", &x)) != 1) {
    if (ferror(f_team)) fatal_CF("Input error from input file");
    if (n == EOF) {
      if (!eof_error_flag) return -1;
      fatal_PE("Unexpected EOF while reading `%s'", name);
    }
    fatal_PE("Cannot parse double value `%s'", name);
  }
  *p_val = x;
  return 1;
}

int checker_read_double(int ind,
                        const unsigned char *name,
                        int eof_error_flag,
                        double *p_val)
{
  double x = 0.0;
  int n;

  if (!name) name = "";
  if ((n = fscanf(f_arr[ind], "%lf", &x)) != 1) {
    if (ferror(f_arr[ind])) fatal_CF("Input error from input file");
    if (n == EOF) {
      if (!eof_error_flag) return -1;
      if (ind == 1)
        fatal_PE("Unexpected EOF while reading `%s'", name);
      fatal_CF("Unexpected EOF while reading `%s'", name);
    }
    if (ind == 1)
      fatal_PE("Cannot parse double value `%s'", name);
    fatal_CF("Cannot parse double value `%s'", name);
  }
  *p_val = x;
  return 1;
}

int checker_read_team_long_double(const unsigned char *name,
                                  int eof_error_flag,
                                  long double *p_val)
{
  long double x = 0.0;
  int n;

  if (!name) name = "";
  if ((n = fscanf(f_team, "%Lf", &x)) != 1) {
    if (ferror(f_team)) fatal_CF("Input error from input file");
    if (n == EOF) {
      if (!eof_error_flag) return -1;
      fatal_PE("Unexpected EOF while reading `%s'", name);
    }
    fatal_PE("Cannot parse double value `%s'", name);
  }
  *p_val = x;
  return 1;
}

int checker_read_buf(int ind,
                     const unsigned char *name,
                     int eof_error_flag,
                     unsigned char *buf,
                     size_t buf_size)
{
  unsigned char format_str[128];
  unsigned char *local_buf;
  size_t format_len, read_len;
  int r;

  if (!buf_size || buf_size >= 100000)
    fatal_CF("checker_read_buf: invalid buf_size %zu", buf_size);

  local_buf = (unsigned char*) alloca(buf_size + 1);
  if (!local_buf) fatal_CF("checker_read_buf: alloca(%d) failed", buf_size+1);
  memset(local_buf, 0, buf_size + 1);
  format_len = snprintf(format_str, sizeof(format_str), "%%%ds", buf_size);
  if (format_len >= sizeof(format_str))
    fatal_CF("checker_read_buf: format string is too long: %zu", format_len);

  r = fscanf(f_arr[ind], format_str, local_buf);
  if (r == 1) {
    read_len = strlen(local_buf);
    if (read_len > buf_size - 1) {
      if (ind == 1)
        fatal_PE("string `%s' is too long (>= %zu) in %s file",
                 name, read_len, f_arr_names[ind]);

      fatal_CF("string `%s' is too long (>= %zu) in %s file",
               name, read_len, f_arr_names[ind]);
    }
    strcpy(buf, local_buf);
    return read_len;
  }
  if (r == 0) fatal_CF("fscanf returned 0!!!");
  if (ferror(f_arr[ind]))
    fatal_CF("input error from %s file", f_arr_names[ind]);
  if (!eof_error_flag) return -1;
  if (ind == 1)
    fatal_PE("unexpected EOF while reading `%s'", name);
  fatal_CF("unexpected EOF while reading `%s'", name);
  return -1;
}

void checker_read_file_by_line(int ind,
                               unsigned char ***out_lines,
                               size_t *out_lines_num)
{
  unsigned char **lb_v = 0;
  size_t lb_a = 0, lb_u = 0;
  unsigned char *b_v = 0;
  size_t b_a = 0, b_u = 0;
  unsigned char tv[512];
  size_t tl;
  unsigned char **bb;

  lb_a = 128;
  lb_v = (unsigned char **) alloca(lb_a * sizeof(lb_v[0]));
  memset(lb_v, 0, lb_a * sizeof(lb_v[0]));
  b_a = 1024;
  b_v = (unsigned char *) alloca(b_a);
  memset(b_v, 0, b_a);

  while (fgets(tv, sizeof(tv), f_arr[ind])) {
    tl = strlen(tv);
    if (tl + b_u >= b_a) {
      size_t new_b_a = b_a;
      unsigned char *new_b_v;

      while (tl + b_u >= new_b_a) new_b_a *= 2;
      new_b_v = (unsigned char*) alloca(new_b_a);
      memset(new_b_v, 0, new_b_a);
      memcpy(new_b_v, b_v, b_u + 1);
      b_v = new_b_v;
      b_a = new_b_a;
    }
    memcpy(b_v + b_u, tv, tl + 1);
    b_u += tl;

    if (tl < sizeof(tv) - 1 || feof(f_arr[ind])) {
      if (lb_u >= lb_a - 1) {
        size_t new_lb_a = lb_a * 2;
        unsigned char **new_lb_v;

        new_lb_v = (unsigned char **) alloca(new_lb_a * sizeof(new_lb_v[0]));
        memset(new_lb_v, 0, new_lb_a * sizeof(new_lb_v[0]));
        memcpy(new_lb_v, lb_v, lb_u * sizeof(lb_v[0]));
        lb_v = new_lb_v;
        lb_a = new_lb_a;
      }
      lb_v[lb_u] = xstrdup(b_v);
      lb_v[++lb_u] = 0;
      b_u = 0;
      b_v[0] = 0;
    }
  }
  if (ferror(f_arr[ind])) {
    fatal_CF("Input error from %s file", f_arr_names[ind]);
  }
  bb = (unsigned char**) xcalloc(lb_u + 1, sizeof(bb[0]));
  memcpy(bb, lb_v, lb_u * sizeof(bb[0]));

  if (out_lines_num) *out_lines_num = lb_u;
  if (out_lines) *out_lines = bb;
}

void checker_normalize_file(unsigned char **lines, size_t *lines_num)
{
  int i;
  size_t len;
  unsigned char *p;

  for (i = 0; i < *lines_num; i++) {
    if (!(p = lines[i])) fatal_CF("lines[%d] is NULL!", i);
    len = strlen(p);
    while (len > 0 && isspace(p[len - 1])) p[--len] = 0;
  }

  i = *lines_num;
  while (i > 0 && !lines[i - 1][0]) {
    i--;
    free(lines[i]);
    lines[i] = 0;
  }
  *lines_num = i;
}
