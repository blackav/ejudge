/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "cgi.h"
#include "settings.h"
#include "errlog.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_SIZE      63
#define MAX_VALUE_SIZE     MAX_CGI_VALUE_LEN
#define MAX_CONTENT_LENGTH MAX_CGI_VALUE_LEN

#if defined EJUDGE_CHARSET
#define DEFAULT_CHARSET              EJUDGE_CHARSET
#else
#define DEFAULT_CHARSET              "iso8859-1"
#endif /* EJUDGE_CHARSET */

struct param
{
  char *name;
  int   size;
  char *value;
};

static char *name_buf = 0;
static int   name_a = 0;
static int   name_u = 0;

static char *value_buf = 0;
static int   value_a = 0;
static int   value_u = 0;

static struct param *params;
static int param_a;
static int param_u;

static char *query;
static int   query_ind;
static int   source = 0;

#define MARK_PLACE fprintf(stderr, "DEBUG: %s, %d\n", __FILE__, __LINE__)

static int
do_get_char()
{
  if (!source) {
    if (!query) return EOF;
    if (!query[query_ind]) return EOF;
    return query[query_ind++];
  } else {
    return getchar();
  }
}

static int
cgi_get_char(void)
{
  int  c = do_get_char();
  char bb[4];

  /* we need to distinguish unescaped '&', '=' from escaped ones */
  if (c == '&' || c == '=') return -c;
  if (c != '%' && c != '+') return c;
  if (c == '+') return ' ';

  c = do_get_char();
  if (c == EOF) return '?';
  if (!isxdigit(c)) return '?';
  bb[0] = c;
  c = do_get_char();
  if (c == EOF) return '?';
  if (!isxdigit(c)) return '?';
  bb[1] = c;
  bb[2] = 0;
  c = strtol(bb, 0, 16);
  return c;
}

static void
cgi_put_char(char **b, int *a, int *u, int c)
{
  if (*u >= *a) {
    *a += 256;
    *b = (char*) xrealloc(*b, *a);
  }
  (*b)[*u] = c;
  (*u)++;
}

static void
add_to_param_list(char const *name, char const *value, int size)
{
  int i;

  for (i = 0; i < param_u; i++) {
    if (!strcmp(name, params[i].name)) break;
  }
  if (i >= param_u) {
    if (param_u >= param_a) {
      param_a += 32;
      params = (struct param*) xrealloc(params, param_a * sizeof(params[0]));
    }
    param_u++;
  }

  params[i].name  = xstrdup(name);
  params[i].size  = size;
  params[i].value = xmalloc(size + 1);
  memcpy(params[i].value, value, size);
  params[i].value[size] = 0;
}

static int
do_cgi_read(void)
{
  int c;

  c = cgi_get_char();
  while (c != EOF) {
    /* read parameter name */
    name_u = 0;
    while (c != EOF && c != -'&' && c != -'=' && name_u < MAX_NAME_SIZE) {
      cgi_put_char(&name_buf, &name_a, &name_u, c);
      c = cgi_get_char();
    }
    cgi_put_char(&name_buf, &name_a, &name_u, 0);
    if (name_u >= MAX_NAME_SIZE && c != EOF && c != -'&' && c != -'=') {
      /* name is too long */
      //printf("NAME TOO LONG\n"); fflush(0);
      return -1;
    }

    if (c == -'=') {
      c = cgi_get_char();
      value_u = 0;
      while (c != EOF && c != -'&' && value_u < MAX_VALUE_SIZE) {
        cgi_put_char(&value_buf, &value_a, &value_u, c);
        c = cgi_get_char();
      }
      cgi_put_char(&value_buf, &value_a, &value_u, 0);
      if (value_u >= MAX_VALUE_SIZE && c != EOF && c != -'&') {
        /* value is too long */
        //printf("VALUE TOO LONG\n"); fflush(0);
        return -1;
      }
    }

    if (!value_buf) {
      value_a = 16;
      value_buf = (char*) xcalloc(value_a, 1);
    }
    add_to_param_list(name_buf, value_buf, strlen(value_buf));

    if (c == -'&') {
      c = cgi_get_char();
    }
  }
  return 0;
}

static void
bad_request(char const *charset)
{
  if (!charset) charset = DEFAULT_CHARSET;

  // as locale_id is not received, no need for localization

  printf("Content-Type: text/html; charset = %s\n\n", charset);
  printf("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>%s</title></head><body><h1>%s</h1><p>", charset,
         "Bad data", "Bad data");
  printf("Your browser has sent the data in the format"
         " that this program cannot parse."
         " Please, report this to address <a href=\"mailto:%s\">%s</a>.</p>", "cher@unicorn.cmc.msu.ru", "cher@unicorn.cmc.msu.ru");
  printf("</p></body></html>\n");
}

static void
request_too_large(char const *charset)
{
  if (!charset) charset = DEFAULT_CHARSET;

  printf("Content-Type: text/html; charset=%s\n\n", charset);
  printf("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>%s</title></head><body><h1>%s</h1><p>",
         charset, "Request is rejected", "Request is rejected");
  printf("Your request has been rejected for its data size exceeds the allowed maximum.");
  printf("</p></body></html>\n");
}

static int
parse_multipart(char const *charset)
{
  static char const mp2[] = "multipart/form-data; boundary=";
  static char const s3[] = "content-disposition:";
  static char const s4[] = "form-data;";
  static char const s5[] = "name=\"";
  static char const s6[] = "content-type:";

  char const *boundary;
  char *ct, *cl;
  int   content_length, n;
  char lbuf[1024];
  int  llen;
  char *p, *q;
  int  linestart;
  int  boundary_len;
  int  c;

  ct = getenv("CONTENT_TYPE");
  if (!ct) return -1;
  if (strncmp(ct, mp2, sizeof(mp2) - 1)) {
    err("parse_multipart: cannot parse CONTENT_TYPE");
    bad_request(charset);
    exit(0);
  }
  boundary = ct + sizeof(mp2) - 1;
  boundary_len = strlen(boundary);

  cl = getenv("CONTENT_LENGTH");
  if (!cl || sscanf(cl, "%d%n", &content_length, &n) != 1 || cl[n]) {
    err("parse_multipart: cannot parse CONTENT_LENGTH");
    bad_request(charset);
    exit(0);
  }
  if (content_length > MAX_CONTENT_LENGTH) {
    request_too_large(charset);
    exit(0);
  }

  name_u = 0;
  value_u = 0;
  fgets(lbuf, sizeof(lbuf), stdin);

  llen = strlen(lbuf);
  if (llen == sizeof(lbuf) - 1 && lbuf[llen - 1] != '\n') {
    err("parse_multipart: boundary string too long");
    bad_request(charset);
    exit(0);
  }
  lbuf[--llen] = 0;
  if (lbuf[llen - 1] == '\r') lbuf[--llen] = 0;
  if (lbuf[0] != '-' || lbuf[1] != '-' || strcmp(boundary, lbuf + 2)) {
    err("got: %s(%zu)", lbuf, strlen(lbuf));
    bad_request(charset);
    exit(0);
  }
  while (1) {
    /* read and parse header lines */
    while (1) {
      fgets(lbuf, sizeof(lbuf), stdin);
      //fprintf(stderr, ">>%s<\n", lbuf);
      llen = strlen(lbuf);
      if (llen == sizeof(lbuf) - 1 && lbuf[llen - 1] != '\n') {
        err("parse_multipart: header string too long");
        bad_request(charset);
        exit(0);
      }
      lbuf[--llen] = 0;
      if (lbuf[llen - 1] == '\r') lbuf[--llen] = 0;
      if (!lbuf[0]) break;
      if (!strncasecmp(lbuf, s3, sizeof(s3) - 1)) {
        /* content-disposition header */
        p = lbuf + sizeof(s3) - 1;
        while (*p == ' ' || *p == '\t') p++;
        if (!strncasecmp(p, s4, sizeof(s4) - 1)) {
          p += sizeof(s4) - 1;
          while (*p == ' ' || *p == '\t') p++;
          if (!strncasecmp(p, s5, sizeof(s5) - 1)) {
            p += sizeof(s5) - 1;
            q = p;
            while (*q != '\"' && *q != 0) q++;
            if (!*q) {
              err("unexpected EOLN: %s", lbuf);
              bad_request(charset);
              exit(0);
            }
            /* get parameter name */
            if (q - p + 1 > name_a) {
              name_a = ((q - p + 1) + 3) & ~3;
              name_buf = xrealloc(name_buf, name_a);
            }
            name_u = q - p;
            memcpy(name_buf, p, name_u);
            name_buf[name_u] = 0;
          } else {
            err("name= expected: %s\n", lbuf);
            bad_request(charset);
            exit(0);
          }
        } else {
          err("unknown content disposition: %s", lbuf);
          bad_request(charset);
          exit(0);
        }
      } else if (!strncasecmp(s6, lbuf, sizeof(s6) - 1)) {
        //err("ignored header: %s", lbuf);
      } else {
        err("unknown header: <%s>", lbuf);
        bad_request(charset);
        exit(0);
      }
    }

    /* read and parse data stream */
    linestart = 0; value_u = 0;
    if (!value_a) {
      value_a = 128;
      value_buf = xmalloc(value_a);
    }
    while (1) {
      c = getchar();
      if (c == EOF) {
        err("unexpected EOF");
        bad_request(charset);
        exit(0);
      }
      if (value_u >= value_a) {
        value_a *= 2;
        value_buf = xrealloc(value_buf, value_a);
      }
      value_buf[value_u++] = c;
      if (value_u - linestart - 2 == boundary_len
          && value_buf[linestart] == '-'
          && value_buf[linestart + 1] == '-'
          && !strncmp(value_buf + linestart + 2, boundary, boundary_len)) {
        /* data ended */
        value_u = linestart;
        if (value_u > 0 && value_buf[value_u - 1] == '\n') value_u--;
        if (value_u > 0 && value_buf[value_u - 1] == '\r') value_u--;
        value_buf[value_u] = 0;
        break;
      }
      if (c == '\n') {
        linestart = value_u;
      }
    }

    /* add variable to list */
    add_to_param_list(name_buf, value_buf, value_u);
    /* skip whitespaces */
    c = getchar();
    if (c == '-') {
      c = getchar();
      if (c == '-') break;
      err("oops: only one '-' after boundary");
      bad_request(charset);
      exit(0);
    } else {
      ungetc(c, stdin);
    }
    while ((c = getchar()) == ' ' || c == '\t' || c == '\n' || c == '\r');
    ungetc(c, stdin);
  }

#if 0
  {
    int i;

    fprintf(stderr, "total: %d\n", param_u);
    for (i = 0; i < param_u; i++) {
      fprintf(stderr, "%s = '%s'\n", params[i].name, params[i].value);
    }
  }
#endif

  return 0;
}

static char const multipart[] = "multipart/form-data;";
/**
 * NAME:    cgi_read
 * PURPOSE: read all the given CGI parameters
 * ARGS:    charset - character set to report errors
 * RETURN:   0 - OK,
 *          -1 - error
 * NOTE:    parse routines write error messages directly to stderr
 */
int
cgi_read(char const *charset)
{
  char *ct = 0;
  query = getenv("QUERY_STRING");
  if (query) {
    source = 0;
    if (do_cgi_read() < 0) return -1;
  }
  ct = getenv("CONTENT_TYPE");
  if (ct && !strncmp(ct, multipart, sizeof(multipart) - 1)) {
    /* got a multipart/form-data */
    return parse_multipart(charset);
  }
  source = 1;
  if (do_cgi_read() < 0) return -1;
  return 0;
}

/**
 * NAME:    cgi_param
 * PURPOSE: return the value of the given parameter
 * ARGS:    name - the parameter name
 * RETURN:  the parameter value
 */
char *
cgi_param(char const *name)
{
  int i;

  for (i = 0; i < param_u; i++)
    if (!strcmp(params[i].name, name))
      return params[i].value;
  return NULL;
}

int
cgi_param_bin(const unsigned char *name, 
              size_t *psize,
              const unsigned char **pvalue)
{
  int i;

  for (i = 0; i < param_u; i++)
    if (!strcmp(params[i].name, name)) {
      if (psize) *psize = params[i].size;
      if (pvalue) *pvalue = params[i].value;
      return 0;
    }
  return -1;
}

/**
 * NAME:    cgi_nparam
 * PURPOSE: return the value of the parameter with the given prefix
 * ARGS:    name  - prefix of the parameter name
 *          nsymb - number of characters to check
 * RETURN:  the value of the first parameter with the given prefix
 */
char *
cgi_nparam(char const *name, int nsymb)
{
  int i;

  for (i = 0; i < param_u; i++)
    if (!strncmp(params[i].name, name, nsymb))
      return params[i].value;
  return NULL;
}

int
cgi_nparam_bin(const unsigned char *prefix,
               size_t nsyms,
               const unsigned char **pname,
               size_t *psize,
               const unsigned char **pvalue)
{
  int i;

  for (i = 0; i < param_u; i++)
    if (!strncmp(params[i].name, prefix, nsyms)) {
      if (pname) *pname = params[i].name;
      if (psize) *psize = params[i].size;
      if (pvalue) *pvalue = params[i].value;
      return 0;
    }
  return -1;
}

/**
 * NAME:    cgi_nname
 * PURPOSE: find the parameter name with the given prefix
 * ARGS:    name  - prefix of the name
 *          nsymb - number of characters to check
 * RETURN:  full parameter name with the given prefix
 *          If several exist, the first is returned.
 */
char *
cgi_nname(char const *name, int nsymb)
{
  int i;

  for (i = 0; i < param_u; i++)
    if (!strncmp(params[i].name, name, nsymb))
      return params[i].name;
  return NULL;
}

int
cgi_get_param_num(void)
{
  return param_u;
}

void
cgi_get_nth_param(int n, unsigned char **p_name, unsigned char **p_value)
{
  if (n < 0 || n >= param_u) {
    if (p_name) *p_name = 0;
    if (p_value) *p_value = 0;
    return;
  }
  if (p_name) *p_name = params[n].name;
  if (p_value) *p_value = params[n].value;
}

void
cgi_get_nth_param_bin(int n, unsigned char **p_name,
                      size_t *p_size, unsigned char **p_value)
{
  if (n < 0 || n >= param_u) {
    if (p_name) *p_name = 0;
    if (p_value) *p_value = 0;
    return;
  }
  if (p_name) *p_name = params[n].name;
  if (p_size) *p_size = params[n].size;
  if (p_value) *p_value = params[n].value;
}

/**
 * NAME:    cgi_print_param
 * PURPOSE: debugging: print all the parameters to the standard output
 */
void
cgi_print_param(void)
{
  int i;

  printf("total: %d\n", param_u);
  for (i = 0; i < param_u; i++) {
    printf("%s = '%s'\n", params[i].name, params[i].value);
  }
  return;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

