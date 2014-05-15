/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/http_request.h"
#include "contests.h"

#include "reuse/logger.h"

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

const unsigned char*
hr_getenv(
        const struct http_request_info *phr,
        const unsigned char *var)
{
  int i;
  size_t var_len;

  if (!var) return 0;
  var_len = strlen(var);
  for (i = 0; i < phr->env_num; i++)
    if (!strncmp(phr->envs[i], var, var_len) && phr->envs[i][var_len] == '=')
      break;
  if (i < phr->env_num)
    return phr->envs[i] + var_len + 1;
  return 0;
}

int
hr_cgi_param(
        const struct http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value)
{
  int i;

  if (!param) return -1;
  for (i = 0; i < phr->param_num; i++)
    if (!strcmp(phr->param_names[i], param))
      break;
  if (i >= phr->param_num) return 0;
  if (strlen(phr->params[i]) != phr->param_sizes[i]) return -1;
  *p_value = phr->params[i];
  return 1;
}

int
hr_cgi_param_bin(
        const struct http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value,
        size_t *p_size)
{
  int i;

  if (!param) return -1;
  for (i = 0; i < phr->param_num; i++)
    if (!strcmp(phr->param_names[i], param))
      break;
  if (i >= phr->param_num) return 0;
  *p_value = phr->params[i];
  *p_size = phr->param_sizes[i];
  return 1;
}

const unsigned char *
hr_cgi_nname(
        const struct http_request_info *phr,
        const unsigned char *prefix,
        size_t pflen)
{
  int i;

  if (!prefix || !pflen) return 0;
  for (i = 0; i < phr->param_num; i++)
    if (!strncmp(phr->param_names[i], prefix, pflen))
      return phr->param_names[i];
  return 0;
}

int
hr_cgi_param_int(
        const struct http_request_info *phr,
        const unsigned char *name,
        int *p_val)
{
  const unsigned char *s = 0, *p = 0;
  char *eptr = 0;
  int x;

  if (hr_cgi_param(phr, name, &s) <= 0) return -1;

  p = s;
  while (*p && isspace(*p)) p++;
  if (!*p) return -1;

  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno || *eptr) return -1;
  if (p_val) *p_val = x;
  return 0;
}

/* returns -1 if invalid param, 0 if no param, 1 if ok */
int
hr_cgi_param_int_2(
        const struct http_request_info *phr,
        const unsigned char *name,
        int *p_val)
{
  const unsigned char *s = 0, *p = 0;
  char *eptr = 0;
  int x, r;

  if ((r = hr_cgi_param(phr, name, &s)) <= 0) return r;

  p = s;
  while (*p && isspace(*p)) p++;
  if (!*p) return 0;

  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno || *eptr) return -1;
  if (p_val) *p_val = x;
  return 1;
}

int
hr_cgi_param_int_opt(
        struct http_request_info *phr,
        const unsigned char *name,
        int *p_val,
        int default_value)
{
  const unsigned char *s = 0, *p;
  char *eptr = 0;
  int x;

  if (!(x = hr_cgi_param(phr, name, &s))) {
    if (p_val) *p_val = default_value;
    return 0;
  } else if (x < 0) return -1;
  p = s;
  while (*p && isspace(*p)) p++;
  if (!*p) {
    if (p_val) *p_val = default_value;
    return 0;
  }
  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno || *eptr) return -1;
  if (p_val) *p_val = x;
  return 0;
}

int
hr_cgi_param_int_opt_2(
        struct http_request_info *phr,
        const unsigned char *name,
        int *p_val,
        int *p_set_flag)
{
  const unsigned char *s = 0, *p;
  char *eptr = 0;
  int x;

  ASSERT(p_val);
  ASSERT(p_set_flag);

  *p_val = 0;
  *p_set_flag = 0;

  if (!(x = hr_cgi_param(phr, name, &s))) return 0;
  else if (x < 0) return -1;

  p = s;
  while (*p && isspace(*p)) p++;
  if (!*p) return 0;

  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno || *eptr) return -1;
  *p_val = x;
  *p_set_flag = 1;
  return 0;
}

void
hr_register_url(
        FILE *out_f,
        const struct http_request_info *phr)
{
  if (phr->rest_mode > 0) {
    fprintf(out_f, "%s/register", phr->context_url);
  } else if (phr->cnts && phr->cnts->register_url) {
    fprintf(out_f, "%s", phr->cnts->register_url);
  } else {
#if defined CGI_PROG_SUFFIX
    fprintf(out_f, "%s/new-register%s", phr->context_url, CGI_PROG_SUFFIX);
#else
    fprintf(out_f, "%s/new-register", phr->contest_url);
#endif
  }
}

void
hr_client_url(
        FILE *out_f,
        const struct http_request_info *phr)
{
  if (phr->rest_mode > 0) {
    fprintf(out_f, "%s/user", phr->context_url);
  } else if (phr->cnts && phr->cnts->team_url) {
    fprintf(out_f, "%s", phr->cnts->team_url);
  } else {
#if defined CGI_PROG_SUFFIX
    fprintf(out_f, "%s/new-client%s", phr->context_url, CGI_PROG_SUFFIX);
#else
    fprintf(out_f, "%s/new-client", phr->contest_url);
#endif
  }
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
