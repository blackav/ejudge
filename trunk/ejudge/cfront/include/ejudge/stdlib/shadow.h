/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SHADOW_H__
#define __RCC_SHADOW_H__ 1

/* Copyright (C) 2003,2004 Alexander Chernov <cher@ispras.ru> */

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
#include <paths.h>
#include <stdio.h>
#include <stddef.h>

#define SHADOW _PATH_SHADOW

struct spwd
{
  char *sp_namp;
  char *sp_pwdp;
  long int sp_lstchg;
  long int sp_min;
  long int sp_max;
  long int sp_warn;
  long int sp_inact;
  long int sp_expire;
  unsigned long int sp_flag;
};

void setspent(void);
void endspent(void);
struct spwd *getspent(void);
struct spwd *getspnam(const char *name);
struct spwd *sgetspent(const char *string);
struct spwd *fgetspent(FILE *stream);
int putspent(const struct spwd *p, FILE *stream);

int getspent_r(struct spwd *result_buf, char *__buffer,
               size_t buflen, struct spwd **result);
int getspnam_r(const char *name, struct spwd *result_buf,
               char *buffer, size_t buflen,
               struct spwd **result);
int sgetspent_r(const char *string, struct spwd *result_buf,
                char *buffer, size_t buflen,
                struct spwd **result);
int fgetspent_r(FILE *stream, struct spwd *result_buf,
                char *buffer, size_t buflen,
                struct spwd **result);
int lckpwdf(void);
int ulckpwdf(void);

#endif /* __RCC_SHADOW_H__ */
