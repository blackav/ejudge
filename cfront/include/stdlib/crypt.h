/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_CRYPT_H__
#define __RCC_CRYPT_H__ 1

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

char *crypt(const char *key, const char *salt);
void setkey(const char *key);
void encrypt(char *block, int edflag);

struct crypt_data
{
  char keysched[16 * 8];
  char sb0[32768];
  char sb1[32768];
  char sb2[32768];
  char sb3[32768];
  char crypt_3_buf[14];
  char current_salt[2];
  long int current_saltbits;
  int  direction, initialized;
};

char *crypt_r(const char *key, const char *salt, struct crypt_data *data);
void setkey_r(const char *key, struct crypt_data *data);
void encrypt_r(char *block, int edflag, struct crypt_data *data);

#endif  /* __RCC_CRYPT_H__ */
