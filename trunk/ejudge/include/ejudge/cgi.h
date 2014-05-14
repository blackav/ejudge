/* -*- c -*- */
/* $Id$ */
#ifndef __CGI_H__
#define __CGI_H__

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

#include <stdlib.h>

int   cgi_read(char const *charset);
char *cgi_param(char const *);
char *cgi_nparam(char const *, int);
char *cgi_nname(char const *, int);
void  cgi_print_param(void);

int cgi_get_param_num(void);
void cgi_get_nth_param(int, unsigned char **, unsigned char **);
void cgi_get_nth_param_bin(int, unsigned char **, size_t *, unsigned char **);

int cgi_param_bin(const unsigned char *, size_t *, const unsigned char **);
int cgi_nparam_bin(const unsigned char *, size_t,
                   const unsigned char **, size_t *, const unsigned char **);

#endif /* __CGI_H__ */
