/* -*- c -*- */
/* $Id$ */
#ifndef __MISCHTML_H__
#define __MISCHTML_H__

/* Copyright (C) 2005-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "ej_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

unsigned char *html_hyperref(unsigned char *buf, size_t size,
                             ej_cookie_t session_id,
                             const unsigned char *self_url,
                             const unsigned char *extra_args,
                             const char *format, ...)
  __attribute__((format(printf, 6, 7)));

void html_start_form(FILE *f, int mode,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars);

void html_date_select(FILE *f, time_t t);

void html_hidden(FILE *fout, const unsigned char *var_name,
                 const char *format, ...)
  __attribute__((format(printf, 3, 4)));

unsigned char *html_input_text(unsigned char *buf, size_t size,
                               const unsigned char *var_name,
                               int text_size, const char *format,
                               ...)
  __attribute__((format(printf, 5, 6)));
unsigned char *html_input_password(unsigned char *buf, size_t size,
                                   const unsigned char *var_name,
                                   int text_size, const char *format,
                                   ...)
  __attribute__((format(printf, 5, 6)));

unsigned char *
html_checkbox(
	unsigned char *buf,
        size_t size,
        const unsigned char *var_name,
        int is_checked);

#endif /* __MISCHTML_H__ */
