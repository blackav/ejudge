/* -*- c -*- */
#ifndef __CLNTUTIL_H__
#define __CLNTUTIL_H__

/* Copyright (C) 2000-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"

#include <stdio.h>
#include <time.h>

extern char program_name[];
extern char form_header_simple[];
extern char form_header_multipart[];

void  client_access_denied(char const *, int locale_id) __attribute__((noreturn));
void  client_not_configured(
        char const*,
        char const*,
        int locale_id,
        const char *messages) __attribute__((noreturn));

void  client_make_form_headers(unsigned char const *);

void  client_put_header(
        FILE *out,
        unsigned char const *template,
        unsigned char const *content_type,
        unsigned char const *charset,
        int http_flag,
        int locale_id, 
        ej_cookie_t client_key,
        char const *format,
        ...)
  __attribute__((format(printf, 8, 9)));
void  client_put_footer(FILE *out, unsigned char const *template);

void parse_client_ip(ej_ip_t *p_ip);

#endif /* __CLNTUTIL_H__ */
