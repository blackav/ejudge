/* -*- c -*- */
/* $Id$ */
#ifndef __MISCTEXT_H__
#define __MISCTEXT_H__

/* Copyright (C) 2000-2005 Alexander Chernov <cher@ispras.ru> */

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

#include <stdio.h>
#include <stdlib.h>

int html_armored_memlen(char const *text, int size);
int html_armored_strlen(char const *str);
int html_armor_text(char const *text, int size, char *out);
int html_armor_string(char const *str, char *out);
unsigned char *html_armor_string_dup(const unsigned char *str);
int html_armor_needed(const unsigned char *str, size_t *psz);

//unsigned char *html_armor_string_dupa(const unsigned char *str);
#define html_armor_string_dupa(s) ({ unsigned char *_dupa_tmp_s = (s); size_t _dupa_tmp_len = strlen(_dupa_tmp_s), _dupa_tmp_len_2 = html_armored_memlen(_dupa_tmp_s, _dupa_tmp_len); unsigned char *_dupa_tmp_str = (unsigned char*) alloca(_dupa_tmp_len_2 + 1); html_armor_text(_dupa_tmp_s, _dupa_tmp_len, _dupa_tmp_str); _dupa_tmp_str; }) 

char *duration_str(int show_astr, unsigned long cur,
                   unsigned long time, char *buf, int len);
char *duration_min_str(unsigned long time, char *buf, int len);

int  message_quoted_size(char const *);
int  message_quote(char const *, char *);
int  message_reply_subj(char const *, char *);
int  message_base64_subj(char const *, char *, int);

size_t url_armor_string(unsigned char *, size_t, const unsigned char *);

size_t text_numbered_memlen(const unsigned char *intxt, size_t insize);
void text_number_lines(const unsigned char *intxt, size_t insize,
                       unsigned char *outtxt);
const unsigned char * const * html_get_armor_table(void);

enum
{
  CONTENT_TYPE_TEXT = 0,
  CONTENT_TYPE_HTML,
  CONTENT_TYPE_XML,
};
int get_content_type(const unsigned char *txt, const unsigned char **p_start_ptr);

unsigned char *html_hyperref(unsigned char *buf, size_t size,
                             unsigned long long session_id,
                             const unsigned char *self_url,
                             const unsigned char *extra_args,
                             const unsigned char *format, ...);

void html_start_form(FILE *f, int mode, unsigned long long sid,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars);

void html_date_select(FILE *f, time_t t);

#endif /* __MISCTEXT_H__ */
