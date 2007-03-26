/* -*- c -*- */
/* $Id$ */
#ifndef __MISCTEXT_H__
#define __MISCTEXT_H__

/* Copyright (C) 2000-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include <string.h>
#include <time.h>

struct html_armor_buffer
{
  unsigned char *buf;
  size_t size;
};

int html_armored_memlen(char const *text, int size);
int html_armored_strlen(char const *str);
int html_armor_text(char const *text, int size, char *out);
int html_armor_string(char const *str, char *out);
unsigned char *html_armor_string_dup(const unsigned char *str);
int html_armor_needed(const unsigned char *str, size_t *psz);

#define HTML_ARMOR_INITIALIZER { 0, 0 }
void html_armor_init(struct html_armor_buffer *pb);
void html_armor_extend(struct html_armor_buffer *pb, size_t newsz);
const unsigned char *html_armor_buf(struct html_armor_buffer *pb,
                                    const unsigned char *s);
const unsigned char *html_armor_buf_bin(struct html_armor_buffer *pb,
                                        const unsigned char *s,
                                        size_t size);
const unsigned char *url_armor_buf(struct html_armor_buffer *pb,
                                   const unsigned char *s);
void html_armor_free(struct html_armor_buffer *pb);


//unsigned char *html_armor_string_dupa(const unsigned char *str);
#define html_armor_string_dupa(s) ({ unsigned char *_dupa_tmp_s = (s); size_t _dupa_tmp_len = strlen(_dupa_tmp_s), _dupa_tmp_len_2 = html_armored_memlen(_dupa_tmp_s, _dupa_tmp_len); unsigned char *_dupa_tmp_str = (unsigned char*) alloca(_dupa_tmp_len_2 + 1); html_armor_text(_dupa_tmp_s, _dupa_tmp_len, _dupa_tmp_str); _dupa_tmp_str; }) 

char *duration_str(int show_astr, time_t cur,
                   time_t time, char *buf, int len);
char *duration_min_str(time_t time, char *buf, int len);

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

unsigned char *dos2unix_str(const unsigned char *s);
size_t dos2unix_buf(unsigned char *s, size_t size);
unsigned char *unparse_sha1(const void *shabuf);

void allowed_list_parse(
	const unsigned char *str,
        unsigned char ***pv,
        size_t *pu);
unsigned char ** allowed_list_free(
	unsigned char **pv,
        size_t u);
void allowed_list_map(
	const unsigned char *user_langs,
        unsigned char **pv,
        size_t pu,
        int **pmap);

int check_str(const unsigned char *str, const unsigned char *map);

#endif /* __MISCTEXT_H__ */
