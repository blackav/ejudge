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
int url_armor_needed(const unsigned char *s, size_t *psize);

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
int check_str_2(const unsigned char *str, const unsigned char *map,
                unsigned char *invchars, size_t invsize, int utf8_flag);

unsigned char *text_input_process_string(const unsigned char *s,
                                         int sep, int sep_repl);
unsigned char *text_area_process_string(const unsigned char *s,
                                        int sep, int sep_repl);

unsigned char *filename_armor_bytes(unsigned char *out, size_t outsize,
                                    const unsigned char *in, size_t insize);

int utf8_fix_string(unsigned char *str, int *gl_ind);
int utf8_cnt(const unsigned char *s, int width, int *p_w);

/*
 * converts UTF8 buffer `in' of the size `in_size' to UCS4 buffer `out'
 * `out' MUST be large enough to hold all the characters
 * safe rule is to allocate `out' buffer for the same elements, as in `in'
 */
int utf8_to_ucs4_buf(int *out, const unsigned char *in, size_t in_size);

/*
 * converts UTF8 string ('\0'-terminated) to UCS4 buffer `out'
 * `out' MUST be large enough to hold all the characters of `in' buffer
 * `out' will be 0-terminated UCS4 string
 * safe usage:
 *   in_len = strlen(in);
 *   out = (int*) alloca((in_len + 1) * sizeof(out[0]));
 *   utf8_to_ucs4_buf(out, in);
 */
int utf8_to_ucs4_str(int *out, const unsigned char *in);

/*
 * calculates the size required to store the UCS4 string `in' in UTF8
 * `in' is a 0-terminated UCS4 string
 * the return value counts the terminating '\0' byte
 * usage:
 *   out_size = ucs4_to_utf8_size(in);
 *   out = (unsigned char*) alloca(out_size);
 *   ucs4_to_utf8_str(out, out_size, in);
 */
size_t ucs4_to_utf8_size(const int *in);

const unsigned char *
ucs4_to_utf8_str(unsigned char *buf, size_t size, const int *in);

unsigned char *get_nth_alternative(const unsigned char *txt, int n);

#endif /* __MISCTEXT_H__ */
