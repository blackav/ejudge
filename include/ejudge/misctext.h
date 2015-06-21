/* -*- c -*- */
#ifndef __MISCTEXT_H__
#define __MISCTEXT_H__

/* Copyright (C) 2000-2015 Alexander Chernov <cher@ejudge.ru> */

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
void html_armor_reserve(struct html_armor_buffer *pb, size_t newsz);
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
char *
duration_str_2(unsigned char *buf, int len, time_t dur, int nsec);
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
unsigned char *unparse_abbrev_sha1(const void *shabuf);
int parse_sha1(void *shabuf, const unsigned char *str);

void allowed_list_parse(
        const unsigned char *str,
        int separator,
        unsigned char ***pv,
        size_t *pu);
unsigned char ** allowed_list_free(
        unsigned char **pv,
        size_t u);
void allowed_list_map(
        const unsigned char *user_langs,
        int separator,
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
 * checks that 'u16str' is an UCS2 string and if so converts it into
 * UTF8 string allocating it on the heap and writing the pointer
 * to 'pu8str'. 'u16len' is the length of 'u16str' in bytes.
 * returns -1, if the 'u16str' is not an UCS2 string, and the string
 * length is all checks are ok
 */
int ucs2_to_utf8(unsigned char **pu8str, const unsigned char *u16str,
                 int u16len); 

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

unsigned char *
ucs4_to_utf8_char(unsigned char *buf, int value);

unsigned char *get_nth_alternative(const unsigned char *txt, int n);

unsigned char *chop2(unsigned char *str);
int is_empty_string(const unsigned char *str);

void
split_to_lines(
        const unsigned char *str,
        char ***plns,
        int ws_mode); // 0 - nothing, 1 - add space, 2 - remove space

unsigned char*
num_to_size_str(
        unsigned char *buf,
        size_t buf_size,
        int num);

unsigned char*
size_t_to_size_str(
        unsigned char *buf,
        size_t buf_size,
        size_t num);
unsigned char *
ll_to_size_str(
        unsigned char *buf,
        size_t buf_size,
        long long value);
void
ll_to_size_str_f(
        FILE *f,
        long long value);
void
size_t_to_size_str_f(
        FILE *f,
        size_t num);

void
text_table_number_lines(
        FILE *out_f,
        const unsigned char *intxt,
        size_t insize,
        const unsigned char *tr_attr,
        const unsigned char *td_attr);

int
has_control_characters(const unsigned char *str);

size_t
c_armored_memlen(char const *str, size_t size);
size_t
c_armored_strlen(char const *str);
int
c_armor_needed(const unsigned char *str, size_t *psz);
int
c_armor_needed_bin(const unsigned char *str, size_t sz, size_t *psz);
const unsigned char *
c_armor_buf(struct html_armor_buffer *pb, const unsigned char *s);

int
text_read_file(
        const unsigned char *path,
        int reserve,
        unsigned char **out,
        size_t *out_len);

int
text_is_valid_char(int c);

int
text_is_binary(const unsigned char *text, size_t size);

enum
{
  TEXT_FIX_CR = 1,              /* dos2unix conversion */
  TEXT_FIX_TR_SP = 2,           /* trailing space removal */
  TEXT_FIX_FINAL_NL = 4,        /* final newline append */
  TEXT_FIX_TR_NL = 8,           /* trailing newline removal */
  TEXT_FIX_NP = 16              /* replace non-printables, except \n, \t, \r with space */
};

/**
 * Normalizes the text buffer according to the given normalization flags.
 * \returns the new string length
 */
size_t
text_normalize_buf(
        unsigned char *in_text,
        size_t in_size,
        int op_mask,
        size_t *p_count,
        int *p_done_mask);

/**
 */
size_t
text_normalize_dup(
        const unsigned char *in_text,
        size_t in_size,
        int op_mask,
        unsigned char **p_out_text,
        size_t *p_count,
        int *p_done_mask);

void
html_print_by_line(
        FILE *f,
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        unsigned char const *s,
        size_t size);
unsigned char *
html_print_by_line_str(
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        unsigned char const *s,
        size_t size);

int
size_str_to_num(const unsigned char *str, int *p_num);
int
size_str_to_size_t(const unsigned char *str, size_t *p_size);
int
size_str_to_size64_t(const unsigned char *str, long long *p_size);

int
is_valid_email_address(const unsigned char *email_address);

size_t csv_armored_memlen(char const *str, size_t size);
size_t csv_armored_strlen(char const *str);
int csv_armor_needed(const unsigned char *str, size_t *psz);
const unsigned char *csv_armor_buf(struct html_armor_buffer *pb, const unsigned char *s);

const unsigned char *
skip_message_headers(const unsigned char *intxt);

int
parse_date_twopart(
        const unsigned char *date_str,
        const unsigned char *time_str,
        time_t *p_time);

int
parse_duration(const unsigned char *str, int default_value);

#endif /* __MISCTEXT_H__ */
