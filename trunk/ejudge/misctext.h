/* -*- c -*- */
/* $Id$ */
#ifndef __MISCTEXT_H__
#define __MISCTEXT_H__

/* Copyright (C) 2000-2003 Alexander Chernov <cher@ispras.ru> */

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

int html_armored_memlen(char const *text, int size);
int html_armored_strlen(char const *str);
int html_armor_text(char const *text, int size, char *out);
int html_armor_string(char const *str, char *out);
int html_armor_needed(const unsigned char *str, size_t *psz);

char *duration_str(int show_astr, unsigned long cur,
                   unsigned long time, char *buf, int len);
char *duration_min_str(unsigned long time, char *buf, int len);

int  message_quoted_size(char const *);
int  message_quote(char const *, char *);
int  message_reply_subj(char const *, char *);
int  message_base64_subj(char const *, char *, int);

size_t url_armor_string(unsigned char *, size_t, const unsigned char *);

#endif /* __MISCTEXT_H__ */
