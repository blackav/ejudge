/* -*- c -*- */
/* $Id$ */

#ifndef __XML_UTILS_H__
#define __XML_UTILS_H__

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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
#include <time.h>

int xml_parse_ip(unsigned char const *path, int line, int column,
                 unsigned char const *s, unsigned long *pip);
int xml_parse_date(unsigned char const *path, int line, int column,
                   unsigned char const *s, time_t *pd);
int xml_parse_int(unsigned char const *path, int line, int column,
                  unsigned char const *str, int *pval);

void xml_unparse_text(FILE *f, const unsigned char *tag_name,
                      unsigned char const *value,
                      unsigned char const *indent);

const unsigned char *xml_unparse_ip(unsigned long ip);
const unsigned char *xml_unparse_date(time_t d);


#endif /* __XML_UTILS_H__ */

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
