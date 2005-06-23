/* -*- c -*- */
/* $Id$ */

#ifndef __XML_UTILS_H__
#define __XML_UTILS_H__

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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

struct xml_tree;
struct xml_attn;

int xml_parse_ip(unsigned char const *path, int line, int column,
                 unsigned char const *s, unsigned long *pip);
int xml_parse_date(unsigned char const *path, int line, int column,
                   unsigned char const *s, time_t *pd);
int xml_parse_int(unsigned char const *path, int line, int column,
                  unsigned char const *str, int *pval);
int xml_parse_ip_mask(const unsigned char *path, int line, int column,
                      const unsigned char *s,
                      unsigned *p_ip, unsigned *p_mask);

void xml_unparse_text(FILE *f, const unsigned char *tag_name,
                      unsigned char const *value,
                      unsigned char const *indent);

const unsigned char *xml_unparse_ip(unsigned long ip);
const unsigned char *xml_unparse_date(time_t d);
const unsigned char *xml_unparse_ip_mask(unsigned int addr, unsigned int mask);

extern const unsigned char *xml_err_path;
extern const char * const *xml_err_elem_names;
extern const char * const *xml_err_attr_names;

void xml_err(const struct xml_tree *pos, const char *format, ...)
     __attribute__((format (printf, 2, 3)));
void xml_err_a(const struct xml_attn *pos, const char *format, ...)
     __attribute__((format (printf, 2, 3)));
void xml_err_attrs(const struct xml_tree *p);
void xml_err_nested_elems(const struct xml_tree *p);
void xml_err_attr_not_allowed(const struct xml_tree *tree,
                              const struct xml_attn *attr);
void xml_err_elem_not_allowed(const struct xml_tree *tree);
void xml_err_elem_redefined(const struct xml_tree *tree);
void xml_err_top_level(const struct xml_tree *tree, int elem);
void xml_err_attr_invalid(const struct xml_attn *a);
void xml_err_elem_undefined(const struct xml_tree *p, int elem);
void xml_err_attr_undefined(const struct xml_tree *p, int attr);

int xml_leaf_elem(struct xml_tree *tree, /* ->text may be modified */
                  unsigned char **value_addr,
                  int move_flag, int empty_allowed_flag);
int xml_empty_text(struct xml_tree *tree);
int xml_attr_bool(struct xml_attn *attr, int *value_ptr);
int xml_elem_ip_mask(struct xml_tree *tree,
                     unsigned int *addr_ptr, unsigned int *mask_ptr);
int xml_parse_int_attr(struct xml_attn *attr, int *value_ptr);

#endif /* __XML_UTILS_H__ */

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
