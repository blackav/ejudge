/* -*- c -*- */
/* $Id$ */

#ifndef __EXPAT_IFACE_H__
#define __EXPAT_IFACE_H__ 1

/* Copyright (C) 2002-2011 Alexander Chernov <cher@ejudge.ru> */

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

/* structure takes 20 bytes (without `name') on ia32 
   and 32 bytes (without `name') on x86_64
*/
struct xml_attr
{
  struct xml_attr *next, *prev;
  unsigned short tag, column;
  int line;
  char *text;
  char *name[0];                /* when "default" node is enabled */
};

/* structure takes 40 bytes (without `name') on ia32 
   and 72 bytes (without `name') on x86_64
*/
struct xml_tree
{
  struct xml_tree *up, *first_down, *last_down, *left, *right;
  struct xml_attr *first, *last;
  unsigned short tag, column;
  int line;
  char *text;
  char *name[0];                /* when "default" node is enabled */
};

struct xml_parse_spec
{
  char const * const *elem_map;
  char const * const *attr_map;
  const size_t *elem_sizes;
  const size_t *attr_sizes;
  int default_elem;
  int default_attr;
  void * (*elem_alloc)(int);
  void * (*attr_alloc)(int);
  void (*elem_free)(struct xml_tree *);
  void (*attr_free)(struct xml_attr *);
  unsigned char const *verbatim_flags;
  int text_elem;                /* element name for texts */
  int unparse_entity;
};

struct xml_tree *
xml_build_tree(FILE *log_f, char const *path, const struct xml_parse_spec *spec);
struct xml_tree *
xml_build_tree_str(FILE *log_f, char const *str, const struct xml_parse_spec *spec);
struct xml_tree *
xml_build_tree_file(FILE *log_f, FILE *f, const struct xml_parse_spec *spec);

struct xml_tree *
xml_tree_free(struct xml_tree *tree, const struct xml_parse_spec *spec);
void xml_tree_free_attrs(struct xml_tree *tree,
                         const struct xml_parse_spec *spec);

void
xml_unparse_tree(FILE *out,
                 struct xml_tree const *tree,
                 char const * const *tag_map,
                 char const * const *attr_map,
                 int (*tag_print)(FILE *, struct xml_tree const *),
                 int (*attr_print)(FILE *, struct xml_attr const *),
                 void (*fmt_print)(FILE *, struct xml_tree const *, int, int));
void
xml_unparse_tree_str(char *buf,
                     int buf_size,
                     struct xml_tree const *tree,
                     char const * const *tag_map,
                     char const * const *attr_map,
                     int (*tag_print)(char *, int, struct xml_tree const *),
                     int (*attr_print)(char *, int, struct xml_attr const *));

void xml_unlink_node(struct xml_tree *p);
void xml_link_node_first(struct xml_tree *p, struct xml_tree *c);
void xml_link_node_last(struct xml_tree *p, struct xml_tree *c);

struct xml_tree *xml_elem_alloc(int tag, const size_t *sizes);
struct xml_attr *xml_attr_alloc(int tag, const size_t *sizes);

void
xml_unparse_raw_tree_subst(
        FILE *out,
        const struct xml_tree *tree,
        const struct xml_parse_spec *spec,
        const unsigned char **vars,
        const unsigned char **vals);
void
xml_unparse_raw_tree(
        FILE *fout,
        const struct xml_tree *tree,
        const struct xml_parse_spec *spec);

struct xml_tree *
xml_parse_text(
        FILE *log_f,
        const unsigned char *text,
        int root_node,
        const struct xml_parse_spec *spec);

#endif /* __EXPAT_IFACE_H__ */
