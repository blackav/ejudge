/* -*- c -*- */
/* $Id$ */

#ifndef __EXPAT_IFACE_H__
#define __EXPAT_IFACE_H__ 1

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>

struct xml_attr
{
  struct xml_attr *next, *prev;
  int tag;
  int line, column;
  char *text;
};

struct xml_tree
{
  struct xml_tree *up, *first_down, *last_down, *left, *right;
  struct xml_attr *first, *last;
  int tag;
  int line, column;
  char *text;
};

struct xml_tree *
xml_build_tree(char const *path,
               char const * const *tag_map,
               char const * const *attr_map,
               void * (*tag_alloc)(int),
               void * (*attr_alloc)(int));
struct xml_tree *
xml_build_tree_str(char const *str,
                   char const * const *tag_map,
                   char const * const *attr_map,
                   void * (*tag_alloc)(int),
                   void * (*attr_alloc)(int));
struct xml_tree *
xml_tree_free(struct xml_tree *tree,
              void (*tag_free)(struct xml_tree *),
              void (*attr_free)(struct xml_attr *));
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

#endif /* __EXPAT_IFACE_H__ */
