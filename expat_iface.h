/* -*- c -*- */
/* $Id$ */

#ifndef __EXPAT_IFACE_H__
#define __EXPAT_IFACE_H__ 1

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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

struct xml_attn
{
  struct xml_attn *next, *prev;
  int tag;
  char *text;
};

struct xml_tree
{
  struct xml_tree *up, *first_down, *last_down, *left, *right;
  struct xml_attn *first, *last;
  int tag;
  char *text;
};

struct xml_tree *
xml_build_tree(char const *path,
               char **tag_map,
               char **attn_map,
               void * (*tag_alloc)(int),
               void * (*attn_alloc)(int));
struct xml_tree *
xml_build_tree_str(char const *str,
                   char **tag_map,
                   char **attn_map,
                   void * (*tag_alloc)(int),
                   void * (*attn_alloc)(int));
struct xml_tree *
xml_tree_free(struct xml_tree *tree,
              void (*tag_free)(void *),
              void (*attn_free)(void *));

#endif /* __EXPAT_IFACE_H__ */
