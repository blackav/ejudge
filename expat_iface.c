/* -*- mode: c -*- */
/* $Id$ */

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

#include "expat_iface.h"
#include "nls.h"
#include "pathutl.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <expat.h>

#include <string.h>
#include <stdio.h>

struct tag_list
{
  struct tag_list *next;

  int itag;
  int a, u;
  unsigned char *str;
  struct xml_tree *tree;
};

struct parser_data
{
  int nest;
  int skipping;
  int skip_stop;
  struct tag_list *tag_stack;
  int err_cntr;
  struct xml_tree *tree;
  char const * const *tag_map;
  char const * const *attn_map;
  void * (*alloc_tag_func)(int);
  void * (*alloc_attn_func)(int);
};

static int
encoding_hnd(void *data, const XML_Char *name, XML_Encoding *info)
{
  int i, o;
  unsigned char cb, cu1, cu2;
  struct nls_table *tab = 0;

  tab = nls_lookup_table(name);
  if (tab) {
    for (i = 0; i < 256; i++) {
      cb = i;
      tab->char2uni(&cb, &o, &cu1, &cu2);
      info->map[i] = (cu2 << 8) | cu1;
    }
    info->data = 0;
    info->convert = 0;
    info->release = 0;
    return 1;
  }

  // unsupported encoding
  return 0;
}

static void
start_hnd(void *data, const XML_Char *name, const XML_Char **atts)
{
  XML_Parser p = (XML_Parser) data;
  int cur_val_size = 0, cur_attr_size = 0, val_len, attr_len;
  char *cur_val = 0, *cur_attr = 0;
  int cur_tag_size = 0, tag_len;
  char *cur_tag = 0;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);
  struct tag_list *tl = 0;
  int itag = 0, iattn = 0;
  struct xml_tree *new_node, *parent_node;
  struct xml_attn *new_attn;

  /* allocate initial space for attrib and value local buffers */
  cur_attr_size = 32;
  cur_attr = (char*) alloca(cur_attr_size);
  cur_val_size = 32;
  cur_val = (char*) alloca(cur_val_size);

  /* recode tag to koi8-r */
  cur_tag_size = 32;
  tag_len = strlen(name);
  while (cur_tag_size <= tag_len) {
    cur_tag_size *= 2;
  }
  cur_tag = (char*) alloca(cur_tag_size);
  str_utf8_to_koi8(cur_tag, cur_tag_size, name);

  if (pd->skipping) {
    pd->nest++;
    return;
  }

  if (!pd->tag_map) {
    err("unknown tag <%s> at line %d, skipping",
        cur_tag, XML_GetCurrentLineNumber(p));
    pd->err_cntr++;
    goto start_skipping;
  }
  for (itag = 1; pd->tag_map[itag]; itag++)
    if (!strcmp(cur_tag, pd->tag_map[itag]))
      break;
  if (!pd->tag_map[itag]) {
    err("unknown tag <%s> at line %d, skipping",
        cur_tag, XML_GetCurrentLineNumber(p));
    pd->err_cntr++;
    goto start_skipping;
  }

  new_node = (struct xml_tree*) pd->alloc_tag_func(itag);
  new_node->tag = itag;
  new_node->line = XML_GetCurrentLineNumber(p);
  new_node->column = XML_GetCurrentColumnNumber(p);
  if (pd->tag_stack) {
    parent_node = pd->tag_stack->tree;
    new_node->up = parent_node;
    if (parent_node->first_down) {
      parent_node->last_down->right = new_node;
      new_node->left = parent_node->last_down;
      parent_node->last_down = new_node;
    } else {
      parent_node->first_down = parent_node->last_down = new_node;
    }
  } else {
    pd->tree = new_node;
  }

  while (*atts) {
    attr_len = strlen(atts[0]);
    val_len = strlen(atts[1]);
    if (attr_len >= cur_attr_size) {
      while (attr_len >= cur_attr_size) {
        cur_attr_size *= 2;
      }
      cur_attr = (char*) alloca(cur_attr_size);
    }
    if (val_len >= cur_val_size) {
      while (val_len >= cur_val_size) {
        cur_val_size *= 2;
      }
      cur_val = (char*) alloca(cur_val_size);
    }
    str_utf8_to_koi8(cur_attr, cur_attr_size, atts[0]);
    str_utf8_to_koi8(cur_val, cur_val_size, atts[1]);

    if (!pd->attn_map) {
      err("unknown attribute <%s> at line %d",
          cur_attr, XML_GetCurrentLineNumber(p));
      pd->err_cntr++;
      atts += 2;
      continue;
    }
    for (iattn = 1; pd->attn_map[iattn]; iattn++)
      if (!strcmp(cur_attr, pd->attn_map[iattn]))
        break;
    if (!pd->attn_map[iattn]) {
      err("unknown attribute <%s> at line %d",
          cur_attr, XML_GetCurrentLineNumber(p));
      pd->err_cntr++;
      atts += 2;
      continue;
    }
    new_attn = (struct xml_attn*) pd->alloc_attn_func(iattn);
    new_attn->tag = iattn;
    new_attn->text = xstrdup(cur_val);
    new_attn->line = XML_GetCurrentLineNumber(p);
    new_attn->column = XML_GetCurrentColumnNumber(p);
    if (!new_node->first) {
      new_node->first = new_node->last = new_attn;
    } else {
      new_node->last->next = new_attn;
      new_attn->prev = new_node->last;
      new_node->last = new_attn;
    }
    atts += 2;
  }

  tl = (struct tag_list*) xcalloc(1, sizeof(*tl));
  tl->itag = itag;
  tl->next = pd->tag_stack;
  tl->tree = new_node;
  pd->tag_stack = tl;
  pd->nest++;
  return;

 start_skipping:
  pd->skipping = 1;
  pd->nest++;
  pd->skip_stop = pd->nest;
}

static void
end_hnd(void *data, const XML_Char *name)
{
  XML_Parser p = (XML_Parser) data;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);
  struct tag_list *tl;

  if (pd->skipping) {
    pd->nest--;
    if (pd->nest < pd->skip_stop) {
      pd->skip_stop = 0;
      pd->skipping = 0;
    }
    return;
  }

  tl = pd->tag_stack;
  pd->tag_stack = tl->next;
  pd->nest--;
  tl->tree->text = str_utf8_to_koi8_heap(tl->str);
  free(tl->str);
}

static void
chardata_hnd(void *data, const XML_Char *s, int len)
{
  XML_Parser p = (XML_Parser) data;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);

  if (!pd->tag_stack) return;
  if (pd->skipping) return;
  if (!pd->tag_stack->a) pd->tag_stack->a = 32;
  while (pd->tag_stack->u + len >= pd->tag_stack->a)
    pd->tag_stack->a *= 2;
  pd->tag_stack->str = (char*) xrealloc(pd->tag_stack->str, pd->tag_stack->a);
  memmove(pd->tag_stack->str + pd->tag_stack->u, s, len);
  pd->tag_stack->u += len;
  pd->tag_stack->str[pd->tag_stack->u] = 0;
}

static void *
generic_tag_alloc(int tag)
{
  return xcalloc(1, sizeof(struct xml_tree));
}
static void *
generic_attn_alloc(int attn)
{
  return xcalloc(1, sizeof(struct xml_attn));
}

struct xml_tree *
xml_build_tree(char const *path,
               char const * const *tag_map,
               char const * const *attn_map,
               void * (*tag_alloc)(int),
               void * (*attn_alloc)(int))
{
  XML_Parser p = 0;
  FILE *f = 0;
  char buf[512];
  int len;
  struct parser_data data;

  memset(&data, 0, sizeof(data));
  ASSERT(path);
  if (!tag_alloc) tag_alloc = generic_tag_alloc;
  if (!attn_alloc) attn_alloc = generic_attn_alloc;

  if (!(f = fopen(path, "r"))) {
    err("cannot open input file `%s'", path);
    goto cleanup_and_exit;
  }

  if (!(p = XML_ParserCreate(NULL))) {
    err("cannot create an XML parser");
    goto cleanup_and_exit;
  }

  XML_SetUnknownEncodingHandler(p, encoding_hnd, NULL);
  XML_SetStartElementHandler(p, start_hnd);
  XML_SetEndElementHandler(p, end_hnd);
  XML_SetCharacterDataHandler(p, chardata_hnd);
  XML_SetUserData(p, &data);
  XML_UseParserAsHandlerArg(p);

  data.tag_map = tag_map;
  data.attn_map = attn_map;
  data.alloc_tag_func = tag_alloc;
  data.alloc_attn_func = attn_alloc;

  while (fgets(buf, sizeof(buf), f)) {
    len = strlen(buf);
    if (XML_Parse(p, buf, len, 0) == XML_STATUS_ERROR) {
      err("%s: %d: parse error: %s",
          path, XML_GetCurrentLineNumber(p),
          XML_ErrorString(XML_GetErrorCode(p)));
      goto cleanup_and_exit;
    }
  }

  if (ferror(f)) {
    err("input error");
    goto cleanup_and_exit;
  }
  if (data.err_cntr) goto cleanup_and_exit;

  XML_ParserFree(p);
  fclose(f);
  return data.tree;

 cleanup_and_exit:
  if (p) XML_ParserFree(p);
  if (f) fclose(f);
  if (data.tree) xml_tree_free(data.tree, 0, 0);
  return 0;
}

struct xml_tree *
xml_build_tree_str(char const *str,
                   char const * const *tag_map,
                   char const * const *attn_map,
                   void * (*tag_alloc)(int),
                   void * (*attn_alloc)(int))
{
  XML_Parser p = 0;
  int len;
  struct parser_data data;

  memset(&data, 0, sizeof(data));
  ASSERT(str);
  ASSERT(tag_map);
  ASSERT(attn_map);
  len = strlen(str);
  if (!tag_alloc) tag_alloc = generic_tag_alloc;
  if (!attn_alloc) attn_alloc = generic_attn_alloc;

  if (!(p = XML_ParserCreate(NULL))) {
    err("cannot create an XML parser");
    goto cleanup_and_exit;
  }

  XML_SetUnknownEncodingHandler(p, encoding_hnd, NULL);
  XML_SetStartElementHandler(p, start_hnd);
  XML_SetEndElementHandler(p, end_hnd);
  XML_SetCharacterDataHandler(p, chardata_hnd);
  XML_SetUserData(p, &data);
  XML_UseParserAsHandlerArg(p);

  data.tag_map = tag_map;
  data.attn_map = attn_map;
  data.alloc_tag_func = tag_alloc;
  data.alloc_attn_func = attn_alloc;
  if (XML_Parse(p, str, len, 0) == XML_STATUS_ERROR) {
    err("%d: parse error: %s",
        XML_GetCurrentLineNumber(p),
        XML_ErrorString(XML_GetErrorCode(p)));
    goto cleanup_and_exit;
  }
  if (data.err_cntr) goto cleanup_and_exit;

  XML_ParserFree(p);
  return data.tree;

 cleanup_and_exit:
  if (p) XML_ParserFree(p);
  if (data.tree) xml_tree_free(data.tree, 0, 0);
  return 0;
}

struct xml_tree *
xml_tree_free(struct xml_tree *tree,
              void (*tag_free)(struct xml_tree *),
              void (*attn_free)(struct xml_attn *))
{
  struct xml_tree *d, *t;
  struct xml_attn *a, *b;

  for (d = tree->first_down; d; d = t) {
    t = d->right;
    xml_tree_free(d, tag_free, attn_free);
  }
  for (a = tree->first; a; a = b) {
    b = a->next;
    if (attn_free) (*attn_free)(a);
    xfree(a->text);
    xfree(a);
  }
  if (tag_free) (*tag_free)(tree);
  xfree(tree->text);
  xfree(tree);

  return 0;
}

static void
do_xml_unparse_tree(int nest,
                    FILE *out,
                    struct xml_tree const *tree,
                    char const * const *tag_map,
                    char const * const *attn_map,
                    int (*tag_print)(FILE *, struct xml_tree const *),
                    int (*attn_print)(FILE *, struct xml_attn const *),
                    void (*fmt_print)(FILE *, struct xml_tree const *,int,int))
{
  int r;
  struct xml_attn const *a;
  struct xml_tree const *t;

  if (!tree || !tag_map) return;

  if (fmt_print) (*fmt_print)(out, tree, 0, nest);
  fprintf(out, "<%s", tag_map[tree->tag]);
  for (a = tree->first; a; a = a->next) {
    if (!attn_map) continue;
    fprintf(out, " %s=\"", attn_map[a->tag]);
    r = 0;
    if (attn_print) r = (*attn_print)(out, a);
    if (!r && a->text) fprintf(out, "%s", a->text);
    fprintf(out, "\"");
  }
  fprintf(out, ">");
  if (fmt_print) (*fmt_print)(out, tree, 1, nest);
  r = 0;
  if (tag_print) r = (*tag_print)(out, tree);
  if (!r && tree->text) fprintf(out, "%s", tree->text);
  for (t = tree->first_down; t; t = t->right)
    do_xml_unparse_tree(nest + 1,
                        out, t, tag_map, attn_map, tag_print, attn_print,
                        fmt_print);
  if (fmt_print) (*fmt_print)(out, tree, 2, nest);
  fprintf(out, "</%s>", tag_map[tree->tag]);
  if (fmt_print) (*fmt_print)(out, tree, 3, nest);
}

void
xml_unparse_tree(FILE *out,
                 struct xml_tree const *tree,
                 char const * const *tag_map,
                 char const * const *attn_map,
                 int (*tag_print)(FILE *, struct xml_tree const *),
                 int (*attn_print)(FILE *, struct xml_attn const *),
                 void (*fmt_print)(FILE *, struct xml_tree const *, int, int))
{
  fprintf(out, "<?xml version=\"1.0\" encoding=\"koi8-r\"?>\n");
  do_xml_unparse_tree(0, out, tree, tag_map, attn_map, tag_print, attn_print,
                      fmt_print);
}

void
xml_unlink_node(struct xml_tree *p)
{
  struct xml_tree *f;

  if (!p) return;
  f = p->up;
  ASSERT(f);

  if (p->left) {
    p->left->right = p->right;
  } else {
    f->first_down = p->right;
  }
  if (p->right) {
    p->right->left = p->left;
  } else {
    f->last_down = p->left;
  }
  p->up = 0;
  p->left = 0;
  p->right = 0;
}

void
xml_link_node_first(struct xml_tree *p, struct xml_tree *c)
{
  if (!p || !c) return;
  c->up = p;
  if (!p->first_down) {
    c->left = c->right = 0;
    p->first_down = p->last_down = c;
  } else {
    c->left = 0;
    c->right = p->first_down;
    p->first_down->left = c;
    p->first_down = c;
  }
}

void
xml_link_node_last(struct xml_tree *p, struct xml_tree *c)
{
  if (!p || !c) return;
  c->up = p;
  if (!p->last_down) {
    c->left = c->right = 0;
    p->first_down = p->last_down = c;
  } else {
    c->right = 0;
    c->left = p->last_down;
    p->last_down->right = c;
    p->last_down = c;
  }
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
