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
#include "utf8_utils.h"
#include "pathutl.h"

#include "reuse/logger.h"
#include "reuse/xalloc.h"

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
  char **tag_map;
  char **attn_map;
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

    for (iattn = 1; pd->attn_map[iattn]; iattn++)
      if (!strcmp(cur_attr, pd->attn_map[iattn]))
        break;
    if (!pd->attn_map[iattn]) {
      err("unknown attribute <%s> at line %d",
          cur_tag, XML_GetCurrentLineNumber(p));
      pd->err_cntr++;
      atts += 2;
      continue;
    }
    new_attn = (struct xml_attn*) pd->alloc_attn_func(iattn);
    new_attn->tag = iattn;
    new_attn->text = xstrdup(cur_val);
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

struct xml_tree *
xml_build_tree(char const *path,
               char **tag_map,
               char **attn_map,
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
  ASSERT(tag_map);
  ASSERT(attn_map);

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
                   char **tag_map,
                   char **attn_map,
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
              void (*tag_free)(void *),
              void (*attn_free)(void *))
{
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
