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

#include "userlist_cfg.h"
#include "nls.h"
#include "userlist.h"
#include "utf8_utils.h"
#include "pathutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <expat.h>

#include <stdio.h>
#include <string.h>

struct tag_list
{
  struct tag_list *next;

  int itag;
  int a, u;
  unsigned char *str;
  void *tree;
};

struct parser_data
{
  int nest;
  int skipping;
  int skip_stop;
  struct tag_list *tag_stack;
  int err_cntr;

  /* actual data to be parsed */
  struct userlist_cfg *cfg;
};

enum
  {
    TG_CONFIG = 1,
    TG_FILE,
    TG_SOCKET,
  };

static char const * const tag_map[] =
{
  0,
  "config",
  "file",
  "socket",

  0
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
handle_attrib(XML_Parser p,
              struct parser_data *pd, void *tree,
              unsigned char const *name, int itag,
              unsigned char const *attrib, unsigned char const *value)
{
  switch (itag) {
  case TG_CONFIG:
  case TG_FILE:
  case TG_SOCKET:
    goto invalid_attribute;
  default:
    err("Unknown tag: %s", name);
    pd->err_cntr++;
    return;
  }
  return;
 
 /*
 invalid_value:
  fprintf(stderr, "Invalid value of attribute `%s'\n", attrib);
  return;
 */

 invalid_attribute:
  err("invalid attribute `%s' for tag `%s'", attrib, name);
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
  void *tree = 0;
  int itag = 0;

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

  for (itag = 1; tag_map[itag]; itag++)
    if (!strcmp(cur_tag, tag_map[itag]))
      break;
  if (!tag_map[itag]) {
    err("unknown tag <%s> at line %d, skipping",
        cur_tag, XML_GetCurrentLineNumber(p));
    pd->err_cntr++;
    goto start_skipping;
  }

  switch (itag) {
  case TG_CONFIG:
    if (pd->tag_stack) goto invalid_usage;
    pd->cfg = xcalloc(1, sizeof(*pd->cfg));
    tree = pd->cfg;
    break;
  case TG_FILE:
    if (!pd->tag_stack || pd->tag_stack->itag != TG_CONFIG)
      goto invalid_usage;
    {
      struct userlist_cfg *uc = (struct userlist_cfg*) pd->tag_stack->tree;
      if (uc->db_path) {
        err("%s can be specified only once", cur_tag);
        pd->err_cntr++;
        goto start_skipping;
      }
      tree = pd->tag_stack->tree;
    }
    break;
  case TG_SOCKET:
    if (!pd->tag_stack || pd->tag_stack->itag != TG_CONFIG)
      goto invalid_usage;
    {
      struct userlist_cfg *uc = (struct userlist_cfg*) pd->tag_stack->tree;
      if (uc->socket_path) {
        err("%s can be specified only once", cur_tag);
        pd->err_cntr++;
        goto start_skipping;
      }
      tree = pd->tag_stack->tree;      
    }
    break;
  default:
  invalid_usage:
    err("Invalid tag `%s' usage", cur_tag);
    pd->err_cntr++;
    goto start_skipping;
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
    handle_attrib(p, pd, tree, cur_tag, itag, cur_attr, cur_val);
    atts += 2;
  }

  tl = (struct tag_list*) xcalloc(1, sizeof(*tl));
  tl->itag = itag;
  tl->next = pd->tag_stack;
  tl->tree = tree;
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
  struct userlist_cfg *uc = 0;

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

  switch (tl->itag) {
  case TG_CONFIG:
    break;
  case TG_FILE:
    uc = (struct userlist_cfg*) tl->tree;
    uc->db_path = str_utf8_to_koi8_heap(tl->str);
    break;
  case TG_SOCKET:
    uc = (struct userlist_cfg*) tl->tree;
    uc->socket_path = str_utf8_to_koi8_heap(tl->str);
    break;
  default:
    err("unexpected closing tag: %s", name);
    pd->err_cntr++;
  }

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

struct userlist_cfg *
userlist_cfg_parse(char const *path)
{
  XML_Parser p = 0;
  FILE *f = 0;
  char buf[512];
  int len;
  struct parser_data data;

  memset(&data, 0, sizeof(data));

  ASSERT(path);
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
  return data.cfg;

 cleanup_and_exit:
  if (p) XML_ParserFree(p);
  if (f) fclose(f);
  if (data.cfg) userlist_cfg_free(data.cfg);
  return 0;
}

struct userlist_cfg *
userlist_cfg_free(struct userlist_cfg *cfg)
{
  xfree(cfg->db_path);
  xfree(cfg->socket_path);
  xfree(cfg);
  return 0;
}

void
userlist_cfg_unparse(struct userlist_cfg *cfg, FILE *f)
{
  if (!cfg) return;
  fprintf(f, "<?xml version=\"1.0\" encoding=\"koi8-r\"?>\n");
  fprintf(f, "<config>\n");
  if (cfg->db_path)
    fprintf(f, "  <file>%s</file>\n", cfg->db_path);
  if (cfg->socket_path)
    fprintf(f, "  <socket>%s</socket>\n", cfg->socket_path);
  fprintf(f, "</config>\n");
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
