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

#include "nls.h"
#include "userlist.h"

#include <expat.h>

#include <stdio.h>

extern struct nls_table *nls_table_koi8_r;
extern struct nls_table *nls_table_utf8;
extern struct nls_table *nls_table_cp1251;
extern struct nls_table *nls_table_cp866;
extern struct nls_table *nls_table_iso8859_5;

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

  /* actual data to be parsed */
  struct userlist_cfg *cfg;
};

static char const * const tag_map[] =
{
  0,

  0
};

int
encoding_hnd(void *data, const XML_Char *name, XML_Encoding *info)
{
  int i, o;
  unsigned char cb, cu1, cu2;
  struct nls_table *tab = 0;

  if (!strcasecmp(name, "koi8-r") || !strcasecmp(name, "koi8-ru")) {
    tab = nls_table_koi8_r;
  } else if(!strcasecmp(name, "microsoft-1251")
            || !strcasecmp(name, "cp1251")) {
    tab = nls_table_cp1251;
  } else if (!strcasecmp(name, "cp866")) {
    tab = nls_table_cp866;
  } else if (!strcasecmp(name, "iso8859-5")) {
    tab = nls_table_iso8859_5;
  }

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

void
handle_attrib(struct parser_data *pd, void *tree,
              unsigned char const *name, int itag,
              unsigned char const *attrib, unsigned char const *value)
{
  switch (itag) {
  default:
    fprintf(stderr, "Unknown tag: %s\n", name);
    return;
  }
  return;

 invalid_value:
  fprintf(stderr, "Invalid value of attribute `%s'\n", attrib);
  return;

 invalid_attribute:
  fprintf(stderr, "Invalid attribute `%s' for tag `%s'\n", attrib, name);
}

void
start_hnd(void *data, const XML_Char *name, const XML_Char **atts)
{
  int cur_val_size = 0, cur_attr_size = 0, val_len, attr_len;
  char *cur_val = 0, *cur_attr = 0;
  int cur_tag_size = 0, tag_len;
  char *cur_tag = 0;
  struct parser_data *pd = (struct parser_data*) data;
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
    fprintf(stderr, "Unknown tag: %s, skipping\n", cur_tag);
    goto start_skipping;
  }

  switch (itag) {
  default:
  invalid_usage:
    fprintf(stderr, "Invalid tag `%s' usage\n", cur_tag);
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
    handle_attrib(pd, tree, cur_tag, itag, cur_attr, cur_val);
    atts += 2;
  }

  tl = (struct tag_list*) calloc(1, sizeof(*tl));
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

void
end_hnd(void *data, const XML_Char *name)
{
  struct parser_data *pd = (struct parser_data*) data;
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

  switch (tl->itag) {
  default:
    fprintf(stderr, "unexpected closing tag: %s\n", name);
  }

  free(tl->str);
}

void
chardata_hnd(void *data, const XML_Char *s, int len)
{
  struct parser_data *pd = (struct parser_data*) data;

  if (!pd->tag_stack) return;
  if (pd->skipping) return;
  if (!pd->tag_stack->a) pd->tag_stack->a = 32;
  while (pd->tag_stack->u + len >= pd->tag_stack->a)
    pd->tag_stack->a *= 2;
  pd->tag_stack->str = (char*) realloc(pd->tag_stack->str, pd->tag_stack->a);
  memmove(pd->tag_stack->str + pd->tag_stack->u, s, len);
  pd->tag_stack->u += len;
  pd->tag_stack->str[pd->tag_stack->u] = 0;
}

int
main(int argc, char **argv)
{
  XML_Parser p = 0;
  FILE *f = 0;
  char buf[512];
  int len;
  struct parser_data data;

  if (argc != 2) {
    fprintf(stderr, "invalid number of parameters\n");
    goto cleanup_and_exit;
  }

  if (!(f = fopen(argv[1], "r"))) {
    fprintf(stderr, "cannot open input file `%s'\n", argv[1]);
    goto cleanup_and_exit;
  }

  if (!(p = XML_ParserCreate(NULL))) {
    fprintf(stderr, "cannot create an XML parser\n");
    goto cleanup_and_exit;
  }

  memset(&data, 0, sizeof(data));

  XML_SetUnknownEncodingHandler(p, encoding_hnd, NULL);
  XML_SetStartElementHandler(p, start_hnd);
  XML_SetEndElementHandler(p, end_hnd);
  XML_SetCharacterDataHandler(p, chardata_hnd);
  XML_SetUserData(p, &data);

  while (fgets(buf, sizeof(buf), f)) {
    len = strlen(buf);
    if (XML_Parse(p, buf, len, 0) == XML_STATUS_ERROR) {
      fprintf(stderr, "parse error at line %d:%s\n",
              XML_GetCurrentLineNumber(p),
              XML_ErrorString(XML_GetErrorCode(p)));
      goto cleanup_and_exit;
    }
  }
  if (ferror(f)) {
    fprintf(stderr, "input error\n");
    goto cleanup_and_exit;
  }

  XML_ParserFree(p);
  fclose(f);
  return 0;

 cleanup_and_exit:
  if (p) XML_ParserFree(p);
  if (f) fclose(f);
  return 1;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
