/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2010 Alexander Chernov <cher@ejudge.ru> */

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

#include "expat_iface.h"
#include "xalloc.h"

#include <expat.h>

#include <string.h>
#include <stdio.h>
#include <iconv.h>
#include <errno.h>

#define DEFAULT_CHARSET "UTF-8"

struct tag_list
{
  struct tag_list *next;

  int itag;
  int a, u;
  char *str;
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
  iconv_t conv_hnd;
  FILE *flog;
};

/*
 * returns:
 *  0 - 6   - ok (the sequence length is returned)
 *  -1 - -6 - invalid sequence (its negated length is returned)
 *  -7      - truncated sequence
 */
static int
is_correct_utf8(const char *par_buf, size_t size)
{
  unsigned int w32 = 0;
  const unsigned char *buf = (const unsigned char*) par_buf;

  if (!size) return 0;
  if (buf[0] <= 0x7F) return 1;
  if ((buf[0] & 0xE0) == 0xC0) {
    // two-byte sequence
    if (size < 2) return -7;
    if ((buf[1] & 0xC0) != 0x80) return -2;
    // check for minimal length
    w32 |= buf[1] & 0x3F;
    w32 |= (buf[0] & 0x1F) << 6;
    if (w32 <= 0x7F) return -2;
    return 2;
  }
  if ((buf[0] & 0xF0) == 0xE0) {
    // three-byte sequence
    if (size < 3) return -7;
    if ((buf[1] & 0xC0) != 0x80) return -3;
    if ((buf[2] & 0xC0) != 0x80) return -3;
    // check for minimal length
    w32 |= buf[2] & 0x3F;
    w32 |= (buf[1] & 0x3F) << 6;
    w32 |= (buf[0] & 0x0F) << 12;
    if (w32 <= 0x7FF) return -3;
    return 3;
  }
  if ((buf[0] & 0xF8) == 0xF0) {
    // four-byte sequence
    if (size < 4) return -7;
    if ((buf[1] & 0xC0) != 0x80) return -4;
    if ((buf[2] & 0xC0) != 0x80) return -4;
    if ((buf[3] & 0xC0) != 0x80) return -4;
    // check for minimal length
    w32 |= buf[3] & 0x3F;
    w32 |= (buf[2] & 0x3F) << 6;
    w32 |= (buf[1] & 0x3F) << 12;
    w32 |= (buf[0] & 0x07) << 18;
    if (w32 <= 0xFFFF) return -4;
    return 4;
  }
  if ((buf[0] & 0xFC) == 0xF8) {
    // five-byte sequence
    if (size < 5) return -7;
    if ((buf[1] & 0xC0) != 0x80) return -5;
    if ((buf[2] & 0xC0) != 0x80) return -5;
    if ((buf[3] & 0xC0) != 0x80) return -5;
    if ((buf[4] & 0xC0) != 0x80) return -5;
    // check for minimal length
    w32 |= buf[4] & 0x3F;
    w32 |= (buf[3] & 0x3F) << 6;
    w32 |= (buf[2] & 0x3F) << 12;
    w32 |= (buf[1] & 0x3F) << 18;
    w32 |= (buf[0] & 0x03) << 24;
    if (w32 <= 0x1FFFFF) return -5;
    return 5;
  }
  if ((buf[0] & 0xFE) == 0xFC) {
    // six-byte sequence
    if (size < 6) return -7;
    if ((buf[1] & 0xC0) != 0x80) return -6;
    if ((buf[2] & 0xC0) != 0x80) return -6;
    if ((buf[3] & 0xC0) != 0x80) return -6;
    if ((buf[4] & 0xC0) != 0x80) return -6;
    if ((buf[5] & 0xC0) != 0x80) return -6;
    // check for minimal length
    w32 |= buf[5] & 0x3F;
    w32 |= (buf[4] & 0x3F) << 6;
    w32 |= (buf[3] & 0x3F) << 12;
    w32 |= (buf[2] & 0x3F) << 18;
    w32 |= (buf[1] & 0x3F) << 24;
    w32 |= (buf[0] & 0x01) << 30;
    if (w32 <= 0x3FFFFFF) return -6;
    return 6;
  }
  // 0xFE, 0xFF are invalid
  return -1;
}

/* returns the number of characters in the given UTF-8 string */
/*
static size_t
utf8_strlen(const unsigned char *buf)
{
}
*/

static size_t
convert_utf8_to_local(iconv_t hnd,
                      const char *par_inbuf, size_t inlen,
                      char *outbuf, size_t outlen)
{
  char *inbuf = (char*) par_inbuf;
  size_t loc_inlen = inlen, loc_outlen = outlen, convlen;
  int stat;

  if (!loc_inlen) return 0;
  while (1) {
    errno = 0;
    convlen = iconv(hnd, &inbuf, &loc_inlen, &outbuf, &loc_outlen);
    if (convlen != (size_t) -1) {
      return outlen - loc_outlen;
    }
    if (errno == E2BIG) {
      // not enough room. fail
      return (size_t) -1;
    }
    // we need to know the exact failure reason in order to recover
    // check, that the input utf-8 sequence is correct
    stat = is_correct_utf8(inbuf, loc_inlen);
    if (stat == -7) {
      // truncated UTF-8 sequence
      // append `?' and quit
      convlen = convert_utf8_to_local(hnd, "?", 1, outbuf, loc_outlen);
      if (convlen == (size_t) -1) return convlen;
      return outlen - loc_outlen + convlen;
    }
    if (stat >= -6 && stat <= -1) {
      // invalid UTF-8 sequence of known length
      convlen = convert_utf8_to_local(hnd, "?", 1, outbuf, loc_outlen);
      if (convlen == (size_t) -1) return convlen;
      inbuf -= stat;
      loc_inlen += stat;
      outbuf += convlen;
      loc_outlen -= convlen;
      continue;
    }
    if (stat >= 1 && stat <= 6) {
      // a good UTF-8 sequence with no mapping to the target charset
      convlen = convert_utf8_to_local(hnd, "?", 1, outbuf, loc_outlen);
      if (convlen == (size_t) -1) return convlen;
      inbuf += stat;
      loc_inlen -= stat;
      outbuf += convlen;
      loc_outlen -= convlen;
      continue;
    }
    abort();
  }
}

static char *
convert_utf8_to_local_heap(iconv_t hnd, const char *str)
{
  size_t inlen, buflen, convlen;
  char *buf = 0;

  if (!str) str = "";
  if (!*str) return xstrdup("");

  inlen = strlen(str);
  // be very pessimistic about the string size :-(
  buflen = 4 * inlen + 16;
  buf = alloca(buflen);
  convlen = convert_utf8_to_local(hnd, str, inlen, buf, buflen);
  buf[convlen] = 0;
  return xstrdup(buf);
}

static int
encoding_hnd(void *data, const XML_Char *name, XML_Encoding *info)
{
  int i;
  iconv_t conv_hnd;
  char in_buf[16], out_buf[16];
  char *p_in_buf, *p_out_buf;
  size_t in_size, out_size, conv_size;

  if ((conv_hnd = iconv_open("utf-16le", name)) == (iconv_t) -1)
    return 0;

  info->data = 0;
  info->convert = 0;
  info->release = 0;

  /* fill up the translation table */
  /* FIXME: this supports only one byte encodings */
  for (i = 0; i < 256; i++) {
    in_size = 1;
    p_in_buf = in_buf;
    in_buf[0] = i;
    out_size = sizeof(out_buf);
    p_out_buf = out_buf;
    conv_size = iconv(conv_hnd, &p_in_buf, &in_size, &p_out_buf, &out_size);
    if (conv_size == (size_t) -1) {
      info->map[i] = '?';
      out_size = sizeof(out_buf);
      p_out_buf = out_buf;
      // reset the shift state
      iconv(conv_hnd, 0, 0, &p_out_buf, &out_size);
    } else {
      info->map[i] = out_buf[0] | (out_buf[1] << 8);
    }
  }

  iconv_close(conv_hnd);
  return 1;

#if 0
  XML_Parser p = (XML_Parser) data;
  int i, o;
  unsigned char cb, cu1, cu2;
  iconv_t conv_hnd;
  unsigned char in_buf[16], out_buf[16];
  unsigned char *p_in_buf, *p_out_buf;

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
#endif
}

static void
start_hnd(void *data, const XML_Char *name, const XML_Char **atts)
{
  XML_Parser p = (XML_Parser) data;
  char *cur_val = 0;
  const char *cur_tag = 0;
  const char *cur_attr = 0;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);
  struct tag_list *tl = 0;
  int itag = 0, iattn = 0;
  struct xml_tree *new_node, *parent_node;
  struct xml_attn *new_attn;

  /* it is safe to preserve the tag in the UTF-8 encoding, since
   * all the correct tags are in Latin-1.
   */
  cur_tag = (const char*) name;

  if (pd->skipping) {
    pd->nest++;
    return;
  }

  if (!pd->tag_map) {
    fprintf(pd->flog, "unknown tag <%s> at line %d, skipping\n",
            cur_tag, (int) XML_GetCurrentLineNumber(p));
    pd->err_cntr++;
    goto start_skipping;
  }
  for (itag = 1; pd->tag_map[itag]; itag++)
    if (!strcmp(cur_tag, pd->tag_map[itag]))
      break;
  if (!pd->tag_map[itag]) {
    fprintf(pd->flog, "unknown tag <%s> at line %d, skipping\n",
            cur_tag, (int) XML_GetCurrentLineNumber(p));
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
    /* it is safe to preserve the attribute name in the UTF-8 */
    cur_attr = (const char*) atts[0];
    cur_val = convert_utf8_to_local_heap(pd->conv_hnd, atts[1]);

    if (!pd->attn_map) {
      fprintf(pd->flog, "unknown attribute <%s> at line %d\n",
              cur_attr, (int) XML_GetCurrentLineNumber(p));
      pd->err_cntr++;
      atts += 2;
      xfree(cur_val); cur_val = 0;
      continue;
    }
    for (iattn = 1; pd->attn_map[iattn]; iattn++)
      if (!strcmp(cur_attr, pd->attn_map[iattn]))
        break;
    if (!pd->attn_map[iattn]) {
      fprintf(pd->flog, "unknown attribute <%s> at line %d\n",
              cur_attr, (int) XML_GetCurrentLineNumber(p));
      pd->err_cntr++;
      atts += 2;
      xfree(cur_val); cur_val = 0;
      continue;
    }
    new_attn = (struct xml_attn*) pd->alloc_attn_func(iattn);
    new_attn->tag = iattn;
    new_attn->text = cur_val;
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
  tl->tree->text = convert_utf8_to_local_heap(pd->conv_hnd, tl->str);
  free(tl->str); tl->str = 0;
  free(tl);
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
               void * (*attn_alloc)(int),
               FILE *flog)
{
  XML_Parser p = 0;
  FILE *f = 0;
  char buf[512];
  int len;
  iconv_t conv_hnd = 0;
  struct parser_data data;

  memset(&data, 0, sizeof(data));
  if (!tag_alloc) tag_alloc = generic_tag_alloc;
  if (!attn_alloc) attn_alloc = generic_attn_alloc;

  if (!(conv_hnd = iconv_open(DEFAULT_CHARSET, "UTF-8"))) {
    fprintf(flog, "no conversion is possible from UTF-8 to %s\n",
            DEFAULT_CHARSET);
    goto cleanup_and_exit;
  }

  if (!(f = fopen(path, "r"))) {
    fprintf(flog, "cannot open input file `%s'\n", path);
    goto cleanup_and_exit;
  }

  if (!(p = XML_ParserCreate(NULL))) {
    fprintf(flog, "cannot create an XML parser\n");
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
  data.conv_hnd = conv_hnd;
  data.flog = flog;

  while (fgets(buf, sizeof(buf), f)) {
    len = strlen(buf);
    if (XML_Parse(p, buf, len, 0) == XML_STATUS_ERROR) {
      fprintf(flog, "%s: %d: parse error: %s\n",
              path, (int) XML_GetCurrentLineNumber(p),
              XML_ErrorString(XML_GetErrorCode(p)));
      goto cleanup_and_exit;
    }
  }

  if (ferror(f)) {
    fprintf(flog, "input error\n");
    goto cleanup_and_exit;
  }
  if (data.err_cntr) goto cleanup_and_exit;

  XML_ParserFree(p);
  fclose(f);
  iconv_close(conv_hnd);
  return data.tree;

 cleanup_and_exit:
  if (conv_hnd) iconv_close(conv_hnd);
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
                   void * (*attn_alloc)(int),
                   FILE *flog)
{
  XML_Parser p = 0;
  int len;
  iconv_t conv_hnd = 0;
  struct parser_data data;

  memset(&data, 0, sizeof(data));
  len = strlen(str);
  if (!tag_alloc) tag_alloc = generic_tag_alloc;
  if (!attn_alloc) attn_alloc = generic_attn_alloc;

  if (!(conv_hnd = iconv_open(DEFAULT_CHARSET, "UTF-8"))) {
    fprintf(flog, "no conversion is possible from UTF-8 to %s\n",
            DEFAULT_CHARSET);
    goto cleanup_and_exit;
  }

  if (!(p = XML_ParserCreate(NULL))) {
    fprintf(flog, "cannot create an XML parser\n");
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
  data.conv_hnd = conv_hnd;
  data.flog = flog;

  if (XML_Parse(p, str, len, 0) == XML_STATUS_ERROR) {
    fprintf(flog, "%d: parse error: %s\n",
            (int) XML_GetCurrentLineNumber(p),
            XML_ErrorString(XML_GetErrorCode(p)));
    goto cleanup_and_exit;
  }
  if (data.err_cntr) goto cleanup_and_exit;

  XML_ParserFree(p);
  iconv_close(conv_hnd);
  return data.tree;

 cleanup_and_exit:
  if (conv_hnd) iconv_close(conv_hnd);
  if (p) XML_ParserFree(p);
  if (data.tree) xml_tree_free(data.tree, 0, 0);
  return 0;
}

struct xml_tree *
xml_build_tree_file(FILE *f,
                    char const * const *tag_map,
                    char const * const *attn_map,
                    void * (*tag_alloc)(int),
                    void * (*attn_alloc)(int),
                    FILE *flog)
{
  XML_Parser p = 0;
  char buf[512];
  int len;
  iconv_t conv_hnd = 0;
  struct parser_data data;

  memset(&data, 0, sizeof(data));
  if (!tag_alloc) tag_alloc = generic_tag_alloc;
  if (!attn_alloc) attn_alloc = generic_attn_alloc;

  if (!(conv_hnd = iconv_open(DEFAULT_CHARSET, "UTF-8"))) {
    fprintf(flog, "no conversion is possible from UTF-8 to %s\n",
            DEFAULT_CHARSET);
    goto cleanup_and_exit;
  }

  if (!(p = XML_ParserCreate(NULL))) {
    fprintf(flog, "cannot create an XML parser\n");
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
  data.conv_hnd = conv_hnd;
  data.flog = flog;

  while (fgets(buf, sizeof(buf), f)) {
    len = strlen(buf);
    if (XML_Parse(p, buf, len, 0) == XML_STATUS_ERROR) {
      fprintf(flog, "%d: parse error: %s\n",
              (int) XML_GetCurrentLineNumber(p),
              XML_ErrorString(XML_GetErrorCode(p)));
      goto cleanup_and_exit;
    }
  }

  if (ferror(f)) {
    fprintf(flog, "input error\n");
    goto cleanup_and_exit;
  }
  if (data.err_cntr) goto cleanup_and_exit;

  XML_ParserFree(p);
  fclose(f);
  iconv_close(conv_hnd);
  return data.tree;

 cleanup_and_exit:
  if (conv_hnd) iconv_close(conv_hnd);
  if (p) XML_ParserFree(p);
  if (f) fclose(f);
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
                    const struct xml_tree *tree,
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
  fprintf(out, "<?xml version=\"1.0\" encoding=\"%s\"?>\n", DEFAULT_CHARSET);
  do_xml_unparse_tree(0, out, tree, tag_map, attn_map, tag_print, attn_print,
                      fmt_print);
}

void
xml_unlink_node(struct xml_tree *p)
{
  struct xml_tree *f;

  if (!p) return;
  f = p->up;

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
 * End:
 */
