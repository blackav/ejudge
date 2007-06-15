/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "settings.h"

#include "expat_iface.h"
#include "pathutl.h"
#include "errlog.h"
#include "misctext.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <expat.h>

#include <string.h>
#include <stdio.h>
#include <iconv.h>
#include <errno.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

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
  int verbatim;
  int verbatim_nest;
  int skip_stop;
  struct tag_list *tag_stack;
  int err_cntr;
  struct xml_tree *tree;
  const struct xml_parse_spec *spec;
  iconv_t conv_hnd;
};

/*
 * returns:
 *  0 - 6   - ok (the sequence length is returned)
 *  -1 - -6 - invalid sequence (its negated length is returned)
 *  -7      - truncated sequence
 */
static int
is_correct_utf8(const unsigned char *buf, size_t size, unsigned int *p_ucs32)
{
  unsigned int w32 = 0;

  if (!size) return 0;
  if (buf[0] <= 0x7F) {
    *p_ucs32 = w32;
    return 1;
  }
  if ((buf[0] & 0xE0) == 0xC0) {
    // two-byte sequence
    if (size < 2) return -7;
    if ((buf[1] & 0xC0) != 0x80) return -2;
    // check for minimal length
    w32 |= buf[1] & 0x3F;
    w32 |= (buf[0] & 0x1F) << 6;
    if (w32 <= 0x7F) return -2;
    *p_ucs32 = w32;
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
    *p_ucs32 = w32;
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
    *p_ucs32 = w32;
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
    *p_ucs32 = w32;
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
    *p_ucs32 = w32;
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
                      const unsigned char *inbuf, size_t inlen,
                      unsigned char *outbuf, size_t outlen)
{
  char *p_inbuf = (char*) inbuf;
  char *p_outbuf = outbuf;
  size_t loc_inlen = inlen, loc_outlen = outlen, convlen;
  int stat;
  unsigned int w32 = 0;

  if (!loc_inlen) return 0;
  while (1) {
    errno = 0;
    convlen = iconv(hnd, &p_inbuf, &loc_inlen, &p_outbuf, &loc_outlen);
    if (convlen != (size_t) -1) {
      ASSERT(!loc_inlen);
      ASSERT(loc_outlen <= outlen);
      return outlen - loc_outlen;
    }
    if (errno == E2BIG) {
      // not enough room. fail
      return (size_t) -1;
    }
    // we need to know the exact failure reason in order to recover
    // check, that the input utf-8 sequence is correct
    ASSERT(loc_inlen > 0);
    stat = is_correct_utf8(p_inbuf, loc_inlen, &w32);
    if (stat == -7) {
      // truncated UTF-8 sequence
      // append `?' and quit
      convlen = convert_utf8_to_local(hnd, "?", 1, p_outbuf, loc_outlen);
      if (convlen == (size_t) -1) return convlen;
      return outlen - loc_outlen + convlen;
    }
    if (stat >= -6 && stat <= -1) {
      // invalid UTF-8 sequence of known length
      convlen = convert_utf8_to_local(hnd, "?", 1, p_outbuf, loc_outlen);
      if (convlen == (size_t) -1) return convlen;
      p_inbuf -= stat;
      loc_inlen += stat;
      p_outbuf += convlen;
      loc_outlen -= convlen;
      continue;
    }
    if (stat >= 1 && stat <= 6) {
      // handle U+2400 - U+2421 special characters
      if (w32 >= 0x2400 && w32 <= 0x2420) {
        p_inbuf += stat;
        loc_inlen -= stat;
        *p_outbuf++ = w32 - 0x2400;
        loc_outlen--;
        continue;
      } else if (w32 == 0x2421) {
        p_inbuf += stat;
        loc_inlen -= stat;
        *p_outbuf++ = 0x7f;
        loc_outlen--;
        continue;
      }
      // a good UTF-8 sequence with no mapping to the target charset
      convlen = convert_utf8_to_local(hnd, "?", 1, p_outbuf, loc_outlen);
      if (convlen == (size_t) -1) return convlen;
      p_inbuf += stat;
      loc_inlen -= stat;
      p_outbuf += convlen;
      loc_outlen -= convlen;
      continue;
    }
    abort();
  }
}

static unsigned char *
convert_utf8_to_local_heap(iconv_t hnd, const unsigned char *str)
{
  size_t inlen, buflen, convlen;
  unsigned char *buf = 0;

  if (!str) str = "";
  if (!*str) return xstrdup("");

  inlen = strlen(str);
  // be very pessimistic about the string size :-(
  buflen = 4 * inlen + 16;
  buf = alloca(buflen);
  convlen = convert_utf8_to_local(hnd, str, inlen, buf, buflen);
  ASSERT(convlen < buflen);
  buf[convlen] = 0;
  return xstrdup(buf);
}

static int
encoding_hnd(void *data, const XML_Char *name, XML_Encoding *info)
{
  int i;
  iconv_t conv_hnd;
  unsigned char in_buf[16], out_buf[16];
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
      ASSERT(!in_size);
      ASSERT(out_size + 2 == sizeof(out_buf));
      info->map[i] = out_buf[0] | (out_buf[1] << 8);
    }
  }

  iconv_close(conv_hnd);
  return 1;
}

static void
start_hnd(void *data, const XML_Char *name, const XML_Char **atts)
{
  XML_Parser p = (XML_Parser) data;
  char *cur_val = 0;
  const unsigned char *cur_tag = 0;
  const unsigned char *cur_attr = 0;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);
  struct tag_list *tl = 0;
  int itag = 0, iattr = 0;
  struct xml_tree *new_node, *parent_node;
  struct xml_attr *new_attr;
  int generic_flag;

  /* it is safe to preserve the tag in the UTF-8 encoding, since
   * all the correct tags are in Latin-1.
   */
  cur_tag = (const unsigned char*) name;

  if (pd->skipping) {
    pd->nest++;
    return;
  }
  if (pd->verbatim) {
    pd->verbatim_nest++;
  }

  if (pd->verbatim && pd->spec->text_elem > 0
      && (tl = pd->tag_stack) && tl->str && *tl->str) {
    if (pd->spec->elem_alloc)
      new_node = (struct xml_tree*)(*pd->spec->elem_alloc)(pd->spec->text_elem);
    else
      new_node = xml_elem_alloc(pd->spec->text_elem, pd->spec->elem_sizes);

    new_node->tag = pd->spec->text_elem;
    new_node->line = XML_GetCurrentLineNumber(p);
    new_node->column = XML_GetCurrentColumnNumber(p);
    parent_node = tl->tree;
    new_node->up = parent_node;
    if (parent_node->first_down) {
      parent_node->last_down->right = new_node;
      new_node->left = parent_node->last_down;
      parent_node->last_down = new_node;
    } else {
      parent_node->first_down = parent_node->last_down = new_node;
    }
    new_node->text = convert_utf8_to_local_heap(pd->conv_hnd, tl->str);
    tl->u = 0;
    //free(tl->str); tl->str = 0;
  }

  generic_flag = 0;
  if (pd->verbatim) {
    itag = pd->spec->default_elem;
    generic_flag = 1;
  } else if (!pd->spec->elem_map) {
    itag = pd->spec->default_elem;
    generic_flag = 1;
    if (itag <= 0) {
      err("unknown tag <%s> at line %ld, skipping",
          cur_tag, (long) XML_GetCurrentLineNumber(p));
      pd->err_cntr++;
      goto start_skipping;
    }
  } else {
    for (itag = 1; pd->spec->elem_map[itag]; itag++)
      if (!strcmp(cur_tag, pd->spec->elem_map[itag]))
        break;
    if (!pd->spec->elem_map[itag]) {
      itag = pd->spec->default_elem;
      generic_flag = 1;
      if (itag <= 0) {
        err("unknown tag <%s> at line %ld, skipping",
            cur_tag, (long) XML_GetCurrentLineNumber(p));
        pd->err_cntr++;
        goto start_skipping;
      }
    }
  }

  if (generic_flag)
    new_node = (struct xml_tree*) xcalloc(1, sizeof(struct xml_tree) + sizeof(char*));
  else if (pd->spec->elem_alloc)
    new_node = (struct xml_tree*) (*pd->spec->elem_alloc)(itag);
  else
    new_node = xml_elem_alloc(itag, pd->spec->elem_sizes);

  new_node->tag = itag;
  new_node->line = XML_GetCurrentLineNumber(p);
  new_node->column = XML_GetCurrentColumnNumber(p);
  if (generic_flag) {
    new_node->name[0] = xstrdup(cur_tag);
  }
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
    cur_attr = (const unsigned char*) atts[0];
    cur_val = convert_utf8_to_local_heap(pd->conv_hnd, atts[1]);

    generic_flag = 0;
    if (pd->verbatim) {
      iattr = pd->spec->default_attr;
      generic_flag = 1;
    } else if (!pd->spec->attr_map) {
      iattr = pd->spec->default_attr;
      generic_flag = 1;
      if (iattr <= 0) {
        err("unknown attribute <%s> at line %ld",
            cur_attr, (long) XML_GetCurrentLineNumber(p));
        pd->err_cntr++;
        atts += 2;
        xfree(cur_val); cur_val = 0;
        continue;
      }
    } else {
      for (iattr = 1; pd->spec->attr_map[iattr]; iattr++)
        if (!strcmp(cur_attr, pd->spec->attr_map[iattr]))
          break;
      if (!pd->spec->attr_map[iattr]) {
        iattr = pd->spec->default_attr;
        generic_flag = 1;
        if (iattr <= 0) {
          err("unknown attribute <%s> at line %ld",
              cur_attr, (long) XML_GetCurrentLineNumber(p));
          pd->err_cntr++;
          atts += 2;
          xfree(cur_val); cur_val = 0;
          continue;
        }
      }
    }

    if (generic_flag)
      new_attr = (struct xml_attr*) xcalloc(1, sizeof(struct xml_attr) + sizeof(char*));
    else if (pd->spec->attr_alloc)
      new_attr = (struct xml_attr*) (*pd->spec->attr_alloc)(iattr);
    else
      new_attr = xml_attr_alloc(iattr, pd->spec->attr_sizes);

    new_attr->tag = iattr;
    new_attr->text = cur_val;
    new_attr->line = XML_GetCurrentLineNumber(p);
    new_attr->column = XML_GetCurrentColumnNumber(p);
    if (generic_flag) {
      new_attr->name[0] = xstrdup(cur_attr);
    }
    if (!new_node->first) {
      new_node->first = new_node->last = new_attr;
    } else {
      new_node->last->next = new_attr;
      new_attr->prev = new_node->last;
      new_node->last = new_attr;
    }
    atts += 2;
  }

  tl = (struct tag_list*) xcalloc(1, sizeof(*tl));
  tl->itag = itag;
  tl->next = pd->tag_stack;
  tl->tree = new_node;
  pd->tag_stack = tl;
  pd->nest++;

  if (pd->spec->verbatim_flags && pd->spec->verbatim_flags[itag]) {
    pd->verbatim = 1;
    pd->verbatim_nest = 0;
  }
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

  if (pd->verbatim) pd->verbatim_nest--;
  if (pd->verbatim && pd->verbatim_nest < 0) {
    pd->verbatim = 0;
  }
}

static void
chardata_hnd(void *data, const XML_Char *s, int len)
{
  XML_Parser p = (XML_Parser) data;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);

  if (!pd->tag_stack) return;
  if (pd->skipping) return;

  if (pd->spec->unparse_entity && len == 1) {
    switch (*s) {
    case '&':  s = "&amp;";  len = 5; break;
    case '<':  s = "&lt;";   len = 4; break;
    case '>':  s = "&gt;";   len = 4; break;
    case '\'': s = "&apos;"; len = 6; break;
    case '\"': s = "&quot;"; len = 6; break;
    }
  }
  
  if (!pd->tag_stack->a) pd->tag_stack->a = 32;
  while (pd->tag_stack->u + len >= pd->tag_stack->a)
    pd->tag_stack->a *= 2;
  pd->tag_stack->str = (char*) xrealloc(pd->tag_stack->str, pd->tag_stack->a);
  memmove(pd->tag_stack->str + pd->tag_stack->u, s, len);
  pd->tag_stack->u += len;
  pd->tag_stack->str[pd->tag_stack->u] = 0;
}

static void *
generic_elem_alloc(int tag, const size_t *sizes)
{
  size_t size = sizeof(struct xml_tree);
  if (sizes && sizes[tag]) size = sizes[tag];
  return xcalloc(1, size);
}
static void *
generic_attr_alloc(int tag, const size_t *sizes)
{
  size_t size = sizeof(struct xml_attr);
  if (sizes && sizes[tag]) size = sizes[tag];
  return xcalloc(1, size);
}

struct xml_tree *
xml_elem_alloc(int tag, const size_t *sizes)
{
  return (struct xml_tree*) generic_elem_alloc(tag, sizes);
}
struct xml_attr *
xml_attr_alloc(int tag, const size_t *sizes)
{
  return (struct xml_attr*) generic_attr_alloc(tag, sizes);
}

static void
xml_skipped_entity_handler(
	void *data,
	const XML_Char *s,
	int   is_parameter_entity)
{
  XML_Parser p = (XML_Parser) data;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);
  int len = strlen(s);

  if (!pd->tag_stack) return;
  if (pd->skipping) return;
  if (is_parameter_entity) return;

  if (!pd->tag_stack->a) pd->tag_stack->a = 32;
  while (pd->tag_stack->u + len + 2 >= pd->tag_stack->a)
    pd->tag_stack->a *= 2;
  pd->tag_stack->str = (char*) xrealloc(pd->tag_stack->str, pd->tag_stack->a);
  pd->tag_stack->str[pd->tag_stack->u] = '&';
  memmove(pd->tag_stack->str + pd->tag_stack->u + 1, s, len);
  pd->tag_stack->u += len + 1;
  pd->tag_stack->str[pd->tag_stack->u++] = ';';
  pd->tag_stack->str[pd->tag_stack->u] = 0;
}

struct xml_tree *
xml_build_tree(char const *path, const struct xml_parse_spec *spec)
{
  XML_Parser p = 0;
  FILE *f = 0;
  char buf[512];
  int len;
  iconv_t conv_hnd = 0;
  struct parser_data data;

  memset(&data, 0, sizeof(data));
  ASSERT(path);
  ASSERT(spec);

  if (!(conv_hnd = iconv_open(EJUDGE_CHARSET, "UTF-8"))) {
    err("no conversion is possible from UTF-8 to %s", EJUDGE_CHARSET);
    goto cleanup_and_exit;
  }

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
  if (spec->unparse_entity) {
    //XML_SetDefaultHandler(p, xml_default_handler);
    XML_UseForeignDTD(p, 1);
    XML_SetSkippedEntityHandler(p, xml_skipped_entity_handler);
  }

  data.spec = spec;
  data.conv_hnd = conv_hnd;

  while (fgets(buf, sizeof(buf), f)) {
    len = strlen(buf);
    if (XML_Parse(p, buf, len, 0) == XML_STATUS_ERROR) {
      err("%s: %ld: parse error: %s",
          path, (long) XML_GetCurrentLineNumber(p),
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
  iconv_close(conv_hnd);
  return data.tree;

 cleanup_and_exit:
  if (conv_hnd) iconv_close(conv_hnd);
  if (p) XML_ParserFree(p);
  if (f) fclose(f);
  if (data.tree) xml_tree_free(data.tree, spec);
  return 0;
}

struct xml_tree *
xml_build_tree_str(char const *str, const struct xml_parse_spec *spec)
{
  XML_Parser p = 0;
  int len;
  iconv_t conv_hnd = 0;
  struct parser_data data;

  memset(&data, 0, sizeof(data));
  ASSERT(str);
  ASSERT(spec);
  len = strlen(str);

  if (!(conv_hnd = iconv_open(EJUDGE_CHARSET, "UTF-8"))) {
    err("no conversion is possible from UTF-8 to %s", EJUDGE_CHARSET);
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
  if (spec->unparse_entity) {
    //XML_SetDefaultHandler(p, xml_default_handler);
    XML_UseForeignDTD(p, 1);
    XML_SetSkippedEntityHandler(p, xml_skipped_entity_handler);
  }

  data.spec = spec;
  data.conv_hnd = conv_hnd;

  if (XML_Parse(p, str, len, 0) == XML_STATUS_ERROR) {
    err("%ld: parse error: %s",
        (long) XML_GetCurrentLineNumber(p),
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
  if (data.tree) xml_tree_free(data.tree, spec);
  return 0;
}

struct xml_tree *
xml_build_tree_file(FILE *f, const struct xml_parse_spec *spec)
{
  XML_Parser p = 0;
  char buf[512];
  int len;
  iconv_t conv_hnd = 0;
  struct parser_data data;

  memset(&data, 0, sizeof(data));
  ASSERT(spec);

  if (!(conv_hnd = iconv_open(EJUDGE_CHARSET, "UTF-8"))) {
    err("no conversion is possible from UTF-8 to %s", EJUDGE_CHARSET);
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
  if (spec->unparse_entity) {
    //XML_SetDefaultHandler(p, xml_default_handler);
    XML_UseForeignDTD(p, 1);
    XML_SetSkippedEntityHandler(p, xml_skipped_entity_handler);
  }

  data.spec = spec;
  data.conv_hnd = conv_hnd;

  while (fgets(buf, sizeof(buf), f)) {
    len = strlen(buf);
    if (XML_Parse(p, buf, len, 0) == XML_STATUS_ERROR) {
      err("%ld: parse error: %s",
          (long) XML_GetCurrentLineNumber(p),
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
  iconv_close(conv_hnd);
  return data.tree;

 cleanup_and_exit:
  if (conv_hnd) iconv_close(conv_hnd);
  if (p) XML_ParserFree(p);
  if (f) fclose(f);
  if (data.tree) xml_tree_free(data.tree, spec);
  return 0;
}

void
xml_tree_free_attrs(struct xml_tree *tree,
                    const struct xml_parse_spec *spec)
{
  struct xml_attr *a, *b;

  if (!tree) return;
  for (a = tree->first; a; a = b) {
    b = a->next;
    if (spec && spec->default_attr > 0 && spec->default_attr == a->tag)
      xfree(a->name[0]);
    if (spec && spec->attr_free) (*spec->attr_free)(a);
    xfree(a->text);
    xfree(a);
  }
  tree->first = tree->last = NULL;
}

struct xml_tree *
xml_tree_free(struct xml_tree *tree, const struct xml_parse_spec *spec)
{
  struct xml_tree *d, *t;

  if (!tree) return 0;

  for (d = tree->first_down; d; d = t) {
    t = d->right;
    xml_tree_free(d, spec);
  }
  xml_tree_free_attrs(tree, spec);
  if (spec && spec->default_elem > 0 && spec->default_elem == tree->tag)
    xfree(tree->name[0]);
  if (spec && spec->elem_free) (*spec->elem_free)(tree);
  xfree(tree->text);
  xfree(tree);

  return 0;
}

static void
do_xml_unparse_tree(int nest,
                    FILE *out,
                    const struct xml_tree *tree,
                    char const * const *tag_map,
                    char const * const *attr_map,
                    int (*tag_print)(FILE *, struct xml_tree const *),
                    int (*attr_print)(FILE *, struct xml_attr const *),
                    void (*fmt_print)(FILE *, struct xml_tree const *,int,int))
{
  int r;
  struct xml_attr const *a;
  struct xml_tree const *t;

  if (!tree || !tag_map) return;

  if (fmt_print) (*fmt_print)(out, tree, 0, nest);
  fprintf(out, "<%s", tag_map[tree->tag]);
  for (a = tree->first; a; a = a->next) {
    if (!attr_map) continue;
    fprintf(out, " %s=\"", attr_map[a->tag]);
    r = 0;
    if (attr_print) r = (*attr_print)(out, a);
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
                        out, t, tag_map, attr_map, tag_print, attr_print,
                        fmt_print);
  if (fmt_print) (*fmt_print)(out, tree, 2, nest);
  fprintf(out, "</%s>", tag_map[tree->tag]);
  if (fmt_print) (*fmt_print)(out, tree, 3, nest);
}

void
xml_unparse_tree(FILE *out,
                 struct xml_tree const *tree,
                 char const * const *tag_map,
                 char const * const *attr_map,
                 int (*tag_print)(FILE *, struct xml_tree const *),
                 int (*attr_print)(FILE *, struct xml_attr const *),
                 void (*fmt_print)(FILE *, struct xml_tree const *, int, int))
{
  fprintf(out, "<?xml version=\"1.0\" encoding=\"%s\"?>\n",
          EJUDGE_CHARSET);
  do_xml_unparse_tree(0, out, tree, tag_map, attr_map, tag_print, attr_print,
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

static const unsigned char *
do_subst(
	struct html_armor_buffer *pb,
        const unsigned char *str,
        const unsigned char **subst)
{
  const unsigned char *s;

  if (!subst || !subst[0] || !str) return str;
  for (s = str; *s && *s != '$'; s++);
  if (!*s) return str;

  //...

  return "";
}

void
xml_unparse_raw_tree(
	FILE *fout,
        const struct xml_tree *tree,
        const struct xml_parse_spec *spec,
        const unsigned char **varsubst)
{
  struct xml_tree *p;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct html_armor_buffer sb = HTML_ARMOR_INITIALIZER;
  struct xml_attr *a;

  if (!tree) return;

  for (p = tree->first_down; p; p = p->right) {
    if (p->tag == spec->text_elem) {
      if (p->text) fprintf(fout, "%s", p->text);
    } else {
      if (p->tag == spec->default_elem) {
        fprintf(fout, "<%s", p->name[0]);
      } else {
        fprintf(fout, "<%s", spec->elem_map[p->tag]);
      }
      for (a = p->first; a; a = a->next) {
        if (a->tag == spec->default_attr) {
          fprintf(fout, " %s=\"%s\"", a->name[0],
                  html_armor_buf(&ab, do_subst(&sb, a->text, varsubst)));
        } else {
          fprintf(fout, " %s=\"%s\"", spec->attr_map[a->tag],
                  html_armor_buf(&ab, do_subst(&sb, a->text, varsubst)));
        }
      }
      if (!p->first_down && (!p->text || !*p->text)) {
        fprintf(fout, "/>");
      } else {
        fprintf(fout, ">");
        xml_unparse_raw_tree(fout, p, spec, varsubst);
        if (p->tag == spec->default_elem) {
          fprintf(fout, "</%s>", p->name[0]);
        } else {
          fprintf(fout, "</%s>", spec->elem_map[p->tag]);
        }
      }
    }
  }

  if (tree->text) fprintf(fout, "%s", tree->text);

  html_armor_free(&ab);
  html_armor_free(&sb);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 * End:
 */
