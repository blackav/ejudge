/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_types.h"

#include "misctext.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <iconv.h>

#if defined EJUDGE_CHARSET
#define INTERNAL_CHARSET EJUDGE_CHARSET
#else
#define INTERNAL_CHARSET "utf-8"
#endif

struct charset_info_s
{
  unsigned char *name;
  iconv_t tr;
};

static size_t charset_info_a, charset_info_u;
static struct charset_info_s *charset_info;

int
charset_get_id(const unsigned char *charset_str)
{
  size_t i;

  // empty string or NULL means internal charset
  if (!charset_str || !*charset_str) return 0;
  if (!strcasecmp(charset_str, INTERNAL_CHARSET)) return 0;

  for (i = 1; i < charset_info_u; i++)
    if (!strcasecmp(charset_info[i].name, charset_str))
      break;
  if (i < charset_info_u) return i;
  if (!charset_info_a) {
    charset_info_a = 16;
    XCALLOC(charset_info, charset_info_a);
  } else {
    size_t new_charset_info_a = charset_info_a * 2;
    struct charset_info_s *new_charset_info = 0;
    XCALLOC(new_charset_info, new_charset_info_a);
    memcpy(new_charset_info, charset_info, charset_info_a * sizeof(new_charset_info[0]));
    xfree(charset_info);
    charset_info = new_charset_info;
    charset_info_a = new_charset_info_a;
  }

  charset_info[i].name = xstrdup(charset_str);
  charset_info[i].tr = (iconv_t) -2;
  charset_info_u++;
  return i;
}

static int
open_charset_iconv(struct charset_info_s *ci)
{
  if ((ci->tr = iconv_open(INTERNAL_CHARSET, ci->name)) == (iconv_t) -1)
    return -1;
  return 0;
}

const unsigned char *
charset_recode_buf(
        int id,
        unsigned char *buf,
        size_t size)
{
  struct charset_info_s *ci;
  size_t inbytesleft, outbytesleft, r;
  char *inbuf, *outbuf;
  unsigned char *tmpbuf;

  ASSERT(buf);
  ASSERT(size > 1);

  if (!id) return buf;
  ci = &charset_info[id];
  if (ci->tr == (iconv_t) -2) open_charset_iconv(ci);
  if (ci->tr == (iconv_t) -1) {
    snprintf(buf, size, "invalid conversion from %s to %s",
             ci->name, INTERNAL_CHARSET);
    return buf;
  }

  // FIXME: maybe there are cases when it is possible to recode
  // using the same buffer...
  tmpbuf = (unsigned char*) alloca(size);
  inbuf = (char*) buf;
  inbytesleft = strnlen(buf, size);
  outbuf = (char*) tmpbuf;
  outbytesleft = size - 1;

  if (!inbytesleft) {
    return buf;
  }

  iconv(ci->tr, NULL, NULL, NULL, NULL);
  do {
    errno = 0;
    r = iconv(ci->tr, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    if (r == -1 && (errno == EILSEQ || errno == EINVAL)) {
      inbuf++; inbytesleft--;
      *outbuf++ = '?'; outbytesleft--;
    }
  } while (inbytesleft && outbytesleft && errno != E2BIG);

  // yes, I know what I'm doing
  tmpbuf[size - outbytesleft - 1] = 0;
  strcpy(buf, tmpbuf);
  return buf;
}

const unsigned char *
charset_recode_to_buf(
        int id,
        unsigned char *buf,
        size_t size,
        const unsigned char *str)
{
  struct charset_info_s *ci;
  size_t inbytesleft, outbytesleft, r;
  char *inbuf, *outbuf;

  ASSERT(buf);
  ASSERT(size > 0);
  ASSERT(str);

  if (!id) {
    snprintf(buf, size, "%s", str);
    return buf;
  }
  ci = &charset_info[id];
  if (ci->tr == (iconv_t) -2) open_charset_iconv(ci);
  if (ci->tr == (iconv_t) -1) {
    snprintf(buf, size, "invalid conversion from %s to %s",
             ci->name, INTERNAL_CHARSET);
    return buf;
  }

  inbuf = (char*) str;
  inbytesleft = strlen(str);
  outbuf = buf;
  outbytesleft = size - 1;

  if (!inbytesleft) {
    *outbuf = 0;
    return buf;
  }

  iconv(ci->tr, NULL, NULL, NULL, NULL);
  do {
    errno = 0;
    r = iconv(ci->tr, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    if (r == -1 && (errno == EILSEQ || errno == EINVAL)) {
      inbuf++; inbytesleft--;
      *outbuf++ = '?'; outbytesleft--;
    }
  } while (inbytesleft && outbytesleft && errno != E2BIG);

  buf[size - outbytesleft - 1] = 0;
  /*
  for (r = 0; buf[r]; r++) {
    fprintf(stderr, "<%02x>", buf[r]);
  }
  fprintf(stderr, "\n");
  */
  return buf;
}

const unsigned char *
charset_recode(
        int id,
        struct html_armor_buffer *ab,
        const unsigned char *str)
{
  struct charset_info_s *ci;
  size_t inbytesleft, outbytesleft, r, conv_size;
  char *inbuf, *outbuf;

  ASSERT(ab);
  ASSERT(str);

  if (!id) return str;
  ci = &charset_info[id];
  if (ci->tr == (iconv_t) -2) open_charset_iconv(ci);
  if (ci->tr == (iconv_t) -1) {
    unsigned char tmpbuf[128];
    size_t tmplen;

    snprintf(tmpbuf, sizeof(tmpbuf), "invalid conversion from %s to %s",
             ci->name, INTERNAL_CHARSET);
    tmplen = strlen(tmpbuf);
    html_armor_reserve(ab, tmplen);
    strcpy(ab->buf, tmpbuf);
    return ab->buf;
  }

  html_armor_reserve(ab, 63);
  inbuf = (char*) str;
  inbytesleft = strlen(str);
  outbuf = ab->buf;
  outbytesleft = ab->size - 1;

  iconv(ci->tr, NULL, NULL, NULL, NULL);
  while (inbytesleft) {
    errno = 0;
    r = iconv(ci->tr, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    if (r == -1 && (errno == EILSEQ || errno == EINVAL)) {
      inbuf++; inbytesleft--;
      if (!outbytesleft) {
        conv_size = (size_t)(outbuf - (char*) ab->buf);
        html_armor_extend(ab, ab->size * 2 - 1);
        outbuf = (char*) ab->buf + conv_size;
        outbytesleft = ab->size - conv_size - 1;
      }
      *outbuf++ = '?'; outbytesleft--;
    }
    if (!outbytesleft || (errno == E2BIG)) {
      conv_size = (size_t)(outbuf - (char*) ab->buf);
      html_armor_extend(ab, ab->size * 2 - 1);
      outbuf = (char*) ab->buf + conv_size;
      outbytesleft = ab->size - conv_size - 1;
    }
  }

  ab->buf[ab->size - outbytesleft - 1] = 0;
  /*
  for (r = 0; ab->buf[r]; r++) {
    fprintf(stderr, "<%02x>", ab->buf[r]);
  }
  fprintf(stderr, "\n");
  */
  return ab->buf;
}

unsigned char *
charset_recode_heap(
        int id,
        unsigned char *str)
{
  struct html_armor_buffer rb = HTML_ARMOR_INITIALIZER;
  const unsigned char *str2;

  if (id <= 0) return str;
  str2 = charset_recode(id, &rb, str);
  if (str2 == (const unsigned char*) str) return str;
  xfree(str);
  return rb.buf;
}

unsigned char *
charset_recode_to_heap(
        int id,
        const unsigned char *str)
{
  struct html_armor_buffer rb = HTML_ARMOR_INITIALIZER;
  const unsigned char *str2;

  if (id <= 0) return xstrdup(str);
  str2 = charset_recode(id, &rb, str);
  if (str2 == str) return xstrdup(str);
  return rb.buf;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
