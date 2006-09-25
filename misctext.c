/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "misctext.h"
#include "base64.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

/* &quot; - '\"', &amp; - '&', &lt; - '<', &gt; - '>' */

static const signed char armored_html_len_table[256] =
{
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 6, 1, 5, 1, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 1, 4, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

static unsigned char const * const armored_html_translate_table[256] =
{
  "?","?","?","?","?","?","?","?","?",0,0,"?","?",0,"?","?",
  "?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?",
  0,0,"&quot;",0,"&#36;",0,"&amp;",0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,"&lt;",0,"&gt;",0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

const unsigned char * const *
html_get_armor_table(void)
{
  return armored_html_translate_table;
}

int
html_armored_memlen(char const *str, int size)
{
  unsigned char const *p = (unsigned char const*) str;

  int i = size;
  int l = 0;

  for (; i > 0; p++, i--) {
    l += armored_html_len_table[*p];
  }
  return l;
}

int
html_armored_strlen(char const *str)
{
  return html_armored_memlen(str, strlen(str)) + 1;
}

int
html_armor_needed(const unsigned char *str, size_t *psz)
{
  const unsigned char *p = str;
  size_t s_sz = 0, d_sz = 0;

  if (!str) return 0;
  while (*p) {
    s_sz++;
    d_sz += armored_html_len_table[*p];
    p++;
  }
  if (s_sz == d_sz) return 0;
  *psz = d_sz;
  return 1;
}

int
html_armor_text(char const *str, int size, char *out)
{
  unsigned char const *p = (unsigned char const *) str;
  char *s = out;
  unsigned char const *t;
  int i = size;

  for (; i > 0; p++, i--) {
    if (!(t = armored_html_translate_table[*p])) {
      *s++ = *p;
    } else {
      while ((*s++ = *t++));
      s--;
    }
  }
  *s = 0;
  return s - out;
}

int
html_armor_string(char const *str, char *out)
{
  return html_armor_text(str, strlen(str), out);
}

unsigned char *
html_armor_string_dup(const unsigned char *str)
{
  int inlen;
  int outlen;
  unsigned char *buf;

  if (!str) str = "";
  inlen = strlen(str);
  outlen = html_armored_memlen(str, inlen);
  buf = (unsigned char*) xmalloc(outlen + 1);
  html_armor_text(str, inlen, buf);
  return buf;
}

char *
duration_str(int show_astr, time_t cur, time_t start, char *buf, int len)
{
  int         hh, mm, ss;
  static char b[64];

  if (show_astr) {
    struct tm *tt = localtime(&cur);

    sprintf(b, "%04d/%02d/%02d %02d:%02d:%02d ",
            tt->tm_year + 1900, tt->tm_mon + 1, tt->tm_mday,
            tt->tm_hour, tt->tm_min, tt->tm_sec);
  } else {
    time_t time = cur - start;

    ss = time % 60;
    time /= 60;
    mm = time % 60;
    time /= 60;
    hh = time;
    sprintf(b, "%d:%02d:%02d", hh, mm, ss);
  }
  if (!buf) return b;
  if (len <= 0) return strcpy(buf, b);
  strncpy(buf, b, len);
  buf[len - 1] = 0;
  return buf;
}

char *
duration_min_str(time_t time, char *buf, int len)
{
  int         hh, mm;
  static char b[64];

  mm = time % 60;
  time /= 60;
  hh = time;
  sprintf(b, "%d:%02d", hh, mm);
  if (!buf) return b;
  if (len <= 0) return strcpy(buf, b);
  strncpy(buf, b, len);
  buf[len - 1] = 0;
  return buf;
}

int
message_quoted_size(char const *intxt)
{
  char const *s = intxt;
  int         lines = 0;

  if (!strncasecmp("subject:", intxt, 8)) {
    s = strchr(s, '\n');
    if (!s) return 0;
    if (s[1] == '\n') s++;
    s++;
  }

  while (1) {
    lines++;
    s = strchr(s, '\n');
    if (!s) break;
    s++;
  }

  return strlen(intxt) + lines * 2 + 1;
}

int
message_quote(char const *inbuf, char *outbuf)
{
  char const *s = inbuf;
  char *p = outbuf;

  p[0] = 0;
  if (!strncasecmp("subject:", inbuf, 8)) {
    s = strchr(s, '\n');
    if (!s) return 0;
    s++;
    if (*s == '\n') s++;
  }

  while (1) {
    if (!*s) break;
    *p++ = '>';
    *p++ = ' ';
    while (*s && *s != '\n') *p++ = *s++;
    if (!*s) break;
    *p++ = *s++;
  }
  *p = 0;
  return p - inbuf;
}

int
message_reply_subj(char const *intxt, char *outtxt)
{
  char const *p, *q;
  char *s;

  if (strncasecmp(intxt, "subject:", 8)) {
    sprintf(outtxt, "Subject: %s\n\n", _("Re: Your question"));
    return strlen(outtxt);
  }
  p = intxt + 8;
  while (*p == ' ' || *p == '\t') p++;
  q = p;
  while (*q != '\n' && *q != 0) q++;
  if (p == q) {
    sprintf(outtxt, "Subject: %s\n\n", _("Re: Your question"));
    return strlen(outtxt);    
  }
  s = outtxt + sprintf(outtxt, "Subject: %s: ", _("Re"));
  while (p <= q) {
    *s++ = *p;
    p++;
  }
  *s++ = '\n';
  *s = 0;
  return strlen(outtxt);
}

int
message_base64_subj(char const *msg, char *out, int maxlen)
{
  char const *s;
  char       *p;
  int         l;
  char       *buf;

  buf = alloca(maxlen + 4);
  ASSERT(buf);

  if (!strncasecmp(msg, "subject:", 8)) {
    s = msg + 8;
    while (1) {
      while (*s == ' ' || *s == '\t') s++;
      if (strncasecmp(s, "re:", 3)) break;
      s += 3;
    }
    if (*s == '\n' || *s == '\r' || !*s) s = _("(no subject)");
  } else {
    s = _("(no subject)");
  }

  for (p = buf, l = maxlen;
       *s && *s != '\n' && *s != '\r' && l;
       s++, p++, l--) {
    *p = *s;
  }
  if (*s && *s != '\n' && *s != '\r') {
    *p = 0;
    *--p = '.';
    *--p = '.';
    *--p = '.';
  } else {
    *p = 0;
  }
  base64_encode_str(buf, out);
  return strlen(out);
}

size_t
url_armor_string(unsigned char *buf, size_t size, const unsigned char *str)
{
  size_t lsz, outsz = 0;
  unsigned char b4[4];

  if (!str) str = "";

  if (!buf || !size) {
    while (*str) {
      if (isalnum(*str)) size++;
      else size += 3;
      str++;
    }
    return size;
  }

  lsz = size - 1;
  while (*str && lsz) {
    if (isalnum(*str)) {
      *buf++ = *str;
      lsz--; outsz++;
    } else {
      sprintf(b4, "%02x", *str);
      *buf++ = '%', lsz--;
      if (lsz) {
        *buf++ = b4[0], lsz--;
        if (lsz) {
          *buf++ = b4[1], lsz--;
        }
      }
      outsz += 3;
    }
    str++;
  }
  *buf = 0;
  while (*str) {
    if (isalnum(*str)) outsz++;
    else outsz += 3;
    str++;
  }
  return outsz;
}

size_t
text_numbered_memlen(const unsigned char *intxt, size_t insize)
{
  size_t i, nlines = 0;

  if (!intxt || !insize) return 0;

  for (i = 0; i < insize; i++) {
    if (intxt[i] == '\n') nlines++;
  }
  if (intxt[insize - 1] != '\n') nlines++;
  return insize + 8 * nlines;
}

void
text_number_lines(const unsigned char *intxt, size_t insize,
                  unsigned char *outtxt)
{
  unsigned char lbuf1[16];
  size_t i, j = 1;
  unsigned char *s = outtxt;

  snprintf(lbuf1, sizeof(lbuf1), "[%zu]", j++);
  s += sprintf(s, "%-8s", lbuf1);
  for (i = 0; i < insize; i++) {
    *s++ = intxt[i];
    if (intxt[i] == '\n' && i + 1 != insize) {
      snprintf(lbuf1, sizeof(lbuf1), "[%zu]", j++);
      s += sprintf(s, "%-8s", lbuf1);
    }
  }
  *s = 0;
}

static const char content_text_html[] = "content-type: text/html\n\n";
static const char content_text_xml[] = "content-type: text/xml\n\n";

int
get_content_type(const unsigned char *txt, const unsigned char **p_start_ptr)
{
  if (!strncasecmp(txt, content_text_xml, sizeof(content_text_xml)-1)) {
    if (p_start_ptr) *p_start_ptr = txt + sizeof(content_text_xml) - 1;
    return CONTENT_TYPE_XML;
  }
  if (!strncasecmp(txt, content_text_html, sizeof(content_text_xml)-1)) {
    if (p_start_ptr) *p_start_ptr = txt + sizeof(content_text_xml) - 1;
    return CONTENT_TYPE_HTML;
  }
  if (p_start_ptr) *p_start_ptr = txt;
  return CONTENT_TYPE_TEXT;
}

unsigned char *
unparse_sha1(const void *shabuf)
{
  const unsigned char *s = (const unsigned char *) shabuf;
  int i;
  static unsigned char buf[64];
  unsigned char *p;
  static const unsigned char hexd[] = "0123456789abcdef";

  for (i = 0, p = buf; i < 20; i++, s++) {
    *p++ = hexd[(*s >> 4) & 0xf];
    *p++ = hexd[*s & 0xf];
  }
  *p = 0;

  return buf;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

