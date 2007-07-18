/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2000-2007 Alexander Chernov <cher@ejudge.ru> */

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
  8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 1, 8, 8, 1, 8, 8, 
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 
  1, 1, 6, 1, 5, 1, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 1, 4, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 8, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

/*
static unsigned char const * const armored_html_translate_table[256] =
{
  "&#0;","&#1;","&#2;","&#3;","&#4;","&#5;","&#6;","&#7;","&#8;",0,0,"&#11;","&#12;",0,"&#14;","&#15;",
  "&#16;","&#17;","&#18;","&#19;","&#20;","&#21;","&#22;","&#23;","&#24;","&#25;","&#26;","&#27;","&#28;","&#29;","&#30;","&#31;",
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
*/

static unsigned char const * const armored_html_translate_table[256] =
{
  "&#x2400;","&#x2401;","&#x2402;","&#x2403;","&#x2404;","&#x2405;","&#x2406;","&#x2407;","&#x2408;",0,0,"&#x240B;","&#x240C;",0,"&#x240E;","&#x240F;",
  "&#x2410;","&#x2411;","&#x2412;","&#x2413;","&#x2414;","&#x2415;","&#x2416;","&#x2417;","&#x2418;","&#x2419;","&#x241A;","&#x241B;","&#x241C;","&#x241D;","&#x241E;","&#x241F;",
  0,0,"&quot;",0,"&#36;",0,"&amp;",0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,"&lt;",0,"&gt;",0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"&#x2421;",
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
html_armor_needed_bin(const unsigned char *str, size_t sz, size_t *psz)
{
  const unsigned char *p = str;
  size_t s_sz = sz, d_sz = 0;

  if (!str || !sz) return 0;

  while (s_sz) {
    d_sz += armored_html_len_table[*p];
    p++; s_sz--;
  }
  if (d_sz == sz && !*p) return 0;
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

static void
url_armor_string_unchecked(const unsigned char *s, unsigned char *buf)
{
  unsigned char *b = buf;
  const unsigned char *p = s;

  *b = 0;
  if (!s) return;

  for (; *p; p++) {
    if (isalnum(*p)) *b++ = *p;
    else b += sprintf(b, "%%%02x", *p);
  }
  *b = 0;
}

int
url_armor_needed(const unsigned char *s, size_t *psize)
{
  size_t sz = 0;
  int needed = 0;
  const unsigned char *p = s;

  if (!s) return 0;
  for (; *p; p++) {
    if (isalnum(*p)) sz++;
    else {
      needed = 1;
      sz += 3;
    }
  }
  if (psize) *psize = sz;
  return needed;
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

void
html_armor_init(struct html_armor_buffer *pb)
{
  if (!pb) return;
  memset(pb, 0, sizeof(*pb));
}

void
html_armor_extend(struct html_armor_buffer *pb, size_t newsz)
{
  if (newsz < pb->size) return;
  xfree(pb->buf);
  if (!pb->size) pb->size = 64;
  while (newsz >= pb->size) pb->size *= 2;
  pb->buf = (unsigned char*) xmalloc(pb->size);
}

const unsigned char *
html_armor_buf(struct html_armor_buffer *pb, const unsigned char *s)
{
  size_t newsz = 0;

  if (!html_armor_needed(s, &newsz)) return s;
  if (newsz >= pb->size) {
    xfree(pb->buf);
    if (!pb->size) pb->size = 64;
    while (newsz >= pb->size) pb->size *= 2;
    pb->buf = (unsigned char*) xmalloc(pb->size);
  }
  html_armor_string(s, pb->buf);
  return pb->buf;
}

const unsigned char *
html_armor_buf_bin(struct html_armor_buffer *pb,
                   const unsigned char *s, size_t sz)
{
  size_t newsz = 0;

  if (!html_armor_needed_bin(s, sz, &newsz)) return s;
  if (newsz >= pb->size) {
    xfree(pb->buf);
    if (!pb->size) pb->size = 64;
    while (newsz >= pb->size) pb->size *= 2;
    pb->buf = (unsigned char*) xmalloc(pb->size);
  }
  html_armor_text(s, sz, pb->buf);
  return pb->buf;
}

const unsigned char *
url_armor_buf(struct html_armor_buffer *pb, const unsigned char *s)
{
  size_t newsz = 0;

  if (!url_armor_needed(s, &newsz)) return s;
  if (newsz >= pb->size) {
    xfree(pb->buf);
    if (!pb->size) pb->size = 64;
    while (newsz >= pb->size) pb->size *= 2;
    pb->buf = (unsigned char*) xmalloc(pb->size);
  }
  url_armor_string_unchecked(s, pb->buf);
  return pb->buf;
}

void
html_armor_free(struct html_armor_buffer *pb)
{
  if (!pb) return;
  xfree(pb->buf);
  memset(pb, 0, sizeof(*pb));
}

int
check_str(const unsigned char *str, const unsigned char *map)
{
  if (!str) return 0;
  for (; *str; str++)
    if (!map[*str])
      return -1;
  return 0;
}

int
check_str_2(const unsigned char *str, const unsigned char *map,
            unsigned char *invchars)
{
  unsigned char invset[256];
  unsigned char *p = invchars;
  int retval = 0, i;

  if (p) *p = 0;
  if (!str) return 0;
  memset(invset, 0, sizeof(invset));

  for (; *str; str++)
    if (!map[*str]) {
      invset[*str] = 1;
      retval = -1;
    }

  if (retval >= 0 || !p) return retval;

  for (i = 0; i < 256; i++)
    if (invset[i])
      *p++ = i;
  *p = 0;

  return retval;
}

unsigned char *
text_input_process_string(const unsigned char *s, int sep, int sep_repl)
{
  int len;
  unsigned char *out = 0, *p, *q;

  if (!s) return xstrdup("");
  out = xstrdup(s);

  // replace suspicious control characters with space
  for (p = out; *p; p++) {
    if (*p < ' ') *p = ' ';
    else if (*p == sep) *p = sep_repl;
    else if (*p == 127) *p = ' ';
  }

  // remove heading spaces
  for (p = out; *p && isspace(*p); p++);
  if (p != out) {
    for (q = out; *p; *q++ = *p++);
    *q = 0;
  }

  // remove trailing spaces
  len = strlen(out);
  while (len > 0 && isspace(out[len - 1])) len--;
  out[len] = 0;

  return out;
}

unsigned char *
text_area_process_string(const unsigned char *s, int sep, int sep_repl)
{
  unsigned char *p, *q, *out;

  if (!s && !*s) return xstrdup("");
  out = (unsigned char *) xmalloc(strlen(s) + 2);
  strcpy(out, s);

  // replace suspicious control characters with space
  for (p = out; *p; p++) {
    if (*p < ' ' && *p != '\n') *p = ' ';
    else if (*p == sep) *p = sep_repl;
    else if (*p == 127) *p = ' ';
  }
  while (p > out && p[-1] == ' ') p--;
  *p = 0;
  if (p == out) return out;
  if (p > out && p[-1] != '\n') {
    *p++ = '\n';
    *p = 0;
  }

  // remove whitespace preceding '\n'
  for (p = q = out; *p; p++) {
    while (*p == '\n' && q > out && q[-1] == ' ') q--;
    *q++ = *p;
  }
  *q = 0;

  // remove trailing empty lines
  while (q > out && q[-1] == '\n') q--;
  if (q > out) *q++ = '\n';
  *q = 0;

  return out;
}

const unsigned char * const filename_armor_table[256] =
{
  "_", "_", "_", "_", "_", "_", "_", "_",
  "_", "_", "_", "_", "_", "_", "_", "_", 
  "_", "_", "_", "_", "_", "_", "_", "_",
  "_", "_", "_", "_", "_", "_", "_", "_", 
  "_", "_", "_", "_", "_", "_", "_", "_",
  "(", ")", "*", "+", ",", "-", ".", "_",
  "0", "1", "2", "3", "4", "5", "6", "7",
  "8", "9", ":", ";", "<", "=", ">", "?",
  "@", "A", "B", "C", "D", "E", "F", "G",
  "H", "I", "J", "K", "L", "M", "N", "O",
  "P", "Q", "R", "S", "T", "U", "V", "W",
  "X", "Y", "Z", "[", "_", "]", "^", "_",
  "_", "a", "b", "c", "d", "e", "f", "g",
  "h", "i", "j", "k", "l", "m", "n", "o",
  "p", "q", "r", "s", "t", "u", "v", "w",
  "x", "y", "z", "{", "|", "}", "~", "_",
  "_", "_", "_", "_", "_", "_", "_", "_",
  "_", "_", "_", "_", "_", "_", "_", "_",
  "_", "_", "_", "_", "_", "_", "_", "_",
  "_", "_", "_", "_", "_", "_", "_", "_",
  "_", "_", "_", "_", "_", "_", "_", "_",
  "_", "_", "_", "_", "_", "_", "_", "_",
  "_", "_", "_", "_", "_", "_", "_", "_",
  "_", "_", "_", "_", "_", "_", "_", "_",
  "yu", "a", "b", "ts", "d", "e", "f", "g",
  "h", "i", "y", "k", "l", "m", "n", "o",
  "p", "ya", "r", "s", "t", "u", "zh", "v",
  "_", "y", "z", "sh", "e", "chsh", "ch", "_",
  "Yu", "A", "B", "Ts", "D", "E", "F", "G",
  "H", "I", "Y", "K", "L", "M", "N", "O",
  "P", "Ya", "R", "S", "T", "U", "Zh", "V",
  "_", "Y", "Z", "Sh", "E", "Chsh", "Ch", "_", 
};

const unsigned char filename_armor_table_len[256] =
{
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
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  2, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 2, 1, 4, 2, 1,
  2, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 2, 1, 4, 2, 1,
};

unsigned char *
filename_armor_bytes(
	unsigned char *out,
        size_t outsize,
        const unsigned char *in,
        size_t insize)
{
  const unsigned char *pin = in;
  unsigned char *pout = out;
  int z;

  while (insize) {
    if ((z = filename_armor_table_len[*pin]) >= outsize) break;
    strcpy(pout, filename_armor_table[*pin]);
    pout += z; outsize -= z;
    insize--; pin++;
  }
  if (outsize) *pout = 0;
  return out;
}

int
utf8_fix_string(unsigned char *str, int *gl_ind)
{
  unsigned char *s = str;
  int w, i = 0, j = 0;

  // i is byte index
  // j is glyph index
  if (gl_ind) gl_ind[0] = 0;
  if (!s) return 0;
  while (*s) {
    if (*s <= 0x7f) {
      s++;
      if (gl_ind) gl_ind[j++] = i++;
    } else if (*s <= 0xbf) {
      // middle of multibyte sequence
      *s++ = '?';
      if (gl_ind) gl_ind[j++] = i++;
    } else if (*s <= 0xc1) {
      // reserved
      *s++ = '?';
      if (gl_ind) gl_ind[j++] = i++;
    } else if (*s <= 0xdf) {
      // two bytes: 0x80-0x7ff
      if (s[1] >= 0x80 && s[1] <= 0xbf) {
        w = ((s[0] & 0x1f) << 6) | (s[1] & 0x3f);
        if (w < 0x80) {
          *s++ = '?';
          *s++ = '?';
          if (gl_ind) {
            gl_ind[j++] = i++;
            gl_ind[j++] = i++;
          }
        } else {
          s += 2;
          if (gl_ind) {
            gl_ind[j++] = i;
            i += 2;
          }
        }
      } else {
        // second byte is invalid
        *s++ = '?';
        if (gl_ind) gl_ind[j++] = i++;
      }
    } else if (*s <= 0xef) {
      // three bytes: 0x800-0xffff
      if (s[1] >= 0x80 && s[1] <= 0xbf) {
        if (s[2] >= 0x80 && s[2] <= 0xbf) {
          w = ((s[0] & 0x0f) << 12) | ((s[1] & 0x3f) << 6) | (s[2] & 0x3f);
          if (w < 0x800) {
            *s++ = '?';
            *s++ = '?';
            *s++ = '?';
            if (gl_ind) {
              gl_ind[j++] = i++;
              gl_ind[j++] = i++;
              gl_ind[j++] = i++;
            }
          } else {
            s += 3;
            if (gl_ind) {
              gl_ind[j++] = i;
              i += 3;
            }
          }
        } else {
          // third byte is invalid
          *s++ = '?';
          *s++ = '?';
          if (gl_ind) {
            gl_ind[j++] = i++;
            gl_ind[j++] = i++;
          }
        }
      } else {
        // second byte is invalid
        *s++ = '?';
        if (gl_ind) gl_ind[j++] = i++;
      }
    } else if (*s <= 0xf7) {
      // four bytes: 0x10000-0x10ffff
      if (s[1] >= 0x80 && s[1] <= 0xbf) {
        if (s[2] >= 0x80 && s[2] <= 0xbf) {
          if (s[3] >= 0x80 && s[3] <= 0xbf) {
            w = ((s[0] & 0x07) << 18) | ((s[1] & 0x3f) << 12) | ((s[2] & 0x3f) << 6) | (s[3] & 0x3f);
            if (w < 0x10000) {
              *s++ = '?';
              *s++ = '?';
              *s++ = '?';
              *s++ = '?';
              if (gl_ind) {
                gl_ind[j++] = i++;
                gl_ind[j++] = i++;
                gl_ind[j++] = i++;
                gl_ind[j++] = i++;
              }
            } else {
              s += 4;
              if (gl_ind) {
                gl_ind[j++] = i;
                i += 4;
              }
            }
          } else {
            *s++ = '?';
            *s++ = '?';
            *s++ = '?';
            if (gl_ind) {
              gl_ind[j++] = i++;
              gl_ind[j++] = i++;
              gl_ind[j++] = i++;
            }
          }
        } else {
          *s++ = '?';
          *s++ = '?';
          if (gl_ind) {
            gl_ind[j++] = i++;
            gl_ind[j++] = i++;
          }
        }
      } else {
        *s++ = '?';
        if (gl_ind) gl_ind[j++] = i++;
      }
    } else {
      // reserved
      *s++ = '?';
      if (gl_ind) gl_ind[j++] = i++;
    }
  }
  if (gl_ind) gl_ind[j] = i;
  return j;
}

int
utf8_cnt(const unsigned char *s, int width, int *p_rem)
{
  int cnt = 0;

  if (!s) return 0;
  while (*s && width) {
    if (*s <= 0x7f) {
      s++;
      width--;
      cnt++;
    } else if (*s <= 0xbf) {
      // middle of multibyte sequence
      s++;
      width--;
      cnt++;
    } else if (*s <= 0xc1) {
      // reserved
      s++;
      width--;
      cnt++;
    } else if (*s <= 0xdf) {
      // two bytes: 0x80-0x7ff
      if (s[1] >= 0x80 && s[1] <= 0xbf) {
        s += 2;
        width--;
        cnt += 2;
      } else {
        s++;
        width--;
        cnt++;
      }
    } else if (*s <= 0xef) {
      // three bytes: 0x800-0xffff
      if (s[1] >= 0x80 && s[1] <= 0xbf && s[2] >= 0x80 && s[2] <= 0xbf) {
        s += 3;
        width--;
        cnt += 3;
      } else {
        s++;
        width--;
        cnt++;
      }
    } else if (*s <= 0xf7) {
      // four bytes: 0x10000-0x10ffff
      if (s[1] >= 0x80 && s[1] <= 0xbf && s[2] >= 0x80 && s[2] <= 0xbf
          && s[3] >= 0x80 && s[3] <= 0xbf) {
        s += 4;
        width--;
        cnt += 4;
      } else {
        s++;
        width--;
        cnt++;
      }
    } else {
      // reserved
      s++;
      width--;
      cnt++;
    }
  }
  if (p_rem) *p_rem = width;
  return cnt;
}

unsigned char *
get_nth_alternative(const unsigned char *txt, int n)
{
  const unsigned char *s, *p;
  unsigned char *txt2;
  size_t txt_len, t_len;
  int line_max_count = 0, line_count = 0, i;
  unsigned char **lines = 0;
  unsigned char *t;

  if (!txt) return 0;

  // normalize the file
  txt_len = strlen(txt);
  txt2 = (unsigned char*) alloca(txt_len + 2);
  memcpy(txt2, txt, txt_len + 1);
  while (txt_len > 0 && isspace(txt2[txt_len - 1])) txt_len--;
  if (!txt_len) return 0;
  txt2[txt_len++] = '\n';
  txt2[txt_len] = 0;

  // count number of lines
  for (s = txt2; *s; s++)
    if (*s == '\n') line_max_count++;

  lines = (unsigned char**) alloca((line_max_count + 1) * sizeof(lines[0]));
  memset(lines, 0, (line_max_count + 1) * sizeof(lines[0]));

  s = txt2;
  while (*s) {
    while (*s != '\n' && isspace(*s)) s++;
    if (*s == '#') while (*s != '\n') s++;
    if (*s == '\n') {
      s++;
      continue;
    }
    p = s;
    while (*s != '\n') s++;
    t_len = s - p;
    t = (unsigned char*) alloca(t_len + 1);
    memcpy(t, p, t_len);
    while (t_len > 0 && isspace(t[t_len - 1])) t_len--;
    t[t_len] = 0;
    lines[line_count++] = t;
  }

  for (i = 0; i + 1 != n && i < line_count; i++);
  if (i + 1 == n && i < line_count) return xstrdup(lines[i]);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

