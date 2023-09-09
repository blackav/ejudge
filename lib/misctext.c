/* -*- mode: c -*- */

/* Copyright (C) 2000-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/misctext.h"
#include "ejudge/base64.h"
#include "ejudge/compat.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "ejudge/win32_compat.h"

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

void
html_armor_to_file_nbsp(FILE *out, char const *str, int size)
{
  unsigned char const *p = (unsigned char const *) str;
  unsigned char const *t;
  int i = size;
  int column = 0;

  for (; i > 0; p++, i--) {
    if (*p == '\r' || *p == '\n') {
      putc_unlocked(*p, out);
      column = 0;
    } else if (*p == '\t') {
      int spacing = ((column + 8) & ~7) - column;
      column = ((column + 8) & ~7);
      for (; spacing; --spacing) {
        fputs("&nbsp;", out);
      }
    } else if (*p <= ' ') {
      fputs("&nbsp;", out);
      ++column;
    } else if (!(t = armored_html_translate_table[*p])) {
      putc(*p, out);
      ++column;
    } else {
      fputs(t, out);
      ++column;
    }
  }
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

    sprintf(b, "%04d-%02d-%02d %02d:%02d:%02d",
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

enum
{
  SECS_PER_MONTH = 30 * 24 * 60 * 60,
  SECS_PER_WEEK = 7 * 24 * 60 * 60,
  SECS_PER_DAY = 24 * 60 * 60,
  SECS_PER_HOUR = 60 * 60,
  SECS_PER_MIN = 60,
};

char *
duration_str_2(unsigned char *buf, int len, time_t dur, int nsec)
{
  if (dur >= SECS_PER_MONTH) {
    int months = (int)(dur / SECS_PER_MONTH);
    dur %= SECS_PER_MONTH;
    int days = (int)(dur / SECS_PER_DAY);
    dur %= SECS_PER_DAY;
    int hours = (int)(dur / SECS_PER_HOUR);
    dur %= SECS_PER_HOUR;
    int mins = (int)(dur / SECS_PER_MIN);
    dur %= SECS_PER_MIN;
    int secs = (int)(dur);
    snprintf(buf, len, "%d month(s) %d day(s) %d:%02d:%02d.%06d", months, days, hours, mins, secs, nsec / 1000);
  } else if (dur >= SECS_PER_WEEK) {
    int weeks = (int)(dur / SECS_PER_WEEK);
    dur %= SECS_PER_WEEK;
    int days = (int)(dur / SECS_PER_DAY);
    dur %= SECS_PER_DAY;
    int hours = (int)(dur / SECS_PER_HOUR);
    dur %= SECS_PER_HOUR;
    int mins = (int)(dur / SECS_PER_MIN);
    dur %= SECS_PER_MIN;
    int secs = (int)(dur);
    snprintf(buf, len, "%d week(s) %d day(s) %d:%02d:%02d.%06d", weeks, days, hours, mins, secs, nsec / 1000);
  } else if (dur >= SECS_PER_DAY) {
    int days = (int)(dur / SECS_PER_DAY);
    dur %= SECS_PER_DAY;
    int hours = (int)(dur / SECS_PER_HOUR);
    dur %= SECS_PER_HOUR;
    int mins = (int)(dur / SECS_PER_MIN);
    dur %= SECS_PER_MIN;
    int secs = (int)(dur);
    snprintf(buf, len, "%d day(s) %d:%02d:%02d.%06d", days, hours, mins, secs, nsec / 1000);
  } else {
    int hours = (int)(dur / SECS_PER_HOUR);
    dur %= SECS_PER_HOUR;
    int mins = (int)(dur / SECS_PER_MIN);
    dur %= SECS_PER_MIN;
    int secs = (int)(dur);
    snprintf(buf, len, "%d:%02d:%02d.%06d", hours, mins, secs, nsec / 1000);
  }
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

const unsigned char *
skip_message_headers(const unsigned char *intxt)
{
  if (!intxt) return intxt;
  const char *p = strstr(intxt, "\n\n");
  if (p) return p + 2;
  p = strstr(intxt, "\r\n\r\n");
  if (p) return p + 4;
  return intxt;
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

  snprintf(lbuf1, sizeof(lbuf1), "[%" EJ_PRINTF_ZSPEC "u]", EJ_PRINTF_ZCAST(j++));
  s += sprintf(s, "%-8s", lbuf1);
  for (i = 0; i < insize; i++) {
    *s++ = intxt[i];
    if (intxt[i] == '\n' && i + 1 != insize) {
      snprintf(lbuf1, sizeof(lbuf1), "[%" EJ_PRINTF_ZSPEC "u]", EJ_PRINTF_ZCAST(j++));
      s += sprintf(s, "%-8s", lbuf1);
    }
  }
  *s = 0;
}

void
text_table_number_lines(
        FILE *out_f,
        const unsigned char *intxt,
        size_t insize,
        const unsigned char *tr_attr,
        const unsigned char *td_attr)
{
  int beg = 0, cur, end;
  int line = 1, lines;

  if (!tr_attr) tr_attr = "";
  if (!td_attr) td_attr = "";

  for (cur = 0, lines = 0; cur < insize; ++cur)
    if (intxt[cur] == '\n') ++lines;
  if (insize > 0 && intxt[insize - 1] != '\n') ++lines;

  fprintf(out_f, "<tr%s><td valign=\"top\"%s>", tr_attr, td_attr);
  for (line = 0; line < lines; ++line)
    fprintf(out_f,"<span onclick=\"markLine(%d)\"><tt>[%d]</tt></span><br/>\n",
            line + 1, line + 1);
  fprintf(out_f, "</td><td valign=\"top\"%s>", td_attr);

  for (cur = 0; cur < insize; ++cur) {
    if (intxt[cur] != '\n') continue;

    end = cur - 1;
    while (end >= beg && isspace(intxt[end])) --end;
    ++end;
    // [beg, end)
    fprintf(out_f, "<span><tt>");
    html_armor_to_file_nbsp(out_f, intxt + beg, end - beg);
    fprintf(out_f, "</tt></span><br/>\n");

    beg = cur + 1;
  }
  if (beg != cur) {
    end = cur - 1;
    while (end >= beg && isspace(intxt[end])) --end;
    ++end;

    // [beg, end)
    fprintf(out_f, "<span><tt>");
    html_armor_to_file_nbsp(out_f, intxt + beg, end - beg);
    fprintf(out_f, "</tt></span></br>\n");
  }
  fprintf(out_f, "</td></tr>");
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

unsigned char *
unparse_sha256(const void *shabuf)
{
  const unsigned char *s = (const unsigned char *) shabuf;
  int i;
  static unsigned char buf[80];
  unsigned char *p;
  static const unsigned char hexd[] = "0123456789abcdef";

  for (i = 0, p = buf; i < 32; i++, s++) {
    *p++ = hexd[(*s >> 4) & 0xf];
    *p++ = hexd[*s & 0xf];
  }
  *p = 0;

  return buf;
}

unsigned char *
unparse_abbrev_sha1(const void *shabuf)
{
  const unsigned char *s = (const unsigned char *) shabuf;
  int i;
  static unsigned char buf[64];
  unsigned char *p;
  static const unsigned char hexd[] = "0123456789abcdef";

  for (i = 0, p = buf; i < 4; i++, s++) {
    *p++ = hexd[(*s >> 4) & 0xf];
    *p++ = hexd[*s & 0xf];
  }
  *p++ = '.';
  *p++ = '.';
  *p++ = '.';
  *p = 0;

  return buf;
}

int
parse_sha1(void *shabuf, const unsigned char *str)
{
  unsigned char *out = (unsigned char *) shabuf;
  const unsigned char *p = str;

  if (!str || !*str) return 0;
  while (isspace(*p)) ++p;
  if (!*p) return 0;

  for (int i = 0; i < 20; ++i) {
    int c = *p++;
    if (!c) return -1;
    int val = 0;
    if (c >= '0' && c <= '9') {
      val |= (c - '0') << 4;
    } else if (c >= 'a' && c <= 'f') {
      val |= (c - 'a' + 10) << 4;
    } else if (c >= 'A' && c <= 'F') {
      val |= (c - 'A' + 10) << 4;
    } else {
      return -1;
    }
    c = *p++;
    if (!c) return -1;
    if (c >= '0' && c <= '9') {
      val |= c - '0';
    } else if (c >= 'a' && c <= 'f') {
      val |= c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
      val |= c - 'A' + 10;
    } else {
      return -1;
    }
    *out++ = val;
  }
  while (isspace(*p)) ++p;
  if (*p) return -1;
  return 1;
}

void
html_armor_init(struct html_armor_buffer *pb)
{
  if (!pb) return;
  memset(pb, 0, sizeof(*pb));
}

void
html_armor_reserve(struct html_armor_buffer *pb, size_t newsz)
{
  if (newsz < pb->size) return;
  xfree(pb->buf);
  if (!pb->size) pb->size = 64;
  while (newsz >= pb->size) pb->size *= 2;
  pb->buf = (unsigned char*) xmalloc(pb->size);
}

void
html_armor_extend(struct html_armor_buffer *pb, size_t newsz)
{
  size_t newalloc = pb->size;
  unsigned char *newbuf = 0;

  if (newsz < newalloc) return;
  if (!newalloc) newalloc = 64;
  while (newsz >= newalloc) newalloc *= 2;
  newbuf = (unsigned char *) xmalloc(newalloc);
  if (pb->size > 0) {
    memcpy(newbuf, pb->buf, pb->size);
  }
  xfree(pb->buf);
  pb->buf = newbuf;
  pb->size = newalloc;
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
check_str_2(
        const unsigned char *str,
        const unsigned char *map, /*if char 255 is valid,any char >= 128 valid*/
        unsigned char *invchars,
        size_t invsize,
        int utf8_flag)
{
  unsigned char *invset;
  unsigned char *p = invchars;
  int retval = 0, i, slen, *wstr, maxinv = -1, invc, *ibuf, j;

  if (!str) return 0;
  if (p) *p = 0;

  if (!utf8_flag) {
    invset = (unsigned char*) alloca(256);
    memset(invset, 0, 256);

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
  } else {
    // unicode version
    invset = (unsigned char*) alloca(65536);
    memset(invset, 0, 65536);
    slen = strlen(str);
    wstr = (int*) alloca((slen + 1) * sizeof(wstr[0]));
    utf8_to_ucs4_str(wstr, str);
    for (; *wstr; wstr++) {
      invc = -1;
      if (*wstr < 0) {
        invc = '?';
      } else if (*wstr >= 128) {
        if (!map[255]) {
          if (*wstr >= 65536) invc = '?';
          else invc = *wstr;
        }
      } else if (!map[*wstr]) {
        if (*wstr < 32) invc = '?';
        else invc = *wstr;
      }
      if (invc > 0) {
        invset[invc] = 1;
        retval = -1;
        if (invc > maxinv) maxinv = invc;
      }
    }

    if (retval >= 0 || !p) return retval;

    ASSERT(maxinv >= ' ');
    ibuf = (int*) alloca((maxinv + 1) * sizeof(ibuf[0]));
    for (i = 0, j = 0; i <= maxinv; i++)
      if (invset[i])
        ibuf[j++] = i;
    ibuf[j++] = 0;
    ucs4_to_utf8_str(invchars, invsize, ibuf);
  }

  return retval;
}

static const unsigned char login_valid_chars[257] =
"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\1\1\1\0\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1";

int
is_valid_login(const unsigned char *str)
{
  // disallow empty login
  if (!str || !*str) return 0;
  // disallow login starting with ' '
  if (*str == ' ') return 0;
  // check valid chars
  for (; *str; ++str) {
    if (!login_valid_chars[*str])
      return 0;
  }
  // disallow login ending with ' '
  if (str[-1] == ' ') return 0;
  return 1;
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
            if (w == 0xffff || w == 0xfffe) {
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

ssize_t
utf8_trim_last_codepoint(
        const unsigned char *str,
        ssize_t size)
{
  if (size <= 0) return 0;
  ssize_t i = size - 1;
  if (str[i] < 0x80) {
    return i + 1;
  }
  if (str[i] >= 0xc0) {
    return i;
  }
  if (--i < 0) return 0;
  if (str[i] < 0x80) {
    return i + 1;
  }
  if (str[i] >= 0xc2 && str[i] <= 0xdf) {
    return i + 2;
  }
  if (str[i] >= 0xc0) {
    return i;
  }
  if (--i < 0) return 0;
  if (str[i] < 0x80) {
    return i + 1;
  }
  if (str[i] >= 0xc2 && str[i] <= 0xdf) {
    return i + 2;
  }
  if (str[i] >= 0xe0 && str[i] <= 0xef) {
    return i + 3;
  }
  if (str[i] >= 0xc0) {
    return i;
  }
  if (--i < 0) return 0;
  if (str[i] < 0x80) {
    return i + 1;
  }
  if (str[i] >= 0xc2 && str[i] <= 0xdf) {
    return i + 2;
  }
  if (str[i] >= 0xe0 && str[i] <= 0xef) {
    return i + 3;
  }
  if (str[i] >= 0xf0 && str[i] <= 0xf7) {
    return i + 4;
  }
  return i;
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

int
utf8_to_ucs4_buf(int *out, const unsigned char *in, size_t in_size)
{
  const unsigned char *p = in;
  int *q = out;
  int w;

  while (in_size) {
    if (*p < 0x80) {
      *q++ = *p++;
      in_size--;
    } else if ((*p & 0xc0) == 0x80) {
      goto broken_coding;
    } else if ((*p & 0xe0) == 0xc0) {
      if (in_size < 2) goto broken_coding;
      if ((p[1] & 0xc0) != 0x80) goto broken_coding;
      w = (*p++ & 0x1f) << 6;
      w |= (*p++ & 0x3f);
      if (w < 0x80) goto broken_coding;
      *q++ = w;
      in_size -= 2;
    } else if ((*p & 0xf0) == 0xe0) {
      // three-byte character
      if (in_size < 3) goto broken_coding;
      if ((p[1] & 0xc0) != 0x80) goto broken_coding;
      if ((p[2] & 0xc0) != 0x80) goto broken_coding;
      w = (*p++ & 0x0f) << 12;
      w |= (*p++ & 0x3f) << 6;
      w |= (*p++ & 0x3f);
      if (w < 0x800) goto broken_coding;
      *q++ = w;
      in_size -= 3;
    } else if ((*p & 0xf8) == 0xf0) {
      // four-byte character
      if (in_size < 4) goto broken_coding;
      if ((p[1] & 0xc0) != 0x80) goto broken_coding;
      if ((p[2] & 0xc0) != 0x80) goto broken_coding;
      if ((p[3] & 0xc0) != 0x80) goto broken_coding;
      w = (*p++ & 0x07) << 18;
      w |= (*p++ & 0x3f) << 12;
      w |= (*p++ & 0x3f) << 6;
      w |= (*p++ & 0x3f);
      if (w < 0x10000) goto broken_coding;
      *q++ = w;
      in_size -= 4;
    } else {
      goto broken_coding;
    }

    continue;

  broken_coding:
    *q++ = '?';
    p++;
    in_size--;
  }

  return q - out;
}

int
utf8_to_ucs4_str(int *out, const unsigned char *in)
{
  size_t in_size = strlen(in);
  int out_size = utf8_to_ucs4_buf(out, in, in_size);
  if (out_size >= 0) out[out_size] = 0;
  return out_size;
}

size_t
ucs4_to_utf8_size(const int *in)
{
  size_t out_size = 1;
  while (*in) {
    if (*in <= 0x7f) {
      out_size++;
    } else if (*in <= 0x7ff) {
      out_size += 2;
    } else if (*in <= 0xffff) {
      out_size += 3;
    } else {
      out_size += 4;
    }
    ++in;
  }

  return out_size;
}

unsigned char *
ucs4_to_utf8_char(unsigned char *buf, int value)
{
  unsigned char *pout = buf;
  if (value < 0 || value >= 0x10000) {
    *pout++ = '?';
  } else if (value <= 0x7f) {
    *pout++ = value;
  } else if (value <= 0x7ff) {
    *pout++ = (value >> 6) | 0xc0;
    *pout++ = (value & 0x3f) | 0x80;
  } else if (value <= 0xffff) {
    *pout++ = (value >> 12) | 0xe0;
    *pout++ = ((value >> 6) & 0x3f) | 0x80;
    *pout++ = (value & 0x3f) | 0x80;
  } else {
    *pout++ = ((value >> 18) & 0x07) | 0xf0;
    *pout++ = ((value >> 12) & 0x3f) | 0x80;
    *pout++ = ((value >> 6) & 0x3f) | 0x80;
    *pout++ = (value & 0x3f) | 0x80;
  }
  return pout;
}

const unsigned char *
ucs4_to_utf8_str(unsigned char *buf, size_t size, const int *in)
{
  const int *pin = in;
  unsigned char *pout = buf;

  if (!buf || !size) return "";
  size--;
  while (*pin && size) {
    if (*pin <= 0x7f) {
      *pout++ = *pin;
      size--;
    } else if (*pin <= 0x7ff) {
      if (size < 2) break;
      *pout++ = (*pin >> 6) | 0xc0;
      *pout++ = (*pin & 0x3f) | 0x80;
      size -= 2;
    } else if (*pin <= 0xffff) {
      if (size < 3) break;
      *pout++ = (*pin >> 12) | 0xe0;
      *pout++ = ((*pin >> 6) & 0x3f) | 0x80;
      *pout++ = (*pin & 0x3f) | 0x80;
      size -= 3;
    } else {
      if (size < 4) break;
      *pout++ = ((*pin >> 18) & 0x07) | 0xf0;
      *pout++ = ((*pin >> 12) & 0x3f) | 0x80;
      *pout++ = ((*pin >> 6) & 0x3f) | 0x80;
      *pout++ = (*pin & 0x3f) | 0x80;
      size -= 4;
    }
    pin++;
  }
  *pout = 0;
  return buf;
}

unsigned char *
chop2(unsigned char *str)
{
  if (!str) return 0;
  int len = strlen(str);
  while (len > 0 && isspace(str[len - 1])) --len;
  str[len] = 0;
  return str;
}

void
split_to_lines(
        const unsigned char *str,
        char ***plns,
        int ws_mode) // 0 - nothing, 1 - add space, 2 - remove space
{
  const unsigned char *s, *q, *r;
  char **lns;
  int lcnt, i;

  if (!str || !*str) {
    *plns = 0;
    return;
  }

  // count lines
  for (s = str, lcnt = 0; *s; ++s)
    if (*s == '\n') lcnt++;
  if (s[-1] != '\n') lcnt++;

  XCALLOC(lns, lcnt + 1);
  for (s = str, i = 0; *s; s = q, ++i) {
    q = s;
    while (*q && *q != '\n') ++q;
    r = q;
    if (*q == '\n') ++q;
    // line is [s, q)
    while (r > s && isspace(r[-1])) --r;
    if (ws_mode == 2) {
      while (s < r && isspace(*s)) ++s;
    }
    if (ws_mode == 1 && s < r && !isspace(*s)) {
      lns[i] = (unsigned char *) xmalloc(r - s + 2);
      lns[i][0] = ' ';
      memcpy(lns[i] + 1, s, r - s);
      lns[i][r - s + 1] = 0;
    } else {
      lns[i] = (unsigned char *) xmalloc(r - s + 1);
      memcpy(lns[i], s, r - s);
      lns[i][r - s] = 0;
    }
  }
  while (i > 0 && !lns[i - 1][0]) {
    --i;
    xfree(lns[i]);
    lns[i] = 0;
  }
  *plns = lns;
}

int
is_empty_string(const unsigned char *s)
{
  if (!s) return 1;
  while (*s && isspace(*s)) ++s;
  return !*s;
}

int
is_empty_string_2(const unsigned char *s)
{
  if (!s) return 1;
  while (*s && (*s <= ' ' || *s == 0x7f)) ++s;
  return !*s;
}

#define SIZE_T (1024LL * 1024LL * 1024LL * 1024LL)
#define SIZE_G (1024 * 1024 * 1024)
#define SIZE_M (1024 * 1024)
#define SIZE_K (1024)

unsigned char*
num_to_size_str(
        unsigned char *buf,
        size_t buf_size,
        int num)
{
  if (!num) snprintf(buf, buf_size, "0");
  else if (!(num % SIZE_G)) snprintf(buf, buf_size, "%uG", num / SIZE_G);
  else if (!(num % SIZE_M)) snprintf(buf, buf_size, "%uM", num / SIZE_M);
  else if (!(num % SIZE_K)) snprintf(buf, buf_size, "%uK", num / SIZE_K);
  else snprintf(buf, buf_size, "%u", num);
  return buf;
}

unsigned char*
size_t_to_size_str(
        unsigned char *buf,
        size_t buf_size,
        size_t num)
{
  if (!num) snprintf(buf, buf_size, "0");
  else if (!(num % SIZE_G)) snprintf(buf, buf_size, "%" EJ_PRINTF_ZSPEC "uG", EJ_PRINTF_ZCAST(num / SIZE_G));
  else if (!(num % SIZE_M)) snprintf(buf, buf_size, "%" EJ_PRINTF_ZSPEC "uM", EJ_PRINTF_ZCAST(num / SIZE_M));
  else if (!(num % SIZE_K)) snprintf(buf, buf_size, "%" EJ_PRINTF_ZSPEC "uK", EJ_PRINTF_ZCAST(num / SIZE_K));
  else snprintf(buf, buf_size, "%" EJ_PRINTF_ZSPEC "u", EJ_PRINTF_ZCAST(num));
  return buf;
}

unsigned char *
ll_to_size_str(
        unsigned char *buf,
        size_t buf_size,
        long long value)
{
  if (value < 0) {
    snprintf(buf, buf_size, "%lld", value);
  } else if (!value) {
    snprintf(buf, buf_size, "0");
  } else if (!(value % SIZE_G)) {
    snprintf(buf, buf_size, "%lldG", value / SIZE_G);
  } else if (!(value % SIZE_M)) {
    snprintf(buf, buf_size, "%lldM", value / SIZE_M);
  } else if (!(value % SIZE_K)) {
    snprintf(buf, buf_size, "%lldK", value / SIZE_K);
  } else {
    snprintf(buf, buf_size, "%lld", value);
  }
  return buf;
}

void
ll_to_size_str_f(
        FILE *f,
        long long value)
{
  if (value < 0) {
    // ...
  } else if (!value) {
    fprintf(f, "0");
  } else if (!(value % SIZE_G)) {
    fprintf(f, "%lldG", value / SIZE_G);
  } else if (!(value % SIZE_M)) {
    fprintf(f, "%lldM", value / SIZE_M);
  } else if (!(value % SIZE_K)) {
    fprintf(f, "%lldK", value / SIZE_K);
  } else {
    fprintf(f, "%lld", value);
  }
}

void
size_t_to_size_str_f(
        FILE *f,
        size_t num)
{
  if (!num) fprintf(f, "0");
  else if (!(num % SIZE_G)) fprintf(f, "%" EJ_PRINTF_ZSPEC "uG", EJ_PRINTF_ZCAST(num / SIZE_G));
  else if (!(num % SIZE_M)) fprintf(f, "%" EJ_PRINTF_ZSPEC "uM", EJ_PRINTF_ZCAST(num / SIZE_M));
  else if (!(num % SIZE_K)) fprintf(f, "%" EJ_PRINTF_ZSPEC "uK", EJ_PRINTF_ZCAST(num / SIZE_K));
  else fprintf(f, "%" EJ_PRINTF_ZSPEC "u", EJ_PRINTF_ZCAST(num));
}

/*
  parse an integral value in range -2147483648...2147483647 checking for overflow
 */
int
size_str_to_num(const unsigned char *str, int *p_num)
{
  const unsigned char *s;
  long value;
  char *eptr = 0;
  int suffix = 0;

  if (!str) return -1;
  s = str;
  while (*s && isspace(*s)) ++s;
  if (!*s) return -1;

  errno = 0;
  value = strtol(str, &eptr, 10);
  if (errno) return -1;
#if LONG_MAX != INT_MAX
  if (value < INT_MIN || value > INT_MAX) return -1;
#endif
  s = (const unsigned char *) eptr;
  if (*s && !isspace(*s)) {
    suffix = toupper(*s);
    if (suffix != 'K' && suffix != 'M' && suffix != 'G' && suffix != 'T')
      return -1;
    ++s;
  }
  while (*s && isspace(*s)) ++s;
  if (*s) return -1;
  if (suffix == 'T') {
    return -1;
  } else if (suffix == 'G') {
    if (value < -2 || value > 1) return -1;
    value *= SIZE_G;
  } else if (suffix == 'M') {
    if (value < -2048 || value > 2047) return -1;
    value *= SIZE_M;
  } else if (suffix == 'K') {
    if (value < -2097152 || value > 2097151) return -1;
    value *= SIZE_K;
  }

  if (p_num) *p_num = (int) value;

  return 0;
}

/*
  parse an integral value in range LONG_MIN ... LONG_MAX checking for overflow
 */
int
size_str_to_size_t(const unsigned char *str, size_t *p_size)
{
  const unsigned char *s;
  long value;
  char *eptr = 0;
  int suffix = 0;

  if (!str) return -1;
  s = str;
  while (*s && isspace(*s)) ++s;
  if (!*s) return -1;

  errno = 0;
  value = strtol(str, &eptr, 10);
  if (errno) return -1;
  s = (const unsigned char *) eptr;
  if (*s && !isspace(*s)) {
    suffix = toupper(*s);
    if (suffix != 'K' && suffix != 'M' && suffix != 'G' && suffix != 'T')
      return -1;
    ++s;
  }
  while (*s && isspace(*s)) ++s;
  if (*s) return -1;

#if INT_MAX == LONG_MAX
  // 32-bit architecture
  if (suffix == 'T') {
    return -1;
  } else if (suffix == 'G') {
    if (value < -2 || value > 1) return -1;
    value *= SIZE_G;
  } else if (suffix == 'M') {
    if (value < -2048 || value > 2047) return -1;
    value *= SIZE_M;
  } else if (suffix == 'K') {
    if (value < -2097152 || value > 2097151) return -1;
    value *= SIZE_K;
  }
#else
  // 64-bit architecture. Note, this will not work for MSVC...
  if (suffix == 'T') {
    if (value < -8388608L || value > 8388607L) return -1;
    value *= SIZE_T;
  } else if (suffix == 'G') {
    if (value < -8589934592L || value > 8589934591L) return -1;
    value *= SIZE_G;
  } else if (suffix == 'M') {
    if (value < -8796093022208L || value > 8796093022207L) return -1;
    value *= SIZE_M;
  } else if (suffix == 'K') {
    if (value < -9007199254740992L || value > 9007199254740991L) return -1;
    value *= SIZE_K;
  }
#endif

  if (p_size) *p_size = (size_t) value;

  return 0;
}

int
size_str_to_size64_t(const unsigned char *str, ej_size64_t *p_size)
{
  if (!str) return -1;

  int len = strlen(str);
  while (len > 0 && isspace(str[len - 1])) --len;
  if (!len) return -1;
  const unsigned char *s = str;
  const unsigned char *e = s + len;
  errno = 0;
  char *eptr = NULL;
  long long x = strtoll(s, &eptr, 10);
  if (errno) return -1;
  s = (const unsigned char *) eptr;
  if (s == e) {
    if (p_size) *p_size = x;
    return 0;
  }
  while (isspace(*s)) ++s;
  if (*s == 't' || *s == 'T') {
    if (x < -8388608LL || x > 8388607LL) return -1;
    x *= SIZE_T;
    ++s;
  } else if (*s == 'g' || *s == 'G') {
    if (x < -8589934592LL || x > 8589934591LL) return -1;
    x *= SIZE_G;
    ++s;
  } else if (*s == 'm' || *s == 'M') {
    if (x < -8796093022208LL || x > 8796093022207LL) return -1;
    x *= SIZE_M;
    ++s;
  } else if (*s == 'k' || *s == 'K') {
    if (x < -9007199254740992LL || x > 9007199254740991LL) return -1;
    x *= SIZE_K;
    ++s;
  }
  if (s != e) return -1;
  if (p_size) *p_size = x;
  return 0;
}

int
has_control_characters(const unsigned char *str)
{
  for (; *str; ++str) {
    if (*str == 127) return 1;
    if (*str < ' ' && *str != '\n' && *str != '\r') return 1;
  }
  return 0;
}

/*
static const unsigned char c_armor_needed_table[256] =
{
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
*/

static const unsigned char armored_c_len_table[256] =
{
  2, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 2, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  1, 1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

static unsigned char const * const armored_c_translate_table[256] =
{
  "\\0", "\\x01", "\\x02", "\\x03", "\\x04", "\\x05", "\\x06", "\\a", "\\b", "\\t", "\\n", "\\v", "\\f", "\\r", "\\x0e", "\\x0f",
  "\\x10", "\\x11", "\\x12", "\\x13", "\\x14", "\\x15", "\\x16", "\\x17", "\\x18", "\\x19", "\\x1a", "\\x1b", "\\x1c", "\\x1d", "\\x1e", "\\x1f",
  0, 0, "\\\"", 0, 0, 0, 0, "\\\'", 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "\\\\", 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "\\x7f",
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

size_t
c_armored_memlen(char const *str, size_t size)
{
  unsigned char const *p = (unsigned char const*) str;
  size_t l = 0;

  for (size_t i = 0; i < size; ++i, ++p) {
    l += armored_c_len_table[*p];
  }
  return l;
}

size_t
c_armored_strlen(char const *str)
{
  const unsigned char *p = (const unsigned char *) str;
  size_t l = 0;

  while (*p) {
    l += armored_c_len_table[*p++];
  }
  return l;
}

int
c_armor_needed(const unsigned char *str, size_t *psz)
{
  const unsigned char *p = str;
  size_t s_sz = 0, d_sz = 0;

  if (!str) return 0;
  while (*p) {
    s_sz++;
    d_sz += armored_c_len_table[*p];
    p++;
  }
  if (s_sz == d_sz) return 0;
  *psz = d_sz;
  return 1;
}

int
c_armor_needed_bin(const unsigned char *str, size_t sz, size_t *psz)
{
  const unsigned char *p = str;
  size_t s_sz = sz, d_sz = 0;

  if (!str || !sz) return 0;

  while (s_sz) {
    d_sz += armored_c_len_table[*p];
    p++; s_sz--;
  }
  if (d_sz == sz && !*p) return 0;
  *psz = d_sz;
  return 1;
}

/*
static int
c_armor_text(char const *str, int size, char *out)
{
  unsigned char const *p = (unsigned char const *) str;
  char *s = out;
  unsigned char const *t;
  int i = size;

  for (; i > 0; p++, i--) {
    if (!(t = armored_c_translate_table[*p])) {
      *s++ = *p;
    } else {
      while ((*s++ = *t++));
      s--;
    }
  }
  *s = 0;
  return s - out;
}
*/

static int
c_armor_string(char const *str, char *out)
{
  unsigned char const *p = (unsigned char const *) str;
  unsigned char const *t;
  char *s = out;

  for (;*p; ++p) {
    if (!(t = armored_c_translate_table[*p])) {
      *s++ = *p;
    } else {
      while ((*s++ = *t++));
      s--;
    }
  }

  *s = 0;
  return s - out;
}

const unsigned char *
c_armor_buf(struct html_armor_buffer *pb, const unsigned char *s)
{
  size_t newsz = 0;

  if (!c_armor_needed(s, &newsz)) return s;
  if (newsz >= pb->size) {
    xfree(pb->buf);
    if (!pb->size) pb->size = 64;
    while (newsz >= pb->size) pb->size *= 2;
    pb->buf = (unsigned char*) xmalloc(pb->size);
  }
  c_armor_string(s, pb->buf);
  return pb->buf;
}

int
text_read_file(
        const unsigned char *path,
        int reserve,
        unsigned char **out,
        size_t *out_len)
{
  unsigned char read_buf[512];
  unsigned char *buf = 0;
  size_t buf_len = 0, read_len = 0;
  FILE *f = 0;

  if (reserve <= 0) reserve = 1;

  if (!(f = fopen(path, "r"))) {
    return -1;
  }

  while (1) {
    read_len = fread(read_buf, 1, sizeof(read_buf), f);
    if (!read_len) break;
    if (!buf_len) {
      buf = (unsigned char*) xcalloc(read_len + reserve, 1);
      memcpy(buf, read_buf, read_len);
      buf_len = read_len;
    } else {
      buf = (unsigned char*) xrealloc(buf, buf_len + reserve + read_len);
      memcpy(buf + buf_len, read_buf, read_len);
      buf_len += read_len;
      buf[buf_len] = 0;
    }
  }
  if (ferror(f)) {
    xfree(buf);
    fclose(f);
    return -1;
  }
  fclose(f); f = NULL;
  if (!buf_len) {
    buf = (unsigned char*) xmalloc(reserve);
    buf[0] = 0;
    buf_len = 0;
  }
  if (out) *out = buf;
  if (out_len) *out_len = buf_len;
  return (int) buf_len;
}

int
text_is_valid_char(int c)
{
  if (c == 0177) return 0;
  if (c < 0 || c >= ' ' || c == '\t' || c == '\n' || c == '\r') return 1;
  return 0;
}

int
text_is_binary(const unsigned char *text, size_t size)
{
  size_t i;

  for (i = 0; i < size; ++i) {
    if (!text_is_valid_char(text[i])) return 1;
    if (text[i] == '\r' && text[i + 1] != '\n') return 1;
  }
  return 0;
}

size_t
text_normalize_buf(
        unsigned char *in_text,
        size_t in_size,
        int op_mask,
        size_t *p_count,
        int *p_done_mask)
{
  size_t i = 0, j = 0;
  int done_mask = 0;
  size_t count = 0;
  unsigned char *out_text;

  if (!in_size) {
    if (p_count) *p_count = 0;
    if (p_done_mask) *p_done_mask = 0;
    return 0;
  }

  out_text = in_text;
  while (in_text[i]) {
    if (in_text[i] == '\n') {
      if (j > 0 && out_text[j - 1] == '\r' && (op_mask & TEXT_FIX_CR)) {
        done_mask |= TEXT_FIX_CR;
        ++count;
        --j;
      }
      if ((op_mask & TEXT_FIX_TR_SP)) {
        while (j > 0 && out_text[j - 1] != '\n' && isspace(out_text[j - 1])) {
          done_mask |= TEXT_FIX_TR_SP;
          ++count;
          --j;
        }
      }
      out_text[j++] = '\n';
      ++i;
    } else if ((op_mask & TEXT_FIX_NP) &&
               (in_text[i] == 127
                || (in_text[i] < ' ' && in_text[i] != '\r' && in_text[i] != '\n' && in_text[i] != '\t'))) {
      out_text[j++] = ' ';
      done_mask |= TEXT_FIX_NP;
      ++count;
      ++i;
    } else {
      out_text[j++] = in_text[i++];
    }
  }
  if ((op_mask & TEXT_FIX_TR_SP)) {
    while (j > 0 && out_text[j - 1] != '\n' && isspace(out_text[j - 1])) {
      done_mask |= TEXT_FIX_TR_SP;
      ++count;
      --j;
    }
  }
  if (i > 0 && in_text[i - 1] != '\n' && (op_mask & TEXT_FIX_FINAL_NL)) {
    done_mask |= TEXT_FIX_FINAL_NL;
    ++count;
    out_text[j++] = '\n';
  }
  if ((op_mask & TEXT_FIX_TR_NL)) {
    while (j > 2 && out_text[j - 1] == '\n' && out_text[j - 2] == '\n') {
      done_mask |= TEXT_FIX_TR_NL;
      --j;
      ++count;
    }
    if (j == 1 && out_text[j - 1] == '\n') {
      done_mask |= TEXT_FIX_TR_NL;
      --j;
      ++count;
    }
  }
  out_text[j] = 0;

  if (p_count) *p_count = count;
  if (p_done_mask) *p_done_mask = done_mask;
  return j;
}

size_t
text_normalize_dup(
        const unsigned char *in_text,
        size_t in_size,
        int op_mask,
        unsigned char **p_out_text,
        size_t *p_count,
        int *p_done_mask)
{
  unsigned char *out_text = 0;

  if (!in_size) {
    *p_out_text = xstrdup("");
    if (p_count) *p_count = 0;
    return 0;
  }
  *p_out_text = out_text = (unsigned char*) xmalloc(in_size + 2);
  memcpy(out_text, in_text, in_size + 1);
  return text_normalize_buf(out_text, in_size, op_mask, p_count, p_done_mask);
}

void
html_print_by_line(
        FILE *f,
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        unsigned char const *s,
        size_t size)
{
  const unsigned char *p = s;
  const unsigned char * const * trans_table;

  if (max_file_length > 0 && size > max_file_length) {
    fprintf(f, "(%s, %s = %" EJ_PRINTF_ZSPEC "u)\n",
            "file is too long", "size", EJ_PRINTF_ZCAST(size));
    return;
  }

  if (!s) {
    fprintf(f, "(%s)\n", "file is missing");
    return;
  }

  trans_table = html_get_armor_table();

  while (*s) {
    while (*s && *s != '\r' && *s != '\n') s++;
    if (max_line_length > 0 && s - p > max_line_length) {
      fprintf(f, "(%s, %s = %" EJ_PRINTF_TSPEC "d)\n",
              "line is too long", "size", EJ_PRINTF_TCAST(s - p));
    } else {
      if (utf8_mode) {
        while (p != s) {
          if (*p <= 0x7f) {
            if (trans_table[*p]) {
              fputs(trans_table[*p++], f);
            } else {
              putc(*p++, f);
            }
          } else if (*p <= 0xbf) {
            // middle of multibyte sequence
            putc('?', f);
            p++;
          } else if (*p <= 0xc1) {
            // reserved
            putc('?', f);
            p++;
          } else if (*p <= 0xdf) {
            // two bytes: 0x80-0x7ff
            if (p + 1 < s && p[1] >= 0x80 && p[1] <= 0xbf && (((p[0] & 0x1f) << 6) | (p[1] & 0x3f)) >= 0x80) {
              putc(*p++, f);
              putc(*p++, f);
            } else {
              putc('?', f);
              p++;
            }
          } else if (*p <= 0xef) {
            // three bytes: 0x800-0xffff
            putc('?', f);
            p++;
            /*
            if (p + 2 < s && p[1] >= 0x80 && p[1] <= 0xbf && p[2] >= 0x80 && p[2] <= 0xbf && (((p[0] & 0x0f) << 12) | ((p[1] & 0x3f) << 6) | (p[2] & 0x3f)) >= 0x800) {
              putc(*p++, f);
              putc(*p++, f);
              putc(*p++, f);
            } else {
              putc('?', f);
              p++;
            }
            */
          } else if (*p <= 0xf7) {
            // four bytes: 0x10000-0x10ffff
            putc('?', f);
            p++;
            /*
            if (p + 3 < s && p[1] >= 0x80 && p[1] <= 0xbf && p[2] >= 0x80 && p[2] <= 0xbf && p[3] >= 0x80 && p[3] <= 0xbf && (((p[0] & 0x07) << 18) | ((p[1] & 0x3f) << 12) | ((p[2] & 0x3f) << 6) | (p[3] & 0x3f)) >= 0x10000) {
              putc(*p++, f);
              putc(*p++, f);
              putc(*p++, f);
              putc(*p++, f);
            } else {
              putc('?', f);
              p++;
            }
            */
          } else {
            // reserved
            putc('?', f);
            p++;
          }
        }
      } else {
        while (p != s)
          if (trans_table[*p]) {
            fputs(trans_table[*p], f);
            p++;
          } else {
            putc(*p++, f);
          }
      }
    }
    while (*s == '\r' || *s == '\n')
      putc(*s++, f);
    p = s;
  }
  putc('\n', f);
}

unsigned char *
html_print_by_line_str(
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        unsigned char const *s,
        size_t size)
{
  char *txt = 0;
  size_t len = 0;
  FILE *f = open_memstream(&txt, &len);
  html_print_by_line(f, utf8_mode, max_file_length, max_line_length, s, size);
  fclose(f); f = NULL;
  return txt;
}

int
ucs2_to_utf8(
        unsigned char **pu8str,
        const unsigned char *u16str,
        int u16len)
{
  int i, out_count, c;
  int is_be = 0; // big endian?
  const unsigned char *u16p = u16str;
  unsigned char *u8o = 0, *u8p = 0;

  if (u16len < 0) return -1;
  if (!u16str || !u16len) {
    if (pu8str) *pu8str = 0;
    return 0;
  }
  if ((u16len & 1)) return -1;

  // check for zero in the middle
  for (i = 0; i < u16len; i += 2) {
    if (!u16str[i] && !u16str[i + 1]) return -1;
  }

  // check for the BOM
  if (u16str[0] == 0xff && u16str[1] == 0xfe) {
    u16p = u16str + 2;
    u16len -= 2;
  } else if (u16str[0] == 0xfe && u16str[1] == 0xff) {
    u16p = u16str + 2;
    u16len -= 2;
    is_be = 1;
  } else {
    int count0 = 0;
    int count1 = 0;
    for (i = 0; i < u16len; i += 2) {
      if (u16str[i] >= ' ') ++count0;
      if (u16str[i + 1] >= ' ') ++count1;
    }
    if (count0 <= 0) {
      is_be = 1;
    }
    if (count0 > 0 && count1 > 0) {
      // do not risk it
      return -1;
    }
  }

  out_count = 0;
  for (i = 0; i < u16len; i += 2) {
    if (is_be) {
      c = (u16p[i] << 8) | u16p[i + 1];
    } else {
      c = (u16p[i + 1] << 8) | u16p[i];
    }

    if (c <= 0x7f) {
      out_count += 1;
    } else if (c <= 0x7ff) {
      out_count += 2;
    } else {
      out_count += 3;
    }
  }
  if (!pu8str) return out_count;

  u8o = (unsigned char*) xmalloc(out_count + 1);
  u8p = u8o;
  for (i = 0; i < u16len; i += 2) {
    if (is_be) {
      c = (u16p[i] << 8) | u16p[i + 1];
    } else {
      c = (u16p[i + 1] << 8) | u16p[i];
    }

    if (c <= 0x7f) {
      *u8p++ = c;
    } else if (c <= 0x7ff) {
      *u8p++ = (c >> 6) | 0xc0;
      *u8p++ = (c & 0x3f) | 0x80;
    } else {
      *u8p++ = (c >> 12) | 0xe0;
      *u8p++ = ((c >> 6) & 0x3f) | 0x80;
      *u8p++ = (c & 0x3f) | 0x80;
    }
  }

  *u8p = 0;
  *pu8str = u8o;
  return out_count;
}

/*
  returns: 0 - address invalid, 1 - valid
 */
int
is_valid_email_address(const unsigned char *email_address)
{
  if (!email_address || !*email_address) return 0;
  const unsigned char *p;
  const unsigned char *at_ptr = 0;
  for (p = email_address; *p; ++p) {
    if (*p <= ' ' || *p >= 127 || *p == '\\' || *p == '\'' || *p == '\"')
      return 0;
    if (*p == '@') {
      if (at_ptr) return 0;
      at_ptr = p;
    }
  }
  if (!at_ptr) return 0;
  if (at_ptr == email_address || !at_ptr[1]) return 0;
  // check domain part
  for (p = at_ptr + 1; *p; ++p) {
    if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.')
      return 0;
    if (*p == '.' && (p[-1] == '@' || !p[1] || p[1] == '.')) return 0;
  }
  // check local part
  for (p = email_address; p < at_ptr; ++p) {
    if (*p == '.') {
      if (p == email_address || p[1] == '@' || p[1] == '.') return 0;
    } else if (isalnum(*p)) {
      // do nothing
    } else if (*p == '!' || *p == '#' || *p == '+' || *p == '-' || *p == '/' || *p == '=' || *p == '?'
               || *p == '^' || *p == '_' || *p == '~') {
      // All valid chars: ! # $ % & * + - / = ? ^ _ ` { | } ~
    } else {
      return 0;
    }
  }
  return 1;
}

size_t
csv_armored_memlen(char const *str, size_t size)
{
  unsigned char const *p = (unsigned char const*) str;
  size_t l = 0;
  int need_quotes = 0;

  for (size_t i = 0; i < size; ++i, ++p) {
    if (*p <= ' ' || *p == ';') {
      need_quotes = 1;
      ++l;
    } else if (*p == '"') {
      need_quotes = 1;
      l += 2;
    } else {
      ++l;
    }
  }
  if (need_quotes) l += 2;
  return l;
}

size_t
csv_armored_strlen(char const *str)
{
  const unsigned char *p = (const unsigned char *) str;
  size_t l = 0;
  int need_quotes = 0;

  for (; *p; ++p) {
    if (*p <= ' ' || *p == ';') {
      need_quotes = 1;
      ++l;
    } else if (*p == '"') {
      need_quotes = 1;
      l += 2;
    } else {
      ++l;
    }
  }
  if (need_quotes) l += 2;
  return l;
}

int
csv_armor_needed(const unsigned char *str, size_t *psz)
{
  const unsigned char *p = str;
  size_t s_sz = 0, d_sz = 0;
  int need_quotes = 0;

  if (!str) return 0;
  for (; *p; ++s_sz, ++p) {
    if (*p <= ' ' || *p == ';') {
      need_quotes = 1;
      ++d_sz;
    } else if (*p == '"') {
      need_quotes = 1;
      d_sz += 2;
    } else {
      ++d_sz;
    }
  }
  if (need_quotes) d_sz += 2;
  if (s_sz == d_sz) return 0;
  *psz = d_sz;
  return 1;
}

/*
int
c_armor_needed_bin(const unsigned char *str, size_t sz, size_t *psz)
{
  const unsigned char *p = str;
  size_t s_sz = sz, d_sz = 0;

  if (!str || !sz) return 0;

  while (s_sz) {
    d_sz += armored_c_len_table[*p];
    p++; s_sz--;
  }
  if (d_sz == sz && !*p) return 0;
  *psz = d_sz;
  return 1;
}
*/

/*
static int
c_armor_text(char const *str, int size, char *out)
{
  unsigned char const *p = (unsigned char const *) str;
  char *s = out;
  unsigned char const *t;
  int i = size;

  for (; i > 0; p++, i--) {
    if (!(t = armored_c_translate_table[*p])) {
      *s++ = *p;
    } else {
      while ((*s++ = *t++));
      s--;
    }
  }
  *s = 0;
  return s - out;
}
*/

static int
csv_armor_string(char const *str, char *out)
{
  unsigned char const *p = (unsigned char const *) str;
  char *s = out;
  int need_quotes = 0;

  for (p = (const unsigned char *) str; *p; ++p) {
    if (*p <= ' ' || *p == ';' || *p == '"') {
      need_quotes = 1;
    }
  }

  if (need_quotes) *s++ = '"';
  for (p = (const unsigned char *) str;*p; ++p) {
    if (*p == '"') {
      *s++ = *p;
      *s++ = *p;
    } else {
      *s++ = *p;
    }
  }
  if (need_quotes) *s++ = '"';

  *s = 0;
  return s - out;
}

const unsigned char *
csv_armor_buf(struct html_armor_buffer *pb, const unsigned char *s)
{
  size_t newsz = 0;

  if (!csv_armor_needed(s, &newsz)) return s;
  if (newsz >= pb->size) {
    xfree(pb->buf);
    if (!pb->size) pb->size = 64;
    while (newsz >= pb->size) pb->size *= 2;
    pb->buf = (unsigned char*) xmalloc(pb->size);
  }
  csv_armor_string(s, pb->buf);
  return pb->buf;
}

int
parse_date_twopart(
        const unsigned char *date_str,
        const unsigned char *time_str,
        time_t *p_time)
{
  if (is_empty_string_2(date_str)) date_str = "";
  if (is_empty_string_2(time_str)) time_str = "";

  *p_time = 0;
  if (!*date_str) {
    return 0;
  }
  size_t dlen = strlen(date_str);
  size_t tlen = strlen(time_str);
  if (dlen >= 128) return -1;
  if (tlen >= 128) return -1;
  unsigned char *str = alloca(dlen + tlen + 2);
  sprintf(str, "%s %s", date_str, time_str);
  if (xml_parse_date(NULL, NULL, 0, 0, str, p_time) < 0) {
    *p_time = 0;
    return -1;
  }
  if (*p_time == 0 || *p_time == ~(time_t) 0) {
    *p_time = 0;
    return -1;
  }
  return 1;
}

int
parse_duration(const unsigned char *str, int default_value)
{
  if (!str) return default_value;
  int len = strlen(str);
  while (len > 0 && isspace(str[len - 1])) --len;
  if (len <= 0) return default_value;
  int h, m, n;
  if (sscanf(str, "%d:%d%n", &h, &m, &n) == 2 && n == len && h >= 0 && h <= 1000000 && m >= 0 && m < 60) {
    return h * 60 + m;
  }
  if (sscanf(str, "%d%n", &m, &n) == 1 && n == len && m >= 0 && m <= 1000000) {
    return m;
  }
  return -1;
}

unsigned char *
text_substitute(
        const void *p,
        const unsigned char *str,
        unsigned char *(*getvar_func)(const void *, const unsigned char *))
{
  int out_z = 0;
  int out_u = 0;
  unsigned char *out_s = NULL;
  int i = 0;

  if (!str) return NULL;
  out_s = xmalloc(out_z = 16);

  while (str[i]) {
    if (str[i] == '$' && str[i + 1] == '{') {
      int j = i + 2;
      while (str[j] && str[j] != '}') ++j;
      if (str[j] == '}') {
        unsigned char *name = xmemdup(str + i + 2, j - i - 2);
        unsigned char *value = getvar_func(p, name);
        if (value) {
          int len = strlen(value);
          if (out_u + len >= out_z) {
            while (out_u + len >= out_z) out_z *= 2;
            out_s = xrealloc(out_s, out_z);
          }
          memcpy(out_s + out_u, value, len);
          out_u += len;
          xfree(value);
        }
        xfree(name);
        i = j + 1;
      } else {
        i = j;
      }
    } else if (str[i] == '$' && str[i + 1] == '$') {
      if (out_u + 1 == out_z) {
        out_s = xrealloc(out_s, out_z *= 2);
      }
      out_s[out_u++] = str[i++];
      ++i;
    } else {
      if (out_u + 1 == out_z) {
        out_s = xrealloc(out_s, out_z *= 2);
      }
      out_s[out_u++] = str[i++];
    }
  }

  out_s[out_u] = 0;
  return out_s;
}

int
json_armor_needed(const unsigned char *str, size_t *psz)
{
  size_t src_z = 0, dst_z = 0;
  while (*str) {
    ++src_z;
    unsigned char c = *str++;
    if (c == '\"' || c == '\\') {
      dst_z += 2;
    } else if (c == 0x7f) {
      dst_z += 6;
    } else if (c >= ' ') {
      ++dst_z;
    } else if (c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') {
      dst_z += 2;
    } else {
      dst_z += 6;
    }
  }
  if (psz) *psz = dst_z;
  return src_z != dst_z;
}

int
json_armor_string(const unsigned char *str, char *out)
{
  char *s = out;
  while (*str) {
    unsigned char c = *str++;
    switch (c) {
    case '\"': *s++ = '\\'; *s++ = '\"'; break;
    case '\\': *s++ = '\\'; *s++ = '\\'; break;
    case '\b': *s++ = '\\'; *s++ = 'b'; break;
    case '\f': *s++ = '\\'; *s++ = 'f'; break;
    case '\n': *s++ = '\\'; *s++ = 'n'; break;
    case '\r': *s++ = '\\'; *s++ = 'r'; break;
    case '\t': *s++ = '\\'; *s++ = 't'; break;
    case 0x7f: *s++ = '\\'; *s++ = 'u'; *s++ = '0'; *s++ = '0'; *s++ = '7'; *s++ = 'f'; break;
    default:
      if (c >= ' ') {
        *s++ = c;
      } else {
        s += sprintf(s, "\\u%04x", c);
      }
      break;
    }
  }
  *s = 0;
  return s - out;
}

const unsigned char *
json_armor_buf(struct html_armor_buffer *pb, const unsigned char *s)
{
  size_t newsz = 0;
  if (!json_armor_needed(s, &newsz)) return s;
  if (newsz >= pb->size) {
    xfree(pb->buf);
    if (!pb->size) pb->size = 64;
    while (newsz >= pb->size) pb->size *= 2;
    pb->buf = (unsigned char*) xmalloc(pb->size);
  }
  json_armor_string(s, pb->buf);
  return pb->buf;
}
