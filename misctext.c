/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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

#include "misctext.h"
#include "base64.h"

#include <reuse/logger.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

static char const * const armored_html_translate_table[256] =
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
html_armor_text(char const *str, int size, char *out)
{
  unsigned char const *p = (unsigned char const *) str;
  char *s = out;
  char const *t;
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

char *
duration_str(unsigned long time, char *buf, int len)
{
  int         hh, mm, ss;
  static char b[64];

  ss = time % 60;
  time /= 60;
  mm = time % 60;
  time /= 60;
  hh = time;
  sprintf(b, "%d:%02d:%02d", hh, mm, ss);
  if (!buf) return b;
  if (len <= 0) return strcpy(buf, b);
  strncpy(buf, b, len);
  buf[len - 1] = 0;
  return buf;
}

char *
duration_min_str(unsigned long time, char *buf, int len)
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

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

