/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

/*
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#include "changelog.h"
#include "xalloc.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

static int
checked_fgets(char *buf, int maxlen, FILE *f,
              FILE *errlog, char const *path, int *p_lineno)
{
  int len;

  if (!fgets(buf, maxlen, f)) return 0;
  (*p_lineno)++;
  len = strlen(buf);
  if (len == maxlen - 1 && buf[len - 1] != '\n') {
    fprintf(errlog, "%s: %d: input line is too long\n", path, *p_lineno);
    return -1;
  }
  return len;
}

static char * monthnames[] =
{
  "Jan", "Feb", "Mar",
  "Apr", "May", "Jun",
  "Jul", "Aug", "Sep",
  "Oct", "Nov", "Dec"
};

int
changelog_read(char const *path, changelog_t *p_log, FILE *errlog)
{
  FILE *fin = 0;
  char  lbuf[8192];
  char  wdaybuf[8192];
  char  mbuf[8192];
  char  authbuf[8192];
  char  revbuf[8192];
  int   llen;
  char *msg = 0;
  int   lineno = 0;

  int   year, month, day, n, nn, hour, min, sec, revision, revlen, nnn;

  strarray_t flist;
  int        i1, i2, i;

  memset(p_log, 0, sizeof(*p_log));

  if (!(fin = fopen(path, "r"))) {
    fprintf(errlog, "cannot open file `%s'\n", path);
    goto _cleanup;
  }

  if ((llen = checked_fgets(lbuf,sizeof(lbuf),fin,errlog,path,&lineno)) < 0)
    goto _cleanup;
  while (llen > 0) {
    if (!strncmp(lbuf, "END", 3)) break;
    // now read date
    if (sscanf(lbuf, "%d-%d-%d%n", &year, &month, &day, &n) == 3) {
      // sanity check for new date format
      if (lbuf[n] != ' '
          || year < 1970 || year > 2050
          || month < 1 || month > 12
          || day < 1 || day > 31) {
        fprintf(errlog, "%s: %d: date format error: `%s'\n",
                path, lineno, lbuf);
        goto _cleanup;
      }
    } else if (sscanf(lbuf, "%s %s %d %d:%d:%d %d%n",
                      wdaybuf, mbuf, &day, &hour, &min, &sec, &year, &n)==7) {
      // old date format, do sanity check
      for (month = 0; month < 12; month++) {
        if (!strcmp(monthnames[month], mbuf)) break;
      }
      if (month >= 12) {
        fprintf(errlog, "%s: %d: cannot parse month name: `%s'\n",
                path, lineno, lbuf);
        goto _cleanup;
      }
      month++;

      if (lbuf[n] != ' '
          || year < 1970 || year > 2050
          || day < 1 || day > 31) {
        fprintf(errlog, "%s: %d: date format error: `%s'\n",
                path, lineno, lbuf);
        goto _cleanup;
      }
    } else {
      fprintf(errlog, "%s: %d: cannot parse date: `%s'\n",
              path, lineno, lbuf);
      goto _cleanup;
    }

    while (isspace(lbuf[n])) n++;
    // FIXME: get the revision
    revision = 0;
    if (sscanf(lbuf + n, "%s%n", revbuf, &nn) == 1 &&
        (revlen = strlen(revbuf)) > 3
        && revbuf[0] == '(' && revbuf[1] == 'r' && revbuf[revlen - 1] == ')'
        && sscanf(revbuf + 2, "%d%n", &revision, &nnn) == 1
        && nnn == revlen - 3 && revision > 0) {
      n = nn;
      while (isspace(lbuf[n])) n++;
    }
    while (isspace(lbuf[llen - 1])) llen--;
    lbuf[llen] = 0;
    strcpy(authbuf, lbuf + n);

    // debug
    //fprintf(stderr, "Date: %d-%d-%d, Author: `%s'\n", 
    //        year, month, day, authbuf);

    if (revision > 0 && revision > p_log->maxrevision) {
      p_log->maxrevision = revision;
    }
    if (year > p_log->maxyear) {
      p_log->maxyear = year;
      p_log->maxmonth = month;
      p_log->maxday = day;
    } else if (year == p_log->maxyear) {
      if (month > p_log->maxmonth) {
        p_log->maxmonth = month;
        p_log->maxday = day;
      } else if (month == p_log->maxmonth) {
        if (day > p_log->maxday) {
          p_log->maxday = day;
        }
      }
    }

    if ((llen = checked_fgets(lbuf,sizeof(lbuf),fin,errlog,path,&lineno)) < 0)
      goto _cleanup;
    if (!llen) break;
    if (lbuf[0] != '\n') goto _format_error;

    llen = checked_fgets(lbuf, sizeof(lbuf), fin, errlog, path, &lineno);
    if (llen < 0) goto _cleanup;
    if (!llen) break;
    while (1) {
      // expect "\t* "
      if (lbuf[0] != '\t' || lbuf[1] != '*' || lbuf[2] != ' ')
        goto _format_error;
      if (lbuf[3] == ':' || lbuf[3] == ',' || lbuf[3] == ' '
          || lbuf[3] == '\n' || llen <= 3) goto _format_error;
      // read the list of files
      flist.u = flist.a = 0;
      flist.v = 0;
      i1 = 3;
      while (1) {
        i2 = i1;
        while (i2 < llen &&
               lbuf[i2] != ':' && lbuf[i2] != ',' && lbuf[i2] != '\n')
          i2++;
        if (i1 == i2 || i2 >= llen || lbuf[i2] == '\n') goto _format_error;
        xexpand(&flist);
        flist.v[flist.u++] = xmemdup(lbuf + i1, i2 - i1);
        i1 = i2;
        if (lbuf[i1] == ':') break;
        i1++;
        if (lbuf[i1] != ' ') goto _format_error;
        i1++;
      }

      // debug: print the list of files
      //fprintf(stderr, "Files:\n");
      //for (i = 0; i < flist.u; i++)
      //  fprintf(stderr, "<%s>\n", flist.v[i]);

      // here lbuf[i1] == ':'
      msg = 0;
      i1++;
      if (lbuf[i1] == ' ') {
        msg = xstrmerge2(msg, lbuf + i1 + 1);
      }

      // read the message text
      llen = checked_fgets(lbuf, sizeof(lbuf), fin, errlog, path, &lineno);
      if (llen < 0) goto _cleanup;
      while (llen > 0 && lbuf[0] == '\t') {
        if (!msg) msg = xstrmerge2(msg, lbuf + 1);
        else msg = xstrmerge2(msg, lbuf);
        llen = checked_fgets(lbuf, sizeof(lbuf), fin, errlog, path, &lineno);
        if (llen < 0) goto _cleanup;
      }

      // debug
      //fprintf(stderr, "Message body: <%s>", msg);

      for (i = 0; i < flist.u; i++) {
        changelog_entry_t *p;
        XEXPAND2(*p_log);
        p = &p_log->v[p_log->u++];
        p->year = year;
        p->month = month;
        p->day = day;
        p->author = xstrdup(authbuf);
        p->text = xstrdup(msg);
        p->file = xstrdup(flist.v[i]);
        p->revision = revision;
      }

      xfree(msg);
      xstrarrayfree(&flist);

      if (llen < 0) break;
      if (lbuf[0] != '\n') goto _format_error;
      llen = checked_fgets(lbuf, sizeof(lbuf), fin, errlog, path, &lineno);
      if (llen < 0) goto _cleanup;
      if (llen == 0 || lbuf[0] != '\t') break;
    }
  }

  fclose(fin);

#if 0
  for (i = 0; i < oldlog.u; i++) {
    struct oldlogentry_t *p = &oldlog.v[i];
    fprintf(stderr, "%d-%d-%d <%s> <%s> <%s>\n",
            p->year, p->month, p->day,
            p->file, p->author, p->text);
  }
#endif

  return 0;

 _format_error:
  fprintf(errlog, "%s:%d: ChangeLog format error\n", path, lineno);

 _cleanup:
  for (i = 0; i < p_log->u; i++) {
    xfree(p_log->v[i].file);
    xfree(p_log->v[i].author);
    xfree(p_log->v[i].text);
  }
  xfree(p_log->v);
  memset(p_log, 0, sizeof(*p_log));
  return -1;
}
