/* Copyright (C) 1999-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* ========== XALLOC.H ========== */

extern void *xmalloc(size_t size);
extern void *xcalloc(size_t nelem, size_t elsize);
extern void *xrealloc(void *ptr, size_t newsize);
extern void xfree(void *ptr);
extern char *xstrdup(char const*);
extern char *xmemdup(char const *, size_t size);

#if defined __GNUC__
#define XCALLOC(p,s)  ((p) = (typeof(p)) xcalloc((s), sizeof((p)[0])))
#define XREALLOC(p,s) ((p) = (typeof(p)) xrealloc((p), (s) * sizeof((p)[0])))
#else /* __GNUC__ */
#define XCALLOC(p,s)  ((p) = xcalloc((s), sizeof((p)[0])))
#define XREALLOC(p,s) ((p) = xrealloc((p), (s) * sizeof((p)[0])))
#endif /* __GNUC__ */

#define XMEMMOVE(d,s,c) (memmove((d),(s),(c)*sizeof(*(d))))
#define XMEMZERO(d,c)   (memset((d),0,(c)*sizeof(*(d))))
#define XEXPAND2(a)     (xexpand2(&(a),sizeof((a).v[0])))

/* s1 and s2 both dropped after merging */
extern char *xstrmerge0(char *s1, char *s2);
/* only s1 dropped after merging */  
extern char *xstrmerge1(char *s1, char const *s2);
/* neither s1 nor x2 are dropped after merging */
extern char *xstrmerge2(char const *s1, char const *s2);
/* only s2 dropped after merging */
extern char *xstrmerge3(char const *s1, char *s2);

/* extendable array of strings */
typedef struct strarray_t
{
  int    a;
  int    u;
  char **v;
} strarray_t;

/* extendable array of ints */
typedef struct intarray_t
{
  int    a;
  int    u;
  int   *v;
} intarray_t;

/* generic extendable array */
typedef struct genarray_t
{
  int    a;
  int    u;
  void  *v;
} genarray_t;

extern void  xexpand(strarray_t *);
extern void  xexpand2(/* array, elsize */);
extern void  xexpand3(/* array, elsize */);
extern void  xexpand4(/* array, elsize, newsize */);

extern void  xstrarrayfree(strarray_t *);

/* ========== end of XALLOC.H ========== */

enum state_t
{
  ST_BETWEEN_FILE,              /* between file entries */
  ST_HEADER,                    /* reading the header */
  ST_DESCRIPTION,               /* reading the description */
  ST_BETWEEN_REV,               /* between revision entries */
  ST_REV,                       /* revision header */
  ST_COMMENT                    /* revision comment */
};

struct revinfo_t
{
  time_t  date;
  char   *file;
  char   *rev;
  char   *author;
  char   *text;
};
struct revarr_t
{
  int               a, u;
  struct revinfo_t *v;
};

struct fileinfo_t
{
  char            *name;
  struct revarr_t  revs;
};
struct filearr_t
{
  int                a, u;
  struct fileinfo_t *v;
};

struct filearr_t   files;
int                state = ST_BETWEEN_FILE;
char               line_buf[1024];

struct fileinfo_t *cur_file;
struct revinfo_t  *cur_rev;

int                 rev_total;
struct revinfo_t  **rev_sorted;

struct usermap_t
{
  char *user;
  char *full;
};
struct usermaparr_t
{
  int               a, u;
  struct usermap_t *v;
};
struct usermaparr_t usermap;

struct oldlogentry_t
{
  int   year, month, day;
  char *file;
  char *author;
  char *text;
};
struct oldlog_t
{
  int a, u;
  struct oldlogentry_t *v;
};
struct oldlog_t oldlog;

int maxoldyear = -1;
int maxoldmonth = -1;
int maxoldday = -1;

  void
read_usermap(char *filename)
{
  FILE             *f;
  char              buf[1024];
  char              user[64];
  struct usermap_t *p;
  int               len;

  if (!filename || !*filename) return;
  if (!(f = fopen(filename, "r"))) return;
  while (fgets(buf, 1024, f) != NULL) {
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
      buf[len - 1] = 0;
    }
    XEXPAND2(usermap);
    p = &usermap.v[usermap.u++];
    sscanf(buf, "%s", user);
    p->user = xstrdup(user);
    p->full = xstrdup(buf + strlen(user) + 1);
  }
  fclose(f);
}

  char *
map_user(char *user)
{
  int i;
  for (i = 0; i < usermap.u; i++) {
    if (!strcmp(usermap.v[i].user, user)) return usermap.v[i].full;
  }
  return user;
}

int
get_line_length(char const *str)
{
  char const *p = str;
  while (*p && *p != '\n') p++;
  return p - str;
}

  int
rev_cmp_func(const void *vp1, const void *vp2)
{
  struct revinfo_t *rp1 = *(struct revinfo_t **) vp1;
  struct revinfo_t *rp2 = *(struct revinfo_t **) vp2;

  if (rp1->date < rp2->date) return 1;
  if (rp1->date > rp2->date) return -1;
  return 0;
}

char * monthnames[] =
{
  "Jan", "Feb", "Mar",
  "Apr", "May", "Jun",
  "Jul", "Aug", "Sep",
  "Oct", "Nov", "Dec"
};

int fgets_line;
int
checked_fgets(char *buf, int maxlen, FILE *f, char const *path)
{
  int len;

  if (!fgets(buf, maxlen, f)) return -1;
  fgets_line++;
  len = strlen(buf);
  if (len == maxlen - 1 && buf[len - 1] != '\n') {
    fprintf(stderr, "line %d is too long in `%s'\n", fgets_line, path);
    exit(1);
  }
  return len;
}

void
read_ChangeLog(char const *path)
{
  FILE *fin = 0;
  char  lbuf[8192];
  char  wdaybuf[8192];
  char  mbuf[8192];
  char  authbuf[8192];
  int   llen;
  char *msg = 0;

  int   year, month, day, n, hour, min, sec;

  strarray_t flist;
  int        i1, i2, i;

  oldlog.u = oldlog.a = 0;
  oldlog.v = 0;

  if (!(fin = fopen(path, "r"))) {
    fprintf(stderr, "cannot open file `%s'\n", path);
    exit(1);
  }

  fgets_line = 0;
  llen = checked_fgets(lbuf, sizeof(lbuf), fin, path);
  while (llen >= 0) {
    if (!strncmp(lbuf, "END", 3)) break;
    // now read date
    if (sscanf(lbuf, "%d-%d-%d%n", &year, &month, &day, &n) == 3) {
      // sanity check for new date format
      if (lbuf[n] != ' '
          || year < 1970 || year > 2050
          || month < 1 || month > 12
          || day < 1 || day > 31) {
        fprintf(stderr, "date format error: `%s'\n", lbuf);
        exit(1);
      }
    } else if (sscanf(lbuf, "%s %s %d %d:%d:%d %d%n",
                      wdaybuf, mbuf, &day, &hour, &min, &sec, &year, &n)==7) {
      // old date format, do sanity check
      for (month = 0; month < 12; month++) {
        if (!strcmp(monthnames[month], mbuf)) break;
      }
      if (month >= 12) {
        fprintf(stderr, "cannot parse month name: `%s'\n", mbuf);
        exit(1);
      }
      month++;

      if (lbuf[n] != ' '
          || year < 1970 || year > 2050
          || day < 1 || day > 31) {
        fprintf(stderr, "date format error: `%s'\n", lbuf);
        exit(1);
      }
    } else {
      fprintf(stderr, "cannot parse date: `%s'\n", lbuf);
      exit(1);
    }

    while (isspace(lbuf[n])) n++;
    while (isspace(lbuf[llen - 1])) llen--;
    lbuf[llen] = 0;
    strcpy(authbuf, lbuf + n);

    // debug
    //fprintf(stderr, "Date: %d-%d-%d, Author: `%s'\n", 
    //        year, month, day, authbuf);

    if (year > maxoldyear) {
      maxoldyear = year;
      maxoldmonth = month;
      maxoldday = day;
    } else if (year == maxoldyear) {
      if (month > maxoldmonth) {
        maxoldmonth = month;
        maxoldday = day;
      } else if (month == maxoldmonth) {
        if (day > maxoldday) {
          maxoldday = day;
        }
      }
    }

    if ((llen = checked_fgets(lbuf, sizeof(lbuf), fin, path)) < 0) break;
    if (lbuf[0] != '\n') goto _format_error;

    llen = checked_fgets(lbuf, sizeof(lbuf), fin, path);
    if (llen < 0) break;
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
      llen = checked_fgets(lbuf, sizeof(lbuf), fin, path);
      while (llen >= 0 && lbuf[0] == '\t') {
        if (!msg) msg = xstrmerge2(msg, lbuf + 1);
        else msg = xstrmerge2(msg, lbuf);
        llen = checked_fgets(lbuf, sizeof(lbuf), fin, path);
      }

      // debug
      //fprintf(stderr, "Message body: <%s>", msg);

      for (i = 0; i < flist.u; i++) {
        struct oldlogentry_t *p;
        XEXPAND2(oldlog);
        p = &oldlog.v[oldlog.u++];
        p->year = year;
        p->month = month;
        p->day = day;
        p->author = xstrdup(authbuf);
        p->text = xstrdup(msg);
        p->file = xstrdup(flist.v[i]);
      }

      xfree(msg);
      xstrarrayfree(&flist);

      if (llen < 0) break;
      if (lbuf[0] != '\n') goto _format_error;
      llen = checked_fgets(lbuf, sizeof(lbuf), fin, path);
      if (llen < 0 || lbuf[0] != '\t') break;
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

  return;

 _format_error:
  fprintf(stderr, "%s:%d: ChangeLog format error\n", path, fgets_line);
  exit(1);
}

char prev_header[1024];
char new_header[1024];

char *inpath = 0;
char *outpath = 0;
int   had_writes = 0;

void
exitfunc(void)
{
  if (outpath) remove(outpath);
}

static char const cvsid[] =
"$Id$";
static char const version[] = "1.0";
static char const copyright[] =
"Copyright (C) 1999-2005 Alexander Chernov <cher@ispras.ru>\n\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";

static char const usage[]=
"Usage: mkChangeLog [[[user_map] input_ChangeLog] output_ChangeLog]\n"
"Update ChangeLog information using CVS (or RCS) file logs.\n"
"The program expects CVS file logs on the standard input, so typical\n"
"usage might be: \"cvs log -l | mkChangeLog ARGUMENTS\".\n"
"\n"
"  Arguments:\n"
"  user_map         - file containing the map from cvs user id to\n"
"                     user strings in the form \"Name <address>\".\n"
"                     The file contains lines, each in the form\n"
"                     \"<login> <string>\".\n"
"  input_ChangeLog  - The name of input ChangeLog file. If this argument\n"
"                     is defined, the mkChangeLog utility prints\n"
"                     only new entries to the standard output.\n"
"  output_ChangeLog - The name of output ChangeLog file. If this argument\n"
"                     is defined, new entries are added to the beginning\n"
"                     of this file as well as printed to the standard\n"
"                     output. It is pretty valid to give the same\n"
"                     name (usually ChangeLog) to the second and third\n"
"                     arguments.\n\n"
"  Options supported:\n"
"  --help           - print this help screen.\n"
"  --version        - print version information.\n";

  int
main(int argc, char *argv[])
{
  FILE *fout = 0;
  FILE *fin = 0;

  if (argc == 2 && !strcmp(argv[1], "--help")) {
    printf("%s", usage);
    return 0;
  }
  if (argc == 2 && !strcmp(argv[1], "--version")) {
    int rev_major = 0;
    int rev_minor = 0;
    int rev_year  = 0;
    int rev_month = 0;
    int rev_day   = 0;
    int n;

    n = sscanf(cvsid, "%*s %*s %d.%d %d/%d/%d %*d:%*d:%*d %*s %*s $",
               &rev_major, &rev_minor, &rev_year, &rev_month, &rev_day);
    if (n != 5){
      printf("mkChangeLog, version %s\n%s\n", version, copyright);
      return 0;
    }
    printf("mkChangeLog, version %s (revision %d.%d, %d/%02d/%02d)\n"
           "%s\n", version, rev_major, rev_minor, rev_year, rev_month,
           rev_day, copyright);
    return 0;
  }

  if (argc > 1) {
    read_usermap(argv[1]);
    if (argc > 2) {
      read_ChangeLog(argv[2]);
      if (argc > 3) {
        inpath = xstrdup(argv[3]);
        outpath = xstrmerge2(inpath, ".tmp");
        fin = fopen(inpath, "r"); /* failure is ok */
        fout = fopen(outpath, "w");
        if (!fout) {
          fprintf(stderr, "cannot open output file `%s'\n", outpath);
          exit(1);
        }
        atexit(exitfunc);
      }
    }
  }

  while (fgets(line_buf, 1024, stdin) != NULL) {
    if (state == ST_COMMENT) {
      if (!strcmp(line_buf, "----------------------------\n")) {
        state = ST_BETWEEN_REV;
      } else if (!strcmp(line_buf, "=============================================================================\n")) {
        state = ST_BETWEEN_FILE;
      } else {
        if (cur_rev->text) {
          cur_rev->text = xstrmerge1(cur_rev->text, "\t");
        }
        cur_rev->text = xstrmerge1(cur_rev->text, line_buf);
      }
    } else if (state == ST_DESCRIPTION) {
      if (!strcmp(line_buf, "----------------------------\n")) {
        state = ST_BETWEEN_REV;
      } else if (!strcmp(line_buf, "=============================================================================\n")) {
        state = ST_BETWEEN_FILE;
      }
    } else if (state == ST_BETWEEN_REV) {
      if (!strncmp(line_buf, "revision", 8)) {
        char rev[32];

        if (sscanf(line_buf, "revision %s", rev) != 1) {
          fprintf(stderr, "failed to read revision line\n");
          continue;
        }
        state = ST_REV;
        XEXPAND2(cur_file->revs);
        cur_rev = &cur_file->revs.v[cur_file->revs.u++];
        cur_rev->rev = xstrdup(rev);
        cur_rev->file = xstrdup(cur_file->name);
      }
    } else if (state == ST_REV) {
      if (!strncmp(line_buf, "date", 4)) {
        int        year;
        int        month;
        int        day;
        int        hour;
        int        min;
        int        sec;
        int        tzoffset;
        char       user[32];
        int        user_len;
        struct tm  tm_time;
        struct tm *ptm;

        state = ST_COMMENT;
        if (sscanf(line_buf,
                   "date: %d/%d/%d %d:%d:%d;  author: %s",
                   &year, &month, &day, &hour, &min, &sec, user) != 7) {
          if (sscanf(line_buf,
                     "date: %d-%d-%d %d:%d:%d %d;  author: %s",
                     &year, &month, &day, &hour, &min, &sec, &tzoffset, user) != 8) {
            fprintf(stderr, "failed to read date: %s\n", line_buf);
            continue;
          }
        }
        user_len = strlen(user);
        if (user_len > 0 && user[user_len - 1] == ';') {
          user[user_len - 1] = 0;
        }
        memset(&tm_time, 0, sizeof(tm_time));
        tm_time.tm_sec  = sec;
        tm_time.tm_min  = min;
        tm_time.tm_hour = hour;
        tm_time.tm_mday = day;
        tm_time.tm_mon  = month - 1;
        tm_time.tm_year = year - 1900;
        tm_time.tm_isdst = -1;
        cur_rev->date = mktime(&tm_time);
        ptm = localtime(&cur_rev->date);
        if (cur_rev->date == (time_t) -1) {
          perror("");
          fprintf(stderr, "mktime failed\n");
          continue;
        }
        cur_rev->author = xstrdup(user);
        //fprintf(stderr, "file=%s rev=%s time=%lu user=%s\n", cur_rev->file, cur_rev->rev, (unsigned long) cur_rev->date,  user);
      }
    } else if (state == ST_BETWEEN_FILE) {
      if (!strncmp(line_buf, "RCS file:", 9)) {
        state = ST_HEADER;
        XEXPAND2(files);
        cur_file = &files.v[files.u++];
      }
    } else if (state == ST_HEADER) {
      if (!strncmp(line_buf, "description", 11)) {
        state = ST_DESCRIPTION;
      } else if (!strncmp(line_buf, "Working file", 12)) {
        char name[256];
        if (sscanf(line_buf, "Working file: %s", name) != 1) {
          fprintf(stderr, "failed to read Working file: string\n");
          continue;
        }
        cur_file->name = xstrdup(name);
      }
    } else {
      fprintf(stderr, "unhandled state %d\n", state);
      abort();
    }
  }

  {
    int i;

    rev_total = 0;
    for (i = 0; i < files.u; i++) {
      rev_total += files.v[i].revs.u;
    }
  }

  fprintf(stderr, "Total revisions: %d\n", rev_total);

  XCALLOC(rev_sorted, rev_total);
  {
    int i, j, k = 0;

    for (i = 0; i < files.u; i++) {
      if (!strcmp(files.v[i].name, "ChangeLog")) continue;
      if (!strcmp(files.v[i].name, ".cvsignore")) continue;
      if (!strcmp(files.v[i].name, "NEWS")) continue;
      if (!strcmp(files.v[i].name, "NEWS.RUS")) continue;

      for (j = 0; j < files.v[i].revs.u; j++) {
        // do not put revisions, older that the last day when
        // changelog ends
        if (maxoldyear > 0) {
          struct tm *ptm = localtime(&files.v[i].revs.v[j].date);
          //fprintf(stderr, "Checking date: %d-%02d-%02d\n",
          //        ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);
          if (ptm->tm_year + 1900 < maxoldyear) continue;
          else if (ptm->tm_year + 1900 == maxoldyear) {
            if (ptm->tm_mon + 1 < maxoldmonth) continue;
            else if (ptm->tm_mon + 1 == maxoldmonth) {
              if (ptm->tm_mday < maxoldday) continue;
            }
          }
          // try to find in the old records
          if (ptm->tm_year + 1900 == maxoldyear
              && ptm->tm_mon + 1 == maxoldmonth
              && ptm->tm_mday == maxoldday) {
            int k;

            for (k = 0; k < oldlog.u; k++) {
              struct oldlogentry_t *olp = &oldlog.v[k];
              if (olp->year == maxoldyear &&
                  olp->month == maxoldmonth &&
                  olp->day == maxoldday &&
                  !strcmp(olp->file, files.v[i].name) &&
                  !strcmp(olp->text, files.v[i].revs.v[j].text))
                break;
            }
            if (k < oldlog.u) {
#if 0
              fprintf(stderr, "Entry exists: %d-%02d-%02d <%s> <%s>\n",
                      maxoldyear, maxoldmonth, maxoldday,
                      oldlog.v[k].file, oldlog.v[k].text);
#endif
              continue;
            }
#if 0
            fprintf(stderr, "Entry not found: %d-%02d-%02d <%s> <%s>\n",
                    maxoldyear, maxoldmonth, maxoldday,
                    files.v[i].name, files.v[i].revs.v[j].text);
#endif
          }
        }
        if (files.v[i].revs.v[j].text)
          rev_sorted[k++] = &files.v[i].revs.v[j];
      }
    }
    rev_total = k;
  }

  qsort(rev_sorted, rev_total, sizeof(rev_sorted[0]), rev_cmp_func);
  prev_header[0] = 0;

  {
    int i;

    for (i = 0; i < rev_total; i++) {
      struct tm *ptm, *pntm;
      char       strt[128];
      int        k, j;
      char      *sep = "\t* ";
      int        linelen = 10;
      struct tm  otm;

      ptm = localtime(&rev_sorted[i]->date);
      otm = *ptm;
      sprintf(strt, "%d-%02d-%02d", ptm->tm_year + 1900,
              ptm->tm_mon + 1, ptm->tm_mday);
      //strt = asctime(ptm);

      for (k = i + 1; k < rev_total; k++) {
        if (strcmp(rev_sorted[i]->text, rev_sorted[k]->text)) break;
        pntm = localtime(&rev_sorted[k]->date);
        if (otm.tm_year != pntm->tm_year
            || otm.tm_mon != pntm->tm_mon
            || otm.tm_mday != pntm->tm_mday) break;
      }

      sprintf(new_header,
              "%.24s  %s\n\n", strt, map_user(rev_sorted[i]->author));
      if (strcmp(prev_header, new_header)) {
        printf("%s", new_header);
        if (fout) fprintf(fout, "%s", new_header);
        strcpy(prev_header, new_header);
        had_writes = 1;
      }

      for (j = i; j < k; j++) {
        linelen += printf("%s%s", sep, rev_sorted[j]->file);
        if (fout) fprintf(fout, "%s%s", sep, rev_sorted[j]->file);
        had_writes = 1;
        sep = ", ";
      }
      linelen += printf(":");
      if (fout) fprintf(fout, ":");
      had_writes = 1;
      if (linelen + get_line_length(rev_sorted[i]->text) > 79) {
        printf("\n\t%s\n", rev_sorted[i]->text);
        if (fout) fprintf(fout, "\n\t%s\n", rev_sorted[i]->text);
        had_writes = 1;
      } else {
        printf(" %s\n", rev_sorted[i]->text);
        if (fout) fprintf(fout, " %s\n", rev_sorted[i]->text);
        had_writes = 1;
      }
      i = j - 1;
    }
  }

  if (fout && !had_writes) {
    fclose(fout);
    if (fin) fclose(fin);
    fprintf(stderr, "No changes to `%s'\n", inpath);
    return 0;
  }

  if (fout) {
    if (fin) {
      int c;

      while ((c = getc(fin)) != EOF) putc(c, fout);
      fclose(fin);
    }
    fclose(fout);
    if (rename(outpath, inpath) < 0) {
      fprintf(stderr, "rename: %s to %s failed\n",
              outpath, inpath);
      exit(1);
    }
    outpath = 0;
  }

  return 0;
}

/* ========== XALLOC.C ========== */

/**
 * NAME:    out_of_mem
 * PURPOSE: report out of virtual memory condition
 */
  static void
out_of_mem(void)
{
  fputs("Failed to allocate more memory!\n", stderr);
  abort();
}

/**
 * NAME:    null_size
 * PURPOSE: report 0 size allocation error
 */
  static void
null_size(void)
{
  fputs("Null size allocation requested!\n", stderr);
  abort();
}

/**
 * NAME:    xmalloc
 * PURPOSE: wrapper over malloc function call
 * NOTE:    xmalloc never returns NULL
 */
  void *
xmalloc(size_t size)
{
  void *ptr;
  if (size == 0) null_size();
  ptr = malloc(size);
  if (ptr == NULL) out_of_mem();
  return ptr;
}

/**
 * NAME:    xcalloc
 * PURPOSE: wrapper over calloc function
 * NOTE:    xcalloc never returns NULL
 */
  void *
xcalloc(size_t nitems, size_t elsize)
{
  void *ptr;
  if (nitems == 0 || elsize == 0) null_size();
  ptr = calloc(nitems, elsize);
  if (ptr == NULL) out_of_mem();
  return ptr;
}

/**
 * NAME:    xfree
 * PURPOSE: wrapper over free function
 * NOTE:    accepts NULL pointer as argument
 */
  void
xfree(void *ptr)
{
  if (ptr == NULL) return;
  free(ptr);
}

/**
 * NAME:    xrealloc
 * PURPOSE: wrapper over realloc function
 * NOTE:    if ptr == NULL,  realloc = malloc
 *          if size == NULL, realloc = free
 *          if ptr == NULL && size == NULL, ?
 */
  void *
xrealloc(void *ptr, size_t size)
{
  if (ptr == NULL && size == 0) null_size();
  ptr = realloc(ptr,size);
  if (ptr == NULL) out_of_mem();
  return ptr;
}

/**
 * NAME:    xstrdup
 * PURPOSE: wrapper over strdup function
 * NOTE:    strdup(NULL) returns ""
 */
  char *
xstrdup(char const*str)
{
  char *ptr;
  if (str == NULL) str = "";
  ptr = strdup(str);
  if (ptr == NULL) out_of_mem();
  return ptr;
}

/**
 * NAME:    xmemdup
 * PURPOSE: returns a copy of the string in the heap
 * ARGS:    str  - string to copy (might not be \0 terminated)
 *          size - string length
 * RETURN:  copy of the string str with \0 terminator added
 */
  char *
xmemdup (char const *str, size_t size)
{
  char *ptr;
  if (str == NULL) str = "";
  ptr = xmalloc (size + 1);
  if (ptr == NULL) out_of_mem();
  memcpy (ptr, str, size);
  ptr[size] = 0;
  return ptr;
}

/**
 * NAME:    xstrmerge0
 * PURPOSE: concatenate two strings
 * ARGS:    str1 - string 1
 *          str2 - string 2
 * RETURN:  concatenation of two strings (allocated in heap)
 * NOTE:    str1 and str2 are freed via xfree call after concatenation
 */
  char *
xstrmerge0(char *str1, char *str2)
{
  char *res;

  if (str1 == NULL && str2 == NULL)
    {
      return NULL;
    }

  if (str1 == NULL)
    {
      return str2;
    }

  if (str2 == NULL)
    {
      return str1;
    }

  res = (char*) xmalloc(strlen(str1) + strlen(str2) + 1);
  strcpy(res, str1);
  strcat(res, str2);
  xfree(str1);
  xfree(str2);
  return res;
}

/**
 * NAME:    xstrmerge1
 * PURPOSE: concatenate two strings
 * ARGS:    str1 - string 1
 *          str2 - string 2
 * RETURN:  concatenation of two strings
 * NOTE:    str1 - freed after concatenation
 *          str2 - not freed
 */
  char *
xstrmerge1(char *str1, char const *str2)
{
  char *res;

  if (str1 == NULL && str2 == NULL)
    return NULL;

  if (str1 == NULL)
    return xstrdup(str2);

  if (str2 == NULL)
    return str1;

  res = (char*) xmalloc(strlen(str1) + strlen(str2) + 1);
  strcpy(res, str1);
  strcat(res, str2);
  xfree(str1);
  return res;
}

/**
 * NAME:    xstrmerge2
 * PURPOSE: concatenate two strings
 * ARGS:    str1 - string 1
 *          str2 - string 2
 * RETURN:  concatenation of two strings
 * NOTE:    str1 - not freed after concatenation
 *          str2 - not freed
 */
  char *
xstrmerge2(char const *str1, char const *str2)
{
  char *res;

  if (str1 == NULL && str2 == NULL)
    return NULL;

  if (str1 == NULL)
    return xstrdup(str2);

  if (str2 == NULL)
    return xstrdup(str1);

  res = (char*) xmalloc(strlen(str1) + strlen(str2) + 1);
  strcpy(res, str1);
  strcat(res, str2);
  return res;
}

/**
 * NAME:    xstrmerge3
 * PURPOSE: concatenate two strings
 * ARGS:    str1 - string 1
 *          str2 - string 2
 * RETURN:  concatenation of two strings
 * NOTE:    str1 - not freed
 *          str2 - freed after concatenation
 */
  char *
xstrmerge3(char const *str1, char *str2)
{
  char *res;

  if (!str1 && !str2) return 0;
  if (!str1)          return str2;
  if (!str2)          return xstrdup(str1);

  res = (char*) xmalloc(strlen(str1) + strlen(str2) + 1);
  strcpy(res, str1);
  strcat(res, str2);
  xfree(str2);
  return res;
}

/**
 * NAME:    xexpand
 * PURPOSE: expand expandable array of strings
 * ARGS:    arr - pointer to expandable array structure
 */
  void
xexpand(strarray_t *arr)
{
  if (arr->u < arr->a) return;

  if (!arr->a)
    {
      arr->a = 32;
      arr->v = (char**) xcalloc(arr->a, sizeof(char **));
      return;
    }

  arr->v = (char**) xrealloc(arr->v, arr->a * sizeof(char**) * 2);
  memset(arr->v + arr->a, 0, arr->a * sizeof(char**));
  arr->a *= 2;
}

/**
 * NAME:    xexpand2
 * PURPOSE: expand generic expandable array
 * ARGS:    arr    - pointer to expandable array structure
 *          elsize - size of an element of the array
 */
  void
xexpand2(arr, elsize)
     genarray_t  *arr;
     size_t       elsize;
{
  if (!arr) return;

  if (elsize <= 0) elsize = sizeof(int);
  if (arr->u < arr->a) return;

  if (!arr->a)
    {
      arr->a = 32;
      arr->v = xcalloc(arr->a, elsize);
      return;
    }

  arr->v = (void*) xrealloc(arr->v, arr->a * elsize * 2);
  memset((char*) arr->v + arr->a * elsize, 0, arr->a * elsize);
  arr->a *= 2;
}

/**
 * NAME:    xexpand3
 * PURPOSE: unconditionally expand the array
 * ARGS:    arr    - array to expand
 *          elsize - element size
 */
  void
xexpand3(arr, elsize)
     genarray_t  *arr;
     size_t       elsize;
{
  if (!arr) return;

  if (elsize <= 0) elsize = sizeof(int);

  if (!arr->a)
    {
      arr->a = 32;
      arr->v = xcalloc(arr->a, elsize);
      return;
    }

  arr->v = (void*) xrealloc(arr->v, arr->a * elsize * 2);
  memset((char*) arr->v + arr->a * elsize, 0, arr->a * elsize);
  arr->a *= 2;
}

/**
 * NAME:    xexpand4
 * PURPOSE: unconditionally expand the array
 * ARGS:    arr     - array to expand
 *          elsize  - element size
 *          newsize - new size of the array
 */
  void
xexpand4(arr, elsize, newsize)
     genarray_t *arr;
     size_t      elsize;
     int         newsize;
{
  int newsz;

  if (!arr) return;
  if (newsize <= arr->a) return;

  if (elsize <= 0) elsize = sizeof(int);
  newsz = arr->a;
  if (!newsz) newsz = 32;
  while (newsz < newsize)
    newsz *= 2;

  arr->v = (void*) xrealloc(arr->v, newsz * elsize);
  memset((char*) arr->v + arr->a * elsize, 0, (newsz - arr->a) * elsize);
  arr->a = newsz;
}

  void
xstrarrayfree(strarray_t *a)
{
  int i;

  if (!a) return;

  for (i = 0; i < a->u; i++) {
    xfree(a->v[i]);
  }
  xfree(a->v);
  a->u = a->a = 0;
  a->v = 0;
}
