/* Copyright (C) 2006-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "svn_xmllog.h"
#include "usermap.h"
#include "xalloc.h"
#include "expat_iface.h"
#include "changelog.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <limits.h>

static char *progname;

static void
fatal(char const *format, ...)
{
  va_list args;
  char buf[512];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  fprintf(stderr, "%s: %s\n", progname, buf);
  exit(2);
}

static char *ignored_entries[] =
{
  "ChangeLog",
  "NEWS",
  "NEWS.RUS",

  0,
};

static char *xmllog_file;
static char *usermap_file;
static struct xmllog_root *xmllog;
static char *usermap_file;
static usermap_t usermap;
static char *input_file;
static char *output_file;
static changelog_t oldlog;
static char *prefix;
static char *strip_prefix;
static int silent_flag;
static char tmp_output_file[PATH_MAX];
static int new_entries_num;
static int ignore_subdirs;
static int latest_revision_flag;

static void
filter_file_prefix(struct xmllog_root *root, const char *prefix)
{
  int ientry, ipath, pref_len, j;
  struct xmllog_entry *pentry;
  struct xmllog_path *ppath;

  pref_len = strlen(prefix);
  for (ientry = 0; ientry < root->e.u; ientry++) {
    pentry = root->e.v[ientry];
    for (ipath = 0; ipath < pentry->paths.u; ipath++) {
      ppath = pentry->paths.v[ipath];
      if (strncmp(prefix, ppath->path, pref_len) != 0) {
        for (j = ipath + 1; j < pentry->paths.u; j++)
          pentry->paths.v[j - 1] = pentry->paths.v[j];
        pentry->paths.u--;
        ipath--;
      }
    }
  }
}

static void
strip_file_prefix(struct xmllog_root *root, const char *prefix)
{
  int ientry, ipath, pref_len, curlen, j;
  struct xmllog_entry *pentry;
  struct xmllog_path *ppath;
  char *s;

  pref_len = strlen(prefix);
  for (ientry = 0; ientry < root->e.u; ientry++) {
    pentry = root->e.v[ientry];
    for (ipath = 0; ipath < pentry->paths.u; ipath++) {
      ppath = pentry->paths.v[ipath];
      curlen = strlen(ppath->path);
      if (curlen <= pref_len) {
        for (j = ipath + 1; j < pentry->paths.u; j++)
          pentry->paths.v[j - 1] = pentry->paths.v[j];
        pentry->paths.u--;
        ipath--;
      } else if (!strncmp(prefix, ppath->path, pref_len)) {
        s = xstrdup(ppath->path + pref_len);
        xfree(ppath->path);
        ppath->path = s;
      }
    }
  }
}

static int
check_entry(const char *str)
{
  const char *s = str;

  if (!s) return 0;
  if (*s++ != '*') return 0;
  if (*s++ != ' ') return 0;
  while (1) {
    while (*s && *s != ':' && *s != ',' && *s != '\n') s++;
    if (*s != ':' && *s != ',') return 0;
    if (*s == ':') return 1;
    s++;
    if (*s++ != ' ') return 0;
  }
}

static void
split_to_lines(char const *str, strarray_t *pl)
{
  char const *p, *s;
  int i, l;

  memset(pl, 0, sizeof(*pl));
  if (!str) return;

  s = str;
  while (1) {
    p = s;
    while (*p && *p != '\n') p++;
    if (!*p) {
      if (p > s) {
        xexpand(pl);
        pl->v[pl->u] = xmemdup(s, p - s);
        pl->u++;
      }
      break;
    }
    xexpand(pl);
    pl->v[pl->u] = xmemdup(s, p - s);
    pl->u++;
    s = p + 1;
  }

  // strip trailing spaces on each line
  for (i = 0; i < pl->u; i++) {
    l = strlen(pl->v[i]);
    while (l > 0 && isspace(pl->v[i][l - 1]))
      pl->v[i][--l] = 0;
  }

  // strip trailing empty lines
  while (pl->u > 0 && !pl->v[pl->u - 1][0]) {
    xfree(pl->v[pl->u - 1]); pl->v[pl->u - 1] = 0;
    pl->u--;
  }
}

static void
mark_correct_entries(struct xmllog_root *root)
{
  int ientry;
  struct xmllog_entry *pentry;

  for (ientry = 0; ientry < root->e.u; ientry++) {
    pentry = root->e.v[ientry];
    pentry->good_msg = check_entry(pentry->msg);
    split_to_lines(pentry->msg, &pentry->msgl);
  }
}

static void
output_tabbed_text(FILE *out, strarray_t *pl)
{
  int i;

  for (i = 0; i < pl->u; i++) {
    if (pl->v[i][0]) {
      fprintf(out, "\t%s\n", pl->v[i]);
    } else if (i < pl->u - 1 && pl->v[i + 1][0] != '*') {
      fputs("\t\n", out);
    } else {
      putc('\n', out);
    }
  }
}

static void
output_new_log(FILE *out,
               struct xmllog_root *root,
               int revision,    /* 0, if not specified */
               int year,
               int month,
               int day)
{
  int ie, in;
  struct xmllog_entry *pe;
  char *name;

  for (ie = 0; ie < root->e.u; ie++) {
    pe = root->e.v[ie];

    /*
    fprintf(stderr, ">>%d,%d,%d,%d\n",
            pe->revision, pe->date.year, pe->date.mon,
            pe->date.mday);
    */

    if (!pe->paths.u) continue;
    if (!pe->msgl.u) continue;
    if (revision > 0 && pe->revision <= revision) return;
    if (year > 0) {
      if (pe->date.year < year) return;
      if (pe->date.year == year) {
        if (pe->date.mon < month) return;
        if (pe->date.mon == month) {
          if (pe->date.mday < day) return;
        }
      }
    }

    name = usermap_lookup(&usermap, pe->author);
    if (!name) name = pe->author;

    fprintf(out, "%04d-%02d-%02d (r%d) %s\n\n",
            pe->date.year, pe->date.mon, pe->date.mday,
            pe->revision, name);
    if (pe->good_msg) {
      output_tabbed_text(out, &pe->msgl);
      fprintf(out, "\n");
    } else {
      fprintf(out, "\t* ");
      for (in = 0; in < pe->paths.u; in++) {
        if (in > 0) fprintf(out, ", ");
        fprintf(out, "%s", pe->paths.v[in]->path);
      }
      fprintf(out, ":\n");
      output_tabbed_text(out, &pe->msgl);
      fprintf(out, "\n");
    }
  }
}

static int
count_new_entries(struct xmllog_root *root,
                  int revision,
                  int year,
                  int month,
                  int day)
{
  int ie, count = 0;
  struct xmllog_entry *pe;

  for (ie = 0; ie < root->e.u; ie++) {
    pe = root->e.v[ie];

    if (!pe->paths.u) continue;
    if (revision > 0 && pe->revision <= revision) break;
    if (year > 0) {
      if (pe->date.year < year) break;
      if (pe->date.year == year) {
        if (pe->date.mon < month) break;
        if (pe->date.mon == month) {
          if (pe->date.mday < day) break;
        }
      }
    }
    count++;
  }
  return count;
}

static void
skip_ignored_entries(struct xmllog_root *root, int ignore_subdirs)
{
  int ie, in, j;
  struct xmllog_entry *pe;

  for (ie = 0; ie < root->e.u; ie++) {
    pe = root->e.v[ie];
    for (in = 0; in < pe->paths.u; in++) {
      for (j = 0; ignored_entries[j]; j++)
        if (!strcmp(ignored_entries[j], pe->paths.v[in]->path))
          break;
      if (ignored_entries[j]) {
        for (j = in + 1; j < pe->paths.u; j++)
          pe->paths.v[j - 1] = pe->paths.v[j];
        pe->paths.u--;
        in--;
        continue;
      }
      if (ignore_subdirs && strchr(pe->paths.v[in]->path, '/')) {
        for (j = in + 1; j < pe->paths.u; j++)
          pe->paths.v[j - 1] = pe->paths.v[j];
        pe->paths.u--;
        in--;
        continue;
      }
    }
  }
}

static void
copy_file(FILE *in, FILE *out)
{
  char buf[4096];
  int r;

  while ((r = fread(buf, 1, sizeof(buf), in)) > 0)
    fwrite(buf, 1, r, out);
}

static void
copy_file_2(char const *path, FILE *out)
{
  FILE *in;

  if (!(in = fopen(path, "r"))) return;
  copy_file(in, out);
  fclose(in);
}

static int
revision_sort_func(const void *vp1, const void *vp2)
{
  const struct xmllog_entry *p1 = *(const struct xmllog_entry**) vp1;
  const struct xmllog_entry *p2 = *(const struct xmllog_entry**) vp2;

  if (p1->revision < p2->revision) return 1;
  if (p1->revision > p2->revision) return -1;
  return 0;
}

static char const cvsid[] =
"$Id$";
static char const version[] = "1.0";
static char const copyright[] =
"Copyright (C) 1999-2006 Alexander Chernov <cher@ispras.ru>\n\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";

static char const usage[]=
"Usage: mkChangeLog2 [OPTIONS]...\n"
"Update ChangeLog information using SVN XML logs.\n"
"The program expects SVN XML verbose log on the standard input, so typical\n"
"usage might be: \"svn log -v --xml | mkChangeLog2 [OPTIONS]...\".\n"
"\n"
"  Options supported:\n"
"  --help             - print this help screen.\n"
"  --version          - print version information.\n"
"  --user-map=FILE    - specify the name of the user map file\n"
"  --input=FILE       - the old ChangeLog to update\n"
"  --output=FILE      - the output ChangeLog (may be the same, as --input)\n"
"  --prefix=P         - ignore the entries not starting with P\n"
"  --strip-prefix=P   - remove the specified prefix P from SVN paths\n"
"  --silent           - do not output the new ChangeLog entries to stdout\n"
"  --ignore-subdirs   - ignore entries in subdirectories\n"
"  --latest-revision  - print the latest revision in the ChangeLog\n";

static void
print_help(void)
{
  printf("%s", usage);
  exit(0);
}

static void
print_version(void)
{
  int revision, year, mon, mday;

  if (sscanf(cvsid, "%*s %*s %d %d-%d-%d",
             &revision, &year, &mon, &mday) != 4) {
    printf("mkChangeLog2, version %s\n%s\n", version, copyright);
  } else {
    printf("mkChangeLog2, version %s (revision %d, %d/%02d/%02d)\n"
           "%s\n", version, revision, year, mon, mday, copyright);
  }

  exit(0);
}

int
main(int argc, char *argv[])
{
  int i;
  FILE *out;

  progname = argv[0];

  i = 1;
  while (i < argc) {
    if (!strcmp(argv[i], "--version")) {
      print_version();
    } else if (!strcmp(argv[i], "--help")) {
      print_help();
    } else if (!strncmp(argv[i], "--user-map=", 11)) {
      usermap_file = argv[i] + 11;
      i++;
    } else if (!strncmp(argv[i], "--input=", 8)) {
      input_file = argv[i] + 8;
      i++;
    } else if (!strncmp(argv[i], "--output=", 9)) {
      output_file = argv[i] + 9;
      i++;
    } else if (!strncmp(argv[i], "--prefix=", 9)) {
      prefix = argv[i] + 9;
      i++;
    } else if (!strncmp(argv[i], "--strip-prefix=", 15)) {
      strip_prefix = argv[i] + 15;
      i++;
    } else if (!strcmp(argv[i], "--silent")) {
      silent_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "--ignore-subdirs")) {
      ignore_subdirs = 1;
      i++;
    } else if (!strcmp(argv[i], "--latest-revision")) {
      latest_revision_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (!strncmp(argv[i], "--", 2)) {
      fatal("invalid option `%s'\n", argv[i]);
      return 1;
    } else {
      break;
    }
  }
  if (i != argc) fatal("invalid arguments");

  if (!latest_revision_flag) {
    if (!xmllog_file) {
      xmllog = svnlog_build_tree_file("<stdin>", stdin, stderr);
    } else {
      xmllog = svnlog_build_tree(xmllog_file, stderr);
    }
    if (!xmllog) return 1;
    if (xmllog->e.u > 0) {
      qsort(xmllog->e.v, xmllog->e.u, sizeof(xmllog->e.v[0]),
            revision_sort_func);
    }
  }

  if (usermap_file && !latest_revision_flag) {
    if (usermap_parse(usermap_file, stderr, &usermap) < 0)
      return 1;
  }

  if (input_file) {
    if (changelog_read(input_file, &oldlog, stderr) < 0)
      return 1;
  }

  if (latest_revision_flag) {
    printf("%d\n", oldlog.maxrevision);
    return 0;
  }

  /*
  fprintf(stderr, "%d,%d,%d,%d\n",
          oldlog.maxrevision, oldlog.maxyear, oldlog.maxmonth,
          oldlog.maxday);
  */

  if (prefix) {
    filter_file_prefix(xmllog, prefix);
  }

  if (strip_prefix) {
    strip_file_prefix(xmllog, strip_prefix);
  }

  mark_correct_entries(xmllog);
  skip_ignored_entries(xmllog, ignore_subdirs);

  new_entries_num = count_new_entries(xmllog,
                                      oldlog.maxrevision, oldlog.maxyear,
                                      oldlog.maxmonth, oldlog.maxday);
  if (!new_entries_num && input_file && output_file
      && !strcmp(input_file, output_file)) {
    // nothing to do
    return 0;
  }

  if (!output_file) {
    output_new_log(stdout, xmllog, 
                   oldlog.maxrevision, oldlog.maxyear,
                   oldlog.maxmonth, oldlog.maxday);
    if (input_file) {
      copy_file_2(input_file, stdout);
    }
  } else {
    if (!input_file || strcmp(input_file, output_file) != 0) {
      if (!(out = fopen(output_file, "w")))
        fatal("cannot open output file %s", output_file);
      output_new_log(out, xmllog, 
                     oldlog.maxrevision, oldlog.maxyear,
                     oldlog.maxmonth, oldlog.maxday);
      if (input_file) {
        copy_file_2(input_file, out);
      }
      fclose(out);
    } else {
      snprintf(tmp_output_file, sizeof(tmp_output_file), "%s.tmp", output_file);
      if (!(out = fopen(tmp_output_file, "w")))
        fatal("cannot open output file %s", output_file);
      output_new_log(out, xmllog, 
                     oldlog.maxrevision, oldlog.maxyear,
                     oldlog.maxmonth, oldlog.maxday);
      if (input_file) {
        copy_file_2(input_file, out);
      }
      fclose(out);
      rename(tmp_output_file, output_file);
    }

    if (!silent_flag) {
      output_new_log(stdout, xmllog,
                     oldlog.maxrevision, oldlog.maxyear,
                     oldlog.maxmonth, oldlog.maxday);
    }
  }

  return 0;
}
