/* -*- c -*- */

/* Copyright (C) 2000-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

struct revdb
{
  char          *file;
  int            major;
  int            minor;
  int            flag;
  unsigned long  summ;
};
struct revdb *revdb;
int revdb_u, revdb_a;
int revdb_updated = 0;

struct files
{
  char *file;
  int   major;
  int   minor;
  int   norev;
};
struct files *files;
int           files_u, files_a;

struct verdb
{
  char   *version;
  int     patch;
  int     revsum;
  time_t  time;
};
struct verdb *verdb;
int verdb_u, verdb_a;
int verdb_updated = 0;

int  has_modified = 0;
char major_version[64];
char full_version[64];
char version_string[1024];

char *variable_prefix = 0;

int svn_mode = 0;

int revdb_major = 0;
int revdb_minor = 0;

void
add_revdb_entry(char const *file, int major, int minor, unsigned long summ)
{
   if (revdb_u >= revdb_a) {
      if (!revdb_a) revdb_a = 8;
      revdb_a *= 2;
      if (!(revdb = realloc(revdb, revdb_a * sizeof(revdb[0])))) {
        fprintf(stderr, "out of heap memory\n");
        exit(1);
      }
   }

   if (!(revdb[revdb_u].file = strdup(file))) {
     fprintf(stderr, "out of heap memory\n");
     exit(1);
   }
   revdb[revdb_u].major = major;
   revdb[revdb_u].minor = minor;
   revdb[revdb_u].summ  = summ;
   revdb[revdb_u].flag  = 0;
   revdb_u++;
}

void
read_revdb(char const *name)
{
  FILE          *f;
  char           buf[78];
  char           fname[sizeof(buf)];
  char           idstr[sizeof(buf)];
  int            major, minor, n, x;
  unsigned long  checksum;
  char          *pid, *pd;

  if (!(f = fopen(name, "r"))) {
    fprintf(stderr, "cannot open database file '%s'\n", name);
    return;
  }

  while (fgets(buf, sizeof(buf), f)) {
    if (strlen(buf) >= sizeof(buf) - 1 &&
        buf[sizeof(buf) - 2] != '\n') {
      fprintf(stderr, "line too long in database file '%s'\n", name);
      exit(1);
    }
    if (buf[0] == '#') {
      if (!svn_mode) continue;
      if (!(pid = strstr(buf, "$" "Id" ":"))) continue;
      if (!(pd = strstr(pid + 4, "$"))) continue;
      memset(idstr, 0, sizeof(idstr));
      memcpy(idstr, pid + 4, (pd - pid) - 4);

      if (sscanf(idstr, "%s %d%n", fname, &x, &n) != 2
          || x < 0 || !isspace(idstr[n])) continue;
      revdb_major = x;
      revdb_minor = 0;

      //fprintf(stderr, "Revision db: %d\n", revdb_major);
      continue;
    }
    if (buf[0] == '\n') continue;
    if (sscanf(buf, "%s %d %d %lu %n",
               fname, &major, &minor, &checksum, &n) != 4
        || buf[n]
        || major < 0 || minor < 0) {
      fprintf(stderr, "line invalid in database file '%s'\n", name);
      exit(1);
    }
    add_revdb_entry(fname, major, minor, checksum);
  }
  if (ferror(f)) {
    fprintf(stderr, "read error from database file '%s'\n", name);
    exit(1);
  }

  fclose(f);
}

void
write_revdb(char const *name)
{
  FILE *f;
  int   i;

  remove(name); /* ignore error code */

  if (!(f = fopen(name, "w"))) {
    fprintf(stderr, "cannot open revdb '%s' for writing\n", name);
    exit(1);
  }

  for (i = 0; i < revdb_u; i++) {
    fprintf(f, "%s %d %d %lu\n",
            revdb[i].file, revdb[i].major, revdb[i].minor, revdb[i].summ);
  }

  fclose(f);
}

int
lookup_revdb(char const *file, int major, int minor, unsigned long *psumm)
{
  int i;

  for (i = 0; i < revdb_u; i++) {
    if (!strcmp(file, revdb[i].file)
        && revdb[i].major == major && revdb[i].minor == minor) {
      if (psumm) *psumm = revdb[i].summ;
      return 1;
    }
  }
  return 0;
}

void
add_files(char const *file, int major, int minor, int norev)
{
  if (files_u >= files_a) {
    if (!files_a) files_a = 8;
    files_a *= 2;
    if (!(files = realloc(files, files_a * sizeof(files[0])))) {
      fprintf(stderr, "out of heap memory\n");
      exit(1);
    }
  }
  if (!(files[files_u].file = strdup(file))) {
    fprintf(stderr, "out of heap memory\n");
    exit(1);
  }
  files[files_u].major = major;
  files[files_u].minor = minor;
  files[files_u].norev = norev;
  files_u++;
}

int
lookup_files(char const *file, int *pmajor, int *pminor, int *pnorev)
{
  int i;

  for (i = 0; i < files_u; i++)
    if (!strcmp(files[i].file, file)) {
      if (pmajor) *pmajor = files[i].major;
      if (pminor) *pminor = files[i].minor;
      if (pnorev) *pnorev = files[i].norev;
      return 1;
    }
  return 0;
}

void
add_verdb(char const *version, int patch, int revsum, time_t rtime)
{
  if (verdb_u >= verdb_a) {
    if (!verdb_a) verdb_a = 8;
    verdb_a *= 2;
    if (!(verdb = realloc(verdb, verdb_a * sizeof(verdb[0])))) {
      fprintf(stderr, "out of heap memory\n");
      exit(1);
    }
  }
  if (!(verdb[verdb_u].version = strdup(version))) {
    fprintf(stderr, "out of heap memory\n");
    exit(1);
  }
  verdb[verdb_u].patch  = patch;
  verdb[verdb_u].revsum = revsum;
  verdb[verdb_u].time = rtime;
  verdb_u++;
}

int
lookup_verdb(char const *version, int revsum, int *ppatch)
{
  int max_patch = -1;
  int i;

  for (i = 0; i < verdb_u; i++) {
    if (!strcmp(version, verdb[i].version)) {
      if (verdb[i].patch > max_patch) max_patch = verdb[i].patch;
      if (revsum == verdb[i].revsum) {
        if (ppatch) *ppatch = verdb[i].patch;
        return 1;
      }
    }
  }
  if (ppatch) *ppatch = max_patch;
  return 0;
}

void
read_verdb(char const *name)
{
  FILE          *f;
  char           buf[78];
  char           version[sizeof(buf)];
  int            patch, revsum, n, buflen, year, month, mday;
  struct tm      ttm;
  time_t         tt;

  if (!(f = fopen(name, "r"))) {
    fprintf(stderr, "cannot open database file '%s'\n", name);
    return;
  }

  while (fgets(buf, sizeof(buf), f)) {
    if (strlen(buf) >= sizeof(buf) - 1 &&
        buf[sizeof(buf) - 2] != '\n') {
      fprintf(stderr, "%s: line too long\n", name);
      exit(1);
    }
    if (buf[0] == '#') continue;
    if (buf[0] == '\n') continue;
    buflen = strlen(buf);
    while (buflen > 0 && isspace(buf[buflen - 1])) buf[--buflen] = 0;
    tt = 0;
    if (sscanf(buf, "%d %s %d %d/%d/%d%n",
               &revsum, version, &patch, &year, &month, &mday, &n) == 6
        && !buf[n]) {
      if (patch < 0 || revsum < 0 || year < 1970 || year > 2040
          || month < 1 || month > 12 || mday < 1 || mday > 31) {
        fprintf(stderr, "%s: line invalid\n", name);
        exit(1);
      }
      memset(&ttm, 0, sizeof(ttm));
      ttm.tm_isdst = -1;
      ttm.tm_year = year - 1900;
      ttm.tm_mon = month - 1;
      ttm.tm_mday = mday;
      if ((tt = mktime(&ttm)) == (time_t) -1) {
        fprintf(stderr, "%s: time specification is invalid\n", name);
        exit(1);
      }
    } else if (sscanf(buf, "%d %s %d%n",
               &revsum, version, &patch, &n) != 3
        || buf[n]
        || patch < 0 || revsum < 0) {
      fprintf(stderr, "%s: line invalid\n", name);
      exit(1);
    }
    add_verdb(version, patch, revsum, tt);
  }
  if (ferror(f)) {
    fprintf(stderr, "%s: read error\n", name);
    exit(1);
  }

  fclose(f);
}

void
write_verdb(char const *name)
{
  FILE *f;
  int   i;
  struct tm *ptm;

  remove(name); /* ignore error code */

  if (!(f = fopen(name, "w"))) {
    fprintf(stderr, "cannot open verdb '%s' for writing\n", name);
    exit(1);
  }

  for (i = 0; i < verdb_u; i++) {
    if (verdb[i].time) {
      ptm = localtime(&verdb[i].time);
      fprintf(f, "%d %s %d %04d/%02d/%02d\n",
              verdb[i].revsum, verdb[i].version, verdb[i].patch,
              ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);
              
    } else {
      fprintf(f, "%d %s %d\n",
              verdb[i].revsum, verdb[i].version, verdb[i].patch);
    }
  }

  fclose(f);
}

void
read_version(char const *name)
{
  FILE *f;
  char  line[64];
  int   n;

  if (!(f = fopen(name, "r"))) {
    fprintf(stderr, "cannot open version file '%s'\n", name);
    exit(1);
  }
  if (!fgets(line, sizeof(line), f)) {
    fprintf(stderr, "%s: cannot read first line\n", name);
    exit(1);
  }
  fclose(f);
  if (strlen(line) >= sizeof(line) - 1) {
    fprintf(stderr, "%s: string is too long\n", name);
    exit(1);
  }
  if (sscanf(line, " %s %n", major_version, &n) != 1) {
    fprintf(stderr, "%s: cannot read version\n", name);
    exit(1);
  }
  if (line[n]) {
    fprintf(stderr, "%s: garbage after version\n", name);
    exit(1);
  }
  printf("version: %s\n", major_version);
}

void
read_build(char const *name, int *pbuild)
{
  FILE *f;

  if (pbuild) *pbuild = 0;
  if (!(f = fopen(name, "r"))) return;
  if (fscanf(f, "%d", pbuild) != 1) {
    fprintf(stderr, "%s: cannot read build number\n", name);
    exit(1);
  }
  fscanf(f, " ");
  if (getc(f) != EOF) {
    fprintf(stderr, "%s: garbage after build number\n", name);
    exit(1);
  }
  fclose(f);
}

void
write_build(char const *name, int build)
{
  FILE *f;

  remove(name);

  if (!(f = fopen(name, "w"))) {
    fprintf(stderr, "%s: cannot open file for writing\n", name);
    exit(1);
  }
  fprintf(f, "%d\n", build);
  fclose(f);
}

void
write_output(char const *name)
{
  FILE   *f;
  char   *s, *p;
  time_t  t;

  t = time(0);
  s = ctime(&t);
  if ((p = strchr(s, '\n'))) *p = 0;
  if ((p = strchr(s, '\r'))) *p = 0;

  remove(name);
  if (!(f = fopen(name, "w"))) {
    fprintf(stderr, "%s: cannot open for writing\n", name);
    exit(1);
  }
  if (!variable_prefix) variable_prefix = "compile";
  fprintf(f,
          "/* THIS IS AUTOGENERATED FILE */\n"
          "char const %s_version[] = \"%s\";\n"
          "char const %s_date[] = \"%s\";\n",
          variable_prefix, version_string, variable_prefix, s);
  fclose(f);
}

unsigned long
count_line_summ(unsigned long insumm, char const *str)
{
  char unsigned const *s = (unsigned const char*) str;

  /* stupid... */
  for (; *s; s++) insumm += *s;
  return insumm;
}

int
scan_file(char const *name, int *pmajor, int *pminor, unsigned long *psumm)
{
  FILE *f;
  char  buf[1024], idstr[sizeof(buf)], filestr[sizeof(buf)];
  char *pid;
  char *pd;
  char *s, *t;
  int   name_len = strlen(name);
  int   file_len;
  int   no_match;
  int   was_error = 0;
  int   nn;

  unsigned long summ = 0;
  int           major = -1, minor = -1, new_major, new_minor;

  if (!(f = fopen(name, "r"))) {
    fprintf(stderr, "scan_file: %s: cannot open\n", name);
    return -1;
  }
  while (fgets(buf, sizeof(buf), f)) {
    if (strlen(buf) >= sizeof(buf) - 1
        && buf[sizeof(buf) - 2] != '\n') {
      fprintf(stderr, "scan_file: %s: line is too long\n", name);
      fclose(f);
      return -1;
    }

    /* add checksumm of the line */
    summ = count_line_summ(summ, buf);

    /* check for Id */
    if (!(pid = strstr(buf, "$" "Id" ":"))) continue;
    if (!(pd = strstr(pid + 4, "$"))) continue;
    for (s = pid + 4, t = idstr; s < pd; s++, t++)
      *t = *s;
    *t = 0;

    if (svn_mode) {
      if (sscanf(idstr, "%s %d%n", filestr, &new_major, &nn) != 2) {
        fprintf(stderr, "scan_file: %s: cannot parse Id line\n", name);
        continue;
      }
      if (new_major < 0) {
        fprintf(stderr, "scan_file: %s: bad revision number\n", name);
        continue;
      }
      new_minor = 0;
    } else {
      if (sscanf(idstr," %[^,],v %d.%d",filestr,&new_major,&new_minor) != 3) {
        fprintf(stderr, "scan_file: %s: cannot parse Id line\n", name);
        continue;
      }
      if (new_major < 0 || new_minor < 0) {
        fprintf(stderr, "scan_file: %s: bad revision number\n", name);
        continue;
      }
    }
    //fprintf(stderr, "file = '%s', major = %d, minor = %d\n",
    //        filestr, major, minor);

    file_len = strlen(filestr);
    no_match = 0;
    if (file_len > name_len) no_match = 1;
    else if (file_len == name_len) {
      if (strcmp(name, filestr)) no_match = 1;
    } else /* file_len < name_len */ {
      if (strcmp(name + name_len - file_len, filestr)) no_match = 1;
      else {
        /* FIXME: check for dos separator? */
        if (name[name_len - file_len - 1] != '/') no_match = 1;
      }
    }
    if (no_match) {
      fprintf(stderr, "scan_file: %s: file names do not match\n", name);
      continue;
    }
    if (major == -1 && !was_error) {
      major = new_major;
      minor = new_minor;
    } else if (major != new_major || minor != new_minor) {
      fprintf(stderr, "scan_file: %s: inconsistant revision number\n",
              name);
      was_error = 1;
      major = minor = -1;
    }
  }
  if (ferror(f)) {
    fprintf(stderr, "scan_file: %s: read error\n", name);
    fclose(f);
    return -1;
  }
  fclose(f);

  if (psumm)  *psumm = summ;
  if (pmajor) *pmajor = major;
  if (pminor) *pminor = minor;

  if (major == -1 && !was_error) {
    fprintf(stderr, "scan_file: %s: no revision information\n", name);
    return 0;
  }

  return 1;
}

int
first_patch(char const *version)
{
  int l = strlen(version);

  if (l > 3 && !strcmp(version + l - 3, "pre")) {
    return 1;
  } else {
    return 0;
  }
}

void
make_full_version(char const *version, int patch)
{
  int l = strlen(version);

  if (l > 3 && !strcmp(version + l - 3, "pre")) {
    sprintf(full_version, "%s%d", version, patch);
  } else {
    sprintf(full_version, "%s.%d", version, patch);
  }
}

void
report_usage(void)
{
  puts("Usage: revinfo [OPTS]... FILES...\n"
       "Options are:\n"
       "  -n        - enable new major/minor version\n"
       "  -p        - disable patch level increase\n"
       "  -C        - put updated database files in CVS/SVN\n"
       "  -S        - SVN mode\n"
       "  -x        - do not commit revision database to version control\n"
       "  -r FILE   - specify revision database (default - revdb)\n"
       "  -d FILE   - specify version database (default - verdb)\n"
       "  -v FILE   - specify version file (default - VERSION)\n"
       "  -V STRING - specify version in string\n"
       "  -b FILE   - specify build number file (default - .build)\n"
       "  -o FILE   - specify output file (default - version.c)\n");
  exit(0);
}

char cmdline[1024];

int
main(int argc, char *argv[])
{
  char *revdb_file = "revdb";
  char *verdb_file = "verdb";
  char *version_file = "VERSION";
  char *output_file = "version.c";
  char *build_file = ".build";
  int   i = 1, r;
  unsigned long summ = 0, oldsumm;
  int major, minor;
  int revsumm, patch;
  int enable_new_version = 0;
  int disable_patch_inc = 0;
  int has_norev = 0;
  int build;
  int use_cvs = 0;
  int do_not_commit_revdb = 0;

  if (argc == 1) report_usage();

  while (1) {
    if (!strcmp(argv[i], "-r")) {
      if (++i >= argc) {
        fprintf(stderr, "option '-r' expects an argument\n");
        exit(1);
      }
      revdb_file = argv[i++];
    } else if (!strcmp(argv[i], "-d")) {
      if (++i >= argc) {
        fprintf(stderr, "option '-d' expects an argument\n");
        exit(1);
      }
      verdb_file = argv[i++];
    } else if (!strcmp(argv[i], "-v")) {
      if (++i >= argc) {
        fprintf(stderr, "option '-v' expects an argument\n");
        exit(1);
      }
      version_file = argv[i++];
    } else if (!strcmp(argv[i], "-V")) {
      if (++i >= argc) {
        fprintf(stderr, "option '-V' expects an argument\n");
        exit(1);
      }
      version_file = 0;
      strcpy(major_version, argv[i++]);
    } else if (!strcmp(argv[i], "-b")) {
      if (++i >= argc) {
        fprintf(stderr, "option '-b' expects an argument\n");
        exit(1);        
      }
      build_file = argv[i++];
    } else if (!strcmp(argv[i], "-P")) {
      if (++i >= argc) {
        fprintf(stderr, "option '-P' expects an argument\n");
        exit(1);        
      }
      variable_prefix = argv[i++];
    } else if (!strcmp(argv[i], "-o")) {
      if (++i >= argc) {
        fprintf(stderr, "option '-o' expects an argument\n");
        exit(1);        
      }
      output_file = argv[i++];
    } else if (!strcmp(argv[i], "-n")) {
      i++;
      enable_new_version = 1;
    } else if (!strcmp(argv[i], "-p")) {
      i++;
      disable_patch_inc = 1;
    } else if (!strcmp(argv[i], "-C")) {
      i++;
      use_cvs = 1;
    } else if (!strcmp(argv[i], "-S")) {
      i++;
      svn_mode = 1;
    } else if (!strcmp(argv[i], "-x")) {
      i++;
      do_not_commit_revdb = 1;
    } else {
      break;
    }
  }
  if (i >= argc) report_usage();

  if (getenv("REVINFO_NO_COMMIT")) do_not_commit_revdb = 1;

  if (version_file) read_version(version_file);
  read_revdb(revdb_file);
  read_verdb(verdb_file);

  for (; i < argc; i++) {
    r = scan_file(argv[i], &major, &minor, &summ);
    if (r < 0) return 1; /* FIXME: is it ok? */
    if (r == 0) {
      /* no revision information */
      add_files(argv[i], 0, 0, 1);
      has_norev = 1;
    } else {
      add_files(argv[i], major, minor, 0);
      r = lookup_revdb(argv[i], major, minor, &oldsumm);
      if (!r) {
        fprintf(stderr,"%s,v %d.%d not in database\n",
                argv[i], major, minor);
        add_revdb_entry(argv[i], major, minor, summ);
        revdb_updated = 1;
      } else {
        if (summ != oldsumm) {
          fprintf(stderr,"%s,v %d.%d is modified\n",
                  argv[i], major, minor);
          has_modified = 1;
        }
      }
    }
  }

  /* scan for missing files */
  for (i = 0; i < revdb_u; i++) {
    int j, max_major, max_minor, f_major, f_minor, f_norev;

    if (revdb[i].flag) continue; /* already seen */
    revdb[i].flag = 1;
    max_major = revdb[i].major;
    max_minor = revdb[i].minor;
    for (j = i + 1; j < revdb_u; j++) {
      if (revdb[j].flag) continue;
      if (strcmp(revdb[i].file, revdb[j].file)) continue;
      revdb[j].flag = 1;
      if (revdb[j].major > max_major) {
        max_major = revdb[j].major;
        max_minor = revdb[j].minor;
      } else if (revdb[j].major == max_major && revdb[j].minor > max_minor) {
        max_minor = revdb[j].minor;
      }
    }

    if (!lookup_files(revdb[i].file, &f_major, &f_minor, &f_norev)) {
      fprintf(stderr, "%s,v %d.%d deleted?\n",
              revdb[i].file, max_major, max_minor);
      //return 1;                 /* FIXME */
    } else {
      if (f_norev) {
        fprintf(stderr, "%s,v %d.%d replaced with new file?\n",
                revdb[i].file, max_major, max_minor);
        return 1;               /* FIXME */
      }
      if (f_major < max_major
          || (f_major == max_major && f_minor < max_minor)) {
        fprintf(stderr, "%s,v %d.%d decreased revision number\n",
                revdb[i].file, max_major, max_minor);
        return 1;               /* FIXME */
      }
    }
  }

  /* calculate revision summ */
  if (svn_mode) {
    revsumm = -1;
    for (i = 0; i < files_u; i++) {
      if (!files[i].norev && revsumm < files[i].major)
        revsumm = files[i].major;
    }
    if (revdb_major > revsumm) revsumm = revdb_major;
    printf("max revision: %d\n", revsumm);
  } else {
    revsumm = 0;
    for (i = 0; i < files_u; i++) {
      if (files[i].norev) { /*revsumm++;*/ }
      else revsumm += files[i].major + files[i].minor;
    }
    printf("revision summ: %d\n", revsumm);
  }

  if (!lookup_verdb(major_version, revsumm, &patch) && patch == -1
      && !enable_new_version) {
    strcat(major_version, "pre");
    enable_new_version = 1;
  }

  if (!lookup_verdb(major_version, revsumm, &patch)) {
    /* no version corresponds to the given revsumm */
    if (patch == -1) {
      /* don't even have this major */
      if (has_modified || has_norev || disable_patch_inc) {
        /* probably we're in preparation for new version */
        /* delay new version until files are checked in */
        read_build(build_file, &build);
        build++;
        write_build(build_file, build);
        sprintf(version_string, "<new version> #%d", build);
      } else {
        patch = first_patch(major_version);
        add_verdb(major_version, patch, revsumm, time(0));
        verdb_updated = 1;
        write_build(build_file, 0);
        make_full_version(major_version, patch);
        sprintf(version_string, "%s", full_version);
      }
    } else {
      if (!has_modified && !has_norev && disable_patch_inc
          && use_cvs && svn_mode) {
        write_build(build_file, 0);
        make_full_version(major_version, patch);
        sprintf(version_string, "%s+ (SVN r%d)", full_version, revsumm);
      } else if ((has_modified || has_norev)
                 && disable_patch_inc && use_cvs && svn_mode) {
        read_build(build_file, &build);
        build++;
        write_build(build_file, build);
        make_full_version(major_version, patch);
        sprintf(version_string, "%s+ (SVN r%d) #%d", full_version, revsumm,
                build);
      } else if (has_modified || has_norev || disable_patch_inc) {
        read_build(build_file, &build);
        build++;
        write_build(build_file, build);
        make_full_version(major_version, patch);
        sprintf(version_string, "%s #%d", full_version, build);
      } else {
        /* increase a minor */
        patch++;
        add_verdb(major_version, patch, revsumm, time(0));
        verdb_updated = 1;
        write_build(build_file, 0);
        make_full_version(major_version, patch);
        sprintf(version_string, "%s", full_version);
      }
    }
  } else {
    if (has_modified || has_norev) {
      /* a modified version */
      read_build(build_file, &build);
      build++;
      write_build(build_file, build);
      make_full_version(major_version, patch);
      sprintf(version_string, "%s #%d", full_version, build);
    } else {
      /* got stock version */
      make_full_version(major_version, patch);
      sprintf(version_string, "%s", full_version);
    }
  }

  write_output(output_file);
  if (revdb_updated) {
    write_revdb(revdb_file);
    if (use_cvs && !do_not_commit_revdb) {
      if (svn_mode) {
        sprintf(cmdline, "svn ci -m \"\" %s", revdb_file);
      } else {
        sprintf(cmdline, "cvs ci -m \"\" %s", revdb_file);
      }
      printf("doing: %s\n", cmdline);
      system(cmdline);
    }
  }
  if (verdb_updated) {
    write_verdb(verdb_file);
    if (use_cvs) {
      if (svn_mode) {
        sprintf(cmdline, "svn ci -m \"\" %s", verdb_file);
      } else {
        sprintf(cmdline, "cvs ci -m \"\" %s", verdb_file);
      }
      printf("doing: %s\n", cmdline);
      system(cmdline);
    }
  }

  return 0;
}
