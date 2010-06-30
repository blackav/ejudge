/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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

#include "../mime_type.h"
#include "../ej_process.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>

extern char **environ;

int
remove_directory_recursively(
        const unsigned char *path,
        int preserve_root);

enum { DEFAULT_MAX_ARCHIVE_SIZE = 1 * 1024 * 1024 };
enum { DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024 };
enum { DEFAULT_MAX_FILE_COUNT = 128 };
enum { DEFAULT_MAX_TEST_COUNT = 99 };
static const unsigned char * const DEFAULT_INPUT_PATTERN = "%03d.dat";
static const unsigned char * const DEFAULT_OUTPUT_PATTERN = "%03d.ans";
static const unsigned char * const DEFAULT_TESTS_DIR = "tests";
static const unsigned char * const DEFAULT_WORK_DIR = "/tmp";

struct archive_entry
{
  long long size;
  int type;
  unsigned char *name;
  int is_processed;
};

struct archive_file
{
  int a, u;
  struct archive_entry *v;
};

static void
die(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "fatal: %s\n", buf);
  exit(1);
}

static int
error(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "error: %s\n", buf);
  return -1;
}

static int
parse_long_long(const unsigned char *str, long long *p_val)
{
  char *eptr = 0;
  long long v = 0;

  if (!str) return -1;
  while (isspace(*str)) ++str;
  if (!*str) return -1;

  errno = 0;
  v = strtoll(str, &eptr, 10);
  if (errno) return -1;
  if (*eptr == 'k' || *eptr == 'K') {
    if ((v & 0xFFE0000000000000ULL) != 0) return -1;
    v <<= 10;
    ++eptr;
  } else if (*eptr == 'm' || *eptr == 'M') {
    if ((v & 0xFFFFF80000000000ULL) != 0) return -1;
    v <<= 20;
    ++eptr;
  } else if (*eptr == 'g' || *eptr == 'G') {
    if ((v & 0xFFFFFFFE00000000ULL) != 0) return -1;
    v <<= 30;
    ++eptr;
  }
  if (*eptr) return -1;
  *p_val = v;
  return 0;
}

static int
fromxdigit(int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

static int
parse_c_string(const unsigned char *in, unsigned char *out)
{
  while (isspace(*in)) ++in;
  if (*in != '\"') return -1;
  ++in;
  while (*in && *in != '\"') {
    if (*in != '\\') {
      *out++ = *in++;
      continue;
    }
    if (in[1] >= '0' && in[1] <= '3'
        && in[2] >= '0' && in[2] <= '7'
        && in[3] >= '0' && in[3] <= '7') {
      *out++ = ((in[1] - '0') << 6) + ((in[2] - '0') << 3) + (in[3] - '0');
      in += 4;
      continue;
    }
    if (in[1] >= '0' && in[1] <= '7'
        && in[2] >= '0' && in[2] <= '7') {
      *out++ = ((in[1] - '0') << 3) + (in[2] - '0');
      in += 3;
      continue;
    }
    if (in[1] >= '0' && in[1] <= '7') {
      *out++ = (in[1] - '0');
      in += 2;
      continue;
    }
    if ((in[1] == 'x' || in[1] == 'X') && isxdigit(in[2]) && isxdigit(in[3])) {
      *out++ = (fromxdigit(in[2]) << 4) + fromxdigit(in[3]);
      in += 4;
      continue;
    }
    if ((in[1] == 'x' || in[1] == 'X') && isxdigit(in[2])) {
      *out++ = fromxdigit(in[2]);
      in += 3;
      continue;
    }
    switch (in[1]) {
    case '\\':
    case '\"':
    case '\'':
      *out++ = in[1];
      break;

    case 'a':
      *out++ = '\a';
      break;
    case 'b':
      *out++ = '\b';
      break;
    case 't':
      *out++ = '\t';
      break;
    case 'n':
      *out++ = '\n';
      break;
    case 'v':
      *out++ = '\v';
      break;
    case 'f':
      *out++ = '\f';
      break;
    case 'r':
      *out++ = '\r';
      break;

    default:
      *out++ = in[1];
      break;
    }
    in += 2;
  }
  if (*in != '\"') return -1;
  ++in;
  if (*in) return -1;

  *out = 0;
  return 0;
}

static int
parse_file_type(const unsigned char *str, int *p_type)
{
  int i, bit, ind;
  int ftype = 0;

  if (!str) return -1;
  // trwxrwxrwx
  if (strlen(str) != 10) return -1;

  if (str[0] == 'd') {
    ftype |= S_IFDIR;
  } else if (str[0] == '-') {
    ftype |= S_IFREG;
  } else return -1;
  for (i = 0, bit = 0400, ind = 1; i < 3; ++i) {
    if (str[ind] == 'r') {
      ftype |= bit;
    } else if (str[ind] == '-') {
    } else return -1;
    ++ind; bit >>= 1;
    if (str[ind] == 'w') {
      ftype |= bit;
    } else if (str[ind] == '-') {
    } else return -1;
    ++ind; bit >>= 1;
    if (str[ind] == 'x') {
      ftype |= bit;
    } else if (str[ind] == '-') {
    } else return -1;
    ++ind; bit >>= 1;
  }
  *p_type = ftype;
  return 0;
}

static void
append_entry(
        struct archive_file *arch,
        long long size,
        int type,
        const unsigned char *name)
{
  if (arch->u >= arch->a) {
    int new_a = arch->a * 2;
    struct archive_entry *new_v = 0;
    if (!new_a) new_a = 32;
    new_v = (struct archive_entry*) calloc(new_a, sizeof(new_v[0]));
    if (arch->a > 0) {
      memcpy(new_v, arch->v, arch->u * sizeof(new_v[0]));
    }
    free(arch->v);
    arch->v = new_v;
    arch->a = new_a;
  }

  arch->v[arch->u].size = size;
  arch->v[arch->u].type = type;
  arch->v[arch->u].name = strdup(name);
  arch->u++;
}

static int
find_entry(struct archive_file *arch, const unsigned char *name)
{
  int i;

  for (i = 0; i < arch->u; ++i) {
    if (!strcmp(arch->v[i].name, name))
      return i;
  }
  return -1;
}

static int
get_tar_listing(const unsigned char *path, struct archive_file *arch)
{
  char *cmds[5];
  int r, n;
  unsigned char *out = 0, *err = 0;
  int len, len1;
  FILE *fin = 0;
  unsigned char *buf1 = 0;
  unsigned char *arg1 = 0;
  unsigned char *arg2 = 0;
  unsigned char *arg3 = 0;
  unsigned char *arg4 = 0;
  unsigned char *arg5 = 0;
  unsigned char *arg6 = 0;
  long long filesize;
  int filetype;

  cmds[0] = "/bin/tar";
  cmds[1] = "tvf";
  cmds[2] = (char*) path;
  cmds[3] = "--quoting-style=c";
  cmds[4] = 0;

  r = ejudge_invoke_process(cmds, NULL, NULL, NULL, 0, &out, &err);
  if (r != 0) {
    error("archiver exit code: %d", r);
    fprintf(stderr, "%s\n", err);
    goto fail;
  }
  free(err); err = 0;
  if (!out) return 0;

  len = strlen(out);
  buf1 = (unsigned char*) malloc(len + 10);
  arg1 = (unsigned char*) malloc(len + 10);
  arg2 = (unsigned char*) malloc(len + 10);
  arg3 = (unsigned char*) malloc(len + 10);
  arg4 = (unsigned char*) malloc(len + 10);
  arg5 = (unsigned char*) malloc(len + 10);
  arg6 = (unsigned char*) malloc(len + 10);
  fin = fmemopen(out, len, "r");
  while (fgets(buf1, len + 10, fin)) {
    len1 = strlen(buf1);
    while (len1 > 0 && isspace(buf1[len1 - 1])) --len1;
    buf1[len1] = 0;

    r = sscanf(buf1, "%s%s%s%s%s%n", arg1, arg2, arg3, arg4, arg5, &n);
    if (r != 5) {
      error("invalid archive output %s", buf1);
      goto fail;
    }

    filetype = 0;
    if (parse_file_type(arg1, &filetype) < 0) {
      error("invalid file type %s", arg1);
      goto fail;
    }

    filesize = 0;
    if (parse_long_long(arg3, &filesize) < 0) {
      error("invalid file length %s", arg3);
      goto fail;
    }
    if (filesize < 0) {
      error("invalid file length %lld", filesize);
      goto fail;
    }

    if (parse_c_string(buf1 + n, arg6) < 0) {
      error("invalid file name %s", buf1 + n);
      goto fail;
    }

    append_entry(arch, filesize, filetype, arg6);
  }
  fclose(fin); fin = 0;

  free(out); out = 0;
  free(buf1); buf1 = 0;
  free(arg1); arg1 = 0;
  free(arg2); arg2 = 0;
  free(arg3); arg3 = 0;
  free(arg4); arg4 = 0;
  free(arg5); arg5 = 0;
  free(arg6); arg6 = 0;

  return r;

fail:
  if (out) free(out);
  if (err) free(err);
  if (fin) fclose(fin);
  if (buf1) free(buf1);
  if (arg1) free(arg1);
  if (arg2) free(arg2);
  if (arg3) free(arg3);
  if (arg4) free(arg4);
  if (arg5) free(arg5);
  if (arg6) free(arg6);
  
  return -1;
}

static int
unpack_tar(const unsigned char *path, const unsigned char *dir)
{
  int r;
  unsigned char *out = 0, *err = 0;
  char *cmds[6];

  cmds[0] = "/bin/tar";
  cmds[1] = "xf";
  cmds[2] = (char*) path;
  cmds[3] = "-C";
  cmds[4] = (char*) dir;
  cmds[5] = 0;

  r = ejudge_invoke_process(cmds, NULL, NULL, NULL, 0, &out, &err);
  if (r != 0) {
    error("archiver exit code: %d", r);
    fprintf(stderr, "%s", err);
    r = -1;
  }

  free(out);
  free(err);
  return r;
}

static int
read_text_file(
        const unsigned char *path,
        const unsigned char *base,
        char **p_txt,
        size_t *p_len)
{
  char *txt = 0;
  size_t len = 0;
  FILE *fin = 0;
  FILE *ftxt = 0;
  int lineno = 1;
  int c;

  if (!(fin = fopen(path, "r"))) {
    error("cannot open %s", path);
    goto fail;
  }
  if (!(ftxt = open_memstream(&txt, &len))) {
    error("cannot open memory stream");
    goto fail;
  }
  while ((c = getc(fin)) != EOF) {
    switch (c) {
    case  0: case  1: case  2: case  3: case  4: case  5: case  6: case  7:
    case  8:                   case 11: case 12:          case 14: case 15:
    case 16: case 17: case 18: case 19: case 20: case 21: case 22: case 23:
    case 24: case 25: case 26: case 27: case 28: case 29: case 30: case 31:
    case 0177:
      error("file %s is not a text file because of \\%o in line %d",
            base, c, lineno);
      break;
    case '\n':
      putc(c, ftxt);
      lineno++;
      break;
    default:
      putc(c, ftxt);
      break;
    }
  }
  fclose(ftxt); ftxt = 0;
  fclose(fin); fin = 0;
  if (p_txt) {
    *p_txt = txt;
  } else {
    free(txt);
  }
  txt = 0;
  if (p_len) *p_len = len;

  return 0;

fail:
  if (fin) fclose(fin);
  if (ftxt) fclose(ftxt);
  if (txt) free(txt);
  return -1;
}

static int
check_sizes(
        struct archive_file *arch,
        int max_file_count,
        long long max_file_size,
        long long max_archive_size)
{
  long long total_size = 0;
  int i;

  if (arch->u > max_file_count) {
    error("the total number of files in the archive exceeds %d",max_file_count);
    return -1;
  }
  for (i = 0; i < arch->u; ++i) {
    if (arch->v[i].size > max_file_size) {
      error("atleast one file exceeds %lld in size", max_file_size);
      return -1;
    }
    total_size += arch->v[i].size;
  }

  if (total_size > max_archive_size) {
    error("the total size of files in the archive exceeds %lld",
          max_archive_size);
    return -1;
  }

  return 0;
}

int
check_tar_tests(
        struct archive_file *arch,
        int max_test_count,
        const unsigned char *dir_prefix,
        const char *input_file_pattern,
        const char *output_file_pattern)
{
  int i, j, num;
  int retcode = 0;
  unsigned char b1[128], b2[128];
  unsigned char n1[256], n2[256];

  // find "tests/" entry
  snprintf(n1, sizeof(n1), "%s/", dir_prefix);
  if ((i = find_entry(arch, n1)) < 0) {
    error("no %s entry in the archive", n1);
    return -1;
  }
  if (!S_ISDIR(arch->v[i].type)) {
    error("%s entry is not a directory", n1);
    return -1;
  }
  if ((arch->v[i].type & 0700) != 0700) {
    error("invalid permissions on %s entry", n1);
    return -1;
  }
  arch->v[i].is_processed = 1;

  // find "tests/README" entry
  snprintf(n1, sizeof(n1), "%s/README", dir_prefix);
  if ((i = find_entry(arch, n1)) < 0) {
    error("no %s entry in the archive", n1);
    return -1;
  }
  if (!S_ISREG(arch->v[i].type)) {
    error("%s is not a regular file", n1);
    return -1;
  }
  if ((arch->v[i].type & 0400) != 0400) {
    error("invalid permissions on %s entry", n1);
    return -1;
  }
  arch->v[i].is_processed = 1;

  num = 1;
  while (1) {
    snprintf(b1, sizeof(b1), input_file_pattern, num);
    snprintf(b2, sizeof(b2), output_file_pattern, num);
    snprintf(n1, sizeof(n1), "%s/%s", dir_prefix, b1);
    snprintf(n2, sizeof(n2), "%s/%s", dir_prefix, b2);

    i = find_entry(arch, n1);
    j = find_entry(arch, n2);

    if (i < 0 && j < 0) break;
    if (i < 0) {
      error("answer file %s exists, but input file %s does not", b2, b1);
      return -1;
    }
    if (j < 0) {
      error("input file %s exists, but answer file %s does not", b1, b2);
      return -1;
    }

    if (!S_ISREG(arch->v[i].type)) {
      error("%s is not a regular file", n1);
      return -1;
    }
    if (!S_ISREG(arch->v[j].type)) {
      error("%s is not a regular file", n2);
      return -1;
    }
    if ((arch->v[i].type & 0400) != 0400) {
      error("invalid permissions on %s entry", n1);
      return -1;
    }
    if ((arch->v[j].type & 0400) != 0400) {
      error("invalid permissions on %s entry", n2);
      return -1;
    }

    arch->v[i].is_processed = 1;
    arch->v[j].is_processed = 1;
    num++;
  }

  if (num == 1) {
    error("no tests found");
    return -1;
  }
  if (num > max_test_count + 1) {
    error("the number of tests %d exceeds the limit %d",
            num - 1, max_test_count);
    return -1;
  }

  // check for garbage
  for (i = 0; i < arch->u; ++i) {
    if (!arch->v[i].is_processed) {
      error("garbage file %s in the archive", arch->v[i].name);
      retcode = -1;
    }
  }

  return retcode;
}

static int
create_arch_dir(
        unsigned char *buf,
        size_t bufsize,
        const unsigned char *work_dir,
        const unsigned char *prefix)
{
  int serial = 0;
  struct timeval tv;
  int pid = getpid();
  enum { MAX_ATTEMPTS = 20 };
  struct stat stb;
  int seed, um;

  if (stat(work_dir, &stb) < 0) {
    error("working directory %s does not exist", work_dir);
    return -1;
  }
  if (!S_ISDIR(stb.st_mode)) {
    error("working directory %s is not a directory", work_dir);
    return -1;
  }
  if (access(work_dir, R_OK | W_OK | X_OK) < 0) {
    error("working directory %s has invalid permissions",
          work_dir);
    return -1;
  }

  while (serial < MAX_ATTEMPTS) {
    gettimeofday(&tv, 0);
    seed = ++serial
      ^ (tv.tv_sec & 0xffff) ^ ((tv.tv_sec >> 16) & 0xffff)
      ^ (tv.tv_usec & 0xffff) ^ ((tv.tv_usec >> 16) & 0xffff)
      ^ (pid & 0xffff) ^ ((pid >> 16) & 0xffff);
    snprintf(buf, bufsize, "%s/%s%d", work_dir, prefix, seed);
    um = umask(0);
    if (mkdir(buf, 0700) >= 0) {
      umask(um);
      break;
    }
    if (errno != EEXIST) {
      error("cannot create directory %s: %s", buf, strerror(errno));
      umask(um);
      return -1;
    }
    umask(um);
  }

  if (serial >= MAX_ATTEMPTS) {
    error("cannot create directory in %s: too many attempts", work_dir);
    return -1;
  }

  return 0;
}

int
make_report(
        struct archive_file *arch,
        const unsigned char *path,
        const unsigned char *work_dir,
        const unsigned char *prefix,
        const unsigned char *tests_dir,
        const unsigned char *input_file_pattern,
        const unsigned char *output_file_pattern,
        int (*unpack_func)(const unsigned char *path,const unsigned char *dir))
{
  unsigned char wd[PATH_MAX];
  int wd_created = 0;
  unsigned char td[PATH_MAX];
  struct stat stb;
  unsigned char fp[PATH_MAX];
  char *txt = 0;
  size_t len = 0;
  int num;
  unsigned char ifbase[PATH_MAX];
  unsigned char ofbase[PATH_MAX];
  unsigned char ifpath[PATH_MAX];
  unsigned char ofpath[PATH_MAX];

  if (create_arch_dir(wd, sizeof(wd), work_dir, prefix) < 0)
    goto fail;
  wd_created = 1;

  if (unpack_func(path, wd) < 0)
    goto fail;

  snprintf(td, sizeof(td), "%s/%s", wd, tests_dir);
  if (stat(td, &stb) < 0) {
    error("directory %s does not exist", td);
    goto fail;
  }
  if (!S_ISDIR(stb.st_mode)) {
    error("directory %s is not a directory", td);
    goto fail;
  }
  if (access(td, R_OK | W_OK | X_OK) < 0) {
    error("directory %s has invalid permissions", td);
    goto fail;
  }

  snprintf(fp, sizeof(fp), "%s/README", td);
  if (read_text_file(fp, "README", &txt, &len) < 0)
    goto fail;
  printf("=== README ===\n%s\n", txt);
  free(txt); txt = 0; len = 0;

  num = 0;
  while (1) {
    ++num;
    snprintf(ifbase, sizeof(ifbase), input_file_pattern, num);
    snprintf(ofbase, sizeof(ofbase), output_file_pattern, num);
    snprintf(ifpath, sizeof(ifpath), "%s/%s", td, ifbase);
    snprintf(ofpath, sizeof(ofpath), "%s/%s", td, ofbase);

    if (stat(ifpath, &stb) < 0) break;

    if (read_text_file(ifpath, ifbase, &txt, &len) < 0)
      goto fail;
    printf("=== %s ===\n%s\n", ifbase, txt);
    free(txt); txt = 0; len = 0;
    if (read_text_file(ofpath, ofbase, &txt, &len) < 0)
      goto fail;
    printf("=== %s ===\n%s\n", ofbase, txt);
    free(txt); txt = 0; len = 0;
  }
  
  remove_directory_recursively(wd, 0);
  return 0;

fail:
  if (wd_created) {
    remove_directory_recursively(wd, 0);
  }
  return -1;
}

int
main(int argc, char **argv)
{
  int i = 1;
  unsigned char *archive_path = 0;
  long long max_archive_size = -1;
  long long max_file_size = -1;
  int max_test_count = -1;
  long long tmp;
  int max_file_count = -1;
  int tests_mode = 0;
  int mime_type;
  struct archive_file arch;
  const unsigned char *if_patt = 0;
  const unsigned char *of_patt = 0;
  const unsigned char *tests_dir = 0;
  const unsigned char *work_dir = 0;
  int (*unpack_func)(const unsigned char *path,const unsigned char *dir) = 0;
  const unsigned char *env;

  signal(SIGPIPE, SIG_IGN);
  memset(&arch, 0, sizeof(arch));

  /* pick up values from environment */
  if ((env = getenv("EJ_MAX_ARCHIVE_SIZE"))) {
    if (parse_long_long(env, &max_archive_size) < 0)
      die("invalid value of EJ_MAX_ARCHIVE_SIZE parameter");
    if (max_file_size <= 0) {
      die("invalid value of EJ_MAX_ARCHIVE_SIZE parameter");
    }
  }
  if ((env = getenv("EJ_MAX_FILE_SIZE"))) {
    if (parse_long_long(env, &max_file_size) < 0)
      die("invalid value of EJ_MAX_FILE_SIZE parameter");
    if (max_file_size <= 0) {
      die("invalid value of EJ_MAX_FILE_SIZE parameter");
    }
  }
  if ((env = getenv("EJ_MAX_FILE_COUNT"))) {
    if (parse_long_long(env, &tmp) < 0)
      die("invalid value of EJ_MAX_FILE_COUNT parameter");
    if (tmp <= 0 || tmp > INT_MAX) {
      die("invalid value of EJ_MAX_FILE_COUNT parameter");
    }
    max_file_count = (int) tmp;
  }
  if ((env = getenv("EJ_MAX_TEST_COUNT"))) {
    if (parse_long_long(env, &tmp) < 0)
      die("invalid value of EJ_MAX_TEST_COUNT parameter");
    if (tmp <= 0 || tmp > INT_MAX) {
      die("invalid value of EJ_MAX_TEST_COUNT parameter");
    }
    max_test_count = (int) tmp;
  }
  if ((env = getenv("EJ_INPUT_PATTERN"))) {
    if_patt = env;
  }
  if ((env = getenv("EJ_OUTPUT_PATTERN"))) {
    of_patt = env;
  }
  if ((env = getenv("EJ_TESTS_DIR"))) {
    tests_dir = env;
  }
  if ((env = getenv("EJ_WORK_DIR"))) {
    work_dir = env;
  }

  while (i < argc) {
    if (!strcmp(argv[i], "--")) {
      ++i;
      break;
    } else if (argv[i][0] != '-') {
      break;
    }
    if (!strcmp(argv[i], "-z")) {
      // total size of uncompressed files
      if (i + 1 >= argc)
        die("argument expected for -z option");
      if (parse_long_long(argv[i + 1], &max_archive_size) < 0)
        die("invalid value of -z parameter");
      if (max_archive_size <= 0)
        die("invalid value of -z parameter");
      i += 2;
    } else if (!strcmp(argv[i], "-f")) {
      // size of one uncompressed file
      if (i + 1 >= argc)
        die("argument expected for -f option");
      if (parse_long_long(argv[i + 1], &max_file_size) < 0)
        die("invalid value of -f parameter");
      if (max_file_size <= 0)
        die("invalid value of -f parameter");
      i += 2;
    } else if (!strcmp(argv[i], "-n")) {
      // number of files
      if (i + 1 >= argc)
        die("argument expected for -n option");
      if (parse_long_long(argv[i + 1], &tmp) < 0)
        die("invalid value of -n parameter");
      if (tmp <= 0 || tmp > INT_MAX)
        die("invalid value of -n parameter");
      max_file_count = (int) tmp;
      i += 2;
    } else if (!strcmp(argv[i], "-t")) {
      // test archive check mode
      tests_mode = 1;
      ++i;
    } else if (!strcmp(argv[i], "-c")) {
      // max number of tests
      if (i + 1 >= argc)
        die("argument expected for -c option");
      if (parse_long_long(argv[i + 1], &tmp) < 0)
        die("invalid value of -c parameter");
      if (tmp <= 0 || tmp > INT_MAX)
        die("invalid value of -c parameter");
      max_test_count = (int) tmp;
      i += 2;
    } else if (!strcmp(argv[i], "-i")) {
      // input file pattern
      if (i + 1 >= argc)
        die("argument expected for -i option");
      if_patt = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-o")) {
      // output file pattern
      if (i + 1 >= argc)
        die("argument expected for -o option");
      of_patt = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-e")) {
      // test dir prefix
      if (i + 1 >= argc)
        die("argument expected for -e option");
      tests_dir = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-w")) {
      // working directory
      if (i + 1 >= argc)
        die("argument expected for -w option");
      work_dir = argv[i + 1];
      i += 2;
    } else {
      die("invalid option `%s'", argv[i]);
    }
  }
  if (i >= argc) {
    die("file name expected");
  }
  archive_path = argv[i++];
  if (i < argc) {
    die("invalid parameters after file name");
  }

  if (max_archive_size <= 0) max_archive_size = DEFAULT_MAX_ARCHIVE_SIZE;
  if (max_file_size <= 0) max_file_size = DEFAULT_MAX_FILE_SIZE;
  if (max_file_count <= 0) max_file_count = DEFAULT_MAX_FILE_COUNT;
  if (max_test_count <= 0) max_test_count = DEFAULT_MAX_TEST_COUNT;
  if (!if_patt) if_patt = DEFAULT_INPUT_PATTERN;
  if (!of_patt) of_patt = DEFAULT_OUTPUT_PATTERN;
  if (!tests_dir) tests_dir = DEFAULT_TESTS_DIR;
  if (!work_dir) work_dir = DEFAULT_WORK_DIR;

  if (access(archive_path, R_OK) < 0)
    die("file %s does not exist or is not readable");

  mime_type = mime_type_guess_file(archive_path, 0);
  if (mime_type < 0)
    die("file type recognition failed");
  if (mime_type == MIME_TYPE_TEXT || mime_type == MIME_TYPE_BINARY)
    die("file type is not recognized");

  switch (mime_type) {
  case MIME_TYPE_APPL_COMPRESS:
  case MIME_TYPE_APPL_GZIP:
  case MIME_TYPE_APPL_TAR:
  case MIME_TYPE_APPL_BZIP2:
    if (get_tar_listing(archive_path, &arch) < 0) return 1;
    if (check_sizes(&arch, max_file_count, max_file_size, max_archive_size)<0)
      return 1;
    if (check_tar_tests(&arch, max_test_count, tests_dir, if_patt, of_patt) < 0)
      return 1;
    unpack_func = unpack_tar;
    break;

  case MIME_TYPE_APPL_ZIP:
    die("this archive type is not supported");
    break;

  default:
    die("file is not an archive file");
  }

  if (make_report(&arch, archive_path, work_dir, "stylearch", tests_dir,
                  if_patt, of_patt, unpack_func) < 0)
    return 1;

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
