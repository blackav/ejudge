/* -*- c -*- */

/* Copyright (C) 2012-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/ej_types.h"
#include "ejudge/misctext.h"

#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#define MAX_TEST_NUM 999
#define MAX_FILE_SIZE 1073741824

static const unsigned char *progname;

static void
fatal(const char *format, ...)
  __attribute__((format(printf, 1, 2), noreturn));
static void
fatal(const char *format, ...)
{
  unsigned char buf[512];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", progname, buf);
  exit(2);
}

static void
report_version(void)
{
  printf("%s: ejudge version %s compiled %s\n",
         progname, compile_version, compile_date);
  exit(0);
}

static const unsigned char help_str[] =
"--version                print the version and exit\n"
"--help                   print this help and exit\n"
"--                       stop option processing\n"
"--mode=MODE              file mode for output file\n"
"--group=GROUP            file group for output file\n"
"--test-pattern=PATTERN   printf-style patter for test files\n"
"--corr-pattern=PATTERN   printf-style patter for corr files\n"
"--type=NORM-TYPE         normalization type\n"
"--workdir=DIR            work in the directory DIR\n"
"--all-tests              process all tests\n"
"--quiet                  quiet mode\n"
"--binary-input           disable normalization\n"
  ;

static void
report_help(void)
{
  printf("%s usage: ej-normalize [OPTIONS]... FILES...\n", progname);
  fputs(help_str, stdout);
  exit(0);
}

static const unsigned char *
check_option(const unsigned char *opt_name, const unsigned char *opt)
{
  int opt_len = strlen(opt_name);
  if (strncmp(opt_name, opt, opt_len) != 0) return NULL;
  if (opt[opt_len] != '=') return NULL;
  return opt + opt_len + 1;
}

static void
parse_mode(const unsigned char *name, const unsigned char *opt, int *pval)
{
  char *eptr = NULL;
  int val = 0;

  errno = 0;
  val = strtol(opt, &eptr, 8);
  if (errno || val <= 0 || val > 07777) fatal("invalid value for option %s", name);
  *pval = val;
}

static void
parse_norm_type(const unsigned char *name, const unsigned char *opt, int *pval)
{
  int val = test_normalization_parse(opt);
  if (val < 0) fatal("invalid value for option %s", name);
  *pval = val;
}

static void
parse_group(const unsigned char *name, const unsigned char *opt, int *pval)
{
  struct group *grp = getgrnam(opt);
  if (!grp || grp->gr_gid <= 0) fatal("invalid group for option %s", name);
  *pval = grp->gr_gid;
}

static int
ends_with(const unsigned char *str, const unsigned char *suffix)
{
  if (!suffix || !*suffix) return 1;
  if (!str || !*str) return 0;
  int len1 = strlen(str);
  int len2 = strlen(suffix);
  if (len2 > len1) return 0;
  return !strcmp(str + len1 - len2, suffix);
}

static int
read_file(
        const unsigned char *path,
        long long *p_size,
        unsigned char **p_data)
{
  FILE *f = NULL;
  unsigned char *b = NULL;
  int z = 0, l = 0, e, r;
  unsigned char buf[4096];

  if (!(f = fopen(path, "rb"))) {
    return -1;
  }
  while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
    if (l + r >= z) {
      if (!z) {
        z = sizeof(buf);
      }
      while (l + r >= z) {
        z *= 2;
      }
      b = xrealloc(b, z * sizeof(*b));
    }
    memcpy(b + l, buf, r);
    l += r;
  }
  if (ferror(f)) goto fail;
  fclose(f); f = NULL;

  if (!b) {
    b = xmalloc(1);
  }

  b[l] = 0;
  *p_data = b;
  *p_size = l;
  return l > 0;

fail:
  e = errno;
  if (f) fclose(f);
  xfree(b);
  errno = e;
  return -1;
}

static unsigned char *
normalize_text(int mode, const unsigned char *text)
{
  size_t tlen = strlen(text);
  int op_mask = 0;
  unsigned char *out_text = NULL;
  size_t out_count = 0;
  int done_mask = 0;

  switch (mode) {
  case TEST_NORM_NONE:
    return xstrdup(text);
  case TEST_NORM_NLWSNP:
    op_mask |= TEXT_FIX_NP;
  case TEST_NORM_NLWS:          // fallthrough
    op_mask |= TEXT_FIX_TR_SP | TEXT_FIX_TR_NL;
  case TEST_NORM_NL:            // fallthrough
    op_mask |= TEXT_FIX_CR | TEXT_FIX_FINAL_NL;
    break;
  case TEST_NORM_NLNP:
    op_mask |= TEXT_FIX_CR | TEXT_FIX_FINAL_NL | TEXT_FIX_NP;
    break;
  default:
    abort();
  }

  text_normalize_dup(text, tlen, op_mask, &out_text, &out_count, &done_mask);
  return out_text;
}

static int
save_file_1(
        const unsigned char *path,
        int mode,
        int group_id,
        int len,
        const unsigned char *bytes)
{
  int retval = -1;
  int pid = getpid();
  int rv = 0;
  struct timeval tv;
  unsigned char tmppath[PATH_MAX];
  FILE *f = NULL;
  int i;
  __attribute__((unused)) int _;

  gettimeofday(&tv, NULL);
  rv = (tv.tv_sec & 0xffff) ^ ((tv.tv_sec >> 16) & 0xffff)
    ^ (tv.tv_usec & 0xffff) ^ ((tv.tv_usec >> 16) & 0xffff)
    ^ (pid & 0xffff);
  snprintf(tmppath, sizeof(tmppath), "%s.tmp%04x", path, rv);

  if (!(f = fopen(tmppath, "wb"))) goto cleanup;
  for (i = 0; i < len; ++i) {
    if (putc(bytes[i], f) == EOF) break;
  }
  if (ferror(f)) goto cleanup;
  fclose(f); f = NULL;

  if (rename(tmppath, path) < 0) goto cleanup;
  tmppath[0] = 0;
  if (mode > 0) _ = chmod(path, mode);
  if (group_id > 0) _ = chown(path, -1, group_id);
  retval = 0;

cleanup:
  if (f) fclose(f);
  if (tmppath[0]) {
    unlink(tmppath);
  }
  return retval;
}

static int
save_file_2(
        const unsigned char *path,
        int mode,
        int group_id,
        int len,
        const unsigned char *bytes)
{
  int retval = -1;
  FILE *f = NULL;
  int i;
  __attribute__((unused)) int _;

  if (!(f = fopen(path, "wb"))) goto cleanup;
  for (i = 0; i < len; ++i) {
    if (putc(bytes[i], f) == EOF) break;
  }
  if (ferror(f)) goto cleanup;
  fclose(f); f = NULL;

  if (mode > 0) _ = chmod(path, mode);
  if (group_id > 0) _ = chown(path, -1, group_id);
  retval = 0;

cleanup:
  if (f) fclose(f);
  return retval;
}

static void
process_one_file(
        const unsigned char *path,
        int norm_type,
        int mode,
        int group_id,
        int quiet_mode,
        int *p_total_count,
        int *p_failed_count)
{
  unsigned char *in_txt = NULL;
  unsigned char *out_txt = NULL;
  long long in_len = 0;
  int out_len;
  int r;
  struct stat stb;

  if (stat(path, &stb) < 0) {
    fprintf(stderr, "%s: %s\n", path, os_ErrorMsg());
    goto fail;
  }
  if (!S_ISREG(stb.st_mode)) {
    fprintf(stderr, "%s: not a regular file\n", path);
    goto fail;
  }
  if (stb.st_size <= 0) {
    if (!quiet_mode) {
      printf("%s: size = 0\n", path);
    }
    goto cleanup;
  }
  if (stb.st_size > MAX_FILE_SIZE) {
    fprintf(stderr, "%s: file is too big (size %lld)\n", path, in_len);
    goto fail;
  }

  if ((r = read_file(path, &in_len, &in_txt)) < 0) {
    fprintf(stderr, "%s: failed to read file: %s\n", path, os_ErrorMsg());
    goto fail;
  }
  if (!r) {
    if (!quiet_mode) {
      printf("%s: size = 0\n", path);
    }
    goto cleanup;
  }

  if (strlen(in_txt) != in_len) {
    fprintf(stderr, "%s: contains \\0 byte in the middle\n", path);
    goto fail;
  }
  if (in_len > MAX_FILE_SIZE) {
    fprintf(stderr, "%s: file is too big (size %lld)\n", path, in_len);
    goto fail;
  }

  out_txt = normalize_text(norm_type, in_txt);
  if (!out_txt) {
    fprintf(stderr, "%s: text normalization failed\n", path);
    goto fail;
  }
  out_len = strlen(out_txt);

  if (!strcmp(in_txt, out_txt)) {
    if (!quiet_mode) {
      printf("%s: size = %lld, normalized\n", path, in_len);
    }
    goto cleanup;
  }

  if (save_file_1(path, mode, group_id, out_len, out_txt) >= 0) {
    if (!quiet_mode) {
      printf("%s: old size = %lld, new size = %d\n", path, in_len, out_len);
    }
    goto cleanup;
  }

  if (save_file_2(path, mode, group_id, out_len, out_txt) >= 0) {
    if (!quiet_mode) {
      printf("%s: old size = %lld, new size = %d\n", path, in_len, out_len);
    }
    goto cleanup;
  }

  fprintf(stderr, "%s: failed to save file\n", path);
  save_file_2(path, mode, group_id, (int) in_len, in_txt);
  goto fail;

cleanup:
  ++(*p_total_count);
  xfree(in_txt);
  xfree(out_txt);
  return;

fail:
  ++(*p_failed_count);
  goto cleanup;
}

static void
process_one_test(
        const unsigned char *workdir,
        const unsigned char *test_pattern,
        const unsigned char *corr_pattern,
        int num,
        int norm_type,
        int mode,
        int group_id,
        int quiet_mode,
        int *p_total_count,
        int *p_failed_count)
{
  unsigned char path[PATH_MAX];
  unsigned char bname[PATH_MAX];

  if (!workdir) workdir = "";

  if (!*workdir) {
    snprintf(path, sizeof(path), test_pattern, num);
  } else {
    snprintf(bname, sizeof(bname), test_pattern, num);
    snprintf(path, sizeof(path), "%s/%s", workdir, bname);
  }
  process_one_file(path, norm_type, mode, group_id, quiet_mode,
                   p_total_count, p_failed_count);

  if (corr_pattern && *corr_pattern) {
    if (!*workdir) {
      snprintf(path, sizeof(path), corr_pattern, num);
    } else {
      snprintf(bname, sizeof(bname), corr_pattern, num);
      snprintf(path, sizeof(path), "%s/%s", workdir, bname);
    }
    process_one_file(path, norm_type, mode, group_id, quiet_mode,
                     p_total_count, p_failed_count);
  }
}

static void
process_one_named_test(
        const unsigned char *test_pattern,
        const unsigned char *corr_pattern,
        const unsigned char *file_name,
        int norm_type,
        int mode,
        int group_id,
        int quiet_mode,
        int *p_total_count,
        int *p_failed_count)
{
  int num;
  unsigned char basename[PATH_MAX];
  int fnlen = strlen(file_name);
  int blen;
  unsigned char dirname[PATH_MAX];

  for (num = 1; num <= MAX_TEST_NUM; ++num) {
    snprintf(basename, sizeof(basename), test_pattern, num);
    if (ends_with(file_name, basename)) {
      break;
    }
  }
  if (num > MAX_TEST_NUM) {
    fprintf(stderr, "%s: file name does not match test_pattern '%s'\n",
            file_name, test_pattern);
    ++(*p_total_count);
    ++(*p_failed_count);
    return;
  }

  blen = strlen(basename);
  if (fnlen > blen && file_name[fnlen - blen - 1] != '/') {
    fprintf(stderr, "%s: file name is not a whole part in test_pattern '%s'\n",
            file_name, test_pattern);
    ++(*p_total_count);
    ++(*p_failed_count);
  }

  dirname[0] = 0;
  if (fnlen > blen) {
    snprintf(dirname, sizeof(dirname), "%s", file_name);
    dirname[fnlen - blen - 1] = 0;
  }

  process_one_test(dirname, test_pattern, corr_pattern, num,
                   norm_type, mode, group_id, quiet_mode,
                   p_total_count, p_failed_count);
}

static void
process_all_tests(
        const unsigned char *workdir,
        const unsigned char *test_pattern,
        const unsigned char *corr_pattern,
        int norm_type,
        int mode,
        int group_id,
        int quiet_mode,
        int *p_total_count,
        int *p_failed_count)
{
  DIR *d = NULL;
  struct dirent *dd;
  unsigned char *test_by_num[MAX_TEST_NUM + 1];
  unsigned char basename[PATH_MAX];
  int num, max_num;

  memset(test_by_num, 0, sizeof(test_by_num));
  if (!test_pattern || !*test_pattern) fatal("--test-pattern is not specified");

  if (!workdir || !*workdir) workdir = ".";
  if (!(d = opendir(workdir))) {
    fatal("cannot open directory '%s'", workdir);
  }
  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
    for (num = 1; num <= MAX_TEST_NUM; ++num) {
      snprintf(basename, sizeof(basename), test_pattern, num);
      if (!strcmp(dd->d_name, basename)) {
        break;
      }
    }
    if (num <= MAX_TEST_NUM) {
      if (test_by_num[num]) fatal("invalid --test-pattern '%s'", test_pattern);
      test_by_num[num] = xstrdup(basename);
    }
  }
  closedir(d); d = NULL;

  for (max_num = 1; max_num <= MAX_TEST_NUM && test_by_num[max_num]; ++max_num) {
  }
  --max_num;
  if (max_num <= 0) {
    if (!quiet_mode) {
      printf("no tests to process\n");
    }
    goto cleanup;
  }

  if (!quiet_mode) {
    printf("processing tests %d-%d\n", 1, max_num);
  }

  for (num = 1; num <= max_num; ++num) {
    process_one_test(workdir, test_pattern, corr_pattern, num,
                     norm_type, mode, group_id, quiet_mode,
                     p_total_count, p_failed_count);
  }

cleanup:
  for (num = 1; num <= MAX_TEST_NUM; ++num) {
    xfree(test_by_num[num]);
  }
}

int
main(int argc, char *argv[])
{
  int cur_arg = 1;
  int retval = 0;
  const unsigned char *p = NULL, *n = NULL;

  const unsigned char *test_pattern = NULL;
  const unsigned char *corr_pattern = NULL;
  const unsigned char *workdir = NULL;
  int norm_type = -1;
  int mode = 0;
  int group_id = 0;
  int all_tests_mode = 0;
  int quiet_mode = 0;
  int binary_input_mode = 0;

  int total_count = 0, failed_count = 0;

  progname = os_GetLastname(argv[0]);

  while (cur_arg < argc) {
    if (!strcmp(argv[cur_arg], "--version")) {
      report_version();
    } else if (!strcmp(argv[cur_arg], "--help")) {
      report_help();
    } else if ((p = check_option("--test-pattern", argv[cur_arg]))) {
      test_pattern = p;
      ++cur_arg;
    } else if ((p = check_option("--corr-pattern", argv[cur_arg]))) {
      corr_pattern = p;
      ++cur_arg;
    } else if ((p = check_option((n = "--type"), argv[cur_arg]))) {
      parse_norm_type(n, p, &norm_type);
      ++cur_arg;
    } else if ((p = check_option("--workdir", argv[cur_arg]))) {
      workdir = p;
      ++cur_arg;
    } else if ((p = check_option("--mode", argv[cur_arg]))) {
      parse_mode("--mode", p, &mode);
      ++cur_arg;
    } else if ((p = check_option("--group", argv[cur_arg]))) {
      parse_group("--group", p, &group_id);
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "--all-tests")) {
      all_tests_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "--quiet")) {
      quiet_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "--binary-input")) {
      binary_input_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "--")) {
      ++cur_arg;
      break;
    } else if (argv[cur_arg][0] == '-') {
      fatal("invalid option '%s'", argv[cur_arg]);
    } else {
      break;
    }
  }

  if (binary_input_mode) {
    return 0;
  }

  if (norm_type < 0) {
    norm_type = TEST_NORM_NL;
  }

  if (all_tests_mode) {
    if (cur_arg < argc) fatal("no files must be specified in --all-tests mode");

    process_all_tests(workdir, test_pattern, corr_pattern, norm_type, mode, group_id, quiet_mode,
                      &total_count, &failed_count);
  } else if (test_pattern && *test_pattern) {
    for (; cur_arg < argc; ++cur_arg) {
      process_one_named_test(test_pattern, corr_pattern, argv[cur_arg],
                             norm_type, mode, group_id, quiet_mode,
                             &total_count, &failed_count);
    }
  } else {
    for (; cur_arg < argc; ++cur_arg) {
      process_one_file(argv[cur_arg], norm_type, mode, group_id, quiet_mode,
                       &total_count, &failed_count);
    }
  }

  if (!quiet_mode) {
    if (failed_count > 0) {
      retval = 1;
      printf("%d files processed, %d FAILED\n", total_count, failed_count);
    } else {
      printf("%d files processed\n", total_count);
    }
  }

  return retval;
}
