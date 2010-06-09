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

extern char **environ;

enum { DEFAULT_MAX_ARCHIVE_SIZE = 1 * 1024 * 1024 };
enum { DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024 };
enum { DEFAULT_MAX_FILE_COUNT = 128 };
enum { DEFAULT_MAX_TEST_COUNT = 99 };
static const unsigned char * const DEFAULT_INPUT_PATTERN = "%03d.dat";
static const unsigned char * const DEFAULT_OUTPUT_PATTERN = "%03d.ans";
static const unsigned char * const DEFAULT_TESTS_DIR = "tests";

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
parse_long_long(const unsigned char *str, long long *p_val)
{
  char *eptr = 0;
  long long v = 0;

  if (!str) return -1;
  while (isspace(*str)) ++str;
  if (!*str) return -1;

  errno = 0;
  v = strtoll(str, &eptr, 10);
  if (errno || *eptr) return -1;
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

static int
invoke_process(
        char **args,
        const unsigned char *workdir,
        const unsigned char *stdin_text,
        unsigned char **stdout_text,
        unsigned char **stderr_text)
{
  char *err_t = 0, *out_t = 0;
  size_t err_z = 0, out_z = 0;
  FILE *err_f = 0, *out_f = 0;
  int pid, out_p[2] = {-1, -1}, err_p[2] = {-1, -1}, in_p[2] = {-1, -1};
  int maxfd, n, status, retcode = 0;
  const unsigned char *stdin_ptr;
  size_t stdin_len;
  unsigned char buf[4096];
  fd_set wset, rset;

  if (!stdin_text) stdin_text = "";
  stdin_ptr = stdin_text;
  stdin_len = strlen(stdin_text);

  if (pipe(in_p) < 0) {
    err_f = open_memstream(&err_t, &err_z);
    fprintf(err_f, "Error: pipe failed: %s\n", strerror(errno));
    goto fail;
  }
  if (pipe(out_p) < 0) {
    err_f = open_memstream(&err_t, &err_z);
    fprintf(err_f, "Error: pipe failed: %s\n", strerror(errno));
    goto fail;
  }
  if (pipe(err_p) < 0) {
    err_f = open_memstream(&err_t, &err_z);
    fprintf(err_f, "Error: pipe failed: %s\n", strerror(errno));
    goto fail;
  }

  if ((pid = fork()) < 0) {
    err_f = open_memstream(&err_t, &err_z);
    fprintf(err_f, "Error: fork failed: %s\n", strerror(errno));
    goto fail;
  } else if (!pid) {
    fflush(stderr);
    dup2(in_p[0], 0); close(in_p[0]); close(in_p[1]);
    dup2(out_p[1], 1); close(out_p[0]); close(out_p[1]);
    dup2(err_p[1], 2); close(err_p[0]); close(err_p[1]);

    if (workdir) {
      if (chdir(workdir) < 0) {
        fprintf(stderr, "Error: cannot change directory to %s: %s\n",
                workdir, strerror(errno));
        fflush(stderr);
        _exit(1);
      }
    }
    execve(args[0], args, environ);
    fprintf(stderr, "Error: exec failed: %s\n", strerror(errno));
    fflush(stderr);
    _exit(1);
  }

  /* parent */
  close(in_p[0]); in_p[0] = -1;
  close(out_p[1]); out_p[1] = -1;
  close(err_p[1]); err_p[1] = -1;
  err_f = open_memstream(&err_t, &err_z);
  out_f = open_memstream(&out_t, &out_z);

  while (1) {
    maxfd = -1;
    FD_ZERO(&wset);
    FD_ZERO(&rset);
    if (in_p[1] >= 0) {
      FD_SET(in_p[1], &wset);
      if (in_p[1] > maxfd) maxfd = in_p[1];
    }
    if (out_p[0] >= 0) {
      FD_SET(out_p[0], &rset);
      if (out_p[0] > maxfd) maxfd = out_p[0];
    }
    if (err_p[0] >= 0) {
      FD_SET(err_p[0], &rset);
      if (err_p[0] > maxfd) maxfd = err_p[0];
    }
    if (maxfd < 0) {
      break;
    }

    n = select(maxfd + 1, &rset, &wset, NULL, NULL);
    if (n < 0) {
      fprintf(err_f, "Error: select failed: %s\n", strerror(errno));
      if (in_p[1] >= 0) close(in_p[1]);
      in_p[1] = -1;
      if (out_p[0] >= 0) close(out_p[0]);
      out_p[0] = -1;
      if (err_p[0] >= 0) close(err_p[0]);
      err_p[0] = -1;
      break;
    }

    if (in_p[1] >= 0 && FD_ISSET(in_p[1], &wset)) {
      if (stdin_len > 0) {
        n = write(in_p[1], stdin_ptr, stdin_len);
        if (n < 0) {
          fprintf(err_f, "Error: write to process failed: %s\n",
                  strerror(errno));
          close(in_p[1]); in_p[1] = -1;
        } else if (!n) {
          fprintf(err_f, "Error: write to process returned 0\n");
          close(in_p[1]); in_p[1] = -1;
        } else {
          stdin_ptr += n;
          stdin_len -= n;
        }
      } else {
        close(in_p[1]); in_p[1] = -1;
      }
    }
    if (out_p[0] >= 0 && FD_ISSET(out_p[0], &rset)) {
      n = read(out_p[0], buf, sizeof(buf));
      if (n < 0) {
        fprintf(err_f, "Error: read from process failed: %s\n",
                strerror(errno));
        close(out_p[0]); out_p[0] = -1;
      } else if (!n) {
        close(out_p[0]); out_p[0] = -1;
      } else {
        fwrite(buf, 1, n, out_f);
      }
    }
    if (err_p[0] >= 0 && FD_ISSET(err_p[0], &rset)) {
      n = read(err_p[0], buf, sizeof(buf));
      if (n < 0) {
        fprintf(err_f, "Error: read from process failed %s\n",
                strerror(errno));
        close(err_p[0]); err_p[0] = -1;
      } else if (!n) {
        close(err_p[0]); err_p[0] = -1;
      } else {
        fwrite(buf, 1, n, err_f);
      }
    }
  }

  n = waitpid(pid, &status, 0);
  if (n < 0) {
    fprintf(err_f, "Error: waiting failed: %s\n", strerror(errno));
    goto fail;
  }

  fclose(out_f); out_f = 0;
  fclose(err_f); err_f = 0;
  if (stdout_text) {
    *stdout_text = out_t; out_t = 0;
  } else {
    free(out_t); out_t = 0;
  }
  if (stderr_text) {
    *stderr_text = err_t; err_t = 0;
  } else {
    free(err_t); err_t = 0;
  }

  if (WIFEXITED(status)) {
    status = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    status = 256 + WTERMSIG(status);
  }

  return retcode;

fail:
  if (in_p[0] >= 0) close(in_p[0]);
  if (in_p[1] >= 0) close(in_p[1]);
  if (out_p[0] >= 0) close(out_p[0]);
  if (out_p[1] >= 0) close(out_p[1]);
  if (err_p[0] >= 0) close(err_p[0]);
  if (err_p[1] >= 0) close(err_p[1]);
  if (err_f) fclose(err_f);
  if (out_f) fclose(out_f);
  if (stderr_text) {
    *stderr_text = err_t; err_t = 0;
  } else {
    free(err_t);
  }
  free(out_t);
  if (stdout_text) *stdout_text = 0;
  return -1;
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
invoke_tar(const unsigned char *path, struct archive_file *arch)
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

  r = invoke_process(cmds, NULL, NULL, &out, &err);
  if (r != 0) {
    fprintf(stderr, "Archiver exit code: %d\n", r);
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
      fprintf(stderr, "Error: invalid archive output %s\n", buf1);
      goto fail;
    }

    filetype = 0;
    if (parse_file_type(arg1, &filetype) < 0) {
      fprintf(stderr, "Error: invalid file type %s\n", arg1);
      goto fail;
    }

    filesize = 0;
    if (parse_long_long(arg3, &filesize) < 0) {
      fprintf(stderr, "Error: invalid file length %s\n", arg3);
      goto fail;
    }
    if (filesize < 0) {
      fprintf(stderr, "Error: invalid file length %lld\n", filesize);
      goto fail;
    }

    if (parse_c_string(buf1 + n, arg6) < 0) {
      fprintf(stderr, "Error: invalid file name %s\n", buf1 + n);
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
check_sizes(
        struct archive_file *arch,
        int max_file_count,
        long long max_file_size,
        long long max_archive_size)
{
  long long total_size = 0;
  int i;

  if (arch->u > max_file_count) {
    fprintf(stderr, "Error: the total number of files in the archive exceeds %d\n", max_file_count);
    return -1;
  }
  for (i = 0; i < arch->u; ++i) {
    if (arch->v[i].size > max_file_size) {
      fprintf(stderr, "Error: atleast one file exceeds %lld in size\n",
              max_file_size);
      return -1;
    }
    total_size += arch->v[i].size;
  }

  if (total_size > max_archive_size) {
    fprintf(stderr, "Error: the total size of files in the archive exceeds %lld\n", max_archive_size);
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
    fprintf(stderr, "Error: no %s entry in the archive\n", n1);
    return -1;
  }
  if (!S_ISDIR(arch->v[i].type)) {
    fprintf(stderr, "Error: %s entry is not a directory\n", n1);
    return -1;
  }
  if ((arch->v[i].type & 0700) != 0700) {
    fprintf(stderr, "Error: invalid permissions on %s entry\n", n1);
    return -1;
  }
  arch->v[i].is_processed = 1;

  // find "tests/README" entry
  snprintf(n1, sizeof(n1), "%s/README", dir_prefix);
  if ((i = find_entry(arch, n1)) < 0) {
    fprintf(stderr, "Error: no %s entry in the archive\n", n1);
    return -1;
  }
  if (!S_ISREG(arch->v[i].type)) {
    fprintf(stderr, "Error: %s is not a regular file\n", n1);
    return -1;
  }
  if ((arch->v[i].type & 0400) != 0400) {
    fprintf(stderr, "Error: invalid permissions on %s entry\n", n1);
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
      fprintf(stderr, "Error: answer file %s exists, but input file %s does not\n", b2, b1);
      return -1;
    }
    if (j < 0) {
      fprintf(stderr, "Error: input file %s exists, but answer file %s does not\n", b1, b2);
      return -1;
    }

    if (!S_ISREG(arch->v[i].type)) {
      fprintf(stderr, "Error: %s is not a regular file\n", n1);
      return -1;
    }
    if (!S_ISREG(arch->v[j].type)) {
      fprintf(stderr, "Error: %s is not a regular file\n", n2);
      return -1;
    }
    if ((arch->v[i].type & 0400) != 0400) {
      fprintf(stderr, "Error: invalid permissions on %s entry\n", n1);
      return -1;
    }
    if ((arch->v[j].type & 0400) != 0400) {
      fprintf(stderr, "Error: invalid permissions on %s entry\n", n2);
      return -1;
    }

    arch->v[i].is_processed = 1;
    arch->v[j].is_processed = 1;
    num++;
  }

  if (num == 1) {
    fprintf(stderr, "Error: no tests found\n");
    return -1;
  }
  if (num > max_test_count + 1) {
    fprintf(stderr, "Error: the number of tests %d exceeds the limit %d\n",
            num - 1, max_test_count);
    return -1;
  }

  // check for garbage
  for (i = 0; i < arch->u; ++i) {
    if (!arch->v[i].is_processed) {
      fprintf(stderr, "Error: garbage file %s in the archive\n",
              arch->v[i].name);
      retcode = -1;
    }
  }

  return retcode;
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

  signal(SIGPIPE, SIG_IGN);
  memset(&arch, 0, sizeof(arch));

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
    if (invoke_tar(archive_path, &arch) < 0) return 1;
    if (check_sizes(&arch, max_file_count, max_file_size, max_archive_size)<0)
      return 1;
    if (check_tar_tests(&arch, max_test_count, tests_dir, if_patt, of_patt) < 0)
      return 1;
    break;

  case MIME_TYPE_APPL_ZIP:
    die("this archive type is not supported");
    break;

  default:
    die("file is not an archive file");
  }

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
