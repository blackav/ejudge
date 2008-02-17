/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2008 Alexander Chernov <cher@ejudge.ru> */

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

/*
 * This program is MS QuickBasic 4.5 compiler helper. Compile packet is
 * prepared in the dosemu work dir, then the dosemu started.
 * Note, that compile process for this language is quite sophisticated
 * and handled by the 'qbasic.bat' batch file in the C:\\ directory.
 */

#if defined HAVE_CONFIG_H
#include "../config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/wait.h>

static unsigned char emupath[4096];

void
myerr(char const *format, ...)
{
  va_list args;

  va_start(args, format);
  fprintf(stderr, "qbemu: ");
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(1);
}

void
copy_file(char const *src, char const *dst)
{
  if (link(src, dst) >= 0) return;

  if (errno != EXDEV && errno != EPERM)
    myerr("link(%s, %s) failed: %s", src, dst, strerror(errno));

  {
    int fdr, fdw;
    unsigned char buf[4096], *p;
    int r, w;

    if ((fdr = open(src, O_RDONLY, 0)) < 0)
      myerr("open `%s' for read failed: %s", src, strerror(errno));
    if ((fdw = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0)
      myerr("open `%s' for write failed: %s", dst, strerror(errno));

    while (1) {
      r = read(fdr, buf, sizeof(buf));
      if (r < 0) myerr("read failed: %s", strerror(errno));
      if (!r) break;
      p = buf;
      while (r) {
        w = write(fdw, p, r);
        if (r <= 0) myerr("write failed: %s", strerror(errno));
        p += w;
        r -= w;
      }
    }

    if (close(fdr) < 0) myerr("close failed: %s", strerror(errno));
    if (close(fdw) < 0) myerr("close failed: %s", strerror(errno));
  }
}

void
cat_file(char *path)
{
  FILE *f;
  int c;

  if (!(f = fopen(path, "r"))) myerr("cannot open %s", path);
  while ((c = getc(f)) != EOF) fputc(c, stderr);
  fclose(f);
}

void
clean_dir(char *path)
{
  DIR *d;
  struct dirent *e;
  char buf[1024];

  while (1) {
    if (!(d = opendir(path))) myerr("cannot open dir %s", path);
    while ((e = readdir(d))) {
      if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
      break;
    }
    if (!e) break;
    snprintf(buf, sizeof(buf), "%s/%s", path, e->d_name);
    closedir(d);
    //fprintf(stderr, "remove %s\n", buf);
    if (unlink(buf) < 0) myerr("unlink failed: %s", strerror(errno));
  }
  closedir(d);
}

void
cleanup_hnd(void)
{
  DIR *d;
  struct dirent *e;
  char buf[1024];

  while (1) {
    if (!(d = opendir(emupath))) return;
    while ((e = readdir(d))) {
      if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
      break;
    }
    if (!e) break;
    snprintf(buf, sizeof(buf), "%s/%s", emupath, e->d_name);
    closedir(d);
    if (unlink(buf) < 0) return;
  }
  closedir(d);
}

int
main(int argc, char *argv[])
{
  FILE *f;
  char buf[1024];
  int pid, stat;
  struct stat ss;
  int fd;

  if (argc != 3) myerr("wrong number of arguments: %d", argc);

#if defined EJUDGE_LOCAL_DIR
  snprintf(emupath, sizeof(emupath), "%s/dosemu/run", EJUDGE_LOCAL_DIR);
#elif defined EJUDGE_CONTESTS_HOME_DIR
  snprintf(emupath, sizeof(emupath), "%s/dosemu/run", EJUDGE_CONTESTS_HOME_DIR);
#else
  snprintf(emupath, sizeof(emupath), "/home/judges/dosemu/run");
#endif

  atexit(cleanup_hnd);
  if (chmod(emupath, 0700) < 0) myerr("chmod failed: %s", strerror(errno));
  clean_dir(emupath);
  snprintf(buf, sizeof(buf), "%s/command.txt", emupath);
  if (!(f = fopen(buf, "w")))
    myerr("fopen w failed on %s: %s", buf, strerror(errno));
  fprintf(f,
          "\r\n"
          "\r\n"
          "output.txt\r\n"
          "errors.txt\r\n"
          "c:\\command.com\r\n"
          "/c\r\n"
          "c:\\qbasic.bat\r\n"
          "\r\n");
  fclose(f);

  snprintf(buf, sizeof(buf), "%s/output.txt", emupath);
  if (!(f = fopen(buf, "w")))
    myerr("fopen failed on %s: %s", buf, strerror(errno));
  fclose(f);
  snprintf(buf, sizeof(buf), "%s/errors.txt", emupath);
  if (!(f = fopen(buf, "w")))
    myerr("fopen failed on %s: %s", buf, strerror(errno));
  fclose(f);

  snprintf(buf, sizeof(buf), "%s/program.bas", emupath);
  copy_file(argv[1], buf);
  fflush(0);

  if ((pid = fork()) < 0) myerr("fork failed: %s", strerror(errno));
  if (!pid) {
    snprintf(buf, sizeof(buf), "%s/../bin/dos", emupath);
    if ((fd = open("/dev/null", O_RDONLY)) < 0)
      myerr("open(/dev/null failed: %s", strerror(errno));
    dup2(fd, 0);
    close(fd);
    if ((fd = open("/dev/null", O_WRONLY)) < 0)
      myerr("open(/dev/null failed: %s", strerror(errno));
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
    execl(buf, buf, "-I", "keystroke \"\\r\" video { none } dpmi 4096", NULL);
    myerr("execl failed: %s", strerror(errno));
    _exit(1);
  }
  wait(&stat);
  if (WIFSIGNALED(stat)) myerr("dos terminated by signal");
  if (!WIFEXITED(stat)) myerr("dos terminated by unknown reason");
  if (WEXITSTATUS(stat)) myerr("dos exited with code %d", WEXITSTATUS(stat));

  snprintf(buf, sizeof(buf), "%s/output.txt", emupath);
  cat_file(buf);
  snprintf(buf, sizeof(buf), "%s/errors.txt", emupath);
  cat_file(buf);

  fprintf(stderr, "\n\n");

  snprintf(buf, sizeof(buf), "%s/retcode.txt", emupath);
  if (!(f = fopen(buf, "r"))) myerr("fopen %s failed: %s",buf,strerror(errno));
  if (fscanf(f, "%d", &stat) != 1)
    myerr("cannot parse retcode.txt");
  fscanf(f, " ");
  if (fgetc(f) != EOF) myerr("garbage in retcode.txt");
  fclose(f);

  if (stat != 0) {
    myerr("compilation process error code is %d", stat);
  }

  snprintf(buf, sizeof(buf), "%s/program.exe", emupath);
  if (lstat(buf, &ss) < 0) myerr("output file %s does not exist", buf);
  copy_file(buf, argv[2]);

  return 0;
}

/*
 * Local variables:
 *  compile-command: "gcc -Wall -O2 qbemu.c -o qbemu"
 * End:
 */
