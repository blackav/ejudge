/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2001 Alexander Chernov <cher@ispras.ru> */

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

/*
 * This program is a replacement for ../scripts/dosrun script.
 * Since the program is implemented directly in C, it should work
 * considerably faster, then shell script.
 * The program accepts one argument: the name of the program to run.
 * Also, the environment variable DOSPATH must be set to the
 * path to `dos' executable from dosemu package.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define ERROR_CODE 100

#define PROGRAM_NAME "dosrun2"
#define OUTPUT_FILE  "./output"
#define ERROR_FILE   "./error"
#define CODE_FILE    "./e"
#define RUN_FILE     "./program.exe"

void do_exit(int) __attribute__ ((noreturn));
void do_exit(int code)
{
  FILE *f = NULL;

  if (!(f = fopen(CODE_FILE, "wb"))) {
    fprintf(stderr, "%s: cannot open %s for writing: %s\n",
            PROGRAM_NAME, CODE_FILE, strerror(errno));
    exit(ERROR_CODE);
  }
  fprintf(f, "%d\r\n", code);
  if (ferror(f)) {
    fprintf(stderr, "%s: i/o error on %s: %s\n",
            PROGRAM_NAME, CODE_FILE, strerror(errno));
    exit(ERROR_CODE);
  }
  if (fclose(f) < 0) {
    fprintf(stderr, "%s: i/o error on %s: %s\n",
            PROGRAM_NAME, CODE_FILE, strerror(errno));
    exit(ERROR_CODE);
  }
  exit(code);
}

void msg_and_exit(int code, char const *msg)
     __attribute__ ((noreturn));
void msg_and_exit(int code, char const *msg)
{
  FILE *f = NULL;

  if (!(f = fopen(ERROR_FILE, "w"))) {
    fprintf(stderr, "%s: cannot open %s for writing: %s\n",
            PROGRAM_NAME, ERROR_FILE, strerror(errno));
    do_exit(ERROR_CODE);
  }
  fprintf(f, "%s: %s\r\n", PROGRAM_NAME, msg);
  if (ferror(f)) {
    fprintf(stderr, "%s: i/o error on %s: %s\n",
            PROGRAM_NAME, ERROR_FILE, strerror(errno));
    do_exit(ERROR_CODE);
  }
  if (fclose(f) < 0) {
    fprintf(stderr, "%s: i/o error on %s: %s\n",
            PROGRAM_NAME, ERROR_FILE, strerror(errno));
    do_exit(ERROR_CODE);
  }
  do_exit(code);
}

char buf[1024];

void msg(char const *format, ...)
     __attribute__ ((noreturn, format(printf, 1, 2)));
void msg(char const *format, ...)
{
  va_list args;
  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  msg_and_exit(ERROR_CODE, buf);
}

void msg_errno(char const *format, ...)
     __attribute__ ((noreturn, format(printf, 1, 2)));
void msg_errno(char const *format, ...)
{
  va_list args;
  int     my_errno = errno;
  int     len;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  len = strlen(buf);
  if (errno != 0 && sizeof(buf) - 1 - len > 0) {
    vsnprintf(buf + len, sizeof(buf) - len, ": %s", strerror(my_errno));
  }
  msg_and_exit(ERROR_CODE, buf);
}

int main(int argc, char *argv[])
{
  char *dospath = NULL;

  if (argc != 2) {
    msg("bad number of arguments: %d", argc);
  }
  if (!(dospath = getenv("DOSPATH"))) {
    msg("DOSPATH environment variable is not set");
  }
  if (chmod(".", 0755) < 0) {
    msg_errno("chmod(\".\",0755) failed");
  }

  // FIXME: hmm... the files could be on different filesystems
  if (rename(argv[1], RUN_FILE) < 0) {
    msg_errno("rename(\"%s\",\"%s\") failed", argv[1], RUN_FILE);
  }

  if (truncate(OUTPUT_FILE, 0) < 0) {
    msg_errno("truncate(\"%s\", 0) failed", OUTPUT_FILE);
  }
  if (truncate(ERROR_FILE, 0) < 0) {
    msg_errno("truncate(\"%s\", 0) failed", ERROR_FILE);
  }
  if (truncate(CODE_FILE, 0) < 0) {
    msg_errno("truncate(\"%s\", 0) failed", CODE_FILE);
  }
  if (chmod(".", 0555) < 0) {
    msg_errno("chmod(\".\",0555) failed");
  }
  execl(dospath, dospath, "-I", "video { none }", NULL);
  msg_errno("execl(\"%s\",...) failed", dospath);
}

/**
 * Local variables:
 *  compile-command: "gcc -s -O2 -Wall dosrun2.c -o dosrun2"
 * End:
 */
