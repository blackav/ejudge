/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002,2003 Alexander Chernov <cher@ispras.ru> */

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

/* Note: this is Borland C program!
 * Recommented memory model: tiny.
 */

#include <stdio.h>
#include <alloc.h>
#include <process.h>
#include <dos.h>
#include <io.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>

/*
 * Format of command file as follows:
 *   <errorcode_file>
 *   <stdin_file>
 *   <stdout_file>
 *   <stderr_file>
 *   <prog_str>
 *   <arg1_src>
 *   <arg2_src>
 */

unsigned _stklen = 1024;
unsigned _heaplen = 8096;

unsigned char errorcode_file[64] = ".\\retcode.txt";
unsigned char errorcode_str[64];
unsigned char stdin_str[64];
unsigned char stdout_str[64];
unsigned char stderr_str[64];
unsigned char prog_str[64];
unsigned char arg1_str[64];
unsigned char arg2_str[64];

void do_exit(int code)
{
  int fd, n;
  char buf[32];

  n = sprintf(buf, "%d\r\n", code);
  fd = _creat(errorcode_file, 0);
  if (fd < 0) {
    fprintf(stderr, "_creat failed:"); perror("");
    exit(code);
  }
  _write(fd, buf, n);
  _close(fd);
  exit(code);
}

int
getstr(FILE *f, unsigned char *buf)
{
  char *x = fgets(buf, 64, f);
  int l;

  if (!x) {
    fprintf(stderr, "unexpected EOF\n");
    do_exit(-1);
  }
  l = strlen(buf);
  if (l == 63) {
    fprintf(stderr, "config string is too long\n");
    do_exit(-1);
  }
  while (l > 0 && isspace(buf[l - 1])) l--;
  buf[l] = 0;
  return l;
}

int main(int argc, char *argv[])
{
  unsigned long memsize;
  FILE *f;
  char *args[10];
  int fd, n;

  setbuf(stdout, 0);
  setbuf(stderr, 0);
  setbuf(stdaux, 0);
  setbuf(stdprn, 0);
  if (argc == 1) {
    fprintf(stderr, "invalid command line arguments\n");
    do_exit(-1);
  }

  f = fopen(argv[1], "r");
  if (!f) {
    fprintf(stderr, "cannot open command file\n");
    do_exit(-1);
  }
  getstr(f, errorcode_str);
  getstr(f, stdin_str);
  getstr(f, stdout_str);
  getstr(f, stderr_str);
  getstr(f, prog_str);
  getstr(f, arg1_str);
  getstr(f, arg2_str);
  fclose(f);
  if (errorcode_str[0]) strcpy(errorcode_file, errorcode_str);

  args[0] = prog_str;
  if (arg1_str[0]) {
    args[1] = arg1_str;
    if (arg2_str[0]) {
      args[2] = arg2_str;
      args[3] = 0;
    } else {
      args[2] = 0;
    }
  } else {
    args[1] = 0;
  }

  if (stdin_str[0]) {
    fd = _open(stdin_str, O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "cannot redirect stdin\n");
      do_exit(-1);
    }
    dup2(fd, 0);
    _close(fd);
  }

  if (stdout_str[0]) {
    fclose(stdout);
    fd = _open(stdout_str, O_WRONLY | O_TRUNC | O_CREAT);
    if (fd < 0) {
      fprintf(stderr, "cannot redirect stdout\n");
      do_exit(-1);
    }
    dup2(fd, 1);
    _close(fd);
  }

  if (stderr_str[0]) {
    fclose(stderr);
    fd = _open(stderr_str, O_WRONLY | O_TRUNC | O_CREAT);
    if (fd < 0) {
      fprintf(stderr, "cannot redirect stderr\n");
      do_exit(-1);
    }
    dup2(fd, 2);
    _close(fd);
  }

  fflush(0);
  n = spawnvp(P_WAIT, args[0], args);
  if (n < 0) do_exit(-1);
  do_exit(n);
  /*
  memsize = coreleft();
  printf("%lu\n", memsize);
  spawnlp(P_WAIT, "coreleft", "coreleft", 0);
  system("coreleft");
  */
  return 0;
}
