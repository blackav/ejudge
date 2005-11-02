/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@unicorn.cmc.msu.ru> */

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

#include "ej_process.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

unsigned char *
read_process_output(const unsigned char *cmd,
                    const unsigned char *workdir,
                    int max_ok_code,
                    int redirect_stderr)
{
  FILE *fin = 0;
  FILE *fout = 0;
  char *out_txt = 0;
  size_t out_len = 0;
  int pfd[2] = { -1, -1 };
  int c, pid, status;
  sigset_t mask;

  if (!(fout = open_memstream(&out_txt, &out_len))) goto failed;
  if (pipe(pfd) < 0) goto failed;
  if ((pid = fork()) < 0) goto failed;
  if (!pid) {
    // child
    close(pfd[0]);
    dup2(pfd[1], 1);
    if (redirect_stderr) dup2(pfd[1], 2);
    close(pfd[1]);
    if (workdir) chdir(workdir);
    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, 0);
    execl("/bin/sh", "/bin/sh", "-c", cmd, NULL);
    _exit(1);
  }
  close(pfd[1]); pfd[1] = -1;
  if (!(fin = fdopen(pfd[0], "r"))) goto failed;
  pfd[0] = -1;
  while ((c = getc(fin)) != EOF) putc(c, fout);
  waitpid(pid, &status, 0);
  fclose(fin);
  fclose(fout);
  c = 1;
  if (WIFEXITED(status) && (WEXITSTATUS(status) & 0xff) <= max_ok_code) c = 0;

  if (c) {
    xfree(out_txt);
    return xstrdup("");
  }

  out_len = strlen(out_txt);
  while (out_len > 0 && isspace(out_txt[out_len - 1])) out_txt[--out_len] = 0;
  return out_txt;

 failed:
  if (pfd[0] >= 0) close(pfd[0]);
  if (pfd[1] >= 0) close(pfd[1]);
  if (fin) pclose(fin);
  if (fout) fclose(fout);
  xfree(out_txt);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
