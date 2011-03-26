/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005-2011 Alexander Chernov <cher@ejudge.ru> */

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
#include "compat.h"

#include "reuse_xalloc.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

static int
error(const char *format, ...)
  __attribute__((format(printf, 1, 2)));
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
fferror(FILE *ferr, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
static int
fferror(FILE *ferr, const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(ferr, "error: %s\n", buf);
  return -1;
}

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
  close_memstream(fout); fout = 0;
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
  if (fout) close_memstream(fout);
  xfree(out_txt);
  return 0;
}

int
ejudge_invoke_process(
        char **args,
        char **envs,
        const unsigned char *workdir,
        const unsigned char *stdin_text,
        int merge_out_flag,
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
  int i;
  sigset_t mask;

  if (!stdin_text) stdin_text = "";
  stdin_ptr = stdin_text;
  stdin_len = strlen(stdin_text);

  if (pipe(in_p) < 0) {
    err_f = open_memstream(&err_t, &err_z);
    fferror(err_f, "pipe failed: %s", strerror(errno));
    goto fail;
  }
  if (pipe(out_p) < 0) {
    err_f = open_memstream(&err_t, &err_z);
    fferror(err_f, "pipe failed: %s", strerror(errno));
    goto fail;
  }
  if (!merge_out_flag) {
    if (pipe(err_p) < 0) {
      err_f = open_memstream(&err_t, &err_z);
      fferror(err_f, "pipe failed: %s", strerror(errno));
      goto fail;
    }
  }

  if ((pid = fork()) < 0) {
    err_f = open_memstream(&err_t, &err_z);
    fferror(err_f, "fork failed: %s", strerror(errno));
    goto fail;
  } else if (!pid) {
    fflush(stderr);
    dup2(in_p[0], 0); close(in_p[0]); close(in_p[1]);
    dup2(out_p[1], 1); close(out_p[0]); close(out_p[1]);
    if (!merge_out_flag) {
      dup2(err_p[1], 2); close(err_p[0]); close(err_p[1]);
    } else {
      dup2(1, 2);
    }

    if (workdir) {
      if (chdir(workdir) < 0) {
        error("cannot change directory to %s: %s", workdir, strerror(errno));
        fflush(stderr);
        _exit(1);
      }
    }
    if (envs) {
      for (i = 0; envs[i]; ++i) {
        putenv(envs[i]);
      }
    }
    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, 0);
    execve(args[0], args, environ);
    error("exec failed: %s", strerror(errno));
    fflush(stderr);
    _exit(1);
  }

  /* parent */
  close(in_p[0]); in_p[0] = -1;
  close(out_p[1]); out_p[1] = -1;
  if (err_p[1] >= 0) {
    close(err_p[1]);
  }
  err_p[1] = -1;
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
    retcode = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    retcode = 256 + WTERMSIG(status);
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

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
