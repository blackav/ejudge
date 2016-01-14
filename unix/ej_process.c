/* -*- mode: c -*- */

/* Copyright (C) 2005-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_process.h"
#include "ejudge/compat.h"
#include "ejudge/list_ops.h"
#include "ejudge/pollfds.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <poll.h>
#include <sys/utsname.h>
#include <dirent.h>

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
        const unsigned char *stdin_file,
        const unsigned char *stdin_text,
        int merge_out_flag,
        unsigned char **stdout_text,
        unsigned char **stderr_text)
{
  char *err_t = 0, *out_t = 0;
  size_t err_z = 0, out_z = 0;
  FILE *err_f = 0, *out_f = 0;
  int pid, out_p[2] = {-1, -1}, err_p[2] = {-1, -1}, in_p[2] = {-1, -1}, in_fd = -1;
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

  if (!stdin_file) {
    if (pipe(in_p) < 0) {
      err_f = open_memstream(&err_t, &err_z);
      fferror(err_f, "pipe failed: %s", strerror(errno));
      goto fail;
    }
  } else {
    if ((in_fd = open(stdin_file, O_RDONLY, 0)) < 0) {
      err_f = open_memstream(&err_t, &err_z);
      fferror(err_f, "cannot open file %s: %s", stdin_file, strerror(errno));
      goto fail;
    }
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
    if (in_fd >= 0) {
      dup2(in_fd, 0); close(in_fd);
    } else {
      dup2(in_p[0], 0); close(in_p[0]); close(in_p[1]);
    }
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
  if (in_fd >= 0) {
    close(in_fd); in_fd = -1;
  }
  if (in_p[0] >= 0) {
    close(in_p[0]); in_p[0] = -1;
  }
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
  if (in_fd >= 0) close(in_fd);
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

struct background_process *
background_process_alloc(void)
{
  struct background_process *prc;

  XCALLOC(prc, 1);
  prc->stdin_f = -1;
  prc->stdout_f = -1;
  prc->stderr_f = -1;
  return prc;
}

struct background_process *
background_process_free(struct background_process *prc)
{
  if (!prc) return NULL;

  xfree(prc->name);
  xfree(prc->stdin_b);
  if (prc->stdin_f >= 0) close(prc->stdin_f);
  if (prc->stdout_f >= 0) close(prc->stdout_f);
  if (prc->stderr_f >= 0) close(prc->stderr_f);
  xfree(prc->out.buf);
  xfree(prc->err.buf);

  memset(prc, 0, sizeof(*prc));
  prc->stdin_f = -1;
  prc->stdout_f = -1;
  prc->stderr_f = -1;

  xfree(prc);
  return NULL;
}

struct background_process *
ejudge_start_process(
        FILE *log_f,
        const unsigned char *name,
        char **args,
        char **envs,
        const unsigned char *workdir,
        const unsigned char *stdin_text,
        int merge_out_flag,
        int time_limit_ms,
        void (*continuation)(struct background_process*),
        void *user)
{
  int in_pipe[2] = { -1, -1 };
  int out_pipe[2] = { -1, -1 };
  int err_pipe[2] = { -1, -1 };
  int pid = 0;
  struct background_process *prc = NULL;
  struct timeval tv;

  if (stdin_text && pipe(in_pipe) < 0) {
    fprintf(log_f, "%s: pipe() failed: %s\n", __FUNCTION__, strerror(errno));
    goto fail;
  }
  if (pipe(out_pipe) < 0) {
    fprintf(log_f, "%s: pipe() failed: %s\n", __FUNCTION__, strerror(errno));
    goto fail;
  }
  if (merge_out_flag <= 0 && pipe(err_pipe) < 0) {
    fprintf(log_f, "%s: pipe() failed: %s\n", __FUNCTION__, strerror(errno));
    goto fail;
  }

  gettimeofday(&tv, NULL);

  if ((pid = fork()) < 0) {
    fprintf(log_f, "%s: fork() failed: %s\n", __FUNCTION__, strerror(errno));
    goto fail;
  } else if (!pid) {
    // son
    fflush(stderr);
    setpgid(0, 0);
    if (err_pipe[1] >= 0) {
      if (dup2(err_pipe[1], 2) < 0) {
        fprintf(stderr, "%s: dup2() failed in child: %s\n", __FUNCTION__,
                strerror(errno));
        fflush(stderr);
        _exit(1);
      }
    } else {
      if (dup2(out_pipe[1], 2) < 0) {
        fprintf(stderr, "%s: dup2() failed in child %s\n", __FUNCTION__,
                strerror(errno));
        fflush(stderr);
        _exit(1);
      }
    }
    // from this point the stderr is redirected to the pipe
    if (dup2(out_pipe[1], 1) < 0) {
      fprintf(stderr, "%s: dup2() failed in child %s\n", __FUNCTION__,
              strerror(errno));
      fflush(stderr);
      _exit(1);
    }
    if (in_pipe[0] < 0) {
      in_pipe[0] = open("/dev/null", O_RDONLY, 0);
      if (in_pipe[0] < 0) {
        fprintf(stderr, "%s: failed to open /dev/null: %s\n", __FUNCTION__,
                strerror(errno));
        _exit(1);
      }
    }
    if (dup2(in_pipe[0], 0) < 0) {
      fprintf(stderr, "%s: dup2() failed in child %s\n", __FUNCTION__,
              strerror(errno));
      fflush(stderr);
      _exit(1);
    }
    if (in_pipe[0] >= 0) close(in_pipe[0]);
    if (in_pipe[1] >= 0) close(in_pipe[1]);
    if (out_pipe[0] >= 0) close(out_pipe[0]);
    if (out_pipe[1] >= 0) close(out_pipe[1]);
    if (err_pipe[0] >= 0) close(err_pipe[0]);
    if (err_pipe[1] >= 0) close(err_pipe[1]);
    if (workdir && chdir(workdir) < 0) {
      fprintf(stderr, "%s: cannot chdir to %s: %s", __FUNCTION__,
              workdir, strerror(errno));
      fflush(stderr);
      _exit(1);
    }
    if (envs) {
      for (int i = 0; envs[i]; ++i) {
        putenv(envs[i]);
      }
    }
    sigset_t mask;
    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, 0);
    execve(args[0], args, environ);
    fprintf(stderr, "%s: exec failed: %s", __FUNCTION__,
            strerror(errno));
    fflush(stderr);
    _exit(1);
  }

  setpgid(pid, pid);

  if (in_pipe[0] >= 0) close(in_pipe[0]);
  in_pipe[0] = -1;
  if (out_pipe[1] >= 0) close(out_pipe[1]);
  out_pipe[1] = -1;
  if (err_pipe[1] >= 0) close(err_pipe[1]);
  err_pipe[1] = -1;

  prc = background_process_alloc();
  prc->name = xstrdup(name);
  if (stdin_text) {
    prc->stdin_b = xstrdup(stdin_text);
    prc->stdin_z = strlen(stdin_text);
  }
  prc->time_limit_ms = time_limit_ms;
  prc->kill_grace_ms = 1000;
  prc->start_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
  prc->merge_out_flag = merge_out_flag;
  if (in_pipe[1] >= 0) {
    prc->stdin_f = in_pipe[1]; in_pipe[1] = -1;
    fcntl(prc->stdin_f, F_SETFL, fcntl(prc->stdin_f, F_GETFL) | O_NONBLOCK);
  }
  if (out_pipe[0] >= 0) {
    prc->stdout_f = out_pipe[0]; out_pipe[0] = -1;
    fcntl(prc->stdout_f, F_SETFL, fcntl(prc->stdout_f, F_GETFL) | O_NONBLOCK);
  }
  if (err_pipe[0] >= 0) {
    prc->stderr_f = err_pipe[0]; err_pipe[0] = -1;
    fcntl(prc->stderr_f, F_SETFL, fcntl(prc->stderr_f, F_GETFL) | O_NONBLOCK);
  }
  prc->state = BACKGROUND_PROCESS_RUNNING;
  prc->pid = pid;
  prc->user = user;
  prc->continuation = continuation;

  return prc;

fail:
  prc = background_process_free(prc);
  if (in_pipe[0] >= 0) close(in_pipe[0]);
  if (in_pipe[1] >= 0) close(in_pipe[1]);
  if (out_pipe[0] >= 0) close(out_pipe[0]);
  if (out_pipe[1] >= 0) close(out_pipe[1]);
  if (err_pipe[0] >= 0) close(err_pipe[0]);
  if (err_pipe[1] >= 0) close(err_pipe[1]);
  return NULL;
}

static int
trywait(struct background_process *prc, long long current_time_ms)
{
  struct rusage usage;
  int status = 0;

  memset(&usage, 0, sizeof(usage));
  if (wait4(prc->pid, &status, WNOHANG, &usage) <= 0) return 0;
  prc->state = BACKGROUND_PROCESS_FINISHED;
  if (WIFEXITED(status)) {
    prc->is_exited = 1;
    prc->exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    prc->is_signaled = 1;
    prc->term_signal = WTERMSIG(status);
  }
  prc->utime_ms = usage.ru_utime.tv_sec * 1000LL + usage.ru_utime.tv_usec / 1000LL;
  prc->stime_ms = usage.ru_stime.tv_sec * 1000LL + usage.ru_stime.tv_usec / 1000LL;
  prc->maxrss = usage.ru_maxrss;
  prc->stop_time_ms = current_time_ms;
  return 1;
}

static void
buffer_append_mem(struct background_process_buffer *p, const unsigned char *buf, int size)
{
  int exp_size = p->size + size + 1;
  int new_size = p->allocated;
  if (exp_size > new_size) {
    if (!new_size) new_size = 64;
    while (new_size < exp_size) new_size *= 2;
    p->buf = xrealloc(p->buf, new_size * sizeof(p->buf[0]));
    p->allocated = new_size;
  }
  memcpy(p->buf + p->size, buf, size);
  p->size += size;
  p->buf[p->size] = 0;
}

static void
buffer_append_str(struct background_process_buffer *p, const unsigned char *str)
{
  if (!str || !*str) return;
  buffer_append_mem(p, str, strlen(str));
}

void
ejudge_check_process_finished(struct background_process *prc)
{
  struct timeval tv;
  long long current_time_ms;
  const unsigned char *msg = NULL;

  if (!prc || prc->state != BACKGROUND_PROCESS_RUNNING) return;

  gettimeofday(&tv, NULL);
  current_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
  if (prc->kill_time_ms > 0) {
    // do nothing
  } else if (prc->term_time_ms > 0) {
    if (current_time_ms >= prc->term_time_ms + prc->kill_grace_ms) {
      kill(-prc->pid, SIGKILL);
      prc->kill_time_ms = current_time_ms;
      msg = "\nKill signal sent\n";
    }
  } else if (prc->time_limit_ms > 0 && current_time_ms >= prc->start_time_ms + prc->time_limit_ms) {
    kill(-prc->pid, SIGTERM);
    prc->term_time_ms = current_time_ms;
    msg = "\nTerm signal sent\n";
  }
  if (msg != NULL) {
    if (prc->merge_out_flag <= 0) {
      buffer_append_str(&prc->err, msg);
    } else {
      buffer_append_str(&prc->out, msg);
    }
  }

  // do not check for finishing until all fds are closed
  if (prc->stdin_f >= 0 || prc->stdout_f >= 0 || prc->stderr_f >= 0) return;
  trywait(prc, current_time_ms);
}

void
background_process_cleanup(struct background_process_head *list)
{
  if (!list) return;
  struct background_process *prc, *next;
  for (prc = list->first; prc; prc = next) {
    next = prc->next;
    if (prc->state == BACKGROUND_PROCESS_GARBAGE) {
      UNLINK_FROM_LIST(prc, list->first, list->last, prev, next);
      background_process_free(prc);
    }
  }
}

int
background_process_set_fds(struct background_process_head *list, int max_fd, void *vprset, void *vpwset)
{
  fd_set *prset = (fd_set*) vprset;
  fd_set *pwset = (fd_set*) vpwset;

  if (!list) return max_fd;
  struct background_process *prc;
  for (prc = list->first; prc; prc = prc->next) {
    if (prc->state != BACKGROUND_PROCESS_RUNNING) continue;
    if (prc->stdin_f >= 0) {
      FD_SET(prc->stdin_f, pwset);
      if (prc->stdin_f > max_fd) max_fd = prc->stdin_f;
    }
    if (prc->stdout_f >= 0) {
      FD_SET(prc->stdout_f, prset);
      if (prc->stdout_f > max_fd) max_fd = prc->stdout_f;
    }
    if (prc->stderr_f >= 0) {
      FD_SET(prc->stderr_f, prset);
      if (prc->stderr_f > max_fd) max_fd = prc->stderr_f;
    }
  }

  return max_fd;
}

static void
handle_stdin(void *context, void *fds, void *user)
{
  struct pollfd *pfd = (struct pollfd *) fds;
  struct background_process *prc = (struct background_process *) user;

  ASSERT(prc);
  ASSERT(prc->stdin_f == pfd->fd);

  if ((pfd->revents & POLLNVAL)) {
    fprintf(stderr, "%s: ppoll invalid request fd=%d\n", __FUNCTION__, pfd->fd);
    goto cleanup;
  }
  if ((pfd->revents & POLLHUP)) {
    fprintf(stderr, "%s: ppoll hangup fd=%d\n", __FUNCTION__, pfd->fd);
    goto cleanup;
  }
  if ((pfd->revents & POLLERR)) {
    fprintf(stderr, "%s: ppoll error fd=%d\n", __FUNCTION__, pfd->fd);
    goto cleanup;
  }
  if (!(pfd->revents & POLLOUT)) {
    fprintf(stderr, "%s: ppoll not ready fd=%d\n", __FUNCTION__, pfd->fd);
    return;
  }

  if (!prc->stdin_b || prc->stdin_z <= 0 || prc->stdin_u >= prc->stdin_z) {
    close(prc->stdin_f); prc->stdin_f = -1;
    return;
  }

  int wsz = prc->stdin_z - prc->stdin_u;
  while (1) {
    int w = write(prc->stdin_f, prc->stdin_b + prc->stdin_u, wsz);
    if (w < 0) {
      if (errno != EAGAIN) {
        fprintf(stderr, "%s: write to pipe fd=%d failed: %s\n", __FUNCTION__,
                pfd->fd, strerror(errno));
        close(prc->stdin_f); prc->stdin_f = -1;
        break;
      } else if (wsz == 1) {
        break;
      } else {
        wsz /= 2;
      }
    } else if (w == 0) {
      fprintf(stderr, "%s: write to pipe fd=%d returned 0!\n", __FUNCTION__,
              pfd->fd);
      close(prc->stdin_f); prc->stdin_f = -1;
      break;
    } else {
      prc->stdin_u += w;
      wsz = prc->stdin_z - prc->stdin_u;
      if (w <= 0) {
        close(prc->stdin_f); prc->stdin_f = -1;
        break;
      }
    }
  }
  return;

cleanup:
  close(prc->stdin_f);
  prc->stdin_f = -1;
  xfree(prc->stdin_b); prc->stdin_b = NULL;
  prc->stdin_z = 0; prc->stdin_u = 0;
}

static void
handle_stdout(void *context, void *fds, void *user)
{
  struct pollfd *pfd = (struct pollfd *) fds;
  struct background_process *prc = (struct background_process *) user;
  unsigned char buf[4096];

  ASSERT(prc);
  ASSERT(prc->stdout_f == pfd->fd);

  if ((pfd->revents & POLLNVAL)) {
    fprintf(stderr, "%s: ppoll invalid request fd=%d\n", __FUNCTION__, pfd->fd);
    close(prc->stdout_f); prc->stdout_f = -1;
    return;
  }
  if ((pfd->revents & POLLHUP)) {
    fprintf(stderr, "%s: ppoll hangup fd=%d\n", __FUNCTION__, pfd->fd);
    close(prc->stdout_f); prc->stdout_f = -1;
    return;
  }
  if ((pfd->revents & POLLERR)) {
    fprintf(stderr, "%s: ppoll error fd=%d\n", __FUNCTION__, pfd->fd);
    close(prc->stdout_f); prc->stdout_f = -1;
    return;
  }
  if (!(pfd->revents & POLLIN)) {
    fprintf(stderr, "%s: ppoll not ready fd=%d\n", __FUNCTION__, pfd->fd);
    return;
  }

  while (1) {
    int r = read(prc->stdout_f, buf, sizeof(buf));
    if (r < 0) {
      if (errno != EAGAIN) {
        fprintf(stderr, "%s: read from pipe fd=%d failed: %s\n", __FUNCTION__,
                pfd->fd, strerror(errno));
        close(prc->stdout_f); prc->stdout_f = -1;
      }
      break;
    } else if (r == 0) {
      close(prc->stdout_f); prc->stdout_f = -1;
      break;
    } else {
      buffer_append_mem(&prc->out, buf, r);
    }
  }
}

static void
handle_stderr(void *context, void *fds, void *user)
{
  struct pollfd *pfd = (struct pollfd *) fds;
  struct background_process *prc = (struct background_process *) user;
  unsigned char buf[4096];

  ASSERT(prc);
  ASSERT(prc->stderr_f == pfd->fd);

  if ((pfd->revents & POLLNVAL)) {
    fprintf(stderr, "%s: ppoll invalid request fd=%d\n", __FUNCTION__, pfd->fd);
    close(prc->stderr_f); prc->stderr_f = -1;
    return;
  }
  if ((pfd->revents & POLLHUP)) {
    fprintf(stderr, "%s: ppoll hangup fd=%d\n", __FUNCTION__, pfd->fd);
    close(prc->stderr_f); prc->stderr_f = -1;
    return;
  }
  if ((pfd->revents & POLLERR)) {
    fprintf(stderr, "%s: ppoll error fd=%d\n", __FUNCTION__, pfd->fd);
    close(prc->stderr_f); prc->stderr_f = -1;
    return;
  }
  if (!(pfd->revents & POLLIN)) {
    fprintf(stderr, "%s: ppoll not ready fd=%d\n", __FUNCTION__, pfd->fd);
    return;
  }

  while (1) {
    int r = read(prc->stderr_f, buf, sizeof(buf));
    if (r < 0) {
      if (errno != EAGAIN) {
        fprintf(stderr, "%s: read from pipe fd=%d failed: %s\n", __FUNCTION__, pfd->fd, strerror(errno));
        close(prc->stderr_f); prc->stderr_f = -1;
      }
      break;
    } else if (r == 0) {
      close(prc->stderr_f); prc->stderr_f = -1;
      break;
    } else {
      buffer_append_mem(&prc->err, buf, r);
    }
  }
}

void
background_process_append_pollfd(struct background_process_head *list, void *vp)
{
  pollfds_t *pfd = (pollfds_t*) vp;
  if (!list) return;
  struct background_process *prc;
  for (prc = list->first; prc; prc = prc->next) {
    if (prc->state != BACKGROUND_PROCESS_RUNNING) continue;
    if (prc->stdin_f >= 0) {
      pollfds_add(pfd, prc->stdin_f, POLLOUT, handle_stdin, prc);
    }
    if (prc->stdout_f >= 0) {
      pollfds_add(pfd, prc->stdout_f, POLLIN, handle_stdout, prc);
    }
    if (prc->stderr_f >= 0) {
      pollfds_add(pfd, prc->stdout_f, POLLIN, handle_stderr, prc);
    }
  }
}

void
background_process_readwrite(struct background_process_head *list, void *vprset, void *vpwset)
{
  fd_set *prset = (fd_set*) vprset;
  fd_set *pwset = (fd_set*) vpwset;
  unsigned char buf[4096];

  if (!list) return;
  struct background_process *prc;
  for (prc = list->first; prc; prc = prc->next) {
    if (prc->state != BACKGROUND_PROCESS_RUNNING) continue;
    if (prc->stdin_f >= 0 && FD_ISSET(prc->stdin_f, pwset)) {
      if (!prc->stdin_b || prc->stdin_z <= 0 || prc->stdin_u >= prc->stdin_z) {
        close(prc->stdin_f); prc->stdin_f = -1;
      } else {
        int wsz = prc->stdin_z - prc->stdin_u;
        while (1) {
          int w = write(prc->stdin_f, prc->stdin_b + prc->stdin_u, wsz);
          if (w < 0) {
            if (errno != EAGAIN) {
              fprintf(stderr, "%s: write to pipe failed: %s\n", __FUNCTION__, strerror(errno));
              close(prc->stdin_f); prc->stdin_f = -1;
              break;
            } else if (wsz == 1) {
              break;
            } else {
              wsz /= 2;
            }
          } else if (w == 0) {
            fprintf(stderr, "%s: write to pipe returned 0!\n", __FUNCTION__);
            close(prc->stdin_f); prc->stdin_f = -1;
            break;
          } else {
            prc->stdin_u += w;
            wsz = prc->stdin_z - prc->stdin_u;
            if (w <= 0) {
              close(prc->stdin_f); prc->stdin_f = -1;
              break;
            }
          }
        }
      }
      //FD_CLR(prc->stdin_f, pwset);
    }
    if (prc->stdout_f >= 0 && FD_ISSET(prc->stdout_f, prset)) {
      while (1) {
        int r = read(prc->stdout_f, buf, sizeof(buf));
        if (r < 0) {
          if (errno != EAGAIN) {
            fprintf(stderr, "%s: read from pipe failed: %s\n", __FUNCTION__, strerror(errno));
            close(prc->stdout_f); prc->stdout_f = -1;
          }
          break;
        } else if (r == 0) {
          close(prc->stdout_f); prc->stdout_f = -1;
          break;
        } else {
          buffer_append_mem(&prc->out, buf, r);
        }
      }
      //FD_CLR(prc->stdout_f, prset);
    }
    if (prc->stderr_f >= 0 && FD_ISSET(prc->stderr_f, prset)) {
      while (1) {
        int r = read(prc->stderr_f, buf, sizeof(buf));
        if (r < 0) {
          if (errno != EAGAIN) {
            fprintf(stderr, "%s: read from pipe failed: %s\n", __FUNCTION__, strerror(errno));
            close(prc->stderr_f); prc->stderr_f = -1;
          }
          break;
        } else if (r == 0) {
          close(prc->stderr_f); prc->stderr_f = -1;
          break;
        } else {
          buffer_append_mem(&prc->err, buf, r);
        }
      }
      //FD_CLR(prc->stderr_f, prset);
    }
  }
}

void
background_process_check_finished(struct background_process_head *list)
{
  if (!list) return;
  struct background_process *prc;
  for (prc = list->first; prc; prc = prc->next) {
    ejudge_check_process_finished(prc);
  }
}

void
background_process_register(struct background_process_head *list, struct background_process *prc)
{
  if (!list || !prc) return;
  LINK_FIRST(prc, list->first, list->last, prev, next);
}

struct background_process *
background_process_find(struct background_process_head *list, const unsigned char *name)
{
  if (!list || !name) return NULL;
  struct background_process *prc;
  for (prc = list->first; prc; prc = prc->next) {
    if (!strcmp(prc->name, name))
      return prc;
  }
  return NULL;
}

int
background_process_handle_termination(
        struct background_process_head *list,
        int pid,
        int status,
        const void *vusage)
{
  const struct rusage *pusage = (typeof(pusage)) vusage;
  if (!list) return 0;
  struct background_process *prc;
  for (prc = list->first; prc; prc = prc->next) {
    if (prc->state == BACKGROUND_PROCESS_RUNNING && prc->pid == pid) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      long long current_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
      prc->state = BACKGROUND_PROCESS_FINISHED;
      if (WIFEXITED(status)) {
        prc->is_exited = 1;
        prc->exit_code = WEXITSTATUS(status);
      } else if (WIFSIGNALED(status)) {
        prc->is_signaled = 1;
        prc->term_signal = WTERMSIG(status);
      }
      prc->utime_ms = pusage->ru_utime.tv_sec * 1000LL + pusage->ru_utime.tv_usec / 1000LL;
      prc->stime_ms = pusage->ru_stime.tv_sec * 1000LL + pusage->ru_stime.tv_usec / 1000LL;
      prc->maxrss = pusage->ru_maxrss;
      prc->stop_time_ms = current_time_ms;
      return 1;
    }
  }
  return 0;
}

void
background_process_call_continuations(struct background_process_head *list)
{
  if (!list) return;
  struct background_process *prc;
  for (prc = list->first; prc; prc = prc->next) {
    if (prc->state == BACKGROUND_PROCESS_FINISHED && prc->continuation) {
      prc->continuation(prc);
    }
  }
}

void
background_process_close_fds(struct background_process_head *list)
{
  if (!list) return;
  struct background_process *prc;
  for (prc = list->first; prc; prc = prc->next) {
    if (prc->stdin_f >= 0) close(prc->stdin_f);
    if (prc->stdout_f >= 0) close(prc->stdout_f);
    if (prc->stderr_f >= 0) close(prc->stderr_f);
  }
}

unsigned char **
ejudge_get_host_names(void)
{
  int names_z = 4, names_u = 0, len;
  unsigned char **names = NULL;
  FILE *f = NULL;
  unsigned char buf[1024], *s, nbuf[1024];
  struct utsname uname_buf;

  static const unsigned char pat1[] = "inet ";
  static const unsigned char pat2[] = "inet6 ";

  XCALLOC(names, names_z);
  if (!(f = popen("/sbin/ifconfig", "r"))) goto fail;

  while (fgets(buf, sizeof(buf), f)) {
    len = strlen(buf);
    if (len + 10 > sizeof(buf)) {
      // line is too long in ifconfig
      goto fail;
    }
    while (len > 0 && isspace(buf[len - 1])) --len;
    buf[len] = 0;
    nbuf[0] = 0;
    if ((s = strstr(buf, pat1))) {
      sscanf(s + sizeof(pat1) - 1, "%s", nbuf);
    } else if ((s = strstr(buf, pat2))) {
      sscanf(s + sizeof(pat2) - 1, "%s", nbuf);
    }

    if (nbuf[0]) {
      if (names_u + 1 >= names_z) {
        XREALLOC(names, (names_z *= 2));
      }
      names[names_u++] = xstrdup(nbuf);
      names[names_u] = NULL;
    }
  }
  pclose(f); f = NULL;

  if (uname(&uname_buf) >= 0) {
    if (names_u + 1 >= names_z) {
      XREALLOC(names, (names_z *= 2));
    }
    names[names_u++] = xstrdup(uname_buf.nodename);
    names[names_u] = NULL;
  }

cleanup:
  if (f) {
    pclose(f); f = NULL;
  }
  return names;

fail:
  if (names) {
    for (int i = 0; names[i]; ++i) {
      xfree(names[i]);
    }
    xfree(names); names = NULL;
  }
  goto cleanup;
}

int
ejudge_start_daemon_process(
        char **args,
        const unsigned char *workdir)
{
  int pid;

  if ((pid = fork()) < 0) {
    fprintf(stderr, "%s: fork() failed: %s\n", __FUNCTION__, strerror(errno));
    return -1;
  }
  if (pid > 0) {
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    // check exit status?
    return 0;
  }

  // now in child
  if ((pid = fork()) != 0) _exit(pid < 0);

  // now in grandchild
  if (workdir) {
    if (chdir(workdir) < 0) _exit(1);
  }

  DIR *d;
  struct dirent *dd;
  int max_fd = -1;
  if ((d = opendir("/proc/self/fd"))) {
    while ((dd = readdir(d))) {
      int n = strtol(dd->d_name, NULL, 10);
      if (n > max_fd) max_fd = n;
    }
    closedir(d);
  }
  if (max_fd < 0) max_fd = 1024;
  for (int fd = 3; fd <= max_fd; ++fd) {
    close(fd);
  }
  close(0); open("/dev/null", O_RDONLY, 0);
  dup2(2, 1);

  sigset_t mask;
  sigemptyset(&mask);
  sigprocmask(SIG_SETMASK, &mask, 0);
  execve(args[0], args, environ);
  _exit(1);
}

static void
msg(const unsigned char *path, const char *function, int lineno,
    const char *format, ...)
  __attribute__((format(printf, 4, 5)));
static void
msg(const unsigned char *path, const char *function, int lineno,
    const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  int revision = 0;
  sscanf("$Revision$", "$" "Revision:%d", &revision);

  if (!path) {
    fprintf(stderr, "%s: %d: %d: %s\n", function, lineno, revision, buf);
  } else {
    FILE *f = fopen(path, "a");
    if (f) {
      fprintf(f, "%s: %d: %d: %s\n", function, lineno, revision, buf);
      fflush(f);
      fclose(f);
      f = NULL;
    }
  }
}

#define MSG(p,f,...) msg(p,__FUNCTION__,__LINE__,f, ## __VA_ARGS__)

int
ejudge_timed_write(
        const unsigned char *log,
        int fd,
        const void *data,
        ssize_t size,
        int timeout_ms)
{
  if (size <= 0) {
    MSG(log, "invalid size: %lld", (long long) size);
    goto fail;
  }
  if (timeout_ms <= 0) {
    MSG(log, "invalid timeout %d", timeout_ms);
    goto fail;
  }
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) {
    MSG(log, "fcntl failed: %s", strerror(errno));
    goto fail;
  }
  if (!(flags & O_NONBLOCK)) {
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      MSG(log, "fcntl failed: %s", strerror(errno));
      goto fail;
    }
  }
  struct timeval cur;
  gettimeofday(&cur, NULL);
  long long cur_ms = cur.tv_sec * 1000LL + cur.tv_usec / 1000;
  long long break_ms = cur_ms + timeout_ms;
  const unsigned char *cur_data = (const unsigned char*) data;
  while (1) {
    long long wait_ms = break_ms - cur_ms;
    if (wait_ms <= 0) {
      MSG(log, "write time-out");
      goto fail;
    }
    struct timeval wait_tv;
    wait_tv.tv_sec = wait_ms / 1000;
    wait_tv.tv_usec = (wait_ms % 1000) * 1000;
    fd_set wfd;
    FD_ZERO(&wfd);
    FD_SET(fd, &wfd);
    int n = select(fd + 1, NULL, &wfd, NULL, &wait_tv);
    if (n < 0 && errno == EINTR) {
      gettimeofday(&cur, NULL);
      cur_ms = cur.tv_sec * 1000LL + cur.tv_usec / 1000;
      continue;
    }
    if (n < 0) {
      MSG(log, "select failed: %s", strerror(errno));
      goto fail;
    }
    if (n == 0) {
      MSG(log, "write time-out");
      goto fail;
    }
    if (!FD_ISSET(fd, &wfd)) {
      gettimeofday(&cur, NULL);
      cur_ms = cur.tv_sec * 1000LL + cur.tv_usec / 1000;
      continue;
    }
    while (1) {
      ssize_t w = write(fd, cur_data, size);
      if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      }
      if (w < 0) {
        MSG(log, "write failed: %s", strerror(errno));
        goto fail;
      }
      if (w == 0) {
        MSG(log, "write returned 0");
        goto fail;
      }
      cur_data += w;
      size -= w;
      if (!size) {
        goto success;
      }
    }
    gettimeofday(&cur, NULL);
    cur_ms = cur.tv_sec * 1000LL + cur.tv_usec / 1000;
  }

success:
  return 0;

fail:
  return -1;
}

ssize_t
ejudge_timed_fdgets(
        const unsigned char *log,
        int fd,
        unsigned char *buf,
        ssize_t size,
        int timeout_ms)
{
  if (size < 2) {
    MSG(log, "invalid size: %lld", (long long) size);
    goto fail;
  }
  if (timeout_ms <= 0) {
    MSG(log, "invalid timeout %d", timeout_ms);
    goto fail;
  }
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) {
    MSG(log, "fcntl failed: %s", strerror(errno));
    goto fail;
  }
  if (!(flags & O_NONBLOCK)) {
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      MSG(log, "fcntl failed: %s", strerror(errno));
      goto fail;
    }
  }
  struct timeval cur;
  gettimeofday(&cur, NULL);
  long long cur_ms = cur.tv_sec * 1000LL + cur.tv_usec / 1000;
  long long break_ms = cur_ms + timeout_ms;
  unsigned char *cur_buf = (unsigned char*) buf;
  ssize_t cur_size = size - 1;
  while (1) {
    long long wait_ms = break_ms - cur_ms;
    if (wait_ms <= 0) {
      MSG(log, "read time-out");
      goto fail;
    }
    struct timeval wait_tv;
    wait_tv.tv_sec = wait_ms / 1000;
    wait_tv.tv_usec = (wait_ms % 1000) * 1000;
    fd_set rfd;
    FD_ZERO(&rfd);
    FD_SET(fd, &rfd);
    int n = select(fd + 1, &rfd, NULL, NULL, &wait_tv);
    if (n < 0 && errno == EINTR) {
      gettimeofday(&cur, NULL);
      cur_ms = cur.tv_sec * 1000LL + cur.tv_usec / 1000;
      continue;
    }
    if (n < 0) {
      MSG(log, "select failed: %s", strerror(errno));
      goto fail;
    }
    if (n == 0) {
      MSG(log, "read time-out");
      goto fail;
    }
    if (!FD_ISSET(fd, &rfd)) {
      gettimeofday(&cur, NULL);
      cur_ms = cur.tv_sec * 1000LL + cur.tv_usec / 1000;
      continue;
    }
    while (1) {
      ssize_t r = read(fd, cur_buf, cur_size);
      if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      }
      if (r < 0) {
        MSG(log, "read failed: %s", strerror(errno));
        goto fail;
      }
      if (!r) {
        // EOF
        cur_size = size - 1 - cur_size;
        buf[cur_size] = 0;
        return cur_size;
      }
      cur_size -= r; cur_buf += r;
      ssize_t len = size - 1 - cur_size;
      buf[len] = 0;
      if (strlen(buf) != len) {
        // '\0' in the middle
        MSG(log, "\\0 byte in read data");
        goto fail;
      }
      char *pp = strchr(buf, '\n');
      if (pp && pp[1]) {
        // '\n' not in the last byte
        MSG(log, "\\n in the middle of read data");
        goto fail;
      }
      if (pp || !cur_size) {
        return len;
      }
    }
    gettimeofday(&cur, NULL);
    cur_ms = cur.tv_sec * 1000LL + cur.tv_usec / 1000;
  }

fail:
  return -1;
}
