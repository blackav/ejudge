/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003 Alexander Chernov <cher@unicorn.cmc.msu.ru> */

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

#include "version.h"
#include "userlist_cfg.h"
#include "contests.h"
#include "pathutl.h"

#include <reuse/xalloc.h>
#include <reuse/osdeps.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <dirent.h>

struct contest_extra
{
  int id;
  unsigned char serve_used;
  unsigned char run_used;
  unsigned char dnotify_flag;

  int serve_pid;
  int run_pid;
  int socket_fd;
  int run_dir_fd;
  int uid;
  int gid;
  unsigned char *socket_path;
  unsigned char *root_dir;
  unsigned char *conf_file;
  unsigned char *log_file;
  unsigned char *run_queue_dir;
  unsigned char *run_log_file;
};

static struct userlist_cfg *config;
static int self_uid;
static int self_gid;

static int contest_num = 0;
static struct contest_extra *contest_extra = 0;

static volatile int term_flag;
static void
handler_term(int signo)
{
  term_flag = 1;
}

static volatile int  hup_flag;
static void
handler_hup(int signo)
{
  hup_flag = 1;
}

static volatile int sigchld_flag;
static void
handler_child(int signo)
{
  sigchld_flag = 1;
}

static volatile int dnotify_flag = 0;
static void
dnotify_handler(int signo, siginfo_t *si, void *data)
{
  int i;

  if (si->si_fd < 0) return;
  /* FIXME: have fd -> contest_id map? */
  for (i = 0; i < contest_num; i++) {
    if (!contest_extra[i].run_used) continue;
    if (contest_extra[i].run_dir_fd == si->si_fd) {
      contest_extra[i].dnotify_flag = 1;
      dnotify_flag = 1;
    }      
  }
}

static void
acquire_resources(void)
{
  unsigned char *contest_map = 0;
  int contest_max_ind = 0, i, errcode;
  struct contest_desc *cnts;
  struct passwd *ppwd;
  struct group *pgrp;
  struct stat stbuf;
  unsigned char serve_cfg[PATH_MAX];
  unsigned char serve_var[PATH_MAX];
  unsigned char serve_socket[PATH_MAX];
  unsigned char run_queue_dir[PATH_MAX];
  unsigned char serve_log[PATH_MAX];
  unsigned char run_log[PATH_MAX];
  int cmd_socket, queue_dir_fd;
  struct sockaddr_un cmd_addr;
  struct contest_extra *cur;
  int need_dnotify_handler = 0;
  struct sigaction dn_act;

  info("scanning available contests...");
  contest_max_ind = contests_get_list(&contest_map);
  if (contest_max_ind <= 0 || !contest_map) return;

  contest_extra = (struct contest_extra*) xcalloc(contest_max_ind + 1, sizeof(contest_extra[0]));
  contest_num = contest_max_ind + 1;

  // scan available contests for managed contests
  for (i = 1; i < contest_max_ind; i++) {
    if (!contest_map[i]) continue;
    if ((errcode = contests_get(i, &cnts)) < 0) {
      err("cannot load contest %d: %s", i, contests_strerror(-errcode));
      continue;
    }
    if (!cnts->managed) {
      info("contest %d is not managed", i);
      continue;
    }
    if (!cnts->root_dir || !*cnts->root_dir) {
      err("contest %d root directory is not set", i);
      continue;
    }

    ppwd = 0;
    pgrp = 0;
    if (cnts->serve_user && *cnts->serve_user) {
      ppwd = getpwnam(cnts->serve_user);
      if (!ppwd) {
        err("contest %d lookup for user %s failed", i, cnts->serve_user);
        continue;
      }
      info("contest %d user '%s' is %d", i, cnts->serve_user, ppwd->pw_uid);
    }
    if (cnts->serve_group && *cnts->serve_group) {
      pgrp = getgrnam(cnts->serve_group);
      if (!pgrp) {
        err("contest %d lookup for group %s failed", i, cnts->serve_group);
        continue;
      }
      info("contest %d group '%s' is %d", i, cnts->serve_group, pgrp->gr_gid);
    }

    if (ppwd && self_uid != 0 && ppwd->pw_uid != self_uid) {
      err("contest %d serve user uid %d differs from self uid %d",
          i, ppwd->pw_uid, self_uid);
      continue;
    }
    if (pgrp && self_uid != 0 && pgrp->gr_gid != self_gid) {
      // FIXME: check, that the group is a secondary group...
      err("contest %d serve group id %d differs grom self gid %d",
          i, pgrp->gr_gid, self_gid);
      continue;
    }

    // serve_root must exist and be a directory
    if (stat(cnts->root_dir, &stbuf) < 0) {
      err("contest %d root_dir '%s' does not exist", i, cnts->root_dir);
      continue;
    }
    if (!S_ISDIR(stbuf.st_mode)) {
      err("contest %d root_dir '%s' is not a directory", i, cnts->root_dir);
      continue;
    }

    // serve config must exist and be a regular file
    // FIXME: add a possibility to define config_name?
    snprintf(serve_cfg, sizeof(serve_cfg), "%s/%s",
             cnts->root_dir, "conf/serve.cfg");
    if (stat(serve_cfg, &stbuf) < 0) {
      err("contest %d configuration file '%s' does not exist", i, serve_cfg);
      continue;
    }
    if (!S_ISREG(stbuf.st_mode)) {
      err("contest %d configuration file '%s' is not regular", i, serve_cfg);
      continue;
    }

    // FIXME: add a possibility to define var_name
    snprintf(serve_var, sizeof(serve_var), "%s/%s", cnts->root_dir, "var");
    if (stat(serve_var, &stbuf) < 0) {
      // FIXME: create directory with proper uid ang gid...
      err("contest %d var directory '%s' does not exist", i, serve_var);
      continue;
    }
    if (!S_ISDIR(stbuf.st_mode)) {
      err("contest %d var directory '%s' is not a directory", i, serve_var);
      continue;
    }

    // FIXME: add a possibility to define socket name
    snprintf(serve_socket, sizeof(serve_socket), "%s/%s", serve_var, "serve");

    cmd_socket = socket(PF_UNIX, SOCK_STREAM, 0);
    if (cmd_socket < 0) {
      err("contest %d socket() failed: %s", i, os_ErrorMsg());
      continue;
    }

    memset(&cmd_addr, 0, sizeof(cmd_addr));
    cmd_addr.sun_family = AF_UNIX;
    strncpy(cmd_addr.sun_path, serve_socket, 108);
    cmd_addr.sun_path[107] = 0;
    errno = 0;
    if (bind(cmd_socket, (struct sockaddr *) &cmd_addr, sizeof(cmd_addr))<0) {
      if (errno == EADDRINUSE) {
        err("contest %d already served (socket exist)", i);
      } else {
        err("contest %d bind() to %s failed: %s",i,serve_socket,os_ErrorMsg());
      }
      close(cmd_socket);
      continue;
    }

    if (chmod(serve_socket, 0777) < 0) {
      err("contest %d chmod failed: %s", i, os_ErrorMsg());
      unlink(serve_socket);
      close(cmd_socket);
      continue;
    }

    if (listen(cmd_socket, 5) < 0) {
      err("contest %d listen failed: %s", i, os_ErrorMsg());
      unlink(serve_socket);
      close(cmd_socket);
      continue;
    }

    snprintf(serve_log, sizeof(serve_log), "%s/%s", serve_var, "messages");

    // create an entry
    cur = &contest_extra[i];
    cur->serve_used = 1;
    cur->id = i;
    cur->serve_pid = -1;
    cur->socket_fd = cmd_socket;
    cur->uid = self_uid;
    if (ppwd) cur->uid = ppwd->pw_uid;
    cur->gid = self_gid;
    if (pgrp) cur->gid = pgrp->gr_gid;
    cur->socket_path = xstrdup(serve_socket);
    cur->root_dir = xstrdup(cnts->root_dir);
    cur->conf_file = xstrdup(serve_cfg);
    cur->log_file = xstrdup(serve_log);
    info("contest %d prepared to serve", i);
  }

  // scan available contests for run_managed contests
  for (i = 1; i < contest_max_ind; i++) {
    if (!contest_map[i]) continue;
    if ((errcode = contests_get(i, &cnts)) < 0) {
      err("cannot load contest %d: %s", i, contests_strerror(-errcode));
      continue;
    }
    if (!cnts->run_managed) {
      info("contest %d is not run_managed", i);
      continue;
    }
    if (!cnts->root_dir || !*cnts->root_dir) {
      err("contest %d root directory is not set", i);
      continue;
    }

    ppwd = 0;
    pgrp = 0;
    if (cnts->serve_user && *cnts->serve_user) {
      ppwd = getpwnam(cnts->serve_user);
      if (!ppwd) {
        err("contest %d lookup for user %s failed", i, cnts->serve_user);
        continue;
      }
      info("contest %d user '%s' is %d", i, cnts->serve_user, ppwd->pw_uid);
    }
    if (cnts->serve_group && *cnts->serve_group) {
      pgrp = getgrnam(cnts->serve_group);
      if (!pgrp) {
        err("contest %d lookup for group %s failed", i, cnts->serve_group);
        continue;
      }
      info("contest %d group '%s' is %d", i, cnts->serve_group, pgrp->gr_gid);
    }

    if (ppwd && self_uid != 0 && ppwd->pw_uid != self_uid) {
      err("contest %d serve user uid %d differs from self uid %d",
          i, ppwd->pw_uid, self_uid);
      continue;
    }
    if (pgrp && self_uid != 0 && pgrp->gr_gid != self_gid) {
      // FIXME: check, that the group is a secondary group...
      err("contest %d serve group id %d differs grom self gid %d",
          i, pgrp->gr_gid, self_gid);
      continue;
    }

    // serve_root must exist and be a directory
    if (stat(cnts->root_dir, &stbuf) < 0) {
      err("contest %d root_dir '%s' does not exist", i, cnts->root_dir);
      continue;
    }
    if (!S_ISDIR(stbuf.st_mode)) {
      err("contest %d root_dir '%s' is not a directory", i, cnts->root_dir);
      continue;
    }

    // serve config must exist and be a regular file
    // FIXME: add a possibility to define config_name?
    snprintf(serve_cfg, sizeof(serve_cfg), "%s/%s",
             cnts->root_dir, "conf/serve.cfg");
    if (stat(serve_cfg, &stbuf) < 0) {
      err("contest %d configuration file '%s' does not exist", i, serve_cfg);
      continue;
    }
    if (!S_ISREG(stbuf.st_mode)) {
      err("contest %d configuration file '%s' is not regular", i, serve_cfg);
      continue;
    }

    // FIXME: add a possibility to define var_name
    snprintf(serve_var, sizeof(serve_var), "%s/%s", cnts->root_dir, "var");
    if (stat(serve_var, &stbuf) < 0) {
      // FIXME: create directory with proper uid ang gid...
      err("contest %d var directory '%s' does not exist", i, serve_var);
      continue;
    }
    if (!S_ISDIR(stbuf.st_mode)) {
      err("contest %d var directory '%s' is not a directory", i, serve_var);
      continue;
    }

    snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/run/queue/dir",
             serve_var);
    if (stat(run_queue_dir, &stbuf) < 0) {
      err("contest %d run queue directory '%s' does not exist", i,
          run_queue_dir);
      continue;
    }
    if (!S_ISDIR(stbuf.st_mode)) {
      err("contest %d run queue directory '%s' is not a directory",
          i, run_queue_dir);
      continue;
    }

    snprintf(run_log, sizeof(run_log), "%s/run_messages",
             serve_var);

    queue_dir_fd = open(run_queue_dir, O_RDONLY);
    if (queue_dir_fd < 0) {
      err("contest %d run queue directory '%s' cannot be opened",
          i, run_queue_dir);
      continue;
    }

    cur = &contest_extra[i];
    cur->id = i;
    cur->run_used = 1;
    cur->run_pid = -1;
    cur->run_dir_fd = queue_dir_fd;
    cur->uid = self_uid;
    if (ppwd) cur->uid = ppwd->pw_uid;
    cur->gid = self_gid;
    if (pgrp) cur->gid = pgrp->gr_gid;
    if (!cur->root_dir) cur->root_dir = xstrdup(cnts->root_dir);
    if (!cur->conf_file) cur->conf_file = xstrdup(serve_cfg);
    cur->run_queue_dir = xstrdup(run_queue_dir);
    cur->run_log_file = xstrdup(run_log);
    info("contest %d prepared to serve", i);
  }

  for (i = 1; i < contest_max_ind; i++) {
    if (!contest_extra[i].run_used) continue;
    need_dnotify_handler = 1;
  }

  if (need_dnotify_handler) {
    memset(&dn_act, 0, sizeof(dn_act));
    dn_act.sa_sigaction = dnotify_handler;
    sigfillset(&dn_act.sa_mask);
    dn_act.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN, &dn_act, NULL);
  }

  info("scanning available contests done");
}

static void
release_resources(void)
{
  int i, alive_children, pid, status;
  sigset_t work_mask;
  struct contest_extra *cur;

  sigfillset(&work_mask);
  sigdelset(&work_mask, SIGTERM);
  sigdelset(&work_mask, SIGINT);
  sigdelset(&work_mask, SIGHUP);
  sigdelset(&work_mask, SIGCHLD);

  // send SIGTERM to all the remaining processes
  info("sending SIGTERM to all chidrens");
  for (i = 0; i < contest_num; i++) {
    if (!contest_extra[i].serve_used) continue;
    if (contest_extra[i].serve_pid > 0) {
      if (kill(contest_extra[i].serve_pid, SIGTERM) < 0) {
        err("contest %d kill to %d failed: %s",
            contest_extra[i].id, contest_extra[i].serve_pid, os_ErrorMsg());
      }
    }
  }
  for (i = 0; i < contest_num; i++) {
    if (!contest_extra[i].run_used) continue;
    if (contest_extra[i].run_pid > 0) {
      if (kill(contest_extra[i].run_pid, SIGTERM) < 0) {
        err("contest %d kill to %d failed: %s",
            contest_extra[i].id, contest_extra[i].run_pid, os_ErrorMsg());
      }
    }
  }

  // wait until no child processes remain
  info("wait for chilrens to terminate");
  while (1) {
    alive_children = 0;
    for (i = 0; i < contest_num; i++) {
      if (contest_extra[i].serve_used && contest_extra[i].serve_pid > 0)
        alive_children++;
      if (contest_extra[i].run_used && contest_extra[i].run_pid > 0)
        alive_children++;
    }
    if (!alive_children) break;

    while (!sigchld_flag) {
      sigsuspend(&work_mask);
    }

    sigchld_flag = 0;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
      for (i = 0; i < contest_num; i++) {
        if (contest_extra[i].serve_used &&
            contest_extra[i].serve_pid == pid) {
          if (WIFEXITED(status)) {
            info("contest %d serve [%d] terminated with status %d",
                 contest_extra[i].id, pid, WEXITSTATUS(status));
          } else if (WIFSIGNALED(status)) {
            err("contest %d serve [%d] terminated with signal %d (%s)",
                contest_extra[i].id, pid, WTERMSIG(status),
                os_GetSignalString(WTERMSIG(status)));
          } else {
            err("contest %d serve unknown termination status", 
                contest_extra[i].id);
          }
          contest_extra[i].serve_pid = -1;
          break;
        }
        if (contest_extra[i].run_used &&
            contest_extra[i].run_pid == pid) {
          if (WIFEXITED(status)) {
            info("contest %d run [%d] terminated with status %d",
                 contest_extra[i].id, pid, WEXITSTATUS(status));
          } else if (WIFSIGNALED(status)) {
            err("contest %d run [%d] terminated with signal %d (%s)",
                contest_extra[i].id, pid, WTERMSIG(status),
                os_GetSignalString(WTERMSIG(status)));
          } else {
            err("contest %d run unknown termination status", 
                contest_extra[i].id);
          }
          contest_extra[i].run_pid = -1;
          break;
        }
      }
      if (i >= contest_num) {
        err("unregistered child %d terminated", pid);
        continue;
      }
    }
  }

  // now release resources
  info("closing all sockets");
  for (i = 0; i < contest_num; i++) {
    cur = &contest_extra[i];
    if (!cur->serve_used) continue;

    if (cur->socket_fd >= 0) close(cur->socket_fd);
    cur->socket_fd = 0;
    if (cur->socket_path) {
      unlink(cur->socket_path);
      xfree(cur->socket_path);
      cur->socket_path = 0;
    }
    xfree(cur->root_dir);
    cur->root_dir = 0;
    xfree(cur->conf_file);
    cur->conf_file = 0;
    xfree(cur->log_file);
    cur->log_file = 0;
  }
  for (i = 0; i < contest_num; i++) {
    cur = &contest_extra[i];
    if (!cur->run_used) continue;
    if (cur->run_dir_fd >= 0) close(cur->run_dir_fd);
    cur->run_dir_fd = 0;
    xfree(cur->root_dir);
    cur->root_dir = 0;
    xfree(cur->conf_file);
    cur->conf_file = 0;
    xfree(cur->run_queue_dir);
    cur->run_queue_dir = 0;
    xfree(cur->run_log_file);
    cur->run_log_file = 0;
  }
}

static int
get_number_of_files(const unsigned char *path)
{
  DIR *d = 0;
  struct dirent *dd;
  int n = 0;

  if (!(d = opendir(path))) {
    err("opendir(%s) failed: %s", path, os_ErrorMsg());
    return -1;
  }
  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".")) continue;
    if (!strcmp(dd->d_name, "..")) continue;
    n++;
  }
  closedir(d);
  return n;
}

static int
do_loop(void)
{
  int fd_max, i, socket_fd, n, errcode, status, pid, tmp_fd, j;
  fd_set rset;
  struct timeval timeout;
  sigset_t block_mask, work_mask, orig_mask;
  struct sockaddr_un in_addr;
  int in_addr_len;
  struct contest_extra *cur;
  int null_fd, log_fd, self_pid;
  unsigned char **args;

  sigfillset(&block_mask);
  sigfillset(&work_mask);
  sigdelset(&work_mask, SIGTERM);
  sigdelset(&work_mask, SIGINT);
  sigdelset(&work_mask, SIGHUP);
  sigdelset(&work_mask, SIGCHLD);
  sigdelset(&work_mask, SIGRTMIN);
  sigprocmask(SIG_SETMASK, &block_mask, &orig_mask);

  signal(SIGTERM, handler_term);
  signal(SIGINT, handler_term);
  signal(SIGHUP, handler_hup);
  signal(SIGCHLD, handler_child);

  while (1) {
    acquire_resources();

    /* set directory notification */
    dnotify_flag = 0;
    for (i = 0; i < contest_num; i++) {
      if (!contest_extra[i].run_used) continue;
      ASSERT(contest_extra[i].run_dir_fd >= 0);
      ASSERT(contest_extra[i].run_pid <= 0);
      // should never fail
      if (fcntl(contest_extra[i].run_dir_fd, F_SETSIG, SIGRTMIN) < 0) {
        err("fcntl(...,F_SETSIG,...) failed: %s", os_ErrorMsg());
        // FIXME: is reasonable recovery possible?
        contest_extra[i].run_used = 0;
        close(contest_extra[i].run_dir_fd);
      }
      if (fcntl(contest_extra[i].run_dir_fd, F_NOTIFY,
                DN_CREATE | DN_DELETE | DN_RENAME | DN_MULTISHOT) < 0) {
        err("fcntl(...,F_NOTIFY,...) failed: %s", os_ErrorMsg());
        // FIXME: is reasonable recovery possible?
        contest_extra[i].run_used = 0;
        close(contest_extra[i].run_dir_fd);
      }
    }

    /* check if some directory already have files */
    for (i = 0; i < contest_num; i++) {
      if (!contest_extra[i].run_used) continue;
      if (get_number_of_files(contest_extra[i].run_queue_dir) <= 0) continue;
      dnotify_flag = 1;
      contest_extra[i].dnotify_flag = 1;
    }

    while (1) {
      fd_max = -1;
      FD_ZERO(&rset);
      for (i = 0; i < contest_num; i++) {
        if (contest_extra[i].serve_pid >= 0) continue;
        socket_fd = contest_extra[i].socket_fd;
        if (socket_fd < 0) continue;
        FD_SET(socket_fd, &rset);
        if (socket_fd > fd_max) fd_max = socket_fd;
      }

      // set a reasonable timeout in case of race condition
      timeout.tv_sec = 10;
      timeout.tv_usec = 0;

      // here's a potential race condition :-(
      // it cannot be handled properly until Linux
      // has the proper psignal implementation
      sigprocmask(SIG_SETMASK, &work_mask, 0);
      errno = 0;
      n = select(fd_max + 1, &rset, 0, 0, &timeout);
      errcode = errno;
      sigprocmask(SIG_SETMASK, &block_mask, 0);
      errno = errcode;
      // end of race condition prone code

      if (n < 0 && errno != EINTR) {
        err("unexpected select error: %s", os_ErrorMsg());
        continue;
      }

      if (sigchld_flag) {
        sigchld_flag = 0;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
          for (i = 0; i < contest_num; i++) {
            if (contest_extra[i].serve_used
                && contest_extra[i].serve_pid == pid) {
              if (WIFEXITED(status)) {
                info("contest %d serve [%d] terminated with status %d",
                     contest_extra[i].id, pid, WEXITSTATUS(status));
              } else if (WIFSIGNALED(status)) {
                err("contest %d serve [%d] terminated with signal %d (%s)",
                    contest_extra[i].id, pid, WTERMSIG(status),
                    os_GetSignalString(WTERMSIG(status)));
              } else {
                err("contest %d serve unknown termination status", i);
              }
              contest_extra[i].serve_pid = -1;
              break;
            }
            if (contest_extra[i].run_used
                && contest_extra[i].run_pid == pid) {
              if (WIFEXITED(status)) {
                info("contest %d run [%d] terminated with status %d",
                     contest_extra[i].id, pid, WEXITSTATUS(status));
              } else if (WIFSIGNALED(status)) {
                err("contest %d run [%d] terminated with signal %d (%s)",
                    contest_extra[i].id, pid, WTERMSIG(status),
                    os_GetSignalString(WTERMSIG(status)));
              } else {
                err("contest %d run unknown termination status", i);
              }

              if (fcntl(contest_extra[i].run_dir_fd, F_SETSIG, SIGRTMIN) < 0) {
                err("fcntl(...,F_SETSIG,...) failed: %s", os_ErrorMsg());
                contest_extra[i].run_used = 0;
                close(contest_extra[i].run_dir_fd);
              }
              if (fcntl(contest_extra[i].run_dir_fd, F_NOTIFY,
                        DN_CREATE | DN_DELETE | DN_RENAME | DN_MULTISHOT)< 0) {
                err("fcntl(...,F_NOTIFY,...) failed: %s", os_ErrorMsg());
                contest_extra[i].run_used = 0;
                close(contest_extra[i].run_dir_fd);
              }
              contest_extra[i].dnotify_flag = 0;
              if (get_number_of_files(contest_extra[i].run_queue_dir) > 0) {
                contest_extra[i].dnotify_flag = 1;
                dnotify_flag = 1;
              }
              contest_extra[i].run_pid = -1;
              break;
            }
          }
          if (i >= contest_num) {
            err("unregistered child %d terminated", pid);
            continue;
          }
        }
      }

      if (hup_flag || term_flag) break;

      if (dnotify_flag) {
        dnotify_flag = 0;
        for (i = 0; i < contest_num; i++) {
          cur = &contest_extra[i];
          if (!cur->run_used) continue;
          if (!cur->dnotify_flag) continue;
          cur->dnotify_flag = 0;
          if (cur->run_pid > 0) continue;
          pid = fork();
          if (pid < 0) {
            err("contest %d run fork() failed: %s", cur->id, os_ErrorMsg());
            /* FIXME: recovery? */
            continue;
          }
          if (pid > 0) {
            info("contest %d new run process %d", cur->id, pid);
            fcntl(cur->run_dir_fd, F_NOTIFY, 0);
            cur->run_pid = pid;
            continue;
          }

          // this is child
          self_pid = getpid();
          cur = &contest_extra[i];

          // 1. close everything
          for (j = 0; j < contest_num; j++) {
            if (!contest_extra[j].serve_used) continue;
            close(contest_extra[j].socket_fd);
          }
          for (j = 0; j < contest_num; j++) {
            if (!contest_extra[j].run_used) continue;
            close(contest_extra[j].run_dir_fd);
          }

          // 2. switch uid and gid
          if (self_uid != cur->uid && setuid(cur->uid) < 0) {
            err("contest %d [%d] setuid failed: %s",
                cur->id, self_pid, os_ErrorMsg());
            _exit(1);
          }
          if (self_gid != cur->gid && setgid(cur->gid) < 0) {
            err("contest %d [%d] setgid failed: %s",
                cur->id, self_pid, os_ErrorMsg());
            _exit(1);
          }

          // 3. open /dev/null and log file
          if ((null_fd = open("/dev/null", O_RDONLY, 0)) < 0) {
            err("contest %d [%d] open(/dev/null) failed: %s",
                cur->id, self_pid, os_ErrorMsg());
            _exit(1);
          }
          if ((log_fd = open(cur->run_log_file, O_WRONLY | O_APPEND | O_CREAT,
                             0600)) < 0) {
            err("contest %d [%d] open(%s) failed: %s",
                cur->id, self_pid, cur->run_log_file, os_ErrorMsg());
            _exit(1);
          }

          // 4. setup file descriptors 0
          if (null_fd != 0) {
            dup2(null_fd, 0);
            close(null_fd);
          }

          // 5. change the current directory
          if (chdir(cur->root_dir) < 0) {
            err("contest %d [%d] chdir(%s) failed: %s",
                cur->id, self_pid, cur->root_dir, os_ErrorMsg());
            _exit(1);
          }

          // 6. setup new process group
          if (setpgid(self_pid, self_pid) < 0) {
            err("contest %d [%d] setpgid failed: %s",
                cur->id, self_pid, os_ErrorMsg());
            _exit(1);
          }

          // 7. setup argument vector
          args = (unsigned char **) alloca(4 * sizeof(args[0]));
          memset(args, 0, 4 * sizeof(args[0]));
          args[0] = config->run_path;
          args[1] = "-S";
          args[2] = cur->conf_file;

          // 8. clear procmask
          sigprocmask(SIG_SETMASK, &orig_mask, 0);

          // 9. setup file descriptors 1, 2
          if (log_fd != 1) {
            dup2(log_fd, 1);
          }
          if (log_fd != 2) {
            dup2(log_fd, 2);
          }
          if (log_fd != 1 && log_fd != 2) {
            close(log_fd);
          }
          // 10. start run
          execve(args[0], (char**) args, environ);
          err("contest %d [%d] execve() failed: %s",
              cur->id, self_pid, os_ErrorMsg());
          _exit(1);
        }
      }

      if (n <= 0) {
        // timeout expired or signal arrived
        continue;
      }

      // scan for ready contests
      for (i = 0; i < contest_num; i++) {
        if (contest_extra[i].serve_pid >= 0) continue;
        if (FD_ISSET(contest_extra[i].socket_fd, &rset)) {
          pid = fork();
          if (pid < 0) {
            err("contest %d fork() failed: %s", 
                contest_extra[i].id, os_ErrorMsg());
            in_addr_len = sizeof(in_addr);
            memset(&in_addr, 0, in_addr_len);
            tmp_fd = accept(contest_extra[i].socket_fd,
                            (struct sockaddr*) &in_addr, &in_addr_len);
            if (tmp_fd >= 0) close(tmp_fd);
            continue;
          }
          if (pid > 0) {
            info("contest %d new serve process %d",
                 contest_extra[i].id, pid);
            contest_extra[i].serve_pid = pid;
            continue;
          }

          // this is child
          self_pid = getpid();
          cur = &contest_extra[i];

          // 1. close everything, except one socket
          for (j = 0; j < contest_num; j++) {
            if (!contest_extra[j].serve_used) continue;
            if (contest_extra[j].socket_fd < 0) continue;
            if (contest_extra[j].socket_fd == cur->socket_fd) continue;
            close(contest_extra[j].socket_fd);
          }
          for (j = 0; j < contest_num; j++) {
            if (!contest_extra[j].run_used) continue;
            close(contest_extra[j].run_dir_fd);
          }

          // 2. switch uid and gid
          if (self_uid != cur->uid && setuid(cur->uid) < 0) {
            err("contest %d [%d] setuid failed: %s",
                cur->id, self_pid, os_ErrorMsg());
            _exit(1);
          }
          if (self_gid != cur->gid && setgid(cur->gid) < 0) {
            err("contest %d [%d] setgid failed: %s",
                cur->id, self_pid, os_ErrorMsg());
            _exit(1);
          }
          // 3. open /dev/null and log file
          if ((null_fd = open("/dev/null", O_RDONLY, 0)) < 0) {
            err("contest %d [%d] open(/dev/null) failed: %s",
                cur->id, self_pid, os_ErrorMsg());
            _exit(1);
          }
          if ((log_fd = open(cur->log_file, O_WRONLY | O_APPEND | O_CREAT,
                             0600)) < 0) {
            err("contest %d [%d] open(%s) failed: %s",
                cur->id, self_pid, cur->log_file, os_ErrorMsg());
            _exit(1);
          }
          // 4. setup file descriptors 0
          if (null_fd != 0) {
            dup2(null_fd, 0);
            close(null_fd);
          }
          // 5. change the current directory
          if (chdir(cur->root_dir) < 0) {
            err("contest %d [%d] chdir(%s) failed: %s",
                cur->id, self_pid, cur->root_dir, os_ErrorMsg());
            _exit(1);
          }
          // 6. setup new process group
          if (setpgid(self_pid, self_pid) < 0) {
            err("contest %d [%d] setpgid failed: %s",
                cur->id, self_pid, os_ErrorMsg());
            _exit(1);
          }
          // 7. setup argument vector
          args = (unsigned char **) alloca(4 * sizeof(args[0]));
          memset(args, 0, 4 * sizeof(args[0]));
          args[0] = config->serve_path;
          args[1] = (unsigned char *) alloca(256);
          snprintf(args[1], 256, "-S%d", cur->socket_fd);
          args[2] = cur->conf_file;
          // 8. clear procmask
          sigprocmask(SIG_SETMASK, &orig_mask, 0);
          // 9. setup file descriptors 1, 2
          if (log_fd != 1) {
            dup2(log_fd, 1);
          }
          if (log_fd != 2) {
            dup2(log_fd, 2);
          }
          if (log_fd != 1 && log_fd != 2) {
            close(log_fd);
          }
          // 10. start serve
          execve(args[0], (char**) args, environ);
          err("contest %d [%d] execve() failed: %s",
              cur->id, self_pid, os_ErrorMsg());
          _exit(1);
        }
      }
    }

    if (term_flag) {
      info("got a termination signal");
    }
    release_resources();

    // we are here if either HUP or, TERM, or INT
    if (term_flag) break;
    hup_flag = 0;
  }

  return 0;
}

static void
print_info(unsigned char const *program_path)
{
  printf("super-serve %s, compiled %s\n", compile_version, compile_date);
  printf("Usage: %s config-file\n", program_path);
}

int
main(int argc, char **argv)
{
  if (argc == 1) {
    print_info(argv[0]);
    return 0;
  }
  if (argc != 2) {
    fprintf(stderr, "%s: invalid number of parameters\n", argv[0]);
    return 1;
  }

  info("super-serve %s, compiled %s", compile_version, compile_date);

  config = userlist_cfg_parse(argv[1]);
  if (!config) return 1;
  if (!config->contests_dir) {
    err("<contests_dir> tag is not set!");
    return 1;
  }
  if (contests_set_directory(config->contests_dir) < 0) {
    err("contests directory is invalid");
    return 1;
  }
  if (!config->serve_path || !*config->serve_path) {
    err("serve_path is not defined");
    return 1;
  }
  if (access(config->serve_path, X_OK) < 0) {
    err("serve_path '%s' is not executable", config->serve_path);
    return 1;
  }
  if (config->run_path && config->run_path[0]
      && access(config->run_path, X_OK) < 0) {
    err("run_path '%s' is not executable", config->run_path);
    return 1;
  }

  self_uid = getuid();
  if (self_uid != 0) {
    info("the uid is %d (non-root): cannot start contests, which require"
         " different uids", self_uid);
  }
  self_gid = getgid();
  return do_loop();
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
