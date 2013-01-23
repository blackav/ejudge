/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2013 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "ej_types.h"

#include "version.h"
#include "ejudge_cfg.h"
#include "contests.h"
#include "pathutl.h"
#include "errlog.h"
#include "userlist_clnt.h"
#include "super_proto.h"
#include "userlist_proto.h"
#include "misctext.h"
#include "super-serve.h"
#include "super_html.h"
#include "prepare.h"
#include "serve_state.h"
#include "random.h"
#include "startstop.h"
#include "super-serve_meta.h"
#include "sock_op.h"
#include "compat.h"
#include "ej_process.h"
#include "ej_byteorder.h"
#include "pollfds.h"

#include "reuse_xalloc.h"
#include "reuse_logger.h"
#include "reuse_osdeps.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
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
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>
#include <sys/inotify.h>

#define SUSPEND_TIMEOUT    60
#define MAX_IN_PACKET_SIZE 134217728 /* 128 mb */
#define SPOOL_DIR_CHECK_INTERVAL 60

enum
{
  STATE_READ_CREDS,
  STATE_READ_FDS,
  STATE_READ_LEN,
  STATE_READ_DATA,
  STATE_READ_READY,
  STATE_WRITE,
  STATE_WRITECLOSE,
  STATE_DISCONNECT,
  STATE_SUSPENDED,
};
struct client_state
{
  struct client_state *next;
  struct client_state *prev;

  int id;
  int fd;
  int state;
  
  int peer_pid;
  int peer_uid;
  int peer_gid;

  int client_fds[2];

  int expected_len;
  int read_len;
  unsigned char *read_buf;

  int write_len;
  int written;
  unsigned char *write_buf;

  int user_id;
  int priv_level;
  ej_cookie_t cookie;
  ej_ip_t ip;
  int ssl;
  unsigned char *login;
  unsigned char *name;
  unsigned char *html_login;
  unsigned char *html_name;

  void *suspend_context;
};

static int daemon_mode;
static int restart_mode;
static int autonomous_mode;
static int forced_mode;
static int slave_mode;
static int manage_all_runs;
static int master_mode;
static unsigned char hostname[1024];

static struct ejudge_cfg *config;
static int self_uid;
static int self_gid;
static int self_group_num;
static int self_group_max;
static gid_t *self_groups;

static int extra_a;
static struct contest_extra **extras;

static int control_socket_fd = -1;
static int run_inotify_fd = -1;
static unsigned char *control_socket_path = 0;
static userlist_clnt_t userlist_clnt = 0;
static struct client_state *clients_first;
static struct client_state *clients_last;
static int cur_client_id = 0;
static sigset_t original_mask;
static int userlist_uid = 0;
static unsigned char *userlist_login = 0;

struct serve_state serve_state;

static struct background_process_head background_processes;

void
super_serve_register_process(struct background_process *prc)
{
  background_process_register(&background_processes, prc);
}
struct background_process *
super_serve_find_process(const unsigned char *name)
{
  return background_process_find(&background_processes, name);
}

static struct client_state *
client_state_new(int fd)
{
  struct client_state *p;

  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

  XCALLOC(p, 1);
  p->id = cur_client_id++;
  p->fd = fd;
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  p->state = STATE_READ_CREDS;

  if (!clients_first) {
    clients_first = clients_last = p;
  } else {
    p->next = clients_first;
    clients_first->prev = p;
    clients_first = p;
  }
  return p;
}
static void
client_state_delete(struct client_state *p)
{
  struct client_state *q;

  // sanity check
  if (!p) return;
  for (q = clients_first; q && q != p; q = q->next);
  ASSERT(q);

  if (p->next && p->prev) {
    // middle element
    p->prev->next = p->next;
    p->next->prev = p->prev;
  } else if (p->next) {
    // the first element
    clients_first = p->next;
    p->next->prev = 0;
  } else if (p->prev) {
    // the last element
    clients_last = p->prev;
    p->prev->next = 0;
  } else {
    // the only element
    clients_first = clients_last = 0;
  }

  fcntl(p->fd, F_SETFL, fcntl(p->fd, F_GETFL) & ~O_NONBLOCK);
  if (p->fd >= 0) close(p->fd);
  if (p->client_fds[0] >= 0) close(p->client_fds[0]);
  if (p->client_fds[1] >= 0) close(p->client_fds[1]);
  xfree(p->read_buf);
  xfree(p->write_buf);
  xfree(p->login);
  xfree(p->name);
  xfree(p->html_login);
  xfree(p->html_name);

  memset(p, -1, sizeof(*p));
  xfree(p);
}
static struct client_state *
client_state_new_autoclose(struct client_state *p,
                           unsigned char *write_buf,
                           int write_len)
{
  struct client_state *q;

  q = client_state_new(p->client_fds[0]);
  q->client_fds[1] = p->client_fds[1];
  q->write_buf = write_buf;
  q->write_len = write_len;
  q->state = STATE_WRITECLOSE;

  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  return q;
}

struct contest_extra *
new_contest_extra(int contest_id)
{
  struct contest_extra *p;

  XCALLOC(p, 1);
  p->id = contest_id;
  p->run_pid = -1;
  p->run_uid = -1;
  p->run_gid = -1;
  return p;
}

static struct contest_extra *
delete_contest_extra(int contest_id)
{
  struct contest_extra *p;

  if (contest_id <= 0 || contest_id >= extra_a) return 0;
  if (!(p = extras[contest_id])) return 0;

  xfree(p->root_dir);
  xfree(p->conf_file);
  xfree(p->var_dir);
  xfree(p->run_queue_dir);
  xfree(p->run_log_file);
  xfree(p->messages);

  extras[contest_id] = 0;
  memset(p, -1, sizeof(*p));
  xfree(p);
  return 0;
}

struct contest_extra *
get_existing_contest_extra(int num)
{
  ASSERT(num > 0 && num <= EJ_MAX_CONTEST_ID);
  if (num >= extra_a) return 0;
  return extras[num];
}

/* note, that contest validity is not checked */
struct contest_extra *
get_contest_extra(int num)
{
  struct contest_extra **new_extras;
  int old_extra_a;

  ASSERT(num > 0 && num < 1000000);
  if (num >= extra_a) {
    old_extra_a = extra_a;
    if (!extra_a) extra_a = 16;
    while (num >= extra_a) extra_a *= 2;
    XCALLOC(new_extras, extra_a);
    if (old_extra_a > 0)
      memcpy(new_extras, extras, old_extra_a * sizeof(new_extras[0]));
    xfree(extras);
    extras = new_extras;
  }
  if (!extras[num]) {
    extras[num] = new_contest_extra(num);
  }
  return extras[num];
}

struct update_state *
update_state_create(void)
{
  struct update_state *us = NULL;
  XCALLOC(us, 1);
  return us;
}

struct update_state *
update_state_free(struct update_state *us)
{
  if (us) {
    xfree(us->conf_file);
    xfree(us->log_file);
    xfree(us->status_file);
    xfree(us->pid_file);
    xfree(us);
  }
  return NULL;
}

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

/* for error reporting purposes */
static FILE *global_error_log = 0;
static int   global_contest_id = 0;

static void startup_err(const char *, ...)
     __attribute__((format(printf, 1, 2)));
static void
startup_err(const char *format, ...)
{
  unsigned char msg[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(msg, sizeof(msg), format, args);
  va_end(args);

  if (global_contest_id > 0) err("contest %d: %s", global_contest_id, msg);
  else err("%s", msg);
  if (global_error_log) fprintf(global_error_log, "%s\n", msg);
}

static void
prepare_run_serving(const struct contest_desc *cnts,
                    struct contest_extra *extra,
                    int do_run_manage)
{
  unsigned char run_queue_dir[1024];
  unsigned char run_log_path[1024];
  struct stat stbuf;
  struct xml_tree *p = 0;

  if (slave_mode && !manage_all_runs) {
    if (cnts->slave_rules) {
      for (p = cnts->slave_rules->first_down; p; p = p->right) {
        if (!strcasecmp(hostname, p->text))
          break;
      }
      if (!p) return;
    } else {
      return;
    }
  } else if (master_mode) {
    return;
  } else {
    if (!cnts->old_run_managed && do_run_manage <= 0) return;
  }

  snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/run/queue/dir",
           extra->var_dir);
  if (stat(run_queue_dir, &stbuf) < 0) {
    startup_err("run queue directory '%s' does not exist", run_queue_dir);
    return;
  }
  if (!S_ISDIR(stbuf.st_mode)) {
    startup_err("run queue directory '%s' is not a directory", run_queue_dir);
    return;
  }

  snprintf(run_log_path, sizeof(run_log_path), "%s/ej-run-messages.log",
           extra->var_dir);

  if (run_inotify_fd >= 0) {
    extra->run_wd = inotify_add_watch(run_inotify_fd, run_queue_dir, IN_MOVED_TO);
    if (extra->run_wd < 0) {
      err("inotify_add_watch failed for %s: %s", run_queue_dir, os_ErrorMsg());
      extra->run_wd = 0;
    }
  }

  extra->run_used = 1;
  extra->run_pid = -1;
  extra->run_queue_dir = xstrdup(run_queue_dir);
  extra->run_log_file = xstrdup(run_log_path);
}

static int
check_user_identity(const unsigned char *prog_name,
                    const unsigned char *user_str,
                    const unsigned char *group_str,
                    int *uid_ptr,
                    int *gid_ptr)
{
  struct passwd *ppwd = 0;
  struct group *pgrp = 0;
  int i;

  if (user_str && *user_str) {
    ppwd = getpwnam(user_str);
    if (!ppwd) {
      startup_err("user %s does exist", user_str);
      return -1;
    }
  }
  if (ppwd && self_uid != 0 && ppwd->pw_uid != self_uid) {
    startup_err("cannot change user id from %d to %d",
                self_uid, (int) ppwd->pw_uid);
    return -1;
  }
  if (ppwd && uid_ptr) *uid_ptr = ppwd->pw_uid;

  if (group_str && *group_str) {
    pgrp = getgrnam(group_str);
    if (!pgrp) {
      startup_err("group %s does not exist", group_str);
      return -1;
    }
  }
  if (pgrp && self_uid != 0) {
    for (i = 0; i < self_group_num; i++)
      if (self_gid == self_groups[i])
        break;
    if (i >= self_group_num) {
      startup_err("cannot change group id from %d to %d",
                  self_uid, (int) pgrp->gr_gid);
      return -1;
    }
  }
  if (pgrp && *gid_ptr) *gid_ptr = pgrp->gr_gid;

  return 0;
}

static void close_all_client_sockets(void);

/*
 * do_{serve,run}_manage may be -1 (use the default value), 0 or 1
 */
static void
acquire_contest_resources(const struct contest_desc *cnts,
                          int do_serve_manage,
                          int do_run_manage)
{
  FILE *error_log = 0;
  char *error_log_txt = 0;
  size_t error_log_size = 0;
  struct contest_extra *extra;
  int i, old_run_managed = 0;
  struct stat stbuf;
  unsigned char config_path[1024];
  unsigned char var_path[1024];
  struct xml_tree *p = 0;

  if (slave_mode && !manage_all_runs) {
    if (cnts->slave_rules) {
      for (p = cnts->slave_rules->first_down; p; p = p->right) {
        //fprintf(stderr, ">>%s,%s<<\n", hostname, p->text);
        if (!strcasecmp(hostname, p->text))
          break;
      }
      if (p) old_run_managed = 1;
    }
  } else if (!master_mode) {
    old_run_managed = cnts->old_run_managed;
  }

  if (!cnts->managed && do_serve_manage <= 0
      && !old_run_managed && do_run_manage <= 0) return;

  if (slave_mode && old_run_managed)
    info("contest %d will be served in slave mode", cnts->id);

  extra = get_contest_extra(cnts->id);
  memset(extra, 0, sizeof(*extra));
  extra->id = cnts->id;
  extra->run_uid = -1;
  extra->run_gid = -1;
  extra->run_pid = -1;

  if (!(error_log = open_memstream(&error_log_txt, &error_log_size))) {
    err("acquire_contest_resources: open_memstream failed");
    return;
  }

  global_error_log = error_log;
  global_contest_id = cnts->id;

  if (!cnts->root_dir || !*cnts->root_dir) {
    startup_err("root_dir is not set, managing is impossible");
    goto done;
  }
  if (stat(cnts->root_dir, &stbuf) < 0) {
    startup_err("root_dir (%s) does not exist", cnts->root_dir);
    goto done;
  }
  if (!S_ISDIR(stbuf.st_mode)) {
    startup_err("root_dir (%s) is not a directory", cnts->root_dir);
    goto done;
  }
  extra->root_dir = xstrdup(cnts->root_dir);

  /* check the serve and run config file 
   * FIXME: make the config_path configurable
   */
  snprintf(config_path, sizeof(config_path), "%s/conf/serve.cfg",
           cnts->root_dir);
  if (stat(config_path, &stbuf) < 0) {
    startup_err("configuration file %s does not exist", config_path);
    goto done;
  }
  if (!S_ISREG(stbuf.st_mode)) {
    startup_err("configuration file %s is not a regular file", config_path);
    goto done;
  }
  extra->conf_file = xstrdup(config_path);

  if (check_user_identity("run", cnts->run_user, cnts->run_group,
                          &extra->run_uid, &extra->run_gid) < 0)
    goto done;

  if (extra->run_uid < 0) extra->run_uid = extra->run_uid;
  if (extra->run_gid < 0) extra->run_gid = extra->run_gid;

  /* check the var directory, and if it does not exist, start the serve
   * in config check mode
   */
  snprintf(var_path, sizeof(var_path), "%s/var", cnts->root_dir);
  if (stat(var_path, &stbuf) < 0) {
    //start_serve(extra, 0, 1);
  }
  // still make an attempt to create var directory
  mkdir(var_path, 0777);
  if (stat(var_path, &stbuf) < 0) {
    startup_err("var directory %s does not exist", var_path);
    goto done;
  }
  if (!S_ISDIR(stbuf.st_mode)) {
    startup_err("var directory %s is not a directory", var_path);
    goto done;
  }
  extra->var_dir = xstrdup(var_path);

  prepare_run_serving(cnts, extra, do_run_manage);

 done:
  ;
  close_memstream(error_log); error_log = 0;
  xfree(extra->messages); extra->messages = 0;
  // avoid logs with only whitespace characters
  if (error_log_txt) {
    for (i = 0; error_log_txt[i] && isspace(error_log_txt[i]); i++);
    if (!error_log_txt[i]) {
      xfree(error_log_txt);
      error_log_txt = 0;
    }
  }
  extra->messages = error_log_txt;
}

static void
acquire_resources(void)
{
  const int *contests = 0;
  int contest_num, errcode, i, j;
  const struct contest_desc *cnts;

  info("scanning available contests...");
  contest_num = contests_get_list(&contests);
  if (contest_num <= 0 || !contests) return;

  for (j = 0; j < contest_num; j++) {
    i = contests[j];
    if ((errcode = contests_get(i, &cnts)) < 0) {
      err("cannot load contest %d: %s", i, contests_strerror(-errcode));
      continue;
    }
    acquire_contest_resources(cnts, -1, -1);
  }

  info("scanning available contests done");
}

static void
release_contest_resources(const struct contest_desc *cnts)
{
  struct contest_extra *extra;
  int status = 0, out_pid;

  if (!cnts) return;
  if (!(extra = get_existing_contest_extra(cnts->id))) return;

  if (extra->run_used && extra->run_pid > 0) {
    if (kill(extra->run_pid, SIGTERM) < 0) {
      err("contest %d: killing run %d failed: %s",
          cnts->id, extra->run_pid, os_ErrorMsg());
    }
    while (1) {
      out_pid = waitpid(extra->run_pid, &status, 0);
      if (out_pid >= 0 || errno != EINTR) break;
    }
    if (out_pid < 0) {
      err("contest %d: waitpid failed: %s", cnts->id, os_ErrorMsg());
    } else {
      ASSERT(extra->run_pid == out_pid);
      if (WIFEXITED(status)) {
        info("contest %d run [%d] terminated with status %d",
             extra->id, out_pid, WEXITSTATUS(status));
      } else if (WIFSIGNALED(status)) {
        err("contest %d run [%d] terminated with signal %d (%s)",
            extra->id, out_pid, WTERMSIG(status), os_GetSignalString(WTERMSIG(status)));
      } else {
        err("contest %d run unknown termination status", extra->id);
      }
      extra->run_pid = -1;
    }
  }

  delete_contest_extra(cnts->id);
}

static void
release_resources(void)
{
  int i, alive_children, pid, status;
  sigset_t work_mask;
  struct rusage usage;

  sigfillset(&work_mask);
  sigdelset(&work_mask, SIGTERM);
  sigdelset(&work_mask, SIGINT);
  sigdelset(&work_mask, SIGHUP);
  sigdelset(&work_mask, SIGCHLD);

  // send SIGTERM to all the remaining processes
  for (i = 0; i < extra_a; i++) {
    if (!extras[i]) continue;
    if (!extras[i]->run_used) continue;
    if (extras[i]->run_pid > 0) {
      if (kill(extras[i]->run_pid, SIGTERM) < 0) {
        err("contest %d kill to %d failed: %s",
            extras[i]->id, extras[i]->run_pid, os_ErrorMsg());
      }
    }
  }

  // wait until no child processes remain
  info("wait for chilren to terminate");
  while (1) {
    alive_children = 0;
    for (i = 0; i < extra_a; i++) {
      if (!extras[i]) continue;
      if (extras[i]->run_used && extras[i]->run_pid > 0)
        alive_children++;
    }
    if (!alive_children) break;

    while (!sigchld_flag) {
      sigsuspend(&work_mask);
    }

    sigchld_flag = 0;
    while ((pid = wait4(-1, &status, WNOHANG, &usage)) > 0) {
      for (i = 0; i < extra_a; i++) {
        if (!extras[i]) continue;
        if (extras[i]->run_used && extras[i]->run_pid == pid) {
          if (WIFEXITED(status)) {
            info("contest %d run [%d] terminated with status %d",
                 extras[i]->id, pid, WEXITSTATUS(status));
          } else if (WIFSIGNALED(status)) {
            err("contest %d run [%d] terminated with signal %d (%s)",
                extras[i]->id, pid, WTERMSIG(status),
                os_GetSignalString(WTERMSIG(status)));
          } else {
            err("contest %d run unknown termination status", 
                extras[i]->id);
          }
          extras[i]->run_pid = -1;
          break;
        }
      }
      if (i >= extra_a) {
        if (!background_process_handle_termination(&background_processes,
                                                   pid, status, &usage)) {
          err("unregistered child %d terminated", pid);
        }
        continue;
      }
    }
  }

  // now release resources
  info("closing all sockets");
  for (i = 0; i < extra_a; i++) {
    delete_contest_extra(i);
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

static void
accept_new_control_connection(void)
{
  struct sockaddr_un addr;
  int fd, addrlen;

  memset(&addr, 0, sizeof(addr));
  addrlen = sizeof(addr);
  if ((fd = accept(control_socket_fd, (struct sockaddr*) &addr, &addrlen))<0){
    err("accept failed: %s", os_ErrorMsg());
    return;
  }

  if (sock_op_enable_creds(fd) < 0) {
    close(fd);
    return;
  }

  client_state_new(fd);
}

static void
read_from_control_connection(struct client_state *p)
{
  int r, n;

  switch (p->state) {
  case STATE_READ_CREDS:
    if (sock_op_get_creds(p->fd, p->id, &p->peer_pid, &p->peer_uid,
                          &p->peer_gid) < 0) {
      p->state = STATE_DISCONNECT;
      return;
    }

    p->state = STATE_READ_LEN;
    break;

  case STATE_READ_FDS:
    if (sock_op_get_fds(p->fd, p->id, p->client_fds) < 0) {
      p->state = STATE_DISCONNECT;
      return;
    }
    p->state = STATE_READ_LEN;
    break;

  case STATE_READ_LEN:
    /* read the packet length */
    if ((r = read(p->fd, &p->expected_len, sizeof(p->expected_len))) < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        info("%d: descriptor not ready", p->id);
        return;
      }
      err("%d: read failed: %s", p->id, os_ErrorMsg());
      p->state = STATE_DISCONNECT;
      return;
    }
    if (!r) {
      // EOF from client
      p->state = STATE_DISCONNECT;
      return;
    }
    if (r != 4) {
      err("%d: expected 4 bytes of packet length", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }
    if (p->expected_len <= 0 || p->expected_len > MAX_IN_PACKET_SIZE) {
      err("%d: bad packet length %d", p->id, p->expected_len);
      p->state = STATE_DISCONNECT;
      return;
    }
    p->read_len = 0;
    p->read_buf = (unsigned char*) xcalloc(1, p->expected_len);
    p->state = STATE_READ_DATA;
    break;

  case STATE_READ_DATA:
    n = p->expected_len - p->read_len;
    ASSERT(n > 0);
    if ((r = read(p->fd, p->read_buf + p->read_len, n)) < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        info("%d: descriptor not ready", p->id);
        return;
      }
      err("%d: read failed: %s", p->id, os_ErrorMsg());
      p->state = STATE_DISCONNECT;
      return;
    }
    if (!r) {
      err("%d: unexpected EOF", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }
    p->read_len += r;
    if (p->read_len == p->expected_len) p->state = STATE_READ_READY;
    break;

  default:
    err("%d: invalid read state %d", p->id, p->state);
    abort();
  }
}

static void
write_to_control_connection(struct client_state *p)
{
  int n, r;

  switch (p->state) {
  case STATE_WRITE:
  case STATE_WRITECLOSE:
    ASSERT(p->write_len > 0);
    ASSERT(p->written >= 0);
    ASSERT(p->written < p->write_len);
    n = p->write_len - p->written;
    if ((r = write(p->fd, p->write_buf + p->written, n)) <= 0) {
      if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
        info("%d: descriptor not ready", p->id);
        return;
      }
      err("%d: write error: %s", p->id, os_ErrorMsg());
      p->state = STATE_DISCONNECT;
      return;
    }
    p->written += r;
    if (p->written == p->write_len) {
      if (p->state == STATE_WRITE) {
        p->state = STATE_READ_LEN;
      } else if (p->state == STATE_WRITECLOSE) {
        p->state = STATE_DISCONNECT;
      } else {
        abort();
      }
      p->written = p->write_len = 0;
      xfree(p->write_buf);
      p->write_buf = 0;
    }
    break;

  default:
    err("%d: invalid write state %d", p->id, p->state);
    abort();
  }
}

static void
close_all_client_sockets(void)
{
  struct client_state *p;

  if (control_socket_fd >= 0) close(control_socket_fd);
  for (p = clients_first; p; p = p->next) {
    if (p->fd >= 0) close(p->fd);
    if (p->client_fds[0] >= 0) close(p->client_fds[0]);
    if (p->client_fds[1] >= 0) close(p->client_fds[1]);
  }
  if (run_inotify_fd >= 0) {
    close(run_inotify_fd);
    run_inotify_fd = -1;
  }
}

static void
enqueue_reply(struct client_state *p, int len, void const *msg)
{
  ASSERT(!p->write_len);

  p->write_len = len + sizeof(len);
  p->write_buf = xmalloc(p->write_len);
  memcpy(p->write_buf, &len, sizeof(len));
  memcpy(p->write_buf + sizeof(len), msg, len);
  p->written = 0;
  p->state = STATE_WRITE;
}

static void
send_reply(struct client_state *p, short answer)
{
  struct prot_super_packet pkt;

  pkt.id = answer;
  pkt.magic = PROT_SUPER_PACKET_MAGIC;
  enqueue_reply(p, sizeof(pkt), &pkt);
}

static void
error_bad_packet_length(struct client_state *p, int len, int exp_len)
{
  err("%d: bad packet length: %d, expected %d", p->id, len, exp_len);
  p->state = STATE_DISCONNECT;
}
static void
error_packet_too_short(struct client_state *p, int len, int min_len)
{
  err("%d: packet is too small: %d, minimum %d", p->id, len, min_len);
  p->state = STATE_DISCONNECT;
}
static void
error_field_len_mismatch(struct client_state *p, const unsigned char *name,
                         int actual_len, int expected_len)
{
  err("%d: field `%s' length mismatch: %d, expected %d",
      p->id, name, actual_len, expected_len);
  p->state = STATE_DISCONNECT;
}
static void
error_slave_mode(struct client_state *p)
{
  err("%d: request disabled in slave mode", p->id);
  send_reply(p, -SSERV_ERR_SLAVE_MODE);
}

static int
open_connection(void)
{
  int r;

  if (userlist_clnt) return 0;

  if (!(userlist_clnt = userlist_clnt_open(config->socket_path))) {
    err("open_connection: connect to server failed");
    return -1;
  }
  if ((r = userlist_clnt_admin_process(userlist_clnt,
                                       &userlist_uid,
                                       &userlist_login,
                                       0)) < 0) {
    err("open_connection: cannot became an admin process: %s",
        userlist_strerror(-r));
    userlist_clnt = userlist_clnt_close(userlist_clnt);
    return -1;
  }

  info("running as %s (%d)", userlist_login, userlist_uid);
  return 0;
}

static int
get_peer_local_user(struct client_state *p)
{
  int r;
  int uid, priv_level, ssl;
  ej_cookie_t cookie;
  ej_ip_t ip;
  unsigned char *login, *name;

  if (p->user_id > 0) return p->user_id;

  if (open_connection() < 0) return -SSERV_ERR_USERLIST_DOWN;

  r = userlist_clnt_get_uid_by_pid_2(userlist_clnt, p->peer_uid,
                                     p->peer_gid, p->peer_pid, 0,
                                     &uid, &priv_level, &cookie, &ip, &ssl,
                                     &login, &name);
  if (r < 0) {
    err("get_peer_local_user: %s", userlist_strerror(-r));
    switch (-r) {
    case ULS_ERR_UNEXPECTED_EOF:
    case ULS_ERR_READ_ERROR:
    case ULS_ERR_PROTOCOL:
    case ULS_ERR_DISCONNECT:
    case ULS_ERR_WRITE_ERROR:
      // client error codes: server disconnected
      userlist_clnt = userlist_clnt_close(userlist_clnt);
      r = -SSERV_ERR_USERLIST_DOWN;
      break;
    default:
      r = -SSERV_ERR_UNEXPECTED_USERLIST_ERROR;
      break;
    }
    return r;
  }

  if (priv_level < PRIV_LEVEL_JUDGE) {
    err("get_peer_local_user: inappropriate privilege level");
    return -SSERV_ERR_PERMISSION_DENIED;
  }

  if (!login) login = xstrdup("");
  if (!name) name = xstrdup("");

  p->user_id = uid;
  p->cookie = cookie;
  p->ip = ip;
  p->ssl = ssl;
  p->login = login;
  p->name = name;
  p->priv_level = priv_level;
  p->html_login = html_armor_string_dup(login);
  p->html_name = html_armor_string_dup(name);

  return 0;
}

static void
cmd_pass_fd(struct client_state *p, int len,
            struct prot_super_packet *pkt)
{
  if (len != sizeof(*pkt))
    return error_bad_packet_length(p, len, sizeof(*pkt));

  if (p->client_fds[0] >= 0 || p->client_fds[1] >= 0) {
    err("%d: cannot stack unprocessed client descriptors", p->id);
    p->state = STATE_DISCONNECT;
    return;
  }

  p->state = STATE_READ_FDS;
}

static struct sid_state *sid_state_first = 0;
static struct sid_state *sid_state_last = 0;
static time_t sid_state_last_check_time = 0;
#define SID_STATE_CLEANUP_TIME (24*3600)
#define SID_STATE_CHECK_INTERVAL 3600

static struct sid_state*
sid_state_find(ej_cookie_t sid)
{
  struct sid_state *p;

  ASSERT(sid);
  for (p = sid_state_first; p; p = p->next)
    if (p->sid == sid) break;
  return p;
}
static struct sid_state*
sid_state_add(
        ej_cookie_t sid,
        ej_ip_t remote_addr,
        int user_id,
        const unsigned char *user_login,
        const unsigned char *user_name)
{
  struct sid_state *n;

  ASSERT(sid);
  XCALLOC(n, 1);
  n->sid = sid;
  n->remote_addr = remote_addr;
  n->init_time = time(0);
  n->flags |= SID_STATE_SHOW_CLOSED;
  n->user_id = user_id;
  n->user_login = xstrdup(user_login);
  n->user_name = xstrdup(user_name);

  if (!sid_state_last) {
    ASSERT(!sid_state_first);
    sid_state_first = sid_state_last = n;
  } else {
    ASSERT(sid_state_first);
    sid_state_last->next = n;
    n->prev = sid_state_last;
    sid_state_last = n;
  }
  return n;
}
static struct sid_state*
sid_state_get(
        ej_cookie_t sid,
        ej_ip_t remote_addr,
        int user_id,
        const unsigned char *user_login,
        const unsigned char *user_name)
{
  struct sid_state *p;

  if (!(p = sid_state_find(sid)))
    p = sid_state_add(sid, remote_addr, user_id, user_login, user_name);
  return p;
}
static void
sid_state_clear(struct sid_state *p)
{
  super_serve_clear_edited_contest(p);
  xfree(p->user_login);
  xfree(p->user_name);
  xfree(p->user_filter);
  bitset_free(&p->marked);
  serve_state_destroy(config, p->te_state, NULL, NULL);
  update_state_free(p->update_state);
  XMEMZERO(p, 1);
}
static struct sid_state*
sid_state_delete(struct sid_state *p)
{
  ASSERT(p);
  if (!p->prev) {
    sid_state_first = p->next;
  } else {
    p->prev->next = p->next;
  }
  if (!p->next) {
    sid_state_last = p->prev;
  } else {
    p->next->prev = p->prev;
  }
  sid_state_clear(p);
  xfree(p);
  return 0;
}
static void
sid_state_cleanup(void)
{
  time_t cur_time;
  struct sid_state *p;

  cur_time = time(0);
  do {
    for (p = sid_state_first; p; p = p->next) {
      if (p->init_time + SID_STATE_CLEANUP_TIME < cur_time) {
        sid_state_delete(p);
        break;
      }
    }
  } while (p);
}
int
super_serve_sid_state_get_max_edited_cnts(void)
{
  struct sid_state *p;
  int max_cnts_id = 0;

  for (p = sid_state_first; p; p = p->next) {
    if (p->edited_cnts && p->edited_cnts->id > max_cnts_id)
      max_cnts_id = p->edited_cnts->id;
  }
  return max_cnts_id;
}
const struct sid_state*
super_serve_sid_state_get_cnts_editor(int contest_id)
{
  struct sid_state *p;

  for (p = sid_state_first; p; p = p->next)
    if (p->edited_cnts && p->edited_cnts->id == contest_id)
      return p;
  return 0;
}
struct sid_state*
super_serve_sid_state_get_cnts_editor_nc(int contest_id)
{
  struct sid_state *p;

  for (p = sid_state_first; p; p = p->next)
    if (p->edited_cnts && p->edited_cnts->id == contest_id)
      return p;
  return 0;
}

const struct sid_state*
super_serve_sid_state_get_test_editor(int contest_id)
{
  struct sid_state *p;

  for (p = sid_state_first; p; p = p->next)
    if (p->te_state && p->te_state->contest_id == contest_id)
      return p;
  return 0;
}

struct sid_state*
super_serve_sid_state_get_test_editor_nc(int contest_id)
{
  struct sid_state *p;

  for (p = sid_state_first; p; p = p->next)
    if (p->te_state && p->te_state->contest_id == contest_id)
      return p;
  return 0;
}

void
super_serve_clear_edited_contest(struct sid_state *p)
{
  int i;

  contests_free(p->edited_cnts); p->edited_cnts = 0;
  xfree(p->users_header_text); p->users_header_text = 0;
  xfree(p->users_footer_text); p->users_footer_text = 0;
  xfree(p->register_header_text); p->register_header_text = 0;
  xfree(p->register_footer_text); p->register_footer_text = 0;
  xfree(p->team_header_text); p->team_header_text = 0;
  xfree(p->team_menu_1_text); p->team_menu_1_text = 0;
  xfree(p->team_menu_2_text); p->team_menu_2_text = 0;
  xfree(p->team_menu_3_text); p->team_menu_3_text = 0;
  xfree(p->team_separator_text); p->team_separator_text = 0;
  xfree(p->team_footer_text); p->team_footer_text = 0;
  xfree(p->priv_header_text); p->priv_header_text = 0;
  xfree(p->priv_footer_text); p->priv_footer_text = 0;
  xfree(p->copyright_text); p->copyright_text = 0;
  xfree(p->welcome_text); p->welcome_text = 0;
  xfree(p->reg_welcome_text); p->reg_welcome_text = 0;
  xfree(p->register_email_text); p->register_email_text = 0;

  p->edit_page = 0;
  p->advanced_view = 0;
  p->show_html_attrs = 0;
  p->show_html_headers = 0;
  p->show_paths = 0;
  p->show_access_rules = 0;
  p->show_permissions = 0;
  p->show_form_fields = 0;
  p->show_notifications = 0;

  xfree(p->serve_parse_errors); p->serve_parse_errors = 0;
  prepare_free_config(p->cfg); p->cfg = 0;
  p->global = 0;
  p->lang_a = 0;
  xfree(p->langs); p->langs = 0;
  xfree(p->loc_cs_map); p->loc_cs_map = 0;
  xfree(p->cs_loc_map); p->cs_loc_map = 0;
  xfree(p->aprobs); p->aprobs = 0;
  p->aprob_u = p->aprob_a = 0;
  xfree(p->aprob_flags); p->aprob_flags = 0;
  p->prob_a = 0;
  xfree(p->probs); p->probs = 0;
  xfree(p->prob_flags); p->prob_flags = 0;
  xfree(p->testers); p->testers = 0;
  xfree(p->atesters); p->atesters = 0;
  p->tester_total = 0;
  p->atester_total = 0;
  p->show_global_1 = 0;
  p->show_global_2 = 0;
  p->show_global_3 = 0;
  p->show_global_4 = 0;
  p->show_global_5 = 0;
  p->show_global_6 = 0;
  p->enable_stand2 = 0;
  p->enable_plog = 0;
  p->enable_extra_col = 0;
  p->disable_compilation_server = 0;
  p->enable_win32_languages = 0;

  for (i = 0; i < p->lang_a; i++)
    xfree(p->lang_opts[i]);
  for (i = 0; i < p->cs_lang_total; i++)
    xfree(p->cs_lang_names[i]);
  p->cs_langs_loaded = p->cs_lang_total = 0;
  prepare_free_config(p->cs_cfg); p->cs_cfg = 0;
  if (p->extra_cs_cfgs) {
    for (int i = 0; p->extra_cs_cfgs[i]; ++i) {
      prepare_free_config(p->extra_cs_cfgs[i]);
      p->extra_cs_cfgs[i] = 0;
    }
    xfree(p->extra_cs_cfgs);
  }
  p->extra_cs_cfgs = 0;
  p->extra_cs_cfgs_total = 0;
  xfree(p->cs_langs); p->cs_langs = 0;
  xfree(p->cs_lang_names); p->cs_lang_names = 0;
  xfree(p->lang_opts); p->lang_opts = 0;
  xfree(p->lang_flags); p->lang_flags = 0;

  xfree(p->contest_start_cmd_text); p->contest_start_cmd_text = 0;
  xfree(p->stand_header_text); p->stand_header_text = 0;
  xfree(p->stand_footer_text); p->stand_footer_text = 0;
  xfree(p->stand2_header_text); p->stand2_header_text = 0;
  xfree(p->stand2_footer_text); p->stand2_footer_text = 0;
  xfree(p->plog_header_text); p->plog_header_text = 0;
  xfree(p->plog_footer_text); p->plog_footer_text = 0;
  xfree(p->var_header_text); p->var_header_text = 0;
  xfree(p->var_footer_text); p->var_footer_text = 0;
  xfree(p->compile_home_dir); p->compile_home_dir = 0;
}

void
super_serve_move_edited_contest(struct sid_state *dst, struct sid_state *src)
{
  dst->edited_cnts = src->edited_cnts; src->edited_cnts = 0;

  // ejintbool_t fields
  static int ejintbool_fields[] =
  {
    SSSS_advanced_view, SSSS_show_html_attrs, SSSS_show_html_headers,
    SSSS_show_paths, SSSS_show_access_rules, SSSS_show_permissions,
    SSSS_show_form_fields, SSSS_show_notifications,
    SSSS_users_header_loaded, SSSS_users_footer_loaded,
    SSSS_register_header_loaded, SSSS_register_footer_loaded,
    SSSS_team_header_loaded, SSSS_team_menu_1_loaded,
    SSSS_team_menu_2_loaded, SSSS_team_menu_3_loaded,
    SSSS_team_separator_loaded, SSSS_team_footer_loaded,
    SSSS_priv_header_loaded, SSSS_priv_footer_loaded,
    SSSS_register_email_loaded, SSSS_copyright_loaded,
    SSSS_welcome_loaded, SSSS_reg_welcome_loaded,
    SSSS_show_global_1, SSSS_show_global_2, SSSS_show_global_3,
    SSSS_show_global_4, SSSS_show_global_5, SSSS_show_global_6,
    SSSS_show_global_7, SSSS_enable_stand2, SSSS_enable_plog,
    SSSS_enable_extra_col, SSSS_disable_compilation_server,
    SSSS_enable_win32_languages,
    0,
  };
  for (int i = 0; ejintbool_fields[i]; ++i) {
    int j = ejintbool_fields[i];
    ejintbool_t *pdst = (ejintbool_t*) ss_sid_state_get_ptr_nc(dst, j);
    ejintbool_t *psrc = (ejintbool_t*) ss_sid_state_get_ptr_nc(src, j);
    *pdst = *psrc; *psrc = 0;
  }

  // string fields
  static int string_fields[] =
  {
    SSSS_users_header_text, SSSS_users_footer_text,
    SSSS_register_header_text, SSSS_register_footer_text,
    SSSS_team_header_text, SSSS_team_menu_1_text, SSSS_team_menu_2_text,
    SSSS_team_menu_3_text, SSSS_team_separator_text, SSSS_team_footer_text,
    SSSS_priv_header_text, SSSS_priv_footer_text, SSSS_register_email_text,
    SSSS_copyright_text, SSSS_welcome_text, SSSS_reg_welcome_text,
    SSSS_serve_parse_errors, SSSS_contest_start_cmd_text,
    SSSS_stand_header_text, SSSS_stand_footer_text,
    SSSS_stand2_header_text, SSSS_stand2_footer_text,
    SSSS_plog_header_text, SSSS_plog_footer_text,
    SSSS_var_header_text, SSSS_var_footer_text, SSSS_compile_home_dir,
    0,
  };
  for (int i = 0; string_fields[i]; ++i) {
    int j = string_fields[i];
    unsigned char **pdst = (unsigned char**) ss_sid_state_get_ptr_nc(dst, j);
    unsigned char **psrc = (unsigned char**) ss_sid_state_get_ptr_nc(src, j);
    *pdst = *psrc; *psrc = 0;
  }

  // other fields
  dst->cfg = src->cfg; src->cfg = 0;
  dst->global = src->global; src->global = 0;
  dst->lang_a = src->lang_a; src->lang_a = 0;
  dst->langs = src->langs; src->langs = 0;
  dst->loc_cs_map = src->loc_cs_map; src->loc_cs_map = 0;
  dst->cs_loc_map = src->cs_loc_map; src->cs_loc_map = 0;
  dst->lang_opts = src->lang_opts; src->lang_opts = 0;
  dst->lang_flags = src->lang_flags; src->lang_flags = 0;
  dst->aprob_u = src->aprob_u; src->aprob_u = 0;
  dst->aprob_a = src->aprob_a; src->aprob_a = 0;
  dst->aprobs = src->aprobs; src->aprobs = 0;
  dst->aprob_flags = src->aprob_flags; src->aprob_flags = 0;
  dst->prob_a = src->prob_a; src->prob_a = 0;
  dst->probs = src->probs; src->probs = 0;
  dst->prob_flags = src->prob_flags; src->prob_flags = 0;
  dst->atester_total = src->atester_total; src->atester_total = 0;
  dst->atesters = src->atesters; src->atesters = 0;
  dst->tester_total = src->tester_total; src->tester_total = 0;
  dst->testers = src->testers; src->testers = 0;
  dst->cs_langs_loaded = src->cs_langs_loaded; src->cs_langs_loaded = 0;
  dst->cs_lang_total = src->cs_lang_total; src->cs_lang_total = 0;
  dst->cs_cfg = src->cs_cfg; src->cs_cfg = 0;
  dst->extra_cs_cfgs_total = src->extra_cs_cfgs_total = 0; src->extra_cs_cfgs_total = 0;
  dst->extra_cs_cfgs = src->extra_cs_cfgs; src->extra_cs_cfgs = 0;
  dst->cs_langs = src->cs_langs; src->cs_langs = 0;
  dst->cs_lang_names = src->cs_lang_names; src->cs_lang_names = 0;
}

static void
activate_problem(struct sid_state *sstate, int prob_id)
{
  if (!sstate) return;
  if (prob_id <= 0 || prob_id >= sstate->prob_a || !sstate->probs || !sstate->prob_flags || !sstate->probs[prob_id]) return;
  for (int i = 1; i < sstate->prob_a; ++i) {
    sstate->prob_flags[i] &= ~SID_STATE_SHOW_HIDDEN;
  }
  sstate->prob_flags[prob_id] |= SID_STATE_SHOW_HIDDEN;
}

static void
cmd_main_page(struct client_state *p, int len,
              struct prot_super_pkt_main_page *pkt)
{
  int r;
  unsigned char *self_url_ptr, *hidden_vars_ptr, *extra_args_ptr;
  int self_url_len, hidden_vars_len, extra_args_len, total_len;
  FILE *f;
  char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;
  opcap_t caps;
  int capbit = 0;
  const struct contest_desc *cnts = 0;
  struct contest_desc *rw_cnts = 0;
  struct sid_state *sstate = 0;
  const struct sid_state *other_ss = 0;

  if (slave_mode) return error_slave_mode(p);

  if (len < sizeof(*pkt)) return error_packet_too_short(p, len, sizeof(*pkt));
  self_url_ptr = pkt->data;
  self_url_len = strlen(self_url_ptr);
  if (self_url_len != pkt->self_url_len)
    return error_field_len_mismatch(p, "self_url",
                                    self_url_len, pkt->self_url_len);
  hidden_vars_ptr = self_url_ptr + self_url_len + 1;
  hidden_vars_len = strlen(hidden_vars_ptr);
  if (hidden_vars_len != pkt->hidden_vars_len)
    return error_field_len_mismatch(p, "hidden_vars",
                                    hidden_vars_len, pkt->hidden_vars_len);
  extra_args_ptr = hidden_vars_ptr + hidden_vars_len + 1;
  extra_args_len = strlen(extra_args_ptr);
  if (extra_args_len != pkt->extra_args_len)
    return error_field_len_mismatch(p, "extra_args",
                                    extra_args_len, pkt->extra_args_len);
  total_len = sizeof(*pkt) + self_url_len + hidden_vars_len + extra_args_len;
  if (total_len != len)
    return error_bad_packet_length(p, len, total_len);

  if ((r = get_peer_local_user(p)) < 0) {
    send_reply(p, r);
    return;
  }

  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("cmd_main_page: two file descriptors expected");
    return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
  }

  sstate = sid_state_get(p->cookie, p->ip, p->user_id, p->login, p->name);

  // extra incoming packet checks
  switch (pkt->b.id) {
  case SSERV_CMD_CONTEST_PAGE:
    if ((r = contests_get(pkt->contest_id, &cnts)) < 0 || !cnts) {
      err("cmd_main_page: invalid contest_id %d", pkt->contest_id);
      cnts = 0;
      //return send_reply(p, -SSERV_ERR_INVALID_CONTEST);
    }
    break;
  case SSERV_CMD_VIEW_RUN_LOG:
  case SSERV_CMD_VIEW_CONTEST_XML:
  case SSERV_CMD_VIEW_SERVE_CFG:
  case SSERV_CMD_EDIT_CONTEST_XML:
  case SSERV_CMD_EDIT_SERVE_CFG_PROB:
    if ((r = contests_get(pkt->contest_id, &cnts)) < 0 || !cnts) {
      return send_reply(p, -SSERV_ERR_INVALID_CONTEST);
    }
    /*
    if (sstate->edited_cnts) {
      return send_reply(p, -SSERV_ERR_CONTEST_EDITED);
    }
    */
    break;
  case SSERV_CMD_CHECK_TESTS:
    if ((r = contests_get(pkt->contest_id, &cnts)) < 0 || !cnts) {
      return send_reply(p, -SSERV_ERR_INVALID_CONTEST);
    }
    if (sstate->edited_cnts) {
      return send_reply(p, -SSERV_ERR_CONTEST_EDITED);
    }
    break;
  }

  // check permissions: MASTER_PAGE
  switch (pkt->b.id) {
  case SSERV_CMD_MAIN_PAGE:
    if (ejudge_cfg_opcaps_find(config, p->login, &caps) < 0) {
      err("%d: user %d has no privileges", p->id, p->user_id);
      return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
    }
    switch (p->priv_level) {
    case PRIV_LEVEL_JUDGE: capbit = OPCAP_JUDGE_LOGIN; break;
    case PRIV_LEVEL_ADMIN: capbit = OPCAP_MASTER_LOGIN; break;
    default:
      return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
    }
    if (opcaps_check(caps, capbit) < 0) {
      err("%d: user %d has no capability %d", p->id, p->user_id, capbit);
      return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
    }
    break;
  case SSERV_CMD_CONTEST_PAGE:
  case SSERV_CMD_VIEW_RUN_LOG:
  case SSERV_CMD_VIEW_CONTEST_XML:
  case SSERV_CMD_VIEW_SERVE_CFG:
    // all checks are performed in super_html_log_page
    break;

    // global CREATE_CONTEST is required
  case SSERV_CMD_CREATE_CONTEST:
    if (p->priv_level != PRIV_LEVEL_ADMIN) {
      err("%d: inappropriate privilege level", p->id);
      return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
    }
    if (ejudge_cfg_opcaps_find(config, p->login, &caps) < 0) {
      err("%d: user %d has no privileges", p->id, p->user_id);
      return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
    }
    if (opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
      err("%d: user %d has no capability %d", p->id, p->user_id, capbit);
      return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
    }
    break;

  case SSERV_CMD_EDIT_CONTEST_XML:
  case SSERV_CMD_EDIT_SERVE_CFG_PROB:
  case SSERV_CMD_CHECK_TESTS:
    if (p->priv_level != PRIV_LEVEL_ADMIN) {
      err("%d: inappropriate privilege level", p->id);
      return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
    }
    if (opcaps_find(&cnts->capabilities, p->login, &caps) < 0) {
      err("%d: user %d has no privileges", p->id, p->user_id);
      return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
    }
    if (opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
      err("%d: user %d has no capability %d", p->id, p->user_id, capbit);
      return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
    }
    break;
    
    // Current contest editing commands are allowed to anybody,
    // because the editing mode cannot be entered without privilege
  case SSERV_CMD_EDIT_CURRENT_CONTEST:
  case SSERV_CMD_EDIT_REGISTER_ACCESS:
  case SSERV_CMD_EDIT_USERS_ACCESS:
  case SSERV_CMD_EDIT_MASTER_ACCESS:
  case SSERV_CMD_EDIT_JUDGE_ACCESS:
  case SSERV_CMD_EDIT_TEAM_ACCESS:
  case SSERV_CMD_EDIT_SERVE_CONTROL_ACCESS:
  case SSERV_CMD_CNTS_EDIT_PERMISSION:
  case SSERV_CMD_CNTS_EDIT_FORM_FIELDS:
  case SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS:
  case SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS:
  case SSERV_CMD_CNTS_EDIT_COACH_FIELDS:
  case SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS:
  case SSERV_CMD_CNTS_EDIT_GUEST_FIELDS:
  case SSERV_CMD_CNTS_EDIT_USERS_HEADER:
  case SSERV_CMD_CNTS_EDIT_USERS_FOOTER:
  case SSERV_CMD_CNTS_EDIT_REGISTER_HEADER:
  case SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER:
  case SSERV_CMD_CNTS_EDIT_TEAM_HEADER:
  case SSERV_CMD_CNTS_EDIT_TEAM_MENU_1:
  case SSERV_CMD_CNTS_EDIT_TEAM_MENU_2:
  case SSERV_CMD_CNTS_EDIT_TEAM_MENU_3:
  case SSERV_CMD_CNTS_EDIT_TEAM_SEPARATOR:
  case SSERV_CMD_CNTS_EDIT_TEAM_FOOTER:
  case SSERV_CMD_CNTS_EDIT_PRIV_HEADER:
  case SSERV_CMD_CNTS_EDIT_PRIV_FOOTER:
  case SSERV_CMD_CNTS_EDIT_COPYRIGHT:
  case SSERV_CMD_CNTS_EDIT_WELCOME:
  case SSERV_CMD_CNTS_EDIT_REG_WELCOME:
  case SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE:
  case SSERV_CMD_CNTS_COMMIT:
  case SSERV_CMD_EDIT_CURRENT_GLOBAL:
  case SSERV_CMD_EDIT_CURRENT_LANG:
  case SSERV_CMD_EDIT_CURRENT_PROB:
  case SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD:
  case SSERV_CMD_GLOB_EDIT_CONTEST_STOP_CMD:
  case SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE:
  case SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE:
  case SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE:
  case SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE:
  case SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE:
  case SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE:
  case SSERV_CMD_VIEW_NEW_SERVE_CFG:
  case SSERV_CMD_PROB_EDIT_VARIANTS:
  case SSERV_CMD_PROB_EDIT_VARIANTS_2:
    // FIXME: add permissions checks
    break;

  default:
    err("%d: unhandled request %d", p->id, pkt->b.id);
    return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
  }

  if (!(f = open_memstream(&html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    return send_reply(p, -SSERV_ERR_SYSTEM_ERROR);
  }

  // handle command
  switch (pkt->b.id) {
  case SSERV_CMD_MAIN_PAGE:
    r = super_html_main_page(f, p->priv_level, p->user_id, p->login,
                             p->cookie, p->ip, p->ssl, pkt->flags, config, sstate,
                             self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;
  case SSERV_CMD_CONTEST_PAGE:
    r = super_html_contest_page(f, p->priv_level, p->user_id, pkt->contest_id,
                                p->login, p->cookie, p->ip, p->ssl, config,
                                self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;
  case SSERV_CMD_VIEW_RUN_LOG:
  case SSERV_CMD_VIEW_CONTEST_XML:
  case SSERV_CMD_VIEW_SERVE_CFG:
    r = super_html_log_page(f, pkt->b.id, p->priv_level, p->user_id,
                            pkt->contest_id, p->login, p->cookie, p->ip, p->ssl,
                            config,
                            self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;
  case SSERV_CMD_CREATE_CONTEST:
    r = super_html_create_contest(f, p->priv_level, p->user_id, p->login,
                                  p->cookie, p->ip, config, sstate,
                                  self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;
  case SSERV_CMD_EDIT_CURRENT_CONTEST:
    r = super_html_edit_contest_page(f, p->priv_level, p->user_id, p->login,
                                     p->cookie, p->ip, config, sstate,
                                     self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;
  case SSERV_CMD_EDIT_REGISTER_ACCESS:
  case SSERV_CMD_EDIT_USERS_ACCESS:
  case SSERV_CMD_EDIT_MASTER_ACCESS:
  case SSERV_CMD_EDIT_JUDGE_ACCESS:
  case SSERV_CMD_EDIT_TEAM_ACCESS:
  case SSERV_CMD_EDIT_SERVE_CONTROL_ACCESS:
    r = super_html_edit_access_rules(f, p->priv_level, p->user_id, p->login,
                                     p->cookie, p->ip, config, sstate, pkt->b.id,
                                     self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;
  case SSERV_CMD_EDIT_CONTEST_XML:
  case SSERV_CMD_EDIT_SERVE_CFG_PROB:
    if (sstate->edited_cnts && sstate->edited_cnts->id == cnts->id) {
      r = super_html_edit_contest_page(f, p->priv_level, p->user_id, p->login,
                                       p->cookie, p->ip, config, sstate,
                                       self_url_ptr, hidden_vars_ptr,
                                       extra_args_ptr);
      break;
    }
    if (sstate->edited_cnts) {
      r = super_html_edited_cnts_dialog(f, p->priv_level, p->user_id, p->login,
                                        p->cookie, p->ip, config, sstate,
                                        self_url_ptr, hidden_vars_ptr,
                                        extra_args_ptr, cnts, 0);
      break;
    }
    if ((other_ss = super_serve_sid_state_get_cnts_editor(cnts->id))) {
      r = super_html_locked_cnts_dialog(f, p->priv_level, p->user_id, p->login,
                                        p->cookie, p->ip, config, sstate,
                                        self_url_ptr, hidden_vars_ptr,
                                        extra_args_ptr, cnts->id,
                                        other_ss, 0);
      break;
    }
    
    if ((r = contests_load(pkt->contest_id, &rw_cnts)) < 0 || !rw_cnts) {
      return send_reply(p, -SSERV_ERR_INVALID_CONTEST);
    }
    sstate->edited_cnts = rw_cnts;
    super_html_load_serve_cfg(rw_cnts, config, sstate);
    if (pkt->b.id == SSERV_CMD_EDIT_SERVE_CFG_PROB) {
      activate_problem(sstate, pkt->flags);
      r = super_html_edit_problems(f, p->priv_level, p->user_id, p->login,
                                   p->cookie, p->ip, config, sstate,
                                   self_url_ptr, hidden_vars_ptr,
                                   extra_args_ptr);
    } else {
      r = super_html_edit_contest_page(f, p->priv_level, p->user_id, p->login,
                                       p->cookie, p->ip, config, sstate,
                                       self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    }
    break;
  case SSERV_CMD_CHECK_TESTS:
    if ((r = contests_load(pkt->contest_id, &rw_cnts)) < 0 || !rw_cnts) {
      return send_reply(p, -SSERV_ERR_INVALID_CONTEST);
    }
    sstate->edited_cnts = rw_cnts;
    super_html_load_serve_cfg(rw_cnts, config, sstate);
    r = super_html_check_tests(f, p->priv_level, p->user_id, p->login,
                               p->cookie, p->ip, config, sstate,
                               self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    super_serve_clear_edited_contest(sstate);
    break;
  case SSERV_CMD_CNTS_EDIT_PERMISSION:
    r = super_html_edit_permission(f, p->priv_level, p->user_id, p->login,
                                   p->cookie, p->ip, config, sstate, pkt->flags,
                                   self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;
  case SSERV_CMD_CNTS_EDIT_FORM_FIELDS:
  case SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS:
  case SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS:
  case SSERV_CMD_CNTS_EDIT_COACH_FIELDS:
  case SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS:
  case SSERV_CMD_CNTS_EDIT_GUEST_FIELDS:
    r = super_html_edit_form_fields(f, p->priv_level, p->user_id, p->login,
                                    p->cookie, p->ip, config, sstate, pkt->b.id,
                                    self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;

  case SSERV_CMD_CNTS_EDIT_USERS_HEADER:
  case SSERV_CMD_CNTS_EDIT_USERS_FOOTER:
  case SSERV_CMD_CNTS_EDIT_REGISTER_HEADER:
  case SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER:
  case SSERV_CMD_CNTS_EDIT_TEAM_HEADER:
  case SSERV_CMD_CNTS_EDIT_TEAM_MENU_1:
  case SSERV_CMD_CNTS_EDIT_TEAM_MENU_2:
  case SSERV_CMD_CNTS_EDIT_TEAM_MENU_3:
  case SSERV_CMD_CNTS_EDIT_TEAM_SEPARATOR:
  case SSERV_CMD_CNTS_EDIT_TEAM_FOOTER:
  case SSERV_CMD_CNTS_EDIT_PRIV_HEADER:
  case SSERV_CMD_CNTS_EDIT_PRIV_FOOTER:
  case SSERV_CMD_CNTS_EDIT_COPYRIGHT:
  case SSERV_CMD_CNTS_EDIT_WELCOME:
  case SSERV_CMD_CNTS_EDIT_REG_WELCOME:
  case SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE:
  case SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD:
  case SSERV_CMD_GLOB_EDIT_CONTEST_STOP_CMD:
  case SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE:
  case SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE:
  case SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE:
  case SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE:
  case SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE:
  case SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE:
    r = super_html_edit_template_file(f, p->priv_level, p->user_id, p->login,
                                      p->cookie, p->ip, config, sstate, pkt->b.id,
                                      self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;
  case SSERV_CMD_CNTS_COMMIT:
    r = super_html_commit_contest(f, p->priv_level, p->user_id, p->login,
                                  p->cookie, p->ip, config, userlist_clnt,
                                  sstate, pkt->b.id,
                                  self_url_ptr, hidden_vars_ptr,
                                  extra_args_ptr);
    break;
  case SSERV_CMD_EDIT_CURRENT_GLOBAL:
    r = super_html_edit_global_parameters(f, p->priv_level, p->user_id, p->login,
                                          p->cookie, p->ip, config, sstate,
                                          self_url_ptr, hidden_vars_ptr,
                                          extra_args_ptr);
    break;

  case SSERV_CMD_EDIT_CURRENT_LANG:
    r = super_html_edit_languages(f, p->priv_level, p->user_id, p->login,
                                  p->cookie, p->ip, config, sstate,
                                  self_url_ptr, hidden_vars_ptr,
                                  extra_args_ptr);
    break;

  case SSERV_CMD_EDIT_CURRENT_PROB:
    r = super_html_edit_problems(f, p->priv_level, p->user_id, p->login,
                                 p->cookie, p->ip, config, sstate,
                                 self_url_ptr, hidden_vars_ptr,
                                 extra_args_ptr);
    break;

  case SSERV_CMD_VIEW_NEW_SERVE_CFG:
    r = super_html_view_new_serve_cfg(f, p->priv_level, p->user_id, p->login,
                                      p->cookie, p->ip, config, sstate,
                                      self_url_ptr, hidden_vars_ptr,
                                      extra_args_ptr);
    break;

  case SSERV_CMD_PROB_EDIT_VARIANTS:
  case SSERV_CMD_PROB_EDIT_VARIANTS_2:
    r = super_html_edit_variants(f, pkt->b.id, p->priv_level, p->user_id, p->login,
                                 p->cookie, p->ip, p->ssl, userlist_clnt,
                                 config, sstate, self_url_ptr, hidden_vars_ptr,
                                 extra_args_ptr);
    break;

  default:
    abort();
  }

  if (r < 0) {
    fclose(f); xfree(html_ptr);
    info("cmd_main_page: %s", super_proto_strerror(-r));
    send_reply(p, r);
    return;
  }

  close_memstream(f); f = 0;
  if (!html_ptr) html_ptr = xstrdup("");
  q = client_state_new_autoclose(p, html_ptr, html_len);
  (void) q;

  info("cmd_main_page: %zu", html_len);
  send_reply(p, SSERV_RPL_OK);
}

static void
cmd_create_contest(struct client_state *p, int len,
                   struct prot_super_pkt_create_contest *pkt)
{
  int r;
  unsigned char *self_url_ptr, *hidden_vars_ptr, *extra_args_ptr;
  int self_url_len, hidden_vars_len, extra_args_len, total_len;
  struct sid_state *sstate;
  char *html_ptr = 0;
  size_t html_len = 0;
  FILE *f;
  struct client_state *q;

  if (slave_mode) return error_slave_mode(p);

  if (len < sizeof(*pkt)) return error_packet_too_short(p, len, sizeof(*pkt));
  self_url_ptr = pkt->data;
  self_url_len = strlen(self_url_ptr);
  if (self_url_len != pkt->self_url_len)
    return error_field_len_mismatch(p, "self_url",
                                    self_url_len, pkt->self_url_len);
  hidden_vars_ptr = self_url_ptr + self_url_len + 1;
  hidden_vars_len = strlen(hidden_vars_ptr);
  if (hidden_vars_len != pkt->hidden_vars_len)
    return error_field_len_mismatch(p, "hidden_vars",
                                    hidden_vars_len, pkt->hidden_vars_len);
  extra_args_ptr = hidden_vars_ptr + hidden_vars_len + 1;
  extra_args_len = strlen(extra_args_ptr);
  if (extra_args_len != pkt->extra_args_len)
    return error_field_len_mismatch(p, "extra_args",
                                    extra_args_len, pkt->extra_args_len);
  total_len = sizeof(*pkt) + self_url_len + hidden_vars_len + extra_args_len;
  if (total_len != len)
    return error_bad_packet_length(p, len, total_len);

  if ((r = get_peer_local_user(p)) < 0) {
    send_reply(p, r);
    return;
  }

  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("cmd_main_page: two file descriptors expected");
    return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
  }

  // FIXME: check permissions

  sstate = sid_state_get(p->cookie, p->ip, p->user_id, p->login, p->name);
  if (!(f = open_memstream(&html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    return send_reply(p, -SSERV_ERR_SYSTEM_ERROR);
  }

  switch (pkt->b.id) {
  case SSERV_CMD_CREATE_CONTEST_2:
    r = super_html_create_contest_2(f, p->priv_level, p->user_id, p->login,
                                    userlist_login,
                                    p->cookie, p->ip, p->ssl, config, sstate,
                                    pkt->num_mode, pkt->templ_mode,
                                    pkt->contest_id, pkt->templ_id,
                                    self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    break;
  default:
    abort();
  }

  if (r < 0) {
    fclose(f);
    xfree(html_ptr);
    send_reply(p, r);
    return;
  }

  close_memstream(f); f = 0;
  if (!html_ptr) html_ptr = xstrdup("");
  q = client_state_new_autoclose(p, html_ptr, html_len);
  (void) q;

  info("cmd_create_contest: %zu", html_len);
  send_reply(p, SSERV_RPL_OK);
}

static int contest_mngmt_cmd(const struct contest_desc *cnts,
                             int cmd,
                             int user_id,
                             const unsigned char *user_login);
static void
cmd_simple_command(struct client_state *p, int len,
                   struct prot_super_pkt_simple_cmd *pkt)
{
  int r;
  const struct contest_desc *cnts;
  struct contest_desc *rw_cnts;
  opcap_t caps;

  if (slave_mode) return error_slave_mode(p);

  if (sizeof(*pkt) != len)
    return error_bad_packet_length(p, len, sizeof(*pkt));

  if ((r = get_peer_local_user(p)) < 0) {
    return send_reply(p, r);
  }

  if (contests_get(pkt->contest_id, &cnts) < 0 || !cnts) {
    return send_reply(p, -SSERV_ERR_INVALID_CONTEST);
  }

  if (opcaps_find(&cnts->capabilities, p->login, &caps) < 0) {
    err("%d: user %d has no privileges", p->id, p->user_id);
    return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
  }
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) {
    err("%d: user %d has no CONTROL_CONTEST capability",p->id, p->user_id);
    return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
  }

  switch (pkt->b.id) {
  case SSERV_CMD_OPEN_CONTEST:
  case SSERV_CMD_CLOSE_CONTEST:
  case SSERV_CMD_INVISIBLE_CONTEST:
  case SSERV_CMD_VISIBLE_CONTEST:
    if (contests_load(pkt->contest_id, &rw_cnts) < 0 || !rw_cnts) {
      return send_reply(p, -SSERV_ERR_INVALID_CONTEST);
    }
    break;
  }

  switch (pkt->b.id) {
  case SSERV_CMD_OPEN_CONTEST:
    r = super_html_open_contest(rw_cnts, p->user_id, p->login, p->ip);
    break;
  case SSERV_CMD_CLOSE_CONTEST:
    r = super_html_close_contest(rw_cnts, p->user_id, p->login, p->ip);
    break;
  case SSERV_CMD_INVISIBLE_CONTEST:
    r = super_html_make_invisible_contest(rw_cnts, p->user_id, p->login, p->ip);
    break;
  case SSERV_CMD_VISIBLE_CONTEST:
    r = super_html_make_visible_contest(rw_cnts, p->user_id, p->login, p->ip);
    break;
  case SSERV_CMD_RUN_LOG_TRUNC:
  case SSERV_CMD_RUN_LOG_DEV_NULL:
  case SSERV_CMD_RUN_LOG_FILE:
  case SSERV_CMD_RUN_MNG_TERM:
  case SSERV_CMD_CONTEST_RESTART:
  case SSERV_CMD_RUN_MNG_RESET_ERROR:
  case SSERV_CMD_CLEAR_MESSAGES:
    r = contest_mngmt_cmd(cnts, pkt->b.id, p->user_id, p->login);
    break;
  default:
    err("%d: unhandled command: %d", p->id, pkt->b.id);
    p->state = STATE_DISCONNECT;
    return;
  }

  send_reply(p, r);
}

static void
cmd_simple_top_command(struct client_state *p, int len,
                       struct prot_super_pkt_simple_cmd *pkt)
{
  int r;
  struct sid_state *sstate;

  if (slave_mode) return error_slave_mode(p);

  if (sizeof(*pkt) != len)
    return error_bad_packet_length(p, len, sizeof(*pkt));

  if ((r = get_peer_local_user(p)) < 0) {
    return send_reply(p, r);
  }
  sstate = sid_state_get(p->cookie, p->ip, p->user_id, p->login, p->name);

  switch (pkt->b.id) {
  case SSERV_CMD_SHOW_HIDDEN:
    sstate->flags |= SID_STATE_SHOW_HIDDEN;
    break;
  case SSERV_CMD_HIDE_HIDDEN:
    sstate->flags &= ~SID_STATE_SHOW_HIDDEN;
    break;
  case SSERV_CMD_SHOW_CLOSED:
    sstate->flags |= SID_STATE_SHOW_CLOSED;
    break;
  case SSERV_CMD_HIDE_CLOSED:
    sstate->flags &= ~SID_STATE_SHOW_CLOSED;
    break;
  case SSERV_CMD_SHOW_UNMNG:
    sstate->flags |= SID_STATE_SHOW_UNMNG;
    break;
  case SSERV_CMD_HIDE_UNMNG:
    sstate->flags &= ~SID_STATE_SHOW_UNMNG;
    break;
  case SSERV_CMD_CNTS_BASIC_VIEW:
    sstate->advanced_view = 0;
    break;
  case SSERV_CMD_CNTS_ADVANCED_VIEW:
    sstate->advanced_view = 1;
    break;
  case SSERV_CMD_CNTS_SHOW_HTML_HEADERS:
    sstate->show_html_headers = 1;
    break;
  case SSERV_CMD_CNTS_HIDE_HTML_HEADERS:
    sstate->show_html_headers = 0;
    break;
  case SSERV_CMD_CNTS_SHOW_HTML_ATTRS:
    sstate->show_html_attrs = 1;
    break;
  case SSERV_CMD_CNTS_HIDE_HTML_ATTRS:
    sstate->show_html_attrs = 0;
    break;
  case SSERV_CMD_CNTS_SHOW_PATHS:
    sstate->show_paths = 1;
    break;
  case SSERV_CMD_CNTS_HIDE_PATHS:
    sstate->show_paths = 0;
    break;
  case SSERV_CMD_CNTS_SHOW_NOTIFICATIONS:
    sstate->show_notifications = 1;
    break;
  case SSERV_CMD_CNTS_HIDE_NOTIFICATIONS:
    sstate->show_notifications = 0;
    break;
  case SSERV_CMD_CNTS_SHOW_ACCESS_RULES:
    sstate->show_access_rules = 1;
    break;
  case SSERV_CMD_CNTS_HIDE_ACCESS_RULES:
    sstate->show_access_rules = 0;
    break;
  case SSERV_CMD_CNTS_SHOW_PERMISSIONS:
    sstate->show_permissions = 1;
    break;
  case SSERV_CMD_CNTS_HIDE_PERMISSIONS:
    sstate->show_permissions = 0;
    break;
  case SSERV_CMD_CNTS_SHOW_FORM_FIELDS:
    sstate->show_form_fields = 1;
    break;
  case SSERV_CMD_CNTS_HIDE_FORM_FIELDS:
    sstate->show_form_fields = 0;
    break;
  case SSERV_CMD_CNTS_FORGET:
    super_serve_clear_edited_contest(sstate);
    break;
  case SSERV_CMD_GLOB_SHOW_1:
    sstate->show_global_1 = 1;
    break;
  case SSERV_CMD_GLOB_HIDE_1:
    sstate->show_global_1 = 0;
    break;
  case SSERV_CMD_GLOB_SHOW_2:
    sstate->show_global_2 = 1;
    break;
  case SSERV_CMD_GLOB_HIDE_2:
    sstate->show_global_2 = 0;
    break;
  case SSERV_CMD_GLOB_SHOW_3:
    sstate->show_global_3 = 1;
    break;
  case SSERV_CMD_GLOB_HIDE_3:
    sstate->show_global_3 = 0;
    break;
  case SSERV_CMD_GLOB_SHOW_4:
    sstate->show_global_4 = 1;
    break;
  case SSERV_CMD_GLOB_HIDE_4:
    sstate->show_global_4 = 0;
    break;
  case SSERV_CMD_GLOB_SHOW_5:
    sstate->show_global_5 = 1;
    break;
  case SSERV_CMD_GLOB_HIDE_5:
    sstate->show_global_5 = 0;
    break;
  case SSERV_CMD_GLOB_SHOW_6:
    sstate->show_global_6 = 1;
    break;
  case SSERV_CMD_GLOB_HIDE_6:
    sstate->show_global_6 = 0;
    break;
  case SSERV_CMD_GLOB_SHOW_7:
    sstate->show_global_7 = 1;
    break;
  case SSERV_CMD_GLOB_HIDE_7:
    sstate->show_global_7 = 0;
    break;

  case SSERV_CMD_CNTS_CLEAR_NAME:
  case SSERV_CMD_CNTS_CLEAR_NAME_EN:
  case SSERV_CMD_CNTS_CLEAR_MAIN_URL:
  case SSERV_CMD_CNTS_CLEAR_KEYWORDS:
  case SSERV_CMD_CNTS_CLEAR_USER_CONTEST:
  case SSERV_CMD_CNTS_CLEAR_DEFAULT_LOCALE:
  case SSERV_CMD_CNTS_CLEAR_DEADLINE:
  case SSERV_CMD_CNTS_CLEAR_SCHED_TIME:
  case SSERV_CMD_CNTS_CLEAR_OPEN_TIME:
  case SSERV_CMD_CNTS_CLEAR_CLOSE_TIME:
  case SSERV_CMD_CNTS_CLEAR_USERS_HEADER:
  case SSERV_CMD_CNTS_CLEAR_USERS_FOOTER:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER:
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEADER:
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1:
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_2:
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_3:
  case SSERV_CMD_CNTS_CLEAR_TEAM_SEPARATOR:
  case SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER:
  case SSERV_CMD_CNTS_CLEAR_PRIV_HEADER:
  case SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER:
  case SSERV_CMD_CNTS_CLEAR_COPYRIGHT:
  case SSERV_CMD_CNTS_CLEAR_WELCOME:
  case SSERV_CMD_CNTS_CLEAR_REG_WELCOME:
  case SSERV_CMD_CNTS_CLEAR_USERS_HEAD_STYLE:
  case SSERV_CMD_CNTS_CLEAR_USERS_PAR_STYLE:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_STYLE:
  case SSERV_CMD_CNTS_CLEAR_USERS_VERB_STYLE:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT_EN:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND_EN:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEAD_STYLE:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_PAR_STYLE:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_TABLE_STYLE:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_NAME_COMMENT:
  case SSERV_CMD_CNTS_CLEAR_ALLOWED_LANGUAGES:
  case SSERV_CMD_CNTS_CLEAR_ALLOWED_REGIONS:
  case SSERV_CMD_CNTS_CLEAR_CF_NOTIFY_EMAIL:
  case SSERV_CMD_CNTS_CLEAR_CLAR_NOTIFY_EMAIL:
  case SSERV_CMD_CNTS_CLEAR_DAILY_STAT_EMAIL:
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEAD_STYLE:
  case SSERV_CMD_CNTS_CLEAR_TEAM_PAR_STYLE:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_URL:
  case SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE:
  case SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE_OPTIONS:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE:
  case SSERV_CMD_CNTS_CLEAR_TEAM_URL:
  case SSERV_CMD_CNTS_CLEAR_STANDINGS_URL:
  case SSERV_CMD_CNTS_CLEAR_PROBLEMS_URL:
  case SSERV_CMD_CNTS_CLEAR_LOGO_URL:
  case SSERV_CMD_CNTS_CLEAR_CSS_URL:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_SUBJECT:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_SUBJECT_EN:
  case SSERV_CMD_CNTS_CLEAR_ROOT_DIR:
  case SSERV_CMD_CNTS_CLEAR_CONF_DIR:
  case SSERV_CMD_CNTS_CLEAR_DIR_MODE:
  case SSERV_CMD_CNTS_CLEAR_DIR_GROUP:
  case SSERV_CMD_CNTS_CLEAR_FILE_MODE:
  case SSERV_CMD_CNTS_CLEAR_FILE_GROUP:
  case SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1_TEXT:
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_2_TEXT:
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_3_TEXT:
  case SSERV_CMD_CNTS_CLEAR_TEAM_SEPARATOR_TEXT:
  case SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_PRIV_HEADER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_COPYRIGHT_TEXT:
  case SSERV_CMD_CNTS_CLEAR_WELCOME_TEXT:
  case SSERV_CMD_CNTS_CLEAR_REG_WELCOME_TEXT:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT:
    r = super_html_clear_variable(sstate, pkt->b.id);
    break;

  case SSERV_CMD_LANG_UPDATE_VERSIONS:
    r = super_html_update_versions(sstate);
    break;

  default:
    err("%d: unhandled command: %d", p->id, pkt->b.id);
    p->state = STATE_DISCONNECT;
    return;
  }

  send_reply(p, r);
}

static void
cmd_set_value(struct client_state *p, int len,
              struct prot_super_pkt_set_param *pkt)
{
  unsigned char *param2_ptr;
  size_t param2_len, total_len;
  struct sid_state *sstate;
  int r;

  if (slave_mode) return error_slave_mode(p);

  if (len < sizeof(*pkt))
    return error_packet_too_short(p, len, sizeof(*pkt));
  param2_ptr = pkt->data;
  param2_len = strlen(param2_ptr);
  if (param2_len != pkt->param2_len)
    return error_field_len_mismatch(p, "param2", param2_len, pkt->param2_len);
  total_len = sizeof(*pkt) + param2_len;
  if (total_len != len)
    return error_bad_packet_length(p, len, total_len);

  if ((r = get_peer_local_user(p)) < 0) {
    return send_reply(p, r);
  }
  sstate = sid_state_get(p->cookie, p->ip, p->user_id, p->login, p->name);

  switch (pkt->b.id) {
  case SSERV_CMD_CNTS_CHANGE_NAME:
  case SSERV_CMD_CNTS_CHANGE_NAME_EN:
  case SSERV_CMD_CNTS_CHANGE_MAIN_URL:
  case SSERV_CMD_CNTS_CHANGE_KEYWORDS:
  case SSERV_CMD_CNTS_CHANGE_USER_CONTEST:
  case SSERV_CMD_CNTS_CHANGE_DEFAULT_LOCALE:
  case SSERV_CMD_CNTS_CHANGE_AUTOREGISTER:
  case SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD:
  case SSERV_CMD_CNTS_CHANGE_SIMPLE_REGISTRATION:
  case SSERV_CMD_CNTS_CHANGE_ASSIGN_LOGINS:
  case SSERV_CMD_CNTS_CHANGE_FORCE_REGISTRATION:
  case SSERV_CMD_CNTS_CHANGE_DISABLE_NAME:
  case SSERV_CMD_CNTS_CHANGE_ENABLE_PASSWORD_RECOVERY:
  case SSERV_CMD_CNTS_CHANGE_EXAM_MODE:
  case SSERV_CMD_CNTS_CHANGE_DISABLE_PASSWORD_CHANGE:
  case SSERV_CMD_CNTS_CHANGE_DISABLE_LOCALE_CHANGE:
  case SSERV_CMD_CNTS_CHANGE_PERSONAL:
  case SSERV_CMD_CNTS_CHANGE_ALLOW_REG_DATA_EDIT:
  case SSERV_CMD_CNTS_CHANGE_SEND_PASSWD_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_MANAGED:
  case SSERV_CMD_CNTS_CHANGE_RUN_MANAGED:
  case SSERV_CMD_CNTS_CHANGE_OLD_RUN_MANAGED:
  case SSERV_CMD_CNTS_CHANGE_CLEAN_USERS:
  case SSERV_CMD_CNTS_CHANGE_CLOSED:
  case SSERV_CMD_CNTS_CHANGE_INVISIBLE:
  case SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE:
  case SSERV_CMD_CNTS_CHANGE_DEADLINE:
  case SSERV_CMD_CNTS_CHANGE_SCHED_TIME:
  case SSERV_CMD_CNTS_CHANGE_OPEN_TIME:
  case SSERV_CMD_CNTS_CHANGE_CLOSE_TIME:
  case SSERV_CMD_CNTS_CHANGE_USERS_HEADER:
  case SSERV_CMD_CNTS_CHANGE_USERS_FOOTER:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_HEADER:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_FOOTER:
  case SSERV_CMD_CNTS_CHANGE_TEAM_HEADER:
  case SSERV_CMD_CNTS_CHANGE_TEAM_MENU_1:
  case SSERV_CMD_CNTS_CHANGE_TEAM_MENU_2:
  case SSERV_CMD_CNTS_CHANGE_TEAM_MENU_3:
  case SSERV_CMD_CNTS_CHANGE_TEAM_SEPARATOR:
  case SSERV_CMD_CNTS_CHANGE_TEAM_FOOTER:
  case SSERV_CMD_CNTS_CHANGE_PRIV_HEADER:
  case SSERV_CMD_CNTS_CHANGE_PRIV_FOOTER:
  case SSERV_CMD_CNTS_CHANGE_COPYRIGHT:
  case SSERV_CMD_CNTS_CHANGE_WELCOME:
  case SSERV_CMD_CNTS_CHANGE_REG_WELCOME:
  case SSERV_CMD_CNTS_CHANGE_USERS_HEAD_STYLE:
  case SSERV_CMD_CNTS_CHANGE_USERS_PAR_STYLE:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_STYLE:
  case SSERV_CMD_CNTS_CHANGE_USERS_VERB_STYLE:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT_EN:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND_EN:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_HEAD_STYLE:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_PAR_STYLE:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_TABLE_STYLE:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_NAME_COMMENT:
  case SSERV_CMD_CNTS_CHANGE_ALLOWED_LANGUAGES:
  case SSERV_CMD_CNTS_CHANGE_ALLOWED_REGIONS:
  case SSERV_CMD_CNTS_CHANGE_CF_NOTIFY_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_CLAR_NOTIFY_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_DAILY_STAT_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_TEAM_HEAD_STYLE:
  case SSERV_CMD_CNTS_CHANGE_TEAM_PAR_STYLE:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_URL:
  case SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE:
  case SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE_OPTIONS:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL_FILE:
  case SSERV_CMD_CNTS_CHANGE_TEAM_URL:
  case SSERV_CMD_CNTS_CHANGE_STANDINGS_URL:
  case SSERV_CMD_CNTS_CHANGE_PROBLEMS_URL:
  case SSERV_CMD_CNTS_CHANGE_LOGO_URL:
  case SSERV_CMD_CNTS_CHANGE_CSS_URL:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_SUBJECT:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_SUBJECT_EN:
  case SSERV_CMD_CNTS_CHANGE_ROOT_DIR:
  case SSERV_CMD_CNTS_CHANGE_CONF_DIR:
  case SSERV_CMD_CNTS_CHANGE_DIR_MODE:
  case SSERV_CMD_CNTS_CHANGE_DIR_GROUP:
  case SSERV_CMD_CNTS_CHANGE_FILE_MODE:
  case SSERV_CMD_CNTS_CHANGE_FILE_GROUP:
  case SSERV_CMD_CNTS_DEFAULT_ACCESS:
  case SSERV_CMD_CNTS_ADD_RULE:
  case SSERV_CMD_CNTS_CHANGE_RULE:
  case SSERV_CMD_CNTS_DELETE_RULE:
  case SSERV_CMD_CNTS_UP_RULE:
  case SSERV_CMD_CNTS_DOWN_RULE:
  case SSERV_CMD_CNTS_COPY_ACCESS:
  case SSERV_CMD_CNTS_DELETE_PERMISSION:
  case SSERV_CMD_CNTS_ADD_PERMISSION:
  case SSERV_CMD_CNTS_SAVE_PERMISSIONS:
  case SSERV_CMD_CNTS_SAVE_FORM_FIELDS:
  case SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS:
  case SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS:
  case SSERV_CMD_CNTS_SAVE_COACH_FIELDS:
  case SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS:
  case SSERV_CMD_CNTS_SAVE_GUEST_FIELDS:
  case SSERV_CMD_CNTS_SAVE_USERS_HEADER:
  case SSERV_CMD_CNTS_SAVE_USERS_FOOTER:
  case SSERV_CMD_CNTS_SAVE_REGISTER_HEADER:
  case SSERV_CMD_CNTS_SAVE_REGISTER_FOOTER:
  case SSERV_CMD_CNTS_SAVE_TEAM_HEADER:
  case SSERV_CMD_CNTS_SAVE_TEAM_MENU_1:
  case SSERV_CMD_CNTS_SAVE_TEAM_MENU_2:
  case SSERV_CMD_CNTS_SAVE_TEAM_MENU_3:
  case SSERV_CMD_CNTS_SAVE_TEAM_SEPARATOR:
  case SSERV_CMD_CNTS_SAVE_TEAM_FOOTER:
  case SSERV_CMD_CNTS_SAVE_PRIV_HEADER:
  case SSERV_CMD_CNTS_SAVE_PRIV_FOOTER:
  case SSERV_CMD_CNTS_SAVE_COPYRIGHT:
  case SSERV_CMD_CNTS_SAVE_WELCOME:
  case SSERV_CMD_CNTS_SAVE_REG_WELCOME:
  case SSERV_CMD_CNTS_SAVE_REGISTER_EMAIL_FILE:
    r = super_html_set_contest_var(sstate, pkt->b.id, pkt->param1, param2_ptr,
                                   pkt->param3, pkt->param4, pkt->param5);
    break;

  case SSERV_CMD_LANG_SHOW_DETAILS:
  case SSERV_CMD_LANG_HIDE_DETAILS:
  case SSERV_CMD_LANG_DEACTIVATE:
  case SSERV_CMD_LANG_ACTIVATE:
  case SSERV_CMD_LANG_CHANGE_DISABLED:
  case SSERV_CMD_LANG_CHANGE_INSECURE:
  case SSERV_CMD_LANG_CHANGE_LONG_NAME:
  case SSERV_CMD_LANG_CLEAR_LONG_NAME:
  case SSERV_CMD_LANG_CHANGE_EXTID:
  case SSERV_CMD_LANG_CLEAR_EXTID:
  case SSERV_CMD_LANG_CHANGE_DISABLE_SECURITY:
  case SSERV_CMD_LANG_CHANGE_DISABLE_AUTO_TESTING:
  case SSERV_CMD_LANG_CHANGE_DISABLE_TESTING:
  case SSERV_CMD_LANG_CHANGE_BINARY:
  case SSERV_CMD_LANG_CHANGE_MAX_VM_SIZE:
  case SSERV_CMD_LANG_CHANGE_MAX_STACK_SIZE:
  case SSERV_CMD_LANG_CHANGE_MAX_FILE_SIZE:
  case SSERV_CMD_LANG_CHANGE_CONTENT_TYPE:
  case SSERV_CMD_LANG_CLEAR_CONTENT_TYPE:
  case SSERV_CMD_LANG_CHANGE_OPTS:
  case SSERV_CMD_LANG_CLEAR_OPTS:
  case SSERV_CMD_LANG_CHANGE_STYLE_CHECKER_CMD:
  case SSERV_CMD_LANG_CLEAR_STYLE_CHECKER_CMD:
  case SSERV_CMD_LANG_CHANGE_STYLE_CHECKER_ENV:
  case SSERV_CMD_LANG_CLEAR_STYLE_CHECKER_ENV:
    r = super_html_lang_cmd(sstate, pkt->b.id, pkt->param1, param2_ptr,
                            pkt->param3, pkt->param4);
    break;

  case SSERV_CMD_PROB_ADD:
  case SSERV_CMD_PROB_ADD_ABSTRACT:
  case SSERV_CMD_PROB_SHOW_DETAILS:
  case SSERV_CMD_PROB_HIDE_DETAILS:
  case SSERV_CMD_PROB_SHOW_ADVANCED:
  case SSERV_CMD_PROB_HIDE_ADVANCED:
    r = super_html_prob_cmd(sstate, pkt->b.id, pkt->param1, param2_ptr,
                            pkt->param3, pkt->param4);
    break;

  case SSERV_CMD_PROB_DELETE:
  case SSERV_CMD_PROB_CHANGE_SHORT_NAME:
  case SSERV_CMD_PROB_CLEAR_SHORT_NAME:
  case SSERV_CMD_PROB_CHANGE_LONG_NAME:
  case SSERV_CMD_PROB_CLEAR_LONG_NAME:
  case SSERV_CMD_PROB_CHANGE_STAND_NAME:
  case SSERV_CMD_PROB_CLEAR_STAND_NAME:
  case SSERV_CMD_PROB_CHANGE_STAND_COLUMN:
  case SSERV_CMD_PROB_CLEAR_STAND_COLUMN:
  case SSERV_CMD_PROB_CHANGE_INTERNAL_NAME:
  case SSERV_CMD_PROB_CLEAR_INTERNAL_NAME:
  case SSERV_CMD_PROB_CHANGE_SUPER:
  case SSERV_CMD_PROB_CHANGE_TYPE:
  case SSERV_CMD_PROB_CHANGE_SCORING_CHECKER:
  case SSERV_CMD_PROB_CHANGE_INTERACTIVE_VALUER:
  case SSERV_CMD_PROB_CHANGE_DISABLE_PE:
  case SSERV_CMD_PROB_CHANGE_DISABLE_WTL:
  case SSERV_CMD_PROB_CHANGE_MANUAL_CHECKING:
  case SSERV_CMD_PROB_CHANGE_EXAMINATOR_NUM:
  case SSERV_CMD_PROB_CHANGE_CHECK_PRESENTATION:
  case SSERV_CMD_PROB_CHANGE_USE_STDIN:
  case SSERV_CMD_PROB_CHANGE_USE_STDOUT:
  case SSERV_CMD_PROB_CHANGE_COMBINED_STDIN:
  case SSERV_CMD_PROB_CHANGE_COMBINED_STDOUT:
  case SSERV_CMD_PROB_CHANGE_BINARY_INPUT:
  case SSERV_CMD_PROB_CHANGE_BINARY:
  case SSERV_CMD_PROB_CHANGE_IGNORE_EXIT_CODE:
  case SSERV_CMD_PROB_CHANGE_OLYMPIAD_MODE:
  case SSERV_CMD_PROB_CHANGE_SCORE_LATEST:
  case SSERV_CMD_PROB_CHANGE_SCORE_LATEST_OR_UNMARKED:
  case SSERV_CMD_PROB_CHANGE_SCORE_LATEST_MARKED:
  case SSERV_CMD_PROB_CHANGE_TIME_LIMIT:
  case SSERV_CMD_PROB_CHANGE_TIME_LIMIT_MILLIS:
  case SSERV_CMD_PROB_CHANGE_REAL_TIME_LIMIT:
  case SSERV_CMD_PROB_CHANGE_USE_AC_NOT_OK:
  case SSERV_CMD_PROB_CHANGE_IGNORE_PREV_AC:
  case SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_REP_VIEW:
  case SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_CE_VIEW:
  case SSERV_CMD_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT:
  case SSERV_CMD_PROB_CHANGE_IGNORE_COMPILE_ERRORS:
  case SSERV_CMD_PROB_CHANGE_DISABLE_USER_SUBMIT:
  case SSERV_CMD_PROB_CHANGE_DISABLE_TAB:
  case SSERV_CMD_PROB_CHANGE_RESTRICTED_STATEMENT:
  case SSERV_CMD_PROB_CHANGE_DISABLE_SUBMIT_AFTER_OK:
  case SSERV_CMD_PROB_CHANGE_DISABLE_SECURITY:
  case SSERV_CMD_PROB_CHANGE_DISABLE_TESTING:
  case SSERV_CMD_PROB_CHANGE_DISABLE_AUTO_TESTING:
  case SSERV_CMD_PROB_CHANGE_ENABLE_COMPILATION:
  case SSERV_CMD_PROB_CHANGE_FULL_SCORE:
  case SSERV_CMD_PROB_CHANGE_FULL_USER_SCORE:
  case SSERV_CMD_PROB_CHANGE_TEST_SCORE:
  case SSERV_CMD_PROB_CHANGE_RUN_PENALTY:
  case SSERV_CMD_PROB_CHANGE_ACM_RUN_PENALTY:
  case SSERV_CMD_PROB_CHANGE_MAX_USER_RUN_COUNT:
  case SSERV_CMD_PROB_CHANGE_DISQUALIFIED_PENALTY:
  case SSERV_CMD_PROB_CHANGE_VARIABLE_FULL_SCORE:
  case SSERV_CMD_PROB_CHANGE_TEST_SCORE_LIST:
  case SSERV_CMD_PROB_CLEAR_TEST_SCORE_LIST:
  case SSERV_CMD_PROB_CHANGE_SCORE_TESTS:
  case SSERV_CMD_PROB_CLEAR_SCORE_TESTS:
  case SSERV_CMD_PROB_CHANGE_TESTS_TO_ACCEPT:
  case SSERV_CMD_PROB_CHANGE_ACCEPT_PARTIAL:
  case SSERV_CMD_PROB_CHANGE_MIN_TESTS_TO_ACCEPT:
  case SSERV_CMD_PROB_CHANGE_HIDDEN:
  case SSERV_CMD_PROB_CHANGE_STAND_HIDE_TIME:
  case SSERV_CMD_PROB_CHANGE_ADVANCE_TO_NEXT:
  case SSERV_CMD_PROB_CHANGE_DISABLE_CTRL_CHARS:
  case SSERV_CMD_PROB_CHANGE_VALUER_SETS_MARKED:
  case SSERV_CMD_PROB_CHANGE_IGNORE_UNMARKED:
  case SSERV_CMD_PROB_CHANGE_DISABLE_STDERR:
  case SSERV_CMD_PROB_CHANGE_ENABLE_PROCESS_GROUP:
  case SSERV_CMD_PROB_CHANGE_ENABLE_TEXT_FORM:
  case SSERV_CMD_PROB_CHANGE_STAND_IGNORE_SCORE:
  case SSERV_CMD_PROB_CHANGE_STAND_LAST_COLUMN:
  case SSERV_CMD_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT:
  case SSERV_CMD_PROB_CHANGE_INTERACTOR_TIME_LIMIT:
  case SSERV_CMD_PROB_CHANGE_MAX_VM_SIZE:
  case SSERV_CMD_PROB_CHANGE_MAX_STACK_SIZE:
  case SSERV_CMD_PROB_CHANGE_MAX_CORE_SIZE:
  case SSERV_CMD_PROB_CHANGE_MAX_FILE_SIZE:
  case SSERV_CMD_PROB_CHANGE_MAX_OPEN_FILE_COUNT:
  case SSERV_CMD_PROB_CHANGE_MAX_PROCESS_COUNT:
  case SSERV_CMD_PROB_CHANGE_INPUT_FILE:
  case SSERV_CMD_PROB_CLEAR_INPUT_FILE:
  case SSERV_CMD_PROB_CHANGE_OUTPUT_FILE:
  case SSERV_CMD_PROB_CLEAR_OUTPUT_FILE:
  case SSERV_CMD_PROB_CHANGE_USE_CORR:
  case SSERV_CMD_PROB_CHANGE_USE_INFO:
  case SSERV_CMD_PROB_CHANGE_TEST_DIR:
  case SSERV_CMD_PROB_CLEAR_TEST_DIR:
  case SSERV_CMD_PROB_CHANGE_CORR_DIR:
  case SSERV_CMD_PROB_CLEAR_CORR_DIR:
  case SSERV_CMD_PROB_CHANGE_INFO_DIR:
  case SSERV_CMD_PROB_CLEAR_INFO_DIR:
  case SSERV_CMD_PROB_CHANGE_TEST_SFX:
  case SSERV_CMD_PROB_CLEAR_TEST_SFX:
  case SSERV_CMD_PROB_CHANGE_TEST_PAT:
  case SSERV_CMD_PROB_CLEAR_TEST_PAT:
  case SSERV_CMD_PROB_CHANGE_CORR_SFX:
  case SSERV_CMD_PROB_CLEAR_CORR_SFX:
  case SSERV_CMD_PROB_CHANGE_CORR_PAT:
  case SSERV_CMD_PROB_CLEAR_CORR_PAT:
  case SSERV_CMD_PROB_CHANGE_INFO_SFX:
  case SSERV_CMD_PROB_CLEAR_INFO_SFX:
  case SSERV_CMD_PROB_CHANGE_INFO_PAT:
  case SSERV_CMD_PROB_CLEAR_INFO_PAT:
  case SSERV_CMD_PROB_CHANGE_TGZ_SFX:
  case SSERV_CMD_PROB_CLEAR_TGZ_SFX:
  case SSERV_CMD_PROB_CHANGE_TGZ_PAT:
  case SSERV_CMD_PROB_CLEAR_TGZ_PAT:
  case SSERV_CMD_PROB_CHANGE_TGZDIR_SFX:
  case SSERV_CMD_PROB_CLEAR_TGZDIR_SFX:
  case SSERV_CMD_PROB_CHANGE_TGZDIR_PAT:
  case SSERV_CMD_PROB_CLEAR_TGZDIR_PAT:
  case SSERV_CMD_PROB_CHANGE_STANDARD_CHECKER:
  case SSERV_CMD_PROB_CHANGE_SCORE_BONUS:
  case SSERV_CMD_PROB_CLEAR_SCORE_BONUS:
  case SSERV_CMD_PROB_CHANGE_OPEN_TESTS:
  case SSERV_CMD_PROB_CLEAR_OPEN_TESTS:    
  case SSERV_CMD_PROB_CHANGE_FINAL_OPEN_TESTS:
  case SSERV_CMD_PROB_CLEAR_FINAL_OPEN_TESTS:    
  case SSERV_CMD_PROB_CHANGE_LANG_COMPILER_ENV:
  case SSERV_CMD_PROB_CLEAR_LANG_COMPILER_ENV:
  case SSERV_CMD_PROB_CHANGE_CHECK_CMD:
  case SSERV_CMD_PROB_CLEAR_CHECK_CMD:
  case SSERV_CMD_PROB_CHANGE_CHECKER_ENV:
  case SSERV_CMD_PROB_CLEAR_CHECKER_ENV:
  case SSERV_CMD_PROB_CHANGE_VALUER_CMD:
  case SSERV_CMD_PROB_CLEAR_VALUER_CMD:
  case SSERV_CMD_PROB_CHANGE_VALUER_ENV:
  case SSERV_CMD_PROB_CLEAR_VALUER_ENV:
  case SSERV_CMD_PROB_CHANGE_INTERACTOR_CMD:
  case SSERV_CMD_PROB_CLEAR_INTERACTOR_CMD:
  case SSERV_CMD_PROB_CHANGE_INTERACTOR_ENV:
  case SSERV_CMD_PROB_CLEAR_INTERACTOR_ENV:
  case SSERV_CMD_PROB_CHANGE_STYLE_CHECKER_CMD:
  case SSERV_CMD_PROB_CLEAR_STYLE_CHECKER_CMD:
  case SSERV_CMD_PROB_CHANGE_STYLE_CHECKER_ENV:
  case SSERV_CMD_PROB_CLEAR_STYLE_CHECKER_ENV:
  case SSERV_CMD_PROB_CHANGE_TEST_CHECKER_CMD:
  case SSERV_CMD_PROB_CLEAR_TEST_CHECKER_CMD:
  case SSERV_CMD_PROB_CHANGE_TEST_CHECKER_ENV:
  case SSERV_CMD_PROB_CLEAR_TEST_CHECKER_ENV:
  case SSERV_CMD_PROB_CHANGE_INIT_CMD:
  case SSERV_CMD_PROB_CLEAR_INIT_CMD:
  case SSERV_CMD_PROB_CHANGE_INIT_ENV:
  case SSERV_CMD_PROB_CLEAR_INIT_ENV:
  case SSERV_CMD_PROB_CHANGE_START_ENV:
  case SSERV_CMD_PROB_CLEAR_START_ENV:
  case SSERV_CMD_PROB_CHANGE_SOLUTION_SRC:
  case SSERV_CMD_PROB_CLEAR_SOLUTION_SRC:
  case SSERV_CMD_PROB_CHANGE_SOLUTION_CMD:
  case SSERV_CMD_PROB_CLEAR_SOLUTION_CMD:
  case SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ:
  case SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ:
  case SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ_MILLIS:
  case SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ_MILLIS:
  case SSERV_CMD_PROB_CHANGE_DISABLE_LANGUAGE:
  case SSERV_CMD_PROB_CLEAR_DISABLE_LANGUAGE:
  case SSERV_CMD_PROB_CHANGE_ENABLE_LANGUAGE:
  case SSERV_CMD_PROB_CLEAR_ENABLE_LANGUAGE:
  case SSERV_CMD_PROB_CHANGE_REQUIRE:
  case SSERV_CMD_PROB_CLEAR_REQUIRE:
  case SSERV_CMD_PROB_CHANGE_TEST_SETS:
  case SSERV_CMD_PROB_CLEAR_TEST_SETS:
  case SSERV_CMD_PROB_CHANGE_SCORE_VIEW:
  case SSERV_CMD_PROB_CLEAR_SCORE_VIEW:
  case SSERV_CMD_PROB_CHANGE_START_DATE:
  case SSERV_CMD_PROB_CLEAR_START_DATE:
  case SSERV_CMD_PROB_CHANGE_DEADLINE:
  case SSERV_CMD_PROB_CLEAR_DEADLINE:
  case SSERV_CMD_PROB_CHANGE_VARIANT_NUM:
  case SSERV_CMD_PROB_CHANGE_XML_FILE:
  case SSERV_CMD_PROB_CLEAR_XML_FILE:
  case SSERV_CMD_PROB_CHANGE_ALTERNATIVES_FILE:
  case SSERV_CMD_PROB_CLEAR_ALTERNATIVES_FILE:
  case SSERV_CMD_PROB_CHANGE_PLUGIN_FILE:
  case SSERV_CMD_PROB_CLEAR_PLUGIN_FILE:
  case SSERV_CMD_PROB_CHANGE_STAND_ATTR:
  case SSERV_CMD_PROB_CLEAR_STAND_ATTR:
  case SSERV_CMD_PROB_CHANGE_SOURCE_HEADER:
  case SSERV_CMD_PROB_CLEAR_SOURCE_HEADER:
  case SSERV_CMD_PROB_CHANGE_SOURCE_FOOTER:
  case SSERV_CMD_PROB_CLEAR_SOURCE_FOOTER:
  case SSERV_CMD_PROB_CHANGE_NORMALIZATION:
  case SSERV_CMD_PROB_CLEAR_NORMALIZATION:
    r = super_html_prob_param(sstate, pkt->b.id, pkt->param1, param2_ptr,
                              pkt->param3, pkt->param4);
    break;

  case SSERV_CMD_PROB_CLEAR_VARIANTS:
  case SSERV_CMD_PROB_RANDOM_VARIANTS:
    r = super_html_variant_prob_op(sstate, pkt->b.id, pkt->param1);
    break;

  case SSERV_CMD_GLOB_CHANGE_DURATION:
  case SSERV_CMD_GLOB_UNLIMITED_DURATION:
  case SSERV_CMD_GLOB_CHANGE_TYPE:
  case SSERV_CMD_GLOB_CHANGE_FOG_TIME:
  case SSERV_CMD_GLOB_CHANGE_UNFOG_TIME:
  case SSERV_CMD_GLOB_DISABLE_FOG:
  case SSERV_CMD_GLOB_CHANGE_STAND_LOCALE:
  case SSERV_CMD_GLOB_CHANGE_SRC_VIEW:
  case SSERV_CMD_GLOB_CHANGE_REP_VIEW:
  case SSERV_CMD_GLOB_CHANGE_CE_VIEW:
  case SSERV_CMD_GLOB_CHANGE_JUDGE_REPORT:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_CLARS:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_TEAM_CLARS:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_EOLN_SELECT:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK:
  case SSERV_CMD_GLOB_CHANGE_IGNORE_COMPILE_ERRORS:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW:
  case SSERV_CMD_GLOB_CHANGE_IGNORE_DUPICATED_RUNS:
  case SSERV_CMD_GLOB_CHANGE_REPORT_ERROR_CODE:
  case SSERV_CMD_GLOB_CHANGE_SHOW_DEADLINE:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_PRINTING:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_BANNER_PAGE:
  case SSERV_CMD_GLOB_CHANGE_PRINTOUT_USES_LOGIN:
  case SSERV_CMD_GLOB_CHANGE_PRUNE_EMPTY_USERS:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_FULL_ARCHIVE:
  case SSERV_CMD_GLOB_CHANGE_ADVANCED_LAYOUT:
  case SSERV_CMD_GLOB_CHANGE_IGNORE_BOM:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_USER_DATABASE:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_MAX_STACK_SIZE:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_REFRESH:
  case SSERV_CMD_GLOB_CHANGE_ALWAYS_SHOW_PROBLEMS:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_USER_STANDINGS:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_LANGUAGE:
  case SSERV_CMD_GLOB_CHANGE_PROBLEM_NAVIGATION:
  case SSERV_CMD_GLOB_CHANGE_VERTICAL_NAVIGATION:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_START:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_AUTO_JUDGE:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_AUTO_PRINT_PROTOCOL:
  case SSERV_CMD_GLOB_CHANGE_NOTIFY_CLAR_REPLY:
  case SSERV_CMD_GLOB_CHANGE_NOTIFY_STATUS_CHANGE:
  case SSERV_CMD_GLOB_CHANGE_TEST_DIR:
  case SSERV_CMD_GLOB_CLEAR_TEST_DIR:
  case SSERV_CMD_GLOB_CHANGE_CORR_DIR:
  case SSERV_CMD_GLOB_CLEAR_CORR_DIR:
  case SSERV_CMD_GLOB_CHANGE_INFO_DIR:
  case SSERV_CMD_GLOB_CLEAR_INFO_DIR:
  case SSERV_CMD_GLOB_CHANGE_TGZ_DIR:
  case SSERV_CMD_GLOB_CLEAR_TGZ_DIR:
  case SSERV_CMD_GLOB_CHANGE_CHECKER_DIR:
  case SSERV_CMD_GLOB_CLEAR_CHECKER_DIR:
  case SSERV_CMD_GLOB_CHANGE_STATEMENT_DIR:
  case SSERV_CMD_GLOB_CLEAR_STATEMENT_DIR:
  case SSERV_CMD_GLOB_CHANGE_PLUGIN_DIR:
  case SSERV_CMD_GLOB_CLEAR_PLUGIN_DIR:
  case SSERV_CMD_GLOB_CHANGE_DESCRIPTION_FILE:
  case SSERV_CMD_GLOB_CLEAR_DESCRIPTION_FILE:
  case SSERV_CMD_GLOB_CHANGE_CONTEST_START_CMD:
  case SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD:
  case SSERV_CMD_GLOB_CHANGE_CONTEST_STOP_CMD:
  case SSERV_CMD_GLOB_CLEAR_CONTEST_STOP_CMD:
  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_SIZE:
  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_TOTAL:
  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_NUM:
  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_SIZE:
  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_TOTAL:
  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_NUM:
  case SSERV_CMD_GLOB_CHANGE_TEAM_PAGE_QUOTA:
  case SSERV_CMD_GLOB_CHANGE_TEAM_INFO_URL:
  case SSERV_CMD_GLOB_CLEAR_TEAM_INFO_URL:
  case SSERV_CMD_GLOB_CHANGE_PROB_INFO_URL:
  case SSERV_CMD_GLOB_CLEAR_PROB_INFO_URL:
  case SSERV_CMD_GLOB_CHANGE_STAND_FILE_NAME:
  case SSERV_CMD_GLOB_CLEAR_STAND_FILE_NAME:
  case SSERV_CMD_GLOB_CHANGE_USERS_ON_PAGE:
  case SSERV_CMD_GLOB_CHANGE_STAND_HEADER_FILE:
  case SSERV_CMD_GLOB_CLEAR_STAND_HEADER_FILE:
  case SSERV_CMD_GLOB_CHANGE_STAND_FOOTER_FILE:
  case SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_FILE:
  case SSERV_CMD_GLOB_CHANGE_STAND_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CHANGE_STAND_IGNORE_AFTER:
  case SSERV_CMD_GLOB_CLEAR_STAND_IGNORE_AFTER:
  case SSERV_CMD_GLOB_CHANGE_APPEAL_DEADLINE:
  case SSERV_CMD_GLOB_CLEAR_APPEAL_DEADLINE:
  case SSERV_CMD_GLOB_CHANGE_CONTEST_FINISH_TIME:
  case SSERV_CMD_GLOB_CLEAR_CONTEST_FINISH_TIME:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_STAND2:
  case SSERV_CMD_GLOB_CHANGE_STAND2_FILE_NAME:
  case SSERV_CMD_GLOB_CLEAR_STAND2_FILE_NAME:
  case SSERV_CMD_GLOB_CHANGE_STAND2_HEADER_FILE:
  case SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_FILE:
  case SSERV_CMD_GLOB_CHANGE_STAND2_FOOTER_FILE:
  case SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_FILE:
  case SSERV_CMD_GLOB_CHANGE_STAND2_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CLEAR_STAND2_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_PLOG:
  case SSERV_CMD_GLOB_CHANGE_PLOG_FILE_NAME:
  case SSERV_CMD_GLOB_CLEAR_PLOG_FILE_NAME:
  case SSERV_CMD_GLOB_CHANGE_PLOG_HEADER_FILE:
  case SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_FILE:
  case SSERV_CMD_GLOB_CHANGE_PLOG_FOOTER_FILE:
  case SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_FILE:
  case SSERV_CMD_GLOB_CHANGE_PLOG_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CLEAR_PLOG_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CHANGE_PLOG_UPDATE_TIME:
  case SSERV_CMD_GLOB_CHANGE_EXTERNAL_XML_UPDATE_TIME:
  case SSERV_CMD_GLOB_CHANGE_INTERNAL_XML_UPDATE_TIME:
  case SSERV_CMD_GLOB_CHANGE_STAND_FANCY_STYLE:
  case SSERV_CMD_GLOB_CHANGE_STAND_TABLE_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_TABLE_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PLACE_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PLACE_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_TEAM_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_TEAM_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PROB_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PROB_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SOLVED_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SOLVED_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SCORE_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SCORE_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PENALTY_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PENALTY_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_USE_LOGIN:
  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_OK_TIME:
  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_ATT_NUM:
  case SSERV_CMD_GLOB_CHANGE_STAND_SORT_BY_SOLVED:
  case SSERV_CMD_GLOB_CHANGE_IGNORE_SUCCESS_TIME:
  case SSERV_CMD_GLOB_CHANGE_STAND_COLLATE_NAME:
  case SSERV_CMD_GLOB_CHANGE_STAND_ENABLE_PENALTY:
  case SSERV_CMD_GLOB_CHANGE_STAND_TIME_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_TIME_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SUCCESS_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SUCCESS_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_FAIL_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_FAIL_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_TRANS_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_TRANS_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_DISQ_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_DISQ_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SELF_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SELF_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_V_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_V_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_R_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_R_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_U_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_U_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_EXTRA_COL:
  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_FORMAT:
  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_FORMAT:
  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_LEGEND:
  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_LEGEND:
  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER:
  case SSERV_CMD_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR:
  case SSERV_CMD_GLOB_CHANGE_SLEEP_TIME:
  case SSERV_CMD_GLOB_CHANGE_SERVE_SLEEP_TIME:
  case SSERV_CMD_GLOB_CHANGE_AUTOUPDATE_STANDINGS:
  case SSERV_CMD_GLOB_CHANGE_USE_AC_NOT_OK:
  case SSERV_CMD_GLOB_CHANGE_ROUNDING_MODE:
  case SSERV_CMD_GLOB_CHANGE_MAX_FILE_LENGTH:
  case SSERV_CMD_GLOB_CHANGE_MAX_LINE_LENGTH:
  case SSERV_CMD_GLOB_CHANGE_INACTIVITY_TIMEOUT:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_TESTING:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_TESTING:
  case SSERV_CMD_GLOB_CHANGE_CR_SERIALIZATION_KEY:
  case SSERV_CMD_GLOB_CHANGE_SHOW_ASTR_TIME:
  case SSERV_CMD_GLOB_CHANGE_MEMOIZE_USER_RESULTS:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_CONTINUE:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_REPORT_UPLOAD:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_RUNLOG_MERGE:
  case SSERV_CMD_GLOB_CHANGE_USE_COMPILATION_SERVER:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_WIN32_LANGUAGES:
  case SSERV_CMD_GLOB_CHANGE_SECURE_RUN:
  case SSERV_CMD_GLOB_CHANGE_DETECT_VIOLATIONS:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR:
  case SSERV_CMD_GLOB_CHANGE_SEPARATE_USER_SCORE:
  case SSERV_CMD_GLOB_CHANGE_STAND_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_CUR_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_CUR_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_COL_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_COL_ATTR:

  case SSERV_CMD_GLOB_CHANGE_ENABLE_L10N:
  case SSERV_CMD_GLOB_CHANGE_CHARSET:
  case SSERV_CMD_GLOB_CLEAR_CHARSET:
  case SSERV_CMD_GLOB_CHANGE_STANDINGS_CHARSET:
  case SSERV_CMD_GLOB_CLEAR_STANDINGS_CHARSET:
  case SSERV_CMD_GLOB_CHANGE_STAND2_CHARSET:
  case SSERV_CMD_GLOB_CLEAR_STAND2_CHARSET:
  case SSERV_CMD_GLOB_CHANGE_PLOG_CHARSET:
  case SSERV_CMD_GLOB_CLEAR_PLOG_CHARSET:
  case SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME:
  case SSERV_CMD_GLOB_DISABLE_TEAM_DOWNLOAD_TIME:
  case SSERV_CMD_GLOB_CHANGE_CPU_BOGOMIPS:
  case SSERV_CMD_GLOB_DETECT_CPU_BOGOMIPS:
  case SSERV_CMD_GLOB_SAVE_CONTEST_START_CMD:
  case SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT:
  case SSERV_CMD_GLOB_SAVE_CONTEST_STOP_CMD:
  case SSERV_CMD_GLOB_CLEAR_CONTEST_STOP_CMD_TEXT:
  case SSERV_CMD_GLOB_SAVE_STAND_HEADER:
  case SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT:
  case SSERV_CMD_GLOB_SAVE_STAND_FOOTER:
  case SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT:
  case SSERV_CMD_GLOB_SAVE_STAND2_HEADER:
  case SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT:
  case SSERV_CMD_GLOB_SAVE_STAND2_FOOTER:
  case SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT:
  case SSERV_CMD_GLOB_SAVE_PLOG_HEADER:
  case SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT:
  case SSERV_CMD_GLOB_SAVE_PLOG_FOOTER:
  case SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT:
  case SSERV_CMD_GLOB_CHANGE_CLARDB_PLUGIN:
  case SSERV_CMD_GLOB_CLEAR_CLARDB_PLUGIN:
  case SSERV_CMD_GLOB_CHANGE_RUNDB_PLUGIN:
  case SSERV_CMD_GLOB_CLEAR_RUNDB_PLUGIN:
  case SSERV_CMD_GLOB_CHANGE_XUSER_PLUGIN:
  case SSERV_CMD_GLOB_CLEAR_XUSER_PLUGIN:
  case SSERV_CMD_GLOB_CHANGE_LOAD_USER_GROUP:
  case SSERV_CMD_GLOB_CLEAR_LOAD_USER_GROUP:
  case SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_VM_SIZE:
  case SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_STACK_SIZE:
  case SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_FILE_SIZE:
    r = super_html_global_param(sstate, pkt->b.id, config,
                                pkt->param1, param2_ptr, pkt->param3, pkt->param4);
    break;

  case SSERV_CMD_PROB_CHANGE_VARIANTS:
  case SSERV_CMD_PROB_DELETE_VARIANTS:
    r = super_html_variant_param(sstate, pkt->b.id,
                                 pkt->param1, param2_ptr, pkt->param3, pkt->param4);
    break;

  default:
    abort();
  }

  send_reply(p, r);
}

static int
check_restart_permissions(struct client_state *p)
{
  struct passwd *sysp = 0;
  opcap_t caps = 0;

  if (!p->peer_uid) return 1;   /* root is allowed */
  if (p->peer_uid == getuid()) return 1; /* the current user also allowed */
  if (!(sysp = getpwuid(p->peer_uid)) || !sysp->pw_name) {
    err("no user %d in system tables", p->peer_uid);
    return -1;
  }
  const unsigned char *ejudge_login = ejudge_cfg_user_map_find(config, sysp->pw_name);
  if (!ejudge_login) return 0;

  if (ejudge_cfg_opcaps_find(config, ejudge_login, &caps) < 0)
    return 0;
  if (opcaps_check(caps, OPCAP_RESTART) < 0) return 0;
  return 1;
}

static void
cmd_control_server(struct client_state *p, int len,
                   struct prot_super_packet *pkt)
{
  int mon_fd = -1;

  if (sizeof(*pkt) != len)
    return error_bad_packet_length(p, len, sizeof(*pkt));

  if (check_restart_permissions(p) <= 0) {
    return send_reply(p, -SSERV_ERR_PERMISSION_DENIED);
  }

  switch (pkt->id) {
  case SSERV_CMD_STOP:
  case SSERV_CMD_RESTART:
    break;
  default:
    abort();
  }

  // mon_fd is intentionally "leaked"
  // it is closed implicitly when the program exits or execs itself
  // client waits for EOF on connection to ensure command completion
  mon_fd = dup(p->fd);
  fcntl(mon_fd, F_SETFD, FD_CLOEXEC);
  p->state = STATE_DISCONNECT;

  switch (pkt->id) {
  case SSERV_CMD_STOP:
    info("STOP");
    term_flag = 1;
    break;
  case SSERV_CMD_RESTART:
    info("RESTART");
    hup_flag = 1;
    break;
  }
}

static void
cmd_http_request_continuation(struct super_http_request_info *phr);

static void
cmd_http_request(
        struct client_state *p,
        int pkt_size,
        struct prot_super_pkt_http_request *pkt)
{
  enum
  {
    MAX_PARAM_NUM = 10000,
    MAX_PARAM_SIZE = 128 * 1024 * 1024,
  };

  struct super_http_request_info *phr = NULL;
  char *out_t = 0;
  size_t out_z = 0;
  int i, r;
  size_t in_size;
  const unsigned char ** args;
  const unsigned char ** envs;
  const unsigned char ** param_names;
  const unsigned char ** params;
  size_t *my_param_sizes;
  unsigned long bptr;
  const ej_size_t *arg_sizes, *env_sizes, *param_name_sizes, *param_sizes;
  struct client_state *q;
  unsigned char *out_ptr;
  int ri_size = sizeof (*phr);

  // FIXME: check for passed fd

  if (pkt_size < sizeof(*pkt))
    return error_bad_packet_length(p, pkt_size, sizeof(*pkt));

  if (pkt->arg_num < 0 || pkt->arg_num > MAX_PARAM_NUM) {
    err("%d: too many arguments: %d", p->id, pkt->arg_num);
    return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
  }
  if (pkt->env_num < 0 || pkt->env_num > MAX_PARAM_NUM) {
    err("%d: too many env vars: %d", p->id, pkt->env_num);
    return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
  }
  if (pkt->param_num < 0 || pkt->param_num > MAX_PARAM_NUM) {
    err("%d: too many params: %d", p->id, pkt->param_num);
    return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
  }

  in_size = sizeof(*pkt);
  in_size += pkt->arg_num * sizeof(ej_size_t);
  in_size += pkt->env_num * sizeof(ej_size_t);
  in_size += pkt->param_num * 2 * sizeof(ej_size_t);
  if (pkt_size < in_size)
    return error_bad_packet_length(p, pkt_size, in_size);

  ri_size = pkt_bin_align(ri_size);
  ri_size += sizeof(args[0]) * pkt->arg_num;
  ri_size = pkt_bin_align(ri_size);
  ri_size += sizeof(envs[0]) * pkt->env_num;
  ri_size = pkt_bin_align(ri_size);
  ri_size += sizeof(param_names[0]) * pkt->param_num;
  ri_size = pkt_bin_align(ri_size);
  ri_size += sizeof(params[0]) * pkt->param_num;
  ri_size = pkt_bin_align(ri_size);
  ri_size += sizeof(my_param_sizes[0]) * pkt->param_num;
  ri_size = pkt_bin_align(ri_size);

  phr = xmalloc(ri_size);
  memset(phr, 0, ri_size);
  out_ptr = phr->data;
  pkt_bin_align_addr(out_ptr, phr->data);
  args = (typeof(args)) out_ptr;
  out_ptr += sizeof(args[0]) * pkt->arg_num;
  pkt_bin_align_addr(out_ptr, phr->data);
  envs = (typeof(envs)) out_ptr;
  out_ptr += sizeof(envs[0]) * pkt->env_num;
  pkt_bin_align_addr(out_ptr, phr->data);
  param_names = (typeof(param_names)) out_ptr;
  out_ptr += sizeof(param_names[0]) * pkt->param_num;
  pkt_bin_align_addr(out_ptr, phr->data);
  params = (typeof(params)) out_ptr;
  out_ptr += sizeof(params[0]) * pkt->param_num;
  pkt_bin_align_addr(out_ptr, phr->data);
  my_param_sizes = (typeof(my_param_sizes)) out_ptr;
  out_ptr += sizeof(my_param_sizes[0]) * pkt->param_num;
  pkt_bin_align_addr(out_ptr, phr->data);
  
  bptr = (unsigned long) pkt;
  bptr += sizeof(*pkt);
  arg_sizes = (const ej_size_t *) bptr;
  bptr += pkt->arg_num * sizeof(ej_size_t);
  env_sizes = (const ej_size_t *) bptr;
  bptr += pkt->env_num * sizeof(ej_size_t);
  param_name_sizes = (const ej_size_t *) bptr;
  bptr += pkt->param_num * sizeof(ej_size_t);
  param_sizes = (const ej_size_t *) bptr;
  bptr += pkt->param_num * sizeof(ej_size_t);

  for (i = 0; i < pkt->arg_num; i++) {
    if (arg_sizes[i] > MAX_PARAM_SIZE) {
      err("%d: argument %d is too long: %d", p->id, i, arg_sizes[i]);
      xfree(phr);
      return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
    }
    in_size += arg_sizes[i] + 1;
  }
  for (i = 0; i < pkt->env_num; i++) {
    if (env_sizes[i] > MAX_PARAM_SIZE) {
      err("%d: env var %d is too long: %d", p->id, i, env_sizes[i]);
      xfree(phr);
      return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
    }
    in_size += env_sizes[i] + 1;
  }
  for (i = 0; i < pkt->param_num; i++) {
    if (param_name_sizes[i] > MAX_PARAM_SIZE) {
      err("%d: param name %d is too long: %d", p->id, i, param_name_sizes[i]);
      xfree(phr);
      return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
    }
    if (param_sizes[i] > MAX_PARAM_SIZE) {
      err("%d: param %d is too long: %d", p->id, i, param_sizes[i]);
      xfree(phr);
      return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
    }
    in_size += param_name_sizes[i] + 1;
    in_size += param_sizes[i] + 1;
  }
  if (pkt_size != in_size) {
    xfree(phr);
    return error_bad_packet_length(p, pkt_size, in_size);
  }

  for (i = 0; i < pkt->arg_num; i++) {
    args[i] = (const unsigned char*) bptr;
    bptr += arg_sizes[i] + 1;
    if (strlen(args[i]) != arg_sizes[i]) {
      err("%d: arg %d length mismatch", p->id, i);
      xfree(phr);
      return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
    }
  }
  for (i = 0; i < pkt->env_num; i++) {
    envs[i] = (const unsigned char*) bptr;
    bptr += env_sizes[i] + 1;
    if (strlen(envs[i]) != env_sizes[i]) {
      err("%d: env var %d length mismatch", p->id, i);
      xfree(phr);
      return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
    }
  }
  for (i = 0; i < pkt->param_num; i++) {
    param_names[i] = (const unsigned char*) bptr;
    bptr += param_name_sizes[i] + 1;
    if (strlen(param_names[i]) != param_name_sizes[i]) {
      err("%d: param name %d length mismatch", p->id, i);
      xfree(phr);
      return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
    }
    params[i] = (const unsigned char *) bptr;
    my_param_sizes[i] = param_sizes[i];
    bptr += param_sizes[i] + 1;
  }

  if ((r = get_peer_local_user(p)) < 0) {
    send_reply(p, r);
    xfree(phr);
    return;
  }

  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("cmd_main_page: two file descriptors expected");
    xfree(phr);
    return send_reply(p, -SSERV_ERR_PROTOCOL_ERROR);
  }

  phr->arg_num = pkt->arg_num;
  phr->args = args;
  phr->env_num = pkt->env_num;
  phr->envs = envs;
  phr->param_num = pkt->param_num;
  phr->param_names = param_names;
  phr->param_sizes = my_param_sizes;
  phr->params = params;

  phr->user_id = p->user_id;
  phr->priv_level = p->priv_level;
  phr->login = p->login;
  phr->name = p->name;
  phr->html_login = p->html_login;
  phr->html_name = p->html_name;
  phr->ip = p->ip;
  phr->ssl_flag = p->ssl;
  phr->system_login = userlist_login;
  phr->userlist_clnt = userlist_clnt;

  phr->ss = sid_state_get(p->cookie, p->ip, p->user_id, p->login, p->name);
  phr->config = config;

  super_html_http_request(&out_t, &out_z, phr);
  if (phr->suspend_reply > 0) {
    p->state = STATE_SUSPENDED;
    phr->suspend_context = p;
    phr->continuation = cmd_http_request_continuation;
    return;
  }

  q = client_state_new_autoclose(p, out_t, out_z);
  (void) q;
  info("cmd_http_request: %zu", out_z);
  send_reply(p, SSERV_RPL_OK);
  xfree(phr);

  //cleanup:
}

static void
cmd_http_request_continuation(struct super_http_request_info *phr)
{
  struct client_state *p = (typeof(p)) phr->suspend_context;
  info("continuation: %d, %d, %d\n", p->fd, p->client_fds[0], p->client_fds[1]);
  close_memstream(phr->out_f); phr->out_f = 0;
  close_memstream(phr->log_f); phr->log_f = 0;
  client_state_new_autoclose(p, phr->out_t, phr->out_z);
  info("cmd_http_request_continuation: %zu", phr->out_z);
  xfree(phr->log_t); phr->log_t = NULL; phr->log_z = 0;
  phr->out_t = NULL; phr->out_z = 0;
  send_reply(p, SSERV_RPL_OK);
  xfree(phr);
}

struct packet_handler
{
  void (*func)();
};
static const struct packet_handler packet_handlers[SSERV_CMD_LAST] =
{
  [SSERV_CMD_PASS_FD] = { cmd_pass_fd },
  [SSERV_CMD_MAIN_PAGE] = { cmd_main_page },
  [SSERV_CMD_CONTEST_PAGE] = { cmd_main_page },
  [SSERV_CMD_VIEW_RUN_LOG] = { cmd_main_page },
  [SSERV_CMD_VIEW_CONTEST_XML] = { cmd_main_page },
  [SSERV_CMD_VIEW_SERVE_CFG] = { cmd_main_page },
  [SSERV_CMD_OPEN_CONTEST] = { cmd_simple_command },
  [SSERV_CMD_CLOSE_CONTEST] = { cmd_simple_command },
  [SSERV_CMD_INVISIBLE_CONTEST] = { cmd_simple_command },
  [SSERV_CMD_VISIBLE_CONTEST] = { cmd_simple_command },
  [SSERV_CMD_RUN_LOG_TRUNC] = { cmd_simple_command },
  [SSERV_CMD_RUN_LOG_DEV_NULL] = { cmd_simple_command },
  [SSERV_CMD_RUN_LOG_FILE] = { cmd_simple_command },
  [SSERV_CMD_RUN_MNG_TERM] = { cmd_simple_command },
  [SSERV_CMD_CONTEST_RESTART] = { cmd_simple_command },
  [SSERV_CMD_RUN_MNG_RESET_ERROR] = { cmd_simple_command },
  [SSERV_CMD_CLEAR_MESSAGES] = { cmd_simple_command },

  [SSERV_CMD_SHOW_HIDDEN] = { cmd_simple_top_command },
  [SSERV_CMD_HIDE_HIDDEN] = { cmd_simple_top_command },
  [SSERV_CMD_SHOW_CLOSED] = { cmd_simple_top_command },
  [SSERV_CMD_HIDE_CLOSED] = { cmd_simple_top_command },
  [SSERV_CMD_SHOW_UNMNG] = { cmd_simple_top_command },
  [SSERV_CMD_HIDE_UNMNG] = { cmd_simple_top_command },
  [SSERV_CMD_CREATE_CONTEST] = { cmd_main_page },
  [SSERV_CMD_CREATE_CONTEST_2] = { cmd_create_contest },
  [SSERV_CMD_EDIT_CURRENT_CONTEST] = { cmd_main_page },
  [SSERV_CMD_CNTS_BASIC_VIEW] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_ADVANCED_VIEW] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_SHOW_HTML_HEADERS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_HIDE_HTML_HEADERS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_SHOW_HTML_ATTRS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_HIDE_HTML_ATTRS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_FORGET] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_SHOW_PATHS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_HIDE_PATHS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_SHOW_NOTIFICATIONS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_HIDE_NOTIFICATIONS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_SHOW_ACCESS_RULES] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_HIDE_ACCESS_RULES] = { cmd_simple_top_command },
  [SSERV_CMD_EDIT_REGISTER_ACCESS] = { cmd_main_page },
  [SSERV_CMD_EDIT_USERS_ACCESS] = { cmd_main_page },
  [SSERV_CMD_EDIT_MASTER_ACCESS] = { cmd_main_page },
  [SSERV_CMD_EDIT_JUDGE_ACCESS] = { cmd_main_page },
  [SSERV_CMD_EDIT_TEAM_ACCESS] = { cmd_main_page },
  [SSERV_CMD_EDIT_SERVE_CONTROL_ACCESS] = { cmd_main_page },
  [SSERV_CMD_CNTS_SHOW_PERMISSIONS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_HIDE_PERMISSIONS] = { cmd_simple_top_command },
  [SSERV_CMD_EDIT_CONTEST_XML] = { cmd_main_page },
  [SSERV_CMD_EDIT_SERVE_CFG_PROB] = { cmd_main_page },
  [SSERV_CMD_CHECK_TESTS] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_PERMISSION] = { cmd_main_page },
  [SSERV_CMD_CNTS_SHOW_FORM_FIELDS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_HIDE_FORM_FIELDS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_EDIT_FORM_FIELDS] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_COACH_FIELDS] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_GUEST_FIELDS] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_USERS_HEADER] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_USERS_FOOTER] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_REGISTER_HEADER] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_TEAM_HEADER] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_TEAM_MENU_1] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_TEAM_MENU_2] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_TEAM_MENU_3] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_TEAM_SEPARATOR] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_TEAM_FOOTER] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_PRIV_HEADER] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_PRIV_FOOTER] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_COPYRIGHT] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_WELCOME] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_REG_WELCOME] = { cmd_main_page },
  [SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE] = { cmd_main_page },
  [SSERV_CMD_CNTS_CLEAR_NAME] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_NAME_EN] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_MAIN_URL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_KEYWORDS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USER_CONTEST] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_DEFAULT_LOCALE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_DEADLINE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_SCHED_TIME] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_OPEN_TIME] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_CLOSE_TIME] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_HEADER] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_FOOTER] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_TEAM_HEADER] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_TEAM_MENU_2] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_TEAM_MENU_3] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_TEAM_SEPARATOR] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_PRIV_HEADER] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_COPYRIGHT] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_WELCOME] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REG_WELCOME] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_HEAD_STYLE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_PAR_STYLE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_STYLE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_VERB_STYLE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT_EN] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND_EN] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_HEAD_STYLE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_PAR_STYLE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_TABLE_STYLE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_NAME_COMMENT] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_ALLOWED_LANGUAGES] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_ALLOWED_REGIONS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_CF_NOTIFY_EMAIL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_CLAR_NOTIFY_EMAIL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_DAILY_STAT_EMAIL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_TEAM_HEAD_STYLE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_TEAM_PAR_STYLE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_URL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE_OPTIONS] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_TEAM_URL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_STANDINGS_URL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_PROBLEMS_URL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_LOGO_URL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_CSS_URL] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_SUBJECT] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_SUBJECT_EN] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_ROOT_DIR] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_CONF_DIR] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_DIR_MODE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_DIR_GROUP] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_FILE_MODE] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CLEAR_FILE_GROUP] = { cmd_simple_top_command },
  [SSERV_CMD_CNTS_CHANGE_NAME] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_NAME_EN] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_MAIN_URL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_KEYWORDS] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USER_CONTEST] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_DEFAULT_LOCALE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_AUTOREGISTER] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_SIMPLE_REGISTRATION] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_ASSIGN_LOGINS] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_FORCE_REGISTRATION] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_DISABLE_NAME] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_ENABLE_PASSWORD_RECOVERY] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_EXAM_MODE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_DISABLE_PASSWORD_CHANGE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_DISABLE_LOCALE_CHANGE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_PERSONAL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_ALLOW_REG_DATA_EDIT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_SEND_PASSWD_EMAIL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_MANAGED] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_RUN_MANAGED] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_OLD_RUN_MANAGED] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_CLEAN_USERS] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_CLOSED] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_INVISIBLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_DEADLINE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_SCHED_TIME] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_OPEN_TIME] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_CLOSE_TIME] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_HEADER] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_FOOTER] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_HEADER] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_FOOTER] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_HEADER] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_MENU_1] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_MENU_2] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_MENU_3] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_SEPARATOR] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_FOOTER] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_PRIV_HEADER] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_PRIV_FOOTER] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_COPYRIGHT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_WELCOME] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REG_WELCOME] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_HEAD_STYLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_PAR_STYLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_STYLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_VERB_STYLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT_EN] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND_EN] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_HEAD_STYLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_PAR_STYLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_TABLE_STYLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_NAME_COMMENT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_ALLOWED_LANGUAGES] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_ALLOWED_REGIONS] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_CF_NOTIFY_EMAIL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_CLAR_NOTIFY_EMAIL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_DAILY_STAT_EMAIL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_HEAD_STYLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_PAR_STYLE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_URL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE_OPTIONS] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL_FILE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_TEAM_URL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_STANDINGS_URL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_PROBLEMS_URL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_LOGO_URL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_CSS_URL] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_SUBJECT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_REGISTER_SUBJECT_EN] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_ROOT_DIR] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_CONF_DIR] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_DIR_MODE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_DIR_GROUP] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_FILE_MODE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_FILE_GROUP] = { cmd_set_value },
  [SSERV_CMD_CNTS_DEFAULT_ACCESS] = { cmd_set_value },
  [SSERV_CMD_CNTS_ADD_RULE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CHANGE_RULE] = { cmd_set_value },
  [SSERV_CMD_CNTS_DELETE_RULE] = { cmd_set_value },
  [SSERV_CMD_CNTS_UP_RULE] = { cmd_set_value },
  [SSERV_CMD_CNTS_DOWN_RULE] = { cmd_set_value },
  [SSERV_CMD_CNTS_COPY_ACCESS] = { cmd_set_value },
  [SSERV_CMD_CNTS_DELETE_PERMISSION] = { cmd_set_value },
  [SSERV_CMD_CNTS_ADD_PERMISSION] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_PERMISSIONS] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_FORM_FIELDS] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_COACH_FIELDS] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_GUEST_FIELDS] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_USERS_HEADER] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_USERS_FOOTER] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_REGISTER_HEADER] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_REGISTER_FOOTER] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_TEAM_HEADER] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_TEAM_MENU_1] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_TEAM_MENU_2] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_TEAM_MENU_3] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_TEAM_SEPARATOR] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_TEAM_FOOTER] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_PRIV_HEADER] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_PRIV_FOOTER] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_COPYRIGHT] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_WELCOME] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_REG_WELCOME] = { cmd_set_value },
  [SSERV_CMD_CNTS_SAVE_REGISTER_EMAIL_FILE] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_TEAM_SEPARATOR_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_PRIV_HEADER_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_COPYRIGHT_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_WELCOME_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_REG_WELCOME_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT] = { cmd_set_value },
  [SSERV_CMD_CNTS_COMMIT] = { cmd_main_page },
  [SSERV_CMD_EDIT_CURRENT_GLOBAL] = { cmd_main_page },
  [SSERV_CMD_GLOB_SHOW_1] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_HIDE_1] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_SHOW_2] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_HIDE_2] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_SHOW_3] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_HIDE_3] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_SHOW_4] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_HIDE_4] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_SHOW_5] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_HIDE_5] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_SHOW_6] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_HIDE_6] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_SHOW_7] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_HIDE_7] = { cmd_simple_top_command },
  [SSERV_CMD_EDIT_CURRENT_LANG] = { cmd_main_page },
  [SSERV_CMD_LANG_SHOW_DETAILS] = { cmd_set_value },
  [SSERV_CMD_LANG_HIDE_DETAILS] = { cmd_set_value },
  [SSERV_CMD_LANG_DEACTIVATE] = { cmd_set_value },
  [SSERV_CMD_LANG_ACTIVATE] = { cmd_set_value },

  [SSERV_CMD_LANG_CHANGE_DISABLED] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_INSECURE] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_LONG_NAME] = { cmd_set_value },
  [SSERV_CMD_LANG_CLEAR_LONG_NAME] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_EXTID] = { cmd_set_value },
  [SSERV_CMD_LANG_CLEAR_EXTID] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_CONTENT_TYPE] = { cmd_set_value },
  [SSERV_CMD_LANG_CLEAR_CONTENT_TYPE] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_DISABLE_SECURITY] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_DISABLE_AUTO_TESTING] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_DISABLE_TESTING] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_BINARY] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_MAX_VM_SIZE] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_MAX_STACK_SIZE] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_MAX_FILE_SIZE] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_OPTS] = { cmd_set_value },
  [SSERV_CMD_LANG_CLEAR_OPTS] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_STYLE_CHECKER_CMD] = { cmd_set_value },
  [SSERV_CMD_LANG_CLEAR_STYLE_CHECKER_CMD] = { cmd_set_value },
  [SSERV_CMD_LANG_CHANGE_STYLE_CHECKER_ENV] = { cmd_set_value },
  [SSERV_CMD_LANG_CLEAR_STYLE_CHECKER_ENV] = { cmd_set_value },

  [SSERV_CMD_EDIT_CURRENT_PROB] = { cmd_main_page },
  [SSERV_CMD_PROB_ADD] = { cmd_set_value },
  [SSERV_CMD_PROB_ADD_ABSTRACT] = { cmd_set_value },
  [SSERV_CMD_PROB_SHOW_DETAILS] = { cmd_set_value },
  [SSERV_CMD_PROB_HIDE_DETAILS] = { cmd_set_value },
  [SSERV_CMD_PROB_SHOW_ADVANCED] = { cmd_set_value },
  [SSERV_CMD_PROB_HIDE_ADVANCED] = { cmd_set_value },

  [SSERV_CMD_PROB_DELETE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SHORT_NAME] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_SHORT_NAME] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_LONG_NAME] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_LONG_NAME] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_STAND_NAME] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_STAND_NAME] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_STAND_COLUMN] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_STAND_COLUMN] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INTERNAL_NAME] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_INTERNAL_NAME] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SUPER] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TYPE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SCORING_CHECKER] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INTERACTIVE_VALUER] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_PE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_WTL] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_MANUAL_CHECKING] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_EXAMINATOR_NUM] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_CHECK_PRESENTATION] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_USE_STDIN] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_USE_STDOUT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_COMBINED_STDIN] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_COMBINED_STDOUT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_BINARY_INPUT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_BINARY] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_IGNORE_EXIT_CODE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_OLYMPIAD_MODE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SCORE_LATEST] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SCORE_LATEST_OR_UNMARKED] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SCORE_LATEST_MARKED] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TIME_LIMIT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TIME_LIMIT_MILLIS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_REAL_TIME_LIMIT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_USE_AC_NOT_OK] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_IGNORE_PREV_AC] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_REP_VIEW] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_CE_VIEW] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_IGNORE_COMPILE_ERRORS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_USER_SUBMIT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_TAB] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_RESTRICTED_STATEMENT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_SUBMIT_AFTER_OK] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_SECURITY] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_TESTING] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_AUTO_TESTING] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_ENABLE_COMPILATION] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_FULL_SCORE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_FULL_USER_SCORE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEST_SCORE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_RUN_PENALTY] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_ACM_RUN_PENALTY] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_MAX_USER_RUN_COUNT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISQUALIFIED_PENALTY] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_VARIABLE_FULL_SCORE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEST_SCORE_LIST] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TEST_SCORE_LIST] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SCORE_TESTS] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_SCORE_TESTS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TESTS_TO_ACCEPT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_ACCEPT_PARTIAL] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_MIN_TESTS_TO_ACCEPT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_HIDDEN] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_STAND_HIDE_TIME] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_ADVANCE_TO_NEXT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_CTRL_CHARS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_VALUER_SETS_MARKED] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_IGNORE_UNMARKED] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_STDERR] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_ENABLE_PROCESS_GROUP] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_ENABLE_TEXT_FORM] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_STAND_IGNORE_SCORE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_STAND_LAST_COLUMN] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INTERACTOR_TIME_LIMIT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_MAX_VM_SIZE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_MAX_STACK_SIZE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_MAX_CORE_SIZE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_MAX_FILE_SIZE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_MAX_OPEN_FILE_COUNT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_MAX_PROCESS_COUNT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INPUT_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_INPUT_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_OUTPUT_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_OUTPUT_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_USE_CORR] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_USE_INFO] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEST_DIR] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TEST_DIR] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_CORR_DIR] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_CORR_DIR] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INFO_DIR] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_INFO_DIR] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEST_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TEST_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEST_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TEST_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_CORR_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_CORR_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_CORR_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_CORR_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INFO_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_INFO_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INFO_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_INFO_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TGZ_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TGZ_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TGZ_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TGZ_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TGZDIR_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TGZDIR_SFX] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TGZDIR_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TGZDIR_PAT] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_STANDARD_CHECKER] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SCORE_BONUS] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_SCORE_BONUS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_OPEN_TESTS] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_OPEN_TESTS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_FINAL_OPEN_TESTS] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_FINAL_OPEN_TESTS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_LANG_COMPILER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_LANG_COMPILER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_CHECK_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_CHECK_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_CHECKER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_CHECKER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_VALUER_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_VALUER_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_VALUER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_VALUER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INTERACTOR_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_INTERACTOR_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INTERACTOR_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_INTERACTOR_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_STYLE_CHECKER_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_STYLE_CHECKER_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_STYLE_CHECKER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_STYLE_CHECKER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEST_CHECKER_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TEST_CHECKER_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEST_CHECKER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TEST_CHECKER_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INIT_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_INIT_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_INIT_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_INIT_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_START_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_START_ENV] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SOLUTION_SRC] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_SOLUTION_SRC] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SOLUTION_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_SOLUTION_CMD] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ_MILLIS] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ_MILLIS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DISABLE_LANGUAGE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_DISABLE_LANGUAGE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_ENABLE_LANGUAGE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_ENABLE_LANGUAGE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_REQUIRE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_REQUIRE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_TEST_SETS] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_TEST_SETS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SCORE_VIEW] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_SCORE_VIEW] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_START_DATE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_START_DATE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_DEADLINE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_DEADLINE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_VARIANT_NUM] = { cmd_set_value },
  [SSERV_CMD_PROB_EDIT_VARIANTS] = { cmd_main_page },
  [SSERV_CMD_PROB_EDIT_VARIANTS_2] = { cmd_main_page },
  [SSERV_CMD_PROB_CHANGE_VARIANTS] = { cmd_set_value },
  [SSERV_CMD_PROB_DELETE_VARIANTS] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_XML_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_XML_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_ALTERNATIVES_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_ALTERNATIVES_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_PLUGIN_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_PLUGIN_FILE] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_STAND_ATTR] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_STAND_ATTR] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SOURCE_HEADER] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_SOURCE_HEADER] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_SOURCE_FOOTER] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_SOURCE_FOOTER] = { cmd_set_value },
  [SSERV_CMD_PROB_CHANGE_NORMALIZATION] = { cmd_set_value },
  [SSERV_CMD_PROB_CLEAR_NORMALIZATION] = { cmd_set_value },

  [SSERV_CMD_GLOB_CHANGE_DURATION] = { cmd_set_value },
  [SSERV_CMD_GLOB_UNLIMITED_DURATION] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_TYPE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_FOG_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_UNFOG_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_DISABLE_FOG] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_LOCALE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_SRC_VIEW] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_REP_VIEW] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_CE_VIEW] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_JUDGE_REPORT] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_CLARS] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_TEAM_CLARS] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_EOLN_SELECT] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_IGNORE_COMPILE_ERRORS] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_IGNORE_DUPICATED_RUNS] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_REPORT_ERROR_CODE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_SHOW_DEADLINE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_PRINTING] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_BANNER_PAGE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_PRINTOUT_USES_LOGIN] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_PRUNE_EMPTY_USERS] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_FULL_ARCHIVE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ADVANCED_LAYOUT] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_IGNORE_BOM] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_USER_DATABASE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_MAX_STACK_SIZE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_REFRESH] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_USER_STANDINGS] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_LANGUAGE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_PROBLEM_NAVIGATION] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_VERTICAL_NAVIGATION] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_START] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_AUTO_JUDGE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_AUTO_PRINT_PROTOCOL] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_NOTIFY_CLAR_REPLY] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_NOTIFY_STATUS_CHANGE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_TEST_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_TEST_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_CORR_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_CORR_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_INFO_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_INFO_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_TGZ_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_TGZ_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_CHECKER_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_CHECKER_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STATEMENT_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STATEMENT_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_PLUGIN_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_PLUGIN_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DESCRIPTION_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_DESCRIPTION_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_CONTEST_START_CMD] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD] = { cmd_set_value },
  [SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD] = { cmd_main_page },
  [SSERV_CMD_GLOB_CHANGE_CONTEST_STOP_CMD] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_CONTEST_STOP_CMD] = { cmd_set_value },
  [SSERV_CMD_GLOB_EDIT_CONTEST_STOP_CMD] = { cmd_main_page },
  [SSERV_CMD_GLOB_CHANGE_MAX_RUN_SIZE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_MAX_RUN_TOTAL] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_MAX_RUN_NUM] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_MAX_CLAR_SIZE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_MAX_CLAR_TOTAL] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_MAX_CLAR_NUM] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_TEAM_PAGE_QUOTA] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_TEAM_INFO_URL] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_TEAM_INFO_URL] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_PROB_INFO_URL] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_PROB_INFO_URL] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_FILE_NAME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_FILE_NAME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_USERS_ON_PAGE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_HEADER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_HEADER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE] = { cmd_main_page },
  [SSERV_CMD_GLOB_CHANGE_STAND_FOOTER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE] = { cmd_main_page },
  [SSERV_CMD_GLOB_CHANGE_STAND_SYMLINK_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_SYMLINK_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_IGNORE_AFTER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_IGNORE_AFTER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_APPEAL_DEADLINE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_APPEAL_DEADLINE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_CONTEST_FINISH_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_CONTEST_FINISH_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_STAND2] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND2_FILE_NAME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND2_FILE_NAME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND2_HEADER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE] = { cmd_main_page },
  [SSERV_CMD_GLOB_CHANGE_STAND2_FOOTER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE] = { cmd_main_page },
  [SSERV_CMD_GLOB_CHANGE_STAND2_SYMLINK_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND2_SYMLINK_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_PLOG] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_PLOG_FILE_NAME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_PLOG_FILE_NAME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_PLOG_HEADER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE] = { cmd_main_page },
  [SSERV_CMD_GLOB_CHANGE_PLOG_FOOTER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_FILE] = { cmd_set_value },
  [SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE] = { cmd_main_page },
  [SSERV_CMD_GLOB_CHANGE_PLOG_SYMLINK_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_PLOG_SYMLINK_DIR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_PLOG_UPDATE_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_EXTERNAL_XML_UPDATE_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_INTERNAL_XML_UPDATE_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_FANCY_STYLE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_TABLE_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_TABLE_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_PLACE_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_PLACE_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_TEAM_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_TEAM_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_PROB_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_PROB_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_SOLVED_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_SOLVED_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_SCORE_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_SCORE_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_PENALTY_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_PENALTY_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_USE_LOGIN] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_SHOW_OK_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_SHOW_ATT_NUM] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_SORT_BY_SOLVED] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_IGNORE_SUCCESS_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_COLLATE_NAME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_ENABLE_PENALTY] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_TIME_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_TIME_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_SUCCESS_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_SUCCESS_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_FAIL_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_FAIL_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_TRANS_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_TRANS_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_DISQ_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_DISQ_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_SELF_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_SELF_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_V_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_V_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_R_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_R_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_U_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_U_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_EXTRA_COL] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_FORMAT] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_FORMAT] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_LEGEND] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_LEGEND] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_SLEEP_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_SERVE_SLEEP_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_AUTOUPDATE_STANDINGS] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_USE_AC_NOT_OK] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ROUNDING_MODE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_MAX_FILE_LENGTH] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_MAX_LINE_LENGTH] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_INACTIVITY_TIMEOUT] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_TESTING] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DISABLE_TESTING] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_CR_SERIALIZATION_KEY] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_SHOW_ASTR_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_MEMOIZE_USER_RESULTS] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_CONTINUE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_REPORT_UPLOAD] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_RUNLOG_MERGE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_USE_COMPILATION_SERVER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_WIN32_LANGUAGES] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_SECURE_RUN] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_DETECT_VIOLATIONS] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_SEPARATE_USER_SCORE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_CUR_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_PAGE_CUR_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_PAGE_ROW_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_COL_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_PAGE_COL_ATTR] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_LOAD_USER_GROUP] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_LOAD_USER_GROUP] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_CLARDB_PLUGIN] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_CLARDB_PLUGIN] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_RUNDB_PLUGIN] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_RUNDB_PLUGIN] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_XUSER_PLUGIN] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_XUSER_PLUGIN] = { cmd_set_value },

  [SSERV_CMD_GLOB_CHANGE_ENABLE_L10N] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_CHARSET] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_CHARSET] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STANDINGS_CHARSET] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STANDINGS_CHARSET] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_STAND2_CHARSET] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND2_CHARSET] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_PLOG_CHARSET] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_PLOG_CHARSET] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_DISABLE_TEAM_DOWNLOAD_TIME] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_CPU_BOGOMIPS] = { cmd_set_value },
  [SSERV_CMD_GLOB_DETECT_CPU_BOGOMIPS] = { cmd_set_value },
  [SSERV_CMD_GLOB_SAVE_CONTEST_START_CMD] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT] = { cmd_set_value },
  [SSERV_CMD_GLOB_SAVE_CONTEST_STOP_CMD] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_CONTEST_STOP_CMD_TEXT] = { cmd_set_value },
  [SSERV_CMD_GLOB_SAVE_STAND_HEADER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT] = { cmd_set_value },
  [SSERV_CMD_GLOB_SAVE_STAND_FOOTER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT] = { cmd_set_value },
  [SSERV_CMD_GLOB_SAVE_STAND2_HEADER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT] = { cmd_set_value },
  [SSERV_CMD_GLOB_SAVE_STAND2_FOOTER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT] = { cmd_set_value },
  [SSERV_CMD_GLOB_SAVE_PLOG_HEADER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT] = { cmd_set_value },
  [SSERV_CMD_GLOB_SAVE_PLOG_FOOTER] = { cmd_set_value },
  [SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT] = { cmd_set_value },
  [SSERV_CMD_VIEW_NEW_SERVE_CFG] = { cmd_main_page },
  [SSERV_CMD_LANG_UPDATE_VERSIONS] = { cmd_simple_top_command },
  [SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_VM_SIZE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_STACK_SIZE] = { cmd_set_value },
  [SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_FILE_SIZE] = { cmd_set_value },

  [SSERV_CMD_PROB_CLEAR_VARIANTS] = { cmd_set_value },
  [SSERV_CMD_PROB_RANDOM_VARIANTS] = { cmd_set_value },

  [SSERV_CMD_STOP] = { cmd_control_server },
  [SSERV_CMD_RESTART] = { cmd_control_server },

  [SSERV_CMD_HTTP_REQUEST] = { cmd_http_request },
};

static void
handle_control_command(struct client_state *p)
{
  struct prot_super_packet *pkt;

  if (p->read_len < sizeof(struct prot_super_packet)) {
    err("%d: packet length is too small: %d", p->id, p->read_len);
    p->state = STATE_DISCONNECT;
    return;
  }
  pkt = (struct prot_super_packet*) p->read_buf;

  if (pkt->magic != PROT_SUPER_PACKET_MAGIC) {
    err("%d: invalid magic value: %04x", p->id, pkt->magic);
    p->state = STATE_DISCONNECT;
    return;
  }

  if (pkt->id <= 0 || pkt->id >= SSERV_CMD_LAST
      || !packet_handlers[pkt->id].func) {
    err("%d: invalid protocol command: %d", p->id, pkt->id);
    p->state = STATE_DISCONNECT;
    return;
  }

  (*packet_handlers[pkt->id].func)(p, p->read_len, pkt);

  if (p->state == STATE_SUSPENDED) return;

  if (p->state == STATE_READ_READY) p->state = STATE_READ_LEN;
  if (p->read_buf) xfree(p->read_buf);
  p->read_buf = 0;
  p->expected_len = 0;
  p->read_len = 0;
}

static int
contest_mngmt_cmd(
        const struct contest_desc *cnts,
        int cmd,
        int user_id,
        const unsigned char *user_login)
{
  path_t log_path;
  struct stat stbuf;
  struct contest_extra *extra;

  switch (cmd) {
  case SSERV_CMD_RUN_LOG_TRUNC:
    snprintf(log_path, sizeof(log_path), "%s/var/ej-run-messages.log", cnts->root_dir);
    if (truncate(log_path, 0) < 0 && errno != ENOENT) {
      err("truncate(\"%s\", 0) failed: %s", log_path, os_ErrorMsg());
      return -SSERV_ERR_SYSTEM_ERROR;
    }
    return 0;

  case SSERV_CMD_RUN_LOG_DEV_NULL:
    snprintf(log_path, sizeof(log_path), "%s/var/ej-run-messages.log", cnts->root_dir);
    if (unlink(log_path) < 0 && errno != ENOENT) {
      err("unlink(\"%s\") failed: %s", log_path, os_ErrorMsg());
      return -SSERV_ERR_SYSTEM_ERROR;
    }
    if (symlink("/dev/null", log_path) < 0) {
      err("symlink(\"dev/null\", \"%s\") failed: %s", log_path, os_ErrorMsg());
      return -SSERV_ERR_SYSTEM_ERROR;
    }
    return 0;

  case SSERV_CMD_RUN_LOG_FILE:
    snprintf(log_path, sizeof(log_path), "%s/var/ej-run-messages.log", cnts->root_dir);
    if (lstat(log_path, &stbuf) >= 0 && S_ISLNK(stbuf.st_mode)) {
      if (unlink(log_path) < 0) {
        err("unlink(\"%s\") failed: %s", log_path, os_ErrorMsg());
        return -SSERV_ERR_SYSTEM_ERROR;
      }
    }
    return 0;

  case SSERV_CMD_RUN_MNG_TERM:
    extra = get_existing_contest_extra(cnts->id);
    if (!extra) return -SSERV_ERR_INVALID_CONTEST;
    if (extra->run_pid > 0) kill(extra->run_pid, SIGTERM);
    if (run_inotify_fd >= 0) {
      close(run_inotify_fd);
      run_inotify_fd = -1;
    }
    return 0;

  case SSERV_CMD_CONTEST_RESTART:
    release_contest_resources(cnts);
    acquire_contest_resources(cnts, -1, -1);
    extra = get_contest_extra(cnts->id);
    if (extra->run_used && extra->run_queue_dir) {
      if (get_number_of_files(extra->run_queue_dir) > 0) {
        extra->dnotify_flag = 1;
      }
    }
    if (run_inotify_fd >= 0) {
      close(run_inotify_fd);
      run_inotify_fd = -1;
    }
    return 0;

  case SSERV_CMD_RUN_MNG_RESET_ERROR:
    extra = get_existing_contest_extra(cnts->id);
    if (!extra || !extra->run_suspended) return 0;
    extra->run_suspend_end = 0;
    if (run_inotify_fd >= 0) {
      close(run_inotify_fd);
      run_inotify_fd = -1;
    }
    return 0;

  case SSERV_CMD_CLEAR_MESSAGES:
    extra = get_existing_contest_extra(cnts->id);
    if (extra && extra->messages) {
      xfree(extra->messages);
      extra->messages = 0;
    }
    return 0;

  default:
    abort();
  }
}

static void
handle_control_accept(void *context, void *fds, void *user)
{
  struct pollfd *pfd = (struct pollfd *) fds;

  if ((pfd->revents & POLLNVAL)) {
    err("%s: ppoll invalid request fd=%d", __FUNCTION__, pfd->fd);
    // FIXME: what to do?
    abort();
  }
  /*
  if ((pfd->revents & POLLHUP)) {
    err("%s: ppoll hangup fd=%d", __FUNCTION__, pfd->fd);
    // FIXME: what to do?
    abort();
  }
  */
  if ((pfd->revents & POLLERR)) {
    err("%s: ppoll error fd=%d", __FUNCTION__, pfd->fd);
    // FIXME: what to do?
    abort();
  }
  if (!(pfd->revents & POLLIN)) {
    err("%s: ppoll not ready fd=%d", __FUNCTION__, pfd->fd);
    return;
  }

  accept_new_control_connection();
}

static void
handle_client_read(void *context, void *fds, void *user)
{
  struct pollfd *pfd = (struct pollfd *) fds;
  struct client_state *p = (struct client_state *) user;

  if ((pfd->revents & POLLNVAL)) {
    err("%s: ppoll invalid request fd=%d", __FUNCTION__, pfd->fd);
    p->state = STATE_DISCONNECT;
    return;
  }
  /*
  if ((pfd->revents & POLLHUP)) {
    err("%s: ppoll hangup fd=%d", __FUNCTION__, pfd->fd);
    p->state = STATE_DISCONNECT;
    return;
  }
  */
  if ((pfd->revents & POLLERR)) {
    err("%s: ppoll error fd=%d", __FUNCTION__, pfd->fd);
    p->state = STATE_DISCONNECT;
    return;
  }
  if (!(pfd->revents & POLLIN)) {
    err("%s: ppoll not ready fd=%d", __FUNCTION__, pfd->fd);
    return;
  }

  read_from_control_connection(p);
}

static void
handle_client_write(void *context, void *fds, void *user)
{
  struct pollfd *pfd = (struct pollfd *) fds;
  struct client_state *p = (struct client_state *) user;

  if ((pfd->revents & POLLNVAL)) {
    err("%s: ppoll invalid request fd=%d", __FUNCTION__, pfd->fd);
    p->state = STATE_DISCONNECT;
    return;
  }
  /*
  if ((pfd->revents & POLLHUP)) {
    err("%s: ppoll hangup fd=%d", __FUNCTION__, pfd->fd);
    p->state = STATE_DISCONNECT;
    return;
  }
  */
  if ((pfd->revents & POLLERR)) {
    err("%s: ppoll error fd=%d", __FUNCTION__, pfd->fd);
    p->state = STATE_DISCONNECT;
    return;
  }
  if (!(pfd->revents & POLLOUT)) {
    err("%s: ppoll not ready fd=%d", __FUNCTION__, pfd->fd);
    return;
  }

  write_to_control_connection(p);
}

static void
handle_inotify_read(void *context, void *fds, void *user)
{
  struct pollfd *pfd = (struct pollfd *) fds;
  unsigned char buf[8192];
  int r, cur_ind = 0, init_offset = 0, i;
  struct inotify_event *pev;
  struct contest_extra *cur;

  if ((pfd->revents & POLLNVAL)) {
    err("%s: ppoll invalid request fd=%d", __FUNCTION__, pfd->fd);
    // FIXME: what to do...
    return;
  }
  if ((pfd->revents & POLLERR)) {
    err("%s: ppoll error fd=%d", __FUNCTION__, pfd->fd);
    // FIXME: what to do...
    return;
  }
  if (!(pfd->revents & POLLIN)) {
    err("%s: ppoll not ready fd=%d", __FUNCTION__, pfd->fd);
    return;
  }

  do {
    r = read(pfd->fd, buf + init_offset, sizeof(buf) - init_offset);
    if (r < 0 && errno == EINTR) {
      err("%s: read() returned EINTR fd=%d", __FUNCTION__, pfd->fd);
      return;
    }
    if (r < 0 && errno == EAGAIN) {
      err("%s: read() returned EAGAIN fd=%d", __FUNCTION__, pfd->fd);
      return;
    }
    if (r < 0) {
      err("%s: read() failed fd=%d: %s", __FUNCTION__, pfd->fd, os_ErrorMsg());
      return;
    }
    if (r == 0) {
      err("%s: read() returned 0 fd=%d", __FUNCTION__, pfd->fd);
      return;
    }
    while (cur_ind < r) {
      if (cur_ind + sizeof(*pev) > r) {
        init_offset = r - cur_ind;
        memmove(buf, buf + cur_ind, init_offset);
        cur_ind = 0;
        break;
      }
      pev = (struct inotify_event *) &buf[cur_ind];
      if (pev->len < 0 || pev->len > 1024) {
        err("%s: ridiculuos len: %zu", __FUNCTION__, (size_t) pev->len);
        return;
      }
      if (cur_ind + sizeof(*pev) + pev->len > r) {
        init_offset = r - cur_ind;
        memmove(buf, buf + cur_ind, init_offset);
        cur_ind = 0;
        break;
      }
      cur_ind += sizeof(*pev) + pev->len;
      fprintf(stderr, "inotify: %d, %u, %u, %u, \"%s\"\n", pev->wd, pev->mask, pev->cookie,
              pev->len, pev->name);
      for (i = 0; i < extra_a; i++) {
        if ((cur = extras[i])
            && cur->run_used && !cur->run_suspended && cur->run_pid <= 0
            && cur->run_queue_dir && cur->run_wd == pev->wd) {
          cur->dnotify_flag = 1;
        }
      }
    }
  } while (r == sizeof(buf));
}

static void
start_run(struct contest_extra *cur, time_t current_time)
{
  int pid, j, null_fd = -1, log_fd = -1;
  unsigned char **args = NULL;

  cur->dnotify_flag = 0;
  cur->run_last_start = current_time;
  pid = fork();
  if (pid < 0) {
    err("contest %d run fork() failed: %s", cur->id, os_ErrorMsg());
    /* FIXME: recovery? */
    return;
  }

  if (pid > 0) {
    info("contest %d new run process %d", cur->id, pid);
    cur->run_pid = pid;
    return;
  }

  // this is child
  pid = getpid();

  // 1. close everything
  for (j = 0; j < extra_a; j++) {
    if (!extras[j]) continue;
    if (!extras[j]->run_used) continue;
  }
  close_all_client_sockets();
  random_cleanup();
  background_process_close_fds(&background_processes);

  // 2. switch uid and gid
  if (cur->run_uid >= 0 && self_uid != cur->run_uid && setuid(cur->run_uid) < 0) {
    err("contest %d [%d] setuid failed: %s", cur->id, pid, os_ErrorMsg());
    _exit(1);
  }
  if (cur->run_gid >= 0 && self_gid != cur->run_gid && setgid(cur->run_gid) < 0) {
    err("contest %d [%d] setgid failed: %s", cur->id, pid, os_ErrorMsg());
    _exit(1);
  }

  // 3. open /dev/null and log file
  if ((null_fd = open("/dev/null", O_RDONLY, 0)) < 0) {
    err("contest %d [%d] open(/dev/null) failed: %s", cur->id, pid, os_ErrorMsg());
    _exit(1);
  }
  if ((log_fd = open(cur->run_log_file, O_WRONLY | O_APPEND | O_CREAT, 0600)) < 0) {
    err("contest %d [%d] open(%s) failed: %s", cur->id, pid, cur->run_log_file, os_ErrorMsg());
    _exit(1);
  }

  // 4. setup file descriptors 0
  if (null_fd != 0) {
    dup2(null_fd, 0);
    close(null_fd);
  }

  // 5. change the current directory
  if (chdir(cur->root_dir) < 0) {
    err("contest %d [%d] chdir(%s) failed: %s", cur->id, pid, cur->root_dir, os_ErrorMsg());
    _exit(1);
  }

  // 6. setup new process group
  if (setpgid(pid, pid) < 0) {
    err("contest %d [%d] setpgid failed: %s", cur->id, pid, os_ErrorMsg());
    _exit(1);
  }

  // 7. setup argument vector
  args = (unsigned char **) alloca(4 * sizeof(args[0]));
  memset(args, 0, 4 * sizeof(args[0]));
  args[0] = config->run_path;
  args[1] = "-S";
  args[2] = cur->conf_file;

  // 8. clear procmask
  sigprocmask(SIG_SETMASK, &original_mask, 0);

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
  err("contest %d [%d] execve() failed: %s", cur->id, pid, os_ErrorMsg());
  _exit(1);
}

static int
do_loop(void)
{
  int i, n, status, pid;
  sigset_t block_mask, work_mask;
  struct contest_extra *cur;
  time_t current_time;
  struct client_state *cur_clnt;
  pollfds_t *pfds = pollfds_create();
  time_t last_scan_time = 0;
  int has_run_files = 0;
  int timeout_ms = 0;
  struct rusage usage;

  sigfillset(&block_mask);
  sigfillset(&work_mask);
  sigdelset(&work_mask, SIGTERM);
  sigdelset(&work_mask, SIGINT);
  sigdelset(&work_mask, SIGHUP);
  sigdelset(&work_mask, SIGCHLD);
  sigprocmask(SIG_SETMASK, &block_mask, 0);

  signal(SIGTERM, handler_term);
  signal(SIGINT, handler_term);
  signal(SIGHUP, handler_hup);
  signal(SIGCHLD, handler_child);

  while (1) {
    acquire_resources();

    while (1) {
      current_time = time(0);

      background_process_cleanup(&background_processes);

      if (sid_state_last_check_time < current_time + SID_STATE_CHECK_INTERVAL) {
        sid_state_cleanup();
        sid_state_last_check_time = current_time;
      }

      if (hup_flag || term_flag) break;

      pollfds_clear(pfds);

      if (run_inotify_fd < 0) {
        info("creating inotify file descriptor");
#if 0
        if ((run_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC)) < 0) {
          err("inotify_init1() failed: %s", os_ErrorMsg());
          return 1;
        }
#else
        if ((run_inotify_fd = inotify_init()) < 0) {
          err("inotify_init() failed: %s", os_ErrorMsg());
          return 1;
        }
        fcntl(run_inotify_fd, F_SETFL, fcntl(run_inotify_fd, F_GETFL) | O_NONBLOCK);
        fcntl(run_inotify_fd, F_SETFD, FD_CLOEXEC);
#endif
        for (i = 0; i < extra_a; i++) {
          if (!(cur = extras[i])) continue;
          if (!cur->run_used || !cur->run_queue_dir) continue;
          cur->run_wd = inotify_add_watch(run_inotify_fd, cur->run_queue_dir, IN_MOVED_TO);
          if (cur->run_wd < 0) {
            err("inotify_add_watch failed for %s: %s", cur->run_queue_dir, os_ErrorMsg());
            cur->run_wd = 0;
          }
        }
      }

      /* handle run suspend end */
      for (i = 0; i < extra_a; i++) {
        if (!(cur = extras[i])) continue;
        if (!cur->run_used || cur->run_pid >= 0 || !cur->run_suspended)
          continue;
        if (current_time > cur->run_suspend_end) {
          info("contest %d run suspend time is finished", cur->id);
          cur->run_suspended = 0;
          cur->run_suspend_end = 0;
        }
      }

      if (last_scan_time <= 0 || last_scan_time + SPOOL_DIR_CHECK_INTERVAL < current_time) {
        //info("full directory scan");
        for (i = 0; i < extra_a; i++) {
          if (!(cur = extras[i])) continue;
          if (!cur->run_used || cur->run_suspended || cur->run_pid > 0 || !cur->run_queue_dir) continue;
          if (get_number_of_files(cur->run_queue_dir) > 0) {
            cur->dnotify_flag = 1;
            has_run_files = 1;
          }
        }
        last_scan_time = current_time;
      }

      if (control_socket_fd >= 0) {
        pollfds_add(pfds, control_socket_fd, POLLIN, handle_control_accept, NULL);
      }
      if (run_inotify_fd >= 0) {
        pollfds_add(pfds, run_inotify_fd, POLLIN, handle_inotify_read, NULL);
      }

      for (cur_clnt = clients_first; cur_clnt; cur_clnt = cur_clnt->next) {
        if (cur_clnt->state == STATE_WRITE || cur_clnt->state == STATE_WRITECLOSE) {
          ASSERT(cur_clnt->fd >= 0);
          pollfds_add(pfds, cur_clnt->fd, POLLOUT, handle_client_write, cur_clnt);
        } else if (cur_clnt->state >= STATE_READ_CREDS && cur_clnt->state <= STATE_READ_DATA) {
          ASSERT(cur_clnt->fd >= 0);
          pollfds_add(pfds, cur_clnt->fd, POLLIN, handle_client_read, cur_clnt);
        }
      }

      background_process_append_pollfd(&background_processes, pfds);

      errno = 0;
      n = 0;
      timeout_ms = 10000;
      if (sigchld_flag || hup_flag || term_flag || has_run_files) {
        timeout_ms = 0;
      }
      n = pollfds_poll(pfds, timeout_ms, &work_mask);

      if (n < 0 && errno != EINTR) {
        err("unexpected select error: %s", os_ErrorMsg());
        continue;
      }

      current_time = time(0);

      if (sigchld_flag) {
        sigchld_flag = 0;
        while ((pid = wait4(-1, &status, WNOHANG, &usage)) > 0) {
          for (i = 0; i < extra_a; i++) {
            if (!(cur = extras[i])) continue;
            if (cur->run_used && cur->run_pid == pid) {
              if (WIFEXITED(status)) {
                info("contest %d run [%d] terminated with status %d",
                     cur->id, pid, WEXITSTATUS(status));
              } else if (WIFSIGNALED(status)) {
                err("contest %d run [%d] terminated with signal %d (%s)",
                    cur->id, pid, WTERMSIG(status),
                    os_GetSignalString(WTERMSIG(status)));
              } else {
                err("contest %d run unknown termination status", i);
              }

              cur->dnotify_flag = 0;
              if (get_number_of_files(cur->run_queue_dir) > 0) {
                cur->dnotify_flag = 1;
              }
              cur->run_pid = -1;
              break;
            }
          }
          if (i >= extra_a) {
            if (!background_process_handle_termination(&background_processes, pid, status, &usage)) {
              err("unregistered child %d terminated", pid);
              continue;
            }
          }
        }
      }

      if (hup_flag || term_flag) break;

      /*
      if (n <= 0) {
        // timeout expired or signal arrived
        continue;
      }
      */

      pollfds_call_handlers(pfds, NULL);

      for (i = 0; i < extra_a; i++) {
        if (!(cur = extras[i])) continue;
        if (!cur->run_used) continue;
        if (!cur->dnotify_flag) continue;
        if (cur->run_pid > 0) continue;
        if (cur->run_suspended) continue;
        if (current_time == cur->run_last_start) {
          err("contest %d run respawns too fast, disabling for %d seconds",
              cur->id, SUSPEND_TIMEOUT);
          cur->run_suspended = 1;
          cur->run_suspend_end = current_time + SUSPEND_TIMEOUT;
          continue;
        }
        start_run(cur, current_time);
      }

      background_process_check_finished(&background_processes);
      background_process_call_continuations(&background_processes);

      // execute ready commands from control connections
      for (cur_clnt = clients_first; cur_clnt; cur_clnt = cur_clnt->next) {
        if (cur_clnt->state == STATE_READ_READY) {
          handle_control_command(cur_clnt);
          ASSERT(cur_clnt->state != STATE_READ_READY);
        }
      }

      // disconnect file descriptors marked for disconnection
      for (cur_clnt = clients_first; cur_clnt; ) {
        if (cur_clnt->state == STATE_DISCONNECT) {
          struct client_state *tmp = cur_clnt->next;
          client_state_delete(cur_clnt);
          cur_clnt = tmp;
        } else {
          cur_clnt = cur_clnt->next;
        }
      }
    }

    if (term_flag) {
      info("got a termination signal");
    }
    release_resources();

    // we are here if either HUP or, TERM, or INT
    if (term_flag || hup_flag) break;
    //hup_flag = 0;
  }

  pfds = pollfds_free(pfds);
  return 0;
}

static int
prepare_sockets(void)
{
  struct sockaddr_un addr;
  pid_t pid;
  path_t socket_dir;

  if (!autonomous_mode) {
    // require super_serve_log and super_serve_socket to be specified
    if (!config->super_serve_log) {
      err("<super_serve_log> must be specified in daemon mode");
      return 1;
    }
    if (!config->super_serve_socket) {
      err("<super_serve_socket> must be specified in daemon mode");
      return 1;
    }

#if 0
    if ((run_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC)) < 0) {
      err("inotify_init1() failed: %s", os_ErrorMsg());
      return 1;
    }
#else
    if ((run_inotify_fd = inotify_init()) < 0) {
      err("inotify_init() failed: %s", os_ErrorMsg());
      return 1;
    }
    fcntl(run_inotify_fd, F_SETFL, fcntl(run_inotify_fd, F_GETFL) | O_NONBLOCK);
    fcntl(run_inotify_fd, F_SETFD, FD_CLOEXEC);
#endif

    // create a control socket
    if ((control_socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
      err("socket() failed: %s", os_ErrorMsg());
      return 1;
    }

    // create the socket directory
    os_rDirName(config->super_serve_socket, socket_dir, sizeof(socket_dir));
    os_MakeDirPath(socket_dir, 0775);
    if (os_IsFile(socket_dir) != OSPK_DIR) {
      err("%s is not a directory", socket_dir);
      return 1;
    }
      
    if (forced_mode) unlink(config->super_serve_socket);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, config->super_serve_socket, 108);
    addr.sun_path[107] = 0;
    if (bind(control_socket_fd, (struct sockaddr *) &addr, sizeof(addr))<0) {
      err("bind() failed: %s", os_ErrorMsg());
      return 1;
    }
    control_socket_path = config->super_serve_socket;

    if (listen(control_socket_fd, 5) < 0) {
      err("listen() failed: %s", os_ErrorMsg());
      return 1;
    }
    if (chmod(control_socket_path, 0777) < 0) {
      err("chmod() failed: %s", os_ErrorMsg());
      return 1;
    }
  }

  // daemonize itself
  if (daemon_mode) {
    if (start_open_log(config->super_serve_log) < 0)
      return 1;

    if ((pid = fork()) < 0) return 1;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return 1;
  } else if (restart_mode) {
    if (start_open_log(config->super_serve_log) < 0)
      return 1;
  }

  return 0;
}

static void
arg_expected(const unsigned char *progname)
{
  fprintf(stderr, "%s: invalid number of arguments\n", progname);
  exit(1);
}

static const unsigned char *program_name = 0;
static void write_help(void) __attribute__((noreturn));
static void
write_help(void)
{
  printf("%s: ejudge super server\n"
         "Usage: %s [OPTIONS] [EJUDGE-XML-PATH]\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "    -u USER   specify the user to run under\n"
         "    -g GROUP  specify the group to run under\n"
         "    -C DIR    specify the current directory\n"
         "    -D        daemon mode\n"
         "    -f        forced start mode\n"
         "    -s        slave mode\n"
         "    -r        serve all contests in slave mode\n"
         "    -m        master mode\n",
         program_name, program_name);
  exit(0);
}
static void write_version(void) __attribute__((noreturn));
static void
write_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
  exit(0);
}

int
main(int argc, char **argv)
{
  unsigned char *ejudge_xml_path = 0;
  int cur_arg = 1, j = 0;
  int retcode = 0;
  const unsigned char *user = 0, *group = 0, *workdir = 0;
  char **argv_restart = 0;
  int pid;

  program_name = os_GetBasename(argv[0]);
  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 2);
  argv_restart[j++] = argv[0];

  while (cur_arg < argc) {
    if (!strcmp(argv[cur_arg], "--help")) {
      write_help();
    } else if (!strcmp(argv[cur_arg], "--version")) {
      write_version();
    } else if (!strcmp(argv[cur_arg], "-D")) {
      daemon_mode = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-R")) {
      restart_mode = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-a")) {
      autonomous_mode = 1;
      argv_restart[j++] = argv[cur_arg];
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-f")) {
      forced_mode = 1;
      argv_restart[j++] = argv[cur_arg];
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-u")) {
      if (cur_arg + 1 >= argc) arg_expected(argv[0]);
      user = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-g")) {
      if (cur_arg + 1 >= argc) arg_expected(argv[0]);
      group = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-C")) {
      if (cur_arg + 1 >= argc) arg_expected(argv[0]);
      workdir = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-s")) {
      slave_mode = 1;
      argv_restart[j++] = argv[cur_arg];
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-r")) {
      manage_all_runs = 1;
      argv_restart[j++] = argv[cur_arg];
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-m")) {
      master_mode = 1;
      argv_restart[j++] = argv[cur_arg];
      cur_arg++;
    } else {
      break;
    }
  }
  argv_restart[j++] = "-R";
  if (cur_arg < argc) {
    ejudge_xml_path = argv[cur_arg];
    argv_restart[j++] = argv[cur_arg];
    cur_arg++;
  }
  if (cur_arg != argc) {
    fprintf(stderr, "%s: invalid number of arguments\n", argv[0]);
    return 1;
  }
  argv_restart[j] = 0;
  start_set_args(argv_restart);

  if (!(pid = start_find_process("ej-super-server", 0))) {
    forced_mode = 1;
  } else if (pid > 0) {
    fprintf(stderr, "%s: is already running as pid %d\n", argv[0], pid);
    return 1;
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) {
    info("using the default %s", EJUDGE_XML_PATH);
    ejudge_xml_path = EJUDGE_XML_PATH;
  }
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) {
    fprintf(stderr, "%s: configuration file is not specified\n", argv[0]);
    return 1;
  }

  if (start_prepare(user, group, workdir) < 0) return 1;

  info("ej-super-server %s, compiled %s", compile_version, compile_date);
  if (slave_mode) info("slave mode enabled");

  config = ejudge_cfg_parse(ejudge_xml_path);
  if (!config) return 1;
  if (!config->contests_dir) {
    err("<contests_dir> tag is not set!");
    return 1;
  }
  if (contests_set_directory(config->contests_dir) < 0) {
    err("contests directory is invalid");
    return 1;
  }
  if (config->run_path && config->run_path[0]
      && access(config->run_path, X_OK) < 0) {
    err("run_path '%s' is not executable", config->run_path);
    return 1;
  }
  if (random_init() < 0) {
    err("cannot initialize random number source");
    return 1;
  }

  snprintf(hostname, sizeof(hostname), "%s", os_NodeName());

  // FIXME: save all uids: real, effective, and saved?
  self_uid = getuid();

  // FIXME: save all gids: real, effective, and saved?
  self_group_max = sysconf(_SC_NGROUPS_MAX);
  if (self_group_max < 16) self_group_max = 16;
  self_group_max *= 2;
  XCALLOC(self_groups, self_group_max);
  self_gid = getgid();
  self_group_num = getgroups(self_group_max, self_groups);
  self_groups[self_group_num++] = self_gid;

  // save the original signal mask
  sigprocmask(SIG_SETMASK, 0, &original_mask);

  retcode = prepare_sockets();
  if (!retcode) retcode = do_loop();

  random_cleanup();
  if (control_socket_fd >= 0) close(control_socket_fd);
  if (control_socket_path) unlink(control_socket_path);
  if (run_inotify_fd >= 0) {
    close(run_inotify_fd);
    run_inotify_fd = -1;
  }

  if (hup_flag) start_restart();
  return retcode;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
