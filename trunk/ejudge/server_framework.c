/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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
#include "settings.h"
#include "ej_types.h"

#include "errlog.h"
#include "server_framework.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#define MAX_IN_PACKET_SIZE 134217728 /* 128 mb */

static volatile int sighup_flag = 0;
static volatile int sigint_flag = 0;
static volatile int sigchld_flag = 0;

static void
sighup_handler(int signo)
{
  sighup_flag = 1;
}
static void
sigint_handler(int signo)
{
  sigint_flag = 1;
}
static void
sigchld_handler(int signo)
{
  sigchld_flag = 1;
}

struct server_framework_state
{
  struct server_framework_params *params;

  int socket_fd;
  sigset_t orig_mask, work_mask, block_mask;

  struct client_state *clients_first;
  struct client_state *clients_last;
};

static void
read_from_control_connection(struct client_state *p)
{
  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct ucred *pcred;
  struct iovec recv_vec[1];
  int val, r, *fds, n;

  switch (p->state) {
  case STATE_READ_CREDS:
    // 4 zero bytes and credentials
    memset(&msg, 0, sizeof(msg));
    msg.msg_flags = 0;
    msg.msg_control = msgbuf;
    msg.msg_controllen = sizeof(msgbuf);
    recv_vec[0].iov_base = &val;
    recv_vec[0].iov_len = 4;
    msg.msg_iov = recv_vec;
    msg.msg_iovlen = 1;
    val = -1;

    if ((r = recvmsg(p->fd, &msg, 0)) < 0) {
      err("%d: recvmsg failed: %s", p->id, os_ErrorMsg());
      p->state = STATE_DISCONNECT;
      return;
    }
    if (r != 4) {
      err("%d: read %d bytes instead of 4", p->id, r);
      p->state = STATE_DISCONNECT;
      return;
    }
    if (val != 0) {
      err("%d: expected 4 zero bytes", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }
    if ((msg.msg_flags & MSG_CTRUNC)) {
      err("%d: protocol error: control buffer too small", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }
    pmsg = CMSG_FIRSTHDR(&msg);
    if (!pmsg) {
      err("%d: empty control data", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }
    if (pmsg->cmsg_level != SOL_SOCKET || pmsg->cmsg_type != SCM_CREDENTIALS
        || pmsg->cmsg_len != CMSG_LEN(sizeof(*pcred))) {
      err("%d: protocol error: unexpected control data", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }
    pcred = (struct ucred*) CMSG_DATA(pmsg);
    p->peer_pid = pcred->pid;
    p->peer_uid = pcred->uid;
    p->peer_gid = pcred->gid;
    if (CMSG_NXTHDR(&msg, pmsg)) {
      err("%d: protocol error: unexpected control data", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }

    p->state = STATE_READ_LEN;
    break;

  case STATE_READ_FDS:
    // we expect 4 zero bytes and 1 or 2 file descriptors
    memset(&msg, 0, sizeof(msg));
    msg.msg_flags = 0;
    msg.msg_control = msgbuf;
    msg.msg_controllen = sizeof(msgbuf);
    recv_vec[0].iov_base = &val;
    recv_vec[0].iov_len = 4;
    msg.msg_iov = recv_vec;
    msg.msg_iovlen = 1;
    val = -1;

    if ((r = recvmsg(p->fd, &msg, 0)) < 0) {
      err("%d: recvmsg failed: %s", p->id, os_ErrorMsg());
      p->state = STATE_DISCONNECT;
      return;
    }
    if (r != 4) {
      err("%d: read %d bytes instead of 4", p->id, r);
      p->state = STATE_DISCONNECT;
      return;
    }
    if (val != 0) {
      err("%d: expected 4 zero bytes", p->id);
      p->state = STATE_DISCONNECT;
      return;
     }
    if ((msg.msg_flags & MSG_CTRUNC)) {
      err("%d: protocol error: control buffer too small", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }

    pmsg = CMSG_FIRSTHDR(&msg);
    while (1) {
      if (!pmsg) break;
      if (pmsg->cmsg_level == SOL_SOCKET && pmsg->cmsg_type == SCM_RIGHTS)
        break;
      pmsg = CMSG_NXTHDR(&msg, pmsg);
    }
    if (!pmsg) {
      err("%d: empty control data", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }

    fds = (int*) CMSG_DATA(pmsg);
    if (pmsg->cmsg_len == CMSG_LEN(2 * sizeof(int))) {
      info("%d: received 2 file descriptors: %d, %d", p->id, fds[0], fds[1]);
      p->client_fds[0] = fds[0];
      p->client_fds[1] = fds[1];
    } else if (pmsg->cmsg_len == CMSG_LEN(1 * sizeof(int))) {
      info("%d: received 1 file descriptor: %d", p->id, fds[0]);
      p->client_fds[0] = fds[0];
      p->client_fds[1] = -1;
    } else {
      err("%d: invalid number of file descriptors passed", p->id);
      p->state = STATE_DISCONNECT;
      return;
    }

    if (CMSG_NXTHDR(&msg, pmsg)) {
      err("%d: protocol error: unexpected control data", p->id);
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

void
server_framework_main_loop(struct server_framework_state *state)
{
  struct client_state *cur_clnt;
  struct timeval timeout;
  int fd_max, n, errcode;
  fd_set rset, wset;

  while (1) {
    fd_max = -1;
    FD_ZERO(&rset);
    FD_ZERO(&wset);

    if (state->socket_fd >= 0) {
      FD_SET(state->socket_fd, &rset);
      if (state->socket_fd > fd_max) fd_max = state->socket_fd;
    }

    for (cur_clnt = state->clients_first; cur_clnt; cur_clnt = cur_clnt->next) {
      if (cur_clnt->state==STATE_WRITE || cur_clnt->state==STATE_WRITECLOSE) {
        FD_SET(cur_clnt->fd, &wset);
        if (cur_clnt->fd > fd_max) fd_max = cur_clnt->fd;
      } else if (cur_clnt->state >= STATE_READ_CREDS
                 && cur_clnt->state <= STATE_READ_DATA) {
        FD_SET(cur_clnt->fd, &rset);
        if (cur_clnt->fd > fd_max) fd_max = cur_clnt->fd;
      }
    }

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    // here's a potential race condition :-(
    // it cannot be handled properly until Linux
    // has the proper pselect implementation
    sigprocmask(SIG_SETMASK, &state->work_mask, 0);
    errno = 0;
    n = select(fd_max + 1, &rset, &wset, 0, &timeout);
    errcode = errno;
    sigprocmask(SIG_SETMASK, &state->block_mask, 0);
    errno = errcode;
    // end of race condition prone code

    if (n < 0 && errno != EINTR) {
      err("unexpected select error: %s", os_ErrorMsg());
      continue;
    }

    // FIXME: check for signal events

    if (n <= 0) continue;

    // read from/write to control sockets
    for (cur_clnt = state->clients_first; cur_clnt; cur_clnt = cur_clnt->next) {
      switch (cur_clnt->state) {
      case STATE_READ_CREDS:
      case STATE_READ_FDS:
      case STATE_READ_LEN:
      case STATE_READ_DATA:
        if (FD_ISSET(cur_clnt->fd, &rset))
          read_from_control_connection(cur_clnt);
        break;
      case STATE_WRITE:
      case STATE_WRITECLOSE:
        if (FD_ISSET(cur_clnt->fd, &wset))
          write_to_control_connection(cur_clnt);
        break;
      }
    }

  }
}

void
server_framework_prepare(struct server_framework_state *state)
{
  struct sockaddr_un addr;

  if (state->params->force_socket_flag) {
    errno = 0;
    if (unlink(state->params->socket_path) < 0 && errno != ENOENT)
      state->params->startup_error("cannot remove stale socket file");
  }

  // create a control socket
  if ((state->socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
    state->params->startup_error("socket() failed: %s", os_ErrorMsg());

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(state->params->socket_path) >= sizeof(addr.sun_path))
    state->params->startup_error("socket path is too long");
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
           state->params->socket_path);
  if (bind(state->socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    state->params->startup_error("bind() failed: %s", os_ErrorMsg());

  if (listen(state->socket_fd, 5) < 0)
    state->params->startup_error("listen() failed: %s", os_ErrorMsg());
  if (chmod(state->params->socket_path, 0777) < 0)
    state->params->startup_error("chmod() failed: %s", os_ErrorMsg());

  sigprocmask(SIG_SETMASK, 0, &state->orig_mask);
  sigfillset(&state->block_mask);
  sigfillset(&state->work_mask);
  sigdelset(&state->work_mask, SIGTERM);
  sigdelset(&state->work_mask, SIGINT);
  sigdelset(&state->work_mask, SIGHUP);
  sigdelset(&state->work_mask, SIGCHLD);

  // FIXME: go daemon
}

void
server_framework_cleanup(struct server_framework_state *state)
{
  if (state->socket_fd >= 0) close(state->socket_fd);
  unlink(state->params->socket_path);
}

struct server_framework_state *
server_framework_init(struct server_framework_params *params,
                      void *data)
{
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
