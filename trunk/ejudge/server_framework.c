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
#include "new_server_proto.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/fcntl.h>
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
  int client_id;

  struct client_state *clients_first;
  struct client_state *clients_last;

  void *user_data;
};

static struct client_state *
client_state_new(struct server_framework_state *state, int fd)
{
  struct client_state *p;

  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

  if (state->params->alloc_state)
    p = state->params->alloc_state(state);
  else {
    XCALLOC(p, 1);
  }

  p->id = state->client_id++;
  p->fd = fd;
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  p->state = STATE_READ_CREDS;

  if (!state->clients_first) {
    state->clients_first = state->clients_last = p;
  } else {
    p->next = state->clients_first;
    state->clients_first->prev = p;
    state->clients_first = p;
  }
  return p;
}

void
nsf_new_autoclose(struct server_framework_state *state,
                  struct client_state *p, void *write_buf,
                  size_t write_len)
{
  struct client_state *q;

  q = client_state_new(state, p->client_fds[0]);
  q->client_fds[1] = p->client_fds[1];
  q->write_buf = write_buf;
  q->write_len = write_len;
  q->state = STATE_WRITECLOSE;

  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
}

static void
client_state_delete(struct server_framework_state *state,
                    struct client_state *p)
{
  if (!p) return;

  if (p->next && p->prev) {
    // middle element
    p->prev->next = p->next;
    p->next->prev = p->prev;
  } else if (p->next) {
    // the first element
    state->clients_first = p->next;
    p->next->prev = 0;
  } else if (p->prev) {
    // the last element
    state->clients_last = p->prev;
    p->prev->next = 0;
  } else {
    // the only element
    state->clients_first = state->clients_last = 0;
  }

  fcntl(p->fd, F_SETFL, fcntl(p->fd, F_GETFL) & ~O_NONBLOCK);
  if (p->fd >= 0) close(p->fd);
  if (p->client_fds[0] >= 0) close(p->client_fds[0]);
  if (p->client_fds[1] >= 0) close(p->client_fds[1]);
  xfree(p->read_buf);
  xfree(p->write_buf);

  if (state->params->cleanup_client)
    state->params->cleanup_client(state, p);

  memset(p, -1, sizeof(*p));
  if (state->params->free_memory)
    state->params->free_memory(state, p);
  else
    xfree(p);
}

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

static void
accept_new_connection(struct server_framework_state *state)
{
  struct sockaddr_un addr;
  int fd, addrlen, val;

  memset(&addr, 0, sizeof(addr));
  addrlen = sizeof(addr);
  if ((fd = accept(state->socket_fd, (struct sockaddr*) &addr, &addrlen))<0){
    err("accept failed: %s", os_ErrorMsg());
    return;
  }

  val = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val)) < 0) {
    err("setsockopt() failed: %s", os_ErrorMsg());
    close(fd);
    return;
  }

  client_state_new(state, fd);
}

void
nsf_enqueue_reply(struct server_framework_state *state,
                  struct client_state *p, size_t len, void const *msg)
{
  ASSERT(!p->write_len);

  p->write_len = len + sizeof(len);
  p->write_buf = xmalloc(p->write_len);
  memcpy(p->write_buf, &len, sizeof(len));
  memcpy(p->write_buf + sizeof(len), msg, len);
  p->written = 0;
  p->state = STATE_WRITE;
}

void
nsf_send_reply(struct server_framework_state *state,
               struct client_state *p, int answer)
{
  struct new_server_prot_packet pkt;

  memset(&pkt, 0, sizeof(pkt));
  pkt.id = answer;
  pkt.magic = NEW_SERVER_PROT_PACKET_MAGIC;
  nsf_enqueue_reply(state, p, sizeof(pkt), &pkt);
}

void
nsf_err_protocol_error(struct server_framework_state *state,
                       struct client_state *p)
{
  err("%d: protocol error", p->id);
  nsf_send_reply(state, p, NEW_SRV_ERR_PROTOCOL_ERROR);
}

void
nsf_err_bad_packet_length(struct server_framework_state *state,
                          struct client_state *p, size_t len, size_t exp_len)
{
  err("%d: bad packet length: %zu, expected %zu", p->id, len, exp_len);
  p->state = STATE_DISCONNECT;
}

void
nsf_err_packet_too_small(struct server_framework_state *state,
                         struct client_state *p, size_t len, size_t min_len)
{
  err("%d: packet is too small: %zu, minimum %zu", p->id, len, min_len);
  p->state = STATE_DISCONNECT;
}

void
nsf_err_invalid_command(struct server_framework_state *state,
                        struct client_state *p, int id)
{
  err("%d: invalid protocol command: %d", p->id, id);
  p->state = STATE_DISCONNECT;
}

static void
cmd_pass_fd(struct server_framework_state *state,
            struct client_state *p,
            size_t len,
            const struct new_server_prot_packet *pkt)
{
  if (len != sizeof(*pkt))
    return nsf_err_bad_packet_length(state, p, len, sizeof(*pkt));

  if (p->client_fds[0] >= 0 || p->client_fds[1] >= 0) {
    err("%d: cannot stack unprocessed client descriptors", p->id);
    p->state = STATE_DISCONNECT;
    return;
  }

  p->state = STATE_READ_FDS;
}

static void
handle_control_command(struct server_framework_state *state,
                       struct client_state *p)
{
  struct new_server_prot_packet *pkt;

  if (p->read_len < sizeof(*pkt)) {
    err("%d: packet length is too small: %d", p->id, p->read_len);
    p->state = STATE_DISCONNECT;
    return;
  }
  pkt = (struct new_server_prot_packet*) p->read_buf;

  if (pkt->magic != NEW_SERVER_PROT_PACKET_MAGIC) {
    err("%d: invalid magic value: %04x", p->id, pkt->magic);
    p->state = STATE_DISCONNECT;
    return;
  }

  if (pkt->id <= 0) {
    err("%d: invalid protocol command: %d", p->id, pkt->id);
    p->state = STATE_DISCONNECT;
    return;
  }

  if (pkt->id == 1) cmd_pass_fd(state, p, p->read_len, pkt);
  if (state->params->handle_packet)
    state->params->handle_packet(state, p, p->read_len, pkt);

  if (p->state == STATE_READ_READY) p->state = STATE_READ_LEN;
  if (p->read_buf) xfree(p->read_buf);
  p->read_buf = 0;
  p->expected_len = 0;
  p->read_len = 0;
}

void
nsf_main_loop(struct server_framework_state *state)
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

      // check for new control connections
    if (state->socket_fd >= 0 && FD_ISSET(state->socket_fd, &rset)) {
      accept_new_connection(state);
    }

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

    // execute ready commands from control connections
    for (cur_clnt = state->clients_first; cur_clnt; cur_clnt = cur_clnt->next) {
      if (cur_clnt->state == STATE_READ_READY) {
        handle_control_command(state, cur_clnt);
        ASSERT(cur_clnt->state != STATE_READ_READY);
      }
    }

    // disconnect file descriptors marked for disconnection
    for (cur_clnt = state->clients_first; cur_clnt; ) {
      if (cur_clnt->state == STATE_DISCONNECT) {
        struct client_state *tmp = cur_clnt->next;
        client_state_delete(state, cur_clnt);
        cur_clnt = tmp;
      } else {
        cur_clnt = cur_clnt->next;
      }
    }
  }
}

int
nsf_prepare(struct server_framework_state *state)
{
  struct sockaddr_un addr;
  struct sigaction act;
  int log_fd, pid;
  unsigned char *log_path;

  if (getuid() == 0) {
    state->params->startup_error("sorry, will not run as the root");
  }

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

  memset(&act, 0, sizeof(act));
  act.sa_handler = sighup_handler;
  sigfillset(&act.sa_mask);
  sigaction(SIGHUP, &act, 0);

  act.sa_handler = sigint_handler;
  sigaction(SIGINT, &act, 0);
  sigaction(SIGTERM, &act, 0);

  act.sa_handler = sigchld_handler;
  sigaction(SIGCHLD, &act, 0);

  if (state->params->daemon_mode_flag) {
    log_path = state->params->log_path;
    if (!log_path) log_path = "/dev/null";
    if ((log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600)) < 0) {
      err("cannot open log file %s", log_path);
      goto cleanup;
    }
    close(0);
    if (open("/dev/null", O_RDONLY) < 0) return -1;
    close(1);
    if (open("/dev/null", O_WRONLY) < 0) return -1;
    close(2); dup(log_fd); close(log_fd);
    if ((pid = fork()) < 0) return -1;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return -1;
  }

  return 0;

 cleanup:
  unlink(state->params->socket_path);
  return -1;
}

void
nsf_cleanup(struct server_framework_state *state)
{
  if (state->socket_fd >= 0) close(state->socket_fd);
  unlink(state->params->socket_path);
}

struct server_framework_state *
nsf_init(struct server_framework_params *params, void *data)
{
  struct server_framework_state *state;

  XCALLOC(state, 1);
  state->params = params;
  state->user_data = data;
  state->client_id = 1;
  return state;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
