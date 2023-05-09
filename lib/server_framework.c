/* -*- mode: c -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/errlog.h"
#include "ejudge/server_framework.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/sock_op.h"
#include "ejudge/startstop.h"
#include "ejudge/sha.h"
#include "ejudge/base64.h"
#include "ejudge/websocket.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/metrics_contest.h"

#include <stdio.h>
#include <string.h>
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
#include <netinet/ip.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/inotify.h>

#define MAX_IN_PACKET_SIZE 134217728 /* 128 mb */

static volatile int sighup_flag = 0;
static volatile int sigint_flag = 0;
static volatile int sigchld_flag = 0;
static volatile int sigusr1_flag = 0;

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
static void
sigusr1_handler(int signo)
{
  sigusr1_flag = 1;
}

struct watchlist
{
  struct watchlist *next, *prev;
  int pending_removal;
  struct server_framework_watch w;
};

struct directory_watch
{
  struct directory_watch *next, *prev;
  const struct ejudge_cfg *config;
  unsigned char *dir;
  unsigned char *dir_dir;
  unsigned char *dir_out;
  unsigned char *data_dir;
  unsigned char *data2_dir;
  void *user;
  void (*callback)(
        const struct ejudge_cfg *config,
        struct server_framework_state *state,
        const unsigned char *dir,
        const unsigned char *dir_dir,
        const unsigned char *dir_out,
        const unsigned char *data_dir,
        const unsigned char *data2_dir,
        void *user);

  int wd; // watch descriptor from inotify_add_watch
  int ready;
};

struct server_framework_state
{
  struct server_framework_params *params;

  int socket_fd;
  sigset_t orig_mask, work_mask, block_mask;
  //int client_id;
  int restart_requested;

  // websocket file descriptor
  int ws_fd;

  // inotify file descriptor
  int ifd;

  time_t server_start_time;

  struct ht_client_state *clients_first;
  struct ht_client_state *clients_last;

  struct watchlist *w_first, *w_last;

  struct server_framework_job *job_first, *job_last;
  int job_count, job_serial;

  void *user_data;

  struct ws_client_state *ws_first;
  struct ws_client_state *ws_last;

  struct directory_watch *dw_first;
  struct directory_watch *dw_last;
};

static int
nsf_get_peer_uid(const struct client_state *p);
static int
nsf_get_contest_id(const struct client_state *p);
static void
nsf_set_destroy_callback(
        struct client_state *p,
        int cnts_id,
        void (*destroy_callback)(struct client_state*));

static const struct client_state_operations http_client_state_operations =
{
  NULL, // destroy
  nsf_get_peer_uid, // get_peer_uid
  nsf_get_contest_id, // get_contest_id
  NULL, // get_ssl_flag
  NULL, // get_host
  NULL, // get_remote_addr
  nsf_set_destroy_callback, // set_destroy_callback
  NULL, // get_reply_id
  NULL, // get_client_auth
  NULL, // set_client_auth
};

static struct ht_client_state *
client_state_new(struct server_framework_state *state, int fd)
{
  struct ht_client_state *p;

  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

  if (state->params->alloc_state)
    p = state->params->alloc_state(state);
  else {
    XCALLOC(p, 1);
  }

  p->b.ops = &http_client_state_operations;
  //p->b.id = state->client_id++;
  p->b.id = metrics.data->client_serial++;
  p->b.fd = fd;
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  p->state = STATE_READ_CREDS;

  if (!state->clients_first) {
    state->clients_first = state->clients_last = p;
  } else {
    p->b.next = (struct client_state *) state->clients_first;
    state->clients_first->b.prev = (struct client_state*) p;
    state->clients_first = p;
  }
  return p;
}

static int
ws_client_get_ssl_flag(const struct client_state *p);
static const unsigned char *
ws_client_get_host(const struct client_state *p);
static const unsigned char *
ws_client_get_remote_addr(const struct client_state *p);
static int
ws_client_get_reply_id(struct client_state *p);
static const struct client_auth *
ws_client_get_client_auth(const struct client_state *p);
static void
ws_client_set_client_auth(struct client_state *, struct client_auth *);

static const struct client_state_operations ws_client_state_operations =
{
  NULL, // destroy
  NULL, // get_peer_uid
  NULL, // get_contest_id
  ws_client_get_ssl_flag, // get_ssl_flag
  ws_client_get_host, // get_host
  ws_client_get_remote_addr, // get_remote_addr
  NULL, // set_destroy_callback
  ws_client_get_reply_id, // get_reply_id
  ws_client_get_client_auth, // get_client_auth
  ws_client_set_client_auth, // set_client_auth
};

static struct ws_client_state *
ws_client_state_new(
        struct server_framework_state *state,
        int fd,
        const unsigned char *remote_addr,
        int remote_port,
        int ssl_flag)
{
  struct ws_client_state *p;

  int old = fcntl(fd, F_GETFL);
  if (old < 0) {
    err("fcntl failed: %s", os_ErrorMsg());
    return NULL;
  }
  if (fcntl(fd, F_SETFL, old | O_NONBLOCK) < 0) {
    err("fcntl failed: %s", os_ErrorMsg());
    return NULL;
  }

  if (state->params->ws_alloc_state) {
    if (!(p = state->params->ws_alloc_state(state))) {
      return NULL;
    }
  } else {
    if (!(p = calloc(1, sizeof(*p)))) {
      err("calloc: out of memory");
      return NULL;
    }
  }

  p->b.ops = &ws_client_state_operations;
  //p->b.id = state->client_id++;
  p->b.id = metrics.data->client_serial++;
  p->b.fd = fd;
  p->state = WS_STATE_INITIAL;
  if (remote_addr) p->remote_addr = xstrdup(remote_addr);
  p->remote_port = remote_port;
  p->ssl_flag = ssl_flag;

  p->b.prev = (struct client_state *) state->ws_last;
  if (p->b.prev) {
    p->b.prev->next = (struct client_state *) p;
  } else {
    state->ws_first = p;
  }
  state->ws_last = p;
  return p;
}

void
nsf_new_autoclose(struct server_framework_state *state,
                  struct client_state *p, void *write_buf,
                  size_t write_len)
{
  struct ht_client_state *pp = (struct ht_client_state*) p;
  struct ht_client_state *q;

  q = client_state_new(state, pp->client_fds[0]);
  q->client_fds[1] = pp->client_fds[1];
  q->write_buf = write_buf;
  q->write_len = write_len;
  q->state = STATE_WRITECLOSE;

  pp->client_fds[0] = -1;
  pp->client_fds[1] = -1;
}

void
nsf_close_client_fds(struct client_state *p)
{
  if (!p) return;
  struct ht_client_state *pp = (struct ht_client_state*) p;

  if (pp->client_fds[0] >= 0) close(pp->client_fds[0]);
  if (pp->client_fds[1] >= 0) close(pp->client_fds[1]);
  pp->client_fds[0] = -1;
  pp->client_fds[1] = -1;
}

struct client_state *
nsf_get_client_by_id(struct server_framework_state *state, int id)
{
  struct client_state *p;

  for (p = (struct client_state*) state->clients_first; p; p = p->next)
    if (p->id == id)
      return p;
  return 0;
}

static int
nsf_get_contest_id(const struct client_state *p)
{
  const struct ht_client_state *pp = (const struct ht_client_state*) p;
  return pp->contest_id;
}

void
nsf_set_destroy_callback(
        struct client_state *p,
        int cnts_id,
        void (*destroy_callback)(struct client_state*))
{
  struct ht_client_state *pp = (struct ht_client_state *) p;
  pp->contest_id = cnts_id;
  pp->destroy_callback = destroy_callback;
}

static int
nsf_get_peer_uid(const struct client_state *p)
{
  const struct ht_client_state *pp = (const struct ht_client_state*) p;
  return pp->peer_uid;
}

static void
client_state_delete(
        struct server_framework_state *state,
        struct client_state *p)
{
  if (!p) return;
  struct ht_client_state *pp = (struct ht_client_state*) p;

  if (pp->contest_id > 0) {
    if (pp->destroy_callback) (*pp->destroy_callback)(p);
    pp->contest_id = 0;
    pp->destroy_callback = 0;
  }

  if (p->next && p->prev) {
    // middle element
    p->prev->next = p->next;
    p->next->prev = p->prev;
  } else if (p->next) {
    // the first element
    state->clients_first = (struct ht_client_state*) p->next;
    p->next->prev = 0;
  } else if (p->prev) {
    // the last element
    state->clients_last = (struct ht_client_state *) p->prev;
    p->prev->next = 0;
  } else {
    // the only element
    state->clients_first = state->clients_last = 0;
  }

  fcntl(p->fd, F_SETFL, fcntl(p->fd, F_GETFL) & ~O_NONBLOCK);
  if (p->fd >= 0) close(p->fd);
  if (pp->client_fds[0] >= 0) close(pp->client_fds[0]);
  if (pp->client_fds[1] >= 0) close(pp->client_fds[1]);
  xfree(pp->read_buf);
  xfree(pp->write_buf);

  if (state->params->cleanup_client)
    state->params->cleanup_client(state, p);

  memset(pp, -1, sizeof(*pp));
  if (state->params->free_memory)
    state->params->free_memory(state, p);
  else
    xfree(p);
}

static void
ws_frame_free(struct ws_frame *wsf)
{
  if (wsf) {
    free(wsf->data);
    free(wsf);
  }
}

void
nsf_client_auth_free(struct client_auth *ca)
{
  if (ca) {
    free(ca->login);
    free(ca->name);
    free(ca);
  }
}

static void
ws_client_state_free(struct ws_client_state *p)
{
  if (p) {
    struct ws_frame *wsp, *wsq;
    for (wsp = p->frame_first; wsp; wsp = wsq) {
      wsq = wsp->next;
      ws_frame_free(wsp);
    }

    free(p->uri);
    free(p->host);
    free(p->user_agent);
    free(p->accept_encoding);
    free(p->origin);
    free(p->remote_addr);
    free(p->read_buf);
    free(p->write_buf);
    if (p->b.fd >= 0) close(p->b.fd);
    nsf_client_auth_free(p->auth);
    memset(p, -1, sizeof(*p));
    free(p);
  }
}

static void
ws_client_state_delete(
        struct server_framework_state *state,
        struct ws_client_state *p)
{
  if (p) {
    if (p->b.prev) {
      p->b.prev->next = p->b.next;
    } else {
      state->ws_first = (struct ws_client_state *) p->b.next;
    }
    if (p->b.next) {
      p->b.next->prev = p->b.prev;
    } else {
      state->ws_last = (struct ws_client_state *) p->b.prev;
    }
    ws_client_state_free(p);
  }
}

int
nsf_add_watch(struct server_framework_state *state,
              struct server_framework_watch *w)
{
  struct watchlist *p;

  for (p = state->w_first; p; p = p->next) {
    if (!p->pending_removal && p->w.fd == w->fd)
      return -1;
  }

  XCALLOC(p, 1);
  p->w = *w;
  if (!state->w_last) {
    state->w_first = state->w_last = p;
  } else {
    p->prev = state->w_last;
    state->w_last->next = p;
    state->w_last = p;
  }
  return 0;
}
int
nsf_remove_watch(struct server_framework_state *state, int fd)
{
  struct watchlist *p;

  for (p = state->w_first; p; p = p->next) {
    if (!p->pending_removal && p->w.fd == fd) {
      p->pending_removal = 1;
      return 1;
    }
  }
  return 0;
}
void
remove_pending_watches(struct server_framework_state *state)
{
  struct watchlist *p, *q;

  for (p = state->w_first; p; p = q) {
    q = p->next;
    if (p->pending_removal) {
      if (p->prev) {
        p->prev->next = p->next;
      } else {
        state->w_first = p->next;
      }
      if (p->next) {
        p->next->prev = p->prev;
      } else {
        state->w_last = p->prev;
      }
      xfree(p);
    }
  }
}

static void
read_from_control_connection(struct ht_client_state *p)
{
  int r, n;

  switch (p->state) {
  case STATE_READ_CREDS:
    if (sock_op_get_creds(p->b.fd, p->b.id, &p->peer_pid, &p->peer_uid,
                          &p->peer_gid) < 0) {
      p->state = STATE_DISCONNECT;
      return;
    }

    p->state = STATE_READ_LEN;
    break;

  case STATE_READ_FDS:
    if (sock_op_get_fds(p->b.fd, p->b.id, p->client_fds) < 0) {
      p->state = STATE_DISCONNECT;
      return;
    }
    p->state = STATE_READ_LEN;
    break;

  case STATE_READ_LEN:
    /* read the packet length */
    if ((r = read(p->b.fd, &p->expected_len, sizeof(p->expected_len))) < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        info("%d: descriptor not ready", p->b.id);
        return;
      }
      err("%d: read failed: %s", p->b.id, os_ErrorMsg());
      p->state = STATE_DISCONNECT;
      return;
    }
    if (!r) {
      // EOF from client
      p->state = STATE_DISCONNECT;
      return;
    }
    if (r != 4) {
      err("%d: expected 4 bytes of packet length", p->b.id);
      p->state = STATE_DISCONNECT;
      return;
    }
    if (p->expected_len <= 0 || p->expected_len > MAX_IN_PACKET_SIZE) {
      err("%d: bad packet length %d", p->b.id, p->expected_len);
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
    if ((r = read(p->b.fd, p->read_buf + p->read_len, n)) < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        info("%d: descriptor not ready", p->b.id);
        return;
      }
      err("%d: read failed: %s", p->b.id, os_ErrorMsg());
      p->state = STATE_DISCONNECT;
      return;
    }
    if (!r) {
      err("%d: unexpected EOF", p->b.id);
      p->state = STATE_DISCONNECT;
      return;
    }
    p->read_len += r;
    if (p->read_len == p->expected_len) p->state = STATE_READ_READY;
    break;

  default:
    err("%d: invalid read state %d", p->b.id, p->state);
    abort();
  }
}

static void
write_to_control_connection(struct ht_client_state *p)
{
  int n, r;

  switch (p->state) {
  case STATE_WRITE:
  case STATE_WRITECLOSE:
    ASSERT(p->write_len > 0);
    ASSERT(p->written >= 0);
    ASSERT(p->written < p->write_len);
    n = p->write_len - p->written;
    if ((r = write(p->b.fd, p->write_buf + p->written, n)) <= 0) {
      if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
        info("%d: descriptor not ready", p->b.id);
        return;
      }
      err("%d: write error: %s", p->b.id, os_ErrorMsg());
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
    err("%d: invalid write state %d", p->b.id, p->state);
    abort();
  }
}

static void
accept_new_connection(struct server_framework_state *state)
{
  struct sockaddr_un addr;
  int fd, addrlen;

  memset(&addr, 0, sizeof(addr));
  addrlen = sizeof(addr);
  if ((fd = accept(state->socket_fd, (struct sockaddr*) &addr, &addrlen))<0){
    err("accept failed: %s", os_ErrorMsg());
    return;
  }

  if (sock_op_enable_creds(fd) < 0) {
    close(fd);
    return;
  }

  client_state_new(state, fd);
}

static void
accept_new_ws_connections(struct server_framework_state *state)
{
  struct sockaddr_in clnt_addr;
  socklen_t addr_len;
  int fd;
  unsigned char addrstr[256];

  while (1) {
    addr_len = sizeof(clnt_addr);
    fd = accept(state->ws_fd, (void*) &clnt_addr, &addr_len);
    if (fd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      break;
    }
    if (fd < 0) {
      err("accept failed: %s", os_ErrorMsg());
      break;
    }
    ASSERT(addr_len == sizeof(clnt_addr));

    inet_ntop(AF_INET, &clnt_addr.sin_addr, addrstr, sizeof(addrstr));
    struct ws_client_state *wcs = ws_client_state_new(state, fd, addrstr, ntohs(clnt_addr.sin_port), 0);
    wcs->state = WS_STATE_INITIAL;
  }
}

int
nsf_ws_append_reply_raw(
        struct ws_client_state *p,
        const unsigned char *buf,
        int size)
{
  if (p->out_close_state > 0) return 0;

  if (p->write_size + size > p->write_reserved) {
    int new_reserved = p->write_reserved;
    if (!new_reserved) new_reserved = 256;
    while (p->write_size + size > new_reserved) new_reserved *= 2;
    if (new_reserved >= 128 * 1024 * 1024) {
      // FIXME: drop the data, report missing packet
      return 0;
    }
    unsigned char *new_buf = realloc(p->write_buf, new_reserved);
    if (!new_buf) {
      // FIXME: drop the data, report missing packet
      return 0;
    }
    p->write_reserved = new_reserved;
    p->write_buf = new_buf;
  }
  memcpy(p->write_buf + p->write_size, buf, size);
  p->write_size += size;
  return 1;
}

static int
append_ws_http_error(
        struct ws_client_state *p,
        const char *text)
{
  if (text && *text) {
    int res = nsf_ws_append_reply_raw(p, text, strlen(text));
    p->state = WS_STATE_HTTP_ERROR;
    return res;
  }
  return 0;
}

void
nsf_ws_append_close_request(
        struct ws_client_state *p,
        int error_code)
{
  if (p->out_close_state > 0) return;

  if (error_code > 0) {
    unsigned char close_pkt[4] = { 0x88, 0x02, error_code >> 8, error_code };
    nsf_ws_append_reply_raw(p, close_pkt, sizeof(close_pkt));
    p->out_close_state = 1;
  } else {
    unsigned char close_pkt[2] = { 0x88, 0x00 };
    nsf_ws_append_reply_raw(p, close_pkt, sizeof(close_pkt));
    p->out_close_state = 1;
  }
}

int
nsf_ws_append_reply_frame(
        struct ws_client_state *p,
        int opcode,
        const unsigned char *data,
        int size)
{
  if (p->out_close_state > 0) return 0;

  ASSERT(size >= 0);
  ASSERT(size < 128 * 1024 * 1024);

  if (!opcode) opcode = WS_FRAME_TEXT;
  unsigned int wire_size = size + 2;
  if (size >= 65536) {
    wire_size += 8;
  } else if (size >= 126) {
    wire_size += 2;
  }
  if (p->write_size + wire_size > p->write_reserved) {
    int new_size = p->write_reserved;
    if (!new_size) new_size = 256;
    while (p->write_size + wire_size > new_size) new_size *= 2;
    if (new_size >= 128 * 1024 * 1024) {
      // FIXME: drop the data, report missing packet
      return 0;
    }
    unsigned char *new_buf = realloc(p->write_buf, new_size);
    if (!new_buf) {
      // FIXME: drop the data, report missing packet
      return 0;
    }
    p->write_reserved = new_size;
    p->write_buf = new_buf;
  }

  // we never mask data and never fragment
  unsigned char *out_ptr = p->write_buf + p->write_size;
  *out_ptr++ = 0x80 | (opcode & 0x0f);
  if (size < 126) {
    *out_ptr++ = size;
  } else if (size < 65536) {
    *out_ptr++ = 126;
    *out_ptr++ = size >> 8;
    *out_ptr++ = size;
  } else {
    *out_ptr++ = 127;
    // the high 32 bits are 0
    *out_ptr++ = 0;
    *out_ptr++ = 0;
    *out_ptr++ = 0;
    *out_ptr++ = 0;
    *out_ptr++ = size >> 24;
    *out_ptr++ = size >> 16;
    *out_ptr++ = size >> 8;
    *out_ptr++ = size;
  }
  memcpy(out_ptr, data, size);
  p->write_size += wire_size;
  return 1;
}

static void
append_ws_bad_request(struct ws_client_state *p)
{
  append_ws_http_error(p, "HTTP/1.1 400 Bad Request\r\n\r\n");
}

static struct ws_frame *
append_new_ws_frame(struct ws_client_state *p)
{
  struct ws_frame *wsf = calloc(1, sizeof(*wsf));
  if (!wsf) return NULL;

  wsf->data = p->read_buf;
  wsf->size = p->read_size;
  wsf->hdr[0] = p->hdr_buf[0];
  wsf->hdr[1] = p->hdr_buf[1];
  p->read_buf = NULL;
  p->read_size = 0;
  p->read_expected = 0;
  p->read_reserved = 0;
  p->hdr_flag = 0;
  p->hdr_expected = 0;
  p->hdr_size = 0;
  wsf->prev = p->frame_last;
  if (!p->frame_last) {
    p->frame_first = wsf;
  } else {
    p->frame_last->next = wsf;
  }
  p->frame_last = wsf;
  return wsf;
}

static void
read_ws_connection(
        struct server_framework_state *state,
        struct ws_client_state *p,
        long long current_time_us)
{
  unsigned char buf[4096];

  if (p->state == WS_STATE_INITIAL) {
    while (1) {
      int r = read(p->b.fd, buf, sizeof(buf));
      if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        // no more data
        break;
      } else if (r < 0) {
        err("read error: %s", os_ErrorMsg());
        append_ws_bad_request(p);
        return;
      } else if (!r) {
        p->in_close_state = 2;
        break;
      } else {
        p->last_read_time_us = current_time_us;
        if (p->read_size + r + 1 > p->read_reserved) {
          int new_reserved = p->read_reserved;
          if (!new_reserved) new_reserved = 1024;
          while (p->read_size + r + 1 > new_reserved) {
            new_reserved *= 2;
          }
          if (new_reserved > 128 * 1024) {
            err("read size exceeds the limit");
            append_ws_bad_request(p);
            return;
          }
          unsigned char *new_ptr = realloc(p->read_buf, new_reserved);
          if (!new_ptr) {
            err("of out memory");
            append_ws_bad_request(p);
            return;
          }
          p->read_reserved = new_reserved;
          p->read_buf = new_ptr;
        }
        memcpy(p->read_buf + p->read_size, buf, r);
        p->read_size += r;
        p->read_buf[p->read_size] = 0;
      }
    }
    int len = strlen(p->read_buf);
    if (len != p->read_size) {
      err("zero byte in WS handshake");
      append_ws_bad_request(p);
      return;
    }
    unsigned char *curc = p->read_buf;
    unsigned char *endp = NULL;
    for (; *curc; ++curc) {
      if (curc[0] == '\n' && curc[1] == '\n') {
        endp = curc + 2;
        break;
      } else if (curc[0] == '\r' && curc[1] == '\n' && curc[2] == '\r' && curc[3] == '\n') {
        endp = curc + 4;
        break;
      }
    }
    if (!endp) {
      // incomplete header, wait for the rest
      return;
    }
    if (*endp) {
      err("garbage after HTTP header");
      append_ws_bad_request(p);
      return;
    }
    fprintf(stderr, "%d,%d:<%s>", p->read_size, p->in_close_state, p->read_buf);

    // parse http header
    const unsigned char *get_uri = NULL;
    const unsigned char *host = NULL;
    const unsigned char *user_agent = NULL;
    const unsigned char *accept_encoding = NULL;
    const unsigned char *sec_websocket_version = NULL;
    const unsigned char *origin = NULL;
    const unsigned char *sec_websocket_extensions = NULL;
    const unsigned char *sec_websocket_key = NULL;
    const unsigned char *connection = NULL;
    const unsigned char *upgrade = NULL;
    const unsigned char *x_forwarded_for = NULL;
    const unsigned char *x_forwarded_host = NULL;

    /*
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,* / *;q=0.8
Accept-Language: en-US,en;q=0.5

Sec-WebSocket-Key: 4LadtICuEqMWoi50H+8+Ug==
Connection: keep-alive, Upgrade
Pragma: no-cache
Cache-Control: no-cache
Upgrade: websocket
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: localhost
X-Forwarded-Server: localhost.localdomain
     */

    curc = p->read_buf;
    while (*curc) {
      unsigned char *nextl;
      nextl = endp = strchr(curc, '\n');
      if (!endp) break;
      while (endp > curc && isspace(endp[-1])) --endp;
      *endp = 0;

      if (*curc) {
        fprintf(stderr, ">>%s<<\n", curc);
        if (!strncasecmp(curc, "GET ", 3)) {
          if (get_uri) {
            err("duplicate GET request");
            append_ws_bad_request(p);
            return;
          }
          unsigned char *pc = curc + 3;
          while (isspace(*pc)) ++pc;
          if (!*pc) {
            err("empty GET request");
            append_ws_bad_request(p);
            return;
          }
          get_uri = pc;
          while (*pc && !isspace(*pc)) ++pc;
          *pc = 0;
        } else {
          const unsigned char *par_name = curc;
          unsigned char *pc = curc;
          while (*pc && *pc != ':' && !isspace(*pc)) ++pc;
          unsigned char *endc = pc;
          while (isspace(*pc)) ++pc;
          if (*pc != ':') {
            err("':' expected");
            append_ws_bad_request(p);
            return;
          }
          *endc = 0;
          ++pc;
          while (isspace(*pc)) ++pc;
          const unsigned char *par_value = pc;

          if (!strcasecmp(par_name, "host")) {
            host = par_value;
          } else if (!strcasecmp(par_name, "user-agent")) {
            user_agent = par_value;
          } else if (!strcasecmp(par_name, "accept-encoding")) {
            accept_encoding = par_value;
          } else if (!strcasecmp(par_name, "sec-websocket-version")) {
            sec_websocket_version = par_value;
          } else if (!strcasecmp(par_name, "origin")) {
            origin = par_value;
          } else if (!strcasecmp(par_name, "sec-websocket-extensions")) {
            sec_websocket_extensions = par_value;
          } else if (!strcasecmp(par_name, "sec-websocket-key")) {
            sec_websocket_key = par_value;
          } else if (!strcasecmp(par_name, "connection")) {
            connection = par_value;
          } else if (!strcasecmp(par_name, "upgrade")) {
            upgrade = par_value;
          } else if (!strcasecmp(par_name, "x-forwarded-for")) {
            x_forwarded_for = par_value;
          } else if (!strcasecmp(par_name, "x-forwarded-host")) {
            x_forwarded_host = par_value;
          } else if (!strcasecmp(par_name, "cookie")) {
            const unsigned char *ckp = strstr(par_value, "EJWSSESSION=");
            //fprintf(stderr, ">>>%s\n", ckp);
            if (ckp) {
              ckp += 12;
              const unsigned char *ckq = ckp;
              // invalid chars: CTL, whitespace, [",;\]
              while (*ckq > ' ' && *ckq < 127 && *ckq != '\"' && *ckq != ',' && *ckq != ';' && *ckq != '\\') {
                ++ckq;
              }
              if (ckq - ckp == 32) {
                unsigned char buf1[17];
                unsigned char buf2[17];
                memcpy(buf1, ckp, 16); buf1[16] = 0;
                memcpy(buf2, ckp + 16, 16); buf2[16] = 0;
                unsigned long long val1 = 0, val2 = 0;
                errno = 0;
                char *eptr;
                val1 = strtoull(buf1, &eptr, 16);
                if (!errno && !*eptr) {
                  val2 = strtoull(buf2, &eptr, 16);
                  if (!errno && !*eptr) {
                    if (state->params->ws_check_session
                        && state->params->ws_check_session(state, p, val1, val2) >= 0) {
                      // nothing
                    }
                  }
                }
              }
            }
          }
        }
      }

      curc = nextl + 1;
    }
    p->read_size = 0;

    if (get_uri) {
      //fprintf(stderr, "URI: %s\n", get_uri);
      p->uri = xstrdup(get_uri);
    }
    if (host) {
      //fprintf(stderr, "Host: %s\n", host);
      p->host = xstrdup(host);
    }
    if (user_agent) {
      //fprintf(stderr, "User-Agent: %s\n", user_agent);
      p->user_agent = xstrdup(user_agent);
    }
    if (accept_encoding) {
      //fprintf(stderr, "Accept-Encoding: %s\n", accept_encoding);
      p->accept_encoding = xstrdup(accept_encoding);
    }
    if (sec_websocket_version) {
      //fprintf(stderr, "Sec-Websocket-Version: %s\n", sec_websocket_version);
    }
    if (origin) {
      //fprintf(stderr, "Origin: %s\n", origin);
      p->origin = xstrdup(origin);
    }
    if (sec_websocket_extensions) {
      //fprintf(stderr, "Sec-Websocket-Extensions: %s\n", sec_websocket_extensions);
    }
    if (sec_websocket_key) {
      //fprintf(stderr, "Sec-Websocket-Key: %s\n", sec_websocket_key);
    }
    if (connection) {
      //fprintf(stderr, "Connection: %s\n", connection);
    }
    if (upgrade) {
      //fprintf(stderr, "Upgrade: %s\n", upgrade);
    }
    if (x_forwarded_for && *x_forwarded_for) {
      free(p->remote_addr);
      p->remote_addr = xstrdup(x_forwarded_for);
    }
    if (x_forwarded_host && *x_forwarded_host) {
      free(p->host);
      p->host = xstrdup(x_forwarded_host);
    }

    if (!connection || !strcasestr(connection, "upgrade")) {
      err("no connection: upgrade");
      append_ws_bad_request(p);
      return;
    }
    if (!upgrade || strcasecmp(upgrade, "websocket")) {
      err("no upgrade: websocket");
      append_ws_bad_request(p);
      return;
    }
    if (!sec_websocket_key || !*sec_websocket_key) {
      err("no sec-websocket-key");
      append_ws_bad_request(p);
      return;
    }

    if (!p->auth) {
      if (state->params->ws_create_session) {
        if (state->params->ws_create_session(state, p) >= 0) {
          // nothing
        }
      }
    }

    //fprintf(stderr, "cookie: %016llx%016llx\n", p->ws_sid_1, p->ws_sid_2);
    
    static const unsigned char ws_handshake_uuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char *ws_concat_keys = NULL;
    int ws_concat_len = asprintf((void *) &ws_concat_keys, "%s%s", sec_websocket_key, ws_handshake_uuid);
    unsigned char shabin[20];
    sha_buffer(ws_concat_keys, ws_concat_len, shabin);
    unsigned char shabuf[64];
    int shabuflen = base64_encode(shabin, sizeof(shabin), shabuf);
    shabuf[shabuflen] = 0;

    char *ws_reply = NULL;
    size_t ws_reply_z = 0;
    FILE *ws_reply_f = open_memstream(&ws_reply, &ws_reply_z);
    fprintf(ws_reply_f, 
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n",
            shabuf);
    if (p->auth && (p->auth->session_id || p->auth->client_key)) {
      fprintf(ws_reply_f,
              "Set-Cookie: EJWSSESSION=%016llx%016llx; HttpOnly; Path=/; SameSite=Lax\r\n",
              p->auth->session_id, p->auth->client_key);
    }
    fprintf(ws_reply_f, "\r\n");
    fclose(ws_reply_f); ws_reply_f = NULL;
    nsf_ws_append_reply_raw(p, ws_reply, ws_reply_z);
    p->state = WS_STATE_INITIAL_REPLY;

    free(ws_concat_keys); ws_concat_keys = NULL;
    free(ws_reply); ws_reply = NULL;
    return;
  } else if (p->state == WS_STATE_ACTIVE) {
    /*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7|8 9 0 1 2 3 4 5|6 7 8 9 0 1 2 3|4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
     */
    while (1) {
      int r = read(p->b.fd, buf, sizeof(buf));
      if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      } else if (r < 0) {
        err("read error: %s", os_ErrorMsg());
        p->state = WS_STATE_DISCONNECT;
        return;
      } else if (!r) {
        p->state = WS_STATE_DISCONNECT;
        return;
      } else {
        p->last_read_time_us = current_time_us;
        const unsigned char *ptr = buf;
        while (r) {
          if (!p->hdr_flag) {
            // reading frame header
            if (!p->hdr_expected) {
              p->hdr_buf[p->hdr_size++] = *ptr++;
              --r;
              if (p->hdr_size == 2) {
                p->hdr_expected = 2;
                unsigned char paylen = p->hdr_buf[1] & 0x7f;
                if (paylen == 126) {
                  p->hdr_expected += 2;
                } else if (paylen == 127) {
                  p->hdr_expected += 8;
                }
                if ((signed char) p->hdr_buf[1] < 0) {
                  // masking enabled
                  p->hdr_expected += 4;
                }
                if (p->hdr_size == p->hdr_expected) {
                  if (paylen >= p->read_reserved) {
                    int new_reserved = p->read_reserved;
                    if (!new_reserved) new_reserved = 64;
                    while (paylen >= new_reserved) new_reserved *= 2;
                    unsigned char *new_ptr = realloc(p->read_buf, new_reserved);
                    if (!new_ptr) {
                      nsf_ws_append_close_request(p, WS_STATUS_MESSAGE_TOO_BIG);
                      return;
                    }
                    p->read_reserved = new_reserved;
                    p->read_buf = new_ptr;
                  }
                  p->hdr_flag = 1;
                  p->read_expected = paylen;
                  p->read_size = 0;
                }
              }
            } else {
              p->hdr_buf[p->hdr_size++] = *ptr++;
              --r;
              if (p->hdr_size == p->hdr_expected) {
                p->hdr_flag = 1;
                unsigned long long payload_size = p->hdr_buf[1] & 0x7f;
                if (payload_size == 126) {
                  payload_size = (unsigned long long) p->hdr_buf[2] << 8;
                  payload_size |= (unsigned long long) p->hdr_buf[3];
                  if (payload_size < 126) {
                    nsf_ws_append_close_request(p, WS_STATUS_PROTOCOL_ERROR);
                    return;
                  }
                } else if (payload_size == 127) {
                  payload_size = (unsigned long long) p->hdr_buf[2] << 56;
                  payload_size |= (unsigned long long) p->hdr_buf[3] << 48;
                  payload_size |= (unsigned long long) p->hdr_buf[4] << 40;
                  payload_size |= (unsigned long long) p->hdr_buf[5] << 32;
                  payload_size |= (unsigned long long) p->hdr_buf[6] << 24;
                  payload_size |= (unsigned long long) p->hdr_buf[7] << 16;
                  payload_size |= (unsigned long long) p->hdr_buf[8] << 8;
                  payload_size |= (unsigned long long) p->hdr_buf[9];
                  if ((long long) payload_size < 0 || payload_size < 65536) {
                    nsf_ws_append_close_request(p, WS_STATUS_PROTOCOL_ERROR);
                    return;
                  }
                }
                if (payload_size >= 128 * 1024 * 1024) {
                  nsf_ws_append_close_request(p, WS_STATUS_MESSAGE_TOO_BIG);
                  return;
                }
                if (payload_size >= p->read_reserved) {
                  int new_reserved = p->read_reserved;
                  if (!new_reserved) new_reserved = 64;
                  while (payload_size >= new_reserved) new_reserved *= 2;
                  unsigned char *new_ptr = realloc(p->read_buf, new_reserved);
                  if (!new_ptr) {
                    nsf_ws_append_close_request(p, WS_STATUS_MESSAGE_TOO_BIG);
                    return;
                  }
                  p->read_reserved = new_reserved;
                  p->read_buf = new_ptr;
                }
                p->read_expected = payload_size;
                p->read_size = 0;
              }
            }
          } else {
            // reading payload
            int want = p->read_expected - p->read_size;
            if (want > r) want = r;
            memcpy(p->read_buf + p->read_size, ptr, want);
            p->read_size += want;
            r -= want;
            if (p->read_size == p->read_expected) {
              if ((signed char) p->hdr_buf[1] < 0) {
                // masking
                const unsigned char *mask_ptr = p->hdr_buf + 2;
                if (p->hdr_buf[1] == (0x80 + 126)) {
                  mask_ptr = p->hdr_buf + 4;
                } else if (p->hdr_buf[1] == (0x80 + 127)) {
                  mask_ptr = p->hdr_buf + 10;
                }
                for (int i = 0; i < p->read_size; ++i) {
                  p->read_buf[i] ^= mask_ptr[i & 3];
                }
              }
              p->read_buf[p->read_size] = 0;
              if (!p->frame_last || (signed char) p->frame_last->hdr[0] < 0) {
                if (!append_new_ws_frame(p)) {
                  nsf_ws_append_close_request(p, WS_STATUS_MESSAGE_TOO_BIG);
                  return;
                }
              } else {
                // opcode must be 0
                if ((p->hdr_buf[0] & 0xf) != 0) {
                  nsf_ws_append_close_request(p, WS_STATUS_PROTOCOL_ERROR);
                  return;
                }
                struct ws_frame *wsf = p->frame_last;
                wsf->hdr[0] |= p->hdr_buf[0] & 0x80;
                if (p->read_size > 0) {
                  unsigned char *new_ptr = realloc(wsf->data, wsf->size + p->read_size);
                  if (!new_ptr) {
                    nsf_ws_append_close_request(p, WS_STATUS_MESSAGE_TOO_BIG);
                    return;
                  }
                  wsf->data = new_ptr;
                  memcpy(new_ptr + wsf->size, p->read_buf, p->read_size);
                  wsf->size += p->read_size;
                }
                p->read_size = 0;
                p->read_expected = 0;
                p->hdr_flag = 0;
                p->hdr_expected = 0;
                p->hdr_size = 0;
              }
            }
          }
        }
      }
    }
  }
}

static void
write_ws_connection(struct ws_client_state *p, long long current_time_us)
{
  while (p->write_size > 0) {
    int w = write(p->b.fd, p->write_buf, p->write_size);
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    } else if (w < 0) {
    } else if (!w) {
    } else {
      if (w < p->write_size) {
        memmove(p->write_buf, p->write_buf + w, p->write_size - w);
      }
      p->write_size -= w;
      p->last_write_time_us = current_time_us;
    }
  }
}

void
nsf_enqueue_reply(struct server_framework_state *state,
                  struct client_state *p, ej_size_t len, void const *msg)
{
  struct ht_client_state *pp = (struct ht_client_state*) p;

  ASSERT(!pp->write_len);

  pp->write_len = len + sizeof(len);
  pp->write_buf = xmalloc(pp->write_len);
  memcpy(pp->write_buf, &len, sizeof(len));
  memcpy(pp->write_buf + sizeof(len), msg, len);
  pp->written = 0;
  pp->state = STATE_WRITE;
}

void
nsf_send_reply(
        struct server_framework_state *state,
        struct client_state *p,
        int answer)
{
  struct new_server_prot_packet pkt;

  memset(&pkt, 0, sizeof(pkt));
  pkt.id = answer;
  pkt.magic = NEW_SERVER_PROT_PACKET_MAGIC;
  nsf_enqueue_reply(state, p, sizeof(pkt), &pkt);
}

void
nsf_err_protocol_error(
        struct server_framework_state *state,
        struct client_state *p)
{
  struct ht_client_state *pp = (struct ht_client_state*) p;
  err("%d: protocol error", p->id);
  nsf_send_reply(state, p, NEW_SRV_ERR_PROTOCOL_ERROR);
  if (pp->client_fds[0] >= 0) close(pp->client_fds[0]);
  if (pp->client_fds[1] >= 0) close(pp->client_fds[1]);
  pp->client_fds[0] = pp->client_fds[1] = -1;
}

void
nsf_err_bad_packet_length(
        struct server_framework_state *state,
        struct client_state *p,
        size_t len,
        size_t exp_len)
{
  struct ht_client_state *pp = (struct ht_client_state*) p;
  err("%d: bad packet length: %zu, expected %zu", p->id, len, exp_len);
  pp->state = STATE_DISCONNECT;
}

void
nsf_err_packet_too_small(
        struct server_framework_state *state,
        struct client_state *p,
        size_t len,
        size_t min_len)
{
  struct ht_client_state *pp = (struct ht_client_state*) p;
  err("%d: packet is too small: %zu, minimum %zu", p->id, len, min_len);
  pp->state = STATE_DISCONNECT;
}

void
nsf_err_invalid_command(
        struct server_framework_state *state,
        struct client_state *p,
        int id)
{
  struct ht_client_state *pp = (struct ht_client_state *) p;
  err("%d: invalid protocol command: %d", p->id, id);
  pp->state = STATE_DISCONNECT;
}

static void
cmd_pass_fd(
        struct server_framework_state *state,
        struct client_state *p,
        size_t len,
        const struct new_server_prot_packet *pkt)
{
  struct ht_client_state *pp = (struct ht_client_state*) p;

  if (len != sizeof(*pkt))
    return nsf_err_bad_packet_length(state, p, len, sizeof(*pkt));

  if (pp->client_fds[0] >= 0 || pp->client_fds[1] >= 0) {
    err("%d: cannot stack unprocessed client descriptors", p->id);
    pp->state = STATE_DISCONNECT;
    return;
  }

  pp->state = STATE_READ_FDS;
}

static void
handle_control_command(
        struct server_framework_state *state,
        struct ht_client_state *p)
{
  struct new_server_prot_packet *pkt;

  if (p->read_len < sizeof(*pkt)) {
    err("%d: packet length is too small: %d", p->b.id, p->read_len);
    p->state = STATE_DISCONNECT;
    return;
  }
  pkt = (struct new_server_prot_packet*) p->read_buf;

  if (pkt->magic != NEW_SERVER_PROT_PACKET_MAGIC) {
    err("%d: invalid magic value: %04x", p->b.id, pkt->magic);
    p->state = STATE_DISCONNECT;
    return;
  }

  if (pkt->id <= 0) {
    err("%d: invalid protocol command: %d", p->b.id, pkt->id);
    p->state = STATE_DISCONNECT;
    return;
  }

  if (pkt->id == 1) cmd_pass_fd(state, &p->b, p->read_len, pkt);
  else if (state->params->handle_packet)
    state->params->handle_packet(state, &p->b, p->read_len, pkt);

  if (p->state == STATE_READ_READY) p->state = STATE_READ_LEN;
  if (p->read_buf) xfree(p->read_buf);
  p->read_buf = 0;
  p->expected_len = 0;
  p->read_len = 0;
}

int
nsf_add_directory_watch(
        const struct ejudge_cfg *config,
        struct server_framework_state *state,
        const unsigned char *dir,
        const unsigned char *data_dir,
        const unsigned char *data2_dir,
        void (*callback)(
                const struct ejudge_cfg *config,
                struct server_framework_state *state,
                const unsigned char *dir,
                const unsigned char *dir_dir,
                const unsigned char *dir_out,
                const unsigned char *data_dir,
                const unsigned char *data2_dir,
                void *user),
        void *user)
{
  struct directory_watch *dw;
  XCALLOC(dw, 1);

  dw->prev = state->dw_last;
  if (state->dw_last) {
    state->dw_last->next = dw;
  } else {
    state->dw_first = dw;
  }
  state->dw_last = dw;

  dw->config = config;
  dw->dir = xstrdup(dir);
  dw->data_dir = xstrdup(data_dir);
  if (data2_dir) {
    dw->data2_dir = xstrdup(data2_dir);
  }
  __attribute__((unused)) int r;
  char *s = NULL;
  r = asprintf(&s, "%s/dir", dw->dir);
  dw->dir_dir = s; s = NULL;
  r = asprintf(&s, "%s/out", dw->dir);
  dw->dir_out = s; s = NULL;
  dw->user = user;
  dw->callback = callback;
  dw->wd = -1;

  return 0;
}

static void
do_inotify_read(struct server_framework_state *state)
{
  unsigned char buf[4096];
  while (1) {
    errno = 0;
    int r = read(state->ifd, buf, sizeof(buf));
    if (r < 0 && errno == EAGAIN) {
      break;
    }
    if (r < 0) {
      err("do_inotify_read: read failed: %s", os_ErrorMsg());
      break;
    }
    if (!r) {
      err("do_inotify_read: read returned 0");
      break;
    }
    const unsigned char *bend = buf + r;
    const unsigned char *p = buf;
    while (p < bend) {
      const struct inotify_event *ev = (const struct inotify_event *) p;
      p += sizeof(*ev) + ev->len;
      struct directory_watch *dw;
      for (dw = state->dw_first; dw; dw = dw->next) {
        if (dw->wd == ev->wd) {
          break;
        }
      }
      if (!dw) {
        err("do_inotify_read: watch descriptor %d not found", ev->wd);
      } else {
        dw->ready = 1;
      }
    }
    if (p > bend) {
      err("do_inotify_read: buffer overrun: end = %p, cur = %p", bend, p);
    }
  }
}

void
nsf_main_loop(struct server_framework_state *state)
{
  struct ht_client_state *cur_clnt;
  struct timespec timeoutn;
  int fd_max, n;
  fd_set rset, wset;
  struct watchlist *pw;
  int mode;
  struct ws_client_state *ws_clnt;
  long long current_time_us;

  while (1) {
    int work_done = 1;
    if (state->params->loop_start) work_done = state->params->loop_start(state);

    for (struct directory_watch *dw = state->dw_first; dw; dw = dw->next) {
      if (dw->ready) {
        dw->callback(dw->config, state, dw->dir, dw->dir_dir, dw->dir_out, dw->data_dir, dw->data2_dir, dw->user);
        dw->ready = 0;
      }
    }

    fd_max = -1;
    FD_ZERO(&rset);
    FD_ZERO(&wset);

    if (state->socket_fd >= 0) {
      FD_SET(state->socket_fd, &rset);
      if (state->socket_fd > fd_max) fd_max = state->socket_fd;
    }
    if (state->ws_fd >= 0) {
      FD_SET(state->ws_fd, &rset);
      if (state->ws_fd > fd_max) fd_max = state->ws_fd;
    }

    if (state->ifd >= 0) {
      FD_SET(state->ifd, &rset);
      if (state->ifd > fd_max) fd_max = state->ifd;
    }

    for (cur_clnt = state->clients_first; cur_clnt; cur_clnt = (struct ht_client_state *) cur_clnt->b.next) {
      if (cur_clnt->state==STATE_WRITE || cur_clnt->state==STATE_WRITECLOSE) {
        FD_SET(cur_clnt->b.fd, &wset);
        if (cur_clnt->b.fd > fd_max) fd_max = cur_clnt->b.fd;
      } else if (cur_clnt->state >= STATE_READ_CREDS
                 && cur_clnt->state <= STATE_READ_DATA) {
        FD_SET(cur_clnt->b.fd, &rset);
        if (cur_clnt->b.fd > fd_max) fd_max = cur_clnt->b.fd;
      }
    }

    for (ws_clnt = state->ws_first; ws_clnt; ws_clnt = (struct ws_client_state *) ws_clnt->b.next) {
      switch (ws_clnt->state) {
      case WS_STATE_INITIAL:
        FD_SET(ws_clnt->b.fd, &rset);
        if (ws_clnt->b.fd > fd_max) fd_max = ws_clnt->b.fd;
        break;
      case WS_STATE_INITIAL_REPLY: case WS_STATE_HTTP_ERROR:
        if (ws_clnt->write_size > 0) {
          FD_SET(ws_clnt->b.fd, &wset);
          if (ws_clnt->b.fd > fd_max) fd_max = ws_clnt->b.fd;
        }
        break;
      case WS_STATE_ACTIVE:
        if (!ws_clnt->in_close_state) {
          FD_SET(ws_clnt->b.fd, &rset);
          if (ws_clnt->b.fd > fd_max) fd_max = ws_clnt->b.fd;
        }
        if (ws_clnt->write_size > 0) {
          FD_SET(ws_clnt->b.fd, &wset);
            if (ws_clnt->b.fd > fd_max) fd_max = ws_clnt->b.fd;
        }
        break;
      default:
        abort();
      }
    }

    remove_pending_watches(state);
    for (pw = state->w_first; pw; pw = pw->next) {
      if (pw->pending_removal || pw->w.fd < 0) continue;
      if ((pw->w.mode & NSF_READ)) {
        FD_SET(pw->w.fd, &rset);
        if (pw->w.fd > fd_max) fd_max = pw->w.fd;
      }
      if ((pw->w.mode & NSF_WRITE)) {
        FD_SET(pw->w.fd, &wset);
        if (pw->w.fd > fd_max) fd_max = pw->w.fd;
      }
    }

    if (work_done) {
      if ((timeoutn.tv_sec = state->params->select_timeout) <= 0) {
        timeoutn.tv_sec = 10;
      }
    } else {
      timeoutn.tv_sec = 0;
    }
    timeoutn.tv_nsec = 0;

    n = pselect(fd_max + 1, &rset, &wset, NULL, &timeoutn, &state->work_mask);

    if (n < 0 && errno != EINTR) {
      err("unexpected select error: %s", os_ErrorMsg());
      continue;
    }

    // FIXME: check for signal events
    if (sigint_flag) break;
    if (sighup_flag) {
      state->restart_requested = 1;
      break;
    }
    if (sigusr1_flag) {
      if (state->params->daemon_mode_flag) {
        start_open_log(state->params->log_path);
      }
      sigusr1_flag = 0;
      continue;
    }

    if (n <= 0) continue;

    // call post-select callback
    if (state->params->post_select) state->params->post_select(state);

    // process watches
    for (pw = state->w_first; pw; pw = pw->next) {
      if (pw->pending_removal || pw->w.fd < 0) continue;
      mode = 0;
      if ((pw->w.mode & NSF_READ) && FD_ISSET(pw->w.fd, &rset))
        mode |= NSF_READ;
      if ((pw->w.mode & NSF_WRITE) && FD_ISSET(pw->w.fd, &wset))
        mode |= NSF_WRITE;
      if (mode) pw->w.callback(state, &pw->w, mode);
    }
    remove_pending_watches(state);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    current_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;
    metrics.data->update_time = tv;

    // new WebSocket connections
    if (state->ws_fd >= 0 && FD_ISSET(state->ws_fd, &rset)) {
      accept_new_ws_connections(state);
    }

    // check for new control connections
    if (state->socket_fd >= 0 && FD_ISSET(state->socket_fd, &rset)) {
      accept_new_connection(state);
    }

    // read from/write to control sockets
    for (cur_clnt = state->clients_first; cur_clnt; cur_clnt = (struct ht_client_state *) cur_clnt->b.next) {
      switch (cur_clnt->state) {
      case STATE_READ_CREDS:
      case STATE_READ_FDS:
      case STATE_READ_LEN:
      case STATE_READ_DATA:
        if (FD_ISSET(cur_clnt->b.fd, &rset))
          read_from_control_connection(cur_clnt);
        break;
      case STATE_WRITE:
      case STATE_WRITECLOSE:
        if (FD_ISSET(cur_clnt->b.fd, &wset))
          write_to_control_connection(cur_clnt);
        break;
      }
    }

    for (ws_clnt = state->ws_first; ws_clnt; ws_clnt = (struct ws_client_state *) ws_clnt->b.next) {
      if (FD_ISSET(ws_clnt->b.fd, &rset)) {
        read_ws_connection(state, ws_clnt, current_time_us);
      }
      if (FD_ISSET(ws_clnt->b.fd, &wset)) {
        write_ws_connection(ws_clnt, current_time_us);
        if (ws_clnt->write_size == 0 && ws_clnt->state == WS_STATE_INITIAL_REPLY) {
          ws_clnt->state = WS_STATE_ACTIVE;
        } else if (ws_clnt->write_size == 0 && ws_clnt->state == WS_STATE_HTTP_ERROR) {
          ws_clnt->state = WS_STATE_DISCONNECT;
        }
      }
    }

    if (state->ifd >= 0 && FD_ISSET(state->ifd, &rset)) {
      do_inotify_read(state);
    }

    // execute ready commands from control connections
    for (cur_clnt = state->clients_first; cur_clnt; cur_clnt = (struct ht_client_state *) cur_clnt->b.next) {
      if (cur_clnt->state == STATE_READ_READY) {
        handle_control_command(state, cur_clnt);
        ASSERT(cur_clnt->state != STATE_READ_READY);
      }
    }

    for (ws_clnt = state->ws_first; ws_clnt; ws_clnt = (struct ws_client_state *) ws_clnt->b.next) {
      if (ws_clnt->state == WS_STATE_ACTIVE) {
        while (1) {
          struct ws_frame *wsf = ws_clnt->frame_first;
          if (!wsf || (signed char) wsf->hdr[0] >= 0) break;

          switch (wsf->hdr[0] & 0x0F) {
          case WS_FRAME_TEXT:
          case WS_FRAME_BIN:
            if (state->params->ws_handle_packet) {
              state->params->ws_handle_packet(state, ws_clnt, wsf->hdr[0] & 0x0F, wsf->data, wsf->size);
            }

            //fprintf(stderr, "ws_frame: %d, %d\n", (wsf->hdr[0] & 0x0F), wsf->size);
            //nsf_ws_append_reply_frame(ws_clnt, WS_FRAME_TEXT, wsf->data, wsf->size);

            break;
          case WS_FRAME_CLOSE:
            fprintf(stderr, "ws_close_frame:\n");
            ws_clnt->in_close_state = 1;
            if (!ws_clnt->out_close_state) {
              int close_code = -1;
              if (wsf->size > 2) {
                close_code = (wsf->data[0] << 8) | (wsf->data[1]);
              }
              nsf_ws_append_close_request(ws_clnt, close_code);
            }
            break;
          case WS_FRAME_PING:
            fprintf(stderr, "ws_ping_frame:\n");
            if (wsf->fragments > 1 || wsf->size >= 126) {
              nsf_ws_append_close_request(ws_clnt, WS_STATUS_PROTOCOL_ERROR);
            } else {
              nsf_ws_append_reply_frame(ws_clnt, WS_FRAME_PONG, wsf->data, wsf->size);
            }
            break;
          default:
            nsf_ws_append_close_request(ws_clnt, WS_STATUS_PROTOCOL_ERROR);
            break;
          }

          ws_clnt->frame_first = wsf->next;
          if (wsf->next) {
            wsf->next->prev = NULL;
          } else {
            ws_clnt->frame_last = NULL;
          }
          ws_frame_free(wsf);
        }
        if (ws_clnt->in_close_state > 0 && ws_clnt->out_close_state == 2) {
          ws_clnt->state = WS_STATE_DISCONNECT;
        }
      }
    }

    // disconnect file descriptors marked for disconnection
    for (cur_clnt = state->clients_first; cur_clnt; ) {
      if (cur_clnt->state == STATE_DISCONNECT) {
        struct client_state *tmp = cur_clnt->b.next;
        client_state_delete(state, &cur_clnt->b);
        cur_clnt = (struct ht_client_state *) tmp;
      } else {
        cur_clnt = (struct ht_client_state *) cur_clnt->b.next;
      }
    }

    for (ws_clnt = state->ws_first; ws_clnt; ) {
      if (ws_clnt->state == WS_STATE_DISCONNECT) {
        struct ws_client_state *tmp = (struct ws_client_state *) ws_clnt->b.next;
        ws_client_state_delete(state, ws_clnt);
        ws_clnt = tmp;
      } else {
        ws_clnt = (struct ws_client_state*) ws_clnt->b.next;
      }
    }
  }
}

int
nsf_prepare(struct server_framework_state *state)
{
  struct sockaddr_un addr;
  struct sigaction act;
  int pid;
  unsigned char socket_dir[4096];

  if (getuid() == 0) {
    state->params->startup_error("sorry, will not run as the root");
  }

  if (state->params->force_socket_flag) {
    errno = 0;
    if (unlink(state->params->socket_path) < 0 && errno != ENOENT)
      state->params->startup_error("cannot remove stale socket file");
  }

  // create a websocket socket
  state->ws_fd = -1;
  if (state->params->ws_port > 0) {
    if ((state->ws_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
      state->params->startup_error("socket() failed: %s", os_ErrorMsg());
    }

    int value = 1;
    if (setsockopt(state->ws_fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
      state->params->startup_error("setsockopt() failed: %s", os_ErrorMsg());
    }
    if (setsockopt(state->ws_fd, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) < 0) {
      state->params->startup_error("setsockopt() failed: %s", os_ErrorMsg());
    }

    struct sockaddr_in bind_addr = {};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(state->params->ws_port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(state->ws_fd, (void *) &bind_addr, sizeof(bind_addr)) < 0) {
      state->params->startup_error("bind() failed: %s", os_ErrorMsg());
    }

    if (listen(state->ws_fd, 32) < 0) {
      state->params->startup_error("listen() failed: %s", os_ErrorMsg());
    }

    int old_flags = fcntl(state->ws_fd, F_GETFL, 0);
    if (old_flags < 0) {
      state->params->startup_error("fcntl() failed: %s", os_ErrorMsg());
    }
    if (fcntl(state->ws_fd, F_SETFL, old_flags | O_NONBLOCK) < 0) {
      state->params->startup_error("fcntl() failed: %s", os_ErrorMsg());
    }
  }

  if (state->dw_first) {
    state->ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (state->ifd < 0) {
      state->params->startup_error("inotify_init1() failed: %s", os_ErrorMsg());
    }

    for (struct directory_watch *dw = state->dw_first; dw; dw = dw->next) {
      dw->wd = inotify_add_watch(state->ifd, dw->dir_dir, IN_CREATE | IN_MOVED_TO);
      if (dw->wd < 0) {
        state->params->startup_error("inotify_add_watch() failed: %s", os_ErrorMsg());
      }
      dw->ready = 1;
    }
  }

  // create a control socket
  if ((state->socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
    state->params->startup_error("socket() failed: %s", os_ErrorMsg());

  // create the socket directory
  os_rDirName(state->params->socket_path, socket_dir, sizeof(socket_dir));
  os_MakeDirPath(socket_dir, 0775);
  if (os_IsFile(socket_dir) != OSPK_DIR) {
    state->params->startup_error("%s is not a directory", socket_dir);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(state->params->socket_path) >= sizeof(addr.sun_path))
    state->params->startup_error("socket path is too long");
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
           state->params->socket_path);
  if (bind(state->socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    state->params->startup_error("bind() failed: %s", os_ErrorMsg());

  if (listen(state->socket_fd, 128) < 0)
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
  sigdelset(&state->work_mask, SIGUSR1);

  // we want these signals handled by backtrace
  sigdelset(&state->work_mask, SIGILL);
  sigdelset(&state->work_mask, SIGBUS);
  sigdelset(&state->work_mask, SIGFPE);
  sigdelset(&state->work_mask, SIGSEGV);
  sigdelset(&state->work_mask, SIGABRT);
  sigdelset(&state->block_mask, SIGILL);
  sigdelset(&state->block_mask, SIGBUS);
  sigdelset(&state->block_mask, SIGFPE);
  sigdelset(&state->block_mask, SIGSEGV);
  sigdelset(&state->block_mask, SIGABRT);

  memset(&act, 0, sizeof(act));
  act.sa_handler = sighup_handler;
  sigfillset(&act.sa_mask);
  sigaction(SIGHUP, &act, 0);

  act.sa_handler = sigint_handler;
  sigaction(SIGINT, &act, 0);
  sigaction(SIGTERM, &act, 0);

  act.sa_handler = sigchld_handler;
  sigaction(SIGCHLD, &act, 0);

  act.sa_handler = sigusr1_handler;
  sigaction(SIGUSR1, &act, 0);

  if (state->params->daemon_mode_flag) {
    if (start_open_log(state->params->log_path) < 0)
      goto cleanup;

    if ((pid = fork()) < 0) return -1;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return -1;
  } else if (state->params->restart_mode_flag) {
    if (start_open_log(state->params->log_path) < 0)
      goto cleanup;
  }

  return 0;

 cleanup:
  unlink(state->params->socket_path);
  return -1;
}

void
nsf_cleanup(struct server_framework_state *state)
{
  struct ht_client_state *p;

  for (p = state->clients_first; p; p = (struct ht_client_state *) p->b.next) {
    if (p->b.fd >= 0) close(p->b.fd);
    p->b.fd = -1;

    if (p->client_fds[0] >= 0) close(p->client_fds[0]);
    if (p->client_fds[1] >= 0) close(p->client_fds[1]);
    p->client_fds[0] = -1;
    p->client_fds[1] = -1;

    // do not flush pending write buffer, just close the connection
    xfree(p->write_buf); p->write_buf = 0;
    p->write_len = p->written = 0;

    xfree(p->read_buf); p->read_buf = 0;
    p->expected_len = p->read_len = 0;

    for (struct directory_watch *dw = state->dw_first; dw; ) {
      struct directory_watch *p = dw;
      dw = dw->next;
      xfree(p->dir_out);
      xfree(p->dir_dir);
      xfree(p->dir);
      xfree(p);
    }
    state->dw_first = NULL;
    state->dw_last = NULL;

    if (state->ifd >= 0) {
      close(state->ifd); state->ifd = -1;
    }
  }

  if (state->socket_fd >= 0) close(state->socket_fd);
  state->socket_fd = -1;
  unlink(state->params->socket_path);
}

int
nsf_is_restart_requested(struct server_framework_state *state)
{
  return state->restart_requested;
}

struct server_framework_state *
nsf_init(
        struct server_framework_params *params,
        void *data,
        time_t server_start_time)
{
  struct server_framework_state *state;

  XCALLOC(state, 1);
  state->params = params;
  state->user_data = data;
  //state->client_id = 1;
  state->server_start_time = server_start_time;
  state->ifd = -1;

  return state;
}

void
nsf_add_job(
        struct server_framework_state *state,
        struct server_framework_job *job)
{
  if (!job) return;
  job->id = ++state->job_serial;
  job->start_time = time(NULL);
  ++state->job_count;
  job->prev = state->job_last;
  job->next = NULL;
  if (state->job_last) {
    state->job_last->next = job;
  } else {
    state->job_first = job;
  }
  state->job_last = job;
}

void
nsf_remove_job(
        struct server_framework_state *state,
        struct server_framework_job *job)
{
  if (job->next) {
    job->next->prev = job->prev;
  } else {
    state->job_last = job->prev;
  }
  if (job->prev) {
    job->prev->next = job->next;
  } else {
    state->job_first = job->next;
  }
  job->next = NULL;
  job->prev = NULL;
  job->vt->destroy(job);
  --state->job_count;
}

struct server_framework_job *
nsf_get_first_job(
        struct server_framework_state *state)
{
  return state->job_first;
}

int
nsf_get_job_count(
        struct server_framework_state *state)
{
  return state->job_count;
}

time_t
nsf_get_server_start_time(
        struct server_framework_state *state)
{
  return state->server_start_time;
}

static int
ws_client_get_ssl_flag(const struct client_state *p)
{
  const struct ws_client_state *pp = (const struct ws_client_state *) p;
  return pp->ssl_flag;
}

static const unsigned char *
ws_client_get_host(const struct client_state *p)
{
  const struct ws_client_state *pp = (const struct ws_client_state *) p;
  return pp->host;
}

static const unsigned char *
ws_client_get_remote_addr(const struct client_state *p)
{
  const struct ws_client_state *pp = (const struct ws_client_state *) p;
  return pp->remote_addr;
}

static int
ws_client_get_reply_id(struct client_state *p)
{
  struct ws_client_state *pp = (struct ws_client_state *) p;
  return ++pp->reply_id;
}

static const struct client_auth *
ws_client_get_client_auth(const struct client_state *p)
{
  const struct ws_client_state *pp = (const struct ws_client_state *) p;
  return pp->auth;
}

static void
ws_client_set_client_auth(struct client_state *p, struct client_auth *auth)
{
  struct ws_client_state *pp = (struct ws_client_state *) p;
  if (pp->auth) {
    nsf_client_auth_free(pp->auth);
  }
  pp->auth = auth;
}
