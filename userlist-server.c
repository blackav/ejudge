/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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

#include "userlist_cfg.h"
#include "userlist.h"
#include "pathutl.h"
#include "base64.h"

#include <reuse/logger.h>
#include <reuse/osdeps.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define CLIENT_TIMEOUT 600

struct client_state
{
  struct client_state *next;
  struct client_state *prev;

  int id;
  int fd;
  int write_len;
  int written;
  unsigned char *write_buf;
  int read_state;
  int expected_len;
  int read_len;
  unsigned char *read_buf;

  time_t last_time;
  int state;

  // some peer information
  int peer_pid;
  int peer_uid;
  int peer_gid;
};

static struct userlist_cfg *config;
static struct userlist_list *users;
static int listen_socket = -1;
static int urandom_fd = -1;
static char *socket_name;
static struct client_state *first_client;
static struct client_state *last_client;
static int serial_id = 1;

static time_t last_flush;
static unsigned long flush_interval;

static unsigned long long
generate_random_cookie(void)
{
  unsigned long long val = 0;
  int n, r;
  char *p;

  ASSERT(urandom_fd >= 0);
  while (!val) {
    p = (char*) &val;
    r = sizeof(val);
    while (r > 0) {
      n = read(urandom_fd, p, r);
      if (n < 0) {
        err("read from /dev/urandom failed: %s", os_ErrorMsg());
        exit(1);
      }
      if (!n) {
        err("EOF on /dev/urandom???");
        exit(1);
      }
      p += n;
      r -= n;
    }
    if (!val) {
      info("got 0 from /dev/urandom");
    }
  }

  return val;
}

static void
generate_random_password(int size, unsigned char *buf)
{
  int rand_bytes;
  unsigned char *rnd_buf = 0;
  unsigned char *b64_buf = 0;
  unsigned char *p;
  int r, n;

  ASSERT(size > 0 && size <= 128);
  ASSERT(buf);

  // estimate the number of random bytes to generate
  rnd_buf = (unsigned char*) alloca(size + 16);
  b64_buf = (unsigned char *) alloca(size + 16);
  if (size % 4) {
    rand_bytes = (size / 4 + 1) * 3;
  } else {
    rand_bytes = (size / 4) * 3;
  }

  // generate the needed number of bytes
  r = rand_bytes;
  p = rnd_buf;
  while (r > 0) {
    n = read(urandom_fd, p, r);
    if (n < 0) {
      err("read from /dev/urandom failed: %s", os_ErrorMsg());
      exit(1);
    }
    if (!n) {
      err("EOF on /dev/urandom???");
      exit(1);
    }
    p += n;
    r -= n;
  }

  // convert to base64
  base64_encode(rnd_buf, rand_bytes, b64_buf);
  b64_buf[size] = 0;
  strcpy(buf, b64_buf);
}

static void
disconnect_client(struct client_state *p)
{
  ASSERT(p);

  close(p->fd);
  if (p->write_buf) xfree(p->write_buf);
  if (p->read_buf) xfree(p->read_buf);

  if (p->prev) {
    p->prev->next = p->next;
  } else {
    first_client = p->next;
  }
  if (p->next) {
    p->next->prev = p->prev;
  } else {
    last_client = p->prev;
  }

  memset(p, 0, sizeof(*p));
  xfree(p);
}

#if 0
int send_email(char const *dest, char const *subj, char const *text)
{
}

void send_message(struct client_state *p)
{
}

static void
send_reply(struct client_state *p,short answer)
{
  p->write_len = sizeof(short);
  p->write_buf = xmalloc(sizeof(short));
  *(p->write_buf) = answer;
  send_message(p);
}


char * mkpasswd()

static void
create_newuser(struct client_state *p, struct newuser_data * data)
{
  struct user_data * user;
  char * buf;

  data->login = data->buffer;
  data->email = data->buffer + data->login_length + 1;
  
  
  user = userlist->first;
  while (user) {
    if (!strcmp(user_data_get_field(user, TAG_LOGIN),data->login)) {
      //Login already exists
      send_reply(p,1);
      return;
    }
    user = user->next;
  }
  
  userlist->last->next = xcalloc(1, sizeof(user_data));
  userlist->last = userlist->last->next;

  user = userlist->last;

  user->next=nul;
  user->parent = userlist;
  
//!!!Must create user_id

  user->ip = data->origin_ip;
  user->contest = data->contest_id;
  user->locale = data->locale_id;
  user->use_cookies = data->use_cookies;
  user_data_set_field(user,TAG_LOGIN,data->login);
  user_data_set_field(user,TAG_EMAIL,data->email);

  user_data_set_field(user,TAG_PASSWORD,mkpasswd());

  buf = (char *) xmalloc(255);
  sprintf(buf,"You are registered in contest system \n"
            "http://contest.cmc.msu.ru/cgi-bin/register?contest_id=%d&locale_id=%d\n"
            "login: %s\n"
            "password: %s\n",
            user->contest,user->locale,
            user->login, user->passwd);
  send_email(user->email,"Registration in contest system",buf);
  free(x);
  send_reply(p,0);
          
}

long long generate_cookie()
{
  //Must generate cookie
}

static void
login_user(struct client_state *p, struct loginuser_data * data)
{
  struct user_data * user;
  struct loginuser_answer * answer;
 
  data->login = data->buffer;
  data->password = data->buffer + data->login_length + 1;
                                                         
  user = userlist->first;
  while (user) {
    if (!strcmp(user->login,data->login)) {
      if (!strcmp(user->passwd,data->password)) {
        //Login and password correct
        p->write_len = sizeof(loginuser_answer)+strlen(user->descr);
        answer = xmalloc(p->write_len);
        p->write_buf = (unsigned char *)answer;

        user->locale = data->locale_id;
        user->use_cookies = data->use_cookies;
        user->ip = data->origin_ip;

        if (data->usecookies==1) {
          answer->reply = 5;
          answer->cookie = generate_cookie();
          //!!!Add time of experied od cookie
        } else {
          answer->reply = 6;
          answer->cookie = 0;
        }
        answer->user_id = user->id;
        answer->name_len = strlen(user->descr);
        strcopy(answer->name,user->descr);
        send_message(p);
        exit;
       
      } else {
        //Incorrect password
        send_reply(p,3);
        exit;
      }
    }
    user = user->next;
  }
  //Wrong login
  send_reply(p,2);
}

static void
login_cookie(struct client_state *p, struct logincookie_data * data)
{
  struct user_data * user;
  struct logincookie_answer * answer;

  user=userlist->first;
  while (user) {
    if ((user->ip==data->origin_ip)&&(user->cookie==data->cookie)) {
      //!!! Must check time of cookie
      p->write_len = sizeof(logincookie_answer)+strlen(user->login)+strlen(user->descr)+1;
      answer = xmalloc(p->write_len);
      p->write_buf = (unsigned char *)answer;
      user->locale = data->locale_id;
      answer->reply = 8;
      answer->user_id = user->id;
      answer->login_length = strlen(user->login);
      answer->name_length = strlen(user->descr);
      strcopy(answer->buf,user->login);
      strcopy(answer->buf + strlen(user->login) + 1, user->descr);
      send_message(p);
      exit;
    }
    user = user->next;
  }
  send_reply(p,7);
}

static void
logout_user(struct client_state *p, struct logout_data * data)
{
  struct user_data * user;

  if (!(data->cookie)) {
    send_reply(p,0);
    return;
  }

  user = userlist->first;

  while (user) {
    if ((user->ip==data->origin_ip)&&(user->cookie==data->cookie)) {
      user->cookie = 0;
      send_reply(p,0);
      return;
    }
    user = user->next;
  }   
  send_reply(p,0);
}


  



static void
process_packet(struct client_state *p, int len, unsigned char *pack)
{
  struct packet_struct * packet;
  
  packet = (struct packet_struct *) pack;
  switch (packet->request) {
  case INCR_NEWUSER:
    create_newuser(p, (struct newuser_data *) pack);  
    break;
  
  case INCR_LOGIN:
    login_user(p, (struct loginuser_data *) pack);  
    break;
    
  case INCR_COOKIE:
    login_cookie(p, (struct logincookie_data *) pack);  
    break;

}
#endif /* 0 */

static void
process_packet(struct client_state *p, int len, unsigned char *pack)
{
}

static int
do_work(void)
{
  struct sockaddr_un addr;
  int val;
  int max_fd;
  struct timeval timeout;
  fd_set rset, wset;
  struct client_state *p;
  time_t cur_time;

  signal(SIGPIPE, SIG_IGN);

  if((urandom_fd = open("/dev/urandom", O_RDONLY)) < 0) {
    err("open of /dev/urandom failed: %s", os_ErrorMsg());
    return 1;
  }

  if ((listen_socket = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
    err("socket() failed :%s", os_ErrorMsg());
    return 1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, config->socket_path, 108);
  addr.sun_path[107] = 0;
  if (bind(listen_socket, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    err("bind() failed: %s", os_ErrorMsg());
    return 1;
  }
  socket_name = config->socket_path;

  /*
  val = 1;
  if (setsockopt(listen_socket, SOL_SOCKET, SO_PASSCRED,
                 &val, sizeof(val)) < 0) {
    err("setsockopt() failed: %s", os_ErrorMsg());
    return 1;
  }
  */

  if (listen(listen_socket, 5) < 0) {
    err("listen() failed: %s", os_ErrorMsg());
    return 1;
  }

  while (1) {
    // flush database
    cur_time = time(0);
    if (cur_time <= last_flush + flush_interval) {
      // FIXME: flush database
    }

    // disconnect idle clients
    while (1) {
      for (p = first_client; p; p = p->next)
        if (p->last_time + CLIENT_TIMEOUT < cur_time) break;
      if (!p) break;
      info("%d: timeout, client disconnected", p->id);
      disconnect_client(p);
    }

    FD_ZERO(&rset);
    FD_ZERO(&wset);
    max_fd = -1;

    FD_SET(listen_socket, &rset);
    max_fd = listen_socket + 1;

    for (p = first_client; p; p = p->next) {
      if (p->write_len > 0) {
        FD_SET(p->fd, &wset);
      } else {
        FD_SET(p->fd, &rset);
      }
      if (p->fd >= max_fd) max_fd = p->fd + 1;
    }

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    val = select(max_fd, &rset, &wset, NULL, &timeout);
    if (val < 0 && errno == EINTR) {
      info("select interrupted, restarting it");
      continue;
    }

    cur_time = time(0);

    if (!val) continue;

    if (FD_ISSET(listen_socket, &rset)) {
      int new_fd;
      int addrlen;
      struct client_state *q;

      memset(&addr, 0, sizeof(addr));
      addrlen = sizeof(addr);
      new_fd = accept(listen_socket, (struct sockaddr*) &addr, &addrlen);
      if (new_fd < 0) {
        err("accept failed: %s", os_ErrorMsg());
      } else {
        q = (struct client_state*) xcalloc(1, sizeof(*q));
        if (last_client) {
          last_client->next = q;
          q->prev = last_client;
          last_client = q;
        } else {
          last_client = first_client = q;
        }
        q->fd = new_fd;
        q->last_time = cur_time;
        q->id = serial_id++;

        val = 1;
        if (setsockopt(new_fd, SOL_SOCKET, SO_PASSCRED,
                       &val, sizeof(val)) < 0) {
          err("%d: setsockopt() failed: %s", q->id, os_ErrorMsg());
          disconnect_client(q);
        } else {
          info("%d: connection accepted", q->id);
        }
      }
    }

    // check write bit and write
  restart_write_scan:
    for (p = first_client; p; p = p->next) {
      if (FD_ISSET(p->fd, &wset)) {
        int w, l;

        l = p->write_len - p->written;
        w = write(p->fd, &p->write_buf[p->written], l);
        if (w <= 0) {
          err("%d: write() failed: %s", p->id, os_ErrorMsg());
          disconnect_client(p);
          goto restart_write_scan; /* UGLY :-( */
        }
        p->written += w;
        if (p->write_len == p->written) {
          p->written = 0;
          p->write_len = 0;
          xfree(p->write_buf);
          p->write_buf = 0;
        }
      }
    }

    // check read bit and read
    while (1) {
      int l, r;

      for (p = first_client; p; p = p->next)
        if (FD_ISSET(p->fd, &rset)) break;
      if (!p) break;

      if (p->state == 0) {
        struct msghdr msg;
        unsigned char msgbuf[512];
        struct cmsghdr *pmsg;
        struct ucred *pcred;
        struct iovec recv_vec[1];
        int val;

        // we expect 4 zero bytes and credentials
        memset(&msg, 0, sizeof(msg));
        msg.msg_flags = 0;
        msg.msg_control = msgbuf;
        msg.msg_controllen = sizeof(msgbuf);
        recv_vec[0].iov_base = &val;
        recv_vec[0].iov_len = 4;
        msg.msg_iov = recv_vec;
        msg.msg_iovlen = 1;
        val = -1;
        r = recvmsg(p->fd, &msg, 0);
        if (r < 0) {
          err("%d: recvmsg failed: %s", p->id, os_ErrorMsg());
          disconnect_client(p);
          continue;
        }
        if (r != 4) {
          err("%d: read %d bytes instead of 4", p->id, r);
          disconnect_client(p);
          continue;
        }
        if (val != 0) {
          err("%d: expected 4 zero bytes", p->id);
          disconnect_client(p);
          continue;
        }
        if ((msg.msg_flags & MSG_CTRUNC)) {
          err("%d: protocol error: control buffer too small", p->id);
          disconnect_client(p);
          continue;
        }

        pmsg = CMSG_FIRSTHDR(&msg);
        if (!pmsg) {
          err("%d: empty control data", p->id);
          disconnect_client(p);
          continue;
        }
        /* cmsg_len, cmsg_level, cmsg_type */
        if (pmsg->cmsg_level != SOL_SOCKET
            || pmsg->cmsg_type != SCM_CREDENTIALS
            || pmsg->cmsg_len != CMSG_LEN(sizeof(*pcred))) {
          err("%d: protocol error: unexpected control data", p->id);
          disconnect_client(p);
          continue;
        }
        pcred = (struct ucred*) CMSG_DATA(pmsg);
        p->peer_pid = pcred->pid;
        p->peer_uid = pcred->uid;
        p->peer_gid = pcred->gid;
        if (CMSG_NXTHDR(&msg, pmsg)) {
          err("%d: protocol error: unexpected control data", p->id);
          disconnect_client(p);
          continue;
        }

        info("%d: received peer information: %d, %d, %d", p->id,
             p->peer_pid, p->peer_uid, p->peer_gid);

        p->state = 1;
        continue;
      }

      if (p->read_state < 4) {
        unsigned char rbuf[4];

        memcpy(rbuf, &p->expected_len, 4);
        l = 4 - p->read_state;
        r = read(p->fd, &rbuf[p->read_state], l);
        if (!p->read_state && !r) {
          info("%d: client closed connection", p->id);
          disconnect_client(p);
          continue;
        }
        if (!r) {
          err("%d: unexpected EOF from client", p->id);
          disconnect_client(p);
          continue;
        }
        if (r < 0) {
          err("%d: read() failed: %s", p->id, os_ErrorMsg());
          disconnect_client(p);
          continue;
        }

        p->read_state += l;
        memcpy(&p->expected_len, rbuf, 4);
        if (p->read_state == 4) {
          if (p->expected_len <= 0 || p->expected_len > 128 * 1024) {
            err("%d: protocol error: bad packet length: %d",
                p->id, p->expected_len);
            disconnect_client(p);
            continue;
          }
          p->read_len = 0;
          p->read_buf = (unsigned char*) xcalloc(1, p->expected_len);
        }
        FD_CLR(p->fd, &rset);
        continue;
      }

      l = p->expected_len - p->read_len;
      r = read(p->fd, &p->read_buf, l);
      if (!r) {
        err("%d: unexpected EOF from client", p->id);
        disconnect_client(p);
        continue;
      }
      if (r < 0) {
        err("%d: read() failed: %s", p->id, os_ErrorMsg());
        disconnect_client(p);
        continue;
      }

      p->read_len += r;
      if (p->expected_len == p->read_len) {
        process_packet(p, p->expected_len, p->read_buf);
        p->read_len = 0;
        p->expected_len = 0;
        p->read_state = 0;
        xfree(p->read_buf);
        p->read_buf = 0;
      }
      FD_CLR(p->fd, &rset);
    }
  }

  return 0;
}

int
main(int argc, char *argv[])
{
  int code = 0;

  if (argc == 1) goto print_usage;
  code = 1;
  if (argc != 2) goto print_usage;

  config = userlist_cfg_parse(argv[1]);
  if (!config) return 1;
  users = userlist_parse(config->db_path);
  if(!users) return 1;

  userlist_unparse(users, stdout);
  return 0;
#if 0
  code = do_work();

  if (socket_name) unlink(socket_name);
  if (listen_socket >= 0) close(listen_socket);
  //userlist_cfg_unparse(config, stdout);
  userlist_cfg_free(config);
  return code;
#endif
  
 print_usage:
  printf("Usage: %s config-file\n", argv[0]);
  return code;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
