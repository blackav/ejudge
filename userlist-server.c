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
#include "userlist_proto.h"
#include "contests.h"

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
#include <stdarg.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define DEFAULT_FLUSH_INTERVAL 600
#define DEFAULT_COOKIE_CHECK_INTERVAL 60
#define DEFAULT_USER_CHECK_INTERVAL 600
#define DEFAULT_BACKUP_INTERVAL (24*60*60)
#define CLIENT_TIMEOUT 600
#define DEFAULT_SERVER_USE_COOKIES 1

// server connection states
enum
  {
    STATE_READ_CREDS,
    STATE_READ_DATA,
    STATE_READ_FDS,
    STATE_AUTOCLOSE,
  };

struct userlist_list * userlist;

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
  int processed;

  time_t last_time;
  int state;

  // some peer information
  int peer_pid;
  int peer_uid;
  int peer_gid;

  // database user_id for access control
  // 0 - root, -1 - unknown (anonymous)
  int user_id;

  // passed file descriptors
  int client_fds[2];
};

static struct userlist_cfg *config;
static int listen_socket = -1;
static int urandom_fd = -1;
static char *socket_name;
static struct client_state *first_client;
static struct client_state *last_client;
static int serial_id = 1;
static struct contest_list *contests;

static time_t cur_time;
static time_t last_flush;
static unsigned long flush_interval;
static int dirty = 0;
static time_t last_cookie_check;
static time_t last_user_check;
static time_t cookie_check_interval;
static time_t user_check_interval;
static time_t last_backup;
static time_t backup_interval;

static void
link_client_state(struct client_state *p)
{
  if (!last_client) {
    p->next = p->prev = 0;
    first_client = last_client = p;
  } else {
    p->next = 0;
    p->prev = last_client;
    last_client->next = p;
    last_client = p;
  }
}

static void
force_check_dirty(int s)
{
  flush_interval = 0;
}
static void
force_flush(int s)
{
  dirty = 1;
  flush_interval = 0;
}

static unsigned long
generate_random_long(void)
{
  unsigned long val = 0;
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

static int
setup_locale(int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  char *e = 0;
  char env_buf[128];

  if (!config->l10n) return 0;

  switch (locale_id) {
  case 1:
    e = "ru_RU.KOI8-R";
    break;
  case 0:
  default:
    locale_id = 0;
    e = "C";
    break;
  }

  sprintf(env_buf, "LC_ALL=%s", e);
  putenv(env_buf);
  setlocale(LC_ALL, "");
  return locale_id;
#else
  return 0;
#endif /* CONF_HAS_LIBINTL */
}

static int
send_email_message(unsigned char const *to,
                   unsigned char const *from,
                   unsigned char const *charset,
                   unsigned char const *subject,
                   unsigned char const *text)
{
  FILE *f = 0;

  ASSERT(config->email_program);
  if (!charset) charset = "koi8-r";

  if (!(f = popen(config->email_program, "w"))) return -1;

  if (charset) {
    fprintf(f, "Content-type: text/plain; charset=\"%s\"\n",
            charset);
  } else {
    fprintf(f, "Content-type: text/plain\n");
  }
  fprintf(f, "To: %s\nFrom: %s\nSubject: %s\n\n%s\n",
          to, from, subject, text);
  pclose(f);
  return 0;
}

static void
disconnect_client(struct client_state *p)
{
  ASSERT(p);

  close(p->fd);
  if (p->write_buf) xfree(p->write_buf);
  if (p->read_buf) xfree(p->read_buf);
  if (p->client_fds[0] >= 0) close(p->client_fds[0]);
  if (p->client_fds[1] >= 0) close(p->client_fds[1]);

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

static void
enqueue_reply_to_client(struct client_state *p,
                        int msg_length,
                        void const *msg)
{
  ASSERT(p);
  ASSERT(msg_length > 0);
  ASSERT(msg);

  if (p->write_len) {
    SWERR(("Server->client reply slot is busy!"));
  }
  p->write_buf = xmalloc(msg_length + 4);
  memcpy(p->write_buf, &msg_length, 4);
  memcpy(p->write_buf + 4, msg, msg_length);
  p->write_len = msg_length + 4;
}

static void
graceful_exit(int s)
{
  if (config && config->socket_path) {
    unlink(config->socket_path);
  }
  signal(s, SIG_DFL);
  raise(s);
}

static unsigned char *
unparse_ip(unsigned long ip)
{
  static char buf[64];

  snprintf(buf, sizeof(buf), "%lu.%lu.%lu.%lu",
           ip >> 24, (ip >> 16) & 0xff,
           (ip >> 8) & 0xff, ip & 0xff);
  return buf;
}

static void
send_reply(struct client_state *p,short answer)
{
  int msg_length;

  msg_length = sizeof(short);
  enqueue_reply_to_client(p,msg_length,&answer);
}

//static void bad_packet(struct client_state *p, char const *format, ...) __attribute__((format(printf,2,3)));
static void
bad_packet(struct client_state *p, char const *format, ...)
{
  unsigned char msgbuf[1024];

  if (format && *format) {
    va_list args;

    va_start(args, format);
    vsnprintf(msgbuf, sizeof(msgbuf), format, args);
    va_end(args);
    err("%d: bad packet: %s", p->id, msgbuf);
  } else {
    err("%d: bad packet", p->id);
  }
  disconnect_client(p);
}

static void
create_newuser(struct client_state *p,
               int pkt_len,
               struct userlist_pk_register_new * data)
{
  struct userlist_user * user;
  char * buf;
  unsigned char * login;
  unsigned char * email;
  int usernum;
  unsigned char urlbuf[1024];

  login = data->data;
  email = data->data + data->login_length + 1;

  user = (struct userlist_user*) userlist->b.first_down;
  while (user) {
    if (!strcmp(user->login,login)) {
      //Login already exists
      send_reply(p, -ULS_ERR_LOGIN_USED);
      return;
    }
    user = (struct userlist_user*) user->b.right;
  }
  user = xcalloc(1, sizeof(struct userlist_user));
  if (userlist->b.first_down) {
    userlist->b.last_down->right = (struct xml_tree *)user;
    user->b.left = userlist->b.last_down;
  } else {
    userlist->b.first_down = (struct xml_tree*) user;
    user->b.left = NULL;
  }
  userlist->b.last_down = (struct xml_tree *)user;

  usernum = 1;
  while (userlist->user_map[usernum]) {
    usernum++;
  }
  userlist->user_map[usernum] = user;
  user->id = usernum;

  user->b.tag = USERLIST_T_USER;
  user->b.right=NULL;
  user->b.up = (struct xml_tree *) userlist;
  user->cookies = NULL;

  user->login = calloc(1,data->login_length+1);
  strcpy(user->login,login);
  user->email = calloc(1,data->email_length+1);
  strcpy(user->email,email);
  user->passwd_method = 0;
  user->passwd = calloc(1,9);
  generate_random_password(8, user->passwd);
  user->name = xstrdup("");
  user->default_use_cookies = -1;

  snprintf(urlbuf, sizeof(urlbuf), "%s", config->register_url);

  buf = (char *) xcalloc(1,1024);
  snprintf(buf, 1024,
           _("Hello,\n"
             "\n"
             "Somebody (probably you) have specified this e-mail address (%s)\n"
             "when registering an account on the Moscow Programming Contests\n"
             "Server.\n"
             "\n"
             "To confirm registration, you should enter the provided login\n"
             "and password on the login page of the server at the\n"
             "following url: %s.\n"
             "\n"
             "Note, that if you do not do this in 24 hours from the moment\n"
             "of sending this letter, registration will be void.\n"
             "\n"
             "login:    %s\n"
             "password: %s\n"
             "\n"
             "Regards,\n"
             "The ejudge contest administration system\n"),
           user->email,
           urlbuf,
           user->login, user->passwd);
  send_email_message(user->email,
                     config->register_email,
                     NULL,
                     "You have been registered",
                     buf);
  free(buf);
  send_reply(p,ULS_OK);

  user->registration_time = cur_time;
  dirty = 1;
  flush_interval /= 2;
}

static struct userlist_cookie *
create_cookie(struct userlist_user * user)
{
  struct userlist_cookie * cookie;

  cookie = xcalloc(1,sizeof(struct userlist_cookie));

  fprintf(stderr, "adding a cookie for user %d\n",
          user->id);

  if (!(user->cookies)) {
    user->cookies = xcalloc(1,sizeof (struct xml_tree));
    user->cookies->up = (struct xml_tree*) user;
    user->cookies->tag = USERLIST_T_COOKIES;
    
    user->cookies->first_down = (struct xml_tree*) cookie;
    user->cookies->last_down = (struct xml_tree*) cookie;
    cookie->b.left = NULL;
  } else {
    cookie->b.left = user->cookies->last_down;
    user->cookies->last_down->right = (struct xml_tree*) cookie;
    user->cookies->last_down = (struct xml_tree*) cookie;
  }
  cookie->b.right = NULL;
  cookie->b.up = user->cookies;
  cookie->b.tag = USERLIST_T_COOKIE;

  dirty = 1;
  return cookie;
}

static void
remove_cookie(struct userlist_cookie * cookie)
{
  struct xml_tree * cookies;
  struct userlist_user * user;

  cookies = cookie->b.up;
  user = (struct userlist_user*) cookies->up;
  
  if (cookie->b.left) {
    cookie->b.left->right = cookie->b.right;
  } else {
    cookies->first_down = cookie->b.right;
  }
  
  if (cookie->b.right) {
    cookie->b.right->left = cookie->b.left;
  } else {
    cookies->first_down = cookie->b.left;
  }

  free(cookie);
  if (!(cookies->first_down)) {
    free(cookies);
    user->cookies = NULL;
  }

  dirty = 1;
}

static void
check_all_cookies(void)
{
  struct userlist_user * user;
  struct userlist_cookie * cookie;
  struct userlist_cookie * rmcookie;
  
  cur_time = time(0);

  user=(struct userlist_user*) userlist->b.first_down;
  while (user) {
    if (user->cookies) {
      cookie = (struct userlist_cookie*) user->cookies->first_down;
      while (cookie) {
        if (cookie->expire<cur_time) {
          rmcookie=cookie;
          cookie = (struct userlist_cookie*) cookie->b.right;
          info("cookies: removing cookie %d,%s,%s,%llx",
               user->id, user->login, unparse_ip(rmcookie->ip),
               rmcookie->cookie);
          remove_cookie(rmcookie);
        } else {
          cookie = (struct userlist_cookie*) cookie->b.right;
        }
      }
    }
    user = (struct userlist_user*) user->b.right;
  }

  last_cookie_check = cur_time;
  cookie_check_interval = DEFAULT_COOKIE_CHECK_INTERVAL;
}

static void
check_all_users(void)
{
  struct xml_tree *t;
  struct userlist_user *usr;

  while (1) {
    for (t = userlist->b.first_down; t; t = t->right) {
      if (t->tag != USERLIST_T_USER) continue;
      usr = (struct userlist_user*) t;
      if (!usr->last_login_time &&
          usr->registration_time + 24 * 60 * 60 < cur_time) {
        info("users: removing user <%d,%s,%s>: not logged in",
             usr->id, usr->login, usr->email);
        userlist_remove_user(userlist, usr);
        dirty = 1;
        flush_interval /= 2;
        break;
      }
      // problematic
      /*
      if (usr->last_login_time + 24 * 60 * 60 * 90 < cur_time) {
        info("users: removing user <%d,%s,%s>: expired",
             usr->id, usr->login, usr->email);
        userlist_remove_user(userlist, usr);
        break;
      }
      */
    }
    if (!t) break;
  }
}

static void
login_user(struct client_state *p,
           int pkt_len,
           struct userlist_pk_do_login * data)
{
  struct userlist_user * user;
  struct userlist_pk_login_ok * answer;
  int ans_len;
  char * login;
  char * password;
  char * name;
  struct userlist_cookie * cookie;

  login = data->data;
  password = data->data + data->login_length + 1;

  if (strlen(login) != data->login_length
      || strlen(password) != data->password_length) {
    bad_packet(p, "");
    return;
  }
  info("%d: login_user: %s, %s", p->id, unparse_ip(data->origin_ip), login);

  if (p->user_id >= 0) {
    err("%d: this connection already authentificated", p->id);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  user = (struct userlist_user*) userlist->b.first_down;
  while (user) {
    ASSERT(user->b.tag == USERLIST_T_USER);
    if (!strcmp(user->login,login)) {
      if (!strcmp(user->passwd,password)) {
        //Login and password correct
        ans_len = sizeof(struct userlist_pk_login_ok)
          + strlen(user->name) + 1 + strlen(user->login) + 1;
        answer = alloca(ans_len);

        if (data->use_cookies == -1) {
          data->use_cookies = user->default_use_cookies;
        }
        if (data->use_cookies == -1) {
          data->use_cookies = DEFAULT_SERVER_USE_COOKIES;
        }
        if (data->use_cookies) {        
          cookie = create_cookie(user);
          cookie->locale_id = data->locale_id;
          cookie->ip = data->origin_ip;
          cookie->contest_id = data->contest_id;
          cookie->expire = time(0)+24*60*60;
          answer->reply_id = ULS_LOGIN_COOKIE;
          cookie->cookie = generate_random_cookie();
          answer->cookie = cookie->cookie;
          dirty = 1;
        } else {
          answer->reply_id = ULS_LOGIN_OK;
          answer->cookie = 0;
        }

        answer->user_id = user->id;
        answer->login_len = strlen(user->login);
        name = answer->data + answer->login_len + 1;
        answer->name_len = strlen(user->name);
        strcpy(answer->data, user->login);
        strcpy(name, user->name);
        enqueue_reply_to_client(p,ans_len,answer);

        user->last_login_time = cur_time;
        user->last_access_time = cur_time;
        dirty = 1;
        info("%d: login_user: OK, cookie = %llx", p->id, answer->cookie);
        p->user_id = user->id;
        return;
      } else {
        //Incorrect password
        info("%d: login_user: BAD PASSWORD", p->id);
        send_reply(p, -ULS_ERR_INVALID_PASSWORD);
        user->last_access_time = cur_time;
        dirty = 1;
        return;
      }
    }
    user = (struct userlist_user*) user->b.right;
  }

  //Wrong login
  send_reply(p, -ULS_ERR_INVALID_LOGIN);
  info("%d: login_user: BAD USER", p->id);
}

static void
login_cookie(struct client_state *p,
             int pkt_len,
             struct userlist_pk_check_cookie * data)
{
  struct userlist_user * user;
  struct userlist_pk_login_ok * answer;
  int anslen;
  struct userlist_cookie * cookie;
  unsigned char *name_beg;

  info("%d: login_cookie: ip = %s, cookie = %llx",
       p->id, unparse_ip(data->origin_ip), data->cookie);

  // cannot login twice
  if (p->user_id >= 0) {
    err("%d: this connection already authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  user = (struct userlist_user*) userlist->b.first_down;
  while (user) {
    if (user->cookies) {
      if (user->cookies->first_down) {
        cookie = (struct userlist_cookie*) user->cookies->first_down;
        while (cookie) {
          if ((cookie->ip == data->origin_ip) &&
              (cookie->cookie == data->cookie) &&
              (time(0)<cookie->expire)) {
            anslen = sizeof(struct userlist_pk_login_ok)
              + strlen(user->name) + 1 + strlen(user->login) + 1;
            answer = alloca(anslen);
            memset(answer, 0, anslen);
            if (data->locale_id != -1) {
              cookie->locale_id = data->locale_id;
              dirty = 1;
              user->last_minor_change_time = cur_time;
            }
            answer->locale_id = cookie->locale_id;
            answer->reply_id = ULS_LOGIN_COOKIE;
            answer->user_id = user->id;
            answer->login_len = strlen(user->login);
            name_beg = answer->data + answer->login_len + 1;
            answer->name_len = strlen(user->name);
            answer->cookie = cookie->cookie;
            strcpy(answer->data, user->login);
            strcpy(name_beg, user->name);
            enqueue_reply_to_client(p,anslen,answer);
            user->last_login_time = cur_time;
            dirty = 1;
            info("%d: login_cookie: OK: %d, %s", p->id, user->id, user->login);
            p->user_id = user->id;
            return;
          }
          cookie = (struct userlist_cookie*) cookie->b.right;
        }
      }
    }
    user = (struct userlist_user*) user->b.right;
  }

  // cookie not found
  info("%d: login_cookie: FAILED", p->id);
  send_reply(p, -ULS_ERR_NO_COOKIE);
}
      
static void
logout_user(struct client_state *p,
            int pkt_len,
            struct userlist_pk_do_logout * data)
{
  struct userlist_user * user;
  struct userlist_cookie * cookie;

  // anonymous cannot logout!
  if (p->user_id <= 0) return;
  ASSERT(p->user_id < userlist->user_map_size);
  user = userlist->user_map[p->user_id];
  ASSERT(user);
  user->last_access_time = cur_time;
  dirty = 1;

  if (user->cookies) {
    if (user->cookies->first_down) {
      cookie = (struct userlist_cookie*) user->cookies->first_down;
      while (cookie) {
        if ((cookie->ip == data->origin_ip) &&
            (cookie->cookie == data->cookie)) {
          remove_cookie(cookie);
          user->last_minor_change_time = cur_time;
          dirty = 1;
          send_reply(p,ULS_OK);
          return;
        }
        cookie = (struct userlist_cookie*) cookie->b.right;
      }
    }
  }
  send_reply(p,ULS_OK);          
}

static void
get_user_info(struct client_state *p,
              int pkt_len,
              struct userlist_pk_get_user_info *pack)
{
  FILE *f = 0;
  unsigned char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  struct userlist_user *user = 0;

  if (pkt_len != sizeof(*pack)) {
    bad_packet(p, "");
    return;
  }

  info("%d: get_user_info: %ld", p->id, pack->user_id);

  if (pack->user_id < 0 || pack->user_id >= userlist->user_map_size
      || !userlist->user_map[pack->user_id]) {
    bad_packet(p, "");
    return;
  }
  if (p->user_id < 0 || p->user_id != pack->user_id) {
    // FIXME: send in somewhat reduced view
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  user = userlist->user_map[pack->user_id];

  if (!(f = open_memstream((char**) &xml_ptr, &xml_size))) {
    err("%d: open_memstream failed!", p->id);
    return;
  }
  userlist_unparse_user(user, f, 1);
  fclose(f);

  ASSERT(xml_size == strlen(xml_ptr));
  ASSERT(xml_size <= 65535);
  out_size = sizeof(*out) + xml_size + 1;
  out = alloca(out_size);
  ASSERT(out);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr);
  user->last_access_time = cur_time;
  dirty = 1;
  enqueue_reply_to_client(p, out_size, out);
  info("%d: get_user_info: size = %d", p->id, out_size);
}

static void
get_user_contests(struct client_state *p,
                  int pkt_len,
                  struct userlist_pk_get_user_info *pack)
{
  FILE *f = 0;
  unsigned char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  struct userlist_user *user = 0;

  if (pkt_len != sizeof(*pack)) {
    bad_packet(p, "");
    return;
  }

  info("%d: get_user_contests: %ld", p->id, pack->user_id);

  if (pack->user_id < 0 || pack->user_id >= userlist->user_map_size
      || !userlist->user_map[pack->user_id]) {
    bad_packet(p, "");
    return;
  }
  if (p->user_id < 0 || p->user_id != pack->user_id) {
    // FIXME: send in somewhat reduced view
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  user = userlist->user_map[pack->user_id];

  if (!(f = open_memstream((char**) &xml_ptr, &xml_size))) {
    err("%d: open_memstream failed!", p->id);
    return;
  }
  userlist_unparse_contests(user, f);
  fclose(f);

  ASSERT(xml_size == strlen(xml_ptr));
  ASSERT(xml_size <= 65535);
  out_size = sizeof(*out) + xml_size + 1;
  out = alloca(out_size);
  ASSERT(out);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr);
  user->last_access_time = cur_time;
  dirty = 1;
  enqueue_reply_to_client(p, out_size, out);
  info("%d: get_user_contests: size = %d", p->id, out_size);
}

static struct userlist_member *
find_member_by_serial(struct userlist_user *u, int serial,
                      int *p_role, int *p_i)
{
  int role, i;
  struct userlist_members *ms;
  struct userlist_member *m;

  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (!u->members[role]) continue;
    ms = u->members[role];
    for (i = 0; i < ms->total; i++) {
      if (!ms->members[i]) continue;
      m = ms->members[i];
      if (serial == m->serial) {
        if (p_role) *p_role = role;
        if (p_i) *p_i = i;
        return m;
      }
    }
  }
  return 0;
}

static struct userlist_member *
unlink_member(struct userlist_user *u, int role, int pers)
{
  struct userlist_members *ms;
  struct userlist_member *m;
  int i;

  ASSERT(u);
  ASSERT(role >= 0 && role < CONTEST_LAST_MEMBER);
  ms = u->members[role];
  ASSERT(ms);
  ASSERT(pers >= 0 && pers < ms->total);
  m = ms->members[pers];
  ASSERT(m);

  // shift members of reference array
  for (i = pers + 1; i < ms->total; i++) {
    ms->members[i - 1] = ms->members[i];
  }
  ms->total--;
  ms->members[ms->total] = 0;

  // destroy the references in member
  xml_unlink_node(&m->b);
  if (ms->total) return m;

  // we now remove list structure
  u->members[role] = 0;
  xml_unlink_node(&ms->b);
  userlist_free(&ms->b);
  return m;
}

static void
link_member(struct userlist_user *u, int role, struct userlist_member *m)
{
  struct userlist_members *ms;

  ASSERT(u);
  ASSERT(role >= 0 && role < CONTEST_LAST_MEMBER);
  ms = u->members[role];
  if (!ms) {
    ms = (struct userlist_members *) userlist_node_alloc(role + USERLIST_T_CONTESTANTS);
    u->members[role] = ms;
    xml_link_node_last(&u->b, &ms->b);
  }
  if (ms->total == ms->allocd) {
    if (!ms->allocd) ms->allocd = 4;
    else ms->allocd *= 2;
    ms->members = xrealloc(ms->members, ms->allocd * sizeof(ms->members[0]));
  }
  ms->members[ms->total++] = m;
  xml_link_node_last(&ms->b, &m->b);
}

static int
needs_update(unsigned char const *old, unsigned char const *new)
{
  if (!new) return 0;
  if (!old) return 1;
  if (strcmp(old, new) == 0) return 0;
  return 1;
}
static int
needs_name_update(unsigned char const *old, unsigned char const *new)
{
  if (!new || !*new) return 0;
  if (!old || !*old) return 1;
  if (strcmp(old, new) == 0) return 0;
  return 1;
}

static void
set_user_info(struct client_state *p,
              int pkt_len,
              struct userlist_pk_set_user_info *pack)
{
  int xml_len;
  struct userlist_user *new_u = 0, *old_u = 0;
  int old_role, old_pers, new_role, new_pers;
  struct userlist_members *old_ms = 0, *new_ms;
  struct userlist_member *new_m, *old_m;
  unsigned char const *role_str = 0;
  int updated = 0;

  xml_len = strlen(pack->data);
  if (xml_len != pack->info_len) {
    bad_packet(p, "");
    return;
  }
  if (pkt_len != sizeof(*pack) + xml_len + 1) {
    bad_packet(p, "");
    return;
  }

  info("%d: set_user_info: %ld, %d", p->id, pack->user_id, pack->info_len);
  if (p->user_id <= 0) {
    info("%d: client not authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != pack->user_id) {
    info("%d: user_id does not match", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  //fprintf(stderr, "======\n%s\n======\n", pack->data);

  if (!(new_u = userlist_parse_user_str(pack->data))) {
    info("%d: XML parse error", p->id);
    send_reply(p, -ULS_ERR_XML_PARSE);
    return;
  }

  if (pack->user_id != new_u->id) {
    info("%d: XML user_id %d does not correspond to packet user_id %lu",
         p->id, new_u->id, pack->user_id);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if (new_u->id <= 0 || new_u->id >= userlist->user_map_size
      || !userlist->user_map[new_u->id]) {
    info("%d: invalid user_id %d", p->id, new_u->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  old_u = userlist->user_map[new_u->id];
  if (strcmp(old_u->email, new_u->email) != 0) {
    info("%d: new email <%s> does not match old <%s>",
         p->id, new_u->email, old_u->email);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (strcmp(old_u->login, new_u->login) != 0) {
    info("%d: new login <%s> does not match old <%s>",
         p->id, new_u->login, old_u->email);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  // update the user's fields
  if (needs_name_update(old_u->name, new_u->name)) {
    xfree(old_u->name);
    old_u->name = xstrdup(new_u->name);
    info("%d: name updated", p->id);
    updated = 1;
  }
  if (needs_update(old_u->homepage, new_u->homepage)) {
    xfree(old_u->homepage);
    old_u->homepage = xstrdup(new_u->homepage);
    info("%d: homepage updated", p->id);
    updated = 1;
  }
  if (needs_update(old_u->inst, new_u->inst)) {
    xfree(old_u->inst);
    old_u->inst = xstrdup(new_u->inst);
    info("%d: inst updated", p->id);
    updated = 1;
  }
  if (needs_update(old_u->instshort, new_u->instshort)) {
    xfree(old_u->instshort);
    old_u->instshort = xstrdup(new_u->instshort);
    info("%d: instshort updated", p->id);
    updated = 1;
  }
  if (needs_update(old_u->fac, new_u->fac)) {
    xfree(old_u->fac);
    old_u->fac = xstrdup(new_u->fac);
    info("%d: fac updated", p->id);
    updated = 1;
  }
  if (needs_update(old_u->facshort, new_u->facshort)) {
    xfree(old_u->facshort);
    old_u->facshort = xstrdup(new_u->facshort);
    info("%d: facshort updated", p->id);
    updated = 1;
  }

  // move members
 restart_movement:
  for (old_role = 0; old_role < CONTEST_LAST_MEMBER; old_role++) {
    old_ms = old_u->members[old_role];
    role_str = userlist_tag_to_str(old_role + USERLIST_T_CONTESTANTS);
    if (!old_ms) continue;
    for (old_pers = 0; old_pers < old_ms->total; old_pers++) {
      old_m = old_ms->members[old_pers];
      if (!old_m) continue;
      ASSERT(old_m->serial > 0);
      new_m = find_member_by_serial(new_u, old_m->serial,
                                    &new_role, &new_pers);
      if (new_m && old_role != new_role) {
        // move to another role
        info("%d: %s.%d moved to %s",
             p->id, role_str, old_pers,
             userlist_tag_to_str(new_role + USERLIST_T_CONTESTANTS));
        updated = 1;
        new_m = unlink_member(old_u, old_role, old_pers);
        ASSERT(new_m == old_m);
        link_member(old_u, new_role, new_m);
        goto restart_movement;
      }
    }
  }

  // update members
  for (old_role = 0; old_role < CONTEST_LAST_MEMBER; old_role++) {
    role_str = userlist_tag_to_str(old_role + USERLIST_T_CONTESTANTS);
    old_ms = old_u->members[old_role];
    if (!old_ms) continue;
    for (old_pers = 0; old_pers < old_ms->total; old_pers++) {
      old_m = old_ms->members[old_pers];
      if (!old_m) continue;
      ASSERT(old_m->serial > 0);
      new_m = find_member_by_serial(new_u, old_m->serial,
                                    &new_role, &new_pers);
      if (!new_m) continue;
      ASSERT(new_role == old_role);
      ASSERT(new_m->serial == old_m->serial);

      if (new_m->status && old_m->status != new_m->status) {
        old_m->status = new_m->status;
        info("%d: updated %s.%d.status", p->id, role_str, old_pers);
        updated = 1;
      }
      if (new_m->grade && old_m->grade != new_m->grade) {
        old_m->grade = new_m->grade;
        info("%d: updated %s.%d.grade", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->firstname, new_m->firstname)) {
        xfree(old_m->firstname);
        old_m->firstname = xstrdup(new_m->firstname);
        info("%d: updated %s.%d.firstname", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->middlename, new_m->middlename)) {
        xfree(old_m->middlename);
        old_m->middlename = xstrdup(new_m->middlename);
        info("%d: updated %s.%d.middlename", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->surname, new_m->surname)) {
        xfree(old_m->surname);
        old_m->surname = xstrdup(new_m->surname);
        info("%d: updated %s.%d.surname", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->group, new_m->group)) {
        xfree(old_m->group);
        old_m->group = xstrdup(new_m->group);
        info("%d: updated %s.%d.group", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->email, new_m->email)) {
        xfree(old_m->email);
        old_m->email = xstrdup(new_m->email);
        info("%d: updated %s.%d.email", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->homepage, new_m->homepage)) {
        xfree(old_m->homepage);
        old_m->homepage = xstrdup(new_m->homepage);
        info("%d: updated %s.%d.homepage", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->inst, new_m->inst)) {
        xfree(old_m->inst);
        old_m->inst = xstrdup(new_m->inst);
        info("%d: updated %s.%d.inst", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->instshort, new_m->instshort)) {
        xfree(old_m->instshort);
        old_m->instshort = xstrdup(new_m->instshort);
        info("%d: updated %s.%d.instshort", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->fac, new_m->fac)) {
        xfree(old_m->fac);
        old_m->fac = xstrdup(new_m->fac);
        info("%d: updated %s.%d.fac", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->facshort, new_m->facshort)) {
        xfree(old_m->facshort);
        old_m->facshort = xstrdup(new_m->facshort);
        info("%d: updated %s.%d.facshort", p->id, role_str, old_pers);
        updated = 1;
      }

      // unlink the new member out of the way
      new_m = unlink_member(new_u, new_role, new_pers);
      userlist_free(&new_m->b);
    }
  }

  // copy new members
 restart_inserting:
  for (new_role = 0; new_role < CONTEST_LAST_MEMBER; new_role++) {
    role_str = userlist_tag_to_str(new_role + USERLIST_T_CONTESTANTS);
    new_ms = new_u->members[new_role];
    if (!new_ms) continue;
    for (new_pers = 0; new_pers < new_ms->total; new_pers++) {
      new_m = new_ms->members[new_pers];
      if (!new_m) continue;
      if (new_m->serial > 0) {
        err("%d: new member in %s has serial number %d",
            p->id, role_str, new_m->serial);
        old_m = unlink_member(new_u, new_role, new_pers);
        ASSERT(old_m == new_m);
        userlist_free(&new_m->b);
        goto restart_inserting;
      }
      info("%d: new member to role %s inserted", p->id, role_str);
      updated = 1;
      old_m = unlink_member(new_u, new_role, new_pers);
      ASSERT(old_m == new_m);
      old_m->serial = userlist->member_serial++;
      link_member(old_u, new_role, new_m);
      goto restart_inserting;
    }
  }

  old_u->last_access_time = cur_time;
  if (updated) {
    old_u->last_change_time = cur_time;
    dirty = 1;
    flush_interval /= 2;
  }
  send_reply(p, ULS_OK);
}

static void
set_password(struct client_state *p, int len,
             struct userlist_pk_set_password *pack)
{
  int old_len, new_len;
  unsigned char *old_pwd, *new_pwd;
  struct userlist_user *u;

  // check packet
  if (len < sizeof(*pack)) {
    bad_packet(p, "");
    return;
  }
  old_pwd = pack->data;
  old_len = strlen(old_pwd);
  if (old_len != pack->old_len) {
    bad_packet(p, "");
    return;
  }
  new_pwd = old_pwd + old_len + 1;
  new_len = strlen(new_pwd);
  if (new_len != pack->new_len) {
    bad_packet(p, "");
    return;
  }
  if (len != sizeof(*pack) + old_len + new_len + 2) {
    bad_packet(p, "");
    return;
  }

  info("%d: set_password: %d", p->id, pack->user_id);
  if (p->user_id <= 0) {
    info("%d: client not authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != pack->user_id) {
    info("%d: user_id does not match", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size) {
    info("%d: user id is out of range", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  u = userlist->user_map[pack->user_id];
  if (!u) {
    info("%d: user id nonexistent", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (u->passwd_method != 0) {
    info("%d: unsupported password method %d", p->id, u->passwd_method);
    send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
    return;
  }
  if (strcmp(u->passwd, old_pwd) != 0) {
    info("%d: provided password does not match", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  xfree(u->passwd);
  u->passwd = xstrdup(new_pwd);

  u->last_pwdchange_time = cur_time;
  u->last_access_time = cur_time;
  dirty = 1;
  flush_interval /= 2;
  send_reply(p, ULS_OK);
}

static void
register_for_contest(struct client_state *p, int len,
                     struct userlist_pk_register_contest *pack)
{
  struct userlist_user *u;
  struct contest_desc *c;
  struct userlist_contest *r;

  if (len != sizeof(*pack)) {
    bad_packet(p, "");
    return;
  }

  info("%d: register_for_contest: %d, %d",
       p->id, pack->user_id, pack->contest_id);
  if (p->user_id <= 0) {
    info("%d: client not authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != pack->user_id) {
    info("%d: user_id does not match", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size) {
    info("%d: user id is out of range", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  u = userlist->user_map[pack->user_id];
  if (!u) {
    info("%d: user id nonexistent", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (pack->contest_id <= 0 || pack->contest_id >= contests->id_map_size) {
    info("%d: contest id is out of range", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  c = contests->id_map[pack->contest_id];
  if (!c) {
    info("%d: contest id is nonexistent", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  /* FIXME: check conditions */

  /* Registration is possible */
  if (!u->contests) {
    u->contests = userlist_node_alloc(USERLIST_T_CONTESTS);
    u->contests->tag = USERLIST_T_CONTESTS;
    xml_link_node_last(&u->b, u->contests);
  }
  /* check that we are already registered */
  for (r = (struct userlist_contest*) u->contests->first_down; r;
       r = (struct userlist_contest*) r->b.right) {
    ASSERT(r->b.tag == USERLIST_T_CONTEST);
    if (r->id == pack->contest_id) break;
  }
  if (r) {
    info("%d: already registered", p->id);
    send_reply(p, ULS_OK);
    return;
  }
  r = (struct userlist_contest*) userlist_node_alloc(USERLIST_T_CONTEST);
  r->b.tag = USERLIST_T_CONTEST;
  xml_link_node_last(u->contests, &r->b);
  r->id = pack->contest_id;
  if (c->autoregister) {
    r->status = USERLIST_REG_OK;
  } else {
    r->status = USERLIST_REG_PENDING;
  }
  flush_interval /= 2;
  dirty = 1;
  u->last_change_time = cur_time;
  u->last_access_time = cur_time;
  info("%d: registered", p->id);
  send_reply(p, ULS_OK);
  return;
}

static void
remove_member(struct client_state *p, int len,
              struct userlist_pk_remove_member *pack)
{
  struct userlist_user *u;
  struct userlist_members *ms;
  struct userlist_member *m;

  if (len != sizeof(*pack)) {
    bad_packet(p, "");
    return;
  }

  info("%d: remove_member: %d, %d, %d, %d",
       p->id, pack->user_id, pack->role_id, pack->pers_id, pack->serial);
  if (p->user_id <= 0) {
    info("%d: client not authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != pack->user_id) {
    info("%d: user_id does not match", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size) {
    info("%d: user id is out of range", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  u = userlist->user_map[pack->user_id];
  if (!u) {
    info("%d: user id nonexistent", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (pack->role_id < 0 || pack->role_id >= CONTEST_LAST_MEMBER) {
    err("%d: invalid role", p->id);
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  ms = u->members[pack->role_id];
  if (!ms) {
    err("%d: no members with that role", p->id);
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  if (pack->pers_id < 0 || pack->pers_id >= ms->total) {
    err("%d: invalid person", p->id);
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  m = ms->members[pack->pers_id];
  if (!m || m->serial != pack->serial) {
    err("%d: invalid person", p->id);
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }

  m = unlink_member(u, pack->role_id, pack->pers_id);
  userlist_free(&m->b);

  flush_interval /= 2;
  dirty = 1;
  u->last_change_time = cur_time;
  u->last_access_time = cur_time;
  info("%d: member removed", p->id);
  send_reply(p, ULS_OK);
}

static void
pass_descriptors(struct client_state *p, int len,
                 struct userlist_packet *pack)
{
  if (len != sizeof(*pack)) {
    bad_packet(p, "");
    return;
  }

  // cannot stack uprocessed descriptors
  if (p->client_fds[0] >= 0 || p->client_fds[1] >= 0) {
    err("%d: cannot stack unprocessed client descriptors", p->id);
    bad_packet(p, "");
    return;
  }

  p->state = STATE_READ_FDS;
}

/*
static void
simple_test(struct client_state *p, int len,
            struct userlist_packet *pack)
{
  struct client_state *q;

  if (len != sizeof (*pack)) {
    bad_packet(p, "");
    return;
  }
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("%d: two client file descriptors required", p->id);
    disconnect_client(p);
    return;
  }

  q = (struct client_state*) xcalloc(1, sizeof(*q));
  q->client_fds[0] = -1;
  q->client_fds[1] = p->client_fds[1];
  q->last_time = cur_time;
  q->id = serial_id++;
  q->user_id = -1;
  q->fd = p->client_fds[0];
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  q->state = STATE_AUTOCLOSE;
  q->write_buf = xstrdup("A test!\n");
  q->write_len = strlen(q->write_buf);
  link_client_state(q);
  info("%d: created new connection %d", p->id, q->id);
  send_reply(p, ULS_OK);
}
*/

static void
process_packet(struct client_state *p, int len, unsigned char *pack)
{
  struct userlist_packet * packet;

  if (len < sizeof(*packet)) {
    bad_packet(p, "length %d < minimum %d", len, sizeof(*packet));
    return;
  }

  packet = (struct userlist_packet *) pack;
  switch (packet->id) {
  case ULS_REGISTER_NEW:
    create_newuser(p, len, (struct userlist_pk_register_new *) pack);  
    break;
  
  case ULS_DO_LOGIN:
    login_user(p, len, (struct userlist_pk_do_login *) pack);  
    break;
    
  case ULS_CHECK_COOKIE:
    login_cookie(p, len, (struct userlist_pk_check_cookie *) pack);  
    break;

  case ULS_DO_LOGOUT:
    logout_user(p, len, (struct userlist_pk_do_logout *) pack);
    break;

  case ULS_GET_USER_INFO:
    get_user_info(p, len, (struct userlist_pk_get_user_info *) pack);
    break;

  case ULS_SET_USER_INFO:
    set_user_info(p, len, (struct userlist_pk_set_user_info *) pack);
    break;

  case ULS_SET_PASSWD:
    set_password(p, len, (struct userlist_pk_set_password *) pack);
    break;

  case ULS_GET_USER_CONTESTS:
    get_user_contests(p, len, (struct userlist_pk_get_user_info *) pack);
    break;

  case ULS_REGISTER_CONTEST:
    register_for_contest(p, len, (struct userlist_pk_register_contest*) pack);
    break;

  case ULS_REMOVE_MEMBER:
    remove_member(p, len, (struct userlist_pk_remove_member*) pack);
    break;

  case ULS_PASS_FD:
    pass_descriptors(p, len, packet);
    break;

  default:
    bad_packet(p, "request_id = %d, packet_len = %d", packet->id, len);
    return;
  }
}

static void
do_backup(void)
{
  struct tm *ptm = 0;
  unsigned char *buf = 0;
  FILE *f = 0;

  buf = alloca(strlen(config->db_path) + 64);
  if (!buf) {
    err("backup: alloca failed");
    return;
  }
  ptm = localtime(&cur_time);
  sprintf(buf, "%s.%d%02d%02d",
          config->db_path, ptm->tm_year + 1900,
          ptm->tm_mon + 1, ptm->tm_mday);
  info("backup: starting backup to %s", buf);

  if (!(f = fopen(buf, "w"))) {
    err("backup: fopen for `%s' failed: %s", buf, os_ErrorMsg());
    return;
  }
  userlist_unparse(userlist, f);
  if (ferror(f)) {
    err("backup: write failed: %s", os_ErrorMsg());
    fclose(f);
    return;
  }
  if (fclose(f) < 0) {
    err("backup: fclose() failed: %s", os_ErrorMsg());
    fclose(f);
    return;
  }

  info("backup: complete");
  last_backup = cur_time;
  backup_interval = DEFAULT_BACKUP_INTERVAL;
}

static void
flush_database(void)
{
  unsigned char *tempname = 0;
  unsigned char  basename[16];
  FILE *f = 0;

  if (!dirty) return;

  tempname = os_DirName(config->db_path);
  snprintf(basename, sizeof(basename), "/%lu", generate_random_long());
  tempname = xstrmerge1(tempname, basename);
  info("bdflush: flushing database to `%s'", tempname);
  if (!(f = fopen(tempname, "w"))) {
    err("bdflush: fopen for `%s' failed: %s", tempname, os_ErrorMsg());
    xfree(tempname);
    return;
  }
  userlist_unparse(userlist, f);
  if (ferror(f)) {
    err("bdflush: write failed: %s", os_ErrorMsg());
    xfree(tempname);
    return;
  }
  if (fclose(f) < 0) {
    err("bdflush: fclose() failed: %s", os_ErrorMsg());
    xfree(tempname);
    return;
  }
  info("bdflush: renaming temporary file to `%s'", config->db_path);
  if (rename(tempname, config->db_path) < 0) {
    err("bdflush: rename() failed: %s", os_ErrorMsg());
    unlink(tempname);
    xfree(tempname);
    return;
  }
  info("bdflush: flush complete");
  xfree(tempname);
  last_flush = cur_time;
  flush_interval = DEFAULT_FLUSH_INTERVAL;
  dirty = 0;
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

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, graceful_exit);
  signal(SIGTERM, graceful_exit);
  signal(SIGHUP, force_check_dirty);
  signal(SIGUSR1, force_flush);

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

  if (chmod(config->socket_path, 0777) < 0) {
    err("chmod() failed: %s", os_ErrorMsg());
    return 1;
  }

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

  last_cookie_check = 0;
  cookie_check_interval = 0;
  last_backup = 0;
  backup_interval = 0;

  info("initialization is ok, now serving requests");

  while (1) {
    cur_time = time(0);

    // check for cookies expiration
    if (cur_time > last_cookie_check + cookie_check_interval) {
      check_all_cookies();
    }

    // check for user account expiration
    if (cur_time > last_user_check + user_check_interval) {
      check_all_users();
    }

    // flush database
    if (cur_time > last_flush + flush_interval) {
      flush_database();
    }

    if (cur_time > last_backup + backup_interval) {
      do_backup();
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
      p->processed = 0;
      if (p->write_len > 0) {
        FD_SET(p->fd, &wset);
        //fprintf(stderr, "w: %d, %d\n", p->fd, p->write_len);
      } else {
        FD_SET(p->fd, &rset);
        //fprintf(stderr, "r: %d\n", p->fd);
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
        q->user_id = -1;
        q->client_fds[0] = -1;
        q->client_fds[1] = -1;

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
      if (FD_ISSET(p->fd, &wset) && !p->processed) {
        int w, l;

        p->processed = 1;
        l = p->write_len - p->written;
        w = write(p->fd, &p->write_buf[p->written], l);

        if (w <= 0) {
          err("%d: write() failed: %s (%d, %d, %d)", p->id, os_ErrorMsg(),
              p->fd, l, p->write_len);
          disconnect_client(p);
          goto restart_write_scan; /* UGLY :-( */
        }
        p->written += w;
        if (p->write_len == p->written) {
          p->written = 0;
          p->write_len = 0;
          xfree(p->write_buf);
          p->write_buf = 0;
          if (p->state == STATE_AUTOCLOSE) {
            info("%d: auto-disconnecting: %d, %d, %d", p->id,
                 p->fd, p->client_fds[0], p->client_fds[1]);
            disconnect_client(p);
            goto restart_write_scan;
          }
        }
      }
    }

    // check read bit and read
    while (1) {
      int l, r;

      for (p = first_client; p; p = p->next)
        if (FD_ISSET(p->fd, &rset) && !p->processed) break;
      if (!p) break;

      p->processed = 1;
      if (p->state == STATE_READ_CREDS) {
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

        p->state = STATE_READ_DATA;
        continue;
      } else if (p->state == STATE_READ_FDS) {
        struct msghdr msg;
        unsigned char msgbuf[512];
        struct cmsghdr *pmsg;
        struct iovec recv_vec[1];
        int *fds;
        int val;

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

        /*
         * actually, the first control message could be credentials
         * so we need to skip it
         */
        pmsg = CMSG_FIRSTHDR(&msg);
        while (1) {
          if (!pmsg) break;
          if (pmsg->cmsg_level == SOL_SOCKET
              && pmsg->cmsg_type == SCM_RIGHTS) break;
          pmsg = CMSG_NXTHDR(&msg, pmsg);
        }
        if (!pmsg) {
          err("%d: empty control data", p->id);
          disconnect_client(p);
          continue;
        }
        fds = (int*) CMSG_DATA(pmsg);
        if (pmsg->cmsg_len == CMSG_LEN(2 * sizeof(int))) {
          info("%d: received 2 file descriptors: %d, %d",p->id,fds[0],fds[1]);
          p->client_fds[0] = fds[0];
          p->client_fds[1] = fds[1];
        } else if (pmsg->cmsg_len == CMSG_LEN(1 * sizeof(int))) {
          info("%d: received 1 file descriptor: %d", p->id, fds[0]);
          p->client_fds[0] = fds[0];
          p->client_fds[1] = -1;
        } else {
          err("%d: invalid number of file descriptors passed", p->id);
          disconnect_client(p);
          continue;
        }

        p->state = STATE_READ_DATA;
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
      r = read(p->fd, &p->read_buf[p->read_len], l);
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
  struct stat finfo;

  if (argc == 1) goto print_usage;
  code = 1;
  if (argc != 2) goto print_usage;

  config = userlist_cfg_parse(argv[1]);
  if (!config) return 1;
  if (!config->contests_path) {
    err("<contests> tag is not set!");
    return 1;
  }
  if (!(contests = parse_contest_xml(config->contests_path))) {
    err("cannot parse contest database");
    return 1;
  }
  if (stat(config->db_path, &finfo) < 0) {
    info("user database `%s' does not exist, creating a new one",
         config->db_path);
    userlist = userlist_new();
    flush_interval = 0;
    dirty = 1;
  } else {
    userlist = userlist_parse(config->db_path);
    if(!userlist) return 1;
    flush_interval = DEFAULT_FLUSH_INTERVAL;
  }
  //userlist_unparse(userlist, stdout);

#if CONF_HAS_LIBINTL - 0 == 1
  /* load the language used */
  if (config->l10n) {
    bindtextdomain("ejudge", config->l10n_dir);
    textdomain("ejudge");
  }
#endif /* CONF_HAS_LIBINTL */

  code = do_work();

  if (socket_name) unlink(socket_name);
  if (listen_socket >= 0) close(listen_socket);
  userlist_cfg_free(config);
  return code;
  
 print_usage:
  printf("Usage: %s config-file\n", argv[0]);
  return code;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding" "va_list")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
