/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002,2003 Alexander Chernov <cher@ispras.ru> */

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

#include "userlist_cfg.h"
#include "userlist.h"
#include "pathutl.h"
#include "base64.h"
#include "userlist_proto.h"
#include "contests.h"
#include "version.h"
#include "sha.h"
#include "misctext.h"

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
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#endif

#define DEFAULT_FLUSH_INTERVAL 600
#define DEFAULT_COOKIE_CHECK_INTERVAL 60
#define DEFAULT_USER_CHECK_INTERVAL 600
#define DEFAULT_BACKUP_INTERVAL (24*60*60)
#define CLIENT_TIMEOUT 600
#define DEFAULT_SERVER_USE_COOKIES 1

#define CONN_ERR(msg, ...) err("%d: %s: " msg, p->id, __FUNCTION__, ## __VA_ARGS__)
#define CONN_INFO(msg, ...) info("%d: %s: " msg, p->id, __FUNCTION__, ## __VA_ARGS__)
#define CONN_BAD(msg, ...) do { err("%d: %s: bad packet: " msg, p->id, __FUNCTION__, ##__VA_ARGS__); disconnect_client(p); } while (0)

// server connection states
enum
  {
    STATE_READ_CREDS,
    STATE_READ_DATA,
    STATE_READ_FDS,
    STATE_AUTOCLOSE,
  };

struct userlist_list * userlist;

struct contest_extra
{
  int nref;
  int id;
  key_t sem_key;
  key_t shm_key;
  int sem_id;
  int shm_id;
  struct userlist_table *tbl;
};

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
  int priv_level;
  unsigned long long cookie;
  unsigned long ip;

  // user capabilities
  //opcap_t caps;

  // passed file descriptors
  int client_fds[2];

  // attached contest exchange info
  struct contest_extra *cnts_extra;
};

static struct userlist_cfg *config;
static int listen_socket = -1;
static int urandom_fd = -1;
static char *socket_name;
static struct client_state *first_client;
static struct client_state *last_client;
static int serial_id = 1;
static unsigned char *program_name;
static struct contest_extra **contest_extras;
static int contest_extras_size;

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
static int interrupt_signaled;

/* the map from system uids into the local uids */
static int *system_uid_map;
static size_t system_uid_map_size;

/* Various strings subject for localization */
#define _(x) x
static unsigned char const * const status_str_map[] =
{
  _("<font color=\"green\">OK</font>"),
  _("<font color=\"magenta\">Pending</font>"),
  _("<font color=\"red\">Rejected</font>"),
};
static char const * const member_string[] =
{
  _("Contestant"),
  _("Reserve"),
  _("Coach"),
  _("Advisor"),
  _("Guest")
};
static char const * const member_string_pl[] =
{
  _("Contestants"),
  _("Reserves"),
  _("Coaches"),
  _("Advisors"),
  _("Guests")
};
static char const * const member_status_string[] =
{
  0,
  _("School student"),
  _("Student"),
  _("Magistrant"),
  _("PhD student"),
  _("School teacher"),
  _("Professor"),
  _("Scientist"),
  _("Other")
};
#undef _

#if CONF_HAS_LIBINTL - 0 == 1
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define FIRST_COOKIE(u) ((struct userlist_cookie*) (u)->cookies->first_down)
#define NEXT_COOKIE(c)  ((struct userlist_cookie*) (c)->b.right)
#define FIRST_CONTEST(u) ((struct userlist_contest*)(u)->contests->first_down)
#define NEXT_CONTEST(c)  ((struct userlist_contest*)(c)->b.right)

static struct contest_extra *
attach_contest_extra(int id, struct contest_desc *cnts)
{
  struct contest_extra *ex = 0;
  key_t ipc_key, shm_key, sem_key;
  int sem_id = -1, shm_id = -1;
  void *shm_addr = 0;

  ASSERT(id > 0);
  ASSERT(cnts);
  if (!contest_extras || contest_extras_size >= id) {
    int new_size = contest_extras_size;
    struct contest_extra **new_extras = 0;

    if (!new_size) new_size = 16;
    while (new_size <= id) new_size *= 2;
    new_extras = xcalloc(new_size, sizeof(new_extras[0]));
    if (contest_extras) {
      memcpy(new_extras, contest_extras,
             sizeof(new_extras[0]) * contest_extras_size);
      xfree(contest_extras);
    }
    contest_extras = new_extras;
    contest_extras_size = new_size;
  }
  if (contest_extras[id]) {
    contest_extras[id]->nref++;
    return contest_extras[id];
  }

  info("creating shared contest info for %d", id);
  ex = xcalloc(1, sizeof(*ex));
  ex->nref = 1;
  ex->id = id;

  ipc_key = ftok(program_name, id);
  sem_key = ipc_key;
  shm_key = ipc_key;
  while (1) {
    sem_id = semget(sem_key, 1, 0666 | IPC_CREAT | IPC_EXCL);
    if (sem_id >= 0) break;
    if (errno != EEXIST) {
      err("semget failed: %s", os_ErrorMsg());
      goto cleanup;
    }
    sem_key++;
  }
  if (semctl(sem_id, 0, SETVAL, 1) < 0) {
    err("semctl failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  while (1) {
    shm_id = shmget(shm_key, sizeof(struct userlist_table),
                    0644 | IPC_CREAT | IPC_EXCL);
    if (shm_id >= 0) break;
    if (errno != EEXIST) {
      err("shmget failed: %s", os_ErrorMsg());
      goto cleanup;
    }
    shm_key++;
  }
  if ((int) (shm_addr = shmat(shm_id, 0, 0)) == -1) {
    err("shmat failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  memset(shm_addr, 0, sizeof(struct userlist_table));
  ex->sem_key = sem_key;
  ex->shm_key = shm_key;
  ex->sem_id = sem_id;
  ex->shm_id = shm_id;
  ex->tbl = shm_addr;
  contest_extras[id] = ex;
  info("done");
  return ex;

 cleanup:
  if (shm_addr) shmdt(shm_addr);
  if (shm_id >= 0) shmctl(shm_id, IPC_RMID, 0);
  if (sem_id >= 0) semctl(sem_id, 0, IPC_RMID);
  xfree(ex);
  return 0;
}

static struct contest_extra *
detach_contest_extra(struct contest_extra *ex)
{
  if (!ex) return 0;

  ASSERT(ex->id > 0 && ex->id < contest_extras_size);
  ASSERT(ex == contest_extras[ex->id]);
  if (--ex->nref > 0) return 0;
  info("destroying shared contest info for %d", ex->id);
  ex->tbl->vintage = 0xffff;    /* the client must note this change */
  if (shmdt(ex->tbl) < 0) info("shmdt failed: %s", os_ErrorMsg());
  if (shmctl(ex->shm_id,IPC_RMID,0)<0) info("shmctl failed: %s",os_ErrorMsg());
  if (semctl(ex->sem_id,0,IPC_RMID)<0) info("semctl failed: %s",os_ErrorMsg());
  contest_extras[ex->id] = 0;
  memset(ex, 0, sizeof(*ex));
  xfree(ex);
  info("done");
  return 0;
}

static void
lock_userlist_table(struct contest_extra *ex)
{
  struct sembuf lock;

  ASSERT(ex);
  lock.sem_num = 0;
  lock.sem_op = -1;
  lock.sem_flg = SEM_UNDO;      /* in case of crash */
  while (1) {
    if (!semop(ex->sem_id, &lock, 1)) break;
    if (errno != EINTR) {
      err("semop failed: %s", os_ErrorMsg());
      exit(1);                  /* FIXME: exit gracefully */
    }
    info("semop restarted after signal");
  }
}
static void
unlock_userlist_table(struct contest_extra *ex)
{
  struct sembuf unlock;

  ASSERT(ex);
  unlock.sem_num = 0;
  unlock.sem_op = 1;
  unlock.sem_flg = SEM_UNDO;
  if (semop(ex->sem_id, &unlock, 1) < 0) {
    err("semop failed: %s", os_ErrorMsg());
    exit(1);                  /* FIXME: exit gracefully */
  }
}
static void
update_userlist_table(int cnts_id)
{
  struct userlist_table *ntb;
  int i = 0, si = 4;
  struct userlist_user *u;
  struct userlist_contest *c;
  unsigned char *n;
  int name_len;
  int login_len, errcode;
  struct contest_extra *ex;
  struct contest_desc *cnts = 0;

  if ((errcode = contests_get(cnts_id, &cnts)) < 0) {
    // FIXME: what to do if the contest unexpectedly disappeared?
    err("contests_get failed: %s", contests_strerror(-errcode));
    abort();
  }
  if (cnts_id >= contest_extras_size || !contest_extras[cnts_id]) return;

  ex = contest_extras[cnts_id];
  ntb = alloca(sizeof(*ntb));
  memset(ntb, 0, sizeof(*ntb));
  for (u = (struct userlist_user*) userlist->b.first_down;
       u; u = (struct userlist_user*) u->b.right) {
    ASSERT(u->b.tag == USERLIST_T_USER);
    if (!u->contests) continue;
    for (c = (struct userlist_contest*) u->contests->first_down;
         c; c = (struct userlist_contest*) c->b.right) {
      if (c->id == cnts_id) break;
    }
    if (!c) continue;
    if (c->status != USERLIST_REG_OK) continue;
    //if ((c->flags & USERLIST_UC_BANNED)) continue;
    // FIXME handle invisibility
    n = u->name;
    if (!n || !*n) n = u->login;
    if (!n) n = "";
    name_len = strlen(n);
    login_len = strlen(u->login);

    if (u->id > 65535) {
      err("userlist_table: user id exceeds 65535");
      continue;
    }
    if (i >= USERLIST_TABLE_SIZE) {
      err("userlist_table: number of users for %d exceeds %d",
          cnts_id, USERLIST_TABLE_SIZE);
      break;
    }
    if (si + name_len + login_len + 2 > USERLIST_TABLE_POOL) {
      err("userlist_table: string pool for %d exceeds %d",
          cnts_id, USERLIST_TABLE_POOL);
      break;
    }
    ntb->users[i].user_id = u->id;
    ntb->users[i].flags = c->flags;
    ntb->users[i].login_idx = si;
    strcpy(ntb->pool + si, u->login);
    si += login_len + 1;
    ntb->users[i].name_idx = si;
    strcpy(ntb->pool + si, n);
    si += name_len + 1;
    i++;
  }
  ntb->total = i;
  ntb->vintage = ex->tbl->vintage + 1;
  if (ntb->vintage == 0xffff) ntb->vintage = 1;
  lock_userlist_table(ex);
  memcpy(ex->tbl, ntb, sizeof(*ntb));
  unlock_userlist_table(ex);
}

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

/* build the map from the system uids to the local uids */
static void
build_system_uid_map(struct xml_tree *xml_user_map)
{
  struct xml_tree *um;
  struct userlist_cfg_user_map *m;
  int max_system_uid = -1, i;

  if (!xml_user_map || !xml_user_map->first_down) return;
  for (um = xml_user_map->first_down; um; um = um->right) {
    m = (struct userlist_cfg_user_map*) um;
    if (m->system_uid < 0) continue;
    if (m->system_uid > max_system_uid)
      max_system_uid = m->system_uid;
  }

  if (max_system_uid < 0) return;
  system_uid_map_size = max_system_uid + 1;
  XCALLOC(system_uid_map, system_uid_map_size);
  for (i = 0; i < system_uid_map_size; i++)
    system_uid_map[i] = -1;
  // system root is always mapped to the local root
  system_uid_map[0] = 0;
  for (um = xml_user_map->first_down; um; um = um->right) {
    m = (struct userlist_cfg_user_map*) um;
    if (m->system_uid < 0) continue;
    if (!strcmp(m->local_user_str, "root")) {
      i = 0;
    } else if (!strcmp(m->local_user_str, "guest")) {
      i = -1;
    } else {
      for (i = 1; i < userlist->user_map_size; i++) {
        if (!userlist->user_map[i]) continue;
        if (!userlist->user_map[i]->login) continue;
        if (!strcmp(userlist->user_map[i]->login, m->local_user_str)) break;
      }
      if (i >= userlist->user_map_size) {
        err("build_system_uid_map: no local user %s", m->local_user_str);
        i = -1;
      }
    }
    info("system user %s(%d) is mapped to local user %s(%d)",
         m->system_user_str, m->system_uid, m->local_user_str, i);
    system_uid_map[m->system_uid] = i;
  }
}

static void
remove_from_system_uid_map(int uid)
{
  int i;

  if (uid <= 0) return;
  for (i = 0; i < system_uid_map_size; i++) {
    if (system_uid_map[i] == uid)
      system_uid_map[i] = -1;
  }
}

/* remove the entry from the system uid->local uid map upon removal */

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
  detach_contest_extra(p->cnts_extra);

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

static void graceful_exit(void) __attribute__((noreturn));
static void
graceful_exit(void)
{
  int i;

  if (config && config->socket_path) {
    unlink(config->socket_path);
  }
  // we need to deallocate shared memory and semafores
  if (contest_extras) {
    for (i = 1; i < contest_extras_size; i++) {
      if (!contest_extras[i]) continue;
      contest_extras[i]->nref = 1;
      detach_contest_extra(contest_extras[i]);
    }
  }
  exit(0);
}
static void
interrupt_signal(int s)
{
  interrupt_signaled = 1;
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

/* this is not good! */
static int
get_uid_caps(const opcaplist_t *list, int uid, opcap_t *pcap)
{
  struct userlist_user *u = 0;

  if (uid <= 0 || uid >= userlist->user_map_size) return -1;
  if (!(u = userlist->user_map[uid])) return -1;
  return opcaps_find(list, u->login, pcap);
}

static int
is_db_capable(struct client_state *p, int bit)
{
  opcap_t caps;

  if (get_uid_caps(&config->capabilities, p->user_id, &caps) < 0) {
    CONN_ERR("user %d has no capabilities for the user database", p->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  if (opcaps_check(caps, bit) < 0) {
    CONN_ERR("user %d has no %d capability", p->user_id, bit);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  return 0;
}

static int
is_cnts_capable(struct client_state *p, struct contest_desc *cnts, int bit)
{
  opcap_t caps;

  if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) < 0) {
    CONN_ERR("user %d has no capabilities for contest %d",
             p->user_id, cnts->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  if (opcaps_check(caps, bit) < 0) {
    CONN_ERR("user %d has no %d capability for contest %d",
             p->user_id, bit, cnts->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  return 0;
}

/*
 * FIXME: this is terribly wrong, since a user may have capabilities
 * FIXME: for some contest, but not for the userbase.
 * FIXME: But lookup of all the contest is very expensive,
 * FIXME: so it is not currently supported.
 */
static int
is_privileged_user(struct userlist_user *u)
{
  opcap_t caps;

  return opcaps_find(&config->capabilities, u->login, &caps);
}

struct passwd_internal
{
  unsigned char pwds[3][64];
};
static void
make_sha1_ascii(void const *data, size_t size, unsigned char *out)
{
  unsigned char buf[20], *s = out;
  int i;

  sha_buffer(data, size, buf);
  for (i = 0; i < 20; i++) {
    s += sprintf(s, "%02x", buf[i]);
  }
}
static int
passwd_convert_to_internal(unsigned char const *pwd_plain,
                           struct passwd_internal *p)
{
  int len;

  if (!pwd_plain) return -1;
  ASSERT(p);
  len = strlen(pwd_plain);
  if (len > 32) return -1;
  memset(p, 0, sizeof(*p));
  strcpy(p->pwds[0], pwd_plain);
  base64_encode(pwd_plain, len, p->pwds[1]);
  make_sha1_ascii(pwd_plain, len, p->pwds[2]);
  return 0;
}
static int
passwd_check(struct passwd_internal *u,
             struct userlist_passwd const *t)
{
  int len, i, j;

  ASSERT(t->method >= USERLIST_PWD_PLAIN && t->method <= USERLIST_PWD_SHA1);
  if (!strcmp(u->pwds[t->method], t->b.text)) return 0;
  // try to remove all whitespace chars and compare again
  len = strlen(u->pwds[0]);
  for (i = 0, j = 0; i < len; i++) {
    if (u->pwds[0][i] > ' ') u->pwds[0][j++] = u->pwds[0][i];
  }
  u->pwds[0][j] = u->pwds[0][i];
  len = strlen(u->pwds[0]);
  base64_encode(u->pwds[0], len, u->pwds[1]);
  make_sha1_ascii(u->pwds[0], len, u->pwds[2]);
  if (!strcmp(u->pwds[t->method], t->b.text)) return 0;
  return -1;
}

static struct userlist_user *
allocate_new_user(void)
{
  struct userlist_user *u = 0;
  int i;
  struct userlist_user **new_map = 0;
  size_t new_size;

  u = (struct userlist_user*) userlist_node_alloc(USERLIST_T_USER);
  u->b.tag = USERLIST_T_USER;
  xml_link_node_last(&userlist->b, &u->b);

  for (i = 1; i < userlist->user_map_size && userlist->user_map[i]; i++);
  if (i >= userlist->user_map_size) {

    new_size = userlist->user_map_size * 2;
    new_map = (struct userlist_user**) xcalloc(new_size, sizeof(new_map[0]));
    memcpy(new_map, userlist->user_map,
           userlist->user_map_size * sizeof(new_map[0]));
    xfree(userlist->user_map);
    userlist->user_map = new_map;
    userlist->user_map_size = new_size;
    info("userlist: user_map extended to %d", new_size);
  }
  userlist->user_map[i] = u;
  u->id = i;
  return u;
}

static void
cmd_register_new(struct client_state *p,
                 int pkt_len,
                 struct userlist_pk_register_new * data)
{
  struct userlist_user * user;
  char * buf;
  unsigned char * login;
  unsigned char * email;
  unsigned char urlbuf[1024], *urlptr = urlbuf;
  int login_len, email_len, errcode, exp_pkt_len;
  struct userlist_passwd *pwd;
  unsigned char passwd_buf[64];
  struct contest_desc *cnts = 0;
  unsigned char * originator_email = 0;

  // validate packet
  login = data->data;
  login_len = strlen(login);
  if (login_len != data->login_length) {
    CONN_BAD("login length mismatch: %d, %d", login_len, data->login_length);
    return;
  }
  email = data->data + data->login_length + 1;
  email_len = strlen(email);
  if (email_len != data->email_length) {
    CONN_BAD("email length mismatch: %d, %d", email_len, data->email_length);
    return;
  }
  exp_pkt_len = sizeof(*data) + login_len + email_len;
  if (pkt_len != exp_pkt_len) {
    CONN_BAD("packet length mismatch: %d, %d", pkt_len, exp_pkt_len);
    return;
  }

  CONN_INFO("%s, %s, %s, %ld",
            unparse_ip(data->origin_ip), login, email, data->contest_id);

  if (data->contest_id != 0) {
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      CONN_ERR("invalid contest id: %s", contests_strerror(-errcode));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
  }
  if (cnts && cnts->register_email) {
    originator_email = cnts->register_email;
  } else if (config->register_email) {
    originator_email = config->register_email;
  } else {
    originator_email = "team@contest.cmc.msu.ru";
  }

  if (cnts && cnts->register_url) {
    urlptr += sprintf(urlptr, "%s", cnts->register_url);
  } else if (config->register_url) {
    urlptr += sprintf(urlptr, "%s", config->register_url);
  } else {
    urlptr += sprintf(urlptr, "%s",
                      "http://contest.cmc.msu.ru/cgi-bin/register");
  }
  urlptr += sprintf(urlptr, "?action=%d&login=%s", 3, login);
  if (data->contest_id > 0) {
    urlptr += sprintf(urlptr, "&contest_id=%ld", data->contest_id);
  }
  if (data->locale_id >= 0) {
    urlptr += sprintf(urlptr, "&locale_id=%d", data->locale_id);
  }

  user = (struct userlist_user*) userlist->b.first_down;
  while (user) {
    if (!strcmp(user->login,login)) {
      //Login already exists
      send_reply(p, -ULS_ERR_LOGIN_USED);
      CONN_ERR("login already exists");
      return;
    }
    user = (struct userlist_user*) user->b.right;
  }

  ASSERT(!user);
  user = allocate_new_user();

  user->login = calloc(1,data->login_length+1);
  strcpy(user->login,login);
  user->email = calloc(1,data->email_length+1);
  strcpy(user->email,email);
  user->name = xstrdup("");
  user->default_use_cookies = -1;

  generate_random_password(8, passwd_buf);
  pwd = (struct userlist_passwd*) userlist_node_alloc(USERLIST_T_PASSWORD);
  user->register_passwd = pwd;
  xml_link_node_last(&user->b, &pwd->b);
  pwd->method = USERLIST_PWD_PLAIN;
  pwd->b.text = xstrdup(passwd_buf);

  setup_locale(data->locale_id);
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
           user->login, pwd->b.text);
  send_email_message(user->email,
                     originator_email,
                     NULL,
                     _("You have been registered"),
                     buf);
  free(buf);
  setup_locale(0);
  send_reply(p,ULS_OK);
  CONN_INFO("ok, user_id = %d", user->id);

  user->registration_time = cur_time;
  dirty = 1;
  flush_interval /= 2;
}

static struct userlist_cookie *
create_cookie(struct userlist_user * user)
{
  struct userlist_cookie * cookie;

  cookie = xcalloc(1,sizeof(struct userlist_cookie));

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
    cookies->last_down = cookie->b.left;
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
do_remove_user(struct userlist_user *u)
{
  struct userlist_contest *reg;

  // scan all registration
  if (u->contests) {
    for (reg = FIRST_CONTEST(u); reg; reg = NEXT_CONTEST(reg)) {
      if (reg->status == USERLIST_REG_OK)
        update_userlist_table(reg->id);
    }
  }

  remove_from_system_uid_map(u->id);
  userlist_remove_user(userlist, u);
  dirty = 1;
  flush_interval /= 2;
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
        do_remove_user(usr);
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
cmd_do_login(struct client_state *p,
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
  struct passwd_internal pwdint;

  login = data->data;
  password = data->data + data->login_length + 1;

  if (strlen(login) != data->login_length
      || strlen(password) != data->password_length) {
    CONN_BAD("packet length mismatch");
    return;
  }
  CONN_INFO("%s, %s", unparse_ip(data->origin_ip), login);

  if (p->user_id >= 0) {
    CONN_ERR("this connection already authentificated");
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  if (passwd_convert_to_internal(password, &pwdint) < 0) {
    CONN_ERR("invalid password");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  user = (struct userlist_user*) userlist->b.first_down;
  while (user) {
    ASSERT(user->b.tag == USERLIST_T_USER);
    if (!strcmp(user->login,login)) {
      if (!user->register_passwd || !user->register_passwd->b.text) {
        CONN_INFO("EMPTY PASSWORD");
        send_reply(p, -ULS_ERR_INVALID_PASSWORD);
        user->last_access_time = cur_time;
        dirty = 1;
        return;
      }
      if (passwd_check(&pwdint, user->register_passwd) >= 0) {
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
          cookie->user = user;
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
        answer->contest_id = data->contest_id;
        answer->login_len = strlen(user->login);
        name = answer->data + answer->login_len + 1;
        answer->name_len = strlen(user->name);
        strcpy(answer->data, user->login);
        strcpy(name, user->name);
        enqueue_reply_to_client(p,ans_len,answer);

        user->last_login_time = cur_time;
        user->last_access_time = cur_time;
        dirty = 1;
        CONN_INFO("OK, cookie = %llx", answer->cookie);
        p->user_id = user->id;
        p->ip = data->origin_ip;
        p->cookie = answer->cookie;
        return;
      } else {
        //Incorrect password
        CONN_INFO("BAD PASSWORD");
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
  CONN_INFO("BAD USER");
}

static void
cmd_team_login(struct client_state *p, int pkt_len,
               struct userlist_pk_do_login * data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  struct userlist_user *u = 0;
  struct passwd_internal pwdint;
  struct contest_desc *cnts = 0;
  struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  struct userlist_cookie *cookie;
  int out_size = 0, login_len, name_len;
  int i, errcode;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet length is too small: %d", pkt_len);
    return;
  }
  login_ptr = data->data;
  if (strlen(login_ptr) != data->login_length) {
    CONN_BAD("login length mismatch");
    return;
  }
  passwd_ptr = login_ptr + data->login_length + 1;
  if (strlen(passwd_ptr) != data->password_length) {
    CONN_BAD("password length mismatch");
    return;
  }
  if (pkt_len != sizeof(*data)+data->login_length+data->password_length) {
    CONN_BAD("packet length mismatch");
    return;
  }
  CONN_INFO("%s, %s, %ld, %d, %d",
            unparse_ip(data->origin_ip), login_ptr, data->contest_id,
            data->locale_id, data->use_cookies);
  if (p->user_id >= 0) {
    CONN_ERR("this connection already authentificated");
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    CONN_BAD("password parse error");
    return;
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!contests_check_team_ip(data->contest_id, data->origin_ip)) {
    CONN_ERR("IP is not allowed");
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }
  if (cnts->client_disable_team) {
    CONN_ERR("team login is disabled");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  for (i = 1; i < userlist->user_map_size; i++) {
    if (!(u = userlist->user_map[i])) continue;
    if (!strcmp(u->login, login_ptr)) break;
  }
  if (i >= userlist->user_map_size) {
    CONN_ERR("BAD LOGIN");
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if(passwd_check(&pwdint,u->team_passwd?u->team_passwd:u->register_passwd)<0){
    CONN_ERR("BAD PASSWORD");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (u->contests) {
    for (c = (struct userlist_contest*) u->contests->first_down;
         c; c = (struct userlist_contest*) c->b.right) {
      if (c->id == data->contest_id) break;
    }
  }
  if (!c || c->status != USERLIST_REG_OK || (c->flags & USERLIST_UC_BANNED)) {
    CONN_ERR("not allowed to participate");
    send_reply(p, -ULS_ERR_CANNOT_PARTICIPATE);
    return;
  }

  login_len = strlen(u->login);
  name_len = strlen(u->name);
  out_size = sizeof(*out) + login_len + name_len + 2;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  if (data->use_cookies == -1) {
    data->use_cookies = u->default_use_cookies;
  }
  if (data->use_cookies == -1) {
    // FIXME: system default
    data->use_cookies = 0;
  }
  if (data->locale_id == -1) {
    data->locale_id = 0;
  }
  if (data->use_cookies) {
    cookie = create_cookie(u);
    cookie->user = u;
    cookie->ip = data->origin_ip;
    cookie->cookie = generate_random_cookie();
    cookie->expire = cur_time + 60 * 60 * 24;
    cookie->contest_id = data->contest_id;
    cookie->locale_id = data->locale_id;
    out->cookie = cookie->cookie;
    out->reply_id = ULS_LOGIN_COOKIE;
  } else {
    out->reply_id = ULS_LOGIN_OK;
  }
  out->user_id = u->id;
  out->contest_id = data->contest_id;
  out->locale_id = data->locale_id;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, u->name);
  
  p->user_id = u->id;
  p->ip = data->origin_ip;
  p->cookie = out->cookie;
  enqueue_reply_to_client(p, out_size, out);
  dirty = 1;
  u->last_login_time = cur_time;
  CONN_INFO("%d,%s,%llx", u->id, u->login,out->cookie);
}

static void
cmd_priv_login(struct client_state *p, int pkt_len,
                    struct userlist_pk_do_login *data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  struct contest_desc *cnts = 0;
  struct passwd_internal pwdint;
  struct userlist_user *u = 0;
  struct userlist_pk_login_ok *out = 0;
  int i, priv_level, login_len, name_len;
  size_t out_size = 0, errcode;
  struct userlist_cookie *cookie;
  opcap_t caps;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet length too small: %d", pkt_len);
    return;
  }
  login_ptr = data->data;
  if (strlen(login_ptr) != data->login_length) {
    CONN_BAD("login length mismatch");
    return;
  }
  passwd_ptr = login_ptr + data->login_length + 1;
  if (strlen(passwd_ptr) != data->password_length) {
    CONN_BAD("password length mismatch");
    return;
  }
  if (pkt_len != sizeof(*data) + data->login_length + data->password_length) {
    CONN_BAD("packet length mismatch");
    return;
  }

  CONN_INFO("%s, %s, %ld, %d, %d",
            unparse_ip(data->origin_ip), login_ptr, data->contest_id,
            data->locale_id, data->use_cookies);
  if (p->user_id >= 0) {
    CONN_ERR("this connection already authentificated");
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    CONN_BAD("password parse error");
    return;
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (data->priv_level <= 0 || data->priv_level > PRIV_LEVEL_ADMIN) {
    CONN_ERR("invalid privelege level: %d", data->priv_level);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  for (i = 1; i < userlist->user_map_size; i++) {
    if (!(u = userlist->user_map[i])) continue;
    if (!strcmp(u->login, login_ptr)) break;
  }
  if (i >= userlist->user_map_size) {
    CONN_ERR("BAD LOGIN");
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (passwd_check(&pwdint, u->register_passwd) < 0) {
    CONN_ERR("BAD PASSWORD");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  // check user capabilities
  if (opcaps_find(&cnts->capabilities, login_ptr, &caps) < 0) {
    CONN_ERR("the user is not privileged");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  priv_level = 0;
  switch (data->priv_level) {
  case PRIV_LEVEL_OBSERVER:
    priv_level = OPCAP_OBSERVER_LOGIN;
    break;
  case PRIV_LEVEL_JUDGE:
    priv_level = OPCAP_JUDGE_LOGIN;
    break;
  case PRIV_LEVEL_ADMIN:
    priv_level = OPCAP_MASTER_LOGIN;
    break;
  default:
    SWERR(("unhandled tag"));
  }
  if (opcaps_check(caps, priv_level) < 0) {
    CONN_ERR("the user cannot have the required privilege level");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  login_len = strlen(u->login);
  name_len = strlen(u->name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  if (data->use_cookies == -1) {
    data->use_cookies = u->default_use_cookies;
  }
  if (data->use_cookies == -1) {
    // FIXME: system default
    data->use_cookies = 0;
  }
  if (data->locale_id == -1) {
    data->locale_id = 0;
  }
  if (data->use_cookies) {
    cookie = create_cookie(u);
    cookie->user = u;
    cookie->ip = data->origin_ip;
    cookie->cookie = generate_random_cookie();
    cookie->expire = cur_time + 60 * 60 * 24;
    cookie->contest_id = data->contest_id;
    cookie->locale_id = data->locale_id;
    cookie->priv_level = data->priv_level;
    out->cookie = cookie->cookie;
    out->reply_id = ULS_LOGIN_COOKIE;
  } else {
    out->reply_id = ULS_LOGIN_OK;
  }
  out->user_id = u->id;
  out->contest_id = data->contest_id;
  out->locale_id = data->locale_id;
  out->priv_level = data->priv_level;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, u->name);
  
  p->user_id = u->id;
  p->priv_level = data->priv_level;
  p->cookie = out->cookie;
  p->ip = data->origin_ip;
  enqueue_reply_to_client(p, out_size, out);
  dirty = 1;
  u->last_login_time = cur_time;
  CONN_INFO("%d,%s,%llx", u->id, u->login,out->cookie);
}

static void
cmd_check_cookie(struct client_state *p,
                 int pkt_len,
                 struct userlist_pk_check_cookie * data)
{
  struct userlist_user * user;
  struct userlist_pk_login_ok * answer;
  int anslen;
  struct userlist_cookie * cookie;
  unsigned char *name_beg;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  CONN_INFO("ip = %s, cookie = %llx",
            unparse_ip(data->origin_ip), data->cookie);

  // cannot login twice
  if (p->user_id >= 0) {
    CONN_ERR("this connection already authentificated");
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
            if (data->contest_id != 0) {
              cookie->contest_id = data->contest_id;
              dirty = 1;
              user->last_minor_change_time = cur_time;
            }
            answer->locale_id = cookie->locale_id;
            answer->reply_id = ULS_LOGIN_COOKIE;
            answer->user_id = user->id;
            answer->contest_id = cookie->contest_id;
            answer->login_len = strlen(user->login);
            name_beg = answer->data + answer->login_len + 1;
            answer->name_len = strlen(user->name);
            answer->cookie = cookie->cookie;
            strcpy(answer->data, user->login);
            strcpy(name_beg, user->name);
            enqueue_reply_to_client(p,anslen,answer);
            user->last_login_time = cur_time;
            dirty = 1;
            CONN_INFO("OK: %d, %s", user->id, user->login);
            p->user_id = user->id;
            p->ip = data->origin_ip;
            p->cookie = data->cookie;
            return;
          }
          cookie = (struct userlist_cookie*) cookie->b.right;
        }
      }
    }
    user = (struct userlist_user*) user->b.right;
  }

  // cookie not found
  CONN_INFO("FAILED");
  send_reply(p, -ULS_ERR_NO_COOKIE);
}

static void
cmd_team_check_cookie(struct client_state *p, int pkt_len,
                      struct userlist_pk_check_cookie * data)
{
  struct contest_desc *cnts = 0;
  struct userlist_user *u = 0;
  struct userlist_cookie *cookie = 0;
  struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  int i, out_size = 0, login_len = 0, name_len = 0, errcode;
  unsigned char *login_ptr, *name_ptr;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  CONN_INFO("%s, %ld, %llx, %d",
            unparse_ip(data->origin_ip), data->contest_id,
            data->cookie, data->locale_id);
  if (p->user_id >= 0) {
    CONN_ERR("this connection already authentificated");
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (data->contest_id) {
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      CONN_ERR("invalid contest: %s", contests_strerror(-errno));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
    if (cnts->client_disable_team) {
      CONN_ERR("team login is disabled");
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  }
  if (!data->cookie) {
    CONN_ERR("cookie value is 0");
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  // FIXME: this is quite inefficient
  for (i = 1; i < userlist->user_map_size; i++) {
    if (!(u = userlist->user_map[i])) continue;
    if (!u->cookies) continue;
    for (cookie = (struct userlist_cookie*) u->cookies->first_down;
         cookie; cookie = (struct userlist_cookie*) cookie->b.right) {
      if (cookie->ip == data->origin_ip
          && !cookie->priv_level
          && cookie->contest_id == data->contest_id
          && cookie->expire > cur_time
          && cookie->cookie == data->cookie) break;
    }
    if (cookie) break;
  }
  if (i >= userlist->user_map_size) {
    CONN_ERR("cookie not found");
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  if (!data->contest_id) {
    data->contest_id = cookie->contest_id;
  }
  if (data->locale_id == -1) {
    data->locale_id = cookie->locale_id;
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errno));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!contests_check_team_ip(data->contest_id, data->origin_ip)) {
    CONN_ERR("IP is not allowed");
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }
  if (u->contests) {
    for (c = (struct userlist_contest*) u->contests->first_down;
         c; c = (struct userlist_contest*) c->b.right) {
      if (c->id == data->contest_id) break;
    }
  }
  if (!c || c->status != USERLIST_REG_OK || (c->flags & USERLIST_UC_BANNED)) {
    CONN_ERR("not allowed to participate");
    send_reply(p, -ULS_ERR_CANNOT_PARTICIPATE);
    return;
  }

  if (data->contest_id > 0) {
    cookie->contest_id = data->contest_id;
    dirty = 1;
    u->last_minor_change_time = cur_time;
  }

  login_len = strlen(u->login);
  name_len = strlen(u->name);
  out_size = sizeof(*out) + login_len + name_len + 2;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  cookie->locale_id = data->locale_id;
  out->cookie = cookie->cookie;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = cookie->contest_id;
  out->locale_id = data->locale_id;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, u->name);
  
  p->user_id = u->id;
  p->ip = data->origin_ip;
  p->cookie = data->cookie;
  enqueue_reply_to_client(p, out_size, out);
  dirty = 1;
  u->last_login_time = cur_time;
  CONN_INFO("%d,%s", u->id, u->login);
}

static void
cmd_priv_check_cookie(struct client_state *p,
                      int pkt_len,
                      struct userlist_pk_check_cookie *data)
{
  struct contest_desc *cnts = 0;
  struct userlist_user *u = 0;
  struct userlist_cookie *cookie = 0;
  struct userlist_pk_login_ok *out;
  size_t login_len, name_len, out_size;
  unsigned char *login_ptr, *name_ptr;
  int priv_level, i, errcode;
  opcap_t caps;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  CONN_INFO("%s, %ld, %llx",
            unparse_ip(data->origin_ip), data->contest_id, data->cookie);
  if (p->user_id >= 0) {
    CONN_ERR("this connection already authentificated");
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (!data->contest_id) {
    CONN_ERR("contest_id is not specified");
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!data->cookie) {
    CONN_ERR("cookie value is 0");
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (!data->origin_ip) {
    CONN_ERR("origin_ip is not set");
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (data->priv_level <= 0 || data->priv_level > PRIV_LEVEL_ADMIN) {
    CONN_ERR("invalid privilege level");
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  for (i = 1; i < userlist->user_map_size; i++) {
    if (!(u = userlist->user_map[i])) continue;
    if (!u->cookies) continue;
    for (cookie = (struct userlist_cookie*) u->cookies->first_down;
         cookie; cookie = (struct userlist_cookie*) cookie->b.right) {
      if (cookie->ip == data->origin_ip
          && cookie->contest_id == data->contest_id
          && cookie->expire > cur_time
          && cookie->priv_level > 0
          && cookie->cookie == data->cookie) break;
    }
    if (cookie) break;
  }
  if (i >= userlist->user_map_size) {
    CONN_ERR("cookie not found");
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  // check user capabilities
  if (get_uid_caps(&cnts->capabilities, u->id, &caps) < 0) {
    CONN_ERR("the user is not privileged");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  priv_level = 0;
  switch (data->priv_level) {
  case PRIV_LEVEL_OBSERVER:
    priv_level = OPCAP_OBSERVER_LOGIN;
    break;
  case PRIV_LEVEL_JUDGE:
    priv_level = OPCAP_JUDGE_LOGIN;
    break;
  case PRIV_LEVEL_ADMIN:
    priv_level = OPCAP_MASTER_LOGIN;
    break;
  default:
    abort();
  }
  if (opcaps_check(caps, priv_level) < 0) {
    CONN_ERR("the user cannot have the required privilege level");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  /* everything is ok, update cookie */
  if (data->locale_id >= 0) {
    cookie->locale_id = data->locale_id;
    dirty = 1;
    u->last_minor_change_time = cur_time;
  }
  if (data->priv_level != cookie->priv_level) {
    cookie->priv_level = data->priv_level;
    dirty = 1;
    u->last_minor_change_time = cur_time;
  }

  login_len = strlen(u->login);
  name_len = strlen(u->name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  out->cookie = cookie->cookie;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = cookie->contest_id;
  out->locale_id = data->locale_id;
  out->login_len = login_len;
  out->name_len = name_len;
  out->priv_level = data->priv_level;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, u->name);
  
  p->user_id = u->id;
  p->priv_level = out->priv_level;
  p->cookie = cookie->cookie;
  p->ip = data->origin_ip;
  enqueue_reply_to_client(p, out_size, out);
  dirty = 1;
  u->last_login_time = cur_time;
  CONN_INFO("%d, %s", u->id, u->login);
}
      
static void
cmd_do_logout(struct client_state *p,
              int pkt_len,
              struct userlist_pk_do_logout * data)
{
  struct userlist_user *u;
  struct userlist_cookie *cookie;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch: %d", pkt_len);
    return;
  }
  CONN_INFO("%s, %016llx", unparse_ip(data->origin_ip), data->cookie);
  if (p->user_id < 0) {
    CONN_ERR("connection is not authentificated");
    send_reply(p, ULS_OK);
    return;
  }
  // user_id == 0 is deprecated
  ASSERT(p->user_id > 0);
  if (!data->cookie) {
    CONN_ERR("cookie is empty");
    send_reply(p, ULS_OK);
    return;
  }
  if (!data->origin_ip) {
    CONN_ERR("origin_ip is empty");
    send_reply(p, ULS_OK);
    return;
  }
  ASSERT(p->user_id > 0 && p->user_id < userlist->user_map_size);
  u = userlist->user_map[p->user_id];
  ASSERT(u);

  u->last_access_time = cur_time;
  cookie = 0;
  if (u->cookies) {
    for (cookie = (struct userlist_cookie*) u->cookies->first_down;
         cookie; cookie = (struct userlist_cookie*) cookie->b.right) {
      if (cookie->ip == data->origin_ip && cookie->cookie == data->cookie)
        break;
    }
  }
  if (!cookie) {
    CONN_ERR("cookie not found");
    send_reply(p, ULS_OK);
    return;
  }

  remove_cookie(cookie);
  u->last_minor_change_time = cur_time;
  dirty = 1;
  send_reply(p, ULS_OK);
  CONN_INFO("cookie removed");
}

/*
 * Unpriveleged: get information about a user.
 * A user may only get information about himself.
 */
static void
cmd_get_user_info(struct client_state *p,
                  int pkt_len,
                  struct userlist_pk_get_user_info *data)
{
  FILE *f = 0;
  unsigned char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  struct userlist_user *user = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch: %d", pkt_len);
    return;
  }

  CONN_INFO("%ld", data->user_id);

  if (p->user_id < 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  // user_id == 0 is deprecated
  ASSERT(p->user_id > 0);

  if (data->user_id <= 0 || data->user_id >= userlist->user_map_size
      || !userlist->user_map[data->user_id]) {
    CONN_ERR("invalid user id");
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (data->user_id != p->user_id) {
    CONN_ERR("user ids does not match: %d, %ld", p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  user = userlist->user_map[data->user_id];

  if (!(f = open_memstream((char**) &xml_ptr, &xml_size))) {
    CONN_ERR("open_memstream() failed!");
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  userlist_unparse_user(user, f, USERLIST_MODE_USER);
  fclose(f);

  ASSERT(xml_size == strlen(xml_ptr));
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
  CONN_INFO("size = %d", out_size);
}

static void
cmd_priv_get_user_info(struct client_state *p,
                       int pkt_len,
                       struct userlist_pk_get_user_info *data)
{
  FILE *f = 0;
  unsigned char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  struct userlist_user *user = 0;
  struct userlist_contest *user_cnts = 0;
  struct contest_desc *cnts = 0;
  opcap_t caps;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch: %d", pkt_len);
    return;
  }

  CONN_INFO("%ld", data->user_id);

  if (p->user_id < 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  // user_id == 0 is deprecated
  ASSERT(p->user_id > 0);

  if (data->user_id <= 0 || data->user_id >= userlist->user_map_size
      || !userlist->user_map[data->user_id]) {
    CONN_ERR("invalid user id");
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  user = userlist->user_map[data->user_id];

  // either p->user_id == data->user_id,
  // or general GET_USER capability is present,
  // or the user is registered for the contest with GET_USER capability
  while (1) {
    if (p->user_id == data->user_id) break;

    if (get_uid_caps(&config->capabilities, p->user_id, &caps) >= 0
        && opcaps_check(caps, OPCAP_GET_USER) >= 0) break;

    // scan contests
    if (user->contests) {
      for (user_cnts = FIRST_CONTEST(user); user_cnts;
           user_cnts = NEXT_CONTEST(user_cnts)) {
        if (contests_get(user_cnts->id, &cnts) < 0)
          continue;
        if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) < 0)
          continue;
        if (opcaps_check(caps, OPCAP_GET_USER) >= 0) break;
      }
      if (user_cnts) break;
    }

    // no access condition holds
    CONN_ERR("user %d has no permission to view this user", p->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (!(f = open_memstream((char**) &xml_ptr, &xml_size))) {
    CONN_ERR("open_memstream() failed!");
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  userlist_unparse_user(user, f, USERLIST_MODE_ALL);
  fclose(f);

  ASSERT(xml_size == strlen(xml_ptr));
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
  CONN_INFO("size = %d", out_size);
}

static void
cmd_list_all_users(struct client_state *p,
                   int pkt_len,
                   struct userlist_pk_map_contest *data)
{
  FILE *f = 0;
  unsigned char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  int errcode;
  struct contest_desc *cnts = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch");
    return;
  }

  CONN_INFO("%d", data->contest_id);
  if (p->user_id < 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->contest_id) {
    // list users for a particular contest
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
    if (is_cnts_capable(p, cnts, OPCAP_LIST_CONTEST_USERS) < 0) return;
  } else {
    // list all users
    if (is_db_capable(p, OPCAP_LIST_ALL_USERS) < 0) return;
  }

  f = open_memstream((char**) &xml_ptr, &xml_size);
  ASSERT(f);
  userlist_unparse_short(userlist, f, data->contest_id);
  fclose(f);
  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size + 1;
  out = alloca(out_size);
  ASSERT(out);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr);
  enqueue_reply_to_client(p, out_size, out);
  info("%d: list_all_users: %d", p->id, xml_size); 
}

static void
cmd_get_user_contests(struct client_state *p,
                      int pkt_len,
                      struct userlist_pk_get_user_info *data)
{
  FILE *f = 0;
  unsigned char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  struct userlist_user *user = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch");
    return;
  }

  CONN_INFO("%ld", data->user_id);

  if (p->user_id < 0) {
    CONN_ERR("connection is not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (data->user_id <= 0 || data->user_id >= userlist->user_map_size
      || !userlist->user_map[data->user_id]) {
    CONN_ERR("invalid user_id");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  // this is unprivileged version
  if (data->user_id != p->user_id) {
    CONN_ERR("requested user_id does not match to the original");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  user = userlist->user_map[data->user_id];

  if (!(f = open_memstream((char**) &xml_ptr, &xml_size))) {
    CONN_ERR("open_memstream failed!");
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  userlist_unparse_contests(user, f);
  fclose(f);

  ASSERT(xml_size == strlen(xml_ptr));
  // FIXME: extend the packet!!!
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
  CONN_INFO("size = %d", out_size);
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
do_set_user_info(struct client_state *p,
                 struct userlist_pk_set_user_info *data)
{
  struct userlist_user *new_u = 0, *old_u = 0;
  int old_role, old_pers, new_role, new_pers;
  struct userlist_members *old_ms = 0, *new_ms;
  struct userlist_member *new_m, *old_m;
  unsigned char const *role_str = 0;
  int updated = 0;

  if (!(new_u = userlist_parse_user_str(data->data))) {
    err("%d: XML parse error", p->id);
    send_reply(p, -ULS_ERR_XML_PARSE);
    return;
  }

  if (data->user_id != new_u->id) {
    err("%d: XML user_id %d does not correspond to packet user_id %lu",
        p->id, new_u->id, data->user_id);
    send_reply(p, -ULS_ERR_PROTOCOL);
    userlist_free(&new_u->b);
    return;
  }
  if (new_u->id <= 0 || new_u->id >= userlist->user_map_size
      || !userlist->user_map[new_u->id]) {
    info("%d: invalid user_id %d", p->id, new_u->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    userlist_free(&new_u->b);
    return;
  }
  old_u = userlist->user_map[new_u->id];
  if (old_u->read_only) {
    err("%d: user cannot be modified", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    userlist_free(&new_u->b);
    return;
  }
  if (strcmp(old_u->email, new_u->email) != 0) {
    err("%d: new email <%s> does not match old <%s>",
        p->id, new_u->email, old_u->email);
    send_reply(p, -ULS_ERR_BAD_UID);
    userlist_free(&new_u->b);
    return;
  }
  if (strcmp(old_u->login, new_u->login) != 0) {
    err("%d: new login <%s> does not match old <%s>",
        p->id, new_u->login, old_u->email);
    send_reply(p, -ULS_ERR_BAD_UID);
    userlist_free(&new_u->b);
    return;
  }

  // update the user's fields
  if (needs_name_update(old_u->name, new_u->name)) {
    xfree(old_u->name);
    old_u->name = xstrdup(new_u->name);
    info("%d: name updated", p->id);
    updated = 1;

    // we have to notify all the contests, where the user participates
    if (old_u->contests) {
      struct userlist_contest *cc;

      for (cc = (struct userlist_contest*) old_u->contests->first_down;
           cc; cc = (struct userlist_contest*) cc->b.right) {
        if (cc->status == USERLIST_REG_OK
            && !(cc->flags & USERLIST_UC_BANNED)) {
          update_userlist_table(cc->id);
        }
      }
    }
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
  if (needs_update(old_u->city, new_u->city)) {
    xfree(old_u->city);
    old_u->city = xstrdup(new_u->city);
    info("%d: city updated", p->id);
    updated = 1;
  }
  if (needs_update(old_u->country, new_u->country)) {
    xfree(old_u->country);
    old_u->country = xstrdup(new_u->country);
    info("%d: country updated", p->id);
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
      if (needs_update(old_m->occupation, new_m->occupation)) {
        xfree(old_m->occupation);
        old_m->occupation = xstrdup(new_m->occupation);
        info("%d: updated %s.%d.occupation", p->id, role_str, old_pers);
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

  userlist_free(&new_u->b);
  old_u->last_access_time = cur_time;
  if (updated) {
    old_u->last_change_time = cur_time;
    dirty = 1;
    flush_interval /= 2;
  }
  send_reply(p, ULS_OK);
}

static void
cmd_set_user_info(struct client_state *p,
                  int pkt_len,
                  struct userlist_pk_set_user_info *data)
{
  size_t xml_len;

  xml_len = strlen(data->data);
  if (xml_len != data->info_len) {
    CONN_BAD("XML length does not match");
    return;
  }
  if (pkt_len != sizeof(*data) + xml_len) {
    CONN_BAD("packet length mismatch");
    return;
  }

  CONN_INFO("%ld, %d", data->user_id, data->info_len);
  if (p->user_id < 0) {
    CONN_ERR("client not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    CONN_ERR("user_id does not match: %d, %ld", p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  do_set_user_info(p, data);
}

static void
cmd_set_passwd(struct client_state *p, int pkt_len,
               struct userlist_pk_set_password *data)
{
  int old_len, new_len, exp_len;
  unsigned char *old_pwd, *new_pwd;
  struct userlist_user *u;
  struct passwd_internal oldint, newint;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet is too small: %d", pkt_len);
    return;
  }
  old_pwd = data->data;
  old_len = strlen(old_pwd);
  if (old_len != data->old_len) {
    CONN_BAD("old password length mismatch: %d, %d", old_len, data->old_len);
    return;
  }
  new_pwd = old_pwd + old_len + 1;
  new_len = strlen(new_pwd);
  if (new_len != data->new_len) {
    CONN_BAD("new password length mismatch: %d, %d", new_len, data->new_len);
    return;
  }
  exp_len = sizeof(*data) + old_len + new_len;
  if (pkt_len != exp_len) {
    CONN_BAD("packet length mismatch: %d, %d", exp_len, pkt_len);
    return;
  }

  CONN_INFO("%d", data->user_id);
  if (p->user_id < 0) {
    CONN_ERR("client not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    CONN_ERR("user_ids does not match: %d, %d", p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  // just in case
  ASSERT(p->user_id < userlist->user_map_size);
  u = userlist->user_map[p->user_id];
  ASSERT(u);

  if (!new_len) {
    CONN_ERR("new password is empty");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (!u->register_passwd || !u->register_passwd->b.text) {
    CONN_ERR("old password is not set");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(old_pwd, &oldint) < 0) {
    CONN_ERR("cannot parse old password");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(new_pwd, &newint) < 0) {
    CONN_ERR("cannot parse new password");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_check(&oldint, u->register_passwd) < 0) {
    CONN_ERR("passwords do not match");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  xfree(u->register_passwd->b.text);
  u->register_passwd->b.text = xstrdup(newint.pwds[USERLIST_PWD_SHA1]);
  u->register_passwd->method = USERLIST_PWD_SHA1;

  u->last_pwdchange_time = cur_time;
  u->last_access_time = cur_time;
  dirty = 1;
  flush_interval /= 2;
  send_reply(p, ULS_OK);
  CONN_INFO("ok");
}

static void
cmd_team_set_passwd(struct client_state *p, int pkt_len,
                    struct userlist_pk_set_password *data)
{
  int old_len, new_len, exp_len;
  unsigned char *old_pwd, *new_pwd;
  struct userlist_user *u;
  struct passwd_internal oldint, newint;
  struct contest_desc *cnts = 0;
  int errcode;

  // check packet
  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet is too small: %d", pkt_len);
    return;
  }
  old_pwd = data->data;
  old_len = strlen(old_pwd);
  if (old_len != data->old_len) {
    CONN_BAD("old password length mismatch: %d, %d", old_len, data->old_len);
    return;
  }
  new_pwd = old_pwd + old_len + 1;
  new_len = strlen(new_pwd);
  if (new_len != data->new_len) {
    CONN_BAD("new password length mismatch: %d, %d", new_len, data->new_len);
    return;
  }
  exp_len = sizeof(*data) + old_len + new_len;
  if (pkt_len !=  exp_len) {
    CONN_BAD("packet length mismatch: %d, %d", exp_len, pkt_len);
    return;
  }

  CONN_INFO("%d, %d", data->user_id, data->contest_id);
  if (p->user_id < 0) {
    CONN_ERR("client not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    CONN_ERR("user_ids do not match: %d, %d", p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  // FIXME: check for proper user removal. If this works, no checking
  // is necessary.
  ASSERT(p->user_id < userlist->user_map_size);
  u = userlist->user_map[data->user_id];
  ASSERT(u);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (cnts->disable_team_password) {
    CONN_ERR("team password is disabled");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (!new_len) {
    CONN_ERR("new password is empty");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(old_pwd, &oldint) < 0) {
    CONN_ERR("cannot parse old password");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(new_pwd, &newint) < 0) {
    CONN_ERR("cannot parse new password");
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  // verify the existing password
  if (u->team_passwd) {
    if (passwd_check(&oldint, u->team_passwd) < 0) {
      CONN_ERR("OLD team password does not match");
      if (passwd_check(&oldint, u->register_passwd) < 0) {
        CONN_ERR("OLD registration password does not match");
        send_reply(p, -ULS_ERR_NO_PERMS);
        return;
      }
    }
  } else {
    if (passwd_check(&oldint, u->register_passwd) < 0) {
      CONN_ERR("OLD registration password does not match");
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  }

  // if team passwd entry does not exist, create it
  if (!u->team_passwd) {
    struct userlist_passwd *tt;
    tt=(struct userlist_passwd*)userlist_node_alloc(USERLIST_T_TEAM_PASSWORD);
    u->team_passwd = tt;
    xml_link_node_last(&u->b, &tt->b);
  } else {
    xfree(u->team_passwd->b.text);
  }
  u->team_passwd->b.text = xstrdup(newint.pwds[USERLIST_PWD_SHA1]);
  u->team_passwd->method = USERLIST_PWD_SHA1;

  u->last_pwdchange_time = cur_time;
  u->last_access_time = cur_time;
  dirty = 1;
  flush_interval /= 2;
  send_reply(p, ULS_OK);
  CONN_INFO("ok");
}

/* unprivileged version of the function */
static void
cmd_register_contest(struct client_state *p, int pkt_len,
                     struct userlist_pk_register_contest *data)
{
  struct userlist_user *u;
  struct contest_desc *c = 0;
  struct userlist_contest *r;
  int errcode;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  CONN_INFO("%d, %d", data->user_id, data->contest_id);
  if (p->user_id < 0) {
    CONN_ERR("client not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    CONN_ERR("user_ids do not match: %d, %d", p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  ASSERT(p->user_id < userlist->user_map_size);
  u = userlist->user_map[p->user_id];
  ASSERT(u);

  if ((errcode = contests_get(data->contest_id, &c)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (c->reg_deadline && cur_time > c->reg_deadline) {
    CONN_ERR("registration deadline exceeded");
    send_reply(p, -ULS_ERR_DEADLINE);
    return;
  }

  /* FIXME: check conditions. What conditions? */

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
    if (r->id == data->contest_id) break;
  }
  if (r) {
    CONN_INFO("already registered");
    send_reply(p, ULS_OK);
    return;
  }
  r = (struct userlist_contest*) userlist_node_alloc(USERLIST_T_CONTEST);
  r->b.tag = USERLIST_T_CONTEST;
  xml_link_node_last(u->contests, &r->b);
  r->id = data->contest_id;
  if (c->autoregister) {
    r->status = USERLIST_REG_OK;
    update_userlist_table(data->contest_id);
  } else {
    r->status = USERLIST_REG_PENDING;
  }
  flush_interval /= 2;
  dirty = 1;
  u->last_change_time = cur_time;
  u->last_access_time = cur_time;
  CONN_INFO("registered");
  send_reply(p, ULS_OK);
  return;
}

/* privileged version */
static void
cmd_priv_register_contest(struct client_state *p, int pkt_len,
                          struct userlist_pk_register_contest *data)
{
  struct userlist_user *u;
  struct contest_desc *c = 0;
  struct userlist_contest *r;
  int errcode;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  CONN_INFO("%d, %d", data->user_id, data->contest_id);
  if (p->user_id < 0) {
    CONN_ERR("client not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);

  if ((errcode = contests_get(data->contest_id, &c)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (data->user_id <= 0 || data->user_id >= userlist->user_map_size
      || !(u = userlist->user_map[data->user_id])) {
    CONN_ERR("invalid user_id");
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (p->user_id != data->user_id) {
    if (is_privileged_user(u) >= 0) {
      if (is_cnts_capable(p, c, OPCAP_PRIV_CREATE_REG) < 0) return;
    } else {
      if (is_cnts_capable(p, c, OPCAP_CREATE_REG) < 0) return;
    }
  }

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
    if (r->id == data->contest_id) break;
  }
  if (r) {
    CONN_INFO("already registered");
    send_reply(p, ULS_OK);
    return;
  }
  r = (struct userlist_contest*) userlist_node_alloc(USERLIST_T_CONTEST);
  r->b.tag = USERLIST_T_CONTEST;
  xml_link_node_last(u->contests, &r->b);
  r->id = data->contest_id;
  if (c->autoregister) {
    r->status = USERLIST_REG_OK;
    update_userlist_table(data->contest_id);
  } else {
    r->status = USERLIST_REG_PENDING;
  }
  flush_interval /= 2;
  dirty = 1;
  u->last_change_time = cur_time;
  u->last_access_time = cur_time;
  CONN_INFO("registered");
  send_reply(p, ULS_OK);
  return;




  SWERR(("not implemented yet!"));
}

static void
cmd_remove_member(struct client_state *p, int pkt_len,
                  struct userlist_pk_remove_member *data)
{
  struct userlist_user *u;
  struct userlist_members *ms;
  struct userlist_member *m;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  CONN_INFO("%d, %d, %d, %d",
            data->user_id, data->role_id, data->pers_id, data->serial);
  if (p->user_id <= 0) {
    CONN_ERR("client not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    CONN_ERR("user_ids do not match: %d, %d", p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  ASSERT(p->user_id < userlist->user_map_size);
  u = userlist->user_map[p->user_id];
  ASSERT(u);

  if (data->role_id < 0 || data->role_id >= CONTEST_LAST_MEMBER) {
    CONN_ERR("invalid role");
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  ms = u->members[data->role_id];
  if (!ms) {
    CONN_ERR("no members with that role");
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  if (data->pers_id < 0 || data->pers_id >= ms->total) {
    CONN_ERR("invalid person");
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  m = ms->members[data->pers_id];
  if (!m || m->serial != data->serial) {
    CONN_ERR("invalid person");
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }

  m = unlink_member(u, data->role_id, data->pers_id);
  userlist_free(&m->b);

  flush_interval /= 2;
  dirty = 1;
  u->last_change_time = cur_time;
  u->last_access_time = cur_time;
  CONN_INFO("member removed");
  send_reply(p, ULS_OK);
}

static void
cmd_pass_fd(struct client_state *p, int pkt_len,
            struct userlist_packet *data)
{
  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (p->client_fds[0] >= 0 || p->client_fds[1] >= 0) {
    CONN_BAD("cannot stack unprocessed client descriptors");
    return;
  }

  p->state = STATE_READ_FDS;
}

static void
do_list_users(FILE *f, int contest_id, struct contest_desc *d,
              int locale_id,
              int user_id, unsigned long flags,
              unsigned char *url, unsigned char *srch)
{
  struct userlist_user *u;
  struct userlist_contest *c;
  struct userlist_user **us = 0;
  struct userlist_contest **cs = 0;
  struct contest_desc *tmpd, *cnts;
  struct contest_member *cm;
  struct userlist_member *m;
  int u_num = 0, i, regtot;
  unsigned char *s;
  unsigned char buf[1024];
  unsigned char *notset = 0;
  int role, pers;

  if (user_id > 0) {
    ASSERT(user_id > 0);
    ASSERT(user_id < userlist->user_map_size);
    u = userlist->user_map[user_id];
    ASSERT(u);

    setup_locale(locale_id);
    fprintf(f, "<h2>%s: %s</h2>\n",
            _("Detailed information for user (team)"), u->name);
    fprintf(f, "<h3>%s</h3>\n", _("General information"));
    fprintf(f, "<table>\n");
    fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>\n",
            _("User ID"), u->id);
    if (u->show_login) {
      fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Login"), u->login);
    }
    if (u->show_email) {
      fprintf(f, "<tr><td>%s:</td><td><a href=\"mailto:%s\">%s</a></td></tr>\n",
              _("E-mail"), u->email, u->email);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Name"), u->name);
    notset = _("<i>Not set</i>");
    if (!d || d->fields[CONTEST_F_HOMEPAGE]) {
      if (!u->homepage) {
        snprintf(buf, sizeof(buf), "%s", notset);
      } else {
        if (!strncasecmp(u->homepage, "http://", 7)) {
          snprintf(buf, sizeof(buf), "<a href=\"%s\">%s</a>",
                   u->homepage, u->homepage);
        } else {
          snprintf(buf, sizeof(buf), "<a href=\"http://%s\">%s</a>",
                   u->homepage, u->homepage);
        }
      }
      fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Homepage"), buf);
    }
    if (!d || d->fields[CONTEST_F_INST]) {
      fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Institution"), u->inst?u->inst:notset);
    }
    if (!d || d->fields[CONTEST_F_INSTSHORT]) {
      fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Institution (short)"), u->instshort?u->instshort:notset);
    }
    if (!d || d->fields[CONTEST_F_FAC]) {
      fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Faculty"), u->fac?u->fac:notset);
    }
    if (!d || d->fields[CONTEST_F_FACSHORT]) {
      fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Faculty (short)"), u->facshort?u->facshort:notset);
    }
    if (!d || d->fields[CONTEST_F_CITY]) {
      fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("City"), u->city?u->city:notset);
    }
    if (!d || d->fields[CONTEST_F_COUNTRY]) {
      fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Country"), u->country?u->country:notset);
    }

    fprintf(f, "</table>\n");

    for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
      if (d && !d->members[role]) continue;
      if (d && d->members[role] && d->members[role]->max_count <= 0)
        continue;
      if (!u->members[role] || !u->members[role]->total)
        continue;
      fprintf(f, "<h3>%s</h3>\n", gettext(member_string_pl[role]));
      for (pers = 0; pers < u->members[role]->total; pers++) {
        m = u->members[role]->members[pers];
        if (!m) continue;
        fprintf(f, "<h3>%s %d</h3>\n", gettext(member_string[role]),
                pers + 1);
        fprintf(f, "<table>\n");
        fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>\n",
                _("Serial No"), m->serial);
        cm = 0;
        if (d) cm = d->members[role];
        if (!d || (cm && cm->fields[CONTEST_MF_FIRSTNAME])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("First name"), m->firstname?m->firstname:notset);
        }
        if (!d || (cm && cm->fields[CONTEST_MF_MIDDLENAME])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("Middle name"), m->middlename?m->middlename:notset);
        }
        if (!d || (cm && cm->fields[CONTEST_MF_SURNAME])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("Family name"), m->surname?m->surname:notset);
        }
        if (!d || (cm && cm->fields[CONTEST_MF_STATUS])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("Status"),
                  gettext(member_status_string[m->status]));
        }
        if (!d || (cm && cm->fields[CONTEST_MF_GRADE])) {
          fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>\n",
                  _("Grade"), m->grade);
        }
        if (!d || (cm && cm->fields[CONTEST_MF_GROUP])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("Group"), m->group?m->group:notset);
        }
        if (!d || (cm && cm->fields[CONTEST_MF_INST])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("Institution"), m->inst?m->inst:notset);
        }
        if (!d || (cm && cm->fields[CONTEST_MF_INSTSHORT])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("Institution (short)"), m->instshort?m->instshort:notset);
        }
        if (!d || (cm && cm->fields[CONTEST_MF_FAC])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("Faculty"), m->fac?m->fac:notset);
        }
        if (!d || (cm && cm->fields[CONTEST_MF_FACSHORT])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("Faculty (short)"), m->facshort?m->facshort:notset);
        }
        if (!d || (cm && cm->fields[CONTEST_MF_OCCUPATION])) {
          fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                  _("Occupation"), m->occupation?m->occupation:notset);
        }
        /*
    CONTEST_MF_EMAIL,
    CONTEST_MF_HOMEPAGE,
         */
        fprintf(f, "</table>\n");
      }
    }

    regtot = 0;
    if (u->contests) {
      for (c = (struct userlist_contest*) u->contests->first_down;
           c; c = (struct userlist_contest*) c->b.right) {
        if (d && c->id != d->id) continue;
        if (contests_get(c->id, &cnts) < 0) continue;
        regtot++;
      }
    }
    if (regtot > 0) {
      fprintf(f, "<h3>%s</h3>\n", _("Contest registrations"));
      fprintf(f, "<table><tr><th>%s</th><th>%s</th></tr>\n",
              _("Contest name"), _("Status"));
      for (c = (struct userlist_contest*) u->contests->first_down;
           c; c = (struct userlist_contest*) c->b.right) {
        if (d && c->id != d->id) continue;
        if (contests_get(c->id, &tmpd) < 0) continue;
        fprintf(f, "<tr><td>%s</td><td>%s</td></tr>\n",
                tmpd->name, gettext(status_str_map[c->status]));
      }
      fprintf(f, "</table>\n");
    }

    setup_locale(0);
    return;
  }

  us = (struct userlist_user**) alloca(userlist->user_map_size*sizeof(us[0]));
  cs =(struct userlist_contest**)alloca(userlist->user_map_size*sizeof(us[0]));

  for (i = 1; i < userlist->user_map_size; i++) {
    u = userlist->user_map[i];
    if (!u) continue;
    c = 0;
    if (u->contests) {
      c = (struct userlist_contest*) u->contests->first_down;
    }
    if (!c) continue;

    for (; c; c = (struct userlist_contest*) c->b.right) {
      if (c->id == contest_id) break;
    }
    if (!c) continue;
    if (c->status < USERLIST_REG_OK || c->status > USERLIST_REG_PENDING)
      continue;
    if ((c->flags & USERLIST_UC_INVISIBLE)) continue;

    us[u_num] = u;
    cs[u_num] = c;
    u_num++;
  }

  /* add additional filters */
  /* add additional sorts */

  setup_locale(locale_id);
  if (!u_num) {
    fprintf(f, "<p>%s</p>\n", _("No users registered for this contest"));
    setup_locale(0);
    return;
  }

  fprintf(f, _("<p>%d users listed</p>\n"), u_num);
  fprintf(f, "<table>\n<hr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></hr>\n",
          _("Serial No"), _("User ID"), _("User name"), _("Institution"), _("Faculty"),
          _("Status"));
  for (i = 0; i < u_num; i++) {
    fprintf(f, "<tr><td>%d</td>", i + 1);
    // FIXME: do html armoring?
    fprintf(f, "<td>%d</td>", us[i]->id);
    s = us[i]->name;
    if (!s) {
      fprintf(f, "<td>&nbsp;</td>");
    } else if (!url) {
      fprintf(f, "<td>%s</td>", s);
    } else {
      fprintf(f, "<td><a href=\"%s?user_id=%d", url, us[i]->id);
      if (contest_id > 0) fprintf(f, "&contest_id=%d", contest_id);
      if (locale_id > 0) fprintf(f, "&locale_id=%d", locale_id);
      fprintf(f, "\">%s</a></td>", s);
    }
    s = us[i]->instshort;
    if (!s) s = "&nbsp;";
    fprintf(f, "<td>%s</td>", s);
    s = us[i]->facshort;
    if (!s) s = "&nbsp;";
    fprintf(f, "<td>%s</td>", s);
    fprintf(f, "<td>%s</td>", gettext(status_str_map[cs[i]->status]));
    fprintf(f, "</tr>\n");
  }
  fprintf(f, "</table>\n");
  setup_locale(0);
}

static void
do_dump_database(FILE *f, int contest_id, struct contest_desc *d)
{
  struct userlist_user *u;
  struct userlist_contest *c;
  struct userlist_member *m;
  unsigned char *notset = 0, *banstr = 0, *invstr = 0, *statstr = 0;
  int i, role, pers, pers_tot;

  fprintf(f, "Content-type: text/plain\n\n");

  notset = "";
  for (i = 1; i < userlist->user_map_size; i++) {
    if (!(u = userlist->user_map[i])) continue;
    if (d && !u->contests) continue;
    for (c = FIRST_CONTEST(u); c; c = NEXT_CONTEST(c)) {
      if (c->id == d->id) break;
    }
    if (!c) continue;

    switch (c->status) {
    case USERLIST_REG_OK:       statstr = "OK";       break;
    case USERLIST_REG_PENDING:  statstr = "PENDING";  break;
    case USERLIST_REG_REJECTED: statstr = "REJECTED"; break;
    default:
      statstr = "UNKNOWN";
    }

    banstr = "";
    invstr = "";
    if ((c->flags & USERLIST_UC_INVISIBLE)) invstr = "I";
    if ((c->flags & USERLIST_UC_BANNED)) banstr = "B";

    pers_tot = 0;
    for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
      if (!u->members[role]) continue;
      for (pers = 0; pers < u->members[role]->total; pers++) {
        unsigned char nbuf[32] = { 0 };
        unsigned char *lptr = nbuf;

        if (!(m = u->members[role]->members[pers])) continue;
        if (role == CONTEST_M_CONTESTANT || role == CONTEST_M_RESERVE) {
          snprintf(nbuf, sizeof(nbuf), "%d", m->grade);
          lptr = nbuf;
        } else {
          lptr = m->occupation;
        }

        pers_tot++;
        fprintf(f, ";%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%d;%s;%s;%s;%s;%s;%s\n",
                u->id, u->login, u->name, u->email,
                u->inst?u->inst:notset,
                u->instshort?u->instshort:notset,
                u->fac?u->fac:notset,
                u->facshort?u->facshort:notset,
                u->city?u->city:notset,
                u->country?u->country:notset,
                statstr, invstr, banstr,
                m->serial,
                gettext(member_string[role]),
                m->surname?m->surname:notset,
                m->firstname?m->firstname:notset,
                m->middlename?m->middlename:notset,
                gettext(member_status_string[m->status]),
                lptr?lptr:notset);
      }
    }
    if (!pers_tot) {
      fprintf(f, ";%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n",
              u->id, u->login, u->name, u->email,
              u->inst?u->inst:notset,
              u->instshort?u->instshort:notset,
              u->fac?u->fac:notset,
              u->facshort?u->facshort:notset,
              u->city?u->city:notset,
              u->country?u->country:notset,
              statstr, invstr, banstr,
              "", "", "", "", "", "", "");
    }
  }
  return;
}

static void
cmd_list_users(struct client_state *p, int pkt_len,
               struct userlist_pk_list_users *data)
{
  struct client_state *q;
  FILE *f = 0;
  unsigned char *html_ptr = 0;
  size_t html_size = 0;
  unsigned char *url_ptr, *srch_ptr;
  struct contest_desc *cnts = 0;
  int errcode, exp_len, url_len, srch_len;

  if (pkt_len < sizeof (*data)) {
    CONN_BAD("packet is too short: %d", pkt_len);
    return;
  }
  url_ptr = data->data;
  url_len = strlen(url_ptr);
  if (url_len != data->url_len) {
    CONN_BAD("url_len mismatch: %d, %d", url_len, data->url_len);
    return;
  }
  srch_ptr = url_ptr + data->url_len + 1;
  srch_len = strlen(srch_ptr);
  if (srch_len != data->srch_len) {
    CONN_BAD("srch_len mismatch: %d, %d", srch_len, data->srch_len);
    return;
  }
  exp_len = sizeof(*data) + data->url_len + data->srch_len;
  if (pkt_len != exp_len) {
    CONN_BAD("packet length mismatch: %d, %d", pkt_len, exp_len);
    return;
  }
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    CONN_BAD("two client file descriptors required");
    return;
  }

  if (data->user_id) {
    if (data->user_id <= 0 || data->user_id >= userlist->user_map_size
        || !userlist->user_map[data->user_id]) {
      CONN_ERR("invalid user: %d", data->user_id);
      send_reply(p, -ULS_ERR_BAD_UID);
      return;
    }
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (!(f = open_memstream((char**) &html_ptr, &html_size))) {
    CONN_ERR("open_memstream failed!");
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_list_users(f, data->contest_id, cnts, data->locale_id,
                data->user_id, data->flags, url_ptr, srch_ptr);
  fclose(f);

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
  q->write_buf = html_ptr;
  q->write_len = html_size;
  link_client_state(q);
  CONN_INFO("created new connection %d", q->id);
  send_reply(p, ULS_OK);
}

static void
cmd_dump_database(struct client_state *p, int pkt_len,
                          struct userlist_pk_dump_database *data)
{
  struct client_state *q;
  FILE *f = 0;
  unsigned char *html_ptr = 0;
  size_t html_size = 0;
  struct contest_desc *cnts = 0;
  int errcode;
  opcap_t caps;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    CONN_BAD("two client file descriptors required");
    return;
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest %d: %s",
             data->contest_id, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (p->user_id < 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  while (1) {
    if (get_uid_caps(&config->capabilities, p->user_id, &caps) >= 0
        && opcaps_check(caps, OPCAP_DUMP_USERS) >= 0)
      break;

    if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) >= 0
        && opcaps_check(caps, OPCAP_DUMP_USERS) >= 0)
      break;

    CONN_ERR("user %d has no capability %d for contest %d",
             p->user_id, OPCAP_DUMP_USERS, data->contest_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (!(f = open_memstream((char**) &html_ptr, &html_size))) {
    CONN_ERR("open_memstream failed!");
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_dump_database(f, data->contest_id, cnts);
  fclose(f);

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
  q->write_buf = html_ptr;
  q->write_len = html_size;
  link_client_state(q);
  CONN_INFO("created new connection %d", q->id);
  send_reply(p, ULS_OK);
}

static void
cmd_map_contest(struct client_state *p, int pkt_len,
                struct userlist_pk_map_contest *data)
{
  struct contest_desc *cnts = 0;
  struct contest_extra *ex = 0;
  size_t out_size;
  struct userlist_pk_contest_mapped *out;
  int errcode;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  CONN_INFO("%d", data->contest_id);
  if (p->user_id < 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest %d: %s", data->contest_id,
             contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (is_cnts_capable(p, cnts, OPCAP_MAP_CONTEST) < 0) return;

  if (!(ex = attach_contest_extra(data->contest_id, cnts))) {
    send_reply(p, -ULS_ERR_IPC_FAILURE);
    return;
  }
  p->cnts_extra = ex;
  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_CONTEST_MAPPED;
  out->sem_key = ex->sem_key;
  out->shm_key = ex->shm_key;
  enqueue_reply_to_client(p, out_size, out);
  update_userlist_table(data->contest_id);
  CONN_INFO("%d, %d", ex->sem_key, ex->shm_key);
}

// just assigns the connection user_id by the system user_id
static void
cmd_admin_process(struct client_state *p, int pkt_len,
                  struct userlist_packet *data)
{
  struct userlist_cfg_user_map *um = 0;
  struct xml_tree *ut = 0;
  int i;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  CONN_INFO("%d, %d", p->peer_pid, p->peer_uid);
  if (!p->peer_uid) {
    CONN_ERR("root is not allowed");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (config->user_map) {
    for (ut = config->user_map->first_down; ut; ut = ut->right) {
      um = (struct userlist_cfg_user_map*) ut;
      if (um->system_uid == p->peer_uid) break;
    }
  }
  if (!ut) {
    CONN_ERR("user id %d is not found in the user id map", p->peer_uid);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  //CONN_INFO("user map: %d->%s", p->peer_uid, um->local_user_str);

  for (i = 1; i < userlist->user_map_size; i++) {
    if (!userlist->user_map[i]) continue;
    if (!strcmp(userlist->user_map[i]->login, um->local_user_str)) break;
  }
  if (i >= userlist->user_map_size) {
    CONN_ERR("local user %s does not exist", um->local_user_str);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  CONN_INFO("user map: %d->%d", p->peer_uid, i);
  p->user_id = i;
  send_reply(p, ULS_OK);
}

static void
do_generate_team_passwd(int contest_id, FILE *log)
{
  struct userlist_user *u;
  struct userlist_contest *c;
  struct userlist_passwd *p;
  struct xml_tree *t;
  unsigned char buf[16];

  fprintf(log, "<table border=\"1\"><tr><th>User ID</th><th>User Login</th><th>User Name</th><th>New User Password</th></tr>\n");
  for (u = (struct userlist_user*) userlist->b.first_down;
       u; u = (struct userlist_user*) u->b.right) {
    if (!u->contests) continue;
    for (c = (struct userlist_contest*) u->contests->first_down;
         c; c = (struct userlist_contest*) c->b.right) {
      if (c->id == contest_id && c->status == USERLIST_REG_OK) break;
    }
    if (!c) continue;

    // do not change password for privileged users
    if (is_privileged_user(u)) continue;

    t = u->cookies;
    if (t) {
      info("removed all cookies for %d (%s)", u->id, u->login);
      xml_unlink_node(t);
      userlist_free(t);
      u->cookies = 0;
    }
    if (!(p = u->team_passwd)) {
      p=(struct userlist_passwd*)userlist_node_alloc(USERLIST_T_TEAM_PASSWORD);
      xml_link_node_last(&u->b, &p->b);
      u->team_passwd = p;
    }
    if (p->b.text) {
      xfree(p->b.text);
      p->b.text = 0;
    }
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    p->method = USERLIST_PWD_PLAIN;
    p->b.text = xstrdup(buf);

  // html table header
    fprintf(log, "<tr><td><b>User ID</b></td><td><b>User Login</b></td><td><b>User Name</b></td><td><b>New User Password</b></td></tr>\n");
    fprintf(log, "<tr><td>%d</td><td>%s</td><td>%s</td><td><tt>%s</tt></td></tr>\n",
            u->id, u->login, u->name, buf);
  }
  fprintf(log, "</table>\n");
  dirty = 1;
  flush_interval /= 2;
}

static void
cmd_generate_team_passwords(struct client_state *p, int pkt_len,
                            struct userlist_pk_map_contest *data)
{
  unsigned char *log_ptr = 0;
  size_t log_size = 0;
  FILE *f = 0;
  struct client_state *q = 0;
  struct contest_desc *cnts = 0;
  int errcode;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  CONN_INFO("%d", data->contest_id);
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest: %d: %s", data->contest_id,
             contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (p->user_id < 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (is_cnts_capable(p, cnts, OPCAP_GENERATE_TEAM_PASSWORDS) < 0)
    return;
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    CONN_BAD("two client file descriptors required");
    return;
  }
  if (!(f = open_memstream((char**) &log_ptr, &log_size))) {
    CONN_ERR("open_memstream failed");
    send_reply(p, ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_generate_team_passwd(data->contest_id, f);
  fclose(f);

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
  q->write_buf = log_ptr;
  q->write_len = log_size;
  link_client_state(q);
  CONN_INFO("created new connection %d", q->id);
  send_reply(p, ULS_OK);
}

static void
cmd_get_contest_name(struct client_state *p, int pkt_len,
                     struct userlist_pk_map_contest *data)
{
  struct userlist_pk_xml_data *out = 0;
  struct contest_desc *cnts = 0;
  int out_size = 0, name_len = 0;
  int errcode;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length %d", pkt_len);
    return;
  }
  CONN_INFO("%d", data->contest_id);
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  name_len = strlen(cnts->name);
  if (name_len > 65000) {
    CONN_ERR("contest name is too long");
    name_len = 65000;
  }
  out_size = sizeof(*out) + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = out_size;
  memcpy(out->data, cnts->name, name_len);
  enqueue_reply_to_client(p, out_size, out);
  CONN_INFO("%d", out->info_len);
}

static void
cmd_edit_registration(struct client_state *p, int pkt_len,
                      struct userlist_pk_edit_registration *data)
{
  struct userlist_user *u;
  struct contest_desc *c = 0;
  struct userlist_contest *uc = 0;
  unsigned int new_flags;
  int updated = 0, errcode;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  CONN_INFO("%d, %d, %d, %d, %08x",
            data->user_id, data->contest_id, data->new_status,
            data->flags_cmd, data->new_flags);
  if (p->user_id < 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if ((errcode = contests_get(data->contest_id, &c)) < 0) {
    CONN_ERR("invalid contest: %s", contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (data->user_id <= 0 || data->user_id >= userlist->user_map_size
      || !(u = userlist->user_map[data->user_id])) {
    CONN_ERR("invalid user");
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (u->contests) {
    for (uc = (struct userlist_contest*) u->contests->first_down;
         uc; uc = (struct userlist_contest*) uc->b.right) {
      if (uc->id == data->contest_id) break;
    }
  }
  if (!uc) {
    CONN_ERR("not registered");
    send_reply(p, -ULS_ERR_NOT_REGISTERED);
    return;
  }

  /* check field values */
  if (data->new_status < -2 || data->new_status >= USERLIST_REG_LAST) {
    CONN_ERR("invalid new status");
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if (data->flags_cmd < 0 || data->flags_cmd > 3) {
    CONN_ERR("invalid flags command");
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if ((data->new_flags & ~USERLIST_UC_ALL)) {
    CONN_ERR("invalid new flags");
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }

  if (data->new_status == -2) {
    if (p->user_id != data->user_id) {
      if (is_privileged_user(u) >= 0) {
        if (is_cnts_capable(p, c, OPCAP_PRIV_DELETE_REG) < 0) return;
      } else {
        if (is_cnts_capable(p, c, OPCAP_DELETE_REG) < 0) return;
      }
    }

    xml_unlink_node(&uc->b);
    if (!u->contests->first_down) {
      xml_unlink_node(u->contests);
      u->contests = 0;
    }
    updated = 1;
    CONN_INFO("registration deleted");
  } else {
    if (is_cnts_capable(p, c, OPCAP_EDIT_REG) < 0) return;

    if (data->new_status != -1 && uc->status != data->new_status) {
      uc->status = data->new_status;
      updated = 1;
      CONN_INFO("status changed");
    }
    new_flags = uc->flags;
    switch (data->flags_cmd) {
    case 1: new_flags |= data->new_flags; break;
    case 2: new_flags &= ~data->new_flags; break;
    case 3: new_flags ^= data->new_flags; break;
    }
    if (new_flags != uc->flags) {
      uc->flags = new_flags;
      CONN_INFO("flags changed");
      updated = 1;
    }
  }
  if (updated) {
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
    update_userlist_table(c->id);
  }
  CONN_INFO("ok");
  send_reply(p, ULS_OK);
}

static void
cmd_delete_field(struct client_state *p, int pkt_len,
                 struct userlist_pk_edit_field *data)
{
  struct userlist_user *u;
  struct userlist_member *m;
  int updated = 0;
  opcap_t caps;
  struct userlist_contest *cntsreg;
  struct contest_desc *cnts;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  CONN_INFO("%d, %d, %d, %d",
            data->user_id, data->role, data->pers, data->field);

  if (data->user_id <= 0 || data->user_id >= userlist->user_map_size
      || !(u = userlist->user_map[data->user_id])) {
    CONN_ERR("invalid user");
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (data->role < -2 || data->role >= CONTEST_LAST_MEMBER) {
    CONN_ERR("invalid role");
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }

  if (data->role == -2) {
    // delete the whole user
    if (is_privileged_user(u) >= 0) {
      if (is_db_capable(p, OPCAP_PRIV_DELETE_USER) < 0) return;
    } else {
      if (is_db_capable(p, OPCAP_DELETE_USER) < 0) return;
    }
    do_remove_user(u);
    updated = 1;

    // oh, it might be ugly :-(
    goto done;
  }

  while (1) {
    if (p->user_id == data->user_id) break;

    if (is_privileged_user(u) >= 0) {
      if (get_uid_caps(&config->capabilities, p->user_id, &caps) >= 0
          && opcaps_check(caps, OPCAP_PRIV_EDIT_USER) >= 0) break;

      if (u->contests) {
        for (cntsreg = FIRST_CONTEST(u); cntsreg;
             cntsreg = NEXT_CONTEST(cntsreg)) {
          if (contests_get(cntsreg->id, &cnts) < 0)
            continue;
          if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) < 0)
            continue;
          if (opcaps_check(caps, OPCAP_PRIV_EDIT_USER) >= 0) break;
        }
        if (cntsreg) break;
      }
    } else {
      if (get_uid_caps(&config->capabilities, p->user_id, &caps) >= 0
          && opcaps_check(caps, OPCAP_EDIT_USER) >= 0) break;

      if (u->contests) {
        for (cntsreg = FIRST_CONTEST(u); cntsreg;
             cntsreg = NEXT_CONTEST(cntsreg)) {
          if (contests_get(cntsreg->id, &cnts) < 0)
            continue;
          if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) < 0)
            continue;
          if (opcaps_check(caps, OPCAP_EDIT_USER) >= 0) break;
        }
        if (cntsreg) break;
      }
    }

    CONN_ERR("user %d has no capability to edit user %d",
             p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->role == -1) {
    if (data->pers == -1) {
      CONN_ERR("role==-1, pers==-1 way for deleting users no longer works");
      send_reply(p, -ULS_ERR_PROTOCOL);
      return;
    }

    if (data->pers == 2) {
      // cookies
      if (data->field == -1) {
        // remove all cookies
        if (!u->cookies) {
          CONN_INFO("no cookies");
        } else {
          xml_unlink_node(u->cookies);
          userlist_free(u->cookies);
          u->cookies = 0;
          CONN_INFO("removed all cookies");
          updated = 1;
        }
      } else {
        // remove one particular cookie
        if (!u->cookies) {
          CONN_INFO("no cookies");
        } else {
          int i;
          struct userlist_cookie *cook = 0;
          for (cook = FIRST_COOKIE(u), i = 0;
               cook && i != data->field; cook = NEXT_COOKIE(cook), i++);
          if (!cook) {
            CONN_INFO("no such cookie %d", data->field);
          } else {
            xml_unlink_node(&cook->b);
            userlist_free(&cook->b);
            if (!u->cookies->first_down) {
              xml_unlink_node(u->cookies);
              userlist_free(u->cookies);
              u->cookies = 0;
            }
            CONN_INFO("removed cookie");
            updated = 1;
          }
        }
      }
      goto done;
    } // done with cookies
    
    if (data->pers != 0) {
      CONN_ERR("invalid pers");
      send_reply(p, -ULS_ERR_CANNOT_DELETE);
      return;
    }

    if (data->field < 0 || data->field > USERLIST_NN_LAST) {
      CONN_ERR("invalid field");
      send_reply(p, -ULS_ERR_CANNOT_DELETE);
      return;
    }
    if ((updated = userlist_delete_user_field(u, data->field)) < 0) {
      CONN_ERR("the field cannot be deleted");
      send_reply(p, -ULS_ERR_CANNOT_DELETE);
      return;
    }
    goto done;
  } // done with (data->role == -1)

  // other roles: contestants, reserves, advisors, coaches, guests
  if (!u->members[data->role]
      || data->pers < 0 || data->pers >= u->members[data->role]->total) {
    CONN_ERR("invalid pers");
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  m = u->members[data->role]->members[data->pers];
  if (!m) {
    CONN_ERR("invalid pers");
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  if (data->field < -1 || data->field > USERLIST_NM_LAST) {
    CONN_ERR("invalid field");
    send_reply(p, -ULS_ERR_CANNOT_DELETE);
    return;
  }
  if (data->field == -1) {
    // remove the whole member
    m = unlink_member(u, data->role, data->pers);
    userlist_free(&m->b);
    updated = 1;
  } else {
    if ((updated = userlist_delete_member_field(m, data->field)) < 0) {
      CONN_ERR("the field cannot be deleted");
      send_reply(p, -ULS_ERR_CANNOT_DELETE);
      return;
    }
  }

 done:
  if (updated) {
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
  }
  send_reply(p, ULS_OK);
  CONN_INFO("done %d", updated);
}

static void
cmd_edit_field(struct client_state *p, int pkt_len,
               struct userlist_pk_edit_field *data)
{
  struct userlist_user *u;
  struct userlist_member *m;
  int updated = 0;
  int vallen, explen, cap_bit;
  struct userlist_contest *cntsreg;
  struct contest_desc *cnts;
  opcap_t caps;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet is too small: %d", pkt_len);
    return;
  }
  vallen = strlen(data->data);
  if (vallen != data->value_len) {
    CONN_BAD("value_len mismatch: %d, %d", vallen, data->value_len);
    return;
  }
  explen = sizeof(*data) + data->value_len;
  if (pkt_len != explen) {
    CONN_BAD("packet length mismatch: %d, %d", explen, pkt_len);
    return;
  }

  CONN_INFO("%d, %d, %d, %d",
            data->user_id, data->role, data->pers, data->field);
  if (p->user_id < 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (data->user_id <= 0 || data->user_id >= userlist->user_map_size
      || !(u = userlist->user_map[data->user_id])) {
    CONN_ERR("invalid user");
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (data->role < -1 || data->role >= CONTEST_LAST_MEMBER) {
    CONN_ERR("invalid role");
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }

  if (data->role == -1 && data->pers == 0 && data->field == USERLIST_NN_LOGIN){
    if (is_privileged_user(u) >= 0) cap_bit = OPCAP_PRIV_DELETE_USER;
    else cap_bit = OPCAP_DELETE_USER;
  } else {
    if (is_privileged_user(u) >= 0) cap_bit = OPCAP_PRIV_EDIT_USER;
    else cap_bit = OPCAP_EDIT_USER;
  }

  while (1) {
    if (data->user_id == p->user_id
        && (cap_bit == OPCAP_PRIV_EDIT_USER || cap_bit == OPCAP_EDIT_USER))
      break;

    if (get_uid_caps(&config->capabilities, p->user_id, &caps) >= 0
        && opcaps_check(caps, cap_bit) >= 0) break;

    if (u->contests
        && (cap_bit == OPCAP_PRIV_EDIT_USER || cap_bit == OPCAP_EDIT_USER)) {
        for (cntsreg = FIRST_CONTEST(u); cntsreg;
             cntsreg = NEXT_CONTEST(cntsreg)) {
          if (contests_get(cntsreg->id, &cnts) < 0)
            continue;
          if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) < 0)
            continue;
          if (opcaps_check(caps, cap_bit) >= 0) break;
        }
        if (cntsreg) break;
    }

    CONN_ERR("user %d has no capability to edit user %d",
             p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->role == -1) {
    if (data->pers != 0) {
      CONN_ERR("invalid pers");
      send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
      return;
    }
    if (data->field < 0 || data->field > USERLIST_NN_LAST) {
      CONN_ERR("invalid field");
      send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
      return;
    }
    if ((updated=userlist_set_user_field_str(u,data->field,data->data)) < 0) {
      CONN_ERR("the field cannot be changed");
      send_reply(p, -ULS_ERR_CANNOT_CHANGE);
      return;
    }
  } else {
    if (!u->members[data->role]
        || data->pers < 0 || data->pers >= u->members[data->role]->total) {
      CONN_ERR("invalid pers");
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    m = u->members[data->role]->members[data->pers];
    if (!m) {
      CONN_ERR("invalid pers");
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    if (data->field < 0 || data->field > USERLIST_NM_LAST) {
      CONN_ERR("invalid field");
      send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
      return;
    }
    if ((updated=userlist_set_member_field_str(m,data->field,data->data))<0) {
      CONN_ERR("the field cannot be changed");
      send_reply(p, -ULS_ERR_CANNOT_CHANGE);
      return;
    }
  }

  if (updated) {
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
  }
  send_reply(p, ULS_OK);
  CONN_INFO("done %d", updated);
}

static void
cmd_add_field(struct client_state *p, int pkt_len,
              struct userlist_pk_edit_field *data)
{
  struct userlist_user *u;
  struct userlist_member *m;
  int updated = 0, cap_bit;
  struct userlist_contest *reg = 0;
  struct contest_desc *cnts = 0;
  opcap_t caps;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  if (data->value_len != 0) {
    CONN_BAD("value_len != 0: %d", data->value_len);
    return;
  }
  CONN_INFO("%d, %d, %d, %d",
            data->user_id, data->role, data->pers, data->field);
  if (p->user_id < 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);

  if (data->user_id == -1) {
    // the operating user must have CREATE_USER capability
    if (is_db_capable(p, OPCAP_CREATE_USER)) return;

    u = allocate_new_user();
    ASSERT(u->id > 0);
    u->login = xstrdup("New login");
    u->email = xstrdup("New email");
    u->registration_time = cur_time;
    u->last_login_time = cur_time;
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
    send_reply(p, ULS_OK);
    CONN_INFO("added new user: %d", u->id);
    return;
  }

  if (data->user_id <= 0 || data->user_id >= userlist->user_map_size
      || !(u = userlist->user_map[data->user_id])) {
    CONN_ERR("invalid user");
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (is_privileged_user(u) >= 0) cap_bit = OPCAP_PRIV_EDIT_USER;
  else cap_bit = OPCAP_EDIT_USER;

  while (1) {
    if (p->user_id == data->user_id) break;

    if (get_uid_caps(&config->capabilities, p->user_id, &caps) >= 0
        && opcaps_check(caps, cap_bit)) break;

    if (u->contests) {
      for (reg = FIRST_CONTEST(u); reg; reg = NEXT_CONTEST(reg)) {
        if (contests_get(reg->id, &cnts) < 0) continue;
        if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) < 0)
          continue;
        if (opcaps_check(caps, cap_bit) >= 0) break;
      }
      if (reg) break;
    }

    CONN_ERR("user %d cannot change user %d", p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->role < -1 || data->role >= CONTEST_LAST_MEMBER) {
    CONN_ERR("invalid role");
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  if (data->role == -1) {
    if (data->pers != 0 || data->field != -1) {
      CONN_ERR("invalid field");
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    // add a new user
  } else {
    if (data->pers != -1 || data->field != -1) {
      CONN_ERR("invalid field");
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    // add a new participant
    m = (struct userlist_member*) userlist_node_alloc(USERLIST_T_MEMBER);
    m->serial = userlist->member_serial++;
    link_member(u, data->role, m);
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
    send_reply(p, ULS_OK);
    CONN_INFO("added new member: %d", m->serial);
    return;
  }

  if (updated) {
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
  }
  send_reply(p, ULS_OK);
  CONN_INFO("done");
}

/*
 * This request is sent from serve to userlist-server
 * each time client connects to the contest server.
 * Thus the regular logging is disable just to reduce the number
 * of messages in the log.
 */

static void
cmd_get_uid_by_pid(struct client_state *p, int pkt_len,
                   struct userlist_pk_get_uid_by_pid *data)
{
  struct client_state *q = 0;
  struct userlist_pk_uid out;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (data->system_uid < 0 || data->system_gid < 0 || data->system_pid <= 1) {
    CONN_ERR("invalid parameters");
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  for (q = first_client; q; q = q->next) {
    if (q->peer_uid == data->system_uid
        && q->peer_gid == data->system_gid
        && q->peer_pid == data->system_pid)
      break;
  }
  if (!q) {
    CONN_ERR("not found among clients");
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  memset(&out, 0, sizeof(out));
  out.reply_id = ULS_UID;
  out.uid = q->user_id;
  out.priv_level = q->priv_level;
  out.cookie = q->cookie;
  out.ip = q->ip;
  enqueue_reply_to_client(p, sizeof(out), &out);
}

static void (*cmd_table[])() =
{
  [ULS_REGISTER_NEW]            cmd_register_new,
  [ULS_DO_LOGIN]                cmd_do_login,
  [ULS_CHECK_COOKIE]            cmd_check_cookie,
  [ULS_DO_LOGOUT]               cmd_do_logout,
  [ULS_GET_USER_INFO]           cmd_get_user_info,
  [ULS_SET_USER_INFO]           cmd_set_user_info,
  [ULS_SET_PASSWD]              cmd_set_passwd,
  [ULS_GET_USER_CONTESTS]       cmd_get_user_contests,
  [ULS_REGISTER_CONTEST]        cmd_register_contest,
  [ULS_REMOVE_MEMBER]           cmd_remove_member,
  [ULS_PASS_FD]                 cmd_pass_fd,
  [ULS_LIST_USERS]              cmd_list_users,
  [ULS_MAP_CONTEST]             cmd_map_contest,
  [ULS_ADMIN_PROCESS]           cmd_admin_process,
  [ULS_GENERATE_TEAM_PASSWORDS] cmd_generate_team_passwords,
  [ULS_TEAM_LOGIN]              cmd_team_login,
  [ULS_TEAM_CHECK_COOKIE]       cmd_team_check_cookie,
  [ULS_GET_CONTEST_NAME]        cmd_get_contest_name,
  [ULS_TEAM_SET_PASSWD]         cmd_team_set_passwd,
  [ULS_LIST_ALL_USERS]          cmd_list_all_users,
  [ULS_EDIT_REGISTRATION]       cmd_edit_registration,
  [ULS_EDIT_FIELD]              cmd_edit_field,
  [ULS_DELETE_FIELD]            cmd_delete_field,
  [ULS_ADD_FIELD]               cmd_add_field,
  [ULS_GET_UID_BY_PID]          cmd_get_uid_by_pid,
  [ULS_PRIV_LOGIN]              cmd_priv_login,
  [ULS_PRIV_CHECK_COOKIE]       cmd_priv_check_cookie,
  [ULS_DUMP_DATABASE]           cmd_dump_database,
  [ULS_PRIV_GET_USER_INFO]      cmd_priv_get_user_info,
  [ULS_PRIV_REGISTER_CONTEST]   cmd_priv_register_contest,

  [ULS_LAST_CMD] 0
};

static void
process_packet(struct client_state *p, int pkt_len, unsigned char *data)
{
  struct userlist_packet * packet;

  if (pkt_len < sizeof(*data)) {
    bad_packet(p, "length %d < minimum %d", pkt_len, sizeof(*packet));
    return;
  }

  packet = (struct userlist_packet *) data;
  if (packet->id<=0 || packet->id>=ULS_LAST_CMD || !cmd_table[packet->id]) {
    bad_packet(p, "request_id = %d, packet_len = %d", packet->id, pkt_len);
    return;
  }
  (*cmd_table[packet->id])(p, pkt_len, data);
}

static void
do_backup(void)
{
  struct tm *ptm = 0;
  unsigned char *buf = 0;
  FILE *f = 0;
  int fd = -1;

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

  if ((fd = open(buf, O_CREAT | O_TRUNC | O_WRONLY, 0600)) < 0) {
    err("backup: fopen for `%s' failed: %s", buf, os_ErrorMsg());
    return;
  }
  if (!(f = fdopen(fd, "w"))) {
    err("backup: fopen for `%s' failed: %s", buf, os_ErrorMsg());
    close(fd);
    return;
  }
  fd = -1;
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
  int fd = -1;

  if (!dirty) return;

  tempname = os_DirName(config->db_path);
  snprintf(basename, sizeof(basename), "/%lu", generate_random_long());
  tempname = xstrmerge1(tempname, basename);
  info("bdflush: flushing database to `%s'", tempname);
  if ((fd = open(tempname, O_CREAT | O_WRONLY | O_TRUNC, 0600)) < 0) {
    err("bdflush: fopen for `%s' failed: %s", tempname, os_ErrorMsg());
    xfree(tempname);
    return;
  }
  if (!(f = fdopen(fd, "w"))) {
    err("bdflush: fopen for `%s' failed: %s", tempname, os_ErrorMsg());
    xfree(tempname);
    close(fd);
    return;
  }
  fd = -1;
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
  struct client_state *p, *q;

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, interrupt_signal);
  signal(SIGTERM, interrupt_signal);
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

    if (interrupt_signaled) {
      flush_interval = 0;
    }

    // flush database
    if (cur_time > last_flush + flush_interval) {
      flush_database();
    }

    if (cur_time > last_backup + backup_interval) {
      do_backup();
    }

    if (interrupt_signaled) {
      graceful_exit();
    }

    // disconnect idle clients
    /*
    while (1) {
      for (p = first_client; p; p = p->next)
        if (p->last_time + CLIENT_TIMEOUT < cur_time && p->user_id != 0) break;
      if (!p) break;
      info("%d: timeout, client disconnected", p->id);
      disconnect_client(p);
    }
    */

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
        /* p may be invalid */
        for (q = first_client; q && q != p; q = q->next);
        if (q) {
          /* p is valid! */
          p->read_len = 0;
          p->expected_len = 0;
          p->read_state = 0;
          xfree(p->read_buf);
          p->read_buf = 0;
        }
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

  info("userlist-server %s, compiled %s", compile_version, compile_date);

  program_name = argv[0];
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

  // initialize system uid->local uid map
  build_system_uid_map(config->user_map);

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
 * End:
 */
