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
  struct contest_desc *desc;
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
static struct contest_list *contests;
static unsigned char *program_name;
static struct contest_extra **contest_extras;

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
attach_contest_extra(int id)
{
  struct contest_extra *ex = 0;
  key_t ipc_key, shm_key, sem_key;
  int sem_id = -1, shm_id = -1;
  void *shm_addr = 0;

  ASSERT(id > 0 && id < contests->id_map_size);
  ASSERT(contests->id_map[id]);
  if (!contest_extras) {
    contest_extras = xcalloc(contests->id_map_size, sizeof(contest_extras[0]));
  }
  if (contest_extras[id]) {
    contest_extras[id]->nref++;
    return contest_extras[id];
  }

  info("creating shared contest info for %d", id);
  ex = xcalloc(1, sizeof(*ex));
  ex->nref = 1;
  ex->id = id;
  ex->desc = contests->id_map[id];

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

  ASSERT(ex->id > 0 && ex->id < contests->id_map_size);
  ASSERT(ex == contest_extras[ex->id]);
  ASSERT(ex->desc == contests->id_map[ex->id]);
  if (--ex->nref > 0) return 0;
  info("destroying shared contest info for %d", ex->id);
  ex->tbl->vintage = 0xffff;    /* the client must note this change */
  if (shmdt(ex->tbl) < 0) info("shmdt failed: %s", os_ErrorMsg());
  if (shmctl(ex->shm_id,IPC_RMID,0)<0) info("shmctl failed: %s",os_ErrorMsg());
  if (semctl(ex->sem_id,0,IPC_RMID)<0) info("semctl failed: %s",os_ErrorMsg());
  contest_extras[ex->id] = 0;
  memset(ex, 0, sizeof(*ex));
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
  int login_len;
  struct contest_extra *ex;

  ASSERT(cnts_id > 0 && cnts_id < contests->id_map_size);
  ASSERT(contests->id_map[cnts_id]);
  if (!contest_extras || !contest_extras[cnts_id]) return;

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
    for (i = 1; i < contests->id_map_size; i++) {
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
create_newuser(struct client_state *p,
               int pkt_len,
               struct userlist_pk_register_new * data)
{
  struct userlist_user * user;
  char * buf;
  unsigned char * login;
  unsigned char * email;
  unsigned char urlbuf[1024], *urlptr = urlbuf;
  int login_len, email_len;
  struct userlist_passwd *pwd;
  unsigned char passwd_buf[64];
  struct contest_desc *cnts = 0;
  unsigned char * originator_email = 0;

  // validate packet
  login = data->data;
  login_len = strlen(login);
  if (login_len != data->login_length) {
    bad_packet(p, "new_user: login length mismatch");
    return;
  }
  email = data->data + data->login_length + 1;
  email_len = strlen(email);
  if (email_len != data->email_length) {
    bad_packet(p, "new_user: email length mismatch");
    return;
  }
  if (pkt_len != sizeof(*data) + login_len + email_len + 2) {
    bad_packet(p, "new_user: packet length mismatch");
    return;
  }

  info("%d: new_user: %s, %s, %s, %ld", p->id,
       unparse_ip(data->origin_ip), login, email, data->contest_id);

  if (data->contest_id != 0) {
    if (data->contest_id <= 0 || data->contest_id >= contests->id_map_size
        || !(cnts = contests->id_map[data->contest_id])) {
      err("%d: invalid contest id", p->id);
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
  urlptr += sprintf(urlptr, "?action=%d&login=%s", 6, login);
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
      err("%d: login already exists", p->id);
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
  info("%d: new_user: ok, user_id = %d", p->id, user->id);

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
  struct passwd_internal pwdint;

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

  if (passwd_convert_to_internal(password, &pwdint) < 0) {
    err("%d: invalid password", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  user = (struct userlist_user*) userlist->b.first_down;
  while (user) {
    ASSERT(user->b.tag == USERLIST_T_USER);
    if (!strcmp(user->login,login)) {
      if (!user->register_passwd || !user->register_passwd->b.text) {
        info("%d: login_user: EMPTY PASSWORD", p->id);
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
login_team_user(struct client_state *p, int pkt_len,
                struct userlist_pk_do_login * data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  struct userlist_user *u;
  struct passwd_internal pwdint;
  struct contest_desc *cnts = 0;
  struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  struct userlist_cookie *cookie;
  int out_size = 0, login_len, name_len;
  int i;

  if (pkt_len < sizeof(*data)) {
    bad_packet(p, "login_team_user: packet length is too small: %d", pkt_len);
    return;
  }
  login_ptr = data->data;
  if (strlen(login_ptr) != data->login_length) {
    bad_packet(p, "login_team_user: login length mismatch");
    return;
  }
  passwd_ptr = login_ptr + data->login_length + 1;
  if (strlen(passwd_ptr) != data->password_length) {
    bad_packet(p, "login_team_user: password length mismatch");
    return;
  }
  if (pkt_len != sizeof(*data)+data->login_length+data->password_length+2) {
    bad_packet(p, "login_team_user: packet length mismatch");
    return;
  }
  info("%d: login_team_user: %s, %s, %ld, %d, %d", p->id,
       unparse_ip(data->origin_ip), login_ptr, data->contest_id,
       data->locale_id, data->use_cookies);
  if (p->user_id >= 0) {
    err("%d: this connection already authentificated", p->id);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    bad_packet(p, "password parse error");
    return;
  }
  if (data->contest_id <= 0
      || data->contest_id >= contests->id_map_size
      || !(cnts = contests->id_map[data->contest_id])) {
    err("%d: invalid contest identifier", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!contests_check_ip(cnts, data->origin_ip)) {
    err("%d: IP is not allowed", p->id);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }

  for (i = 1; i < userlist->user_map_size; i++) {
    if (!(u = userlist->user_map[i])) continue;
    if (!strcmp(u->login, login_ptr)) break;
  }
  if (i >= userlist->user_map_size) {
    err("%d: BAD LOGIN", p->id);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if(passwd_check(&pwdint,u->team_passwd?u->team_passwd:u->register_passwd)<0){
    err("%d: BAD PASSWORD", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (u->contests) {
    for (c = (struct userlist_contest*) u->contests->first_down;
         c; c = (struct userlist_contest*) c->b.right) {
      if (c->id == data->contest_id) break;
    }
  }
  if (!c || c->status != USERLIST_REG_OK || (c->status & USERLIST_UC_BANNED)) {
    err("%d: not allowed to participate", p->id);
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
  enqueue_reply_to_client(p, out_size, out);
  dirty = 1;
  u->last_login_time = cur_time;
  info("%d: login_team_user: %d,%s,%llx", p->id, u->id, u->login,out->cookie);
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
login_team_cookie(struct client_state *p, int pkt_len,
                  struct userlist_pk_check_cookie * data)
{
  struct contest_desc *cnts = 0;
  struct userlist_user *u;
  struct userlist_cookie *cookie;
  struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  int i, out_size = 0, login_len = 0, name_len = 0;
  unsigned char *login_ptr, *name_ptr;

  if (pkt_len != sizeof(*data)) {
    bad_packet(p, "login_team_cookie: bad packet length %d", pkt_len);
    return;
  }
  info("%d: login_team_cookie: %s, %ld, %llx, %d",
       p->id, unparse_ip(data->origin_ip), data->contest_id,
       data->cookie, data->locale_id);
  if (p->user_id >= 0) {
    err("%d: this connection already authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (data->contest_id) {
    if (data->contest_id < 0 || data->contest_id >= contests->id_map_size
        || !(cnts = contests->id_map[data->contest_id])) {
      err("%d: invalid contest identifier", p->id);
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
  }
  if (!data->cookie) {
    err("%d: cookie value is 0", p->id);
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
          && cookie->expire > cur_time
          && cookie->cookie == data->cookie) break;
    }
    if (cookie) break;
  }
  if (i >= userlist->user_map_size) {
    err("%d: cookie not found", p->id);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  if (!data->contest_id) {
    data->contest_id = cookie->contest_id;
  }
  if (data->locale_id == -1) {
    data->locale_id = cookie->locale_id;
  }
  if (data->contest_id <= 0
      || data->contest_id >= contests->id_map_size
      || !(cnts = contests->id_map[data->contest_id])) {
    err("%d: invalid contest identifier", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!contests_check_ip(cnts, data->origin_ip)) {
    err("%d: IP is not allowed", p->id);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }
  if (u->contests) {
    for (c = (struct userlist_contest*) u->contests->first_down;
         c; c = (struct userlist_contest*) c->b.right) {
      if (c->id == data->contest_id) break;
    }
  }
  if (!c || c->status != USERLIST_REG_OK || (c->status & USERLIST_UC_BANNED)) {
    err("%d: not allowed to participate", p->id);
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
  enqueue_reply_to_client(p, out_size, out);
  dirty = 1;
  u->last_login_time = cur_time;
  info("%d: login_team_cookie: %d,%s", p->id, u->id, u->login);
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
  int mode = 1;

  if (pkt_len != sizeof(*pack)) {
    bad_packet(p, "");
    return;
  }

  info("%d: get_user_info: %ld", p->id, pack->user_id);

  if (pack->user_id < 0 || pack->user_id >= userlist->user_map_size
      || !userlist->user_map[pack->user_id]) {
    err("%d: invalid user id", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (p->user_id != 0 && (p->user_id < 0 || p->user_id != pack->user_id)) {
    err("%d: permission denied", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  user = userlist->user_map[pack->user_id];

  if (!(f = open_memstream((char**) &xml_ptr, &xml_size))) {
    err("%d: open_memstream failed!", p->id);
    return;
  }
  if (!p->user_id) mode = 0;
  userlist_unparse_user(user, f, mode);
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
cmd_list_all_users(struct client_state *p,
                   int len,
                   struct userlist_pk_map_contest *pack)
{
  FILE *f = 0;
  unsigned char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;

  if (len != sizeof(*pack)) {
    bad_packet(p, "list_all_users: packet length mismatch");
    return;
  }

  info("%d: list_all_users: %d", p->id, pack->contest_id);
  if (p->user_id != 0) {
    err("%d: only administrator is allowed to do that", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->contest_id &&
      (pack->contest_id < 1 || pack->contest_id >= contests->id_map_size
       || !contests->id_map[pack->contest_id])) {
    err("%d: invalid contest id", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  f = open_memstream((char**) &xml_ptr, &xml_size);
  ASSERT(f);
  userlist_unparse_short(userlist, f, pack->contest_id);
  fclose(f);
  ASSERT(xml_size == strlen(xml_ptr));
  if (xml_size > 65535) {
    err("%d: XML data is too large", p->id);
    send_reply(p, -ULS_ERR_INVALID_SIZE);
    return;
  }
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
    err("%d: client not authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != pack->user_id) {
    err("%d: user_id does not match", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  //fprintf(stderr, "======\n%s\n======\n", pack->data);

  if (!(new_u = userlist_parse_user_str(pack->data))) {
    err("%d: XML parse error", p->id);
    send_reply(p, -ULS_ERR_XML_PARSE);
    return;
  }

  if (pack->user_id != new_u->id) {
    err("%d: XML user_id %d does not correspond to packet user_id %lu",
        p->id, new_u->id, pack->user_id);
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
set_password(struct client_state *p, int len,
             struct userlist_pk_set_password *pack)
{
  int old_len, new_len;
  unsigned char *old_pwd, *new_pwd;
  struct userlist_user *u;
  struct passwd_internal oldint, newint;

  // check packet
  if (len < sizeof(*pack)) {
    bad_packet(p, "set_password: bad packet length %d", len);
    return;
  }
  old_pwd = pack->data;
  old_len = strlen(old_pwd);
  if (old_len != pack->old_len) {
    bad_packet(p, "set_password: old password length mismatch");
    return;
  }
  new_pwd = old_pwd + old_len + 1;
  new_len = strlen(new_pwd);
  if (new_len != pack->new_len) {
    bad_packet(p, "set_password: new password length mismatch");
    return;
  }
  if (len != sizeof(*pack) + old_len + new_len + 2) {
    bad_packet(p, "set_password: packet length mismatch");
    return;
  }

  info("%d: set_password: %d", p->id, pack->user_id);
  if (p->user_id <= 0) {
    err("%d: client not authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != pack->user_id) {
    err("%d: user_id does not match", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size) {
    err("%d: user id is out of range", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  u = userlist->user_map[pack->user_id];
  if (!u) {
    err("%d: user id nonexistent", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (!new_len) {
    err("%d: new password cannot be empty", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (!u->register_passwd || !u->register_passwd->b.text) {
    err("%d: password is not set for %d", p->id, p->user_id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(old_pwd, &oldint) < 0) {
    err("%d: cannot parse old password", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(new_pwd, &newint) < 0) {
    err("%d: cannot parse new password", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_check(&oldint, u->register_passwd) < 0) {
    err("%d: provided password does not match", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
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
}

static void
team_set_password(struct client_state *p, int len,
                  struct userlist_pk_set_password *pack)
{
  int old_len, new_len;
  unsigned char *old_pwd, *new_pwd;
  struct userlist_user *u;
  struct passwd_internal oldint, newint;

  // check packet
  if (len < sizeof(*pack)) {
    bad_packet(p, "team_set_password: bad length %d", len);
    return;
  }
  old_pwd = pack->data;
  old_len = strlen(old_pwd);
  if (old_len != pack->old_len) {
    bad_packet(p, "team_set_password: old password length mismatch");
    return;
  }
  new_pwd = old_pwd + old_len + 1;
  new_len = strlen(new_pwd);
  if (new_len != pack->new_len) {
    bad_packet(p, "team_set_password: new password length mismatch");
    return;
  }
  if (len != sizeof(*pack) + old_len + new_len + 2) {
    bad_packet(p, "team_set_password: packet length mismatch %d, %d",
               len, sizeof(*pack) + old_len + new_len + 2);
    return;
  }

  info("%d: team_set_password: %d", p->id, pack->user_id);
  if (p->user_id <= 0) {
    err("%d: client not authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != pack->user_id) {
    err("%d: user_id does not match", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size) {
    err("%d: user id is out of range", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  u = userlist->user_map[pack->user_id];
  if (!u) {
    err("%d: user id nonexistent", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (!new_len) {
    err("%d: new password cannot be empty", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(old_pwd, &oldint) < 0) {
    err("%d: cannot parse old password", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(new_pwd, &newint) < 0) {
    err("%d: cannot parse new password", p->id);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  // verify the existing password
  if (u->team_passwd) {
    if (passwd_check(&oldint, u->team_passwd) < 0) {
      err("%d: OLD team password does not match", p->id);
      if (passwd_check(&oldint, u->register_passwd) < 0) {
        err("%d: OLD password does not match", p->id);
        send_reply(p, -ULS_ERR_INVALID_PASSWORD);
        return;
      }
    }
  } else {
    if (passwd_check(&oldint, u->register_passwd) < 0) {
      err("%d: OLD password does not match", p->id);
      send_reply(p, -ULS_ERR_INVALID_PASSWORD);
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
  info("%d: ok", p->id);
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
  if (p->user_id < 0) {
    err("%d: client not authentificated", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size) {
    err("%d: user id is out of range", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  u = userlist->user_map[pack->user_id];
  if (!u) {
    err("%d: user id nonexistent", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (pack->contest_id <= 0 || pack->contest_id >= contests->id_map_size) {
    err("%d: contest id is out of range", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  c = contests->id_map[pack->contest_id];
  if (!c) {
    err("%d: contest id is nonexistent", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (p->user_id > 0) {
    if (p->user_id != pack->user_id) {
      err("%d: user_id does not match", p->id);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    if (c->reg_deadline && cur_time > c->reg_deadline) {
      err("%d: registration deadline exceeded", p->id);
      send_reply(p, -ULS_ERR_DEADLINE);
      return;
    }
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
    update_userlist_table(pack->contest_id);
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

static void
do_list_users(FILE *f, int contest_id, int locale_id,
              int user_id, unsigned long flags,
              unsigned char *url, unsigned char *srch)
{
  struct userlist_user *u;
  struct userlist_contest *c;
  struct userlist_user **us = 0;
  struct userlist_contest **cs = 0;
  struct contest_desc *d, *tmpd;
  struct contest_member *cm;
  struct userlist_member *m;
  int u_num = 0, i, regtot;
  unsigned char *s;
  unsigned char buf[1024];
  unsigned char *notset = 0;
  int role, pers;

  if (flags) {
    d = 0;
    if (contest_id) {
      ASSERT(contest_id > 0);
      ASSERT(contest_id < contests->id_map_size);
      d = contests->id_map[contest_id];
      ASSERT(d);
    }

    setup_locale(locale_id);
    notset = "";
    for (i = 1; i < userlist->user_map_size; i++) {
      if (!(u = userlist->user_map[i])) continue;
      if (d && !u->contests) continue;
      if (d) {
        for (c = FIRST_CONTEST(u); c; c = NEXT_CONTEST(c)) {
          if (c->id == d->id) break;
        }
        if (!c) continue;
      }
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

          fprintf(f, ";%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n",
                  u->id, u->login, u->name, u->email,
                  u->inst?u->inst:notset,
                  u->instshort?u->instshort:notset,
                  u->fac?u->fac:notset,
                  u->facshort?u->facshort:notset,
                  gettext(member_string[role]),
                  m->surname?m->surname:notset,
                  m->firstname?m->firstname:notset,
                  m->middlename?m->middlename:notset,
                  gettext(member_status_string[m->status]),
                  lptr?lptr:notset);
        }
      }
    }
    setup_locale(0);

    return;
  }

  if (user_id > 0) {
    ASSERT(user_id > 0);
    ASSERT(user_id < userlist->user_map_size);
    u = userlist->user_map[user_id];
    ASSERT(u);

    d = 0;
    if (contest_id) {
      ASSERT(contest_id > 0);
      ASSERT(contest_id < contests->id_map_size);
      d = contests->id_map[contest_id];
      ASSERT(d);
    }

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
        if (c->id <= 0 || c->id >= contests->id_map_size
            || !contests->id_map[c->id]) continue;
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
        if (c->id <= 0 || c->id >= contests->id_map_size
            || !(tmpd = contests->id_map[c->id])) continue;
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
list_users(struct client_state *p, int len,
           struct userlist_pk_list_users *pack)
{
  struct client_state *q;
  FILE *f = 0;
  unsigned char *html_ptr = 0;
  size_t html_size = 0;
  unsigned char *url_ptr, *srch_ptr;

  if (len < sizeof (*pack)) {
    bad_packet(p, "list_users: packet too short");
    return;
  }
  url_ptr = pack->data;
  if (strlen(url_ptr) != pack->url_len) {
    bad_packet(p, "list_users: url length mismatch");
    return;
  }
  srch_ptr = url_ptr + pack->url_len + 1;
  if (strlen(srch_ptr) != pack->srch_len) {
    bad_packet(p, "list_users: srch length mismatch");
    return;
  }
  if (len != sizeof(*pack) + pack->url_len + pack->srch_len + 2) {
    bad_packet(p, "list_users: packet length mismatch");
    return;
  }
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("%d: two client file descriptors required", p->id);
    disconnect_client(p);
    return;
  }
  if (pack->user_id) {
    if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size
        || !userlist->user_map[pack->user_id]) {
      err("%d: invalid user %d", p->id, pack->user_id);
      send_reply(p, -ULS_ERR_BAD_UID);
      return;
    }
  }
  if (pack->contest_id <= 0 || pack->contest_id >= contests->id_map_size
      || !contests->id_map[pack->contest_id]) {
    err("%d: invalid contest %ld", p->id, pack->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (!(f = open_memstream((char**) &html_ptr, &html_size))) {
    err("%d: open_memstream failed!", p->id);
    return;
  }
  do_list_users(f, pack->contest_id, pack->locale_id,
                pack->user_id, pack->flags, url_ptr, srch_ptr);
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
  info("%d: created new connection %d", p->id, q->id);
  send_reply(p, ULS_OK);
}

static void
cmd_map_contest(struct client_state *p, int len,
                struct userlist_pk_map_contest *pack)
{
  struct contest_desc *cnts = 0;
  struct contest_extra *ex = 0;
  size_t out_size;
  struct userlist_pk_contest_mapped *out;

  if (len != sizeof(*pack)) {
    bad_packet(p, "map_contest: bad packet length: %d", len);
    return;
  }
  info("%d: map_contest: %d", p->id, pack->contest_id);
  if (p->user_id != 0) {
    err("%d: map_contest: permission denied: %d", p->id, p->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->contest_id <= 0 || pack->contest_id >= contests->id_map_size) {
    err("%d: map_contest: contest identifier is out of range", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!(cnts = contests->id_map[pack->contest_id])) {
    err("%d: map_contest: nonexistant contest", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!(ex = attach_contest_extra(pack->contest_id))) {
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
  update_userlist_table(pack->contest_id);
  info("%d: map_contest: %d, %d", p->id, ex->sem_key, ex->shm_key);
}

static void
cmd_admin_process(struct client_state *p, int len,
                  struct userlist_packet *pack)
{
  unsigned char proc_buf[1024];
  unsigned char exe_buf[1024];
  struct userlist_cfg_admin_proc *prc;

  if (len != sizeof(*pack)) {
    bad_packet(p, "admin_process: bad packet length: %d", len);
    return;
  }
  info("%d: admin_process: %d, %d", p->id, p->peer_pid, p->peer_uid);
  // try just an user
  for (prc = (struct userlist_cfg_admin_proc*) config->admin_processes->first_down; prc; prc = (struct userlist_cfg_admin_proc*) prc->b.right) {
    if (prc->uid == p->peer_uid && !strcmp(prc->path, "ANY")) break;
  }
  if (!prc) {
    snprintf(proc_buf, sizeof(proc_buf), "/proc/%d/exe", p->peer_pid);
    memset(exe_buf, 0, sizeof(exe_buf));
    if (readlink(proc_buf, exe_buf, sizeof(exe_buf) - 1) < 0) {
      err("%d: admin_process: readlink failed: %s", p->id, os_ErrorMsg());
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;    
    }
    info("%d: admin_process: path = %s", p->id, exe_buf);
    if (!config->admin_processes) {
      err("%d: admin_process: no admin processes specified", p->id);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    for (prc = (struct userlist_cfg_admin_proc *) config->admin_processes->first_down; prc; prc = (struct userlist_cfg_admin_proc*) prc->b.right) {
      if (!strcmp(prc->path, exe_buf) && prc->uid == p->peer_uid) break;
    }
  }
  if (!prc) {
    err("%d: admin_process: no such admin process", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  send_reply(p, ULS_OK);
  p->user_id = 0;
  info("%d: admin_process: ok", p->id);
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
cmd_generate_team_passwd(struct client_state *p, int len,
                         struct userlist_pk_map_contest *pack)
{
  unsigned char *log_ptr = 0;
  size_t log_size = 0;
  FILE *f = 0;
  struct client_state *q = 0;

  if (len != sizeof(*pack)) {
    bad_packet(p, "generate_team_paswords: bad length %d", len);
    return;
  }
  info("%d: generate_team_paswords: %d", p->id, pack->contest_id);
  if (p->user_id != 0) {
    err("%d: only administrator can do that", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->contest_id <= 0 || pack->contest_id >= contests->id_map_size
      || !contests->id_map[pack->contest_id]) {
    err("%d: invalid contest identifier", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("%d: two client file descriptors required", p->id);
    disconnect_client(p);
    return;
  }
  if (!(f = open_memstream((char**) &log_ptr, &log_size))) {
    err("%d: open_memstream failed!", p->id);
    disconnect_client(p);
    return;
  }
  do_generate_team_passwd(pack->contest_id, f);
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
  info("%d: created new connection %d", p->id, q->id);
  send_reply(p, ULS_OK);
}

static void
cmd_get_contest_name(struct client_state *p, int len,
                     struct userlist_pk_map_contest *pack)
{
  struct userlist_pk_xml_data *out = 0;
  struct contest_desc *cnts = 0;
  int out_size = 0, name_len = 0;

  if (len != sizeof(*pack)) {
    bad_packet(p, "get_contest_name: bad length %d", len);
    return;
  }
  info("%d: get_contest_name: %d", p->id, pack->contest_id);
  if (pack->contest_id <= 0 || pack->contest_id >= contests->id_map_size
      || !(cnts = contests->id_map[pack->contest_id])) {
    err("%d: invalid contest identifier", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  name_len = strlen(cnts->name);
  if (name_len > 65535) {
    err("%d: contest name is too long", p->id);
    name_len = 65535;
  }
  out_size = sizeof(*out) + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = out_size;
  memcpy(out->data, cnts->name, name_len);
  enqueue_reply_to_client(p, out_size, out);
  info("%d: get_contest_name: %d", p->id, out->info_len);
}

static void
cmd_edit_registration(struct client_state *p, int len,
                      struct userlist_pk_edit_registration *pack)
{
  struct userlist_user *u;
  struct contest_desc *c;
  struct userlist_contest *uc = 0;
  unsigned int new_flags;
  int updated = 0;

  if (len != sizeof(*pack)) {
    bad_packet(p, "edit_registration: packet length mismatch");
    return;
  }
  info("%d: edit_registration: %d, %d, %d, %d, %08x",
       p->id, pack->user_id, pack->contest_id, pack->new_status,
       pack->flags_cmd, pack->new_flags);
  if (p->user_id != 0) {
    err("%d: only administrator can do that", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size
      || !(u = userlist->user_map[pack->user_id])) {
    err("%d: invalid user", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (pack->contest_id <= 0 || pack->contest_id >= contests->id_map_size
      || !(c = contests->id_map[pack->contest_id])) {
    err("%d: invalid contest", p->id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (u->contests) {
    for (uc = (struct userlist_contest*) u->contests->first_down;
         uc; uc = (struct userlist_contest*) uc->b.right) {
      if (uc->id == pack->contest_id) break;
    }
  }
  if (!uc) {
    err("%d: not registered", p->id);
    send_reply(p, -ULS_ERR_NOT_REGISTERED);
    return;
  }
  if (pack->new_status < -2 || pack->new_status >= USERLIST_REG_LAST) {
    err("%d: invalid new status", p->id);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if (pack->flags_cmd < 0 || pack->flags_cmd > 3) {
    err("%d: invalid flags command", p->id);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if ((pack->new_flags & ~USERLIST_UC_ALL)) {
    err("%d: invalid new flags", p->id);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if (pack->new_status == -2) {
    xml_unlink_node(&uc->b);
    if (!u->contests->first_down) {
      xml_unlink_node(u->contests);
      u->contests = 0;
    }
    updated = 1;
    info("%d: registration deleted", p->id);
  } else {
    if (pack->new_status != -1 && uc->status != pack->new_status) {
      uc->status = pack->new_status;
      updated = 1;
      info("%d: status changed", p->id);
    }
    new_flags = uc->flags;
    switch (pack->flags_cmd) {
    case 1: new_flags |= pack->new_flags; break;
    case 2: new_flags &= ~pack->new_flags; break;
    case 3: new_flags ^= pack->new_flags; break;
    }
    if (new_flags != uc->flags) {
      uc->flags = new_flags;
      info("%d: flags changed", p->id);
      updated = 1;
    }
  }
  if (updated) {
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
    update_userlist_table(c->id);
  }
  info("%d: edit_registration: ok", p->id);
  send_reply(p, ULS_OK);
}

static void
cmd_delete_field(struct client_state *p, int len,
                 struct userlist_pk_edit_field *pack)
{
  struct userlist_user *u;
  struct userlist_member *m;
  int updated = 0;

  if (len != sizeof(*pack) + 1) {
    bad_packet(p, "delete_field: packet length mismatch: %d", len);
    return;
  }
  info("%d: delete_field: %d, %d, %d, %d",
       p->id, pack->user_id, pack->role, pack->pers, pack->field);
  if (p->user_id != 0) {
    err("%d: only administrator can do that", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size
      || !(u = userlist->user_map[pack->user_id])) {
    err("%d: invalid user", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (pack->role < -2 || pack->role >= CONTEST_LAST_MEMBER) {
    err("%d: invalid role", p->id);
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  if (pack->role == -2) {
    // delete the whole user
    do_remove_user(u);
    updated = 1;
  } else if (pack->role == -1) {
    if (pack->pers == -1) {
      do_remove_user(u);
      updated = 1;
    } else if (pack->pers == 2) {
      // cookies
      if (pack->field == -1) {
        // remove all cookies
        if (!u->cookies) {
          info("%d: no cookies", p->id);
        } else {
          xml_unlink_node(u->cookies);
          userlist_free(u->cookies);
          u->cookies = 0;
          info("%d: removed all cookies", p->id);
          updated = 1;
        }
      } else {
        // remove one particular cookie
        if (!u->cookies) {
          info("%d: no cookies", p->id);
        } else {
          int i;
          struct userlist_cookie *cook = 0;
          for (cook = FIRST_COOKIE(u), i = 0;
               cook && i != pack->field; cook = NEXT_COOKIE(cook), i++);
          if (!cook) {
            info("%d: no such cookie %d", p->id, pack->field);
          } else {
            xml_unlink_node(&cook->b);
            userlist_free(&cook->b);
            if (!u->cookies->first_down) {
              xml_unlink_node(u->cookies);
              userlist_free(u->cookies);
              u->cookies = 0;
            }
            info("%d: removed cookie", p->id);
            updated = 1;
          }
        }
      }
    } else if (pack->pers != 0) {
      err("%d: invalid pers", p->id);
      send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
      return;
    } else {
      if (pack->field < 0 || pack->field > USERLIST_NN_LAST) {
        err("%d: invalid field", p->id);
        send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
        return;
      }
      if ((updated = userlist_delete_user_field(u, pack->field)) < 0) {
        err("%d: the field cannot be deleted", p->id);
        send_reply(p, -ULS_ERR_CANNOT_DELETE);
        return;
      }
    }
  } else {
    if (!u->members[pack->role]
        || pack->pers < 0 || pack->pers >= u->members[pack->role]->total) {
      err("%d: invalid pers", p->id);
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    m = u->members[pack->role]->members[pack->pers];
    if (!m) {
      err("%d: invalid pers", p->id);
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    if (pack->field < -1 || pack->field > USERLIST_NM_LAST) {
      err("%d: invalid field", p->id);
      send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
      return;
    }
    if (pack->field == -1) {
      // remove the whole member
      m = unlink_member(u, pack->role, pack->pers);
      userlist_free(&m->b);
      updated = 1;
    } else {
      if ((updated = userlist_delete_member_field(m, pack->field)) < 0) {
        err("%d: the field cannot be deleted", p->id);
        send_reply(p, -ULS_ERR_CANNOT_DELETE);
        return;
      }
    }
  }

  if (updated) {
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
  }
  send_reply(p, ULS_OK);
  info("%d: delete_field: done %d", p->id, updated);
}

static void
cmd_edit_field(struct client_state *p, int len,
               struct userlist_pk_edit_field *pack)
{
  struct userlist_user *u;
  struct userlist_member *m;
  int updated = 0;

  if (len < sizeof(*pack)) {
    bad_packet(p, "edit_field: length is too small: %d", len);
    return;
  }
  if (strlen(pack->data) != pack->value_len) {
    bad_packet(p, "edit_field: value length mismatch");
    return;
  }
  if (len != sizeof(*pack) + pack->value_len + 1) {
    bad_packet(p, "edit_field: packet length mismatch");
    return;
  }
  info("%d: edit_field: %d, %d, %d, %d",
       p->id, pack->user_id, pack->role, pack->pers, pack->field);
  if (p->user_id != 0) {
    err("%d: only administrator can do that", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size
      || !(u = userlist->user_map[pack->user_id])) {
    err("%d: invalid user", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (pack->role < -1 || pack->role >= CONTEST_LAST_MEMBER) {
    err("%d: invalid role", p->id);
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  if (pack->role == -1) {
    if (pack->pers != 0) {
      err("%d: invalid pers", p->id);
      send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
      return;
    }
    if (pack->field < 0 || pack->field > USERLIST_NN_LAST) {
      err("%d: invalid field", p->id);
      send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
      return;
    }
    if ((updated=userlist_set_user_field_str(u,pack->field,pack->data)) < 0) {
      err("%d: the field cannot be changed", p->id);
      send_reply(p, -ULS_ERR_CANNOT_CHANGE);
      return;
    }
  } else {
    if (!u->members[pack->role]
        || pack->pers < 0 || pack->pers >= u->members[pack->role]->total) {
      err("%d: invalid pers", p->id);
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    m = u->members[pack->role]->members[pack->pers];
    if (!m) {
      err("%d: invalid pers", p->id);
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    if (pack->field < 0 || pack->field > USERLIST_NM_LAST) {
      err("%d: invalid field", p->id);
      send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
      return;
    }
    if ((updated=userlist_set_member_field_str(m,pack->field,pack->data))<0) {
      err("%d: the field cannot be changed", p->id);
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
  info("%d: edit_field: done %d", p->id, updated);
}

static void
cmd_add_field(struct client_state *p, int len,
              struct userlist_pk_edit_field *pack)
{
  struct userlist_user *u;
  struct userlist_member *m;
  int updated = 0;

  if (len != sizeof(*pack) + 1) {
    bad_packet(p, "add_field: packet length mismatch: %d", len);
    return;
  }
  if (pack->value_len != 0) {
    bad_packet(p, "add_field: value_len not 0: %d", pack->value_len);
    return;
  }
  info("%d: add_field: %d, %d, %d, %d", p->id, pack->user_id,
       pack->role, pack->pers, pack->field);
  if (p->user_id != 0) {
    err("%d: only administrator can do that", p->id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (pack->user_id == -1) {
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
    info("add_field: added new user: %d", u->id);
    return;
  }
  if (pack->user_id <= 0 || pack->user_id >= userlist->user_map_size
      || !(u = userlist->user_map[pack->user_id])) {
    err("%d: invalid user", p->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (pack->role < -1 || pack->role >= CONTEST_LAST_MEMBER) {
    err("%d: invalid role", p->id);
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  if (pack->role == -1) {
    if (pack->pers != 0 || pack->field != -1) {
      err("%d: invalid field", p->id);
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    // add a new user
  } else {
    if (pack->pers != -1 || pack->field != -1) {
      err("%d: invalid field", p->id);
      send_reply(p, -ULS_ERR_BAD_MEMBER);
      return;
    }
    // add a new participant
    m = (struct userlist_member*) userlist_node_alloc(USERLIST_T_MEMBER);
    m->serial = userlist->member_serial++;
    link_member(u, pack->role, m);
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
    send_reply(p, ULS_OK);
    info("add_field: added new member: %d", m->serial);
    return;
  }

  if (updated) {
    dirty = 1;
    flush_interval /= 2;
    u->last_change_time = cur_time;
  }
  send_reply(p, ULS_OK);
  info("add_field: done");
}

static void
cmd_get_uid_by_pid(struct client_state *p, int len,
                   struct userlist_pk_get_uid_by_pid *pack)
{
  struct client_state *q = 0;
  struct userlist_pk_uid out;

  if (len != sizeof(*pack)) {
    bad_packet(p, "get_uid_by_pid: packet lendth mismatch: %d", len);
    return;
  }
  info("%d: get_uid_by_pid: %d, %d, %d", p->id, pack->system_uid,
       pack->system_gid, pack->system_pid);
  if (pack->system_uid < 0 || pack->system_gid < 0 || pack->system_pid <= 1) {
    err("%d: invalid parameters", p->id);
    send_reply(p, ULS_ERR_BAD_UID);
    return;
  }

  for (q = first_client; q; q = q->next) {
    if (q->peer_uid == pack->system_uid
        && q->peer_gid == pack->system_gid
        && q->peer_pid == pack->system_pid)
      break;
  }
  if (!q) {
    err("%d: not found among clients", p->id);
    send_reply(p, ULS_ERR_INVALID_LOGIN);
    return;
  }

  memset(&out, 0, sizeof(out));
  out.reply_id = ULS_UID;
  out.uid = q->user_id;
  // FIXME: fetch the actual cookie
  out.cookie = 0;
  info("%d: get_uid_by_pid: %d, %016llx", p->id, out.uid, out.cookie);
  enqueue_reply_to_client(p, sizeof(out), &out);
}

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

  case ULS_LIST_USERS:
    list_users(p, len, (struct userlist_pk_list_users*) pack);
    break;

  case ULS_MAP_CONTEST:
    cmd_map_contest(p, len, (struct userlist_pk_map_contest*) pack);
    break;

  case ULS_ADMIN_PROCESS:
    cmd_admin_process(p, len, (struct userlist_packet*) pack);
    break;

  case ULS_GENERATE_TEAM_PASSWORDS:
    cmd_generate_team_passwd(p, len, (struct userlist_pk_map_contest*) pack);
    break;

  case ULS_TEAM_LOGIN:
    login_team_user(p, len, (struct userlist_pk_do_login*) pack);
    break;

  case ULS_TEAM_CHECK_COOKIE:
    login_team_cookie(p, len, (struct userlist_pk_check_cookie*) pack);
    break;

  case ULS_GET_CONTEST_NAME:
    cmd_get_contest_name(p, len, (struct userlist_pk_map_contest*) pack);
    break;

  case ULS_TEAM_SET_PASSWD:
    team_set_password(p, len, (struct userlist_pk_set_password *) pack);
    break;

  case ULS_LIST_ALL_USERS:
    cmd_list_all_users(p, len, (struct userlist_pk_map_contest*) pack);
    break;

  case ULS_EDIT_REGISTRATION:
    cmd_edit_registration(p, len,
                          (struct userlist_pk_edit_registration*) pack);
    break;

  case ULS_EDIT_FIELD:
    cmd_edit_field(p, len, (struct userlist_pk_edit_field*) pack);
    break;

  case ULS_DELETE_FIELD:
    cmd_delete_field(p, len, (struct userlist_pk_edit_field*) pack);
    break;

  case ULS_ADD_FIELD:
    cmd_add_field(p, len, (struct userlist_pk_edit_field*) pack);
    break;

  case ULS_GET_UID_BY_PID:
    cmd_get_uid_by_pid(p, len, (struct userlist_pk_get_uid_by_pid*) pack);
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
  struct client_state *p;

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
    while (1) {
      for (p = first_client; p; p = p->next)
        if (p->last_time + CLIENT_TIMEOUT < cur_time && p->user_id != 0) break;
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

  info("userlist-server %s, compiled %s", compile_version, compile_date);

  program_name = argv[0];
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
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
