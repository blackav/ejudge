/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ispras.ru> */

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

#include "ejudge_cfg.h"
#include "userlist.h"
#include "pathutl.h"
#include "errlog.h"
#include "base64.h"
#include "userlist_proto.h"
#include "contests.h"
#include "version.h"
#include "sha.h"
#include "misctext.h"
#include "l10n.h"
#include "tsc.h"
#include "sformat.h"
#include "fileutl.h"
#include "job_packet.h"
#include "ejudge_plugin.h"
#include "uldb_plugin.h"
#include "xml_utils.h"
#include "random.h"

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
#include <string.h>
#include <zlib.h>
#include <pwd.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#endif

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

#define DEFAULT_COOKIE_CHECK_INTERVAL 60
#define DEFAULT_USER_CHECK_INTERVAL 600
#define CLIENT_TIMEOUT 600
#define MAX_EXPECTED_LEN MAX_USERLIST_PACKET_LEN

#define CONN_ERR(msg, ...) err("%d: %s: " msg, p->id, __FUNCTION__, ## __VA_ARGS__)
#define CONN_INFO(msg, ...) info("%d: %s: " msg, p->id, __FUNCTION__, ## __VA_ARGS__)
#define CONN_BAD(msg, ...) do { err("%d: %s: bad packet: " msg, p->id, __FUNCTION__, ##__VA_ARGS__); disconnect_client(p); } while (0)

static void graceful_exit(void) __attribute__((noreturn));

// server connection states
enum
  {
    STATE_READ_CREDS,
    STATE_READ_DATA,
    STATE_READ_FDS,
    STATE_AUTOCLOSE,
  };

struct contest_extra
{
  int nref;
  int id;
  key_t shm_key;
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
  ej_cookie_t cookie;
  ej_ip_t ip;
  int ssl;

  // user capabilities
  //opcap_t caps;

  // passed file descriptors
  int client_fds[2];

  // attached contest exchange info
  struct contest_extra *cnts_extra;
};

static struct ejudge_cfg *config;
static int listen_socket = -1;
static char *socket_name;
static struct client_state *first_client;
static struct client_state *last_client;
static int serial_id = 1;
static unsigned char *program_name;
static struct contest_extra **contest_extras;
static int contest_extras_size;

static time_t cur_time;
static time_t last_cookie_check;
static time_t last_user_check;
static time_t cookie_check_interval;
static time_t user_check_interval;
static int interrupt_signaled;
static int daemon_mode = 0;
static int forced_mode = 0;

static int server_start_time = 0;
static int server_finish_time = 0;

// plugin information
struct uldb_loaded_plugin
{
  struct uldb_plugin_iface *iface;
  void *data;
};

enum { ULDB_PLUGIN_MAX_NUM = 16 };
static int uldb_plugins_num;
static struct uldb_loaded_plugin uldb_plugins[ULDB_PLUGIN_MAX_NUM];
static struct uldb_loaded_plugin *uldb_default = 0;

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
#define gettext(x) x
#endif

#define FIRST_CONTEST(u) ((struct userlist_contest*)(u)->contests->first_down)
#define NEXT_CONTEST(c)  ((struct userlist_contest*)(c)->b.right)

static struct contest_extra *
attach_contest_extra(int id, struct contest_desc *cnts)
{
  struct contest_extra *ex = 0;
  key_t ipc_key, shm_key;
  int shm_id = -1;
  void *shm_addr = 0;

  ASSERT(id > 0);
  ASSERT(cnts);
  if (!contest_extras || id >= contest_extras_size) {
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

  if (!daemon_mode)
    info("creating shared contest info for %d", id);
  ex = xcalloc(1, sizeof(*ex));
  ex->nref = 1;
  ex->id = id;

  ipc_key = ftok(program_name, id);
  shm_key = ipc_key;
  while (1) {
    shm_id = shmget(shm_key, sizeof(struct userlist_table),
                    0644 | IPC_CREAT | IPC_EXCL);
    if (shm_id >= 0) break;
    if (errno != EEXIST) {
      err("shmget failed: %s", os_ErrorMsg());
      goto cleanup;
    }
    shm_key++;
    if (!shm_key) shm_key = 1;
  }
  if ((long) (shm_addr = shmat(shm_id, 0, 0)) == -1) {
    err("shmat failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  memset(shm_addr, 0, sizeof(struct userlist_table));
  ex->shm_key = shm_key;
  ex->shm_id = shm_id;
  ex->tbl = shm_addr;
  contest_extras[id] = ex;
  if (!daemon_mode) info("done");
  return ex;

 cleanup:
  if (shm_addr) shmdt(shm_addr);
  if (shm_id >= 0) shmctl(shm_id, IPC_RMID, 0);
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
  if (!daemon_mode)
    info("destroying shared contest info for %d", ex->id);
  ex->tbl->vintage = 0xffffffff;    /* the client must note this change */
  if (shmdt(ex->tbl) < 0) err("shmdt failed: %s", os_ErrorMsg());
  if (shmctl(ex->shm_id,IPC_RMID,0)<0) err("shmctl failed: %s",os_ErrorMsg());
  contest_extras[ex->id] = 0;
  memset(ex, 0, sizeof(*ex));
  xfree(ex);
  if (!daemon_mode) info("done");
  return 0;
}

static void
update_userlist_table(int cnts_id)
{
  struct userlist_table *ntb;
  struct contest_extra *ex;

  ASSERT(cnts_id > 0);
  if (cnts_id >= contest_extras_size) return;
  ex = contest_extras[cnts_id];
  if (!ex) return;
  ntb = ex->tbl;
  if (!ntb) return;
  ntb->vintage++;
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

// methods for accessing the default userlist database backend
#define default_get_user_full(a, b) uldb_default->iface->get_user_full(uldb_default->data, a, b)
#define default_get_user_id_iterator() uldb_default->iface->get_user_id_iterator(uldb_default->data)
#define default_get_user_by_login(a) uldb_default->iface->get_user_by_login(uldb_default->data, a)
#define default_sync() uldb_default->iface->sync(uldb_default->data)
#define default_forced_sync() uldb_default->iface->forced_sync(uldb_default->data)
#define default_get_login(a) uldb_default->iface->get_login(uldb_default->data, a)
#define default_new_user(a,b,c,d) uldb_default->iface->new_user(uldb_default->data, a, b, c, d)
#define default_remove_user(a) uldb_default->iface->remove_user(uldb_default->data, a)
#define default_get_cookie(a, b) uldb_default->iface->get_cookie(uldb_default->data, a, b)
#define default_new_cookie(a, b, c, d, e, f, g, h, i) uldb_default->iface->new_cookie(uldb_default->data, a, b, c, d, e, f, g, h, i)
#define default_remove_cookie(a) uldb_default->iface->remove_cookie(uldb_default->data, a)
#define default_remove_user_cookies(a) uldb_default->iface->remove_user_cookies(uldb_default->data, a)
#define default_remove_expired_cookies(a) uldb_default->iface->remove_expired_cookies(uldb_default->data, a)
#define default_get_user_contest_iterator(a) uldb_default->iface->get_user_contest_iterator(uldb_default->data, a)
#define default_remove_expired_users(a) uldb_default->iface->remove_expired_users(uldb_default->data, a)
#define default_get_user_info_1(a, b) uldb_default->iface->get_user_info_1(uldb_default->data, a, b)
#define default_get_user_info_2(a, b, c, d) uldb_default->iface->get_user_info_2(uldb_default->data, a, b, c, d)
#define default_touch_login_time(a, b) uldb_default->iface->touch_login_time(uldb_default->data, a, b)
#define default_get_user_info_3(a, b, c, d, e) uldb_default->iface->get_user_info_3(uldb_default->data, a, b, c, d, e)
#define default_set_cookie_contest(a, b) uldb_default->iface->set_cookie_contest(uldb_default->data, a, b)
#define default_set_cookie_locale(a, b) uldb_default->iface->set_cookie_locale(uldb_default->data, a, b)
#define default_set_cookie_priv_level(a, b) uldb_default->iface->set_cookie_priv_level(uldb_default->data, a, b)
#define default_get_user_info_4(a, b, c) uldb_default->iface->get_user_info_4(uldb_default->data, a, b, c)
#define default_get_user_info_5(a, b, c) uldb_default->iface->get_user_info_5(uldb_default->data, a, b, c)
#define default_get_brief_list_iterator(a) uldb_default->iface->get_brief_list_iterator(uldb_default->data, a)
#define default_get_standings_list_iterator(a) uldb_default->iface->get_standings_list_iterator(uldb_default->data, a)
#define default_check_user(a) uldb_default->iface->check_user(uldb_default->data, a)
#define default_set_reg_passwd(a, b, c, d) uldb_default->iface->set_reg_passwd(uldb_default->data, a, b, c, d)
#define default_set_team_passwd(a, b, c, d, e, f) uldb_default->iface->set_team_passwd(uldb_default->data, a, b, c, d, e, f)
#define default_register_contest(a, b, c, d, e) uldb_default->iface->register_contest(uldb_default->data, a, b, c, d, e)
#define default_remove_member(a, b, c, d, e) uldb_default->iface->remove_member(uldb_default->data, a, b, c, d, e)
#define default_is_read_only(a, b) uldb_default->iface->is_read_only(uldb_default->data, a, b)
#define default_get_info_list_iterator(a, b) uldb_default->iface->get_info_list_iterator(uldb_default->data, a, b)
#define default_clear_team_passwd(a, b, c) uldb_default->iface->clear_team_passwd(uldb_default->data, a, b, c)
#define default_remove_registration(a, b) uldb_default->iface->remove_registration(uldb_default->data, a, b)
#define default_set_reg_status(a, b, c) uldb_default->iface->set_reg_status(uldb_default->data, a, b, c)
#define default_set_reg_flags(a, b, c, d) uldb_default->iface->set_reg_flags(uldb_default->data, a, b, c, d)
#define default_remove_user_contest_info(a, b) uldb_default->iface->remove_user_contest_info(uldb_default->data, a, b)
#define default_clear_user_field(a, b, c) uldb_default->iface->clear_user_field(uldb_default->data, a, b, c)
#define default_clear_user_info_field(a, b, c, d, e) uldb_default->iface->clear_user_info_field(uldb_default->data, a, b, c, d, e)
#define default_clear_member_field(a, b, c, d, e, f) uldb_default->iface->clear_user_member_field(uldb_default->data, a, b, c, d, e, f)
#define default_set_user_field(a, b, c, d) uldb_default->iface->set_user_field(uldb_default->data, a, b, c, d)
#define default_set_user_info_field(a, b, c, d, e, f) uldb_default->iface->set_user_info_field(uldb_default->data, a, b, c, d, e, f)
#define default_set_user_member_field(a, b, c, d, e, f, g) uldb_default->iface->set_user_member_field(uldb_default->data, a, b, c, d, e, f, g)
#define default_new_member(a, b, c, d, e) uldb_default->iface->new_member(uldb_default->data, a, b, c, d, e)
#define default_change_member_rol(a, b, c, d, e, f) uldb_default->iface->change_member_role(uldb_default->data, a, b, c, d, e, f)
#define default_set_user_xml(a, b, c, d, e) uldb_default->iface->set_user_xml(uldb_default->data, a, b, c, d, e)

static void
update_all_user_contests(int user_id)
{
  const struct userlist_contest *c;
  ptr_iterator_t iter;

  for (iter = default_get_user_contest_iterator(user_id);
       iter->has_next(iter);
       iter->next(iter)) {
    c = (const struct userlist_contest *) iter->get(iter);
    update_userlist_table(c->id);
  }
}

static void
force_check_dirty(int s)
{
  default_sync();
}
static void
force_flush(int s)
{
  default_forced_sync();
}

static void
generate_random_password(int size, unsigned char *buf)
{
  int rand_bytes;
  unsigned char *rnd_buf = 0;
  unsigned char *b64_buf = 0;
  unsigned char *p;

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
  random_bytes(rnd_buf, rand_bytes);

  // convert to base64
  base64_encode(rnd_buf, rand_bytes, b64_buf);
  b64_buf[size] = 0;
  for (p = b64_buf; *p; p++) {
    /* rename: l, I, 1, O, 0*/
    switch (*p) {
    case 'l': *p = '!'; break;
    case 'I': *p = '@'; break;
    case '1': *p = '^'; break;
    case 'O': *p = '*'; break;
    case '0': *p = '-'; break;
    }
  }
  strcpy(buf, b64_buf);
}

/* build the map from the system uids to the local uids */
static void
build_system_uid_map(struct xml_tree *xml_user_map)
{
  struct xml_tree *um;
  struct ejudge_cfg_user_map *m;
  int max_system_uid = -1, i;

  if (!xml_user_map || !xml_user_map->first_down) return;
  for (um = xml_user_map->first_down; um; um = um->right) {
    m = (struct ejudge_cfg_user_map*) um;
    if (m->system_uid < 0) continue;
    if (m->system_uid > max_system_uid)
      max_system_uid = m->system_uid;
  }

  if (max_system_uid < 0) return;
  system_uid_map_size = max_system_uid + 1;
  XCALLOC(system_uid_map, system_uid_map_size);
  for (i = 0; i < system_uid_map_size; i++)
    system_uid_map[i] = -1;
  for (um = xml_user_map->first_down; um; um = um->right) {
    m = (struct ejudge_cfg_user_map*) um;
    if (m->system_uid < 0) continue;
    i = default_get_user_by_login(m->local_user_str);
    if (!daemon_mode)
      info("system user %s(%d) is mapped to local user %s(%d)",
           m->system_user_str, m->system_uid, m->local_user_str, i);
    system_uid_map[m->system_uid] = i;
  }
}

/* remove the entry from the system uid->local uid map upon removal */
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

static int
send_email_message(unsigned char const *to,
                   unsigned char const *from,
                   unsigned char const *charset,
                   unsigned char const *subject,
                   unsigned char const *text)
{
  FILE *f = 0;
  int r;

  ASSERT(config->email_program);
  if (!charset) charset = EJUDGE_CHARSET;

  if (!(f = popen(config->email_program, "w"))) {
    err("send_email_message: popen failed: %s", os_ErrorMsg());
    return -1;
  }

  if (charset) {
    fprintf(f, "Content-type: text/plain; charset=\"%s\"\n",
            charset);
  } else {
    fprintf(f, "Content-type: text/plain\n");
  }
  fprintf(f, "To: %s\nFrom: %s\nSubject: %s\n\n%s\n",
          to, from, subject, text);
  if (ferror(f)) {
    err("send_email_message: write error");
    pclose(f);
    return -1;
  }
  if ((r = pclose(f)) < 0) {
    err("send_email_message: pclose failed: %s", os_ErrorMsg());
    return -1;
  } else if (r > 0) {
    err("send_email_message: the MTA exit code is %d", r);
    return -1;
  }
  return 0;
}

static void
disconnect_client(struct client_state *p)
{
  ASSERT(p);

  // return the descriptor to the blocking mode
  fcntl(p->fd, F_SETFL, fcntl(p->fd, F_GETFL) & ~O_NONBLOCK);

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

static void report_uptime(time_t t1, time_t t2);
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
  uldb_default->iface->close(uldb_default->data);
  server_finish_time = time(0);
  report_uptime(server_start_time, server_finish_time);
  exit(0);
}
static void
interrupt_signal(int s)
{
  interrupt_signaled = 1;
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
  unsigned char *l = default_get_login(uid);
  int r;

  if (!l) return -1;
  r = opcaps_find(list, l, pcap);
  xfree(l);
  return r;
}

static int
is_db_capable(struct client_state *p, int bit, const unsigned char *pfx)
{
  opcap_t caps;

  if (get_uid_caps(&config->capabilities, p->user_id, &caps) < 0) {
    if (pfx) {
      err("%s -> no capability %d", pfx, bit);
    } else {
      CONN_ERR("user %d has no capabilities for the user database",p->user_id);
    }
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  if (opcaps_check(caps, bit) < 0) {
    if (pfx) {
      err("%s -> no capability %d", pfx, bit);
    } else {
      CONN_ERR("user %d has no %d capability", p->user_id, bit);
    }
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  return 0;
}

static int
is_cnts_capable(struct client_state *p, struct contest_desc *cnts, int bit,
                const unsigned char *pfx)
{
  opcap_t caps;

  if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) < 0) {
    if (pfx) {
      err("%s -> no capability %d", pfx, bit);
    } else {
      CONN_ERR("user %d has no capabilities for contest %d",
               p->user_id, cnts->id);
    }
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  if (opcaps_check(caps, bit) < 0) {
    if (pfx) {
      err("%s -> no capability %d", pfx, bit);
    } else {
      CONN_ERR("user %d has no %d capability for contest %d",
               p->user_id, bit, cnts->id);
    }
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
is_privileged_user(const struct userlist_user *u)
{
  opcap_t caps;

  if (u->is_privileged) return 1;
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
passwd_check(struct passwd_internal *u, const unsigned char *passwd, int method)
{
  int len, i, j;

  ASSERT(method >= USERLIST_PWD_PLAIN && method <= USERLIST_PWD_SHA1);
  if (!strcmp(u->pwds[method], passwd)) return 0;
  // try to remove all whitespace chars and compare again
  len = strlen(u->pwds[0]);
  for (i = 0, j = 0; i < len; i++) {
    if (u->pwds[0][i] > ' ') u->pwds[0][j++] = u->pwds[0][i];
  }
  u->pwds[0][j] = u->pwds[0][i];
  len = strlen(u->pwds[0]);
  base64_encode(u->pwds[0], len, u->pwds[1]);
  make_sha1_ascii(u->pwds[0], len, u->pwds[2]);
  if (!strcmp(u->pwds[method], passwd)) return 0;
  return -1;
}

static unsigned char *
get_email_sender(struct contest_desc *cnts)
{
  int sysuid;
  struct passwd *ppwd;

  if (cnts && cnts->register_email) return cnts->register_email;
  if (config && config->register_email) return config->register_email;
  sysuid = getuid();
  ppwd = getpwuid(sysuid);
  return ppwd->pw_name;
}

static void
cmd_register_new_2(struct client_state *p,
                   int pkt_len,
                   struct userlist_pk_register_new * data)
{
  unsigned char * login;
  unsigned char * email;
  int login_len, email_len, errcode, exp_pkt_len;
  unsigned char passwd_buf[64];
  struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0, passwd_len;
  time_t current_time = time(0);
  int user_id;
  const struct userlist_user *u;

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

  snprintf(logbuf, sizeof(logbuf), "NEW_USER_2: %s, %s, %s, %d",
           xml_unparse_ip(data->origin_ip), login, email, data->contest_id);

  if (data->contest_id <= 0) {
    err("%s -> contest_id unspecified", logbuf);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!cnts->simple_registration) {
    err("%s -> simple registration is not enabled", logbuf);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;    
  }
  if (cnts->closed) {
    err("%s -> contest is closed", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_PARTICIPATE);
    return;        
  }
  if (cnts->reg_deadline && current_time > cnts->reg_deadline){
    err("%s -> registration deadline", logbuf);
    send_reply(p, -ULS_ERR_DEADLINE);
    return;
  }
  if (!contests_check_register_ip_2(cnts, data->origin_ip, data->ssl)) {
    err("%s -> rejected IP", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }

  user_id = default_get_user_by_login(login);
  if (user_id >= 0) {
    send_reply(p, -ULS_ERR_LOGIN_USED);
    err("%s -> login already exists", logbuf);
    return;
  }

  generate_random_password(8, passwd_buf);
  user_id = default_new_user(login, email, passwd_buf, 1);

  out_size = sizeof(*out) + passwd_len;
  out = (struct userlist_pk_xml_data*) alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_PASSWORD;
  out->info_len = passwd_len;
  memcpy(out->data, passwd_buf, passwd_len + 1);
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> ok, %d", logbuf, user_id);

  if (!cnts->send_passwd_email) return;

  // send a notification email anyway
  {
    struct sformat_extra_data sformat_data;
    unsigned char urlbuf[1024];
    unsigned char email_tmpl_path[PATH_MAX];
    unsigned char email_tmpl_path2[PATH_MAX];
    char *email_tmpl = 0;
    size_t email_tmpl_size = 0, buf_size = 0;
    unsigned char contest_url[1024];
    unsigned char *buf = 0;
    unsigned char *originator_email;
    unsigned char contest_str[256];
    unsigned char locale_str[256];
    unsigned char *url_str = 0;
    unsigned char *mail_args[7];

    default_get_user_info_1(user_id, &u);

    // prepare the file path for the email template
    memset(&sformat_data, 0, sizeof(sformat_data));
    sformat_data.locale_id = data->locale_id;
    sformat_data.url = urlbuf;
    if (cnts->register_email_file) {
      sformat_message(email_tmpl_path, sizeof(email_tmpl_path),
                      cnts->register_email_file,
                      0, 0, 0, 0, 0, u, cnts, &sformat_data);
      if (generic_read_file(&email_tmpl, 0, &email_tmpl_size, 0,
                            "", email_tmpl_path, "") < 0) {
        sformat_data.locale_id = 0;
        sformat_message(email_tmpl_path2, sizeof(email_tmpl_path2),
                        cnts->register_email_file,
                        0, 0, 0, 0, 0, u, cnts, &sformat_data);
        if (strcmp(email_tmpl_path, email_tmpl_path2) != 0) {
          strcpy(email_tmpl_path, email_tmpl_path2);
          if (generic_read_file(&email_tmpl, 0, &email_tmpl_size, 0,
                                "", email_tmpl_path, "") < 0) {
            email_tmpl = 0;
            email_tmpl_size = 0;
          }
        } else {
          email_tmpl = 0;
          email_tmpl_size = 0;
        }
      }
    }

    originator_email = get_email_sender(cnts);

    contest_str[0] = 0;
    if (data->contest_id > 0) {
      snprintf(contest_str, sizeof(contest_str), "&contest_id=%d",
               data->contest_id);
    }
    locale_str[0] = 0;
    if (data->locale_id >= 0) {
      snprintf(locale_str, sizeof(locale_str), "&locale_id=%d",
               data->locale_id);
    }
    if (cnts && cnts->register_url) {
      url_str = cnts->register_url;
    } else if (config->register_url) {
      url_str = config->register_url;
    } else {
      url_str = "http://localhost/cgi-bin/register";
    }
    snprintf(urlbuf, sizeof(urlbuf), "%s?action=%d&login=%s%s%s",
             url_str, 3, login, contest_str, locale_str);

    l10n_setlocale(data->locale_id);

    sformat_data.server_name = config->server_name;
    sformat_data.server_name_en = config->server_name_en;
    sformat_data.str1 = contest_url;

    contest_url[0] = 0;
    if (cnts->main_url) {
      snprintf(contest_url, sizeof(contest_url), " (%s)", cnts->main_url);
    }

    if (!email_tmpl) {
      email_tmpl =
        _("Hello,\n"
          "\n"
          "Somebody (probably you) has registered a new account\n"
          "to participate in contest \"%LCn\"%V1\n"
          "using this e-mail address (%Ue).\n"
          "\n"
          "Registration has completed successfully. This message\n"
          "contains your login and password for your convenience.\n"
          "\n"
          "login:    %Ul\n"
          "password: %Uz\n"
          "URL:      %Vu\n"
          "\n"
          "Regards,\n"
          "The ejudge contest administration system (www.ejudge.ru)\n");
      email_tmpl = xstrdup(email_tmpl);
      email_tmpl_size = strlen(email_tmpl);
    }

    buf_size = email_tmpl_size * 2;
    if (buf_size < 2048) buf_size = 2048;
    buf = (char*) xmalloc(buf_size);
    sformat_message(buf, buf_size, email_tmpl,
                    0, 0, 0, 0, 0, u, cnts, &sformat_data);

    mail_args[0] = "mail";
    mail_args[1] = "";
    mail_args[2] = _("You have been registered");
    mail_args[3] = originator_email;
    mail_args[4] = email;
    mail_args[5] = buf;
    mail_args[6] = 0;
    send_job_packet(NULL, mail_args);

    xfree(buf);
    xfree(email_tmpl);

    l10n_setlocale(0);
  }
}

static void
cmd_register_new(struct client_state *p,
                 int pkt_len,
                 struct userlist_pk_register_new * data)
{
  const struct userlist_user *u;
  char * buf;
  unsigned char * login;
  unsigned char * email;
  unsigned char urlbuf[1024];
  int login_len, email_len, errcode, exp_pkt_len;
  unsigned char passwd_buf[64];
  struct contest_desc *cnts = 0;
  unsigned char * originator_email = 0;
  unsigned char logbuf[1024];
  unsigned char email_tmpl_path[PATH_MAX];
  unsigned char email_tmpl_path2[PATH_MAX];
  struct sformat_extra_data sformat_data;
  char *email_tmpl = 0;
  size_t email_tmpl_size = 0, buf_size = 0;
  unsigned char contest_str[256];
  unsigned char locale_str[256];
  unsigned char *url_str = 0;
  unsigned char contest_url[256];
  int user_id;

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

  snprintf(logbuf, sizeof(logbuf), "NEW_USER: %s, %s, %s, %d",
           xml_unparse_ip(data->origin_ip), login, email, data->contest_id);

  if (data->contest_id != 0) {
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
  }
  originator_email = get_email_sender(cnts);
 
  contest_str[0] = 0;
  if (data->contest_id > 0) {
    snprintf(contest_str, sizeof(contest_str), "&contest_id=%d",
             data->contest_id);
  }
  locale_str[0] = 0;
  if (data->locale_id >= 0) {
    snprintf(locale_str, sizeof(locale_str), "&locale_id=%d",
             data->locale_id);
  }
  if (cnts && cnts->register_url) {
    url_str = cnts->register_url;
  } else if (config->register_url) {
    url_str = config->register_url;
  } else {
    url_str = "http://localhost/cgi-bin/register";
  }
  snprintf(urlbuf, sizeof(urlbuf), "%s?action=%d&login=%s%s%s",
           url_str, 3, login, contest_str, locale_str);

  user_id = default_get_user_by_login(login);
  if (user_id >= 0) {
    send_reply(p, -ULS_ERR_LOGIN_USED);
    err("%s -> login already exists", logbuf);
    return;
  }

  generate_random_password(8, passwd_buf);
  user_id = default_new_user(login, email, passwd_buf, 0);
  default_get_user_info_1(user_id, &u);

  // prepare the file path for the email template
  memset(&sformat_data, 0, sizeof(sformat_data));
  sformat_data.locale_id = data->locale_id;
  sformat_data.url = urlbuf;
  sformat_data.server_name = config->server_name;
  sformat_data.server_name_en = config->server_name_en;
  sformat_data.str1 = contest_url;

  if (cnts && cnts->register_email_file) {
    sformat_message(email_tmpl_path, sizeof(email_tmpl_path),
                    cnts->register_email_file,
                    0, 0, 0, 0, 0, u, cnts, &sformat_data);
    if (generic_read_file(&email_tmpl, 0, &email_tmpl_size, 0,
                          "", email_tmpl_path, "") < 0) {
      sformat_data.locale_id = 0;
      sformat_message(email_tmpl_path2, sizeof(email_tmpl_path2),
                      cnts->register_email_file,
                      0, 0, 0, 0, 0, u, cnts, &sformat_data);
      if (strcmp(email_tmpl_path, email_tmpl_path2) != 0) {
        strcpy(email_tmpl_path, email_tmpl_path2);
        if (generic_read_file(&email_tmpl, 0, &email_tmpl_size, 0,
                              "", email_tmpl_path, "") < 0) {
          email_tmpl = 0;
          email_tmpl_size = 0;
        }
      } else {
        email_tmpl = 0;
        email_tmpl_size = 0;
      }
    }
  }

  l10n_setlocale(data->locale_id);
  if (!email_tmpl) {
    if (cnts) {
      contest_url[0] = 0;
      if (cnts->main_url) {
        snprintf(contest_url, sizeof(contest_url), " (%s)", cnts->main_url);
      }

      email_tmpl =
        _("Hello,\n"
          "\n"
          "Somebody (probably you) have specified this e-mail address (%Ue)\n"
          "when registering an account to participate in %LCn%V1.\n"
          "\n"
          "To confirm registration, you should enter the provided login\n"
          "and password on the login page of the server at the\n"
          "following url: %Vu.\n"
          "\n"
          "Note, that if you do not do this in 24 hours from the moment\n"
          "of sending this letter, registration will be void.\n"
          "\n"
          "login:    %Ul\n"
          "password: %Uz\n"
          "\n"
          "Regards,\n"
          "The ejudge contest administration system (www.ejudge.ru)\n");
    } else {
      contest_url[0] = 0;
      if (config->server_main_url) {
        snprintf(contest_url, sizeof(contest_url), " (%s)",
                 config->server_main_url);
      }

      email_tmpl =
        _("Hello,\n"
          "\n"
          "Somebody (probably you) have specified this e-mail address (%Ue)\n"
          "when registering an account on the %LVn%V1.\n"
          "\n"
          "To confirm registration, you should enter the provided login\n"
          "and password on the login page of the server at the\n"
          "following url: %Vu.\n"
          "\n"
          "Note, that if you do not do this in 24 hours from the moment\n"
          "of sending this letter, registration will be void.\n"
          "\n"
          "login:    %Ul\n"
          "password: %Uz\n"
          "\n"
          "Regards,\n"
          "The ejudge contest administration system (www.ejudge.ru)\n");
    }
    email_tmpl = xstrdup(email_tmpl);
    email_tmpl_size = strlen(email_tmpl);
  }

  buf_size = email_tmpl_size * 2;
  if (buf_size < 2048) buf_size = 2048;
  buf = (char*) xmalloc(buf_size);
  sformat_message(buf, buf_size, email_tmpl,
                  0, 0, 0, 0, 0, u, cnts, &sformat_data);
  if (send_email_message(u->email,
                         originator_email,
                         NULL,
                         _("You have been registered"),
                         buf) < 0) {
    // since we're unable to send a mail message, we should
    // remove a newly added user and return an appropriate error code
    default_remove_user(user_id);
    xfree(buf);
    xfree(email_tmpl);
    l10n_setlocale(0);
    send_reply(p, ULS_ERR_EMAIL_FAILED);
    info("%s -> failed (e-mail)", logbuf);
    return;
  }

  xfree(buf);
  xfree(email_tmpl);
  l10n_setlocale(0);
  send_reply(p,ULS_OK);
  info("%s -> ok, %d", logbuf, u->id);
}

static void
do_remove_user(const struct userlist_user *u)
{
  ptr_iterator_t iter = 0;
  struct userlist_contest *reg;

  // check all the registrations
  for (iter = default_get_user_contest_iterator(u->id);
       iter->has_next(iter);
       iter->next(iter)) {
    reg = (struct userlist_contest*) iter->get(iter);
    if (reg->status == USERLIST_REG_OK)
      update_userlist_table(reg->id);
  }

  remove_from_system_uid_map(u->id);
  default_remove_user(u->id);
}

static void
cmd_do_login(struct client_state *p,
             int pkt_len,
             struct userlist_pk_do_login * data)
{
  const struct userlist_user *u = 0;
  struct userlist_pk_login_ok * answer;
  int ans_len, act_pkt_len;
  char * login;
  char * password;
  char * name;
  const struct userlist_cookie * cookie;
  struct passwd_internal pwdint;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;
  int user_id;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet is too small: %d", pkt_len);
    return;
  }
  login = data->data;
  if (strlen(login) != data->login_length) {
    CONN_BAD("login length mismatch");
    return;
  }
  password = data->data + data->login_length + 1;
  if (strlen(password) != data->password_length) {
    CONN_BAD("password length mismatch");
    return;
  }
  act_pkt_len = sizeof(*data) + data->login_length + data->password_length;
  if (act_pkt_len != pkt_len) {
    CONN_BAD("packet length mismatch");
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "LOGIN: %s, %d, %s",
           xml_unparse_ip(data->origin_ip), data->ssl, login);

  if (p->user_id >= 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  if (passwd_convert_to_internal(password, &pwdint) < 0) {
    err("%s -> invalid password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  rdtscll(tsc1);
  if ((user_id = default_get_user_by_login(login)) <= 0) {
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    err("%s -> WRONG USER", logbuf);
    return;
  }
  default_get_user_info_2(user_id, data->contest_id, &u, &ui);
  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  if (!u->passwd) {
    err("%s -> EMPTY PASSWORD", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_check(&pwdint, u->passwd, u->passwd_method) < 0) {
    err("%s -> WRONG PASSWORD", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  //Login and password correct
  ans_len = sizeof(struct userlist_pk_login_ok)
    + strlen(ui->name) + strlen(u->login);
  answer = alloca(ans_len);
  memset(answer, 0, ans_len);

  if (default_new_cookie(u->id, data->origin_ip, data->ssl, 0, 0, data->contest_id, data->locale_id, PRIV_LEVEL_USER, &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  answer->reply_id = ULS_LOGIN_COOKIE;
  answer->cookie = cookie->cookie;
  answer->user_id = u->id;
  answer->contest_id = data->contest_id;
  answer->login_len = strlen(u->login);
  name = answer->data + answer->login_len + 1;
  answer->name_len = strlen(ui->name);
  strcpy(answer->data, u->login);
  strcpy(name, ui->name);
  enqueue_reply_to_client(p,ans_len,answer);

  default_touch_login_time(user_id, cur_time);
  p->user_id = u->id;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  p->cookie = answer->cookie;
  info("%s -> OK, %d, %llx", logbuf, u->id, answer->cookie);
}

static void
cmd_team_login(struct client_state *p, int pkt_len,
               struct userlist_pk_do_login * data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  const struct userlist_user *u = 0;
  struct passwd_internal pwdint;
  struct contest_desc *cnts = 0;
  const struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  const struct userlist_cookie *cookie;
  int out_size = 0, login_len, name_len;
  int errcode;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;
  int user_id;

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

  snprintf(logbuf, sizeof(logbuf),
           "TEAM_LOGIN: %s, %d, %s, %d, %d",
           xml_unparse_ip(data->origin_ip), data->ssl, login_ptr, data->contest_id,
           data->locale_id);

  if (p->user_id >= 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    err("%s -> invalid password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!contests_check_team_ip(data->contest_id, data->origin_ip, data->ssl)) {
    err("%s -> IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }
  if (cnts->client_disable_team) {
    err("%s -> team logins are disabled", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  rdtscll(tsc1);
  if ((user_id = default_get_user_by_login(login_ptr)) <= 0) {
    err("%s -> WRONG USER", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  default_get_user_info_3(user_id, data->contest_id, &u, &ui, &c);
  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  if (cnts->disable_team_password) {
    if (!u->passwd) {
      err("%s -> EMPTY PASSWORD", logbuf);
      send_reply(p, -ULS_ERR_INVALID_PASSWORD);
      return;
    }
    if(passwd_check(&pwdint, u->passwd, u->passwd_method) < 0){
      err("%s -> WRONG PASSWORD", logbuf);
      send_reply(p, -ULS_ERR_INVALID_PASSWORD);
      return;
    }
  } else {
    if (!ui->team_passwd) {
      err("%s -> EMPTY PASSWORD", logbuf);
      send_reply(p, -ULS_ERR_INVALID_PASSWORD);
      return;
    }
    if(passwd_check(&pwdint, ui->team_passwd, ui->team_passwd_method) < 0){
      err("%s -> WRONG PASSWORD", logbuf);
      send_reply(p, -ULS_ERR_INVALID_PASSWORD);
      return;
    }
  }
  if (!c) {
    err("%s -> NOT REGISTERED", logbuf);
    send_reply(p, -ULS_ERR_NOT_REGISTERED);
    return;
  }
  if (c->status != USERLIST_REG_OK || (c->flags & USERLIST_UC_BANNED)
      || (c->flags & USERLIST_UC_LOCKED)) {
    err("%s -> NOT ALLOWED", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_PARTICIPATE);
    return;
  }

  login_len = strlen(u->login);
  name_len = strlen(ui->name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  if (data->locale_id == -1) {
    data->locale_id = 0;
  }
  if (default_new_cookie(u->id, data->origin_ip, data->ssl, 0, 0,
                         data->contest_id, data->locale_id,
                         PRIV_LEVEL_USER, &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  out->cookie = cookie->cookie;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = data->contest_id;
  out->locale_id = data->locale_id;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, ui->name);
  
  p->user_id = u->id;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  p->cookie = out->cookie;
  enqueue_reply_to_client(p, out_size, out);
  default_touch_login_time(user_id, cur_time);
  if (daemon_mode) {
    info("%s -> OK, %d, %llx", logbuf, u->id, out->cookie);
  } else {
    info("%s -> %d,%s,%llx, time = %llu us",
         logbuf, u->id, u->login,out->cookie,tsc2);
  }
}

static void
cmd_priv_login(struct client_state *p, int pkt_len,
                    struct userlist_pk_do_login *data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  struct contest_desc *cnts = 0;
  struct passwd_internal pwdint;
  const struct userlist_user *u = 0;
  const struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  int priv_level, login_len, name_len;
  size_t out_size = 0, errcode;
  const struct userlist_cookie *cookie;
  opcap_t caps;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  int user_id;
  const struct userlist_user_info *ui;

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

  snprintf(logbuf, sizeof(logbuf),
           "PRIV_LOGIN: %s, %d, %s, %d, %d",
           xml_unparse_ip(data->origin_ip), data->ssl, login_ptr, data->contest_id,
           data->locale_id);

  if (p->user_id >= 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    err("%s -> invalid password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  // if contest_id == 0, the user must have the correspondent global
  // capability bit
  if (data->contest_id > 0) {
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
  }
  if (data->priv_level <= 0 || data->priv_level > PRIV_LEVEL_ADMIN) {
    err("%s -> invalid privelege level: %d", logbuf, data->priv_level);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  rdtscll(tsc1);
  if ((user_id = default_get_user_by_login(login_ptr)) <= 0) {
    err("%s -> WRONG LOGIN", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  default_get_user_info_3(user_id, data->contest_id, &u, &ui, &c);
  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  if (!u) {
    err("%s -> WRONG LOGIN", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (!u->passwd) {
    err("%s -> EMPTY PASSWORD", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_check(&pwdint, u->passwd, u->passwd_method) < 0) {
    err("%s -> WRONG PASSWORD", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  if (data->contest_id > 0) {
    if (!c) {
      err("%s -> NOT REGISTERED", logbuf);
      send_reply(p, -ULS_ERR_NOT_REGISTERED);
      return;
    }
    if (c->status != USERLIST_REG_OK || (c->flags & USERLIST_UC_BANNED)
        || (c->flags & USERLIST_UC_LOCKED)) {
      err("%s -> NOT ALLOWED", logbuf);
      send_reply(p, -ULS_ERR_CANNOT_PARTICIPATE);
      return;
    }
    if (opcaps_find(&cnts->capabilities, login_ptr, &caps) < 0) {
      err("%s -> NOT PRIVILEGED", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  } else {
    if (get_uid_caps(&config->capabilities, u->id, &caps) < 0) {
      err("%s -> NOT PRIVILEGED", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    // if ADMIN level access requested, but only JUDGE can
    // be granted, decrease the privilege level
    if (data->priv_level == PRIV_LEVEL_ADMIN
        && opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0
        && opcaps_check(caps, OPCAP_JUDGE_LOGIN) >= 0)
      data->priv_level = PRIV_LEVEL_JUDGE;
  }

  // check user capabilities
  priv_level = 0;
  switch (data->priv_level) {
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
    err("%s -> NOT PRIVILEGED", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  login_len = strlen(u->login);
  name_len = strlen(u->i.name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  if (data->locale_id == -1) {
    data->locale_id = 0;
  }

  if (default_new_cookie(u->id, data->origin_ip, data->ssl, 0, 0,
                         data->contest_id, data->locale_id,
                         data->priv_level, &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  out->cookie = cookie->cookie;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = data->contest_id;
  out->locale_id = data->locale_id;
  out->priv_level = data->priv_level;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, u->i.name);
  
  p->user_id = u->id;
  p->priv_level = data->priv_level;
  p->cookie = out->cookie;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  enqueue_reply_to_client(p, out_size, out);
  default_touch_login_time(u->id, cur_time);
  if (daemon_mode) {
    info("%s -> OK, %d, %llx", logbuf, u->id, out->cookie);
  } else {
    info("%s -> %d,%s,%llx, time = %llu us", logbuf,
         u->id, u->login,out->cookie, tsc2);
  }
}

static void
cmd_check_cookie(struct client_state *p,
                 int pkt_len,
                 struct userlist_pk_check_cookie * data)
{
  const struct userlist_user *u;
  struct userlist_pk_login_ok * answer;
  int anslen;
  const struct userlist_cookie * cookie = 0;
  unsigned char *name_beg;
  ej_tsc_t tsc1, tsc2;
  time_t current_time = time(0);
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "COOKIE: ip = %s, %d, cookie = %llx",
           xml_unparse_ip(data->origin_ip), data->ssl, data->cookie);

  // cannot login twice
  if (p->user_id >= 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  rdtscll(tsc1);
  if (default_get_cookie(data->cookie, &cookie) < 0 || !cookie) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  default_get_user_info_2(cookie->user_id, data->contest_id, &u, &ui);

  if (cookie->ip != data->origin_ip) {
    err("%s -> IP address mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (current_time > cookie->expire) {
    err("%s -> cookie expired", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  anslen = sizeof(struct userlist_pk_login_ok)
    + strlen(ui->name) + 1 + strlen(u->login) + 1;
  answer = alloca(anslen);
  memset(answer, 0, anslen);
  if (data->locale_id != -1) {
    default_set_cookie_locale(cookie, data->locale_id);
  }
  if (data->contest_id != 0) {
    default_set_cookie_contest(cookie, data->contest_id);
  }
  answer->locale_id = cookie->locale_id;
  answer->reply_id = ULS_LOGIN_COOKIE;
  answer->user_id = u->id;
  answer->contest_id = cookie->contest_id;
  answer->login_len = strlen(u->login);
  name_beg = answer->data + answer->login_len + 1;
  answer->name_len = strlen(ui->name);
  answer->cookie = cookie->cookie;
  strcpy(answer->data, u->login);
  strcpy(name_beg, ui->name);
  enqueue_reply_to_client(p,anslen,answer);
  if (!daemon_mode) {
    info("%s -> OK, %d, %s, %llu us", logbuf, u->id, u->login, tsc2);
  }
  p->user_id = u->id;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  p->cookie = data->cookie;
  return;
}

static void
cmd_team_check_cookie(struct client_state *p, int pkt_len,
                      struct userlist_pk_check_cookie * data)
{
  struct contest_desc *cnts = 0;
  const struct userlist_user *u = 0;
  const struct userlist_cookie *cookie = 0;
  const struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  int out_size = 0, login_len = 0, name_len = 0, errcode;
  unsigned char *login_ptr, *name_ptr;
  ej_tsc_t tsc1, tsc2;
  time_t current_time = time(0);
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "TEAM_COOKIE: %s, %d, %d, %llx, %d",
           xml_unparse_ip(data->origin_ip), data->ssl, data->contest_id,
           data->cookie, data->locale_id);

  if (p->user_id >= 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (!data->cookie) {
    err("%s -> cookie value is 0", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  rdtscll(tsc1);
  if (default_get_cookie(data->cookie, &cookie) < 0 || !cookie) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  default_get_user_info_3(cookie->user_id, data->contest_id, &u, &ui, &c);

  if (cookie->ip != data->origin_ip) {
    err("%s -> IP address mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (current_time > cookie->expire) {
    err("%s -> cookie expired", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (cookie->priv_level > 0) {
    err("%s -> privilege level mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (!data->contest_id && !cookie->contest_id) {
    err("%s -> contest is not defined", logbuf);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (data->contest_id && cookie->contest_id
      && data->contest_id != cookie->contest_id) {
    err("%s -> contest_id mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (data->contest_id && !cookie->contest_id) {
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      err("%s -> invalid contest: %s", logbuf, contests_strerror(-errno));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
    if (!cnts->disable_team_password) {
      err("%s -> attempt to set cookie's contest_id", logbuf);
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
    if (cnts->client_disable_team) {
      err("%s -> team login is disabled", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    default_set_cookie_contest(cookie, data->contest_id);
  }
  if (!data->contest_id) {
    err("%s -> contest is not defined", logbuf);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (cookie->contest_id != data->contest_id) {
    err("%s -> contest_id mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errno));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (data->locale_id == -1) {
    data->locale_id = cookie->locale_id;
  }
  if (!contests_check_team_ip(data->contest_id, data->origin_ip, data->ssl)) {
    err("%s -> IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }
  if (!c) {
    err("%s -> NOT REGISTERED", logbuf);
    send_reply(p, -ULS_ERR_NOT_REGISTERED);
    return;
  }
  if (c->status != USERLIST_REG_OK || (c->flags & USERLIST_UC_BANNED)
      || (c->flags & USERLIST_UC_LOCKED)) {
    err("%s -> NOT ALLOWED", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_PARTICIPATE);
    return;
  }

  if (data->contest_id > 0) {
    default_set_cookie_contest(cookie, data->contest_id);
  }

  login_len = strlen(u->login);
  name_len = strlen(ui->name);
  out_size = sizeof(*out) + login_len + name_len + 2;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  default_set_cookie_locale(cookie, data->locale_id);
  out->cookie = cookie->cookie;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = cookie->contest_id;
  out->locale_id = data->locale_id;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, ui->name);
  
  p->user_id = u->id;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  p->cookie = data->cookie;
  enqueue_reply_to_client(p, out_size, out);
  if (!daemon_mode) {
    CONN_INFO("%s -> ok, %d, %s, %llu us", logbuf, u->id, u->login, tsc2);
  }
}

static void
cmd_priv_check_cookie(struct client_state *p,
                      int pkt_len,
                      struct userlist_pk_check_cookie *data)
{
  struct contest_desc *cnts = 0;
  const struct userlist_user *u = 0;
  const struct userlist_cookie *cookie = 0;
  struct userlist_pk_login_ok *out;
  const struct userlist_contest *c = 0;
  const struct userlist_user_info *ui = 0;
  size_t login_len, name_len, out_size;
  unsigned char *login_ptr, *name_ptr;
  int priv_level, errcode;
  opcap_t caps;
  time_t current_time = time(0);
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "PRIV_COOKIE: %s, %d, %d, %llx",
           xml_unparse_ip(data->origin_ip), data->ssl, data->contest_id, data->cookie);

  if (p->user_id >= 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (data->contest_id > 0) {
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
  }
  if (!data->cookie) {
    err("%s -> cookie value is 0", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (!data->origin_ip) {
    err("%s -> origin_ip is not set", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (data->priv_level <= 0 || data->priv_level > PRIV_LEVEL_ADMIN) {
    err("%s -> invalid privilege level", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  rdtscll(tsc1);
  if (default_get_cookie(data->cookie, &cookie) < 0 || !cookie) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  default_get_user_info_3(cookie->user_id, data->contest_id, &u, &ui, &c);

  if (cookie->ip != data->origin_ip) {
    err("%s -> IP address mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (current_time > cookie->expire) {
    err("%s -> cookie expired", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (!cookie->priv_level) {
    err("%s -> privilege level mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  /*
  if (cookie->contest_id != data->contest_id) {
    err("%s -> contest_id mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  */

  if (data->contest_id > 0) {
    if (!c) {
      err("%s -> NOT REGISTERED", logbuf);
      send_reply(p, -ULS_ERR_NOT_REGISTERED);
      return;
    }
    if (c->status != USERLIST_REG_OK || (c->flags & USERLIST_UC_BANNED)
        || (c->flags & USERLIST_UC_LOCKED)) {
      err("%s -> NOT ALLOWED", logbuf);
      send_reply(p, -ULS_ERR_CANNOT_PARTICIPATE);
      return;
    }
    if (get_uid_caps(&cnts->capabilities, u->id, &caps) < 0) {
      err("%s -> NOT PRIVILEGED", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  } else {
    if (get_uid_caps(&config->capabilities, u->id, &caps) < 0) {
      err("%s -> NOT PRIVILEGED", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    // if ADMIN level access requested, but only JUDGE can
    // be granted, decrease the privilege level
    if (data->priv_level == PRIV_LEVEL_ADMIN
        && opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0
        && opcaps_check(caps, OPCAP_JUDGE_LOGIN) >= 0)
      data->priv_level = PRIV_LEVEL_JUDGE;
  }

  // check user capabilities
  priv_level = 0;
  switch (data->priv_level) {
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
    err("%s -> NOT PRIVILEGED", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  /* everything is ok, update cookie */
  if (data->locale_id >= 0) {
    default_set_cookie_locale(cookie, data->locale_id);
  }
  if (data->priv_level != cookie->priv_level) {
    default_set_cookie_priv_level(cookie, data->priv_level);
  }
  if (data->contest_id != cookie->contest_id) {
    default_set_cookie_contest(cookie, data->contest_id);
  }

  login_len = strlen(u->login);
  name_len = strlen(u->i.name);
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
  strcpy(name_ptr, u->i.name);
  
  p->user_id = u->id;
  p->priv_level = out->priv_level;
  p->cookie = cookie->cookie;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  enqueue_reply_to_client(p, out_size, out);

  if (!daemon_mode) {
    CONN_INFO("%s -> OK, %d, %s, %llu us", logbuf, u->id, u->login, tsc2);
  }
}
      
static void
cmd_do_logout(struct client_state *p,
              int pkt_len,
              struct userlist_pk_do_logout * data)
{
  const struct userlist_cookie *cookie;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "LOGOUT: %s, %016llx",
           xml_unparse_ip(data->origin_ip), data->cookie);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, ULS_OK);
    return;
  }
  // user_id == 0 is deprecated
  ASSERT(p->user_id > 0);
  if (!data->cookie) {
    err("%s -> cookie is empty", logbuf);
    send_reply(p, ULS_OK);
    return;
  }
  if (!data->origin_ip) {
    err("%s -> origin_ip is empty", logbuf);
    send_reply(p, ULS_OK);
    return;
  }

  if (default_get_cookie(data->cookie, &cookie) < 0 || !cookie) {
    err("%s -> cookie not found", logbuf);
    send_reply(p, ULS_OK);
    return;
  }
  if (cookie->user_id != p->user_id) {
    err("%s -> cookie belongs to another user", logbuf);
    send_reply(p, ULS_OK);
    return;
  }
  if (cookie->ip != data->origin_ip) {
    err("%s -> IP address does not match", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  default_remove_cookie(cookie);
  send_reply(p, ULS_OK);
  if (!daemon_mode) {
    CONN_INFO("cookie removed");
  }
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
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  const struct userlist_user *u = 0;
  unsigned char logbuf[1024];
  struct contest_desc *cnts = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "GET_USER_INFO: %d", data->user_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  // user_id == 0 is deprecated
  ASSERT(p->user_id > 0);

  if (data->user_id != p->user_id) {
    err("%s -> user ids does not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->contest_id < 0
      || (data->contest_id > 0 && contests_get(data->contest_id, &cnts) < 0)) {
    err("%s -> contest_id is invalid: %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (default_get_user_info_4(p->user_id, data->contest_id, &u) < 0) {
    err("%s -> invalid user id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (!(f = open_memstream(&xml_ptr, &xml_size))) {
    err("%s -> open_memstream() failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  userlist_unparse_user(u, f, USERLIST_MODE_USER, data->contest_id);
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
  if (!daemon_mode) {
    CONN_INFO("%s -> OK, size = %zu", logbuf, out_size);
  }
}

static void
cmd_priv_get_user_info(struct client_state *p,
                       int pkt_len,
                       struct userlist_pk_get_user_info *data)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  const struct userlist_user *u = 0;
  struct userlist_contest *user_cnts = 0;
  struct contest_desc *cnts = 0;
  opcap_t caps;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "PRIV_USER_INFO: %d, %d",
           p->user_id, data->user_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  // user_id == 0 is deprecated
  ASSERT(p->user_id > 0);

  if (data->contest_id < 0
      || (data->contest_id > 0 && contests_get(data->contest_id, &cnts) < 0)) {
    err("%s -> invalid contest_id: %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (default_get_user_info_5(data->user_id, data->contest_id, &u) < 0) {
    err("%s -> invalid user id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  // either p->user_id == data->user_id,
  // or general GET_USER capability is present,
  // or the user is registered for the contest with GET_USER capability
  while (1) {
    if (p->user_id == data->user_id) break;

    if (get_uid_caps(&config->capabilities, p->user_id, &caps) >= 0
        && opcaps_check(caps, OPCAP_GET_USER) >= 0) break;

    // scan contests
    if (u->contests) {
      for (user_cnts = FIRST_CONTEST(u); user_cnts;
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
    err("%s -> permission denied", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (!(f = open_memstream(&xml_ptr, &xml_size))) {
    err("%s -> open_memstream() failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  userlist_unparse_user(u, f, USERLIST_MODE_ALL, data->contest_id);
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
  info("%s -> OK, size = %zu", logbuf, out_size);
}

static void
cmd_list_all_users(struct client_state *p,
                   int pkt_len,
                   struct userlist_pk_map_contest *data)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  int errcode;
  struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  ptr_iterator_t iter;
  const struct userlist_user *u;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch");
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "PRIV_ALL_USERS: %d, %d",
           p->user_id, data->contest_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->contest_id) {
    // list users for a particular contest
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
    if (is_cnts_capable(p, cnts, OPCAP_LIST_CONTEST_USERS, logbuf) < 0) return;
  } else {
    // list all users
    if (is_db_capable(p, OPCAP_LIST_ALL_USERS, logbuf) < 0) return;
  }

  f = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(f);
  for (iter = default_get_brief_list_iterator(data->contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    userlist_unparse_user_short(u, f, data->contest_id);
  }
  userlist_write_xml_footer(f);
  iter->destroy(iter);
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
  info("%s -> OK, size = %zu", logbuf, xml_size); 
}

static void
cmd_list_standings_users(struct client_state *p,
                         int pkt_len,
                         struct userlist_pk_map_contest *data)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  int errcode;
  struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  ptr_iterator_t iter;
  const struct userlist_user *u;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch");
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "PRIV_STANDINGS_USERS: %d, %d",
           p->user_id, data->contest_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (data->contest_id <= 0) {
    err("%s -> invalid contest %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (is_cnts_capable(p, cnts, OPCAP_MAP_CONTEST, logbuf) < 0) return;

  f = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(f);
  for (iter = default_get_standings_list_iterator(data->contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    userlist_real_unparse_user(u, f, USERLIST_MODE_STAND, data->contest_id);
  }
  userlist_write_xml_footer(f);
  iter->destroy(iter);
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
  info("%s -> OK, size = %zu", logbuf, xml_size); 
}

static void
cmd_get_user_contests(struct client_state *p,
                      int pkt_len,
                      struct userlist_pk_get_user_info *data)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  unsigned char logbuf[1024];
  ptr_iterator_t iter;
  const struct userlist_contest *c;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch");
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "GET_USER_CONTESTS: %d", data->user_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  // this is unprivileged version
  if (data->user_id != p->user_id) {
    err("%s -> requested user_id does not match to the original", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user_id", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (!(f = open_memstream(&xml_ptr, &xml_size))) {
    err("%s -> open_memstream failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  userlist_write_contests_xml_header(f);
  for (iter = default_get_user_contest_iterator(data->user_id);
       iter->has_next(iter);
       iter->next(iter)) {
    c = (const struct userlist_contest*) iter->get(iter);
    userlist_unparse_contest(c, f, "  ");
  }
  userlist_write_contests_xml_footer(f);
  iter->destroy(iter);
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
  enqueue_reply_to_client(p, out_size, out);
  if (!daemon_mode) {
    info("%s -> OK, size = %zu", logbuf, out_size);
  }
}

/////////////////////////////////////////
#if 0
static struct userlist_member *
find_member_by_serial(struct userlist_user_info *ui, int serial,
                      int copied_from,
                      int *p_role, int *p_i)
{
  int role, i;
  struct userlist_members *ms;
  struct userlist_member *m;

  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (!ui->members[role]) continue;
    ms = ui->members[role];
    for (i = 0; i < ms->total; i++) {
      if (!ms->members[i]) continue;
      m = ms->members[i];
      if (serial == m->serial
          || (m->copied_from > 0 && serial == m->copied_from)
          || (m->copied_from > 0 && copied_from > 0 && copied_from == m->copied_from)
          || (copied_from > 0 && copied_from == m->serial)) {
        if (p_role) *p_role = role;
        if (p_i) *p_i = i;
        return m;
      }
    }
  }
  return 0;
}

static struct userlist_member *
unlink_member(struct userlist_user_info *ui, int role, int pers)
{
  struct userlist_members *ms;
  struct userlist_member *m;
  int i;

  ASSERT(ui);
  ASSERT(role >= 0 && role < CONTEST_LAST_MEMBER);
  ms = ui->members[role];
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
  ui->members[role] = 0;
  xml_unlink_node(&ms->b);
  userlist_free(&ms->b);
  return m;
}

static void
link_member(struct userlist_user_info *ui,
            struct xml_tree *link_node,
            int role, struct userlist_member *m)
{
  struct userlist_members *ms;

  ASSERT(ui);
  ASSERT(role >= 0 && role < CONTEST_LAST_MEMBER);
  ms = ui->members[role];
  if (!ms) {
    ms = (struct userlist_members *) userlist_node_alloc(role + USERLIST_T_CONTESTANTS);
    ui->members[role] = ms;
    xml_link_node_last(link_node, &ms->b);
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
do_set_user_info(struct client_state *p, struct contest_desc *cnts,
                 struct userlist_pk_set_user_info *data,
                 const unsigned char *msg)
{
  struct userlist_user *new_u = 0, *old_u = 0;
  int old_role, old_pers, new_role, new_pers;
  struct userlist_members *old_ms = 0, *new_ms;
  struct userlist_member *new_m, *old_m;
  unsigned char const *role_str = 0;
  int updated = 0;
  int max_count = 0;
  struct userlist_user_info *ui;
  struct xml_tree *link_node;

  if (!(new_u = userlist_parse_user_str(data->data))) {
    err("%s -> XML parse error", msg);
    send_reply(p, -ULS_ERR_XML_PARSE);
    return;
  }

  if (data->user_id != new_u->id) {
    err("%s -> XML user_id %d does not correspond to packet user_id %d",
        msg, new_u->id, data->user_id);
    send_reply(p, -ULS_ERR_PROTOCOL);
    userlist_free(&new_u->b);
    return;
  }
  if (new_u->id <= 0 || new_u->id >= userlist->user_map_size
      || !userlist->user_map[new_u->id]) {
    err("%s -> invalid user_id %d", msg, new_u->id);
    send_reply(p, -ULS_ERR_BAD_UID);
    userlist_free(&new_u->b);
    return;
  }
  old_u = userlist->user_map[new_u->id];
  if (old_u->read_only) {
    err("%s -> user cannot be modified", msg);
    send_reply(p, -ULS_ERR_NO_PERMS);
    userlist_free(&new_u->b);
    return;
  }
  if (strcmp(old_u->email, new_u->email) != 0) {
    err("%s -> new email <%s> does not match old <%s>",
        msg, new_u->email, old_u->email);
    send_reply(p, -ULS_ERR_BAD_UID);
    userlist_free(&new_u->b);
    return;
  }
  if (strcmp(old_u->login, new_u->login) != 0) {
    err("%s -> new login <%s> does not match old <%s>",
        msg, new_u->login, old_u->email);
    send_reply(p, -ULS_ERR_BAD_UID);
    userlist_free(&new_u->b);
    return;
  }

  // clone the user information structure, if necessary
  if (data->contest_id > 0) {
    userlist_clone_user_info(old_u, data->contest_id,
                             &userlist->member_serial, time(0));
    ui = &old_u->cntsinfo[data->contest_id]->i;
    link_node = &old_u->b;
  } else {
    ui = &old_u->i;
    link_node = &old_u->cntsinfo[data->contest_id]->b;
  }

  if (ui->cnts_read_only) {
    err("%s -> user cannot be modified", msg);
    send_reply(p, -ULS_ERR_NO_PERMS);
    userlist_free(&new_u->b);
    return;
  }

  // update the user's fields
  if (needs_name_update(ui->name, new_u->i.name)) {
    xfree(ui->name);
    ui->name = xstrdup(new_u->i.name);
    if (!daemon_mode) info("%d: name updated", p->id);
    updated = 1;

    // we have to notify all the contests, where the user participates
    if (old_u->contests) {
      struct userlist_contest *cc;

      for (cc = (struct userlist_contest*) old_u->contests->first_down;
           cc; cc = (struct userlist_contest*) cc->b.right) {
        if (cc->status == USERLIST_REG_OK) {
          //&& !(cc->flags & USERLIST_UC_BANNED)) { why???
          update_userlist_table(cc->id);
        }
      }
    }
  }
  if (needs_update(ui->homepage, new_u->i.homepage)) {
    xfree(ui->homepage);
    ui->homepage = xstrdup(new_u->i.homepage);
    if (!daemon_mode) info("%d: homepage updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->phone, new_u->i.phone)) {
    xfree(ui->phone);
    ui->phone = xstrdup(new_u->i.phone);
    if (!daemon_mode) info("%d: phone updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->inst, new_u->i.inst)) {
    xfree(ui->inst);
    ui->inst = xstrdup(new_u->i.inst);
    if (!daemon_mode) info("%d: inst updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->inst_en, new_u->i.inst_en)) {
    xfree(ui->inst_en);
    ui->inst_en = xstrdup(new_u->i.inst_en);
    if (!daemon_mode) info("%d: inst_en updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->instshort, new_u->i.instshort)) {
    xfree(ui->instshort);
    ui->instshort = xstrdup(new_u->i.instshort);
    if (!daemon_mode) info("%d: instshort updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->instshort_en, new_u->i.instshort_en)) {
    xfree(ui->instshort_en);
    ui->instshort_en = xstrdup(new_u->i.instshort_en);
    if (!daemon_mode) info("%d: instshort_en updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->fac, new_u->i.fac)) {
    xfree(ui->fac);
    ui->fac = xstrdup(new_u->i.fac);
    if (!daemon_mode) info("%d: fac updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->fac_en, new_u->i.fac_en)) {
    xfree(ui->fac_en);
    ui->fac_en = xstrdup(new_u->i.fac_en);
    if (!daemon_mode) info("%d: fac_en updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->facshort, new_u->i.facshort)) {
    xfree(ui->facshort);
    ui->facshort = xstrdup(new_u->i.facshort);
    if (!daemon_mode) info("%d: facshort updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->facshort_en, new_u->i.facshort_en)) {
    xfree(ui->facshort_en);
    ui->facshort_en = xstrdup(new_u->i.facshort_en);
    if (!daemon_mode) info("%d: facshort_en updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->city, new_u->i.city)) {
    xfree(ui->city);
    ui->city = xstrdup(new_u->i.city);
    if (!daemon_mode) info("%d: city updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->city_en, new_u->i.city_en)) {
    xfree(ui->city_en);
    ui->city_en = xstrdup(new_u->i.city_en);
    if (!daemon_mode) info("%d: city_en updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->country, new_u->i.country)) {
    xfree(ui->country);
    ui->country = xstrdup(new_u->i.country);
    if (!daemon_mode) info("%d: country updated", p->id);
    updated = 1;
  }
  if (needs_update(ui->country_en, new_u->i.country_en)) {
    xfree(ui->country_en);
    ui->country_en = xstrdup(new_u->i.country_en);
    if (!daemon_mode) info("%d: country_en updated", p->id);
    updated = 1;
  }
  /*
  if (needs_update(old_u->location, new_u->location)) {
    xfree(old_u->location);
    old_u->location = xstrdup(new_u->location);
    if (!daemon_mode) info("%d: location updated", p->id);
    updated = 1;
  }
  if (needs_update(old_u->spelling, new_u->spelling)) {
    xfree(old_u->spelling);
    old_u->spelling = xstrdup(new_u->spelling);
    if (!daemon_mode) info("%d: spelling updated", p->id);
    updated = 1;
  }
  */
  if (needs_update(ui->languages, new_u->i.languages)) {
    xfree(ui->languages);
    ui->languages = xstrdup(new_u->i.languages);
    if (!daemon_mode) info("%d: languages updated", p->id);
    updated = 1;
  }

  // move members
 restart_movement:
  for (old_role = 0; old_role < CONTEST_LAST_MEMBER; old_role++) {
    old_ms = ui->members[old_role];
    role_str = userlist_tag_to_str(old_role + USERLIST_T_CONTESTANTS);
    if (!old_ms) continue;
    for (old_pers = 0; old_pers < old_ms->total; old_pers++) {
      old_m = old_ms->members[old_pers];
      if (!old_m) continue;
      ASSERT(old_m->serial > 0);
      new_m = find_member_by_serial(&new_u->i, old_m->serial, old_m->copied_from,
                                    &new_role, &new_pers);
      if (new_m && old_role != new_role) {
        // move to another role
        if (!daemon_mode) {
          info("%d: %s.%d moved to %s",
               p->id, role_str, old_pers,
               userlist_tag_to_str(new_role + USERLIST_T_CONTESTANTS));
        }
        updated = 1;
        new_m = unlink_member(ui, old_role, old_pers);
        ASSERT(new_m == old_m);
        link_member(ui, link_node, new_role, new_m);
        goto restart_movement;
      }
    }
  }

  // update members
  for (old_role = 0; old_role < CONTEST_LAST_MEMBER; old_role++) {
    role_str = userlist_tag_to_str(old_role + USERLIST_T_CONTESTANTS);
    old_ms = ui->members[old_role];
    if (!old_ms) continue;
    for (old_pers = 0; old_pers < old_ms->total; old_pers++) {
      old_m = old_ms->members[old_pers];
      if (!old_m) continue;
      ASSERT(old_m->serial > 0);
      new_m = find_member_by_serial(&new_u->i, old_m->serial, old_m->copied_from,
                                    &new_role, &new_pers);
      if (!new_m) continue;
      ASSERT(new_role == old_role);
      //ASSERT(new_m->serial == old_m->serial);

      if (new_m->status && old_m->status != new_m->status) {
        old_m->status = new_m->status;
        if (!daemon_mode)
          info("%d: updated %s.%d.status", p->id, role_str, old_pers);
        updated = 1;
      }
      if (new_m->grade && old_m->grade != new_m->grade) {
        old_m->grade = new_m->grade;
        if (!daemon_mode)
          info("%d: updated %s.%d.grade", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->firstname, new_m->firstname)) {
        xfree(old_m->firstname);
        old_m->firstname = xstrdup(new_m->firstname);
        if (!daemon_mode)
          info("%d: updated %s.%d.firstname", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->firstname_en, new_m->firstname_en)) {
        xfree(old_m->firstname_en);
        old_m->firstname_en = xstrdup(new_m->firstname_en);
        if (!daemon_mode)
          info("%d: updated %s.%d.firstname_en", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->middlename, new_m->middlename)) {
        xfree(old_m->middlename);
        old_m->middlename = xstrdup(new_m->middlename);
        if (!daemon_mode)
          info("%d: updated %s.%d.middlename", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->middlename_en, new_m->middlename_en)) {
        xfree(old_m->middlename_en);
        old_m->middlename_en = xstrdup(new_m->middlename_en);
        if (!daemon_mode)
          info("%d: updated %s.%d.middlename_en", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->surname, new_m->surname)) {
        xfree(old_m->surname);
        old_m->surname = xstrdup(new_m->surname);
        if (!daemon_mode)
          info("%d: updated %s.%d.surname", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->surname_en, new_m->surname_en)) {
        xfree(old_m->surname_en);
        old_m->surname_en = xstrdup(new_m->surname_en);
        if (!daemon_mode)
          info("%d: updated %s.%d.surname_en", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->group, new_m->group)) {
        xfree(old_m->group);
        old_m->group = xstrdup(new_m->group);
        if (!daemon_mode)
          info("%d: updated %s.%d.group", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->group_en, new_m->group_en)) {
        xfree(old_m->group_en);
        old_m->group_en = xstrdup(new_m->group_en);
        if (!daemon_mode)
          info("%d: updated %s.%d.group_en", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->email, new_m->email)) {
        xfree(old_m->email);
        old_m->email = xstrdup(new_m->email);
        if (!daemon_mode)
          info("%d: updated %s.%d.email", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->homepage, new_m->homepage)) {
        xfree(old_m->homepage);
        old_m->homepage = xstrdup(new_m->homepage);
        if (!daemon_mode)
          info("%d: updated %s.%d.homepage", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->phone, new_m->phone)) {
        xfree(old_m->phone);
        old_m->phone = xstrdup(new_m->phone);
        if (!daemon_mode)
          info("%d: updated %s.%d.phone", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->inst, new_m->inst)) {
        xfree(old_m->inst);
        old_m->inst = xstrdup(new_m->inst);
        if (!daemon_mode)
          info("%d: updated %s.%d.inst", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->inst_en, new_m->inst_en)) {
        xfree(old_m->inst_en);
        old_m->inst_en = xstrdup(new_m->inst_en);
        if (!daemon_mode)
          info("%d: updated %s.%d.inst_en", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->instshort, new_m->instshort)) {
        xfree(old_m->instshort);
        old_m->instshort = xstrdup(new_m->instshort);
        if (!daemon_mode)
          info("%d: updated %s.%d.instshort", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->instshort_en, new_m->instshort_en)) {
        xfree(old_m->instshort_en);
        old_m->instshort_en = xstrdup(new_m->instshort_en);
        if (!daemon_mode)
          info("%d: updated %s.%d.instshort_en", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->fac, new_m->fac)) {
        xfree(old_m->fac);
        old_m->fac = xstrdup(new_m->fac);
        if (!daemon_mode)
          info("%d: updated %s.%d.fac", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->fac_en, new_m->fac_en)) {
        xfree(old_m->fac_en);
        old_m->fac_en = xstrdup(new_m->fac_en);
        if (!daemon_mode)
          info("%d: updated %s.%d.fac_en", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->facshort, new_m->facshort)) {
        xfree(old_m->facshort);
        old_m->facshort = xstrdup(new_m->facshort);
        if (!daemon_mode)
          info("%d: updated %s.%d.facshort", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->facshort_en, new_m->facshort_en)) {
        xfree(old_m->facshort_en);
        old_m->facshort_en = xstrdup(new_m->facshort_en);
        if (!daemon_mode)
          info("%d: updated %s.%d.facshort_en", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->occupation, new_m->occupation)) {
        xfree(old_m->occupation);
        old_m->occupation = xstrdup(new_m->occupation);
        if (!daemon_mode)
          info("%d: updated %s.%d.occupation", p->id, role_str, old_pers);
        updated = 1;
      }
      if (needs_update(old_m->occupation_en, new_m->occupation_en)) {
        xfree(old_m->occupation_en);
        old_m->occupation_en = xstrdup(new_m->occupation_en);
        if (!daemon_mode)
          info("%d: updated %s.%d.occupation_en", p->id, role_str, old_pers);
        updated = 1;
      }

      // unlink the new member out of the way
      new_m = unlink_member(&new_u->i, new_role, new_pers);
      userlist_free(&new_m->b);
    }
  }

  // copy new members
 restart_inserting:
  for (new_role = 0; new_role < CONTEST_LAST_MEMBER; new_role++) {
    role_str = userlist_tag_to_str(new_role + USERLIST_T_CONTESTANTS);
    new_ms = new_u->i.members[new_role];
    if (!new_ms) continue;
    for (new_pers = 0; new_pers < new_ms->total; new_pers++) {
      new_m = new_ms->members[new_pers];
      if (!new_m) continue;
      if (new_m->serial > 0) {
        err("%s -> new member in %s has serial number %d",
            msg, role_str, new_m->serial);
        old_m = unlink_member(ui, new_role, new_pers);
        //ASSERT(old_m == new_m);
        userlist_free(&new_m->b);
        goto restart_inserting;
      }
      if (!cnts) {
        max_count = 10;
      } if (!cnts->members[new_role]) {
        max_count = 0;
      } else {
        max_count = cnts->members[new_role]->max_count;
      }
      if (!max_count) {
        err("%s -> members of role %s are not allowed in current contest",
            msg, role_str);
        old_m = unlink_member(ui, new_role, new_pers);
        ASSERT(old_m == new_m);
        userlist_free(&new_m->b);
        goto restart_inserting;
      }
      if (ui->members[new_role]
          && ui->members[new_role]->total >= max_count) {
        err("%s -> too many members for role %s", msg, role_str);
        old_m = unlink_member(ui, new_role, new_pers);
        ASSERT(old_m == new_m);
        userlist_free(&new_m->b);
        goto restart_inserting;
      }
      if (!daemon_mode)
        info("%s -> new member to role %s inserted", msg, role_str);
      updated = 1;
      old_m = unlink_member(&new_u->i, new_role, new_pers);
      //ASSERT(old_m == new_m);
      old_m->serial = userlist->member_serial++;
      link_member(ui, link_node, new_role, new_m);
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
  info("%s -> OK", msg);
  send_reply(p, ULS_OK);
}
#endif

static void
cmd_set_user_info(struct client_state *p,
                  int pkt_len,
                  struct userlist_pk_set_user_info *data)
{
  size_t xml_len;
  struct contest_desc *cnts = 0;
  int errcode = 0;
  unsigned char logbuf[1024];
  struct userlist_user *new_u = 0;
  int reply_code = ULS_OK, cloned_flag = 0;

  xml_len = strlen(data->data);
  if (xml_len != data->info_len) {
    CONN_BAD("XML length does not match");
    return;
  }
  if (pkt_len != sizeof(*data) + xml_len) {
    CONN_BAD("packet length mismatch");
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "SET_USER_INFO: %d, %d", data->user_id, data->info_len);

  if (data->contest_id) {
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
  }

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    err("%s -> user_id does not match: %d, %d", logbuf,
        p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (!(new_u = userlist_parse_user_str(data->data))) {
    err("%s -> XML parse error", logbuf);
    send_reply(p, -ULS_ERR_XML_PARSE);
    return;
  }

  if (data->user_id != new_u->id) {
    err("%s -> XML user_id %d does not correspond to packet user_id %d",
        logbuf, new_u->id, data->user_id);
    send_reply(p, -ULS_ERR_PROTOCOL);
    userlist_free(&new_u->b);
    return;
  }

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    userlist_free(&new_u->b);
    return;
  }

  if (default_is_read_only(data->user_id, data->contest_id) != 0) {
    err("%s -> user cannot be changed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    userlist_free(&new_u->b);
    return;
  }
  if (default_set_user_xml(data->user_id, data->contest_id, new_u,
                           cur_time, &cloned_flag) < 0) {
    err("%s -> user update failed", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    userlist_free(&new_u->b);
    return;
  }

  update_all_user_contests(data->user_id);
  if (cloned_flag) reply_code = ULS_CLONED;
  info("%s -> OK", logbuf);
  send_reply(p, reply_code);
  userlist_free(&new_u->b);
}

static void
cmd_set_passwd(struct client_state *p, int pkt_len,
               struct userlist_pk_set_password *data)
{
  int old_len, new_len, exp_len;
  unsigned char *old_pwd, *new_pwd;
  const struct userlist_user *u;
  struct passwd_internal oldint, newint;
  unsigned char logbuf[1024];

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

  snprintf(logbuf, sizeof(logbuf), "SET_PASSWD: %d", data->user_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    err("%s -> user_ids does not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (!new_len) {
    err("%s -> new password is empty", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (!u->passwd) {
    err("%s -> old password is not set", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(old_pwd, &oldint) < 0) {
    err("%s -> old password is invalid", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(new_pwd, &newint) < 0) {
    err("%s -> new password is invalid", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_check(&oldint, u->passwd, u->passwd_method) < 0) {
    err("%s -> passwords do not match", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  default_set_reg_passwd(u->id, USERLIST_PWD_SHA1,
                         newint.pwds[USERLIST_PWD_SHA1], cur_time);
  default_remove_user_cookies(u->id);
  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
}

static void
cmd_team_set_passwd(struct client_state *p, int pkt_len,
                    struct userlist_pk_set_password *data)
{
  int old_len, new_len, exp_len;
  unsigned char *old_pwd, *new_pwd;
  const struct userlist_user *u;
  struct passwd_internal oldint, newint;
  struct contest_desc *cnts = 0;
  int errcode, reply_code = ULS_OK, cloned_flag = 0;
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;
  const struct userlist_contest *c;

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

  snprintf(logbuf, sizeof(logbuf),
           "SET_TEAM_PASSWD: %d, %d", data->user_id, data->contest_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    err("%s -> user_ids do not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (cnts->disable_team_password) {
    err("%s -> team password is disabled", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (!new_len) {
    err("%s -> new password is empty", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(old_pwd, &oldint) < 0) {
    err("%s -> old password is invalid", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(new_pwd, &newint) < 0) {
    err("%s -> new password is invalid", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  default_get_user_info_3(data->user_id, data->contest_id, &u, &ui, &c);
  if (!c || c->status != USERLIST_REG_OK) {
    err("%s -> not registered", logbuf);
    send_reply(p, -ULS_ERR_NOT_REGISTERED);
    return;
  }

  if (!ui->team_passwd) {
    err("%s -> empty password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  if (passwd_check(&oldint, ui->team_passwd, ui->team_passwd_method) < 0) {
    err("%s -> OLD registration password does not match", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  // if team passwd entry does not exist, create it
  default_set_team_passwd(u->id, data->contest_id, USERLIST_PWD_SHA1,
                          newint.pwds[USERLIST_PWD_SHA1], cur_time,
                          &cloned_flag);
  if (cloned_flag) reply_code = ULS_CLONED;
  default_remove_user_cookies(u->id);
  send_reply(p, reply_code);
  info("%s -> OK", logbuf);
}

/* unprivileged version of the function */
static void
cmd_register_contest(struct client_state *p, int pkt_len,
                     struct userlist_pk_register_contest *data)
{
  struct contest_desc *c = 0;
  const struct userlist_contest *r;
  int errcode, status = USERLIST_REG_PENDING;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "REGISTER_CONTEST: %d, %d",
           data->user_id, data->contest_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    err("%s -> user_ids do not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if ((errcode = contests_get(data->contest_id, &c)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (c->reg_deadline && cur_time > c->reg_deadline) {
    err("%s -> registration deadline exceeded", logbuf);
    send_reply(p, -ULS_ERR_DEADLINE);
    return;
  }
  if (c->closed) {
    err("%s -> the contest is closed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  /* FIXME: add IP information to request packet and check it here */

  if (c->autoregister) status = USERLIST_REG_OK;
  errcode = default_register_contest(data->user_id, data->contest_id,
                                     status, cur_time, &r);
  if (errcode < 0) {
    err("%s -> registration failed", logbuf);
    send_reply(p, -ULS_ERR_UNSPECIFIED_ERROR);
    return;
  } else if (!errcode) {
    info("%s -> already registered", logbuf);
    send_reply(p, ULS_OK);
    return;
  }

  if (r->status == USERLIST_REG_OK) {
    update_userlist_table(data->contest_id);
  }
  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
  return;
}

/* privileged version */
static void
cmd_priv_register_contest(struct client_state *p, int pkt_len,
                          struct userlist_pk_register_contest *data)
{
  const struct userlist_user *u;
  struct contest_desc *c = 0;
  const struct userlist_contest *r;
  int errcode, status = USERLIST_REG_PENDING;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "PRIV_REGISTER_CONTEST: %d, %d, %d",
           p->user_id, data->user_id, data->contest_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);

  if ((errcode = contests_get(data->contest_id, &c)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0) {
    err("%s -> invalid user_id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (p->user_id != data->user_id) {
    if (is_privileged_user(u) >= 0) {
      if (is_cnts_capable(p, c, OPCAP_PRIV_CREATE_REG, logbuf) < 0) return;
    } else {
      if (is_cnts_capable(p, c, OPCAP_CREATE_REG, logbuf) < 0) return;
    }
  }
  // FIXME: this is a potential hole: a user without any permission
  // for a particular contest may register itself...

  if (c->autoregister) status = USERLIST_REG_OK;
  status = default_register_contest(data->user_id, data->contest_id, status,
                                    cur_time, &r);
  if (status < 0) {
    err("%s -> registration failed", logbuf);
    send_reply(p, -ULS_ERR_UNSPECIFIED_ERROR);
    return;
  } else if (!status) {
    info("%s -> already registered", logbuf);
    send_reply(p, ULS_OK);
    return;
  }

  if (r->status == USERLIST_REG_OK) {
    update_userlist_table(data->contest_id);
  }
  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
  return;
}

static void
cmd_delete_member(struct client_state *p, int pkt_len,
                  struct userlist_pk_delete_info *data)
{
  unsigned char logbuf[1024];
  struct contest_desc *cnts;
  int reply_code = ULS_OK, cloned_flag = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "DELETE_MEMBER: %d, %d, %d",
           data->user_id, data->contest_id, data->serial);

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (p->user_id != data->user_id) {
    err("%s -> user_ids do not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->contest_id < 0
      || (data->contest_id > 0 && contests_get(data->contest_id, &cnts) < 0)) {
    err("%s -> invalid contest_id: %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (default_is_read_only(data->user_id, data->contest_id) != 0) {
    err("%s -> user cannot be modified", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (default_remove_member(data->user_id, data->contest_id,
                            data->serial, cur_time, &cloned_flag) < 0) {
    err("%s -> unspecified error", logbuf);
    return send_reply(p, -ULS_ERR_UNSPECIFIED_ERROR);
  }

  if (cloned_flag) reply_code = ULS_CLONED;
  info("%s -> OK", logbuf);
  send_reply(p, reply_code);
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

static int
split_table_spec(const unsigned char *str, unsigned char ***p_split)
{
  unsigned char **split = 0;
  int field_count = 0, i;
  const unsigned char *p, *q;

  *p_split = 0;
  if (!str || !*str) return 0;

  for (p = str; *p; p++)
    if (*p == '|')
      field_count++;
  field_count++;

  XCALLOC(split, field_count);
  for (p = str, i = 0; i < field_count && *p; i++) {
    q = p;
    while (*q && *q != '|') q++;
    split[i] = xmemdup(p, q - p);
    if (*q == '|') q++;
    p = q;
  }

  *p_split = split;
  return field_count;
}

static unsigned char **
free_table_spec(int n, unsigned char **t)
{
  int i;

  if (!t) return 0;
  for (i = 0; i < n; i++)
    xfree(t[i]);
  xfree(t);
  return 0;
}

static void
list_user_info(FILE *f, int contest_id, const struct contest_desc *d,
               int locale_id, int user_id, unsigned long flags,
               const unsigned char *url, const unsigned char *srch)
{
  const struct userlist_user *u;
  const struct userlist_user_info *ui;
  const struct userlist_contest *c;
  const unsigned char *notset;
  unsigned char buf[1024];
  int role, pers;
  const struct userlist_member *m;
  const struct contest_member *cm;

  if (default_get_user_info_3(user_id, contest_id, &u, &ui, &c) < 0 || !c) {
    fprintf(f, "<%s>%s</%s>\n",
            d->users_head_style,
            _("Information is not available"),
            d->users_head_style);
    return;
  }

  l10n_setlocale(locale_id);
  notset = _("<i>Not set</i>");

  fprintf(f, "<%s>%s: %s</%s>\n",
          d->users_head_style,
          _("Detailed information for user (team)"), ui->name,
          d->users_head_style);
  fprintf(f, "<h3>%s</h3>\n", _("General information"));
  fprintf(f, "<table>\n");
  fprintf(f, "<tr><td%s>%s:</td><td%s>%d</td></tr>\n",
          d->users_verb_style, _("User ID"), d->users_verb_style, u->id);
  if (u->show_login) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Login"),
            d->users_verb_style, u->login);
  }
  if (u->show_email) {
    fprintf(f, "<tr><td%s>%s:</td><td%s><a href=\"mailto:%s\">%s</a></td></tr>\n",
            d->users_verb_style,
            _("E-mail"), d->users_verb_style, u->email, u->email);
  }
  fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
          d->users_verb_style, _("Name"), d->users_verb_style, ui->name);
  if (!d || d->fields[CONTEST_F_HOMEPAGE]) {
    if (!ui->homepage) {
      snprintf(buf, sizeof(buf), "%s", notset);
    } else {
      if (!strncasecmp(ui->homepage, "http://", 7)) {
        snprintf(buf, sizeof(buf), "<a href=\"%s\">%s</a>",
                 ui->homepage, ui->homepage);
      } else {
        snprintf(buf, sizeof(buf), "<a href=\"http://%s\">%s</a>",
                 ui->homepage, ui->homepage);
      }
    }
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Homepage"),
            d->users_verb_style, buf);
  }
  if (!d || d->fields[CONTEST_F_INST]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Institution"),
            d->users_verb_style, ui->inst?ui->inst:notset);
  }
  if (!d || d->fields[CONTEST_F_INST_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Institution (En)"),
            d->users_verb_style, ui->inst_en?ui->inst_en:notset);
  }
  if (!d || d->fields[CONTEST_F_INSTSHORT]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Institution (short)"),
            d->users_verb_style, ui->instshort?ui->instshort:notset);
  }
  if (!d || d->fields[CONTEST_F_INSTSHORT_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Institution (short) (En)"),
            d->users_verb_style, ui->instshort_en?ui->instshort_en:notset);
  }
  if (!d || d->fields[CONTEST_F_FAC]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Faculty"),
            d->users_verb_style, ui->fac?ui->fac:notset);
  }
  if (!d || d->fields[CONTEST_F_FAC_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Faculty (En)"),
            d->users_verb_style, ui->fac_en?ui->fac_en:notset);
  }
  if (!d || d->fields[CONTEST_F_FACSHORT]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Faculty (short)"),
            d->users_verb_style, ui->facshort?ui->facshort:notset);
  }
  if (!d || d->fields[CONTEST_F_FACSHORT_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Faculty (short) (En)"),
            d->users_verb_style, ui->facshort_en?ui->facshort_en:notset);
  }
  if (!d || d->fields[CONTEST_F_CITY]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("City"),
            d->users_verb_style, ui->city?ui->city:notset);
  }
  if (!d || d->fields[CONTEST_F_CITY_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("City (En)"),
            d->users_verb_style, ui->city_en?ui->city_en:notset);
  }
  if (!d || d->fields[CONTEST_F_COUNTRY]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Country"),
            d->users_verb_style, ui->country?ui->country:notset);
  }
  if (!d || d->fields[CONTEST_F_COUNTRY_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Country (En)"),
            d->users_verb_style, ui->country_en?ui->country_en:notset);
  }
    /* Location is never shown
    if (!d || d->fields[CONTEST_F_LOCATION]) {
      fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
              d->users_verb_style, _("Location"),
              d->users_verb_style, u->location?u->location:notset);
    }
    */
  if (!d || d->fields[CONTEST_F_LANGUAGES]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Prog. languages"),
            d->users_verb_style, ui->languages?ui->languages:notset);
  }

  fprintf(f, "</table>\n");

  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (d && !d->members[role]) continue;
    if (d && d->members[role] && d->members[role]->max_count <= 0)
      continue;
    if (!ui->members[role] || !ui->members[role]->total)
      continue;
    fprintf(f, "<h3>%s</h3>\n", gettext(member_string_pl[role]));
    for (pers = 0; pers < ui->members[role]->total; pers++) {
      if (d && d->members[role] && pers >= d->members[role]->max_count)
        break;
      m = ui->members[role]->members[pers];
      if (!m) continue;
      fprintf(f, "<h3>%s %d</h3>\n", gettext(member_string[role]),
              pers + 1);
      fprintf(f, "<table>\n");
      fprintf(f, "<tr><td%s>%s:</td><td%s>%d</td></tr>\n",
              d->users_verb_style, _("Serial No"),
              d->users_verb_style, m->serial);
      cm = 0;
      if (d) cm = d->members[role];
      if (!d || (cm && cm->fields[CONTEST_MF_FIRSTNAME])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("First name"),
                d->users_verb_style, m->firstname?m->firstname:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FIRSTNAME_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("First name (En)"),
                d->users_verb_style, m->firstname_en?m->firstname_en:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_MIDDLENAME])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Middle name"),
                d->users_verb_style, m->middlename?m->middlename:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_MIDDLENAME_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Middle name (En)"),
                d->users_verb_style, m->middlename_en?m->middlename_en:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_SURNAME])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Family name"),
                d->users_verb_style, m->surname?m->surname:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_SURNAME_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Family name (En)"),
                d->users_verb_style, m->surname_en?m->surname_en:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_STATUS])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Status"),
                d->users_verb_style, gettext(member_status_string[m->status]));
      }
      if (!d || (cm && cm->fields[CONTEST_MF_GRADE])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%d</td></tr>\n",
                d->users_verb_style, _("Grade"),
                d->users_verb_style, m->grade);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_GROUP])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Group"),
                d->users_verb_style, m->group?m->group:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_GROUP_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Group (En)"),
                d->users_verb_style, m->group_en?m->group_en:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_INST])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Institution"),
                d->users_verb_style, m->inst?m->inst:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_INST_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Institution (En)"),
                d->users_verb_style, m->inst_en?m->inst_en:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_INSTSHORT])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Institution (short)"),
                d->users_verb_style, m->instshort?m->instshort:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_INSTSHORT_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Institution (short) (En)"),
                d->users_verb_style, m->instshort_en?m->instshort_en:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FAC])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Faculty"),
                d->users_verb_style, m->fac?m->fac:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FAC_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Faculty (En)"),
                d->users_verb_style, m->fac_en?m->fac_en:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FACSHORT])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Faculty (short)"),
                d->users_verb_style, m->facshort?m->facshort:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FACSHORT_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Faculty (short) (En)"),
                d->users_verb_style, m->facshort_en?m->facshort_en:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_OCCUPATION])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Occupation"),
                d->users_verb_style, m->occupation?m->occupation:notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_OCCUPATION_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Occupation (En)"),
                d->users_verb_style, m->occupation_en?m->occupation_en:notset);
      }
        /*
    CONTEST_MF_EMAIL,
    CONTEST_MF_HOMEPAGE,
         */
      fprintf(f, "</table>\n");
    }
  }

  fprintf(f, "<h3>%s</h3>\n", _("Contest registrations"));
  fprintf(f, "<table><tr><th>%s</th><th>%s</th></tr>\n",
          _("Contest name"), _("Status"));
  fprintf(f, "<tr><td>%s</td><td>%s</td></tr>\n",
          d->name, gettext(status_str_map[c->status]));
  fprintf(f, "</table>\n");

  l10n_setlocale(0);
}

static void
do_list_users(FILE *f, int contest_id, struct contest_desc *d,
              int locale_id,
              int user_id, unsigned long flags,
              unsigned char *url, unsigned char *srch)
{
  const struct userlist_user *u;
  const struct userlist_user_info *ui;
  const struct userlist_contest *c;
  struct contest_desc *cnts;
  int i, j;
  unsigned char *s;
  unsigned char buf[1024];
  const unsigned char *table_format = 0, *table_legend = 0;
  unsigned char **format_s = 0, **legend_s = 0;
  int legend_n = 0, format_n = 0;
  struct sformat_extra_data sformat_extra;
  ptr_iterator_t iter;

  /* add additional filters */
  /* add additional sorts */

  l10n_setlocale(locale_id);
  iter = default_get_info_list_iterator(contest_id,
                                        USERLIST_UC_LOCKED|USERLIST_UC_BANNED);
  if (!iter->has_next(iter)) {
    fprintf(f, "<p%s>%s</p>\n",
            d->users_par_style, _("No users registered for this contest"));
    l10n_setlocale(0);
    return;
  }

  cnts = 0;
  if (contest_id > 0 && contests_get(contest_id, &cnts) >= 0) {
    if (locale_id && cnts->users_table_format) {
      table_format = cnts->users_table_format;
      table_legend = cnts->users_table_legend;
    } else if (!locale_id && cnts->users_table_format_en) {
      table_format = cnts->users_table_format_en;
      table_legend = cnts->users_table_legend_en;
    } else if (cnts->users_table_format) {
      table_format = cnts->users_table_format;
      table_legend = cnts->users_table_legend;
    } else if (cnts->users_table_format_en) {
      table_format = cnts->users_table_format_en;
      table_legend = cnts->users_table_legend_en;
    }
    if (table_format && !table_legend) table_format = 0;
    if (!table_format && table_legend) table_legend = 0;
  }
  if (table_format) {
    format_n = split_table_spec(table_format, &format_s);
    legend_n = split_table_spec(table_legend, &legend_s);
    if (format_n != legend_n) {
      format_s = free_table_spec(format_n, format_s);
      legend_s = free_table_spec(legend_n, legend_s);
      format_n = legend_n = 0;
      table_format = table_legend = 0;
    }
  }

  //fprintf(f, _("<p%s>%d users listed</p>\n"), d->users_par_style, u_num);

  fprintf(f, "<table width=\"100%%\">\n<tr><td%s><b>%s</b></td>",
          d->users_table_style, _("Serial No"));
  if (table_legend) {
    for (j = 0; j < legend_n; j++) {
      s = html_armor_string_dup(legend_s[j]);
      fprintf(f, "<td%s><b>%s</b></td>", d->users_table_style, s);
      xfree(s);
    }
  } else {
    fprintf(f, "<td%s><b>%s</b></td><td%s><b>%s</b></td><td%s><b>%s</b></td><td%s><b>%s</b></td>\n",
            d->users_table_style, _("User ID"),
            d->users_table_style, _("User name"),
            d->users_table_style, _("Institution"),
            d->users_table_style, _("Faculty"));
  }
  fprintf(f, "<td%s><b>%s</b></td></tr>\n", d->users_table_style, _("Status"));

  memset(&sformat_extra, 0, sizeof(sformat_extra));
  sformat_extra.locale_id = locale_id;

  for (; iter->has_next(iter); iter->next(iter)) {
    fprintf(f, "<tr><td%s>%d</td>", d->users_table_style, i + 1);

    u = (const struct userlist_user*) iter->get(iter);
    ui = userlist_get_user_info(u, contest_id);
    if (!(c = userlist_get_user_contest(u, contest_id))) continue;

    if (table_format) {
      for (j = 0; j < format_n; j++) {
        sformat_message(buf, sizeof(buf), format_s[j], 0, 0, 0, 0, 0,
                        u, cnts, &sformat_extra);
        s = html_armor_string_dup(buf);
        if (!s || !*s) {
          fprintf(f, "<td%s>&nbsp;</td>", d->users_table_style);
        } else {
          if (!strcmp(format_s[j], "%Un")
              || !strcmp(format_s[j], "%Ui")
              || !strcmp(format_s[j], "%Ul")) {
            fprintf(f, "<td%s><a href=\"%s?user_id=%d", d->users_table_style,
                    url, u->id);
            if (contest_id > 0) fprintf(f, "&contest_id=%d", contest_id);
            if (locale_id > 0) fprintf(f, "&locale_id=%d", locale_id);
            fprintf(f, "\">%s</a></td>", s);
          } else {
            fprintf(f, "<td%s>%s</td>", d->users_table_style, s);
          }
        }
        xfree(s);
      }
    } else {
      // FIXME: do html armoring?
      fprintf(f, "<td%s>%d</td>", d->users_table_style, u->id);
      s = ui->name;
      if (!s) {
        fprintf(f, "<td%s>&nbsp;</td>", d->users_table_style);
      } else if (!url) {
        fprintf(f, "<td%s>%s</td>", d->users_table_style, s);
      } else {
        fprintf(f, "<td%s><a href=\"%s?user_id=%d", d->users_table_style,
                url, u->id);
        if (contest_id > 0) fprintf(f, "&contest_id=%d", contest_id);
        if (locale_id > 0) fprintf(f, "&locale_id=%d", locale_id);
        fprintf(f, "\">%s</a></td>", s);
      }
      if (!locale_id) {
        s = ui->instshort_en;
        if (!s) s = ui->instshort;
      } else {
        s = ui->instshort;
        if (!s) s = ui->instshort_en;
      }
      if (!s) s = "&nbsp;";
      fprintf(f, "<td%s>%s</td>", d->users_table_style, s);
      if (!locale_id) {
        s = ui->facshort_en;
        if (!s) s = ui->facshort;
      } else {
        s = ui->facshort;
        if (!s) s = ui->facshort_en;
      }
      if (!s) s = "&nbsp;";
      fprintf(f, "<td%s>%s</td>", d->users_table_style, s);
    }
    fprintf(f, "<td%s>%s</td>", d->users_table_style,
            gettext(status_str_map[c->status]));
    fprintf(f, "</tr>\n");
  }
  fprintf(f, "</table>\n");
  l10n_setlocale(0);
  format_s = free_table_spec(format_n, format_s);
  legend_s = free_table_spec(legend_n, legend_s);
}

static void
do_dump_database(FILE *f, int contest_id, struct contest_desc *d, int html_flag)
{
  const struct userlist_user *u;
  const struct userlist_contest *c;
  const struct userlist_member *m;
  unsigned char *notset = 0, *banstr = 0, *invstr = 0, *statstr = 0;
  int role, pers, pers_tot;
  const struct userlist_user_info *ui;
  ptr_iterator_t iter;


  if (html_flag) {
    fprintf(f, "Content-type: text/plain\n\n");
  }
  notset = "";

  for (iter = default_get_info_list_iterator(contest_id, USERLIST_UC_ALL);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    ui = userlist_get_user_info(u, contest_id);
    c = userlist_get_user_contest(u, contest_id);

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
    if ((c->flags & USERLIST_UC_LOCKED)) banstr = "L";

    pers_tot = 0;
    for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
      if (!ui->members[role]) continue;
      for (pers = 0; pers < ui->members[role]->total; pers++) {
        unsigned char nbuf[32] = { 0 };
        unsigned char *lptr = nbuf;

        if (!(m = ui->members[role]->members[pers])) continue;
        if (role == CONTEST_M_CONTESTANT || role == CONTEST_M_RESERVE) {
          snprintf(nbuf, sizeof(nbuf), "%d", m->grade);
          lptr = nbuf;
        } else {
          lptr = m->occupation;
        }

        pers_tot++;
        fprintf(f, ";%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%d;%s;%s;%s;%s;%s;%s;%s;%s;%s\n",
                u->id, u->login, ui->name, u->email,
                ui->inst?ui->inst:notset,
                ui->inst_en?ui->inst_en:notset,
                ui->instshort?ui->instshort:notset,
                ui->instshort_en?ui->instshort_en:notset,
                ui->fac?ui->fac:notset,
                ui->fac_en?ui->fac_en:notset,
                ui->facshort?ui->facshort:notset,
                ui->facshort_en?ui->facshort_en:notset,
                ui->city?ui->city:notset,
                ui->city_en?ui->city_en:notset,
                ui->country?ui->country:notset,
                ui->country_en?ui->country_en:notset,
                ui->location?ui->location:notset,
                ui->printer_name?ui->printer_name:notset,
                ui->languages?ui->languages:notset,
                statstr, invstr, banstr,
                m->serial,
                gettext(member_string[role]),
                m->surname?m->surname:notset,
                m->surname_en?m->surname_en:notset,
                m->firstname?m->firstname:notset,
                m->firstname_en?m->firstname_en:notset,
                m->middlename?m->middlename:notset,
                m->middlename_en?m->middlename_en:notset,
                gettext(member_status_string[m->status]),
                lptr?lptr:notset);
      }
    }
    if (!pers_tot) {
      fprintf(f, ";%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n",
              u->id, u->login, ui->name, u->email,
              ui->inst?ui->inst:notset,
              ui->inst_en?ui->inst_en:notset,
              ui->instshort?ui->instshort:notset,
              ui->instshort_en?ui->instshort_en:notset,
              ui->fac?ui->fac:notset,
              ui->fac_en?ui->fac_en:notset,
              ui->facshort?ui->facshort:notset,
              ui->facshort_en?ui->facshort_en:notset,
              ui->city?ui->city:notset,
              ui->city_en?ui->city_en:notset,
              ui->country?ui->country:notset,
              ui->country_en?ui->country_en:notset,
              ui->location?ui->location:notset,
              ui->printer_name?ui->printer_name:notset,
              ui->languages?ui->languages:notset,
              statstr, invstr, banstr,
              "", "", "", "", "", "", "");
    }
  }
  return;
}

static void
do_dump_whole_database(FILE *f, int contest_id, struct contest_desc *d,
                       int html_flag)
{
  const struct userlist_user *u;
  unsigned char *notset = 0;
  const struct userlist_user_info *ui;
  ptr_iterator_t iter;

  if (html_flag) {
    fprintf(f, "Content-type: text/plain\n\n");
  }
  notset = "";

  for (iter = default_get_info_list_iterator(contest_id, USERLIST_UC_ALL);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    ui = userlist_get_user_info(u, contest_id);

    fprintf(f, ";%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n",
            u->id, u->login, ui->name, u->email,
            ui->inst?ui->inst:notset,
            ui->inst_en?ui->inst_en:notset,
            ui->instshort?ui->instshort:notset,
            ui->instshort_en?ui->instshort_en:notset,
            ui->fac?ui->fac:notset,
            ui->fac_en?ui->fac_en:notset,
            ui->facshort?ui->facshort:notset,
            ui->facshort_en?ui->facshort_en:notset,
            ui->city?ui->city:notset,
            ui->city_en?ui->city_en:notset,
            ui->country?ui->country:notset,
            ui->country_en?ui->country_en:notset,
            ui->location?ui->location:notset,
            ui->printer_name?ui->printer_name:notset,
            ui->languages?ui->languages:notset);
    }
}

static void
cmd_list_users(struct client_state *p, int pkt_len,
               struct userlist_pk_list_users *data)
{
  struct client_state *q;
  FILE *f = 0;
  char *html_ptr = 0;
  size_t html_size = 0;
  unsigned char *url_ptr, *srch_ptr;
  struct contest_desc *cnts = 0;
  int errcode, exp_len, url_len, srch_len;
  unsigned char logbuf[1024];

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

  snprintf(logbuf, sizeof(logbuf), "LIST_USERS: %d, %d",
           data->contest_id, data->user_id);

  if (data->user_id) {
    if (default_check_user(data->user_id) < 0) {
      err("%s -> invalid user", logbuf);
      send_reply(p, -ULS_ERR_BAD_UID);
      return;
    }
  }
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (!(f = open_memstream(&html_ptr, &html_size))) {
    err("%s -> open_memstream failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  if (data->user_id > 0) {
    list_user_info(f, data->contest_id, cnts, data->locale_id,
                   data->user_id, data->flags, url_ptr, srch_ptr);
  } else {
    do_list_users(f, data->contest_id, cnts, data->locale_id,
                  data->user_id, data->flags, url_ptr, srch_ptr);
  }
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
  fcntl(q->fd, F_SETFL, fcntl(q->fd, F_GETFL) | O_NONBLOCK);
  link_client_state(q);
  if (!daemon_mode) info("%s -> OK, %d", logbuf, q->id);
  send_reply(p, ULS_OK);
}

static void
cmd_dump_database(struct client_state *p, int pkt_len,
                  struct userlist_pk_dump_database *data)
{
  struct client_state *q;
  FILE *f = 0;
  char *html_ptr = 0;
  size_t html_size = 0;
  struct contest_desc *cnts = 0;
  int errcode;
  opcap_t caps;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    CONN_BAD("two client file descriptors required");
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "DUMP_DATA: %d, %d",
           p->user_id, data->contest_id);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
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

    err("%s -> no capability %d", logbuf, OPCAP_DUMP_USERS);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (!(f = open_memstream(&html_ptr, &html_size))) {
    err("%s -> open_memstream failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_dump_database(f, data->contest_id, cnts, data->html_flag);
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
  fcntl(q->fd, F_SETFL, fcntl(q->fd, F_GETFL) | O_NONBLOCK);
  link_client_state(q);
  info("%s -> OK, %d", logbuf, q->id);
  send_reply(p, ULS_OK);
}

static void
cmd_dump_whole_database(struct client_state *p, int pkt_len,
                        struct userlist_pk_dump_database *data)
{
  struct client_state *q;
  FILE *f = 0;
  char *html_ptr = 0;
  size_t html_size = 0;
  struct contest_desc *cnts = 0;
  opcap_t caps;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    CONN_BAD("two client file descriptors required");
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "DUMP_ALL_DATA: %d",
           p->user_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);

  if (get_uid_caps(&config->capabilities, p->user_id, &caps) < 0
      || opcaps_check(caps, OPCAP_DUMP_USERS) < 0) {
    err("%s -> no capability %d", logbuf, OPCAP_DUMP_USERS);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (!(f = open_memstream(&html_ptr, &html_size))) {
    err("%s -> open_memstream failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_dump_whole_database(f, data->contest_id, cnts, data->html_flag);
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
  fcntl(q->fd, F_SETFL, fcntl(q->fd, F_GETFL) | O_NONBLOCK);
  link_client_state(q);
  info("%s -> OK, %d", logbuf, q->id);
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
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "MAP_CONTEST: %d, %d",
           p->user_id, data->contest_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (is_cnts_capable(p, cnts, OPCAP_MAP_CONTEST, logbuf) < 0) return;

  if (!(ex = attach_contest_extra(data->contest_id, cnts))) {
    send_reply(p, -ULS_ERR_IPC_FAILURE);
    return;
  }
  p->cnts_extra = ex;
  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_CONTEST_MAPPED;
  out->sem_key = 0;
  out->shm_key = ex->shm_key;
  enqueue_reply_to_client(p, out_size, out);
  update_userlist_table(data->contest_id);
  info("%s -> OK, %d", logbuf, ex->shm_key);
}

// just assigns the connection user_id by the system user_id
static void
cmd_admin_process(struct client_state *p, int pkt_len,
                  struct userlist_packet *data)
{
  struct ejudge_cfg_user_map *um = 0;
  struct xml_tree *ut = 0;
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  const struct userlist_user_info *ui;
  unsigned char *login, *name, *login_ptr, *name_ptr;
  size_t login_len, name_len, out_len;
  struct userlist_pk_uid_2 *out;
  int user_id;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "ADMIN_PROCESS: %d, %d",
           p->peer_pid, p->peer_uid);

  if (!p->peer_uid) {
    err("%s -> root is not allowed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (config->user_map) {
    for (ut = config->user_map->first_down; ut; ut = ut->right) {
      um = (struct ejudge_cfg_user_map*) ut;
      if (um->system_uid == p->peer_uid) break;
    }
  }
  if (!ut) {
    err("%s -> user is not found in the user id map", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "ADMIN_PROCESS: %d, %d, %s",
           p->peer_pid, p->peer_uid, um->local_user_str);

  if ((user_id = default_get_user_by_login(um->local_user_str)) <= 0) {
    err("%s -> local user does not exist", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  p->user_id = user_id;

  snprintf(logbuf, sizeof(logbuf), "ADMIN_PROCESS: %d, %d, %d",
           p->peer_pid, p->peer_uid, p->user_id);

  default_get_user_info_2(user_id, 0, &u, &ui);
  login = u->login;
  if (!login) login = "";
  name = ui->name;
  if (!name || !*name) name = u->login;
  login_len = strlen(login);
  name_len = strlen(name);

  out_len = sizeof(*out) + login_len + name_len;
  out = (struct userlist_pk_uid_2 *) alloca(out_len);
  memset(out, 0, out_len);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;

  out->reply_id = ULS_UID_2;
  out->uid = p->user_id;
  out->priv_level = p->priv_level;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, login);
  strcpy(name_ptr, name);
  enqueue_reply_to_client(p, out_len, out);
}

static void
do_generate_passwd(int contest_id, FILE *log)
{
  const struct userlist_user *u;
  const struct userlist_contest *c;
  unsigned char buf[16];
  const struct userlist_user_info *ui;
  ptr_iterator_t iter;

  fprintf(log, "<table border=\"1\"><tr><th>User ID</th><th>User Login</th><th>User Name</th><th>New User Login Password</th><th>Location</th></tr>\n");

  for (iter = default_get_standings_list_iterator(contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    ui = userlist_get_user_info(u, contest_id);
    if (!(c = userlist_get_user_contest(u, contest_id))) continue;

    // do not change password for privileged users
    if (is_privileged_user(u) >= 0) continue;

    // also do not change password for invisible, banned or locked users
    if ((c->flags & USERLIST_UC_ALL)) continue;

    default_remove_user_cookies(u->id);
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_reg_passwd(u->id, USERLIST_PWD_PLAIN, buf, cur_time);

  // html table header
    fprintf(log, "<tr><td><b>User ID</b></td><td><b>User Login</b></td><td><b>User Name</b></td><td><b>New User Login Password</b></td><td><b>Location</b></td></tr>\n");
    fprintf(log, "<tr><td>%d</td><td>%s</td><td>%s</td><td><tt>%s</tt></td><td><tt>%s</tt></td></tr>\n",
            u->id, u->login, ui->name, buf, ui->location?(char*)ui->location:"N/A");
  }
  fprintf(log, "</table>\n");
}

static void
cmd_generate_register_passwords(struct client_state *p, int pkt_len,
                                struct userlist_pk_map_contest *data)
{
  char *log_ptr = 0;
  size_t log_size = 0;
  FILE *f = 0;
  struct client_state *q = 0;
  struct contest_desc *cnts = 0;
  int errcode;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "GENERATE_REGISTER_PASSWORDS: %d, %d",
           p->user_id, data->contest_id);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (is_cnts_capable(p, cnts, OPCAP_GENERATE_TEAM_PASSWORDS, logbuf) < 0)
    return;
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    CONN_BAD("two client file descriptors required");
    return;
  }
  if (!(f = open_memstream(&log_ptr, &log_size))) {
    err("%s -> open_memstream failed", logbuf);
    send_reply(p, ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_generate_passwd(data->contest_id, f);
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
  fcntl(q->fd, F_SETFL, fcntl(q->fd, F_GETFL) | O_NONBLOCK);
  link_client_state(q);
  info("%s -> OK, %d", logbuf, q->id);
  send_reply(p, ULS_OK);
}

static void
do_generate_team_passwd(int contest_id, FILE *log)
{
  const struct userlist_user *u;
  const struct userlist_contest *c;
  unsigned char buf[16];
  const struct userlist_user_info *ui;
  ptr_iterator_t iter;

  fprintf(log, "<table border=\"1\"><tr><th>User ID</th><th>User Login</th><th>User Name</th><th>New User Password</th><th>Location</th></tr>\n");
  for (iter = default_get_standings_list_iterator(contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    ui = userlist_get_user_info(u, contest_id);
    if (!(c = userlist_get_user_contest(u, contest_id))) continue;

    // do not change password for privileged users
    if (is_privileged_user(u) >= 0) continue;

    // also do not change password for invisible, banned or locked users
    if ((c->flags & USERLIST_UC_ALL)) continue;

    default_remove_user_cookies(u->id);
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_team_passwd(u->id, contest_id, USERLIST_PWD_PLAIN,
                            buf, cur_time, NULL);

  // html table header
    fprintf(log, "<tr><td><b>User ID</b></td><td><b>User Login</b></td><td><b>User Name</b></td><td><b>New User Password</b></td><td><b>Location</b></td></tr>\n");
    fprintf(log, "<tr><td>%d</td><td>%s</td><td>%s</td><td><tt>%s</tt></td><td><tt>%s</tt></td></tr>\n",
            u->id, u->login, ui->name, buf, ui->location?(char*)ui->location:"N/A");
  }
  fprintf(log, "</table>\n");
}

static void
cmd_generate_team_passwords(struct client_state *p, int pkt_len,
                            struct userlist_pk_map_contest *data)
{
  char *log_ptr = 0;
  size_t log_size = 0;
  FILE *f = 0;
  struct client_state *q = 0;
  struct contest_desc *cnts = 0;
  int errcode;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "GENERATE_TEAM_PASSWORDS: %d, %d",
           p->user_id, data->contest_id);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (is_cnts_capable(p, cnts, OPCAP_GENERATE_TEAM_PASSWORDS, logbuf) < 0)
    return;
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    CONN_BAD("two client file descriptors required");
    return;
  }
  if (!(f = open_memstream(&log_ptr, &log_size))) {
    err("%s -> open_memstream failed", logbuf);
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
  fcntl(q->fd, F_SETFL, fcntl(q->fd, F_GETFL) | O_NONBLOCK);
  link_client_state(q);
  info("%s -> OK, %d", logbuf, q->id);
  send_reply(p, ULS_OK);
}

static void
do_clear_team_passwords(int contest_id)
{
  const struct userlist_user *u;
  const struct userlist_contest *c;
  ptr_iterator_t iter;

  for (iter = default_get_standings_list_iterator(contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    if (!(c = userlist_get_user_contest(u, contest_id))) continue;

    // do not change password for privileged users
    if (is_privileged_user(u) >= 0) continue;

    // also do not change password for invisible, banned or locked users
    if ((c->flags & USERLIST_UC_ALL)) continue;

    default_clear_team_passwd(u->id, contest_id, NULL);
    default_remove_user_cookies(u->id);
  }
}

static void
cmd_clear_team_passwords(struct client_state *p, int pkt_len,
                         struct userlist_pk_map_contest *data)
{
  struct contest_desc *cnts = 0;
  int errcode;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "CLEAR_TEAM_PASSWORDS: %d, %d",
           p->user_id, data->contest_id);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (is_cnts_capable(p, cnts, OPCAP_GENERATE_TEAM_PASSWORDS, logbuf) < 0)
    return;
  do_clear_team_passwords(data->contest_id);
  info("%s -> OK", logbuf);
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
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "GET_CONTEST_NAME: %d",
           data->contest_id);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  name_len = strlen(cnts->name);
  if (name_len > 65000) {
    err("%s -> contest name is too long", logbuf);
    name_len = 65000;
  }
  out_size = sizeof(*out) + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = name_len;
  memcpy(out->data, cnts->name, name_len);
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, %d", logbuf, out->info_len);
}

static void
cmd_edit_registration(struct client_state *p, int pkt_len,
                      struct userlist_pk_edit_registration *data)
{
  const struct userlist_user *u;
  struct contest_desc *c = 0;
  const struct userlist_contest *uc = 0;
  int errcode;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "EDIT_REGISTRATION: %d, %d, %d, %d, %d, %08x",
           p->user_id, data->user_id, data->contest_id, data->new_status,
           data->flags_cmd, data->new_flags);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if ((errcode = contests_get(data->contest_id, &c)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (default_get_user_info_3(data->user_id, data->contest_id, &u, 0, &uc)<0){
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (!uc) {
    err("%s -> not registered", logbuf);
    send_reply(p, -ULS_ERR_NOT_REGISTERED);
    return;
  }

  /* check field values */
  if (data->new_status < -2 || data->new_status >= USERLIST_REG_LAST) {
    err("%s -> invalid new status", logbuf);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if (data->flags_cmd < 0 || data->flags_cmd > 3) {
    err("%s -> invalid flags command", logbuf);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if ((data->new_flags & ~USERLIST_UC_ALL)) {
    err("%s -> invalid new flags", logbuf);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }

  if (data->new_status == -2) {
    // remove a registration
    if (is_privileged_user(u) >= 0) {
      if (is_cnts_capable(p, c, OPCAP_PRIV_DELETE_REG, logbuf) < 0) return;
    } else {
      if (is_cnts_capable(p, c, OPCAP_DELETE_REG, logbuf) < 0) return;
    }
    default_remove_registration(data->user_id, data->contest_id);
  } else {
    if (is_cnts_capable(p, c, OPCAP_EDIT_REG, logbuf) < 0) return;

    if (data->new_status != -1) {
      default_set_reg_status(data->user_id, data->contest_id, data->new_status);
    }
    default_set_reg_flags(data->user_id, data->contest_id,
                          data->flags_cmd, data->new_flags);
  }
  update_userlist_table(data->contest_id);
  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
}

// 0 - ok, -1 - no
static int
check_editing_caps(int conn_user_id, int req_user_id,
                   const struct userlist_user *u, int contest_id)
{
  int edcap = OPCAP_EDIT_USER;
  ptr_iterator_t iter;
  const struct userlist_contest *c;
  struct contest_desc *cnts;
  opcap_t caps;

  if (conn_user_id == req_user_id) {
    // if the contest is not read-only, allow the operation
    // else use the main access control rules
    if (!default_is_read_only(conn_user_id, contest_id)) return 0;
  }

  if (is_privileged_user(u) >= 0) edcap = OPCAP_PRIV_EDIT_USER;

  // check if the user has the global editing capability
  if (get_uid_caps(&config->capabilities, conn_user_id, &caps) >= 0
      && opcaps_check(caps, edcap) >= 0) return 0;

  // check, that there exist a contest, for which the user has
  // editing capability
  for (iter = default_get_user_contest_iterator(req_user_id);
       iter->has_next(iter);
       iter->next(iter)) {
    c = (const struct userlist_contest *) iter->get(iter);

    if (contests_get(c->id, &cnts) >= 0
        && get_uid_caps(&cnts->capabilities, conn_user_id, &caps) >= 0
        && opcaps_check(caps, edcap) >= 0) return 0;
  }

  return -1;
}

static void
cmd_delete_user(struct client_state *p, int pkt_len,
                struct userlist_pk_delete_info *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "DELETE_USER: %d, %d",
           p->user_id, data->user_id);

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  default_get_user_info_1(data->user_id, &u);

  if (is_privileged_user(u) >= 0) {
    if (is_db_capable(p, OPCAP_PRIV_DELETE_USER, logbuf) < 0) return;
  } else {
    if (is_db_capable(p, OPCAP_DELETE_USER, logbuf) < 0) return;
  }
  do_remove_user(u);

  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
}

static void
cmd_priv_delete_member(struct client_state *p, int pkt_len,
                       struct userlist_pk_delete_info *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u;
  struct contest_desc *cnts;
  int r, reply_code = ULS_OK, cloned_flag = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (contests_get(data->contest_id, &cnts) < 0) {
    err("%s -> invalid contest_id: %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "PRIV_DELETE_MEMBER: %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id, data->serial);

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  default_get_user_info_1(data->user_id, &u);

  if (check_editing_caps(p->user_id, data->user_id, u, data->contest_id) < 0) {
    err("%s -> no capability to edit user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  r = default_remove_member(data->user_id, data->contest_id, data->serial,
                            cur_time, &cloned_flag);
  if (r < 0) {
    err("%s -> member removal failed", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_DELETE);
    return;
  }
  if (r == 1) {
    update_userlist_table(data->contest_id);
  }
  if (cloned_flag) reply_code = ULS_CLONED;
  send_reply(p, reply_code);
  info("%s -> OK, %d", logbuf, reply_code);
}

static void
cmd_delete_cookie(struct client_state *p, int pkt_len,
                  struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u;
  const struct userlist_cookie *c;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "DELETE_COOKIE: %d, %d, %llx",
           p->user_id, data->user_id, data->cookie);

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  default_get_user_info_1(data->user_id, &u);

  if (is_privileged_user(u) >= 0) {
    if (is_db_capable(p, OPCAP_PRIV_EDIT_USER, logbuf) < 0) return;
  } else {
    if (is_db_capable(p, OPCAP_EDIT_USER, logbuf) < 0) return;
  }

  if (!data->cookie) {
    default_remove_user_cookies(data->user_id);
  } else {
    if (default_get_cookie(data->cookie, &c) < 0) {
      err("%s -> no such cookie", logbuf);
      send_reply(p, -ULS_ERR_NO_COOKIE);
      return;
    }
    if (c->user_id != data->user_id) {
      err("%s -> cookie belongs to different user", logbuf);
      send_reply(p, -ULS_ERR_NO_COOKIE);
      return;
    }
    default_remove_cookie(c);
  }
  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
  return;
}

static void
cmd_delete_user_info(struct client_state *p, int pkt_len,
                     struct userlist_pk_delete_info *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u;
  struct contest_desc *cnts;
  int r;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (contests_get(data->contest_id, &cnts) < 0) {
    err("%s -> invalid contest_id: %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "DELETE_USER_INFO: %d, %d, %d",
           p->user_id, data->user_id, data->contest_id);

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  default_get_user_info_1(data->user_id, &u);

  if (check_editing_caps(p->user_id, data->user_id, u, data->contest_id) < 0) {
    err("%s -> no capability to edit user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if ((r=default_remove_user_contest_info(data->user_id, data->contest_id))== 1)
    update_userlist_table(data->contest_id);
  send_reply(p, ULS_OK);
  info("%s -> OK, %d", logbuf, r);
}

static void
cmd_delete_field(struct client_state *p, int pkt_len,
                 struct userlist_pk_edit_field *data)
{
  const struct userlist_user *u;
  struct contest_desc *cnts;
  unsigned char logbuf[1024];
  int r, reply_code = ULS_OK, cloned_flag = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "DELETE_FIELD: %d, %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id,
           data->serial, data->field);

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (data->contest_id < 0
      || (data->contest_id > 0 && contests_get(data->contest_id, &cnts) < 0)) {
    err("%s -> invalid contest_id: %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  default_get_user_info_1(data->user_id, &u);

  if (check_editing_caps(p->user_id, data->user_id, u, data->contest_id) < 0) {
    err("%s -> no capability to edit user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->field >= USERLIST_NN_FIRST && data->field < USERLIST_NN_LAST) {
    switch (data->field) {
    case USERLIST_NN_ID:
    case USERLIST_NN_LOGIN:
    case USERLIST_NN_IS_PRIVILEGED:
      err("%s -> the field cannot be deleted", logbuf);
      send_reply(p, -ULS_ERR_CANNOT_DELETE);
      return;
    }
    if ((r = default_clear_user_field(data->user_id,
                                      data->field, cur_time)) < 0) {
      err("%s -> the field cannot be deleted", logbuf);
      send_reply(p, -ULS_ERR_CANNOT_DELETE);
      return;
    }
    update_all_user_contests(data->user_id);
    goto done;
  }

  if (data->field >= USERLIST_NC_FIRST && data->field < USERLIST_NC_LAST){
    if ((r = default_clear_user_info_field(data->user_id, data->contest_id,
                                           data->field, cur_time,
                                           &cloned_flag)) < 0) {
      err("%s -> the field cannot be deleted", logbuf);
      send_reply(p, -ULS_ERR_CANNOT_DELETE);
      return;
    }
    update_userlist_table(data->contest_id);
    goto done;
  }

  if (data->field < USERLIST_NM_FIRST || data->field >= USERLIST_NM_LAST) {
    err("%s -> invalid field", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_DELETE);
    return;
  }

  if (data->field == USERLIST_NM_SERIAL) {
    err("%s -> the field cannot be deleted", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_DELETE);
    return;
  }

  if ((r = default_clear_member_field(data->user_id, data->contest_id,
                                      data->serial, data->field,
                                      cur_time, &cloned_flag)) < 0) {
    err("%s -> the field cannot be deleted", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_DELETE);
    return;
  }

 done:
  if (cloned_flag) reply_code = ULS_CLONED;
  send_reply(p, reply_code);
  info("%s -> OK, %d", logbuf, r);
}

static void
cmd_edit_field(struct client_state *p, int pkt_len,
               struct userlist_pk_edit_field *data)
{
  const struct userlist_user *u;
  int vallen, explen;
  unsigned char logbuf[1024];
  int r = 0, reply_code = ULS_OK, cloned_flag = 0;

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

  snprintf(logbuf, sizeof(logbuf), "EDIT_FIELD: %d, %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id,
           data->serial, data->field);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (check_editing_caps(p->user_id, data->user_id, u, data->contest_id) < 0) {
    err("%s -> no capability to edit user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->field >= USERLIST_NN_FIRST && data->field < USERLIST_NN_LAST) {
    if ((r = default_set_user_field(data->user_id, data->field, data->data,
                                    cur_time)) < 0) goto cannot_change;
    if (r > 0) update_all_user_contests(data->user_id);
    goto done;
  }

  if (data->field >= USERLIST_NC_FIRST && data->field < USERLIST_NC_LAST) {
    if ((r = default_set_user_info_field(data->user_id, data->contest_id,
                                         data->field, data->data, cur_time,
                                         &cloned_flag))<0)
      goto cannot_change;
    if (r > 0 && data->contest_id > 0)
      update_userlist_table(data->contest_id);
    goto done;
  }

  if (data->field >= USERLIST_NM_FIRST && data->field < USERLIST_NM_LAST) {
    if ((r = default_set_user_member_field(data->user_id, data->contest_id,
                                           data->serial, data->field,
                                           data->data, cur_time,
                                           &cloned_flag)) < 0)
      goto cannot_change;
    if (r > 0 && data->contest_id > 0)
      update_userlist_table(data->contest_id);
    goto done;
  }

 done:
  if (cloned_flag) reply_code = ULS_CLONED;
  send_reply(p, reply_code);
  info("%s -> OK, %d", logbuf, r);
  return;

 cannot_change:
  err("%s -> the field cannot be changed", logbuf);
  send_reply(p, -ULS_ERR_CANNOT_CHANGE);
  return;
}

static void
cmd_create_user(struct client_state *p, int pkt_len,
                struct userlist_pk_edit_field *data)
{
  struct userlist_pk_login_ok out;
  unsigned char logbuf[1024];
  int serial = -1, user_id;
  unsigned char buf[64];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  if (data->value_len != 0) {
    CONN_BAD("value_len != 0: %d", data->value_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "CREATE_USER: %d", p->user_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (is_db_capable(p, OPCAP_CREATE_USER, logbuf) < 0) return;

  do {
    serial++;
    if (!serial) {
      snprintf(buf, sizeof(buf), "New_login");
    } else {
      snprintf(buf, sizeof(buf), "New_login_%d", serial);
    }
  } while (default_get_user_by_login(buf) >= 0);

  if ((user_id = default_new_user(buf, "N/A", NULL, 0)) <= 0) {
    err("%s -> cannot create user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  default_touch_login_time(user_id, cur_time);

  info("%s -> new user %d", logbuf, user_id);
  memset(&out, 0, sizeof(out));
  out.reply_id = ULS_LOGIN_OK;
  out.user_id = user_id;
  enqueue_reply_to_client(p, sizeof(out), &out);
  return;
}

static void
cmd_create_member(struct client_state *p, int pkt_len,
                  struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];
  struct contest_desc *cnts;
  const struct userlist_user *u;
  int reply_code = ULS_OK, cloned_flag = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  if (data->value_len != 0) {
    CONN_BAD("value_len != 0: %d", data->value_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "CREATE_MEMBER: %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id, data->serial);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);

  if (data->contest_id < 0 ||
      (data->contest_id > 0 && contests_get(data->contest_id, &cnts))) {
    err("%s -> invalid contest_id: %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (check_editing_caps(p->user_id, data->user_id, u, data->contest_id) < 0) {
    err("%s -> no capability to edit user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (data->serial < -1 || data->serial >= CONTEST_LAST_MEMBER) {
    err("%s -> invalid role", logbuf);
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }
  if (default_new_member(data->user_id, data->contest_id, data->serial,
                         cur_time, &cloned_flag) < 0) {
    err("%s -> new member creation failed", logbuf);
    send_reply(p, -ULS_ERR_UNSPECIFIED_ERROR);
    return;
  }
  if (cloned_flag) reply_code = ULS_CLONED;
  send_reply(p, reply_code);
  info("%s -> OK", logbuf);
}

static void
cmd_add_field(struct client_state *p, int pkt_len,
              struct userlist_pk_edit_field *data)
{
  err("ADD_FIELD -> no longer supported");
  send_reply(p, -ULS_ERR_PROTOCOL);
}

/*
 * This request is sent from serve to userlist-server
 * each time client connects to the contest server.
 * Thus the regular logging is disabled just to reduce the number
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

  if (data->system_pid <= 1) {
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
  out.ssl = q->ssl;
  enqueue_reply_to_client(p, sizeof(out), &out);
}

static void
cmd_get_uid_by_pid_2(struct client_state *p, int pkt_len,
                   struct userlist_pk_get_uid_by_pid *data)
{
  struct client_state *q = 0;
  struct userlist_pk_uid_2 *out = 0;
  const unsigned char *login = 0, *name = 0;
  unsigned char *login_ptr, *name_ptr;
  int login_len, name_len, out_len;
  const struct userlist_user *u;
  const struct userlist_user_info *ui;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (data->system_pid <= 1) {
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
  if (q->user_id <= 0) {
    CONN_ERR("not yet authentificated");
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  if (default_get_user_info_2(q->user_id, data->contest_id, &u, &ui) < 0) {
    CONN_ERR("invalid login");
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  login = u->login;
  if (!login) login = "";
  name = ui->name;
  if (!name || !*name) name = u->login;
  login_len = strlen(login);
  name_len = strlen(name);

  out_len = sizeof(*out) + login_len + name_len;
  out = (struct userlist_pk_uid_2 *) alloca(out_len);
  memset(out, 0, out_len);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;

  out->reply_id = ULS_UID_2;
  out->uid = q->user_id;
  out->priv_level = q->priv_level;
  out->cookie = q->cookie;
  out->ip = q->ip;
  out->ssl = q->ssl;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, login);
  strcpy(name_ptr, name);
  enqueue_reply_to_client(p, out_len, out);
}

static void
cmd_is_valid_cookie(struct client_state *p,
                    int pkt_len,
                    struct userlist_pk_do_logout *data)
{
  const struct userlist_cookie *c = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  if (p->user_id <= 0) {
    CONN_ERR("not authentificated");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (is_db_capable(p, OPCAP_MAP_CONTEST, "IS_VALID_COOKIE") < 0) {
    CONN_ERR("no MAP_CONTEST capability");
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (default_get_cookie(data->cookie, &c) < 0 || !c) {
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  send_reply(p, ULS_OK);
}

static void
cmd_user_op(struct client_state *p,
            int pkt_len,
            struct userlist_pk_register_contest *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  unsigned char buf[16];
  const struct userlist_user_info *ui;
  int reply_code = ULS_OK, cloned_flag = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "USER_OP: %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id, data->request_id);

  if (p->user_id <= 0) {
    CONN_ERR("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0) goto invalid_user;
  if (check_editing_caps(p->user_id, data->user_id, u, data->contest_id) < 0) {
    err("%s -> no capability to edit user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  switch (data->request_id) {
  case ULS_RANDOM_PASSWD:
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_reg_passwd(data->user_id, USERLIST_PWD_PLAIN, buf, cur_time);
    break;
  case ULS_COPY_TO_REGISTER:
    if (default_get_user_info_2(data->user_id, data->contest_id, &u, &ui) < 0)
      goto invalid_user;
    if (!ui || !ui->team_passwd) goto empty_password;
    default_set_reg_passwd(data->user_id, ui->team_passwd_method,
                           ui->team_passwd, cur_time);
    break;
  case ULS_RANDOM_TEAM_PASSWD:
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_team_passwd(data->user_id, data->contest_id,
                            USERLIST_PWD_PLAIN, buf, cur_time, &cloned_flag);
    break;
  case ULS_COPY_TO_TEAM:
    if (!u->passwd) goto empty_password;
    default_set_team_passwd(data->user_id, data->contest_id,
                            u->passwd_method, u->passwd, cur_time,
                            &cloned_flag);
    break;
  case ULS_FIX_PASSWORD:
    if (default_get_user_info_2(data->user_id, data->contest_id, &u, &ui) < 0)
      goto invalid_user;
    if (!ui->team_passwd) break;
    default_set_reg_passwd(data->user_id, ui->team_passwd_method,
                           ui->team_passwd, cur_time);
    break;
  default:
    err("%s -> not implemented", logbuf);
    send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
    return;
  }

  if (cloned_flag) reply_code = ULS_CLONED;
  info("%s -> OK", logbuf);
  send_reply(p, reply_code);
  return;

 invalid_user:
  err("%s -> invalid user", logbuf);
  send_reply(p, -ULS_ERR_BAD_UID);
  return;

 empty_password:
  err("%s -> empty password", logbuf);
  send_reply(p, -ULS_ERR_INVALID_PASSWORD);
  return;
}

static void
cmd_lookup_user(struct client_state *p,
                int pkt_len,
                struct userlist_pk_do_login *data)
{
  struct userlist_pk_login_ok *out;
  size_t l, out_size, login_len, name_len;
  unsigned char logbuf[1024];
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  const struct userlist_user *u = 0;
  const struct userlist_user_info *ui;
  int user_id;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet length is too small: %d, must be >= %zu",
             pkt_len, sizeof(*data));
    return;
  }
  login_ptr = data->data;
  if ((l = strlen(login_ptr)) != data->login_length) {
    CONN_BAD("login length mismatch: %zu instead of %d", l, data->login_length);
    return;
  }
  passwd_ptr = login_ptr + data->login_length + 1;
  if ((l = strlen(passwd_ptr)) != data->password_length) {
    CONN_BAD("password length mismatch: %zu instead of %d",
             l, data->password_length);
    return;
  }
  if (pkt_len != (l = sizeof(*data)+data->login_length+data->password_length)) {
    CONN_BAD("packet length mismatch: %zu instead of %d", l, pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "LOOKUP_USER: %s", data->data);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (is_db_capable(p, OPCAP_LIST_ALL_USERS, logbuf)) return;

  if (data->login_length <= 0) {
    err("%s -> EMPTY LOGIN", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if ((user_id = default_get_user_by_login(login_ptr)) <= 0
      || default_get_user_info_2(user_id, data->contest_id, &u, &ui) < 0
      || !u || !ui) {
    err("%s -> NO SUCH USER", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  login_len = strlen(u->login);
  name_len = 0;
  if (ui->name) name_len = strlen(ui->name);
  out_size = sizeof(*out) + login_len + name_len;
  out = (struct userlist_pk_login_ok*) alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;

  out->reply_id = ULS_LOGIN_OK;
  out->user_id = u->id;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, ui->name);
  enqueue_reply_to_client(p, out_size, out);
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
  [ULS_DELETE_MEMBER]           cmd_delete_member,
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
  [ULS_GENERATE_PASSWORDS]      cmd_generate_register_passwords,
  [ULS_CLEAR_TEAM_PASSWORDS]    cmd_clear_team_passwords,
  [ULS_LIST_STANDINGS_USERS]    cmd_list_standings_users,
  [ULS_GET_UID_BY_PID_2]        cmd_get_uid_by_pid_2,
  [ULS_IS_VALID_COOKIE]         cmd_is_valid_cookie,
  [ULS_DUMP_WHOLE_DATABASE]     cmd_dump_whole_database,
  [ULS_RANDOM_PASSWD]           cmd_user_op,
  [ULS_RANDOM_TEAM_PASSWD]      cmd_user_op,
  [ULS_COPY_TO_TEAM]            cmd_user_op,
  [ULS_COPY_TO_REGISTER]        cmd_user_op,
  [ULS_FIX_PASSWORD]            cmd_user_op,
  [ULS_LOOKUP_USER]             cmd_lookup_user,
  [ULS_REGISTER_NEW_2]          cmd_register_new_2,
  [ULS_DELETE_USER]             cmd_delete_user,
  [ULS_DELETE_COOKIE]           cmd_delete_cookie,
  [ULS_DELETE_USER_INFO]        cmd_delete_user_info,
  [ULS_CREATE_USER]             cmd_create_user,
  [ULS_CREATE_MEMBER]           cmd_create_member,
  [ULS_PRIV_DELETE_MEMBER]      cmd_priv_delete_member,

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

static int
do_work(void)
{
  struct sockaddr_un addr;
  int val;
  int max_fd;
  struct timeval timeout;
  fd_set rset, wset;
  struct client_state *p, *q;
  int saved_fd;

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, interrupt_signal);
  signal(SIGTERM, interrupt_signal);
  signal(SIGHUP, force_check_dirty);
  signal(SIGUSR1, force_flush);

  if ((listen_socket = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
    err("socket() failed: %s", os_ErrorMsg());
    return 1;
  }

  if (forced_mode) unlink(config->socket_path);
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

  info("initialization is ok, now serving requests");

  while (1) {
    cur_time = time(0);

    // check for cookies expiration
    if (cur_time > last_cookie_check + cookie_check_interval) {
      default_remove_expired_cookies(cur_time);
      last_cookie_check = cur_time;
      cookie_check_interval = DEFAULT_COOKIE_CHECK_INTERVAL;
    }

    // check for user account expiration
    if (cur_time > last_user_check + user_check_interval) {
      default_remove_expired_users(cur_time - 24 * 60 * 60);
      last_user_check = cur_time;
      user_check_interval = DEFAULT_USER_CHECK_INTERVAL;
    }

    if (interrupt_signaled) {
      uldb_default->iface->sync(uldb_default->data);
    }

    uldb_default->iface->maintenance(uldb_default->data, cur_time);

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
      if (!daemon_mode)
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
        fcntl(new_fd, F_SETFL, fcntl(new_fd, F_GETFL) | O_NONBLOCK);
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
          if (!daemon_mode)
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

        if (w < 0 && (errno == EINTR || errno == EAGAIN)) {
          FD_CLR(p->fd, &wset);
          info("%d: not ready descriptor", p->id);
          goto restart_write_scan;
        }
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
            if (!daemon_mode)
              info("%d: auto-disconnecting: %d, %d, %d", p->id,
                   p->fd, p->client_fds[0], p->client_fds[1]);
            disconnect_client(p);
            goto restart_write_scan;
          }
          FD_CLR(p->fd, &wset);
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

        if (!daemon_mode)
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
          if (!daemon_mode)
            info("%d: received 2 file descriptors: %d, %d",
                 p->id, fds[0], fds[1]);
          p->client_fds[0] = fds[0];
          p->client_fds[1] = fds[1];
        } else if (pmsg->cmsg_len == CMSG_LEN(1 * sizeof(int))) {
          if (!daemon_mode)
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
          if (!daemon_mode)
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
          if (errno == EINTR || errno == EAGAIN) {
            FD_CLR(p->fd, &rset);
            info("%d: not ready descriptor", p->id);
            continue;
          }
          err("%d: read() failed: %s", p->id, os_ErrorMsg());
          disconnect_client(p);
          continue;
        }

        p->read_state += l;
        memcpy(&p->expected_len, rbuf, 4);
        if (p->read_state == 4) {
          if (p->expected_len <= 0 || p->expected_len > MAX_EXPECTED_LEN) {
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
        if (errno == EINTR || errno == EAGAIN) {
          FD_CLR(p->fd, &rset);
          info("%d: not ready descriptor", p->id);
          continue;
        }
        err("%d: read() failed: %s", p->id, os_ErrorMsg());
        disconnect_client(p);
        continue;
      }

      p->read_len += r;
      saved_fd = p->fd;
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
      FD_CLR(saved_fd, &rset);
    }
  }

  return 0;
}

static void
report_uptime(time_t t1, time_t t2)
{
  struct tm *ptm;
  unsigned char buf1[128], buf2[128];
  time_t dt = t2 - t1;
  int up_days, up_hours, up_mins, up_secs;

  ptm = localtime(&t1);
  snprintf(buf1, sizeof(buf1), "%04d/%02d/%02d %02d:%02d:%02d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  ptm = localtime(&t2);
  snprintf(buf2, sizeof(buf2), "%04d/%02d/%02d %02d:%02d:%02d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  info("server started: %s, stopped: %s", buf1, buf2);

  up_days = dt / (24 * 60 * 60); dt %= 24 * 60 * 60;
  up_hours = dt / (60 * 60); dt %= 60 * 60;
  up_mins = dt / 60; up_secs = dt % 60;
  info("server uptime: %d day(s), %d hour(s), %d min(s), %d sec(s)",
       up_days, up_hours, up_mins, up_secs);
}

// dirty hack to force linking of some functions
static void *forced_link[] __attribute__((unused));
static void *forced_link[] =
{
  &xml_err_elem_undefined_s,
};

static int
load_plugins(void)
{
  struct ejudge_plugin_iface *base_iface = 0;
  struct uldb_plugin_iface *uldb_iface = 0;
  struct xml_tree *p;
  struct ejudge_plugin *plg;
  void *plugin_data = 0;

  plugin_set_directory(config->plugin_dir);

  ejudge_cfg_unparse_plugins(config, stdout);

  // XML plugin always loaded
  uldb_plugins_num = 0;
  uldb_plugins[uldb_plugins_num].iface = &uldb_plugin_xml;
  if (!(plugin_data = uldb_plugin_xml.init(config))) {
    err("cannot initialize XML database plugin");
    return -1;
  }
  if (uldb_plugin_xml.parse(config, 0, plugin_data) < 0) {
    err("cannot initialize XML database plugin");
    return -1;
  }
  uldb_plugins[uldb_plugins_num].data = plugin_data;
  uldb_plugins_num++;

  // load other userdb plugins
  for (p = config->plugin_list; p; p = p->right) {
    plg = (struct ejudge_plugin*) p;

    if (!plg->load_flag) continue;
    if (strcmp(plg->type, "userdb") != 0) continue;

    if (uldb_plugins_num == ULDB_PLUGIN_MAX_NUM) {
      err("too many userlist database plugins");
      return 1;
    }

    if (!(base_iface = plugin_load(plg->path, plg->type, plg->name))) {
      err("cannot load plugin");
      return 1;
    }
    uldb_iface = (struct uldb_plugin_iface*) base_iface;
    if (uldb_iface->b.size != sizeof(*uldb_iface)) {
      err("plugin size mismatch");
      return 1;
    }
    if (uldb_iface->uldb_version != ULDB_PLUGIN_IFACE_VERSION) {
      err("plugin version mismatch");
      return 1;
    }
    if (!(plugin_data = uldb_iface->init(config))) {
      err("plugin initialization failed");
      return 1;
    }
    if (uldb_iface->parse(config, plg->data, plugin_data) < 0) {
      err("plugin failed to parse its configuration");
      return 1;
    }


    uldb_plugins[uldb_plugins_num].iface = uldb_iface;
    uldb_plugins[uldb_plugins_num].data = plugin_data;

    if (plg->default_flag) {
      if (uldb_default) {
        err("more than one plugin is defined as default");
        return 1;
      }
      uldb_default = &uldb_plugins[uldb_plugins_num];
    }

    uldb_plugins_num++;
  }

  if (!uldb_default) {
    info("using XML as the userlist database");
    uldb_default = &uldb_plugins[0];
  }

  return 0;
}

static struct uldb_loaded_plugin *
find_uldb_plugin(const unsigned char *name)
{
  int i;

  if (!name) return uldb_default;
  for (i = 0; i < uldb_plugins_num; i++)
    if (!strcmp(uldb_plugins[i].iface->b.name, name))
      return &uldb_plugins[i];
  return 0;
}

static int
convert_database(const unsigned char *from_name, const unsigned char *to_name)
{
  struct uldb_loaded_plugin *from_plugin = find_uldb_plugin(from_name);
  struct uldb_loaded_plugin *to_plugin = find_uldb_plugin(to_name);
  int r, user_id;
  int_iterator_t ui;
  const struct userlist_user *u;

  if (!from_plugin) {
    err("plugin %s does not exist or is not loaded", from_name);
    return 1;
  }
  if (!to_plugin) {
    err("plugin %s does not exist or is not loaded", to_name);
    return 1;
  }
  if (from_plugin == to_plugin) {
    err("--from-plugin and --to-plugin are the same");
    return 1;
  }

  // prepare the source plugin
  if (from_plugin->iface->open(from_plugin->data) < 0) {
    err("plugin %s failed to open its connection", from_name);
    return 1;
  }
  if ((r = from_plugin->iface->check(from_plugin->data)) < 0) {
    err("plugin %s failed to check its data", from_name);
    return 1;
  }
  if (!r) {
    err("database of plugin %s contains no data", from_name);
    return 1;
  }

  // prepare the destination plugin
  if (to_plugin->iface->open(to_plugin->data) < 0) {
    err("plugin %s failed to open its connection", to_name);
    return 1;
  }
  if (to_plugin->iface->create(to_plugin->data) < 0) {
    err("plugin %s failed to create a new database", to_name);
    return 1;
  }

  // enumerate users
  for (ui = from_plugin->iface->get_user_id_iterator(from_plugin->data);
       ui->has_next(ui);
       ui->next(ui)) {
    user_id = ui->get(ui);

    r = from_plugin->iface->get_user_full(from_plugin->data, user_id, &u);
    ASSERT(r == 1);

    r = to_plugin->iface->insert(to_plugin->data, u);
    if (r < 0) break;
  }
  ui->destroy(ui);

  return 0;
}

int
main(int argc, char *argv[])
{
  int code = 0;
  unsigned char *ejudge_xml_path = 0;
  int cur_arg = 1;
  int pid, log_fd;
  unsigned char *from_plugin = 0, *to_plugin = 0;
  int convert_flag = 0;
  int create_flag = 0;

  while (cur_arg < argc) {
    if (!strcmp(argv[cur_arg], "-D")) {
      daemon_mode = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-f")) {
      forced_mode = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "--from-plugin")) {
      from_plugin = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "--to-plugin")) {
      to_plugin = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "--convert")) {
      convert_flag = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "--create")) {
      create_flag = 1;
      cur_arg++;
    } else {
      break;
    }
  }
  if (cur_arg < argc) {
    ejudge_xml_path = argv[cur_arg++];
  }
  if (cur_arg != argc) {
    fprintf(stderr, "%s: invalid number of arguments\n", argv[0]);
    return 1;
  }
#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) {
    ejudge_xml_path = EJUDGE_XML_PATH;
  }
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) {
    err("configuration file is not specified");
    return 1;
  }

  info("userlist-server %s, compiled %s", compile_version, compile_date);

  if (getuid() == 0) {
    err("sorry, will not run as the root");
    return 1;
  }

  if (tsc_init() < 0) return 1;
  program_name = argv[0];
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
  if (random_init() < 0) return 1;
  l10n_prepare(config->l10n, config->l10n_dir);

  if (load_plugins() < 0) return 1;

  if (convert_flag) {
    return convert_database(from_plugin, to_plugin);
  }

  // initialize the default plugin
  if (uldb_default->iface->open(uldb_default->data) < 0) {
    err("default plugin failed to open its connection");
    return 1;
  }

  if (create_flag) {
    if (uldb_default->iface->create(uldb_default->data) < 0) {
      err("database creation failed");
      return 1;
    }
    if (uldb_default->iface->close(uldb_default->data) < 0) {
      err("database closing failed");
      return 1;
    }
    return 0;
  }

  if (uldb_default->iface->check(uldb_default->data) <= 0) {
    err("default plugin failed to check its data");
    return 1;
  }

  // initialize system uid->local uid map
  build_system_uid_map(config->user_map);

  /*
  return 0;

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
  if (userlist_build_login_hash(userlist) < 0) return 1;
  if (userlist_build_cookie_hash(userlist) < 0) return 1;
  //userlist_unparse(userlist, stdout);


  // initialize system uid->local uid map
  build_system_uid_map(config->user_map);
  */

  if (daemon_mode && !config->userlist_log) {
    err("<userlist_log> must be specified in daemon mode");
    return 1;
  }

  if (daemon_mode) {
    // daemonize itself
    if ((log_fd = open(config->userlist_log,
                       O_WRONLY | O_CREAT | O_APPEND, 0600)) < 0) {
      err("cannot open log file `%s'", config->userlist_log);
      return 1;
    }
    close(0);
    if (open("/dev/null", O_RDONLY) < 0) return 1;
    close(1);
    if (open("/dev/null", O_WRONLY) < 0) return 1;
    close(2); dup(log_fd); close(log_fd);
    if ((pid = fork()) < 0) return 1;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return 1;
  }

  server_start_time = time(0);
  code = do_work();

  if (socket_name) unlink(socket_name);
  if (listen_socket >= 0) close(listen_socket);
  ejudge_cfg_free(config);
  server_finish_time = time(0);
  report_uptime(server_start_time, server_finish_time);

  return code;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding" "va_list" "gzFile")
 * End:
 */
