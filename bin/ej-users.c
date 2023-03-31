/* -*- mode: c -*- */

/* Copyright (C) 2002-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/userlist.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/base64.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/contests.h"
#include "ejudge/version.h"
#include "ejudge/sha.h"
#include "ejudge/misctext.h"
#include "ejudge/l10n.h"
#include "ejudge/tsc.h"
#include "ejudge/sformat.h"
#include "ejudge/fileutl.h"
#include "ejudge/job_packet.h"
#include "ejudge/ejudge_plugin.h"
#include "ejudge/uldb_plugin.h"
#include "ejudge/xml_utils.h"
#include "ejudge/random.h"
#include "ejudge/startstop.h"
#include "ejudge/csv.h"
#include "ejudge/sock_op.h"
#include "ejudge/compat.h"
#include "ejudge/bitset.h"
#include "ejudge/sha256utils.h"
#include "ejudge/userlist_bin.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

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
#define EJUDGE_CHARSET EJ_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

#define ARMOR(s)  html_armor_buf(&ab, (s))

#define DEFAULT_COOKIE_CHECK_INTERVAL 600
#define DEFAULT_USER_CHECK_INTERVAL 600
#define CLIENT_TIMEOUT 600
#define MAX_EXPECTED_LEN EJ_MAX_USERLIST_PACKET_LEN

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

/* information about a connections, which observe changes */
struct client_state;
struct new_contest_extra;
struct observer_info
{
  // next and previous element in the contest_extra's list
  struct observer_info *cnts_next, *cnts_prev;
  // next and previous element in the client_state's list
  struct observer_info *clnt_next, *clnt_prev;
  // the client, which observes
  struct client_state *client;
  // the contest, which is observed
  struct new_contest_extra *contest;
  // the event flag
  int changed;
};

struct contest_extra
{
  int nref;
  int id;
  key_t shm_key;
  int shm_id;
  struct userlist_table *tbl;
};

/* new extra information about contest */
struct new_contest_extra
{
  int id;
  struct observer_info *o_first, *o_last; /* list of observers */
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
  int user_id;
  int contest_id;
  int priv_level;
  ej_cookie_t cookie;
  ej_cookie_t client_key;
  ej_ip_t ip;
  int ssl;
  int cnts_login;               /* 1, if logged to contest */

  // user capabilities
  //opcap_t caps;

  // passed file descriptors
  int client_fds[2];

  // attached contest exchange info
  struct contest_extra *cnts_extra;

  /* list of contests, which are observed */
  struct observer_info *o_first, *o_last;
  int o_count;                  /* counter of triggered observers */
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

// sometimes these will replace `contest_extras'
static struct new_contest_extra **new_contest_extras;
static size_t new_contest_extras_size;

static time_t cur_time;
static time_t last_cookie_check;
static time_t last_user_check;
static time_t cookie_check_interval;
static time_t user_check_interval;
static volatile int interrupt_signaled;
static volatile int restart_signaled;
static volatile int usr1_signaled;
static volatile int usr2_signaled;
static volatile int winch_signaled;
static int daemon_mode = 0;
static int forced_mode = 0;

static int server_start_time = 0;
static int server_finish_time = 0;

static const struct common_loaded_plugin *uldb_default = 0;

/* the map from system uids into the local uids */
/* for removal
static int *system_uid_map;
static size_t system_uid_map_size;
*/

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
static char const * const member_gender_string[] =
{
  0,
  _("Male"),
  _("Female"),
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
attach_contest_extra(int id, const struct contest_desc *cnts)
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

static struct new_contest_extra *
new_contest_extra_get(int contest_id)
{
  size_t new_size = 0;
  struct new_contest_extra **new_ptr = 0, *p;

  ASSERT(contest_id > 0);
  if (contest_id >= new_contest_extras_size) {
    if (!(new_size = new_contest_extras_size)) new_size = 32;
    while (contest_id >= new_size) new_size *= 2;
    XCALLOC(new_ptr, new_size);
    if (new_contest_extras_size > 0)
      memcpy(new_ptr, new_contest_extras,
             new_contest_extras_size * sizeof(new_ptr[0]));
    xfree(new_contest_extras);
    new_contest_extras_size = new_size;
    new_contest_extras = new_ptr;
  }
  if (!(p = new_contest_extras[contest_id])) {
    XCALLOC(p, 1);
    p->id = contest_id;
    new_contest_extras[contest_id] = p;
  }
  return new_contest_extras[contest_id];
}

static struct new_contest_extra *
new_contest_extra_try(int contest_id)
{
  ASSERT(contest_id > 0);
  if (contest_id >= new_contest_extras_size) return 0;
  return new_contest_extras[contest_id];
}

static void
add_observer(struct client_state *client, int contest_id)
{
  struct observer_info *p;
  struct new_contest_extra *contest;

  // check, that the contest is already observed
  for (p = client->o_first; p; p = p->clnt_next)
    if (p->contest->id == contest_id)
      return;

  contest = new_contest_extra_get(contest_id);
  XCALLOC(p, 1);
  p->client = client;
  p->contest = contest;

  p->clnt_next = client->o_first;
  if (client->o_first) {
    client->o_first->clnt_prev = p;
  } else {
    client->o_last = p;
  }
  client->o_first = p;

  p->cnts_next = contest->o_first;
  if (contest->o_first) {
    contest->o_first->cnts_prev = p;
  } else {
    contest->o_last = p;
  }
  contest->o_first = p;
}

static void
remove_observer(struct observer_info *p)
{
  struct new_contest_extra *contest;
  struct client_state *client;

  if (!p) return;
  contest = p->contest;
  client = p->client;

  // remove from contest list
  if (p->cnts_next) {
    p->cnts_next->cnts_prev = p->cnts_prev;
  } else {
    contest->o_last = p->cnts_prev;
  }
  if (p->cnts_prev) {
    p->cnts_prev->cnts_next = p->cnts_next;
  } else {
    contest->o_first = p->cnts_next;
  }

  // remove from client list
  if (p->clnt_next) {
    p->clnt_next->clnt_prev = p->clnt_prev;
  } else {
    client->o_last = p->clnt_prev;
  }
  if (p->clnt_prev) {
    p->clnt_prev->clnt_next = p->clnt_next;
  } else {
    client->o_first = p->clnt_next;
  }

  if (p->changed) client->o_count--;
  memset(p, 0, sizeof(*p));
  xfree(p);
}

static void
remove_observer_2(struct client_state *client, int contest_id)
{
  struct observer_info *p;

  for (p = client->o_first; p; p = p->clnt_next)
    if (p->contest->id == contest_id)
      return remove_observer(p);
}

static void
old_update_userlist_table(int cnts_id)
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
new_update_userlist_table(int cnts_id)
{
  struct new_contest_extra *ne;
  struct observer_info *p;

  if (!(ne = new_contest_extra_try(cnts_id))) return;
  for (p = ne->o_first; p; p = p->cnts_next) {
    if (!p->changed) {
      p->changed = 1;
      p->client->o_count++;
    }
  }
}

static void
update_userlist_table(int cnts_id)
{
  int i;
  const struct contest_desc *cnts;

  if (cnts_id <= 0) return;

  old_update_userlist_table(cnts_id);
  new_update_userlist_table(cnts_id);

  for (i = 1; i < new_contest_extras_size; ++i) {
    if (cnts_id == i || !new_contest_extras[i]) continue;
    cnts = 0;
    if (contests_get(i, &cnts) < 0 || !cnts) continue;
    if (cnts->user_contest_num == cnts_id) {
      old_update_userlist_table(i);
      new_update_userlist_table(i);
    }
  }
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

#define dflt_iface ((struct uldb_plugin_iface*)(uldb_default->iface))

#define plugin_func(func) (dflt_iface->func)

#define plugin_call(func, ...) (dflt_iface->func)(uldb_default->data, __VA_ARGS__)
#define plugin_call0(func) (dflt_iface->func)(uldb_default->data)
#define plugin_call1(func, a) (dflt_iface->func)(uldb_default->data, (a))
#define plugin_call2(func, a, b) (dflt_iface->func)(uldb_default->data, (a), (b))
#define plugin_call3(func, a, b, c) (dflt_iface->func)(uldb_default->data, (a), (b), (c))
#define plugin_call5(func, a, b, c, d, e) (dflt_iface->func)(uldb_default->data, (a), (b), (c), (d), (e))

// methods for accessing the default userlist database backend
#define default_get_user_full(a, b) dflt_iface->get_user_full(uldb_default->data, a, b)
#define default_get_user_id_iterator() dflt_iface->get_user_id_iterator(uldb_default->data)
#define default_get_user_by_login(a) dflt_iface->get_user_by_login(uldb_default->data, a)
#define default_sync() dflt_iface->sync(uldb_default->data)
#define default_forced_sync() dflt_iface->forced_sync(uldb_default->data)
#define default_get_login(a) dflt_iface->get_login(uldb_default->data, a)
#define default_new_user(a,b,c,d,e,f,g,h,i,j,k,l,m) dflt_iface->new_user(uldb_default->data, a, b, c, d, e, f, g, h, i, j, k, l, m)
#define default_remove_user(a) dflt_iface->remove_user(uldb_default->data, a)
#define default_get_cookie(a, b, c) dflt_iface->get_cookie(uldb_default->data, a, b, c)
#define default_new_cookie(a, b, c, d, e, f, g, h, i, j, k, l) dflt_iface->new_cookie(uldb_default->data, a, b, c, d, e, f, g, h, i, j, k, l)
#define default_remove_cookie(a) dflt_iface->remove_cookie(uldb_default->data, a)
#define default_remove_user_cookies(a) dflt_iface->remove_user_cookies(uldb_default->data, a)
#define default_remove_expired_cookies(a) dflt_iface->remove_expired_cookies(uldb_default->data, a)
#define default_get_user_contest_iterator(a) dflt_iface->get_user_contest_iterator(uldb_default->data, a)
#define default_remove_expired_users(a) dflt_iface->remove_expired_users(uldb_default->data, a)
#define default_get_user_info_1(a, b) dflt_iface->get_user_info_1(uldb_default->data, a, b)
#define default_get_user_info_2(a, b, c, d) dflt_iface->get_user_info_2(uldb_default->data, a, b, c, d)
#define default_touch_login_time(a, b, c) dflt_iface->touch_login_time(uldb_default->data, a, b, c)
#define default_get_user_info_3(a, b, c, d, e) dflt_iface->get_user_info_3(uldb_default->data, a, b, c, d, e)
#define default_set_cookie_contest(a, b) dflt_iface->set_cookie_contest(uldb_default->data, a, b)
#define default_set_cookie_locale(a, b) dflt_iface->set_cookie_locale(uldb_default->data, a, b)
#define default_set_cookie_priv_level(a, b) dflt_iface->set_cookie_priv_level(uldb_default->data, a, b)
#define default_set_cookie_team_login(a, b) dflt_iface->set_cookie_team_login(uldb_default->data, a, b)
#define default_get_user_info_4(a, b, c) dflt_iface->get_user_info_4(uldb_default->data, a, b, c)
#define default_get_user_info_5(a, b, c) dflt_iface->get_user_info_5(uldb_default->data, a, b, c)
#define default_get_brief_list_iterator(a) dflt_iface->get_brief_list_iterator(uldb_default->data, a)
#define default_get_standings_list_iterator(a) dflt_iface->get_standings_list_iterator(uldb_default->data, a)
#define default_check_user(a) dflt_iface->check_user(uldb_default->data, a)
#define default_set_reg_passwd(a, b, c, d) dflt_iface->set_reg_passwd(uldb_default->data, a, b, c, d)
#define default_set_team_passwd(a, b, c, d, e, f) dflt_iface->set_team_passwd(uldb_default->data, a, b, c, d, e, f)
#define default_register_contest(a, b, c, d, e, f) dflt_iface->register_contest(uldb_default->data, a, b, c, d, e, f)
#define default_remove_member(a, b, c, d, e) dflt_iface->remove_member(uldb_default->data, a, b, c, d, e)
#define default_is_read_only(a, b) dflt_iface->is_read_only(uldb_default->data, a, b)
#define default_get_info_list_iterator(a, b) dflt_iface->get_info_list_iterator(uldb_default->data, a, b)
#define default_clear_team_passwd(a, b, c) dflt_iface->clear_team_passwd(uldb_default->data, a, b, c)
#define default_remove_registration(a, b) dflt_iface->remove_registration(uldb_default->data, a, b)
#define default_set_reg_status(a, b, c) dflt_iface->set_reg_status(uldb_default->data, a, b, c)
#define default_set_reg_flags(a, b, c, d) dflt_iface->set_reg_flags(uldb_default->data, a, b, c, d)
#define default_remove_user_contest_info(a, b) dflt_iface->remove_user_contest_info(uldb_default->data, a, b)
#define default_clear_user_field(a, b, c) dflt_iface->clear_user_field(uldb_default->data, a, b, c)
#define default_clear_user_info_field(a, b, c, d, e) dflt_iface->clear_user_info_field(uldb_default->data, a, b, c, d, e)
#define default_clear_member_field(a, b, c, d, e, f) dflt_iface->clear_user_member_field(uldb_default->data, a, b, c, d, e, f)
#define default_set_user_field(a, b, c, d) dflt_iface->set_user_field(uldb_default->data, a, b, c, d)
#define default_set_user_info_field(a, b, c, d, e, f) dflt_iface->set_user_info_field(uldb_default->data, a, b, c, d, e, f)
#define default_set_user_member_field(a, b, c, d, e, f, g) dflt_iface->set_user_member_field(uldb_default->data, a, b, c, d, e, f, g)
#define default_new_member(a, b, c, d, e) dflt_iface->new_member(uldb_default->data, a, b, c, d, e)
#define default_set_user_xml(a, b, c, d, e) dflt_iface->set_user_xml(uldb_default->data, a, b, c, d, e)
#define default_copy_user_info(a, b, c, d, e, f) dflt_iface->copy_user_info(uldb_default->data, a, b, c, d, e, f)
#define default_check_user_reg_data(a, b) dflt_iface->check_user_reg_data(uldb_default->data, a, b)
#define default_move_member(a, b, c, d, e, f) dflt_iface->move_member(uldb_default->data, a, b, c, d, e, f)
#define default_get_user_info_6(a, b, c, d, e, f) dflt_iface->get_user_info_6(uldb_default->data, a, b, c, d, e, f)
#define default_get_user_info_7(a, b, c, d, e) dflt_iface->get_user_info_7(uldb_default->data, a, b, c, d, e)
#define default_unlock_user(a) dflt_iface->unlock_user(uldb_default->data, a)
#define default_get_contest_reg(a, b) dflt_iface->get_contest_reg(uldb_default->data, a, b)
#define default_try_new_login(a, b, c, d, e) dflt_iface->try_new_login(uldb_default->data, a, b, c, d, e)
#define default_set_simple_reg(a, b, c) dflt_iface->set_simple_reg(uldb_default->data, a, b, c)
#define default_get_brief_list_iterator_2(a, b, c, d, e, f, g, h, i, j) dflt_iface->get_brief_list_iterator_2(uldb_default->data, a, b, c, d, e, f, g, h, i, j)
#define default_get_user_count(a, b, c, d, e, f, g) dflt_iface->get_user_count(uldb_default->data, a, b, c, d, e, f, g)
#define default_get_group_iterator_2(a, b, c) dflt_iface->get_group_iterator_2(uldb_default->data, a, b, c)
#define default_get_group_count(a, b) dflt_iface->get_group_count(uldb_default->data, a, b)
#define default_new_cookie_2(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o) dflt_iface->new_cookie_2(uldb_default->data, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o)

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

static const unsigned char password_chars[] = "wy23456789abcdefghijkzmnxpqrstuv";

static void
generate_random_password(int size, unsigned char *buf)
{
  int aligned_size, rand_size, i, j;
  unsigned char *rnd_buf = 0;
  unsigned char *b64_buf = 0;
  unsigned char *p, *q;
  long long w;

  ASSERT(size > 0 && size <= 128);
  ASSERT(buf);

  // 5 bits per character, 8 characters require 40 bits
  // align up the size
  aligned_size = (size + 7) & ~7;
  b64_buf = alloca(aligned_size + 1);

  rand_size = aligned_size / 8 * 5;
  rnd_buf = alloca(rand_size);
  random_bytes(rnd_buf, rand_size);

  q = b64_buf;
  p = rnd_buf;
  for (i = 0; i < rand_size; i += 5) {
    w = *p++;
    for (j = 0; j < 4; ++j) {
      w <<= 8;
      w |= *p++;
    }
    for (j = 0; j < 8; ++j) {
      *q++ = password_chars[(unsigned) w & 31];
      w >>= 5;
    }
  }
  b64_buf[size] = 0;
  strcpy(buf, b64_buf);
}

/* build the map from the system uids to the local uids */
/* for removal
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
*/

/* remove the entry from the system uid->local uid map upon removal */
/* for removal
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
 */

static int
send_email_message(unsigned char const *to,
                   unsigned char const *from,
                   unsigned char const *charset,
                   unsigned char const *subject,
                   unsigned char const *text)
{
  FILE *f = 0;
  int r;
  unsigned char cmdline[1024];

  ASSERT(config->email_program);
  if (!charset) charset = EJUDGE_CHARSET;

  // sendmail mode
  if (strstr(config->email_program, "sendmail")) {
    // should we add -ba?
    snprintf(cmdline, sizeof(cmdline), "%s -B8BITMIME -t",
             config->email_program);
  } else {
    snprintf(cmdline, sizeof(cmdline), "%s", config->email_program);
  }

  if (!(f = popen(cmdline, "w"))) {
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
  struct observer_info *o, *oo;

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

  for (o = p->o_first; o; o = oo) {
    oo = o->clnt_next;
    remove_observer(o);
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
enqueue_reply_to_client_2(
        struct client_state *p,
        int msg_length,
        void *msg)
{
  ASSERT(p);
  ASSERT(msg_length > 0);
  ASSERT(msg);

  if (p->write_len) {
    SWERR(("Server->client reply slot is busy!"));
  }
  p->write_buf = msg;
  memcpy(p->write_buf, &msg_length, 4);
  p->write_len = msg_length + 4;
}

static void report_uptime(time_t t1, time_t t2);
static void cleanup_clients(void);
static void
graceful_exit(void)
{
  if (config && config->socket_path) {
    unlink(config->socket_path);
  }
  if (listen_socket >= 0) close(listen_socket);
  cleanup_clients();
  random_cleanup();
  dflt_iface->close(uldb_default->data);
  server_finish_time = time(0);
  report_uptime(server_start_time, server_finish_time);

  if (restart_signaled) start_restart();
  exit(0);
}
static void
interrupt_signal(int s)
{
  interrupt_signaled = 1;
}
static void
restart_signal(int s)
{
  interrupt_signaled = 1;
  restart_signaled = 1;
}
static void
usr1_signal(int s)
{
  usr1_signaled = 1;
}
static void
usr2_signal(int s)
{
  usr2_signaled = 1;
}
static void
winch_signal(int s)
{
  winch_signaled = 1;
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
get_global_uid_caps(const struct ejudge_cfg *cfg, int user_id, opcap_t *pcap)
{
  unsigned char *login_str = default_get_login(user_id);
  if (!login_str) return -1;
  int r = ejudge_cfg_opcaps_find(cfg, login_str, pcap);
  xfree(login_str);
  return r;
}

static int
is_admin(struct client_state *p, const unsigned char *pfx)
{
  if (p->user_id <= 0) {
    err("%s -> not authentificated", pfx);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  if (p->priv_level != PRIV_LEVEL_ADMIN) {
    err("%s -> invalid privilege level", pfx);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  return 0;
}

static int
is_judge(struct client_state *p, const unsigned char *pfx)
{
  if (p->user_id <= 0) {
    err("%s -> not authentificated", pfx);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  if (p->priv_level < PRIV_LEVEL_JUDGE) {
    err("%s -> invalid privilege level", pfx);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  return 0;
}

static int
is_judge_or_same_user(
        struct client_state *p,
        int user_id,
        int contest_id,
        const unsigned char *pfx)
{
  if (p->user_id <= 0) {
    err("%s -> not authentificated", pfx);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  if (p->user_id == user_id && contest_id > 0) return 0;
  if (p->priv_level < PRIV_LEVEL_JUDGE) {
    err("%s -> invalid privilege level", pfx);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }
  return 0;
}

static int
is_db_capable(struct client_state *p, int bit, const unsigned char *pfx)
{
  opcap_t caps;

  if (get_global_uid_caps(config, p->user_id, &caps) < 0) {
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
check_db_capable(struct client_state *p, int bit)
{
  opcap_t caps;

  if (get_global_uid_caps(config, p->user_id, &caps) < 0) return -1;
  if (opcaps_check(caps, bit) < 0) return -1;
  return 0;
}

static int
is_cnts_capable(struct client_state *p, const struct contest_desc *cnts,
                int bit, const unsigned char *pfx)
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
static int
check_cnts_capable(
        struct client_state *p,
        const struct contest_desc *cnts,
        int bit)
{
  opcap_t caps;

  if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) < 0) return -1;
  if (opcaps_check(caps, bit) < 0) return -1;
  return 0;
}
*/

static int
is_dbcnts_capable(
        struct client_state *p,
        const struct contest_desc *cnts,
        int bit,
        const unsigned char *pfx)
{
  opcap_t caps;

  // have general DB capability
  if (get_global_uid_caps(config, p->user_id, &caps) >= 0
      && opcaps_check(caps, bit) >= 0)
    return 0;

  if (!cnts) {
    if (pfx) {
      err("%s -> no capability %d", pfx, bit);
    } else {
      CONN_ERR("user %d has no capabilities for contest %d",
               p->user_id, cnts->id);
    }
    send_reply(p, -ULS_ERR_NO_PERMS);
    return -1;
  }

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

static int
check_dbcnts_capable(
        struct client_state *p,
        const struct contest_desc *cnts,
        int bit)
{
  opcap_t caps;

  // have general DB capability
  if (get_global_uid_caps(config, p->user_id, &caps) >= 0
      && opcaps_check(caps, bit) >= 0)
    return 0;

  // have the contest capability
  if (!cnts) return -1;
  if (get_uid_caps(&cnts->capabilities, p->user_id, &caps) < 0) return -1;
  if (opcaps_check(caps, bit) < 0) return -1;
  return 0;
}

static int
check_pk_map_contest(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch");
    return -1;
  }
  return 0;
}

static int
check_pk_edit_field(
        struct client_state *p,
        int pkt_len,
        const struct userlist_pk_edit_field *data)
{
  int value_len;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("bad packet length: %d instead of %d", pkt_len,(int)sizeof(*data));
    return -1;
  }
  value_len = strlen(data->data);
  if (value_len != data->value_len) {
    CONN_BAD("login_len mismatch %d instead of %d", value_len, data->value_len);
    return -1;
  }
  if (value_len + sizeof(*data) != pkt_len) {
    CONN_BAD("packet size mismatch: %d instead of %d", pkt_len,
             value_len + (int) sizeof(*data));
    return -1;
  }

  return 0;
}

static int
check_pk_delete_info(
        struct client_state *p,
        int pkt_len,
        const struct userlist_pk_delete_info *data)
{
  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d instead of %d",pkt_len,(int) sizeof(*data));
    return -1;
  }

  return 0;
}

static int
check_pk_register_contest(
        struct client_state *p,
        int pkt_len,
        const struct userlist_pk_register_contest *data)
{
  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d instead of %d",pkt_len,(int) sizeof(*data));
    return -1;
  }

  return 0;
}

static int
check_pk_set_password(
        struct client_state *p,
        int pkt_len,
        const struct userlist_pk_set_password *data)
{
  const char *old_pwd, *new_pwd, *admin_pwd;
  int old_len, new_len, admin_len, exp_len;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet too small: %d instead of %d",
             pkt_len, (int) sizeof(*data));
    return -1;
  }

  old_pwd = data->data;
  old_len = strlen(old_pwd);
  if (old_len != data->old_len) {
    CONN_BAD("old_len mismatch: %d instead of %d", data->old_len, old_len);
    return -1;
  }

  new_pwd = old_pwd + old_len + 1;
  new_len = strlen(new_pwd);
  if (new_len != data->new_len) {
    CONN_BAD("new_len mismatch: %d instead of %d", data->new_len, new_len);
    return -1;
  }

  admin_pwd = new_pwd + new_len + 1;
  admin_len = strlen(admin_pwd);
  if (admin_len != data->admin_len) {
    CONN_BAD("admin_len mismatch: %d instead of %d", data->admin_len, admin_len);
    return -1;
  }

  exp_len = sizeof(*data) + old_len + new_len + admin_len;
  if (pkt_len != exp_len) {
    CONN_BAD("pkt_len mismatch: %d instead of %d", pkt_len, exp_len);
    return -1;
  }

  return 0;
}

static int
check_pk_set_user_info(
        struct client_state *p,
        int pkt_len,
        const struct userlist_pk_set_user_info *data)
{
  int xml_len, exp_len;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet too small: %d instead of %d",
             pkt_len, (int) sizeof(*data));
    return -1;
  }
  xml_len = strlen(data->data);
  if (xml_len != data->info_len) {
    CONN_BAD("info_len mismatch: %d instead of %d", data->info_len, xml_len);
    return -1;
  }
  exp_len = sizeof(*data) + xml_len;
  if (pkt_len != exp_len) {
    CONN_BAD("pkt_len mismatch: %d instead of %d", pkt_len, exp_len);
    return -1;
  }

  return 0;
}

static int
check_pk_list_users_2(
        struct client_state *p,
        int pkt_len,
        const struct userlist_pk_list_users_2 *data)
{
  int filter_len, exp_len;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet too small: %d instead of %d",
             pkt_len, (int) sizeof(*data));
    return -1;
  }
  if (pkt_len > (128*1024*1024)) {
    CONN_BAD("packet too big: %d", pkt_len);
    return -1;
  }
  if (data->filter_len < 0 || data->filter_len > (128*1024*1024)) {
    CONN_BAD("filter_len is invalid: %d", data->filter_len);
    return -1;
  }
  filter_len = strlen(data->data);
  if (filter_len != data->filter_len) {
    CONN_BAD("filter_len mismatch: %d instead of %d",
             filter_len, data->filter_len);
    return -1;
  }
  exp_len = sizeof(*data) + filter_len;
  if (exp_len != pkt_len) {
    CONN_BAD("pkt_len mismatch: %d instead of %d", pkt_len, exp_len);
    return -1;
  }

  return 0;
}

static int
check_pk_create_user_2(
        struct client_state *p,
        int pkt_len,
        const struct userlist_pk_create_user_2 *data)
{
  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet too small: %d instead of %d", pkt_len, (int) sizeof(*data));
    return -1;
  }
  if (pkt_len > (128*1024*1024)) {
    CONN_BAD("packet too big: %d", pkt_len);
    return -1;
  }

  if (data->login_len < 0 || data->login_len > 65535) {
    CONN_BAD("login_len is invalid: %d", data->login_len);
    return -1;
  }
  if (data->email_len < 0 || data->email_len > 65535) {
    CONN_BAD("email_len is invalid: %d", data->email_len);
    return -1;
  }
  if (data->reg_password_len < 0 || data->reg_password_len > 65535) {
    CONN_BAD("reg_password_len is invalid: %d", data->reg_password_len);
    return -1;
  }
  if (data->cnts_password_len < 0 || data->cnts_password_len > 65535) {
    CONN_BAD("cnts_password_len is invalid: %d", data->cnts_password_len);
    return -1;
  }
  if (data->cnts_name_len < 0 || data->cnts_name_len > 65535) {
    CONN_BAD("cnts_name_len is invalid: %d", data->cnts_name_len);
    return -1;
  }
  int exp_len = sizeof(*data) + data->login_len + data->email_len + data->reg_password_len + data->cnts_password_len + data->cnts_name_len;
  if (exp_len != pkt_len) {
    CONN_BAD("pkt_len mismatch: %d instead of %d", pkt_len, exp_len);
    return -1;
  }

  const unsigned char *str = data->data;
  int len = strlen(str);
  if (len != data->login_len) {
    CONN_BAD("login_len mismatch: %d instead of %d", len, data->login_len);
    return -1;
  }
  str += len + 1;
  len = strlen(str);
  if (len != data->email_len) {
    CONN_BAD("email_len mismatch: %d instead of %d", len, data->email_len);
    return -1;
  }
  str += len + 1;
  len = strlen(str);
  if (len != data->reg_password_len) {
    CONN_BAD("reg_password_len mismatch: %d instead of %d", len, data->reg_password_len);
    return -1;
  }
  str += len + 1;
  len = strlen(str);
  if (len != data->cnts_password_len) {
    CONN_BAD("cnts_password_len mismatch: %d instead of %d", len, data->cnts_password_len);
    return -1;
  }
  str += len + 1;
  len = strlen(str);
  if (len != data->cnts_name_len) {
    CONN_BAD("cnts_name_len mismatch: %d instead of %d", len, data->cnts_name_len);
    return -1;
  }

  return 0;
}

static int
full_get_contest(
        struct client_state *p,
        const unsigned char *pfx,
        int *p_contest_id,
        const struct contest_desc **p_cnts)
{
  int errcode = 0;

  if (!*p_contest_id) {
    err("%s -> contest is not specified", pfx);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return -1;
  }
  if ((errcode = contests_get(*p_contest_id, p_cnts)) < 0 || !*p_cnts) {
    err("%s -> invalid contest: %s", pfx, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return -1;
  }
  if ((*p_cnts)->user_contest_num > 0) {
    *p_contest_id = (*p_cnts)->user_contest_num;
    if ((errcode = contests_get(*p_contest_id, p_cnts)) < 0 || !*p_cnts) {
      err("%s -> invalid user contest: %s", pfx, contests_strerror(-errcode));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return -1;
    }
    if ((*p_cnts)->user_contest_num > 0) {
      err("%s -> transitive contest sharing", pfx);
      send_reply(p, -ULS_ERR_TRANSITIVE_SHARING);
      return -1;
    }
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

  if (u->is_privileged) return 0;
  return ejudge_cfg_opcaps_find(config, u->login, &caps);
}

static int
is_privileged_cnts_user(
        const struct userlist_user *u,
        const struct contest_desc *cnts)
{
  opcap_t caps;

  if (u->is_privileged) return 0;
  if (cnts && opcaps_find(&cnts->capabilities, u->login, &caps) >= 0) return 0;
  return ejudge_cfg_opcaps_find(config, u->login, &caps);
}

static int
is_privileged_cnts2_user(
        const struct userlist_user *u,
        const struct contest_desc *cnts,
        const struct contest_desc *cnts2)
{
  opcap_t caps;

  if (u->is_privileged) return 0;
  if (cnts2 && opcaps_find(&cnts2->capabilities,u->login,&caps) >= 0) return 0;
  if (cnts && opcaps_find(&cnts->capabilities, u->login, &caps) >= 0) return 0;
  return ejudge_cfg_opcaps_find(config, u->login, &caps);
}

struct passwd_internal
{
  unsigned char pwd[128];
  unsigned char pwd_nows[128];
  unsigned char encoded[128];
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
  int i = 0, j = 0;
  if (!pwd_plain) return -1;
  snprintf(p->pwd, sizeof(p->pwd), "%s", pwd_plain);
  while (i + 1 < sizeof(p->pwd_nows) && pwd_plain[j]) {
    if (pwd_plain[j] > ' ') {
      p->pwd_nows[i++] = pwd_plain[j];
    }
    ++j;
  }
  p->pwd_nows[i] = 0;
  return 0;
}
static void
passwd_convert(
        struct passwd_internal *u,
        const unsigned char *raw,
        const unsigned char *passwd,
        int method)
{
  unsigned char saltbuf[16];

  if (method == USERLIST_PWD_PLAIN) {
    snprintf(u->encoded, sizeof(u->encoded), "%s", raw);
  } else if (method == USERLIST_PWD_SHA256) {
    int len = strlen(raw);
    ASSERT(len < sizeof(u->encoded));
    // first 4 chars (24 random bits uuencoded) is salt
    if (!passwd) {
      // make random new salt
      unsigned r = random_u32();
      char rr[4];
      rr[0] = r & 0xff;
      rr[1] = (r >> 8) & 0xff;
      rr[2] = (r >> 16) & 0xff;
      int i = base64_encode(rr, 3, saltbuf);
      saltbuf[i] = 0;
      passwd = saltbuf;
    }
    int plen = strlen(passwd);
    unsigned char buf[sizeof(u->encoded) * 2];
    if (plen >= 4) {
      buf[0] = passwd[0];
      buf[1] = passwd[1];
      buf[2] = passwd[2];
      buf[3] = passwd[3];
      u->encoded[0] = passwd[0];
      u->encoded[1] = passwd[1];
      u->encoded[2] = passwd[2];
      u->encoded[3] = passwd[3];
    } else {
      buf[0] = '$';
      buf[1] = '$';
      buf[2] = '$';
      buf[3] = '$';
      u->encoded[0] = '$';
      u->encoded[1] = '$';
      u->encoded[2] = '$';
      u->encoded[3] = '$';
    }
    strcpy(buf + 4, raw);
    sha256b64buf(u->encoded + 4, sizeof(u->encoded) - 4, buf, len + 4);
  } else if (method == USERLIST_PWD_SHA1) {
    int len = strlen(raw);
    make_sha1_ascii(raw, len, u->encoded);
  } else if (method == USERLIST_PWD_BASE64) {
    int len = strlen(raw);
    if (len > sizeof(u->encoded) / 2) {
      ASSERT(len < sizeof(u->encoded));
      unsigned char buf[sizeof(u->encoded) * 2];
      int outlen = base64_encode(raw, len, buf);
      buf[outlen] = 0;
      snprintf(u->encoded, sizeof(u->encoded), "%s", buf);
    } else {
      int outlen = base64_encode(raw, len, u->encoded);
      u->encoded[outlen] = 0;
    }
  } else {
    abort();
  }
}

static int
passwd_check(struct passwd_internal *u, const unsigned char *passwd, int method)
{
  if (!passwd) return -1;

  passwd_convert(u, u->pwd_nows, passwd, method);
  if (!strcmp(u->encoded, passwd)) return 0;
  passwd_convert(u, u->pwd, passwd, method);
  if (!strcmp(u->encoded, passwd)) return 0;
  return -1;
}

static unsigned char *
get_email_sender(const struct contest_desc *cnts)
{
  int sysuid;
  struct passwd *ppwd;

  if (cnts && cnts->register_email) return cnts->register_email;
  if (config && config->register_email) return config->register_email;
  sysuid = getuid();
  ppwd = getpwuid(sysuid);
  return ppwd->pw_name;
}

static int
send_registration_email(
        const struct contest_desc *cnts,
        const struct userlist_user *u,
        int locale_id,
        const unsigned char *self_url,
        int confirm_action)
{
  struct sformat_extra_data sformat_data;
  path_t email_template_path;
  path_t email_template_locale_0_path;
  char *email_template = 0;
  size_t email_template_size = 0;

  memset(&sformat_data, 0, sizeof(sformat_data));
  sformat_data.locale_id = locale_id;
  sformat_data.server_name = config->server_name;
  sformat_data.server_name_en = config->server_name_en;

  // load the registration letter template file
  if (cnts && cnts->register_email_file) {
    sformat_message(email_template_path, sizeof(email_template_path), 0,
                    cnts->register_email_file, 0, 0, 0, 0, 0,
                    u, cnts, &sformat_data);
    if (generic_read_file(&email_template, 0, &email_template_size, 0, "", email_template_path, "") < 0) {
      // the template file for the given locale_id does not exist, so try locale_id = 0
      sformat_data.locale_id = 0;
      sformat_message(email_template_locale_0_path, sizeof(email_template_locale_0_path), 0,
                      cnts->register_email_file, 0, 0, 0, 0, 0,
                      u, cnts, &sformat_data);
      if (strcmp(email_template_path, email_template_locale_0_path) != 0) {
        strcpy(email_template_path, email_template_locale_0_path);
        if (generic_read_file(&email_template, 0, &email_template_size, 0, "", email_template_path, "") < 0) {
          email_template = 0;
          email_template_size = 0;
        }
      } else {
        email_template = 0;
        email_template_size = 0;
      }
    }
  }
  sformat_data.locale_id = locale_id;

  // sanity checks
  if (email_template_size > 1 * 1024 * 1024) {
    xfree(email_template); email_template = 0;
    email_template_size = 0;
  }
  if (email_template && strlen(email_template) != email_template_size) {
    xfree(email_template); email_template = 0;
    email_template_size = 0;
  }
  if (email_template && is_empty_string(email_template)) {
    xfree(email_template); email_template = 0;
    email_template_size = 0;
  }

  unsigned char contest_id_str[64] = { 0 };
  if (cnts) {
    snprintf(contest_id_str, sizeof(contest_id_str), "&contest_id=%d", cnts->id);
  }
  unsigned char locale_id_str[64] = { 0 };
  if (locale_id > 0) {
    snprintf(locale_id_str, sizeof(locale_id_str), "&locale_id=%d", locale_id);
  }
  const unsigned char *base_url = 0;
  if (self_url && *self_url) {
    base_url = self_url;
  } else if (cnts && cnts->register_url) {
    base_url = cnts->register_url;
  } else if (config->register_url) {
    base_url = config->register_url;
  } else {
    base_url = "http://localhost/cgi-bin/register";
  }
  if (confirm_action <= 0 && cnts && cnts->force_registration) confirm_action = 4;
  if (confirm_action <= 0) confirm_action = 3;
  unsigned char confirm_url_buf[1024];
  snprintf(confirm_url_buf, sizeof(confirm_url_buf), "%s?action=%d&login=%s%s%s",
           base_url, confirm_action, u->login, contest_id_str, locale_id_str);
  sformat_data.url = confirm_url_buf;

  unsigned char contest_main_url[1024] = { 0 };
  if (cnts && cnts->main_url) {
    snprintf(contest_main_url, sizeof(contest_main_url), " (%s)", cnts->main_url);
  } else if (config->server_main_url) {
    snprintf(contest_main_url, sizeof(contest_main_url), " (%s)", config->server_main_url);
  }
  sformat_data.str1 = contest_main_url;

  l10n_setlocale(locale_id);
  if (!email_template && cnts) {
    email_template =
      _("Hello,\n"
        "\n"
        "Somebody (probably you) have specified this e-mail address (%Ue)\n"
        "when registering an account to participate in \"%Cn\"%V1.\n"
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
    email_template = xstrdup(email_template);
    email_template_size = strlen(email_template);
  }
  if (!email_template) {
    email_template =
      _("Hello,\n"
        "\n"
        "Somebody (probably you) have specified this e-mail address (%Ue)\n"
        "when registering an account on the %Vn%V1.\n"
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
    email_template = xstrdup(email_template);
    email_template_size = strlen(email_template);
  }

  unsigned char *email_subject = NULL;

  if (cnts) {
    if (locale_id == 1) {
      // russian
      if (cnts->register_subject) {
        email_subject = cnts->register_subject;
      } else if (cnts->register_subject_en) {
        email_subject = cnts->register_subject_en;
      }
    } else {
      // default - english
      if (cnts->register_subject_en) {
        email_subject = cnts->register_subject_en;
      } else if (cnts->register_subject) {
        email_subject = cnts->register_subject;
      }
    }
  }

  size_t email_text_size = email_template_size * 4;
  if (email_text_size < 4096) email_text_size = 4096;
  unsigned char *email_text = (unsigned char *) xcalloc(email_text_size, 1);
  sformat_message(email_text, email_text_size, 0, email_template,
                  0, 0, 0, 0, 0, u, cnts, &sformat_data);
  if (email_subject == NULL) {
    email_subject = _("You have been registered");
  }
  l10n_resetlocale();

  const unsigned char *sender_address = get_email_sender(cnts);
  int retval = send_email_message(u->email, sender_address, NULL, email_subject, email_text);
  xfree(email_text); email_text = 0;
  xfree(email_template); email_template = 0;

  return retval;
}

static void
cmd_register_new_2(struct client_state *p,
                   int pkt_len,
                   struct userlist_pk_register_new * data)
{
  unsigned char * login;
  unsigned char * email;
  unsigned char * self_url;
  int login_len, email_len, self_url_len, errcode, exp_pkt_len;
  unsigned char passwd_buf[64];
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  struct userlist_pk_new_password *out = 0;
  size_t out_size = 0, passwd_len;
  time_t current_time = time(0);
  int user_id, serial = 0, action = 3, serial_step = 1, n;
  const struct userlist_user *u;
  unsigned char login_buf[1024];

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
  self_url = email + email_len + 1;
  self_url_len = strlen(self_url);
  if (self_url_len != data->self_url_length) {
    CONN_BAD("email length mismatch: %d, %d",
             self_url_len, data->self_url_length);
    return;
  }
  exp_pkt_len = sizeof(*data) + login_len + email_len + self_url_len;
  if (pkt_len != exp_pkt_len) {
    CONN_BAD("packet length mismatch: %d, %d", pkt_len, exp_pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "NEW_USER_2: %s, %s, %s, %d",
           xml_unparse_ipv6(&data->origin_ip), login, email, data->contest_id);

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
  if (!contests_check_register_ip_2(cnts, &data->origin_ip, data->ssl)) {
    err("%s -> rejected IP", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }

  if (cnts->assign_logins && cnts->login_template) {
    if (cnts->login_template_options
        && sscanf(cnts->login_template_options, "%d%d%n",
                  &serial, &serial_step, &n) == 2
        && !cnts->login_template_options[n] && serial_step != 0) {
      serial -= serial_step;
    } else {
      serial = 0;
      serial_step = 1;
    }
    if (dflt_iface->try_new_login) {
      serial += serial_step;
      if (default_try_new_login(login_buf, sizeof(login_buf), cnts->login_template, serial, serial_step) < 0) {
        send_reply(p, -ULS_ERR_DB_ERROR);
        err("%s -> database error", logbuf);
        return;
      }
    } else {
      while (1) {
        serial += serial_step;
        snprintf(login_buf, sizeof(login_buf), cnts->login_template, serial);
        if ((user_id = default_get_user_by_login(login_buf)) < 0) break;
      }
    }
    login = login_buf;
  } else if (!login || !*login) {
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    err("%s -> empty login", logbuf);
    return;
  }

  user_id = default_get_user_by_login(login);
  if (user_id >= 0) {
    send_reply(p, -ULS_ERR_LOGIN_USED);
    err("%s -> login already exists", logbuf);
    return;
  }

  generate_random_password(8, passwd_buf);
  passwd_len = strlen(passwd_buf);
  user_id = default_new_user(login, email, USERLIST_PWD_PLAIN, passwd_buf, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  if (user_id <= 0) {
    send_reply(p, -ULS_ERR_DB_ERROR);
    err("%s -> database error", logbuf);
    return;
  }

  login_len = strlen(login);
  out_size = sizeof(*out) + login_len + passwd_len;
  out = (struct userlist_pk_new_password*) alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_PASSWORD;
  out->user_id = user_id;
  out->login_len = login_len;
  out->passwd_len = passwd_len;
  memcpy(out->data, login, login_len + 1);
  memcpy(out->data + login_len + 2, passwd_buf, passwd_len + 1);
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

    if (default_get_user_info_1(user_id, &u) < 0 || !u) {
      send_reply(p, -ULS_ERR_DB_ERROR);
      err("%s -> database error", logbuf);
      return;
    }

    // prepare the file path for the email template
    memset(&sformat_data, 0, sizeof(sformat_data));
    sformat_data.locale_id = data->locale_id;
    sformat_data.url = urlbuf;
    if (cnts->register_email_file) {
      sformat_message(email_tmpl_path, sizeof(email_tmpl_path), 0,
                      cnts->register_email_file,
                      0, 0, 0, 0, 0, u, cnts, &sformat_data);
      if (generic_read_file(&email_tmpl, 0, &email_tmpl_size, 0,
                            "", email_tmpl_path, "") < 0) {
        sformat_data.locale_id = 0;
        sformat_message(email_tmpl_path2, sizeof(email_tmpl_path2), 0,
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
    if (self_url && *self_url) {
      url_str = self_url;
    } else if (cnts && cnts->register_url) {
      url_str = cnts->register_url;
    } else if (config->register_url) {
      url_str = config->register_url;
    } else {
      url_str = "http://localhost/cgi-bin/register";
    }
    if (data->action > 0) {
      action = data->action;
    } else if (cnts->force_registration) {
      action = 4;
    }
    snprintf(urlbuf, sizeof(urlbuf), "%s?action=%d&login=%s%s%s",
             url_str, action, login, contest_str, locale_str);

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
          "to participate in contest \"%Cn\"%V1\n"
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
    sformat_message(buf, buf_size, 0, email_tmpl,
                    0, 0, 0, 0, 0, u, cnts, &sformat_data);

    unsigned char *register_subject = NULL;

    if (data->locale_id == 1) {
      // russian
      if (cnts->register_subject) {
        register_subject = cnts->register_subject;
      } else if (cnts->register_subject_en) {
        register_subject = cnts->register_subject_en;
      }
    } else {
      // default - english
      if (cnts->register_subject_en) {
        register_subject = cnts->register_subject_en;
      } else if (cnts->register_subject) {
        register_subject = cnts->register_subject;
      }
    }

    if (register_subject == NULL) {
      register_subject = _("You have been registered");
    }

    mail_args[0] = "mail";
    mail_args[1] = "";
    mail_args[2] = register_subject;
    mail_args[3] = originator_email;
    mail_args[4] = email;
    mail_args[5] = buf;
    mail_args[6] = 0;
    send_job_packet(config, mail_args);

    xfree(buf);
    xfree(email_tmpl);

    l10n_resetlocale();
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
  const struct contest_desc *cnts = 0;
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
  int user_id, serial = 0, action = 3, serial_step = 1, n;
  unsigned char login_buf[1024];
  unsigned char *self_url = 0;
  int self_url_len;

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
  self_url = email + data->email_length + 1;
  self_url_len = strlen(self_url);
  if (self_url_len != data->self_url_length) {
    CONN_BAD("self_url length mismatch: %d, %d", self_url_len,
             data->self_url_length);
    return;
  }
  exp_pkt_len = sizeof(*data) + login_len + email_len + self_url_len;
  if (pkt_len != exp_pkt_len) {
    CONN_BAD("packet length mismatch: %d, %d", pkt_len, exp_pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "NEW_USER: %s, %s, %s, %d",
           xml_unparse_ipv6(&data->origin_ip), login, email, data->contest_id);

  if (data->contest_id != 0) {
    if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
      err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
  }
  originator_email = get_email_sender(cnts);

  if (cnts && cnts->assign_logins && cnts->login_template) {
    if (cnts->login_template_options
        && sscanf(cnts->login_template_options, "%d%d%n",
                  &serial, &serial_step, &n) == 2
        && !cnts->login_template_options[n] && serial_step != 0) {
      serial -= serial_step;
    } else {
      serial = 0;
      serial_step = 1;
    }
    if (dflt_iface->try_new_login) {
      serial += serial_step;
      if (default_try_new_login(login_buf, sizeof(login_buf), cnts->login_template, serial, serial_step) < 0) {
        send_reply(p, -ULS_ERR_DB_ERROR);
        err("%s -> database error", logbuf);
        return;
      }
    } else {
      while (1) {
        serial += serial_step;
        snprintf(login_buf, sizeof(login_buf), cnts->login_template, serial);
        if ((user_id = default_get_user_by_login(login_buf)) < 0) break;
      }
    }
    login = login_buf;
  }

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
  if (self_url[0]) {
    url_str = self_url;
  } else if (cnts && cnts->register_url) {
    url_str = cnts->register_url;
  } else if (config->register_url) {
    url_str = config->register_url;
  } else {
    url_str = "http://localhost/cgi-bin/register";
  }
  if (cnts && cnts->force_registration) action = 4;
  if (data->action > 0) action = data->action;
  snprintf(urlbuf, sizeof(urlbuf), "%s?action=%d&login=%s%s%s",
           url_str, action, login, contest_str, locale_str);

  user_id = default_get_user_by_login(login);
  if (user_id >= 0) {
    send_reply(p, -ULS_ERR_LOGIN_USED);
    err("%s -> login already exists", logbuf);
    return;
  }

  generate_random_password(8, passwd_buf);
  user_id = default_new_user(login, email, USERLIST_PWD_PLAIN, passwd_buf, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  if (user_id <= 0) {
    send_reply(p, -ULS_ERR_DB_ERROR);
    err("%s -> database error", logbuf);
    return;
  }
  if (default_get_user_info_1(user_id, &u) < 0 || !u) {
    send_reply(p, -ULS_ERR_DB_ERROR);
    err("%s -> database error", logbuf);
    return;
  }

  // prepare the file path for the email template
  memset(&sformat_data, 0, sizeof(sformat_data));
  sformat_data.locale_id = data->locale_id;
  sformat_data.url = urlbuf;
  sformat_data.server_name = config->server_name;
  sformat_data.server_name_en = config->server_name_en;
  sformat_data.str1 = contest_url;

  if (cnts && cnts->register_email_file) {
    sformat_message(email_tmpl_path, sizeof(email_tmpl_path), 0,
                    cnts->register_email_file,
                    0, 0, 0, 0, 0, u, cnts, &sformat_data);
    if (generic_read_file(&email_tmpl, 0, &email_tmpl_size, 0,
                          "", email_tmpl_path, "") < 0) {
      sformat_data.locale_id = 0;
      sformat_message(email_tmpl_path2, sizeof(email_tmpl_path2), 0,
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
          "when registering an account to participate in \"%Cn\"%V1.\n"
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
          "when registering an account on the %Vn%V1.\n"
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
  sformat_message(buf, buf_size, 0, email_tmpl,
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
    l10n_resetlocale();
    send_reply(p, -ULS_ERR_EMAIL_FAILED);
    info("%s -> failed (e-mail)", logbuf);
    return;
  }

  xfree(buf);
  xfree(email_tmpl);
  l10n_resetlocale();
  send_reply(p,ULS_OK);
  info("%s -> ok, %d", logbuf, u->id);
}

static void
cmd_recover_password_1(struct client_state *p,
                       int pkt_len,
                       struct userlist_pk_register_new *data)
{
  unsigned char *login, *email, *originator_email, *self_url;
  int login_len, email_len, exp_pkt_len, errcode, user_id, self_url_len;
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  const struct userlist_user_info *ui = 0;
  const struct userlist_contest *c = 0;
  const struct contest_desc *cnts = 0;
  const struct userlist_cookie *cookie = 0;
  opcap_t caps;
  FILE *msg_f = 0;
  char *msg_text = 0;
  size_t msg_size = 0;
  unsigned char *mail_args[7];

  login = data->data;
  login_len = strlen(login);
  if (login_len != data->login_length) {
    CONN_BAD("login length mismatch: %d, %d", login_len, data->login_length);
    return;
  }
  email = login + data->login_length + 1;
  email_len = strlen(email);
  if (email_len != data->email_length) {
    CONN_BAD("email length mismatch: %d, %d", email_len, data->email_length);
    return;
  }
  self_url = email + email_len + 1;
  self_url_len = strlen(self_url);
  if (self_url_len != data->self_url_length) {
    CONN_BAD("self_url length mismatch: %d, %d", self_url_len,
             data->self_url_length);
    return;
  }
  exp_pkt_len = sizeof(*data) + login_len + email_len + self_url_len;
  if (pkt_len != exp_pkt_len) {
    CONN_BAD("packet length mismatch: %d, %d", pkt_len, exp_pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "RECOVER_1: %s, %s, %s, %d",
           xml_unparse_ipv6(&data->origin_ip), login, email, data->contest_id);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  originator_email = get_email_sender(cnts);

  if (!cnts->enable_password_recovery
      || (cnts->simple_registration && !cnts->send_passwd_email)) {
    err("%s -> password recovery disabled", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if ((user_id = default_get_user_by_login(login)) <= 0) {
    err("%s -> no such login", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (default_get_user_info_3(user_id,data->contest_id,&u,&ui,&c) < 0 || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  if (u->simple_registration && !c && cnts->disable_team_password
      && cnts->autoregister) {
    if (cnts->closed) {
      err("%s -> contest closed", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  } else {
    /*
    if (!c) {
      err("%s -> not registered", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    */
    if (c && (c->status != USERLIST_REG_OK || c->flags != 0)) {
      err("%s -> not ordinary user", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  }
  if (!u || !u->email || !strchr(u->email, '@')) {
    err("%s -> invalid e-mail", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (strcasecmp(email, u->email) != 0) {
    err("%s -> e-mails do not match", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (opcaps_find(&cnts->capabilities, login, &caps) >= 0
      || ejudge_cfg_opcaps_find(config, login, &caps) >= 0) {
    err("%s -> privileged user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  // generate new cookie for password recovery
  if (default_new_cookie(u->id, &data->origin_ip, data->ssl, 0, 0,
                         data->contest_id, data->locale_id,
                         PRIV_LEVEL_USER, 0, 1, 0, &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  msg_f = open_memstream(&msg_text, &msg_size);
  fprintf(msg_f,
          _("Hello,\n"
            "\n"
            "Somebody (probably you) have requested registration password\n"
            "regeneration for login `%s'.\n\n"),
          login);
  fprintf(msg_f,
          _("To confirm password regeneration, you should visit the following URL:\n"
            "%s?contest_id=%d&locale_id=%d&SID=%016llx&action=%d.\n"
            "\n"),
          self_url, data->contest_id, data->locale_id, cookie->cookie,
          data->action);
  fprintf(msg_f,
          _("Note, that if you do not do this in 24 hours from the moment\n"
            "of sending this letter, operation will be cancelled.\n"
            "\n"
            "If you don't want to regenerate the password, just ignore this\n"
            "message\n\n"));
  fprintf(msg_f,
          _("Regards,\n"
            "The ejudge contest administration system (www.ejudge.ru)\n"));
  close_memstream(msg_f); msg_f = 0;

  if (send_email_message(u->email,
                         originator_email,
                         NULL,
                         _("Password regeneration requested"),
                         msg_text) < 0) {
    send_reply(p, -ULS_ERR_EMAIL_FAILED);
    info("%s -> failed (e-mail)", logbuf);
    xfree(msg_text);
    return;
  }
  xfree(msg_text); msg_text = 0; msg_size = 0;

  if (cnts->daily_stat_email) {
    msg_f = open_memstream(&msg_text, &msg_size);
    fprintf(msg_f,
            _("Hello,\n"
              "\n"
              "User `%s' (email %s) has initiated password regeneration\n"
              "in contest %d from IP %s\n\n"),
            login, email, data->contest_id,
            xml_unparse_ipv6(&data->origin_ip));
    fprintf(msg_f,
            _("Regards,\n"
              "The ejudge contest administration system (www.ejudge.ru)\n"));
    close_memstream(msg_f); msg_f = 0;

    mail_args[0] = "mail";
    mail_args[1] = "";
    mail_args[2] = _("Password regeneration requested");
    mail_args[3] = originator_email;
    mail_args[4] = cnts->daily_stat_email;
    mail_args[5] = msg_text;
    mail_args[6] = 0;
    send_job_packet(config, mail_args);
    xfree(msg_text); msg_text = 0;
  }

  send_reply(p, ULS_OK);
  info("%s -> ok", logbuf);
}

static void
cmd_recover_password_2(struct client_state *p,
                       int pkt_len,
                       struct userlist_pk_check_cookie *data)
{
  unsigned char logbuf[1024], passwd_buf[64];
  const struct userlist_cookie *cookie = 0;
  struct userlist_pk_new_password *out = 0;
  const struct contest_desc *cnts = 0;
  const struct userlist_user *u = 0;
  const struct userlist_user_info *ui = 0;
  const struct userlist_contest *c = 0;
  int errcode = 0;
  unsigned char *originator_email = 0;
  opcap_t caps;
  FILE *msg_f = 0;
  char *msg_text = 0;
  size_t msg_size = 0;
  unsigned char *mail_args[7];
  int login_len, name_len, passwd_len, packet_len;
  unsigned char *s;
  unsigned char *name = 0;
  int user_id = 0, regstatus = -1;
  unsigned char *login = 0;
  unsigned char *email = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "RECOVER_2: %d, %llx", data->contest_id, data->cookie);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  originator_email = get_email_sender(cnts);
  if (!cnts->enable_password_recovery
      || (cnts->simple_registration && !cnts->send_passwd_email)) {
    err("%s -> password recovery disabled", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (default_get_cookie(data->cookie, 0, &cookie) < 0 || !cookie) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (!cookie->recovery) {
    err("%s -> not a recovery cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (cookie->contest_id != data->contest_id) {
    err("%s -> contest_id mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (default_get_user_info_3(cookie->user_id,data->contest_id,&u,&ui,&c)<0
      || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  if (ui && ui->name) name = xstrdup(ui->name);
  if (!name || !*name) name = xstrdup(u->login);
  if (!name) name = xstrdup("");

  if (u->simple_registration && !c && cnts->disable_team_password
      && cnts->autoregister) {
    if (cnts->closed) {
      err("%s -> contest closed", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  } else {
    /*
    if (!c) {
      err("%s -> not registered", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    */
    if (c && (c->status != USERLIST_REG_OK || c->flags != 0)) {
      err("%s -> not ordinary user", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    if (c) regstatus = c->status;
  }
  if (!u || !u->email || !strchr(u->email, '@')) {
    err("%s -> invalid e-mail", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (opcaps_find(&cnts->capabilities, u->login, &caps) >= 0
      || ejudge_cfg_opcaps_find(config, u->login, &caps) >= 0) {
    err("%s -> privileged user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  user_id = u->id;
  login = xstrdup(u->login);
  email = xstrdup(u->email);

  // generate new password
  generate_random_password(8, passwd_buf);
  default_remove_user_cookies(user_id);
  default_set_reg_passwd(user_id, USERLIST_PWD_PLAIN, passwd_buf, cur_time);
  default_set_simple_reg(user_id, 0, cur_time);

  // generate a e-mail message
  msg_f = open_memstream(&msg_text, &msg_size);
  fprintf(msg_f,
          _("Hello,\n"
            "\n"
            "New random password was successfully generated!\n\n"));
  fprintf(msg_f,
          "User Id:  %d\n"
          "Login:    %s\n"
          "E-mail:   %s\n"
          "Name:     %s\n"
          "Password: %s\n\n",
          user_id, login, email, name, passwd_buf);
  fprintf(msg_f,
          _("Regards,\n"
            "The ejudge contest administration system (www.ejudge.ru)\n"));
  close_memstream(msg_f); msg_f = 0;

  if (send_email_message(email,
                         originator_email,
                         NULL,
                         _("Password regeneration successful"),
                         msg_text) < 0) {
    send_reply(p, -ULS_ERR_EMAIL_FAILED);
    info("%s -> failed (e-mail)", logbuf);
    xfree(msg_text);
    // FIXME: free all allocated strings
    return;
  }
  xfree(msg_text); msg_text = 0; msg_size = 0;

  if (cnts->daily_stat_email) {
    msg_f = open_memstream(&msg_text, &msg_size);
    fprintf(msg_f,
            _("Hello,\n"
              "\n"
              "User `%s' (email %s) completed password regeneration\n"
              "in contest %d from IP %s\n\n"),
            login, email, data->contest_id,
            xml_unparse_ipv6(&data->origin_ip));
    fprintf(msg_f,
            _("Regards,\n"
              "The ejudge contest administration system (www.ejudge.ru)\n"));
    close_memstream(msg_f); msg_f = 0;

    mail_args[0] = "mail";
    mail_args[1] = "";
    mail_args[2] = _("Password regeneration successful");
    mail_args[3] = originator_email;
    mail_args[4] = cnts->daily_stat_email;
    mail_args[5] = msg_text;
    mail_args[6] = 0;
    send_job_packet(config, mail_args);
    xfree(msg_text); msg_text = 0;
  }

  login_len = strlen(login);
  name_len = strlen(name);
  passwd_len = strlen(passwd_buf);
  packet_len = sizeof(*out);
  packet_len += login_len + name_len + passwd_len;
  out = (struct userlist_pk_new_password*) alloca(packet_len);
  memset(out, 0, packet_len);
  s = out->data;
  out->reply_id = ULS_NEW_PASSWORD;
  out->user_id = user_id;
  out->regstatus = regstatus;
  out->login_len = login_len;
  out->name_len = name_len;
  out->passwd_len = passwd_len;
  strcpy(s, login); s += login_len + 1;
  strcpy(s, name); s += name_len + 1;
  strcpy(s, passwd_buf);
  enqueue_reply_to_client(p, packet_len, out);
  info("%s -> OK", logbuf);
  xfree(login);
  xfree(email);
  xfree(name);
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

  //remove_from_system_uid_map(u->id);
  default_remove_user(u->id);
}

static void
cmd_login(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_login * data)
{
  const struct userlist_user *u = 0;
  struct userlist_pk_login_ok * answer;
  int ans_len, act_pkt_len;
  char * login;
  char * password;
  char * name_ptr;
  const struct userlist_cookie * cookie;
  struct passwd_internal pwdint;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;
  int user_id, orig_contest_id;
  const struct contest_desc *cnts = 0;
  const unsigned char *name = 0;
  unsigned char cbuf[64];

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
           xml_unparse_ipv6(&data->origin_ip), data->ssl, login);

  if (p->user_id > 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  orig_contest_id = data->contest_id;
  if (data->contest_id) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
    if (cnts->closed) {
      err("%s -> contest is closed", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    if (!contests_check_register_ip(orig_contest_id, &data->origin_ip, data->ssl)) {
      err("%s -> IP is not allowed", logbuf);
      send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
      return;
    }
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
  if (default_get_user_info_2(user_id, data->contest_id, &u, &ui) < 0 || !u) {
    send_reply(p, -ULS_ERR_DB_ERROR);
    err("%s -> database error", logbuf);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }
  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

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
    + strlen(name) + strlen(u->login);
  answer = alloca(ans_len);
  memset(answer, 0, ans_len);

  if (default_new_cookie_2(u->id, &data->origin_ip, data->ssl, 0,
                           data->client_key,
                           0, orig_contest_id, data->locale_id, PRIV_LEVEL_USER,
                           0, 0, 0,
                           0, /* is_ws */
                           0, /* is_job */
                           &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  answer->reply_id = ULS_LOGIN_COOKIE;
  answer->cookie = cookie->cookie;
  answer->client_key = cookie->client_key;
  answer->user_id = u->id;
  answer->contest_id = orig_contest_id;
  answer->passwd_method = u->passwd_method;
  answer->login_len = strlen(u->login);
  name_ptr = answer->data + answer->login_len + 1;
  answer->name_len = strlen(name);
  strcpy(answer->data, u->login);
  strcpy(name_ptr, name);
  enqueue_reply_to_client(p,ans_len,answer);

  default_touch_login_time(user_id, 0, cur_time);
  p->user_id = user_id;
  p->contest_id = orig_contest_id;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  p->cookie = answer->cookie;
  p->client_key = answer->client_key;
  info("%s -> OK, %d, %s", logbuf, user_id,
       xml_unparse_full_cookie(cbuf, sizeof(cbuf), &answer->cookie, &answer->client_key));
}

static void
cmd_check_user(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_login *data)
{
  const struct userlist_user *u = 0;
  struct userlist_pk_login_ok * answer;
  int ans_len, act_pkt_len;
  char * login;
  char * password;
  char * name_ptr;
  const struct userlist_cookie * cookie;
  struct passwd_internal pwdint;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;
  int user_id, orig_contest_id;
  const struct contest_desc *cnts = 0;
  const unsigned char *name = 0;
  unsigned char cbuf[64];

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

  snprintf(logbuf, sizeof(logbuf), "CHECK_USER: %s, %d, %s",
           xml_unparse_ipv6(&data->origin_ip), data->ssl, login);

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf) < 0) return;

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
  if (default_get_user_info_2(user_id, data->contest_id, &u, &ui) < 0 || !u) {
    send_reply(p, -ULS_ERR_DB_ERROR);
    err("%s -> database error", logbuf);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }
  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  orig_contest_id = data->contest_id;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  if (cnts->closed) {
    err("%s -> contest is closed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (!contests_check_register_ip(orig_contest_id, &data->origin_ip, data->ssl)) {
    err("%s -> IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
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
  if (u->simple_registration && !cnts->simple_registration) {
    err("%s -> user is simple_registered, but the contest is not", logbuf);
    send_reply(p, -ULS_ERR_SIMPLE_REGISTERED);
    return;
  }

  //Login and password correct
  ans_len = sizeof(struct userlist_pk_login_ok)
    + strlen(name) + strlen(u->login);
  answer = alloca(ans_len);
  memset(answer, 0, ans_len);

  if (default_new_cookie_2(u->id, &data->origin_ip, data->ssl, 0, data->client_key, 0,
                           orig_contest_id, data->locale_id, PRIV_LEVEL_USER, 0,
                           0, 0,
                           0, /* is_ws */
                           0, /* is_job */
                           &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  answer->reply_id = ULS_LOGIN_COOKIE;
  answer->cookie = cookie->cookie;
  answer->client_key = cookie->client_key;
  answer->user_id = u->id;
  answer->contest_id = orig_contest_id;
  answer->passwd_method = u->passwd_method;
  answer->login_len = strlen(u->login);
  name_ptr = answer->data + answer->login_len + 1;
  answer->name_len = strlen(name);
  strcpy(answer->data, u->login);
  strcpy(name_ptr, name);
  enqueue_reply_to_client(p,ans_len,answer);

  default_touch_login_time(user_id, 0, cur_time);
  info("%s -> OK, %d, %s", logbuf, user_id,
       xml_unparse_full_cookie(cbuf, sizeof(cbuf), &answer->cookie, &answer->client_key));
}

static void
cmd_check_user_2(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_login *data)
{
  const struct userlist_user *u = 0;
  struct userlist_pk_login_ok * answer;
  int ans_len, act_pkt_len;
  char * login;
  char * password;
  char * name_ptr;
  const struct userlist_cookie * cookie;
  struct passwd_internal pwdint;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui = NULL;
  int user_id;
  const unsigned char *name = 0;
  unsigned char cbuf[64];

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

  snprintf(logbuf, sizeof(logbuf), "CHECK_USER_2: %s, %d, %s",
           xml_unparse_ipv6(&data->origin_ip), data->ssl, login);

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf) < 0) return;

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
  if (default_get_user_info_2(user_id, 0, &u, &ui) < 0 || !u) {
    send_reply(p, -ULS_ERR_DB_ERROR);
    err("%s -> database error", logbuf);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }
  if (!name || !*name) name = u->login;
  if (!name) name = "";

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
  ans_len = sizeof(struct userlist_pk_login_ok) + strlen(name) + strlen(u->login);
  answer = alloca(ans_len);
  memset(answer, 0, ans_len);

  if (default_new_cookie_2(u->id, &data->origin_ip, data->ssl, 0, data->client_key, 0,
                           0, data->locale_id, PRIV_LEVEL_USER, 0,
                           0, 0,
                           0, /* is_ws */
                           0, /* is_job */
                           &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  answer->reply_id = ULS_LOGIN_COOKIE;
  answer->cookie = cookie->cookie;
  answer->client_key = cookie->client_key;
  answer->user_id = u->id;
  answer->contest_id = 0;
  answer->expire = cookie->expire;
  answer->passwd_method = u->passwd_method;
  answer->login_len = strlen(u->login);
  name_ptr = answer->data + answer->login_len + 1;
  answer->name_len = strlen(name);
  strcpy(answer->data, u->login);
  strcpy(name_ptr, name);
  enqueue_reply_to_client(p,ans_len,answer);

  default_touch_login_time(user_id, 0, cur_time);
  info("%s -> OK, %d, %s", logbuf, user_id,
       xml_unparse_full_cookie(cbuf, sizeof(cbuf), &answer->cookie, &answer->client_key));
}

static void
cmd_team_login(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_login * data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  const struct userlist_user *u = 0;
  struct passwd_internal pwdint;
  const struct contest_desc *cnts = 0;
  const struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  const struct userlist_cookie *cookie;
  int out_size = 0, login_len, name_len;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;
  int user_id;
  int orig_contest_id;
  const unsigned char *name = 0;
  unsigned char cbuf[64];

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
           xml_unparse_ipv6(&data->origin_ip), data->ssl, login_ptr,
           data->contest_id, data->locale_id);

  if (p->user_id > 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    err("%s -> invalid password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  orig_contest_id = data->contest_id;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  if (!contests_check_team_ip(orig_contest_id, &data->origin_ip, data->ssl)) {
    err("%s -> IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }
  if (cnts->closed) {
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
  if (default_get_user_info_3(user_id, data->contest_id, &u, &ui, &c) < 0
      || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }
  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  if (!c) {
    err("%s -> NOT REGISTERED", logbuf);
    send_reply(p, -ULS_ERR_NOT_REGISTERED);
    return;
  }
  if (cnts->disable_team_password || (c->flags & USERLIST_UC_PRIVILEGED)) {
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
  if (c->status != USERLIST_REG_OK || (c->flags & USERLIST_UC_BANNED)
      || (c->flags & USERLIST_UC_LOCKED)) {
    err("%s -> NOT ALLOWED", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_PARTICIPATE);
    return;
  }
  if (!(c->flags & USERLIST_UC_PRIVILEGED) && (c->flags & USERLIST_UC_INCOMPLETE)) {
    err("%s -> INCOMPLETE REGISTRATION", logbuf);
    send_reply(p, -ULS_ERR_INCOMPLETE_REG);
    return;
  }

  login_len = strlen(u->login);
  name_len = strlen(name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  if (data->locale_id == -1) {
    data->locale_id = 0;
  }

  if (default_new_cookie_2(u->id, &data->origin_ip, data->ssl, 0, data->client_key, 0,
                           orig_contest_id, data->locale_id,
                           PRIV_LEVEL_USER, 0, 0, 1,
                           0, /* is_ws */
                           0, /* is_job */
                           &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  out->cookie = cookie->cookie;
  out->client_key = cookie->client_key;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = orig_contest_id;
  out->locale_id = data->locale_id;
  if (cnts->disable_team_password || !ui || (c->flags & USERLIST_UC_PRIVILEGED)) {
    out->passwd_method = u->passwd_method;
  } else {
    out->passwd_method = ui->team_passwd_method;
  }
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, name);

  p->user_id = u->id;
  p->contest_id = orig_contest_id;
  p->cnts_login = 1;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  p->cookie = out->cookie;
  p->client_key = out->client_key;
  enqueue_reply_to_client(p, out_size, out);
  default_touch_login_time(user_id, data->contest_id, cur_time);
  if (daemon_mode) {
    info("%s -> OK, %d, %s", logbuf, user_id,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key));
  } else {
    info("%s -> %d, %s, %s, time = %llu us",
         logbuf, user_id, login_ptr,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key),
         tsc2);
  }
}

static void
cmd_team_check_user(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_login *data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  const struct userlist_user *u = 0;
  struct passwd_internal pwdint;
  const struct contest_desc *cnts = 0;
  const struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  const struct userlist_cookie *cookie;
  int out_size = 0, login_len, name_len;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;
  int user_id, orig_contest_id = 0;
  const unsigned char *name = 0;
  unsigned char cbuf[64];

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
           "TEAM_CHECK_USER: %s, %d, %s, %d, %d",
           xml_unparse_ipv6(&data->origin_ip), data->ssl, login_ptr,
           data->contest_id, data->locale_id);

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf) < 0) return;

  orig_contest_id = data->contest_id;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    err("%s -> invalid password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  if (!contests_check_team_ip(orig_contest_id, &data->origin_ip, data->ssl)) {
    err("%s -> IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }
  if (cnts->closed) {
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
  if (default_get_user_info_3(user_id, data->contest_id, &u, &ui, &c) < 0
      || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }
  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  if (!c) {
    err("%s -> NOT REGISTERED", logbuf);
    send_reply(p, -ULS_ERR_NOT_REGISTERED);
    return;
  }
  if (data->pwd_special != 0x73629ae8) {
    if (cnts->disable_team_password || (c->flags & USERLIST_UC_PRIVILEGED)) {
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
      if (!ui || !ui->team_passwd) {
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
  }
  if (c->status != USERLIST_REG_OK || (c->flags & USERLIST_UC_BANNED)
      || (c->flags & USERLIST_UC_LOCKED)) {
    err("%s -> NOT ALLOWED", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_PARTICIPATE);
    return;
  }
  if (!(c->flags & USERLIST_UC_PRIVILEGED) && (c->flags & USERLIST_UC_INCOMPLETE)) {
    err("%s -> INCOMPLETE REGISTRATION", logbuf);
    send_reply(p, -ULS_ERR_INCOMPLETE_REG);
    return;
  }

  login_len = strlen(u->login);
  name_len = strlen(name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  if (data->locale_id == -1) {
    data->locale_id = 0;
  }

  if (default_new_cookie_2(u->id, &data->origin_ip, data->ssl,
                           data->cookie,
                           data->client_key, data->expire,
                           orig_contest_id, data->locale_id,
                           PRIV_LEVEL_USER, 0, 0, 1,
                           data->is_ws,
                           0, /* is_job */
                           &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  out->cookie = cookie->cookie;
  out->client_key = cookie->client_key;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = orig_contest_id;
  out->locale_id = data->locale_id;
  out->priv_level = PRIV_LEVEL_USER;
  out->reg_status = c->status;
  out->reg_flags = c->flags;
  out->expire = cookie->expire;
  if (cnts->disable_team_password || !ui || (c->flags & USERLIST_UC_PRIVILEGED)) {
    out->passwd_method = u->passwd_method;
  } else {
    out->passwd_method = ui->team_passwd_method;
  }
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, name);

  enqueue_reply_to_client(p, out_size, out);
  default_touch_login_time(user_id, data->contest_id, cur_time);
  if (daemon_mode) {
    info("%s -> OK, %d, %s", logbuf, user_id,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key));
  } else {
    info("%s -> %d, %s, %s, time = %llu us",
         logbuf, user_id, login_ptr,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key),
         tsc2);
  }
}

static void
cmd_priv_login(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_login *data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  const struct contest_desc *cnts = 0;
  struct passwd_internal pwdint;
  const struct userlist_user *u = 0;
  const struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  int capbit, login_len, name_len, priv_level = -1, r;
  size_t out_size = 0;
  const struct userlist_cookie *cookie;
  opcap_t caps;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  int user_id, orig_contest_id;
  const struct userlist_user_info *ui;
  const unsigned char *name = 0;
  unsigned char cbuf[64];

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
           xml_unparse_ipv6(&data->origin_ip), data->ssl, login_ptr,
           data->contest_id, data->locale_id);

  if (p->user_id > 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    err("%s -> invalid password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  if (data->role == USER_ROLE_CONTESTANT)
    priv_level = PRIV_LEVEL_USER;
  else if (data->role > USER_ROLE_CONTESTANT && data->role < USER_ROLE_ADMIN)
    priv_level = PRIV_LEVEL_JUDGE;
  else if (data->role == USER_ROLE_ADMIN)
    priv_level = PRIV_LEVEL_ADMIN;

  // if contest_id == 0, the user must have the correspondent global
  // capability bit
  orig_contest_id = data->contest_id;
  if (data->contest_id > 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }
  if (priv_level <= 0 || priv_level > PRIV_LEVEL_ADMIN) {
    err("%s -> invalid privelege level: %d", logbuf, priv_level);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  r = -1;
  if (data->contest_id > 0 && priv_level == PRIV_LEVEL_ADMIN) {
    r = contests_check_master_ip(orig_contest_id, &data->origin_ip, data->ssl);
  } else if (data->contest_id > 0 && priv_level == PRIV_LEVEL_JUDGE) {
    r = contests_check_judge_ip(orig_contest_id, &data->origin_ip, data->ssl);
  }
  if (!r) {
    err("%s -> IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }

  rdtscll(tsc1);
  if ((user_id = default_get_user_by_login(login_ptr)) <= 0) {
    err("%s -> WRONG LOGIN", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (default_get_user_info_3(user_id, data->contest_id, &u, &ui, &c) < 0
      || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

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
    if (get_global_uid_caps(config, u->id, &caps) < 0) {
      err("%s -> NOT PRIVILEGED", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    // if ADMIN level access requested, but only JUDGE can
    // be granted, decrease the privilege level
    if (priv_level == PRIV_LEVEL_ADMIN
        && opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0
        && opcaps_check(caps, OPCAP_JUDGE_LOGIN) >= 0)
      priv_level = PRIV_LEVEL_JUDGE;
  }

  // check user capabilities
  capbit = 0;
  switch (priv_level) {
  case PRIV_LEVEL_JUDGE:
    capbit = OPCAP_JUDGE_LOGIN;
    break;
  case PRIV_LEVEL_ADMIN:
    capbit = OPCAP_MASTER_LOGIN;
    break;
  default:
    SWERR(("unhandled tag"));
  }
  if (opcaps_check(caps, capbit) < 0) {
    err("%s -> NOT PRIVILEGED", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  login_len = strlen(u->login);
  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";
  name_len = strlen(name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  if (data->locale_id == -1) {
    data->locale_id = 0;
  }

  if (default_new_cookie_2(u->id, &data->origin_ip, data->ssl, 0,
                           data->client_key, 0,
                           orig_contest_id, data->locale_id,
                           priv_level, data->role, 0, 0,
                           0, /* is_ws */
                           0, /* is_job */
                           &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  out->cookie = cookie->cookie;
  out->client_key = cookie->client_key;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = orig_contest_id;
  out->locale_id = data->locale_id;
  out->priv_level = priv_level;
  out->passwd_method = u->passwd_method;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, name);

  p->user_id = u->id;
  p->priv_level = priv_level;
  p->cookie = out->cookie;
  p->client_key = out->client_key;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  enqueue_reply_to_client(p, out_size, out);
  default_touch_login_time(p->user_id, 0, cur_time);
  if (daemon_mode) {
    info("%s -> OK, %d, %s", logbuf, p->user_id,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key));
  } else {
    info("%s -> %d, %s, %s, time = %llu us", logbuf,
         p->user_id, login_ptr,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key),
         tsc2);
  }
}

static void
cmd_priv_check_user(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_login *data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  struct passwd_internal pwdint;
  const struct userlist_user *u = 0;
  const struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  int login_len, name_len, priv_level = -1, r, capbit = 0;
  size_t out_size = 0;
  const struct userlist_cookie *cookie;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  unsigned char cbuf[64];
  int user_id, orig_contest_id;
  const struct userlist_user_info *ui;
  const struct contest_desc *cnts = 0;
  const unsigned char *name = 0;

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
           "PRIV_CHECK_USER: %s, %d, %s, %d, %d, %d",
           xml_unparse_ipv6(&data->origin_ip), data->ssl, login_ptr,
           data->contest_id, data->locale_id, data->role);

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->role <= USER_ROLE_CONTESTANT || data->role > USER_ROLE_ADMIN) {
    err("%s -> invalid role %d", logbuf, data->role);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->role == USER_ROLE_CONTESTANT)
    priv_level = PRIV_LEVEL_USER;
  else if (data->role > USER_ROLE_CONTESTANT && data->role < USER_ROLE_ADMIN)
    priv_level = PRIV_LEVEL_JUDGE;
  else if (data->role == USER_ROLE_ADMIN)
    priv_level = PRIV_LEVEL_ADMIN;

  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf)) return;
  /*
  if (!data->origin_ip) {
    err("%s -> origin_ip is not set", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  */

  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    err("%s -> invalid password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  orig_contest_id = data->contest_id;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  r = -1;
  if (data->contest_id > 0 && priv_level == PRIV_LEVEL_ADMIN) {
    r = contests_check_master_ip(orig_contest_id, &data->origin_ip, data->ssl);
  } else if (data->contest_id > 0 && priv_level == PRIV_LEVEL_JUDGE) {
    r = contests_check_judge_ip(orig_contest_id, &data->origin_ip, data->ssl);
  }
  if (!r) {
    err("%s -> IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }

  rdtscll(tsc1);
  if ((user_id = default_get_user_by_login(login_ptr)) <= 0) {
    err("%s -> WRONG LOGIN", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (default_get_user_info_3(user_id, data->contest_id, &u, &ui, &c) < 0
      || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

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

  capbit = 0;
  if (data->role == USER_ROLE_JUDGE) capbit = OPCAP_JUDGE_LOGIN;
  else if (data->role == USER_ROLE_ADMIN) capbit = OPCAP_MASTER_LOGIN;
  if (capbit > 0 && is_cnts_capable(p, cnts, capbit, logbuf) < 0) return;

  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  login_len = strlen(u->login);
  name_len = strlen(name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  if (data->locale_id == -1) {
    data->locale_id = 0;
  }

  if (default_new_cookie_2(u->id, &data->origin_ip, data->ssl, 0, data->client_key, 0,
                           orig_contest_id, data->locale_id,
                           priv_level, data->role, 0, 0,
                           0, /* is_ws */
                           0, /* is_job */
                           &cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  out->cookie = cookie->cookie;
  out->client_key = cookie->client_key;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = orig_contest_id;
  out->locale_id = data->locale_id;
  out->passwd_method = u->passwd_method;
  out->priv_level = priv_level;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, name);

  enqueue_reply_to_client(p, out_size, out);
  default_touch_login_time(out->user_id, 0, cur_time);
  if (daemon_mode) {
    info("%s -> OK, %d, %s", logbuf, out->user_id,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key));
  } else {
    info("%s -> %d, %s, %s, time = %llu us", logbuf,
         out->user_id, login_ptr,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key),
         tsc2);
  }
}

static void
cmd_priv_check_password(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_login *data)
{
  unsigned char *login_ptr, *passwd_ptr, *name_ptr;
  struct passwd_internal pwdint;
  const struct userlist_user *u = 0;
  const struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  int login_len, name_len;
  size_t out_size = 0;
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  int user_id;
  const struct userlist_user_info *ui;
  const unsigned char *name = 0;

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
           "PRIV_CHECK_PASSWORD: %s", login_ptr);

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf)) return;

  if (passwd_convert_to_internal(passwd_ptr, &pwdint) < 0) {
    err("%s -> invalid password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  rdtscll(tsc1);
  if ((user_id = default_get_user_by_login(login_ptr)) <= 0) {
    err("%s -> WRONG LOGIN", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if (default_get_user_info_3(user_id, 0, &u, &ui, &c) < 0 || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

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

  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  login_len = strlen(u->login);
  name_len = strlen(name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  out->reply_id = ULS_LOGIN_OK;
  out->user_id = u->id;
  out->contest_id = 0;
  out->locale_id = 0;
  out->priv_level = 0;
  out->passwd_method = u->passwd_method;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, name);

  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, %d", logbuf, out->user_id);
}

static void
cmd_check_cookie(
        struct client_state *p,
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
  unsigned char cbuf[64];
  const struct userlist_user_info *ui;
  const struct contest_desc *cnts = 0;
  int orig_contest_id = 0;
  unsigned char *name = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "COOKIE: ip = %s, %d, cookie = %s",
           xml_unparse_ipv6(&data->origin_ip), data->ssl,
           xml_unparse_full_cookie(cbuf, sizeof(cbuf), &data->cookie, &data->client_key));

  // cannot login twice
  if (p->user_id > 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  rdtscll(tsc1);
  if (default_get_cookie(data->cookie, data->client_key, &cookie) < 0 || !cookie) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

  if (data->contest_id < 0) data->contest_id = cookie->contest_id;
  orig_contest_id = data->contest_id;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  if (config->enable_cookie_ip_check > 0) {
    if (ipv6cmp(&cookie->ip, &data->origin_ip) != 0 || cookie->ssl != data->ssl) {
      err("%s -> IP address mismatch", logbuf);
      send_reply(p, -ULS_ERR_NO_COOKIE);
      return;
    }
  }
  if (current_time > cookie->expire) {
    err("%s -> cookie expired", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (cookie->priv_level > 0 || cookie->role > 0) {
    err("%s -> privilege level mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  if (default_get_user_info_2(cookie->user_id, data->contest_id, &u, &ui) < 0 || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  if (orig_contest_id != cookie->contest_id) {
    err("%s -> contest_id mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  /* deny attempt to log into a closed contest */
  if (data->contest_id > 0) {
    if (cnts->closed) {
      err("%s -> contest is closed", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    if (!contests_check_register_ip(orig_contest_id, &data->origin_ip, data->ssl)) {
      err("%s -> IP is not allowed", logbuf);
      send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
      return;
    }

    if (!cnts->disable_team_password && cookie->team_login) {
      err("%s -> this is a team cookie", logbuf);
      send_reply(p, -ULS_ERR_NO_COOKIE);
      return;
    }
  }

  anslen = sizeof(struct userlist_pk_login_ok)
    + strlen(name) + 1 + strlen(u->login) + 1;
  answer = alloca(anslen);
  memset(answer, 0, anslen);
  answer->locale_id = cookie->locale_id;
  answer->reply_id = ULS_LOGIN_COOKIE;
  answer->user_id = u->id;
  answer->contest_id = cookie->contest_id;
  answer->passwd_method = u->passwd_method;
  answer->login_len = strlen(u->login);
  name_beg = answer->data + answer->login_len + 1;
  answer->name_len = strlen(name);
  answer->cookie = cookie->cookie;
  answer->client_key = cookie->client_key;
  strcpy(answer->data, u->login);
  strcpy(name_beg, name);
  default_set_cookie_contest(cookie, orig_contest_id);
  default_set_cookie_team_login(cookie, 0);
  enqueue_reply_to_client(p, anslen, answer);
  if (!daemon_mode) {
    info("%s -> OK, %d, %s, %llu us", logbuf, u->id, u->login, tsc2);
  }
  p->user_id = u->id;
  p->contest_id = orig_contest_id;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  p->cookie = data->cookie;
  p->client_key = data->client_key;
  p->cnts_login = 0;
  return;
}

static void
cmd_team_check_cookie(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_check_cookie * data)
{
  const struct contest_desc *cnts = 0;
  const struct userlist_user *u = 0;
  const struct userlist_cookie *cookie = 0;
  const struct userlist_contest *c = 0;
  struct userlist_pk_login_ok *out = 0;
  int out_size = 0, login_len = 0, name_len = 0;
  unsigned char *login_ptr, *name_ptr;
  ej_tsc_t tsc1, tsc2;
  time_t current_time = time(0);
  unsigned char logbuf[1024];
  unsigned char cbuf[64];
  const struct userlist_user_info *ui;
  int orig_contest_id = 0;
  const unsigned char *name = 0;
  int locale_id;
  const unsigned char *user_login = 0;
  int user_id = 0;
  int need_touch_login_time = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "TEAM_COOKIE: %s, %d, %d, %s",
           xml_unparse_ipv6(&data->origin_ip), data->ssl, data->contest_id,
           xml_unparse_full_cookie(cbuf, sizeof(cbuf), &data->cookie, &data->client_key));

  if (p->user_id > 0) {
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
  if (default_get_cookie(data->cookie, data->client_key, &cookie) < 0 || !cookie) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

  if (data->contest_id < 0) data->contest_id = cookie->contest_id;
  orig_contest_id = data->contest_id;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  if (default_get_user_info_3(cookie->user_id,data->contest_id,&u,&ui,&c) < 0
      || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  user_login = u->login;
  user_id = u->id;
  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  if (config->enable_cookie_ip_check > 0) {
    if (ipv6cmp(&cookie->ip, &data->origin_ip) != 0 || cookie->ssl != data->ssl) {
      err("%s -> IP address mismatch", logbuf);
      send_reply(p, -ULS_ERR_NO_COOKIE);
      return;
    }
  }
  if (current_time > cookie->expire) {
    err("%s -> cookie expired", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (cookie->priv_level > 0 || cookie->role > 0) {
    err("%s -> privilege level mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (orig_contest_id != cookie->contest_id) {
    err("%s -> contest_id mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  if (cnts->closed) {
    err("%s -> contest is closed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (!contests_check_team_ip(orig_contest_id, &data->origin_ip, data->ssl)) {
    err("%s -> IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }
  if (!cnts->disable_team_password && !cookie->team_login) {
    err("%s -> not a team cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  locale_id = cookie->locale_id;
  if (!cookie->team_login) {
    need_touch_login_time = 1;
  }
  default_set_cookie_team_login(cookie, 1);
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
  if (!(c->flags & USERLIST_UC_PRIVILEGED) && (c->flags & USERLIST_UC_INCOMPLETE)) {
    err("%s -> INCOMPLETE REGISTRATION", logbuf);
    send_reply(p, -ULS_ERR_INCOMPLETE_REG);
    return;
  }

  login_len = strlen(user_login);
  name_len = strlen(name);
  out_size = sizeof(*out) + login_len + name_len + 2;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  out->cookie = data->cookie;
  out->client_key = data->client_key;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = user_id;
  out->contest_id = orig_contest_id;
  out->locale_id = locale_id;
  if (cnts->disable_team_password || !ui) {
    out->passwd_method = u->passwd_method;
  } else {
    out->passwd_method = ui->team_passwd_method;
  }
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, user_login);
  strcpy(name_ptr, name);

  p->user_id = user_id;
  p->contest_id = orig_contest_id;
  p->cnts_login = 1;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  p->cookie = data->cookie;
  p->client_key = data->client_key;
  enqueue_reply_to_client(p, out_size, out);
  if (!daemon_mode) {
    CONN_INFO("%s -> ok, %d, %s, %llu us", logbuf, user_id, user_login, tsc2);
  }
  if (need_touch_login_time) {
    default_touch_login_time(cookie->user_id, orig_contest_id, current_time);
  }
}

static void
cmd_priv_check_cookie(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_check_cookie *data)
{
  const struct contest_desc *cnts = 0;
  const struct userlist_user *u = 0;
  const struct userlist_cookie *cookie = 0;
  struct userlist_pk_login_ok *out;
  const struct userlist_contest *c = 0;
  const struct userlist_user_info *ui = 0;
  size_t login_len, name_len, out_size;
  unsigned char *login_ptr, *name_ptr;
  int capbit, orig_contest_id;
  opcap_t caps;
  time_t current_time = time(0);
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  unsigned char cbuf[64];
  const unsigned char *name = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "PRIV_COOKIE: %s, %d, %d, %s",
           xml_unparse_ipv6(&data->origin_ip), data->ssl, data->contest_id,
           xml_unparse_full_cookie(cbuf, sizeof(cbuf), &data->cookie, &data->client_key));

  if (p->user_id > 0) {
    err("%s -> already authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (!data->cookie) {
    err("%s -> cookie value is 0", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  /*
  if (!data->origin_ip) {
    err("%s -> origin_ip is not set", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  */

  rdtscll(tsc1);
  if (default_get_cookie(data->cookie, data->client_key, &cookie) < 0 || !cookie) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

  if (data->contest_id < 0) data->contest_id = cookie->contest_id;
  orig_contest_id = data->contest_id;
  if (data->contest_id > 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }

  if (data->contest_id != cookie->contest_id) {
    err("%s -> contest_id mismatch: %d, %d", logbuf,
        data->contest_id, cookie->contest_id);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  if (data->priv_level < 0) data->priv_level = cookie->priv_level;
  if (data->priv_level <= 0 || data->priv_level > PRIV_LEVEL_ADMIN) {
    err("%s -> invalid privilege level %d", logbuf, data->priv_level);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (!cookie->priv_level || data->priv_level != cookie->priv_level) {
    err("%s -> privilege level mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  if (default_get_user_info_3(cookie->user_id,data->contest_id,&u,&ui,&c) < 0
      || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  if (config->enable_cookie_ip_check > 0) {
    if (ipv6cmp(&cookie->ip, &data->origin_ip) != 0 || cookie->ssl != data->ssl) {
      err("%s -> IP address mismatch", logbuf);
      send_reply(p, -ULS_ERR_NO_COOKIE);
      return;
    }
  }
  if (current_time > cookie->expire) {
    err("%s -> cookie expired", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
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
    if (get_uid_caps(&cnts->capabilities, u->id, &caps) < 0) {
      err("%s -> NOT PRIVILEGED", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  } else {
    if (get_global_uid_caps(config, u->id, &caps) < 0) {
      err("%s -> NOT PRIVILEGED", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  }

  // check user capabilities
  capbit = -1;
  if (data->priv_level == PRIV_LEVEL_ADMIN) capbit = OPCAP_MASTER_LOGIN;
  else if (data->priv_level == PRIV_LEVEL_JUDGE) capbit = OPCAP_JUDGE_LOGIN;
  if (capbit < 0) {
    err("%s -> invalid privilege level", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (opcaps_check(caps, capbit) < 0) {
    err("%s -> NOT PRIVILEGED", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  login_len = strlen(u->login);
  name_len = strlen(name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  out->cookie = cookie->cookie;
  out->client_key = cookie->client_key;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = orig_contest_id;
  out->locale_id = cookie->locale_id;
  out->passwd_method = u->passwd_method;
  out->login_len = login_len;
  out->name_len = name_len;
  out->priv_level = data->priv_level;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, name);

  p->user_id = u->id;
  p->contest_id = orig_contest_id;
  p->priv_level = out->priv_level;
  p->cookie = cookie->cookie;
  p->client_key = cookie->client_key;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  enqueue_reply_to_client(p, out_size, out);

  if (!daemon_mode) {
    CONN_INFO("%s -> OK, %d, %s, %llu us", logbuf, u->id, u->login, tsc2);
  }
}

static void
cmd_priv_cookie_login(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_cookie_login *data)
{
  const struct contest_desc *cnts = 0;
  const struct userlist_user *u = 0;
  const struct userlist_cookie *cookie = 0, *new_cookie = 0;
  struct userlist_pk_login_ok *out;
  const struct userlist_contest *c = 0;
  const struct userlist_user_info *ui = 0;
  size_t login_len, name_len, out_size;
  unsigned char *login_ptr, *name_ptr;
  int priv_level, capbit, orig_contest_id, r;
  opcap_t caps;
  time_t current_time = time(0);
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024], cbuf[64];
  const unsigned char *name = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "PRIV_COOKIE_LOGIN: %s, %d, %d, %s",
           xml_unparse_ipv6(&data->origin_ip), data->ssl, data->contest_id,
           xml_unparse_full_cookie(cbuf, sizeof(cbuf), &data->cookie, &data->client_key));

  if (is_judge(p, logbuf) < 0) return;

  orig_contest_id = data->contest_id;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  if (!data->cookie) {
    err("%s -> cookie value is 0", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  /*
  if (!data->origin_ip) {
    err("%s -> origin_ip is not set", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  */

  if (data->role <= 0 || data->role >= USER_ROLE_LAST) {
    err("%s -> invalid privilege level", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (data->role == USER_ROLE_ADMIN) priv_level = PRIV_LEVEL_ADMIN;
  else priv_level = PRIV_LEVEL_JUDGE;

  rdtscll(tsc1);
  if (default_get_cookie(data->cookie, data->client_key, &cookie) < 0 || !cookie) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

  if (default_get_user_info_3(cookie->user_id,data->contest_id,&u,&ui,&c) < 0
      || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  if (config->enable_cookie_ip_check > 0) {
    if (ipv6cmp(&cookie->ip, &data->origin_ip) != 0 || cookie->ssl != data->ssl) {
      err("%s -> IP address or SSL flag mismatch", logbuf);
      send_reply(p, -ULS_ERR_NO_COOKIE);
      return;
    }
  }
  if (current_time > cookie->expire) {
    err("%s -> cookie expired", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (cookie->priv_level < priv_level) {
    err("%s -> privilege level mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  if (cookie->contest_id > 0) {
    err("%s -> contest_id mismatch", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
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
  if (get_uid_caps(&cnts->capabilities, u->id, &caps) < 0) {
    err("%s -> NOT PRIVILEGED", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  // check user capabilities
  capbit = 0;
  switch (priv_level) {
  case PRIV_LEVEL_JUDGE:
    capbit = OPCAP_JUDGE_LOGIN;
    break;
  case PRIV_LEVEL_ADMIN:
    capbit = OPCAP_MASTER_LOGIN;
    break;
  default:
    abort();
  }
  if (opcaps_check(caps, capbit) < 0) {
    err("%s -> NOT PRIVILEGED", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  r = -1;
  switch (priv_level) {
  case PRIV_LEVEL_JUDGE:
    r = contests_check_judge_ip(orig_contest_id, &data->origin_ip, data->ssl);
    break;
  case PRIV_LEVEL_ADMIN:
    r = contests_check_master_ip(orig_contest_id, &data->origin_ip, data->ssl);
    break;
  default:
    abort();
  }
  if (!r) {
    err("%s -> IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_IP_NOT_ALLOWED);
    return;
  }

  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  /* everything is ok, create new cookie */
  login_len = strlen(u->login);
  name_len = strlen(name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;

  if (default_new_cookie_2(u->id, &data->origin_ip, data->ssl, 0, data->client_key,
                           0, orig_contest_id, data->locale_id,
                           priv_level, data->role, 0, 0,
                           0, /* is_ws */
                           0, /* is_job */
                           &new_cookie) < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  out->cookie = new_cookie->cookie;
  out->client_key = new_cookie->client_key;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = u->id;
  out->contest_id = orig_contest_id;
  out->locale_id = data->locale_id;
  out->priv_level = priv_level;
  out->passwd_method = u->passwd_method;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, u->login);
  strcpy(name_ptr, name);

  /*
  p->user_id = u->id;
  p->contest_id = orig_contest_id;
  p->priv_level = priv_level;
  p->cookie = cookie->cookie;
  p->ip = data->origin_ip;
  p->ssl = data->ssl;
  */

  enqueue_reply_to_client(p, out_size, out);
  if (daemon_mode) {
    info("%s -> OK, %d, %s", logbuf, out->user_id,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key));
  } else {
    info("%s -> %d, %s, %s, time = %llu us", logbuf,
         out->user_id, login_ptr,
         xml_unparse_full_cookie(cbuf, sizeof(cbuf), &out->cookie, &out->client_key),
         tsc2);
  }
  default_touch_login_time(out->user_id, 0, cur_time);
}

static void
cmd_do_logout(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_logout * data)
{
  const struct userlist_cookie *cookie;
  unsigned char logbuf[1024];
  unsigned char cbuf[64];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf),
           "LOGOUT: %s, %s",
           xml_unparse_ipv6(&data->origin_ip),
           xml_unparse_full_cookie(cbuf, sizeof(cbuf), &data->cookie, &data->client_key));

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, ULS_OK);
    return;
  }
  if (!data->cookie) {
    err("%s -> cookie is empty", logbuf);
    send_reply(p, ULS_OK);
    return;
  }
  /*
  if (!data->origin_ip) {
    err("%s -> origin_ip is empty", logbuf);
    send_reply(p, ULS_OK);
    return;
  }
  */

  if (default_get_cookie(data->cookie, data->client_key , &cookie) < 0 || !cookie) {
    err("%s -> cookie not found", logbuf);
    send_reply(p, ULS_OK);
    return;
  }
  if (cookie->user_id != p->user_id) {
    err("%s -> cookie belongs to another user", logbuf);
    send_reply(p, ULS_OK);
    return;
  }
  if (config->enable_cookie_ip_check > 0) {
    if (ipv6cmp(&cookie->ip, &data->origin_ip) != 0 || cookie->ssl != data->ssl) {
      err("%s -> IP address does not match", logbuf);
      send_reply(p, -ULS_ERR_NO_COOKIE);
      return;
    }
  }

  default_remove_cookie(cookie);
  send_reply(p, ULS_OK);
  if (!daemon_mode) {
    CONN_INFO("cookie removed");
  }
}

/*
 * Unprivileged: get information about a user.
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
  const struct contest_desc *cnts = 0;
  int orig_contest_id;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch: %d", pkt_len);
    return;
  }

  if (data->user_id <= 0 && p->user_id > 0) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "GET_USER_INFO: %d", data->user_id);

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (data->user_id != p->user_id) {
    err("%s -> user ids does not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (data->contest_id != p->contest_id) {
    err("%s -> contest_id does not match", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  orig_contest_id = data->contest_id;
  (void) orig_contest_id;
  if (data->contest_id) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }

  if (default_get_user_info_4(p->user_id, data->contest_id, &u) < 0 || !u) {
    err("%s -> invalid user id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (!(f = open_memstream(&xml_ptr, &xml_size))) {
    err("%s -> open_memstream() failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  userlist_unparse_user(u, f, USERLIST_MODE_USER, data->contest_id, 0);
  close_memstream(f); f = 0;
  default_unlock_user(u);

  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size;
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
  unsigned char logbuf[1024];
  int flags, capbit = -1;
  const struct contest_desc *cnts = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length mismatch: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "PRIV_USER_INFO: %d, %d",
           p->user_id, data->user_id);

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }

  if (default_get_user_info_5(data->user_id, data->contest_id, &u) < 0 || !u) {
    err("%s -> invalid user id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (is_dbcnts_capable(p, cnts, OPCAP_GET_USER, logbuf) < 0) return;
  if (is_privileged_cnts_user(u, cnts) >= 0) {
    capbit = OPCAP_PRIV_EDIT_PASSWD;
  } else {
    capbit = OPCAP_EDIT_PASSWD;
  }
  flags = USERLIST_SHOW_REG_PASSWD | USERLIST_SHOW_CNTS_PASSWD;
  if (check_dbcnts_capable(p, cnts, capbit) < 0) {
    flags &= ~(USERLIST_SHOW_REG_PASSWD | USERLIST_SHOW_CNTS_PASSWD);
  } else if (check_db_capable(p, capbit) < 0
             && cnts && !cnts->disable_team_password) {
    flags &= ~USERLIST_SHOW_REG_PASSWD;
  }

  if (!(f = open_memstream(&xml_ptr, &xml_size))) {
    err("%s -> open_memstream() failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  userlist_unparse_user(u, f, USERLIST_MODE_ALL, data->contest_id, flags);
  close_memstream(f); f = 0;
  default_unlock_user(u);

  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size;
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
cmd_list_all_users(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  ptr_iterator_t iter;
  const struct userlist_user *u;

  snprintf(logbuf, sizeof(logbuf), "PRIV_ALL_USERS: %d, %d",
           p->user_id, data->contest_id);

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;

  f = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(f, -1);
  iter = default_get_brief_list_iterator(data->contest_id);
  if (iter) {
    for (; iter->has_next(iter); iter->next(iter)) {
      if (!(u = (const struct userlist_user*) iter->get(iter))) continue;
      userlist_unparse_user_short(u, f, data->contest_id);
      default_unlock_user(u);
    }
  }
  userlist_write_xml_footer(f);
  if (iter) iter->destroy(iter);
  close_memstream(f); f = 0;
  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size;
  out = (typeof(out)) xcalloc(1, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr);
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu", logbuf, xml_size);
  xfree(out);
}

static void
cmd_list_standings_users(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  int flags = 0, subflags;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  ptr_iterator_t iter;
  const struct userlist_user *u;
  struct timeval ts1, ts2;

  snprintf(logbuf, sizeof(logbuf), "PRIV_STANDINGS_USERS: %d, %d",
           p->user_id, data->contest_id);

  gettimeofday(&ts1, NULL);

  if (is_admin(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  if (is_cnts_capable(p, cnts, OPCAP_MAP_CONTEST, logbuf) < 0) return;

  if (cnts->personal) flags |= USERLIST_FORCE_FIRST_MEMBER;
  flags |= USERLIST_SHOW_PRIV_REG_PASSWD | USERLIST_SHOW_PRIV_CNTS_PASSWD
    | USERLIST_SHOW_REG_PASSWD | USERLIST_SHOW_CNTS_PASSWD;
  if (check_dbcnts_capable(p, cnts, OPCAP_PRIV_EDIT_PASSWD) < 0) {
    flags &= ~(USERLIST_SHOW_PRIV_REG_PASSWD | USERLIST_SHOW_PRIV_CNTS_PASSWD);
  } else if (check_db_capable(p, OPCAP_PRIV_EDIT_PASSWD) < 0
             && !cnts->disable_team_password) {
    flags &= ~USERLIST_SHOW_PRIV_REG_PASSWD;
  }
  if (check_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD) < 0) {
    flags &= ~(USERLIST_SHOW_REG_PASSWD | USERLIST_SHOW_CNTS_PASSWD);
  } else if (check_db_capable(p, OPCAP_EDIT_PASSWD) < 0
             && !cnts->disable_team_password) {
    flags &= ~USERLIST_SHOW_REG_PASSWD;
  }

  f = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(f, -1);
  for (iter = default_get_standings_list_iterator(data->contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);

    subflags = flags & USERLIST_FORCE_FIRST_MEMBER;
    if (is_privileged_cnts_user(u, cnts) >= 0) {
      if ((flags & USERLIST_SHOW_PRIV_REG_PASSWD))
        subflags |= USERLIST_SHOW_REG_PASSWD;
      if ((flags & USERLIST_SHOW_PRIV_CNTS_PASSWD))
        subflags |= USERLIST_SHOW_CNTS_PASSWD;
    } else {
      subflags |= flags & (USERLIST_SHOW_REG_PASSWD|USERLIST_SHOW_CNTS_PASSWD);
    }

    userlist_real_unparse_user(u, f, USERLIST_MODE_STAND, data->contest_id,
                               subflags);

    default_unlock_user(u);
  }
  userlist_write_xml_footer(f);
  iter->destroy(iter);
  close_memstream(f); f = 0;
  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size;
  out = (typeof(out)) xcalloc(1, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr);

  gettimeofday(&ts2, NULL);

  unsigned long long ms1 = ts1.tv_sec * 1000000ULL;
  ms1 += ts1.tv_usec;
  unsigned long long ms2 = ts2.tv_sec * 1000000ULL;
  ms2 += ts2.tv_usec;

  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu, time = %llu", logbuf, xml_size, (ms2 - ms1));
  xfree(out);
}

static void
cmd_list_standings_users_2(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  int flags = 0, subflags;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  ptr_iterator_t iter;
  const struct userlist_user *u;
  UserlistBinaryContext cntx;
  struct timeval ts1, ts2;

  snprintf(logbuf, sizeof(logbuf), "PRIV_STANDINGS_USERS_2: %d, %d",
           p->user_id, data->contest_id);

  gettimeofday(&ts1, NULL);

  if (is_admin(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  if (is_cnts_capable(p, cnts, OPCAP_MAP_CONTEST, logbuf) < 0) return;

  if (cnts->personal) flags |= USERLIST_FORCE_FIRST_MEMBER;
  flags |= USERLIST_SHOW_PRIV_REG_PASSWD | USERLIST_SHOW_PRIV_CNTS_PASSWD
    | USERLIST_SHOW_REG_PASSWD | USERLIST_SHOW_CNTS_PASSWD;
  if (check_dbcnts_capable(p, cnts, OPCAP_PRIV_EDIT_PASSWD) < 0) {
    flags &= ~(USERLIST_SHOW_PRIV_REG_PASSWD | USERLIST_SHOW_PRIV_CNTS_PASSWD);
  } else if (check_db_capable(p, OPCAP_PRIV_EDIT_PASSWD) < 0
             && !cnts->disable_team_password) {
    flags &= ~USERLIST_SHOW_PRIV_REG_PASSWD;
  }
  if (check_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD) < 0) {
    flags &= ~(USERLIST_SHOW_REG_PASSWD | USERLIST_SHOW_CNTS_PASSWD);
  } else if (check_db_capable(p, OPCAP_EDIT_PASSWD) < 0
             && !cnts->disable_team_password) {
    flags &= ~USERLIST_SHOW_REG_PASSWD;
  }

  userlist_bin_init_context(&cntx);
  userlist_bin_marshall_user_list(&cntx, NULL, data->contest_id);
  // pass1 - compute the total size of the data
  for (iter = default_get_standings_list_iterator(data->contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);

    subflags = flags & USERLIST_FORCE_FIRST_MEMBER;
    if (is_privileged_cnts_user(u, cnts) >= 0) {
      if ((flags & USERLIST_SHOW_PRIV_REG_PASSWD))
        subflags |= USERLIST_SHOW_REG_PASSWD;
      if ((flags & USERLIST_SHOW_PRIV_CNTS_PASSWD))
        subflags |= USERLIST_SHOW_CNTS_PASSWD;
    } else {
      subflags |= flags & (USERLIST_SHOW_REG_PASSWD|USERLIST_SHOW_CNTS_PASSWD);
    }

    userlist_bin_marshall_user(&cntx, u, data->contest_id);
    default_unlock_user(u);
  }
  iter->destroy(iter);
  userlist_bin_finish_context(&cntx);

  unsigned char *msg = xmalloc(cntx.total_size + 4);
  UserlistBinaryHeader *header = userlist_bin_marshall(msg + 4, &cntx, data->contest_id);
  header->reply_id = ULS_BIN_DATA;
  userlist_bin_destroy_context(&cntx);

  gettimeofday(&ts2, NULL);

  unsigned long long ms1 = ts1.tv_sec * 1000000ULL;
  ms1 += ts1.tv_usec;
  unsigned long long ms2 = ts2.tv_sec * 1000000ULL;
  ms2 += ts2.tv_usec;

  enqueue_reply_to_client_2(p, header->pkt_size, msg);
  info("%s -> OK, size = %u, time = %llu", logbuf, (unsigned) header->pkt_size, (ms2 - ms1));
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

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

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
  close_memstream(f); f = 0;

  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size;
  out = alloca(out_size);
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

static void
cmd_set_user_info(struct client_state *p,
                  int pkt_len,
                  struct userlist_pk_set_user_info *data)
{
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  struct userlist_user *new_u = 0;
  int reply_code = ULS_OK, cloned_flag = 0;

  snprintf(logbuf, sizeof(logbuf),
           "SET_USER_INFO: %d, %d", data->user_id, data->info_len);

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != data->user_id) {
    err("%s -> user_id does not match: %d, %d", logbuf,
        p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

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

  default_check_user_reg_data(data->user_id, data->contest_id);
  update_all_user_contests(data->user_id);
  if (cloned_flag) reply_code = ULS_CLONED;
  info("%s -> OK", logbuf);
  send_reply(p, reply_code);
  userlist_free(&new_u->b);
}

/*
This function is not used. Pending removal.
 */
static void
cmd_set_passwd(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_set_password *data)
{
  int contest_id = 0;
  unsigned char *old_pwd, *new_pwd;
  const struct userlist_user *u;
  struct passwd_internal oldint, newint;
  unsigned char logbuf[1024];
  const struct contest_desc *cnts = 0;

  old_pwd = data->data;
  new_pwd = old_pwd + data->old_len + 1;

  snprintf(logbuf, sizeof(logbuf), "SET_PASSWD: %d", data->user_id);

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != data->user_id) {
    err("%s -> user_ids does not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (p->cnts_login) {
    contest_id = p->contest_id;
    if (full_get_contest(p, logbuf, &contest_id, &cnts) < 0) return;
    if (!cnts->disable_team_password) {
      err("%s -> attempt to change reg passwd from contest login", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
  }

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (data->new_len <= 0) {
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

  passwd_convert(&newint, newint.pwd_nows, NULL, USERLIST_PWD_SHA256);
  default_set_reg_passwd(u->id, USERLIST_PWD_SHA256, newint.encoded, cur_time);
  default_remove_user_cookies(u->id);
  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
}

static void
cmd_team_set_passwd(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_set_password *data)
{
  unsigned char *old_pwd, *new_pwd;
  const struct userlist_user *u;
  struct passwd_internal oldint, newint;
  const struct contest_desc *cnts = 0;
  int reply_code = ULS_OK, cloned_flag = 0;
  unsigned char logbuf[1024];
  const struct userlist_user_info *ui;
  const struct userlist_contest *c;

  old_pwd = data->data;
  new_pwd = old_pwd + data->old_len + 1;

  snprintf(logbuf, sizeof(logbuf),
           "SET_TEAM_PASSWD: %d, %d", data->user_id, data->contest_id);

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != data->user_id) {
    err("%s -> user_ids do not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (!p->cnts_login) {
    err("%s -> attempt to change cnts passwd from reg login", logbuf);
    return;
  }
  if (p->contest_id != data->contest_id) {
    err("%s -> contest_id mismatch: %d, %d",
        logbuf, p->contest_id, data->contest_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  if (cnts->disable_team_password) {
    err("%s -> team password is disabled", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (data->new_len <= 0) {
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

  if (default_get_user_info_3(data->user_id, data->contest_id, &u, &ui, &c) < 0
      || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
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
  passwd_convert(&newint, newint.pwd_nows, NULL, USERLIST_PWD_SHA256);
  default_set_team_passwd(u->id, data->contest_id, USERLIST_PWD_SHA256,
                          newint.encoded, cur_time,
                          &cloned_flag);
  if (cloned_flag) reply_code = ULS_CLONED;
  default_remove_user_cookies(u->id);
  send_reply(p, reply_code);
  info("%s -> OK", logbuf);
}

/* unprivileged version of the function */
static void
cmd_register_contest(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_register_contest *data)
{
  const struct contest_desc *c = 0;
  const struct userlist_contest *r;
  int errcode, status = USERLIST_REG_PENDING, orig_contest_id = 0;
  unsigned char logbuf[1024];

  snprintf(logbuf, sizeof(logbuf), "REGISTER_CONTEST: %d, %d",
           data->user_id, data->contest_id);

  if (p->user_id <= 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  if (p->user_id != data->user_id) {
    err("%s -> user_ids do not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  orig_contest_id = data->contest_id;
  if (full_get_contest(p, logbuf, &data->contest_id, &c) < 0) return;
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
  if (!contests_check_register_ip(orig_contest_id, &data->ip, data->ssl_flag)){
    err("%s -> this IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (c->autoregister) status = USERLIST_REG_OK;
  errcode = default_register_contest(data->user_id, data->contest_id,
                                     status, 0, cur_time, &r);
  if (errcode < 0) {
    err("%s -> registration failed", logbuf);
    send_reply(p, -ULS_ERR_UNSPECIFIED_ERROR);
    return;
  } else if (!errcode) {
    info("%s -> already registered", logbuf);
    send_reply(p, ULS_OK);
    return;
  }

  default_check_user_reg_data(data->user_id, data->contest_id);
  if (r->status == USERLIST_REG_OK) {
    update_userlist_table(data->contest_id);
  }
  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
  return;
}

/* unprivileged version for use by `new-register' */
static void
cmd_register_contest_2(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_register_contest *data)
{
  const struct contest_desc *c = 0;
  const struct userlist_contest *r;
  int errcode, status = USERLIST_REG_PENDING, bit;
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;

  snprintf(logbuf, sizeof(logbuf), "REGISTER_CONTEST_2: %d, %d",
           data->user_id, data->contest_id);

  if (is_judge(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &c) < 0) return;

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> invalid user_id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  bit = OPCAP_CREATE_REG;
  if (is_privileged_cnts_user(u, c) >= 0) bit = OPCAP_PRIV_CREATE_REG;
  if (is_cnts_capable(p, c, bit, logbuf) < 0) return;

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

  if (u->simple_registration && !c->simple_registration) {
    err("%s -> user is simple_registered, but the contest is not", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (contests_check_register_ip(data->contest_id,&data->ip,data->ssl_flag)<=0){
    err("%s -> this IP is not allowed", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (c->autoregister) status = USERLIST_REG_OK;
  errcode = default_register_contest(data->user_id, data->contest_id,
                                     status, 0, cur_time, &r);
  if (errcode < 0) {
    err("%s -> registration failed", logbuf);
    send_reply(p, -ULS_ERR_UNSPECIFIED_ERROR);
    return;
  } else if (!errcode) {
    info("%s -> already registered", logbuf);
    send_reply(p, ULS_OK);
    return;
  }

  default_check_user_reg_data(data->user_id, data->contest_id);
  r = default_get_contest_reg(data->user_id, data->contest_id);
  update_userlist_table(data->contest_id);
  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
  return;
}

/* privileged version */
static void
cmd_priv_register_contest(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_register_contest *data)
{
  const struct userlist_user *u;
  const struct contest_desc *c = 0;
  const struct userlist_contest *r;
  int status = USERLIST_REG_PENDING, bit;
  unsigned char logbuf[1024];

  snprintf(logbuf, sizeof(logbuf), "PRIV_REGISTER_CONTEST: %d, %d, %d",
           p->user_id, data->user_id, data->contest_id);

  if (is_judge(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &c) < 0) return;

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> invalid user_id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  bit = OPCAP_CREATE_REG;
  if (is_privileged_cnts_user(u, c) >= 0) bit = OPCAP_PRIV_CREATE_REG;
  if (is_cnts_capable(p, c, bit, logbuf) < 0) return;

  if (c->autoregister) status = USERLIST_REG_OK;
  status = default_register_contest(data->user_id, data->contest_id, status, 0,
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

  if (r && r->status == USERLIST_REG_OK) {
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
  const struct contest_desc *cnts;
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
  if (p->user_id != data->user_id) {
    err("%s -> user_ids do not match: %d, %d",
        logbuf, p->user_id, data->user_id);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

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

  update_userlist_table(data->contest_id);
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
  int role, pers, role_cnt;
  const struct userlist_member *m;
  const struct contest_member *cm;
  const struct userlist_members *mm;
  const unsigned char *name = 0;
  struct userlist_user_info ui_empty;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (default_get_user_info_6(user_id, contest_id, &u, &ui, &c, &mm) < 0
      || !u || !c) {
    fprintf(f, "<%s>%s</%s>\n",
            d->users_head_style,
            _("Information is not available"),
            d->users_head_style);
    return;
  }

  if (!ui) {
    memset(&ui_empty, 0, sizeof(ui_empty));
    ui = &ui_empty;
  }

  name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  l10n_setlocale(locale_id);
  notset = _("<i>Not set</i>");

  fprintf(f, "<%s>%s: %s</%s>\n",
          d->users_head_style,
          _("Detailed information for user (team)"), name,
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
          d->users_verb_style, _("Name"), d->users_verb_style, ARMOR(name));
  if (!d || d->fields[CONTEST_F_HOMEPAGE]) {
    if (!ui->homepage) {
      snprintf(buf, sizeof(buf), "%s", notset);
    } else {
      if (!strncasecmp(ui->homepage, "http://", 7)) {
        snprintf(buf, sizeof(buf), "<a href=\"%s\">%s</a>",
                 ui->homepage, ARMOR(ui->homepage));
      } else {
        snprintf(buf, sizeof(buf), "<a href=\"http://%s\">%s</a>",
                 ui->homepage, ARMOR(ui->homepage));
      }
    }
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Homepage"),
            d->users_verb_style, buf);
  }
  if (!d || d->fields[CONTEST_F_INST]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Institution"),
            d->users_verb_style, ui->inst?ARMOR(ui->inst):notset);
  }
  if (!d || d->fields[CONTEST_F_INST_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Institution (En)"),
            d->users_verb_style, ui->inst_en?ARMOR(ui->inst_en):notset);
  }
  if (!d || d->fields[CONTEST_F_INSTSHORT]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Institution (short)"),
            d->users_verb_style, ui->instshort?ARMOR(ui->instshort):notset);
  }
  if (!d || d->fields[CONTEST_F_INSTSHORT_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Institution (short) (En)"),
            d->users_verb_style,
            ui->instshort_en?ARMOR(ui->instshort_en):notset);
  }
  if ((!d || d->fields[CONTEST_F_INSTNUM]) && ui->instnum >= 0) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%d</td></tr>\n",
            d->users_verb_style, _("Institution number"),
            d->users_verb_style, ui->instnum);
  }
  if (!d || d->fields[CONTEST_F_FAC]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Faculty"),
            d->users_verb_style, ui->fac?ui->fac:notset);
  }
  if (!d || d->fields[CONTEST_F_FAC_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Faculty (En)"),
            d->users_verb_style, ui->fac_en?ARMOR(ui->fac_en):notset);
  }
  if (!d || d->fields[CONTEST_F_FACSHORT]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Faculty (short)"),
            d->users_verb_style, ui->facshort?ARMOR(ui->facshort):notset);
  }
  if (!d || d->fields[CONTEST_F_FACSHORT_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Faculty (short) (En)"),
            d->users_verb_style,
            ui->facshort_en?ARMOR(ui->facshort_en):notset);
  }
  if (!d || d->fields[CONTEST_F_CITY]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("City"),
            d->users_verb_style, ui->city?ARMOR(ui->city):notset);
  }
  if (!d || d->fields[CONTEST_F_CITY_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("City (En)"),
            d->users_verb_style, ui->city_en?ARMOR(ui->city_en):notset);
  }
  if (!d || d->fields[CONTEST_F_COUNTRY]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Country"),
            d->users_verb_style, ui->country?ARMOR(ui->country):notset);
  }
  if (!d || d->fields[CONTEST_F_COUNTRY_EN]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Country (En)"),
            d->users_verb_style,
            ui->country_en?ARMOR(ui->country_en):notset);
  }
  if (!d || d->fields[CONTEST_F_REGION]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Region"),
            d->users_verb_style, ui->region?ARMOR(ui->region):notset);
  }
  if (!d || d->fields[CONTEST_F_AREA]) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
            d->users_verb_style, _("Area"),
            d->users_verb_style, ui->area?ARMOR(ui->area):notset);
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
            d->users_verb_style, ui->languages?ARMOR(ui->languages):notset);
  }

  fprintf(f, "</table>\n");

  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (d && !d->members[role]) continue;
    if (d && d->members[role] && d->members[role]->max_count <= 0)
      continue;
    if (!(role_cnt = userlist_members_count(mm, role)))
      continue;
    fprintf(f, "<h3>%s</h3>\n", gettext(member_string_pl[role]));
    for (pers = 0; pers < role_cnt; pers++) {
      if (d && d->members[role] && pers >= d->members[role]->max_count)
        break;
      if (!(m = userlist_members_get_nth(mm, role, pers)))
        continue;
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
                d->users_verb_style, m->firstname?ARMOR(m->firstname):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FIRSTNAME_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("First name (En)"),
                d->users_verb_style,
                m->firstname_en?ARMOR(m->firstname_en):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_MIDDLENAME])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Middle name"),
                d->users_verb_style,
                m->middlename?ARMOR(m->middlename):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_MIDDLENAME_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Middle name (En)"),
                d->users_verb_style,
                m->middlename_en?ARMOR(m->middlename_en):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_SURNAME])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Family name"),
                d->users_verb_style, m->surname?ARMOR(m->surname):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_SURNAME_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Family name (En)"),
                d->users_verb_style,
                m->surname_en?ARMOR(m->surname_en):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_STATUS])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Status"),
                d->users_verb_style, gettext(member_status_string[m->status]));
      }
      if (!d || (cm && cm->fields[CONTEST_MF_GENDER])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Gender"),
                d->users_verb_style, gettext(member_gender_string[m->gender]));
      }
      if ((!d || (cm && cm->fields[CONTEST_MF_GRADE])) && m->grade >= 0) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%d</td></tr>\n",
                d->users_verb_style, _("Grade"),
                d->users_verb_style, m->grade);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_GROUP])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Group"),
                d->users_verb_style, m->group?ARMOR(m->group):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_GROUP_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Group (En)"),
                d->users_verb_style, m->group_en?ARMOR(m->group_en):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_INST])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Institution"),
                d->users_verb_style, m->inst?ARMOR(m->inst):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_INST_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Institution (En)"),
                d->users_verb_style, m->inst_en?ARMOR(m->inst_en):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_INSTSHORT])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Institution (short)"),
                d->users_verb_style, m->instshort?ARMOR(m->instshort):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_INSTSHORT_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Institution (short) (En)"),
                d->users_verb_style,
                m->instshort_en?ARMOR(m->instshort_en):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FAC])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Faculty"),
                d->users_verb_style, m->fac?ARMOR(m->fac):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FAC_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Faculty (En)"),
                d->users_verb_style, m->fac_en?ARMOR(m->fac_en):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FACSHORT])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Faculty (short)"),
                d->users_verb_style, m->facshort?ARMOR(m->facshort):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_FACSHORT_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Faculty (short) (En)"),
                d->users_verb_style,
                m->facshort_en?ARMOR(m->facshort_en):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_OCCUPATION])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Occupation"),
                d->users_verb_style,
                m->occupation?ARMOR(m->occupation):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_OCCUPATION_EN])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Occupation (En)"),
                d->users_verb_style,
                m->occupation_en?ARMOR(m->occupation_en):notset);
      }
      if (!d || (cm && cm->fields[CONTEST_MF_DISCIPLINE])) {
        fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n",
                d->users_verb_style, _("Discipline"),
                d->users_verb_style,
                m->discipline?ARMOR(m->discipline):notset);
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

  l10n_resetlocale();
  html_armor_free(&ab);
}

static void
do_list_users(FILE *f, int contest_id, const struct contest_desc *d,
              int locale_id,
              int user_id, unsigned long flags,
              unsigned char *url, unsigned char *srch)
{
  const struct userlist_user *u;
  const struct userlist_user_info *ui;
  const struct userlist_contest *c;
  const struct contest_desc *cnts;
  int i, j;
  const unsigned char *s;
  unsigned char buf[1024];
  const unsigned char *table_format = 0, *table_legend = 0;
  unsigned char **format_s = 0, **legend_s = 0;
  int legend_n = 0, format_n = 0;
  struct sformat_extra_data sformat_extra;
  ptr_iterator_t iter;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  /* add additional filters */
  /* add additional sorts */

  l10n_setlocale(locale_id);
  iter = default_get_info_list_iterator(contest_id,
                                        USERLIST_UC_LOCKED
                                        | USERLIST_UC_BANNED
                                        | USERLIST_UC_DISQUALIFIED);
  if (!iter || !iter->has_next(iter)) {
    fprintf(f, "<p%s>%s</p>\n",
            d->users_par_style, _("No users registered for this contest"));
    l10n_resetlocale();
    if (iter) iter->destroy(iter);
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
      fprintf(f, "<td%s><b>%s</b></td>", d->users_table_style,
              ARMOR(legend_s[j]));
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

  for (i = 1; iter->has_next(iter); iter->next(iter), i++) {
    fprintf(f, "<tr><td%s>%d</td>", d->users_table_style, i);

    u = (const struct userlist_user*) iter->get(iter);
    ui = userlist_get_user_info(u, contest_id);
    if (!(c = userlist_get_user_contest(u, contest_id))) continue;

    if (table_format) {
      for (j = 0; j < format_n; j++) {
        sformat_message(buf, sizeof(buf), 0, format_s[j], 0, 0, 0, 0, 0,
                        u, cnts, &sformat_extra);
        if (!*buf) {
          fprintf(f, "<td%s>&nbsp;</td>", d->users_table_style);
        } else {
          s = ARMOR(buf);
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
      }
    } else {
      fprintf(f, "<td%s>%d</td>", d->users_table_style, u->id);
      s = 0;
      if (ui) s = ui->name;
      if (!s) {
        fprintf(f, "<td%s>&nbsp;</td>", d->users_table_style);
      } else if (!url) {
        fprintf(f, "<td%s>%s</td>", d->users_table_style, ARMOR(s));
      } else {
        fprintf(f, "<td%s><a href=\"%s?user_id=%d", d->users_table_style,
                url, u->id);
        if (contest_id > 0) fprintf(f, "&contest_id=%d", contest_id);
        if (locale_id > 0) fprintf(f, "&locale_id=%d", locale_id);
        fprintf(f, "\">%s</a></td>", ARMOR(s));
      }
      s = 0;
      if (ui) {
        if (!locale_id) {
          s = ui->instshort_en;
          if (!s) s = ui->instshort;
        } else {
          s = ui->instshort;
          if (!s) s = ui->instshort_en;
        }
      }
      if (!s) s = "&nbsp;";
      else s = ARMOR(s);
      fprintf(f, "<td%s>%s</td>", d->users_table_style, s);
      s = 0;
      if (ui) {
        if (!locale_id) {
          s = ui->facshort_en;
          if (!s) s = ui->facshort;
        } else {
          s = ui->facshort;
          if (!s) s = ui->facshort_en;
        }
      }
      if (!s) s = "&nbsp;";
      else s = ARMOR(s);
      fprintf(f, "<td%s>%s</td>", d->users_table_style, s);
    }
    fprintf(f, "<td%s>%s</td>", d->users_table_style,
            gettext(status_str_map[c->status]));
    fprintf(f, "</tr>\n");
    default_unlock_user(u);
  }
  fprintf(f, "</table>\n");
  l10n_resetlocale();
  format_s = free_table_spec(format_n, format_s);
  legend_s = free_table_spec(legend_n, legend_s);
  iter->destroy(iter);
  html_armor_free(&ab);
}

static void
do_dump_database(FILE *f, int contest_id, const struct contest_desc *d,
                 int html_flag)
{
  const struct userlist_user *u;
  const struct userlist_contest *c;
  const struct userlist_member *m;
  const struct userlist_members *mm;
  unsigned char *notset = 0, *banstr = 0, *invstr = 0, *statstr = 0;
  int role, pers, pers_tot, role_cnt;
  const struct userlist_user_info *ui;
  ptr_iterator_t iter;
  unsigned char dbuf[64];

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
    mm = 0;
    if (ui) mm = ui->members;

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
      if ((role_cnt = userlist_members_count(mm, role)) <= 0)
        continue;
      for (pers = 0; pers < role_cnt; pers++) {
        unsigned char nbuf[32] = { 0 };
        unsigned char *lptr = nbuf;

        if (!(m = userlist_members_get_nth(mm, role, pers)))
          continue;
        if (role == CONTEST_M_CONTESTANT || role == CONTEST_M_RESERVE) {
          snprintf(nbuf, sizeof(nbuf), "%d", m->grade);
          lptr = nbuf;
        } else {
          lptr = m->occupation;
        }

        pers_tot++;
        fprintf(f, ";%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%d;%s;%s;%s;%s;%s;%s;%s;%s;%s",
                u->id, u->login, ui?ui->name:notset, u->email,
                (ui && ui->inst)?ui->inst:notset,
                (ui && ui->inst_en)?ui->inst_en:notset,
                (ui && ui->instshort)?ui->instshort:notset,
                (ui && ui->instshort_en)?ui->instshort_en:notset,
                (ui && ui->fac)?ui->fac:notset,
                (ui && ui->fac_en)?ui->fac_en:notset,
                (ui && ui->facshort)?ui->facshort:notset,
                (ui && ui->facshort_en)?ui->facshort_en:notset,
                (ui && ui->city)?ui->city:notset,
                (ui && ui->city_en)?ui->city_en:notset,
                (ui && ui->country)?ui->country:notset,
                (ui && ui->country_en)?ui->country_en:notset,
                (ui && ui->region)?ui->region:notset,
                (ui && ui->location)?ui->location:notset,
                (ui && ui->printer_name)?ui->printer_name:notset,
                (ui && ui->languages)?ui->languages:notset,
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
        if (role == CONTEST_M_CONTESTANT || role == CONTEST_M_RESERVE) {
          dbuf[0] = 0;
          if (m->birth_date)
            userlist_unparse_date_2(dbuf, sizeof(dbuf), m->birth_date, 0);
          fprintf(f, ";%s", dbuf);
          dbuf[0] = 0;
          if (m->entry_date)
            userlist_unparse_date_2(dbuf, sizeof(dbuf), m->entry_date, 0);
          fprintf(f, ";%s", dbuf);
          dbuf[0] = 0;
          if (m->graduation_date)
            userlist_unparse_date_2(dbuf, sizeof(dbuf), m->graduation_date, 0);
          fprintf(f, ";%s", dbuf);
        }
        fprintf(f, "\n");
      }
    }
    if (!pers_tot) {
      fprintf(f, ";%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n",
              u->id, u->login, ui?ui->name:notset, u->email,
              (ui && ui->inst)?ui->inst:notset,
              (ui && ui->inst_en)?ui->inst_en:notset,
              (ui && ui->instshort)?ui->instshort:notset,
              (ui && ui->instshort_en)?ui->instshort_en:notset,
              (ui && ui->fac)?ui->fac:notset,
              (ui && ui->fac_en)?ui->fac_en:notset,
              (ui && ui->facshort)?ui->facshort:notset,
              (ui && ui->facshort_en)?ui->facshort_en:notset,
              (ui && ui->city)?ui->city:notset,
              (ui && ui->city_en)?ui->city_en:notset,
              (ui && ui->country)?ui->country:notset,
              (ui && ui->country_en)?ui->country_en:notset,
              (ui && ui->region)?ui->region:notset,
              (ui && ui->location)?ui->location:notset,
              (ui && ui->printer_name)?ui->printer_name:notset,
              (ui && ui->languages)?ui->languages:notset,
              statstr, invstr, banstr,
              "", "", "", "", "", "", "");
    }
    default_unlock_user(u);
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

    fprintf(f, ";%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n",
            u->id, u->login, ui?ui->name:notset, u->email,
            (ui && ui->inst)?ui->inst:notset,
            (ui && ui->inst_en)?ui->inst_en:notset,
            (ui && ui->instshort)?ui->instshort:notset,
            (ui && ui->instshort_en)?ui->instshort_en:notset,
            (ui && ui->fac)?ui->fac:notset,
            (ui && ui->fac_en)?ui->fac_en:notset,
            (ui && ui->facshort)?ui->facshort:notset,
            (ui && ui->facshort_en)?ui->facshort_en:notset,
            (ui && ui->city)?ui->city:notset,
            (ui && ui->city_en)?ui->city_en:notset,
            (ui && ui->country)?ui->country:notset,
            (ui && ui->country_en)?ui->country_en:notset,
            (ui && ui->region)?ui->region:notset,
            (ui && ui->location)?ui->location:notset,
            (ui && ui->printer_name)?ui->printer_name:notset,
            (ui && ui->languages)?ui->languages:notset);
    default_unlock_user(u);
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
  const struct contest_desc *cnts = 0;
  int exp_len, url_len, srch_len;
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
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

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
  close_memstream(f); f = 0;

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
  const struct contest_desc *cnts = 0;
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

  if (is_judge(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_DUMP_USERS, logbuf) < 0) return;

  if (!(f = open_memstream(&html_ptr, &html_size))) {
    err("%s -> open_memstream failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_dump_database(f, data->contest_id, cnts, data->html_flag);
  close_memstream(f); f = 0;

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

  if (is_judge(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_DUMP_USERS, logbuf) < 0) return;

  if (!(f = open_memstream(&html_ptr, &html_size))) {
    err("%s -> open_memstream failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_dump_whole_database(f, data->contest_id, cnts, data->html_flag);
  close_memstream(f); f = 0;

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
cmd_map_contest(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *ex = 0;
  size_t out_size;
  struct userlist_pk_contest_mapped *out;
  int errcode;
  unsigned char logbuf[1024];

  snprintf(logbuf, sizeof(logbuf), "MAP_CONTEST: %d, %d",
           p->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;
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
  info("%s -> OK, %d", logbuf, (int) ex->shm_key);
}

// just assigns the connection user_id by the system user_id
static void
cmd_admin_process(struct client_state *p, int pkt_len,
                  struct userlist_packet *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  const struct userlist_user_info *ui;
  unsigned char *login, *name = 0, *login_ptr, *name_ptr;
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

  const unsigned char *ejudge_login = ejudge_cfg_user_map_find_uid(config, p->peer_uid);
  if (!ejudge_login) {
    err("%s -> user is not found in the user id map", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "ADMIN_PROCESS: %d, %d, %s",
           p->peer_pid, p->peer_uid, ejudge_login);

  if ((user_id = default_get_user_by_login(ejudge_login)) <= 0) {
    err("%s -> local user does not exist", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  p->user_id = user_id;
  p->priv_level = PRIV_LEVEL_ADMIN;

  snprintf(logbuf, sizeof(logbuf), "ADMIN_PROCESS: %d, %d, %d",
           p->peer_pid, p->peer_uid, p->user_id);

  if (default_get_user_info_2(user_id, 0, &u, &ui) < 0 || !u) {
    err("%s -> local user does not exist", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  login = u->login;
  if (!login) login = "";
  if (ui) name = ui->name;
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
  const unsigned char *notset = "&nbsp;";

  fprintf(log, "<table border=\"1\"><tr><th>User ID</th><th>User Login</th><th>User Name</th><th>New User Login Password</th><th>Location</th></tr>\n");

  for (iter = default_get_standings_list_iterator(contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    ui = userlist_get_user_info(u, contest_id);
    if (!(c = userlist_get_user_contest(u, contest_id))) {
      default_unlock_user(u);
      continue;
    }

    // do not change password for privileged users
    if (is_privileged_user(u) >= 0) {
      default_unlock_user(u);
      continue;
    }

    // also do not change password for invisible, banned, locked
    // or disqualified users
    if ((c->flags & USERLIST_UC_NOPASSWD)) {
      default_unlock_user(u);
      continue;
    }

    default_unlock_user(u);
    default_remove_user_cookies(u->id);
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_reg_passwd(u->id, USERLIST_PWD_PLAIN, buf, cur_time);

  // html table header
    fprintf(log, "<tr><td><b>User ID</b></td><td><b>User Login</b></td><td><b>User Name</b></td><td><b>New User Login Password</b></td><td><b>Location</b></td></tr>\n");
    fprintf(log, "<tr><td>%d</td><td>%s</td><td>%s</td><td><tt>%s</tt></td><td><tt>%s</tt></td></tr>\n",
            u->id, u->login, (ui && ui->name)?ui->name:notset, buf, (ui && ui->location)?ui->location:notset);
  }
  fprintf(log, "</table>\n");
}

static void
cmd_generate_register_passwords(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  char *log_ptr = 0;
  size_t log_size = 0;
  FILE *f = 0;
  struct client_state *q = 0;
  const struct contest_desc *cnts = 0;
  int errcode;
  unsigned char logbuf[1024];

  snprintf(logbuf, sizeof(logbuf), "GENERATE_REGISTER_PASSWORDS: %d, %d",
           p->user_id, data->contest_id);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;

  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    CONN_BAD("two client file descriptors required");
    return;
  }
  if (!(f = open_memstream(&log_ptr, &log_size))) {
    err("%s -> open_memstream failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_generate_passwd(data->contest_id, f);
  close_memstream(f); f = 0;

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

/* quiet password regeneration */
static void
cmd_generate_register_passwords_2(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  const struct userlist_user *u;
  const struct userlist_contest *c;
  unsigned char buf[16];
  ptr_iterator_t iter;
  const struct contest_desc *cnts;
  int errcode;
  unsigned char logbuf[1024];

  snprintf(logbuf, sizeof(logbuf), "GENERATE_REGISTER_PASSWORDS_2: %d, %d",
           p->user_id, data->contest_id);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }
  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;

  for (iter = default_get_standings_list_iterator(data->contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    if (!(c = userlist_get_user_contest(u, data->contest_id))) {
      default_unlock_user(u);
      continue;
    }

    // do not change password for privileged users
    if (is_privileged_user(u) >= 0) {
      default_unlock_user(u);
      continue;
    }

    // also do not change password for invisible, banned or locked users
    if ((c->flags & USERLIST_UC_NOPASSWD)) {
      default_unlock_user(u);
      continue;
    }

    default_unlock_user(u);
    default_remove_user_cookies(u->id);
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_reg_passwd(u->id, USERLIST_PWD_PLAIN, buf, cur_time);
  }
  update_userlist_table(data->contest_id);
  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
}

/* quiet password regeneration */
static void
cmd_generate_team_passwords_2(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  const struct userlist_user *u;
  const struct userlist_contest *c;
  unsigned char buf[16];
  ptr_iterator_t iter;
  const struct contest_desc *cnts = NULL;
  unsigned char logbuf[1024];
  int errcode = 0;

  snprintf(logbuf, sizeof(logbuf), "GENERATE_TEAM_PASSWORDS_2: %d, %d",
           p->user_id, data->contest_id);

  if ((errcode = contests_get(data->contest_id, &cnts)) < 0) {
    err("%s -> invalid contest: %s", logbuf, contests_strerror(-errcode));
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  if (is_admin(p, logbuf) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  for (iter = default_get_standings_list_iterator(data->contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    if (!(c = userlist_get_user_contest(u, data->contest_id))) {
      default_unlock_user(u);
      continue;
    }

    // do not change password for privileged users
    if (is_privileged_user(u) >= 0) {
      default_unlock_user(u);
      continue;
    }

    // also do not change password for invisible, banned or locked users
    if ((c->flags & USERLIST_UC_NOPASSWD)) {
      default_unlock_user(u);
      continue;
    }

    default_unlock_user(u);
    default_remove_user_cookies(u->id);
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_team_passwd(u->id, data->contest_id, USERLIST_PWD_PLAIN,
                            buf, cur_time, NULL);
  }
  update_userlist_table(data->contest_id);
  info("%s -> OK", logbuf);
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
  const unsigned char *notset = "&nbsp;";

  fprintf(log, "<table border=\"1\"><tr><th>User ID</th><th>User Login</th><th>User Name</th><th>New User Password</th><th>Location</th></tr>\n");
  for (iter = default_get_standings_list_iterator(contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    ui = userlist_get_user_info(u, contest_id);
    if (!(c = userlist_get_user_contest(u, contest_id))) {
      default_unlock_user(u);
      continue;
    }

    // do not change password for privileged users
    if (is_privileged_user(u) >= 0) {
      default_unlock_user(u);
      continue;
    }

    // also do not change password for invisible, banned or locked users
    if ((c->flags & USERLIST_UC_NOPASSWD)) {
      default_unlock_user(u);
      continue;
    }

    default_unlock_user(u);
    default_remove_user_cookies(u->id);
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_team_passwd(u->id, contest_id, USERLIST_PWD_PLAIN,
                            buf, cur_time, NULL);

  // html table header
    fprintf(log, "<tr><td><b>User ID</b></td><td><b>User Login</b></td><td><b>User Name</b></td><td><b>New User Password</b></td><td><b>Location</b></td></tr>\n");
    fprintf(log, "<tr><td>%d</td><td>%s</td><td>%s</td><td><tt>%s</tt></td><td><tt>%s</tt></td></tr>\n",
            u->id, u->login, (ui && ui->name)?ui->name:notset, buf, (ui && ui->location)?ui->location:notset);
  }
  fprintf(log, "</table>\n");
}

static void
cmd_generate_team_passwords(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  char *log_ptr = 0;
  size_t log_size = 0;
  FILE *f = 0;
  struct client_state *q = 0;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];

  snprintf(logbuf, sizeof(logbuf), "GENERATE_TEAM_PASSWORDS: %d, %d",
           p->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    CONN_BAD("two client file descriptors required");
    return;
  }
  if (!(f = open_memstream(&log_ptr, &log_size))) {
    err("%s -> open_memstream failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_generate_team_passwd(data->contest_id, f);
  close_memstream(f); f = 0;

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
    if (!(c = userlist_get_user_contest(u, contest_id))) {
      default_unlock_user(u);
      continue;
    }

    // do not change password for privileged users
    if (is_privileged_user(u) >= 0) {
      default_unlock_user(u);
      continue;
    }

    // also do not change password for invisible, banned or locked users
    if ((c->flags & USERLIST_UC_NOPASSWD)) {
      default_unlock_user(u);
      continue;
    }

    default_unlock_user(u);
    default_clear_team_passwd(u->id, contest_id, NULL);
    default_remove_user_cookies(u->id);
  }
}

static void
cmd_clear_team_passwords(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];

  snprintf(logbuf, sizeof(logbuf), "CLEAR_TEAM_PASSWORDS: %d, %d",
           p->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  do_clear_team_passwords(data->contest_id);
  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
}

static void
cmd_get_contest_name(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  struct userlist_pk_xml_data *out = 0;
  const struct contest_desc *cnts = 0;
  int out_size = 0, name_len = 0;
  int errcode;
  unsigned char logbuf[1024];

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
  const struct contest_desc *c = 0;
  const struct userlist_contest *uc = 0;
  int bit;
  unsigned char logbuf[1024];

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf),
           "EDIT_REGISTRATION: %d, %d, %d, %d, %d, %08x",
           p->user_id, data->user_id, data->contest_id, data->new_status,
           data->flags_cmd, data->new_flags);

  if (is_judge(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &c) < 0) return;

  if (default_get_user_info_3(data->user_id, data->contest_id, &u, 0, &uc) < 0
      || !u){
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
  if (data->flags_cmd < 0 || data->flags_cmd > 4) {
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
    bit = OPCAP_DELETE_REG;
    if (is_privileged_cnts_user(u, c) >= 0) bit = OPCAP_PRIV_DELETE_REG;
    if (is_cnts_capable(p, c, bit, logbuf) < 0) return;
    default_remove_registration(data->user_id, data->contest_id);
  } else {
    bit = OPCAP_EDIT_REG;
    if (is_privileged_cnts_user(u, c) >= 0) bit = OPCAP_PRIV_EDIT_REG;
    if (is_cnts_capable(p, c, bit, logbuf) < 0) return;

    if (data->new_status != -1) {
      default_set_reg_status(data->user_id, data->contest_id, data->new_status);
    }
    default_set_reg_flags(data->user_id, data->contest_id,
                          data->flags_cmd, data->new_flags);
    if (!(data->new_flags & USERLIST_UC_PRIVILEGED) && !(data->new_flags & USERLIST_UC_INCOMPLETE))
      default_check_user_reg_data(data->user_id, data->contest_id);
  }
  update_userlist_table(data->contest_id);
  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
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

  if (is_admin(p, logbuf) < 0) return;

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

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
  const struct contest_desc *cnts;
  int r, reply_code = ULS_OK, cloned_flag = 0, bit;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "PRIV_DELETE_MEMBER: %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id, data->serial);

  if (is_judge_or_same_user(p, data->user_id, data->contest_id, logbuf) < 0)
    return;
  if (data->contest_id) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  if (data->user_id != p->user_id) {
    bit = OPCAP_EDIT_USER;
    if (is_privileged_cnts_user(u, cnts) >= 0) bit = OPCAP_PRIV_EDIT_USER;
    if (is_dbcnts_capable(p, cnts, bit, logbuf) < 0) return;
  }

  r = default_remove_member(data->user_id, data->contest_id, data->serial,
                            cur_time, &cloned_flag);
  if (r < 0) {
    err("%s -> member removal failed", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_DELETE);
    return;
  }
  default_check_user_reg_data(data->user_id, data->contest_id);
  if (r == 1) {
    update_userlist_table(data->contest_id);
  }
  if (cloned_flag) reply_code = ULS_CLONED;
  send_reply(p, reply_code);
  info("%s -> OK, %d", logbuf, reply_code);
}

static void
cmd_delete_cookie(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];
  unsigned char cbuf[64];
  const struct userlist_user *u;
  const struct userlist_cookie *c;

  snprintf(logbuf, sizeof(logbuf), "DELETE_COOKIE: %d, %d, %s",
           p->user_id, data->user_id,
           xml_unparse_full_cookie(cbuf, sizeof(cbuf), &data->cookie, &data->client_key));

  if (is_judge(p, logbuf) < 0) return;

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  if (is_privileged_user(u) >= 0) {
    if (is_db_capable(p, OPCAP_PRIV_EDIT_USER, logbuf) < 0) return;
  } else {
    if (is_db_capable(p, OPCAP_EDIT_USER, logbuf) < 0) return;
  }

  if (!data->cookie) {
    default_remove_user_cookies(data->user_id);
  } else {
    if (default_get_cookie(data->cookie, data->client_key, &c) < 0) {
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
  const struct contest_desc *cnts;
  int r, capbit;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "DELETE_USER_INFO: %d, %d, %d",
           p->user_id, data->user_id, data->contest_id);

  if (is_judge(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  capbit = OPCAP_EDIT_USER;
  if (is_privileged_cnts_user(u, cnts) >= 0) capbit = OPCAP_PRIV_EDIT_USER;
  if (is_dbcnts_capable(p, cnts, capbit, logbuf) < 0) return;

  if ((r=default_remove_user_contest_info(data->user_id, data->contest_id))== 1)
    update_userlist_table(data->contest_id);
  default_check_user_reg_data(data->user_id, data->contest_id);
  send_reply(p, ULS_OK);
  info("%s -> OK, %d", logbuf, r);
}

static void
cmd_delete_field(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  const struct userlist_user *u;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  int r, reply_code = ULS_OK, cloned_flag = 0, bit = 0;

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "DELETE_FIELD: %d, %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id,
           data->serial, data->field);

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (data->contest_id != 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  /*
  if (check_editing_caps(p->user_id, data->user_id, u, data->contest_id) < 0) {
    err("%s -> no capability to edit user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  */

  if (data->field==USERLIST_NN_PASSWD || data->field==USERLIST_NC_TEAM_PASSWD) {
    bit = OPCAP_EDIT_PASSWD;
    if (is_privileged_cnts_user(u, cnts) >= 0) bit = OPCAP_PRIV_EDIT_PASSWD;
  } else {
    bit = OPCAP_EDIT_USER;
    if (is_privileged_cnts_user(u, cnts) >= 0) bit = OPCAP_PRIV_EDIT_USER;
  }
  if (data->field >= USERLIST_NN_FIRST && data->field < USERLIST_NN_LAST) {
    if (is_db_capable(p, bit, logbuf) < 0) return;
  } else {
    if (is_dbcnts_capable(p, cnts, bit, logbuf) < 0) return;
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
  default_check_user_reg_data(data->user_id, data->contest_id);
  if (cloned_flag) reply_code = ULS_CLONED;
  send_reply(p, reply_code);
  info("%s -> OK, %d", logbuf, r);
}

static void
cmd_edit_field(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  const struct userlist_user *u;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  int r = 0, reply_code = ULS_OK, cloned_flag = 0, bit;

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "EDIT_FIELD: %d, %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id,
           data->serial, data->field);

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id > 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  /*
  if (check_editing_caps(p->user_id, data->user_id, u, data->contest_id) < 0) {
    err("%s -> no capability to edit user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  */

  if (data->field==USERLIST_NN_PASSWD || data->field==USERLIST_NC_TEAM_PASSWD) {
    bit = OPCAP_EDIT_PASSWD;
    if (is_privileged_cnts_user(u, cnts) >= 0) bit = OPCAP_PRIV_EDIT_PASSWD;
  } else {
    bit = OPCAP_EDIT_USER;
    if (is_privileged_cnts_user(u, cnts) >= 0) bit = OPCAP_PRIV_EDIT_USER;
  }
  if (data->field >= USERLIST_NN_FIRST && data->field < USERLIST_NN_LAST) {
    if (is_db_capable(p, bit, logbuf) < 0) return;
  } else {
    if (is_dbcnts_capable(p, cnts, bit, logbuf) < 0) return;
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
  default_check_user_reg_data(data->user_id, data->contest_id);
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
cmd_create_user(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  struct userlist_pk_login_ok out;
  unsigned char logbuf[1024];
  int serial = -1, user_id;
  unsigned char buf[64];
  unsigned char *login_ptr = 0;

  snprintf(logbuf, sizeof(logbuf), "CREATE_USER: %d, %s", p->user_id,
           data->data);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (is_db_capable(p, OPCAP_CREATE_USER, logbuf) < 0) return;

  if (data->value_len > 0) {
    if (default_get_user_by_login(data->data) >= 0) {
      err("%s -> login already exists", logbuf);
      send_reply(p, -ULS_ERR_LOGIN_USED);
      return;
    }
    login_ptr = data->data;
  } else {
    if (dflt_iface->try_new_login) {
      serial = 0;
      if (default_try_new_login(buf, sizeof(buf), "New_login_%d", serial, 1) < 0) {
        err("%s -> database error", logbuf);
        send_reply(p, -ULS_ERR_DB_ERROR);
        return;
      }
    } else {
      do {
        serial++;
        if (!serial) {
          snprintf(buf, sizeof(buf), "New_login");
        } else {
          snprintf(buf, sizeof(buf), "New_login_%d", serial);
        }
      } while (default_get_user_by_login(buf) >= 0);
    }
    login_ptr = buf;
  }

  if ((user_id = default_new_user(login_ptr, "N/A", USERLIST_PWD_PLAIN, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0)) <= 0) {
    err("%s -> cannot create user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  default_touch_login_time(user_id, 0, cur_time);

  info("%s -> new user %d", logbuf, user_id);
  memset(&out, 0, sizeof(out));
  out.reply_id = ULS_LOGIN_OK;
  out.user_id = user_id;
  enqueue_reply_to_client(p, sizeof(out), &out);
  return;
}

static void
cmd_create_member(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];
  const struct contest_desc *cnts = 0;
  const struct userlist_user *u;
  int cloned_flag = 0, m = 0, bit;
  struct userlist_pk_login_ok out;

  if (data->serial < -1 || data->serial >= CONTEST_LAST_MEMBER) {
    err("%s -> invalid role", logbuf);
    send_reply(p, -ULS_ERR_BAD_MEMBER);
    return;
  }

  if (data->user_id <= 0 && p->user_id > 0) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "CREATE_MEMBER: %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id, data->serial);

  if (is_judge_or_same_user(p, data->user_id, data->contest_id, logbuf) < 0)
    return;
  if (data->contest_id) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0)
      return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (p->user_id != data->user_id) {
    bit = OPCAP_EDIT_USER;
    if (is_privileged_cnts_user(u, cnts) >= 0) bit = OPCAP_PRIV_EDIT_USER;
    if (is_dbcnts_capable(p, cnts, bit, logbuf) < 0) return;
  }

  if ((m = default_new_member(data->user_id, data->contest_id, data->serial,
                              cur_time, &cloned_flag)) < 0) {
    err("%s -> new member creation failed", logbuf);
    send_reply(p, -ULS_ERR_UNSPECIFIED_ERROR);
    return;
  }
  default_check_user_reg_data(data->user_id, data->contest_id);

  info("%s -> new member %d", logbuf, m);
  memset(&out, 0, sizeof(out));
  out.reply_id = ULS_LOGIN_OK;
  out.user_id = m;
  enqueue_reply_to_client(p, sizeof(out), &out);
  return;
}

/*
 * This request is sent from serve to userlist-server
 * each time client connects to the contest server.
 * Thus the regular logging is disabled just to reduce the number
 * of messages in the log.
 */

static void
cmd_get_uid_by_pid(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_get_uid_by_pid *data)
{
  struct client_state *q = 0;
  struct userlist_pk_uid out;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (is_admin(p, "GET_UID_BY_PID") < 0) return;

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
  out.client_key = q->client_key;
  out.ip = q->ip;
  out.ssl = q->ssl;
  enqueue_reply_to_client(p, sizeof(out), &out);
}

static void
cmd_get_uid_by_pid_2(
        struct client_state *p,
        int pkt_len,
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

  if (is_admin(p, "GET_UID_BY_PID") < 0) return;

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

  if (default_get_user_info_2(q->user_id, data->contest_id, &u, &ui)<0 || !u){
    CONN_ERR("invalid login");
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  login = u->login;
  if (!login) login = "";
  if (ui) name = ui->name;
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
  out->client_key = q->client_key;
  out->ip = q->ip;
  out->ssl = q->ssl;
  out->login_len = login_len;
  out->name_len = name_len;
  strcpy(login_ptr, login);
  strcpy(name_ptr, name);
  enqueue_reply_to_client(p, out_len, out);
}

static void
cmd_is_valid_cookie(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_do_logout *data)
{
  const struct userlist_cookie *c = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }
  if (is_admin(p, "IS_VALID_COOKIE") < 0) return;
  if (is_db_capable(p, OPCAP_MAP_CONTEST, "IS_VALID_COOKIE") < 0) return;

  if (default_get_cookie(data->cookie, data->client_key, &c) < 0 || !c) {
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }
  send_reply(p, ULS_OK);
}

static void
cmd_user_op(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_register_contest *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  unsigned char buf[16];
  const struct userlist_user_info *ui;
  int reply_code = ULS_OK, cloned_flag = 0;
  const struct contest_desc *cnts = 0;

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "USER_OP: %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id, data->request_id);

  if (data->user_id != p->user_id && is_admin(p, logbuf) < 0) return;

  if (data->contest_id > 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) goto invalid_user;

  /*
  if (check_editing_caps(p->user_id, data->user_id, u, data->contest_id) < 0) {
    err("%s -> no capability to edit user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  */

  switch (data->request_id) {
  case ULS_RANDOM_PASSWD:
    if (p->user_id != data->user_id) {
      if (is_privileged_user(u) >= 0) {
        if (is_db_capable(p, OPCAP_PRIV_EDIT_PASSWD, logbuf) < 0) return;
      } else {
        if (is_db_capable(p, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
      }
    }
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_reg_passwd(data->user_id, USERLIST_PWD_PLAIN, buf, cur_time);
    break;
  case ULS_COPY_TO_REGISTER:
    if (p->user_id != data->user_id) {
      if (is_privileged_cnts_user(u, cnts) >= 0) {
        if (is_db_capable(p, OPCAP_PRIV_EDIT_PASSWD, logbuf) < 0) return;
      } else {
        if (is_db_capable(p, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
      }
      if (is_dbcnts_capable(p, cnts, OPCAP_GET_USER, logbuf) < 0) return;
    }
    if (default_get_user_info_2(data->user_id, data->contest_id, &u, &ui) < 0 || !u)
      goto invalid_user;
    if (!ui || !ui->team_passwd) goto empty_password;
    default_set_reg_passwd(data->user_id, ui->team_passwd_method,
                           ui->team_passwd, cur_time);
    break;
  case ULS_RANDOM_TEAM_PASSWD:
    if (p->user_id != data->user_id) {
      if (is_privileged_cnts_user(u, cnts) >= 0) {
        if (is_dbcnts_capable(p, cnts, OPCAP_PRIV_EDIT_PASSWD, logbuf) < 0)
          return;
      } else {
        if (is_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
      }
    }
    memset(buf, 0, sizeof(buf));
    generate_random_password(8, buf);
    default_set_team_passwd(data->user_id, data->contest_id,
                            USERLIST_PWD_PLAIN, buf, cur_time, &cloned_flag);
    break;
  case ULS_COPY_TO_TEAM:
    if (p->user_id != data->user_id) {
      if (is_privileged_cnts_user(u, cnts) >= 0) {
        if (is_dbcnts_capable(p, cnts, OPCAP_PRIV_EDIT_PASSWD, logbuf) < 0)
          return;
      } else {
        if (is_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
      }
      if (is_dbcnts_capable(p, cnts, OPCAP_GET_USER, logbuf) < 0) return;
    }
    if (!u->passwd) goto empty_password;
    default_set_team_passwd(data->user_id, data->contest_id,
                            u->passwd_method, u->passwd, cur_time,
                            &cloned_flag);
    break;
  case ULS_FIX_PASSWORD:
    if (p->user_id != data->user_id) {
      if (is_privileged_cnts_user(u, cnts) >= 0) {
        if (is_db_capable(p, OPCAP_PRIV_EDIT_PASSWD, logbuf) < 0) return;
      } else {
        if (is_db_capable(p, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
      }
      if (is_dbcnts_capable(p, cnts, OPCAP_GET_USER, logbuf) < 0) return;
    }
    if (default_get_user_info_2(data->user_id, data->contest_id, &u, &ui) < 0 || !u)
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
cmd_copy_user_info(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  const struct contest_desc *cnts = 0, *cnts2 = 0;
  int reply_code = ULS_OK, copy_passwd_flag = 1;

  // data->contest_id --- source contest
  // data->serial     --- destination contest

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "COPY_USER_INFO: %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id, data->serial);

  if (is_judge(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  if (full_get_contest(p, logbuf, &data->serial, &cnts2) < 0) return;

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) goto invalid_user;

  // GET_USER for reading + {PRIV_}EDIT_PASSWD for password reading
  // {PRIV_}EDIT_USER + {PRIV_}EDIT_PASSWD
  if (is_dbcnts_capable(p, cnts, OPCAP_GET_USER, logbuf) < 0) return;
  if (is_privileged_cnts2_user(u, cnts, cnts2) >= 0) {
    if (is_dbcnts_capable(p, cnts2, OPCAP_PRIV_EDIT_USER, logbuf) < 0) return;
    if (check_dbcnts_capable(p, cnts, OPCAP_PRIV_EDIT_PASSWD) < 0)
      copy_passwd_flag = 0;
    if (check_dbcnts_capable(p, cnts2, OPCAP_PRIV_EDIT_PASSWD) < 0)
      copy_passwd_flag = 0;
  } else {
    if (is_dbcnts_capable(p, cnts2, OPCAP_EDIT_USER, logbuf) < 0) return;
    if (check_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD) < 0)
      copy_passwd_flag = 0;
    if (check_dbcnts_capable(p, cnts2, OPCAP_EDIT_PASSWD) < 0)
      copy_passwd_flag = 0;
  }

  default_copy_user_info(data->user_id, data->contest_id, data->serial,
                         copy_passwd_flag, cur_time, cnts2);

  default_check_user_reg_data(data->user_id, data->contest_id);
  info("%s -> OK", logbuf);
  send_reply(p, reply_code);
  return;

 invalid_user:
  err("%s -> invalid user", logbuf);
  send_reply(p, -ULS_ERR_BAD_UID);
  return;
}

static void
cmd_copy_all(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];

  int user_id = data->user_id;
  if (user_id <= 0) user_id = p->user_id;
  int from_contest_id = data->contest_id;
  int to_contest_id = data->serial;
  const struct contest_desc *from_cnts = NULL;
  const struct contest_desc *to_cnts = NULL;
  const struct userlist_user *u = NULL;
  const struct userlist_user_info *ui = NULL;
  const struct userlist_contest *uc = NULL;
  const struct userlist_contest *to_uc = NULL;

  snprintf(logbuf, sizeof(logbuf), "COPY_ALL: %d, %d, %d, %d",
           p->user_id, user_id, from_contest_id, to_contest_id);

  if (is_judge(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &from_contest_id, &from_cnts) < 0) return;
  if (full_get_contest(p, logbuf, &to_contest_id, &to_cnts) < 0) return;
  if (default_get_user_info_3(user_id,from_contest_id,&u,&ui,&uc) < 0 || !u) {
    err("%s -> invalid user_id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (!uc) {
    err("%s -> not registered", logbuf);
    send_reply(p, -ULS_ERR_NOT_REGISTERED);
    return;
  }
  int to_bits = OPCAP_CREATE_REG;
  if (is_privileged_cnts_user(u, to_cnts) >= 0) to_bits = OPCAP_PRIV_CREATE_REG;
  if (is_cnts_capable(p, to_cnts, to_bits, logbuf) < 0) return;

  int copy_passwd_flag = 1;
  if (is_dbcnts_capable(p, from_cnts, OPCAP_GET_USER, logbuf) < 0) return;
  if (is_privileged_cnts_user(u, from_cnts) >= 0) {
    if (check_dbcnts_capable(p, from_cnts, OPCAP_PRIV_EDIT_PASSWD) < 0)
      copy_passwd_flag = 0;
  } else {
    if (check_dbcnts_capable(p, from_cnts, OPCAP_EDIT_PASSWD) < 0)
      copy_passwd_flag = 0;
  }
  if (is_privileged_cnts_user(u, to_cnts) >= 0) {
    if (is_dbcnts_capable(p, to_cnts, OPCAP_PRIV_EDIT_USER, logbuf) < 0) return;
    if (check_dbcnts_capable(p, to_cnts, OPCAP_PRIV_EDIT_PASSWD) < 0)
      copy_passwd_flag = 0;
  } else {
    if (is_dbcnts_capable(p, to_cnts, OPCAP_EDIT_USER, logbuf) < 0) return;
    if (check_dbcnts_capable(p, to_cnts, OPCAP_EDIT_PASSWD) < 0)
      copy_passwd_flag = 0;
  }

  int r = default_register_contest(user_id, to_contest_id, uc->status, uc->flags, cur_time, &to_uc);
  if (r < 0) {
    err("%s -> registration failed", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  default_copy_user_info(user_id, from_contest_id, to_contest_id,
                         copy_passwd_flag, cur_time, to_cnts);

  default_check_user_reg_data(user_id, to_contest_id);

  if (to_uc && to_uc->status == USERLIST_REG_OK) {
    update_userlist_table(to_contest_id);
  }

  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
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
  const struct contest_desc *cnts = 0;
  const unsigned char *name = 0;

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

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id > 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf)) return;

  if (data->login_length <= 0) {
    err("%s -> EMPTY LOGIN", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }
  if ((user_id = default_get_user_by_login(login_ptr)) <= 0
      || default_get_user_info_2(user_id, data->contest_id, &u, &ui) < 0 || !u) {
    err("%s -> NO SUCH USER", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  login_len = strlen(u->login);
  name_len = 0;
  name_len = strlen(name);
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
  strcpy(name_ptr, name);
  enqueue_reply_to_client(p, out_size, out);
}

static void
cmd_lookup_user_id(struct client_state *p,
                   int pkt_len,
                   struct userlist_pk_get_user_info *data)
{
  struct userlist_pk_login_ok *out;
  size_t out_size, login_len, name_len;
  unsigned char logbuf[1024];
  unsigned char *login_ptr, *name_ptr;
  const struct userlist_user *u = 0;
  const struct userlist_user_info *ui;
  const struct contest_desc *cnts = 0;
  const unsigned char *name = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet length is too small: %d, must be >= %zu",
             pkt_len, sizeof(*data));
    return;
  }

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "LOOKUP_USER_ID: %d, %d", data->user_id,
           data->contest_id);

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id > 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf)) return;

  if (default_get_user_info_2(data->user_id, data->contest_id, &u, &ui) < 0 || !u) {
    err("%s -> NO SUCH USER", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (ui) name = ui->name;
  if (!name || !*name) name = u->login;
  if (!name) name = "";

  login_len = strlen(u->login);
  name_len = 0;
  name_len = strlen(name);
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
  strcpy(name_ptr, name);
  enqueue_reply_to_client(p, out_size, out);
}

#define FAIL(code,str) do { errmsg = (str); errcode = -(code); goto fail; } while (0)

static void
cmd_get_cookie(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_check_cookie *data)
{
  const struct userlist_user *u = 0;
  const struct userlist_cookie *cookie = 0;
  struct userlist_pk_login_ok *out;
  const struct userlist_contest *c = 0;
  const struct userlist_user_info *ui = 0;
  const struct contest_desc *cnts = 0;
  size_t login_len, name_len, out_size;
  unsigned char *login_ptr, *name_ptr;
  time_t current_time = time(0);
  ej_tsc_t tsc1, tsc2;
  unsigned char logbuf[1024];
  unsigned char cbuf[64];
  unsigned char *user_name = 0, *user_login = 0;
  int new_contest_id = 0;
  const unsigned char *errmsg = 0;
  int errcode = 0;
  int cookie_contest_id;
  int cookie_locale_id;
  int cookie_priv_level;
  int cookie_role;
  int cookie_team_login;
  int user_id = 0;
  int need_touch_login_time = 0;
  int passwd_method = 0;
  int cookie_is_ws = 0;
  int cookie_is_job = 0;
  time_t cookie_expire = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  /*
  snprintf(logbuf, sizeof(logbuf),
           "GET_COOKIE: %s, %d, %llx",
           xml_unparse_ip(data->origin_ip), data->ssl, data->cookie);
  */
  logbuf[0] = 0;

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf)) return;

  /*
  if (!data->origin_ip)
    FAIL(ULS_ERR_NO_COOKIE, "origin_ip is not set");
  */

  rdtscll(tsc1);
  if (default_get_cookie(data->cookie, data->client_key, &cookie) < 0 || !cookie)
    FAIL(ULS_ERR_NO_COOKIE, "no such cookie");
  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

  new_contest_id = cookie->contest_id;
  if (cookie->contest_id > 0) {
    if (full_get_contest(p, logbuf, &new_contest_id, &cnts) < 0) return;
  }

  cookie_contest_id = cookie->contest_id;
  cookie_locale_id = cookie->locale_id;
  cookie_priv_level = cookie->priv_level;
  cookie_role = cookie->role;
  cookie_team_login = cookie->team_login;
  cookie_is_ws = cookie->is_ws;
  cookie_is_job = cookie->is_job;
  cookie_expire = cookie->expire;

  if (default_get_user_info_3(cookie->user_id, new_contest_id, &u, &ui, &c) < 0
      || !u)
    FAIL(ULS_ERR_DB_ERROR, "database error");
  user_login = u->login;
  user_id = cookie->user_id;

  if (config->enable_cookie_ip_check > 0) {
    if (ipv6cmp(&cookie->ip, &data->origin_ip) != 0 || cookie->ssl != data->ssl)
      FAIL(ULS_ERR_NO_COOKIE, "IP address mismatch");
  }
  if (current_time > cookie->expire)
    FAIL(ULS_ERR_NO_COOKIE, "cookie expired");
  switch (data->request_id) {
  case ULS_GET_COOKIE:
    if (cnts && !cnts->disable_team_password && cookie->team_login)
      FAIL(ULS_ERR_NO_COOKIE, "participation cookie");
    if (cookie->priv_level > 0 || cookie->role > 0)
      FAIL(ULS_ERR_NO_COOKIE, "invalid role");
    default_set_cookie_team_login(cookie, 0);
    cookie_team_login = 0;
    passwd_method = u->passwd_method;
    break;
  case ULS_TEAM_GET_COOKIE:
    if (!cnts)
      FAIL(ULS_ERR_NO_COOKIE, "no contest");
    if (cookie->priv_level > 0 || cookie->role > 0)
      FAIL(ULS_ERR_NO_COOKIE, "invalid role");
    if (!cnts->disable_team_password && !cookie->team_login)
      FAIL(ULS_ERR_NO_COOKIE, "registration cookie");
    if (!c || c->status != USERLIST_REG_OK || (c->flags & USERLIST_UC_BANNED)
        || (c->flags & USERLIST_UC_LOCKED))
      FAIL(ULS_ERR_CANNOT_PARTICIPATE, "NOT ALLOWED");
    if (!(c->flags & USERLIST_UC_PRIVILEGED) && (c->flags & USERLIST_UC_INCOMPLETE))
      FAIL(ULS_ERR_INCOMPLETE_REG, "INCOMPLETE REGISTRATION");
    if (ui) user_name = ui->name;
    if (!cookie->team_login) {
      need_touch_login_time = 1;
    }
    default_set_cookie_team_login(cookie, 1);
    cookie_team_login = 1;
    if (cnts->disable_team_password || !ui) {
      passwd_method = u->passwd_method;
    } else {
      passwd_method = ui->team_passwd_method;
    }
    break;
  case ULS_PRIV_GET_COOKIE:
    if (cookie->priv_level <= 0 && cookie->role <= 0)
      FAIL(ULS_ERR_NO_COOKIE, "invalid privilege level");
    if (ui) user_name = ui->name;
    break;
  case ULS_FETCH_COOKIE:
    break;
  }
  if (!user_name) user_name = user_login;
  if (!user_name) user_name = "";

  /*
  if (default_get_cookie(data->cookie, &cookie) < 0 || !cookie)
    FAIL(ULS_ERR_NO_COOKIE, "no such cookie");
  */

  login_len = strlen(user_login);
  name_len = strlen(user_name);
  out_size = sizeof(*out) + login_len + name_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  login_ptr = out->data;
  name_ptr = login_ptr + login_len + 1;
  out->cookie = data->cookie;
  out->client_key = data->client_key;
  out->reply_id = ULS_LOGIN_COOKIE;
  out->user_id = user_id;
  out->contest_id = cookie_contest_id;
  out->locale_id = cookie_locale_id;
  out->login_len = login_len;
  out->name_len = name_len;
  out->priv_level = cookie_priv_level;
  out->role = cookie_role;
  out->team_login = cookie_team_login;
  out->is_ws = cookie_is_ws;
  out->is_job = cookie_is_job;
  out->reg_status = -1;
  out->passwd_method = passwd_method;
  out->expire = cookie_expire;
  if (c) {
    out->reg_status = c->status;
    out->reg_flags = c->flags;
  }
  strcpy(login_ptr, user_login);
  strcpy(name_ptr, user_name);

  enqueue_reply_to_client(p, out_size, out);

  /*
  if (!daemon_mode) {
    CONN_INFO("%s -> OK, %d, %s, %d, %llu us", logbuf, user_id, user_login,
              out->contest_id, tsc2);
  }
  */
  if (need_touch_login_time) {
    default_touch_login_time(user_id, cookie_contest_id, 0);
  }
  return;

 fail:
  if (!errmsg) errmsg = "unspecified error";
  err("GET_COOKIE: %s, %d, %s -> %s",
      xml_unparse_ipv6(&data->origin_ip), data->ssl,
      xml_unparse_full_cookie(cbuf, sizeof(cbuf), &data->cookie, &data->client_key),
      errmsg);
  if (errcode >= 0) errcode = -ULS_ERR_NO_COOKIE;
  send_reply(p, errcode);
}

static void
cmd_set_cookie(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];
  unsigned char cbuf[64];
  const struct userlist_cookie *cookie;
  int contest_id = 0;
  const struct contest_desc *cnts = 0;

  snprintf(logbuf, sizeof(logbuf),
           "SET_COOKIE: %s, %d, %d",
           xml_unparse_full_cookie(cbuf, sizeof(cbuf), &data->cookie, &data->client_key),
           data->request_id, data->serial);

  if (is_judge(p, logbuf) < 0) return;

  if (default_get_cookie(data->cookie, data->client_key, &cookie) < 0 || !cookie) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  if (cookie->contest_id) {
    contest_id = cookie->contest_id;
    if (full_get_contest(p, logbuf, &contest_id, &cnts) < 0) return;
  }
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;

  if (default_set_cookie_locale(cookie, data->serial) < 0) {
    err("%s -> no such cookie", logbuf);
    send_reply(p, -ULS_ERR_NO_COOKIE);
    return;
  }

  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
  return;
}

static void
cmd_observer_cmd(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  unsigned char logbuf[1024];
  const struct contest_desc *cnts = 0;

  snprintf(logbuf, sizeof(logbuf), "OBSERVER: %d, %d, %d",
           p->id, data->request_id, data->contest_id);

  if (is_judge(p, logbuf) < 0) return;

  if (contests_get(data->contest_id, &cnts) < 0 || !cnts) {
    err("%s -> invalid contest_id: %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
    return;
  }

  switch (data->request_id) {
  case ULS_ADD_NOTIFY:
    add_observer(p, data->contest_id);
    break;
  case ULS_DEL_NOTIFY:
    remove_observer_2(p, data->contest_id);
    break;
  default:
    abort();
  }

  info("%s -> OK", logbuf);
  send_reply(p, ULS_OK);
  return;
}

static void
cmd_priv_set_passwd(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_set_password *data)
{
  const unsigned char *old_pwd, *new_pwd;
  unsigned char logbuf[1024];
  struct passwd_internal oldint, newint;
  const struct userlist_user *u = 0;
  const struct contest_desc *cnts = 0;
  const struct userlist_user_info *ui = 0;
  const struct userlist_contest *c = 0;
  int reply_code = ULS_OK, cloned_flag = 0, contest_id = 0;

  old_pwd = data->data;
  new_pwd = old_pwd + data->old_len + 1;

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "PRIV_SET_PASSWD: %d, %d, %d",
           data->request_id, data->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;

  if (data->old_len <= 0) {
    err("%s -> old password is empty", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(old_pwd, &oldint) < 0) {
    err("%s -> old password is invalid", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (data->new_len <= 0) {
    err("%s -> new password is empty", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(new_pwd, &newint) < 0) {
    err("%s -> new password is invalid", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  switch (data->request_id) {
  case ULS_PRIV_SET_REG_PASSWD:
    if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
      err("%s -> invalid user", logbuf);
      send_reply(p, -ULS_ERR_BAD_UID);
      return;
    }
    if (data->user_id != p->user_id) {
      if (is_privileged_user(u) >= 0) {
        if (is_db_capable(p, OPCAP_PRIV_EDIT_PASSWD, logbuf) < 0) return;
      } else {
        if (is_db_capable(p, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
      }
    }
    if (!u->passwd) {
      err("%s -> old password is not set", logbuf);
      send_reply(p, -ULS_ERR_INVALID_PASSWORD);
      return;
    }
    if (passwd_check(&oldint, u->passwd, u->passwd_method) < 0) {
      err("%s -> passwords do not match", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    passwd_convert(&newint, newint.pwd_nows, NULL, USERLIST_PWD_SHA256);
    default_set_reg_passwd(u->id, USERLIST_PWD_SHA256, newint.encoded, cur_time);
    break;

  case ULS_PRIV_SET_TEAM_PASSWD:
    contest_id = data->contest_id;
    if (contest_id > 0) {
      if (full_get_contest(p, logbuf, &contest_id, &cnts) < 0) return;
      if (cnts->disable_team_password) {
        err("%s -> team password is disabled", logbuf);
        send_reply(p, -ULS_ERR_NO_PERMS);
        return;
      }
    }

    if (default_get_user_info_3(data->user_id, contest_id, &u, &ui, &c) < 0
        || !u) {
      err("%s -> invalid user", logbuf);
      send_reply(p, -ULS_ERR_BAD_UID);
      return;
    }
    if (data->user_id != p->user_id) {
      if (is_privileged_cnts_user(u, cnts) >= 0) {
        if (is_dbcnts_capable(p, cnts, OPCAP_PRIV_EDIT_PASSWD, logbuf) < 0)
          return;
      } else {
        if (is_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
      }
    }
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

    passwd_convert(&newint, newint.pwd_nows, NULL, USERLIST_PWD_SHA256);
    default_set_team_passwd(data->user_id, contest_id, USERLIST_PWD_SHA256,
                            newint.encoded, cur_time,
                            &cloned_flag);
    if (cloned_flag) reply_code = ULS_CLONED;
    break;

  default:
    abort();
  }

  default_remove_user_cookies(data->user_id);
  send_reply(p, reply_code);
  info("%s -> OK, %d", logbuf, cloned_flag);
}

static void
cmd_priv_set_passwd_2(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_set_password *data)
{
  const unsigned char *old_pwd, *new_pwd, *admin_pwd;
  unsigned char logbuf[1024];
  struct passwd_internal newint;
  struct passwd_internal adminint;
  const struct userlist_user *u = 0;
  const struct contest_desc *cnts = 0;
  const struct userlist_user_info *ui = 0;
  const struct userlist_contest *c = 0;
  int reply_code = ULS_OK, cloned_flag = 0, contest_id = 0;

  old_pwd = data->data;
  new_pwd = old_pwd + data->old_len + 1;
  admin_pwd = new_pwd + data->new_len + 1;

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "PRIV_SET_PASSWD_2: %d, %d, %d",
           data->request_id, data->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;

  if (data->admin_user_id > 0) {
    if (!*admin_pwd) {
      err("%s -> admin password is empty", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    if (passwd_convert_to_internal(admin_pwd, &adminint) < 0) {
      err("%s -> admin password is invalid", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    if (default_get_user_info_2(data->admin_user_id, 0, &u, &ui) < 0 || !u) {
      send_reply(p, -ULS_ERR_NO_PERMS);
      err("%s -> no admin user %d", logbuf, data->admin_user_id);
      return;
    }
    if (passwd_check(&adminint, u->passwd, u->passwd_method) < 0) {
      err("%s -> WRONG ADMIN PASSWORD", logbuf);
      send_reply(p, -ULS_ERR_NO_PERMS);
      return;
    }
    u = NULL; ui = NULL;
  }

  if (data->new_len <= 0) {
    err("%s -> new password is empty", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (passwd_convert_to_internal(new_pwd, &newint) < 0) {
    err("%s -> new password is invalid", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }

  switch (data->request_id) {
  case ULS_PRIV_SET_REG_PASSWD_PLAIN:
  case ULS_PRIV_SET_REG_PASSWD_SHA1:
    if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
      err("%s -> invalid user", logbuf);
      send_reply(p, -ULS_ERR_BAD_UID);
      return;
    }
    if (data->user_id != p->user_id) {
      if (is_privileged_user(u) >= 0) {
        if (is_db_capable(p, OPCAP_PRIV_EDIT_PASSWD, logbuf) < 0) return;
      } else {
        if (is_db_capable(p, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
      }
    }

    if (data->request_id == ULS_PRIV_SET_REG_PASSWD_PLAIN) {
      default_set_reg_passwd(u->id, USERLIST_PWD_PLAIN,
                             newint.pwd_nows, cur_time);
    } else if (data->request_id == ULS_PRIV_SET_REG_PASSWD_SHA1) {
      passwd_convert(&newint, newint.pwd_nows, NULL, USERLIST_PWD_SHA256);
      default_set_reg_passwd(u->id, USERLIST_PWD_SHA256, newint.encoded, cur_time);
    } else {
      abort();
    }
    break;

  case ULS_PRIV_SET_CNTS_PASSWD_PLAIN:
  case ULS_PRIV_SET_CNTS_PASSWD_SHA1:
    contest_id = data->contest_id;
    if (contest_id > 0) {
      if (full_get_contest(p, logbuf, &contest_id, &cnts) < 0) return;
      if (cnts->disable_team_password) {
        err("%s -> team password is disabled", logbuf);
        send_reply(p, -ULS_ERR_NO_PERMS);
        return;
      }
    }

    if (default_get_user_info_3(data->user_id, contest_id, &u, &ui, &c) < 0
        || !u) {
      err("%s -> invalid user", logbuf);
      send_reply(p, -ULS_ERR_BAD_UID);
      return;
    }
    if (data->user_id != p->user_id) {
      if (is_privileged_cnts_user(u, cnts) >= 0) {
        if (is_dbcnts_capable(p, cnts, OPCAP_PRIV_EDIT_PASSWD, logbuf) < 0)
          return;
      } else {
        if (is_dbcnts_capable(p, cnts, OPCAP_EDIT_PASSWD, logbuf) < 0) return;
      }
    }
    if (contest_id > 0 && (!c || c->status != USERLIST_REG_OK)) {
      err("%s -> not registered", logbuf);
      send_reply(p, -ULS_ERR_NOT_REGISTERED);
      return;
    }

    if (data->request_id == ULS_PRIV_SET_CNTS_PASSWD_PLAIN) {
      default_set_team_passwd(data->user_id, contest_id, USERLIST_PWD_PLAIN,
                              newint.pwd_nows, cur_time,
                              &cloned_flag);
    } else if (data->request_id == ULS_PRIV_SET_CNTS_PASSWD_SHA1) {
      passwd_convert(&newint, newint.pwd_nows, NULL, USERLIST_PWD_SHA256);
      default_set_team_passwd(data->user_id, contest_id, USERLIST_PWD_SHA256,
                              newint.encoded, cur_time,
                              &cloned_flag);
    }
    if (cloned_flag) reply_code = ULS_CLONED;
    break;

  default:
    abort();
  }

  default_remove_user_cookies(data->user_id);
  send_reply(p, reply_code);
  info("%s -> OK, %d", logbuf, cloned_flag);
}

#define CSVARMOR(s)  csv_armor_buf(&ab, s)

static void
do_get_database(FILE *f, int contest_id, const struct contest_desc *cnts)
{
  const struct userlist_user *u;
  const struct userlist_contest *c;
  const struct userlist_member *m;
  const struct contest_member *cm;
  int role, pers, pers_tot, need_members = 0, i, role_cnt;
  const struct userlist_user_info *ui;
  const struct userlist_members *mm;
  ptr_iterator_t iter;
  FILE *gen_f = 0;
  char *gen_text = 0;
  size_t gen_size = 0;
  const unsigned char *s;
  unsigned char vbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  static const unsigned char * const cnts_field_names[CONTEST_LAST_FIELD] =
  {
    [CONTEST_F_HOMEPAGE] = "Homepage",
    [CONTEST_F_PHONE] = "Phone",
    [CONTEST_F_INST] = "Inst",
    [CONTEST_F_INST_EN] = "Inst_en",
    [CONTEST_F_INSTSHORT] = "Instshort",
    [CONTEST_F_INSTSHORT_EN] = "Instshort_en",
    [CONTEST_F_INSTNUM] = "Instnum",
    [CONTEST_F_FAC] = "Fac",
    [CONTEST_F_FAC_EN] = "Fac_en",
    [CONTEST_F_FACSHORT] = "Facshort",
    [CONTEST_F_FACSHORT_EN] = "Facshort_en",
    [CONTEST_F_CITY] = "City",
    [CONTEST_F_CITY_EN] = "City_en",
    [CONTEST_F_COUNTRY] = "Country",
    [CONTEST_F_COUNTRY_EN] = "Country_en",
    [CONTEST_F_REGION] = "Region",
    [CONTEST_F_AREA] = "Area",
    [CONTEST_F_ZIP] = "Zip",
    [CONTEST_F_STREET] = "Street",
    [CONTEST_F_LANGUAGES] = "Languages",
    [CONTEST_F_FIELD0] = "Field0",
    [CONTEST_F_FIELD1] = "Field1",
    [CONTEST_F_FIELD2] = "Field2",
    [CONTEST_F_FIELD3] = "Field3",
    [CONTEST_F_FIELD4] = "Field4",
    [CONTEST_F_FIELD5] = "Field5",
    [CONTEST_F_FIELD6] = "Field6",
    [CONTEST_F_FIELD7] = "Field7",
    [CONTEST_F_FIELD8] = "Field8",
    [CONTEST_F_FIELD9] = "Field9",
  };

  // check, that we need iterate over members
  for (i = 0; i < CONTEST_LAST_MEMBER; i++)
    if (cnts->members[i] && cnts->members[i]->max_count > 0)
      need_members = 1;

  // print the header row
  fprintf(f, "Id;Login;Name;Email;Reg;St;Ban;Lock;Inv");
  for (i = 0; i < CONTEST_LAST_FIELD; i++) {
    if (cnts->fields[i] && cnts_field_names[i])
      fprintf(f, ";%s", cnts_field_names[i]);
  }
  if (need_members) {
    fprintf(f, ";Serial;Role");
  }
  fprintf(f, "\n");

  if (!(iter = default_get_info_list_iterator(contest_id, USERLIST_UC_ALL)))
    return;

  for (; iter->has_next(iter); iter->next(iter)) {
    u = (const struct userlist_user*) iter->get(iter);
    ui = userlist_get_user_info(u, contest_id);
    c = userlist_get_user_contest(u, contest_id);
    mm = 0;
    if (ui) mm = ui->members;

    gen_f = open_memstream(&gen_text, &gen_size);
    fprintf(gen_f, "%d;%s", u->id, CSVARMOR(u->login));
    s = NULL;
    if (ui) s = ui->name;
    if (!s) s = "";
    fprintf(gen_f, ";%s", CSVARMOR(s));
    s = u->email;
    if (!s) s = "";
    fprintf(gen_f, ";%s", CSVARMOR(s));

    switch (c->status) {
    case USERLIST_REG_OK:       s = "OK";       break;
    case USERLIST_REG_PENDING:  s = "PENDING";  break;
    case USERLIST_REG_REJECTED: s = "REJECTED"; break;
    default:
      s = "UNKNOWN";
    }
    fprintf(gen_f, ";%s", s);

    s = "";
    if ((c->flags & USERLIST_UC_INVISIBLE)) s = "I";
    fprintf(gen_f, ";%s", s);
    s = "";
    if ((c->flags & USERLIST_UC_BANNED)) s = "B";
    fprintf(gen_f, ";%s", s);
    s = "";
    if ((c->flags & USERLIST_UC_LOCKED)) s = "L";
    fprintf(gen_f, ";%s", s);
    s = "";
    if ((c->flags & USERLIST_UC_DISQUALIFIED)) s = "D";
    fprintf(gen_f, ";%s", s);

    for (i = 0; i < CONTEST_LAST_FIELD; i++) {
      if (!cnts->fields[i] || !userlist_contest_field_ids[i]) continue;
      vbuf[0] = 0;
      userlist_get_user_info_field_str(vbuf, sizeof(vbuf),
                                       ui, userlist_contest_field_ids[i], 0);
      fprintf(gen_f, ";%s", CSVARMOR(vbuf));
    }
    {
      vbuf[0] = 0;
      userlist_get_user_info_field_str(vbuf, sizeof(vbuf), ui, USERLIST_NC_AVATAR_ID, 0);
      fprintf(gen_f, ";%s", CSVARMOR(vbuf));
      vbuf[0] = 0;
      userlist_get_user_info_field_str(vbuf, sizeof(vbuf), ui, USERLIST_NC_AVATAR_SUFFIX, 0);
      fprintf(gen_f, ";%s", CSVARMOR(vbuf));
    }
    close_memstream(gen_f); gen_f = 0;

    pers_tot = 0;
    for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
      if ((role_cnt = userlist_members_count(mm, role)) <= 0)
        continue;
      if (!(cm = cnts->members[role])) continue;
      for (pers = 0; pers < role_cnt; pers++) {
        if (!(m = userlist_members_get_nth(mm, role, pers)))
          continue;
        if (pers >= cm->max_count) continue;
        pers_tot++;
        fwrite(gen_text, 1, gen_size, f);
        fprintf(f, ";%d;%s", m->serial, member_string[role]);

        for (i = 0; i < CONTEST_LAST_MEMBER_FIELD; i++) {
          if (!cm->fields[i] || !userlist_member_field_ids[i]) continue;
          vbuf[0] = 0;
          userlist_get_member_field_str(vbuf, sizeof(vbuf), m,
                                        userlist_member_field_ids[i], 0, 0);
          fprintf(f, ";%s", CSVARMOR(vbuf));
        }
        fprintf(f, "\n");
      }
    }
    if (!pers_tot) {
      fwrite(gen_text, 1, gen_size, f);
      fprintf(f, "\n");
    }
    xfree(gen_text); gen_text = 0;
    gen_size = 0;
    default_unlock_user(u);
  }
  iter->destroy(iter);
  html_armor_free(&ab);
}

static void
cmd_get_database(struct client_state *p, int pkt_len,
                 struct userlist_pk_dump_database *data)
{
  unsigned char logbuf[1024];
  const struct contest_desc *cnts = 0;
  char *db_text = 0;
  size_t db_size = 0, out_size = 0;
  FILE *f = 0;
  struct userlist_pk_xml_data *out = 0;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "GET_DATABASE: %d, %d",
           p->user_id, data->contest_id);

  if (is_judge(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  if (is_dbcnts_capable(p, cnts, OPCAP_DUMP_USERS, logbuf) < 0) return;

  if (!(f = open_memstream(&db_text, &db_size))) {
    err("%s -> open_memstream failed!", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }
  do_get_database(f, data->contest_id, cnts);
  close_memstream(f); f = 0;

  out_size = sizeof(*out) + db_size;
  out = (struct userlist_pk_xml_data*) alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_TEXT_DATA;
  out->info_len = db_size;
  memcpy(out->data, db_text, db_size + 1);
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> ok, %zu", logbuf, out_size);
  xfree(db_text);
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
cmd_control_server(struct client_state *p, int pkt_len,
                   struct userlist_packet *data)
{
  int mon_fd = -1;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (check_restart_permissions(p) <= 0) {
    return send_reply(p, -ULS_ERR_NO_PERMS);
  }

  switch (data->id) {
  case ULS_STOP:
    info("STOP");
    // mon_fd is intentionally "leaked"
    // it is closed implicitly when the program exits
    // client waits for EOF on connection to ensure command completion
    mon_fd = dup(p->fd);
    disconnect_client(p);
    fcntl(mon_fd, F_SETFD, FD_CLOEXEC);
    interrupt_signaled = 1;
    break;
  case ULS_RESTART:
    info("RESTART");
    // mon_fd is intentionally "leaked"
    // it is closed implicitly when the program execs itself
    // client waits for EOF on connection to ensure command completion
    mon_fd = dup(p->fd);
    disconnect_client(p);
    fcntl(mon_fd, F_SETFD, FD_CLOEXEC);
    interrupt_signaled = 1;
    restart_signaled = 1;
    break;
  default:
    CONN_BAD("unhandled command: %d", data->id);
    return;
  }
}

static void
cmd_edit_field_seq(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field_seq *data)
{
  size_t cur_size, sz;
  const unsigned char *pktptr;
  int *deleted_ids = 0, *edited_ids = 0, *edited_lens = 0;
  const unsigned char **edited_strs = 0;
  int i, cloned_flag = 0, f = 0, r, reply_code = 0, capbit;
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  const struct contest_desc *cnts = 0;
  const struct userlist_user_info *ui = 0;
  const struct userlist_member *m = 0;
  const struct userlist_members *mm = 0;

  if (pkt_len < sizeof(*data)) {
    CONN_BAD("packet is too small: %d < %zu", pkt_len, sizeof(*data));
    return;
  }
  if (data->deleted_num < 0 || data->deleted_num > 1000) {
    CONN_BAD("deleted_num is invalid");
    return;
  }
  if (data->edited_num < 0 || data->edited_num > 1000) {
    CONN_BAD("edited_num is invalid");
    return;
  }
  cur_size = sizeof(*data);
  pktptr = (const unsigned char*) data->data;
  if (data->deleted_num > 0) {
    sz = data->deleted_num * sizeof(deleted_ids[0]);
    if (cur_size +  sz > pkt_len) {
      CONN_BAD("packet overrun");
      return;
    }
    deleted_ids = (int*) alloca(sz);
    memcpy(deleted_ids, pktptr, sz);
    pktptr += sz; cur_size += sz;
  }
  if (data->edited_num > 0) {
    sz = data->edited_num * sizeof(edited_ids[0]);
    if (cur_size + sz > pkt_len) {
      CONN_BAD("packet overrun");
      return;
    }
    edited_ids = (int*) alloca(sz);
    memcpy(edited_ids, pktptr, sz);
    pktptr += sz; cur_size += sz;

    sz = data->edited_num * sizeof(edited_lens[0]);
    if (cur_size + sz > pkt_len) {
      CONN_BAD("packet overrun");
      return;
    }
    edited_lens = (int*) alloca(sz);
    memcpy(edited_lens, pktptr, sz);
    pktptr += sz; cur_size += sz;

    sz = data->edited_num * sizeof(edited_strs[0]);
    edited_strs = (const unsigned char**) alloca(sz);
    memset(edited_strs, 0, sz);
  }

  for (i = 0; i < data->edited_num; i++) {
    if (edited_lens[i] < 0 || edited_lens[i] > 1024 * 1024) {
      CONN_BAD("invalid field length");
      return;
    }
    if (cur_size + edited_lens[i] > pkt_len) {
      CONN_BAD("packet overrun");
      return;
    }
    edited_strs[i] = (const unsigned char*) pktptr;
    if (strlen(edited_strs[i]) != edited_lens[i]) {
      CONN_BAD("invalid string length");
      return;
    }
    pktptr += edited_lens[i] + 1; cur_size += edited_lens[i] + 1;
  }

  if (cur_size != pkt_len) {
    CONN_BAD("packet size mismatch");
    return;
  }

  snprintf(logbuf, sizeof(logbuf), "EDIT_FIELD_SEQ: %d, %d, %d, %d",
           p->user_id, data->user_id, data->contest_id, data->serial);

  for (i = 0; i < data->edited_num; i++) {
    if (edited_ids[i] == USERLIST_NN_PASSWD
        || edited_ids[i] == USERLIST_NC_TEAM_PASSWD) {
      err("%s -> password cannot be edited", logbuf);
      send_reply(p, -ULS_ERR_BAD_FIELD);
      return;
    }
  }
  for (i = 0; i < data->deleted_num; i++) {
    if (deleted_ids[i] == USERLIST_NN_PASSWD
        || deleted_ids[i] == USERLIST_NC_TEAM_PASSWD) {
      err("%s -> password cannot be deleted", logbuf);
      send_reply(p, -ULS_ERR_BAD_FIELD);
      return;
    }
  }

  if (is_judge_or_same_user(p, data->user_id, data->contest_id, logbuf) < 0)
    return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  if (default_get_user_info_7(data->user_id, data->contest_id, &u, &ui, &mm)<0
      || !u){
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (u->read_only || (ui && ui->cnts_read_only)) {
    err("%s -> read-only user", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  if (p->user_id != data->user_id) {
    capbit = OPCAP_EDIT_USER;
    if (is_privileged_cnts_user(u, cnts) >= 0) capbit = OPCAP_PRIV_EDIT_USER;
    if (is_dbcnts_capable(p, cnts, capbit, logbuf) < 0) return;
  }

  if (data->serial > 0) {
    for (i = 0; i < data->deleted_num; i++) {
      if (deleted_ids[i] < USERLIST_NM_FIRST
          || deleted_ids[i] >= USERLIST_NM_LAST) {
        err("%s -> invalid field %d", logbuf, deleted_ids[i]);
        send_reply(p, -ULS_ERR_BAD_FIELD);
        return;
      }
      if ((r = default_clear_member_field(data->user_id, data->contest_id,
                                          data->serial, deleted_ids[i],
                                          cur_time, &f)) < 0)
        goto cannot_change;
      cloned_flag |= f;
    }

    for (i = 0; i < data->edited_num; i++) {
      if (edited_ids[i] < USERLIST_NM_FIRST
          || edited_ids[i] >= USERLIST_NM_LAST) {
        err("%s -> invalid field %d", logbuf, edited_ids[i]);
        send_reply(p, -ULS_ERR_BAD_FIELD);
        return;
      }
      if ((r = default_set_user_member_field(data->user_id, data->contest_id,
                                             data->serial, edited_ids[i],
                                             edited_strs[i], cur_time, &f)) < 0)
        goto cannot_change;
      cloned_flag |= f;
    }
    goto done;
  }

  /* edit general info and default member info in case of personal contest */
  for (i = 0; i < data->deleted_num; i++) {
    if (deleted_ids[i] >= USERLIST_NM_FIRST
        && deleted_ids[i] < USERLIST_NM_LAST
        && cnts->personal) {
      if ((m = userlist_members_get_first(mm))) {
        if ((r = default_clear_member_field(data->user_id, data->contest_id,
                                            m->serial, deleted_ids[i],
                                            cur_time, &f)) < 0)
          goto cannot_change;
        cloned_flag |= f;
        default_get_user_info_7(data->user_id, data->contest_id, &u, &ui, &mm);
      }
    } else if (deleted_ids[i] >= USERLIST_NC_FIRST
               && deleted_ids[i] < USERLIST_NC_LAST) {
      if ((r = default_clear_user_info_field(data->user_id, data->contest_id,
                                             deleted_ids[i], cur_time, &f)) < 0)
        goto cannot_change;
      cloned_flag |= f;
    } else {
      err("%s -> invalid field %d", logbuf, deleted_ids[i]);
      send_reply(p, -ULS_ERR_BAD_FIELD);
      return;
    }
  }

  for (i = 0; i < data->edited_num; i++) {
    if (edited_ids[i] >= USERLIST_NM_FIRST
        && edited_ids[i] < USERLIST_NM_LAST
        && cnts->personal) {
      if (userlist_members_count(mm, CONTEST_M_CONTESTANT) <= 0) {
        if ((r = default_new_member(data->user_id, data->contest_id,
                                    CONTEST_M_CONTESTANT, cur_time, &f)) < 0)
          goto cannot_change;
        cloned_flag |= f;
        default_get_user_info_7(data->user_id, data->contest_id, &u, &ui, &mm);
      }
      m = userlist_members_get_first(mm);
      ASSERT(m);
      if ((r = default_set_user_member_field(data->user_id, data->contest_id,
                                             m->serial, edited_ids[i],
                                             edited_strs[i], cur_time, &f)) < 0)
        goto cannot_change;
      cloned_flag |= f;
      default_get_user_info_7(data->user_id, data->contest_id, &u, &ui, &mm);
    } else if (edited_ids[i] >= USERLIST_NC_FIRST
               && edited_ids[i] < USERLIST_NC_LAST) {
      if ((r = default_set_user_info_field(data->user_id, data->contest_id,
                                           edited_ids[i],
                                           edited_strs[i], cur_time, &f)) < 0)
        goto cannot_change;
      cloned_flag |= f;
    } else {
      err("%s -> invalid field %d", logbuf, edited_ids[i]);
      send_reply(p, -ULS_ERR_BAD_FIELD);
      return;
    }
  }

 done:
  default_check_user_reg_data(data->user_id, data->contest_id);
  if (cloned_flag) reply_code = ULS_CLONED;
  send_reply(p, reply_code);
  info("%s -> OK", logbuf);
  return;

 cannot_change:
  default_check_user_reg_data(data->user_id, data->contest_id);
  err("%s -> the fields cannot be changed", logbuf);
  send_reply(p, -ULS_ERR_CANNOT_CHANGE);
  return;
}

static void
cmd_move_member(struct client_state *p, int pkt_len,
                struct userlist_pk_move_info *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u;
  const struct contest_desc *cnts = 0;
  int r, reply_code = ULS_OK, cloned_flag = 0, bit;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("bad packet length: %d", pkt_len);
    return;
  }

  if (!data->user_id) data->user_id = p->user_id;
  snprintf(logbuf, sizeof(logbuf), "MOVE_MEMBER: %d, %d, %d, %d %d",
           p->user_id, data->user_id, data->contest_id, data->serial,
           data->new_role);

  if (is_judge_or_same_user(p, data->user_id, data->contest_id, logbuf) < 0)
    return;
  if (data->contest_id) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }

  if (default_check_user(data->user_id) < 0) {
    err("%s -> invalid user", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  if (data->user_id != p->user_id) {
    bit = OPCAP_EDIT_USER;
    if (is_privileged_cnts_user(u, cnts) >= 0) bit = OPCAP_PRIV_EDIT_USER;
    if (is_dbcnts_capable(p, cnts, bit, logbuf) < 0) return;
  }

  r = default_move_member(data->user_id, data->contest_id, data->serial,
                          data->new_role, cur_time, &cloned_flag);
  if (r < 0) {
    err("%s -> member move failed", logbuf);
    send_reply(p, -ULS_ERR_CANNOT_CHANGE);
    return;
  }
  default_check_user_reg_data(data->user_id, data->contest_id);
  if (r == 1) {
    update_userlist_table(data->contest_id);
  }
  if (cloned_flag) reply_code = ULS_CLONED;
  send_reply(p, reply_code);
  info("%s -> OK, %d", logbuf, reply_code);
}

static const struct { unsigned char *str; int ind; } field_names[] =
{
  { "User_Id", USERLIST_NN_ID },
  { "Login", USERLIST_NN_LOGIN },
  { "E-mail", USERLIST_NN_EMAIL },
  { "Password", USERLIST_NN_PASSWD },

  { "Name", USERLIST_NC_NAME },
  { "Team_Password", USERLIST_NC_TEAM_PASSWD },
  { "Inst", USERLIST_NC_INST },
  { "Inst_En", USERLIST_NC_INST_EN },
  { "Instshort", USERLIST_NC_INSTSHORT },
  { "Instshort_En", USERLIST_NC_INSTSHORT_EN },
  { "Instnum", USERLIST_NC_INSTNUM },
  { "Fac", USERLIST_NC_FAC },
  { "Fac_En", USERLIST_NC_FAC_EN },
  { "Facshort", USERLIST_NC_FACSHORT },
  { "Facshort_En", USERLIST_NC_FACSHORT_EN },
  { "Homepage", USERLIST_NC_HOMEPAGE },
  { "City", USERLIST_NC_CITY },
  { "City_En", USERLIST_NC_CITY_EN },
  { "Country", USERLIST_NC_COUNTRY },
  { "Country_En", USERLIST_NC_COUNTRY_EN },
  { "Region", USERLIST_NC_REGION },
  { "Area", USERLIST_NC_AREA },
  { "Zip", USERLIST_NC_ZIP },
  { "Street", USERLIST_NC_STREET },
  { "Location", USERLIST_NC_LOCATION },
  { "Spelling", USERLIST_NC_SPELLING },
  { "Printer_Name", USERLIST_NC_PRINTER_NAME },
  { "Exam_Id", USERLIST_NC_EXAM_ID },
  { "Exam_Cypher", USERLIST_NC_EXAM_CYPHER },
  { "Languages", USERLIST_NC_LANGUAGES },
  { "Phone", USERLIST_NC_PHONE },
  { "Field0", USERLIST_NC_FIELD0 },
  { "Field1", USERLIST_NC_FIELD1 },
  { "Field2", USERLIST_NC_FIELD2 },
  { "Field3", USERLIST_NC_FIELD3 },
  { "Field4", USERLIST_NC_FIELD4 },
  { "Field5", USERLIST_NC_FIELD5 },
  { "Field6", USERLIST_NC_FIELD6 },
  { "Field7", USERLIST_NC_FIELD7 },
  { "Field8", USERLIST_NC_FIELD8 },
  { "Field9", USERLIST_NC_FIELD9 },
  { "Avatar_Store", USERLIST_NC_AVATAR_STORE },
  { "Avatar_Id", USERLIST_NC_AVATAR_ID },
  { "Avatar_Suffix", USERLIST_NC_AVATAR_SUFFIX },

  { "Status", USERLIST_NM_STATUS },
  { "Grade", USERLIST_NM_GRADE },
  { "Firstname", USERLIST_NM_FIRSTNAME },
  { "Firstname_En", USERLIST_NM_FIRSTNAME_EN },
  { "Middlename", USERLIST_NM_MIDDLENAME },
  { "Middlename_En", USERLIST_NM_MIDDLENAME_EN },
  { "Surname", USERLIST_NM_SURNAME },
  { "Surname_En", USERLIST_NM_SURNAME_EN },
  { "Group", USERLIST_NM_GROUP },
  { "Group_En", USERLIST_NM_GROUP_EN },
  { "Occupation", USERLIST_NM_OCCUPATION },
  { "Occupation_En", USERLIST_NM_OCCUPATION_EN },
  { "Discipline", USERLIST_NM_DISCIPLINE },
  { "Birth_Date", USERLIST_NM_BIRTH_DATE },
  { "Entry_Date", USERLIST_NM_ENTRY_DATE },
  { "Graduation_Date", USERLIST_NM_GRADUATION_DATE },

  { 0, -1 },
};

/*
  `field' - field separator
  `serial' - flags (1 - create new users)
 */
static void
cmd_import_csv_users(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  int separator;
  struct csv_file *csv = 0;
  FILE *log_f = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  int i, j, k, field_num, user_id, f, need_member = 0;
  int *field_ind = 0, *user_ids = 0;
  int field_rev[USERLIST_NM_LAST];
  const struct userlist_user *u;
  const struct userlist_user_info *ui;
  const struct userlist_contest *c;
  const struct userlist_member *m;
  const struct userlist_members *mm;
  int retval = ULS_TEXT_DATA_FAILURE;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  int cloned_flag = 0;
  int member_serial = 0;

  snprintf(logbuf, sizeof(logbuf), "IMPORT_CSV_USERS: %d, %d, %d",
           data->contest_id, data->field, data->serial);

  if (is_admin(p, logbuf) < 0) return;
  if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;

  if (is_cnts_capable(p, cnts, OPCAP_EDIT_USER, logbuf) < 0
      || is_cnts_capable(p, cnts, OPCAP_PRIV_EDIT_USER, logbuf) < 0
      || is_cnts_capable(p, cnts, OPCAP_CREATE_REG, logbuf) < 0
      || is_cnts_capable(p, cnts, OPCAP_PRIV_CREATE_REG, logbuf) < 0)
    return;
  separator = data->field;
  if (separator < ' ') separator = ';';

  log_f = open_memstream(&log_txt, &log_len);
  if (!(csv = csv_parse(data->data, log_f, separator))) {
    fprintf(log_f, "cannot parse the CSV file\n");
    goto cleanup;
  }
  if (csv->u < 1) {
    fprintf(log_f, "too few rows in the table\n");
    goto cleanup;
  }
  // check, that all rows have the same number of columns
  for (i = 1; i < csv->u; i++) {
    if (csv->v[i].u != csv->v[0].u) {
      fprintf(log_f, "row %d has %zu columns, but the header has %zu columns\n",
              i + 1, csv->v[i].u, csv->v[0].u);
      goto cleanup;
    }
  }
  // parse the first line
  field_num = csv->v[0].u;
  field_ind = (int*) alloca(field_num * sizeof(field_ind[0]));
  memset(field_ind, -1, field_num * sizeof(field_ind[0]));
  memset(field_rev, -1, sizeof(field_rev));
  XALLOCAZ(user_ids, csv->u);
  for (j = 0; j < field_num; j++) {
    if (!csv->v[0].v[j][0]) {
      fprintf(log_f, "Empty field (%d), ignored\n", j + 1);
      continue;
    }
    for (k = 0; field_names[k].str; k++)
      if (!strcasecmp(field_names[k].str, csv->v[0].v[j]))
        break;
    if (field_names[k].str) {
      f = field_names[k].ind;
      if (field_rev[f] >= 0) {
        fprintf(log_f, "Duplicated field `%s'\n", field_names[k].str);
        goto cleanup;
      }
      field_rev[f] = j;
      field_ind[j] = f;
      if (f >= USERLIST_NM_FIRST && f < USERLIST_NM_LAST
          && !cnts->personal) {
        fprintf(log_f, "Contest is not personal\n");
        goto cleanup;
      }
      if (f >= USERLIST_NM_FIRST && f < USERLIST_NM_LAST)
        need_member = 1;
    } else {
      fprintf(log_f, "Unknown field `%s', ignored\n", csv->v[0].v[j]);
    }
  }

  // check the uniqueness of the logins
  if (field_rev[USERLIST_NN_ID] >= 0 && field_rev[USERLIST_NN_LOGIN] >= 0) {
    fprintf(log_f, "Both `User_Id' and `Login' are specified\n");
    goto cleanup;
  }
  if (field_rev[USERLIST_NN_ID] < 0 && field_rev[USERLIST_NN_LOGIN] < 0) {
    fprintf(log_f, "Neither `User_Id' nor `Login' is specified\n");
    goto cleanup;
  }
  if ((j = field_rev[USERLIST_NN_LOGIN]) < 0) j = field_rev[USERLIST_NN_ID];
  for (i = 1; i < csv->u; i++) {
    if (field_rev[USERLIST_NN_LOGIN] >= 0) {
      if ((user_id = default_get_user_by_login(csv->v[i].v[j])) <= 0) {
        fprintf(log_f, "Invalid login `%s' in row %d\n", csv->v[i].v[j], i);
        goto cleanup;
      }
    } else {
      int n;
      if (sscanf(csv->v[i].v[j], "%d%n", &user_id, &n) != 1
          || csv->v[i].v[j][n] || user_id <= 0
          || default_check_user(user_id) < 0) {
        fprintf(log_f, "Invalid user_id `%s' in row %d\n", csv->v[i].v[j], i);
        goto cleanup;
      }
    }
    user_ids[i] = user_id;
    for (k = 1; k < i; k++) {
      if (user_ids[k] == user_ids[i]) {
        fprintf(log_f, "Duplicated login `%s'\n", csv->v[i].v[j]);
        goto cleanup;
      }
    }

    // check contest registration
    c = 0;
    if (default_get_user_info_3(user_id, data->contest_id, &u, &ui, &c) < 0
        || !u) {
      fprintf(log_f, "Database error\n");
      goto cleanup;
    }
    if (!c) {
      fprintf(log_f, "User `%s' is not registered for the contest\n",
              csv->v[i].v[j]);
      goto cleanup;
    }
    if (c->status != USERLIST_REG_OK || c->flags != 0) {
      fprintf(log_f, "User `%s' is not a regular user\n", csv->v[i].v[j]);
      goto cleanup;
    }
    if (u->read_only || (ui && ui->cnts_read_only)) {
      fprintf(log_f, "User `%s' is read-only\n", u->login);
      goto cleanup;
    }
  }

  // set the fields
  for (i = 1; i < csv->u; i++) {
    user_id = user_ids[i];
    u = 0; ui = 0;
    if (default_get_user_info_7(user_id, data->contest_id, &u, &ui, &mm) < 0
        || !u)
      abort();
    if (need_member && (!ui || !userlist_members_get_first(mm))) {
      if (default_new_member(user_id, data->contest_id, CONTEST_M_CONTESTANT,
                             cur_time, &cloned_flag) < 0) {
        fprintf(log_f, "Cannot create a new member for user `%s'\n", u->login);
        goto cleanup;
      }

      if (default_get_user_info_7(user_id, data->contest_id, &u, &ui, &mm) < 0
          || !u)
        abort();
    }
    m = 0;
    if (need_member) {
      m = 0; u =0; ui = 0;
      if (default_get_user_info_2(user_id, data->contest_id, &u, &ui)<0 || !u)
        abort();
      if (ui) m = userlist_members_get_first(mm);
      ASSERT(m);
      member_serial = m->serial;
    }
    for (j = 0; j < csv->v[i].u; j++) {
      if ((f = field_ind[j]) < 0 || f == USERLIST_NN_LOGIN) continue;
      if (f >= USERLIST_NN_FIRST && f < USERLIST_NN_LAST) {
        if (default_set_user_field(user_id, f, csv->v[i].v[j], cur_time) < 0) {
          fprintf(log_f, "Failed to update user `%s'\n", u->login);
          goto cleanup;
        }
      } else if (f >= USERLIST_NC_FIRST && f < USERLIST_NC_LAST) {
        if (default_set_user_info_field(user_id, data->contest_id, f,
                                        csv->v[i].v[j], cur_time,
                                        &cloned_flag) < 0) {
          fprintf(log_f, "Failed to update user `%s'\n", u->login);
          goto cleanup;
        }
      } else if (f >= USERLIST_NM_FIRST && f < USERLIST_NM_LAST) {
        if (default_set_user_member_field(user_id, data->contest_id,
                                          member_serial, f, csv->v[i].v[j],
                                          cur_time, &cloned_flag) < 0) {
          fprintf(log_f, "Failed to update user `%s'\n", u->login);
          goto cleanup;
        }
      }
    }
  }

  fprintf(log_f, "Operation completed successfully\n");
  close_memstream(log_f); log_f = 0;
  retval = ULS_TEXT_DATA;
  (void) retval;

 cleanup:
  if (log_f) close_memstream(log_f);
  log_f = 0;
  csv_free(csv);

  out_size = sizeof(*out) + log_len;
  out = (struct userlist_pk_xml_data*) alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_TEXT_DATA_FAILURE;
  out->info_len = log_len;
  memcpy(out->data, log_txt, log_len + 1);
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> ok, %zu", logbuf, out_size);
  xfree(log_txt);
}

static void
cmd_list_all_groups(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  unsigned char logbuf[1024];
  FILE *fout = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  ptr_iterator_t iter = 0;
  const struct userlist_group *grp = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;

  snprintf(logbuf, sizeof(logbuf), "PRIV_ALL_GROUPS: %d", p->user_id);
  if (is_admin(p, logbuf) < 0) return;

  if (!plugin_func(get_group_iterator)) {
    err("%s -> not implemented", logbuf);
    send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
    return;
  }

  fout = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(fout, -1);
  userlist_write_groups_header(fout);
  iter = plugin_call0(get_group_iterator);
  if (iter) {
    for (; iter->has_next(iter); iter->next(iter)) {
      grp = (const struct userlist_group*) iter->get(iter);
      if (grp) {
        userlist_unparse_usergroup(fout, grp, "      ", "\n");
        // plugin_call1(unlock_group, grp);
      }
    }
    iter->destroy(iter); iter = 0;
  }
  userlist_write_groups_footer(fout);
  userlist_write_xml_footer(fout);
  fclose(fout); fout = 0;

  out_size = sizeof(*out) + xml_size;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr); xml_ptr = 0;
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu", logbuf, xml_size);
}

static void
cmd_create_group(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];
  unsigned char buf[64];
  const unsigned char *group_name = 0;
  int group_id = -1;
  struct userlist_pk_login_ok out;

  snprintf(logbuf, sizeof(logbuf), "CREATE_GROUP: %d, %s",
           p->user_id, data->data);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (is_db_capable(p, OPCAP_CREATE_USER, logbuf) < 0) return;

  if (!plugin_func(create_group)) {
    err("%s -> not implemented", logbuf);
    send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
    return;
  }

  if (data->value_len > 0) {
    if (plugin_call(get_group_by_name, data->data)) {
      err("%s -> group already exists", logbuf);
      send_reply(p, -ULS_ERR_GROUP_NAME_USED);
      return;
    }
    group_name = data->data;
  } else {
    if (plugin_call(try_new_group_name, buf, sizeof(buf), "New_group_%d", 0, 1) < 0) {
      err("%s -> database error", logbuf);
      send_reply(p, -ULS_ERR_DB_ERROR);
      return;
    }
    group_name = buf;
  }

  group_id = plugin_call(create_group, group_name, p->user_id);
  if (group_id <= 0) {
    err("%s -> cannot create group", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }

  info("%s -> new group %d", logbuf, group_id);
  memset(&out, 0, sizeof(out));
  out.reply_id = ULS_LOGIN_OK;
  out.user_id = group_id;
  enqueue_reply_to_client(p, sizeof(out), &out);
}

static void
cmd_delete_group(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_delete_info *data)
{
  unsigned char logbuf[1024];

  snprintf(logbuf, sizeof(logbuf), "DELETE_GROUP: %d, %d",
           p->user_id, data->user_id);

  if (is_admin(p, logbuf) < 0) return;

  plugin_call(remove_group, data->user_id);

  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
}

static void
cmd_edit_group_field(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];
  int errcode = 0;

  snprintf(logbuf, sizeof(logbuf), "EDIT_GROUP_FIELD: %d, %d, %d, \"%s\"",
           p->user_id, data->user_id, data->field, data->data);

  if (is_admin(p, logbuf) < 0) return;

  errcode = plugin_call(edit_group_field, data->user_id, data->field, data->data);
  if (errcode < 0) {
    err("%s -> database error %d", logbuf, -errcode);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
}

static void
cmd_delete_group_field(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_edit_field *data)
{
  unsigned char logbuf[1024];
  int errcode = 0;

  snprintf(logbuf, sizeof(logbuf), "DELETE_GROUP_FIELD: %d, %d, %d",
           p->user_id, data->user_id, data->field);

  if (is_admin(p, logbuf) < 0) return;

  errcode = plugin_call(clear_group_field, data->user_id, data->field);
  if (errcode < 0) {
    err("%s -> database error %d", logbuf, -errcode);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
}

static void
cmd_list_group_users(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  unsigned char logbuf[1024];
  char *xml_ptr = 0;
  size_t xml_size = 0;
  FILE *fout = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size;
  const struct userlist_group *grp;
  ptr_iterator_t iter = 0;
  const struct userlist_user *u;
  const struct userlist_groupmember *gm;

  snprintf(logbuf, sizeof(logbuf), "LIST_GROUP_USERS: %d, %d",
           p->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;

  grp = plugin_call(get_group, data->contest_id);
  if (!grp) {
    err("%s -> invalid group %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_GROUP_ID);
    return;
  }

  fout = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(fout, -1);
  iter = plugin_call(get_group_user_iterator, grp->group_id);
  if (iter) {
    for (; iter->has_next(iter); iter->next(iter)) {
      if (!(u = (const struct userlist_user*) iter->get(iter))) continue;
      userlist_unparse_user_short(u, fout, 0);
      default_unlock_user(u);
    }
    iter->destroy(iter); iter = 0;
  }
  userlist_write_groups_header(fout);
  userlist_unparse_usergroup(fout, grp, "      ", "\n");
  userlist_write_groups_footer(fout);
  userlist_write_groupmembers_header(fout);
  iter = plugin_call(get_group_member_iterator, grp->group_id);
  if (iter) {
    for (; iter->has_next(iter); iter->next(iter)) {
      if (!(gm = (const struct userlist_groupmember*) iter->get(iter)))
        continue;
      userlist_unparse_usergroupmember(fout, gm, "      ", "\n");
    }
    iter->destroy(iter); iter = 0;
  }
  userlist_write_groupmembers_footer(fout);
  userlist_write_xml_footer(fout);
  fclose(fout); fout = 0;

  out_size = sizeof(*out) + xml_size;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr); xml_ptr = 0;
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu", logbuf, xml_size);
}

static void
cmd_create_group_member(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_register_contest *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  const struct userlist_group *grp = 0;
  int r;

  snprintf(logbuf, sizeof(logbuf), "CREATE_GROUP_MEMBER: %d, %d, %d",
           p->user_id, data->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> invalid user_id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  grp = plugin_call(get_group, data->contest_id);
  if (!grp) {
    err("%s -> invalid group %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_GROUP_ID);
    return;
  }

  if ((r = plugin_call(create_group_member,data->contest_id,data->user_id))<0) {
    err("%s -> database error %d", logbuf, -r);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
}

static void
cmd_delete_group_member(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_register_contest *data)
{
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  const struct userlist_group *grp = 0;
  int r;

  snprintf(logbuf, sizeof(logbuf), "DELETE_GROUP_MEMBER: %d, %d, %d",
           p->user_id, data->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;

  if (default_get_user_info_1(data->user_id, &u) < 0 || !u) {
    err("%s -> invalid user_id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }
  grp = plugin_call(get_group, data->contest_id);
  if (!grp) {
    err("%s -> invalid group %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_GROUP_ID);
    return;
  }

  if ((r = plugin_call(remove_group_member,data->contest_id,data->user_id))<0) {
    err("%s -> database error %d", logbuf, -r);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
}

static void
cmd_get_groups(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_set_user_info *data)
{
  unsigned char logbuf[1024];
  struct userlist_pk_xml_data *out = 0;
  size_t out_size, xml_size = 0;
  char *xml_text = 0;
  FILE *xml_file = 0;
  unsigned char *group_name = 0;
  int offset = 0, n, group_count = 0, i;
  int *groups = 0;
  const struct userlist_group *grp;
  ptr_iterator_t iter = 0;
  const struct userlist_groupmember *gm;

  snprintf(logbuf, sizeof(logbuf), "GET_GROUPS: %d, %s",
           p->user_id, data->data);

  /* space-separated list of group names */
  if (data->info_len <= 0 /* || data->info_len > 64 * 1024 */) {
    err("%s -> invalid size %d", logbuf, data->info_len);
    send_reply(p, -ULS_ERR_INVALID_SIZE);
    goto cleanup;
  }
  group_name = alloca(data->info_len + 32);
  while (sscanf(data->data + offset, "%s%n", group_name, &n) == 1) {
    offset += n;
    ++group_count;
  }
  if (group_count <= 0 || group_count > 256) {
    err("%s -> invalid group count %d", logbuf, group_count);
    send_reply(p, -ULS_ERR_INVALID_SIZE);
    goto cleanup;
  }
  XALLOCAZ(groups, group_count);
  i = 0;
  offset = 0;
  while (sscanf(data->data + offset, "%s%n", group_name, &n) == 1) {
    grp = plugin_call(get_group_by_name, group_name);
    if (!grp) {
      err("%s -> invalid group %s", logbuf, group_name);
      send_reply(p, -ULS_ERR_BAD_GROUP_ID);
      goto cleanup;
    }
    groups[i] = grp->group_id;

    offset += n;
    ++i;
  }
  ASSERT(i == group_count);

  xml_file = open_memstream(&xml_text, &xml_size);
  userlist_write_xml_header(xml_file, -1);
  userlist_write_groups_header(xml_file);
  for (i = 0; i < group_count; ++i) {
    grp = plugin_call(get_group, groups[i]);
    if (grp) {
      userlist_unparse_usergroup(xml_file, grp, "      ", "\n");
    }
  }
  userlist_write_groups_footer(xml_file);
  userlist_write_groupmembers_header(xml_file);
  for (i = 0; i < group_count; ++i) {
    iter = plugin_call(get_group_member_iterator, groups[i]);
    if (iter) {
      for (; iter->has_next(iter); iter->next(iter)) {
        if ((gm = (const struct userlist_groupmember*) iter->get(iter))) {
          userlist_unparse_usergroupmember(xml_file, gm, "      ", "\n");
        }
      }
      iter->destroy(iter); iter = 0;
    }
  }
  userlist_write_groupmembers_footer(xml_file);
  userlist_write_xml_footer(xml_file);
  fclose(xml_file); xml_file = 0;

  out_size = sizeof(*out) + xml_size;
  out = (struct userlist_pk_xml_data*) xmalloc(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_text, xml_size + 1);
  xfree(xml_text); xml_text = 0;
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu", logbuf, xml_size);

cleanup:
  if (iter) iter->destroy(iter);
  if (xml_file) fclose(xml_file);
  xfree(xml_text);
}

static void
cmd_list_all_users_2(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_list_users_2 *data)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  ptr_iterator_t iter;
  const struct userlist_user *u;

  snprintf(logbuf, sizeof(logbuf), "LIST_ALL_USERS_2: %d, %d, %d, %d, %d",
           p->user_id, data->contest_id, data->group_id, data->offset, data->count);

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id > 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;

  f = open_memstream(&xml_ptr, &xml_size);
  iter = default_get_brief_list_iterator_2(data->contest_id, data->group_id, data->data, data->offset, data->count,
                                           data->page, data->sort_field, data->sort_order, data->filter_field, data->filter_op);
  long long total = -1;
  if (iter->get_total) total = iter->get_total(iter);
  if (total < 0) {
    default_get_user_count(data->contest_id, data->group_id, data->data, data->filter_field, data->filter_op, 1, &total);
  }
  userlist_write_xml_header(f, total);
  if (iter) {
    for (; iter->has_next(iter); iter->next(iter)) {
      if (!(u = (const struct userlist_user*) iter->get(iter))) continue;
      userlist_unparse_user_short(u, f, data->contest_id);
      default_unlock_user(u);
    }
  }
  userlist_write_xml_footer(f);
  if (iter) iter->destroy(iter);
  close_memstream(f); f = 0;
  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size;
  out = (struct userlist_pk_xml_data*) xmalloc(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr); xml_ptr = 0;
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu", logbuf, xml_size);
  xfree(out); out = 0;
}

static void
cmd_get_user_count(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_list_users_2 *data)
{
  struct userlist_pk_count out;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  long long count = -1;
  int r;

  snprintf(logbuf, sizeof(logbuf), "GET_USER_COUNT: %d, %d",
           p->user_id, data->contest_id);

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;

  r = default_get_user_count(data->contest_id, data->group_id, data->data, data->filter_field, data->filter_op, 0, &count);
  if (r < 0) {
    err("%s -> database error %d", logbuf, -r);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  if (count < 0) {
    err("%s -> invalid value of count %lld", logbuf, count);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  memset(&out, 0, sizeof(out));
  out.reply_id = ULS_COUNT;
  out.count = count;
  enqueue_reply_to_client(p, sizeof(out), &out);
  info("%s -> OK, %lld", logbuf, out.count);
}

static void
cmd_list_all_groups_2(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_list_users_2 *data)
{
  FILE *fout = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  unsigned char logbuf[1024];
  ptr_iterator_t iter;
  const struct userlist_group *grp;

  snprintf(logbuf, sizeof(logbuf), "LIST_ALL_GROUPS_2: %d, %d, %d",
           p->user_id, data->offset, data->count);

  if (is_judge(p, logbuf) < 0) return;
  if (is_dbcnts_capable(p, NULL, OPCAP_LIST_USERS, logbuf) < 0) return;

  fout = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(fout, -1);
  userlist_write_groups_header(fout);
  iter = default_get_group_iterator_2(data->data, data->offset, data->count);
  if (iter) {
    for (; iter->has_next(iter); iter->next(iter)) {
      grp = (const struct userlist_group*) iter->get(iter);
      if (grp) {
        userlist_unparse_usergroup(fout, grp, "      ", "\n");
        // plugin_call1(unlock_group, grp);
      }
    }
    iter->destroy(iter); iter = 0;
  }
  userlist_write_groups_footer(fout);
  userlist_write_xml_footer(fout);
  fclose(fout); fout = 0;

  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size;
  out = (struct userlist_pk_xml_data*) xmalloc(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr); xml_ptr = 0;
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu", logbuf, xml_size);
  xfree(out); out = 0;
}

static void
cmd_get_group_count(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_list_users_2 *data)
{
  struct userlist_pk_count out;
  unsigned char logbuf[1024];
  long long count = -1;
  int r;

  snprintf(logbuf, sizeof(logbuf), "GET_GROUP_COUNT: %d", p->user_id);

  if (is_judge(p, logbuf) < 0) return;
  if (is_dbcnts_capable(p, NULL, OPCAP_LIST_USERS, logbuf) < 0) return;

  r = default_get_group_count(data->data, &count);
  if (r < 0) {
    err("%s -> database error %d", logbuf, -r);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }
  if (count < 0) {
    err("%s -> invalid value of count %lld", logbuf, count);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  memset(&out, 0, sizeof(out));
  out.reply_id = ULS_COUNT;
  out.count = count;
  enqueue_reply_to_client(p, sizeof(out), &out);
  info("%s -> OK, %lld", logbuf, out.count);
}

static void
cmd_create_user_2(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_create_user_2 *data)
{
  unsigned char logbuf[1024];
  const unsigned char *login_str = data->data;
  const unsigned char *email_str = login_str + data->login_len + 1;
  const unsigned char *reg_password_str = email_str + data->email_len + 1;
  const unsigned char *cnts_password_str = reg_password_str + data->reg_password_len + 1;
  const unsigned char *cnts_name_str = cnts_password_str + data->cnts_password_len + 1;
  int user_id = 0;
  unsigned char random_reg_password_buf[64];
  int reg_password_len = data->reg_password_len;
  int reg_password_method = USERLIST_PWD_PLAIN;
  const struct contest_desc *cnts = 0;
  int login_len = data->login_len;
  unsigned char auto_login_buf[64];
  const struct userlist_contest *cnts_reg = 0;
  const struct userlist_group *ul_group = 0;
  int cnts_password_method = USERLIST_PWD_PLAIN;
  unsigned char random_cnts_password_buf[64];
  int cloned_flag = 0;
  int send_email_flag = data->send_email_flag;
  struct passwd_internal pwdnew;
  struct passwd_internal cpwdnew;

  snprintf(logbuf, sizeof(logbuf), "CREATE_USER_2: %d", p->user_id);

  if (p->user_id < 0) {
    err("%s -> not authentificated", logbuf);
    send_reply(p, -ULS_ERR_NO_PERMS);
    return;
  }
  ASSERT(p->user_id > 0);
  if (is_db_capable(p, OPCAP_CREATE_USER, logbuf) < 0) return;

  if (data->contest_id != 0) {
    if (contests_get(data->contest_id, &cnts) < 0 || !cnts) {
      err("%s -> invalid contest %d", logbuf, data->contest_id);
      send_reply(p, -ULS_ERR_BAD_CONTEST_ID);
      return;
    }
  }
  if (data->group_id > 0) {
    ul_group = plugin_call(get_group, data->group_id);
    if (!ul_group) {
      err("%s -> invalid group %d", logbuf, data->group_id);
      send_reply(p, -ULS_ERR_BAD_GROUP_ID);
      return;
    }
  }

  if (!login_len && cnts && cnts->assign_logins && cnts->login_template) {
    int serial = 0;
    int serial_step = 1;
    int n = 0;
    if (cnts->login_template_options
        && sscanf(cnts->login_template_options, "%d%d%n",
                  &serial, &serial_step, &n) == 2
        && !cnts->login_template_options[n] && serial_step != 0) {
      serial -= serial_step;
    } else {
      serial = 0;
      serial_step = 1;
    }
    if (dflt_iface->try_new_login) {
      serial += serial_step;
      if (default_try_new_login(auto_login_buf, sizeof(auto_login_buf), cnts->login_template, serial, serial_step) < 0) {
        send_reply(p, -ULS_ERR_DB_ERROR);
        err("%s -> database error", logbuf);
        return;
      }
    } else {
      while (1) {
        serial += serial_step;
        snprintf(auto_login_buf, sizeof(auto_login_buf), cnts->login_template, serial);
        if ((user_id = default_get_user_by_login(auto_login_buf)) < 0) break;
      }
    }
    login_str = auto_login_buf;
    login_len = strlen(login_str);
  }

  if (!login_len) {
    err("%s -> empty login", logbuf);
    send_reply(p, -ULS_ERR_INVALID_LOGIN);
    return;
  }

  user_id = default_get_user_by_login(login_str);
  if (data->register_existing_flag <= 0 && user_id >= 0) {
    err("%s: %s -> login already exists", login_str, logbuf);
    send_reply(p, -ULS_ERR_LOGIN_USED);
    return;
  }
  if (user_id <= 0) user_id = -1;

  if (data->random_password_flag) {
    generate_random_password(8, random_reg_password_buf);
    reg_password_str = random_reg_password_buf;
    reg_password_len = strlen(reg_password_str);
  }
  if (!reg_password_len) {
    err("%s -> empty password", logbuf);
    send_reply(p, -ULS_ERR_INVALID_PASSWORD);
    return;
  }
  if (data->use_sha1_flag) {
    passwd_convert_to_internal(reg_password_str, &pwdnew);
    passwd_convert(&pwdnew, pwdnew.pwd_nows, NULL, USERLIST_PWD_SHA256);
    reg_password_method = USERLIST_PWD_SHA256;
    reg_password_str = pwdnew.encoded;
    reg_password_len = strlen(pwdnew.encoded);
  }

  if (user_id > 0 && data->reset_existing_passwords_flag > 0) {
    default_set_reg_passwd(user_id, reg_password_method, reg_password_str, cur_time);
  }

  if (user_id < 0) {
    user_id = default_new_user(login_str,
                               email_str,
                               reg_password_method,
                               reg_password_str,
                               data->is_privileged_flag,
                               data->is_invisible_flag,
                               data->is_banned_flag,
                               data->is_locked_flag,
                               data->show_login_flag,
                               data->show_email_flag,
                               data->read_only_flag,
                               data->never_clean_flag,
                               data->simple_registration_flag);
    if (user_id <= 0) {
      err("%s -> cannot create user", logbuf);
      send_reply(p, -ULS_ERR_DB_ERROR);
      return;
    }
  }

  if (data->contest_id) {
    int cnts_flags = 0;
    if (data->cnts_is_invisible_flag) cnts_flags |= USERLIST_UC_INVISIBLE;
    if (data->cnts_is_banned_flag) cnts_flags |= USERLIST_UC_BANNED;
    if (data->cnts_is_locked_flag) cnts_flags |= USERLIST_UC_LOCKED;
    if (data->cnts_is_incomplete_flag) cnts_flags |= USERLIST_UC_INCOMPLETE;
    if (data->cnts_is_disqualified_flag) cnts_flags |= USERLIST_UC_DISQUALIFIED;
    if (data->cnts_is_privileged_flag) cnts_flags |= USERLIST_UC_PRIVILEGED;
    if (data->cnts_is_reg_readonly_flag) cnts_flags |= USERLIST_UC_REG_READONLY;
    if (default_register_contest(user_id, data->contest_id, data->cnts_status, cnts_flags,
                                 cur_time, &cnts_reg) < 0) {
      err("%s -> cannot register user", logbuf);
      send_reply(p, -ULS_ERR_DB_ERROR);
      return;
    }
  }

  if (cnts && !cnts->disable_team_password) {
    if (data->cnts_use_reg_passwd_flag) {
      default_set_team_passwd(user_id, data->contest_id, reg_password_method, reg_password_str,
                              cur_time, &cloned_flag);
    } else if (data->cnts_set_null_passwd_flag) {
      // do nothing...
    } else {
      if (data->cnts_random_password_flag) {
        generate_random_password(8, random_cnts_password_buf);
        cnts_password_str = random_cnts_password_buf;
      }
      if (data->cnts_use_sha1_flag) {
        passwd_convert_to_internal(cnts_password_str, &cpwdnew);
        passwd_convert(&cpwdnew, cpwdnew.pwd_nows, NULL, USERLIST_PWD_SHA256);
        cnts_password_method = USERLIST_PWD_SHA256;
        cnts_password_str = cpwdnew.encoded;
      }
      default_set_team_passwd(user_id, data->contest_id, cnts_password_method, cnts_password_str,
                              cur_time, &cloned_flag);
    }
  }

  if (cnts && cnts_name_str && *cnts_name_str) {
    if (default_set_user_info_field(user_id, data->contest_id,
                                    USERLIST_NC_NAME, cnts_name_str,
                                    cur_time, &cloned_flag) < 0) {
      err("%s -> cannot set user name", logbuf);
      send_reply(p, -ULS_ERR_DB_ERROR);
      return;
    }
    if (default_set_user_info_field(user_id, 0,
                                    USERLIST_NC_NAME, cnts_name_str,
                                    cur_time, &cloned_flag) < 0) {
      err("%s -> cannot set user name", logbuf);
      send_reply(p, -ULS_ERR_DB_ERROR);
      return;
    }
  }

  if (ul_group) {
    if (plugin_call(create_group_member, data->group_id, user_id) < 0) {
      err("%s -> cannot add user to a group", logbuf);
      send_reply(p, -ULS_ERR_DB_ERROR);
      return;
    }
  }

  const struct userlist_user *u = 0;
  if (default_get_user_info_1(user_id, &u) < 0 || !u) {
    send_reply(p, -ULS_ERR_DB_ERROR);
    err("%s -> database error", logbuf);
    return;
  }

  if (!email_str || !*email_str) send_email_flag = 0;
  /* FIXME: check other conditions when email is not send */

  if (send_email_flag) {
    send_registration_email(cnts, u, 0, NULL, 0);
  }

  if (!send_email_flag || !data->confirm_email_flag) {
    default_touch_login_time(user_id, 0, cur_time);
  }

  struct userlist_pk_login_ok out;
  memset(&out, 0, sizeof(out));
  out.reply_id = ULS_LOGIN_OK;
  out.user_id = user_id;
  enqueue_reply_to_client(p, sizeof(out), &out);
  info("%s -> OK, %d", logbuf, user_id);
}

static void
cmd_next_user(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_list_users_2 *data)
{
  unsigned char logbuf[1024];
  const struct contest_desc *cnts = 0;
  int user_id = 0;

  snprintf(logbuf, sizeof(logbuf), "NEXT_USER: %d, %d, %d, %d", p->user_id,
           data->user_id, data->contest_id, data->group_id);

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;

  int (*func)(void *, int contest_id, int group_id, int user_id, const unsigned char *filter, int *p_user_id);
  switch (data->request_id) {
  case ULS_PREV_USER:
    func = plugin_func(get_prev_user_id);
    break;
  case ULS_NEXT_USER:
    func = plugin_func(get_next_user_id);
    break;
  default:
    send_reply(p, -ULS_ERR_PROTOCOL);
    err("%s -> invalid request", logbuf);
    return;
  }

  struct userlist_pk_login_ok out;
  memset(&out, 0, sizeof(out));

  if (!func) {
    out.reply_id = ULS_LOGIN_OK;
    out.user_id = 0;
    enqueue_reply_to_client(p, sizeof(out), &out);
    info("%s -> not implemented, %d", logbuf, 0);
    return;
  }

  if (func(uldb_default->data, data->contest_id, data->group_id, data->user_id, data->data, &user_id) < 0) {
    err("%s -> database error", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  out.reply_id = ULS_LOGIN_OK;
  out.user_id = user_id;
  enqueue_reply_to_client(p, sizeof(out), &out);
  info("%s -> OK, %d", logbuf, user_id);
}

static void
cmd_list_all_users_3(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_list_users_2 *data)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  bitset_t marked = BITSET_INITIALIZER;
  int user_id;

  snprintf(logbuf, sizeof(logbuf), "LIST_ALL_USERS_3: %d, %d, %d, %d, %d",
           p->user_id, data->contest_id, data->group_id, data->offset, data->count);

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id > 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;

  bitset_url_decode(data->data, &marked);
  f = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(f, -1);
  if (marked.size > 0) {
    for (user_id = 1; user_id < marked.size; ++user_id) {
      if (bitset_get(&marked, user_id)) {
        if (default_get_user_info_4(user_id, data->contest_id, &u) >= 0 && u) {
          userlist_unparse_user_short(u, f, data->contest_id);
          default_unlock_user(u);
        }
      }
    }
  }
  userlist_write_xml_footer(f);
  close_memstream(f); f = 0;
  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size;
  out = (struct userlist_pk_xml_data*) xmalloc(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr); xml_ptr = 0;
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu", logbuf, xml_size);
  xfree(out); out = 0;
  bitset_free(&marked);
}

static void
cmd_list_all_users_4(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_list_users_2 *data)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size = 0;
  const struct contest_desc *cnts = 0;
  unsigned char logbuf[1024];
  const struct userlist_user *u = 0;
  bitset_t marked = BITSET_INITIALIZER;
  int user_id;

  snprintf(logbuf, sizeof(logbuf), "LIST_ALL_USERS_4: %d, %d, %d, %d, %d",
           p->user_id, data->contest_id, data->group_id, data->offset, data->count);

  if (is_judge(p, logbuf) < 0) return;
  if (data->contest_id > 0) {
    if (full_get_contest(p, logbuf, &data->contest_id, &cnts) < 0) return;
  }
  if (is_dbcnts_capable(p, cnts, OPCAP_LIST_USERS, logbuf) < 0) return;

  bitset_url_decode(data->data, &marked);
  f = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(f, -1);
  if (marked.size > 0) {
    for (user_id = 1; user_id < marked.size; ++user_id) {
      if (bitset_get(&marked, user_id)) {
        if (default_get_user_info_5(user_id, data->contest_id, &u) >= 0 && u) {
          userlist_real_unparse_user(u, f, USERLIST_MODE_ALL, data->contest_id,
                                     USERLIST_SHOW_REG_PASSWD | USERLIST_SHOW_CNTS_PASSWD);
          default_unlock_user(u);
        }
      }
    }
  }
  userlist_write_xml_footer(f);
  close_memstream(f); f = 0;
  ASSERT(xml_size == strlen(xml_ptr));
  out_size = sizeof(*out) + xml_size;
  out = (struct userlist_pk_xml_data*) xmalloc(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr); xml_ptr = 0;
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu", logbuf, xml_size);
  xfree(out); out = 0;
  bitset_free(&marked);
}

static void
cmd_get_group_info(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_map_contest *data)
{
  unsigned char logbuf[1024];
  const struct userlist_group *grp;
  char *xml_ptr = 0;
  size_t xml_size = 0;
  FILE *fout = 0;
  struct userlist_pk_xml_data *out = 0;
  size_t out_size;

  snprintf(logbuf, sizeof(logbuf), "GET_GROUP_INFO: %d, %d",
           p->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;

  grp = plugin_call(get_group, data->contest_id);
  if (!grp) {
    err("%s -> invalid group %d", logbuf, data->contest_id);
    send_reply(p, -ULS_ERR_BAD_GROUP_ID);
    return;
  }

  fout = open_memstream(&xml_ptr, &xml_size);
  userlist_write_xml_header(fout, -1);
  userlist_write_groups_header(fout);
  userlist_unparse_usergroup(fout, grp, "      ", "\n");
  userlist_write_groups_footer(fout);
  userlist_write_xml_footer(fout);
  fclose(fout); fout = 0;

  out_size = sizeof(*out) + xml_size;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->reply_id = ULS_XML_DATA;
  out->info_len = xml_size;
  memcpy(out->data, xml_ptr, xml_size + 1);
  xfree(xml_ptr); xml_ptr = 0;
  enqueue_reply_to_client(p, out_size, out);
  info("%s -> OK, size = %zu", logbuf, xml_size);
}

static void
cmd_create_cookie(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_cookie_login *data)
{
  unsigned char logbuf[1024];
  unsigned char cbuf[64];
  struct userlist_pk_login_ok *answer = NULL;
  int ans_len = 0;
  const struct userlist_cookie *cookie = NULL;
  time_t current_time = time(NULL);

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet size is invalid: %d instead of %d", pkt_len, (int) sizeof(*data));
    return;
  }
  snprintf(logbuf, sizeof(logbuf), "CREATE_COOKIE: %s, %d, %d, %d",
           xml_unparse_ipv6(&data->origin_ip), data->ssl, data->user_id, data->contest_id);

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf) < 0) return;

  int r = default_new_cookie_2(
    data->user_id,
    &data->origin_ip,
    data->ssl,
    0 /* cookie */,     // ignore data->cookie
    data->client_key,
    0 /* expire */,     // ignore data->expire
    data->contest_id,
    0 /* locale_id */,  // ignore data->locale_id
    0 /* priv_level */, // ignore data->priv_level
    0 /* role*/,        // ignore data->role
    0 /* recovery */,   // ignore data->recovery
    data->team_login,
    0 /* is_ws */,
    data->is_job,
    &cookie);
  if (r < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  ans_len = sizeof(struct userlist_pk_login_ok);
  answer = alloca(ans_len);
  memset(answer, 0, ans_len);
  answer->reply_id = ULS_LOGIN_COOKIE;

  answer->user_id = cookie->user_id;
  answer->cookie = cookie->cookie;
  answer->client_key = cookie->client_key;
  answer->contest_id = cookie->contest_id;
  answer->locale_id = cookie->locale_id;
  answer->priv_level = cookie->priv_level;
  answer->role = cookie->role;
  answer->team_login = cookie->team_login;
  answer->expire = cookie->expire;

  default_touch_login_time(data->user_id, data->contest_id, current_time);

  enqueue_reply_to_client(p, ans_len, answer);
  info("%s -> OK, %d, %s, %lld", logbuf, data->user_id,
       xml_unparse_full_cookie(cbuf, sizeof(cbuf), &answer->cookie, &answer->client_key),
       (long long) answer->expire);
}

static void
cmd_priv_create_cookie(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_cookie_login *data)
{
  unsigned char logbuf[1024];
  unsigned char cbuf[64];
  struct userlist_pk_login_ok *answer = NULL;
  int ans_len = 0;
  const struct userlist_cookie *cookie = NULL;

  if (pkt_len != sizeof(*data)) {
    CONN_BAD("packet size is invalid: %d instead of %d", pkt_len, (int) sizeof(*data));
    return;
  }
  snprintf(logbuf, sizeof(logbuf), "PRIV_CREATE_COOKIE: %s, %d, %d, %d, %d, %d",
           xml_unparse_ipv6(&data->origin_ip), data->ssl, data->user_id, data->contest_id, data->priv_level, data->role);

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf) < 0) return;

  int r = default_new_cookie_2(
    data->user_id,
    &data->origin_ip,
    data->ssl,
    0 /* cookie */,     // ignore data->cookie
    data->client_key,
    0 /* expire */,     // ignore data->expire
    data->contest_id,
    0 /* locale_id */,  // ignore data->locale_id
    data->priv_level,
    data->role,
    0 /* recovery */,   // ignore data->recovery
    data->team_login,
    0 /* is_ws */,
    data->is_job,
    &cookie);
  if (r < 0) {
    err("%s -> cookie creation failed", logbuf);
    send_reply(p, -ULS_ERR_OUT_OF_MEM);
    return;
  }

  ans_len = sizeof(struct userlist_pk_login_ok);
  answer = alloca(ans_len);
  memset(answer, 0, ans_len);
  answer->reply_id = ULS_LOGIN_COOKIE;

  answer->user_id = cookie->user_id;
  answer->cookie = cookie->cookie;
  answer->client_key = cookie->client_key;
  answer->contest_id = cookie->contest_id;
  answer->locale_id = cookie->locale_id;
  answer->priv_level = cookie->priv_level;
  answer->role = cookie->role;
  answer->team_login = cookie->team_login;
  answer->expire = cookie->expire;

  enqueue_reply_to_client(p, ans_len, answer);
  info("%s -> OK, %d, %s, %lld", logbuf, data->user_id,
       xml_unparse_full_cookie(cbuf, sizeof(cbuf), &answer->cookie, &answer->client_key),
       (long long) answer->expire);
}

static int
check_pk_api_key_data(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_api_key_data *data)
{
  if (pkt_len < sizeof(struct userlist_pk_api_key_data)) {
    CONN_BAD("packet length mismatch");
    return -1;
  }
  if (data->contest_info_count != 0 && data->contest_info_count != 1) {
    CONN_BAD("contest_info_count value invalid");
    return -1;
  }
  int contest_info_size = data->contest_info_count * sizeof(struct userlist_pk_contest_info);
  if (!data->api_key_count) {
    if (pkt_len != sizeof(struct userlist_pk_api_key_data) + contest_info_size) {
      CONN_BAD("packet length mismatch");
      return -1;
    }
    if (data->string_pool_size) {
      CONN_BAD("invalid string pool size");
      return -1;
    }
    return 0;
  }
  if (data->api_key_count < 0 || data->api_key_count > 100) {
    CONN_BAD("api_key_count value invalid");
    return -1;
  }
  if (data->string_pool_size <= 0 || data->string_pool_size > 100000) {
    CONN_BAD("string_pool_size value invalid");
    return -1;
  }

  // more checks
  /*
struct userlist_pk_api_key
{
  char token[32];
  ej_time64_t create_time;
  ej_time64_t expiry_time;
  int user_id;
  int contest_id;
  int payload_offset;
  int origin_offset;
};

struct userlist_pk_api_key_data
{
  short request_id;
  int api_key_count;
  int string_pool_size;
  struct userlist_pk_api_key api_keys[0];
};
   */

  return 0;
}

static void
make_pk_api_key_data(
        int in_count,
        const struct userlist_api_key **in_api_keys,
        struct userlist_contest_info *cnts_info,
        struct userlist_pk_api_key_data **p_out_pkt,
        int *p_out_size)
{
  int string_pool_size = 1;
  int out_size = sizeof(struct userlist_pk_api_key_data);

  ASSERT(in_count >= 0);

  if (!in_count) {
    void *out_data = malloc(out_size);
    memset(out_data, 0, out_size);
    struct userlist_pk_api_key_data *out_pkt = out_data;
    out_pkt->api_key_count = in_count;
    out_pkt->string_pool_size = 0;

    *p_out_pkt = out_pkt;
    *p_out_size = out_size;
    return;
  }

  for (int i = 0; i < in_count; ++i) {
    const struct userlist_api_key *k = in_api_keys[i];
    if (k->payload) {
      string_pool_size += strlen(k->payload) + 1;
    }
    if (k->origin) {
      string_pool_size += strlen(k->origin) + 1;
    }
  }
  out_size += sizeof(struct userlist_pk_api_key) * in_count;

  int contest_info_size = 0;
  if (cnts_info) {
    contest_info_size = sizeof(struct userlist_pk_contest_info);
    if (cnts_info->login) {
      string_pool_size += strlen(cnts_info->login) + 1;
    }
    if (cnts_info->name) {
      string_pool_size += strlen(cnts_info->name) + 1;
    }
  }
  out_size += contest_info_size;
  out_size += string_pool_size;

  void *out_data = malloc(out_size);
  memset(out_data, 0, out_size);
  struct userlist_pk_api_key_data *out_pkt = out_data;
  char *out_pool = (char*) out_pkt->api_keys + sizeof(struct userlist_pk_api_key) * in_count + contest_info_size;
  int out_offset = 1;
  for (int i = 0; i < in_count; ++i) {
    const struct userlist_api_key *in_k = in_api_keys[i];
    struct userlist_pk_api_key *out_k = &out_pkt->api_keys[i];
    memcpy(out_k->token, in_k->token, sizeof(out_k->token));
    memcpy(out_k->secret, in_k->secret, sizeof(out_k->secret));
    out_k->create_time = in_k->create_time;
    out_k->expiry_time = in_k->expiry_time;
    out_k->user_id = in_k->user_id;
    out_k->contest_id = in_k->contest_id;
    out_k->all_contests = in_k->all_contests;
    out_k->role = in_k->role;
    if (in_k->payload) {
      out_k->payload_offset = out_offset;
      int len = strlen(in_k->payload);
      memcpy(out_pool + out_offset, in_k->payload, len);
      out_offset += len + 1;
    }
    if (in_k->origin) {
      out_k->origin_offset = out_offset;
      int len = strlen(in_k->origin);
      memcpy(out_pool + out_offset, in_k->origin, len);
      out_offset += len + 1;
    }
  }

  if (cnts_info) {
    struct userlist_pk_contest_info *out_cnts_info = (struct userlist_pk_contest_info *) ((char*) out_pkt->api_keys + sizeof(struct userlist_pk_api_key) * in_count);
    out_cnts_info->user_id = cnts_info->user_id;
    out_cnts_info->contest_id = cnts_info->contest_id;
    if (cnts_info->login) {
      out_cnts_info->login_offset = out_offset;
      int len = strlen(cnts_info->login);
      memcpy(out_pool + out_offset, cnts_info->login, len);
      out_offset += len + 1;
    }
    if (cnts_info->name) {
      out_cnts_info->name_offset = out_offset;
      int len = strlen(cnts_info->name);
      memcpy(out_pool + out_offset, cnts_info->name, len);
      out_offset += len + 1;
    }
    out_cnts_info->reg_status = cnts_info->reg_status;
    out_cnts_info->reg_flags = cnts_info->reg_flags;
    out_pkt->contest_info_count = 1;
  }

  out_pkt->api_key_count = in_count;
  out_pkt->string_pool_size = string_pool_size;

  *p_out_pkt = out_pkt;
  *p_out_size = out_size;
}

static void
cmd_create_api_key(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_api_key_data *data)
{

  if (data->api_key_count != 1) {
    err("CREATE_API_KEY: -> invalid api_key_count %d", data->api_key_count);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if (!dflt_iface->new_api_key) {
    send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
    return;
  }

  struct userlist_pk_api_key *in_apk = &data->api_keys[0];
  char *in_pool = (char*) data->api_keys + data->api_key_count * sizeof(struct userlist_pk_api_key);

  unsigned char logbuf[1024];
  snprintf(logbuf, sizeof(logbuf), "CREATE_API_KEY: %d, %d", in_apk->user_id, in_apk->contest_id);

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_CREATE_USER, logbuf) < 0) return;

  int existing_api_key_count = dflt_iface->get_api_keys_count(uldb_default->data, in_apk->user_id);
  if (existing_api_key_count >= 10) {
    send_reply(p, -ULS_ERR_TOO_MANY_API_KEYS);
    return;
  }

  static const char zero_token[32] = {};
  struct userlist_api_key apk;
  memset(&apk, 0, sizeof(apk));
  if (!memcmp(in_apk->token, zero_token, 32)) {
    random_bytes(apk.token, 32);
  } else {
    memcpy(&apk.token, in_apk->token, 32);
  }
  if (!memcmp(in_apk->secret, zero_token, 32)) {
    random_bytes(apk.secret, 32);
  } else {
    memcpy(&apk.secret, in_apk->secret, 32);
  }
  apk.user_id = in_apk->user_id;
  apk.contest_id = in_apk->contest_id;
  apk.create_time = in_apk->create_time;
  if (apk.create_time <= 0) {
    apk.create_time = time(NULL);
  }
  apk.expiry_time = in_apk->expiry_time;
  apk.all_contests = in_apk->all_contests;
  apk.role = in_apk->role;
  if (in_apk->payload_offset) {
    apk.payload = in_pool + in_apk->payload_offset;
  }
  if (in_apk->origin_offset) {
    apk.origin = in_pool + in_apk->origin_offset;
  }

  const struct userlist_api_key *res_apk = NULL;
  int r = dflt_iface->new_api_key(uldb_default->data, &apk, &res_apk);
  if (r < 0) {
    err("%s -> api_key creation failed", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  struct userlist_pk_api_key_data *out_pkt = NULL;
  int out_size = 0;
  make_pk_api_key_data(1, (const struct userlist_api_key *[1]) { res_apk }, NULL, &out_pkt, &out_size);
  out_pkt->request_id = ULS_API_KEY_DATA;
  enqueue_reply_to_client(p, out_size, out_pkt);
  info("%s -> OK", logbuf);
  xfree(out_pkt);
}

static void
cmd_get_api_key(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_api_key_data *data)
{
  if (data->api_key_count != 1) {
    err("GET_API_KEY: -> invalid api_key_count %d", data->api_key_count);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if (!dflt_iface->get_api_key) {
    send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
    return;
  }

  struct userlist_pk_api_key *in_apk = &data->api_keys[0];

  char token_buf[64];
  int token_len = base64u_encode(in_apk->token, 32, token_buf);
  token_buf[token_len] = 0;
  unsigned char logbuf[1024];
  snprintf(logbuf, sizeof(logbuf), "GET_API_KEY: %s", token_buf);

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf) < 0) return;

  const struct userlist_api_key *res_apk = NULL;
  int r = dflt_iface->get_api_key(uldb_default->data, in_apk->token, &res_apk);
  if (r < 0) {
    err("%s -> api_key fetch failed", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  struct userlist_pk_api_key_data *out_pkt = NULL;
  int out_size = 0;

  if (!r) {
    make_pk_api_key_data(0, NULL, NULL, &out_pkt, &out_size);
  } else {
    struct userlist_contest_info uci = {};
    struct userlist_contest_info *puci = NULL;

    if (data->contest_info_count == 1 && res_apk) {
      int cnts_user_id = res_apk->user_id;
      int cnts_contest_id = 0;
      const struct contest_desc *cnts = NULL;

      if (!res_apk->all_contests) {
        if (res_apk->contest_id > 0 && contests_get(res_apk->contest_id, &cnts) >= 0 && cnts) {
          cnts_contest_id = res_apk->contest_id;
        }
      } else if (!in_apk->contest_id && res_apk->contest_id > 0) {
        if (res_apk->contest_id > 0 && contests_get(res_apk->contest_id, &cnts) >= 0 && cnts) {
          cnts_contest_id = res_apk->contest_id;
        }
      } else if (in_apk->contest_id > 0) {
        if (contests_get(in_apk->contest_id, &cnts) >= 0 && cnts) {
          cnts_contest_id = in_apk->contest_id;
        }
      }

      if (cnts_user_id > 0 && cnts_contest_id > 0) {
        int check_contest_id = cnts_contest_id;
        if (full_get_contest(p, logbuf, &check_contest_id, &cnts) < 0) {
          xfree(out_pkt);
          return;
        }

        const struct userlist_user *u = NULL;
        const struct userlist_user_info *ui = NULL;
        const struct userlist_contest *c = NULL;
        if (default_get_user_info_3(cnts_user_id, check_contest_id, &u, &ui, &c) >= 0) {
          if (!c) {
            err("%s -> not registered for contest", logbuf);
            send_reply(p, -ULS_ERR_NOT_REGISTERED);
            xfree(out_pkt);
            return;
          }
          uci.user_id = cnts_user_id;
          uci.contest_id = cnts_contest_id;
          if (u && u->login) {
            uci.login = xstrdup(u->login);
          }
          if (ui && ui->name) {
            uci.name = xstrdup(ui->name);
          }
          uci.reg_status = c->status;
          uci.reg_flags = c->flags;
          puci = &uci;
        }
      }
    }

    make_pk_api_key_data(1, (const struct userlist_api_key *[1]) { res_apk }, puci, &out_pkt, &out_size);
    xfree(uci.login);
    xfree(uci.name);
  }

  out_pkt->request_id = ULS_API_KEY_DATA;
  enqueue_reply_to_client(p, out_size, out_pkt);
  info("%s -> OK", logbuf);
  xfree(out_pkt);
}

static void
cmd_get_api_keys_for_user(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_api_key_data *data)
{
  if (data->api_key_count != 1) {
    err("GET_API_KEYS_FOR_USER: -> invalid api_key_count %d", data->api_key_count);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if (!dflt_iface->get_api_keys_for_user) {
    send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
    return;
  }

  struct userlist_pk_api_key *in_apk = &data->api_keys[0];

  unsigned char logbuf[1024];
  snprintf(logbuf, sizeof(logbuf), "GET_API_KEYS_FOR_USER: %d", in_apk->user_id);

  if (in_apk->user_id <= 0) {
    err("%s -> invalid user_id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf) < 0) return;

  const struct userlist_api_key **res_apks = NULL;
  int r = dflt_iface->get_api_keys_for_user(uldb_default->data, in_apk->user_id, &res_apks);
  if (r < 0) {
    err("%s -> api_key fetch failed", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  struct userlist_pk_api_key_data *out_pkt = NULL;
  int out_size = 0;
  make_pk_api_key_data(r, res_apks, NULL, &out_pkt, &out_size);
  out_pkt->request_id = ULS_API_KEY_DATA;
  enqueue_reply_to_client(p, out_size, out_pkt);
  info("%s -> OK", logbuf);
  xfree(out_pkt);
  xfree(res_apks);
}

static void
cmd_delete_api_key(
        struct client_state *p,
        int pkt_len,
        struct userlist_pk_api_key_data *data)
{
  if (data->api_key_count != 1) {
    err("DELETE_API_KEY: -> invalid api_key_count %d", data->api_key_count);
    send_reply(p, -ULS_ERR_PROTOCOL);
    return;
  }
  if (!dflt_iface->get_api_keys_for_user) {
    send_reply(p, -ULS_ERR_NOT_IMPLEMENTED);
    return;
  }

  struct userlist_pk_api_key *in_apk = &data->api_keys[0];

  char token_buf[64];
  int token_len = base64u_encode(in_apk->token, 32, token_buf);
  token_buf[token_len] = 0;
  unsigned char logbuf[1024];
  snprintf(logbuf, sizeof(logbuf), "DELETE_API_KEY: %d, %s", in_apk->user_id, token_buf);

  if (in_apk->user_id <= 0) {
    err("%s -> invalid user_id", logbuf);
    send_reply(p, -ULS_ERR_BAD_UID);
    return;
  }

  if (is_admin(p, logbuf) < 0) return;
  if (is_db_capable(p, OPCAP_LIST_USERS, logbuf) < 0) return;

  int r = dflt_iface->remove_api_key(uldb_default->data, in_apk->user_id, in_apk->token);
  if (r < 0) {
    err("%s -> failed", logbuf);
    send_reply(p, -ULS_ERR_DB_ERROR);
    return;
  }

  send_reply(p, ULS_OK);
  info("%s -> OK", logbuf);
}

static void (*cmd_table[])() =
{
  [ULS_REGISTER_NEW] =          cmd_register_new,
  [ULS_DO_LOGIN] =              cmd_login,
  [ULS_CHECK_COOKIE] =          cmd_check_cookie,
  [ULS_DO_LOGOUT] =             cmd_do_logout,
  [ULS_GET_USER_INFO] =         cmd_get_user_info,
  [ULS_SET_USER_INFO] =         cmd_set_user_info,
  [ULS_SET_PASSWD] =            cmd_set_passwd,
  [ULS_GET_USER_CONTESTS] =     cmd_get_user_contests,
  [ULS_REGISTER_CONTEST] =      cmd_register_contest,
  [ULS_DELETE_MEMBER] =         cmd_delete_member,
  [ULS_PASS_FD] =               cmd_pass_fd,
  [ULS_LIST_USERS] =            cmd_list_users,
  [ULS_MAP_CONTEST] =           cmd_map_contest,
  [ULS_ADMIN_PROCESS] =         cmd_admin_process,
  [ULS_GENERATE_TEAM_PASSWORDS]=cmd_generate_team_passwords,
  [ULS_TEAM_LOGIN] =            cmd_team_login,
  [ULS_TEAM_CHECK_COOKIE] =     cmd_team_check_cookie,
  [ULS_GET_CONTEST_NAME] =      cmd_get_contest_name,
  [ULS_TEAM_SET_PASSWD] =       cmd_team_set_passwd,
  [ULS_LIST_ALL_USERS] =        cmd_list_all_users,
  [ULS_EDIT_REGISTRATION] =     cmd_edit_registration,
  [ULS_EDIT_FIELD] =            cmd_edit_field,
  [ULS_DELETE_FIELD] =          cmd_delete_field,
  [ULS_ADD_FIELD] =             0,
  [ULS_GET_UID_BY_PID] =        cmd_get_uid_by_pid,
  [ULS_PRIV_LOGIN] =            cmd_priv_login,
  [ULS_PRIV_CHECK_COOKIE] =     cmd_priv_check_cookie,
  [ULS_DUMP_DATABASE] =         cmd_dump_database,
  [ULS_PRIV_GET_USER_INFO] =    cmd_priv_get_user_info,
  [ULS_PRIV_REGISTER_CONTEST] = cmd_priv_register_contest,
  [ULS_GENERATE_PASSWORDS] =    cmd_generate_register_passwords,
  [ULS_CLEAR_TEAM_PASSWORDS] =  cmd_clear_team_passwords,
  [ULS_LIST_STANDINGS_USERS] =  cmd_list_standings_users,
  [ULS_GET_UID_BY_PID_2] =      cmd_get_uid_by_pid_2,
  [ULS_IS_VALID_COOKIE] =       cmd_is_valid_cookie,
  [ULS_DUMP_WHOLE_DATABASE] =   cmd_dump_whole_database,
  [ULS_RANDOM_PASSWD] =         cmd_user_op,
  [ULS_RANDOM_TEAM_PASSWD] =    cmd_user_op,
  [ULS_COPY_TO_TEAM] =          cmd_user_op,
  [ULS_COPY_TO_REGISTER] =      cmd_user_op,
  [ULS_FIX_PASSWORD] =          cmd_user_op,
  [ULS_LOOKUP_USER] =           cmd_lookup_user,
  [ULS_REGISTER_NEW_2] =        cmd_register_new_2,
  [ULS_DELETE_USER] =           cmd_delete_user,
  [ULS_DELETE_COOKIE] =         cmd_delete_cookie,
  [ULS_DELETE_USER_INFO] =      cmd_delete_user_info,
  [ULS_CREATE_USER] =           cmd_create_user,
  [ULS_CREATE_MEMBER] =         cmd_create_member,
  [ULS_PRIV_DELETE_MEMBER] =    cmd_priv_delete_member,
  [ULS_PRIV_CHECK_USER] =       cmd_priv_check_user,
  [ULS_PRIV_GET_COOKIE] =       cmd_get_cookie,
  [ULS_LOOKUP_USER_ID] =        cmd_lookup_user_id,
  [ULS_TEAM_CHECK_USER] =       cmd_team_check_user,
  [ULS_TEAM_GET_COOKIE] =       cmd_get_cookie,
  [ULS_ADD_NOTIFY] =            cmd_observer_cmd,
  [ULS_DEL_NOTIFY] =            cmd_observer_cmd,
  [ULS_SET_COOKIE_LOCALE] =     cmd_set_cookie,
  [ULS_PRIV_SET_REG_PASSWD] =   cmd_priv_set_passwd,
  [ULS_PRIV_SET_TEAM_PASSWD] =  cmd_priv_set_passwd,
  [ULS_GENERATE_TEAM_PASSWORDS_2]=cmd_generate_team_passwords_2,
  [ULS_GENERATE_PASSWORDS_2] =  cmd_generate_register_passwords_2,
  [ULS_GET_DATABASE] =          cmd_get_database,
  [ULS_COPY_USER_INFO] =        cmd_copy_user_info,
  [ULS_RECOVER_PASSWORD_1] =    cmd_recover_password_1,
  [ULS_RECOVER_PASSWORD_2] =    cmd_recover_password_2,
  [ULS_STOP] =                  cmd_control_server,
  [ULS_RESTART] =               cmd_control_server,
  [ULS_PRIV_COOKIE_LOGIN] =     cmd_priv_cookie_login,
  [ULS_CHECK_USER] =            cmd_check_user,
  [ULS_REGISTER_CONTEST_2] =    cmd_register_contest_2,
  [ULS_GET_COOKIE] =            cmd_get_cookie,
  [ULS_EDIT_FIELD_SEQ] =        cmd_edit_field_seq,
  [ULS_MOVE_MEMBER] =           cmd_move_member,
  [ULS_IMPORT_CSV_USERS] =      cmd_import_csv_users,
  [ULS_FETCH_COOKIE] =          cmd_get_cookie,
  [ULS_LIST_ALL_GROUPS] =       cmd_list_all_groups,
  [ULS_CREATE_GROUP] =          cmd_create_group,
  [ULS_DELETE_GROUP] =          cmd_delete_group,
  [ULS_EDIT_GROUP_FIELD] =      cmd_edit_group_field,
  [ULS_DELETE_GROUP_FIELD] =    cmd_delete_group_field,
  [ULS_LIST_GROUP_USERS] =      cmd_list_group_users,
  [ULS_CREATE_GROUP_MEMBER] =   cmd_create_group_member,
  [ULS_DELETE_GROUP_MEMBER] =   cmd_delete_group_member,
  [ULS_GET_GROUPS] =            cmd_get_groups,
  [ULS_LIST_ALL_USERS_2] =      cmd_list_all_users_2,
  [ULS_GET_USER_COUNT] =        cmd_get_user_count,
  [ULS_LIST_ALL_GROUPS_2] =     cmd_list_all_groups_2,
  [ULS_GET_GROUP_COUNT] =       cmd_get_group_count,
  [ULS_PRIV_SET_REG_PASSWD_PLAIN] = cmd_priv_set_passwd_2,
  [ULS_PRIV_SET_REG_PASSWD_SHA1] = cmd_priv_set_passwd_2,
  [ULS_PRIV_SET_CNTS_PASSWD_PLAIN] = cmd_priv_set_passwd_2,
  [ULS_PRIV_SET_CNTS_PASSWD_SHA1] = cmd_priv_set_passwd_2,
  [ULS_CREATE_USER_2] =         cmd_create_user_2,
  [ULS_PREV_USER] =             cmd_next_user,
  [ULS_NEXT_USER] =             cmd_next_user,
  [ULS_LIST_ALL_USERS_3] =      cmd_list_all_users_3,
  [ULS_LIST_ALL_USERS_4] =      cmd_list_all_users_4,
  [ULS_GET_GROUP_INFO] =        cmd_get_group_info,
  [ULS_PRIV_CHECK_PASSWORD] =   cmd_priv_check_password,
  [ULS_LIST_STANDINGS_USERS_2] =cmd_list_standings_users_2,
  [ULS_CHECK_USER_2] =          cmd_check_user_2,
  [ULS_CREATE_COOKIE] =         cmd_create_cookie,
  [ULS_CREATE_API_KEY] =        cmd_create_api_key,
  [ULS_GET_API_KEY] =           cmd_get_api_key,
  [ULS_GET_API_KEYS_FOR_USER] = cmd_get_api_keys_for_user,
  [ULS_DELETE_API_KEY] =        cmd_delete_api_key,
  [ULS_PRIV_CREATE_COOKIE] =    cmd_priv_create_cookie,
  [ULS_COPY_ALL] =              cmd_copy_all,

  [ULS_LAST_CMD] = 0
};

static int (*check_table[])() =
{
  [ULS_REGISTER_NEW] =          0,
  [ULS_DO_LOGIN] =              0,
  [ULS_CHECK_COOKIE] =          0,
  [ULS_DO_LOGOUT] =             0,
  [ULS_GET_USER_INFO] =         0,
  [ULS_SET_USER_INFO] =         check_pk_set_user_info,
  [ULS_SET_PASSWD] =            check_pk_set_password,
  [ULS_GET_USER_CONTESTS] =     0,
  [ULS_REGISTER_CONTEST] =      check_pk_register_contest,
  [ULS_DELETE_MEMBER] =         0,
  [ULS_PASS_FD] =               0,
  [ULS_LIST_USERS] =            0,
  [ULS_MAP_CONTEST] =           check_pk_map_contest,
  [ULS_ADMIN_PROCESS] =         0,
  [ULS_GENERATE_TEAM_PASSWORDS]=check_pk_map_contest,
  [ULS_TEAM_LOGIN] =            0,
  [ULS_TEAM_CHECK_COOKIE] =     0,
  [ULS_GET_CONTEST_NAME] =      check_pk_map_contest,
  [ULS_TEAM_SET_PASSWD] =       check_pk_set_password,
  [ULS_LIST_ALL_USERS] =        check_pk_map_contest,
  [ULS_EDIT_REGISTRATION] =     0,
  [ULS_EDIT_FIELD] =            check_pk_edit_field,
  [ULS_DELETE_FIELD] =          check_pk_edit_field,
  [ULS_ADD_FIELD] =             0,
  [ULS_GET_UID_BY_PID] =        0,
  [ULS_PRIV_LOGIN] =            0,
  [ULS_PRIV_CHECK_COOKIE] =     0,
  [ULS_DUMP_DATABASE] =         0,
  [ULS_PRIV_GET_USER_INFO] =    0,
  [ULS_PRIV_REGISTER_CONTEST] = check_pk_register_contest,
  [ULS_GENERATE_PASSWORDS] =    check_pk_map_contest,
  [ULS_CLEAR_TEAM_PASSWORDS] =  check_pk_map_contest,
  [ULS_LIST_STANDINGS_USERS] =  check_pk_map_contest,
  [ULS_GET_UID_BY_PID_2] =      0,
  [ULS_IS_VALID_COOKIE] =       0,
  [ULS_DUMP_WHOLE_DATABASE] =   0,
  [ULS_RANDOM_PASSWD] =         check_pk_register_contest,
  [ULS_RANDOM_TEAM_PASSWD] =    check_pk_register_contest,
  [ULS_COPY_TO_TEAM] =          check_pk_register_contest,
  [ULS_COPY_TO_REGISTER] =      check_pk_register_contest,
  [ULS_FIX_PASSWORD] =          check_pk_register_contest,
  [ULS_LOOKUP_USER] =           0,
  [ULS_REGISTER_NEW_2] =        0,
  [ULS_DELETE_USER] =           0,
  [ULS_DELETE_COOKIE] =         check_pk_edit_field,
  [ULS_DELETE_USER_INFO] =      0,
  [ULS_CREATE_USER] =           check_pk_edit_field,
  [ULS_CREATE_MEMBER] =         check_pk_edit_field,
  [ULS_PRIV_DELETE_MEMBER] =    0,
  [ULS_PRIV_CHECK_USER] =       0,
  [ULS_PRIV_GET_COOKIE] =       0,
  [ULS_LOOKUP_USER_ID] =        0,
  [ULS_TEAM_CHECK_USER] =       0,
  [ULS_TEAM_GET_COOKIE] =       0,
  [ULS_ADD_NOTIFY] =            check_pk_map_contest,
  [ULS_DEL_NOTIFY] =            check_pk_map_contest,
  [ULS_SET_COOKIE_LOCALE] =     check_pk_edit_field,
  [ULS_PRIV_SET_REG_PASSWD] =   check_pk_set_password,
  [ULS_PRIV_SET_TEAM_PASSWD] =  check_pk_set_password,
  [ULS_GENERATE_TEAM_PASSWORDS_2]=check_pk_map_contest,
  [ULS_GENERATE_PASSWORDS_2] =  check_pk_map_contest,
  [ULS_GET_DATABASE] =          0,
  [ULS_COPY_USER_INFO] =        check_pk_edit_field,
  [ULS_RECOVER_PASSWORD_1] =    0,
  [ULS_RECOVER_PASSWORD_2] =    0,
  [ULS_STOP] =                  0,
  [ULS_RESTART] =               0,
  [ULS_PRIV_COOKIE_LOGIN] =     0,
  [ULS_CHECK_USER] =            0,
  [ULS_REGISTER_CONTEST_2] =    check_pk_register_contest,
  [ULS_GET_COOKIE] =            0,
  [ULS_EDIT_FIELD_SEQ] =        0,
  [ULS_MOVE_MEMBER] =           0,
  [ULS_IMPORT_CSV_USERS] =      check_pk_edit_field,
  [ULS_FETCH_COOKIE] =          0,
  [ULS_LIST_ALL_GROUPS] =       check_pk_map_contest,
  [ULS_CREATE_GROUP] =          check_pk_edit_field,
  [ULS_DELETE_GROUP] =          check_pk_delete_info,
  [ULS_EDIT_GROUP_FIELD] =      check_pk_edit_field,
  [ULS_DELETE_GROUP_FIELD] =    check_pk_edit_field,
  [ULS_LIST_GROUP_USERS] =      check_pk_map_contest,
  [ULS_CREATE_GROUP_MEMBER] =   check_pk_register_contest,
  [ULS_DELETE_GROUP_MEMBER] =   check_pk_register_contest,
  [ULS_GET_GROUPS] =            check_pk_set_user_info,
  [ULS_LIST_ALL_USERS_2] =      check_pk_list_users_2,
  [ULS_GET_USER_COUNT] =        check_pk_list_users_2,
  [ULS_LIST_ALL_GROUPS_2] =     check_pk_list_users_2,
  [ULS_GET_GROUP_COUNT] =       check_pk_list_users_2,
  [ULS_PRIV_SET_REG_PASSWD_PLAIN] = check_pk_set_password,
  [ULS_PRIV_SET_REG_PASSWD_SHA1] = check_pk_set_password,
  [ULS_PRIV_SET_CNTS_PASSWD_PLAIN] = check_pk_set_password,
  [ULS_PRIV_SET_CNTS_PASSWD_SHA1] = check_pk_set_password,
  [ULS_CREATE_USER_2] =         check_pk_create_user_2,
  [ULS_PREV_USER] =             check_pk_list_users_2,
  [ULS_NEXT_USER] =             check_pk_list_users_2,
  [ULS_LIST_ALL_USERS_3] =      check_pk_list_users_2,
  [ULS_LIST_ALL_USERS_4] =      check_pk_list_users_2,
  [ULS_GET_GROUP_INFO] =        check_pk_map_contest,
  [ULS_LIST_STANDINGS_USERS_2] =check_pk_map_contest,
  [ULS_CHECK_USER] =            NULL,
  [ULS_CREATE_COOKIE] =         NULL,
  [ULS_CREATE_API_KEY] =        check_pk_api_key_data,
  [ULS_GET_API_KEY] =           check_pk_api_key_data,
  [ULS_GET_API_KEYS_FOR_USER] = check_pk_api_key_data,
  [ULS_DELETE_API_KEY] =        check_pk_api_key_data,
  [ULS_PRIV_CREATE_COOKIE] =    NULL,
  [ULS_COPY_ALL] =              check_pk_edit_field,

  [ULS_LAST_CMD] = 0
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
  if (check_table[packet->id]
      && (*check_table[packet->id])(p, pkt_len, data) < 0) {
    return;
  }
  (*cmd_table[packet->id])(p, pkt_len, data);
}

static void
check_observers(void)
{
  struct client_state *p;
  struct observer_info *o;
  struct userlist_pk_notification out;

  for (p = first_client; p; p = p->next) {
    if (p->write_len > 0
        || p->state != STATE_READ_DATA
        || p->read_state != 0
        || p->o_count <= 0) continue;
    for (o = p->o_first; o; o = o->clnt_next)
      if (o->changed)
        break;
    if (!o) {
      p->o_count = 0;
      continue;
    }
    memset(&out, 0, sizeof(out));
    out.reply_id = ULS_NOTIFICATION;
    out.contest_id = o->contest->id;
    enqueue_reply_to_client(p, sizeof(out), &out);
    o->changed = 0;
    p->o_count--;
  }
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
  path_t socket_dir;

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, interrupt_signal);
  signal(SIGTERM, interrupt_signal);
  signal(SIGHUP, restart_signal);
  signal(SIGUSR1, usr1_signal);
  signal(SIGUSR2, usr2_signal);
  signal(SIGURG, winch_signal);

  if ((listen_socket = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
    err("socket() failed: %s", os_ErrorMsg());
    return 1;
  }

  // create the socket directory
  os_rDirName(config->socket_path, socket_dir, sizeof(socket_dir));
  os_MakeDirPath(socket_dir, 0775);
  if (os_IsFile(socket_dir) != OSPK_DIR) {
    err("%s is not a directory", socket_dir);
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
      dflt_iface->sync(uldb_default->data);
    }

    dflt_iface->maintenance(uldb_default->data, cur_time);

    if (interrupt_signaled) {
      graceful_exit();
    }

    if (usr1_signaled) {
      if (daemon_mode) {
        start_open_log(config->userlist_log);
      }
      usr1_signaled = 0;
    }
    /*
      FIXME: use another signal
    if (usr1_signaled) {
      default_forced_sync();
      if (dflt_iface->disable_cache)
        (*dflt_iface->disable_cache)(uldb_default->data);
      usr1_signaled = 0;
    }
    */
    if (usr2_signaled) {
      default_sync();
      if (dflt_iface->drop_cache)
        (*dflt_iface->drop_cache)(uldb_default->data);
      usr2_signaled = 0;
    }
    if (winch_signaled) {
      if (dflt_iface->enable_cache)
        (*dflt_iface->enable_cache)(uldb_default->data);
      winch_signaled = 0;
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
    /* check, that there exist outstanding observer events */
    check_observers();

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

        if (sock_op_enable_creds(new_fd) < 0) {
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
        if (sock_op_get_creds(p->fd, p->id, &p->peer_pid, &p->peer_uid,
                              &p->peer_gid) < 0) {
          disconnect_client(p);
          continue;
        }

        if (!daemon_mode)
          info("%d: received peer information: %d, %d, %d", p->id,
               p->peer_pid, p->peer_uid, p->peer_gid);

        p->state = STATE_READ_DATA;
        continue;
      } else if (p->state == STATE_READ_FDS) {
        if (sock_op_get_fds(p->fd, p->id, p->client_fds) < 0) {
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
  snprintf(buf1, sizeof(buf1), "%04d-%02d-%02d %02d:%02d:%02d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  ptm = localtime(&t2);
  snprintf(buf2, sizeof(buf2), "%04d-%02d-%02d %02d:%02d:%02d",
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

static void
cleanup_clients(void)
{
  int i;

  while (first_client) {
    disconnect_client(first_client);
  }

  if (contest_extras) {
    for (i = 0; i < contest_extras_size; i++) {
      if (contest_extras[i]) contest_extras[i]->nref = 1;
      contest_extras[i] = detach_contest_extra(contest_extras[i]);
    }
  }
}

static int
load_plugins(const unsigned char *plugin_dir)
{
  struct xml_tree *p;
  struct ejudge_plugin *plg;
  const struct common_loaded_plugin *iface = 0;

  if (!plugin_dir) plugin_dir = config->plugin_dir;
  plugin_set_directory(plugin_dir);

  //ejudge_cfg_unparse_plugins(config, stdout);
  if (!plugin_register_builtin(&uldb_plugin_xml.b, config)) {
    err("cannot load XML plugin");
    return 1;
  }

  // load other userdb plugins
  for (p = config->plugin_list; p; p = p->right) {
    plg = (struct ejudge_plugin*) p;

    if (!plg->load_flag) continue;
    if (strcmp(plg->type, "uldb") != 0) continue;

    if (!(iface = plugin_load_external(plg->path,plg->type,plg->name,config))) {
      err("cannot load plugin %s, %s", plg->type, plg->name);
      return 1;
    }

    if (plg->default_flag) {
      if (uldb_default) {
        err("more than one plugin is defined as default");
        return 1;
      }
      uldb_default = iface;
    }
  }

  if (!uldb_default) {
    info("using XML as the userlist database");
    uldb_default = plugin_get("uldb", "xml");
  }

  return 0;
}

static int
convert_database(const unsigned char *from_name, const unsigned char *to_name)
{
  const struct common_loaded_plugin *from_plugin = plugin_get("uldb",from_name);
  const struct common_loaded_plugin *to_plugin = plugin_get("uldb", to_name);
  int r, user_id;
  int_iterator_t ui;
  const struct userlist_user *u;
  int member_serial = 0;

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
  if (((struct uldb_plugin_iface*)from_plugin->iface)->open(from_plugin->data) < 0) {
    err("plugin %s failed to open its connection", from_name);
    return 1;
  }
  if ((r = ((struct uldb_plugin_iface*)from_plugin->iface)->check(from_plugin->data)) < 0) {
    err("plugin %s failed to check its data", from_name);
    return 1;
  }
  if (!r) {
    err("database of plugin %s contains no data", from_name);
    return 1;
  }

  if (!((struct uldb_plugin_iface *)from_plugin->iface)->get_member_serial) {
    err("`get_member_serial' is not implemented in plugin %s", from_name);
    return 1;
  }
  member_serial = ((struct uldb_plugin_iface *)from_plugin->iface)->get_member_serial(from_plugin->data);

  // prepare the destination plugin
  if (((struct uldb_plugin_iface*)to_plugin->iface)->open(to_plugin->data) < 0) {
    err("plugin %s failed to open its connection", to_plugin->iface->b.name);
    return 1;
  }
  int v = ((struct uldb_plugin_iface*)to_plugin->iface)->check(to_plugin->data);
  if (v < 0) {
    err("plugin %s database is invalid",to_plugin->iface->b.name);
    return 1;
  }
  if (v > 0) {
    info("plugin %s database already created",to_plugin->iface->b.name);
    return 0;
  }

  if (((struct uldb_plugin_iface*)to_plugin->iface)->create(to_plugin->data) < 0) {
    err("plugin %s failed to create a new database",to_plugin->iface->b.name);
    return 1;
  }

  // enumerate users
  for (ui = ((struct uldb_plugin_iface*)from_plugin->iface)->get_user_id_iterator(from_plugin->data);
       ui->has_next(ui);
       ui->next(ui)) {
    user_id = ui->get(ui);

    r = ((struct uldb_plugin_iface*)from_plugin->iface)->get_user_full(from_plugin->data, user_id, &u);
    ASSERT(r == 1);

    r = ((struct uldb_plugin_iface*)to_plugin->iface)->insert(to_plugin->data, u, &member_serial);
    if (r < 0) break;
  }
  ui->destroy(ui);

  return 0;
}

static void
arg_expected(const unsigned char *progname)
{
  fprintf(stderr, "%s: invalid number of arguments\n", progname);
  exit(1);
}

void *
forced_symbols[] =
{
  xml_err_elem_undefined_s,
  base64u_decode,
  ej_uuid_parse,
};

int
main(int argc, char *argv[])
{
  int code = 0;
  unsigned char *ejudge_xml_path = 0;
  int cur_arg = 1, j = 0;
  int pid;
  unsigned char *from_plugin = 0, *to_plugin = 0;
  int convert_flag = 0;
  int create_flag = 0;
  const unsigned char *user = 0, *group = 0, *workdir = 0, *plugin_dir = 0;
  char **argv_restart = 0;
  int restart_mode = 0;
  int disable_stack_trace = 0;

  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 2);
  argv_restart[j++] = argv[0];

  while (cur_arg < argc) {
    if (!strcmp(argv[cur_arg], "-D")) {
      daemon_mode = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-R")) {
      restart_mode = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-nst")) {
      disable_stack_trace = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-f")) {
      forced_mode = 1;
      argv_restart[j++] = argv[cur_arg];
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "--from-plugin")) {
      if (cur_arg + 1 >= argc) arg_expected(argv[0]);
      from_plugin = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "--to-plugin")) {
      if (cur_arg + 1 >= argc) arg_expected(argv[0]);
      to_plugin = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "--plugin-dir")) {
      if (cur_arg + 1 >= argc) arg_expected(argv[0]);
      plugin_dir = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "--convert")) {
      convert_flag = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "--create")) {
      create_flag = 1;
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
  if (disable_stack_trace <= 0) {
    start_enable_stacktrace(NULL);
  }

  if (!convert_flag && !create_flag) {
    if (!(pid = start_find_process("ej-users", NULL, 0))) {
      forced_mode = 1;
    } else if (pid > 0) {
      fprintf(stderr, "%s: is already running as pid %d\n", argv[0], pid);
      return 1;
    }
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

  if (start_prepare(user, group, workdir) < 0) return 1;

  info("ej-users %s, compiled %s", compile_version, compile_date);

  if (tsc_init() < 0) return 1;
  program_name = argv[0];
  config = ejudge_cfg_parse(ejudge_xml_path, 0);
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

  if (load_plugins(plugin_dir) != 0) return 1;

  if (convert_flag) {
    if (!from_plugin) {
      err("--from-plugin is undefined");
      return 1;
    }
    if (!to_plugin) {
      err("--to-plugin is undefined");
      return 1;
    }
    return convert_database(from_plugin, to_plugin);
  }

  // initialize the default plugin
  if (((struct uldb_plugin_iface*)uldb_default->iface)->open(uldb_default->data) < 0) {
    err("default plugin failed to open its connection");
    return 1;
  }

  if (create_flag) {
    if (dflt_iface->create(uldb_default->data) < 0) {
      err("database creation failed");
      return 1;
    }
    if (dflt_iface->close(uldb_default->data) < 0) {
      err("database closing failed");
      return 1;
    }
    return 0;
  }

  if (dflt_iface->check(uldb_default->data) <= 0) {
    err("default plugin failed to check its data");
    return 1;
  }

  // initialize system uid->local uid map
  //build_system_uid_map(config->user_map);

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
    if (start_open_log(config->userlist_log) < 0)
      return 1;

    if ((pid = fork()) < 0) return 1;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return 1;
  } else if (restart_mode) {
    if (start_open_log(config->userlist_log) < 0)
      return 1;
  }

  server_start_time = time(0);
  code = do_work();

  if (socket_name) unlink(socket_name);
  if (listen_socket >= 0) close(listen_socket);
  cleanup_clients();
  random_cleanup();
  ejudge_cfg_free(config);
  server_finish_time = time(0);
  report_uptime(server_start_time, server_finish_time);

  if (restart_signaled) start_restart();
  return code;
}
