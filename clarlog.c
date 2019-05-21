/* -*- c -*- */

/* Copyright (C) 2000-2019 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/clarlog.h"
#include "ejudge/cldb_plugin.h"
#include "ejudge/clarlog_state.h"
#include "ejudge/teamdb.h"
#include "ejudge/base64.h"
#include "unix/unix_fileutl.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/xml_utils.h"
#include "ejudge/charsets.h"
#include "ejudge/prepare.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#if defined EJUDGE_CHARSET
#define INTERNAL_CHARSET EJUDGE_CHARSET
#else
#define INTERNAL_CHARSET "utf-8"
#endif

#define ERR_R(t, args...) do { do_err_r(__FUNCTION__, t , ##args); return -1; } while (0)

clarlog_state_t
clar_init(void)
{
  clarlog_state_t p;

  XCALLOC(p, 1);
  return p;
}

clarlog_state_t
clar_destroy(clarlog_state_t state)
{
  int i;

  if (!state) return 0;
  xfree(state->clars.v);
  for (i = 0; i < state->allocd; i++)
    xfree(state->subjects[i]);
  xfree(state->subjects);
  xfree(state->charset_codes);
  if (state->iface) state->iface->close(state->cnts);
  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

static int
clar_expand(
        clarlog_state_t state,
        int new_id)
{
  if (new_id < 0) new_id = state->clars.u;
  if (new_id >= state->clars.a) {
    int new_a = state->clars.a;
    struct clar_entry_v2 *new_v = 0;

    if (!new_a) new_a = 128;
    while (new_id >= new_a) new_a *= 2;
    XCALLOC(new_v, new_a);
    if (state->clars.a) {
      memcpy(new_v, state->clars.v, state->clars.a * sizeof(new_v[0]));
    }
    for (int i = state->clars.a; i < new_a; new_v[i++].id = -1);
    xfree(state->clars.v);
    state->clars.v = new_v;
    state->clars.a = new_a;
  }
  if (new_id >= state->clars.u) {
    state->clars.u = new_id + 1;
  }
  return new_id;
}

int
clar_open(
        clarlog_state_t state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const unsigned char *plugin_name,
        int flags)
{
  const struct xml_tree *p;
  const struct ejudge_plugin *plg;
  const struct common_loaded_plugin *loaded_plugin;

  if (!plugin_register_builtin(&cldb_plugin_file.b, config)) {
    err("cannot register default plugin");
    return -1;
  }

  if (!plugin_name) {
    // use the default plugin
    if (global) plugin_name = global->clardb_plugin;
  }
  if (!plugin_name) plugin_name = "";

  if (!plugin_name[0] || !strcmp(plugin_name, "file")) {
    if (!(loaded_plugin = plugin_get("cldb", "file"))) {
      err("cannot load default plugin");
      return -1;
    }
    state->iface = (struct cldb_plugin_iface*) loaded_plugin->iface;
    state->data = (struct cldb_plugin_data*) loaded_plugin->data;

    if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                           global, flags)))
      return -1;
    return 0;
  }

  // look up the table of loaded plugins
  if ((loaded_plugin = plugin_get("cldb", plugin_name))) {
    state->iface = (struct cldb_plugin_iface*) loaded_plugin->iface;
    state->data = (struct cldb_plugin_data*) loaded_plugin->data;

    if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                           global, flags)))
      return -1;
    return 0;
  }

  if (!config) {
    err("cannot load any plugin");
    return -1;
  }

  // find an appropriate plugin
  for (p = config->plugin_list; p; p = p->right) {
    plg = (const struct ejudge_plugin*) p;
    if (plg->load_flag && !strcmp(plg->type, "cldb")
        && !strcmp(plg->name, plugin_name))
      break;
  }
  if (!p) {
    err("clarlog plugin `%s' is not registered", plugin_name);
    return -1;
  }

  loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
  if (!loaded_plugin) {
    err("cannot load plugin %s, %s", plg->type, plg->name);
    return -1;
  }

  state->iface = (struct cldb_plugin_iface*) loaded_plugin->iface;
  state->data = (struct cldb_plugin_data*) loaded_plugin->data;

  if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                         global, flags)))
    return -1;
  return 0;
}

int
clar_add_record(
        clarlog_state_t state,
        time_t          time,
        int             nsec,
        size_t          size,
        const ej_ip_t   *pip,
        int             ssl_flag,
        int             from,
        int             to,
        int             flags,
        int             j_from,
        int             hide_flag,
        int             locale_id,
        int             in_reply_to,
        const ej_uuid_t *pin_reply_uuid,
        int             run_id,
        const ej_uuid_t *prun_uuid,
        int             appeal_flag,
        int             old_run_status,
        int             new_run_status,
        int             utf8_mode,
        const unsigned char *charset,
        const unsigned char *subj,
        ej_uuid_t       *puuid)
{
  int i, j;
  unsigned char subj2[CLAR_ENTRY_V2_SUBJ_SIZE];
  size_t subj_len;
  struct clar_entry_v2 *pc;

  i = clar_expand(state, -1);
  pc = &state->clars.v[i];

  memset(pc, 0, sizeof(*pc));
  pc->id = i;
  ej_uuid_generate(&pc->uuid);
  pc->time = time;
  pc->nsec = nsec;
  pc->size = size;
  pc->from = from;
  pc->to = to;
  pc->flags = flags;
  pc->j_from = j_from;
  pc->hide_flag = hide_flag;
  ipv6_to_clar_entry(pip, pc);
  pc->ssl_flag = ssl_flag;
  pc->locale_id = locale_id;
  pc->in_reply_to = in_reply_to;
  if (pin_reply_uuid) {
    ej_uuid_copy(&pc->in_reply_uuid, pin_reply_uuid);
  }
  pc->run_id = run_id;
  if (prun_uuid) {
    ej_uuid_copy(&pc->run_uuid, prun_uuid);
  }
  pc->old_run_status = old_run_status;
  pc->new_run_status = new_run_status;
  pc->appeal_flag = appeal_flag;

  if (!charset) charset = INTERNAL_CHARSET;
  strncpy(pc->charset, charset, CLAR_ENTRY_V2_CHARSET_SIZE);
  pc->charset[CLAR_ENTRY_V2_CHARSET_SIZE - 1] = 0;
  for (j = 0; pc->charset[j]; j++)
    pc->charset[j] = tolower(pc->charset[j]);

  if (!subj) subj = "";
  subj_len = strlen(subj);
  if (subj_len >= CLAR_ENTRY_V2_SUBJ_SIZE) {
    memcpy(subj2, subj, CLAR_ENTRY_V2_SUBJ_SIZE);
    j = CLAR_ENTRY_V2_SUBJ_SIZE - 4;
    if (utf8_mode) {
      while (j >= 0 && subj2[j] >= 0x80 && subj2[j] <= 0xbf) j--;
      if (j < 0) j = 0;
    }
    subj2[j++] = '.';
    subj2[j++] = '.';
    subj2[j++] = '.';
    subj2[j++] = 0;
    strcpy(pc->subj, subj2);
  } else {
    strcpy(pc->subj, subj);
  }

  if (state->iface->add_entry(state->cnts, i) < 0) return -1;
  if (puuid) {
    ej_uuid_copy(puuid, &pc->uuid);
  }
  return i;
}

int
clar_put_record(
        clarlog_state_t state,
        int clar_id,
        const struct clar_entry_v2 *pclar)
{
  if (clar_id < 0) ERR_R("bad id: %d", clar_id);
  if (!pclar || pclar->id < 0) ERR_R("bad pclar");
  clar_expand(state, clar_id);
  if (state->clars.v[clar_id].id >= 0) ERR_R("clar %d already used", clar_id);
  memcpy(&state->clars.v[clar_id], pclar, sizeof(state->clars.v[clar_id]));
  state->clars.v[clar_id].id = clar_id;

  if (state->iface->add_entry(state->cnts, clar_id) < 0) return -1;
  return clar_id;
}

int
clar_get_record(
        clarlog_state_t state,
        int clar_id,
        struct clar_entry_v2 *pclar)
{
  if (clar_id < 0 || clar_id >= state->clars.u) ERR_R("bad id: %d", clar_id);
  if (state->clars.v[clar_id].id >= 0 && state->clars.v[clar_id].id != clar_id)
    ERR_R("id mismatch: %d, %d", clar_id, state->clars.v[clar_id].id);
  memcpy(pclar, &state->clars.v[clar_id], sizeof(*pclar));
  return 0;
}

static void
extend_charset_ids(clarlog_state_t state)
{
  size_t new_size;
  int *new_ids = 0;
  unsigned char **new_subj = 0;

  if (!state->clars.u || state->clars.u <= state->allocd) return;
  new_size = 128;
  while (new_size < state->clars.u) new_size *= 2;
  XCALLOC(new_ids, new_size);
  XCALLOC(new_subj, new_size);
  memset(new_ids, -1, new_size * sizeof(new_ids[0]));
  if (state->allocd > 0) {
    memcpy(new_ids, state->charset_codes, state->allocd * sizeof(new_ids[0]));
    memcpy(new_subj, state->subjects, state->allocd * sizeof(new_subj[0]));
  }
  xfree(state->charset_codes);
  xfree(state->subjects);
  state->allocd = new_size;
  state->charset_codes = new_ids;
  state->subjects = new_subj;
}

const unsigned char *
clar_get_subject(
        clarlog_state_t state,
        int id)
{
  unsigned char buf[1024];

  if (id < 0 || id >= state->clars.u) return NULL;

  extend_charset_ids(state);
  // pre-recoded subject is already stored
  if (state->subjects[id]) return state->subjects[id];
  // charset is not yet defined
  if (state->charset_codes[id] < 0)
    state->charset_codes[id] = charset_get_id(state->clars.v[id].charset);
  // subject is in local charset
  if (!state->charset_codes[id]) return state->clars.v[id].subj;
  // subject is in non-local charset, but not yet encoded
  if (state->charset_codes[id] > 0) {
    buf[0] = 0;
    charset_decode_to_buf(state->charset_codes[id],
                          buf, sizeof (buf), state->clars.v[id].subj);
    state->subjects[id] = xstrdup(buf);
    return state->subjects[id];
  }
  // something got wrong...
  return "invalid subject";
}

int
clar_get_charset_id(
        clarlog_state_t state,
        int id)
{
  if (id < 0 || id >= state->clars.u) return 0;
  extend_charset_ids(state);
  if (state->charset_codes[id] < 0)
    state->charset_codes[id] = charset_get_id(state->clars.v[id].charset);
  if (state->charset_codes[id] < 0) state->charset_codes[id] = 0;
  return state->charset_codes[id];
}

int
clar_update_flags(
        clarlog_state_t state,
        int id,
        int flags)
{
  if (id < 0 || id >= state->clars.u) ERR_R("bad id: %d", id);
  if (state->clars.v[id].id < 0) return 0;
  if (state->clars.v[id].id != id)
    ERR_R("id mismatch: %d, %d", id, state->clars.v[id].id);
  if (flags < 0 || flags > 255) ERR_R("bad flags: %d", flags);

  state->clars.v[id].flags = flags;
  if (state->iface->set_flags(state->cnts, id) < 0) return -1;
  return 0;
}

int
clar_set_charset(
        clarlog_state_t state,
        int id,
        const unsigned char *charset)
{
  if (id < 0 || id >= state->clars.u) ERR_R("bad id: %d", id);
  if (state->clars.v[id].id < 0) return 0;
  if (state->clars.v[id].id != id)
    ERR_R("id mismatch: %d, %d", id, state->clars.v[id].id);
  snprintf(state->clars.v[id].charset, sizeof(state->clars.v[id].charset),
           "%s", charset);
  if (state->iface->set_charset(state->cnts, id) < 0) return -1;
  return 0;
}

int
clar_get_total(clarlog_state_t state)
{
  return state->clars.u;
}

void
clar_get_user_usage(
        clarlog_state_t state,
        int from,
        int *pn,
        size_t *ps)
{
  int i;
  size_t total = 0;
  int n = 0;

  for (i = 0; i < state->clars.u; i++)
    if (state->clars.v[i].from == from) {
      total += state->clars.v[i].size;
      n++;
    }
  if (pn) *pn = n;
  if (ps) *ps = total;
}

void
clar_get_all_users_usage(
        clarlog_state_t state,
        int map_size,
        int *clar_counts,
        size_t *clar_sizes)
{
  for (int i = 0; i < state->clars.u; ++i) {
    struct clar_entry_v2 *pc = &state->clars.v[i];
    if (pc->from > 0 && pc->from < map_size) {
      if (clar_counts) ++clar_counts[pc->from];
      if (clar_sizes) clar_sizes[pc->from] += pc->size;
    }
  }
}

int
clar_get_unanswered_count(
        clarlog_state_t state,
        time_t thr_time)
{
  int count = 0;

  for (int i = 0; i < state->clars.u; i++) {
    if (state->clars.v[i].from != 0 && state->clars.v[i].flags != 2) {
      if (thr_time <= 0 || state->clars.v[i].time < thr_time) {
        ++count;
      }
    }
  }
  return count;
}

char *
clar_flags_html(
        clarlog_state_t state,
        int flags,
        int from,
        int to,
        char *buf,
        int len)
{
  char *s = "";

  if (!from)           s = "&nbsp;";
  else if (flags == 0) s = "N";
  else if (flags == 1) s = "R";
  else if (flags == 2) s = "A";
  else s = "?";

  if (!buf) return s;
  if (len <= 0) return strcpy(buf, s);
  strncpy(buf, s, len);
  buf[len - 1] = 0;
  return buf;
}

void
clar_reset(clarlog_state_t state)
{
  int i;

  if (!state->iface->reset) {
    err("`reset' operation is not supported for this clarlog");
    return;
  }
  state->iface->reset(state->cnts);

  for (i = 0; i < state->allocd; i++)
    xfree(state->subjects[i]);
  xfree(state->subjects);
  xfree(state->charset_codes);
  state->allocd = 0;
  state->subjects = 0;
  state->charset_codes = 0;
}

int
clar_get_text(
        clarlog_state_t state,
        int clar_id,
        unsigned char **p_text,
        size_t *p_size)
{
  unsigned char *raw_text = 0;
  size_t raw_size = 0;
  int charset_id;

  ASSERT(state);
  if (clar_id < 0 || clar_id >= state->clars.u) ERR_R("bad id: %d", clar_id);
  if (state->clars.v[clar_id].id < 0) {
    *p_text = xstrdup("");
    *p_size = 0;
    return 0;
  }
  if (state->clars.v[clar_id].id != clar_id)
    ERR_R("id mismatch: %d, %d", clar_id, state->clars.v[clar_id].id);

  if (state->iface->get_raw_text(state->cnts, clar_id, &raw_text, &raw_size)<0)
    return -1;
  if (!(charset_id = clar_get_charset_id(state, clar_id))) {
    *p_text = raw_text;
    *p_size = raw_size;
    return 0;
  }
  raw_text = charset_decode_heap(charset_id, raw_text);
  raw_size = strlen(raw_text);

  *p_text = raw_text;
  *p_size = raw_size;
  return 0;
}

int
clar_get_raw_text(
        clarlog_state_t state,
        int clar_id,
        unsigned char **p_text,
        size_t *p_size)
{
  ASSERT(state);
  if (clar_id < 0 || clar_id >= state->clars.u) ERR_R("bad id: %d", clar_id);
  if (state->clars.v[clar_id].id < 0) {
    *p_text = xstrdup("");
    *p_size = 0;
    return 0;
  }
  if (state->clars.v[clar_id].id != clar_id)
    ERR_R("id mismatch: %d, %d", clar_id, state->clars.v[clar_id].id);

  return state->iface->get_raw_text(state->cnts, clar_id, p_text, p_size);
}

int
clar_add_text(
        clarlog_state_t state,
        int clar_id,
        const ej_uuid_t *puuid,
        const unsigned char *text,
        size_t size)
{
  return state->iface->add_text(state->cnts, clar_id, puuid, text, size);
}

int
clar_modify_text(
        clarlog_state_t state,
        int clar_id,
        unsigned char *text,
        size_t size)
{
  return state->iface->modify_text(state->cnts, clar_id, text, size);
}

int
clar_modify_record(
        clarlog_state_t state,
        int clar_id,
        int mask,
        const struct clar_entry_v2 *pclar)
{
  if (clar_id < 0 || clar_id >= state->clars.u) ERR_R("bad id: %d", clar_id);
  struct clar_entry_v2 *pe = &state->clars.v[clar_id];

  if (mask & (1 << CLAR_FIELD_SIZE)) {
    pe->size = pclar->size;
  }
  if (mask & (1 << CLAR_FIELD_FROM)) {
    pe->from = pclar->from;
  }
  if (mask & (1 << CLAR_FIELD_TO)) {
    pe->to = pclar->to;
  }
  if (mask & (1 << CLAR_FIELD_J_FROM)) {
    pe->j_from = pclar->j_from;
  }
  if (mask & (1 << CLAR_FIELD_FLAGS)) {
    pe->flags = pclar->flags;
  }
  if (mask & (1 << CLAR_FIELD_HIDE_FLAG)) {
    pe->hide_flag = pclar->hide_flag;
  }
  if (mask & (1 << CLAR_FIELD_SSL_FLAG)) {
    pe->ssl_flag = pclar->ssl_flag;
  }
  if (mask & (1 << CLAR_FIELD_APPEAL_FLAG)) {
    pe->appeal_flag = pclar->appeal_flag;
  }
  if (mask & (1 << CLAR_FIELD_IP)) {
    pe->ipv6_flag = pclar->ipv6_flag;
    pe->a = pclar->a;
  }
  if (mask & (1 << CLAR_FIELD_LOCALE_ID)) {
    pe->locale_id = pclar->locale_id;
  }
  if (mask & (1 << CLAR_FIELD_IN_REPLY_TO)) {
    pe->in_reply_to = pclar->in_reply_to;
  }
  if (mask & (1 << CLAR_FIELD_IN_REPLY_UUID)) {
    ej_uuid_copy(&pe->in_reply_uuid, &pclar->in_reply_uuid);
  }
  if (mask & (1 << CLAR_FIELD_RUN_ID)) {
    pe->run_id = pclar->run_id;
  }
  if (mask & (1 << CLAR_FIELD_RUN_UUID)) {
    ej_uuid_copy(&pe->run_uuid, &pclar->run_uuid);
  }
  if (mask & (1 << CLAR_FIELD_OLD_RUN_STATUS)) {
    pe->old_run_status = pclar->old_run_status;
  }
  if (mask & (1 << CLAR_FIELD_NEW_RUN_STATUS)) {
    pe->new_run_status = pclar->new_run_status;
  }
  if (mask & (1 << CLAR_FIELD_CHARSET)) {
    snprintf(pe->charset, sizeof(pe->charset), "%s", pclar->charset);
  }
  if (mask & (1 << CLAR_FIELD_SUBJECT)) {
    snprintf(pe->subj, sizeof(pe->subj), "%s", pclar->subj);
  }

  return state->iface->modify_record(state->cnts, clar_id, mask, pclar);
}

void
clar_entry_to_ipv6(const struct clar_entry_v2 *pe, ej_ip_t *p_ip)
{
  memset(p_ip, 0, sizeof(*p_ip));
  if (pe->ipv6_flag) {
    p_ip->ipv6_flag = 1;
    memcpy(p_ip->u.v6.addr, pe->a.ipv6, sizeof(p_ip->u.v6.addr));
  } else {
    p_ip->u.v4.addr = pe->a.ip;
  }
}

void
ipv6_to_clar_entry(const ej_ip_t *p_ip, struct clar_entry_v2 *pe)
{
  pe->ipv6_flag = 0;
  memset(&pe->a, 0, sizeof(pe->a));
  if (p_ip->ipv6_flag) {
    pe->ipv6_flag = 1;
    memcpy(pe->a.ipv6, p_ip->u.v6.addr, sizeof(pe->a.ipv6));
  } else {
    pe->a.ip = p_ip->u.v4.addr;
  }
}

int
clar_fetch_run_messages(
        clarlog_state_t state,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry_vector *pfcev)
{
  if (state->iface->fetch_run_messages) {
    struct full_clar_entry *pp = NULL;
    int count = (*state->iface->fetch_run_messages)(state->cnts, p_run_uuid, &pp);
    if (count <= 0) return count;

    if (pfcev->u + count > pfcev->a) {
      int new_sz = pfcev->a * 2;
      if (!new_sz) new_sz = 8;
      while (pfcev->u + count > new_sz) new_sz *= 2;
      XREALLOC(pfcev->v, new_sz);
      pfcev->a = new_sz;
    }
    memcpy(&pfcev->v[pfcev->u], pp, count * sizeof(pp[0]));
    pfcev->u += count;
    xfree(pp);
    return count;
  } else {
    ERR_R("not supported");
  }
  return -1;
}

void
clar_free_fcev(struct full_clar_entry_vector *pfcev)
{
  if (pfcev) {
    for (int i = 0; i < pfcev->u; ++i) {
      xfree(pfcev->v[i].text);
    }
    xfree(pfcev->v);
    memset(pfcev, 0, sizeof(*pfcev));
  }
}

int
clar_fetch_run_messages_2(
        clarlog_state_t state,
        int uuid_count,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry_vector *pfcev)
{
  if (state->iface->fetch_run_messages_2) {
    struct full_clar_entry *pp = NULL;
    int count = (*state->iface->fetch_run_messages_2)(state->cnts, uuid_count, p_run_uuid, &pp);
    if (count <= 0) return count;

    if (pfcev->u + count > pfcev->a) {
      int new_sz = pfcev->a * 2;
      if (!new_sz) new_sz = 8;
      while (pfcev->u + count > new_sz) new_sz *= 2;
      XREALLOC(pfcev->v, new_sz);
      pfcev->a = new_sz;
    }
    memcpy(&pfcev->v[pfcev->u], pp, count * sizeof(pp[0]));
    pfcev->u += count;
    xfree(pp);
    return count;
  } else {
    ERR_R("not supported");
  }
  return -1;
}

int
clar_count_run_messages(
        clarlog_state_t state,
        const ej_uuid_t *p_run_uuid)
{
  int count = 0;
  for (int clar_id = 0; clar_id < state->clars.u; ++clar_id) {
    const struct clar_entry_v2 *pe = &state->clars.v[clar_id];
    count += (!memcmp(p_run_uuid, &pe->run_uuid, sizeof(pe->run_uuid)));
  }
  return count;
}

int
clar_fetch_total(clarlog_state_t state)
{
  if (state->iface->fetch_total) {
    int res = (*state->iface->fetch_total)(state->cnts);
    if (res < 0) res = state->clars.u;
  }
  return state->clars.u;
}
