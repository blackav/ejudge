/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2008 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_types.h"

#include "clarlog.h"
#include "cldb_plugin.h"
#include "clarlog_state.h"

#include "teamdb.h"
#include "base64.h"

#include "unix/unix_fileutl.h"
#include "pathutl.h"
#include "errlog.h"
#include "xml_utils.h"
#include "charsets.h"
#include "prepare.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

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

/* plugin information */
struct cldb_loaded_plugin
{
  struct cldb_plugin_iface *iface;
  struct cldb_plugin_data *data;
};

enum { CLDB_PLUGIN_MAX_NUM = 16 };
static int cldb_plugins_num;
static struct cldb_loaded_plugin cldb_plugins[CLDB_PLUGIN_MAX_NUM];

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

int
clar_open(
        clarlog_state_t state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
  int i;
  const struct xml_tree *p;
  const struct ejudge_plugin *plg;
  struct ejudge_plugin_iface *base_iface = 0;
  struct cldb_plugin_iface *cldb_iface = 0;
  struct cldb_plugin_data *plugin_data = 0;

  if (!cldb_plugins_num) {
    cldb_plugins[0].iface = &cldb_plugin_file;
    if (!(cldb_plugins[0].data = cldb_plugin_file.init(config))
        || cldb_plugin_file.prepare(cldb_plugins[0].data, config, 0) < 0) {
      err("cannot initialize `file' clarlog plugin");
      return -1;
    }
    cldb_plugins_num++;
  }

  if (!global || !global->clardb_plugin[0]
      || !strcmp(global->clardb_plugin, "file")) {
    state->iface = cldb_plugins[0].iface;
    state->data = cldb_plugins[0].data;

    if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                           global, flags)))
      return -1;
    return 0;
  }

  // look up the table of loaded plugins
  for (i = 1; i < cldb_plugins_num; i++) {
    if (!strcmp(cldb_plugins[i].iface->b.name, global->clardb_plugin))
      break;
  }
  if (i < cldb_plugins_num) {
    state->iface = cldb_plugins[i].iface;
    state->data = cldb_plugins[i].data;
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
        && !strcmp(plg->name, global->clardb_plugin))
      break;
  }
  if (!p) {
    err("clarlog plugin `%s' is not registered", global->clardb_plugin);
    return -1;
  }
  if (cldb_plugins_num == CLDB_PLUGIN_MAX_NUM) {
    err("too many clarlog plugins already loaded");
    return -1;
  }
  plugin_set_directory(config->plugin_dir);
  if (!(base_iface = plugin_load(plg->path, plg->type, plg->name))) {
    err("cannot load plugin `%s'", plg->name);
    return 1;
  }
  cldb_iface = (struct cldb_plugin_iface*) base_iface;
  if (base_iface->size != sizeof(*cldb_iface)) {
    err("plugin `%s' size mismatch", plg->name);
    return -1;
  }
  if (cldb_iface->cldb_version != CLDB_PLUGIN_IFACE_VERSION) {
    err("plugin `%s' version mismatch", plg->name);
    return -1;
  }
  if (!(plugin_data = cldb_iface->init(config))) {
    err("plugin `%s' initialization failed", plg->name);
    return -1;
  }
  if (cldb_iface->prepare(plugin_data, config, plg->data) < 0) {
    err("plugin %s failed to parse its configuration", plg->name);
    return -1;
  }

  cldb_plugins[cldb_plugins_num].iface = cldb_iface;
  cldb_plugins[cldb_plugins_num].data = plugin_data;
  cldb_plugins_num++;

  state->iface = cldb_iface;
  state->data = plugin_data;
  if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                         global, flags)))
    return -1;
  return 0;
}

int
clar_add_record(
        clarlog_state_t state,
        time_t         time,
        int            nsec,
        size_t         size,
        ej_ip_t        ip,
        int            ssl_flag,
        int            from,
        int            to,
        int            flags,
        int            j_from,
        int            hide_flag,
        int            locale_id,
        int            in_reply_to,
        int            appeal_flag,
        int            utf8_mode,
        const unsigned char *charset,
        const unsigned char *subj)
{
  int i, j;
  unsigned char subj2[CLAR_ENTRY_SUBJ_SIZE];
  size_t subj_len;
  struct clar_entry_v1 *pc;

  if (state->clars.u >= state->clars.a) {
    if (!(state->clars.a *= 2)) state->clars.a = 128;
    state->clars.v = xrealloc(state->clars.v, state->clars.a * sizeof(state->clars.v[0]));
    info("clar_add_record: array extended: %d", state->clars.a);
  }
  i = state->clars.u++;
  pc = &state->clars.v[i];

  memset(pc, 0, sizeof(*pc));
  pc->id = i;
  pc->time = time;
  pc->nsec = nsec;
  pc->size = size;
  pc->from = from;
  pc->to = to;
  pc->flags = flags;
  pc->j_from = j_from;
  pc->hide_flag = hide_flag;
  pc->a.ip = ip;
  pc->ssl_flag = ssl_flag;
  pc->locale_id = locale_id;
  pc->in_reply_to = in_reply_to;
  pc->appeal_flag = appeal_flag;

  if (!charset) charset = INTERNAL_CHARSET;
  strncpy(pc->charset, charset, CLAR_ENTRY_CHARSET_SIZE);
  pc->charset[CLAR_ENTRY_CHARSET_SIZE - 1] = 0;
  for (j = 0; pc->charset[j]; j++)
    pc->charset[j] = tolower(pc->charset[j]);

  if (!subj) subj = "";
  subj_len = strlen(subj);
  if (subj_len >= CLAR_ENTRY_SUBJ_SIZE) {
    memcpy(subj2, subj, CLAR_ENTRY_SUBJ_SIZE);
    j = CLAR_ENTRY_SUBJ_SIZE - 4;
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
  return i;
}

int
clar_get_record(
        clarlog_state_t state,
        int clar_id,
        struct clar_entry_v1 *pclar)
{
  if (clar_id < 0 || clar_id >= state->clars.u) ERR_R("bad id: %d", clar_id);
  if (state->clars.v[clar_id].id != clar_id)
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
  if (!state->iface->create_new) {
    err("`reset' operation is not supported for this clarlog");
    return;
  }
  state->iface->create_new(state->cnts);
}

void
clar_clear_variables(clarlog_state_t state)
{
  abort();
  if (state->clars.v) xfree(state->clars.v);
  state->clars.v = 0;
  state->clars.u = state->clars.a = 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
