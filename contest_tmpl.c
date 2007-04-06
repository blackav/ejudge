/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "version.h"

#include "contests.h"
#include "ejudge_cfg.h"
#include "expat_iface.h"
#include "super_html.h"
#include "super-serve.h"
#include "fileutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <limits.h>

static struct contest_access *
new_contest_access(int tag)
{
  struct contest_access *p;
  struct contest_ip *q;

  p = (struct contest_access*) contests_new_node(tag);
  q = (struct contest_ip*) contests_new_node(CONTEST_IP);
  q->allow = 1;
  q->addr = 127U << 24 | 1U;
  q->mask = 0xffffffff;
  xml_link_node_last(&p->b, &q->b);
  return p;
}

struct contest_desc *
contest_tmpl_new(int contest_id,
                 const unsigned char *login,
                 const unsigned char *self_url,
                 const unsigned char *ss_login,
                 const struct ejudge_cfg *ejudge_config)
{
  struct contest_desc *cnts;
  unsigned char root_dir_buf[4096];
  unsigned char url_base[1024];
  unsigned char ubuf[1024];
  unsigned char *contests_home_dir = 0;
  struct contest_access *acc;
  int self_url_len, i;
  struct xml_tree *t;
  struct opcap_list_item *cap;

  ASSERT(contest_id > 0 && contest_id <= 999999);

  url_base[0] = 0;
  self_url_len = strlen(self_url);
  if (self_url_len > 13
      && !strcmp(self_url + (self_url_len - 14), "/serve-control")) {
    snprintf(url_base, sizeof(url_base), "%.*s",
             self_url_len - 14, self_url);
  }

  cnts = (struct contest_desc*) contests_new_node(CONTEST_CONTEST);
  cnts->id = contest_id;
  cnts->clean_users = 1;
  cnts->new_managed = 1;
  cnts->run_managed = 1;
  cnts->disable_team_password = 1;
  if (url_base[0]) {
    snprintf(ubuf, sizeof(ubuf), "%s/register", url_base);
    cnts->register_url = xstrdup(ubuf);
    snprintf(ubuf, sizeof(ubuf), "%s/team", url_base);
    cnts->team_url = xstrdup(ubuf);
  }

  if (ejudge_config && ejudge_config->contests_home_dir) {
    contests_home_dir = ejudge_config->contests_home_dir;
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!contests_home_dir) contests_home_dir = EJUDGE_CONTESTS_HOME_DIR;
#endif
  snprintf(root_dir_buf, sizeof(root_dir_buf), "%s/%06d",
           contests_home_dir, contest_id);
  cnts->root_dir = xstrdup(root_dir_buf);

  cnts->register_access = acc = new_contest_access(CONTEST_REGISTER_ACCESS);
  xml_link_node_last(&cnts->b, &acc->b);
  cnts->users_access = acc = new_contest_access(CONTEST_USERS_ACCESS);
  xml_link_node_last(&cnts->b, &acc->b);
  cnts->master_access = acc = new_contest_access(CONTEST_MASTER_ACCESS);
  xml_link_node_last(&cnts->b, &acc->b);
  cnts->judge_access = acc = new_contest_access(CONTEST_JUDGE_ACCESS);
  xml_link_node_last(&cnts->b, &acc->b);
  cnts->team_access = acc = new_contest_access(CONTEST_TEAM_ACCESS);
  xml_link_node_last(&cnts->b, &acc->b);
  cnts->serve_control_access = acc = new_contest_access(CONTEST_SERVE_CONTROL_ACCESS);
  xml_link_node_last(&cnts->b, &acc->b);

  t = contests_new_node(CONTEST_CAPS);
  xml_link_node_last(&cnts->b, t);
  cnts->caps_node = t;

  cap = (typeof(cap)) contests_new_node(CONTEST_CAP);
  for (i = 0; i < OPCAP_LAST; i++)
    cap->caps |= 1ULL << i;
  cap->login = xstrdup(login);
  xml_link_node_last(t, &cap->b);
  cnts->capabilities.first = cap;

  if (ss_login && *ss_login && strcmp(cap->login, ss_login)) {
    cap = (typeof(cap)) contests_new_node(CONTEST_CAP);
    cap->caps |= 1ULL << OPCAP_MAP_CONTEST;
    cap->login = xstrdup(ss_login);
    xml_link_node_last(t, &cap->b);
  }

  cnts->client_ignore_time_skew = 1;
  return cnts;
}

static unsigned char *
strsubst(const unsigned char *str, const unsigned char *from,
         const unsigned char *to)
{
  unsigned char *p, *q;
  size_t from_len = strlen(from);
  size_t to_len = strlen(to);
  size_t str_len = strlen(str);

  if (!(p = strstr(str, from))) return 0;

  q = xmalloc(str_len - from_len + to_len + 1);
  memcpy(q, str, p - str);
  memcpy(q + (p - str), to, to_len);
  strcpy(q + (p - str) + to_len, p + from_len);
  return q;
}

static void
subst_param(unsigned char **p_param,
            int n,
            unsigned char s_from[][32], unsigned char s_to[][32])
{
  int i;
  unsigned char *t;
  unsigned char *param = *p_param;

  if (!param) return;
  for (i = 0; i < n; i++) {
    if (!(t = strsubst(param, s_from[i], s_to[i]))) continue;
    xfree(param);
    *p_param = t;
    return;
  }
}

static unsigned char *
do_load_file(const unsigned char *conf_path, const unsigned char *file)
{
  unsigned char full_path[PATH_MAX];
  char *buf = 0;
  size_t buf_size = 0;

  if (!file || !*file) return 0;

  if (!os_IsAbsolutePath(file)) {
    snprintf(full_path, sizeof(full_path), "%s/%s", conf_path, file);
  } else {
    snprintf(full_path, sizeof(full_path), "%s", file);
  }

  if (generic_read_file(&buf, 0, &buf_size, 0, 0, full_path, 0) < 0) return 0;
  return buf;
}

static void
load_header_files(struct sid_state *sstate, struct contest_desc *cnts)
{
  unsigned char conf_path[PATH_MAX];

  if (!cnts->root_dir || !*cnts->root_dir) return;
  if (!os_IsAbsolutePath(cnts->root_dir)) return;
  if (!cnts->conf_dir) {
    snprintf(conf_path, sizeof(conf_path), "%s/%s", cnts->root_dir, "conf");
  } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(conf_path, sizeof(conf_path), "%s/%s", cnts->root_dir, cnts->conf_dir);
  } else {
    snprintf(conf_path, sizeof(conf_path), "%s", cnts->conf_dir);
  }

  sstate->register_header_text = do_load_file(conf_path, cnts->register_header_file);
  sstate->register_footer_text = do_load_file(conf_path, cnts->register_footer_file);
  sstate->users_header_text = do_load_file(conf_path, cnts->users_header_file);
  sstate->users_footer_text = do_load_file(conf_path, cnts->users_footer_file);
  sstate->team_header_text = do_load_file(conf_path, cnts->team_header_file);
  sstate->team_footer_text = do_load_file(conf_path, cnts->team_footer_file);
  sstate->copyright_text = do_load_file(conf_path, cnts->copyright_file);
  sstate->priv_header_text = do_load_file(conf_path, cnts->priv_header_file);
  sstate->priv_footer_text = do_load_file(conf_path, cnts->priv_footer_file);
  sstate->register_email_text = do_load_file(conf_path, cnts->register_email_file);
}

struct contest_desc *
contest_tmpl_clone(struct sid_state *sstate,
                   int contest_id, int orig_id, const unsigned char *login,
                   const unsigned char *ss_login)
{
  struct contest_desc *cnts = 0;
  unsigned char substs_from[6][32];
  unsigned char substs_to[6][32];
  struct opcap_list_item *cap;
  struct xml_tree *caps;
  int i;

  if (contests_load(orig_id, &cnts) < 0 || !cnts) return 0;
  load_header_files(sstate, cnts);

  snprintf(substs_from[0], sizeof(substs_from[0]), "%06d", orig_id);
  snprintf(substs_from[1], sizeof(substs_from[0]), "%05d", orig_id);
  snprintf(substs_from[2], sizeof(substs_from[0]), "%04d", orig_id);
  snprintf(substs_from[3], sizeof(substs_from[0]), "%03d", orig_id);
  snprintf(substs_from[4], sizeof(substs_from[0]), "%02d", orig_id);
  snprintf(substs_from[5], sizeof(substs_from[0]), "%d", orig_id);
  snprintf(substs_to[0], sizeof(substs_to[0]), "%06d", contest_id);
  snprintf(substs_to[1], sizeof(substs_to[0]), "%05d", contest_id);
  snprintf(substs_to[2], sizeof(substs_to[0]), "%04d", contest_id);
  snprintf(substs_to[3], sizeof(substs_to[0]), "%03d", contest_id);
  snprintf(substs_to[4], sizeof(substs_to[0]), "%02d", contest_id);
  snprintf(substs_to[5], sizeof(substs_to[0]), "%d", contest_id);

  cnts->id = contest_id;
  subst_param(&cnts->users_header_file, 6, substs_from, substs_to);
  subst_param(&cnts->users_footer_file, 6, substs_from, substs_to);
  subst_param(&cnts->register_header_file, 6, substs_from, substs_to);
  subst_param(&cnts->register_footer_file, 6, substs_from, substs_to);
  subst_param(&cnts->team_header_file, 6, substs_from, substs_to);
  subst_param(&cnts->team_footer_file, 6, substs_from, substs_to);
  subst_param(&cnts->copyright_file, 6, substs_from, substs_to);
  subst_param(&cnts->priv_header_file, 6, substs_from, substs_to);
  subst_param(&cnts->priv_footer_file, 6, substs_from, substs_to);
  subst_param(&cnts->register_email, 6, substs_from, substs_to);
  subst_param(&cnts->register_url, 6, substs_from, substs_to);
  subst_param(&cnts->team_url, 6, substs_from, substs_to);
  subst_param(&cnts->root_dir, 6, substs_from, substs_to);
  subst_param(&cnts->conf_dir, 6, substs_from, substs_to);
  subst_param(&cnts->register_email_file, 6, substs_from, substs_to);

  for (cap = cnts->capabilities.first; cap; cap = (typeof(cap)) cap->b.right)
    if (!strcmp(cap->login, login))
      break;
  if (!cap) {
    if (!cnts->caps_node) {
      caps = (typeof(caps)) contests_new_node(CONTEST_CAPS);
      xml_link_node_last(&cnts->b, caps);
      cnts->caps_node = caps;
    }
    cap = (typeof(cap)) contests_new_node(CONTEST_CAP);
    cap->login = xstrdup(login);
    xml_link_node_last(cnts->caps_node, &cap->b);
    if (!cnts->capabilities.first) cnts->capabilities.first = cap;
  }
  for (i = 0; i < OPCAP_LAST; i++)
    cap->caps |= 1ULL << i;

  if (ss_login && *ss_login && strcmp(login, ss_login)) {
    for (cap = cnts->capabilities.first; cap; cap = (typeof(cap)) cap->b.right)
      if (!strcmp(cap->login, ss_login))
        break;
    if (!cap) {
      cap = (typeof(cap)) contests_new_node(CONTEST_CAP);
      cap->login = xstrdup(ss_login);
      xml_link_node_last(cnts->caps_node, &cap->b);
    }
    cap->caps |= 1ULL << OPCAP_MAP_CONTEST;
  }

  return cnts;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
