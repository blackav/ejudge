/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@unicorn.cmc.msu.ru> */

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

#include "super_html.h"
#include "super-serve.h"
#include "super_actions.h"
#include "super_proto.h"
#include "contests.h"
#include "misctext.h"
#include "opcaps.h"
#include "protocol.h"
#include "userlist_cfg.h"
#include "pathutl.h"
#include "fileutl.h"
#include "xml_utils.h"
#include "prepare.h"
#include "userlist_proto.h"
#include "userlist_clnt.h"
#include "userlist.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

int
super_html_clear_variable(struct sid_state *sstate, int cmd)
{
  unsigned char **p_str = 0;
  struct contest_desc *cnts = sstate->edited_cnts;

  if (!cnts) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }

  switch (cmd) {
  case SSERV_CMD_CNTS_CLEAR_DEADLINE:
    cnts->reg_deadline = 0;
    return 0;
    
  case SSERV_CMD_CNTS_CLEAR_NAME: p_str = &cnts->name; break;
  case SSERV_CMD_CNTS_CLEAR_NAME_EN: p_str = &cnts->name_en; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_HEADER: p_str = &cnts->users_header_file; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_FOOTER: p_str = &cnts->users_footer_file; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER: p_str = &cnts->register_header_file; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER: p_str = &cnts->register_footer_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEADER: p_str = &cnts->team_header_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER: p_str = &cnts->team_footer_file; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_HEAD_STYLE: p_str = &cnts->users_head_style; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_PAR_STYLE: p_str = &cnts->users_par_style; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_STYLE: p_str = &cnts->users_table_style; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_VERB_STYLE: p_str = &cnts->users_verb_style; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEAD_STYLE: p_str=&cnts->register_head_style;break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_PAR_STYLE: p_str = &cnts->register_par_style; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_TABLE_STYLE: p_str = &cnts->register_table_style; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEAD_STYLE: p_str = &cnts->team_head_style; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_PAR_STYLE: p_str = &cnts->team_par_style; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL: p_str = &cnts->register_email; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_URL: p_str = &cnts->register_url; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE: p_str = &cnts->register_email_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_URL: p_str = &cnts->team_url; break;
  case SSERV_CMD_CNTS_CLEAR_STANDINGS_URL: p_str = &cnts->standings_url; break;
  case SSERV_CMD_CNTS_CLEAR_PROBLEMS_URL: p_str = &cnts->problems_url; break;
  case SSERV_CMD_CNTS_CLEAR_ROOT_DIR: p_str = &cnts->root_dir; break;
  case SSERV_CMD_CNTS_CLEAR_CONF_DIR: p_str = &cnts->conf_dir; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT:
    p_str = &sstate->users_header_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT:
    p_str = &sstate->users_footer_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT:
    p_str = &sstate->register_header_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT:
    p_str = &sstate->register_footer_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT:
    p_str = &sstate->team_header_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT:
    p_str = &sstate->team_footer_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT:
    p_str = &sstate->register_email_text;
    break;
  default:
    abort();
  }

  xfree(*p_str);
  *p_str = 0;
  return 0;
}

static const int access_tags_map[] =
{
  CONTEST_REGISTER_ACCESS,
  CONTEST_USERS_ACCESS,
  CONTEST_MASTER_ACCESS,
  CONTEST_JUDGE_ACCESS,
  CONTEST_TEAM_ACCESS,
  CONTEST_SERVE_CONTROL_ACCESS,
};

static struct xml_tree*
get_nth_child(struct xml_tree *t, int n)
{
  struct xml_tree *p;

  if (!t) return 0;
  for (p = t->first_down; p && n; p = p->right, n--);
  return p;
}

static void
swap_tree_nodes(struct xml_tree *first)
{
  struct xml_tree *second;
  struct xml_tree *top;
  struct xml_tree *before_first;
  struct xml_tree *after_second;

  ASSERT(first);
  second = first->right;
  ASSERT(second);
  ASSERT(second->left == first);
  top = first->up;
  ASSERT(top == second->up);
  before_first = first->left;
  after_second = second->right;
  first->left = second;
  first->right = after_second;
  second->left = before_first;
  second->right = first;
  if (!before_first) {
    ASSERT(top->first_down == first);
    top->first_down = second;
  } else {
    before_first->right = second;
  }
  if (!after_second) {
    ASSERT(top->last_down == second);
    top->last_down = first;
  } else {
    after_second->left = first;
  }
}

static unsigned char const login_accept_chars[] =
"._-0123456789?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

int
super_html_set_contest_var(struct sid_state *sstate, int cmd,
                           int param1, const unsigned char *param2,
                           int param3, int param4)
{
  unsigned char **p_str = 0;
  unsigned char *p_bool = 0;
  time_t *p_date = 0;
  int v, n, memb_ind;
  struct contest_desc *cnts = sstate->edited_cnts;
  struct contest_access **p_access = 0, *new_acc;
  unsigned int ip_addr, ip_mask;
  struct contest_ip *new_ip;
  struct opcap_list_item *cap_node;
  struct contest_field *fld_node;
  struct contest_member *memb;

  if (!cnts) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }

  switch (cmd) {
  case SSERV_CMD_CNTS_CHANGE_NAME:
    p_str = &cnts->name;
    break;
  case SSERV_CMD_CNTS_CHANGE_NAME_EN:
    p_str = &cnts->name_en;
    break;
  case SSERV_CMD_CNTS_CHANGE_AUTOREGISTER:
    p_bool = &cnts->autoregister;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD:
    p_bool = &cnts->disable_team_password;
    break;
  case SSERV_CMD_CNTS_CHANGE_MANAGED:
    p_bool = &cnts->managed;
    break;
  case SSERV_CMD_CNTS_CHANGE_RUN_MANAGED:
    p_bool = &cnts->run_managed;
    break;
  case SSERV_CMD_CNTS_CHANGE_CLEAN_USERS:
    p_bool = &cnts->clean_users;
    break;
  case SSERV_CMD_CNTS_CHANGE_CLOSED:
    p_bool = &cnts->closed;
    break;
  case SSERV_CMD_CNTS_CHANGE_INVISIBLE:
    p_bool = &cnts->invisible;
    break;
  case SSERV_CMD_CNTS_CHANGE_TIME_SKEW:
    p_bool = &cnts->client_ignore_time_skew;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_LOGIN:
    p_bool = &cnts->client_disable_team;
    break;
  case SSERV_CMD_CNTS_CHANGE_DEADLINE:
    p_date = &cnts->reg_deadline;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_HEADER:
    p_str = &cnts->users_header_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_FOOTER:
    p_str = &cnts->users_footer_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_HEADER:
    p_str = &cnts->register_header_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_FOOTER:
    p_str = &cnts->register_footer_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_HEADER:
    p_str = &cnts->team_header_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_FOOTER:
    p_str = &cnts->team_footer_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_HEAD_STYLE:
    p_str = &cnts->users_head_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_PAR_STYLE:
    p_str = &cnts->users_par_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_STYLE:
    p_str = &cnts->users_table_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_VERB_STYLE:
    p_str = &cnts->users_verb_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_HEAD_STYLE:
    p_str = &cnts->register_head_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_PAR_STYLE:
    p_str = &cnts->register_par_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_TABLE_STYLE:
    p_str = &cnts->register_table_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_HEAD_STYLE:
    p_str = &cnts->team_head_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_PAR_STYLE:
    p_str = &cnts->team_par_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL:
    p_str = &cnts->register_email;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_URL:
    p_str = &cnts->register_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL_FILE:
    p_str = &cnts->register_email_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_URL:
    p_str = &cnts->team_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_STANDINGS_URL:
    p_str = &cnts->standings_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_PROBLEMS_URL:
    p_str = &cnts->problems_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_ROOT_DIR:
    p_str = &cnts->root_dir;
    break;
  case SSERV_CMD_CNTS_CHANGE_CONF_DIR:
    p_str = &cnts->conf_dir;
    break;

  case SSERV_CMD_CNTS_SAVE_USERS_HEADER:
    p_str = &sstate->users_header_text;
    break;
  case SSERV_CMD_CNTS_SAVE_USERS_FOOTER:
    p_str = &sstate->users_footer_text;
    break;
  case SSERV_CMD_CNTS_SAVE_REGISTER_HEADER:
    p_str = &sstate->register_header_text;
    break;
  case SSERV_CMD_CNTS_SAVE_REGISTER_FOOTER:
    p_str = &sstate->register_footer_text;
    break;
  case SSERV_CMD_CNTS_SAVE_TEAM_HEADER:
    p_str = &sstate->team_header_text;
    break;
  case SSERV_CMD_CNTS_SAVE_TEAM_FOOTER:
    p_str = &sstate->team_footer_text;
    break;
  case SSERV_CMD_CNTS_SAVE_REGISTER_EMAIL_FILE:
    p_str = &sstate->register_email_text;
    break;

  case SSERV_CMD_CNTS_DEFAULT_ACCESS:
  case SSERV_CMD_CNTS_ADD_RULE:
  case SSERV_CMD_CNTS_CHANGE_RULE:
  case SSERV_CMD_CNTS_DELETE_RULE:
  case SSERV_CMD_CNTS_UP_RULE:
  case SSERV_CMD_CNTS_DOWN_RULE:
    switch (param1) {
    case 0: p_access = &cnts->register_access; break;
    case 1: p_access = &cnts->users_access; break;
    case 2: p_access = &cnts->master_access; break;
    case 3: p_access = &cnts->judge_access; break;
    case 4: p_access = &cnts->team_access; break;
    case 5: p_access = &cnts->serve_control_access; break;
    default:
      return -SSERV_ERR_INVALID_PARAMETER;
    }
    
    switch (cmd) {
    case SSERV_CMD_CNTS_DEFAULT_ACCESS:
      if (param3 < 0 || param3 > 1) return -SSERV_ERR_INVALID_PARAMETER;
      if (!param3) {
        // setting access to deny
        if (!*p_access) return 0;
        (*p_access)->default_is_allow = 0;
        if (!(*p_access)->b.first_down) {
          xml_unlink_node(&(*p_access)->b);
          contests_free_2(&(*p_access)->b);
          *p_access = 0;
        }
      } else {
        // setting access to allow
        if (!*p_access) {
          new_acc = (struct contest_access*)contests_new_node(access_tags_map[param1]);
          xml_link_node_last(&cnts->b, &new_acc->b);
          *p_access = new_acc;
        }
        (*p_access)->default_is_allow = 1;
      }
      return 0;
    case SSERV_CMD_CNTS_ADD_RULE:
      if (param3 < 0 || param3 > 1) return -SSERV_ERR_INVALID_PARAMETER;
      if (xml_parse_ip_mask(0, -1, 0, param2, &ip_addr, &ip_mask) < 0)
        return -SSERV_ERR_INVALID_PARAMETER;
      if (!*p_access) {
        new_acc = (struct contest_access*) contests_new_node(access_tags_map[param1]);
        xml_link_node_last(&cnts->b, &new_acc->b);
        *p_access = new_acc;
      }
      new_ip = (struct contest_ip*) contests_new_node(CONTEST_IP);
      new_ip->addr = ip_addr;
      new_ip->mask = ip_mask;
      new_ip->allow = param3;
      xml_link_node_last(&(*p_access)->b, &new_ip->b);
      return 0;
    case SSERV_CMD_CNTS_CHANGE_RULE:
      if (param3 < 0 || param3 > 1) return -SSERV_ERR_INVALID_PARAMETER;
      if (!(new_ip = (struct contest_ip*) get_nth_child(&(*p_access)->b, param4)))
        return -SSERV_ERR_INVALID_PARAMETER;
      new_ip->allow = param3;
      return 0;
    case SSERV_CMD_CNTS_DELETE_RULE:
      if (!(new_ip = (struct contest_ip*) get_nth_child(&(*p_access)->b, param4)))
        return -SSERV_ERR_INVALID_PARAMETER;
      xml_unlink_node(&new_ip->b);
      contests_free_2(&new_ip->b);
      if (!(*p_access)->b.first_down) {
        xml_unlink_node(&(*p_access)->b);
        contests_free_2(&(*p_access)->b);
        *p_access = 0;
      }
      return 0;
    case SSERV_CMD_CNTS_UP_RULE:
      if (!(new_ip = (struct contest_ip*) get_nth_child(&(*p_access)->b, param4)))
        return -SSERV_ERR_INVALID_PARAMETER;
      if (!new_ip->b.left) return -SSERV_ERR_INVALID_PARAMETER;
      swap_tree_nodes(new_ip->b.left);
      return 0;
    case SSERV_CMD_CNTS_DOWN_RULE:
      if (!(new_ip = (struct contest_ip*) get_nth_child(&(*p_access)->b, param4)))
        return -SSERV_ERR_INVALID_PARAMETER;
      if (!new_ip->b.right) return -SSERV_ERR_INVALID_PARAMETER;
      swap_tree_nodes(&new_ip->b);
      return 0;
    default:
      abort();
    }

  case SSERV_CMD_CNTS_DELETE_PERMISSION:
    if (!(cap_node = (struct opcap_list_item*) get_nth_child(cnts->caps_node, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    xml_unlink_node(&cap_node->b);
    contests_free_2(&cap_node->b);
    cnts->capabilities.first = (struct opcap_list_item*) cnts->caps_node->first_down;
    if (!cnts->capabilities.first) {
      xml_unlink_node(cnts->caps_node);
      contests_free_2(cnts->caps_node);
      cnts->caps_node = 0;
    }
    return 0;

  case SSERV_CMD_CNTS_ADD_PERMISSION:
    if (!param2 || !*param2) return -SSERV_ERR_INVALID_PARAMETER;
    if (strspn(param2, login_accept_chars) != strlen(param2))
      return -SSERV_ERR_INVALID_PARAMETER;
    for (cap_node = cnts->capabilities.first; cap_node;
         cap_node = (typeof(cap_node)) cap_node->b.right)
      if (!strcmp(cap_node->login, param2))
        return -SSERV_ERR_DUPLICATED_LOGIN;
    if (!cnts->caps_node) {
      cnts->caps_node = contests_new_node(CONTEST_CAPS);
      xml_link_node_last(&cnts->b, cnts->caps_node);
    }
    cap_node = (typeof(cap_node)) contests_new_node(CONTEST_CAP);
    if (!cnts->capabilities.first) cnts->capabilities.first = cap_node;
    cap_node->login = xstrdup(param2);
    xml_link_node_last(cnts->caps_node, &cap_node->b);
    return 0;

  case SSERV_CMD_CNTS_SAVE_PERMISSIONS:
    if (!(cap_node = (struct opcap_list_item*) get_nth_child(cnts->caps_node, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (strlen(param2) != 64) return -SSERV_ERR_INVALID_PARAMETER;
    for (n = 0; n < 64; n++)
      if (param2[n] != '0' && param2[n] != '1')
        return -SSERV_ERR_INVALID_PARAMETER;

    cap_node->caps = 0ULL;
    for (n = 0; n < 64; n++)
      if (param2[n] == '1')
        cap_node->caps |= (1ULL << n);
    return 0;

  case SSERV_CMD_CNTS_SAVE_FORM_FIELDS:
    if (param1 != -1 || param3 != -1 || param4 != -1)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (strlen(param2) != CONTEST_LAST_FIELD)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (param2[0] != '0')
      return -SSERV_ERR_INVALID_PARAMETER;
    for (n = 1; n < CONTEST_LAST_FIELD; n++)
      if (param2[n] < '0' || param2[n] > '2')
        return -SSERV_ERR_INVALID_PARAMETER;
    for (n = 1; n < CONTEST_LAST_FIELD; n++) {
      if (param2[n] == '0') {
        if (cnts->fields[n]) {
          xml_unlink_node(&cnts->fields[n]->b);
          contests_free_2(&cnts->fields[n]->b);
          cnts->fields[n] = 0;
        }
      } else {
        if (!cnts->fields[n]) {
          fld_node = (typeof(fld_node)) contests_new_node(CONTEST_FIELD);
          fld_node->id = n;
          cnts->fields[n] = fld_node;
          xml_link_node_last(&cnts->b, &fld_node->b);
        }
        cnts->fields[n]->mandatory = 0;
        if (param2[n] == '2') cnts->fields[n]->mandatory = 1;
      }
    }
    return 0;

  case SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS:
  case SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS:
  case SSERV_CMD_CNTS_SAVE_COACH_FIELDS:
  case SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS:
  case SSERV_CMD_CNTS_SAVE_GUEST_FIELDS:
    // param1 - init_count
    // param2 - field flags
    // param3 - min_count
    // param4 - max_count
    memb_ind = cmd - SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS;
    memb = cnts->members[memb_ind];

    if (param1 < 0 || param1 > 5) return -SSERV_ERR_INVALID_PARAMETER;
    if (param3 < 0 || param3 > 5) return -SSERV_ERR_INVALID_PARAMETER;
    if (param4 < 0 || param4 > 5) return -SSERV_ERR_INVALID_PARAMETER;
    if (param3 > param4) return -SSERV_ERR_INVALID_PARAMETER;
    if (param1 < param3 || param1 > param4) return -SSERV_ERR_INVALID_PARAMETER;
    if (strlen(param2) != CONTEST_LAST_MEMBER_FIELD)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (param2[0] != '0')
      return -SSERV_ERR_INVALID_PARAMETER;
    for (n = 1; n < CONTEST_LAST_MEMBER_FIELD; n++)
      if (param2[n] < '0' || param2[n] > '2')
        return -SSERV_ERR_INVALID_PARAMETER;

    // check, that we must remove this member
    if (!param1 && !param3 && !param4) {
      for (n = 1; n < CONTEST_LAST_MEMBER_FIELD; n++)
        if (param2[n] != '0')
          break;
      if (n == CONTEST_LAST_MEMBER_FIELD) {
        // completely remove this member
        if (memb) {
          for (n = 1; n < CONTEST_LAST_MEMBER_FIELD; n++)
            if (memb->fields[n]) {
              xml_unlink_node(&memb->fields[n]->b);
              contests_free_2(&memb->fields[n]->b);
              memb->fields[n] = 0;
            }
          xml_unlink_node(&memb->b);
          contests_free_2(&memb->b);
          cnts->members[memb_ind] = 0;
        }
        return 0;
      }
    }

    if (!memb) {
      memb = (typeof(memb)) contests_new_node(CONTEST_CONTESTANTS + memb_ind);
      xml_link_node_last(&cnts->b, &memb->b);
      cnts->members[memb_ind] = memb;
    }

    memb->min_count = param3;
    memb->max_count = param4;
    memb->init_count = param1;

    for (n = 1; n < CONTEST_LAST_MEMBER_FIELD; n++) {
      if (param2[n] == '0') {
        if (memb->fields[n]) {
          xml_unlink_node(&memb->fields[n]->b);
          contests_free_2(&memb->fields[n]->b);
          memb->fields[n] = 0;
        }
      } else {
        if (!memb->fields[n]) {
          fld_node = (typeof(fld_node)) contests_new_node(CONTEST_FIELD);
          fld_node->id = n;
          memb->fields[n] = fld_node;
          xml_link_node_last(&memb->b, &fld_node->b);
        }
        memb->fields[n]->mandatory = 0;
        if (param2[n] == '2') memb->fields[n]->mandatory = 1;
      }
    }
    return 0;

  default:
    abort();
  }

  if (p_date) {
    if (xml_parse_date("", 0, 0, param2, p_date) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;
  }

  if (p_bool) {
    // boolean variable
    if (!param2 || sscanf(param2, "%d%n", &v, &n) != 1 || param2[n] || v < 0 || v > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_bool = v;
    return 0;
  }

  if (p_str) {
    // text variable
    xfree(*p_str);
    *p_str = xstrdup(param2);
    return 0;
  }

  abort();
}

static void
make_conf_path(unsigned char *p, const unsigned char *d, const unsigned char *f)
{
  if (!os_IsAbsolutePath(f)) {
    snprintf(p, sizeof(path_t), "%s/%s", d, f);
  } else {
    snprintf(p, sizeof(path_t), "%s", f);
  }
}

static int
make_temp_file(unsigned char *out, const unsigned char *in)
{
  path_t buf;

  int n = 1, r;
  do {
    snprintf(buf, sizeof(path_t), "%s.%d", in, n++);
  } while ((r = open(buf, O_CREAT | O_EXCL | O_WRONLY | O_TRUNC, 0664)) < 0
           && errno == EEXIST);
  if (r >= 0) {
    close(r);
    r = 0;
    snprintf(out, sizeof(path_t), "%s", buf);
  }
  return r;
}

static int
save_conf_file(FILE *flog, const unsigned char *desc,
               const unsigned char *file, const unsigned char *text,
               const unsigned char *conf_path,
               unsigned char *path, unsigned char *path_2)
{
  int errcode;
  char *old_text = 0;
  size_t old_size = 0;

  if (file && *file && text) {
    make_conf_path(path, conf_path, file);

    // try to read the file
    errcode = generic_read_file(&old_text, 0, &old_size, 0, 0, path, 0);
    if (errcode >= 0 && strlen(text) == old_size
        && memcmp(text, old_text, old_size) == 0) {
      // file not changed
      fprintf(flog, "%s `%s' is not changed\n", desc, file);
      xfree(old_text);
      return 0;
    }
    xfree(old_text); old_text = 0; old_size = 0;

    if (make_temp_file(path_2, path) < 0) {
      fprintf(flog, "error: cannot create a temporary %s `%s'\n"
              "error: %s\n", desc, path, os_ErrorMsg());
      return -1;
    }
    if (generic_write_file(text, strlen(text), 0, 0, path_2, 0) < 0) {
      fprintf(flog, "error: saving of temporary %s `%s' failed\n"
              "error: %s\n", desc, path_2, os_ErrorMsg());
      return -1;
    }
    fprintf(flog, "%s `%s' is temporarily saved as `%s'\n", desc, file, path_2);
  }
  return 1;
}

static int
get_contest_header_and_footer(const unsigned char *path,
                              unsigned char **before_start,
                              unsigned char **after_end)
{
  char *xml_text = 0, *p1, *p2;
  unsigned char *s1 = 0, *s2 = 0;
  size_t xml_text_size = 0;
  struct stat sb;
  int errcode = 0;

  if (stat(path, &sb) < 0) return -SSERV_ERR_FILE_NOT_EXIST;

  if (generic_read_file(&xml_text, 0, &xml_text_size, 0, 0, path, 0) < 0)
    return -SSERV_ERR_FILE_READ_ERROR;

  if (!(p1 = strstr(xml_text, "<contest "))) {
    errcode = -SSERV_ERR_FILE_FORMAT_INVALID;
    goto failure;
  }
  if (!(p2 = strstr(xml_text, "</contest>"))) {
    errcode = -SSERV_ERR_FILE_FORMAT_INVALID;
    goto failure;
  }
    
  s1 = xmalloc(xml_text_size + 1);
  s2 = xmalloc(xml_text_size + 1);

  memcpy(s1, xml_text, p1 - xml_text);
  s1[p1 - xml_text] = 0;
  strcpy(s2, p2 + 10);

  *before_start = s1;
  *after_end = s2;

  xfree(xml_text);
  return 0;

 failure:
  xfree(xml_text);
  return errcode;
}

static void
rename_files(FILE *flog, int flag, unsigned char *to, unsigned char *from)
{
  if (!flag) return;
  if (!from || !*from || !to || !*to) return;
  if (rename(from, to) < 0) {
    fprintf(flog, "error: renaming %s to %s failed: %s\n",
            from, to, os_ErrorMsg());
  } else {
    fprintf(flog, "renamed %s to %s\n", from, to);
  }
}

int
super_html_commit_contest(FILE *f,
                          int priv_level,
                          int user_id,
                          const unsigned char *login,
                          unsigned long long session_id,
                          unsigned int ip_address,
                          struct userlist_cfg *config,
                          struct userlist_clnt *us_conn,
                          struct sid_state *sstate,
                          int cmd,
                          const unsigned char *self_url,
                          const unsigned char *hidden_vars,
                          const unsigned char *extra_args)
{
  struct contest_desc *cnts = sstate->edited_cnts;
  struct section_global_data *global = sstate->global;
  struct stat sb;
  char *flog_txt = 0;
  size_t flog_size = 0;
  FILE *flog = 0;
  int errcode;
  unsigned char *s = 0;
  unsigned char hbuf[1024];
  unsigned char *xml_header = 0;
  unsigned char *xml_footer = 0;
  unsigned char *serve_header = 0;
  unsigned char *serve_footer = 0;
  unsigned char audit_rec[1024];
  unsigned char serve_audit_rec[1024];
  int i, j;

  path_t conf_path;
  path_t var_path;
  path_t xml_path;
  path_t serve_path;
  path_t serve_path_2 = { 0 };
  path_t users_header_path = { 0 };
  path_t users_header_path_2 = { 0 };
  path_t users_footer_path = { 0 };
  path_t users_footer_path_2 = { 0 };
  path_t register_header_path = { 0 };
  path_t register_header_path_2 = { 0 };
  path_t register_footer_path = { 0 };
  path_t register_footer_path_2 = { 0 };
  path_t team_header_path = { 0 };
  path_t team_header_path_2 = { 0 };
  path_t team_footer_path = { 0 };
  path_t team_footer_path_2 = { 0 };
  path_t register_email_path = { 0 };
  path_t register_email_path_2 = { 0 };
  path_t contest_start_cmd_path = { 0 };
  path_t contest_start_cmd_path_2 = { 0 };
  path_t stand_header_path = { 0 };
  path_t stand_header_path_2 = { 0 };
  path_t stand_footer_path = { 0 };
  path_t stand_footer_path_2 = { 0 };
  path_t stand2_header_path = { 0 };
  path_t stand2_header_path_2 = { 0 };
  path_t stand2_footer_path = { 0 };
  path_t stand2_footer_path_2 = { 0 };
  path_t plog_header_path = { 0 };
  path_t plog_header_path_2 = { 0 };
  path_t plog_footer_path = { 0 };
  path_t plog_footer_path_2 = { 0 };

  int uhf, uff, rhf, rff, thf, tff, ref;
  int csf = 0, shf = 0, sff = 0, s2hf = 0, s2ff = 0, phf = 0, pff = 0, sf = 0;

  if (!cnts) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "No current contest!");
  }
  if (!cnts->root_dir || !*cnts->root_dir) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "root_dir is not set!");
  }
  if (!cnts->name) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "contest name is not defined");
  }
  if (!os_IsAbsolutePath(cnts->root_dir)) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "root_dir is not an absolute path!");
  }
  if (stat(cnts->root_dir, &sb) >= 0 && !S_ISDIR(sb.st_mode)) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "root_dir is not a directory!");
  }
  if (!sstate->serve_parse_errors && sstate->disable_compilation_server) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "Compilation server must be enabled");
  }
  if (!sstate->serve_parse_errors && sstate->global) {
    j = 0;
    if (sstate->langs) {
      for (i = 1; i < sstate->lang_a; i++)
        if (sstate->langs[i]) j++;
    }
    if (!j)
      return super_html_report_error(f, session_id, self_url, extra_args,
                                     "No languages activated");
    j = 0;
    if (sstate->probs) {
      for (i = 1; i < sstate->prob_a; i++)
        if (sstate->probs[i]) j++;
    }
    if (!j)
      return super_html_report_error(f, session_id, self_url, extra_args,
                                     "No problems defined");
  }
  // FIXME: what else we should validate

  if (!cnts->conf_dir) {
    snprintf(conf_path, sizeof(conf_path), "%s/%s", cnts->root_dir, "conf");
  } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(conf_path, sizeof(conf_path), "%s/%s", cnts->root_dir, cnts->conf_dir);
  } else {
    snprintf(conf_path, sizeof(conf_path), "%s", cnts->conf_dir);
  }

  flog = open_memstream(&flog_txt, &flog_size);

  /* 1. Create the contest root directory */
  if (stat(cnts->root_dir, &sb) >= 0) {
    if (!S_ISDIR(sb.st_mode)) {
      fprintf(flog, "error: contest root directory `%s' is not actually a directory\n",
              cnts->root_dir);
      goto failed;
    }
    fprintf(flog, "contest root directory `%s' already exists\n", cnts->root_dir);
  } else {
    if ((errcode = os_MakeDirPath(cnts->root_dir, 0775)) < 0) {
      fprintf(flog, "error: contest root directory `%s' creation failed\n",
              cnts->root_dir);
      fprintf(flog, "error: %s\n", os_GetErrorString(-errcode));
      goto failed;
    }
    fprintf(flog, "contest root directory `%s' is created\n", cnts->root_dir);
  }

  /* 2. Create the contest configuration directory */
  if (stat(conf_path, &sb) >= 0) {
    if (!S_ISDIR(sb.st_mode)) {
      fprintf(flog, "error: contest configuration directory `%s' is not actually a directory\n", conf_path);
      goto failed;
    }
    fprintf(flog, "contest configuration directory `%s' already exists\n", conf_path);
  } else {
    if ((errcode = os_MakeDirPath(conf_path, 0775)) < 0) {
      fprintf(flog, "error: contest configuration directory `%s' creation failed\n",
              conf_path);
      fprintf(flog, "error: %s\n", os_GetErrorString(-errcode));
      goto failed;
    }
    fprintf(flog, "contest configuration directory `%s' is created\n", conf_path);
  }

  /* 3. Save the users_header_file as temporary file */
  if ((uhf = save_conf_file(flog, "`users' HTML header file",
                            cnts->users_header_file, sstate->users_header_text,
                            conf_path,
                            users_header_path, users_header_path_2)) < 0)
    goto failed;

  /* 4. Save the users_footer_file as temporary file */
  if ((uff = save_conf_file(flog, "`users' HTML footer file",
                            cnts->users_footer_file, sstate->users_footer_text,
                            conf_path,
                            users_footer_path, users_footer_path_2)) < 0)
    goto failed;

  /* 5. Save the register_header_file as temporary file */
  if ((rhf = save_conf_file(flog, "`register' HTML header file",
                            cnts->register_header_file, sstate->register_header_text,
                            conf_path,
                            register_header_path, register_header_path_2)) < 0)
    goto failed;

  /* 6. Save the register_footer_file as temporary file */
  if ((rff = save_conf_file(flog, "`register' HTML footer file",
                            cnts->register_footer_file, sstate->register_footer_text,
                            conf_path,
                            register_footer_path, register_footer_path_2)) < 0)
    goto failed;

  /* 7. Save the team_header_file as temporary file */
  if ((thf = save_conf_file(flog, "`team' HTML header file",
                            cnts->team_header_file, sstate->team_header_text,
                            conf_path,
                            team_header_path, team_header_path_2)) < 0)
    goto failed;

  /* 8. Save the team_footer_file as temporary file */
  if ((tff = save_conf_file(flog, "`team' HTML footer file",
                            cnts->team_footer_file, sstate->team_footer_text,
                            conf_path,
                            team_footer_path, team_footer_path_2)) < 0)
    goto failed;

  /* 9. Save the register_email_file as temporary file */
  if ((ref = save_conf_file(flog, "registration e-mail template",
                            cnts->register_email_file, sstate->register_email_text,
                            conf_path,
                            register_email_path, register_email_path_2)) < 0)
    goto failed;

  if (global) {
    if ((csf = save_conf_file(flog, "contest start command script",
                              global->contest_start_cmd,sstate->contest_start_cmd_text,
                              conf_path,
                              contest_start_cmd_path, contest_start_cmd_path_2)) < 0)
      goto failed;
    if ((shf = save_conf_file(flog, "standings HTML header file",
                              global->stand_header_file, sstate->stand_header_text,
                              conf_path,
                              stand_header_path, stand_header_path_2)) < 0)
      goto failed;
    if ((sff = save_conf_file(flog, "standings HTML footer file",
                              global->stand_footer_file, sstate->stand_footer_text,
                              conf_path,
                              stand_footer_path, stand_footer_path_2)) < 0)
      goto failed;
    if ((s2hf = save_conf_file(flog, "supplementary standings HTML header file",
                               global->stand2_header_file, sstate->stand2_header_text,
                               conf_path,
                               stand2_header_path, stand2_header_path_2)) < 0)
      goto failed;
    if ((s2ff = save_conf_file(flog, "supplementary standings HTML footer file",
                               global->stand2_footer_file, sstate->stand2_footer_text,
                               conf_path,
                               stand2_footer_path, stand2_footer_path_2)) < 0)
      goto failed;
    if ((phf = save_conf_file(flog, "public submission log HTML header file",
                              global->plog_header_file, sstate->plog_header_text,
                              conf_path,
                              plog_header_path, plog_header_path_2)) < 0)
      goto failed;
    if ((pff = save_conf_file(flog, "public submission log HTML footer file",
                              global->plog_footer_file, sstate->plog_footer_text,
                              conf_path,
                              plog_footer_path, plog_footer_path_2)) < 0)
      goto failed;
  }

  /* 10. Load the previous contest.xml and extract header and footer */
  contests_make_path(xml_path, sizeof(xml_path), cnts->id);
  errcode = get_contest_header_and_footer(xml_path, &xml_header, &xml_footer);
  if (errcode == -SSERV_ERR_FILE_NOT_EXIST) {
    fprintf(flog, "XML file `%s' does not exist\n", xml_path);
    snprintf(audit_rec, sizeof(audit_rec),
             "<!-- audit: created %s %d (%s) %s -->\n",
             xml_unparse_date(time(0)), user_id, login,
             xml_unparse_ip(ip_address));
  } else if (errcode < 0) {
    fprintf(flog, "Failed to read XML file `%s': %s\n",
            xml_path, super_proto_strerror(-errcode));
    goto failed;
  } else {
    snprintf(audit_rec, sizeof(audit_rec),
             "<!-- audit: edited %s %d (%s) %s -->\n",
             xml_unparse_date(time(0)), user_id, login,
             xml_unparse_ip(ip_address));
  }
  if (!xml_header) {
    snprintf(hbuf, sizeof(hbuf),
             "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", EJUDGE_CHARSET);
    xml_header = xstrdup(hbuf);
  }
  if (!xml_footer) xml_footer = xstrdup("\n");

  /* Load the previous serve.cfg */
  if (!sstate->serve_parse_errors && sstate->global) {
    snprintf(serve_path, sizeof(serve_path), "%s/serve.cfg", conf_path);
    if (make_temp_file(serve_path_2, serve_path) < 0) {
      fprintf(flog, "error: cannot create a temporary serve.cfg `%s'\n"
              "error: %s\n", serve_path, os_ErrorMsg());
      goto failed;
    }

    errcode = super_html_get_serve_header_and_footer(serve_path, &serve_header, &serve_footer);
    if (errcode == -SSERV_ERR_FILE_NOT_EXIST) {
      fprintf(flog, "serve configuration file `%s' does not exist\n",
              serve_path);
      snprintf(serve_audit_rec, sizeof(serve_audit_rec),
               "# audit: created %s %d (%s) %s\n",
               xml_unparse_date(time(0)), user_id, login,
               xml_unparse_ip(ip_address));
    } else if (errcode < 0) {
      fprintf(flog, "failed to read serve configuration file `%s': %s\n",
              serve_path, super_proto_strerror(-errcode));
      goto failed;
    } else {
      snprintf(serve_audit_rec, sizeof(audit_rec),
               "# audit: edited %s %d (%s) %s\n",
               xml_unparse_date(time(0)), user_id, login,
               xml_unparse_ip(ip_address));
    }

    if ((sf = super_html_serve_unparse_and_save(serve_path, serve_path_2,
                                                sstate, config,
                                                serve_header, serve_footer,
                                                serve_audit_rec)) < 0)
      goto failed;
  }

  /* 11. Save the XML file */
  errcode = contests_unparse_and_save(cnts, xml_header, xml_footer, audit_rec);
  if (errcode < 0) {
    fprintf(flog, "error: saving of `%s' failed: %s\n", xml_path,
            contests_strerror(-errcode));
    goto failed;
  } else {
    fprintf(flog, "contest XML file `%s' saved successfully\n", xml_path);
  }

  /* 12. Rename files */
  rename_files(flog, uhf, users_header_path, users_header_path_2);
  rename_files(flog, uff, users_footer_path, users_footer_path_2);
  rename_files(flog, rhf, register_header_path, register_header_path_2);
  rename_files(flog, rff, register_footer_path, register_footer_path_2);
  rename_files(flog, thf, team_header_path, team_header_path_2);
  rename_files(flog, tff, team_footer_path, team_footer_path_2);
  rename_files(flog, ref, register_email_path, register_email_path_2);
  rename_files(flog, csf, contest_start_cmd_path, contest_start_cmd_path_2);
  if (csf) chmod(contest_start_cmd_path, 0755);
  rename_files(flog, shf, stand_header_path, stand_header_path_2);
  rename_files(flog, sff, stand_footer_path, stand_footer_path_2);
  rename_files(flog, s2hf, stand2_header_path, stand2_header_path_2);
  rename_files(flog, s2ff, stand2_footer_path, stand2_footer_path_2);
  rename_files(flog, phf, plog_header_path, plog_header_path_2);
  rename_files(flog, pff, plog_footer_path, plog_footer_path_2);
  rename_files(flog, sf, serve_path, serve_path_2);

  if ((i = userlist_clnt_register_contest(us_conn, ULS_PRIV_REGISTER_CONTEST,
                                          user_id, cnts->id)) < 0
      || (i = userlist_clnt_change_registration(us_conn, user_id, cnts->id,
                                                USERLIST_REG_OK, 0, 0) < 0)) {
    fprintf(flog, "failed to register user %s (%d) for contest %d: %s\n",
            login, user_id, cnts->id, userlist_strerror(-i));
  } else {
    fprintf(flog, "user %s (%d) is registered for contest %d\n",
            login, user_id, cnts->id);
  }

  // start serve and create all the necessary dirs
  snprintf(var_path, sizeof(var_path), "%s/var", cnts->root_dir);
  if (stat(var_path, &sb) < 0) {
    unsigned char *serve_buf = 0;
    fprintf(flog, "starting `serve' in prepare mode:\n\n");
    i = super_serve_start_serve_test_mode(cnts, &serve_buf);
    fprintf(flog, "%s\n", serve_buf);
    xfree(serve_buf);
  }

  fclose(flog);
  xfree(xml_header);
  xfree(xml_footer);

  /* all is done */
  fprintf(f, "<h2>Contest is saved successfully</h2>\n");
  s = html_armor_string_dup(flog_txt);
  fprintf(f, "<p>Contest saving log:<br><pre>%s</pre>\n", s);
  xfree(s);
  xfree(flog_txt);

  if (!sstate->serve_parse_errors) {
    flog_txt = 0; flog_size = 0;
    flog = open_memstream(&flog_txt, &flog_size);
    prepare_further_instructions(flog, cnts->root_dir, cnts->conf_dir,
                                 global, sstate->aprob_u, sstate->aprobs,
                                 sstate->prob_a, sstate->probs);
    fclose(flog);
    s = html_armor_string_dup(flog_txt);
    fprintf(f, "<h2>Further instructions</h2><p><pre>%s</pre>\n", s);
    xfree(s);
    xfree(flog_txt);
  }

  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td>%sTo the top</a></td></tr></table>\n",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,""));

  super_serve_clear_edited_contest(sstate);
  return 0;

 failed:
  xfree(xml_header);
  xfree(xml_footer);
  fclose(flog);

  if (users_header_path_2[0]) unlink(users_header_path_2);
  if (users_footer_path_2[0]) unlink(users_footer_path_2);
  if (register_header_path_2[0]) unlink(register_header_path_2);
  if (register_footer_path_2[0]) unlink(register_footer_path_2);
  if (team_header_path_2[0]) unlink(team_header_path_2);
  if (team_footer_path_2[0]) unlink(team_footer_path_2);
  if (register_email_path_2[0]) unlink(register_email_path_2);
  if (contest_start_cmd_path_2[0]) unlink(contest_start_cmd_path_2);
  if (stand_header_path_2[0]) unlink(stand_header_path_2);
  if (stand_footer_path_2[0]) unlink(stand_footer_path_2);
  if (stand2_header_path_2[0]) unlink(stand2_header_path_2);
  if (stand2_footer_path_2[0]) unlink(stand2_footer_path_2);
  if (plog_header_path_2[0]) unlink(plog_header_path_2);
  if (plog_footer_path_2[0]) unlink(plog_footer_path_2);
  if (serve_path_2[0]) unlink(serve_path_2);

  fprintf(f, "<h2><font color=\"red\">Contest saving failed</font></h2>\n");
  s = html_armor_string_dup(flog_txt);
  fprintf(f, "<p>Contest saving log:<br><pre>%s</pre>\n", s);
  xfree(s);
  xfree(flog_txt);
  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td>%sTo the top</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,""));
  fprintf(f, "<td>%sBack</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "action=%d", SUPER_ACTION_EDIT_CURRENT_CONTEST));
  fprintf(f, "</tr></table>\n");
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
