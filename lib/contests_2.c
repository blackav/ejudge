/* -*- mode: c -*- */

/* Copyright (C) 2008-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/contests.h"
#include "ejudge/meta/contests_meta.h"
#include "ejudge/xml_utils.h"
#include "ejudge/misctext.h"
#include "ejudge/pathutl.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/errlog.h"
#include "ejudge/fileutl.h"
#include "ejudge/compat.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#if defined EJUDGE_CHARSET
#define INTERNAL_CHARSET EJUDGE_CHARSET
#else
#define INTERNAL_CHARSET "utf-8"
#endif

extern char const * const contests_elem_map[];
extern char const * const contests_attr_map[];
extern const int contests_tag_to_meta_map[CONTEST_LAST_TAG];
extern const int contests_attr_to_meta_map[CONTEST_LAST_ATTR];
extern char const * const contests_field_map[];
extern char const * const contests_member_field_map[];
extern unsigned char *contests_dir;

void
contests_write_header(
        FILE *f,
        const struct contest_desc *cnts,
        int auto_contest_id)
{
  const int *flist;
  int i, j;

  fprintf(f, "<%s", contests_elem_map[CONTEST_CONTEST]);
  if (auto_contest_id > 0 && cnts->id == auto_contest_id) {
    fprintf(f, " %s=\"auto\"", contests_attr_map[CONTEST_A_ID]);
  } else {
    fprintf(f, " %s=\"%d\"", contests_attr_map[CONTEST_A_ID], cnts->id);
  }

  flist = (const int[]) {
    CONTEST_A_AUTOREGISTER, CONTEST_A_DISABLE_TEAM_PASSWORD, CONTEST_A_FORCE_PASSWORD_CHANGE,
    CONTEST_A_SIMPLE_REGISTRATION,
    CONTEST_A_SEND_PASSWD_EMAIL, CONTEST_A_ASSIGN_LOGINS,
    CONTEST_A_FORCE_REGISTRATION, CONTEST_A_DISABLE_NAME,
    CONTEST_A_ENABLE_PASSWORD_RECOVERY, CONTEST_A_EXAM_MODE,
    CONTEST_A_DISABLE_PASSWORD_CHANGE, CONTEST_A_DISABLE_LOCALE_CHANGE,
    CONTEST_A_PERSONAL, CONTEST_A_ALLOW_REG_DATA_EDIT,
    CONTEST_A_ENABLE_USER_TELEGRAM, CONTEST_A_ENABLE_AVATAR, CONTEST_A_ENABLE_LOCAL_PAGES,
    CONTEST_A_DISABLE_MEMBER_DELETE, CONTEST_A_CLOSED, CONTEST_A_INVISIBLE,
    CONTEST_A_MANAGED, CONTEST_A_RUN_MANAGED, CONTEST_A_OLD_RUN_MANAGED, CONTEST_A_READY, CONTEST_A_READ_ONLY_NAME,
    CONTEST_A_ENABLE_OAUTH, CONTEST_A_ENABLE_REMINDERS,
    CONTEST_A_DISABLE_STANDALONE_REG, CONTEST_A_ENABLE_TELEGRAM_REGISTRATION,
    0
  };
  for (i = 0; flist[i]; ++i) {
    j = contests_attr_to_meta_map[flist[i]];
    if (*(const unsigned char*) contest_desc_get_ptr(cnts, j))
      fprintf(f, "\n         %s=\"%s\"", contests_attr_map[flist[i]], "yes");
  }
  if (!cnts->clean_users) {
    fprintf(f, "\n         %s=\"%s\"",
            contests_attr_map[CONTEST_A_CLEAN_USERS], "no");
  }

  fprintf(f, ">");
}

static void
unparse_access(FILE *f, const struct contest_access *acc, int tag)
{
  struct contest_ip *ip;
  unsigned char ssl_str[64];

  if (!acc) return;
  if (!acc->default_is_allow && !acc->b.first_down) return;
  if (!acc->b.first_down) {
    fprintf(f, "  <%s default=\"%s\"/>\n", contests_elem_map[tag],
            acc->default_is_allow?"allow":"deny");
    return;
  }
  fprintf(f, "  <%s default=\"%s\">\n", contests_elem_map[tag],
          acc->default_is_allow?"allow":"deny");
  for (ip = (typeof(ip)) acc->b.first_down; ip;
       ip = (typeof(ip)) ip->b.right) {
    ssl_str[0] = 0;
    if (ip->ssl >= 0)
      snprintf(ssl_str, sizeof(ssl_str), " %s=\"%s\"",
               contests_attr_map[CONTEST_A_SSL], ip->ssl?"yes":"no");
    fprintf(f, "    <%s %s=\"%s\"%s>%s</%s>\n",
            contests_elem_map[CONTEST_IP], contests_attr_map[CONTEST_A_ALLOW],
            ip->allow?"yes":"no", ssl_str,
            xml_unparse_ipv6_mask(&ip->addr, &ip->mask),
            contests_elem_map[CONTEST_IP]);
  }
  fprintf(f, "  </%s>\n", contests_elem_map[tag]);
}

static void
unparse_field(
        FILE *f,
        const struct contest_field *pf,
        int id,
        char const * const field_map[],
        const unsigned char *indent)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (!pf) return;
  fprintf(f, "%s<%s %s=\"%s\" %s=\"%s\"",
          indent, contests_elem_map[CONTEST_FIELD],
          contests_attr_map[CONTEST_A_ID], field_map[id],
          contests_attr_map[CONTEST_A_MANDATORY], pf->mandatory?"yes":"no");
  if (pf->separator && pf->separator[0]) {
    fprintf(f, " %s=\"%s\"", contests_attr_map[CONTEST_A_SEPARATOR],
            html_armor_buf(&ab, pf->separator));
  }
  if (pf->options && pf->options[0]) {
    fprintf(f, " %s=\"%s\"", contests_attr_map[CONTEST_A_OPTIONS],
            html_armor_buf(&ab, pf->options));
  }
  if (pf->checkbox) {
    fprintf(f, " %s=\"%s\"", contests_attr_map[CONTEST_A_CHECKBOX], "yes");
  }
  if (pf->legend && pf->legend[0]) {
    fprintf(f, ">%s</%s>\n", html_armor_buf(&ab, pf->legend),
            contests_elem_map[CONTEST_FIELD]);
  } else {
    fprintf(f, "/>\n");
  }
  html_armor_free(&ab);
}

static void
unparse_fields(FILE *f, const struct contest_member *memb, int tag)
{
  int i;

  if (!memb) return;
  fprintf(f, "  <%s", contests_elem_map[tag]);
  if (memb->min_count >= 0)
    fprintf(f, " %s=\"%d\"",
            contests_attr_map[CONTEST_A_MIN], memb->min_count);
  if (memb->max_count >= 0)
    fprintf(f, " %s=\"%d\"",
            contests_attr_map[CONTEST_A_MAX], memb->max_count);
  if (memb->init_count >= 0)
    fprintf(f, " %s=\"%d\"",
            contests_attr_map[CONTEST_A_INITIAL], memb->init_count);
  fprintf(f, ">\n");
  for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++)
    unparse_field(f, memb->fields[i], i, contests_member_field_map, "    ");
  fprintf(f, "  </%s>\n", contests_elem_map[tag]);
}

static void
unparse_text(FILE *f, int tag, const unsigned char *txt)
{
  size_t arm_sz;
  unsigned char *arm_txt;

  if (!txt) return;
  if (html_armor_needed(txt, &arm_sz)) {
    arm_txt = (unsigned char*) alloca(arm_sz + 1);
    html_armor_string(txt, arm_txt);
    txt = arm_txt;
  }
  fprintf(f, "  <%s>%s</%s>\n", contests_elem_map[tag], txt,
          contests_elem_map[tag]);
}

static void
unparse_texts(
        FILE *f,
        const struct contest_desc *cnts,
        const int *flist)
{
  for (int i = 0; flist[i]; ++i)
    unparse_text(f, flist[i], *(const unsigned char **) contest_desc_get_ptr(cnts, contests_tag_to_meta_map[flist[i]]));
}

void
contests_unparse(
        FILE *f,
        const struct contest_desc *cnts,
        int auto_contest_id)
{
  const struct opcap_list_item *cap;
  unsigned char *s;
  int i, len, skip_elem;
  struct xml_tree *p;
  path_t tmp1, tmp2;

  contests_write_header(f, cnts, auto_contest_id);
  fprintf(f, "\n");

  unparse_texts(f, cnts, (const int[]) {
    CONTEST_NAME, CONTEST_NAME_EN, CONTEST_DEFAULT_LOCALE, CONTEST_MAIN_URL,
    CONTEST_KEYWORDS, CONTEST_COMMENT,
    0
  });

  // avoid generating root_dir and conf_dir if their values are default
  skip_elem = 0;
  tmp1[0] = 0;
  if (ejudge_config && ejudge_config->contests_home_dir) {
    snprintf(tmp1, sizeof(tmp1), "%s", ejudge_config->contests_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!tmp1[0]) {
    snprintf(tmp1, sizeof(tmp1), "%s", EJUDGE_CONTESTS_HOME_DIR);
  }
#endif
  if (tmp1[0] && cnts->root_dir) {
    len = strlen(tmp1);
    snprintf(tmp2, sizeof(tmp2), "%s/%06d", tmp1, cnts->id);
    if (!strcmp(tmp2, cnts->root_dir)) {
      // do nothing, <root_dir> has the default value
      skip_elem = 1;
    } else if (!strncmp(tmp1, cnts->root_dir, len)
               && cnts->root_dir[len] == '/') {
      while (cnts->root_dir[len] == '/') len++;
      unparse_text(f, CONTEST_ROOT_DIR, cnts->root_dir + len);
      skip_elem = 1;
    }
  }
  if (!skip_elem) unparse_text(f, CONTEST_ROOT_DIR, cnts->root_dir);

  skip_elem = 0;
  if (cnts->root_dir && cnts->conf_dir) {
    snprintf(tmp1, sizeof(tmp1), "%s/conf", cnts->root_dir);
    if (!strcmp(tmp1, cnts->conf_dir)) skip_elem = 1;
  }
  if (!skip_elem) unparse_text(f, CONTEST_CONF_DIR, cnts->conf_dir);

  if (cnts->user_contest && cnts->user_contest[0])
    unparse_text(f, CONTEST_USER_CONTEST, cnts->user_contest);
  if (cnts->reg_deadline > 0) {
    fprintf(f, "  <%s>%s</%s>\n",
            contests_elem_map[CONTEST_REGISTRATION_DEADLINE],
            xml_unparse_date(cnts->reg_deadline),
            contests_elem_map[CONTEST_REGISTRATION_DEADLINE]);
  }
  if (cnts->sched_time > 0) {
    fprintf(f, "  <%s>%s</%s>\n", contests_elem_map[CONTEST_SCHED_TIME],
            xml_unparse_date(cnts->sched_time),
            contests_elem_map[CONTEST_SCHED_TIME]);
  }
  if (cnts->open_time > 0) {
    fprintf(f, "  <%s>%s</%s>\n", contests_elem_map[CONTEST_OPEN_TIME],
            xml_unparse_date(cnts->open_time),
            contests_elem_map[CONTEST_OPEN_TIME]);
  }
  if (cnts->close_time > 0) {
    fprintf(f, "  <%s>%s</%s>\n", contests_elem_map[CONTEST_CLOSE_TIME],
            xml_unparse_date(cnts->close_time),
            contests_elem_map[CONTEST_CLOSE_TIME]);
  }
  if (cnts->update_time > 0) {
    fprintf(f, "  <%s>%s</%s>\n", contests_elem_map[CONTEST_UPDATE_TIME],
            xml_unparse_date(cnts->update_time),
            contests_elem_map[CONTEST_UPDATE_TIME]);
  }

  unparse_texts(f, cnts, (const int[]) {
    CONTEST_REGISTER_EMAIL, CONTEST_REGISTER_URL, CONTEST_TEAM_URL,
    CONTEST_STANDINGS_URL, CONTEST_PROBLEMS_URL, CONTEST_REGISTER_EMAIL_FILE,
    CONTEST_LOGIN_TEMPLATE, CONTEST_LOGIN_TEMPLATE_OPTIONS,
    CONTEST_LOGO_URL, CONTEST_CSS_URL, CONTEST_REGISTER_SUBJECT,
    CONTEST_REGISTER_SUBJECT_EN,
    0,
  });

  for (i = CONTEST_REGISTER_ACCESS; i <= CONTEST_SERVE_CONTROL_ACCESS; ++i) {
    unparse_access(f, *(const struct contest_access**) contest_desc_get_ptr(cnts, contests_tag_to_meta_map[i]), i);
  }

  if (cnts->caps_node) {
    fprintf(f, "  <%s>\n", contests_elem_map[CONTEST_CAPS]);
    for (cap = CNTS_FIRST_PERM(cnts); cap; cap = CNTS_NEXT_PERM(cap)) {
      fprintf(f, "    <%s %s = \"%s\">\n",
              contests_elem_map[CONTEST_CAP],
              contests_attr_map[CONTEST_A_LOGIN], cap->login);
      s = opcaps_unparse(6, 60, cap->caps);
      fprintf(f, "%s", s);
      xfree(s);
      fprintf(f, "    </%s>\n", contests_elem_map[CONTEST_CAP]);
    }
    fprintf(f, "  </%s>\n", contests_elem_map[CONTEST_CAPS]);
  }

  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    unparse_field(f, cnts->fields[i], i, contests_field_map, "  ");
  }

  for (i = CONTEST_M_CONTESTANT; i <= CONTEST_M_GUEST; ++i) {
    unparse_fields(f, cnts->members[i], CONTEST_CONTESTANTS + i);
  }

  unparse_texts(f, cnts, (const int[]) {
    CONTEST_USERS_HEADER_FILE, CONTEST_USERS_FOOTER_FILE,
    CONTEST_REGISTER_HEADER_FILE, CONTEST_REGISTER_FOOTER_FILE,
    CONTEST_TEAM_HEADER_FILE, CONTEST_TEAM_MENU_1_FILE,
    CONTEST_TEAM_MENU_2_FILE, CONTEST_TEAM_MENU_3_FILE,
    CONTEST_TEAM_SEPARATOR_FILE, CONTEST_TEAM_FOOTER_FILE,
    CONTEST_COPYRIGHT_FILE, CONTEST_PRIV_HEADER_FILE, CONTEST_PRIV_FOOTER_FILE,
    CONTEST_WELCOME_FILE, CONTEST_REG_WELCOME_FILE,

    CONTEST_USERS_HEAD_STYLE, CONTEST_USERS_PAR_STYLE,
    CONTEST_USERS_TABLE_STYLE, CONTEST_USERS_VERB_STYLE,
    CONTEST_USERS_TABLE_FORMAT, CONTEST_USERS_TABLE_FORMAT_EN,
    CONTEST_USERS_TABLE_LEGEND, CONTEST_USERS_TABLE_LEGEND_EN,
    CONTEST_REGISTER_HEAD_STYLE, CONTEST_REGISTER_PAR_STYLE,
    CONTEST_REGISTER_TABLE_STYLE, CONTEST_TEAM_HEAD_STYLE,
    CONTEST_TEAM_PAR_STYLE,

    CONTEST_SERVE_USER, CONTEST_SERVE_GROUP,
    CONTEST_RUN_USER, CONTEST_RUN_GROUP,

    CONTEST_DIR_MODE, CONTEST_DIR_GROUP,
    CONTEST_FILE_MODE, CONTEST_FILE_GROUP,

    CONTEST_USER_NAME_COMMENT, CONTEST_ALLOWED_LANGUAGES,
    CONTEST_ALLOWED_REGIONS, CONTEST_CF_NOTIFY_EMAIL,
    CONTEST_CLAR_NOTIFY_EMAIL, CONTEST_DAILY_STAT_EMAIL,

    CONTEST_EXT_ID, CONTEST_PROBLEM_COUNT, CONTEST_TELEGRAM_BOT_ID,
    CONTEST_TELEGRAM_ADMIN_CHAT_ID, CONTEST_TELEGRAM_USER_CHAT_ID,
    CONTEST_AVATAR_PLUGIN,
    CONTEST_CONTENT_PLUGIN,
    CONTEST_CONTENT_URL_PREFIX,

    0,
  });

  if (cnts->slave_rules) {
    fprintf(f, "  <%s>\n", contests_elem_map[CONTEST_SLAVE_RULES]);
    for (p = cnts->slave_rules->first_down; p; p = p->right) {
      fprintf(f, "    <%s>%s</%s>\n",
              contests_elem_map[p->tag], p->text, contests_elem_map[p->tag]);
    }
    fprintf(f, "  </%s>\n", contests_elem_map[CONTEST_SLAVE_RULES]);
  }
  if (cnts->oauth_rules) {
    fprintf(f, "  <%s>\n", contests_elem_map[CONTEST_OAUTH_RULES]);
    for (p = cnts->oauth_rules->first_down; p; p = p->right) {
      if (p->tag == CONTEST_OAUTH_RULE) {
        fprintf(f, "    <%s", contests_elem_map[CONTEST_OAUTH_RULE]);
        for (struct xml_attr *a = p->first; a; a = a->next) {
          // FIXME: XML escape?
          fprintf(f, " %s=\"%s\"", contests_attr_map[a->tag], a->text);
        }
        fprintf(f, " />\n");
      }
    }
    fprintf(f, "  </%s>\n", contests_elem_map[CONTEST_OAUTH_RULES]);
  }
  fprintf(f, "</%s>", contests_elem_map[CONTEST_CONTEST]);
}

int
contests_save_xml(
        struct contest_desc *cnts,
        const unsigned char *txt1,
        const unsigned char *txt2,
        const unsigned char *txt3)
{
  int serial = 1;
  unsigned char tmp_path[1024];
  unsigned char xml_path[1024];
  int fd;
  FILE *f;
  struct stat xml_stat;

  while (1) {
    snprintf(tmp_path, sizeof(tmp_path), "%s/_contests_tmp_%d.xml",
             contests_dir, serial++);
    if ((fd = open(tmp_path, O_WRONLY| O_CREAT| O_TRUNC|O_EXCL, 0600)) >= 0)
      break;
    if (errno != EEXIST) return -CONTEST_ERR_FILE_CREATION_ERROR;
  }
  if (!(f = fdopen(fd, "w"))) {
    close(fd);
    unlink(tmp_path);
    return -CONTEST_ERR_FILE_CREATION_ERROR;
  }

  fputs(txt1, f);
  contests_write_header(f, cnts, cnts->id);
  fputs(txt2, f);
  fputs(txt3, f);
  if (ferror(f)) {
    fclose(f);
    unlink(tmp_path);
    return -CONTEST_ERR_IO_ERROR;
  }
  if (fclose(f) < 0) {
    unlink(tmp_path);
    return -CONTEST_ERR_IO_ERROR;
  }

  contests_make_path(xml_path, sizeof(xml_path), cnts->id);
  if (stat(xml_path, &xml_stat) < 0) {
    unlink(tmp_path);
    return -CONTEST_ERR_NO_CONTEST;
  }
  if (!S_ISREG(xml_stat.st_mode)) {
    unlink(tmp_path);
    return -CONTEST_ERR_NO_CONTEST;
  }

  // try to change the owner, but ignore the error
  __attribute__((unused)) int _;
  _ = chown(tmp_path, xml_stat.st_uid, -1);
  // try to change the group and log errors
  if (chown(tmp_path, -1, xml_stat.st_gid) < 0) {
    err("contests_save_xml: chgrp failed: %s", os_ErrorMsg());
  }
  // try to change permissions and log errors
  if (chmod(tmp_path, xml_stat.st_mode & 07777) < 0) {
    err("contests_save_xml: chmod failed: %s", os_ErrorMsg());
  }

  if (rename(tmp_path, xml_path) < 0) {
    err("contests_save_xml: rename failed: %s", os_ErrorMsg());
    unlink(tmp_path);
    return -CONTEST_ERR_FILE_CREATION_ERROR;
  }
  return 0;
}

int
contests_unparse_and_save(
        struct contest_desc *cnts,
        const unsigned char *charset,
        const unsigned char *header,
        const unsigned char *footer,
        const unsigned char *add_footer,
        unsigned char *(*diff_func)(const unsigned char *,
                                    const unsigned char *),
        unsigned char **p_diff_txt)
{
  int serial = 1;
  unsigned char tmp_path[1024];
  unsigned char xml_path[1024];
  int fd;
  FILE *f;
  struct stat xml_stat;
  char *old_text = 0;
  size_t old_size = 0;
  char *new_text = 0;
  size_t new_size = 0;
  unsigned char *diff_txt = 0;

  if (!charset || !*charset) charset = INTERNAL_CHARSET;

  f = open_memstream(&new_text, &new_size);
  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", charset);
  if (header) fputs(header, f);
  contests_unparse(f, cnts, cnts->id);
  if (footer) fputs(footer, f);
  close_memstream(f); f = 0;

  contests_make_path(xml_path, sizeof(xml_path), cnts->id);

  // read the previuos file and compare it with the new
  if (generic_read_file(&old_text, 0, &old_size, 0, 0, xml_path, 0) >= 0
      && new_size == old_size && memcmp(new_text, old_text, new_size) == 0) {
    info("contest_save_xml: %d is not changed", cnts->id);
    xfree(old_text);
    xfree(new_text);
    return 0;
  }
  xfree(old_text); old_text = 0;
  old_size = 0;

  while (1) {
    snprintf(tmp_path, sizeof(tmp_path), "%s/_contests_tmp_%d.xml",
             contests_dir, serial++);
    if ((fd = open(tmp_path, O_WRONLY| O_CREAT| O_TRUNC|O_EXCL, 0600)) >= 0)
      break;
    if (errno != EEXIST) {
      xfree(new_text);
      return -CONTEST_ERR_FILE_CREATION_ERROR;
    }
  }
  if (!(f = fdopen(fd, "w"))) {
    close(fd);
    xfree(new_text);
    unlink(tmp_path);
    return -CONTEST_ERR_FILE_CREATION_ERROR;
  }

  fwrite(new_text, 1, new_size, f);
  xfree(new_text); new_text = 0;
  new_size = 0;
  if (add_footer) fputs(add_footer, f);
  if (ferror(f)) {
    fclose(f);
    unlink(tmp_path);
    return -CONTEST_ERR_IO_ERROR;
  }
  if (fclose(f) < 0) {
    unlink(tmp_path);
    return -CONTEST_ERR_IO_ERROR;
  }

  if (diff_func && p_diff_txt) {
    diff_txt = (*diff_func)(xml_path, tmp_path);
  }

  if (stat(xml_path, &xml_stat) >= 0) {
    if (!S_ISREG(xml_stat.st_mode)) {
      unlink(tmp_path);
      xfree(diff_txt);
      return -CONTEST_ERR_NO_CONTEST;
    }

    // try to change the owner, but ignore the error
    __attribute__((unused)) int _;
    _ = chown(tmp_path, xml_stat.st_uid, -1);
    // try to change the group and log errors
    if (chown(tmp_path, -1, xml_stat.st_gid) < 0) {
      err("contests_save_xml: chgrp failed: %s", os_ErrorMsg());
    }
    // try to change permissions and log errors
    if (chmod(tmp_path, xml_stat.st_mode & 07777) < 0) {
      err("contests_save_xml: chmod failed: %s", os_ErrorMsg());
    }
  } else {
    if (chmod(tmp_path, 0664) < 0) {
      err("contests_save_xml: chmod failed: %s", os_ErrorMsg());
    }
  }

  if (rename(tmp_path, xml_path) < 0) {
    err("contests_save_xml: rename failed: %s", os_ErrorMsg());
    unlink(tmp_path);
    xfree(diff_txt);
    return -CONTEST_ERR_FILE_CREATION_ERROR;
  }
  if (p_diff_txt) *p_diff_txt = diff_txt;
  return 0;
}

int
contests_remove_nth_permission(struct contest_desc *cnts, int n)
{
  struct opcap_list_item *perms;
  int j;

  for (j = 0, perms = CNTS_FIRST_PERM(cnts);
       perms && n != j;
       perms = CNTS_NEXT_PERM_NC(perms), ++j) {}
  if (!perms || n != j) return -1;

  xml_unlink_node(&perms->b);
  contests_free_2(&perms->b);
  cnts->capabilities.first=(struct opcap_list_item*)cnts->caps_node->first_down;
  if (!cnts->capabilities.first) {
    xml_unlink_node(cnts->caps_node);
    contests_free_2(cnts->caps_node);
    cnts->caps_node = 0;
  }
  return 0;
}

int
contests_add_permission(
        struct contest_desc *cnts,
        const unsigned char *login,
        opcap_t caps)
{
  struct opcap_list_item *cap_node;

  for (cap_node = CNTS_FIRST_PERM(cnts); cap_node;
       cap_node = CNTS_NEXT_PERM_NC(cap_node))
    if (!strcmp(cap_node->login, login)) {
      cap_node->caps |= caps;
      return 0;
    }

  if (!cnts->caps_node) {
    cnts->caps_node = contests_new_node(CONTEST_CAPS);
    xml_link_node_last(&cnts->b, cnts->caps_node);
  }
  cap_node = (typeof(cap_node)) contests_new_node(CONTEST_CAP);
  if (!cnts->capabilities.first) cnts->capabilities.first = cap_node;
  cap_node->login = xstrdup(login);
  cap_node->caps = caps;
  xml_link_node_last(cnts->caps_node, &cap_node->b);
  return 1;
}

int
contests_upsert_permission(
        struct contest_desc *cnts,
        const unsigned char *login,
        opcap_t caps)
{
  struct opcap_list_item *cap_node;

  for (cap_node = CNTS_FIRST_PERM(cnts); cap_node;
       cap_node = CNTS_NEXT_PERM_NC(cap_node))
    if (!strcmp(cap_node->login, login)) {
      cap_node->caps = caps;
      return 0;
    }

  if (!cnts->caps_node) {
    cnts->caps_node = contests_new_node(CONTEST_CAPS);
    xml_link_node_last(&cnts->b, cnts->caps_node);
  }
  cap_node = (typeof(cap_node)) contests_new_node(CONTEST_CAP);
  if (!cnts->capabilities.first) cnts->capabilities.first = cap_node;
  cap_node->login = xstrdup(login);
  cap_node->caps = caps;
  xml_link_node_last(cnts->caps_node, &cap_node->b);
  return 1;
}

void
contests_copy_permissions(
        struct contest_desc *cdst,
        const struct contest_desc *csrc)
{
  struct opcap_list_item *dperms1, *dperms2;
  const struct opcap_list_item *sperms;

  if (!cdst || !csrc) return;

  // remove all permissions from cdst
  for (dperms1 = CNTS_FIRST_PERM(cdst); dperms1; dperms1 = dperms2) {
    dperms2 = CNTS_NEXT_PERM_NC(dperms1);
    xml_unlink_node(&dperms1->b);
    contests_free_2(&dperms1->b);
  }
  if (cdst->caps_node) {
    xml_unlink_node(cdst->caps_node);
    contests_free_2(cdst->caps_node);
  }
  cdst->caps_node = 0;
  cdst->capabilities.first = 0;

  if (!csrc->capabilities.first) return;

  // copy all permissions from csrc to cdst
  cdst->caps_node = contests_new_node(CONTEST_CAPS);
  xml_link_node_last(&cdst->b, cdst->caps_node);

  for (sperms = CNTS_FIRST_PERM(csrc); sperms;
       sperms = CNTS_NEXT_PERM(sperms)) {
    dperms1 = (struct opcap_list_item *) contests_new_node(CONTEST_CAP);
    if (!cdst->capabilities.first) cdst->capabilities.first = dperms1;
    dperms1->login = xstrdup(sperms->login);
    dperms1->caps = sperms->caps;
    xml_link_node_last(cdst->caps_node, &dperms1->b);
  }
}

int
contests_set_permission(
        struct contest_desc *cnts,
        int num,
        opcap_t caps)
{
  struct opcap_list_item *p;
  int i;

  for (i = 0, p = CNTS_FIRST_PERM(cnts); i != num && p;
       ++i, p = CNTS_NEXT_PERM_NC(p));
  if (i != num || !p) return -1;
  p->caps = caps;
  return 0;
}

void
contests_set_default(
        struct contest_desc *cnts,
        struct contest_access **p_acc,
        int tag,
        int default_is_allow)
{
  struct contest_access *new_acc = 0;

  if (*p_acc && (*p_acc)->b.first_down) {
    (*p_acc)->default_is_allow = !!default_is_allow;
    return;
  }
  if (!default_is_allow) {
    if (!*p_acc) return;
    (*p_acc)->default_is_allow = 0;
    if (!(*p_acc)->b.first_down) {
      xml_unlink_node(&(*p_acc)->b);
      contests_free_2(&(*p_acc)->b);
      *p_acc = 0;
    }
    return;
  }

  if (!*p_acc) {
    new_acc = (struct contest_access*) contests_new_node(tag);
    xml_link_node_last(&cnts->b, &new_acc->b);
    *p_acc = new_acc;
  }
  (*p_acc)->default_is_allow = default_is_allow;
}

void
contests_add_ip(
        struct contest_desc *cnts,
        struct contest_access **p_acc,
        int tag,
        const ej_ip_t *p_addr,
        const ej_ip_t *p_mask,
        int ssl_flag,
        int default_allow)
{
  struct contest_access *new_acc = 0;
  struct contest_ip *new_ip;

  if (!*p_acc) {
    new_acc = (struct contest_access*) contests_new_node(tag);
    xml_link_node_last(&cnts->b, &new_acc->b);
    *p_acc = new_acc;
  }
  new_ip = (struct contest_ip*) contests_new_node(CONTEST_IP);
  new_ip->addr = *p_addr;
  new_ip->mask = *p_mask;
  new_ip->allow = default_allow;
  new_ip->ssl = ssl_flag;
  xml_link_node_last(&(*p_acc)->b, &new_ip->b);
}

struct contest_ip *
contests_get_ip_rule_nc(
        struct contest_access *acc,
        int n)
{
  struct contest_ip *p;
  int i;

  if (!acc) return 0;

  for (i = 0, p = CNTS_FIRST_IP_NC(acc); p && i != n;
       ++i, p = CNTS_NEXT_IP_NC(p));
  if (p && i == n) return p;
  return 0;
}

int
contests_delete_ip_rule(
        struct contest_access **p_acc,
        int n)
{
  int i;
  struct contest_ip *p;

  if (!*p_acc) return -1;

  for (i = 0, p = CNTS_FIRST_IP_NC(*p_acc); i != n && p;
       ++i, p = CNTS_NEXT_IP_NC(p));
  if (!p || i != n) return -1;

  xml_unlink_node(&p->b);
  contests_free_2(&p->b);
  if (!CNTS_FIRST_IP(*p_acc) && !(*p_acc)->default_is_allow) {
    xml_unlink_node(&(*p_acc)->b);
    contests_free_2(&(*p_acc)->b);
    *p_acc = 0;
  }
  return 0;
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

int
contests_forward_ip_rule(
        struct contest_access **p_acc,
        int n)
{
  int i;
  struct contest_ip *p;
  struct contest_access *acc = *p_acc;

  if (!acc) return -1;

  for (i = 0, p = CNTS_FIRST_IP_NC(acc); i != n && p;
       ++i, p = CNTS_NEXT_IP_NC(p));
  if (!p || i != n) return -1;
  if (!p->b.left) return -1;
  swap_tree_nodes(p->b.left);
  return 0;
}

int
contests_backward_ip_rule(
        struct contest_access **p_acc,
        int n)
{
  int i;
  struct contest_ip *p;
  struct contest_access *acc = *p_acc;

  if (!acc) return -1;

  for (i = 0, p = CNTS_FIRST_IP_NC(acc); i != n && p;
       ++i, p = CNTS_NEXT_IP_NC(p));
  if (!p || i != n) return -1;
  if (!p->b.right) return -1;
  swap_tree_nodes(&p->b);
  return 0;
}

int
contests_set_general_field(
        struct contest_desc *cnts,
        int field_id,
        int opt_val,
        const unsigned char *legend)
{
  struct contest_field *p;

  ASSERT(cnts);
  ASSERT(field_id > 0 && field_id < CONTEST_LAST_FIELD);
  ASSERT(opt_val >= 0 && opt_val <= 2);

  if (!opt_val) {
    if (cnts->fields[field_id]) {
      xml_unlink_node(&cnts->fields[field_id]->b);
      contests_free_2(&cnts->fields[field_id]->b);
      cnts->fields[field_id] = 0;
    }
  } else {
    if (!(p = cnts->fields[field_id])) {
      p = (struct contest_field *) contests_new_node(CONTEST_FIELD);
      p->id = field_id;
      cnts->fields[field_id] = p;
      xml_link_node_last(&cnts->b, &p->b);
    }
    p->mandatory = 0;
    if (opt_val == 2) p->mandatory = 1;
    if (!p->legend || p->legend != legend) {
      xfree(p->legend); p->legend = 0;
      if (legend) p->legend = xstrdup(legend);
    }
  }
  return 0;
}

void
contests_delete_member_fields(
        struct contest_desc *cnts,
        int m_id)
{
  struct contest_member *memb;
  int ff;

  ASSERT(cnts);
  ASSERT(m_id >= 0 && m_id < CONTEST_LAST_MEMBER);

  if (!(memb = cnts->members[m_id])) return;
  for (ff = 0; ff < CONTEST_LAST_MEMBER_FIELD; ++ff)
    if (memb->fields[ff]) {
      xml_unlink_node(&memb->fields[ff]->b);
      contests_free_2(&memb->fields[ff]->b);
      memb->fields[ff] = 0;
    }
  xml_unlink_node(&memb->b);
  contests_free_2(&memb->b);
  cnts->members[m_id] = 0;
}

void
contests_set_member_counts(
        struct contest_desc *cnts,
        int m_id,
        int min_count,
        int max_count,
        int init_count)
{
  struct contest_member *memb;

  ASSERT(cnts);
  ASSERT(m_id >= 0 || m_id < CONTEST_LAST_MEMBER);
  ASSERT(min_count >= 0 && min_count <= 5);
  ASSERT(max_count >= 0 && max_count <= 5);
  ASSERT(init_count >= 0 && init_count <= 5);
  ASSERT(min_count <= max_count);

  if (!(memb = cnts->members[m_id]) && !min_count && !max_count && !init_count)
    return;
  if (!memb) {
    memb = (struct contest_member*) contests_new_node(CONTEST_CONTESTANTS+m_id);
    xml_link_node_last(&cnts->b, &memb->b);
    cnts->members[m_id] = memb;
  }
  memb->min_count = min_count;
  memb->max_count = max_count;
  memb->init_count = init_count;
}

void
contests_set_member_field(
        struct contest_desc *cnts,
        int m_id,
        int field_id,
        int opt_val,
        const unsigned char *legend)
{
  struct contest_member *memb;
  struct contest_field *p;

  ASSERT(cnts);
  ASSERT(m_id >= 0 && m_id < CONTEST_LAST_MEMBER);
  ASSERT(field_id > 0 && field_id < CONTEST_LAST_MEMBER_FIELD);

  if (!(memb = cnts->members[m_id])) {
    memb = (struct contest_member*) contests_new_node(CONTEST_CONTESTANTS+m_id);
    xml_link_node_last(&cnts->b, &memb->b);
    cnts->members[m_id] = memb;
  }

  if (!opt_val) {
    if (!memb->fields[field_id]) return;
    xml_unlink_node(&memb->fields[field_id]->b);
    contests_free_2(&memb->fields[field_id]->b);
    memb->fields[field_id] = 0;
    return;
  }
  if (!(p = memb->fields[field_id])) {
    p = (struct contest_field*) contests_new_node(CONTEST_FIELD);
    p->id = field_id;
    memb->fields[field_id] = p;
    xml_link_node_last(&memb->b, &p->b);
  }
  p->mandatory = 0;
  if (opt_val == 2) p->mandatory = 1;
  if (!p->legend || p->legend != legend) {
    xfree(p->legend); p->legend = 0;
    if (legend) p->legend = xstrdup(legend);
  }
}
