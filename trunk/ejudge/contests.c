/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

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

#include "contests.h"
#include "pathutl.h"
#include "userlist.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>

#define MAX_CONTEST_ID 1000
#define CONTEST_CHECK_TIME 5

static char const * const tag_map[] =
{
  0,
  "contests",
  "contest",
  "register_access",
  "users_access",
  "master_access",
  "judge_access",
  "team_access",
  "ip",
  "field",
  "name",
  "name_en",
  "contestants",
  "reserves",
  "coaches",
  "advisors",
  "guests",
  "users_header_file",
  "users_footer_file",
  "register_email",
  "register_url",
  "team_url",
  "registration_deadline",
  "cap",
  "caps",
  "root_dir",
  "standings_url",
  "problems_url",
  "client_flags",
  "serve_user",
  "serve_group",
  "register_header_file",
  "register_footer_file",
  "team_header_file",
  "team_footer_file",
  "users_head_style",
  "users_par_style",
  "users_table_style",
  "users_verb_style",
  "register_head_style",
  "register_par_style",
  "register_table_style",
  "team_head_style",
  "team_par_style",

  0
};
static char const * const attn_map[] =
{
  0,
  "id",
  "default",
  "allow",
  "deny",
  "mandatory",
  "optional",
  "min",
  "max",
  "autoregister",
  "initial",
  "disable_team_password",
  "login",
  "managed",
  "clean_users",
  "run_managed",
  "closed",

  0
};
static size_t const tag_sizes[CONTEST_LAST_TAG] =
{
  0,
  sizeof(struct contest_list),  /* CONTEST_CONTESTS */
  sizeof(struct contest_desc),  /* CONTEST_CONTEST */
  sizeof(struct contest_access), /* CONTEST_REGISTER_ACCESS */
  sizeof(struct contest_access), /* CONTEST_USERS_ACCESS */
  sizeof(struct contest_access), /* CONTEST_MASTER_ACCESS */
  sizeof(struct contest_access), /* CONTEST_JUDGE_ACCESS */
  sizeof(struct contest_access), /* CONTEST_TEAM_ACCESS */
  sizeof(struct contest_ip),    /* CONTEST_IP */
  sizeof(struct contest_field), /* CONTEST_FIELD */
  0,                            /* CONTEST_NAME */
  0,                            /* CONTEST_NAME_EN */
  sizeof(struct contest_member), /* CONTEST_CONTESTANTS */
  sizeof(struct contest_member), /* CONTEST_RESERVES */
  sizeof(struct contest_member), /* CONTEST_COACHES */
  sizeof(struct contest_member), /* CONTEST_ADVISORS */
  sizeof(struct contest_member), /* CONTEST_GUESTS */
  0,                            /* CONTEST_USERS_HEADER_FILE */
  0,                            /* CONTEST_USERS_FOOTER_FILE */
  0,                            /* CONTEST_REGISTER_EMAIL */
  0,                            /* CONTEST_REGISTER_URL */
  0,                            /* CONTEST_TEAM_URL */
  0,                            /* CONTEST_REGISTRATION_DEADLINE */
  sizeof(struct opcap_list_item), /* CONTEST_CAP */
  0,                            /* CONTEST_CAPS */
  0,                            /* CONTEST_ROOT_DIR */
  0,                            /* CONTEST_STANDINGS_URL */
  0,                            /* CONTEST_PROBLEMS_URL */
  0,                            /* CONTEST_CLIENT_FLAGS */
  0,                            /* CONTEST_SERVE_USER */
  0,                            /* CONTEST_SERVE_GROUP */
  0,                            /* REGISTER_HEADER_FILE */
  0,                            /* REGISTER_FOOTER_FILE */
  0,                            /* TEAM_HEADER_FILE */
  0,                            /* TEAM_FOOTER_FILE */
  0,                            /* USERS_HEAD_STYLE */
  0,                            /* USERS_PAR_STYLE */
  0,                            /* USERS_TABLE_STYLE */
  0,                            /* USERS_VERB_STYLE */
  0,                            /* REGISTER_HEAD_STYLE */
  0,                            /* REGISTER_PAR_STYLE */
  0,                            /* REGISTER_TABLE_STYLE */
  0,                            /* TEAM_HEAD_STYLE */
  0,                            /* TEAM_PAR_STYLE */
};
static size_t const attn_sizes[CONTEST_LAST_ATTN] =
{
  0,
  sizeof(struct xml_attn),
};

static void *
node_alloc(int tag)
{
  size_t sz;
  ASSERT(tag >= 1 && tag < CONTEST_LAST_TAG);
  if (!(sz = tag_sizes[tag])) sz = sizeof(struct xml_tree);
  return xcalloc(1, sz);
}
static void *
attn_alloc(int tag)
{
  size_t sz;

  ASSERT(tag >= 1 && tag < CONTEST_LAST_ATTN);
  if (!(sz = attn_sizes[tag])) sz = sizeof(struct xml_attn);
  return xcalloc(1, sz);
}
static void
node_free(struct xml_tree *t)
{
  switch (t->tag) {
  case CONTEST_CONTESTS:
    xfree(((struct contest_list *) t)->id_map);
    break;
  }
}
static void
attn_free(struct xml_attn *a)
{
}

static char const * const field_map[] =
{
  0,
  "homepage",
  "inst",
  "inst_en",
  "instshort",
  "instshort_en",
  "fac",
  "fac_en",
  "facshort",
  "facshort_en",
  "city",
  "city_en",
  "country",
  "country_en",

  0
};

static char const * const member_field_map[] =
{
  0,
  "firstname",
  "firstname_en",
  "middlename",
  "middlename_en",
  "surname",
  "surname_en",
  "status",
  "grade",
  "group",
  "group_en",
  "email",
  "homepage",
  "inst",
  "inst_en",
  "instshort",
  "instshort_en",
  "fac",
  "fac_en",
  "facshort",
  "facshort_en",
  "occupation",
  "occupation_en",

  0,
};

static int
parse_date(unsigned char const *s, unsigned long *pd)
{
  int year, month, day, hour, min, sec, n;
  time_t t;
  struct tm tt;

  if (!s) goto failed;
  if (sscanf(s, "%d/%d/%d %d:%d:%d %n", &year, &month, &day, &hour,
             &min, &sec, &n) != 6) goto failed;
  if (s[n]) goto failed;
  if (year < 1900 || year > 2100 || month < 1 || month > 12
      || day < 1 || day > 31 || hour < 0 || hour >= 24
      || min < 0 || min >= 60 || sec < 0 || sec >= 60) goto failed;
  tt.tm_sec = sec;
  tt.tm_min = min;
  tt.tm_hour = hour;
  tt.tm_mday = day;
  tt.tm_mon = month - 1;
  tt.tm_year = year - 1900;
  if ((t = mktime(&tt)) == (time_t) -1) goto failed;
  *pd = t;
  return 0;

 failed:
  return -1;
}

static int
parse_bool(char const *str)
{
  if (!str) return -1;
  if (!strcasecmp(str, "true")
      || !strcasecmp(str, "yes")
      || !strcasecmp(str, "1")) return 1;
  if (!strcasecmp(str, "false")
      || !strcasecmp(str, "no")
      || !strcasecmp(str, "0")) return 0;
  return -1;
}

static int
parse_access(struct contest_access *acc, char const *path)
{
  struct xml_attn *a;
  struct xml_tree *t;
  struct contest_ip *ip;
  int n;
  unsigned int b1, b2, b3, b4;

  for (a = acc->b.first; a; a = a->next) {
    switch (a->tag) {
    case CONTEST_A_DEFAULT:
      if (!strcasecmp(a->text, "allow")) {
        acc->default_is_allow = 1;
      } else if (!strcasecmp(a->text, "deny")) {
        acc->default_is_allow = 0;
      } else {
        err("%s:%d:%d: invalid value for attribute", path, a->line, a->column);
        return -1;
      }
      break;
    default:
      err("%s:%d:%d: attribute \"%s\" is invalid here",
          path, a->line, a->column, attn_map[a->tag]);
      return -1;
    }
  }

  for (t = acc->b.first_down; t; t = t->right) {
    if (t->tag != CONTEST_IP) {
      err("%s:%d:%d: tag <%s> is invalid here",
          path, t->line, t->column, tag_map[t->tag]);
      return -1;
    }
    if (t->first_down) {
      err("%s:%d:%d: nested tags are not allowed", path, t->line, t->column);
      return -1;
    }

    ip = (struct contest_ip*) t;
    ip->allow = -1;
    for (a = ip->b.first; a; a = a->next) {
      if (a->tag != CONTEST_A_ALLOW && a->tag != CONTEST_A_DENY) {
        err("%s:%d:%d: attribute \"%s\" is invalid here",
            path, a->line, a->column, attn_map[a->tag]);
        return -1;
      }
      if (ip->allow != -1) {
        err("%s:%d:%d: attribute \"allow\" already defined",
            path, a->line, a->column);
        return -1;
      }
      if ((ip->allow = parse_bool(a->text)) < 0) {
        err("%s:%d:%d invalid boolean value",
            path, a->line, a->column);
        return -1;
      }
      if (a->tag == CONTEST_A_DENY) ip->allow = !ip->allow;
    }
    if (ip->allow == -1) ip->allow = 0;

    n = 0;
    if (sscanf(ip->b.text, "%u.%u.%u.%u %n", &b1, &b2, &b3, &b4, &n) == 4
        && !ip->b.text[n]
        && b1 <= 255 && b2 <= 255 && b3 <= 255 && b4 <= 255) {
      ip->addr = b1 << 24 | b2 << 16 | b3 << 8 | b4;
      ip->mask = 0xFFFFFFFF;
    } else if (sscanf(ip->b.text, "%u.%u.%u. %n", &b1, &b2, &b3, &n) == 3
               && !ip->b.text[n] && b1 <= 255 && b2 <= 255 && b3 <= 255) {
      ip->addr = b1 << 24 | b2 << 16 | b3 << 8;
      ip->mask = 0xFFFFFF00;
    } else if (sscanf(ip->b.text, "%u.%u. %n", &b1, &b2, &n) == 2
               && !ip->b.text[n] && b1 <= 255 && b2 <= 255) {
      ip->addr = b1 << 24 | b2 << 16;
      ip->mask = 0xFFFF0000;
    } else if (sscanf(ip->b.text, "%u. %n", &b1, &n) == 1
               && !ip->b.text[n] && b1 <= 255) {
      ip->addr = b1 << 24;
      ip->mask = 0xFF000000;
    } else {
      err("%s:%d:%d: invalid IP-address", path, ip->b.line, ip->b.column);
      return -1;
    }
  }

  xfree(acc->b.text); acc->b.text = 0;
  return 0;
}

static int
parse_member(struct contest_member *mb, char const *path)
{
  struct xml_attn *a;
  struct xml_tree *t;
  struct contest_field *pf;
  int i, n;

  mb->min_count = -1;
  mb->max_count = -1;
  for (a = mb->b.first; a; a = a->next) {
    switch (a->tag) {
    case CONTEST_A_MIN:
    case CONTEST_A_MAX:
    case CONTEST_A_INITIAL:
      if (!a->text || sscanf(a->text, "%d %n", &i, &n) != 1
          || a->text[n] || i < 0 || i > 100) {
        err("%s:%d:%d: invalid value", path, a->line, a->column);
        return -1;
      }
      switch (a->tag) {
      case CONTEST_A_MIN:     mb->min_count = i;  break;
      case CONTEST_A_MAX:     mb->max_count = i;  break;
      case CONTEST_A_INITIAL: mb->init_count = i; break;
      }
      break;
    default:
      err("%s:%d:%d: attribute \"%s\" is invalid here",
          path, a->line, a->column, attn_map[a->tag]);
      return -1;
    }
  }

  xfree(mb->b.text); mb->b.text = 0;
  for (t = mb->b.first_down; t; t = t->right) {
    if (t->tag != CONTEST_FIELD) {
      err("%s:%d:%d: tag <%s> is invalid here",
          path, t->line, t->column, tag_map[t->tag]);
      return -1;
    }
    if (t->text && *t->text) {
      err("%s:%d:%d: tag <%s> cannot contain text",
          path, t->line, t->column, tag_map[t->tag]);
      return -1;
    }
    if (t->first_down) {
      err("%s:%d:%d: nested tags are not allowed",
          path, t->line, t->column);
      return -1;
    }
    pf = (struct contest_field*) t;

    pf->mandatory = -1;
    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case CONTEST_A_ID:
        for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
          if (!member_field_map[i]) continue;
          if (!strcmp(a->text, member_field_map[i])) break;
        }
        if (i >= CONTEST_LAST_MEMBER_FIELD) {
          err("%s:%d:%d: invalid field id \"%s\"",
              path, a->line, a->column, a->text);
          return -1;
        }
        if (mb->fields[i]) {
          err("%s:%d:%d: field \"%s\" already defined",
              path, a->line, a->column, a->text);
          return -1;
        }
        mb->fields[i] = pf;
        break;
      case CONTEST_A_MANDATORY:
      case CONTEST_A_OPTIONAL:
        if (pf->mandatory != -1) {
          err("%s:%d:%d: attribute \"mandatory\" already defined",
              path, a->line, a->column);
          return -1;
        }
        if ((pf->mandatory = parse_bool(a->text)) < 0) {
          err("%s:%d:%d: invalid boolean value",
              path, a->line, a->column);
          return -1;
        }
        if (a->tag == CONTEST_A_OPTIONAL) pf->mandatory = !pf->mandatory;
        break;
      default:
        err("%s:%d:%d: attribute \"%s\" is invalid here",
            path, a->line, a->column, attn_map[a->tag]);
        return -1;
      }
    }
    if (pf->mandatory == -1) pf->mandatory = 0;
  }
  return 0;
}

static int
handle_final_tag(char const *path, struct xml_tree *t, unsigned char **ps)
{
  if (*ps) {
    err("%s:%d:%d: duplicated element <%s>",
        path, t->line, t->column, tag_map[t->tag]);
    return -1;
  }
  if (!t->text || !*t->text) {
    err("%s:%d:%d: empty element <%s>", path, t->line, t->column,
        tag_map[t->tag]);
    return -1;
  }
  if (t->first_down) {
    err("%s:%d:%d: element <%s> cannot contain nested elements",
        path, t->line, t->column, tag_map[t->tag]);
    return -1;
  }
  if (t->first) {
    err("%s:%d:%d: element <%s> cannot have attributes",
        path, t->line, t->column, tag_map[t->tag]);
    return -1;
  }
  *ps = t->text; t->text = 0;
  return 0;
}

static int
parse_capabilities(unsigned char const *path,
                   struct contest_desc *cnts,
                   struct xml_tree *ct)
{
  struct xml_tree *p;
  struct opcap_list_item *pp;

  ASSERT(ct->tag == CONTEST_CAPS);

  if (cnts->capabilities.first) {
    err("%s:%d:%d: element <caps> already defined",
        path, ct->line, ct->column);
    return -1;
  }

  xfree(ct->text); ct->text = 0;
  if (ct->first) {
    err("%s:%d:%d: element <caps> cannot have attributes",
        path, ct->line, ct->column);
    return -1;
  }
  p = ct->first_down;
  if (!p) return 0;
  cnts->capabilities.first = (struct opcap_list_item*) p;

  for (; p; p = p->right) {
    if (p->tag != CONTEST_CAP) {
      err("%s:%d:%d: element <cap> expected", path, p->line, p->column);
      return -1;
    }
    pp = (struct opcap_list_item*) p;

    if (!p->first) {
      err("%s:%d:%d: element <cap> must have attribute",
          path, p->line, p->column);
      return -1;
    }
    if (p->first->next) {
      err("%s:%d:%d: element <cap> must have only one attribute",
          path, p->line, p->column);
      return -1;
    }
    if (p->first->tag != CONTEST_A_LOGIN) {
      err("%s:%d:%d: \"login\" attribute expected",
          path, p->line, p->column);
      return -1;
    }
    pp->login = p->first->text;
    if (!pp->login || !*pp->login) {
      err("%s:%d:%d: \"login\" cannot be empty",
          path, p->line, p->column);
      return -1;
    }
    if (opcaps_parse(p->text, &pp->caps) < 0) {
      err("%s:%d:%d: invalid capabilities",
          path, p->line, p->column);
      return -1;
    }
  }
  return 0;
}

static int
parse_client_flags(unsigned char const *path, struct contest_desc *cnts,
                   struct xml_tree *xt)
{
  int len;
  unsigned char *str2, *q, *str3;
  unsigned char const *p, *s, *str;

  str = xt->text;
  if (!str) str = "";
  len = strlen(str);
  str2 = (unsigned char *) alloca(len + 10);
  for (p = str, q = str2; *p; p++) {
    if (isspace(*p)) continue;
    if (isalpha(*p)) {
      *q++ = toupper(*p);
    } else {
      *q++ = *p;
    }
  }
  *q++ = 0;

  str3 = (unsigned char *) alloca(len + 10);
  p = str2;
  while (1) {
    while (*p == ',') p++;
    if (!*p) break;
    for (s = p; *s && *s != ','; s++);
    memset(str3, 0, len + 10);
    memcpy(str3, p, s - p);
    p = s;

    if (!strcmp(str3, "IGNORE_TIME_SKEW")) {
      cnts->client_ignore_time_skew = 1;
    } else if (!strcmp(str3, "DISABLE_TEAM")) {
      cnts->client_disable_team = 1;
    } else {
      err("%s:%d:%d: unknown flag '%s'", path, xt->line, xt->column, str3);
      return -1;
    }
  }

  return 0;
}

static int
parse_contest(struct contest_desc *cnts, char const *path)
{
  struct xml_attn *a;
  struct xml_tree *t;
  int x, n, mb_id;
  unsigned char *reg_deadline_str = 0;
  struct contest_access **pacc;

  cnts->clean_users = 1;

  for (a = cnts->b.first; a; a = a->next) {
    switch (a->tag) {
    case CONTEST_A_ID:
      x = n = 0;
      if (sscanf(a->text, "%d %n", &x, &n) != 1 || a->text[n]
          || x <= 0 || x > MAX_CONTEST_ID) {
        err("%s:%d:%d: attribute value is invalid", path, a->line, a->column);
        return -1;
      }
      cnts->id = x;
      break;
    case CONTEST_A_AUTOREGISTER:
      x = parse_bool(a->text);
      if (x < 0 || x > 1) {
        err("%s:%d:%d: attribute value is invalid", path, a->line, a->column);
        return -1;
      }
      cnts->autoregister = x;
      break;
    case CONTEST_A_MANAGED:
      x = parse_bool(a->text);
      if (x < 0 || x > 1) {
        err("%s:%d:%d: attribute value is invalid", path, a->line, a->column);
        return -1;
      }
      cnts->managed = x;
      break;
    case CONTEST_A_RUN_MANAGED:
      x = parse_bool(a->text);
      if (x < 0 || x > 1) {
        err("%s:%d:%d: attribute value is invalid", path, a->line, a->column);
        return -1;
      }
      cnts->run_managed = x;
      break;
    case CONTEST_A_CLEAN_USERS:
      x = parse_bool(a->text);
      if (x < 0 || x > 1) {
        err("%s:%d:%d: attribute value is invalid", path, a->line, a->column);
        return -1;
      }
      cnts->clean_users = x;
      break;
    case CONTEST_A_DISABLE_TEAM_PASSWORD:
      x = parse_bool(a->text);
      if (x < 0 || x > 1) {
        err("%s:%d:%d: attribute value is invalid", path, a->line, a->column);
        return -1;
      }
      cnts->disable_team_password = x;
      break;
    case CONTEST_A_CLOSED:
      x = parse_bool(a->text);
      if (x < 0 || x > 1) {
        err("%s:%d:%d: attribute value is invalid", path, a->line, a->column);
        return -1;
      }
      cnts->closed = x;
      break;
    default:
      err("%s:%d:%d: attribute \"%s\" is invalid here",
          path, a->line, a->column, attn_map[a->tag]);
      return -1;
    }
  }

  if (!cnts->id) {
    err("%s:%d:%d: contest id is not defined",
        path, cnts->b.line, cnts->b.column);
    return -1;
  }

  for (t = cnts->b.first_down; t; t = t->right) {
    switch(t->tag) {
    case CONTEST_NAME:
      if (handle_final_tag(path, t, &cnts->name) < 0) return -1;
      break;
    case CONTEST_NAME_EN:
      if (handle_final_tag(path, t, &cnts->name_en) < 0) return -1;
      break;
    case CONTEST_USERS_HEADER_FILE:
      if (handle_final_tag(path, t, &cnts->users_header_file) < 0) return -1;
      break;
    case CONTEST_USERS_FOOTER_FILE:
      if (handle_final_tag(path, t, &cnts->users_footer_file) < 0) return -1;
      break;
    case CONTEST_REGISTER_HEADER_FILE:
      if (handle_final_tag(path, t, &cnts->register_header_file)<0) return -1;
      break;
    case CONTEST_REGISTER_FOOTER_FILE:
      if (handle_final_tag(path, t, &cnts->register_footer_file)<0) return -1;
      break;
    case CONTEST_TEAM_HEADER_FILE:
      if (handle_final_tag(path, t, &cnts->team_header_file) < 0) return -1;
      break;
    case CONTEST_TEAM_FOOTER_FILE:
      if (handle_final_tag(path, t, &cnts->team_footer_file) < 0) return -1;
      break;
    case CONTEST_USERS_HEAD_STYLE:
      if (handle_final_tag(path, t, &cnts->users_head_style) < 0) return -1;
      break;
    case CONTEST_USERS_PAR_STYLE:
      if (handle_final_tag(path, t, &cnts->users_par_style) < 0) return -1;
      break;
    case CONTEST_USERS_TABLE_STYLE:
      if (handle_final_tag(path, t, &cnts->users_table_style) < 0) return -1;
      break;
    case CONTEST_USERS_VERB_STYLE:
      if (handle_final_tag(path, t, &cnts->users_verb_style) < 0) return -1;
      break;
    case CONTEST_REGISTER_HEAD_STYLE:
      if (handle_final_tag(path, t, &cnts->register_head_style) < 0) return -1;
      break;
    case CONTEST_REGISTER_PAR_STYLE:
      if (handle_final_tag(path, t, &cnts->register_par_style) < 0) return -1;
      break;
    case CONTEST_REGISTER_TABLE_STYLE:
      if (handle_final_tag(path, t, &cnts->register_table_style)< 0) return -1;
      break;
    case CONTEST_TEAM_HEAD_STYLE:
      if (handle_final_tag(path, t, &cnts->team_head_style) < 0) return -1;
      break;
    case CONTEST_TEAM_PAR_STYLE:
      if (handle_final_tag(path, t, &cnts->team_par_style) < 0) return -1;
      break;
    case CONTEST_REGISTER_EMAIL:
      if (handle_final_tag(path, t, &cnts->register_email) < 0) return -1;
      break;
    case CONTEST_REGISTER_URL:
      if (handle_final_tag(path, t, &cnts->register_url) < 0) return -1;
      break;
    case CONTEST_TEAM_URL:
      if (handle_final_tag(path, t, &cnts->team_url) < 0) return -1;
      break;
    case CONTEST_ROOT_DIR:
      if (handle_final_tag(path, t, &cnts->root_dir) < 0) return -1;
      break;
    case CONTEST_STANDINGS_URL:
      if (handle_final_tag(path, t, &cnts->standings_url) < 0) return -1;
      break;
    case CONTEST_PROBLEMS_URL:
      if (handle_final_tag(path, t, &cnts->problems_url) < 0) return -1;
      break;
    case CONTEST_SERVE_USER:
      if (handle_final_tag(path, t, &cnts->serve_user) < 0) return -1;
      break;
    case CONTEST_SERVE_GROUP:
      if (handle_final_tag(path, t, &cnts->serve_group) < 0) return -1;
      break;
    case CONTEST_CLIENT_FLAGS:
      if (t->first_down) {
        err("%s:%d:%d: element <%s> cannot contain nested elements",
            path, t->line, t->column, tag_map[t->tag]);
        return -1;
      }
      if (t->first) {
        err("%s:%d:%d: element <%s> cannot have attributes",
            path, t->line, t->column, tag_map[t->tag]);
        return -1;
      }
      if (parse_client_flags(path, cnts, t) < 0) return -1;
      break;
    case CONTEST_REGISTRATION_DEADLINE:
      if (handle_final_tag(path, t, &reg_deadline_str) < 0) {
        xfree(reg_deadline_str);
        return -1;
      }
      t->text = reg_deadline_str;
      if (parse_date(reg_deadline_str, &cnts->reg_deadline) < 0) {
        err("%s:%d:%d: invalid date", path, t->line, t->column);
        return -1;
      }
      break;

    case CONTEST_CAPS:
      if (parse_capabilities(path, cnts, t) < 0) return -1;
      break;

    case CONTEST_CONTESTANTS:
      mb_id = CONTEST_M_CONTESTANT;
      goto process_members;
    case CONTEST_RESERVES:
      mb_id = CONTEST_M_RESERVE;
      goto process_members;
    case CONTEST_COACHES:
      mb_id = CONTEST_M_COACH;
      goto process_members;
    case CONTEST_ADVISORS:
      mb_id = CONTEST_M_ADVISOR;
      goto process_members;
    case CONTEST_GUESTS:
      mb_id = CONTEST_M_GUEST;

    process_members:
      if (cnts->members[mb_id]) {
        err("%s:%d:%d: tag <%s> redefined",
            path, t->line, t->column, tag_map[t->tag]);
        return -1;
      }
      if (parse_member((struct contest_member*) t, path) < 0)
        return -1;
      cnts->members[mb_id] = (struct contest_member*) t;
      break;

    case CONTEST_REGISTER_ACCESS:
      pacc = &cnts->register_access;
      goto process_access;
    case CONTEST_USERS_ACCESS:
      pacc = &cnts->users_access;
      goto process_access;
    case CONTEST_MASTER_ACCESS:
      pacc = &cnts->master_access;
      goto process_access;
    case CONTEST_JUDGE_ACCESS:
      pacc = &cnts->judge_access;
      goto process_access;
    case CONTEST_TEAM_ACCESS:
      pacc = &cnts->team_access;
    process_access:
      if (*pacc) {
        err("%s:%d:%d: contest access is already defined",
            path, t->line, t->column);
        return -1;
      }
      *pacc = (struct contest_access*) t;
      if (parse_access(*pacc, path) < 0) return -1;
      break;

    case CONTEST_FIELD:
      if (t->first_down) {
        err("%s:%d:%d: nested tags are not allowed", path, t->line, t->column);
        return -1;
      }
      if (t->text && t->text[0]) {
        err("%s:%d:%d: <field> tag cannot contain text",
            path, t->line, t->column);
        return -1;
      }
      xfree(t->text);
      t->text = 0;
      {
        struct contest_field *pf = (struct contest_field*) t;
        int i;

        pf->mandatory = -1;
        for (a = t->first; a; a = a->next) {
          switch (a->tag) {
          case CONTEST_A_ID:
            for (i = 1; i < CONTEST_LAST_FIELD; i++) {
              if (!field_map[i]) continue;
              if (!strcmp(a->text, field_map[i])) break;
            }
            if (i >= CONTEST_LAST_FIELD) {
              err("%s:%d:%d: invalid field id \"%s\"",
                  path, a->line, a->column, a->text);
              return -1;
            }
            if (cnts->fields[i]) {
              err("%s:%d:%d: field \"%s\" already defined",
                  path, a->line, a->column, a->text);
              return -1;
            }
            cnts->fields[i] = pf;
            break;
          case CONTEST_A_MANDATORY:
          case CONTEST_A_OPTIONAL:
            if (pf->mandatory != -1) {
              err("%s:%d:%d: attribute \"mandatory\" already defined",
                  path, a->line, a->column);
              return -1;
            }
            if ((pf->mandatory = parse_bool(a->text)) < 0) {
              err("%s:%d:%d: invalid boolean value",
                  path, a->line, a->column);
              return -1;
            }
            if (a->tag == CONTEST_A_OPTIONAL) pf->mandatory = !pf->mandatory;
            break;
          default:
            err("%s:%d:%d: attribute \"%s\" is invalid here",
                path, a->line, a->column, attn_map[a->tag]);
            return -1;
          }
        }
        if (pf->mandatory == -1) pf->mandatory = 0;
      }
      break;

    default:
      err("%s:%d:%d: tag <%s> is invalid here",
          path, t->line, t->column, tag_map[t->tag]);
      return -1;
    }
  }
  xfree(cnts->b.text); cnts->b.text = 0;

  if (!cnts->name) {
    err("%s:%d:%d: contest name is not defined",
        path, cnts->b.line, cnts->b.column);
    return -1;
  }

  if (!cnts->users_head_style) {
    cnts->users_head_style = xstrdup("h2");
  }
  if (!cnts->register_head_style) {
    cnts->register_head_style = xstrdup("h2");
  }
  if (!cnts->team_head_style) {
    cnts->team_head_style = xstrdup("h2");
  }
  if (!cnts->users_par_style)
    cnts->users_par_style = xstrdup("");
  if (!cnts->register_par_style)
    cnts->register_par_style = xstrdup("");
  if (!cnts->team_par_style)
    cnts->team_par_style = xstrdup("");
  if (!cnts->users_table_style)
    cnts->users_table_style = xstrdup("");
  if (!cnts->register_table_style)
    cnts->register_table_style = xstrdup("");
  if (!cnts->users_verb_style)
    cnts->users_verb_style = xstrdup("");

  return 0;
}

static struct contest_desc *
parse_one_contest_xml(char const *path, int number)
{
  struct xml_tree *tree = 0;
  struct contest_desc *d = 0;

  tree = xml_build_tree(path, tag_map, attn_map, node_alloc, attn_alloc);
  if (!tree) goto failed;
  if (tree->tag != CONTEST_CONTEST) {
    err("%s:%d:%d: top-level tag must be <contest>",
        path, tree->line, tree->column);
    goto failed;
  }
  d = (struct contest_desc *) tree;
  if (parse_contest(d, path) < 0) goto failed;
  return d;

 failed:
  if (tree) xml_tree_free(tree, node_free, attn_free);
  return 0;
}

static int
do_check_ip(struct contest_access *acc, unsigned long ip)
{
  struct contest_ip *p;

  if (!acc) return 0;
  if (!ip && acc->default_is_allow) return 1;
  if (!ip) return 0;

  for (p = (struct contest_ip*) acc->b.first_down;
       p; p = (struct contest_ip*) p->b.right) {
    if ((ip & p->mask) == p->addr) return p->allow;
  }
  return acc->default_is_allow;
}

int
contests_check_ip(int num, int field, unsigned long ip)
{
  struct contest_desc *d = 0;
  struct contest_access *acc = 0;
  int e;

  if ((e = contests_get(num, &d)) < 0) {
    err("contests_check_ip: %d: %s", num, contests_strerror(-e));
    return 0;
  }
  switch (field) {
  case CONTEST_REGISTER_ACCESS: acc = d->register_access; break;
  case CONTEST_USERS_ACCESS:    acc = d->users_access; break;
  case CONTEST_MASTER_ACCESS:   acc = d->master_access; break;
  case CONTEST_JUDGE_ACCESS:    acc = d->judge_access; break;
  case CONTEST_TEAM_ACCESS:     acc = d->team_access; break;
  default:
    err("contests_check_ip: %d: invalid field %d", num, field);
    return 0;
  }
  return do_check_ip(acc, ip);
}

int
contests_check_register_ip(int num, unsigned long ip)
{
  return contests_check_ip(num, CONTEST_REGISTER_ACCESS, ip);
}
int
contests_check_users_ip(int num, unsigned long ip)
{
  return contests_check_ip(num, CONTEST_USERS_ACCESS, ip);
}
int
contests_check_master_ip(int num, unsigned long ip)
{
  return contests_check_ip(num, CONTEST_MASTER_ACCESS, ip);
}
int
contests_check_judge_ip(int num, unsigned long ip)
{
  return contests_check_ip(num, CONTEST_JUDGE_ACCESS, ip);
}
int
contests_check_team_ip(int num, unsigned long ip)
{
  return contests_check_ip(num, CONTEST_TEAM_ACCESS, ip);
}

struct callback_list_item
{
  struct callback_list_item *next;
  void (*func)(const struct contest_desc *);
};
static struct callback_list_item *load_list;
static struct callback_list_item *unload_list;

static struct callback_list_item *
contests_set_callback(struct callback_list_item *list,
                      void (*f)(const struct contest_desc *))
{
  struct callback_list_item *p = 0;

  if (!f) return list;
  for (p = list; p; p = p->next)
    if (p->func == f)
      return list;

  p = (struct callback_list_item *) xcalloc(1, sizeof(*p));
  p->next = list;
  p->func = f;
  return p;
}

void
contests_set_load_callback(void (*f)(const struct contest_desc *))
{
  load_list = contests_set_callback(load_list, f);
}
void
contests_set_unload_callback(void (*f)(const struct contest_desc *))
{
  unload_list = contests_set_callback(unload_list, f);
}

static unsigned char const *contests_dir;
static unsigned int contests_allocd;
static struct contest_desc **contests_desc;

static void
contests_free(struct contest_desc *cnts)
{
  xml_tree_free((struct xml_tree *) cnts, node_free, attn_free);
}

static int
contests_make_path(unsigned char *buf, size_t sz, int num)
{
  return snprintf(buf, sz, "%s/%06d.xml", contests_dir, num);
}

int
contests_set_directory(unsigned char const *dir)
{
  struct stat bbb;

  if (!dir) return -CONTEST_ERR_BAD_DIR;
  if (stat(dir, &bbb) < 0) return -CONTEST_ERR_BAD_DIR;
  if (!S_ISDIR(bbb.st_mode)) return -CONTEST_ERR_BAD_DIR;
  contests_dir = xstrdup(dir);
  return 0;
}

int
contests_get_list(unsigned char **p_map)
{
  DIR *d = 0;
  struct dirent *dd = 0;
  int entries_num = -1, i, j;
  unsigned char *flags = 0;
  struct stat bbb;
  unsigned char c_path[1024];

  // we don't check specifically for "." or ".."
  if (!(d = opendir(contests_dir))) return -CONTEST_ERR_BAD_DIR;
  while ((dd = readdir(d))) {
    if (sscanf(dd->d_name, "%d", &j) == 1) {
      snprintf(c_path, sizeof(c_path), "%06d.xml", j);
      if (!strcmp(c_path, dd->d_name) && j > entries_num) entries_num = j;
    }
  }
  closedir(d);
  if (entries_num < 0) {
    *p_map = 0;
    return 0;
  }

  flags = (unsigned char *) alloca(entries_num + 1);
  memset(flags, 0, entries_num + 1);

  for (i = 1; i <= entries_num; i++) {
    contests_make_path(c_path, sizeof(c_path), i);
    if (stat(c_path, &bbb) < 0) continue;
    if (access(c_path, R_OK) < 0) continue;
    if (!S_ISREG(bbb.st_mode)) continue;
    // FIXME: check the owner of the file?
    flags[i] = 1;
  }

  while (entries_num >= 0 && !flags[entries_num]) entries_num--;
  if (!p_map) return entries_num + 1;
  *p_map = 0;
  if (entries_num < 0) return 0;
  *p_map = (unsigned char *) xmalloc(entries_num + 1);
  memcpy(*p_map, flags, entries_num + 1);
  return entries_num + 1;
}

int
contests_get(int number, struct contest_desc **p_desc)
{
  unsigned char c_path[1024];
  struct stat sb;
  struct contest_desc *cnts;
  time_t cur_time;

  ASSERT(p_desc);
  *p_desc = 0;
  if (number <= 0) return -CONTEST_ERR_BAD_ID;

  if (number >= contests_allocd || !contests_desc[number]) {
    // no previous info about the contest
    contests_make_path(c_path, sizeof(c_path), number);
    if (stat(c_path, &sb) < 0) return -CONTEST_ERR_NO_CONTEST;
    // load the info and adjust time marks
    cnts = parse_one_contest_xml(c_path, number);
    if (!cnts) return -CONTEST_ERR_BAD_XML;
    if (cnts->id != number) {
      contests_free(cnts);
      return -CONTEST_ERR_ID_NOT_MATCH;
    }
    cnts->last_check_time = time(0);
    cnts->last_file_time = sb.st_mtime;
    // extend arrays
    if (number >= contests_allocd) {
      unsigned int new_allocd = contests_allocd;
      struct contest_desc **new_contests = 0;

      if (!new_allocd) new_allocd = 32;
      while (number >= new_allocd) new_allocd *= 2;
      new_contests = xcalloc(new_allocd, sizeof(new_contests[0]));
      if (contests_allocd > 0) {
        memcpy(new_contests, contests_desc,
               contests_allocd * sizeof(new_contests[0]));
      }
      contests_allocd = new_allocd;
      contests_desc = new_contests;
    }
    // put new contest into the array
    contests_desc[number] = cnts;
    *p_desc = cnts;
    return 0;
  }

  cur_time = time(0);
  cnts = contests_desc[number];
  ASSERT(cnts->id == number);
  // check the time since last check
  if (cur_time <= cnts->last_check_time + CONTEST_CHECK_TIME) {
    *p_desc = cnts;
    return 0;
  }

  contests_make_path(c_path, sizeof(c_path), number);
  if (stat(c_path, &sb) < 0) {
    // FIXME: contest removed. what to do?
    contests_free(cnts);
    contests_desc[number] = 0;
    return -CONTEST_ERR_REMOVED;
  }
  // check whether update timestamp is changed
  if (sb.st_mtime == cnts->last_file_time) {
    *p_desc = cnts;
    return 0;
  }

  // load the info and adjust time marks
  // FIXME: try to merge data?
  cnts = parse_one_contest_xml(c_path, number);
  if (!cnts) return -CONTEST_ERR_BAD_XML;
  if (cnts->id != number) {
    contests_free(cnts);
    return -CONTEST_ERR_ID_NOT_MATCH;
  }
  cnts->last_check_time = time(0);
  cnts->last_file_time = sb.st_mtime;
  contests_desc[number] = cnts;
  *p_desc = cnts;
  return 0;
}

static unsigned char const * const contests_errors[] =
{
  "no error",
  "invalid contests directory",
  "invalid contest id",
  "contest does not exist",
  "error during XML reading",
  "contest id in the file and file name do not match",
  "contest is removed",

  [CONTEST_ERR_LAST] "unknown error"
};

unsigned char *
contests_strerror(int e)
{
  if (e < 0) e = -e;
  if (e > CONTEST_ERR_LAST) e = CONTEST_ERR_LAST;
  return (unsigned char *) contests_errors[e];
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
