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
#include "expat_iface.h"
#include "pathutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <string.h>
#include <pwd.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#endif

enum
  {
    TG_CONFIG = 1,
    TG_FILE,
    TG_SOCKET,
    TG_CONTESTS_DIR,
    TG_EMAIL_PROGRAM,
    TG_REGISTER_URL,
    TG_REGISTER_EMAIL,
    TG_USER_MAP,
    TG_MAP,
    TG_CAPS,
    TG_CAP,
    TG_SERVE_PATH,
  };
enum
  {
    AT_ENABLE_L10N = 1,
    AT_DISABLE_L10N,
    AT_L10N,
    AT_L10N_DIR,
    AT_USER,
    AT_PATH,
    AT_SYSTEM_USER,
    AT_LOCAL_USER,
    AT_LOGIN,
  };

static char const * const tag_map[] =
{
  0,
  "config",
  "file",
  "socket",
  "contests_dir",
  "email_program",
  "register_url",
  "register_email",
  "user_map",
  "map",
  "caps",
  "cap",
  "serve_path",

  0
};

static char const * const attn_map[] =
{
  0,
  "enable_l10n",
  "disable_l10n",
  "l10n",
  "l10n_dir",
  "user",
  "path",
  "system_user",
  "local_user",
  "login",

  0
};

static void *
tree_alloc_func(int tag)
{
  switch (tag) {
  case TG_CONFIG:
    return xcalloc(1, sizeof(struct userlist_cfg));
  case TG_SOCKET:
  case TG_FILE:
  case TG_CONTESTS_DIR:
  case TG_EMAIL_PROGRAM:
  case TG_REGISTER_EMAIL:
  case TG_REGISTER_URL:
  case TG_USER_MAP:
  case TG_CAPS:
  case TG_SERVE_PATH:
    return xcalloc(1, sizeof(struct xml_tree));
  case TG_MAP:
    return xcalloc(1, sizeof(struct userlist_cfg_user_map));
  case TG_CAP:
    return xcalloc(1, sizeof(struct opcap_list_item));
  default:
    SWERR(("unhandled tag: %d", tag));
  }
}

static void *
attn_alloc_func(int tag)
{
  return xcalloc(1, sizeof(struct xml_attn));
}

static int
err_dupl_elem(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: element <%s> may appear only once", path, t->line, t->column,
      tag_map[t->tag]);
  return -1;
}
static int
err_text_not_allowed(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: text is not allowed for element <%s>",
      path, t->line, t->column, tag_map[t->tag]);
  return -1;
}
static int
err_attr_not_allowed(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: attributes are not allowed for element <%s>",
      path, t->line, t->column, tag_map[t->tag]);
  return -1;
}
static int
err_empty_elem(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: element <%s> is empty",
      path, t->line, t->column, tag_map[t->tag]);
  return -1;
}
static int
err_nested_not_allowed(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: nested elements are not allowed for element <%s>",
      path, t->line, t->column, tag_map[t->tag]);
  return -1;
}
static int
err_invalid_elem(char const *path, struct xml_tree *tag)
{
  err("%s:%d:%d: element <%s> is invalid here", path, tag->line, tag->column,
      tag_map[tag->tag]);
  return -1;
}
static int
err_invalid_attn(char const *path, struct xml_attn *a)
{
  err("%s:%d:%d: attribute \"%s\" is invalid here", path, a->line, a->column,
      attn_map[a->tag]);
  return -1;
}

static int
handle_final_tag(char const *path, struct xml_tree *t, unsigned char **ps)
{
  if (*ps) return err_dupl_elem(path, t);
  if (!t->text || !*t->text) return err_empty_elem(path, t);
  if (t->first_down) return err_nested_not_allowed(path, t);
  if (t->first) return err_attr_not_allowed(path, t);
  *ps = t->text; t->text = 0;
  return 0;
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

static struct xml_tree *
parse_user_map(char const *path, struct xml_tree *p)
{
  struct xml_tree *q;
  struct xml_attn *a;
  struct userlist_cfg_user_map *m;

  ASSERT(p);
  ASSERT(p->tag == TG_USER_MAP);
  xfree(p->text); p->text = 0;
  if (p->first) {
    err_attr_not_allowed(path, p);
    return 0;
  }
  for (q = p->first_down; q; q = q->right) {
    if (q->tag != TG_MAP) {
      err_invalid_elem(path, q);
      return 0;
    }
    if (q->text && *q->text) {
      err_text_not_allowed(path, q);
      return 0;
    }
    if (q->first_down) {
      err_nested_not_allowed(path, q);
      return 0;
    }
    m = (struct userlist_cfg_user_map*) q;
    for (a = q->first; a; a = a->next) {
      switch (a->tag) {
      case AT_SYSTEM_USER:
        {
          struct passwd *pwd;

          if (!(pwd = getpwnam(a->text))) {
            err("%s:%d:%d: user %s does not exist", path, a->line, a->column,
                a->text);
            return 0;
          }
          m->system_uid = pwd->pw_uid;
          info("user %s uid is %d", a->text, pwd->pw_uid);
        }
        m->system_user_str = a->text; a->text = 0;
        break;
      case AT_LOCAL_USER:
        m->local_user_str = a->text; a->text = 0;
        break;
      default:
        err_invalid_attn(path, a);
        return 0;
      }
    }
  }
  return p;
}

static int
parse_capabilities(unsigned char const *path,
                   struct userlist_cfg *cfg,
                   struct xml_tree *ct)
{
  struct xml_tree *p;
  struct opcap_list_item *pp;

  ASSERT(ct->tag == TG_CAPS);

  if (cfg->capabilities.first) {
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
  cfg->capabilities.first = (struct opcap_list_item*) p;

  for (; p; p = p->right) {
    if (p->tag != TG_CAP) {
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
    if (p->first->tag != AT_LOGIN) {
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

struct userlist_cfg *
userlist_cfg_parse(char const *path)
{
  struct xml_tree *tree = 0, *p;
  struct userlist_cfg *cfg = 0;
  struct xml_attn *a;

  tree = xml_build_tree(path, tag_map, attn_map, tree_alloc_func,
                        attn_alloc_func);
  if (!tree) return 0;
  if (tree->tag != TG_CONFIG) {
    err("%s: %d: top-level tag must be <config>", path, tree->line);
    goto failed;
  }
  cfg = (struct userlist_cfg *) tree;
  xfree(cfg->b.text); cfg->b.text = 0;
  cfg->l10n = -1;

  for (a = cfg->b.first; a; a = a->next) {
    switch (a->tag) {
    case AT_ENABLE_L10N:
    case AT_DISABLE_L10N:
    case AT_L10N:
#if CONF_HAS_LIBINTL - 0 == 1
      if (cfg->l10n != -1) {
        err("%s:%d:%d: attribute \"%s\" already defined",
            path, a->line, a->column, attn_map[a->tag]);
        goto failed;
      }
      if ((cfg->l10n = parse_bool(a->text)) < 0) {
        err("%s:%d:%d: invalid boolean value", path, a->line, a->column);
        goto failed;
      }
      if (a->tag == AT_DISABLE_L10N) cfg->l10n = !cfg->l10n;
      break;
#else
      err("%s:%d:%d: localization support is not compiled",
          path, a->line, a->column);
      goto failed;
#endif /* CONF_HAS_LIBINTL */
    case AT_L10N_DIR:
#if CONF_HAS_LIBINTL - 0 == 1
      cfg->l10n_dir = a->text;
      break;
#else
      err("%s:%d:%d: localization support is not compiled",
          path, a->line, a->column);
      goto failed;
#endif /* CONF_HAS_LIBINTL */
    default:
      err("%s:%d:%d: attribute \"%s\" is not allowed here",
          path, a->line, a->column, attn_map[a->tag]);
      goto failed;
    }
  }
  if (!cfg->l10n_dir || !*cfg->l10n_dir) cfg->l10n = 0;
  if (cfg->l10n == -1) cfg->l10n = 0;

  for (p = cfg->b.first_down; p; p = p->right) {
    switch (p->tag) {
    case TG_FILE:
      if (handle_final_tag(path, p, &cfg->db_path) < 0) goto failed;
      break;
    case TG_SOCKET:
      if (handle_final_tag(path, p, &cfg->socket_path) < 0) goto failed;
      break;
    case TG_CONTESTS_DIR:
      if (handle_final_tag(path, p, &cfg->contests_dir) < 0) goto failed;
      break;
    case TG_EMAIL_PROGRAM:
      if (handle_final_tag(path, p, &cfg->email_program) < 0) goto failed;
      break;
    case TG_REGISTER_URL:
      if (handle_final_tag(path, p, &cfg->register_url) < 0) goto failed;
      break;
    case TG_REGISTER_EMAIL:
      if (handle_final_tag(path, p, &cfg->register_email) < 0) goto failed;
      break;
    case TG_SERVE_PATH:
      if (handle_final_tag(path, p, &cfg->serve_path) < 0) goto failed;
      break;
    case TG_USER_MAP:
      if (!(cfg->user_map = parse_user_map(path, p))) goto failed;
      break;
    case TG_CAPS:
      if (parse_capabilities(path, cfg, p) < 0) goto failed;
      break;
    default:
      err("%s:%d:%d: element <%s> is invalid here",
          path, p->line, p->column, tag_map[p->tag]);
      break;
    }
  }

  if (!cfg->db_path) {
    err("%s: element <file> is not defined", path);
    goto failed;
  }
  if (!cfg->socket_path) {
    err("%s: element <socket> is not defined", path);
    goto failed;
  }
  if (!cfg->contests_dir) {
    err("%s: element <contests_dir> is not defined", path);
    goto failed;
  }
  if (!cfg->email_program) {
    err("%s: element <email_program> is not defined", path);
    goto failed;
  }
  if (!cfg->register_url) {
    err("%s: element <register_url> is not defined", path);
    goto failed;
  }
  if (!cfg->register_email) {
    err("%s: element <register_email> is not defined", path);
    goto failed;
  }

  //userlist_cfg_unparse(cfg, stdout);
  return cfg;

 failed:
  if (tree) userlist_cfg_free((struct userlist_cfg *) tree);
  return 0;
}

struct userlist_cfg *
userlist_cfg_free(struct userlist_cfg *cfg)
{
  xml_tree_free((struct xml_tree*) cfg, 0, 0);
  return 0;
}

static void
fmt_func(FILE *o, struct xml_tree const *p, int s, int n)
{
  switch (p->tag) {
  case TG_CONFIG:
    if (s == 1 || s == 3) fprintf(o, "\n");
    break;
  case TG_FILE:
  case TG_SOCKET:
  case TG_CONTESTS_DIR:
    if (s == 3) fprintf(o, "\n");
    if (s == 0) fprintf(o, "  ");
    break;
  default:
    SWERR(("unhandled tag %d", p->tag));
  }
}

void
userlist_cfg_unparse(struct userlist_cfg *cfg, FILE *f)
{
  if (!cfg) return;

  xml_unparse_tree(stdout, (struct xml_tree*) cfg, tag_map, 0, 0, 0,
                   fmt_func);
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 * End:
 */
