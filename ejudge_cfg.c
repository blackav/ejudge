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

#include "ejudge_cfg.h"
#include "expat_iface.h"
#include "errlog.h"
#include "xml_utils.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <limits.h>

enum
  {
    TG_CONFIG = 1,
    TG_USERDB_FILE,
    TG_SOCKET_PATH,
    TG_CONTESTS_DIR,
    TG_EMAIL_PROGRAM,
    TG_REGISTER_URL,
    TG_REGISTER_EMAIL,
    TG_SERVER_NAME,
    TG_SERVER_NAME_EN,
    TG_SERVER_MAIN_URL,
    TG_USER_MAP,
    TG_MAP,
    TG_CAPS,
    TG_CAP,
    TG_SERVE_PATH,
    TG_L10N_DIR,
    TG_RUN_PATH,
    TG_CHARSET,
    TG_CONFIG_DIR,
    TG_CONTESTS_HOME_DIR,
    TG_FULL_CGI_DATA_DIR,
    TG_COMPILE_HOME_DIR,
    TG_TESTING_WORK_DIR,
    TG_SCRIPT_DIR,
    TG_SERIALIZATION_KEY,
    TG_ADMIN_EMAIL,
    TG_USERLIST_LOG,
    TG_VAR_DIR,
    TG_SUPER_SERVE_LOG,
    TG_COMPILE_LOG,
    TG_SUPER_SERVE_SOCKET,
    TG_SUPER_SERVE_USER,
    TG_SUPER_SERVE_GROUP,
    TG_USERLIST_USER,
    TG_USERLIST_GROUP,
    TG_JOB_SERVER_LOG,
    TG_JOB_SERVER_SPOOL,
    TG_JOB_SERVER_WORK,

    TG_LAST_TAG,
  };
enum
  {
    AT_ENABLE_L10N = 1,
    AT_DISABLE_L10N,
    AT_L10N,
    AT_SYSTEM_USER,
    AT_LOCAL_USER,
    AT_LOGIN,
    AT_EJUDGE_USER,

    AT_LAST_TAG,
  };

static char const * const elem_map[] =
{
  0,
  "config",
  "userdb_file",
  "socket_path",
  "contests_dir",
  "email_program",
  "register_url",
  "register_email",
  "server_name",
  "server_name_en",
  "server_main_url",
  "user_map",
  "map",
  "caps",
  "cap",
  "serve_path",
  "l10n_dir",
  "run_path",
  "charset",
  "config_dir",
  "contests_home_dir",
  "full_cgi_data_dir",
  "compile_home_dir",
  "testing_work_dir",
  "script_dir",
  "serialization_key",
  "admin_email",
  "userlist_log",
  "var_dir",
  "super_serve_log",
  "compile_log",
  "super_serve_socket",
  "super_serve_user",
  "super_serve_group",
  "userlist_user",
  "userlist_group",
  "job_server_log",
  "job_server_spool",
  "job_server_work",

  0
};

static char const * const attr_map[] =
{
  0,
  "enable_l10n",
  "disable_l10n",
  "l10n",
  "system_user",
  "local_user",
  "login",
  "ejudge_user",

  0
};

static size_t elem_sizes[TG_LAST_TAG] =
{
  [TG_CONFIG] = sizeof(struct ejudge_cfg),
  [TG_MAP] = sizeof(struct ejudge_cfg_user_map),
  [TG_CAP] = sizeof(struct opcap_list_item),
};

static struct xml_parse_spec ejudge_config_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = elem_sizes,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = NULL,
  .attr_free = NULL,
};

static struct xml_tree *
parse_user_map(char const *path, struct xml_tree *p)
{
  struct xml_tree *q;
  struct xml_attr *a;
  struct ejudge_cfg_user_map *m;

  ASSERT(p);
  ASSERT(p->tag == TG_USER_MAP);
  xfree(p->text); p->text = 0;
  if (p->first) {
    xml_err_attrs(p);
    return 0;
  }
  for (q = p->first_down; q; q = q->right) {
    if (q->tag != TG_MAP) {
      xml_err_elem_not_allowed(q);
      return 0;
    }
    if (xml_empty_text(q)) return 0;
    if (q->first_down) {
      xml_err_nested_elems(q);
      return 0;
    }
    m = (struct ejudge_cfg_user_map*) q;
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
      case AT_EJUDGE_USER:
        m->local_user_str = a->text; a->text = 0;
        break;
      default:
        xml_err_attr_not_allowed(q, a);
        return 0;
      }
    }
  }
  return p;
}

static int
parse_capabilities(unsigned char const *path,
                   struct ejudge_cfg *cfg,
                   struct xml_tree *ct)
{
  struct xml_tree *p;
  struct opcap_list_item *pp;

  ASSERT(ct->tag == TG_CAPS);

  if (cfg->capabilities.first) return xml_err_elem_redefined(ct);

  xfree(ct->text); ct->text = 0;
  if (ct->first) return xml_err_attrs(ct);
  p = ct->first_down;
  if (!p) return 0;
  cfg->capabilities.first = (struct opcap_list_item*) p;

  for (; p; p = p->right) {
    if (p->tag != TG_CAP) return xml_err_elem_not_allowed(p);
    pp = (struct opcap_list_item*) p;

    if (!p->first) return xml_err_elem_invalid(p);
    if (p->first->next) return xml_err_elem_invalid(p);
    if (p->first->tag != AT_LOGIN)
      return xml_err_attr_not_allowed(p, p->first);
    pp->login = p->first->text;
    //if (xml_empty_text(p) < 0) return -1;
    if (opcaps_parse(p->text, &pp->caps) < 0) {
      xml_err(p, "invalid capabilities");
      return -1;
    }
  }
  return 0;
}

#define CONFIG_OFFSET(f) XOFFSET(struct ejudge_cfg, f)

static const size_t cfg_final_offsets[TG_LAST_TAG] =
{
  [TG_USERDB_FILE] = CONFIG_OFFSET(db_path),
  [TG_SOCKET_PATH] = CONFIG_OFFSET(socket_path),
  [TG_CONTESTS_DIR] = CONFIG_OFFSET(contests_dir),
  [TG_EMAIL_PROGRAM] = CONFIG_OFFSET(email_program),
  [TG_REGISTER_URL] = CONFIG_OFFSET(register_url),
  [TG_REGISTER_EMAIL] = CONFIG_OFFSET(register_email),
  [TG_SERVER_NAME] = CONFIG_OFFSET(server_name),
  [TG_SERVER_NAME_EN] = CONFIG_OFFSET(server_name_en),
  [TG_SERVER_MAIN_URL] = CONFIG_OFFSET(server_main_url),
  [TG_SERVE_PATH] = CONFIG_OFFSET(serve_path),
  [TG_L10N_DIR] = CONFIG_OFFSET(l10n_dir),
  [TG_RUN_PATH] = CONFIG_OFFSET(run_path),
  [TG_CHARSET] = CONFIG_OFFSET(charset),
  [TG_CONFIG_DIR] = CONFIG_OFFSET(config_dir),
  [TG_CONTESTS_HOME_DIR] = CONFIG_OFFSET(contests_home_dir),
  [TG_FULL_CGI_DATA_DIR] = CONFIG_OFFSET(full_cgi_data_dir),
  [TG_COMPILE_HOME_DIR] = CONFIG_OFFSET(compile_home_dir),
  [TG_TESTING_WORK_DIR] = CONFIG_OFFSET(testing_work_dir),
  [TG_SCRIPT_DIR] = CONFIG_OFFSET(script_dir),
  [TG_ADMIN_EMAIL] = CONFIG_OFFSET(admin_email),
  [TG_USERLIST_LOG] = CONFIG_OFFSET(userlist_log),
  [TG_VAR_DIR] = CONFIG_OFFSET(var_dir),
  [TG_SUPER_SERVE_LOG] = CONFIG_OFFSET(super_serve_log),
  [TG_COMPILE_LOG] = CONFIG_OFFSET(compile_log),
  [TG_SUPER_SERVE_SOCKET] = CONFIG_OFFSET(super_serve_socket),
  [TG_SUPER_SERVE_USER] = CONFIG_OFFSET(super_serve_user),
  [TG_SUPER_SERVE_GROUP] = CONFIG_OFFSET(super_serve_group),
  [TG_USERLIST_USER] = CONFIG_OFFSET(userlist_user),
  [TG_USERLIST_GROUP] = CONFIG_OFFSET(userlist_group),
  [TG_JOB_SERVER_LOG] = CONFIG_OFFSET(job_server_log),
  [TG_JOB_SERVER_SPOOL] = CONFIG_OFFSET(job_server_spool),
  [TG_JOB_SERVER_WORK] = CONFIG_OFFSET(job_server_work),
};

struct ejudge_cfg *
ejudge_cfg_parse(char const *path)
{
  struct xml_tree *tree = 0, *p;
  struct ejudge_cfg *cfg = 0;
  struct xml_attr *a;
  unsigned char pathbuf[PATH_MAX];
  unsigned char **p_str;

  xml_err_path = path;
  xml_err_elem_names = elem_map;
  xml_err_attr_names = attr_map;

  tree = xml_build_tree(path, &ejudge_config_parse_spec);
  if (!tree) return 0;
  if (tree->tag != TG_CONFIG) {
    xml_err_top_level(tree, TG_CONFIG);
    goto failed;
  }
  cfg = (struct ejudge_cfg *) tree;
  xfree(cfg->b.text); cfg->b.text = 0;
  cfg->l10n = -1;

  for (a = cfg->b.first; a; a = a->next) {
    switch (a->tag) {
    case AT_ENABLE_L10N:
    case AT_DISABLE_L10N:
    case AT_L10N:
      if (xml_attr_bool(a, &cfg->l10n) < 0) goto failed;
      if (a->tag == AT_DISABLE_L10N) cfg->l10n = !cfg->l10n;
      break;
    default:
      xml_err_attr_not_allowed(&cfg->b, a);
      goto failed;
    }
  }

  for (p = cfg->b.first_down; p; p = p->right) {
    if (cfg_final_offsets[p->tag] > 0) {
      p_str = XPDEREF(unsigned char *, cfg, cfg_final_offsets[p->tag]);
      if (xml_leaf_elem(p, p_str, 1, 0) < 0) goto failed;
      continue;
    }
    switch (p->tag) {
    case TG_USER_MAP:
      if (!(cfg->user_map = parse_user_map(path, p))) goto failed;
      break;
    case TG_CAPS:
      if (parse_capabilities(path, cfg, p) < 0) goto failed;
      break;
    case TG_SERIALIZATION_KEY:
      {
        int k, n;

        if (cfg->serialization_key) {
          xml_err_elem_redefined(p);
          goto failed;
        }
        if (!p->text || !p->text[0]
            || sscanf(p->text, "%d%n", &k, &n) != 1 || p->text[n]
            || k <= 0 || k >= 32768) {
          xml_err_elem_invalid(p);
          goto failed;
        }
        cfg->serialization_key = k;
      }
      break;
    default:
      xml_err_elem_not_allowed(p);
      break;
    }
  }

#if CONF_HAS_LIBINTL - 0 == 1
  if (cfg->l10n < 0) cfg->l10n = 1;
  if (cfg->l10n && (!cfg->l10n_dir || !*cfg->l10n_dir)) {
    cfg->l10n_dir = xstrdup(EJUDGE_LOCALE_DIR);
  }
#else
  cfg->l10n = 0;
#endif

  if (!cfg->db_path) {
    xml_err_elem_undefined(&cfg->b, TG_USERDB_FILE);
    goto failed;
  }
#if defined EJUDGE_SOCKET_PATH
  if (!cfg->socket_path) {
    cfg->socket_path = xstrdup(EJUDGE_SOCKET_PATH);
  }
#endif /* EJUDGE_SOCKET_PATH */
  if (!cfg->socket_path) {
    xml_err_elem_undefined(&cfg->b, TG_SOCKET_PATH);
    goto failed;
  }
#if defined EJUDGE_SUPER_SERVE_SOCKET
  if (!cfg->super_serve_socket) {
    cfg->super_serve_socket = xstrdup(EJUDGE_SUPER_SERVE_SOCKET);
  }
#endif /* EJUDGE_SUPER_SERVE_SOCKET */
#if defined EJUDGE_CONTESTS_DIR
  if (!cfg->contests_dir) {
    cfg->contests_dir = xstrdup(EJUDGE_CONTESTS_DIR);
  }
#endif /* EJUDGE_CONTESTS_DIR */
  if (!cfg->contests_dir) {
    xml_err_elem_undefined(&cfg->b, TG_CONTESTS_DIR);
    goto failed;
  }
  if (!cfg->email_program) {
    xml_err_elem_undefined(&cfg->b, TG_EMAIL_PROGRAM);
    goto failed;
  }
  if (!cfg->register_url) {
    xml_err_elem_undefined(&cfg->b, TG_REGISTER_URL);
    goto failed;
  }
  if (!cfg->register_email) {
    xml_err_elem_undefined(&cfg->b, TG_REGISTER_EMAIL);
    goto failed;
  }

  if (cfg->var_dir && cfg->userlist_log
      && !os_IsAbsolutePath(cfg->userlist_log)) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
             cfg->var_dir, cfg->userlist_log);
    xfree(cfg->userlist_log);
    cfg->userlist_log = xstrdup(pathbuf);
  }
  if (cfg->var_dir && cfg->super_serve_log
      && !os_IsAbsolutePath(cfg->super_serve_log)) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
             cfg->var_dir, cfg->super_serve_log);
    xfree(cfg->super_serve_log);
    cfg->super_serve_log = xstrdup(pathbuf);
  }
  if (cfg->var_dir && cfg->compile_log
      && !os_IsAbsolutePath(cfg->compile_log)) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
             cfg->var_dir, cfg->compile_log);
    xfree(cfg->compile_log);
    cfg->compile_log = xstrdup(pathbuf);
  }

#if defined EJUDGE_SERVE_PATH
  if (!cfg->serve_path) {
    cfg->serve_path = xstrdup(EJUDGE_SERVE_PATH);
  }
#endif /* EJUDGE_SERVE_PATH */

#if defined EJUDGE_RUN_PATH
  if (!cfg->run_path) {
    cfg->run_path = xstrdup(EJUDGE_RUN_PATH);
  }
#endif /* EJUDGE_RUN_PATH */

  //ejudge_cfg_unparse(cfg, stdout);
  return cfg;

 failed:
  if (tree) ejudge_cfg_free((struct ejudge_cfg *) tree);
  return 0;
}

struct ejudge_cfg *
ejudge_cfg_free(struct ejudge_cfg *cfg)
{
  xml_tree_free((struct xml_tree*) cfg, &ejudge_config_parse_spec);
  return 0;
}

static void
fmt_func(FILE *o, struct xml_tree const *p, int s, int n)
{
  switch (p->tag) {
  case TG_CONFIG:
    if (s == 1 || s == 3) fprintf(o, "\n");
    break;
  case TG_USERDB_FILE:
  case TG_SOCKET_PATH:
  case TG_CONTESTS_DIR:
    if (s == 3) fprintf(o, "\n");
    if (s == 0) fprintf(o, "  ");
    break;
  default:
    SWERR(("unhandled tag %d", p->tag));
  }
}

void
ejudge_cfg_unparse(struct ejudge_cfg *cfg, FILE *f)
{
  if (!cfg) return;

  xml_unparse_tree(stdout, (struct xml_tree*) cfg, elem_map, 0, 0, 0,
                   fmt_func);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 * End:
 */
