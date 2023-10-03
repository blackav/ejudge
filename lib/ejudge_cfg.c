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

#ifdef __MINGW32__
#undef HAVE_PWD_H
#endif

#include "ejudge/ejudge_cfg.h"
#include "ejudge/expat_iface.h"
#include "ejudge/errlog.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#if HAVE_PWD_H
#include <pwd.h>
#endif

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

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
    TG_PLUGIN_DIR,
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
    TG_PLUGINS,
    TG_PLUGIN,
    TG_PATH,
    TG_COMPILE_SERVERS,
    TG_NEW_SERVER_SOCKET,
    TG_NEW_SERVER_LOG,
    TG_DEFAULT_CLARDB_PLUGIN,
    TG_DEFAULT_RUNDB_PLUGIN,
    TG_DEFAULT_XUSER_PLUGIN,
    TG_DEFAULT_AVATAR_PLUGIN,
    TG_DEFAULT_VARIANT_PLUGIN,
    TG_DEFAULT_CONTENT_PLUGIN,
    TG_DEFAULT_CONTENT_URL_PREFIX,
    TG_HOSTS_OPTIONS,
    TG_CAPS_FILE,
    TG_BUTTONS,
    TG_BUTTON,
    TG_LABEL,
    TG_VALUE,
    TG_SCRIPT,
    TG_PAGE,
    TG_CONTESTS_WS_PORT,
    TG_MAX_LOADED_CONTESTS,
    TG_DEFAULT_STATUS_PLUGIN,
    TG_OAUTH_USER_MAP,
    TG_OAUTH_ENTRY,
    TG_COMPILER_OPTIONS,
    TG_COMPILER_OPTION,

    TG__BARRIER,
    TG__DEFAULT,

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
    AT_NAME,
    AT_TYPE,
    AT_LOAD,
    AT_DEFAULT,
    AT_DISABLE_COOKIE_IP_CHECK,
    AT_ENABLE_COOKIE_IP_CHECK,
    AT_ENABLE_CONTEST_SELECT,
    AT_DISABLE_NEW_USERS,
    AT_FORCE_CONTAINER,
    AT_OAUTH_USER,
    AT_PROVIDER,
    AT_ENABLE_OAUTH,
    AT_ENABLE_COMPILE_CONTAINER,
    AT_COMPILER,
    AT_OPTION,
    AT_DISABLE_AUTOUPDATE_STANDINDGS,
    AT_ENABLE_TELEGRAM_REGISTRATION,

    AT__BARRIER,
    AT__DEFAULT,

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
  "plugin_dir",
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
  "plugins",
  "plugin",
  "path",
  "compile_servers",
  "new_server_socket",
  "new_server_log",
  "default_clardb_plugin",
  "default_rundb_plugin",
  "default_xuser_plugin",
  "default_avatar_plugin",
  "default_variant_plugin",
  "default_content_plugin",
  "default_content_url_prefix",
  "hosts_options",
  "caps_file",
  "buttons",
  "button",
  "label",
  "value",
  "script",
  "page",
  "contests_ws_port",
  "max_loaded_contests",
  "default_status_plugin",
  "oauth_user_map",
  "oauth_entry",
  "compiler_options",
  "compiler_option",
  0,
  "_default",

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
  "name",
  "type",
  "load",
  "default",
  "disable_cookie_ip_check",
  "enable_cookie_ip_check",
  "enable_contest_select",
  "disable_new_users",
  "force_container",
  "oauth_user",
  "provider",
  "enable_oauth",
  "enable_compile_container",
  "compiler",
  "option",
  "disable_autoupdate_standings",
  "enable_telegram_registration",
  0,
  "_default",

  0
};

static size_t elem_sizes[TG_LAST_TAG] =
{
  [TG_CONFIG] = sizeof(struct ejudge_cfg),
  [TG_MAP] = sizeof(struct ejudge_cfg_user_map),
  [TG_CAP] = sizeof(struct opcap_list_item),
  [TG_PLUGIN] = sizeof(struct ejudge_plugin),
  [TG_OAUTH_ENTRY] = sizeof(struct ejudge_cfg_oauth_user_map),
};

static const unsigned char verbatim_flags[TG_LAST_TAG] =
{
  [TG_PLUGIN] = 1,
  [TG_HOSTS_OPTIONS] = 1,
};

static struct xml_tree *
new_node(int tag)
{
  struct xml_tree *p = xml_elem_alloc(tag, elem_sizes);
  p->tag = tag;
  return p;
}

static void
node_free(struct xml_tree *t)
{
  switch (t->tag) {
  case TG_CONFIG:
    {
      struct ejudge_cfg *p = (struct ejudge_cfg*) t;
      xfree(p->socket_path);
      xfree(p->db_path);
      xfree(p->contests_dir);
      xfree(p->email_program);
      xfree(p->register_url);
      xfree(p->register_email);
      xfree(p->server_name);
      xfree(p->server_name_en);
      xfree(p->server_main_url);
      xfree(p->admin_email);
      xfree(p->l10n_dir);
      xfree(p->run_path);
      xfree(p->charset);
      xfree(p->config_dir);
      xfree(p->contests_home_dir);
      xfree(p->full_cgi_data_dir);
      xfree(p->compile_home_dir);
      xfree(p->testing_work_dir);
      xfree(p->script_dir);
      xfree(p->plugin_dir);
      xfree(p->var_dir);
      xfree(p->userlist_log);
      xfree(p->super_serve_log);
      xfree(p->job_server_log);
      xfree(p->compile_log);
      xfree(p->super_serve_socket);
      xfree(p->super_serve_user);
      xfree(p->super_serve_group);
      xfree(p->userlist_user);
      xfree(p->userlist_group);
      xfree(p->job_server_spool);
      xfree(p->job_server_work);
      xfree(p->new_server_socket);
      xfree(p->new_server_log);
      xfree(p->default_clardb_plugin);
      xfree(p->default_rundb_plugin);
      xfree(p->default_xuser_plugin);
      xfree(p->default_avatar_plugin);
      xfree(p->default_variant_plugin);
      xfree(p->default_content_plugin);
      xfree(p->default_content_url_prefix);
      xfree(p->default_status_plugin);
      xfree(p->caps_file);
    }
    break;
  case TG_MAP:
    {
      struct ejudge_cfg_user_map *p = (struct ejudge_cfg_user_map *) t;
      xfree(p->system_user_str);
      xfree(p->local_user_str);
    }
    break;
  case TG_CAP:
    {
      struct opcap_list_item *p = (struct opcap_list_item*) t;
      xfree(p->login);
    }
    break;
  case TG_PLUGIN:
    {
      struct ejudge_plugin *p = (struct ejudge_plugin *) t;
      xfree(p->name);
      xfree(p->type);
      xfree(p->path);
    }
    break;
  case TG_OAUTH_ENTRY:
    {
      struct ejudge_cfg_oauth_user_map *p = (struct ejudge_cfg_oauth_user_map *) t;
      xfree(p->oauth_user_str);
      xfree(p->local_user_str);
      xfree(p->provider);
    }
    break;
  }
}

static struct xml_parse_spec ejudge_config_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = elem_sizes,
  .attr_sizes = NULL,
  .default_elem = TG__DEFAULT,
  .default_attr = AT__DEFAULT,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = node_free,
  .attr_free = NULL,
  .verbatim_flags = verbatim_flags,
};

const char *
ejudge_cfg_get_elem_name(int tag)
{
  if (tag <= 0 || tag >= TG__BARRIER) return "";
  return elem_map[tag];
}

const struct xml_parse_spec *
ejudge_cfg_get_spec(void)
{
  return &ejudge_config_parse_spec;
}

static struct xml_tree *
parse_user_map(char const *path, struct xml_tree *p, int no_system_lookup)
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
#if HAVE_PWD_H
        if (!no_system_lookup) {
          struct passwd *pwd;

          if (!(pwd = getpwnam(a->text))) {
            err("%s:%d:%d: user %s does not exist", path, a->line, a->column,
                a->text);
            return 0;
          }
          m->system_uid = pwd->pw_uid;
          //info("user %s uid is %d", a->text, pwd->pw_uid);
        }
#endif
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

static struct xml_tree *
parse_oauth_user_map(char const *path, struct xml_tree *p)
{
  ASSERT(p);
  ASSERT(p->tag == TG_OAUTH_USER_MAP);
  xfree(p->text); p->text = 0;

  for (struct xml_tree *q = p->first_down; q; q = q->right) {
    if (q->tag != TG_OAUTH_ENTRY) {
      xml_err_elem_not_allowed(q);
      return 0;
    }
    if (xml_empty_text(q)) return 0;
    if (q->first_down) {
      xml_err_nested_elems(q);
      return 0;
    }
    struct ejudge_cfg_oauth_user_map *m = (struct ejudge_cfg_oauth_user_map *) q;
    for (struct xml_attr *a = q->first; a; a = a->next) {
      switch (a->tag) {
      case AT_OAUTH_USER:
        m->oauth_user_str = a->text; a->text = NULL;
        break;
      case AT_LOCAL_USER:
      case AT_EJUDGE_USER:
        xfree(m->local_user_str); m->local_user_str = a->text; a->text = NULL;
        break;
      case AT_PROVIDER:
        m->provider = a->text; a->text = NULL;
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
parse_capabilities(struct ejudge_cfg *cfg, struct xml_tree *ct)
{
  struct xml_tree *p;
  struct opcap_list_item *pp;

  ASSERT(ct->tag == TG_CAPS);

  if (cfg->capabilities.first) return xml_err_elem_redefined(ct);

  cfg->caps_node = ct;
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
    pp->login = p->first->text; p->first->text = NULL;
    //if (xml_empty_text(p) < 0) return -1;
    if (opcaps_parse(p->text, &pp->caps) < 0) {
      xml_err(p, "invalid capabilities");
      return -1;
    }
  }
  return 0;
}

static int
parse_plugins(struct ejudge_cfg *cfg, struct xml_tree *tree)
{
  struct xml_tree *p, *q;
  struct ejudge_plugin *plg;
  struct xml_attr *a;

  if (!tree) return 0;
  if (tree->tag != TG_PLUGINS) return xml_err_elem_not_allowed(tree);
  if (xml_empty_text(tree) < 0) return -1;
  if (tree->first) return xml_err_attrs(tree);

  for (p = tree->first_down; p; p = p->right) {
    if (p->tag != TG_PLUGIN) return xml_err_elem_not_allowed(p);
    if (xml_empty_text(p) < 0) return -1;
    plg = (struct ejudge_plugin*) p;

    for (a = p->first; a; a = a->next) {
      switch (a->tag) {
      case AT_NAME:
        plg->name = a->text;
        a->text = 0;
        break;
      case AT_TYPE:
        plg->type = a->text;
        a->text = 0;
        break;
      case AT_LOAD:
        if (xml_attr_bool(a, &plg->load_flag) < 0) return -1;
        break;
      case AT_DEFAULT:
        if (xml_attr_bool(a, &plg->default_flag) < 0) return -1;
        break;
      default:
        return xml_err_attr_not_allowed(p, a);
      }
    }
    xml_tree_free_attrs(p, &ejudge_config_parse_spec);
    if (!plg->name) return xml_err_attr_undefined(p, AT_NAME);
    if (!plg->type) return xml_err_attr_undefined(p, AT_TYPE);

    for (q = p->first_down; q; q = q->right) {
      ASSERT(q->tag == TG__DEFAULT);
      if (!strcmp(q->name[0], "config")) {
        if (plg->data) return xml_err_elem_redefined(q);
        plg->data = q;
      } else if (!strcmp(q->name[0], "path")) {
        if (xml_leaf_elem(q, &plg->path, 1, 0) < 0) return -1;
      } else {
        return xml_err_elem_not_allowed(q);
      }
    }

    if (!plg->data) return xml_err_elem_undefined(p, TG_CONFIG);
  }
  cfg->plugin_list = tree->first_down;

  return 0;
}

static int
parse_compile_servers(struct ejudge_cfg *cfg, struct xml_tree *tree)
{
  struct xml_tree *p;

  if (!tree) return 0;
  if (tree->tag != TG_COMPILE_SERVERS) return xml_err_elem_not_allowed(tree);
  if (xml_empty_text(tree) < 0) return -1;
  if (tree->first) return xml_err_attrs(tree);

  for (p = tree->first_down; p; p = p->right) {
    if (p->tag != TG_PATH) return xml_err_elem_not_allowed(p);
    if (p->first) return xml_err_attrs(tree);
    if (p->first_down) return xml_err_nested_elems(p);
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
  //[TG_SERVE_PATH] = CONFIG_OFFSET(serve_path),
  [TG_L10N_DIR] = CONFIG_OFFSET(l10n_dir),
  [TG_RUN_PATH] = CONFIG_OFFSET(run_path),
  [TG_CHARSET] = CONFIG_OFFSET(charset),
  [TG_CONFIG_DIR] = CONFIG_OFFSET(config_dir),
  [TG_CONTESTS_HOME_DIR] = CONFIG_OFFSET(contests_home_dir),
  [TG_FULL_CGI_DATA_DIR] = CONFIG_OFFSET(full_cgi_data_dir),
  [TG_COMPILE_HOME_DIR] = CONFIG_OFFSET(compile_home_dir),
  [TG_TESTING_WORK_DIR] = CONFIG_OFFSET(testing_work_dir),
  [TG_SCRIPT_DIR] = CONFIG_OFFSET(script_dir),
  [TG_PLUGIN_DIR] = CONFIG_OFFSET(plugin_dir),
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
  [TG_NEW_SERVER_SOCKET] = CONFIG_OFFSET(new_server_socket),
  [TG_NEW_SERVER_LOG] = CONFIG_OFFSET(new_server_log),
  [TG_DEFAULT_CLARDB_PLUGIN] = CONFIG_OFFSET(default_clardb_plugin),
  [TG_DEFAULT_RUNDB_PLUGIN] = CONFIG_OFFSET(default_rundb_plugin),
  [TG_DEFAULT_XUSER_PLUGIN] = CONFIG_OFFSET(default_xuser_plugin),
  [TG_DEFAULT_AVATAR_PLUGIN] = CONFIG_OFFSET(default_avatar_plugin),
  [TG_DEFAULT_VARIANT_PLUGIN] = CONFIG_OFFSET(default_variant_plugin),
  [TG_DEFAULT_CONTENT_PLUGIN] = CONFIG_OFFSET(default_content_plugin),
  [TG_DEFAULT_CONTENT_URL_PREFIX] = CONFIG_OFFSET(default_content_url_prefix),
  [TG_DEFAULT_STATUS_PLUGIN] = CONFIG_OFFSET(default_status_plugin),
  [TG_CAPS_FILE] = CONFIG_OFFSET(caps_file),
};

static struct ejudge_cfg *
ejudge_cfg_do_parse(char const *path, FILE *in_file, int no_system_lookup)
{
  struct xml_tree *tree = 0, *p;
  struct ejudge_cfg *cfg = 0;
  struct xml_attr *a;
  unsigned char **p_str;

  xml_err_path = path;
  xml_err_spec = &ejudge_config_parse_spec;

  if (in_file) {
    tree = xml_build_tree_file(NULL, in_file, &ejudge_config_parse_spec);
    // in_file is closed in the function, so reset the pointer
    in_file = NULL;
  } else {
    tree = xml_build_tree(NULL, path, &ejudge_config_parse_spec);
  }
  if (!tree) return 0;
  if (tree->tag != TG_CONFIG) {
    xml_err_top_level(tree, TG_CONFIG);
    goto failed;
  }
  cfg = (struct ejudge_cfg *) tree;
  xfree(cfg->b.text); cfg->b.text = 0;
  cfg->l10n = -1;

  cfg->ejudge_xml_path = xstrdup(path);

  for (a = cfg->b.first; a; a = a->next) {
    switch (a->tag) {
    case AT_ENABLE_L10N:
    case AT_DISABLE_L10N:
    case AT_L10N:
      if (xml_attr_bool(a, &cfg->l10n) < 0) goto failed;
      if (a->tag == AT_DISABLE_L10N) cfg->l10n = !cfg->l10n;
      break;
    case AT_DISABLE_COOKIE_IP_CHECK:
      if (xml_attr_bool(a, &cfg->disable_cookie_ip_check) < 0) goto failed;
      break;
    case AT_ENABLE_COOKIE_IP_CHECK:
      if (xml_attr_bool(a, &cfg->enable_cookie_ip_check) < 0) goto failed;
      break;
    case AT_ENABLE_CONTEST_SELECT:
      if (xml_attr_bool(a, &cfg->enable_contest_select) < 0) goto failed;
      break;
    case AT_DISABLE_NEW_USERS:
      if (xml_attr_bool(a, &cfg->disable_new_users) < 0) goto failed;
      break;
    case AT_FORCE_CONTAINER:
      if (xml_attr_bool(a, &cfg->force_container) < 0) goto failed;
      break;
    case AT_ENABLE_OAUTH:
      if (xml_attr_bool(a, &cfg->enable_oauth) < 0) goto failed;
      break;
    case AT_ENABLE_COMPILE_CONTAINER:
      if (xml_attr_bool(a, &cfg->enable_compile_container) < 0) goto failed;
      break;
    case AT_DISABLE_AUTOUPDATE_STANDINDGS:
      if (xml_attr_bool(a, &cfg->disable_autoupdate_standings) < 0) goto failed;
      break;
    case AT_ENABLE_TELEGRAM_REGISTRATION:
      if (xml_attr_bool(a, &cfg->enable_telegram_registration) < 0) goto failed;
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
      if (!(cfg->user_map = parse_user_map(path, p, 0))) goto failed;
      break;
    case TG_OAUTH_USER_MAP:
      if (!(cfg->oauth_user_map = parse_oauth_user_map(path, p))) goto failed;
      break;
    case TG_CAPS:
      if (parse_capabilities(cfg, p) < 0) goto failed;
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
    case TG_PLUGINS:
      if (parse_plugins(cfg, p) < 0) goto failed;
      break;
    case TG_COMPILE_SERVERS:
      if (parse_compile_servers(cfg, p) < 0) goto failed;
      break;
    case TG_SERVE_PATH:
      break;
    case TG_HOSTS_OPTIONS:
      cfg->hosts_options = p;
      break;
    case TG_BUTTONS:
      cfg->buttons = p;
      break;
    case TG_COMPILER_OPTIONS:
      cfg->compiler_options = p;
      break;
    case TG_CONTESTS_WS_PORT:
      {
        if (cfg->contests_ws_port > 0) {
          xml_err_elem_redefined(p);
          goto failed;
        }
        if (p->text && p->text[0]) {
          errno = 0;
          char *eptr = NULL;
          long k = strtol(p->text, &eptr, 10);
          if (errno || *eptr || eptr == p->text || k <= 0 || k > 65535) {
            xml_err_elem_invalid(p);
            goto failed;
          }
          cfg->contests_ws_port = k;
        }
      }
      break;
    case TG_MAX_LOADED_CONTESTS:
      {
        if (cfg->max_loaded_contests > 0) {
          xml_err_elem_redefined(p);
          goto failed;
        }
        if (p->text && p->text[0]) {
          errno = 0;
          char *eptr = NULL;
          long k = strtol(p->text, &eptr, 10);
          if (errno || *eptr || eptr == p->text || k < 0 || k > 10000) {
            xml_err_elem_invalid(p);
            goto failed;
          }
          cfg->max_loaded_contests = k;
        }
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
  return cfg;

 failed:
  if (tree) ejudge_cfg_free((struct ejudge_cfg *) tree);
  return 0;
}

static struct ejudge_cfg *
ejudge_cfg_parse_2(char const *path, FILE *in_file, int no_system_lookup)
{
  struct ejudge_cfg *cfg = 0;
  unsigned char pathbuf[PATH_MAX];

  cfg = ejudge_cfg_do_parse(path, in_file, no_system_lookup);
  if (!cfg) return NULL;

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

#if defined EJUDGE_RUN_PATH
  xfree(cfg->run_path);
  cfg->run_path = xstrdup(EJUDGE_RUN_PATH);
#endif /* EJUDGE_RUN_PATH */

  if (!cfg->plugin_dir && cfg->script_dir) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/plugins", cfg->script_dir);
    cfg->plugin_dir = xstrdup(pathbuf);
  }
#if defined EJUDGE_SCRIPT_DIR
  if (!cfg->plugin_dir) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/plugins", EJUDGE_SCRIPT_DIR);
    cfg->plugin_dir = xstrdup(pathbuf);
  }
#endif /* EJUDGE_SCRIPT_DIR */

  if (!cfg->contest_server_id || !*cfg->contest_server_id) {
    xfree(cfg->contest_server_id); cfg->contest_server_id = NULL;
    const unsigned char *s = getenv("EJ_CONTEST_SERVER_ID");
    if (s && *s) {
      cfg->contest_server_id = xstrdup(s);
    }
  }
  if (!cfg->contest_server_id || !*cfg->contest_server_id) {
    xfree(cfg->contest_server_id); cfg->contest_server_id = NULL;
    cfg->contest_server_id = xstrdup(os_NodeName());
  }
  if (!cfg->contest_server_id || !*cfg->contest_server_id) {
    xfree(cfg->contest_server_id); cfg->contest_server_id = NULL;
    cfg->contest_server_id = "localhost";
  }

  if (path) {
    cfg->caps_file_info = ejudge_cfg_create_caps_file(path);
  }

  //ejudge_cfg_unparse(cfg, stdout);
  return cfg;

 failed:
  if (cfg) ejudge_cfg_free(cfg);
  return 0;
}

struct ejudge_cfg *
ejudge_cfg_parse(char const *path, int no_system_lookup)
{
  return ejudge_cfg_parse_2(path, NULL, no_system_lookup);
}

struct ejudge_cfg *
ejudge_cfg_parse_file(const char *path, FILE *in_file, int no_system_lookup)
{
  return ejudge_cfg_parse_2(path, in_file, no_system_lookup);
}

struct ejudge_cfg *
ejudge_cfg_free(struct ejudge_cfg *cfg)
{
  if (!cfg) return NULL;
  ejudge_cfg_free_caps_file(cfg->caps_file_info);
  xfree(cfg->ejudge_xml_path);
  xml_tree_free((struct xml_tree*) cfg, &ejudge_config_parse_spec);
  return 0;
}

struct xml_tree *
ejudge_cfg_free_subtree(struct xml_tree *p)
{
  if (p) {
    xml_tree_free((struct xml_tree*) p, &ejudge_config_parse_spec);
  }
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

static void
unparse_default_tree(struct xml_tree *t, FILE *f, int offset)
{
  struct xml_tree *p;
  struct xml_attr *a;
  unsigned char *ostr;
  const unsigned char *s;

  if (!t) return;
  ASSERT(t->tag == TG__DEFAULT);

  ostr = alloca(offset + 1);
  memset(ostr, ' ', offset);
  ostr[offset] = 0;

  if ((s = t->text)) {
    for (; *s; s++)
      if (!isspace(*s))
        break;
    if (!*s) {
      xfree(t->text);
      t->text = 0;
    }
  }

  fprintf(f, "%s<%s", ostr, t->name[0]);
  for (a = t->first; a; a = a->next) {
    ASSERT(a->tag == AT__DEFAULT);
    // FIXME: do XML armoring
    fprintf(f, " %s=\"%s\"", a->name[0], a->text);
  }
  if (t->first_down) {
    fprintf(f, ">\n");
    for (p = t->first_down; p; p = p->right) {
      unparse_default_tree(p, f, offset + 2);
    }
    fprintf(f, "%s</%s>\n", ostr, t->name[0]);
  } else if (t->text) {
    fprintf(f, ">%s</%s>\n", t->text, t->name[0]);
  } else {
    fprintf(f, "/>\n");
  }
}

void
ejudge_cfg_unparse_plugins(struct ejudge_cfg *cfg, FILE *f)
{
  struct xml_tree *p;
  struct ejudge_plugin *plg;

  if (!cfg || !cfg->plugin_list) return;
  fprintf(f, "<%s>\n", elem_map[TG_PLUGINS]);
  for (p = cfg->plugin_list; p; p = p->right) {
    plg = (struct ejudge_plugin*) p;
    fprintf(f, "  <%s %s=\"%s\" %s=\"%s\"",
            elem_map[TG_PLUGIN],
            attr_map[AT_TYPE], plg->type,
            attr_map[AT_NAME], plg->name);
    if (plg->load_flag) {
      fprintf(f, " %s=\"%s\"",
              attr_map[AT_LOAD], xml_unparse_bool(plg->load_flag));
    }
    if (plg->default_flag) {
      fprintf(f, " %s=\"%s\"",
              attr_map[AT_DEFAULT], xml_unparse_bool(plg->default_flag));
    }
    fprintf(f, ">\n");
    unparse_default_tree(plg->data, f, 4);
    fprintf(f, "  </%s>\n", elem_map[TG_PLUGIN]);
  }
  fprintf(f, "</%s>\n", elem_map[TG_PLUGINS]);
}

struct xml_tree *
ejudge_cfg_get_plugin_config(
        const struct ejudge_cfg *cfg,
        const unsigned char *type,
        const unsigned char *name)
{
  struct xml_tree *p;
  struct ejudge_plugin *plg;

  if (!cfg || !cfg->plugin_list) return NULL;

  for (p = cfg->plugin_list; p; p = p->right) {
    plg = (struct ejudge_plugin*) p;
    if (!strcmp(type, plg->type) && !strcmp(name, plg->name))
      return plg->data;
  }
  return NULL;
}

static struct xml_attr *
get_attr_by_name(struct xml_tree *p, const unsigned char *name)
{
  struct xml_attr *a;
  if (!p) return NULL;
  for (a = p->first; a; a = a->next) {
    if (a->tag != ejudge_config_parse_spec.default_attr) continue;
    if (!strcmp(a->name[0], name)) return a;
  }
  return NULL;
}

const unsigned char *
ejudge_cfg_get_host_option(
        const struct ejudge_cfg *cfg,
        unsigned char **host_names,
        const unsigned char *option_name)
{
  struct xml_tree *p, *q;
  struct xml_attr *a, *b;
  int  i;

  if (!cfg || !cfg->hosts_options) return NULL;
  for (p = cfg->hosts_options->first_down; p; p = p->right) {
    if (p->tag != ejudge_config_parse_spec.default_elem) continue;
    if (strcmp(p->name[0], "host") != 0) continue;
    if (!(a = get_attr_by_name(p, "name"))) continue;
    for (i = 0; host_names[i]; ++i) {
      if (!strcmp(host_names[i], a->text))
        break;
    }
    if (!host_names[i]) continue;
    for (q = p->first_down; q; q = q->right) {
      if (q->tag != ejudge_config_parse_spec.default_elem) continue;
      if (strcmp(q->name[0], "option") != 0) continue;
      if (!(a = get_attr_by_name(q, "name"))) continue;
      if (!(b = get_attr_by_name(q, "value"))) continue;
      if (!strcmp(a->text, option_name)) return b->text;
    }
  }

  return NULL;
}

int
ejudge_cfg_get_host_option_int(
        const struct ejudge_cfg *cfg,
        unsigned char **host_names,
        const unsigned char *option_name,
        int default_value,
        int error_value)
{
  const unsigned char *str = ejudge_cfg_get_host_option(cfg, host_names, option_name);
  int len;
  unsigned char *buf;
  long val;
  char *eptr = NULL;

  if (!str) return default_value;
  len = strlen(str);
  if (len > 1024) return error_value;
  buf = alloca(len + 1);
  strcpy(buf, str);
  while (len > 0 && isspace(buf[len - 1])) --len;
  buf[len] = 0;
  if (len <= 0) return default_value;

  errno = 0;
  val = strtol(buf, &eptr, 10);
  if (errno || *eptr) return error_value;
  return val;
}

struct ejudge_cfg_caps_file *
ejudge_cfg_create_caps_file(const unsigned char *base_path)
{
  struct ejudge_cfg_caps_file *info = NULL;
  XCALLOC(info, 1);
  if (base_path) info->base_path = xstrdup(base_path);
  return info;
}

struct ejudge_cfg_caps_file *
ejudge_cfg_free_caps_file(struct ejudge_cfg_caps_file *info)
{
  if (!info) return NULL;
  ejudge_cfg_free(info->root);
  xfree(info->path);
  xfree(info->base_path);
  memset(info, 0, sizeof(*info));
  xfree(info);
  return NULL;
}

enum { CAPS_FILE_CHECK_INTERVAL = 10 };

void
ejudge_cfg_refresh_caps_file(const struct ejudge_cfg *cfg, int force_flag)
{
  unsigned char path[PATH_MAX];
  unsigned char dirname[PATH_MAX];

  if (!cfg) return;
  struct ejudge_cfg_caps_file *inf = cfg->caps_file_info;
  if (!inf || inf->error_flag) return;

  if (!inf->path) {
    if (!cfg->caps_file) return;
    if (os_IsAbsolutePath(cfg->caps_file)) {
      snprintf(path, sizeof(path), "%s", cfg->caps_file);
    } else {
      if (!inf->base_path) {
        snprintf(path, sizeof(path), "%s/%s", EJUDGE_CONF_DIR, cfg->caps_file);
      } else if (!os_IsAbsolutePath(inf->base_path)) {
        err("%s: ejudge.xml configuration path %s is relative", __FUNCTION__, inf->base_path);
        inf->error_flag = 1;
        return;
      } else if (os_IsFile(inf->base_path) < 0) {
        err("%s: ejudge.xml configuration path %s does not exist", __FUNCTION__, inf->base_path);
        inf->error_flag = 1;
        return;
      } else if (os_IsFile(inf->base_path) == OSPK_DIR) {
        snprintf(path, sizeof(path), "%s/%s", inf->base_path, cfg->caps_file);
      } else if (os_IsFile(inf->base_path) == OSPK_REG) {
        os_rDirName(inf->base_path, dirname, sizeof(dirname));
        snprintf(path, sizeof(path), "%s/%s", dirname, cfg->caps_file);
      } else {
        err("%s: ejudge.xml configuration path %s is invalid", __FUNCTION__, inf->base_path);
        inf->error_flag = 1;
        return;
      }
    }
    inf->path = xstrdup(path);
  }

  time_t cur_time = time(NULL);
  if (inf->last_caps_file_check > 0 && cur_time < inf->last_caps_file_check + CAPS_FILE_CHECK_INTERVAL && !force_flag)
    return;
  inf->last_caps_file_check = cur_time;

  info("checking %s", inf->path);

  // FIXME: win32 compilation
  struct stat stbuf;
  if (stat(inf->path, &stbuf) < 0) {
    // remove the existing capabilities
    if (inf->root) {
      ejudge_cfg_free(inf->root);
      inf->root = NULL;
      inf->last_caps_file_mtime = 0;
    }
    return;
  }

  if (inf->last_caps_file_mtime > 0 && inf->last_caps_file_mtime == stbuf.st_mtime && !force_flag)
    return;
  inf->last_caps_file_mtime = stbuf.st_mtime;

  info("reloading %s", inf->path);

  struct ejudge_cfg *new_cfg = ejudge_cfg_do_parse(inf->path, NULL, 0);
  if (!new_cfg) {
    err("%s: %s parsing failed", __FUNCTION__, inf->path);
    return;
  }

  /*
  for (const struct opcap_list_item *p = new_cfg->capabilities.first; p; p = (const struct opcap_list_item*) p->b.right) {
    fprintf(stderr, "%s: %016llx\n", p->login, p->caps);
  }

  if (new_cfg->user_map) {
    for (const struct xml_tree *p = new_cfg->user_map->first_down; p; p = p->right) {
      const struct ejudge_cfg_user_map *m = (const struct ejudge_cfg_user_map*) p;
      fprintf(stderr, "%s -> %s\n", m->system_user_str, m->local_user_str);
    }
  }
  */

  ejudge_cfg_free(inf->root);
  inf->root = new_cfg;
  return;
}

int
ejudge_cfg_opcaps_find(
        const struct ejudge_cfg *cfg,
        const unsigned char *login_str,
        opcap_t *p_caps)
{
  int r;

  if (p_caps) *p_caps = 0;
  if (!login_str || !*login_str) return -1;
  r = opcaps_find(&cfg->capabilities, login_str, p_caps);
  if (r >= 0) return r;

  ejudge_cfg_refresh_caps_file(cfg, 0);
  if (!cfg->caps_file_info) return -1;
  if (!cfg->caps_file_info->root) return -1;
  return opcaps_find(&cfg->caps_file_info->root->capabilities, login_str, p_caps);
}

const unsigned char *
ejudge_cfg_user_map_find(
        const struct ejudge_cfg *cfg,
        const unsigned char *system_user_str)
{
  if (!system_user_str || !*system_user_str) return NULL;
  if (!cfg || !cfg->user_map) return NULL;
  for (const struct xml_tree *p = cfg->user_map->first_down; p; p = p->right) {
    const struct ejudge_cfg_user_map *m = (const struct ejudge_cfg_user_map*) p;
    if (m->system_user_str && !strcmp(system_user_str, m->system_user_str)) {
      return m->local_user_str;
    }
  }

  ejudge_cfg_refresh_caps_file(cfg, 0);
  if (!cfg->caps_file_info || !cfg->caps_file_info->root || !cfg->caps_file_info->root->user_map) return NULL;
  for (const struct xml_tree *p = cfg->caps_file_info->root->user_map->first_down; p; p = p->right) {
    const struct ejudge_cfg_user_map *m = (const struct ejudge_cfg_user_map*) p;
    if (m->system_user_str && !strcmp(system_user_str, m->system_user_str)) {
      return m->local_user_str;
    }
  }

  return NULL;
}

const unsigned char *
ejudge_cfg_user_map_find_uid(
        const struct ejudge_cfg *cfg,
        int system_user_id)
{
  if (system_user_id <= 0) return NULL;
  if (!cfg || !cfg->user_map) return NULL;
  for (const struct xml_tree *p = cfg->user_map->first_down; p; p = p->right) {
    const struct ejudge_cfg_user_map *m = (const struct ejudge_cfg_user_map*) p;
    if (m->system_uid == system_user_id) {
      return m->local_user_str;
    }
  }

  ejudge_cfg_refresh_caps_file(cfg, 0);
  if (!cfg->caps_file_info || !cfg->caps_file_info->root || !cfg->caps_file_info->root->user_map) return NULL;
  for (const struct xml_tree *p = cfg->caps_file_info->root->user_map->first_down; p; p = p->right) {
    const struct ejudge_cfg_user_map *m = (const struct ejudge_cfg_user_map*) p;
    if (m->system_uid == system_user_id) {
      return m->local_user_str;
    }
  }

  return NULL;
}

const unsigned char *
ejudge_cfg_user_map_find_simple(
        const struct ejudge_cfg *cfg,
        const unsigned char *system_user_str)
{
  if (!system_user_str || !*system_user_str) return NULL;
  if (!cfg || !cfg->user_map) return NULL;
  for (const struct xml_tree *p = cfg->user_map->first_down; p; p = p->right) {
    const struct ejudge_cfg_user_map *m = (const struct ejudge_cfg_user_map*) p;
    if (m->system_user_str && !strcmp(system_user_str, m->system_user_str)) {
      return m->local_user_str;
    }
  }
  return NULL;
}

void
ejudge_cfg_user_map_add(
        struct ejudge_cfg *cfg,
        const unsigned char *unix_login,
        const unsigned char *ejudge_login)
{
  if (!cfg) return;
  struct xml_tree *um = cfg->user_map;
  if (!um) {
    um = new_node(TG_USER_MAP);
    xml_link_node_last(&cfg->b, um);
    cfg->user_map = um;
  }
  struct ejudge_cfg_user_map *m = (struct ejudge_cfg_user_map*) new_node(TG_MAP);
  xml_link_node_last(um, &m->b);
  m->system_user_str = xstrdup(unix_login);
  m->local_user_str = xstrdup(ejudge_login);
}

void
ejudge_cfg_caps_add(
        struct ejudge_cfg *cfg,
        const unsigned char *login,
        opcap_t caps)
{
  struct opcap_list_item *cap_node;

  if (!cfg->caps_node) {
    cfg->caps_node = new_node(TG_CAPS);
    xml_link_node_last(&cfg->b, cfg->caps_node);
  }
  cap_node = (typeof(cap_node)) new_node(TG_CAP);
  if (!cfg->capabilities.first) cfg->capabilities.first = cap_node;
  cap_node->login = xstrdup(login);
  cap_node->caps = caps;
  xml_link_node_last(cfg->caps_node, &cap_node->b);
}

const unsigned char *
ejudge_cfg_get_telegram_bot_id(
        const struct ejudge_cfg *cfg,
        const unsigned char *bot_user_id)
{
  struct xml_tree *tree = ejudge_cfg_get_plugin_config(cfg, "sn", "telegram");
  if (!tree) return NULL;

  if (tree->tag != TG__DEFAULT || strcmp(tree->name[0], "config")) {
    return NULL;
  }

  int bot_user_id_len = 0;
  if (bot_user_id) bot_user_id_len = strlen(bot_user_id);

  int bot_count = 0;
  const unsigned char *bot_token = NULL;
  for (struct xml_tree *p = tree->first_down; p; p = p->right) {
    ASSERT(p->tag == TG__DEFAULT);
    if (!strcmp(p->name[0], "bots")) {
      for (struct xml_tree *q = p->first_down; q; q = q->right) {
        ASSERT(q->tag == TG__DEFAULT);
        if (!strcmp(q->name[0], "bot")) {
          const unsigned char *cur_id = q->text;
          if (!cur_id || !*cur_id) continue;
          if (bot_user_id_len <= 0) {
            ++bot_count;
            if (!bot_token) bot_token = cur_id;
          } else {
            int cur_id_len = strlen(cur_id);
            if (cur_id_len > bot_user_id_len + 1
                && !strncmp(cur_id, bot_user_id, bot_user_id_len)
                && cur_id[bot_user_id_len] == ':') {
              ++bot_count;
              if (!bot_token) bot_token = cur_id;
            }
          }
        }
      }
    }
  }
  if (bot_count > 1) bot_token = NULL;
  return bot_token;
}

const unsigned char *
ejudge_cfg_oauth_user_map_find(
        const struct ejudge_cfg *cfg,
        const unsigned char *oauth_user_str,
        const unsigned char *provider)
{
  if (!oauth_user_str || !*oauth_user_str) return NULL;
  if (!cfg) return NULL;
  if (cfg->oauth_user_map) {
    for (const struct xml_tree *p = cfg->oauth_user_map->first_down; p; p = p->right) {
      const struct ejudge_cfg_oauth_user_map *m = (const struct ejudge_cfg_oauth_user_map *) p;
      if (m->oauth_user_str && !strcmp(oauth_user_str, m->oauth_user_str)) {
        if (!m->provider || !*m->provider) return m->local_user_str;
        if (!provider || !*provider) return m->local_user_str;
        if (!strcmp(provider, m->provider)) return m->local_user_str;
      }
    }
  }

  ejudge_cfg_refresh_caps_file(cfg, 0);
  if (!cfg->caps_file_info || !cfg->caps_file_info->root || !cfg->caps_file_info->root->oauth_user_map) return NULL;

  for (const struct xml_tree *p = cfg->caps_file_info->root->oauth_user_map->first_down; p; p = p->right) {
    const struct ejudge_cfg_oauth_user_map *m = (const struct ejudge_cfg_oauth_user_map *) p;
    if (m->oauth_user_str && !strcmp(oauth_user_str, m->oauth_user_str)) {
      if (!m->provider || !*m->provider) return m->local_user_str;
      if (!provider || !*provider) return m->local_user_str;
      if (!strcmp(provider, m->provider)) return m->local_user_str;
    }
  }

  return NULL;
}

const unsigned char *
ejudge_cfg_get_compiler_option(
        const struct ejudge_cfg *cfg,
        const unsigned char *compiler)
{
  if (!cfg->compiler_options) return NULL;
  for (const struct xml_tree *p = cfg->compiler_options->first_down; p; p = p->right) {
    if (p->tag == TG_COMPILER_OPTION) {
      const unsigned char *option = NULL;
      const unsigned char *comp = NULL;
      for (const struct xml_attr *a = p->first; a; a = a->next) {
        if (a->tag == AT_COMPILER) {
          comp = a->text;
        } else if (a->tag == AT_OPTION) {
          option = a->text;
        }
      }
      if (comp && !strcmp(comp, compiler)) {
        return option;
      }
    }
  }
  return NULL;
}
