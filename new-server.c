/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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
#include "settings.h"
#include "ej_types.h"
#include "version.h"

#include "errlog.h"
#include "server_framework.h"
#include "new_server_proto.h"
#include "new-server.h"
#include "ejudge_cfg.h"
#include "contests.h"
#include "ejudge_plugin.h"
#include "nsdb_plugin.h"
#include "l10n.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void startup_error(const char *, ...) __attribute__((noreturn,format(printf, 1, 2)));
static void handle_packet_func(struct server_framework_state *,
                               struct client_state *,
                               size_t,
                               const struct new_server_prot_packet *);

static struct server_framework_params params =
{
  .daemon_mode_flag = 0,
  .force_socket_flag = 0,
  .program_name = 0,
  .socket_path = "/tmp/new-server-socket",
  .log_path = "/tmp/new-server-log",
  .user_data = 0,
  .startup_error = startup_error,
  .handle_packet = handle_packet_func,
};

static struct server_framework_state *state = 0;
static unsigned char *ejudge_xml_path;
struct ejudge_cfg *config;

struct userlist_clnt *ul_conn;
int ul_uid;
unsigned char *ul_login;

// plugin information
struct nsdb_loaded_plugin
{
  struct nsdb_plugin_iface *iface;
  void *data;
};

enum { NSDB_PLUGIN_MAX_NUM = 16 };
static int nsdb_plugins_num;
static struct nsdb_loaded_plugin nsdb_plugins[NSDB_PLUGIN_MAX_NUM];
static struct nsdb_loaded_plugin *nsdb_default = 0;

int
nsdb_check_role(int user_id, int contest_id, int role)
{
  return nsdb_default->iface->check_role(nsdb_default->data, user_id, contest_id, role);
}
int_iterator_t
nsdb_get_contest_user_id_iterator(int contest_id)
{
  return nsdb_default->iface->get_contest_user_id_iterator(nsdb_default->data, contest_id);
}
int
nsdb_get_priv_role_mask_by_iter(int_iterator_t iter, unsigned int *p_mask)
{
  return nsdb_default->iface->get_priv_role_mask_by_iter(nsdb_default->data, iter, p_mask);
}
int
nsdb_add_role(int user_id, int contest_id, int role)
{
  return nsdb_default->iface->add_role(nsdb_default->data, user_id, contest_id, role);
}
int
nsdb_del_role(int user_id, int contest_id, int role)
{
  return nsdb_default->iface->del_role(nsdb_default->data, user_id, contest_id, role);
}
int
nsdb_priv_remove_user(int user_id, int contest_id)
{
  return nsdb_default->iface->priv_remove_user(nsdb_default->data, user_id, contest_id);
}


static void
startup_error(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", params.program_name, buf);
  exit(1);
}

static void
cmd_http_request(struct server_framework_state *state,
                 struct client_state *p,
                 size_t pkt_size,
                 const struct new_server_prot_packet *pkt_gen)
{
  enum
  {
    MAX_PARAM_NUM = 10000,
    MAX_PARAM_SIZE = 128 * 1024 * 1024,
  };

  const struct new_server_prot_http_request *pkt;
  size_t in_size;
  const ej_size_t *arg_sizes, *env_sizes, *param_name_sizes, *param_sizes;
  unsigned long bptr;
  const unsigned char ** args;
  const unsigned char ** envs;
  const unsigned char ** param_names;
  const unsigned char ** params;
  size_t *my_param_sizes;
  int i;
  char *out_txt = 0;
  size_t out_size = 0;
  FILE *out_f = 0;
  struct http_request_info hr;

  if (pkt_size < sizeof(*pkt))
    return nsf_err_packet_too_small(state, p, pkt_size, sizeof(*pkt));
  pkt = (const struct new_server_prot_http_request *) pkt_gen;

  if (pkt->arg_num < 0 || pkt->arg_num > MAX_PARAM_NUM)
    return nsf_err_protocol_error(state, p);
  if (pkt->env_num < 0 || pkt->env_num > MAX_PARAM_NUM)
    return nsf_err_protocol_error(state, p);
  if (pkt->param_num < 0 || pkt->param_num > MAX_PARAM_NUM)
    return nsf_err_protocol_error(state, p);

  in_size = sizeof(*pkt);
  in_size += pkt->arg_num * sizeof(ej_size_t);
  in_size += pkt->env_num * sizeof(ej_size_t);
  in_size += pkt->param_num * 2 * sizeof(ej_size_t);
  if (pkt_size < in_size)
    return nsf_err_packet_too_small(state, p, pkt_size, in_size);

  XALLOCAZ(args, pkt->arg_num);
  XALLOCAZ(envs, pkt->env_num);
  XALLOCAZ(param_names, pkt->param_num);
  XALLOCAZ(params, pkt->param_num);
  XALLOCAZ(my_param_sizes, pkt->param_num);

  bptr = (unsigned long) pkt;
  bptr += sizeof(*pkt);
  arg_sizes = (const ej_size_t *) bptr;
  bptr += pkt->arg_num * sizeof(ej_size_t);
  env_sizes = (const ej_size_t *) bptr;
  bptr += pkt->env_num * sizeof(ej_size_t);
  param_name_sizes = (const ej_size_t *) bptr;
  bptr += pkt->param_num * sizeof(ej_size_t);
  param_sizes = (const ej_size_t *) bptr;
  bptr += pkt->param_num * sizeof(ej_size_t);

  for (i = 0; i < pkt->arg_num; i++) {
    if (arg_sizes[i] > MAX_PARAM_SIZE) return nsf_err_protocol_error(state, p);
    in_size += arg_sizes[i] + 1;
  }
  for (i = 0; i < pkt->env_num; i++) {
    if (env_sizes[i] > MAX_PARAM_SIZE) return nsf_err_protocol_error(state, p);
    in_size += env_sizes[i] + 1;
  }
  for (i = 0; i < pkt->param_num; i++) {
    if (param_name_sizes[i] > MAX_PARAM_SIZE)
      return nsf_err_protocol_error(state, p);
    if (param_sizes[i] > MAX_PARAM_SIZE)
      return nsf_err_protocol_error(state, p);
    in_size += param_name_sizes[i] + 1;
    in_size += param_sizes[i] + 1;
  }
  if (pkt_size != in_size)
    return nsf_err_bad_packet_length(state, p, pkt_size, in_size);

  for (i = 0; i < pkt->arg_num; i++) {
    args[i] = (const unsigned char*) bptr;
    bptr += arg_sizes[i] + 1;
    if (strlen(args[i]) != arg_sizes[i])
      return nsf_err_protocol_error(state, p);
  }
  for (i = 0; i < pkt->env_num; i++) {
    envs[i] = (const unsigned char*) bptr;
    bptr += env_sizes[i] + 1;
    if (strlen(envs[i]) != env_sizes[i])
      return nsf_err_protocol_error(state, p);
  }
  for (i = 0; i < pkt->param_num; i++) {
    param_names[i] = (const unsigned char*) bptr;
    bptr += param_name_sizes[i] + 1;
    if (strlen(param_names[i]) != param_name_sizes[i])
      return nsf_err_protocol_error(state, p);
    params[i] = (const unsigned char *) bptr;
    my_param_sizes[i] = param_sizes[i];
    bptr += param_sizes[i] + 1;
  }

  memset(&hr, 0, sizeof(hr));
  hr.arg_num = pkt->arg_num;
  hr.args = args;
  hr.env_num = pkt->env_num;
  hr.envs = envs;
  hr.param_num = pkt->param_num;
  hr.param_names = param_names;
  hr.param_sizes = my_param_sizes;
  hr.params = params;

  // ok, generate HTML
  out_f = open_memstream(&out_txt, &out_size);
  new_server_handle_http_request(state, p, out_f, &hr);
  fclose(out_f); out_f = 0;

  xfree(hr.login);
  xfree(hr.name);
  xfree(hr.name_arm);
  nsf_new_autoclose(state, p, out_txt, out_size);
  info("HTTP_REQUEST -> OK, %zu", out_size);
  nsf_send_reply(state, p, NEW_SRV_RPL_OK);
}

typedef void handler_t(struct server_framework_state *state,
                       struct client_state *p,
                       size_t pkt_size,
                       const struct new_server_prot_packet *pkt);

static handler_t *handlers[NEW_SRV_CMD_LAST] =
{
  [NEW_SRV_CMD_HTTP_REQUEST] cmd_http_request,
};

static void
handle_packet_func(struct server_framework_state *state,
                   struct client_state *p,
                   size_t pkt_size,
                   const struct new_server_prot_packet *pkt)
{
  if (pkt->id <= 1 || pkt->id >= NEW_SRV_CMD_LAST || !handlers[pkt->id])
    return nsf_err_invalid_command(state, p, pkt->id);

  handlers[pkt->id](state, p, pkt_size, pkt);
}

static int
load_plugins(void)
{
  struct ejudge_plugin_iface *base_iface = 0;
  struct nsdb_plugin_iface *nsdb_iface = 0;
  struct xml_tree *p;
  struct ejudge_plugin *plg, *files_plg;
  void *plugin_data = 0;

  plugin_set_directory(config->plugin_dir);

  ejudge_cfg_unparse_plugins(config, stdout);

  // find config section for files plugin
  for (p = config->plugin_list; p; p = p->right) {
    files_plg = (struct ejudge_plugin*) p;
    if (!strcmp(files_plg->type, "nsdb") && !strcmp(files_plg->name, "files"))
      break;
  }
  if (!p) files_plg = 0;
  p = 0;
  if (files_plg) p = files_plg->data;

  // `files' plugin always loaded
  nsdb_plugins_num = 0;
  nsdb_plugins[nsdb_plugins_num].iface = &nsdb_plugin_files;
  if (!(plugin_data = nsdb_plugin_files.init(config))) {
    startup_error("cannot initialize files database plugin");
    return -1;
  }
  if (nsdb_plugin_files.parse(plugin_data, config, p) < 0) {
    startup_error("cannot initialize files database plugin");
    return -1;
  }
  nsdb_plugins[nsdb_plugins_num].data = plugin_data;
  nsdb_plugins_num++;

  // load other userdb plugins
  for (p = config->plugin_list; p; p = p->right) {
    plg = (struct ejudge_plugin*) p;

    if (!plg->load_flag) continue;
    if (strcmp(plg->type, "userdb") != 0) continue;
    // `files' plugin is already loaded
    if (!strcmp(plg->name, "files")) continue;

    if (nsdb_plugins_num == NSDB_PLUGIN_MAX_NUM) {
      startup_error("too many userlist database plugins");
      return -1;
    }

    if (!(base_iface = plugin_load(plg->path, plg->type, plg->name))) {
      startup_error("cannot load plugin");
      return -1;
    }
    nsdb_iface = (struct nsdb_plugin_iface*) base_iface;
    if (nsdb_iface->b.size != sizeof(*nsdb_iface)) {
      startup_error("plugin size mismatch");
      return -1;
    }
    if (nsdb_iface->nsdb_version != NSDB_PLUGIN_IFACE_VERSION) {
      startup_error("plugin version mismatch");
      return -1;
    }
    if (!(plugin_data = nsdb_iface->init(config))) {
      startup_error("plugin initialization failed");
      return -1;
    }
    if (nsdb_iface->parse(plugin_data, config, plg->data) < 0) {
      startup_error("plugin failed to parse its configuration");
      return -1;
    }

    nsdb_plugins[nsdb_plugins_num].iface = nsdb_iface;
    nsdb_plugins[nsdb_plugins_num].data = plugin_data;

    if (plg->default_flag) {
      if (nsdb_default) {
        startup_error("more than one plugin is defined as default");
        return -1;
      }
      nsdb_default = &nsdb_plugins[nsdb_plugins_num];
    }

    nsdb_plugins_num++;
  }

  if (!nsdb_default) {
    info("using files as the new-server database");
    nsdb_default = &nsdb_plugins[0];
  }

  return 0;
}

int
main(int argc, char *argv[])
{
  int i;
  int create_flag = 0;

  params.program_name = argv[0];
  for (i = 1; i < argc; ) {
    if (!strcmp(argv[i], "-D")) {
      params.daemon_mode_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "-f")) {
      params.force_socket_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "--create")) {
      create_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (argv[i][0] == '-') {
      startup_error("invalid option `%s'", argv[i]);
    } else
      break;
  }
  if (i < argc) ejudge_xml_path = argv[i++];
  if (i != argc) startup_error("invalid number of parameters");

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) startup_error("configuration file is not specified");

  config = ejudge_cfg_parse(ejudge_xml_path);
  if (!config) return 1;
  if (contests_set_directory(config->contests_dir) < 0) return 1;
  l10n_prepare(config->l10n, config->l10n_dir);

  info("new-server %s, compiled %s", compile_version, compile_date);

  if (load_plugins() < 0) return 1;

  // initialize the default plugin
  if (nsdb_default->iface->open(nsdb_default->data) < 0) {
    startup_error("default plugin failed to open its connection");
    return 1;
  }

  if (create_flag) {
    if (nsdb_default->iface->create(nsdb_default->data) < 0) {
      startup_error("database creation failed");
      return 1;
    }
    if (nsdb_default->iface->close(nsdb_default->data) < 0) {
      startup_error("database closing failed");
      return 1;
    }
    return 0;
  }

  if (nsdb_default->iface->check(nsdb_default->data) <= 0) {
    startup_error("default plugin failed to check its data");
    return 1;
  }

  if (!(state = nsf_init(&params, 0))) return 1;
  if (nsf_prepare(state) < 0) return 1;
  nsf_main_loop(state);
  nsf_cleanup(state);
  nsdb_default->iface->close(nsdb_default->data);

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
