/* -*- mode: c -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/version.h"
#include "ejudge/startstop.h"
#include "ejudge/errlog.h"
#include "ejudge/server_framework.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/new-server.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/contests.h"
#include "ejudge/ejudge_plugin.h"
#include "ejudge/nsdb_plugin.h"
#include "ejudge/l10n.h"
#include "ejudge/pathutl.h"
#include "ejudge/userlist.h"
#include "ejudge/compat.h"
#include "ejudge/xml_utils.h"
#include "ejudge/cJSON.h"
#include "ejudge/misctext.h"
#include "ejudge/base64.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/oauth.h"
#include "ejudge/sha256utils.h"
#include "ejudge/metrics_contest.h"
#include "ejudge/teamdb.h"
#include "ejudge/session_cache.h"
#include "ejudge/server_info.h"
#include "ejudge/mixed_id.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"
#include "ejudge/html.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>

int utf8_mode;

static void startup_error(const char *, ...) __attribute__((noreturn,format(printf, 1, 2)));
static void handle_packet_func(struct server_framework_state *,
                               struct client_state *,
                               size_t,
                               const struct new_server_prot_packet *);
static void
handle_ws_request(
        struct server_framework_state *state,
        struct ws_client_state *p,
        int opcode,
        const unsigned char *data,
        size_t size);

static struct server_framework_params params =
{
  .daemon_mode_flag = 0,
  .force_socket_flag = 0,
  .program_name = 0,
  .socket_path = "/tmp/new-server-socket",
  .log_path = "/tmp/ej-contests.log",
  .select_timeout = 1,
  .user_data = 0,
  .startup_error = startup_error,
  .handle_packet = handle_packet_func,
  .loop_start = ns_loop_callback,
  .post_select = ns_post_select_callback,
  .ws_handle_packet = handle_ws_request,
  .ws_check_session = ns_ws_check_session,
  .ws_create_session = ns_ws_create_session,
};

static struct server_framework_state *state = 0;
static unsigned char *ejudge_xml_path;
//struct ejudge_cfg *ejudge_config;

struct userlist_clnt *ul_conn;
int ul_uid;
unsigned char *ul_login;

// global session cache
extern struct id_cache main_id_cache;

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

int
nsdb_find_chief_examiner(int contest_id, int prob_id)
{
  return nsdb_default->iface->find_chief_examiner(nsdb_default->data, contest_id, prob_id);
}
int
nsdb_assign_chief_examiner(int user_id, int contest_id, int prob_id)
{
  return nsdb_default->iface->assign_chief_examiner(nsdb_default->data, user_id, contest_id, prob_id, 1);
}
int
nsdb_assign_examiner(int user_id, int contest_id, int prob_id)
{
  return nsdb_default->iface->assign_examiner(nsdb_default->data, user_id, contest_id, prob_id);
}
int
nsdb_remove_examiner(int user_id, int contest_id, int prob_id)
{
  return nsdb_default->iface->remove_examiner(nsdb_default->data, user_id, contest_id, prob_id);
}
int_iterator_t
nsdb_get_examiner_user_id_iterator(int contest_id, int prob_id)
{
  return nsdb_default->iface->get_examiner_user_id_iterator(nsdb_default->data, contest_id, prob_id);
}
int
nsdb_get_examiner_count(int contest_id, int prob_id)
{
  return nsdb_default->iface->get_examiner_count(nsdb_default->data, contest_id, prob_id);
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

int
ns_is_valid_client_id(int client_id)
{
  return nsf_get_client_by_id(state, client_id) != NULL;
}

void
ns_client_state_clear_contest_id(int client_id)
{
  struct ht_client_state *p = (struct ht_client_state *) nsf_get_client_by_id(state, client_id);
  if (p) {
    p->contest_id = 0;
    p->destroy_callback = 0;
  }
}

void
ns_close_client_fds(int client_id)
{
  struct client_state *p = nsf_get_client_by_id(state, client_id);
  if (p) {
    nsf_close_client_fds(p);
  }
}

void
ns_send_reply_2(int client_id, int answer)
{
  struct client_state *p = nsf_get_client_by_id(state, client_id);
  if (p) {
    nsf_send_reply(state, p, answer);
  }
}

void
ns_new_autoclose_2(int client_id, void *write_buf, size_t write_len)
{
  struct client_state *p = nsf_get_client_by_id(state, client_id);
  if (p) {
    nsf_new_autoclose(state, p, write_buf, write_len);
  }
}

extern const unsigned char * const ns_symbolic_action_table[NEW_SRV_ACTION_LAST];

static void
cmd_http_request(
        struct server_framework_state *state,
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
  struct http_request_info hr;
  unsigned char info_buf[1024];
  unsigned char *pbuf = info_buf;

  memset(&hr, 0, sizeof(hr));
  hr.id = p->id;
  hr.client_state = p;
  hr.fw_state = state;
  gettimeofday(&hr.timestamp1, 0);
  hr.current_time = hr.timestamp1.tv_sec;
  hr.current_time_us = hr.timestamp1.tv_sec * 1000000LL + hr.timestamp1.tv_usec;
  hr.locale_id = -1;

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

  hr.arg_num = pkt->arg_num;
  hr.args = args;
  hr.env_num = pkt->env_num;
  hr.envs = envs;
  hr.param_num = pkt->param_num;
  hr.param_names = param_names;
  hr.param_sizes = my_param_sizes;
  hr.params = params;
  hr.config = ejudge_config;

  // ok, generate HTML
  hr.out_f = open_memstream(&hr.out_t, &hr.out_z);
  ns_handle_http_request(state, hr.out_f, &hr);
  close_memstream(hr.out_f); hr.out_f = NULL;

  if (!hr.disable_log) {
    *pbuf = 0;
    // report IP?
    if (hr.ssl_flag) {
      pbuf = stpcpy(pbuf, "HTTPS:");
    } else {
      pbuf = stpcpy(pbuf, "HTTPS:");
    }
    pbuf = stpcpy(pbuf, xml_unparse_ipv6(&hr.ip));
    *pbuf++ = ':';
    if (/*hr.role_name*/ 1) {
      pbuf = stpcpy(pbuf, hr.role_name);
    }
    if (hr.action > 0 && hr.action < NEW_SRV_ACTION_LAST && ns_symbolic_action_table[hr.action]) {
      *pbuf++ = '/';
      pbuf = stpcpy(pbuf, ns_symbolic_action_table[hr.action]);
    }
    if (hr.session_id) {
      *pbuf++ = '/';
      *pbuf++ = 'S';
      pbuf += sprintf(pbuf, "%016llx", hr.session_id);
      if (hr.client_key) {
        *pbuf++ = '-';
        pbuf += sprintf(pbuf, "%016llx", hr.client_key);
      }
    }
    if (hr.user_id > 0) {
      *pbuf++ = '/';
      *pbuf++ = 'U';
      pbuf += sprintf(pbuf, "%d", hr.user_id);
    }
    if (hr.contest_id > 0) {
      *pbuf++ = '/';
      *pbuf++ = 'C';
      pbuf += sprintf(pbuf, "%d", hr.contest_id);
    }
  }

  // no reply now
  if (hr.no_reply) goto cleanup;

  if (hr.protocol_reply) {
    xfree(hr.out_t); hr.out_t = NULL;
    if (!hr.disable_log) {
      info("%d:%s -> %d", p->id, info_buf, hr.protocol_reply);
    }
    nsf_close_client_fds(p);
    nsf_send_reply(state, p, hr.protocol_reply);
    goto cleanup;
  }

  if (hr.redirect) {
    xfree(hr.out_t); hr.out_t = NULL;
    hr.out_z = 0;
    hr.out_f = open_memstream(&hr.out_t, &hr.out_z);
    if (hr.client_key) {
      fprintf(hr.out_f, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", hr.client_key);
    }
    fprintf(hr.out_f, "Location: %s\n\n", hr.redirect);
    fclose(hr.out_f); hr.out_f = NULL;
    xfree(hr.redirect); hr.redirect = NULL;
  } else if (hr.json_reply && !hr.content_type[0]) {
    // generate JSON responce header
    char *hdr_t = NULL;
    size_t hdr_z = 0;
    FILE *hdr_f = open_memstream(&hdr_t, &hdr_z);

    fprintf(hdr_f, "Content-Type: %s\n", "text/json");
    fprintf(hdr_f, "Cache-Control: no-cache\n");
    fprintf(hdr_f, "Pragma: no-cache\n");
    putc('\n', hdr_f);
    if (hr.out_z > 0) {
      fwrite(hr.out_t, 1, hr.out_z, hdr_f);
    }
    fclose(hdr_f); hdr_f = NULL;
    free(hr.out_t);
    hr.out_t = hdr_t;
    hr.out_z = hdr_z;
  } else if (/*hr.content_type &&*/ hr.content_type[0]) {
    // generate header
    char *hdr_t = NULL;
    size_t hdr_z = 0;
    FILE *hdr_f = open_memstream(&hdr_t, &hdr_z);

    fprintf(hdr_f, "Content-Type: %s\n", hr.content_type);
    fprintf(hdr_f, "Cache-Control: no-cache\n");
    fprintf(hdr_f, "Pragma: no-cache\n");
    if (hr.client_key) {
      fprintf(hdr_f, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", hr.client_key);
    }
    putc('\n', hdr_f);
    if (hr.out_z > 0) {
      fwrite(hr.out_t, 1, hr.out_z, hdr_f);
    }
    fclose(hdr_f); hdr_f = NULL;
    free(hr.out_t);
    hr.out_t = hdr_t;
    hr.out_z = hdr_z;
  }

  if (!hr.out_t || !*hr.out_t) {
    xfree(hr.out_t); hr.out_t = NULL;
    if (hr.allow_empty_output) {
      if (!hr.disable_log) {
        info("%d:%s -> OK", p->id, info_buf);
      }
      nsf_close_client_fds(p);
      nsf_send_reply(state, p, NEW_SRV_RPL_OK);
      goto cleanup;
    }
    hr.out_f = open_memstream(&hr.out_t, &hr.out_z);
    fprintf(hr.out_f, "Content-type: text/plain\n\n");
    close_memstream(hr.out_f); hr.out_f = NULL;
  }

  nsf_new_autoclose(state, p, hr.out_t, hr.out_z);
  if (!hr.disable_log) {
    info("%d:%s -> OK, %zu", p->id, info_buf, hr.out_z);
  }
  nsf_send_reply(state, p, NEW_SRV_RPL_OK);
  hr.out_t = NULL; hr.out_z = 0;

 cleanup:
  if (hr.out_f) fclose(hr.out_f);
  xfree(hr.out_t);
  if (hr.log_f) fclose(hr.log_f);
  xfree(hr.log_t);
  xfree(hr.login);
  xfree(hr.name);
  xfree(hr.name_arm);
  xfree(hr.script_part);
  xfree(hr.body_attr);
  if (hr.user_info) {
    userlist_free(&hr.user_info->b);
  }
}

void
ns_ws_error(
        struct ws_client_state *p,
        int error_code)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  char *out_s = NULL;
  size_t out_z = 0;
  FILE *out_f = open_memstream(&out_s, &out_z);
  fprintf(out_f, "{\n");
  fprintf(out_f, "  \"ok\": false");
  fprintf(out_f, ",\n  \"error\": {\n");
  fprintf(out_f, "    \"num\": %d", error_code);
  fprintf(out_f, ",\n    \"symbol\": \"%s\"", ns_error_symbol(error_code));
  const unsigned char *msg = ns_error_title_2(error_code);
  if (msg) {
    fprintf(out_f, ",\n    \"message\": \"%s\"", json_armor_buf(&ab, msg));
  }
  fprintf(out_f, "\n  }");
  fprintf(out_f, "\n}\n");
  fclose(out_f); out_f = NULL;
  html_armor_free(&ab);
  nsf_ws_append_reply_frame(p, 0, out_s, out_z);
  free(out_s);
}

static void
handle_ws_request(
        struct server_framework_state *state,
        struct ws_client_state *p,
        int opcode,
        const unsigned char *data,
        size_t size)
{
  struct http_request_info hr;
  unsigned char info_buf[1024];
  unsigned char *pbuf = info_buf;

  // FIXME: handle only WS_FRAME_TEXT?
  cJSON *root = cJSON_Parse(data);
  if (!root) {
    ns_ws_error(p, NEW_SRV_ERR_PROTOCOL_ERROR);
    return;
  }
  if (root->type != cJSON_Object) {
    ns_ws_error(p, NEW_SRV_ERR_PROTOCOL_ERROR);
    cJSON_Delete(root);
    return;
  }

  memset(&hr, 0, sizeof(hr));
  hr.id = p->b.id;
  hr.client_state = &p->b;
  hr.fw_state = state;
  gettimeofday(&hr.timestamp1, 0);
  hr.current_time = hr.timestamp1.tv_sec;
  hr.current_time_us = hr.timestamp1.tv_sec * 1000000LL + hr.timestamp1.tv_usec;
  hr.locale_id = -1;
  hr.config = ejudge_config;
  hr.json = root;

  //hr.log_f = open_memstream(&hr.log_t, &hr.log_z);
  hr.out_f = open_memstream(&hr.out_t, &hr.out_z);
  ns_handle_http_request(state, hr.out_f, &hr);
  if (hr.log_f) {
    close_memstream(hr.log_f); hr.log_f = NULL;
  }
  if (hr.out_f) {
    close_memstream(hr.out_f); hr.out_f = NULL;
  }

  *pbuf = 0;
  if (hr.ssl_flag) {
    pbuf = stpcpy(pbuf, "WSS:");
  } else {
    pbuf = stpcpy(pbuf, "WS:");
  }
  pbuf = stpcpy(pbuf, xml_unparse_ipv6(&hr.ip));
  *pbuf++ = ':';
  if (/*hr.role_name*/ 1) {
    pbuf = stpcpy(pbuf, hr.role_name);
  }
  if (hr.action > 0 && hr.action < NEW_SRV_ACTION_LAST && ns_symbolic_action_table[hr.action]) {
    *pbuf++ = '/';
    pbuf = stpcpy(pbuf, ns_symbolic_action_table[hr.action]);
  }
  if (hr.session_id) {
    *pbuf++ = '/';
    *pbuf++ = 'S';
    pbuf += sprintf(pbuf, "%016llx", hr.session_id);
    if (hr.client_key) {
      *pbuf++ = '-';
      pbuf += sprintf(pbuf, "%016llx", hr.client_key);
    }
  }
  if (hr.user_id > 0) {
    *pbuf++ = '/';
    *pbuf++ = 'U';
    pbuf += sprintf(pbuf, "%d", hr.user_id);
  }
  if (hr.contest_id > 0) {
    *pbuf++ = '/';
    *pbuf++ = 'C';
    pbuf += sprintf(pbuf, "%d", hr.contest_id);
  }

  nsf_ws_append_reply_frame(p, 0, hr.out_t, hr.out_z);
  info("%d:%s -> OK", p->b.id, info_buf);

  if (hr.out_f) fclose(hr.out_f);
  xfree(hr.out_t);
  if (hr.log_f) fclose(hr.log_f);
  xfree(hr.log_t);
  xfree(hr.login);
  xfree(hr.name);
  xfree(hr.name_arm);
  xfree(hr.script_part);
  xfree(hr.body_attr);
  cJSON_Delete(root);
}

static int
check_restart_permissions(struct client_state *p)
{
  struct ht_client_state *pp = (struct ht_client_state *) p;
  struct passwd *sysp = 0;
  opcap_t caps = 0;

  if (!pp->peer_uid) return 1;   /* root is allowed */
  if (pp->peer_uid == getuid()) return 1; /* the current user also allowed */
  if (!(sysp = getpwuid(pp->peer_uid)) || !sysp->pw_name) {
    err("no user %d in system tables", pp->peer_uid);
    return -1;
  }
  const unsigned char *ejudge_login = ejudge_cfg_user_map_find(ejudge_config, sysp->pw_name);
  if (ejudge_login) return 0;

  if (ejudge_cfg_opcaps_find(ejudge_config, ejudge_login, &caps) < 0)
    return 0;
  if (opcaps_check(caps, OPCAP_RESTART) < 0) return 0;
  return 1;
}

static void
cmd_control(struct server_framework_state *state,
            struct client_state *p,
            size_t pkt_size,
            const struct new_server_prot_packet *pkt)
{
  struct ht_client_state *pp = (struct ht_client_state *) p;

  int mon_fd = -1;
  int sig = 0;

  if (pkt_size != sizeof(*pkt))
    return nsf_err_bad_packet_length(state, p, pkt_size, sizeof(*pkt));

  if (check_restart_permissions(p) <= 0) {
    return nsf_send_reply(state, p, -NEW_SRV_ERR_PERMISSION_DENIED);
  }

  switch (pkt->id) {
  case NEW_SRV_CMD_STOP:
    sig = SIGTERM;
    break;
  case NEW_SRV_CMD_RESTART:
    sig = SIGHUP;
    break;
  default:
    return nsf_err_invalid_command(state, p, pkt->id);
  }

  mon_fd = dup(p->fd);
  fcntl(mon_fd, F_SETFD, FD_CLOEXEC);
  pp->state = STATE_DISCONNECT;
  raise(sig);
}

typedef void handler_t(struct server_framework_state *state,
                       struct client_state *p,
                       size_t pkt_size,
                       const struct new_server_prot_packet *pkt);

static handler_t *handlers[NEW_SRV_CMD_LAST] =
{
  [NEW_SRV_CMD_HTTP_REQUEST] = cmd_http_request,
  [NEW_SRV_CMD_STOP] = cmd_control,
  [NEW_SRV_CMD_RESTART] = cmd_control,
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

  plugin_set_directory(ejudge_config->plugin_dir);

  //ejudge_cfg_unparse_plugins(ejudge_config, stdout);

  // find config section for files plugin
  for (p = ejudge_config->plugin_list; p; p = p->right) {
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
  if (!(plugin_data = nsdb_plugin_files.init(ejudge_config))) {
    startup_error("cannot initialize files database plugin");
    return -1;
  }
  if (nsdb_plugin_files.parse(plugin_data, ejudge_config, p) < 0) {
    startup_error("cannot initialize files database plugin");
    return -1;
  }
  nsdb_plugins[nsdb_plugins_num].data = plugin_data;
  nsdb_plugins_num++;

  // load other userdb plugins
  for (p = ejudge_config->plugin_list; p; p = p->right) {
    plg = (struct ejudge_plugin*) p;

    if (!plg->load_flag) continue;
    if (strcmp(plg->type, "nsdb") != 0) continue;
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
    if (!(plugin_data = nsdb_iface->init(ejudge_config))) {
      startup_error("plugin initialization failed");
      return -1;
    }
    if (nsdb_iface->parse(plugin_data, ejudge_config, plg->data) < 0) {
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
    //info("using files as the new-server database");
    nsdb_default = &nsdb_plugins[0];
  }

  return 0;
}

static void
setup_log_file(void)
{
  path_t buf;
  const unsigned char *s1, *s2;

  if (ejudge_config->new_server_log
      && os_IsAbsolutePath(ejudge_config->new_server_log))
    return;
  if (ejudge_config->var_dir && os_IsAbsolutePath(ejudge_config->var_dir)) {
    if (!(s1 = ejudge_config->new_server_log)) s1 = "ej-contests.log";
    snprintf(buf, sizeof(buf), "%s/%s", ejudge_config->var_dir, s1);
    xfree(ejudge_config->new_server_log);
    ejudge_config->new_server_log = xstrdup(buf);
    return;
  }
  if (ejudge_config->contests_home_dir
      && os_IsAbsolutePath(ejudge_config->contests_home_dir)){
    if (!(s1 = ejudge_config->new_server_log)) s1 = "ej-contests.log";
    if (!(s2 = ejudge_config->var_dir)) s2 = "var";
    snprintf(buf, sizeof(buf), "%s/%s/%s", ejudge_config->contests_home_dir,
             s2, s1);
    xfree(ejudge_config->new_server_log);
    ejudge_config->new_server_log = xstrdup(buf);
    return;
  }
  ejudge_config->new_server_log = xstrdup("/tmp/ej-contests.log");
}

static void
setup_spool_dirs(const struct ejudge_cfg *config, struct server_framework_state *state)
{
  __attribute__((unused)) int r;
  const unsigned char *contest_server_id = config->contest_server_id;

#if defined EJUDGE_COMPILE_SPOOL_DIR
  const unsigned char *compile_spool_dir = EJUDGE_COMPILE_SPOOL_DIR;

  unsigned char compile_report_buf[PATH_MAX];
  unsigned char compile_status_buf[PATH_MAX];
  unsigned char compile_status_dir_buf[PATH_MAX];
  unsigned char compile_status_in_buf[PATH_MAX];
  unsigned char compile_status_out_buf[PATH_MAX];

  r = snprintf(compile_status_buf, sizeof(compile_status_buf), "%s/%s/status", compile_spool_dir, contest_server_id);
  r = snprintf(compile_report_buf, sizeof(compile_report_buf), "%s/%s/report", compile_spool_dir, contest_server_id);
  r = snprintf(compile_status_dir_buf, sizeof(compile_status_dir_buf), "%s/dir", compile_status_buf);
  r = snprintf(compile_status_in_buf, sizeof(compile_status_in_buf), "%s/in", compile_status_buf);
  r = snprintf(compile_status_out_buf, sizeof(compile_status_out_buf), "%s/out", compile_status_buf);

  const unsigned char *compile_group = NULL;
#if defined EJUDGE_COMPILE_USER
  compile_group = EJUDGE_COMPILE_USER;
#endif

  if (os_MakeDirPath2(compile_report_buf, "0770", compile_group) < 0) {
    startup_error("failed to create compile spool: %s", os_ErrorMsg());
  }
  if (os_MakeDirPath2(compile_status_dir_buf, "0770", compile_group) < 0) {
    startup_error("failed to create compile spool: %s", os_ErrorMsg());
  }
  if (os_MakeDirPath2(compile_status_in_buf, "0770", compile_group) < 0) {
    startup_error("failed to create compile spool: %s", os_ErrorMsg());
  }
  if (os_MakeDirPath2(compile_status_out_buf, "0700", NULL) < 0) {
    startup_error("failed to create compile spool: %s", os_ErrorMsg());
  }

  nsf_add_directory_watch(config, state, compile_status_buf, compile_report_buf, NULL, ns_compile_dir_ready, NULL);
#endif

#if defined EJUDGE_RUN_SPOOL_DIR
  const unsigned char *run_spool_dir = EJUDGE_RUN_SPOOL_DIR;

  unsigned char run_status_buf[PATH_MAX];
  unsigned char run_status_dir_buf[PATH_MAX];
  unsigned char run_status_in_buf[PATH_MAX];
  unsigned char run_status_out_buf[PATH_MAX];
  unsigned char run_report_buf[PATH_MAX];
  unsigned char run_full_archive_buf[PATH_MAX];

  r = snprintf(run_status_buf, sizeof(run_status_buf), "%s/%s/status", run_spool_dir, contest_server_id);
  r = snprintf(run_report_buf, sizeof(run_report_buf), "%s/%s/report", run_spool_dir, contest_server_id);
  r = snprintf(run_full_archive_buf, sizeof(run_full_archive_buf), "%s/%s/output", run_spool_dir, contest_server_id);
  r = snprintf(run_status_dir_buf, sizeof(run_status_dir_buf), "%s/dir", run_status_buf);
  r = snprintf(run_status_in_buf, sizeof(run_status_in_buf), "%s/in", run_status_buf);
  r = snprintf(run_status_out_buf, sizeof(run_status_out_buf), "%s/out", run_status_buf);

  if (os_MakeDirPath(run_report_buf, 0700) < 0) {
    startup_error("failed to create run spool '%s': %s",
                  run_report_buf, os_ErrorMsg());
  }
  if (os_MakeDirPath(run_full_archive_buf, 0700) < 0) {
    startup_error("failed to create run spool '%s': %s",
                  run_full_archive_buf, os_ErrorMsg());
  }
  if (os_MakeDirPath(run_status_dir_buf, 0700) < 0) {
    startup_error("failed to create run spool '%s': %s",
                  run_status_dir_buf, os_ErrorMsg());
  }
  if (os_MakeDirPath(run_status_in_buf, 0700) < 0) {
    startup_error("failed to create run spool '%s': %s",
                  run_status_in_buf, os_ErrorMsg());
  }
  if (os_MakeDirPath(run_status_out_buf, 0700) < 0) {
    startup_error("failed to create run spool '%s': %s",
                  run_status_out_buf, os_ErrorMsg());
  }

  nsf_add_directory_watch(config, state,
                          run_status_buf, run_report_buf, run_full_archive_buf,
                          ns_run_dir_ready, NULL);
#endif /* EJUDGE_RUN_SPOOL_DIR */
}

extern int ej_bson_force_link_dummy;
extern int ej_bson_new_force_link_dummy;

static void *forced_symbols[] __attribute__((unused,used)) =
{
  &ej_bson_force_link_dummy,
  &ej_bson_new_force_link_dummy,
  &base64u_encode,
  &base64u_decode,
  &userlist_clnt_api_key_request,
  &oauth_get_redirect_url,
  &userlist_clnt_edit_field,
  &sha256b64ubuf,
  &teamdb_get_user_map,
  &stand_setup_style,
  &server_info_get_processes,
  &mixed_id_marshall,
};

int
main(int argc, char *argv[])
{
  int i, j = 0;
  int create_flag = 0;
  const unsigned char *user = 0, *group = 0, *workdir = 0;
  int restart_flag = 0;
  char **argv_restart = 0;
  int pid;
  time_t server_start_time = 0;
  int disable_stack_trace = 0;

  hr_set_symbolic_action_table(NEW_SRV_ACTION_LAST, ns_symbolic_action_table, ns_submit_button_labels, 0);
  time(&server_start_time);
  start_set_self_args(argc, argv);
  /* certain options should be removed for restart */
  XCALLOC(argv_restart, argc + 2);
  argv_restart[j++] = argv[0];

  params.program_name = argv[0];
  for (i = 1; i < argc; ) {
    if (!strcmp(argv[i], "-D")) {
      params.daemon_mode_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "-f")) {
      params.force_socket_flag = 1;
      argv_restart[j++] = argv[i];
      i++;
    } else if (!strcmp(argv[i], "--create")) {
      create_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "-u")) {
      if (++i >= argc) startup_error("invalid usage");
      user = argv[i++];
    } else if (!strcmp(argv[i], "-g")) {
      if (++i >= argc) startup_error("invalid usage");
      group = argv[i++];
    } else if (!strcmp(argv[i], "-C")) {
      if (++i >= argc) startup_error("invalid usage");
      workdir = argv[i++];
    } else if (!strcmp(argv[i], "-R")) {
      params.restart_mode_flag = 1;
      ++i;
    } else if (!strcmp(argv[i], "-nst")) {
      disable_stack_trace = 1;
      ++i;
    } else if (!strcmp(argv[i], "--")) {
      argv_restart[j++] = argv[i];
      i++;
      break;
    } else if (argv[i][0] == '-') {
      startup_error("invalid option `%s'", argv[i]);
    } else
      break;
  }
  argv_restart[j++] = "-R";
  if (i < argc) {
    argv_restart[j++] = argv[i];
    ejudge_xml_path = argv[i++];
  }
  if (i != argc) startup_error("invalid number of parameters");
  argv_restart[j] = 0;
  start_set_args(argv_restart);
  if (disable_stack_trace <= 0) {
    start_enable_stacktrace(NULL);
  }

  if (!(pid = start_find_process("ej-contests", NULL, 0))) {
    params.force_socket_flag = 1;
  } else if (pid > 0) {
    fprintf(stderr, "%s: is already running as pid %d\n", argv[0], pid);
    return 1;
  }

  if (start_prepare(user, group, workdir) < 0) return 1;

  if (workdir && *workdir) {
    if (chdir(workdir) < 0) {
      err("cannot change directory to %s", workdir);
      return 1;
    }
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) startup_error("configuration file is not specified");

  ejudge_config = ejudge_cfg_parse(ejudge_xml_path, 0);
  if (!ejudge_config) return 1;
  if (contests_set_directory(ejudge_config->contests_dir) < 0) return 1;
  l10n_prepare(ejudge_config->l10n, ejudge_config->l10n_dir);
  if (!strcasecmp(EJUDGE_CHARSET, "UTF-8")) utf8_mode = 1;
#if defined EJUDGE_NEW_SERVER_SOCKET
  if (!ejudge_config->new_server_socket)
    ejudge_config->new_server_socket = xstrdup(EJUDGE_NEW_SERVER_SOCKET);
#endif
  if (!ejudge_config->new_server_socket)
    ejudge_config->new_server_socket=xstrdup(EJUDGE_NEW_SERVER_SOCKET_DEFAULT);

#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!ejudge_config->contests_home_dir)
    ejudge_config->contests_home_dir = xstrdup(EJUDGE_CONTESTS_HOME_DIR);
#endif
  setup_log_file();
  setup_metrics_file(ejudge_config);

  info("ej-contests %s, compiled %s", compile_version, compile_date);

  params.socket_path = ejudge_config->new_server_socket;
  params.log_path = ejudge_config->new_server_log;
  if (ejudge_config->contests_ws_port > 0) {
    params.ws_port = ejudge_config->contests_ws_port;
  }

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

  idc_init(&main_id_cache);
  if (!(state = nsf_init(&params, 0, server_start_time))) return 1;
  setup_spool_dirs(ejudge_config, state);
  if (nsf_prepare(state) < 0) return 1;
  nsf_main_loop(state);
  restart_flag = nsf_is_restart_requested(state);
  ns_unload_contests();
  nsf_cleanup(state);
  nsdb_default->iface->close(nsdb_default->data);

  if (restart_flag) start_restart();

  return 0;
}
