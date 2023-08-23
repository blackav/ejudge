/* -*- mode: c -*- */

/* Copyright (C) 2011-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/version.h"
#include "ejudge/ej_limits.h"
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"
#include "ejudge/super_proto.h"
#include "ejudge/mischtml.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist.h"
#include "ejudge/misctext.h"
#include "ejudge/errlog.h"
#include "ejudge/xml_utils.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/super_html_6.h"
#include "ejudge/meta/super_html_6_meta.h"
#include "ejudge/meta_generic.h"
#include "ejudge/charsets.h"
#include "ejudge/csv.h"
#include "ejudge/bitset.h"
#include "ejudge/fileutl.h"
#include "ejudge/polygon_packet.h"
#include "ejudge/prepare.h"
#include "ejudge/ej_process.h"
#include "ejudge/problem_config.h"
#include "ejudge/mime_type.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <stdarg.h>
#include <printf.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <signal.h>

#define ARMOR(s)  html_armor_buf(&ab, (s))
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

#define FIRST_COOKIE(u) ((struct userlist_cookie*) (u)->cookies->first_down)
#define NEXT_COOKIE(c)  ((struct userlist_cookie*) (c)->b.right)
#define FIRST_CONTEST(u) ((struct userlist_contest*)(u)->contests->first_down)
#define NEXT_CONTEST(c)  ((struct userlist_contest*)(c)->b.right)

void
super_html_6_force_link()
{
}

unsigned char *
ss_url_unescaped(
        unsigned char *buf,
        size_t size,
        const struct http_request_info *phr,
        int action,
        int op,
        const char *format,
        ...)
{
  unsigned char fbuf[1024];
  unsigned char abuf[64];
  unsigned char obuf[64];
  const unsigned char *sep = "";
  va_list args;

  fbuf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(fbuf, sizeof(fbuf), format, args);
    va_end(args);
  }
  if (fbuf[0]) sep = "&";

  abuf[0] = 0;
  if (action > 0) snprintf(abuf, sizeof(abuf), "&action=%d", action);
  obuf[0] = 0;
  if (op > 0) snprintf(obuf, sizeof(obuf), "&op=%d", op);

  snprintf(buf, size, "%s?SID=%016llx%s%s%s%s", phr->self_url,
           phr->session_id, abuf, obuf, sep, fbuf);
  return buf;
}

void
ss_redirect(
        FILE *fout,
        struct http_request_info *phr,
        int new_op,
        const unsigned char *extra)
{
  unsigned char url[1024];

  if (extra && *extra) {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, "%s", extra);
  } else {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, 0);
  }

  if (phr->client_key) {
    fprintf(fout, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", phr->client_key);
  }
  fprintf(fout, "Location: %s\n", url);
  putc('\n', fout);
}

void
ss_redirect_2(
        FILE *fout,
        struct http_request_info *phr,
        int new_op,
        int contest_id,
        int group_id,
        int other_user_id,
        const unsigned char *marked_str)
{
  unsigned char url[1024];
  char *o_str = 0;
  size_t o_len = 0;
  FILE *o_out = 0;

  o_out = open_memstream(&o_str, &o_len);
  if (contest_id > 0) {
    fprintf(o_out, "&contest_id=%d", contest_id);
  }
  if (group_id > 0) {
    fprintf(o_out, "&group_id=%d", group_id);
  }
  if (other_user_id > 0) {
    fprintf(o_out, "&other_user_id=%d", other_user_id);
  }
  if (marked_str && *marked_str) {
    fprintf(o_out, "&marked=%s", marked_str);
  }
  fclose(o_out); o_out = 0;

  if (o_str && *o_str) {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, "%s", o_str);
  } else {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, 0);
  }

  xfree(o_str); o_str = 0; o_len = 0;

  if (phr->client_key) {
    fprintf(fout, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", phr->client_key);
  }
  fprintf(fout, "Location: %s\n", url);
  putc('\n', fout);
}

static void
ss_redirect_3(
        FILE *fout,
        struct http_request_info *phr,
        int action,
        const char *format, ...)
  __attribute__((format(printf, 4, 5)));
static void
ss_redirect_3(
        FILE *fout,
        struct http_request_info *phr,
        int action,
        const char *format, ...)
{
  unsigned char buf[1024];
  va_list args;

  fprintf(fout, "Location: %s?SID=%016llx", phr->self_url, phr->session_id);
  if (action > 0) {
    fprintf(fout, "&action=%d", action);
  }
  if (format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    fprintf(fout, "&%s", buf);
  }
  fprintf(fout, "\n");
  if (phr->client_key) {
    fprintf(fout, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", phr->client_key);
  }
  putc('\n', fout);
}

static unsigned char *
fix_string(const unsigned char *s)
{
  if (!s) return NULL;

  int len = strlen(s);
  if (len < 0) return NULL;

  while (len > 0 && (s[len - 1] <= ' ' || s[len - 1] == 127)) --len;
  if (len <= 0) return xstrdup("");

  int i = 0;
  while (i < len && (s[i] <= ' ' || s[i] == 127)) ++i;
  if (i >= len) return xstrdup("");

  unsigned char *out = (unsigned char *) xmalloc(len + 1);
  int j = 0;
  for (; i < len; ++i, ++j) {
    if (s[i] <= ' ' || s[i] == 127) {
      out[j] = ' ';
    } else {
      out[j] = s[i];
    }
  }
  out[j] = 0;

  return out;
}

static unsigned char *
fix_string_2(const unsigned char *s)
{
  if (!s) return NULL;

  int len = strlen(s);
  if (len < 0) return NULL;

  while (len > 0 && (s[len - 1] <= ' ' || s[len - 1] == 127)) --len;
  if (len <= 0) return NULL;

  int i = 0;
  while (i < len && (s[i] <= ' ' || s[i] == 127)) ++i;
  if (i >= len) return NULL;

  unsigned char *out = (unsigned char *) xmalloc(len + 1);
  int j = 0;
  for (; i < len; ++i, ++j) {
    if (s[i] <= ' ' || s[i] == 127) {
      out[j] = ' ';
    } else {
      out[j] = s[i];
    }
  }
  out[j] = 0;

  return out;
}

int
ss_get_global_caps(
        const struct http_request_info *phr,
        opcap_t *pcap)
{
  return ejudge_cfg_opcaps_find(phr->config, phr->login, pcap);
}
int
ss_get_contest_caps(
        const struct http_request_info *phr,
        const struct contest_desc *cnts,
        opcap_t *pcap)
{
  return opcaps_find(&cnts->capabilities, phr->login, pcap);
}

int
ss_is_globally_privileged(
        const struct http_request_info *phr,
        const struct userlist_user *u)
{
  opcap_t caps = 0;
  if (u->is_privileged) return 1;
  if (ejudge_cfg_opcaps_find(phr->config, u->login, &caps) >= 0) return 1;
  return 0;
}
int
ss_is_contest_privileged(
        const struct contest_desc *cnts,
        const struct userlist_user *u)
{
  opcap_t caps = 0;
  if (!cnts) return 0;
  if (opcaps_find(&cnts->capabilities, u->login, &caps) >= 0) return 1;
  return 0;
}
int
ss_is_privileged(
        const struct http_request_info *phr,
        const struct contest_desc *cnts,
        const struct userlist_user *u)
{
  opcap_t caps = 0;
  if (u->is_privileged) return 1;
  if (ejudge_cfg_opcaps_find(phr->config, u->login, &caps) >= 0) return 1;
  if (!cnts) return 0;
  if (opcaps_find(&cnts->capabilities, u->login, &caps) >= 0) return 1;
  return 0;
}

static int
ss_parse_params(
        struct http_request_info *phr,
        const struct meta_methods *mth,
        void *params)
{
  int field_id, field_type;
  void *field_ptr;
  const unsigned char *field_name;

  for (field_id = 1; field_id < mth->last_tag; ++field_id) {
    field_type = mth->get_type(field_id);
    field_ptr = mth->get_ptr_nc(params, field_id);
    field_name = mth->get_name(field_id);
    if (!field_ptr || !field_name) continue;
    switch (field_type) {
    case '0':                   /* ej_int_opt_0_t */
      hr_cgi_param_int_opt(phr, field_name, (int*) field_ptr, 0);
      break;
    case '1':                   /* ej_textbox_t */
      {
        const unsigned char *s = 0;
        if (hr_cgi_param(phr, field_name, &s) <= 0 || !s || !*s) {
          return -SSERV_ERR_INV_VALUE;
        }
        unsigned char *s2 = fix_string(s);
        if (!s2 || !*s2) {
          xfree(s2);
          return -SSERV_ERR_INV_VALUE;
        }
        *(unsigned char **) field_ptr = s2;
      }
      break;
    case '2':                   /* ej_textbox_opt_t */
      {
        const unsigned char *s = 0;
        if (hr_cgi_param(phr, field_name, &s) < 0) {
          return -SSERV_ERR_INV_VALUE;
        }
        unsigned char *s2 = fix_string(s);
        if (!s2) s2 = xstrdup("");
        *(unsigned char **) field_ptr = s2;
      }
      break;
    case '3':                   /* ej_checkbox_t */
      {
        int *ip = (int*) field_ptr;
        hr_cgi_param_int_opt(phr, field_name, ip, 0);
        if (*ip != 1) *ip = 0;
      }
      break;
    case '4':                   /* ej_int_opt_1_t */
      hr_cgi_param_int_opt(phr, field_name, (int*) field_ptr, 1);
      break;
    case '5':                   /* ej_int_opt_m1_t */
      hr_cgi_param_int_opt(phr, field_name, (int*) field_ptr, -1);
      break;
    default:
      abort();
    }
  }

  return 0;
}

struct userlist_user *
ss_get_user_info(
        struct http_request_info *phr,
        int user_id,
        int contest_id)
{
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;

  if (userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             user_id, contest_id, &xml_text) < 0 || !xml_text) {
    return NULL;
  }
  u = userlist_parse_user_str(xml_text);
  xfree(xml_text);
  return u;
}

const unsigned char * const ss_reg_status_strs[] =
{
  "<font color=\"green\">OK</font>",
  "<font color=\"magenta\">Pending</font>",
  "<font color=\"red\">Rejected</font>",
  "<font color=\"red\"><b>Invalid status</b></font>",
};
const unsigned char * const ss_flag_op_legends[] =
{
  "Do nothing", "Clear", "Set", "Toggle", NULL,
};

unsigned char *
ss_collect_marked_set(
        struct http_request_info *phr,
        bitset_t *pms)
{
  const unsigned char *s = 0;

  if (hr_cgi_param(phr, "selected_users", &s) > 0 && s) {
    const unsigned char *p = s;
    int max_user_id = -1;
    while (1) {
      int n, v;
      if (sscanf(p, "%d%n", &v, &n) != 1) break;
      p += n;
      if (v > 0 && v < 10000000 && v > max_user_id) {
        max_user_id = v;
      }
      if (*p == ',') ++p;
    }
    if (max_user_id <= 0) {
      return bitset_url_encode(pms);
    }
    bitset_init(pms, max_user_id + 1);
    p = s;
    while (1) {
      int n, v;
      if (sscanf(p, "%d%n", &v, &n) != 1) break;
      p += n;
      if (v > 0 && v < 10000000) {
        bitset_on(pms, v);
      }
      if (*p == ',') ++p;
    }
    return bitset_url_encode(pms);
  }

  if (hr_cgi_param(phr, "marked", &s) > 0 && s) {
    bitset_url_decode(s, pms);
  }

  int min_user_id = 0;
  int max_user_id = 0;
  hr_cgi_param_int_opt(phr, "min_user_id", &min_user_id, 0);
  hr_cgi_param_int_opt(phr, "max_user_id", &max_user_id, 0);
  if (min_user_id <= 0 || min_user_id > EJ_MAX_USER_ID
      || max_user_id <= 0 || max_user_id > EJ_MAX_USER_ID
      || min_user_id > max_user_id) return bitset_url_encode(pms);

  bitset_resize(pms, max_user_id + 1);
  for (int i = min_user_id; i <= max_user_id; ++i)
    bitset_off(pms, i);

  for (int i = 0; i < phr->param_num; ++i) {
    if (!strncmp(phr->param_names[i], "user_", 5)) {
      int user_id = 0, n = 0;
      if (sscanf(phr->param_names[i] + 5, "%d%n", &user_id, &n) == 1
          && !phr->param_names[i][n + 5]
          && user_id >= min_user_id
          && user_id <= max_user_id) {
        if (phr->param_sizes[i] == 1 && phr->params[i][0] == '1') {
          bitset_on(pms, user_id);
        }
      }
    }
  }
  return bitset_url_encode(pms);
}

int
super_serve_op_USER_FILTER_CHANGE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  long long total_count = 0;
  int user_offset = 0;
  int user_count = 0;
  int value, r;
  int contest_id = 0, group_id = 0;
  const struct contest_desc *cnts = 0;
  opcap_t gcaps = 0;
  opcap_t caps = 0;
  bitset_t marked = BITSET_INITIALIZER;
  unsigned char *marked_str = 0;
  int notfirst = 0;
  FILE *extra_f = 0;
  char *extra_t = 0;
  size_t extra_z = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  marked_str = ss_collect_marked_set(phr, &marked);

  if (contest_id < 0) contest_id = 0;
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (group_id < 0) group_id = 0;

  extra_f = open_memstream(&extra_t, &extra_z);
  if (contest_id > 0) {
    fprintf(extra_f, "contest_id=%d", contest_id);
    notfirst = 1;
  }
  if (group_id > 0) {
    if (notfirst) putc('&', extra_f);
    notfirst = 1;
    fprintf(extra_f, "group_id=%d", group_id);
  }
  if (marked_str && *marked_str) {
    if (notfirst) putc('&', extra_f);
    notfirst = 1;
    fprintf(extra_f, "marked=%s", marked_str);
  }
  fclose(extra_f); extra_f = 0;

  if (ss_get_global_caps(phr, &gcaps) >= 0 && opcaps_check(gcaps, OPCAP_LIST_USERS) >= 0) {
    // this user can view the full user list and the user list for any contest
  } else if (!cnts) {
    // user without global OPCAP_LIST_USERS capability cannot view the full user list
    FAIL(SSERV_ERR_PERM_DENIED);
  } else if (ss_get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_LIST_USERS) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (!phr->userlist_clnt) {
    goto cleanup;
  }
  if ((r = userlist_clnt_get_count(phr->userlist_clnt, ULS_GET_USER_COUNT,
                                   contest_id, group_id, 0,
                                   // FIXME: fill these fields
                                   -1 /* filter_field */, 0 /* filter_op */,
                                   &total_count)) < 0) {
    err("set_user_filter: get_count failed: %d", -r);
    goto cleanup;
  }
  if (total_count <= 0) goto cleanup;
  if (phr->ss->user_filter_set) {
    user_offset = phr->ss->user_offset;
    user_count = phr->ss->user_count;
  }
  if (user_count <= 0) user_count = 20;
  if (user_count > 200) user_count = 200;

  switch (phr->action) {
  case SSERV_CMD_USER_FILTER_CHANGE_ACTION:
    if (hr_cgi_param_int(phr, "user_offset", &value) >= 0) {
      user_offset = value;
    }
    if (hr_cgi_param_int(phr, "user_count", &value) >= 0) {
      user_count = value;
    }
    if (user_count <= 0) user_count = 20;
    if (user_count > 200) user_count = 200;
    break;

  case SSERV_CMD_USER_FILTER_FIRST_PAGE_ACTION:
    user_offset = 0;
    break;
  case SSERV_CMD_USER_FILTER_PREV_PAGE_ACTION:
    user_offset -= user_count;
    break;
  case SSERV_CMD_USER_FILTER_NEXT_PAGE_ACTION:
    user_offset += user_count;
    break;
  case SSERV_CMD_USER_FILTER_LAST_PAGE_ACTION:
    user_offset = total_count;
    break;
  }

  if (user_offset + user_count > total_count) {
    user_offset = total_count - user_count;
  }
  if (user_offset < 0) user_offset = 0;
  phr->ss->user_filter_set = 1;
  phr->ss->user_offset = user_offset;
  phr->ss->user_count = user_count;

cleanup:
  ss_redirect(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, extra_t);
  bitset_free(&marked);
  xfree(marked_str);
  if (extra_f) fclose(extra_f);
  xfree(extra_t);
  return retval;
}

int
super_serve_op_USER_JUMP_CONTEST_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0, group_id = 0, jump_contest_id = 0;
  const struct contest_desc *cnts = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "jump_contest_id", &jump_contest_id, 0);

  if (jump_contest_id < 0) jump_contest_id = 0;
  if (jump_contest_id > 0 && (contests_get(jump_contest_id, &cnts) < 0 || !cnts)) {
    cnts = 0;
    jump_contest_id = contest_id;
    if (jump_contest_id > 0 && (contests_get(jump_contest_id, &cnts) < 0 || !cnts)) {
      jump_contest_id = 0;
    }
  }

  ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, jump_contest_id, group_id, 0, NULL);

  return retval;
}

int
super_serve_op_USER_JUMP_GROUP_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  int contest_id = 0, group_id = 0, jump_group_id = 0, real_jump_group_id = 0;
  unsigned char *xml_text = NULL;
  struct userlist_list *users = NULL;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "jump_group_id", &jump_group_id, 0);

  if (jump_group_id < 0) jump_group_id = 0;
  if (group_id < 0) group_id = 0;

  if (jump_group_id > 0) {
    if (!phr->userlist_clnt) FAIL(SSERV_ERR_DB_ERROR);
    r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_GET_GROUP_INFO,
                                     jump_group_id, &xml_text);
    if (r < 0) FAIL(SSERV_ERR_DB_ERROR);
    users = userlist_parse_str(xml_text);
    xfree(xml_text); xml_text = NULL;
    if (!users) FAIL(SSERV_ERR_DB_ERROR);
    if (jump_group_id < users->group_map_size && users->group_map[jump_group_id]) {
      real_jump_group_id = jump_group_id;
    }
    userlist_free(&users->b); users = NULL;
  }
  if (group_id > 0) {
    if (!phr->userlist_clnt) FAIL(SSERV_ERR_DB_ERROR);
    r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_GET_GROUP_INFO,
                                     group_id, &xml_text);
    if (r < 0) FAIL(SSERV_ERR_DB_ERROR);
    users = userlist_parse_str(xml_text);
    xfree(xml_text); xml_text = NULL;
    if (!users) FAIL(SSERV_ERR_DB_ERROR);
    if (group_id < users->group_map_size && users->group_map[group_id]) {
      real_jump_group_id = group_id;
    }
    userlist_free(&users->b); users = NULL;
  }

cleanup:
  ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, contest_id, real_jump_group_id, 0, NULL);

  userlist_free(&users->b); users = NULL;
  xfree(xml_text); xml_text = NULL;
  return retval;
}

int
super_serve_op_USER_BROWSE_MARK_ALL_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  int contest_id = 0, group_id = 0;
  bitset_t marked = BITSET_INITIALIZER;
  unsigned char *marked_str = 0;
  const struct contest_desc *cnts = 0;
  int user_id = 0;
  struct userlist_list *users = 0;
  unsigned char *xml_text = 0;
  int notfirst = 0;
  FILE *extra_f = 0;
  char *extra_t = 0;
  size_t extra_z = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  marked_str = ss_collect_marked_set(phr, &marked);

  if (contests_get(contest_id, &cnts) < 0 || !cnts) {
    contest_id = 0;
  }
  if (group_id < 0) group_id = 0;

  if (phr->action == SSERV_CMD_USER_BROWSE_UNMARK_ALL_ACTION) {
    xfree(marked_str); marked_str = 0;
    goto cleanup;
  }

  // get the IDs of all users registered for contest
  r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_LIST_ALL_USERS, cnts->id, &xml_text);
  if (r < 0 || !xml_text) goto cleanup;
  users = userlist_parse_str(xml_text);
  if (!users) goto cleanup;
  xfree(xml_text); xml_text = 0;
  bitset_resize(&marked, users->user_map_size);

  if (phr->action == SSERV_CMD_USER_BROWSE_MARK_ALL_ACTION) {
    for (user_id = 1; user_id < users->user_map_size; ++user_id) {
      if (users->user_map[user_id]) {
        bitset_on(&marked, user_id);
      }
    }
  } else if (phr->action == SSERV_CMD_USER_BROWSE_TOGGLE_ALL_ACTION) {
    for (user_id = 1; user_id < users->user_map_size; ++user_id) {
      if (users->user_map[user_id]) {
        bitset_toggle(&marked, user_id);
      }
    }
  }

  xfree(marked_str);
  marked_str = bitset_url_encode(&marked);

cleanup:
  extra_f = open_memstream(&extra_t, &extra_z);
  if (contest_id > 0) {
    fprintf(extra_f, "contest_id=%d", contest_id);
    notfirst = 1;
  }
  if (group_id > 0) {
    if (notfirst) putc('&', extra_f);
    notfirst = 1;
    fprintf(extra_f, "group_id=%d", group_id);
  }
  if (marked_str && *marked_str) {
    if (notfirst) putc('&', extra_f);
    notfirst = 1;
    fprintf(extra_f, "marked=%s", marked_str);
  }
  fclose(extra_f); extra_f = 0;
  ss_redirect(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, extra_t);
  xfree(marked_str);
  bitset_free(&marked);
  if (extra_f) fclose(extra_f);
  xfree(extra_t);
  userlist_free(&users->b); users = 0;
  xfree(xml_text);
  return retval;
}

/*
handles: USER_SEL_RANDOM_PASSWD_PAGE
         USER_SEL_CLEAR_CNTS_PASSWD_PAGE
         USER_SEL_RANDOM_CNTS_PASSWD_PAGE
         USER_SEL_DELETE_REG_PAGE
         USER_SEL_CHANGE_REG_STATUS_PAGE
         USER_SEL_CHANGE_REG_FLAGS_PAGE
         USER_SEL_CREATE_REG_PAGE
         USER_SEL_CREATE_REG_AND_COPY_PAGE
         USER_SEL_ADD_TO_GROUP_PAGE
 */

int
super_serve_op_USER_SEL_RANDOM_PASSWD_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  int contest_id = 0, group_id = 0;
  bitset_t marked = BITSET_INITIALIZER;
  unsigned char *marked_str = 0;
  const struct contest_desc *cnts = 0, *other_cnts = 0;
  int status = -1;
  int invisible_op = 0, banned_op = 0, locked_op = 0, incomplete_op = 0, disqualified_op = 0;
  int privileged_op = 0, reg_readonly_op = 0;
  int clear_mask = 0, set_mask = 0, toggle_mask = 0;
  int other_contest_id = 0;
  int other_group_id = 0;
  opcap_t gcaps = 0, caps = 0, rcaps = 0;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  int user_id = 0, user_count = 0;
  const struct userlist_user *u = 0;
  const struct userlist_contest *reg = 0;
  int include_privileged = 0, include_invisible = 0, include_banned = 0, include_locked = 0, include_disqualified = 0;
  int include_reg_privileged = 0, include_reg_readonly = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  marked_str = ss_collect_marked_set(phr, &marked);

  if (contest_id < 0) contest_id = 0;
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (group_id < 0) group_id = 0;
  if (group_id > 0) {
    r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_GET_GROUP_INFO, group_id, &xml_text);
    if (r >= 0) {
      users = userlist_parse_str(xml_text);
      if (users && group_id < users->group_map_size && users->group_map[group_id]) {
        // ...
      } else {
        group_id = 0;
      }
    } else {
      group_id = 0;
    }
    userlist_free(&users->b); users = 0;
    xfree(xml_text); xml_text = 0;
  }

  hr_cgi_param_int_opt(phr, "include_privileged", &include_privileged, 0);
  if (include_privileged != 1) include_privileged = 0;
  hr_cgi_param_int_opt(phr, "include_invisible", &include_invisible, 0);
  if (include_invisible != 1) include_invisible = 0;
  hr_cgi_param_int_opt(phr, "include_banned", &include_banned, 0);
  if (include_banned != 1) include_banned = 0;
  hr_cgi_param_int_opt(phr, "include_locked", &include_locked, 0);
  if (include_locked != 1) include_locked = 0;
  hr_cgi_param_int_opt(phr, "include_disqualified", &include_disqualified, 0);
  if (include_disqualified != 1) include_disqualified = 0;
  hr_cgi_param_int_opt(phr, "include_reg_privileged", &include_reg_privileged, 0);
  if (include_reg_privileged != 1) include_reg_privileged = 0;
  hr_cgi_param_int_opt(phr, "include_reg_readonly", &include_reg_readonly, 0);
  if (include_reg_readonly != 1) include_reg_readonly = 0;

  /* additional parameters */
  switch (phr->action) {
  case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_ACTION:
    hr_cgi_param_int_opt(phr, "status", &status, -1);
    if (status < 0 || status >= USERLIST_REG_LAST) FAIL(SSERV_ERR_INV_VALUE);
    break;
  case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION:
    hr_cgi_param_int_opt(phr, "invisible_op", &invisible_op, 0);
    hr_cgi_param_int_opt(phr, "banned_op", &banned_op, 0);
    hr_cgi_param_int_opt(phr, "locked_op", &locked_op, 0);
    hr_cgi_param_int_opt(phr, "incomplete_op", &incomplete_op, 0);
    hr_cgi_param_int_opt(phr, "disqualified_op", &disqualified_op, 0);
    hr_cgi_param_int_opt(phr, "privileged_op", &privileged_op, 0);
    hr_cgi_param_int_opt(phr, "reg_readonly_op", &reg_readonly_op, 0);
    if (invisible_op < 0 || invisible_op > 3) invisible_op = 0;
    if (banned_op < 0 || banned_op > 3) banned_op = 0;
    if (locked_op < 0 || locked_op > 3) locked_op = 0;
    if (incomplete_op < 0 || incomplete_op > 3) incomplete_op = 0;
    if (disqualified_op < 0 || disqualified_op > 3) disqualified_op = 0;
    if (privileged_op < 0 || privileged_op > 3) privileged_op = 0;
    if (reg_readonly_op < 0 || reg_readonly_op > 3) reg_readonly_op = 0;
    if (invisible_op == 1) {
      clear_mask |= USERLIST_UC_INVISIBLE;
    } else if (invisible_op == 2) {
      set_mask |= USERLIST_UC_INVISIBLE;
    } else if (invisible_op == 3) {
      toggle_mask |= USERLIST_UC_INVISIBLE;
    }
    if (banned_op == 1) {
      clear_mask |= USERLIST_UC_BANNED;
    } else if (banned_op == 2) {
      set_mask |= USERLIST_UC_BANNED;
    } else if (banned_op == 3) {
      toggle_mask |= USERLIST_UC_BANNED;
    }
    if (locked_op == 1) {
      clear_mask |= USERLIST_UC_LOCKED;
    } else if (locked_op == 2) {
      set_mask |= USERLIST_UC_LOCKED;
    } else if (locked_op == 3) {
      toggle_mask |= USERLIST_UC_LOCKED;
    }
    if (incomplete_op == 1) {
      clear_mask |= USERLIST_UC_INCOMPLETE;
    } else if (incomplete_op == 2) {
      set_mask |= USERLIST_UC_INCOMPLETE;
    } else if (incomplete_op == 3) {
      toggle_mask |= USERLIST_UC_INCOMPLETE;
    }
    if (disqualified_op == 1) {
      clear_mask |= USERLIST_UC_DISQUALIFIED;
    } else if (disqualified_op == 2) {
      set_mask |= USERLIST_UC_DISQUALIFIED;
    } else if (disqualified_op == 3) {
      toggle_mask |= USERLIST_UC_DISQUALIFIED;
    }
    if (privileged_op == 1) {
      clear_mask |= USERLIST_UC_PRIVILEGED;
    } else if (privileged_op == 2) {
      set_mask |= USERLIST_UC_PRIVILEGED;
    } else if (privileged_op == 3) {
      toggle_mask |= USERLIST_UC_PRIVILEGED;
    }
    if (reg_readonly_op == 1) {
      clear_mask |= USERLIST_UC_REG_READONLY;
    } else if (reg_readonly_op == 2) {
      set_mask |= USERLIST_UC_REG_READONLY;
    } else if (reg_readonly_op == 3) {
      toggle_mask |= USERLIST_UC_REG_READONLY;
    }
    if (!(clear_mask + set_mask + toggle_mask)) goto done;
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_ACTION:
  case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_ACTION:
    hr_cgi_param_int_opt(phr, "other_contest_id_1", &other_contest_id, 0);
    if (other_contest_id <= 0 || contests_get(other_contest_id, &other_cnts) < 0 || !other_cnts) {
      other_contest_id = 0;
    }
    if (!other_cnts) FAIL(SSERV_ERR_INV_CONTEST);
    break;
  case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_ACTION:
    hr_cgi_param_int_opt(phr, "other_group_id_1", &other_group_id, 0);
    if (other_group_id <= 0) FAIL(SSERV_ERR_INV_GROUP_ID);
    r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_GET_GROUP_INFO, other_group_id, &xml_text);
    if (r < 0) FAIL(SSERV_ERR_INV_GROUP_ID);
    users = userlist_parse_str(xml_text);
    if (!users || other_group_id >= users->group_map_size || !users->group_map[other_group_id])
      FAIL(SSERV_ERR_INV_GROUP_ID);
    userlist_free(&users->b); users = 0;
    xfree(xml_text); xml_text = 0;
    break;
  case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_ACTION:
    if (group_id <= 0) FAIL(SSERV_ERR_INV_GROUP_ID);
    break;
  }

  switch (phr->action) {
  case SSERV_CMD_USER_SEL_RANDOM_PASSWD_ACTION:
    if (ss_get_global_caps(phr, &gcaps) < 0) FAIL(SSERV_ERR_PERM_DENIED);
    if (opcaps_check(gcaps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_ACTION:
  case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_ACTION:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    ss_get_global_caps(phr, &gcaps);
    ss_get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_DELETE_REG_ACTION:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    ss_get_global_caps(phr, &gcaps);
    if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_DELETE_REG;
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_DELETE_REG;
    ss_get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0 && opcaps_check(caps, OPCAP_DELETE_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_ACTION:
  case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    ss_get_global_caps(phr, &gcaps);
    if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_EDIT_REG;
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_EDIT_REG;
    ss_get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_EDIT_REG) < 0 && opcaps_check(caps, OPCAP_EDIT_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_ACTION:
    ss_get_global_caps(phr, &gcaps);
    ss_get_contest_caps(phr, other_cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_CREATE_REG) < 0 && opcaps_check(caps, OPCAP_CREATE_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_ACTION:
    if  (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    ss_get_global_caps(phr, &gcaps);
    ss_get_contest_caps(phr, other_cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_CREATE_REG) < 0 && opcaps_check(caps, OPCAP_CREATE_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    ss_get_contest_caps(phr, cnts, &rcaps);
    rcaps |= gcaps;
    if (opcaps_check(rcaps, OPCAP_GET_USER) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_ACTION:
  case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_ACTION:
    if (ss_get_global_caps(phr, &gcaps) < 0) FAIL(SSERV_ERR_PERM_DENIED);
    if (opcaps_check(gcaps, OPCAP_EDIT_USER) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  default:
    abort();
  }

  if (!phr->userlist_clnt) FAIL(SSERV_ERR_DB_ERROR);
  r = userlist_clnt_list_users_2(phr->userlist_clnt, ULS_LIST_ALL_USERS_3,
                                 contest_id, group_id, marked_str, 0, 0,
                                 // FIXME: fill the fields
                                 -1 /* page */, -1 /* sort_field */, 0 /* sort_order */,
                                 -1 /* filter_field */, 0 /* filter_op */,
                                 &xml_text);
  if (r < 0) FAIL(SSERV_ERR_DB_ERROR);
  users = userlist_parse_str(xml_text);
  if (!users) FAIL(SSERV_ERR_DB_ERROR);

  for (user_id = 1; user_id < marked.size; ++user_id) {
    if (bitset_get(&marked, user_id)) {
      if (user_id >= users->user_map_size || !(u = users->user_map[user_id])) {
        bitset_off(&marked, user_id);
        continue;
      }
      if (contest_id > 0 && !userlist_get_user_contest(u, contest_id)) {
        bitset_off(&marked, user_id);
        continue;
      }
      if (!include_privileged && ss_is_privileged(phr, cnts, u)) {
        bitset_off(&marked, user_id);
        continue;
      }
      if (cnts && phr->action != SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION
          && (reg = userlist_get_user_contest(u, contest_id))) {
        if (((reg->flags & USERLIST_UC_INVISIBLE) && !include_invisible)
            || ((reg->flags & USERLIST_UC_BANNED) && !include_banned)
            || ((reg->flags & USERLIST_UC_LOCKED) && !include_locked)
            || ((reg->flags & USERLIST_UC_DISQUALIFIED) && !include_disqualified)
            || ((reg->flags & USERLIST_UC_PRIVILEGED) && !include_reg_privileged)
            || ((reg->flags & USERLIST_UC_REG_READONLY) && !include_reg_readonly)) {
          bitset_off(&marked, user_id);
          continue;
        }
      }
      switch (phr->action) {
      case SSERV_CMD_USER_SEL_RANDOM_PASSWD_ACTION:
        if (ss_is_privileged(phr, cnts, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0) u = 0;
        } else {
          if (opcaps_check(gcaps, OPCAP_EDIT_PASSWD) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_ACTION:
      case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_ACTION:
        if (ss_is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0) u = 0;
        } else if (ss_is_contest_privileged(cnts, u)) {
          if (opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_DELETE_REG_ACTION:
        if (ss_is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_DELETE_REG) < 0) u = 0;
        } else if (ss_is_contest_privileged(cnts, u)) {
          if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_DELETE_REG) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_ACTION:
      case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION:
        if (ss_is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_REG) < 0) u = 0;
        } else if (ss_is_contest_privileged(cnts, u)) {
          if (opcaps_check(caps, OPCAP_PRIV_EDIT_REG) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_EDIT_REG) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CREATE_REG_ACTION:
      case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_ACTION:
        if (ss_is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_CREATE_REG) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_CREATE_USER) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_ACTION:
      case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_ACTION:
        break;
      default:
        abort();
      }
      if (!u) {
        bitset_off(&marked, user_id);
        continue;
      }
      ++user_count;
    }
  }
  if (user_count <= 0) goto done;

  /* do the requested operation */
  for (user_id = 1; user_id < marked.size; ++user_id) {
    if (!bitset_get(&marked, user_id)) continue;

    r = 0;
    switch (phr->action) {
    case SSERV_CMD_USER_SEL_RANDOM_PASSWD_ACTION:
      r = userlist_clnt_register_contest(phr->userlist_clnt, ULS_RANDOM_PASSWD, user_id,
                                         contest_id, 0, 0);
      break;
    case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_ACTION:
      r = userlist_clnt_delete_field(phr->userlist_clnt, ULS_DELETE_FIELD,
                                     user_id, contest_id, 0, USERLIST_NC_TEAM_PASSWD);
      break;
    case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_ACTION:
      r = userlist_clnt_register_contest(phr->userlist_clnt, ULS_RANDOM_TEAM_PASSWD, user_id,
                                         contest_id, 0, 0);
      break;
    case SSERV_CMD_USER_SEL_DELETE_REG_ACTION:
      r = userlist_clnt_change_registration(phr->userlist_clnt, user_id, contest_id, -2, 0, 0);
      break;
    case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_ACTION:
      r = userlist_clnt_change_registration(phr->userlist_clnt, user_id, contest_id, status, 0, 0);
      break;
    case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION:
      if (clear_mask > 0 && r >= 0) {
        r = userlist_clnt_change_registration(phr->userlist_clnt, user_id, contest_id, -1, 2, clear_mask);
      }
      if (set_mask > 0 && r >= 0) {
        r = userlist_clnt_change_registration(phr->userlist_clnt, user_id, contest_id, -1, 1, set_mask);
      }
      if (toggle_mask > 0 && r >= 0) {
        r = userlist_clnt_change_registration(phr->userlist_clnt, user_id, contest_id, -1, 3, toggle_mask);
      }
      break;
    case SSERV_CMD_USER_SEL_CREATE_REG_ACTION:
      r = userlist_clnt_register_contest(phr->userlist_clnt, ULS_PRIV_REGISTER_CONTEST,
                                         user_id, other_contest_id, 0, 0);
      break;
    case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_ACTION:
      r = userlist_clnt_register_contest(phr->userlist_clnt, ULS_PRIV_REGISTER_CONTEST,
                                         user_id, other_contest_id, 0, 0);
      if (r >= 0) {
        r = userlist_clnt_copy_user_info(phr->userlist_clnt, ULS_COPY_USER_INFO, user_id, contest_id, other_contest_id);
      }
      break;
    case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_ACTION:
      r = userlist_clnt_register_contest(phr->userlist_clnt, ULS_CREATE_GROUP_MEMBER,
                                         user_id, other_group_id, 0, 0);
      break;
    case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_ACTION:
      r = userlist_clnt_register_contest(phr->userlist_clnt, ULS_DELETE_GROUP_MEMBER,
                                         user_id, group_id, 0, 0);
      break;
    default:
      abort();
    }
    if (r < 0) FAIL(SSERV_ERR_DB_ERROR);
  }

done:
  ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, contest_id, group_id, 0, NULL);

cleanup:
  userlist_free(&users->b); users = 0;
  bitset_free(&marked);
  xfree(marked_str);
  xfree(xml_text);
  return retval;
}

int
super_serve_op_USER_SEL_CANCEL_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int contest_id = 0, group_id = 0;
  bitset_t marked = BITSET_INITIALIZER;
  unsigned char *marked_str = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  marked_str = ss_collect_marked_set(phr, &marked);
  ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, contest_id, group_id, 0, marked_str);

  xfree(marked_str);
  bitset_free(&marked);
  return 0;
}

char const * const ss_member_string[] =
{
  "Contestant",
  "Reserve",
  "Coach",
  "Advisor",
  "Guest"
};
char const * const ss_member_string_pl[] =
{
  "Contestants",
  "Reserves",
  "Coaches",
  "Advisors",
  "Guests"
};

void
ss_string_row(
        FILE *out_f,
        const unsigned char *tr_class,
        int is_hidden,
        const unsigned char *td_class,
        const unsigned char *legend,
        const unsigned char *param_suffix,
        const unsigned char *str)
{
  unsigned char trcl[256];
  unsigned char tdcl[256];
  unsigned char param_name[256];
  unsigned char buf[1024];
  unsigned char onchange[1024];
  const unsigned char *checked = "";
  const unsigned char *display = "";
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  trcl[0] = 0;
  if (tr_class) {
    snprintf(trcl, sizeof(trcl), " class=\"%s\"", tr_class);
  }
  tdcl[0] = 0;
  if (td_class) {
    snprintf(tdcl, sizeof(tdcl), " class=\"%s\"", td_class);
  }
  if (!str) {
    checked = " checked=\"checked\"";
    str = "";
  }
  snprintf(param_name, sizeof(param_name), "field_%s", param_suffix);
  if (is_hidden) {
    display = " style=\"display: none;\"";
  }

  fprintf(out_f, "<tr%s%s>", trcl, display);
  fprintf(out_f, "<td%s><b>%s:</b></td>", tdcl, legend);
  fprintf(out_f, "<td%s><input type=\"checkbox\" onchange=\"checkNull('%s')\" name=\"field_null_%s\" value=\"1\"%s /></td>",
          tdcl, param_suffix, param_suffix, checked);
  snprintf(onchange, sizeof(onchange), "uncheckNull('%s')", param_suffix);
  fprintf(out_f, "<td%s>%s</td>", tdcl,
          html_input_text_js(buf, sizeof(buf), param_name, 50, onchange, "%s", ARMOR(str)));
  fprintf(out_f, "<td%s>&nbsp;</td>", tdcl);
  fprintf(out_f, "</tr>\n");
  html_armor_free(&ab);
}

const struct ss_user_row_info ss_user_flag_rows[] =
{
  { USERLIST_NN_IS_PRIVILEGED, "Globally privileged" },
  { USERLIST_NN_IS_INVISIBLE, "Globally invisible" },
  { USERLIST_NN_IS_BANNED, "Globally banned" },
  { USERLIST_NN_IS_LOCKED, "Globally locked" },
  { USERLIST_NN_SHOW_LOGIN, "Show login to everybody" },
  { USERLIST_NN_SHOW_EMAIL, "Show email to everybody" },
  { USERLIST_NN_READ_ONLY, "Globally read-only" },
  { USERLIST_NN_NEVER_CLEAN, "Do not auto-clean" },
  { USERLIST_NN_SIMPLE_REGISTRATION, "Simple registration" },
  { 0, 0 },
};

const struct ss_user_row_info ss_user_timestamp_rows[] =
{
  { USERLIST_NN_REGISTRATION_TIME, "Registration time" },
  { USERLIST_NN_LAST_LOGIN_TIME, "Last login time" },
  { USERLIST_NN_LAST_CHANGE_TIME, "Last change time" },
  { USERLIST_NN_LAST_PWDCHANGE_TIME, "Last password change time" },
  { 0, 0 },
};

const struct ss_user_row_info ss_user_info_rows[] =
{
  { USERLIST_NC_INST, "Institution name" },
  { USERLIST_NC_INST_EN, "Inst. name (En)" },
  { USERLIST_NC_INSTSHORT, "Short inst. name" },
  { USERLIST_NC_INSTSHORT_EN, "Short inst. name (En)" },
  { USERLIST_NC_INSTNUM, "Institution number" },
  { USERLIST_NC_FAC, "Faculty name" },
  { USERLIST_NC_FAC_EN, "Faculty name (En)" },
  { USERLIST_NC_FACSHORT, "Short faculty name" },
  { USERLIST_NC_FACSHORT_EN, "Short faculty name (En)" },
  { USERLIST_NC_HOMEPAGE, "Web home page" },
  { USERLIST_NC_CITY, "City" },
  { USERLIST_NC_CITY_EN, "City (En)" },
  { USERLIST_NC_COUNTRY, "Country" },
  { USERLIST_NC_COUNTRY_EN, "Country (En)" },
  { USERLIST_NC_REGION, "Region" },
  { USERLIST_NC_AREA, "Region (En)" },
  { USERLIST_NC_ZIP, "Zip code" },
  { USERLIST_NC_STREET, "Street address" },
  { USERLIST_NC_LOCATION, "Computer location" },
  { USERLIST_NC_SPELLING, "Name spelling" },
  { USERLIST_NC_PRINTER_NAME, "Printer name" },
  { USERLIST_NC_EXAM_ID, "Examination Id" },
  { USERLIST_NC_EXAM_CYPHER, "Examination cypher" },
  { USERLIST_NC_LANGUAGES, "Programming languages" },
  { USERLIST_NC_PHONE, "Contact phone" },
  { USERLIST_NC_FIELD0, "Additional field 0" },
  { USERLIST_NC_FIELD1, "Additional field 1" },
  { USERLIST_NC_FIELD2, "Additional field 2" },
  { USERLIST_NC_FIELD3, "Additional field 3" },
  { USERLIST_NC_FIELD4, "Additional field 4" },
  { USERLIST_NC_FIELD5, "Additional field 5" },
  { USERLIST_NC_FIELD6, "Additional field 6" },
  { USERLIST_NC_FIELD7, "Additional field 7" },
  { USERLIST_NC_FIELD8, "Additional field 8" },
  { USERLIST_NC_FIELD9, "Additional field 9" },
  { USERLIST_NC_AVATAR_STORE, "Avatar store type" },
  { USERLIST_NC_AVATAR_ID, "Avatar ID" },
  { USERLIST_NC_AVATAR_SUFFIX, "Avatar Suffix" },

  { 0, 0 },
};

const struct ss_user_row_info ss_user_info_stat_rows[] =
{
  { USERLIST_NC_CREATE_TIME, "Create time" },
  { USERLIST_NC_LAST_LOGIN_TIME, "Last login time" },
  { USERLIST_NC_LAST_CHANGE_TIME, "Last change time" },
  { USERLIST_NC_LAST_PWDCHANGE_TIME, "Last password change time" },

  { 0, 0 },
};

const struct ss_user_row_info ss_member_rows[] =
{
  { USERLIST_NM_FIRSTNAME, "First name" },
  { USERLIST_NM_FIRSTNAME_EN, "First name (En)" },
  { USERLIST_NM_MIDDLENAME, "Middle name" },
  { USERLIST_NM_MIDDLENAME_EN, "Middle name (En)" },
  { USERLIST_NM_SURNAME, "Surname" },
  { USERLIST_NM_SURNAME_EN, "Surname (En)" },
  { USERLIST_NM_GROUP, "Academic group" },
  { USERLIST_NM_GROUP_EN, "Academic group (En)" },
  { USERLIST_NM_EMAIL, "Email" },
  { USERLIST_NM_HOMEPAGE, "Web home page" },
  { USERLIST_NM_OCCUPATION, "Occupation" },
  { USERLIST_NM_OCCUPATION_EN, "Occupation (En)" },
  { USERLIST_NM_DISCIPLINE, "Discipline" },
  { USERLIST_NM_INST, "Institution name" },
  { USERLIST_NM_INST_EN, "Institution name (En)" },
  { USERLIST_NM_INSTSHORT, "Short inst. name" },
  { USERLIST_NM_INSTSHORT_EN, "Short inst. name (En)" },
  { USERLIST_NM_FAC, "Faculty name" },
  { USERLIST_NM_FAC_EN, "Faculty name (En)" },
  { USERLIST_NM_FACSHORT, "Short faculty name" },
  { USERLIST_NM_FACSHORT_EN, "Short faculty name (En)" },
  { USERLIST_NM_PHONE, "Phone" },

  { 0, 0 },
};

const struct ss_user_row_info ss_member_date_rows[] =
{
  { USERLIST_NM_BIRTH_DATE, "Date of birth" },
  { USERLIST_NM_ENTRY_DATE, "Date of entry" },
  { USERLIST_NM_GRADUATION_DATE, "Graduation date" },

  { 0, 0 },
};

const struct ss_user_row_info ss_member_time_rows[] =
{
  { USERLIST_NM_CREATE_TIME, "Create time" },
  { USERLIST_NM_LAST_CHANGE_TIME, "Last change time" },

  { 0, 0 },
};

int
super_serve_op_USER_CHANGE_PASSWORD_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  int contest_id = 0, group_id = 0, other_user_id = 0, next_op = 0, usesha1 = 0;
  const struct contest_desc *cnts = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  opcap_t caps = 0;
  const unsigned char *s = 0;
  unsigned char *admin_password = NULL;
  unsigned char *reg_password1 = 0;
  unsigned char *reg_password2 = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "next_op", &next_op, 0);
  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }

  s = NULL;
  if (hr_cgi_param(phr, "admin_password", &s) <= 0 || !s) FAIL(SSERV_ERR_PERM_DENIED);
  admin_password = fix_string(s);
  if (!s || !*s) FAIL(SSERV_ERR_PERM_DENIED);

  s = 0;
  if (hr_cgi_param(phr, "reg_password1", &s) <= 0 || !s) FAIL(SSERV_ERR_UNSPEC_PASSWD1);
  reg_password1 = fix_string(s);
  if (!reg_password1 || !*reg_password1) FAIL(SSERV_ERR_UNSPEC_PASSWD1);
  if (strlen(reg_password1) > 1024) FAIL(SSERV_ERR_INV_PASSWD1);
  s = 0;
  if (hr_cgi_param(phr, "reg_password2", &s) <= 0 || !s) FAIL(SSERV_ERR_UNSPEC_PASSWD2);
  reg_password2 = fix_string(s);
  if (!reg_password2 || !*reg_password2) FAIL(SSERV_ERR_UNSPEC_PASSWD2);
  if (strlen(reg_password2) > 1024) FAIL(SSERV_ERR_INV_PASSWD2);
  if (strcmp(reg_password1, reg_password2) != 0) FAIL(SSERV_ERR_PASSWDS_DIFFER);

  hr_cgi_param_int_opt(phr, "usesha1", &usesha1, 0);
  if (usesha1 != 1) usesha1 = 0;

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  if (ss_get_global_caps(phr, &caps) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) FAIL(SSERV_ERR_INV_USER_ID);
  if (!phr->userlist_clnt) FAIL(SSERV_ERR_NO_CONNECTION);
  r = userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, 0, &xml_text);
  if (r < 0) {
    if (r == -ULS_ERR_BAD_UID) FAIL(SSERV_ERR_INV_USER_ID);
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (!(u = userlist_parse_user_str(xml_text))) FAIL(SSERV_ERR_DB_ERROR);
  if (ss_is_globally_privileged(phr, u) && opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);
  else if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  r = ULS_PRIV_SET_REG_PASSWD_PLAIN;
  if (usesha1) r = ULS_PRIV_SET_REG_PASSWD_SHA1;

  r = userlist_clnt_set_passwd(phr->userlist_clnt, r, other_user_id, 0, phr->user_id, "", reg_password1, admin_password);
  if (r < 0) FAIL(SSERV_ERR_DB_ERROR);

  if (next_op == SSERV_CMD_USER_DETAIL_PAGE) {
    ss_redirect_2(out_f, phr, SSERV_CMD_USER_DETAIL_PAGE, contest_id, group_id, other_user_id, NULL);
  } else {
    ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, contest_id, group_id, 0, NULL);
  }

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  xfree(reg_password1); reg_password1 = 0;
  xfree(reg_password2); reg_password2 = 0;
  xfree(admin_password); admin_password = NULL;
  return retval;
}

int
super_serve_op_USER_CHANGE_CNTS_PASSWORD_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  int contest_id = 0, group_id = 0, other_user_id = 0;
  int next_op = 0;
  const struct contest_desc *cnts = 0;
  int useregpasswd = 0, settonull = 0, usesha1 = 0;
  unsigned char *cnts_password1 = 0;
  unsigned char *cnts_password2 = 0;
  unsigned char *admin_password = NULL;
  const unsigned char *s = 0;
  opcap_t gcaps = 0, ccaps = 0, fcaps = 0;
  struct userlist_user *u = 0;
  unsigned char *xml_text = 0;

  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contest_id <= 0 || contests_get(contest_id, &cnts) < 0 || !cnts)
    FAIL(SSERV_ERR_INV_CONTEST);

  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "next_op", &next_op, 0);

  hr_cgi_param_int_opt(phr, "useregpasswd", &useregpasswd, 0);
  if (useregpasswd != 1) useregpasswd = 0;
  hr_cgi_param_int_opt(phr, "settonull", &settonull, 0);
  if (settonull != 1) settonull = 0;
  hr_cgi_param_int_opt(phr, "usesha1", &usesha1, 0);
  if (usesha1 != 1) usesha1 = 0;

  s = NULL;
  if (hr_cgi_param(phr, "admin_password", &s) <= 0 || !s) FAIL(SSERV_ERR_PERM_DENIED);
  if (!s || !*s) FAIL(SSERV_ERR_PERM_DENIED);
  admin_password = fix_string(s);

  if (!useregpasswd && !settonull) {
    s = 0;
    if (hr_cgi_param(phr, "cnts_password1", &s) <= 0 || !s) FAIL(SSERV_ERR_UNSPEC_PASSWD1);
    cnts_password1 = fix_string(s);
    if (!cnts_password1 || !*cnts_password1) FAIL(SSERV_ERR_UNSPEC_PASSWD1);
    if (strlen(cnts_password1) > 1024) FAIL(SSERV_ERR_INV_PASSWD1);
    s = 0;
    if (hr_cgi_param(phr, "cnts_password2", &s) <= 0 || !s) FAIL(SSERV_ERR_UNSPEC_PASSWD2);
    cnts_password2 = fix_string(s);
    if (!cnts_password2 || !*cnts_password2) FAIL(SSERV_ERR_UNSPEC_PASSWD2);
    if (strlen(cnts_password2) > 1024) FAIL(SSERV_ERR_INV_PASSWD2);
    if (strcmp(cnts_password1, cnts_password2) != 0) FAIL(SSERV_ERR_PASSWDS_DIFFER);
  }

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  ss_get_global_caps(phr, &gcaps);
  ss_get_contest_caps(phr, cnts, &ccaps);
  fcaps = gcaps | ccaps;
  if (opcaps_check(fcaps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(fcaps, OPCAP_PRIV_EDIT_PASSWD) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) FAIL(SSERV_ERR_INV_USER_ID);
  if (!phr->userlist_clnt) FAIL(SSERV_ERR_NO_CONNECTION);
  r = userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, contest_id, &xml_text);
  if (r < 0) {
    if (r == -ULS_ERR_BAD_UID) FAIL(SSERV_ERR_INV_USER_ID);
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (!(u = userlist_parse_user_str(xml_text))) FAIL(SSERV_ERR_DB_ERROR);

  if (ss_is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (ss_is_contest_privileged(cnts, u)) {
    if (opcaps_check(fcaps, OPCAP_PRIV_EDIT_PASSWD) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(fcaps, OPCAP_EDIT_PASSWD) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (settonull) {
    r = userlist_clnt_delete_field(phr->userlist_clnt, ULS_DELETE_FIELD,
                                   other_user_id, contest_id, 0,
                                   USERLIST_NC_TEAM_PASSWD);
  } else if (useregpasswd) {
    r = userlist_clnt_register_contest(phr->userlist_clnt, ULS_COPY_TO_TEAM, other_user_id,
                                       contest_id, 0, 0);
  } else {
    r = ULS_PRIV_SET_CNTS_PASSWD_PLAIN;
    if (usesha1) r = ULS_PRIV_SET_CNTS_PASSWD_SHA1;

    r = userlist_clnt_set_passwd(phr->userlist_clnt, r, other_user_id, contest_id, phr->user_id, "", cnts_password1, admin_password);
  }
  if (r < 0) FAIL(SSERV_ERR_DB_ERROR);

  if (next_op == SSERV_CMD_USER_DETAIL_PAGE) {
    ss_redirect_2(out_f, phr, SSERV_CMD_USER_DETAIL_PAGE, contest_id, group_id, other_user_id, NULL);
  } else {
    ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, contest_id, group_id, 0, NULL);
  }

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  xfree(cnts_password1); cnts_password1 = 0;
  xfree(cnts_password2); cnts_password2 = 0;
  xfree(admin_password);
  return retval;
}

int
super_serve_op_USER_CREATE_ONE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  opcap_t caps = 0;
  const struct contest_desc *cnts = 0;
  int other_user_id = 0;
  unsigned char *xml_text = 0;

  struct ss_op_param_USER_CREATE_ONE_ACTION params;
  memset(&params, 0, sizeof(params));
  retval = ss_parse_params(phr, &meta_ss_op_param_USER_CREATE_ONE_ACTION_methods, &params);
  if (retval < 0) goto cleanup;

  if (params.contest_id > 0) {
    cnts = 0;
    if (contests_get(params.contest_id, &cnts) < 0 || !cnts) {
      params.contest_id = 0;
    }
  }
  cnts = 0;
  if (params.reg_cnts_create) {
    if (contests_get(params.other_contest_id_1, &cnts) < 0 || !cnts) {
      FAIL(SSERV_ERR_INV_CONTEST);
    }
  } else {
    params.other_contest_id_1 = 0;
  }

  if (params.group_create) {
    r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_LIST_GROUP_USERS,
                                     params.other_group_id, &xml_text);
    if (r < 0) FAIL(SSERV_ERR_INV_GROUP_ID);
  } else {
    params.other_group_id = 0;
  }

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }
  if (cnts) {
    if (ss_get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_REG) < 0) {
      FAIL(SSERV_ERR_PERM_DENIED);
    }
  }

  if (!params.other_login || !*params.other_login) FAIL(SSERV_ERR_UNSPEC_LOGIN);
  if (!params.reg_password1 || !*params.reg_password1) FAIL(SSERV_ERR_UNSPEC_PASSWD1);
  if (!params.reg_password2 || !*params.reg_password2) FAIL(SSERV_ERR_UNSPEC_PASSWD2);
  if (strcmp(params.reg_password1, params.reg_password2) != 0) FAIL(SSERV_ERR_PASSWDS_DIFFER);
  if (params.cnts_status < 0 || params.cnts_status >= USERLIST_REG_LAST) params.cnts_status = USERLIST_REG_PENDING;
  if (cnts && !cnts->disable_team_password && !params.cnts_use_reg_passwd && !params.cnts_null_passwd) {
    if (!params.cnts_password1 || !*params.cnts_password1) FAIL(SSERV_ERR_UNSPEC_PASSWD1);
    if (!params.cnts_password2 || !*params.cnts_password2) FAIL(SSERV_ERR_UNSPEC_PASSWD2);
    if (strcmp(params.cnts_password1, params.cnts_password2) != 0) FAIL(SSERV_ERR_PASSWDS_DIFFER);
  }
  if (params.other_email && *params.other_email && !is_valid_email_address(params.other_email))
    FAIL(SSERV_ERR_INV_EMAIL);

  struct userlist_pk_create_user_2 up;
  memset(&up, 0, sizeof(up));
  up.send_email_flag = params.send_email;
  up.confirm_email_flag = params.confirm_email;
  up.use_sha1_flag = params.reg_sha1;
  up.is_privileged_flag = params.field_1;
  up.is_invisible_flag = params.field_2;
  up.is_banned_flag = params.field_3;
  up.is_locked_flag = params.field_4;
  up.show_login_flag = params.field_5;
  up.show_email_flag = params.field_6;
  up.read_only_flag = params.field_7;
  up.never_clean_flag = params.field_8;
  up.simple_registration_flag = params.field_9;
  up.contest_id = params.other_contest_id_1;
  up.cnts_status = params.cnts_status;
  up.cnts_is_invisible_flag = params.is_invisible;
  up.cnts_is_banned_flag = params.is_banned;
  up.cnts_is_locked_flag = params.is_locked;
  up.cnts_is_incomplete_flag = params.is_incomplete;
  up.cnts_is_disqualified_flag = params.is_disqualified;
  up.cnts_is_privileged_flag = params.is_privileged;
  up.cnts_is_reg_readonly_flag = params.is_reg_readonly;
  up.cnts_use_reg_passwd_flag = params.cnts_use_reg_passwd;
  up.cnts_set_null_passwd_flag = params.cnts_null_passwd;
  up.cnts_use_sha1_flag = params.cnts_sha1;
  up.group_id = params.other_group_id;

  r = userlist_clnt_create_user_2(phr->userlist_clnt, ULS_CREATE_USER_2, &up,
                                  params.other_login, params.other_email,
                                  params.reg_password1, params.cnts_password1,
                                  params.cnts_name, &other_user_id);
  if (r < 0 && r == -ULS_ERR_LOGIN_USED) {
    FAIL(SSERV_ERR_DUPLICATED_LOGIN);
  }
  if (r < 0 || other_user_id <= 0) {
    FAIL(SSERV_ERR_DB_ERROR);
  }

  ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, params.contest_id, params.group_id, 0, NULL);

cleanup:
  xfree(xml_text); xml_text = 0;
  meta_destroy_fields(&meta_ss_op_param_USER_CREATE_ONE_ACTION_methods, &params);
  return retval;
}

static unsigned char **create_many_sorted_logins;
static int create_many_sort_func(const void *p1, const void *p2)
{
  return strcmp(*(const unsigned char**) p1, *(const unsigned char **) p2);
}

int
super_serve_op_USER_CREATE_MANY_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r, i;
  opcap_t caps = 0;
  const struct contest_desc *cnts = 0;
  unsigned char *xml_text = 0;
  int serial_count = 0, cur_serial;
  unsigned char **login_strs = 0;
  unsigned char buf[1024];
  unsigned char **reg_password_strs = 0;
  unsigned char **cnts_password_strs = 0;
  unsigned char **cnts_name_strs = 0;
  int other_user_id = 0;

  struct ss_op_param_USER_CREATE_MANY_ACTION params;
  memset(&params, 0, sizeof(params));
  retval = ss_parse_params(phr, &meta_ss_op_param_USER_CREATE_MANY_ACTION_methods, &params);
  if (retval < 0) goto cleanup;

  if (params.contest_id > 0) {
    cnts = 0;
    if (contests_get(params.contest_id, &cnts) < 0 || !cnts) {
      params.contest_id = 0;
    }
  }
  cnts = 0;
  if (params.reg_cnts_create) {
    if (contests_get(params.other_contest_id_1, &cnts) < 0 || !cnts) {
      FAIL(SSERV_ERR_INV_CONTEST);
    }
  } else {
    params.other_contest_id_1 = 0;
  }

  if (params.group_create) {
    r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_LIST_GROUP_USERS,
                                     params.other_group_id, &xml_text);
    if (r < 0) FAIL(SSERV_ERR_INV_GROUP_ID);
  } else {
    params.other_group_id = 0;
  }

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }
  if (cnts) {
    if (ss_get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_REG) < 0) {
      FAIL(SSERV_ERR_PERM_DENIED);
    }
  }

  if (params.first_serial < 0 || params.first_serial >= 1000000000) FAIL(SSERV_ERR_INV_FIRST_SERIAL);
  if (params.last_serial < 0 || params.last_serial >= 1000000000) FAIL(SSERV_ERR_INV_LAST_SERIAL);
  if (params.first_serial > params.last_serial) FAIL(SSERV_ERR_INV_RANGE);
  serial_count = params.last_serial - params.first_serial + 1;
  if (serial_count > 1000) FAIL(SSERV_ERR_INV_RANGE);
  if (!params.login_template || !*params.login_template) FAIL(SSERV_ERR_INV_LOGIN_TEMPLATE);

  int printf_arg_types[10];
  memset(printf_arg_types, 0, sizeof(printf_arg_types));
  int printf_arg_count = parse_printf_format(params.login_template, 10, printf_arg_types);
  if (printf_arg_count != 1) FAIL(SSERV_ERR_INV_LOGIN_TEMPLATE);
  if ((printf_arg_types[0] & ~PA_FLAG_MASK) != PA_INT) FAIL(SSERV_ERR_INV_LOGIN_TEMPLATE);

  if (create_many_sorted_logins) {
    xfree(create_many_sorted_logins);
    create_many_sorted_logins = 0;
  }
  XCALLOC(create_many_sorted_logins, serial_count);
  XCALLOC(login_strs, serial_count);
  for (i = 0, cur_serial = params.first_serial; cur_serial <= params.last_serial; ++i, ++cur_serial) {
    snprintf(buf, sizeof(buf), params.login_template, cur_serial);
    if (strlen(buf) > 1000) FAIL(SSERV_ERR_INV_LOGIN_TEMPLATE);
    login_strs[i] = xstrdup(buf);
    create_many_sorted_logins[i] = login_strs[i];
  }
  /* check login uniqueness */
  qsort(create_many_sorted_logins, serial_count, sizeof(create_many_sorted_logins), create_many_sort_func);
  for (i = 1; i < serial_count; ++i) {
    if (!strcmp(create_many_sorted_logins[i - 1], create_many_sorted_logins[i]))
      FAIL(SSERV_ERR_INV_LOGIN_TEMPLATE);
  }

  XCALLOC(reg_password_strs, serial_count);
  if (!params.reg_random) {
    if (!params.reg_password_template || !*params.reg_password_template) FAIL(SSERV_ERR_INV_REG_PASSWORD_TEMPLATE);
    memset(printf_arg_types, 0, sizeof(printf_arg_types));
    printf_arg_count = parse_printf_format(params.reg_password_template, 10, printf_arg_types);
    if (printf_arg_count != 0 && printf_arg_count != 1)
      FAIL(SSERV_ERR_INV_REG_PASSWORD_TEMPLATE);
    if (printf_arg_count == 1 && (printf_arg_types[0] & ~PA_FLAG_MASK) != PA_INT)
      FAIL(SSERV_ERR_INV_REG_PASSWORD_TEMPLATE);
    for (i = 0, cur_serial = params.first_serial; cur_serial <= params.last_serial; ++i, ++cur_serial) {
      snprintf(buf, sizeof(buf), params.reg_password_template, cur_serial);
      if (strlen(buf) > 1000) FAIL(SSERV_ERR_INV_REG_PASSWORD_TEMPLATE);
      reg_password_strs[i] = xstrdup(buf);
    }
  }

  XCALLOC(cnts_password_strs, serial_count);
  if (cnts && !cnts->disable_team_password && !params.cnts_use_reg_passwd
      && !params.cnts_null_passwd && !params.cnts_random_passwd) {
    if (!params.cnts_password_template || !*params.cnts_password_template) FAIL(SSERV_ERR_INV_CNTS_PASSWORD_TEMPLATE);
    memset(printf_arg_types, 0, sizeof(printf_arg_types));
    printf_arg_count = parse_printf_format(params.cnts_password_template, 10, printf_arg_types);
    if (printf_arg_count != 0 && printf_arg_count != 1)
      FAIL(SSERV_ERR_INV_CNTS_PASSWORD_TEMPLATE);
    if (printf_arg_count == 1 && (printf_arg_types[0] & ~PA_FLAG_MASK) != PA_INT)
      FAIL(SSERV_ERR_INV_CNTS_PASSWORD_TEMPLATE);
    for (i = 0, cur_serial = params.first_serial; cur_serial <= params.last_serial; ++i, ++cur_serial) {
      snprintf(buf, sizeof(buf), params.cnts_password_template, cur_serial);
      if (strlen(buf) > 1000) FAIL(SSERV_ERR_INV_CNTS_PASSWORD_TEMPLATE);
      cnts_password_strs[i] = xstrdup(buf);
    }
  }

  XCALLOC(cnts_name_strs, serial_count);
  if (cnts) {
    if (!params.cnts_name_template || !*params.cnts_name_template) {
      params.cnts_name_template = xstrdup(params.login_template);
    }
    memset(printf_arg_types, 0, sizeof(printf_arg_types));
    printf_arg_count = parse_printf_format(params.cnts_name_template, 10, printf_arg_types);
    if (printf_arg_count != 0 && printf_arg_count != 1)
      FAIL(SSERV_ERR_INV_CNTS_NAME_TEMPLATE);
    if (printf_arg_count == 1 && (printf_arg_types[0] & ~PA_FLAG_MASK) != PA_INT)
      FAIL(SSERV_ERR_INV_CNTS_NAME_TEMPLATE);
    for (i = 0, cur_serial = params.first_serial; cur_serial <= params.last_serial; ++i, ++cur_serial) {
      snprintf(buf, sizeof(buf), params.cnts_name_template, cur_serial);
      if (strlen(buf) > 1000) FAIL(SSERV_ERR_INV_CNTS_NAME_TEMPLATE);
      cnts_name_strs[i] = xstrdup(buf);
    }
  }

  for (i = 0, cur_serial = params.first_serial; cur_serial <= params.last_serial; ++i, ++cur_serial) {
    struct userlist_pk_create_user_2 up;
    memset(&up, 0, sizeof(up));
    up.random_password_flag = params.reg_random;
    up.use_sha1_flag = params.reg_sha1;
    up.is_privileged_flag = params.field_1;
    up.is_invisible_flag = params.field_2;
    up.is_banned_flag = params.field_3;
    up.is_locked_flag = params.field_4;
    up.show_login_flag = params.field_5;
    up.show_email_flag = params.field_6;
    up.read_only_flag = params.field_7;
    up.never_clean_flag = params.field_8;
    up.simple_registration_flag = params.field_9;
    up.contest_id = params.other_contest_id_1;
    up.cnts_status = params.cnts_status;
    up.cnts_is_invisible_flag = params.is_invisible;
    up.cnts_is_banned_flag = params.is_banned;
    up.cnts_is_locked_flag = params.is_locked;
    up.cnts_is_incomplete_flag = params.is_incomplete;
    up.cnts_is_disqualified_flag = params.is_disqualified;
    up.cnts_is_privileged_flag = params.is_privileged;
    up.cnts_is_reg_readonly_flag = params.is_reg_readonly;
    up.cnts_use_reg_passwd_flag = params.cnts_use_reg_passwd;
    up.cnts_set_null_passwd_flag = params.cnts_null_passwd;
    up.cnts_random_password_flag = params.cnts_random_passwd;
    up.cnts_use_sha1_flag = params.cnts_sha1;
    up.group_id = params.other_group_id;
    other_user_id = 0;
    r = userlist_clnt_create_user_2(phr->userlist_clnt, ULS_CREATE_USER_2, &up,
                                    login_strs[i], NULL,
                                    reg_password_strs[i], cnts_password_strs[i],
                                    cnts_name_strs[i], &other_user_id);
    if (r < 0 && r == -ULS_ERR_LOGIN_USED) {
      FAIL(SSERV_ERR_DUPLICATED_LOGIN);
    }
    if (r < 0 || other_user_id <= 0) {
      FAIL(SSERV_ERR_DB_ERROR);
    }
  }

  ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, params.contest_id, params.group_id, 0, NULL);

cleanup:
  if (login_strs) {
    for (i = 0; i < serial_count; ++i) xfree(login_strs[i]);
    xfree(login_strs); login_strs = 0;
  }
  if (reg_password_strs) {
    for (i = 0; i < serial_count; ++i) xfree(reg_password_strs[i]);
    xfree(reg_password_strs); reg_password_strs = 0;
  }
  if (cnts_password_strs) {
    for (i = 0; i < serial_count; ++i) xfree(cnts_password_strs[i]);
    xfree(cnts_password_strs); cnts_password_strs = 0;
  }
  if (cnts_name_strs) {
    for (i = 0; i < serial_count; ++i) xfree(cnts_name_strs[i]);
    xfree(cnts_name_strs); cnts_name_strs = 0;
  }
  xfree(create_many_sorted_logins); create_many_sorted_logins = 0;
  xfree(xml_text); xml_text = 0;
  meta_destroy_fields(&meta_ss_op_param_USER_CREATE_MANY_ACTION_methods, &params);
  return retval;
}

int
super_serve_op_USER_CREATE_FROM_CSV_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  opcap_t caps = 0;
  const struct contest_desc *cnts = 0;
  unsigned char *xml_text = 0;
  struct csv_file *csv_parsed = 0;
  const unsigned char *csv_text = 0;
  unsigned char *recoded_csv_text = 0;
  const unsigned char *separator = 0;
  unsigned char *login_str = 0;
  unsigned char *email_str = 0;
  unsigned char *reg_password_str = 0;
  unsigned char *cnts_password_str = 0;
  unsigned char *cnts_name_str = 0;

  struct ss_op_param_USER_CREATE_FROM_CSV_ACTION params;
  memset(&params, 0, sizeof(params));
  retval = ss_parse_params(phr, &meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_methods, &params);
  if (retval < 0) goto cleanup;

  if (params.contest_id > 0) {
    cnts = 0;
    if (contests_get(params.contest_id, &cnts) < 0 || !cnts) {
      params.contest_id = 0;
    }
  }
  cnts = 0;
  if (params.reg_cnts_create) {
    if (contests_get(params.other_contest_id_1, &cnts) < 0 || !cnts) {
      FAIL(SSERV_ERR_INV_CONTEST);
    }
  } else {
    params.other_contest_id_1 = 0;
  }

  if (params.group_create) {
    r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_LIST_GROUP_USERS,
                                     params.other_group_id, &xml_text);
    if (r < 0) FAIL(SSERV_ERR_INV_GROUP_ID);
  } else {
    params.other_group_id = 0;
  }

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }
  if (cnts) {
    if (ss_get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_REG) < 0) {
      FAIL(SSERV_ERR_PERM_DENIED);
    }
  }

  if (hr_cgi_param(phr, "csv_file", &csv_text) <= 0 || !csv_text) {
    FAIL(SSERV_ERR_INV_CSV_FILE);
  }

  if (params.charset && *params.charset) {
    int charset_id = charset_get_id(params.charset);
    if (charset_id < 0) FAIL(SSERV_ERR_INV_CHARSET);
    if (charset_id >= 0) {
      recoded_csv_text = charset_decode_to_heap(charset_id, csv_text);
      if (!recoded_csv_text) FAIL(SSERV_ERR_INV_CHARSET);
      csv_text = recoded_csv_text;
    }
  }

  separator = params.separator;
  if (!separator || !*separator) separator = ";";
  if (strlen(separator) != 1) FAIL(SSERV_ERR_INV_SEPARATOR);
  csv_parsed = csv_parse(csv_text, log_f, separator[0]);
  if (!csv_parsed) FAIL(SSERV_ERR_INV_CSV_FILE);

  if (!csv_parsed->u) {
    fprintf(log_f, "CSV file is empty\n");
    FAIL(SSERV_ERR_INV_CSV_FILE);
  }
  if (csv_parsed->u > 10000) {
    fprintf(log_f, "CSV file is too big\n");
    FAIL(SSERV_ERR_INV_CSV_FILE);
  }

  // columns: login, email, reg_password (regpassword, password), cnts_password (cntspassword), name (cnts_name, cntsname)
  int login_idx = -1, email_idx = -1, reg_password_idx = -1, cnts_password_idx = -1, cnts_name_idx = -1, cnts_contest_id_idx = -1;
  int column_count = csv_parsed->v[0].u;
  int failed = 0;
  for (int col = 0; col < column_count; ++col) {
    unsigned char *txt = fix_string(csv_parsed->v[0].v[col]);
    if (!txt || !*txt) {
      fprintf(log_f, "unidentified column %d, skipped\n", col + 1);
    } else if (!strcasecmp(txt, "login")) {
      if (login_idx >= 0) {
        fprintf(log_f, "dupicated column 'login'\n");
        failed = 1;
      } else {
        login_idx = col;
      }
    } else if (!strcasecmp(txt, "email")) {
      if (email_idx >= 0) {
        fprintf(log_f, "dupicated column 'email'\n");
        failed = 1;
      } else {
        email_idx = col;
      }
    } else if (!strcasecmp(txt, "password") || !strcasecmp(txt, "reg_password") || !strcasecmp(txt, "regpassword")) {
      if (reg_password_idx >= 0) {
        fprintf(log_f, "dupicated column 'reg_password'\n");
        failed = 1;
      } else {
        reg_password_idx = col;
      }
    } else if (!strcasecmp(txt, "cnts_password") || !strcasecmp(txt, "cntspassword")) {
      if (cnts_password_idx >= 0) {
        fprintf(log_f, "dupicated column 'cnts_password'\n");
        failed = 1;
      } else {
        cnts_password_idx = col;
      }
    } else if (!strcasecmp(txt, "cntsname") || !strcasecmp(txt, "name")) {
      if (cnts_name_idx >= 0) {
        fprintf(log_f, "dupicated column 'cnts_name'\n");
        failed = 1;
      } else {
        cnts_name_idx = col;
      }
    } else if (!strcasecmp(txt, "contest_id")) {
      if (cnts_contest_id_idx >= 0) {
        fprintf(log_f, "dupicated column 'contest_id'\n");
        failed = 1;
      } else {
        cnts_contest_id_idx = col;
      }
    } else {
      fprintf(log_f, "unidentified column %d (%s), skipped\n", col + 1, txt);
    }
    xfree(txt); txt = 0;
  }
  if (login_idx < 0) {
    fprintf(log_f, "missing column 'login'\n");
    failed = 1;
  }
  if (params.send_email && email_idx < 0) {
    fprintf(log_f, "missing column 'email'\n");
    failed = 1;
  }
  if (!params.reg_random && reg_password_idx < 0) {
    fprintf(log_f, "missing column 'reg_password'\n");
    failed = 1;
  }
  if (params.reg_random) {
    reg_password_idx = -1;
  }
  if (cnts && !cnts->disable_team_password && !params.cnts_use_reg_passwd
      && !params.cnts_null_passwd && !params.cnts_random_passwd
      && cnts_password_idx < 0) {
    fprintf(log_f, "missing column 'cnts_password'\n");
    failed = 1;
  }
  if (!cnts || cnts->disable_team_password || params.cnts_use_reg_passwd
      || params.cnts_null_passwd || params.cnts_random_passwd) {
    cnts_password_idx = -1;
  }
  if (!cnts) {
    cnts_name_idx = -1;
  }
  if (!cnts) {
    cnts_contest_id_idx = -1;
  }
  if (failed) FAIL(SSERV_ERR_INV_CSV_FILE);

  // dry run
  for (int row = 1; row < csv_parsed->u; ++row) {
    if (csv_parsed->v[row].u != column_count) {
      fprintf(log_f, "row %d contains %zu column, but %d columns expected\n",
              row + 1, csv_parsed->v[row].u, column_count);
      failed = 1;
      continue;
    }
    unsigned char *txt = fix_string(csv_parsed->v[row].v[login_idx]);
    int user_id = 0, r = 0;
    r = userlist_clnt_lookup_user(phr->userlist_clnt, txt, 0, &user_id, NULL);
    if (r < 0 && r != -ULS_ERR_INVALID_LOGIN) {
      xfree(txt); txt = 0;
      FAIL(SSERV_ERR_DB_ERROR);
    }
    if (params.register_existing <= 0 && r >= 0 && user_id > 0) {
      fprintf(log_f, "row %d: login '%s' already exists\n", row + 1, txt);
      failed = 1;
    }
    xfree(txt); txt = 0;
    if (email_idx >= 0) {
      txt = fix_string(csv_parsed->v[row].v[email_idx]);
      if (txt && *txt && !is_valid_email_address(txt)) {
        fprintf(log_f, "row %d: invalid email address\n", row + 1);
        failed = 1;
      } else if (params.send_email) {
        if (!txt || !*txt) {
          fprintf(log_f, "row %d: email is not specified\n", row + 1);
          failed = 1;
        }
      }
      xfree(txt); txt = 0;
    }
    if (reg_password_idx >= 0) {
      txt = fix_string(csv_parsed->v[row].v[reg_password_idx]);
      if (!txt || !*txt) {
        fprintf(log_f, "row %d: reg_password is not specified\n", row + 1);
        failed = 1;
      }
      xfree(txt); txt = 0;
    }
    if (cnts_password_idx >= 0) {
      txt = fix_string(csv_parsed->v[row].v[cnts_password_idx]);
      if (!txt || !*txt) {
        fprintf(log_f, "row %d: cnts_password is not specified\n", row + 1);
        failed = 1;
      }
      xfree(txt); txt = 0;
    }
    if (cnts_contest_id_idx >= 0) {
      txt = fix_string(csv_parsed->v[row].v[cnts_contest_id_idx]);
      if (txt && *txt) {
        char *eptr = NULL;
        errno = 0;
        long cur_contest_id = strtol(txt, &eptr, 10);
        const struct contest_desc *cur_cnts = NULL;
        if (*eptr || errno || (int) cur_contest_id != cur_contest_id || cur_contest_id <= 0 || contests_get(cur_contest_id, &cur_cnts) < 0 || !cur_cnts) {
          fprintf(log_f, "row %d: invalid contest_id %s\n", row + 1, txt);
          failed = 1;
        }
      }
      xfree(txt); txt = NULL;
    }
  }
  if (failed) FAIL(SSERV_ERR_INV_CSV_FILE);

  for (int row = 1; row < csv_parsed->u; ++row) {
    login_str = 0;
    email_str = 0;
    reg_password_str = 0;
    cnts_password_str = 0;
    cnts_name_str = 0;

    login_str = fix_string(csv_parsed->v[row].v[login_idx]);
    if (email_idx >= 0) email_str = fix_string(csv_parsed->v[row].v[email_idx]);
    if (reg_password_idx >= 0) reg_password_str = fix_string(csv_parsed->v[row].v[reg_password_idx]);
    if (cnts_password_idx >= 0) cnts_password_str = fix_string(csv_parsed->v[row].v[cnts_password_idx]);
    if (cnts_name_idx >= 0) cnts_name_str = fix_string(csv_parsed->v[row].v[cnts_name_idx]);
    int cur_contest_id = -1;
    if (cnts_contest_id_idx >= 0) {
      unsigned char *txt = fix_string(csv_parsed->v[row].v[cnts_contest_id_idx]);
      cur_contest_id = strtol(txt, NULL, 10);
      xfree(txt);
    }

    struct userlist_pk_create_user_2 up;
    int other_user_id = 0;
    memset(&up, 0, sizeof(up));
    up.random_password_flag = params.reg_random;
    up.use_sha1_flag = params.reg_sha1;
    up.is_privileged_flag = params.field_1;
    up.is_invisible_flag = params.field_2;
    up.is_banned_flag = params.field_3;
    up.is_locked_flag = params.field_4;
    up.show_login_flag = params.field_5;
    up.show_email_flag = params.field_6;
    up.read_only_flag = params.field_7;
    up.never_clean_flag = params.field_8;
    up.simple_registration_flag = params.field_9;
    if (cur_contest_id > 0) {
      up.contest_id = cur_contest_id;
    } else {
      up.contest_id = params.other_contest_id_1;
    }
    up.cnts_status = params.cnts_status;
    up.cnts_is_invisible_flag = params.is_invisible;
    up.cnts_is_banned_flag = params.is_banned;
    up.cnts_is_locked_flag = params.is_locked;
    up.cnts_is_incomplete_flag = params.is_incomplete;
    up.cnts_is_disqualified_flag = params.is_disqualified;
    up.cnts_is_privileged_flag = params.is_privileged;
    up.cnts_is_reg_readonly_flag = params.is_reg_readonly;
    up.cnts_use_reg_passwd_flag = params.cnts_use_reg_passwd;
    up.cnts_set_null_passwd_flag = params.cnts_null_passwd;
    up.cnts_random_password_flag = params.cnts_random_passwd;
    up.cnts_use_sha1_flag = params.cnts_sha1;
    up.group_id = params.other_group_id;
    up.register_existing_flag = params.register_existing;
    up.reset_existing_passwords_flag = params.reset_existing_passwords;
    r = userlist_clnt_create_user_2(phr->userlist_clnt, ULS_CREATE_USER_2, &up,
                                    login_str, email_str,
                                    reg_password_str, cnts_password_str,
                                    cnts_name_str, &other_user_id);
    if (r < 0 && r == -ULS_ERR_LOGIN_USED) {
      FAIL(SSERV_ERR_DUPLICATED_LOGIN);
    }
    if (r < 0 || other_user_id <= 0) {
      FAIL(SSERV_ERR_DB_ERROR);
    }

    xfree(login_str); login_str = 0;
    xfree(email_str); email_str = 0;
    xfree(reg_password_str); reg_password_str = 0;
    xfree(cnts_password_str); cnts_password_str = 0;
    xfree(cnts_name_str); cnts_name_str = 0;
  }

  ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, params.contest_id, params.group_id, 0, NULL);

cleanup:
  xfree(login_str); login_str = 0;
  xfree(email_str); email_str = 0;
  xfree(reg_password_str); reg_password_str = 0;
  xfree(cnts_password_str); cnts_password_str = 0;
  xfree(cnts_name_str); cnts_name_str = 0;
  csv_parsed = csv_free(csv_parsed);
  xfree(recoded_csv_text); recoded_csv_text = 0;
  xfree(xml_text); xml_text = 0;
  meta_destroy_fields(&meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_methods, &params);
  return retval;
}

int
super_serve_op_USER_SAVE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0, group_id = 0, other_user_id = 0;
  const struct contest_desc *cnts = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const struct userlist_user_info *ui = 0;
  unsigned char *other_login_str = 0;
  unsigned char *email_str = 0;
  const unsigned char *s = 0;
  unsigned char param_name[64];
  opcap_t gcaps = 0;
  opcap_t caps = 0;
  int changed_ids[USERLIST_NM_LAST];
  int deleted_ids[USERLIST_NM_LAST];
  const unsigned char *changed_strs[USERLIST_NM_LAST];
  int new_cnts_read_only = 0;
  int field_id;

  unsigned char *info_fields[USERLIST_NC_LAST];
  memset(info_fields, 0, sizeof(info_fields));

  unsigned char *member_fields[USERLIST_NM_LAST];
  memset(member_fields, 0, sizeof(member_fields));

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0)
    FAIL(SSERV_ERR_INV_USER_ID);
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts)
      FAIL(SSERV_ERR_INV_CONTEST);
  }

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  ss_get_global_caps(phr, &gcaps);
  if (cnts) {
    ss_get_contest_caps(phr, cnts, &caps);
  } else {
    caps = gcaps;
  }

  if (userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, contest_id, &xml_text) < 0) {
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (!(u = userlist_parse_user_str(xml_text))) FAIL(SSERV_ERR_DB_ERROR);

  if (hr_cgi_param(phr, "other_login", &s) <= 0 || !s) FAIL(SSERV_ERR_UNSPEC_LOGIN);
  other_login_str = fix_string(s);
  if (hr_cgi_param(phr, "email", &s) <= 0) FAIL(SSERV_ERR_INV_VALUE);
  email_str = fix_string(s);
  if (email_str && *email_str && !is_valid_email_address(email_str))
    FAIL(SSERV_ERR_INV_EMAIL);

  static const int global_checkbox_ids[] =
  {
    USERLIST_NN_IS_PRIVILEGED,
    USERLIST_NN_IS_INVISIBLE,
    USERLIST_NN_IS_BANNED,
    USERLIST_NN_IS_LOCKED,
    USERLIST_NN_SHOW_LOGIN,
    USERLIST_NN_SHOW_EMAIL,
    USERLIST_NN_READ_ONLY,
    USERLIST_NN_NEVER_CLEAN,
    USERLIST_NN_SIMPLE_REGISTRATION,
    0,
  };
  int global_checkbox_vals[USERLIST_NN_LAST];
  memset(global_checkbox_vals, 0, sizeof(global_checkbox_vals));
  for (int i = 0; (field_id = global_checkbox_ids[i]); ++i) {
    snprintf(param_name, sizeof(param_name), "field_%d", field_id);
    int val = 0;
    hr_cgi_param_int_opt(phr, param_name, &val, 0);
    if (val != 1) val = 0;
    global_checkbox_vals[field_id] = val;
  }

  int changed_count = 0;
  if (strcmp(u->login, other_login_str) != 0) {
    ++changed_count;
  }
  if (strcmp(u->email, email_str) != 0) {
    ++changed_count;
  }
  for (int i = 0; global_checkbox_ids[i]; ++i) {
    const void *ptr = userlist_get_user_field_ptr(u, global_checkbox_ids[i]);
    if (ptr) {
      int ival = *(const int*) ptr;
      if (ival != global_checkbox_vals[i]) {
        ++changed_count;
      }
    }
  }
  if (changed_count > 0) {
    int bit = 0;
    if (ss_is_globally_privileged(phr, u)
        || (cnts && ss_is_contest_privileged(cnts, u))
        || global_checkbox_vals[USERLIST_NN_IS_PRIVILEGED] != u->is_privileged) {
      bit = OPCAP_PRIV_EDIT_USER;
    } else {
      bit = OPCAP_EDIT_USER;
    }
    if (opcaps_check(gcaps, bit) < 0) FAIL(SSERV_ERR_PERM_DENIED);


    if (strcmp(u->login, other_login_str) != 0) {
      if (userlist_clnt_edit_field(phr->userlist_clnt, ULS_EDIT_FIELD, other_user_id, contest_id, 0,
                                   USERLIST_NN_LOGIN, other_login_str))
        FAIL(SSERV_ERR_DB_ERROR);
    }
    if (strcmp(u->email, email_str) != 0) {
      if (userlist_clnt_edit_field(phr->userlist_clnt, ULS_EDIT_FIELD, other_user_id, contest_id, 0,
                                   USERLIST_NN_EMAIL, email_str))
        FAIL(SSERV_ERR_DB_ERROR);
    }
    changed_count = 0;
    for (int i = 0; (field_id = global_checkbox_ids[i]); ++i) {
      const void *ptr = userlist_get_user_field_ptr(u, field_id);
      if (ptr) {
        int ival = *(const int*) ptr;
        if (ival != global_checkbox_vals[field_id]) {
          changed_ids[changed_count] = field_id;
          changed_strs[changed_count] = ival?"1":"0";
          ++changed_count;
        }
      }
    }

    if (changed_count > 0) {
      if (userlist_clnt_edit_field_seq(phr->userlist_clnt, ULS_EDIT_FIELD_SEQ,
                                       other_user_id, contest_id, 0, 0, changed_count,
                                       NULL, changed_ids, changed_strs) < 0) {
        FAIL(SSERV_ERR_DB_ERROR);
      }
    }
  }

  static const int info_field_ids[] =
  {
    // USERLIST_NC_CNTS_READ_ONLY,
    USERLIST_NC_NAME,
    USERLIST_NC_INST,
    USERLIST_NC_INST_EN,
    // 105
    USERLIST_NC_INSTSHORT,
    USERLIST_NC_INSTSHORT_EN,
    USERLIST_NC_INSTNUM,
    USERLIST_NC_FAC,
    USERLIST_NC_FAC_EN,
    // 110
    USERLIST_NC_FACSHORT,
    USERLIST_NC_FACSHORT_EN,
    USERLIST_NC_HOMEPAGE,
    USERLIST_NC_CITY,
    USERLIST_NC_CITY_EN,
    // 115
    USERLIST_NC_COUNTRY,
    USERLIST_NC_COUNTRY_EN,
    USERLIST_NC_REGION,
    USERLIST_NC_AREA,
    USERLIST_NC_ZIP,
    // 120
    USERLIST_NC_STREET,
    USERLIST_NC_LOCATION,
    USERLIST_NC_SPELLING,
    USERLIST_NC_PRINTER_NAME,
    USERLIST_NC_EXAM_ID,
    // 125
    USERLIST_NC_EXAM_CYPHER,
    USERLIST_NC_LANGUAGES,
    USERLIST_NC_PHONE,
    USERLIST_NC_FIELD0,
    USERLIST_NC_FIELD1,
    // 130
    USERLIST_NC_FIELD2,
    USERLIST_NC_FIELD3,
    USERLIST_NC_FIELD4,
    USERLIST_NC_FIELD5,
    USERLIST_NC_FIELD6,
    // 135
    USERLIST_NC_FIELD7,
    USERLIST_NC_FIELD8,
    USERLIST_NC_FIELD9,
    USERLIST_NC_AVATAR_STORE,
    USERLIST_NC_AVATAR_ID,
    // 140
    USERLIST_NC_AVATAR_SUFFIX,
    0,
  };
  int info_null_fields[USERLIST_NC_LAST];
  memset(info_null_fields, 0, sizeof(info_null_fields));
  for (int i = 0; (field_id = info_field_ids[i]); ++i) {
    snprintf(param_name, sizeof(param_name), "field_null_%d", field_id);
    int val = 0;
    hr_cgi_param_int_opt(phr, param_name, &val, 0);
    if (val != 1) val = 0;
    info_null_fields[field_id] = val;
  }

  snprintf(param_name, sizeof(param_name), "field_%d", USERLIST_NC_CNTS_READ_ONLY);
  hr_cgi_param_int_opt(phr, param_name, &new_cnts_read_only, 0);
  if (new_cnts_read_only != 1) new_cnts_read_only = 0;

  int cnts_read_only = 0;
  if (ui && ui->cnts_read_only) cnts_read_only = 1;

  for (int i = 0; (field_id = info_field_ids[i]); ++i) {
    if (info_null_fields[field_id]) continue;
    snprintf(param_name, sizeof(param_name), "field_%d", field_id);
    s = 0;
    if (hr_cgi_param(phr, param_name, &s) < 0) FAIL(SSERV_ERR_INV_VALUE);
    if (!s) s = "";
    info_fields[field_id] = fix_string(s);
  }

  if (u) ui = u->cnts0;
  int is_changed = 0;
  for (int i = 0; (field_id = info_field_ids[i]); ++i) {
    if (info_null_fields[field_id]) {
      if (ui && !userlist_is_empty_user_info_field(ui, field_id)) is_changed = 1;
    } else if (info_fields[field_id]) {
      if (!ui || !userlist_is_equal_user_info_field(ui, field_id, info_fields[field_id])) is_changed = 1;
    }
  }

  int deleted_count = 0;
  changed_count = 0;
  if (is_changed) {
    if (cnts_read_only && new_cnts_read_only) FAIL(SSERV_ERR_DATA_READ_ONLY);
    if (cnts_read_only != new_cnts_read_only) {
      changed_ids[changed_count] = USERLIST_NC_CNTS_READ_ONLY;
      changed_strs[changed_count] = new_cnts_read_only?"1":"0";
      ++changed_count;
    }
    for (int i = 0; (field_id = info_field_ids[i]); ++i) {
      if (info_null_fields[field_id]) {
        if (ui && !userlist_is_empty_user_info_field(ui, field_id)) {
          deleted_ids[deleted_count] = field_id;
          ++deleted_count;
        }
      } else if (info_fields[field_id]) {
        if (!ui || !userlist_is_equal_user_info_field(ui, field_id, info_fields[field_id])) {
          changed_ids[changed_count] = field_id;
          changed_strs[changed_count] = info_fields[field_id];
          ++changed_count;
        }
      }
    }
  }

  if (deleted_count > 0 || changed_count > 0) {
    if (ss_is_globally_privileged(phr, u)) {
      if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0)
        FAIL(SSERV_ERR_PERM_DENIED);
    } else if (ss_is_contest_privileged(cnts, u)) {
      if (opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
    } else {
      if (opcaps_check(caps, OPCAP_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
    }

    if (userlist_clnt_edit_field_seq(phr->userlist_clnt, ULS_EDIT_FIELD_SEQ,
                                     other_user_id, contest_id, 0, deleted_count, changed_count,
                                     deleted_ids, changed_ids, changed_strs) < 0) {
      FAIL(SSERV_ERR_DB_ERROR);
    }
  }

  static const int member_field_ids[] =
  {
    USERLIST_NM_STATUS,
    USERLIST_NM_GENDER,
    USERLIST_NM_GRADE,
    USERLIST_NM_FIRSTNAME,
    /* 205 */
    USERLIST_NM_FIRSTNAME_EN,
    USERLIST_NM_MIDDLENAME,
    USERLIST_NM_MIDDLENAME_EN,
    USERLIST_NM_SURNAME,
    USERLIST_NM_SURNAME_EN,
    /* 210 */
    USERLIST_NM_GROUP,
    USERLIST_NM_GROUP_EN,
    USERLIST_NM_EMAIL,
    USERLIST_NM_HOMEPAGE,
    USERLIST_NM_OCCUPATION,
    /* 215 */
    USERLIST_NM_OCCUPATION_EN,
    USERLIST_NM_DISCIPLINE,
    USERLIST_NM_INST,
    USERLIST_NM_INST_EN,
    USERLIST_NM_INSTSHORT,
    /* 220 */
    USERLIST_NM_INSTSHORT_EN,
    USERLIST_NM_FAC,
    USERLIST_NM_FAC_EN,
    USERLIST_NM_FACSHORT,
    USERLIST_NM_FACSHORT_EN,
    /* 225 */
    USERLIST_NM_PHONE,
    USERLIST_NM_CREATE_TIME,
    USERLIST_NM_LAST_CHANGE_TIME,
    USERLIST_NM_BIRTH_DATE,
    USERLIST_NM_ENTRY_DATE,
    /* 230 */
    USERLIST_NM_GRADUATION_DATE,
    0,
  };
  int member_null_fields[USERLIST_NM_LAST];

  if (ui && ui->members) {
    for (int role = 0; role < CONTEST_LAST_MEMBER; ++role) {
      int role_cnt = userlist_members_count(ui->members, role);
      if (role_cnt <= 0) continue;
      for (int pers = 0; pers < role_cnt; ++pers) {
        const struct userlist_member *m;
        if (!(m = (const struct userlist_member*) userlist_members_get_nth(ui->members, role, pers)))
          continue;

        memset(member_null_fields, 0, sizeof(member_null_fields));
        memset(member_fields, 0, sizeof(member_fields));

        for (int i = 0; (field_id = member_field_ids[i]); ++i) {
          snprintf(param_name, sizeof(param_name), "field_null_%d_%d", field_id, m->serial);
          int val = 0;
          hr_cgi_param_int_opt(phr, param_name, &val, 0);
          if (val != 1) val = 0;
          member_null_fields[field_id] = val;
        }

        for (int i = 0; (field_id = member_field_ids[i]); ++i) {
          if (member_null_fields[field_id]) continue;
          snprintf(param_name, sizeof(param_name), "field_%d_%d", field_id, m->serial);
          int r = hr_cgi_param(phr, param_name, &s);
          if (!r || !s) continue;
          if (r < 0) FAIL(SSERV_ERR_INV_VALUE);
          if (!s) s = "";
          member_fields[field_id] = fix_string(s);
        }

        is_changed = 0;
        for (int i = 0; (field_id = member_field_ids[i]); ++i) {
          if (member_null_fields[field_id]) {
            if (!userlist_is_empty_member_field(m, field_id)) is_changed = 1;
          } else if (member_fields[field_id]) {
            if (!userlist_is_equal_member_field(m, field_id, member_fields[field_id])) is_changed = 1;
          }
        }

        deleted_count = 0;
        changed_count = 0;
        if (is_changed) {
          if (cnts_read_only && new_cnts_read_only) FAIL(SSERV_ERR_DATA_READ_ONLY);

          for (int i = 0; (field_id = member_field_ids[i]); ++i) {
            if (member_null_fields[field_id]) {
              if (!userlist_is_empty_member_field(m, field_id)) {
                deleted_ids[deleted_count] = field_id;
                ++deleted_count;
              }
            } else if (member_fields[field_id]){
              if (!userlist_is_equal_member_field(m, field_id, member_fields[field_id])) {
                changed_ids[changed_count] = field_id;
                changed_strs[changed_count] = member_fields[field_id];
                ++changed_count;
              }
            }
          }
        }

        if (deleted_count > 0 || changed_count > 0) {
          if (ss_is_globally_privileged(phr, u)) {
            if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0)
              FAIL(SSERV_ERR_PERM_DENIED);
          } else if (ss_is_contest_privileged(cnts, u)) {
            if (opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
          } else {
            if (opcaps_check(caps, OPCAP_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
          }

          if (userlist_clnt_edit_field_seq(phr->userlist_clnt, ULS_EDIT_FIELD_SEQ,
                                           other_user_id, contest_id, m->serial, deleted_count, changed_count,
                                           deleted_ids, changed_ids, changed_strs) < 0) {
            FAIL(SSERV_ERR_DB_ERROR);
          }
        }

        for (int i = USERLIST_NM_FIRST; i < USERLIST_NM_LAST; ++i) {
          xfree(member_fields[i]);
        }
        memset(member_fields, 0, sizeof(member_fields));
      }
    }
  }

  int next_user_id = 0;
  int next_op = SSERV_CMD_USER_DETAIL_PAGE;
  if (phr->action == SSERV_CMD_USER_SAVE_AND_PREV_ACTION) {
    userlist_clnt_get_prev_user_id(phr->userlist_clnt, ULS_PREV_USER, contest_id, group_id, other_user_id,
                                   NULL, &next_user_id);
  } else if (phr->action == SSERV_CMD_USER_SAVE_AND_NEXT_ACTION) {
    userlist_clnt_get_prev_user_id(phr->userlist_clnt, ULS_NEXT_USER, contest_id, group_id, other_user_id,
                                   NULL, &next_user_id);
  } else {
    next_op = SSERV_CMD_USER_BROWSE_PAGE;
  }
  if (next_user_id <= 0) next_op = SSERV_CMD_USER_BROWSE_PAGE;

  ss_redirect_2(out_f, phr, next_op, contest_id, group_id, next_user_id, NULL);

cleanup:
  for (int i = 0; i < USERLIST_NC_LAST; ++i) {
    xfree(info_fields[i]); info_fields[i] = 0;
  }
  for (int i = USERLIST_NM_FIRST; i < USERLIST_NM_LAST; ++i) {
    xfree(member_fields[i]); member_fields[i] = 0;
  }
  xfree(email_str); email_str = 0;
  xfree(other_login_str); other_login_str = 0;
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  return retval;
}

int
super_serve_op_USER_CANCEL_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0, group_id = 0, other_user_id = 0;
  const struct contest_desc *cnts = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "other_user_id", &other_user_id, 0);
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts)
      FAIL(SSERV_ERR_INV_CONTEST);
  }
  if (other_user_id <= 0) phr->action = SSERV_CMD_USER_CANCEL_ACTION;

  int next_user_id = 0;
  int next_op = SSERV_CMD_USER_DETAIL_PAGE;
  if (phr->action == SSERV_CMD_USER_CANCEL_AND_PREV_ACTION) {
    userlist_clnt_get_prev_user_id(phr->userlist_clnt, ULS_PREV_USER, contest_id, group_id, other_user_id,
                                   NULL, &next_user_id);
  } else if (phr->action == SSERV_CMD_USER_CANCEL_AND_NEXT_ACTION) {
    userlist_clnt_get_prev_user_id(phr->userlist_clnt, ULS_NEXT_USER, contest_id, group_id, other_user_id,
                                   NULL, &next_user_id);
  } else {
    next_op = SSERV_CMD_USER_BROWSE_PAGE;
  }
  if (next_user_id <= 0) next_op = SSERV_CMD_USER_BROWSE_PAGE;

  ss_redirect_2(out_f, phr, next_op, contest_id, group_id, next_user_id, NULL);

cleanup:
  return retval;
}

int
super_serve_op_USER_CREATE_MEMBER_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0, group_id = 0, other_user_id = 0, role = 0;
  const struct contest_desc *cnts = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  opcap_t gcaps = 0, caps = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "other_user_id", &other_user_id, 0);
  hr_cgi_param_int_opt(phr, "role", &role, -1);

  if (contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(SSERV_ERR_INV_CONTEST);
  if (group_id < 0) group_id = 0;

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  ss_get_global_caps(phr, &gcaps);
  ss_get_contest_caps(phr, cnts, &caps);
  caps = (caps | gcaps) & ((1L << OPCAP_EDIT_USER) | (1L << OPCAP_PRIV_EDIT_USER));
  if (!caps) FAIL(SSERV_ERR_PERM_DENIED);

  if (userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, contest_id, &xml_text) < 0) {
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (!(u = userlist_parse_user_str(xml_text))) FAIL(SSERV_ERR_DB_ERROR);
  --role;
  if (role < 0 || role >= USERLIST_MB_LAST) FAIL(SSERV_ERR_INV_VALUE);

  if (ss_is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (ss_is_contest_privileged(cnts, u)) {
    if (opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(caps, OPCAP_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  int max_count = 0;
  if (role == CONTEST_M_CONTESTANT) {
    if (cnts->personal) {
      max_count = 1;
    } else if (cnts->members[role]) {
      max_count = cnts->members[role]->max_count;
    }
  } else if (role == CONTEST_M_RESERVE) {
    if (cnts->personal) {
      max_count = 0;
    } else if (cnts->members[role]) {
      max_count = cnts->members[role]->max_count;
    }
  } else {
    if (cnts->members[role]) {
      max_count = cnts->members[role]->max_count;
    }
  }

  int cur_count = 0;
  if (u && u->cnts0 && u->cnts0->members) {
    cur_count = userlist_members_count(u->cnts0->members, role);
  }
  if (cur_count >= max_count) FAIL(SSERV_ERR_TOO_MANY_MEMBERS);

  if (userlist_clnt_create_member(phr->userlist_clnt, other_user_id, contest_id, role) < 0)
    FAIL(SSERV_ERR_DB_ERROR);

  ss_redirect_2(out_f, phr, SSERV_CMD_USER_DETAIL_PAGE, contest_id, group_id, other_user_id, NULL);

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  return retval;
}

int
super_serve_op_USER_DELETE_MEMBER_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0, group_id = 0, other_user_id = 0, serial = 0;
  const struct contest_desc *cnts = 0;
  opcap_t gcaps = 0, caps = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const struct userlist_member *m = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "other_user_id", &other_user_id, 0);
  hr_cgi_param_int_opt(phr, "serial", &serial, 0);

  if (contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(SSERV_ERR_INV_CONTEST);
  if (group_id < 0) group_id = 0;

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  ss_get_global_caps(phr, &gcaps);
  ss_get_contest_caps(phr, cnts, &caps);
  caps = (caps | gcaps) & ((1L << OPCAP_EDIT_USER) | (1L << OPCAP_PRIV_EDIT_USER));
  if (!caps) FAIL(SSERV_ERR_PERM_DENIED);

  if (userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, contest_id, &xml_text) < 0) {
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (!(u = userlist_parse_user_str(xml_text))) FAIL(SSERV_ERR_DB_ERROR);

  if (ss_is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (ss_is_contest_privileged(cnts, u)) {
    if (opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(caps, OPCAP_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  m = 0;
  if (u->cnts0 && u->cnts0->members) {
    m = userlist_get_member_nc(u->cnts0->members, serial, NULL, NULL);
  }
  if (!m) FAIL(SSERV_ERR_INV_SERIAL);

  if (userlist_clnt_delete_info(phr->userlist_clnt, ULS_PRIV_DELETE_MEMBER,
                                other_user_id, contest_id, serial) < 0)
    FAIL(SSERV_ERR_DB_ERROR);

  ss_redirect_2(out_f, phr, SSERV_CMD_USER_DETAIL_PAGE, contest_id, group_id, other_user_id, NULL);

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  return retval;
}

int
super_serve_op_USER_CREATE_REG_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct userlist_user *u = 0;

  struct ss_op_param_USER_CREATE_REG_ACTION params;
  memset(&params, 0, sizeof(params));
  retval = ss_parse_params(phr, &meta_ss_op_param_USER_CREATE_REG_ACTION_methods, &params);
  if (retval < 0) goto cleanup;

  const struct contest_desc *cnts = 0;
  if (params.contest_id > 0) {
    if (contests_get(params.contest_id, &cnts) < 0 || !cnts)
      params.contest_id = 0;
  } else {
    params.contest_id = 0;
  }
  cnts = 0;
  if (params.other_contest_id_1 <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(params.other_contest_id_1, &cnts) < 0 || !cnts) FAIL(SSERV_ERR_INV_CONTEST);

  if (params.group_id < 0) params.group_id = 0;

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  opcap_t gcaps = 0, caps = 0;
  ss_get_global_caps(phr, &gcaps);
  if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_CREATE_REG;
  if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_CREATE_REG;
  ss_get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (opcaps_check(caps, OPCAP_CREATE_REG) < 0 && opcaps_check(caps, OPCAP_PRIV_CREATE_REG) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (!(u = ss_get_user_info(phr, params.other_user_id, cnts->id))) FAIL(SSERV_ERR_DB_ERROR);
  if (ss_is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_CREATE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (ss_is_contest_privileged(cnts, u)) {
    if (opcaps_check(caps, OPCAP_PRIV_CREATE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(caps, OPCAP_CREATE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (params.status < 0 || params.status >= USERLIST_REG_LAST) params.status = USERLIST_REG_PENDING;

  int flags = 0;
  if (params.is_invisible) flags |= USERLIST_UC_INVISIBLE;
  if (params.is_banned) flags |= USERLIST_UC_BANNED;
  if (params.is_locked) flags |= USERLIST_UC_LOCKED;
  if (params.is_incomplete) flags |= USERLIST_UC_INCOMPLETE;
  if (params.is_disqualified) flags |= USERLIST_UC_DISQUALIFIED;
  if (params.is_privileged) flags |= USERLIST_UC_PRIVILEGED;
  if (params.is_reg_readonly) flags |= USERLIST_UC_REG_READONLY;

  if (userlist_clnt_register_contest(phr->userlist_clnt,
                                     ULS_PRIV_REGISTER_CONTEST,
                                     params.other_user_id, cnts->id, 0, 0) < 0)
    FAIL(SSERV_ERR_DB_ERROR);
  if (userlist_clnt_change_registration(phr->userlist_clnt, params.other_user_id,
                                        cnts->id, params.status, 4, flags) < 0)
    FAIL(SSERV_ERR_DB_ERROR);

  ss_redirect_2(out_f, phr, SSERV_CMD_USER_DETAIL_PAGE, params.contest_id, params.group_id, params.other_user_id, NULL);

cleanup:
  meta_destroy_fields(&meta_ss_op_param_USER_CREATE_REG_ACTION_methods, &params);
  userlist_free(&u->b); u = 0;
  return retval;
}

int
super_serve_op_USER_EDIT_REG_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct userlist_user *u = 0;

  struct ss_op_param_USER_EDIT_REG_ACTION params;
  memset(&params, 0, sizeof(params));
  retval = ss_parse_params(phr, &meta_ss_op_param_USER_EDIT_REG_ACTION_methods, &params);
  if (retval < 0) goto cleanup;

  const struct contest_desc *cnts = 0;
  if (params.contest_id > 0) {
    if (contests_get(params.contest_id, &cnts) < 0 || !cnts)
      params.contest_id = 0;
  } else {
    params.contest_id = 0;
  }
  cnts = 0;
  if (params.other_contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(params.other_contest_id, &cnts) < 0 || !cnts) FAIL(SSERV_ERR_INV_CONTEST);

  if (params.group_id < 0) params.group_id = 0;

  if (params.next_op != SSERV_CMD_USER_DETAIL_PAGE) params.next_op = SSERV_CMD_USER_BROWSE_PAGE;

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  opcap_t gcaps = 0, caps = 0;
  ss_get_global_caps(phr, &gcaps);
  if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_EDIT_REG;
  if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_EDIT_REG;
  ss_get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (opcaps_check(caps, OPCAP_CREATE_REG) < 0 && opcaps_check(caps, OPCAP_PRIV_CREATE_REG) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (!(u = ss_get_user_info(phr, params.other_user_id, cnts->id))) FAIL(SSERV_ERR_DB_ERROR);
  if (ss_is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (ss_is_contest_privileged(cnts, u)) {
    if (opcaps_check(caps, OPCAP_PRIV_EDIT_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(caps, OPCAP_EDIT_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (params.status < 0 || params.status >= USERLIST_REG_LAST) params.status = USERLIST_REG_PENDING;

  int flags = 0;
  if (params.is_invisible) flags |= USERLIST_UC_INVISIBLE;
  if (params.is_banned) flags |= USERLIST_UC_BANNED;
  if (params.is_locked) flags |= USERLIST_UC_LOCKED;
  if (params.is_incomplete) flags |= USERLIST_UC_INCOMPLETE;
  if (params.is_disqualified) flags |= USERLIST_UC_DISQUALIFIED;
  if (params.is_privileged) flags |= USERLIST_UC_PRIVILEGED;
  if (params.is_reg_readonly) flags |= USERLIST_UC_REG_READONLY;

  if (userlist_clnt_change_registration(phr->userlist_clnt, params.other_user_id,
                                        cnts->id, params.status, 4, flags) < 0)
    FAIL(SSERV_ERR_DB_ERROR);

  if (params.next_op == SSERV_CMD_USER_DETAIL_PAGE) {
    ss_redirect_2(out_f, phr, params.next_op, params.contest_id, params.group_id, params.other_user_id, NULL);
  } else {
    ss_redirect_2(out_f, phr, params.next_op, params.contest_id, params.group_id, 0, NULL);
  }

cleanup:
  meta_destroy_fields(&meta_ss_op_param_USER_EDIT_REG_ACTION_methods, &params);
  userlist_free(&u->b); u = 0;
  return retval;
}

int
super_serve_op_USER_DELETE_REG_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct userlist_user *u = 0;
  int contest_id = 0, group_id = 0, other_user_id = 0, other_contest_id = 0, next_op = 0;
  const struct contest_desc *cnts = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "other_user_id", &other_user_id, 0);
  hr_cgi_param_int_opt(phr, "other_contest_id", &other_contest_id, 0);
  hr_cgi_param_int_opt(phr, "next_op", &next_op, 0);

  if (contest_id < 0) contest_id = 0;
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts)
      contest_id = 0;
  }
  if (group_id < 0) group_id = 0;
  if (next_op != SSERV_CMD_USER_DETAIL_PAGE) next_op = SSERV_CMD_USER_BROWSE_PAGE;

  cnts = 0;
  if (other_contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(other_contest_id, &cnts) < 0 || !cnts) FAIL(SSERV_ERR_INV_CONTEST);

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  opcap_t gcaps = 0, caps = 0;
  ss_get_global_caps(phr, &gcaps);
  if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_DELETE_REG;
  if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_DELETE_REG;
  ss_get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0 && opcaps_check(caps, OPCAP_DELETE_REG) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (!(u = ss_get_user_info(phr, other_user_id, cnts->id))) FAIL(SSERV_ERR_DB_ERROR);
  if (ss_is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_DELETE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (ss_is_contest_privileged(cnts, u)) {
    if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(caps, OPCAP_DELETE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (userlist_clnt_change_registration(phr->userlist_clnt, u->id, cnts->id, -2, 0, 0) < 0)
    FAIL(SSERV_ERR_DB_ERROR);

  if (next_op == SSERV_CMD_USER_DETAIL_PAGE) {
    ss_redirect_2(out_f, phr, next_op, contest_id, group_id, other_user_id, NULL);
  } else {
    ss_redirect_2(out_f, phr, next_op, contest_id, group_id, 0, NULL);
  }

cleanup:
  userlist_free(&u->b); u = 0;
  return retval;
}

static const unsigned char clearable_fields[] =
{
  [USERLIST_NN_IS_PRIVILEGED] = 1,
  [USERLIST_NN_IS_INVISIBLE] = 1,
  [USERLIST_NN_IS_BANNED] = 1,
  [USERLIST_NN_IS_LOCKED] = 1,
  [USERLIST_NN_SHOW_LOGIN] = 1,
  [USERLIST_NN_SHOW_EMAIL] = 1,
  [USERLIST_NN_READ_ONLY] = 1,
  [USERLIST_NN_NEVER_CLEAN] = 1,
  [USERLIST_NN_SIMPLE_REGISTRATION] = 1,
  [USERLIST_NN_EMAIL] = 1,

  [USERLIST_NC_CNTS_READ_ONLY] = 1,
  [USERLIST_NC_NAME] = 1,
  [USERLIST_NC_INST] = 1,
  [USERLIST_NC_INST_EN] = 1,
  [USERLIST_NC_INSTSHORT] = 1,
  [USERLIST_NC_INSTSHORT_EN] = 1,
  [USERLIST_NC_INSTNUM] = 1,
  [USERLIST_NC_FAC] = 1,
  [USERLIST_NC_FAC_EN] = 1,
  [USERLIST_NC_FACSHORT] = 1,
  [USERLIST_NC_FACSHORT_EN] = 1,
  [USERLIST_NC_HOMEPAGE] = 1,
  [USERLIST_NC_CITY] = 1,
  [USERLIST_NC_CITY_EN] = 1,
  [USERLIST_NC_COUNTRY] = 1,
  [USERLIST_NC_COUNTRY_EN] = 1,
  [USERLIST_NC_REGION] = 1,
  [USERLIST_NC_AREA] = 1,
  [USERLIST_NC_ZIP] = 1,
  [USERLIST_NC_STREET] = 1,
  [USERLIST_NC_LOCATION] = 1,
  [USERLIST_NC_SPELLING] = 1,
  [USERLIST_NC_PRINTER_NAME] = 1,
  [USERLIST_NC_EXAM_ID] = 1,
  [USERLIST_NC_EXAM_CYPHER] = 1,
  [USERLIST_NC_LANGUAGES] = 1,
  [USERLIST_NC_PHONE] = 1,
  [USERLIST_NC_FIELD0] = 1,
  [USERLIST_NC_FIELD1] = 1,
  [USERLIST_NC_FIELD2] = 1,
  [USERLIST_NC_FIELD3] = 1,
  [USERLIST_NC_FIELD4] = 1,
  [USERLIST_NC_FIELD5] = 1,
  [USERLIST_NC_FIELD6] = 1,
  [USERLIST_NC_FIELD7] = 1,
  [USERLIST_NC_FIELD8] = 1,
  [USERLIST_NC_FIELD9] = 1,
  [USERLIST_NC_AVATAR_STORE] = 1,
  [USERLIST_NC_AVATAR_ID] = 1,
  [USERLIST_NC_AVATAR_SUFFIX] = 1,

  [USERLIST_NM_STATUS] = 1,
  [USERLIST_NM_GENDER] = 1,
  [USERLIST_NM_GRADE] = 1,
  [USERLIST_NM_FIRSTNAME] = 1,
  [USERLIST_NM_FIRSTNAME_EN] = 1,
  [USERLIST_NM_MIDDLENAME] = 1,
  [USERLIST_NM_MIDDLENAME_EN] = 1,
  [USERLIST_NM_SURNAME] = 1,
  [USERLIST_NM_SURNAME_EN] = 1,
  [USERLIST_NM_GROUP] = 1,
  [USERLIST_NM_GROUP_EN] = 1,
  [USERLIST_NM_EMAIL] = 1,
  [USERLIST_NM_HOMEPAGE] = 1,
  [USERLIST_NM_OCCUPATION] = 1,
  [USERLIST_NM_OCCUPATION_EN] = 1,
  [USERLIST_NM_DISCIPLINE] = 1,
  [USERLIST_NM_INST] = 1,
  [USERLIST_NM_INST_EN] = 1,
  [USERLIST_NM_INSTSHORT] = 1,
  [USERLIST_NM_INSTSHORT_EN] = 1,
  [USERLIST_NM_FAC] = 1,
  [USERLIST_NM_FAC_EN] = 1,
  [USERLIST_NM_FACSHORT] = 1,
  [USERLIST_NM_FACSHORT_EN] = 1,
  [USERLIST_NM_PHONE] = 1,
  [USERLIST_NM_BIRTH_DATE] = 1,
  [USERLIST_NM_ENTRY_DATE] = 1,
  [USERLIST_NM_GRADUATION_DATE] = 1,
};

int
super_serve_op_USER_CLEAR_FIELD_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0, group_id = 0, other_user_id = 0, field_id = 0, member_id = 0;
  const struct contest_desc *cnts = 0;
  struct userlist_user *u = 0;
  const struct userlist_member *m = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "other_user_id", &other_user_id, 0);
  hr_cgi_param_int_opt(phr, "field_id", &field_id, 0);
  hr_cgi_param_int_opt(phr, "member_id", &member_id, 0);

  if (contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(SSERV_ERR_INV_CONTEST);
  if (group_id < 0) group_id = 0;

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  opcap_t gcaps = 0, caps = 0;
  ss_get_global_caps(phr, &gcaps);
  ss_get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0 && opcaps_check(caps, OPCAP_EDIT_USER) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (!(u = ss_get_user_info(phr, other_user_id, cnts->id))) FAIL(SSERV_ERR_DB_ERROR);
  if (ss_is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (ss_is_contest_privileged(cnts, u)) {
    if (opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(caps, OPCAP_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (field_id < USERLIST_NN_FIRST || field_id >= USERLIST_NM_LAST)
    FAIL(SSERV_ERR_INV_VALUE);
  if (!clearable_fields[field_id])
    FAIL(SSERV_ERR_INV_VALUE);

  if (field_id >= USERLIST_NM_FIRST && field_id < USERLIST_NM_LAST) {
    if (u->cnts0 && u->cnts0->members) {
      m = userlist_get_member_nc(u->cnts0->members, field_id, NULL, NULL);
    }
    if (!m) {
      member_id = 0;
    }
  } else {
    member_id = 0;
  }

  if (userlist_clnt_delete_field(phr->userlist_clnt, ULS_DELETE_FIELD,
                                 other_user_id, contest_id, member_id,
                                 field_id) < 0) {
    FAIL(SSERV_ERR_DB_ERROR);
  }

  ss_redirect_2(out_f, phr, SSERV_CMD_USER_DETAIL_PAGE, contest_id, group_id, other_user_id, NULL);

cleanup:
  userlist_free(&u->b); u = 0;
  return retval;
}

int
super_serve_op_USER_SEL_VIEW_PASSWD_REDIRECT(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int contest_id = 0, group_id = 0, next_op = 0;
  bitset_t marked = BITSET_INITIALIZER;
  unsigned char *marked_str = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  marked_str = ss_collect_marked_set(phr, &marked);
  switch (phr->action) {
  case SSERV_CMD_USER_SEL_VIEW_PASSWD_REDIRECT:
    next_op = SSERV_CMD_USER_SEL_VIEW_PASSWD_PAGE;
    break;
  case SSERV_CMD_USER_SEL_VIEW_CNTS_PASSWD_REDIRECT:
    next_op = SSERV_CMD_USER_SEL_VIEW_CNTS_PASSWD_PAGE;
    break;
  default:
    abort();
  }
  ss_redirect_2(out_f, phr, next_op, contest_id, group_id, 0, marked_str);

  xfree(marked_str);
  bitset_free(&marked);
  return 0;
}

int
super_serve_op_USER_IMPORT_CSV_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0, group_id = 0;
  const struct contest_desc *cnts = 0;
  opcap_t caps = 0LL;
  const unsigned char *separator = NULL;
  const unsigned char *csv_text = 0;
  const unsigned char *charset = 0;
  unsigned char *recoded_csv_text = 0;
  struct csv_file *csv_parsed = 0;
  int *user_ids = 0;
  int *serials = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (group_id < 0) group_id = 0;

  /* FIXME: refine caps */
  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (hr_cgi_param(phr, "csv_file", &csv_text) <= 0 || !csv_text) {
    FAIL(SSERV_ERR_INV_CSV_FILE);
  }

  hr_cgi_param(phr, "charset", &charset);
  if (charset && *charset) {
    int charset_id = charset_get_id(charset);
    if (charset_id < 0) FAIL(SSERV_ERR_INV_CHARSET);
    if (charset_id > 0) {
      recoded_csv_text = charset_decode_to_heap(charset_id, csv_text);
      if (!recoded_csv_text) FAIL(SSERV_ERR_INV_CHARSET);
      csv_text = recoded_csv_text;
    }
  }

  hr_cgi_param(phr, "separator", &separator);
  if (!separator || !*separator) separator = ";";
  if (strlen(separator) != 1) FAIL(SSERV_ERR_INV_SEPARATOR);

  csv_parsed = csv_parse(csv_text, log_f, separator[0]);
  if (!csv_parsed) FAIL(SSERV_ERR_INV_CSV_FILE);

  if (csv_parsed->u <= 0) {
    fprintf(log_f, "CSV file is empty\n");
    FAIL(SSERV_ERR_INV_CSV_FILE);
  }
  if (csv_parsed->u > 10000) {
    fprintf(log_f, "CSV file is too big\n");
    FAIL(SSERV_ERR_INV_CSV_FILE);
  }

  int column_count = csv_parsed->v[0].u;

  // search for the key field (either login or user_id) and for 'serial' field
  int login_idx = -1, user_id_idx = -1, serial_idx = -1, failed = 0;
  int col;
  for (col = 0; col < column_count; ++col) {
    unsigned char *txt = fix_string(csv_parsed->v[0].v[col]);
    if (!txt || !*txt) {
      // nothing
    } else if (!strcasecmp(txt, "login")) {
      if (login_idx >= 0) {
        fprintf(log_f, "dupicated column 'login'\n");
        failed = 1;
      } else {
        login_idx = col;
      }
    } else if (!strcasecmp(txt, "user_id") || !strcasecmp(txt, "userid")) {
      if (user_id_idx >= 0) {
        fprintf(log_f, "dupicated column 'user_id'\n");
        failed = 1;
      } else {
        user_id_idx = col;
      }
    } else if (!strcasecmp(txt, "serial")) {
      if (serial_idx >= 0) {
        fprintf(log_f, "dupicated column 'serial'\n");
        failed = 1;
      } else {
        serial_idx = col;
      }
    }
    xfree(txt); txt = 0;
  }
  if (login_idx >= 0 && user_id_idx >= 0) {
    fprintf(log_f, "both 'login' and 'user_id' are defined\n");
    failed = 1;
  }
  if (login_idx < 0 && user_id_idx < 0) {
    fprintf(log_f, "neither 'login' nor 'user_id' are defined\n");
    failed = 1;
  }
  if (failed) FAIL(SSERV_ERR_INV_CSV_FILE);

  int field_idx[USERLIST_NM_LAST];
  memset(field_idx, -1, sizeof(field_idx));
  for (col = 0; col < column_count; ++col) {
    unsigned char *txt = fix_string(csv_parsed->v[0].v[col]);
    int fid = -1;
    if (!txt || !*txt) {
      fprintf(log_f, "empty column %d is ignored\n", col + 1);
      fprintf(stderr, "empty column %d is ignored\n", col + 1);
      // nothing
    } else if ((fid = userlist_lookup_csv_field_name(txt)) <= 0) {
      fprintf(log_f, "unknown column '%s' (%d) is ignored\n", txt, col + 1);
      fprintf(stderr, "unknown column '%s' (%d) is ignored\n", txt, col + 1);
    } else if (field_idx[fid] >= 0) {
      fprintf(log_f, "duplicated column '%s' (%d)\n", userlist_get_csv_field_name(fid), col + 1);
      failed = 1;
    } else {
      field_idx[fid] = col;
    }
    xfree(txt); txt = 0;
  }
  if (failed) FAIL(SSERV_ERR_INV_CSV_FILE);

  // clear unsettable fields
  field_idx[USERLIST_NN_ID] = -1;
  field_idx[USERLIST_NN_LOGIN] = -1;
  field_idx[USERLIST_NN_REGISTRATION_TIME] = -1;
  field_idx[USERLIST_NN_LAST_LOGIN_TIME] = -1;
  field_idx[USERLIST_NN_LAST_CHANGE_TIME] = -1;
  field_idx[USERLIST_NN_LAST_PWDCHANGE_TIME] = -1;
  field_idx[USERLIST_NC_CREATE_TIME] = -1;
  field_idx[USERLIST_NC_LAST_LOGIN_TIME] = -1;
  field_idx[USERLIST_NC_LAST_CHANGE_TIME] = -1;
  field_idx[USERLIST_NC_LAST_PWDCHANGE_TIME] = -1;
  field_idx[USERLIST_NM_SERIAL] = -1;
  field_idx[USERLIST_NM_CREATE_TIME] = -1;
  field_idx[USERLIST_NM_LAST_CHANGE_TIME] = -1;

  int has_global_fields = 0, has_contest_fields = 0, has_member_fields = 0;
  int field_id;
  for (field_id = USERLIST_NN_FIRST; field_id < USERLIST_NN_LAST; ++field_id) {
    if (field_idx[field_id] >= 0) has_global_fields = 1;
  }
  for (field_id = USERLIST_NC_FIRST; field_id < USERLIST_NC_LAST; ++field_id) {
    if (field_idx[field_id] >= 0) has_contest_fields = 1;
  }
  for (field_id = USERLIST_NM_FIRST; field_id < USERLIST_NM_LAST; ++field_id) {
    if (field_idx[field_id] >= 0) has_member_fields = 1;
  }
  if (has_member_fields && !cnts->personal) {
    if (serial_idx < 0) {
      fprintf(log_f, "'serial' field must be specified for non-personal contests\n");
      failed = 1;
    }
    if (has_global_fields || has_contest_fields) {
      fprintf(log_f, "global or contest fields cannot be changed with member fields\n");
      failed = 1;
    }
  } else if (has_member_fields && cnts->personal) {
    if (serial_idx >= 0) {
      fprintf(log_f, "'serial' field must not be specified for personal contests\n");
      failed = 1;
    }
  }
  if (failed) FAIL(SSERV_ERR_INV_CSV_FILE);

  if (cnts->disable_team_password && field_idx[USERLIST_NC_TEAM_PASSWD] >= 0) {
    fprintf(log_f, "contest password is ignored because of contest settings\n");
    field_idx[USERLIST_NC_TEAM_PASSWD] = -1;
  }

  XCALLOC(user_ids, csv_parsed->u);
  XCALLOC(serials, csv_parsed->u);
  int row;
  for (row = 1; row < csv_parsed->u; ++row) {
    if (csv_parsed->v[row].u != column_count) {
      fprintf(log_f, "row %d contains %zu column, but %d columns expected\n",
              row + 1, csv_parsed->v[row].u, column_count);
      failed = 1;
      continue;
    }
    unsigned char *txt = 0;
    if (user_id_idx >= 0) {
      txt = fix_string(csv_parsed->v[row].v[user_id_idx]);
      if (!txt || !*txt) {
        fprintf(log_f, "'user_id' empty in row %d\n", row + 1);
        failed = 1;
      } else {
        int user_id = 0;
        char *eptr = 0;
        errno = 0;
        user_id = strtol(txt, &eptr, 10);
        if (errno || *eptr || user_id <= 0 || user_id >= 1000000000) {
          fprintf(log_f, "invalid user_id '%s' in row %d\n", txt, row + 1);
          failed = 1;
        } else {
          int r = 0;
          r = userlist_clnt_lookup_user_id(phr->userlist_clnt, user_id, contest_id, NULL, NULL);
          if (r < 0) {
            fprintf(log_f, "non-existant user_id %d or user is not registered for this contest in row %d\n", user_id, row + 1);
            failed = 1;
          } else {
            user_ids[row] = user_id;
          }
        }
      }
      xfree(txt); txt = 0;
    } else if (login_idx >= 0) {
      txt = fix_string(csv_parsed->v[row].v[login_idx]);
      if (!txt || !*txt) {
        fprintf(log_f, "'login' empty in row %d\n", row + 1);
        failed = 1;
      } else {
        int user_id = 0, r = 0;
        r = userlist_clnt_lookup_user(phr->userlist_clnt, txt, contest_id, &user_id, NULL);
        if (r < 0 || user_id <= 0) {
          fprintf(log_f, "non-existant login '%s' or user is not registered for this contest in row %d\n", txt, row + 1);
          failed = 1;
        } else {
          user_ids[row] = user_id;
        }
      }
      xfree(txt); txt = 0;
    }
    if (serial_idx >= 0) {
      txt = fix_string(csv_parsed->v[row].v[user_id_idx]);
      if (!txt || !*txt) {
        fprintf(log_f, "'serial' empty in row %d\n", row + 1);
        failed = 1;
      } else {
        char *eptr = 0;
        errno = 0;
        int serial = strtol(txt, &eptr, 10);
        if (errno || *eptr || serial <= 0 || serial >= 1000000000) {
          fprintf(log_f, "invalid serial '%s' in row %d\n", txt, row + 1);
          failed = 1;
        } else {
          serials[row] = serial;
        }
      }
      xfree(txt); txt = 0;
    }
  }
  if (failed) FAIL(SSERV_ERR_INV_CSV_FILE);

  int deleted_ids[USERLIST_NM_LAST];
  int changed_ids[USERLIST_NM_LAST];
  unsigned char *changed_strs[USERLIST_NM_LAST];
  int deleted_count = 0;
  int changed_count = 0;
  memset(deleted_ids, 0, sizeof(deleted_ids));
  memset(changed_ids, 0, sizeof(changed_ids));
  memset(changed_strs, 0, sizeof(changed_strs));

  for (row = 1; row < csv_parsed->u; ++row) {
    for (field_id = 1; field_id < USERLIST_NM_LAST; ++field_id) {
      if (field_idx[field_id] >= 0) {
        unsigned char *txt = fix_string(csv_parsed->v[row].v[field_idx[field_id]]);
        if (!txt || !*txt) {
          deleted_ids[deleted_count++] = field_id;
          xfree(txt); txt = NULL;
        } else {
          changed_ids[changed_count] = field_id;
          changed_strs[changed_count] = txt; txt = NULL;
          ++changed_count;
        }
      }
    }

    if (userlist_clnt_edit_field_seq(phr->userlist_clnt, ULS_EDIT_FIELD_SEQ,
                                     user_ids[row], contest_id, serials[row], deleted_count, changed_count,
                                     deleted_ids, changed_ids,
                                     (const unsigned char **) changed_strs) < 0) {
      FAIL(SSERV_ERR_DB_ERROR);
    }

    for (int i = 0; i < changed_count; ++i) {
      xfree(changed_strs[i]);
    }
    memset(deleted_ids, 0, sizeof(deleted_ids));
    memset(changed_ids, 0, sizeof(changed_ids));
    memset(changed_strs, 0, sizeof(changed_strs));
    changed_count = 0;
    deleted_count = 0;
  }

  ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, contest_id, group_id, 0, NULL);

cleanup:
  xfree(serials);
  xfree(user_ids);
  csv_parsed = csv_free(csv_parsed);
  xfree(recoded_csv_text); recoded_csv_text = 0;
  return retval;
}

int
super_serve_GROUP_FILTER_CHANGE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int r, value, retval = 0;
  opcap_t gcaps = 0;
  long long total_count = 0;
  int group_offset = 0;
  int group_count = 0;

  if (ss_get_global_caps(phr, &gcaps) < 0 && opcaps_check(gcaps, OPCAP_LIST_USERS) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (!phr->userlist_clnt) {
    goto cleanup;
  }
  if ((r = userlist_clnt_get_count(phr->userlist_clnt, ULS_GET_GROUP_COUNT,
                                   0, 0, 0,
                                   // FIXME: fill the fields
                                   -1 /* filter_field */, 0 /* filter_op */,
                                   &total_count)) < 0) {
    err("set_group_filter: get_count failed: %d", -r);
    goto cleanup;
  }
  if (total_count <= 0) goto cleanup;
  if (phr->ss->group_filter_set) {
    group_offset = phr->ss->group_offset;
    group_count = phr->ss->group_count;
  }
  if (group_count <= 0) group_count = 20;
  if (group_count > 200) group_count = 200;

  switch (phr->action) {
  case SSERV_CMD_GROUP_FILTER_CHANGE_ACTION:
    if (hr_cgi_param_int(phr, "group_offset", &value) >= 0) {
      group_offset = value;
    }
    if (hr_cgi_param_int(phr, "group_count", &value) >= 0) {
      group_count = value;
    }
    if (group_count <= 0) group_count = 20;
    if (group_count > 200) group_count = 200;
    break;

  case SSERV_CMD_GROUP_FILTER_FIRST_PAGE_ACTION:
    group_offset = 0;
    break;
  case SSERV_CMD_GROUP_FILTER_PREV_PAGE_ACTION:
    group_offset -= group_count;
    break;
  case SSERV_CMD_GROUP_FILTER_NEXT_PAGE_ACTION:
    group_offset += group_count;
    break;
  case SSERV_CMD_GROUP_FILTER_LAST_PAGE_ACTION:
    group_offset = group_count;
    break;
  }

  if (group_offset + group_count > total_count) {
    group_offset = total_count - group_count;
  }
  if (group_offset < 0) group_offset = 0;
  phr->ss->group_filter_set = 1;
  phr->ss->group_offset = group_offset;
  phr->ss->group_count = group_count;

cleanup:
  ss_redirect(out_f, phr, SSERV_CMD_GROUP_BROWSE_PAGE, NULL);
  return retval;
}

int
super_serve_op_GROUP_DELETE_PAGE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int group_id = 0;

  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  if (group_id <= 0) group_id = 0;
  ss_redirect_2(out_f, phr, SSERV_CMD_GROUP_DELETE_PAGE, 0, group_id, 0, 0);
  return 0;
}

int
super_serve_op_GROUP_MODIFY_PAGE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int group_id = 0;

  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  if (group_id <= 0) group_id = 0;
  ss_redirect_2(out_f, phr, SSERV_CMD_GROUP_MODIFY_PAGE, 0, group_id, 0, 0);
  return 0;
}

int
super_serve_op_GROUP_CREATE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r, group_id = 0;
  opcap_t caps = 0;
  const unsigned char *s = NULL;
  unsigned char *group_name = NULL;
  unsigned char *description = NULL;

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  s = 0;
  if (hr_cgi_param(phr, "group_name", &s) <= 0 || !s) FAIL(SSERV_ERR_INV_GROUP_NAME);
  group_name = fix_string(s);
  if (!group_name || !*group_name) FAIL(SSERV_ERR_INV_GROUP_NAME);
  if (strlen(group_name) > 1024) FAIL(SSERV_ERR_INV_GROUP_NAME);
  if (!is_valid_login(group_name)) FAIL(SSERV_ERR_INV_GROUP_NAME);

  s = 0;
  if (hr_cgi_param(phr, "description", &s) < 0) FAIL(SSERV_ERR_INV_DESCRIPTION);
  if (!s) {
    description = xstrdup("");
  } else {
    description = fix_string(s);
  }
  if (!description) description = xstrdup("");
  if (strlen(description) > 1024) FAIL(SSERV_ERR_INV_DESCRIPTION);

  r = userlist_clnt_create_user(phr->userlist_clnt, ULS_CREATE_GROUP, group_name, &group_id);
  if (r < 0 || group_name < 0) FAIL(SSERV_ERR_GROUP_CREATION_FAILED);
  r = userlist_clnt_edit_field(phr->userlist_clnt, ULS_EDIT_GROUP_FIELD, group_id, 0,
                               0, USERLIST_GRP_DESCRIPTION, description);
  if (r < 0) FAIL(SSERV_ERR_DB_ERROR);

  ss_redirect_2(out_f, phr, SSERV_CMD_GROUP_BROWSE_PAGE, 0, 0, 0, 0);

cleanup:
  xfree(group_name); group_name = NULL;
  xfree(description); description = NULL;
  return retval;
}

int
super_serve_op_GROUP_MODIFY_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  int group_id = 0;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  opcap_t caps = 0;
  const struct userlist_group *g = 0;
  const unsigned char *s;
  unsigned char *group_name = NULL;
  unsigned char *description = NULL;

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  if (group_id <= 0) FAIL(SSERV_ERR_INV_GROUP_ID);

  if (!phr->userlist_clnt) FAIL(SSERV_ERR_DB_ERROR);
  r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_GET_GROUP_INFO,
                                   group_id, &xml_text);
  if (r < 0) FAIL(SSERV_ERR_DB_ERROR);
  users = userlist_parse_str(xml_text);
  if (!users) FAIL(SSERV_ERR_DB_ERROR);
  if (group_id >= users->group_map_size || !(g = users->group_map[group_id]))
    FAIL(SSERV_ERR_INV_GROUP_ID);

  s = 0;
  if (hr_cgi_param(phr, "group_name", &s) <= 0 || !s) FAIL(SSERV_ERR_INV_GROUP_NAME);
  group_name = fix_string(s);
  if (!group_name || !*group_name) FAIL(SSERV_ERR_INV_GROUP_NAME);
  if (strlen(group_name) > 1024) FAIL(SSERV_ERR_INV_GROUP_NAME);
  if (!is_valid_login(group_name)) FAIL(SSERV_ERR_INV_GROUP_NAME);

  s = 0;
  if (hr_cgi_param(phr, "description", &s) < 0) FAIL(SSERV_ERR_INV_DESCRIPTION);
  if (!s) {
    description = xstrdup("");
  } else {
    description = fix_string(s);
  }
  if (!description) description = xstrdup("");
  if (strlen(description) > 1024) FAIL(SSERV_ERR_INV_DESCRIPTION);

  if (!g->group_name || strcmp(g->group_name, group_name) != 0) {
    r = userlist_clnt_edit_field(phr->userlist_clnt, ULS_EDIT_GROUP_FIELD,
                                 group_id, 0, 0, USERLIST_GRP_GROUP_NAME, group_name);
    if (r < 0) FAIL(SSERV_ERR_DB_ERROR);
  }

  if (!g->description || strcmp(g->description, description) != 0) {
    r = userlist_clnt_edit_field(phr->userlist_clnt, ULS_EDIT_GROUP_FIELD,
                                 group_id, 0, 0, USERLIST_GRP_DESCRIPTION, description);
    if (r < 0) FAIL(SSERV_ERR_DB_ERROR);
  }

  ss_redirect_2(out_f, phr, SSERV_CMD_GROUP_BROWSE_PAGE, 0, 0, 0, 0);

cleanup:
  userlist_free(&users->b); users = 0;
  xfree(xml_text); xml_text = 0;
  xfree(group_name); group_name = NULL;
  xfree(description); description = NULL;
  return retval;
}

int
super_serve_op_GROUP_DELETE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  int group_id = 0;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  opcap_t caps = 0;
  const struct userlist_group *g = 0;

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_DELETE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  if (group_id <= 0) FAIL(SSERV_ERR_INV_GROUP_ID);

  if (!phr->userlist_clnt) FAIL(SSERV_ERR_DB_ERROR);
  r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_GET_GROUP_INFO,
                                   group_id, &xml_text);
  if (r < 0) FAIL(SSERV_ERR_DB_ERROR);
  users = userlist_parse_str(xml_text);
  if (!users) FAIL(SSERV_ERR_DB_ERROR);
  if (group_id >= users->group_map_size || !(g = users->group_map[group_id]))
    FAIL(SSERV_ERR_INV_GROUP_ID);

  r = userlist_clnt_delete_info(phr->userlist_clnt, ULS_DELETE_GROUP, group_id, 0, 0);
  if (r < 0) FAIL(SSERV_ERR_DB_ERROR);

  ss_redirect_2(out_f, phr, SSERV_CMD_GROUP_BROWSE_PAGE, 0, 0, 0, 0);

cleanup:
  userlist_free(&users->b); users = 0;
  xfree(xml_text); xml_text = 0;
  return retval;
}

void
ss_find_elem_positions(
        unsigned char *text,
        int size,
        int *p_user_map_count,
        int *p_user_map_begin,
        int *p_user_map_end,
        int *p_caps_count,
        int *p_caps_begin,
        int *p_caps_end)
{
  unsigned char *xml_text = xmemdup(text, size);
  unsigned char *pos = xml_text;

  // preprocess
  while (*pos) {
    if (pos[0] == '<' && pos[1] == '?'
        && pos[2] == 'x' && pos[3] == 'm' && pos[4] == 'l'
        && isspace(pos[5])) {
      pos[0] = ' '; pos[1] = ' '; pos[2] = ' '; pos[3] = ' '; pos[4] = ' ';
      pos += 5;
      while (pos[0] && (pos[0] != '?' || pos[1] != '>')) {
        *pos++ = ' ';
      }
      if (pos[0] == '?' && pos[1] == '>') {
        pos[0] = ' ';
        pos[1] = ' ';
        pos += 2;
      }
    } else if (pos[0] == '<' && pos[1] == '!' && pos[2] == '-' && pos[3] == '-') {
      pos[0] = ' '; pos[1] = ' '; pos[2] = ' '; pos[3] = ' ';
      pos += 4;
      while (pos[0] && (pos[0] != '-' || pos[1] != '-' || pos[2] != '>')) {
        *pos++ = ' ';
      }
      if (pos[0] == '-' && pos[1] == '-' && pos[2] == '>') {
        pos[0] = ' '; pos[1] = ' '; pos[2] = ' ';
        pos += 3;
      }
    } else if (pos[0] == '"') {
      *pos++ = ' ';
      while (pos[0] && pos[0] != '"') {
        *pos++ = ' ';
      }
      if (pos[0] == '"') {
        *pos++ = ' ';
      }
    } else if (pos[0] == '\'') {
      *pos++ = ' ';
      while (pos[0] && pos[0] != '\'') {
        *pos++ = ' ';
      }
      if (pos[0] == '\'') {
        *pos++ = ' ';
      }
    } else if (pos[0] < ' ' && pos[0] != '\n') {
      *pos++ = ' ';
    } else if (pos[0] == 127) {
      *pos++ = ' ';
    } else {
      ++pos;
    }
  }

  *p_user_map_count = 0;
  *p_user_map_begin = -1;
  *p_user_map_end = -1;
  *p_caps_count = 0;
  *p_caps_begin = -1;
  *p_caps_end = -1;

  // detect <user_map>
  if ((pos = strstr(xml_text, "<user_map>"))) {
    if (strstr(pos + 1, "<user_map>")) {
      *p_user_map_count = 2;
    } else {
      *p_user_map_count = 1;
      *p_user_map_begin = pos - xml_text;
      if ((pos = strstr(pos, "</user_map>"))) {
        *p_user_map_end = pos - xml_text + 11;
      }
    }
  }

  // detect <caps>
  if ((pos = strstr(xml_text, "<caps>"))) {
    if (strstr(pos + 1, "<caps>")) {
      *p_caps_count = 2;
    } else {
      *p_caps_count = 1;
      *p_caps_begin = pos - xml_text;
      if ((pos = strstr(pos, "</caps>"))) {
        *p_caps_end = pos - xml_text + 7;
      }
    }
  }

  xfree(xml_text);
}

int
super_serve_op_EJUDGE_XML_CANCEL_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  fprintf(out_f, "Location: %s?SID=%016llx\n", phr->self_url, phr->session_id);
  if (phr->client_key) {
    fprintf(out_f, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", phr->client_key);
  }
  putc('\n', out_f);
  return 0;
}

static int
save_caps_file(FILE *log_f, const struct ejudge_cfg *cfg)
{
  int retval = 0;
  unsigned char caps_xml_tmp_path[PATH_MAX];
  unsigned char caps_xml_bak_path[PATH_MAX];
  FILE *f = NULL;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  caps_xml_tmp_path[0] = 0;
  caps_xml_bak_path[0] = 0;

  if (!cfg->caps_file) return 0;
  if (!cfg->caps_file_info) return 0;
  if (!cfg->caps_file_info->root) return 0;
  if (!cfg->caps_file_info->path) return 0;

  struct ejudge_cfg *root = cfg->caps_file_info->root;
  int pid = getpid();
  time_t cur_time = time(0);
  struct tm *ptm = localtime(&cur_time);

  snprintf(caps_xml_tmp_path, sizeof(caps_xml_tmp_path),
           "%s.tmp.%04d%02d%02d.%d", cfg->caps_file_info->path,
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, pid);
  snprintf(caps_xml_bak_path, sizeof(caps_xml_bak_path),
           "%s.bak.%04d%02d%02d", cfg->caps_file_info->path,
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);

  if (!(f = fopen(caps_xml_tmp_path, "w"))) {
    fprintf(log_f, "failed to open '%s' for writing\n", caps_xml_tmp_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\"?>\n"
          "<config>\n", EJUDGE_CHARSET);
  fprintf(f, "  <user_map>\n");
  if (root->user_map) {
    for (const struct xml_tree *p = root->user_map->first_down; p; p = p->right) {
      const struct ejudge_cfg_user_map *m = (const struct ejudge_cfg_user_map*) p;
      fprintf(f, "    <map system_user=\"%s\"", ARMOR(m->system_user_str));
      fprintf(f, " local_user=\"%s\" />\n", ARMOR(m->local_user_str));
    }
  }
  fprintf(f, "  </user_map>\n");
  fprintf(f, "  <caps>\n");
  if (root->capabilities.first) {
    for (const struct opcap_list_item *p = root->capabilities.first; p;
         p = (const struct opcap_list_item*) p->b.right) {
      fprintf(f, "    <cap login=\"%s\">\n", ARMOR(p->login));
      unsigned char *s = opcaps_unparse(6, 60, p->caps);
      fprintf(f, "%s", s);
      xfree(s);
      fprintf(f, "    </cap>\n");
    }
  }
  fprintf(f, "  </caps>\n");
  fprintf(f, "</config>\n");
  fclose(f); f = NULL;

  struct stat stb;
  __attribute__((unused)) int _;
  if (stat(cfg->caps_file_info->path, &stb) > 0 && S_ISREG(stb.st_mode)) {
    _ = chown(caps_xml_tmp_path, -1, stb.st_gid);
    _ = chmod(caps_xml_tmp_path, stb.st_mode & 07777);
  } else {
    _ = chmod(caps_xml_tmp_path, 0600);
  }

  errno = 0;
  if (link(cfg->caps_file_info->path, caps_xml_bak_path) < 0 && errno != EEXIST) {
    fprintf(log_f, "failed to link '%s' -> '%s'\n", cfg->caps_file_info->path, caps_xml_bak_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }
  if (rename(caps_xml_tmp_path, cfg->caps_file_info->path) < 0) {
    fprintf(log_f, "failed to rename '%s' -> '%s'\n", caps_xml_tmp_path, cfg->caps_file_info->path);
    unlink(caps_xml_bak_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }
  caps_xml_tmp_path[0] = 0;

cleanup:
  html_armor_free(&ab);
  if (f) fclose(f);
  if (caps_xml_tmp_path[0]) unlink(caps_xml_tmp_path);
  return retval;
}

int
super_serve_op_USER_MAP_DELETE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0;

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }
  if (!phr->config->caps_file) goto done;

  ejudge_cfg_refresh_caps_file(phr->config, 1);

  if (!phr->config->caps_file_info) goto done;
  if (!phr->config->caps_file_info->root) goto done;
  if (!phr->config->caps_file_info->root->user_map) goto done;

  int serial = -1;
  hr_cgi_param_int_opt(phr, "serial", &serial, -1);
  if (serial <= 0) goto done;
  int i = 1;
  struct xml_tree *p = phr->config->caps_file_info->root->user_map->first_down;
  for (;p && i != serial; p = p->right, ++i) {
  }
  if (!p) goto done;
  xml_unlink_node(p);
  p = ejudge_cfg_free_subtree(p);

  if ((retval = save_caps_file(log_f, phr->config)) < 0) goto cleanup;

done:
  ss_redirect(out_f, phr, SSERV_CMD_USER_MAP_MAIN_PAGE, NULL);

cleanup:
  ejudge_cfg_refresh_caps_file(phr->config, 1);
  return retval;
}

int
super_serve_op_USER_MAP_ADD_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0;

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (!phr->config->caps_file) {
    fprintf(log_f, "<caps_file> element is undefined in ejudge.xml\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (!phr->config->caps_file_info || !phr->config->caps_file_info->root) {
    fprintf(log_f, "invalid <caps_file> element in ejudge.xml\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  const unsigned char *unix_login = NULL;
  const unsigned char *ejudge_login = NULL;
  if (hr_cgi_param(phr, "unix_login", &unix_login) <= 0) {
    fprintf(log_f, "unix login is undefined\n");
    FAIL(SSERV_ERR_INV_OPER);
  }
  if (hr_cgi_param(phr, "ejudge_login", &ejudge_login) <= 0) {
    fprintf(log_f, "ejudge login is undefined\n");
    FAIL(SSERV_ERR_INV_OPER);
  }
  struct passwd *pwd = getpwnam(unix_login);
  if (!pwd) {
    fprintf(log_f, "unix login '%s' does not exist\n", unix_login);
    FAIL(SSERV_ERR_INV_OPER);
  }
  if (pwd->pw_uid <= 0) {
    fprintf(log_f, "unix login '%s' is root login\n", unix_login);
    FAIL(SSERV_ERR_INV_OPER);
  }

  int user_id = 0;
  int r = userlist_clnt_lookup_user(phr->userlist_clnt, ejudge_login, 0, &user_id, NULL);
  if (r < 0 && r != -ULS_ERR_INVALID_LOGIN) {
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (r < 0) {
    fprintf(log_f, "ejudge login '%s' does not exist\n", ejudge_login);
    FAIL(SSERV_ERR_INV_OPER);
  }

  const unsigned char *ex_ejudge_login = ejudge_cfg_user_map_find_simple(phr->config, unix_login);
  if (ex_ejudge_login && !strcmp(ex_ejudge_login, ejudge_login)) goto done;
  if (ex_ejudge_login) {
    fprintf(log_f, "mapping of unix login '%s' cannot be changed\n", unix_login);
    FAIL(SSERV_ERR_INV_OPER);
  }
  ex_ejudge_login = ejudge_cfg_user_map_find_simple(phr->config->caps_file_info->root, unix_login);
  if (ex_ejudge_login && !strcmp(ex_ejudge_login, ejudge_login)) goto done;
  if (ex_ejudge_login) {
    fprintf(log_f, "mapping of unix login '%s' to ejudge login '%s' already exists\n", unix_login, ex_ejudge_login);
    FAIL(SSERV_ERR_INV_OPER);
  }

  ejudge_cfg_user_map_add(phr->config->caps_file_info->root, unix_login, ejudge_login);

  if ((retval = save_caps_file(log_f, phr->config)) < 0) goto cleanup;

done:
  ss_redirect(out_f, phr, SSERV_CMD_USER_MAP_MAIN_PAGE, NULL);

cleanup:
  ejudge_cfg_refresh_caps_file(phr->config, 1);
  return retval;
}

int
super_serve_op_CAPS_DELETE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0;

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }
  if (!phr->config->caps_file) goto done;

  ejudge_cfg_refresh_caps_file(phr->config, 1);

  if (!phr->config->caps_file_info) goto done;
  if (!phr->config->caps_file_info->root) goto done;
  struct ejudge_cfg *root = phr->config->caps_file_info->root;

  if (!root->capabilities.first) goto done;

  int serial = -1;
  hr_cgi_param_int_opt(phr, "serial", &serial, -1);
  if (serial <= 0) goto done;

  int i = 1;
  struct opcap_list_item *p = root->capabilities.first;
  for (; p && i != serial; p = (struct opcap_list_item*) p->b.right, ++i) {
  }
  if (!p) goto done;
  xml_unlink_node(&p->b);
  ejudge_cfg_free_subtree(&p->b);
  root->capabilities.first = (struct opcap_list_item*) root->caps_node->first_down;
  if (!root->capabilities.first) {
    xml_unlink_node(root->caps_node);
    ejudge_cfg_free_subtree(root->caps_node);
    root->caps_node = NULL;
  }

  if ((retval = save_caps_file(log_f, phr->config)) < 0) goto cleanup;

done:
  ss_redirect(out_f, phr, SSERV_CMD_CAPS_MAIN_PAGE, NULL);

cleanup:
  ejudge_cfg_refresh_caps_file(phr->config, 1);
  return retval;
}

int
super_serve_op_CAPS_ADD_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0;

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (!phr->config->caps_file) {
    fprintf(log_f, "<caps_file> element is undefined in ejudge.xml\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  ejudge_cfg_refresh_caps_file(phr->config, 1);

  if (!phr->config->caps_file_info || !phr->config->caps_file_info->root) {
    fprintf(log_f, "invalid <caps_file> element in ejudge.xml\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  struct ejudge_cfg *root = phr->config->caps_file_info->root;

  const unsigned char *ejudge_login = NULL;
  if (hr_cgi_param(phr, "ejudge_login", &ejudge_login) <= 0 || !ejudge_login) {
    fprintf(log_f, "ejudge login is undefined\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  int user_id = 0;
  int r = userlist_clnt_lookup_user(phr->userlist_clnt, ejudge_login, 0, &user_id, NULL);
  if (r < 0 && r != -ULS_ERR_INVALID_LOGIN) {
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (r < 0) {
    fprintf(log_f, "ejudge login '%s' does not exist\n", ejudge_login);
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (opcaps_find(&phr->config->capabilities, ejudge_login, &caps) >= 0) {
    fprintf(log_f, "capabilities for '%s' aready exist and cannot be changed\n", ejudge_login);
    FAIL(SSERV_ERR_INV_OPER);
  }
  if (opcaps_find(&root->capabilities, ejudge_login, &caps) >= 0) {
    fprintf(log_f, "capabilities for '%s' already exist\n", ejudge_login);
    FAIL(SSERV_ERR_INV_OPER);
  }

  ejudge_cfg_caps_add(root, ejudge_login, 0);

  if ((retval = save_caps_file(log_f, phr->config)) < 0) goto cleanup;

  ss_redirect(out_f, phr, SSERV_CMD_CAPS_MAIN_PAGE, NULL);

cleanup:
  ejudge_cfg_refresh_caps_file(phr->config, 1);
  return retval;
}

const unsigned char * const ss_global_cap_descs[OPCAP_LAST] =
{
  [OPCAP_MASTER_LOGIN] = "Allowed login to serve-control with administrative capabilities",
  [OPCAP_JUDGE_LOGIN] = "Allowed login to serve-control with less capabilities",
  [OPCAP_SUBMIT_RUN] = NULL,
  [OPCAP_MAP_CONTEST] = NULL, //"Reserved",
  [OPCAP_LIST_USERS] = "Allowed to obtain the whole user list",
  [OPCAP_PRIV_EDIT_REG] = "Allowed to edit registration info of any privileged users in any contest",
  [OPCAP_CREATE_USER] = "Allowed to create a new user",
  [OPCAP_GET_USER] = "Allowed to obtain the detailed info for any user",
  [OPCAP_EDIT_USER] = "Allowed to modify data of any non-privileged user",
  [OPCAP_DELETE_USER] = "Allowed to delete any non-privileged user",
  [OPCAP_PRIV_EDIT_USER] = "Allowed to modify data of any privileged user",
  [OPCAP_PRIV_DELETE_USER] = "Allowed to delete any privileged user",
  [OPCAP_EDIT_CONTEST] = "Allowed to edit settings of any contest",
  [OPCAP_CREATE_REG] = "Allowed to register any non-privileged user to any contest",
  [OPCAP_EDIT_REG] = "Alower to edit registration info of any non-privileged user in any contest",
  [OPCAP_DELETE_REG] = "Allowed to delete registration of any non-privileged user in any contest",
  [OPCAP_PRIV_CREATE_REG] = "Allowed to register any privileged user to any contest",
  [OPCAP_PRIV_DELETE_REG] = "Allowed to delete registration of any privileged user in any contest",
  [OPCAP_DUMP_USERS] = "Allowed to dump all users in CSV format",
  [OPCAP_DUMP_RUNS] = NULL,
  [OPCAP_DUMP_STANDINGS] = NULL,
  [OPCAP_VIEW_STANDINGS] = NULL,
  [OPCAP_VIEW_SOURCE] = NULL,
  [OPCAP_VIEW_REPORT] = NULL,
  [OPCAP_VIEW_CLAR] = NULL,
  [OPCAP_EDIT_RUN] = NULL,
  [OPCAP_REJUDGE_RUN] = NULL,
  [OPCAP_NEW_MESSAGE] = NULL,
  [OPCAP_REPLY_MESSAGE] = NULL,
  [OPCAP_CONTROL_CONTEST] = NULL,
  [OPCAP_IMPORT_XML_RUNS] = NULL,
  [OPCAP_PRINT_RUN] = NULL,
  [OPCAP_EDIT_PASSWD] = "Allowed to change registration password of any non-privileged user",
  [OPCAP_PRIV_EDIT_PASSWD] = "Allowed to change registration password of any privileged user",
  [OPCAP_RESTART] = "Allowed to restart ejudge processes",
  [OPCAP_COMMENT_RUN] = NULL,
  [OPCAP_UNLOAD_CONTEST] = "Allowed to force reload of any contest",
  [OPCAP_LOCAL_0] = "Local capability 0",
  [OPCAP_LOCAL_1] = "Local capability 1",
  [OPCAP_LOCAL_2] = "Local capability 2",
  [OPCAP_LOCAL_3] = "Local capability 3",
};

int
super_serve_op_CAPS_EDIT_CANCEL_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  ss_redirect(out_f, phr, SSERV_CMD_CAPS_MAIN_PAGE, NULL);
  return 0;
}

int
super_serve_op_CAPS_EDIT_SAVE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0;

  if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (!phr->config->caps_file) {
    fprintf(log_f, "<caps_file> element is undefined in ejudge.xml\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  ejudge_cfg_refresh_caps_file(phr->config, 1);

  if (!phr->config->caps_file_info || !phr->config->caps_file_info->root) {
    fprintf(log_f, "invalid <caps_file> element in ejudge.xml\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  struct ejudge_cfg *root = phr->config->caps_file_info->root;

  int serial = -1;
  hr_cgi_param_int_opt(phr, "serial", &serial, -1);
  if (serial <= 0) FAIL(SSERV_ERR_INV_OPER);

  int i = 1;
  struct opcap_list_item *p = root->capabilities.first;
  for (; p && i != serial; p = (struct opcap_list_item*) p->b.right, ++i) {
  }
  if (!p) FAIL(SSERV_ERR_INV_OPER);

  opcap_t new_caps = 0;
  for (int cap = 0; cap < OPCAP_LAST; ++cap) {
    unsigned char nbuf[64];
    snprintf(nbuf, sizeof(nbuf), "cap_%d", cap);
    const unsigned char *s = NULL;
    if (hr_cgi_param(phr, nbuf, &s) > 0 && s) {
      new_caps |= 1ULL << cap;
    }
  }

  if (p->caps != new_caps) {
    p->caps = new_caps;
    if ((retval = save_caps_file(log_f, phr->config)) < 0) goto cleanup;
  }

  ss_redirect(out_f, phr, SSERV_CMD_CAPS_MAIN_PAGE, NULL);

cleanup:
  ejudge_cfg_refresh_caps_file(phr->config, 1);
  return retval;
}

static char *
trim_fgets(unsigned char *buf, size_t size, FILE *f)
{
  if (!fgets(buf, size, f)) return NULL;
  size_t len = strlen(buf);
  while (len > 0 && isspace((unsigned char) buf[len - 1])) --len;
  buf[len] = 0;
  return buf;
}

int
ss_get_saved_auth(
        const unsigned char *ej_login,
        unsigned char **p_poly_login,
        unsigned char **p_poly_password,
        unsigned char **p_poly_url,
        unsigned char **p_poly_key,
        unsigned char **p_poly_secret)
{
  unsigned char path[PATH_MAX];
  FILE *f = NULL;
  unsigned char lb[1024], pb[1024], ub[1024], kb[1024], sb[1024];

  lb[0] = 0;
  pb[0] = 0;
  ub[0] = 0;
  kb[0] = 0;
  sb[0] = 0;
  snprintf(path, sizeof(path), "%s/db/%s", EJUDGE_CONF_DIR, ej_login);
  if (!(f = fopen(path, "r"))) return -1;

  (void) (trim_fgets(lb, sizeof(lb), f)
          && trim_fgets(pb, sizeof(pb), f)
          && trim_fgets(ub, sizeof(ub), f)
          && trim_fgets(kb, sizeof(kb), f)
          && trim_fgets(sb, sizeof(sb), f));

  *p_poly_login = xstrdup(lb);
  *p_poly_password = xstrdup(pb);
  *p_poly_url = xstrdup(ub);
  if (p_poly_key) *p_poly_key = xstrdup(kb);
  if (p_poly_secret) *p_poly_secret = xstrdup(sb);

  return 1;
}

static void
save_auth(
        const unsigned char *ej_login,
        const unsigned char *poly_login,
        const unsigned char *poly_password,
        const unsigned char *poly_url,
        const unsigned char *poly_key,
        const unsigned char *poly_secret)
{
  unsigned char path[PATH_MAX];
  FILE *f = NULL;

  if (!poly_login) poly_login = "";
  if (!poly_password) poly_password = "";
  if (!poly_url) poly_url = "";
  if (!poly_key) poly_key = "";
  if (!poly_secret) poly_secret = "";

  snprintf(path, sizeof(path), "%s/db/%s", EJUDGE_CONF_DIR, ej_login);
  if (!(f = fopen(path, "w"))) {
    return;
  }
  fprintf(f, "%s\n%s\n%s\n%s\n%s\n", poly_login, poly_password, poly_url,
          poly_key, poly_secret);
  fflush(f);
  if (ferror(f)) {
    fclose(f); unlink(path);
    return;
  }
  fclose(f);
  chmod(path, 0600);
}

int
ss_find_free_prob_id(const struct sid_state *ss)
{
  if (ss->prob_a <= 1) return 1;
  if (ss->probs[ss->prob_a - 1]) return ss->prob_a;

  int prob_id = ss->prob_a - 1;
  while (prob_id > 0 && !ss->probs[prob_id]) --prob_id;
  if (prob_id <= 0) {
    prob_id = 1;
  } else {
    ++prob_id;
  }
  return prob_id;
}

int
ss_find_free_prob_id_and_name(
        const struct sid_state *ss,
        unsigned char *prob_buf,
        size_t buf_size)
{
  int prob_id = ss_find_free_prob_id(ss);
  unsigned char name_buf[128];
  int short_id = prob_id;

  int found = 0;
  do {
    problem_id_to_short_name(short_id, name_buf);
    for (int i = 0; i < ss->prob_a; ++i) {
      if (ss->probs[i] && !strcmp(ss->probs[i]->short_name, name_buf)) {
        found = 1;
        break;
      }
    }
  } while (found);

  snprintf(prob_buf, buf_size, "%s", name_buf);
  return prob_id;
}

int
super_serve_op_IMPORT_FROM_POLYGON_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0, lcaps = 0;
  struct sid_state *ss = phr->ss;
  int ej_prob_id = 0;
  const unsigned char *s = NULL;
  int r;
  unsigned char *ej_short_name = NULL;
  unsigned char *polygon_login = NULL;
  unsigned char *polygon_password = NULL;
  unsigned char *polygon_id = NULL;
  unsigned char *polygon_url = NULL;
  unsigned char *polygon_key = NULL;
  unsigned char *polygon_secret = NULL;
  const unsigned char *language_priority = NULL;
  int save_auth_flag = 0;
  int max_stack_size_flag = 0;
  int ignore_solutions_flag = 0;
  int fetch_latest_available_flag = 0;
  struct polygon_packet *pp = NULL;
  const struct contest_desc *cnts = ss->edited_cnts;
  struct update_state *us = NULL;
  FILE *f = NULL;
  int contest_mode = 0;
  unsigned char *polygon_contest_id = NULL;
  int upload_mode = 0;
  const unsigned char *package_file_data = NULL;
  size_t package_file_size = 0;
  int binary_input_flag = 0;
  int enable_iframe_statement_flag = 0;
  int enable_api_flag = 0;
  int verbose_flag = 0;
  int ignore_main_solution_flag = 0;

  if (!ss->edited_cnts || !ss->global) {
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  }

  ss_get_global_caps(phr, &caps);
  ss_get_contest_caps(phr, ss->edited_cnts, &lcaps);
  caps |= lcaps;

  if (opcaps_check(lcaps, OPCAP_EDIT_CONTEST) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (ss->update_state) {
    fprintf(log_f, "there is a background update in progress\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (ss->global->advanced_layout <= 0) {
    fprintf(log_f, "advanced_layout must be set\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (hr_cgi_param(phr, "verbose", &s) > 0) verbose_flag = 1;

  hr_cgi_param_int_opt(phr, "contest_mode", &contest_mode, 0);
  contest_mode = !!contest_mode;

  if (!contest_mode) {
    hr_cgi_param_int_opt(phr, "ejudge_id", &ej_prob_id, 0);
    if (ej_prob_id < 0) {
      fprintf(log_f, "ejudge problem id (%d) is invalid\n", ej_prob_id);
      FAIL(SSERV_ERR_INV_OPER);
    }
    if (ej_prob_id > EJ_MAX_PROB_ID) {
      fprintf(log_f, "ejudge problem id (%d) is too big\n", ej_prob_id);
      FAIL(SSERV_ERR_INV_OPER);
    }
    if (ej_prob_id < ss->prob_a && ss->probs[ej_prob_id]) {
      fprintf(log_f, "ejudge problem id (%d) is already used\n", ej_prob_id);
      FAIL(SSERV_ERR_INV_OPER);
    }

    if ((r = hr_cgi_param(phr, "ejudge_short_name", &s)) < 0) {
      fprintf(log_f, "ejudge problem short name is invalid\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    if (!r) {
      fprintf(log_f, "ejudge problem short name is undefined\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    ej_short_name = fix_string_2(s);
    if (!ej_short_name) {
      fprintf(log_f, "ejudge problem short name is undefined\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
  // FIXME: check for valid characters
  }

  if (hr_cgi_param_bin(phr, "package_file", &package_file_data, &package_file_size) > 0 && package_file_size > 0) {
    upload_mode = 1;
  }

  if (!upload_mode) {
    if (hr_cgi_param(phr, "enable_api", &s) > 0) enable_api_flag = 1;

    if (!enable_api_flag) {
      if ((r = hr_cgi_param(phr, "polygon_login", &s)) < 0) {
        fprintf(log_f, "polygon login is invalid\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      if (!r || !s || !*s) {
        fprintf(log_f, "polygon login is undefined\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      polygon_login = xstrdup(s);

      if ((r = hr_cgi_param(phr, "polygon_password", &s)) < 0) {
        fprintf(log_f, "polygon password is invalid\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      if (!r || !s || !*s) {
        fprintf(log_f, "polygon password is undefined\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      polygon_password = xstrdup(s);
    }

    if (hr_cgi_param(phr, "save_auth", &s) > 0) save_auth_flag = 1;

    if (enable_api_flag) {
      if ((r = hr_cgi_param(phr, "polygon_key", &s)) < 0) {
        fprintf(log_f, "polygon key is invalid\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      if (!r || !s || !*s) {
        fprintf(log_f, "polygon key is undefined\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      polygon_key = xstrdup(s);

      if ((r = hr_cgi_param(phr, "polygon_secret", &s)) < 0) {
        fprintf(log_f, "polygon secret is invalid\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      if (!r || !s || !*s) {
        fprintf(log_f, "polygon secret is undefined\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      polygon_secret = xstrdup(s);
    }

    if (contest_mode) {
      if ((r = hr_cgi_param(phr, "polygon_contest_id", &s)) < 0) {
        fprintf(log_f, "polygon contest id/name is invalid\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      if (!r) {
        fprintf(log_f, "polygon contest id/name is undefined\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      polygon_contest_id = fix_string_2(s);
      if (!polygon_contest_id) {
        fprintf(log_f, "polygon contest id/name is undefined\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
    } else {
      if ((r = hr_cgi_param(phr, "polygon_id", &s)) < 0) {
        fprintf(log_f, "polygon problem id/name is invalid\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      if (!r) {
        fprintf(log_f, "polygon problem id/name is undefined\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
      polygon_id = fix_string_2(s);
      if (!polygon_id) {
        fprintf(log_f, "polygon problem id/name is undefined\n");
        FAIL(SSERV_ERR_INV_OPER);
      }
    }

    if ((r = hr_cgi_param(phr, "polygon_url", &s)) < 0) {
      fprintf(log_f, "polygon url is invalid\n");
      FAIL(SSERV_ERR_INV_OPER);
    } else if (r > 0) {
      polygon_url = fix_string_2(s);
    }
  }

  if (hr_cgi_param(phr, "max_stack_size", &s) > 0) max_stack_size_flag = 1;
  if (hr_cgi_param(phr, "ignore_main_solution", &s) > 0) ignore_main_solution_flag = 1;
  if (hr_cgi_param(phr, "ignore_solutions", &s) > 0) ignore_solutions_flag = 1;
  if (hr_cgi_param(phr, "fetch_latest_available", &s) > 0) fetch_latest_available_flag = 1;
  if (hr_cgi_param(phr, "binary_input", &s) > 0) binary_input_flag = 1;
  if (hr_cgi_param(phr, "enable_iframe_statement", &s) > 0) enable_iframe_statement_flag = 1;

  if (hr_cgi_param(phr, "language_priority", &s) > 0 && *s) {
    if (!strcmp(s, "ru,en")
        || !strcmp(s, "en,ru")) {
      language_priority = s;
    }
  }

  if (!upload_mode) {
    if (save_auth_flag) {
      save_auth(phr->login, polygon_login, polygon_password, polygon_url, polygon_key, polygon_secret);
    }
  }

  s = getenv("TMPDIR");
  if (!s) s = getenv("TEMPDIR");
#if defined P_tmpdir
  if (!s) s = P_tmpdir;
#endif
  if (!s) s = "/tmp";

  time_t cur_time = time(NULL);
  unsigned char rand_base[PATH_MAX];
  unsigned char working_dir[PATH_MAX];
  snprintf(rand_base, sizeof(rand_base), "%s_%d", phr->login, (int) cur_time);
  snprintf(working_dir, sizeof(working_dir), "%s/ej_download_%s", s, rand_base);

  if (mkdir(working_dir, 0700) < 0) {
    if (errno != EEXIST) {
      fprintf(log_f, "mkdir '%s' failed: %s\n", working_dir, os_ErrorMsg());
      FAIL(SSERV_ERR_FS_ERROR);
    }
    int serial = 1;
    for (; serial < 10; ++serial) {
      snprintf(working_dir, sizeof(working_dir), "%s/ej_download_%s_%d", s, rand_base, serial);
      if (mkdir(working_dir, 0700) >= 0) break;
      if (errno != EEXIST) {
        fprintf(log_f, "mkdir '%s' failed: %s\n", working_dir, os_ErrorMsg());
        FAIL(SSERV_ERR_FS_ERROR);
      }
    }
    if (serial >= 10) {
      fprintf(log_f, "failed to create working directory '%s': too many attempts\n", working_dir);
      FAIL(SSERV_ERR_OPERATION_FAILED);
    }
  }

  unsigned char package_path[PATH_MAX];
  package_path[0] = 0;
  if (upload_mode > 0) {
    snprintf(package_path, sizeof(package_path), "%s/pkg_%s", working_dir, rand_base);
    int r = generic_write_file(package_file_data, package_file_size, 0,
                               NULL, package_path, NULL);
    if (r < 0) {
      FAIL(SSERV_ERR_OPERATION_FAILED);
    }
    r = mime_type_guess_file(package_path, 0);
    if (r < 0) {
      FAIL(SSERV_ERR_OPERATION_FAILED);
    }
    if (r != MIME_TYPE_APPL_ZIP) {
      FAIL(SSERV_ERR_OPERATION_FAILED);
    }
    unsigned char tmp_pkg_path[PATH_MAX];
    snprintf(tmp_pkg_path, sizeof(tmp_pkg_path), "%s.zip", package_path);
    rename(package_path, tmp_pkg_path);
    snprintf(package_path, sizeof(package_path), "%s", tmp_pkg_path);
  }

  unsigned char conf_path[PATH_MAX];
  unsigned char log_path[PATH_MAX];
  unsigned char pid_path[PATH_MAX];
  unsigned char stat_path[PATH_MAX];
  unsigned char download_path[PATH_MAX];
  unsigned char problem_path[PATH_MAX];
  unsigned char start_path[PATH_MAX];

  snprintf(conf_path, sizeof(conf_path), "%s/conf.cfg", working_dir);
  snprintf(log_path, sizeof(log_path), "%s/log.txt", working_dir);
  snprintf(pid_path, sizeof(pid_path), "%s/pid.txt", working_dir);
  snprintf(stat_path, sizeof(stat_path), "%s/stat.txt", working_dir);
  snprintf(download_path, sizeof(download_path), "%s/download", cnts->root_dir);
  snprintf(problem_path, sizeof(problem_path), "%s/problems", cnts->root_dir);
  snprintf(start_path, sizeof(start_path), "%s/ej-polygon", EJUDGE_SERVER_BIN_PATH);

  pp = polygon_packet_alloc();
  pp->enable_max_stack_size = max_stack_size_flag;
  pp->ignore_main_solution = ignore_main_solution_flag;
  pp->ignore_solutions = ignore_solutions_flag;
  pp->binary_input = binary_input_flag;
  pp->enable_iframe_statement = enable_iframe_statement_flag;
  pp->verbose = verbose_flag;
  pp->create_mode = 1;
  if (upload_mode <= 0) {
    pp->fetch_latest_available = fetch_latest_available_flag;
    pp->polygon_url = polygon_url; polygon_url = NULL;
    pp->login = polygon_login; polygon_login = NULL;
    pp->password = polygon_password; polygon_password = NULL;
    if (enable_api_flag) {
      pp->enable_api = 1;
      pp->key = polygon_key; polygon_key = NULL;
      pp->secret = polygon_secret; polygon_secret = NULL;
    }
  }
  pp->language_priority = xstrdup2(language_priority);
  pp->working_dir = xstrdup(working_dir);
  pp->log_file = xstrdup(log_path);
  pp->status_file = xstrdup(stat_path);
  pp->pid_file = xstrdup(pid_path);
  pp->download_dir = xstrdup(download_path);
  pp->problem_dir = xstrdup(problem_path);
  pp->dir_mode = xstrdup2(cnts->dir_mode);
  pp->dir_group = xstrdup2(cnts->dir_group);
  pp->file_mode = xstrdup2(cnts->file_mode);
  pp->file_group = xstrdup2(cnts->file_group);
  if (contest_mode) {
    pp->polygon_contest_id = xstrdup2(polygon_contest_id);
  } else {
    XCALLOC(pp->id, 2);
    pp->id[0] = polygon_id; polygon_id = NULL;
    if (ej_prob_id > 0) {
      unsigned char buf[64];
      snprintf(buf, sizeof(buf), "%d", ej_prob_id);
      XCALLOC(pp->ejudge_id, 2);
      pp->ejudge_id[0] = xstrdup(buf);
    }
    if (ej_short_name) {
      XCALLOC(pp->ejudge_short_name, 2);
      pp->ejudge_short_name[0] = ej_short_name; ej_short_name = NULL;
    }
  }
  if (package_path[0]) {
    pp->package_file = xstrdup(package_path);
  }

  if (!(f = fopen(conf_path, "w"))) {
    fprintf(log_f, "failed to open file '%s': %s\n", conf_path, os_ErrorMsg());
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  polygon_packet_unparse(f, pp);
  fclose(f); f = NULL;

  us = update_state_create();
  us->start_time = cur_time;
  us->contest_id = cnts->id;
  us->create_mode = 1;
  us->contest_mode = contest_mode;
  us->working_dir = xstrdup(working_dir);
  us->conf_file = xstrdup(conf_path);
  us->log_file = xstrdup(log_path);
  us->status_file = xstrdup(stat_path);
  us->pid_file = xstrdup(pid_path);
  ss->update_state = us; us = NULL;

  char *args[3];
  args[0] = start_path;
  args[1] = conf_path;
  args[2] = NULL;
  ejudge_start_daemon_process(args, working_dir);

  ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);

cleanup:
  xfree(polygon_contest_id);
  xfree(ej_short_name);
  xfree(polygon_login);
  xfree(polygon_password);
  xfree(polygon_id);
  xfree(polygon_url);
  polygon_packet_free((struct generic_section_config*) pp);
  update_state_free(us);
  return retval;
}

int
ss_read_download_status(
        FILE *log_f,
        const unsigned char *path,
        FILE *f,
        int *p_exit_code,
        int *p_count,
        struct ss_download_status **p_statuses)
{
  unsigned char buf[1024];
  int len, exit_code = -1, n, count = 0;
  struct ss_download_status *statuses = NULL;

  if (!fgets(buf, sizeof(buf), f)) {
    fprintf(log_f, "%s: unexpected EOF for exit_code\n", path);
    goto fail;
  }
  if ((len = strlen(buf)) + 1 >= sizeof(buf)) {
    fprintf(log_f, "%s: exit_code line is too long\n", path);
    goto fail;
  }
  while (len > 0 && isspace(buf[len - 1])) --len;
  buf[len] = 0;
  if (len <= 0) {
    fprintf(log_f, "%s: exit_code line is empty\n", path);
    goto fail;
  }
  if (sscanf(buf, "%d%n", &exit_code, &n) != 1 || buf[n] || exit_code < 0 || exit_code >= 256) {
    fprintf(log_f, "%s: exit_code is invalid\n", path);
    goto fail;
  }

  if (!fgets(buf, sizeof(buf), f)) {
    fprintf(log_f, "%s: unexpected EOF for count\n", path);
    goto fail;
  }
  if ((len = strlen(buf)) + 1 >= sizeof(buf)) {
    fprintf(log_f, "%s: count line is too long\n", path);
    goto fail;
  }
  while (len > 0 && isspace(buf[len - 1])) --len;
  buf[len] = 0;
  if (len <= 0) {
    fprintf(log_f, "%s: count line is empty\n", path);
    goto fail;
  }
  if (sscanf(buf, "%d%n", &count, &n) != 1 || buf[n] || count <= 0 || count > 1024) {
    fprintf(log_f, "%s: count is invalid\n", path);
    goto fail;
  }

  XCALLOC(statuses, count);
  for (int i = 0; i < count; ++i) {
    if (!fgets(buf, sizeof(buf), f)) {
      fprintf(log_f, "%s: unexpected EOF for status[%d]\n", path, i + 1);
      goto fail;
    }
    if ((len = strlen(buf)) + 1 >= sizeof(buf)) {
      fprintf(log_f, "%s: status[%d] line is too long\n", path, i + 1);
      goto fail;
    }
    while (len > 0 && isspace(buf[len - 1])) --len;
    buf[len] = 0;
    if (len <= 0) {
      fprintf(log_f, "%s: status[%d] line is empty\n", path, i + 1);
      goto fail;
    }
    unsigned char *s = buf, *q;
    if (!(q = strchr(s, ';'))) q = strchr(s, 0);
    statuses[i].key = xmemdup(s, q - s);
    s = q;
    if (*s == ';') ++s;
    if (!(q = strchr(s, ';'))) q = strchr(s, 0);
    statuses[i].status = xmemdup(s, q - s);
    s = q;
    if (*s == ';') ++s;
    if (!(q = strchr(s, ';'))) q = strchr(s, 0);
    statuses[i].polygon_id = xmemdup(s, q - s);
    s = q;
    if (*s == ';') ++s;
    if (!(q = strchr(s, ';'))) q = strchr(s, 0);
    statuses[i].polygon_name = xmemdup(s, q - s);
    s = q;
    if (*s == ';') ++s;
  }

  *p_exit_code = exit_code;
  *p_count = count;
  *p_statuses = statuses;
  return count;

fail:
  if (statuses) {
    for (int i = 0; i < count; ++i) {
      xfree(statuses[i].key);
      xfree(statuses[i].status);
      xfree(statuses[i].polygon_id);
      xfree(statuses[i].polygon_name);
    }
    xfree(statuses);
  }
  return -1;
}

int
super_serve_op_DOWNLOAD_CLEANUP_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct sid_state *ss = phr->ss;
  struct update_state *us = ss->update_state;
  int pid = 0;
  FILE *f = NULL;

  if (!us) {
    // redirect to main page
    ss_redirect_3(out_f, phr, 0, NULL);
    goto cleanup;
  }
  if (us->pid_file) {
    f = fopen(us->pid_file, "r");
    if (f && fscanf(f, "%d", &pid) == 1 && pid > 0 && kill(pid, 0) >= 0) {
      ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);
      goto cleanup;
    }
  }
  if (us->working_dir) {
    remove_directory_recursively(us->working_dir, 0);
  }
  ss->update_state = NULL;

  if (ss->edited_cnts) {
    ss_redirect_3(out_f, phr, SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE, NULL);
    goto cleanup;
  }
  if (us->contest_id <= 0) {
    ss_redirect_3(out_f, phr, 0, NULL);
    goto cleanup;
  }

  int action = SSERV_CMD_CONTEST_PAGE;
  if (phr->action == SSERV_CMD_DOWNLOAD_CLEANUP_AND_CHECK_ACTION) action = SSERV_CMD_CHECK_TESTS_PAGE;
  ss_redirect_3(out_f, phr, action, "contest_id=%d", us->contest_id);

cleanup:
  if (f) fclose(f);
  update_state_free(us);
  return retval;
}

int
super_serve_op_DOWNLOAD_KILL_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct sid_state *ss = phr->ss;
  struct update_state *us = ss->update_state;
  int pid = 0;
  FILE *f = NULL;

  if (!us) {
    // redirect to main page
    ss_redirect_3(out_f, phr, 0, NULL);
    goto cleanup;
  }
  if (us->pid_file) {
    f = fopen(us->pid_file, "r");
    if (f && fscanf(f, "%d", &pid) == 1 && pid > 0) {
      kill(pid, SIGTERM);
    }
  }

  ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);

cleanup:
  if (f) fclose(f);
  return retval;
}

static int
do_import_problem(
        FILE *log_f,
        struct http_request_info *phr,
        const unsigned char *internal_name)
{
  int retval = 0;
  struct sid_state *ss = phr->ss;
  FILE *f = NULL;
  struct problem_config_section *cfg = NULL;

  if (!internal_name || !*internal_name) {
    fprintf(log_f, "internal name is empty\n");
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  for (int prob_id = 1; prob_id < ss->prob_a; ++prob_id) {
    struct section_problem_data *prob = ss->probs[prob_id];
    if (prob && prob->internal_name && !strcmp(prob->internal_name, internal_name)) {
      fprintf(log_f, "internal name '%s' is not unique in this contest\n", internal_name);
      FAIL(SSERV_ERR_OPERATION_FAILED);
    }
    if (prob /*&& prob->short_name*/ && !strcmp(prob->short_name, internal_name)) {
      fprintf(log_f, "internal name '%s' matches short name in this contest\n", internal_name);
      FAIL(SSERV_ERR_OPERATION_FAILED);
    }
  }

  unsigned char problem_dir[PATH_MAX];
  snprintf(problem_dir, sizeof(problem_dir), "%s/problems/%s", ss->edited_cnts->root_dir, internal_name);

  unsigned char config_file[PATH_MAX];
  snprintf(config_file, sizeof(config_file), "%s/problem.cfg", problem_dir);
  if (!(f = fopen(config_file, "r"))) {
    fprintf(log_f, "cannot open '%s' for reading: %s\n", config_file, os_ErrorMsg());
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  cfg = problem_config_section_parse_cfg(config_file, f);
  f = NULL;
  if (!cfg) {
    fprintf(log_f, "failed to parse '%s'\n", config_file);
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }

  if (cfg->id < 0) cfg->id = 0;
  if (cfg->id > EJ_MAX_PROB_ID) {
    fprintf(log_f, "invalid problem id %d\n", cfg->id);
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  if (cfg->id > 0 && cfg->id < ss->prob_a && ss->probs[cfg->id]) {
    fprintf(log_f, "problem id %d is already used\n", cfg->id);
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  if (!cfg->internal_name || !*cfg->internal_name) {
    fprintf(log_f, "internal_name is undefined in '%s'\n", config_file);
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  if (strcmp(cfg->internal_name, internal_name)) {
    fprintf(log_f, "internal_name (%s) in '%s' does not match the status file (%s)\n",
            cfg->internal_name, config_file, internal_name);
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }

  if (cfg->short_name && *cfg->short_name) {
    for (int prob_id = 1; prob_id < ss->prob_a; ++prob_id) {
      struct section_problem_data *prob = ss->probs[prob_id];
      if (prob /*&& prob->short_name*/ && !strcmp(prob->short_name, cfg->short_name)) {
        fprintf(log_f, "short name '%s' is not unique in this contest\n", cfg->short_name);
        FAIL(SSERV_ERR_OPERATION_FAILED);
      }
      if (prob && prob->internal_name && !strcmp(prob->internal_name, cfg->short_name)) {
        fprintf(log_f, "short name '%s' matches internal name in this contest\n", cfg->short_name);
        FAIL(SSERV_ERR_OPERATION_FAILED);
      }
    }
    if (cfg->id <= 0) cfg->id = ss_find_free_prob_id(ss);
  } else {
    if (cfg->id <= 0) cfg->id = ss_find_free_prob_id(ss);
    unsigned char name_buf[32];
    problem_id_to_short_name(cfg->id - 1, name_buf);
    for (int prob_id = 1; prob_id < ss->prob_a; ++prob_id) {
      struct section_problem_data *prob = ss->probs[prob_id];
      if (prob /*&& prob->short_name*/ && !strcmp(prob->short_name, name_buf)) {
        fprintf(log_f, "failed to auto-assign short_name\n");
        FAIL(SSERV_ERR_OPERATION_FAILED);
      }
      if (prob && prob->internal_name && !strcmp(prob->internal_name, name_buf)) {
        fprintf(log_f, "failed to auto-assign short_name\n");
        FAIL(SSERV_ERR_OPERATION_FAILED);
      }
    }
    xfree(cfg->short_name); cfg->short_name = xstrdup(name_buf);
  }

  struct section_problem_data *super_prob = NULL;
  if (ss->aprob_u == 1) super_prob = ss->aprobs[0];

  struct section_problem_data *prob = super_html_create_problem(ss, cfg->id);
  if (!prob) {
    fprintf(log_f, "failed to create a problem\n");
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  snprintf(prob->short_name, sizeof(prob->short_name), "%s", cfg->short_name);
  if (super_prob) {
    snprintf(prob->super, sizeof(prob->super), "%s", super_prob->short_name);
  }
  xstrdup3(&prob->internal_name, cfg->internal_name);
  if (cfg->extid) prob->extid = xstrdup(cfg->extid);
  if (cfg->long_name) {
    xstrdup3(&prob->long_name, cfg->long_name);
  }
  long time_limit_ms = 0;
  if (cfg->time_limit_millis > 0) {
    prob->time_limit_millis = cfg->time_limit_millis;
    time_limit_ms = cfg->time_limit_millis;
  } else if (cfg->time_limit > 0) {
    prob->time_limit = cfg->time_limit;
    time_limit_ms = cfg->time_limit * 1000;
  }
  long real_time_limit_ms = 0;
  if (super_prob && super_prob->real_time_limit > 0) real_time_limit_ms = super_prob->real_time_limit * 1000;
  if (time_limit_ms > 0 && time_limit_ms * 2 > real_time_limit_ms) {
    prob->real_time_limit = (time_limit_ms * 2 + 999) / 1000;
  }
  if (cfg->use_stdin > 0) {
    prob->use_stdin = 1;
  } else if (!cfg->use_stdin) {
    prob->use_stdin = 0;
    xstrdup3(&prob->input_file, cfg->input_file);
  }
  if (cfg->use_stdout > 0) {
    prob->use_stdout = 1;
  } else if (!cfg->use_stdout) {
    prob->use_stdout = 0;
    xstrdup3(&prob->output_file,  cfg->output_file);
  }
  if (cfg->enable_testlib_mode > 0) {
    prob->enable_testlib_mode = 1;
  }
  if (cfg->binary_input > 0) {
    prob->binary_input = 1;
  }
  if (cfg->enable_iframe_statement > 0) {
    prob->enable_iframe_statement = 1;
  }
  if (cfg->max_vm_size != (size_t) -1L && cfg->max_vm_size) {
    prob->max_vm_size = cfg->max_vm_size;
  }
  if (cfg->max_stack_size != (size_t) -1L && cfg->max_stack_size) {
    prob->max_stack_size = cfg->max_stack_size;
  }
  if (cfg->max_rss_size != (size_t) -1L && cfg->max_rss_size) {
    prob->max_rss_size = cfg->max_rss_size;
  }
  if (cfg->test_pat && cfg->test_pat[0]) {
    xstrdup3(&prob->test_pat, cfg->test_pat);
  }
  if (cfg->use_corr > 0) {
    prob->use_corr = 1;
  } else if (!cfg->use_corr) {
    prob->use_corr = 0;
  }
  if (cfg->corr_pat && cfg->corr_pat[0]) {
    xstrdup3(&prob->corr_pat, cfg->corr_pat);
  }
  if (cfg->standard_checker && cfg->standard_checker[0]) {
    xstrdup3(&prob->standard_checker, cfg->standard_checker);
  } else if (cfg->check_cmd && cfg->check_cmd[0]) {
    xstrdup3(&prob->check_cmd, cfg->check_cmd);
  }
  if (cfg->checker_env && cfg->checker_env[0]) {
    prob->checker_env = sarray_copy(cfg->checker_env);
  }
  if (cfg->test_checker_cmd && cfg->test_checker_cmd[0]) {
    prob->test_checker_cmd = xstrdup(cfg->test_checker_cmd);
  }
  if (cfg->solution_cmd && cfg->solution_cmd[0]) {
    prob->solution_cmd = xstrdup(cfg->solution_cmd);
  }
  if (cfg->interactor_cmd && cfg->interactor_cmd[0]) {
    xstrdup3(&prob->interactor_cmd, cfg->interactor_cmd);
  }
  if (cfg->xml_file && cfg->xml_file[0]) {
    xstrdup3(&prob->xml_file, cfg->xml_file);
  }

cleanup:
  if (f) fclose(f);
  problem_config_section_free((struct generic_section_config*) cfg);
  return retval;
}

int
super_serve_op_DOWNLOAD_CLEANUP_AND_IMPORT_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct sid_state *ss = phr->ss;
  struct update_state *us = ss->update_state;
  FILE *f = NULL;
  int exit_code = -1, count = 0, successes = 0, failures = 0;
  struct ss_download_status *statuses = NULL;

  if (!us) {
    int action = 0;
    if (ss->global) {
      action = SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE;
    } else if (ss->edited_cnts) {
      action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    }
    ss_redirect_3(out_f, phr, action, NULL);
    goto cleanup;
  }
  if (!ss->global || !us->status_file || us->create_mode <= 0) {
    ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);
    goto cleanup;
  }

  if (!(f = fopen(us->status_file, "r"))) {
    ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);
    goto cleanup;
  }
  ss_read_download_status(stderr, us->status_file, f, &exit_code, &count, &statuses);
  fclose(f); f = NULL;
  if (exit_code != 0 || count <= 0) {
    ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);
    goto cleanup;
  }
  for (int i = 0; i < count; ++i) {
    if (statuses[i].status &&
        (!strcmp(statuses[i].status, "ACTUAL") || !strcmp(statuses[i].status, "UPDATED") || !strcmp(statuses[i].status, "ALREADY_EXISTS"))) {
      ++successes;
    } else {
      ++failures;
    }
  }
  if (failures > 0) {
    ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);
    goto cleanup;
  }

  for (int i = 0; i < count; ++i) {
    int val = do_import_problem(log_f, phr, statuses[i].polygon_name);
    if (val) retval = val;
  }

  if (us->working_dir) {
    remove_directory_recursively(us->working_dir, 0);
  }
  ss->update_state = NULL;
  update_state_free(us); us = NULL;

  ss_redirect_3(out_f, phr, SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE, NULL);

cleanup:
  if (f) fclose(f);
  if (statuses) {
    for (int i = 0; i < count; ++i) {
      xfree(statuses[i].key);
      xfree(statuses[i].status);
      xfree(statuses[i].polygon_id);
      xfree(statuses[i].polygon_name);
    }
    xfree(statuses);
  }
  return retval;
}

int
super_serve_op_UPDATE_FROM_POLYGON_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0, lcaps = 0;
  struct sid_state *ss = phr->ss;
  const unsigned char *s = NULL;
  int r;
  unsigned char *polygon_login = NULL;
  unsigned char *polygon_password = NULL;
  unsigned char *polygon_url = NULL;
  unsigned char *polygon_key = NULL;
  unsigned char *polygon_secret = NULL;
  int save_auth_flag = 0;
  int ignore_solutions_flag = 0;
  int fetch_latest_available_flag = 0;
  struct polygon_packet *pp = NULL;
  const struct contest_desc *cnts = NULL;
  struct update_state *us = NULL;
  FILE *f = NULL;
  int contest_id = 0;
  int free_edited_cnts_flag = 0;
  int enable_api_flag = 0;
  int verbose_flag = 0;
  int binary_input_flag = 0;
  int enable_iframe_statement_flag = 0;

  if (hr_cgi_param(phr, "verbose", &s) > 0) verbose_flag = 1;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(SSERV_ERR_INV_CONTEST);

  ss_get_global_caps(phr, &caps);
  ss_get_contest_caps(phr, cnts, &lcaps);
  caps |= lcaps;

  if (opcaps_check(lcaps, OPCAP_EDIT_CONTEST) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (ss->update_state) {
    fprintf(log_f, "there is a background update in progress\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (ss->edited_cnts || ss->global) {
    fprintf(log_f, "a contest is opened for editing at the moment\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  free_edited_cnts_flag = 1;
  struct contest_desc *rw_cnts = NULL;
  if (contests_load(contest_id, &rw_cnts) < 0 || !rw_cnts) FAIL(SSERV_ERR_INV_CONTEST);
  ss->edited_cnts = rw_cnts; rw_cnts = NULL;
  super_html_load_serve_cfg(ss->edited_cnts, phr->config, ss);
  if (!ss->global) {
    fprintf(log_f, "failed to load the contest configuration file\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (ss->global->advanced_layout <= 0) {
    fprintf(log_f, "advanced_layout must be set\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (ss->prob_a <= 1) {
    fprintf(log_f, "contest contains no problems\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  int polygon_count = 0;
  for (int prob_id = 1; prob_id < ss->prob_a; ++prob_id) {
    const struct section_problem_data *prob = ss->probs[prob_id];
    if (prob && prob->extid && !strncmp("polygon:", prob->extid, 8))
      ++polygon_count;
  }
  if (polygon_count <= 0) {
    fprintf(log_f, "no problems to update (no problems imported from polygon)\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (hr_cgi_param(phr, "enable_api", &s) > 0) enable_api_flag = 1;

  if (!enable_api_flag) {
    if ((r = hr_cgi_param(phr, "polygon_login", &s)) < 0) {
      fprintf(log_f, "polygon login is invalid\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    if (!r || !s || !*s) {
      fprintf(log_f, "polygon login is undefined\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    polygon_login = xstrdup(s);

    if ((r = hr_cgi_param(phr, "polygon_password", &s)) < 0) {
      fprintf(log_f, "polygon password is invalid\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    if (!r || !s || !*s) {
      fprintf(log_f, "polygon password is undefined\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    polygon_password = xstrdup(s);
  } else {
    if ((r = hr_cgi_param(phr, "polygon_key", &s)) < 0) {
      fprintf(log_f, "polygon key is invalid\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    if (!r || !s || !*s) {
      fprintf(log_f, "polygon key is undefined\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    polygon_key = xstrdup(s);

    if ((r = hr_cgi_param(phr, "polygon_secret", &s)) < 0) {
      fprintf(log_f, "polygon secret is invalid\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    if (!r || !s || !*s) {
      fprintf(log_f, "polygon secret is undefined\n");
      FAIL(SSERV_ERR_INV_OPER);
    }
    polygon_secret = xstrdup(s);
  }

  if (hr_cgi_param(phr, "save_auth", &s) > 0) save_auth_flag = 1;

  if (hr_cgi_param(phr, "ignore_solutions", &s) > 0) ignore_solutions_flag = 1;
  if (hr_cgi_param(phr, "fetch_latest_available", &s) > 0) fetch_latest_available_flag = 1;
  if (hr_cgi_param(phr, "binary_input", &s) > 0) binary_input_flag = 1;
  if (hr_cgi_param(phr, "enable_iframe_statement", &s) > 0) enable_iframe_statement_flag = 1;

  if ((r = hr_cgi_param(phr, "polygon_url", &s)) < 0) {
    fprintf(log_f, "polygon url is invalid\n");
    FAIL(SSERV_ERR_INV_OPER);
  } else if (r > 0) {
    polygon_url = fix_string_2(s);
  }

  if (save_auth_flag) {
    save_auth(phr->login, polygon_login, polygon_password, polygon_url, polygon_key, polygon_secret);
  }

  s = getenv("TMPDIR");
  if (!s) s = getenv("TEMPDIR");
#if defined P_tmpdir
  if (!s) s = P_tmpdir;
#endif
  if (!s) s = "/tmp";

  time_t cur_time = time(NULL);
  unsigned char rand_base[PATH_MAX];
  unsigned char working_dir[PATH_MAX];
  snprintf(rand_base, sizeof(rand_base), "%s_%d", phr->login, (int) cur_time);
  snprintf(working_dir, sizeof(working_dir), "%s/ej_download_%s", s, rand_base);

  if (mkdir(working_dir, 0700) < 0) {
    if (errno != EEXIST) {
      fprintf(log_f, "mkdir '%s' failed: %s\n", working_dir, os_ErrorMsg());
      FAIL(SSERV_ERR_FS_ERROR);
    }
    int serial = 1;
    for (; serial < 10; ++serial) {
      snprintf(working_dir, sizeof(working_dir), "%s/ej_download_%s_%d", s, rand_base, serial);
      if (mkdir(working_dir, 0700) >= 0) break;
      if (errno != EEXIST) {
        fprintf(log_f, "mkdir '%s' failed: %s\n", working_dir, os_ErrorMsg());
        FAIL(SSERV_ERR_FS_ERROR);
      }
    }
    if (serial >= 10) {
      fprintf(log_f, "failed to create working directory '%s': too many attempts\n", working_dir);
      FAIL(SSERV_ERR_OPERATION_FAILED);
    }
  }

  unsigned char conf_path[PATH_MAX];
  unsigned char log_path[PATH_MAX];
  unsigned char pid_path[PATH_MAX];
  unsigned char stat_path[PATH_MAX];
  unsigned char download_path[PATH_MAX];
  unsigned char problem_path[PATH_MAX];
  unsigned char start_path[PATH_MAX];

  snprintf(conf_path, sizeof(conf_path), "%s/conf.cfg", working_dir);
  snprintf(log_path, sizeof(log_path), "%s/log.txt", working_dir);
  snprintf(pid_path, sizeof(pid_path), "%s/pid.txt", working_dir);
  snprintf(stat_path, sizeof(stat_path), "%s/stat.txt", working_dir);
  snprintf(download_path, sizeof(download_path), "%s/download", cnts->root_dir);
  snprintf(problem_path, sizeof(problem_path), "%s/problems", cnts->root_dir);
  snprintf(start_path, sizeof(start_path), "%s/ej-polygon", EJUDGE_SERVER_BIN_PATH);

  pp = polygon_packet_alloc();
  pp->verbose = verbose_flag;
  pp->ignore_solutions = ignore_solutions_flag;
  pp->fetch_latest_available = fetch_latest_available_flag;
  pp->polygon_url = polygon_url; polygon_url = NULL;
  pp->login = polygon_login; polygon_login = NULL;
  pp->password = polygon_password; polygon_password = NULL;
  if (enable_api_flag) {
    pp->enable_api = 1;
    pp->key = polygon_key; polygon_key = NULL;
    pp->secret = polygon_secret; polygon_secret = NULL;
  }
  pp->working_dir = xstrdup(working_dir);
  pp->log_file = xstrdup(log_path);
  pp->status_file = xstrdup(stat_path);
  pp->pid_file = xstrdup(pid_path);
  pp->download_dir = xstrdup(download_path);
  pp->problem_dir = xstrdup(problem_path);
  pp->dir_mode = xstrdup2(cnts->dir_mode);
  pp->dir_group = xstrdup2(cnts->dir_group);
  pp->file_mode = xstrdup2(cnts->file_mode);
  pp->file_group = xstrdup2(cnts->file_group);
  pp->binary_input = binary_input_flag;
  pp->enable_iframe_statement = enable_iframe_statement_flag;
  XCALLOC(pp->id, polygon_count + 1);
  for (int prob_id = 1, ind = 0; prob_id < ss->prob_a; ++prob_id) {
    const struct section_problem_data *prob = ss->probs[prob_id];
    if (prob && prob->extid && !strncmp("polygon:", prob->extid, 8)) {
      pp->id[ind++] = xstrdup(prob->extid + 8);
    }
  }

  if (!(f = fopen(conf_path, "w"))) {
    fprintf(log_f, "failed to open file '%s': %s\n", conf_path, os_ErrorMsg());
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  polygon_packet_unparse(f, pp);
  fclose(f); f = NULL;

  us = update_state_create();
  us->start_time = cur_time;
  us->contest_id = cnts->id;
  us->working_dir = xstrdup(working_dir);
  us->conf_file = xstrdup(conf_path);
  us->log_file = xstrdup(log_path);
  us->status_file = xstrdup(stat_path);
  us->pid_file = xstrdup(pid_path);
  ss->update_state = us; us = NULL;

  char *args[3];
  args[0] = start_path;
  args[1] = conf_path;
  args[2] = NULL;
  ejudge_start_daemon_process(args, working_dir);

  ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);

cleanup:
  xfree(polygon_login);
  xfree(polygon_password);
  xfree(polygon_url);
  polygon_packet_free((struct generic_section_config*) pp);
  update_state_free(us);
  if (free_edited_cnts_flag) {
    super_serve_clear_edited_contest(ss);
  }
  return retval;
}

int
super_serve_op_IMPORT_PROBLEMS_BATCH_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0LL;
  const unsigned char *path = NULL;

  ss_get_global_caps(phr, &caps);

  if (opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (hr_cgi_param(phr, "path", &path) <= 0 || !path || !*path) {
    fprintf(log_f, "'path' parameter is undefined");
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }

  struct stat stb;
  if (stat(path, &stb) < 0) {
    fprintf(log_f, "'path' ('%s') does not exist", path);
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  if (!S_ISREG(stb.st_mode)) {
    fprintf(log_f, "'path' ('%s') is not a regular file", path);
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }
  if (access(path, R_OK) < 0) {
    fprintf(log_f, "'path' ('%s') is not readable", path);
    FAIL(SSERV_ERR_OPERATION_FAILED);
  }

  unsigned char start_path[PATH_MAX];
  snprintf(start_path, sizeof(start_path), "%s/ej-import-contest", EJUDGE_SERVER_BIN_PATH);
  char *args[3];
  args[0] = start_path;
  args[1] = (char*) path;
  args[2] = NULL;
  ejudge_start_daemon_process(args, NULL);

  fprintf(out_f, "Content-type: text/plain\n\n");
  fprintf(out_f, "OK\n");

cleanup:
  return retval;
}

int
super_serve_op_CREATE_CONTEST_BATCH_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0LL;
  int contest_id = 0;
  char *cfg_file_text = NULL;
  size_t cfg_file_size = 0;
  char *out_text = NULL;
  size_t out_size = 0;
  FILE *out_file = NULL;
  unsigned char errbuf[1024];

  errbuf[0] = 0;
  ss_get_global_caps(phr, &caps);

  if (opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
    snprintf(errbuf, sizeof(errbuf), "permission denied");
    FAIL(SSERV_ERR_PERM_DENIED);
  }
  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0) {
    snprintf(errbuf, sizeof(errbuf), "contest_id is undefined");
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  if (contest_id < 0) {
    snprintf(errbuf, sizeof(errbuf), "contest_id is invalid");
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  if (!contest_id) {
    const int *contests = NULL;
    int contest_num = contests_get_list(&contests);
    if (!contests || contest_num <= 0) {
      contest_id = 1;
    } else {
      contest_id = contests[contest_num - 1] + 1;
    }
  }
  const struct contest_desc *cnts = NULL;
  if (contests_get(contest_id, &cnts) >= 0) {
    snprintf(errbuf, sizeof(errbuf), "contest %d already exist", contest_id);
    FAIL(SSERV_ERR_INV_CONTEST);
  }

  const unsigned char *xml_path = NULL;
  if (hr_cgi_param(phr, "xml_path", &xml_path) < 0 || !xml_path) {
    snprintf(errbuf, sizeof(errbuf), "xml_path is undefined");
    FAIL(SSERV_ERR_INV_OPER);
  }
  const unsigned char *cfg_path = NULL;
  if (hr_cgi_param(phr, "cfg_path", &cfg_path) < 0 || !cfg_path) {
    snprintf(errbuf, sizeof(errbuf), "cfg_path is undefined");
    FAIL(SSERV_ERR_INV_OPER);
  }

  struct contest_desc *rw_cnts = NULL;
  if (contests_load_file(xml_path, &rw_cnts) < 0 || !rw_cnts) {
    snprintf(errbuf, sizeof(errbuf), "failed to load contest.xml file '%s'", xml_path);
    FAIL(SSERV_ERR_INV_OPER);
  }
  if (generic_read_file(&cfg_file_text, 0, &cfg_file_size, 0, NULL, cfg_path, NULL) < 0) {
    snprintf(errbuf, sizeof(errbuf), "failed to load serve.cfg file '%s'", cfg_path);
    FAIL(SSERV_ERR_INV_OPER);
  }

  rw_cnts->id = contest_id;
  xfree(rw_cnts->root_dir); rw_cnts->root_dir = NULL;
  if (contests_unparse_and_save(rw_cnts, NULL, NULL, NULL, NULL, NULL, NULL) < 0) {
    snprintf(errbuf, sizeof(errbuf), "failed to write contest.xml file");
    FAIL(SSERV_ERR_INV_OPER);
  }

  unsigned char contest_dir[PATH_MAX];
  snprintf(contest_dir, sizeof(contest_dir), "%s/%06d", EJUDGE_CONTESTS_HOME_DIR, contest_id);
  if (os_MakeDirPath2(contest_dir, rw_cnts->dir_mode, rw_cnts->dir_group) < 0) {
    snprintf(errbuf, sizeof(errbuf), "failed to create '%s'", contest_dir);
    FAIL(SSERV_ERR_INV_OPER);
  }
  unsigned char conf_dir[PATH_MAX];
  snprintf(conf_dir, sizeof(conf_dir), "%s/conf", contest_dir);
  if (os_MakeDirPath2(conf_dir, rw_cnts->dir_mode, rw_cnts->dir_group) < 0) {
    snprintf(errbuf, sizeof(errbuf), "failed to create '%s'", conf_dir);
    FAIL(SSERV_ERR_INV_OPER);
  }

  out_file = open_memstream(&out_text, &out_size);
  fprintf(out_file,
          "# -*- coding: utf-8 -*-\n"
          "contest_id = %d\n\n%s\n",
          contest_id, cfg_file_text);
  fclose(out_file); out_file = NULL;

  unsigned char serve_cfg_path[PATH_MAX];
  snprintf(serve_cfg_path, sizeof(serve_cfg_path), "%s/serve.cfg", conf_dir);
  if (generic_write_file(out_text, out_size, 0, NULL, serve_cfg_path, NULL) < 0) {
    snprintf(errbuf, sizeof(errbuf), "failed to create '%s'", serve_cfg_path);
    FAIL(SSERV_ERR_INV_OPER);
  }
  if (super_html_set_cnts_file_perms(stderr, serve_cfg_path, rw_cnts) < 0) {
    snprintf(errbuf, sizeof(errbuf), "failed to change permissions on '%s'", serve_cfg_path);
    FAIL(SSERV_ERR_INV_OPER);
  }
  retval = contest_id;
  contests_clear_cache();

cleanup:
  fprintf(out_f, "Content-type: text/plain\n\n");
  fprintf(out_f, "%d\n", retval);
  if (errbuf[0]) {
    fprintf(out_f, "%s\n", errbuf);
  }

  if (out_file) fclose(out_file);
  xfree(out_text);
  xfree(cfg_file_text);
  return 0;
}
