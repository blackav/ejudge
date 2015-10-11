/* -*- mode: c -*- */

/* Copyright (C) 2011-2015 Alexander Chernov <cher@ejudge.ru> */

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
    fprintf(fout, "Set-Cookie: EJSID=%016llx; Path=/\n", phr->client_key);
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
    fprintf(fout, "Set-Cookie: EJSID=%016llx; Path=/\n", phr->client_key);
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
    fprintf(fout, "Set-Cookie: EJSID=%016llx; Path=/\n", phr->client_key);
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

static void
ss_select(
        FILE *fout,
        const unsigned char *param,
        const unsigned char **options,
        int value)
{
  int option_count = 0, i;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s;

  if (!options) return;
  for (; options[option_count]; ++option_count);
  if (option_count <= 0) return;

  if (value < 0 || value >= option_count) value = 0;

  fprintf(fout, "<select name=\"%s\">", param);
  for (i = 0; i < option_count; ++i) {
    s = "";
    if (i == value) s = " selected=\"selected\"";
    fprintf(fout, "<option value=\"%d\"%s>%s</option>",
            i, s, ARMOR(options[i]));
  }
  fprintf(fout, "</select>");
  html_armor_free(&ab);
}

static int
get_global_caps(const struct http_request_info *phr, opcap_t *pcap)
{
  return ejudge_cfg_opcaps_find(phr->config, phr->login, pcap);
}
static int
get_contest_caps(const struct http_request_info *phr, const struct contest_desc *cnts, opcap_t *pcap)
{
  return opcaps_find(&cnts->capabilities, phr->login, pcap);
}

static int
is_globally_privileged(const struct http_request_info *phr, const struct userlist_user *u)
{
  opcap_t caps = 0;
  if (u->is_privileged) return 1;
  if (ejudge_cfg_opcaps_find(phr->config, u->login, &caps) >= 0) return 1;
  return 0;
}
static int
is_contest_privileged(
        const struct contest_desc *cnts,
        const struct userlist_user *u)
{
  opcap_t caps = 0;
  if (!cnts) return 0;
  if (opcaps_find(&cnts->capabilities, u->login, &caps) >= 0) return 1;
  return 0;
}
static int
is_privileged(
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

static int
userlist_user_count_contests(struct userlist_user *u)
{
  struct userlist_contest *c;
  int tot = 0;

  if (!u || !u->contests) return 0;
  for (c = FIRST_CONTEST(u); c; c = NEXT_CONTEST(c), tot++);
  return tot;
}
static int
userlist_user_count_cookies(struct userlist_user *u)
{
  struct userlist_cookie *cookie;
  int tot = 0;

  if (!u) return 0;
  if (!u->cookies) return 0;
  for (cookie = FIRST_COOKIE(u); cookie; cookie = NEXT_COOKIE(cookie), tot++);
  return tot;
}

static struct userlist_user *
get_user_info(
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

static void
print_top_navigation_links(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr,
        int contest_id,
        int group_id,
        int other_user_id,
        const unsigned char *marked_str)
{
  unsigned char hbuf[1024];
  unsigned char contest_id_str[1024];
  unsigned char group_id_str[1024];
  unsigned char *marked_param = "";

  contest_id_str[0] = 0;
  if (contest_id > 0) {
    snprintf(contest_id_str, sizeof(contest_id_str), "&amp;contest_id=%d", contest_id);
  }
  if (group_id < 0) group_id = 0;
  group_id_str[0] = 0;
  if (group_id > 0) {
    snprintf(group_id_str, sizeof(group_id_str), "&amp;group_id=%d", group_id);
  }
  if (marked_str && *marked_str) {
    int len = strlen(marked_str);
    if (len < 100000) {
      marked_param = alloca(len + 32);
      sprintf(marked_param, "&amp;marked=%s", marked_str);
    }
  }

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d%s",
                        SSERV_CMD_USER_BROWSE_PAGE, marked_param),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_GROUP_BROWSE_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d%s%s",
                          SSERV_CMD_USER_BROWSE_PAGE,
                          contest_id_str, marked_param),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d%s%s",
                          SSERV_CMD_USER_BROWSE_PAGE,
                          group_id_str, marked_param),
            "Browse users of group", group_id);
  }
  if (other_user_id > 0) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;other_user_id=%d%s%s",
                          SSERV_CMD_USER_DETAIL_PAGE,
                          other_user_id,
                          contest_id_str, group_id_str),
            "User details");
  }
  fprintf(out_f, "</ul>\n");
}

static const unsigned char * const reg_status_strs[] =
{
  "<font color=\"green\">OK</font>",
  "<font color=\"magenta\">Pending</font>",
  "<font color=\"red\">Rejected</font>",
  "<font color=\"red\"><b>Invalid status</b></font>",
};
static const unsigned char * const flag_op_legends[] =
{
  "Do nothing", "Clear", "Set", "Toggle", NULL,
};

static unsigned char *
collect_marked_set(
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
  marked_str = collect_marked_set(phr, &marked);

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

  if (get_global_caps(phr, &gcaps) >= 0 && opcaps_check(gcaps, OPCAP_LIST_USERS) >= 0) {
    // this user can view the full user list and the user list for any contest
  } else if (!cnts) {
    // user without global OPCAP_LIST_USERS capability cannot view the full user list
    FAIL(SSERV_ERR_PERM_DENIED);
  } else if (get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_LIST_USERS) < 0) {
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
  marked_str = collect_marked_set(phr, &marked);

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
super_serve_op_USER_SEL_RANDOM_PASSWD_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0, group_id = 0;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
  unsigned char buf[1024];
  unsigned char *marked_str = 0;
  bitset_t marked = BITSET_INITIALIZER;
  const struct contest_desc *cnts = 0;
  int user_id = 0, user_count = 0, serial;
  const unsigned char *cl = 0;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  struct userlist_list *groups = 0;
  const struct userlist_user *u = 0;
  const struct userlist_contest *reg = 0;
  const struct userlist_user_info *ui = 0;
  const struct userlist_group *g = 0;
  const unsigned char *s = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  opcap_t gcaps = 0, caps = 0;
  int r;
  int need_privileged = 0, need_invisible = 0, need_banned = 0, need_locked = 0, need_disqualified = 0;
  int operation = 0;
  const unsigned char *button_label = 0;
  int status = USERLIST_REG_REJECTED;
  int invisible_op = 0, banned_op = 0, locked_op = 0, incomplete_op = 0, disqualified_op = 0;
  int is_set_changed = 0;
  const int *cnts_id_list = 0;
  int cnts_id_count = 0;
  int other_contest_id = 0;
  int other_group_id = 0;
  const struct contest_desc *other_cnts = 0;
  unsigned char *group_name = NULL;
  unsigned char *group_desc = NULL;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  marked_str = collect_marked_set(phr, &marked);

  if (contest_id < 0) contest_id = 0;
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  contest_id_str[0] = 0;
  if (contest_id > 0) {
    snprintf(contest_id_str, sizeof(contest_id_str), "&amp;contest_id=%d", contest_id);
  }
  if (group_id < 0) group_id = 0;
  if (group_id > 0) {
    r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_GET_GROUP_INFO, group_id, &xml_text);
    if (r >= 0) {
      users = userlist_parse_str(xml_text);
      if (users && group_id < users->group_map_size && (g = users->group_map[group_id])) {
        group_name = xstrdup(g->group_name);
        group_desc = xstrdup(g->description);
      } else {
        group_id = 0;
      }
    } else {
      group_id = 0;
    }
    userlist_free(&users->b); users = 0;
    xfree(xml_text); xml_text = 0;
  }
  group_id_str[0] = 0;
  if (group_id > 0) {
    snprintf(group_id_str, sizeof(group_id_str), "&amp;group_id=%d", group_id);
  }

  /* additional parameters */
  switch (phr->action) {
  case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_PAGE:
    hr_cgi_param_int_opt(phr, "status", &status, -1);
    if (status < 0 || status >= USERLIST_REG_LAST) FAIL(SSERV_ERR_INV_VALUE);
    break;
  case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_PAGE:
    hr_cgi_param_int_opt(phr, "invisible_op", &invisible_op, 0);
    hr_cgi_param_int_opt(phr, "banned_op", &banned_op, 0);
    hr_cgi_param_int_opt(phr, "locked_op", &locked_op, 0);
    hr_cgi_param_int_opt(phr, "incomplete_op", &incomplete_op, 0);
    hr_cgi_param_int_opt(phr, "disqualified_op", &disqualified_op, 0);
    if (invisible_op < 0 || invisible_op > 3) invisible_op = 0;
    if (banned_op < 0 || banned_op > 3) banned_op = 0;
    if (locked_op < 0 || locked_op > 3) locked_op = 0;
    if (incomplete_op < 0 || incomplete_op > 3) incomplete_op = 0;
    if (disqualified_op < 0 || disqualified_op > 3) disqualified_op = 0;
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_PAGE:
  case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_PAGE:
    hr_cgi_param_int_opt(phr, "other_contest_id", &other_contest_id, 0);
    if (other_contest_id <= 0 || contests_get(other_contest_id, &other_cnts) < 0 || !other_cnts) {
      other_contest_id = 0;
    }
    cnts_id_count = contests_get_list(&cnts_id_list);
    break;
  case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_PAGE:
    hr_cgi_param_int_opt(phr, "other_group_id", &other_group_id, 0);
    if (other_group_id < 0) other_group_id = 0;
    if (other_group_id > 0) {
      r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_GET_GROUP_INFO, other_group_id, &xml_text);
      if (r < 0) other_group_id = 0;
      users = userlist_parse_str(xml_text);
      if (!users || group_id >= users->group_map_size || !users->group_map[other_group_id])
        other_group_id = 0;
      userlist_free(&users->b); users = 0;
      xfree(xml_text); xml_text = 0;
    }
    r = userlist_clnt_list_all_users(phr->userlist_clnt, ULS_LIST_ALL_GROUPS, 0, &xml_text);
    if (r >= 0) {
      groups = userlist_parse_str(xml_text);
      xfree(xml_text); xml_text = 0;
    }
    break;
  case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_PAGE:
    if (group_id <= 0) FAIL(SSERV_ERR_INV_VALUE);
    break;
  }

  /* contest_id check and preliminary permission check */
  switch (phr->action) {
  case SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE:
    if (get_global_caps(phr, &gcaps) < 0) FAIL(SSERV_ERR_PERM_DENIED);
    if (opcaps_check(gcaps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_PAGE:
  case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_PAGE:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    get_global_caps(phr, &gcaps);
    get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_DELETE_REG_PAGE:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    get_global_caps(phr, &gcaps);
    if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_DELETE_REG;
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_DELETE_REG;
    get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0 && opcaps_check(caps, OPCAP_DELETE_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_PAGE:
  case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_PAGE:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    get_global_caps(phr, &gcaps);
    if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_EDIT_REG;
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_EDIT_REG;
    get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_EDIT_REG) < 0 && opcaps_check(caps, OPCAP_EDIT_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_PAGE:
  case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_PAGE:
    break;
  case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_PAGE:
  case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_PAGE:
    if (get_global_caps(phr, &gcaps) < 0) FAIL(SSERV_ERR_PERM_DENIED);
    if (opcaps_check(gcaps, OPCAP_EDIT_USER) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  default:
    abort();
  }

  if (!phr->userlist_clnt) FAIL(SSERV_ERR_DB_ERROR);
  r = userlist_clnt_list_users_2(phr->userlist_clnt, ULS_LIST_ALL_USERS_3,
                                 contest_id, group_id, marked_str, 0, 0,
                                 // FIXME: fill these fields
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
        is_set_changed = 1;
        continue;
      }
      if (contest_id > 0 && !userlist_get_user_contest(u, contest_id)) {
        bitset_off(&marked, user_id);
        is_set_changed = 1;
        continue;
      }
      /* per-user check */
      switch (phr->action) {
      case SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE:
        if (is_privileged(phr, cnts, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0) u = 0;
        } else {
          if (opcaps_check(gcaps, OPCAP_EDIT_PASSWD) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_PAGE:
      case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_PAGE:
        if (is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0) u = 0;
        } else if (is_contest_privileged(cnts, u)) {
          if (opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_DELETE_REG_PAGE:
        if (is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_DELETE_REG) < 0) u = 0;
        } else if (is_contest_privileged(cnts, u)) {
          if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_DELETE_REG) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_PAGE:
      case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_PAGE:
        if (is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_REG) < 0) u = 0;
        } else if (is_contest_privileged(cnts, u)) {
          if (opcaps_check(caps, OPCAP_PRIV_EDIT_REG) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_EDIT_REG) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CREATE_REG_PAGE:
      case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_PAGE:
        break;
      case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_PAGE:
      case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_PAGE:
        break;
      default:
        abort();
      }
      if (!u) {
        bitset_off(&marked, user_id);
        is_set_changed = 1;
        continue;
      }
      ++user_count;
    }
  }
  if (user_count <= 0) {
    ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, contest_id, group_id, 0, NULL);
    goto cleanup;
  }

  if (is_set_changed) {
    xfree(marked_str);
    marked_str = bitset_url_encode(&marked);
  }

  /* page header generation */
  switch (phr->action) {
  case SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, generate random registration passwords", phr->html_name);
    break;
  case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, clear contest passwords for contest %d",
             phr->html_name, contest_id);
    break;
  case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, generate random contest passwords for contest %d",
             phr->html_name, contest_id);
    break;
  case SSERV_CMD_USER_SEL_DELETE_REG_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, delete registrations from contest %d",
             phr->html_name, contest_id);
    break;
  case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, change registration statuses in contest %d",
             phr->html_name, contest_id);
    break;
  case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_PAGE:
    if (!(invisible_op + banned_op + locked_op + incomplete_op + disqualified_op)) {
      ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, contest_id, group_id, 0, marked_str);
      goto cleanup;
    }
    snprintf(buf, sizeof(buf), "serve-control: %s, change registration flags in contest %d",
             phr->html_name, contest_id);
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, register users for another contest",
             phr->html_name);
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, register users for another contest and copy data",
             phr->html_name);
    break;
  case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, add users to a group",
             phr->html_name);
    break;
  case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, remove users from group %d",
             phr->html_name, group_id);
    break;
  default:
    abort();
  }

  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<script language=\"javascript\">\n");
  fprintf(out_f,
          "function updateCnts1()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj1.value;\n"
          "  var i;\n"
          "  for (i = 0; i < obj2.options.length; ++i) {\n"
          "    if (obj2.options[i].value == value) {\n"
          "      obj2.options.selectedIndex = i;\n"
          "      break;\n"
          "    }\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function updateCnts2()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj2.options[obj2.selectedIndex].value;\n"
          "  obj1.value = value;\n"
          "}\n");
  fprintf(out_f,
          "function updateGroup1()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"group1\");\n"
          "  var obj2 = document.getElementById(\"group2\");\n"
          "  var value = obj1.value;\n"
          "  var i;\n"
          "  for (i = 0; i < obj2.options.length; ++i) {\n"
          "    if (obj2.options[i].value == value) {\n"
          "      obj2.options.selectedIndex = i;\n"
          "      break;\n"
          "    }\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function updateGroup2()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"group1\");\n"
          "  var obj2 = document.getElementById(\"group2\");\n"
          "  var value = obj2.options[obj2.selectedIndex].value;\n"
          "  obj1.value = value;\n"
          "}\n");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  /* additional info */
  switch (phr->action) {
  case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_PAGE:
  case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_PAGE:
  case SSERV_CMD_USER_SEL_DELETE_REG_PAGE:
  case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_PAGE:
  case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_PAGE:
    fprintf(out_f, "<h2>%s</h2>\n", ARMOR(cnts->name));
    break;
  case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_PAGE:
    fprintf(out_f, "<h2>Group: %s</h2>\n", ARMOR(group_name));
    break;
  }

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, 0, marked_str);

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  if (marked_str && *marked_str) {
    html_hidden(out_f, "marked", "%s", marked_str);
  }

  /* additional info */
  switch (phr->action) {
  case SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE:
    fprintf(out_f, "<p>The registration passwords are to be regenerated for the following %d users:</p>\n",
            user_count);
    operation = SSERV_CMD_USER_SEL_RANDOM_PASSWD_ACTION;
    button_label = "Generate passwords!";
    break;
  case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_PAGE:
    fprintf(out_f, "<p>The contest passwords are to be cleared for the following %d users:</p>\n",
            user_count);
    operation = SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_ACTION;
    button_label = "Clear contest passwords!";
    break;
  case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_PAGE:
    fprintf(out_f, "<p>The contest passwords are to be regenerated for the following %d users:</p>\n",
            user_count);
    operation = SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_ACTION;
    button_label = "Generate contest passwords!";
    break;
  case SSERV_CMD_USER_SEL_DELETE_REG_PAGE:
    fprintf(out_f, "<p>The registrations are to be deleted for the following %d users:</p>\n", user_count);
    operation = SSERV_CMD_USER_SEL_DELETE_REG_ACTION;
    button_label = "Delete registrations!";
    break;
  case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_PAGE:
    html_hidden(out_f, "status", "%d", status);
    fprintf(out_f, "<p>The registration status is to be changed to %s for the following %d users:</p>\n",
            reg_status_strs[status], user_count);
    operation = SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_ACTION;
    button_label = "Change!";
    break;
  case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_PAGE:
    html_hidden(out_f, "invisible_op", "%d", invisible_op);
    html_hidden(out_f, "banned_op", "%d", banned_op);
    html_hidden(out_f, "locked_op", "%d", locked_op);
    html_hidden(out_f, "incomplete_op", "%d", incomplete_op);
    html_hidden(out_f, "disqualified_op", "%d", disqualified_op);
    fprintf(out_f, "<p>The registration flags are to be changed for the following %d users as follows:</p>\n",
            user_count);
    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s>", cl);
    if (invisible_op > 0) {
      fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>",
              cl, "Invisible", cl, flag_op_legends[invisible_op]);
    }
    if (banned_op > 0) {
      fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>",
              cl, "Banned", cl, flag_op_legends[banned_op]);
    }
    if (locked_op > 0) {
      fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>",
              cl, "Locked", cl, flag_op_legends[locked_op]);
    }
    if (incomplete_op > 0) {
      fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>",
              cl, "Incomplete", cl, flag_op_legends[incomplete_op]);
    }
    if (disqualified_op > 0) {
      fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>",
              cl, "Disqualified", cl, flag_op_legends[disqualified_op]);
    }
    fprintf(out_f, "</table>\n");
    operation = SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION;
    button_label = "Change!";
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_PAGE:
  case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_PAGE:
    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s>\n", cl);
    buf[0] = 0;
    if (other_contest_id > 0) snprintf(buf, sizeof(buf), "%d", other_contest_id);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input id=\"cnts1\" onchange=\"updateCnts1()\" type=\"text\" name=\"other_contest_id_1\" size=\"20\" value=\"%s\"/></td></tr>\n",
            cl, "Contest ID", cl, buf);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>", cl, "Contest name", cl);
    fprintf(out_f, "<select id=\"cnts2\" onchange=\"updateCnts2()\" name=\"other_contest_id_2\"><option value=\"0\"></option>");
    for (int i = 0; i < cnts_id_count; ++i) {
      int other_contest_id_2 = cnts_id_list[i];
      if (other_contest_id_2 <= 0) continue;
      if (contests_get(other_contest_id_2, &cnts) < 0 || !cnts) continue;
      if (cnts->closed) continue;
      s = "";
      if (other_contest_id_2 == other_contest_id) s = " selected=\"selected\"";
      fprintf(out_f, "<option value=\"%d\"%s>%s</option>", other_contest_id_2, s, ARMOR(cnts->name));
    }
    fprintf(out_f, "</select>");
    fprintf(out_f, "</td></tr>\n");
    fprintf(out_f, "</table>\n");

    switch (phr->action) {
    case SSERV_CMD_USER_SEL_CREATE_REG_PAGE:
      operation = SSERV_CMD_USER_SEL_CREATE_REG_ACTION;
      button_label = "Register!";
      break;
    case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_PAGE:
      operation = SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_ACTION;
      button_label = "Register and copy!";
      break;
    }
    break;
  case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_PAGE:
    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s>\n", cl);
    buf[0] = 0;
    if (other_group_id > 0) snprintf(buf, sizeof(buf), "%d", other_group_id);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input id=\"group1\" onchange=\"updateGroup1()\" type=\"text\" name=\"other_group_id_1\" size=\"20\" value=\"%s\"/></td></tr>\n",
            cl, "Group ID", cl, buf);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>", cl, "Group name", cl);
    fprintf(out_f, "<select id=\"group2\" onchange=\"updateGroup2()\" name=\"other_group_id_2\"><option value=\"0\"></option>");
    if (groups) {
      for (int i = 0; i < groups->group_map_size; ++i) {
        if (!(g = groups->group_map[i])) continue;
        s = "";
        if (i == other_group_id) s = " selected=\"selected\"";
        fprintf(out_f, "<option value=\"%d\"%s>%s</option>", i, s, ARMOR(g->group_name));
      }
    }
    fprintf(out_f, "</select>");
    fprintf(out_f, "</td></tr>\n");
    fprintf(out_f, "</table>\n");
    operation = SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_ACTION;
    button_label = "Add to group";
    break;
  case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_PAGE:
    fprintf(out_f, "<p>The following users are to be removed from group %d:</p>\n", group_id);
    operation = SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_ACTION;
    button_label = "Remove from group";
    break;
  default:
    abort();
  }

  cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>", cl);
  fprintf(out_f, "<tr><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th></tr>\n",
          cl, "NN", cl, "User ID", cl, "Login", cl, "Name", cl, "Status", cl, "Flags");
  for (user_id = 1, serial = 0; user_id < marked.size; ++user_id) {
    if (bitset_get(&marked, user_id)) {
      u = users->user_map[user_id];
      ui = u->cnts0;
      reg = 0;
      if (contest_id > 0) {
        reg = userlist_get_user_contest(u, contest_id);
      }
      fprintf(out_f, "<tr><td%s>%d</td>", cl, ++serial);
      fprintf(out_f, "<td%s>%d</td>", cl, user_id);
      fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(u->login));
      s = u->login;
      if (ui && ui->name && *ui->name) s = ui->name;
      fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(s));
      if (cnts && reg) {
        r = reg->status;
        if (r < 0 || r >= USERLIST_REG_LAST) r = USERLIST_REG_LAST;
        fprintf(out_f, "<td%s>%s</td>", cl, reg_status_strs[r]);
      } else {
        fprintf(out_f, "<td%s>&nbsp;</td>", cl);
      }
      fprintf(out_f, "<td%s>", cl);
      s = "";
      if (is_privileged(phr, cnts, u)) {
        need_privileged = 1;
        fprintf(out_f, "%s%s", s, "privileged");
        s = ", ";
      }
      if (cnts && reg) {
        if ((reg->flags & USERLIST_UC_INVISIBLE)) {
          need_invisible = 1;
          fprintf(out_f, "%s%s", s, "invisible");
          s = ", ";
        }
        if ((reg->flags & USERLIST_UC_BANNED)) {
          need_banned = 1;
          fprintf(out_f, "%s%s", s, "banned");
          s = ", ";
        }
        if ((reg->flags & USERLIST_UC_LOCKED)) {
          need_locked = 1;
          fprintf(out_f, "%s%s", s, "locked");
          s = ", ";
        }
        if ((reg->flags & USERLIST_UC_DISQUALIFIED)) {
          need_disqualified = 1;
          fprintf(out_f, "%s%s", s, "disqualified");
          s = ", ";
        }
      }
      if (!*s) fprintf(out_f, "&nbsp;");
      fprintf(out_f, "</td>");
      fprintf(out_f, "</tr>\n");
    }
  }
  fprintf(out_f, "</table>\n");

  if (phr->action != SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_PAGE) {
    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s>", cl);
    if (need_privileged) {
      fprintf(out_f, "<tr><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" /></td><td%s>%s</td></tr>\n",
              cl, "include_privileged", cl, "Peform the operation even for PRIVILEGED users");
    }
    if (need_invisible) {
      fprintf(out_f, "<tr><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" /></td><td%s>%s</td></tr>\n",
              cl, "include_invisible", cl, "Peform the operation even for INVISIBLE users");
    }
    if (need_banned) {
      fprintf(out_f, "<tr><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" /></td><td%s>%s</td></tr>\n",
              cl, "include_banned", cl, "Peform the operation even for BANNED users");
    }
    if (need_locked) {
      fprintf(out_f, "<tr><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" /></td><td%s>%s</td></tr>\n",
              cl, "include_locked", cl, "Peform the operation even for LOCKED users");
    }
    if (need_disqualified) {
      fprintf(out_f, "<tr><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" /></td><td%s>%s</td></tr>\n",
              cl, "include_disqualified", cl, "Peform the operation even for DISQUALIFIED users");
    }
    fprintf(out_f, "</table>");
  }

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr>", cl);
  fprintf(out_f, "<tr><td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
            cl, SSERV_CMD_USER_SEL_CANCEL_ACTION, "Cancel");
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td></tr>",
            cl, operation, button_label);
  fprintf(out_f, "</tr></table>\n");
    
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  userlist_free(&groups->b); groups = 0;
  userlist_free(&users->b); users = 0;
  bitset_free(&marked);
  xfree(marked_str);
  xfree(xml_text);
  xfree(group_name);
  xfree(group_desc);
  return retval;
}

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

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  marked_str = collect_marked_set(phr, &marked);

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
    if (invisible_op < 0 || invisible_op > 3) invisible_op = 0;
    if (banned_op < 0 || banned_op > 3) banned_op = 0;
    if (locked_op < 0 || locked_op > 3) locked_op = 0;
    if (incomplete_op < 0 || incomplete_op > 3) incomplete_op = 0;
    if (disqualified_op < 0 || disqualified_op > 3) disqualified_op = 0;
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
    if (get_global_caps(phr, &gcaps) < 0) FAIL(SSERV_ERR_PERM_DENIED);
    if (opcaps_check(gcaps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_ACTION:
  case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_ACTION:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    get_global_caps(phr, &gcaps);
    get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_DELETE_REG_ACTION:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    get_global_caps(phr, &gcaps);
    if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_DELETE_REG;
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_DELETE_REG;
    get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0 && opcaps_check(caps, OPCAP_DELETE_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_ACTION:
  case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    get_global_caps(phr, &gcaps);
    if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_EDIT_REG;
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_EDIT_REG;
    get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_EDIT_REG) < 0 && opcaps_check(caps, OPCAP_EDIT_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_ACTION:
    get_global_caps(phr, &gcaps);
    get_contest_caps(phr, other_cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_CREATE_REG) < 0 && opcaps_check(caps, OPCAP_CREATE_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_ACTION:
    if  (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    get_global_caps(phr, &gcaps);
    get_contest_caps(phr, other_cnts, &caps);
    caps |= gcaps;
    if (opcaps_check(caps, OPCAP_PRIV_CREATE_REG) < 0 && opcaps_check(caps, OPCAP_CREATE_REG) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    get_contest_caps(phr, cnts, &rcaps);
    rcaps |= gcaps;
    if (opcaps_check(rcaps, OPCAP_GET_USER) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
    break;
  case SSERV_CMD_USER_SEL_CREATE_GROUP_MEMBER_ACTION:
  case SSERV_CMD_USER_SEL_DELETE_GROUP_MEMBER_ACTION:
    if (get_global_caps(phr, &gcaps) < 0) FAIL(SSERV_ERR_PERM_DENIED);
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
      if (!include_privileged && is_privileged(phr, cnts, u)) {
        bitset_off(&marked, user_id);
        continue;
      }
      if (cnts && phr->action != SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION
          && (reg = userlist_get_user_contest(u, contest_id))) {
        if (((reg->flags & USERLIST_UC_INVISIBLE) && !include_invisible)
            || ((reg->flags & USERLIST_UC_BANNED) && !include_banned)
            || ((reg->flags & USERLIST_UC_LOCKED) && !include_locked)
            || ((reg->flags & USERLIST_UC_DISQUALIFIED) && !include_disqualified)) {
          bitset_off(&marked, user_id);
          continue;
        }
      }
      switch (phr->action) {
      case SSERV_CMD_USER_SEL_RANDOM_PASSWD_ACTION:
        if (is_privileged(phr, cnts, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0) u = 0;
        } else {
          if (opcaps_check(gcaps, OPCAP_EDIT_PASSWD) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_ACTION:
      case SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_ACTION:
        if (is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0) u = 0;
        } else if (is_contest_privileged(cnts, u)) {
          if (opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_DELETE_REG_ACTION:
        if (is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_DELETE_REG) < 0) u = 0;
        } else if (is_contest_privileged(cnts, u)) {
          if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_DELETE_REG) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_ACTION:
      case SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_ACTION:
        if (is_globally_privileged(phr, u)) {
          if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_REG) < 0) u = 0;
        } else if (is_contest_privileged(cnts, u)) {
          if (opcaps_check(caps, OPCAP_PRIV_EDIT_REG) < 0) u = 0;
        } else {
          if (opcaps_check(caps, OPCAP_EDIT_REG) < 0) u = 0;
        }
        break;
      case SSERV_CMD_USER_SEL_CREATE_REG_ACTION:
      case SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_ACTION:
        if (is_globally_privileged(phr, u)) {
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
        r = userlist_clnt_copy_user_info(phr->userlist_clnt, user_id, contest_id, other_contest_id);
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
  marked_str = collect_marked_set(phr, &marked);
  ss_redirect_2(out_f, phr, SSERV_CMD_USER_BROWSE_PAGE, contest_id, group_id, 0, marked_str);

  xfree(marked_str);
  bitset_free(&marked);
  return 0;
}

struct user_row_info
{
  int field_id;
  unsigned char *field_desc;
};

static char const * const member_string[] =
{
  "Contestant",
  "Reserve",
  "Coach",
  "Advisor",
  "Guest"
};
static char const * const member_string_pl[] =
{
  "Contestants",
  "Reserves",
  "Coaches",
  "Advisors",
  "Guests"
};

static void
string_row(
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

static const struct user_row_info user_flag_rows[] =
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

static const struct user_row_info user_timestamp_rows[] =
{
  { USERLIST_NN_REGISTRATION_TIME, "Registration time" },
  { USERLIST_NN_LAST_LOGIN_TIME, "Last login time" },
  { USERLIST_NN_LAST_CHANGE_TIME, "Last change time" },
  { USERLIST_NN_LAST_PWDCHANGE_TIME, "Last password change time" },
  { 0, 0 },
};

static const struct user_row_info user_info_rows[] =
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

  { 0, 0 },
};

static const struct user_row_info user_info_stat_rows[] =
{
  { USERLIST_NC_CREATE_TIME, "Create time" },
  { USERLIST_NC_LAST_LOGIN_TIME, "Last login time" },
  { USERLIST_NC_LAST_CHANGE_TIME, "Last change time" },
  { USERLIST_NC_LAST_PWDCHANGE_TIME, "Last password change time" },

  { 0, 0 },
};

static const struct user_row_info member_rows[] =
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

static const struct user_row_info member_date_rows[] =
{
  { USERLIST_NM_BIRTH_DATE, "Date of birth" },
  { USERLIST_NM_ENTRY_DATE, "Date of entry" },
  { USERLIST_NM_GRADUATION_DATE, "Graduation date" },

  { 0, 0 },
};

static const struct user_row_info member_time_rows[] =
{
  { USERLIST_NM_CREATE_TIME, "Create time" },
  { USERLIST_NM_LAST_CHANGE_TIME, "Last change time" },

  { 0, 0 },
};

int
super_serve_op_USER_DETAIL_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r, row, role, pers, reg_count, cookie_count;
  int other_user_id = 0, contest_id = 0, group_id = 0;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
  unsigned char buf[1024];
  unsigned char buf2[1024];
  unsigned char hbuf[1024];
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  const unsigned char *cl, *s, *s2;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct userlist_member *m;
  const struct contest_desc *cnts = 0;
  struct userlist_contest *reg;
  struct userlist_cookie *cookie;
  opcap_t gcaps = 0;
  opcap_t caps = 0;

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(SSERV_ERR_INV_USER_ID);
  }
  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id < 0) contest_id = 0;
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  contest_id_str[0] = 0;
  if (contest_id > 0) {
    snprintf(contest_id_str, sizeof(contest_id_str), "&amp;contest_id=%d", contest_id);
  }
  if (group_id < 0) group_id = 0;
  group_id_str[0] = 0;
  if (group_id > 0) {
    snprintf(group_id_str, sizeof(group_id_str), "&amp;group_id=%d", group_id);
  }

  if (get_global_caps(phr, &gcaps) >= 0 && opcaps_check(gcaps, OPCAP_GET_USER) >= 0) {
    // this user can view the full user list and the user list for any contest
  } else if (!cnts) {
    // user without global OPCAP_LIST_USERS capability cannot view the full user list
    FAIL(-SSERV_ERR_PERM_DENIED);
  } else if (get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_GET_USER) < 0) {
    FAIL(-SSERV_ERR_PERM_DENIED);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, viewing user %d",
           phr->html_name, other_user_id);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<script language=\"javascript\">\n");
  fprintf(out_f,
          "function toggleRowsVisibility(value, rows1, rows2)\n"
          "{\n"
          "  var vis1 = \"\";\n"
          "  var vis2 = \"\";\n"
          "  if (value == true) {\n"
          "    vis1 = \"none\";\n"
          "  } else {\n"
          "    vis2 = \"none\";\n"
          "  }\n"
          "  if (rows1 != null) {\n"
          "    for (var row in rows1) {\n"
          "      var obj = document.getElementById(rows1[row]);\n"
          "      if (obj != null) {\n"
          "        obj.style.display = vis1;\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "  if (rows2 != null) {\n"
          "    for (var row in rows2) {\n"
          "      var obj = document.getElementById(rows2[row]);\n"
          "      if (obj != null) {\n"
          "        obj.style.display = vis2;\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "}\n"
          "function toggleRowsVisibility2(value, tid, rowclass1, rowclass2)\n"
          "{\n"
          "  var vis1 = \"\";\n"
          "  var vis2 = \"\";\n"
          "  if (value == true) {\n"
          "    vis1 = \"none\";\n"
          "  } else {\n"
          "    vis2 = \"none\";\n"
          "  }\n"
          "  var tobj = document.getElementById(tid);\n"
          "  if (tobj == null) {\n"
          "    return;\n"
          "  }\n"
          "  var trows = tobj.rows;\n"
          "  if (trows != null) {\n"
          "    for (var row in trows) {\n"
          "      if (trows[row].className == rowclass1) {\n"
          "        trows[row].style.display = vis1;\n"
          "      } else if (trows[row].className == rowclass2) {\n"
          "        trows[row].style.display = vis2;\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "}\n"
          "function toggleStatVisibility(value)\n"
          "{\n"
          "  toggleRowsVisibility2(value, \"UserData\", \"StatRow1\", \"StatRow2\");\n"
          "}\n"
          "function toggleFlagVisibility(value)\n"
          "{\n"
          "  toggleRowsVisibility2(value, \"UserData\", \"FlagRow1\", \"FlagRow2\");\n"
          "}\n"
          "function toggleUserInfoVisibility(value)\n"
          "{\n"
          "  toggleRowsVisibility2(value, \"UserData\", \"UserInfoRow1\", \"UserInfoRow2\");\n"
          "}\n"
          "function toggleMemberInfoVisibility(value)\n"
          "{\n"
          "  toggleRowsVisibility2(value, \"UserData\", \"MemberInfoRow1\", \"MemberInfoRow2\");\n"
          "}\n"
          "function showContestRegs()\n"
          "{\n"
          "  document.getElementById(\"ContestRegsShowLink\").style.display = \"none\";\n"
          "  document.getElementById(\"ContestRegsTable\").style.display = \"\";\n"
          "}\n"
          "function hideContestRegs()\n"
          "{\n"
          "  document.getElementById(\"ContestRegsShowLink\").style.display = \"\";\n"
          "  document.getElementById(\"ContestRegsTable\").style.display = \"none\";\n"
          "}\n"
          "function showCookies()\n"
          "{\n"
          "  document.getElementById(\"CookiesShowLink\").style.display = \"none\";\n"
          "  document.getElementById(\"CookiesTable\").style.display = \"\";\n"
          "}\n"
          "function hideCookies()\n"
          "{\n"
          "  document.getElementById(\"CookiesShowLink\").style.display = \"\";\n"
          "  document.getElementById(\"CookiesTable\").style.display = \"none\";\n"
          "}\n"
          "function checkNull(field_id)\n"
          "{\n"
          "  var form_obj = document.getElementById(\"UserForm\");\n"
          "  var checkbox_obj = form_obj[\"field_null_\" + field_id];\n"
          "  var text_obj = form_obj[\"field_\" + field_id];\n"
          "  if (checkbox_obj != null && checkbox_obj.checked) {\n"
          "    if (text_obj) text_obj.value = \"\";\n"
          "  }\n"
          "}\n"
          "function uncheckNull(field_id)\n"
          "{\n"
          "  var form_obj = document.getElementById(\"UserForm\");\n"
          "  var checkbox_obj = form_obj[\"field_null_\" + field_id];\n"
          "  var text_obj = form_obj[\"field_\" + field_id];\n"
          "  if (text_obj != null && (text_obj.value != null && text_obj.value != \"\")) {\n"
          "    if (checkbox_obj != null) checkbox_obj.checked = false;\n"
          "  }\n"
          "}\n"
          "");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, other_user_id, NULL);

  if (!(u = get_user_info(phr, other_user_id, contest_id))) FAIL(SSERV_ERR_DB_ERROR);
  ui = u->cnts0;

  html_start_form_id(out_f, 1, phr->self_url, "UserForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "other_user_id", "%d", other_user_id);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  cl = " class=\"b1\"";
  fprintf(out_f, "<table%s id=\"UserData\">\n", cl);
  fprintf(out_f, "<tr><td%s colspan=\"4\" align=\"center\">", cl);
  fprintf(out_f, "%s%s</a>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id,
                        phr->self_url, NULL,
                        "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_CANCEL_AND_PREV_ACTION,
                        other_user_id, contest_id_str, group_id_str),
          "Prev user");
  fprintf(out_f, "&nbsp;%s%s</a>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id,
                        phr->self_url, NULL,
                        "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_CANCEL_AND_NEXT_ACTION,
                        other_user_id, contest_id_str, group_id_str),
          "Next user");
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr><th%s width=\"250px\">&nbsp;</th><th%s><b>NULL?</b></th><th%s>&nbsp;</th><th%s>&nbsp;</th></tr>\n", cl, cl, cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          cl, "User ID", cl, cl, other_user_id, cl);
  s = u->login;
  if (!s) s = "";
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
          cl, "User login", cl, cl, 
          html_input_text(buf, sizeof(hbuf), "other_login", 50, 0, "%s", ARMOR(s)), cl);
  s = u->email;
  if (!s) s = "";
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
          cl, "User e-mail", cl, cl, 
          html_input_text(buf, sizeof(buf), "email", 50, 0, "%s", ARMOR(s)), cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
          cl, "Password", cl, cl);
  if (!u->passwd) {
    fprintf(out_f, "<i>NULL</i>");
  } else if (u->passwd_method == USERLIST_PWD_PLAIN) {
    fprintf(out_f, "<tt>%s</tt>", ARMOR(u->passwd));
  } else if (u->passwd_method == USERLIST_PWD_SHA1) {
    fprintf(out_f, "<i>Hashed with SHA1</i>");
  } else {
    fprintf(out_f, "<i>Unsupported method</i>");
  }
  fprintf(out_f, "</td><td%s>%s%s</a></td></tr>", cl,
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;next_op=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_PASSWORD_PAGE,
                        other_user_id, SSERV_CMD_USER_DETAIL_PAGE, contest_id_str, group_id_str),
          "[Change]");
  fprintf(out_f, "<tr class=\"StatRow1\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleStatVisibility(true)\">[%s]</a></td></tr>\n",
          cl, "Show user statistics");
  fprintf(out_f, "<tr class=\"StatRow2\" style=\"display: none;\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleStatVisibility(false)\">[%s]</a></td></tr>\n", cl, "Hide user statistics");

  for (row = 0; user_timestamp_rows[row].field_id > 0; ++row) {
    fprintf(out_f, "<tr class=\"StatRow2\" style=\"display: none;\"><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
            cl, user_timestamp_rows[row].field_desc, cl, cl);
    time_t *pt = (time_t*) userlist_get_user_field_ptr(u, user_timestamp_rows[row].field_id);
    if (pt && *pt > 0) {
      fprintf(out_f, "%s</td><td%s>%s%s</a></td></tr>\n",
              xml_unparse_date(*pt), cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;field_id=%d%s%s",
                            SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_CLEAR_FIELD_ACTION,
                            other_user_id, user_timestamp_rows[row].field_id,
                            contest_id_str, group_id_str),
              "[Reset]");
    } else if (pt) {
      fprintf(out_f, "<i>Not set</i></td><td%s>&nbsp;</td></tr>\n", cl);
    } else {
      fprintf(out_f, "<i>Invalid field</i></td><td%s>&nbsp;</td></tr>\n", cl);
    }
  }

  fprintf(out_f, "<tr class=\"FlagRow1\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleFlagVisibility(true)\">[%s]</a></td></tr>\n",
          cl, "Show user flags");
  fprintf(out_f, "<tr class=\"FlagRow2\" style=\"display: none;\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleFlagVisibility(false)\">[%s]</a></td></tr>\n", cl, "Hide user flags");

  for (row = 0; user_flag_rows[row].field_id > 0; ++row) {
    fprintf(out_f, "<tr class=\"FlagRow2\" style=\"display: none;\"><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
            cl, user_flag_rows[row].field_desc, cl, cl);
    int *pi = (int*) userlist_get_user_field_ptr(u, user_flag_rows[row].field_id);
    if (pi) {
      s = "";
      if (*pi > 0) {
        s = " checked=\"checked\"";
      }
      fprintf(out_f, "<input type=\"checkbox\" name=\"field_%d\" value=\"1\"%s />",
              user_flag_rows[row].field_id, s);
    } else {
      fprintf(out_f, "<i>Invalid field</i>");
    }
    fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);
  }

  fprintf(out_f, "<tr><td%s align=\"center\" colspan=\"4\"><b>%s</b></td></tr>\n",
          cl, "Generic contest-specific fields");
  s = "";
  if (ui && ui->cnts_read_only > 0) s = " checked=\"checked\"";
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s><input type=\"checkbox\" name=\"field_%d\" value=\"1\"%s /></td><td%s>&nbsp;</td></tr>\n",
          cl, "User data is read-only", cl, cl, USERLIST_NC_CNTS_READ_ONLY, s, cl);
  s = "";
  s2 = 0;
  if (ui) s2 = ui->name;
  if (!s2) {
    s = " checked=\"checked\"";
    s2 = "";
  }
  snprintf(hbuf, sizeof(hbuf), "field_%d", USERLIST_NC_NAME);
  snprintf(buf2, sizeof(buf2), "uncheckNull('%d')", USERLIST_NC_NAME);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"checkNull('%d')\" name=\"field_null_%d\" value=\"1\"%s /></td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
          cl, "User name", cl, USERLIST_NC_NAME, USERLIST_NC_NAME, s, cl, 
          html_input_text_js(buf, sizeof(buf), hbuf, 50, buf2, "%s", ARMOR(s2)), cl);
  if (contest_id > 0 && cnts && !cnts->disable_team_password) {
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
            cl, "Contest password", cl, cl);
    if (!ui || !ui->team_passwd) {
      fprintf(out_f, "<i>NULL</i>");
    } else if (ui->team_passwd_method == USERLIST_PWD_PLAIN) {
      fprintf(out_f, "<tt>%s</tt>", ARMOR(ui->team_passwd));
    } else if (ui->team_passwd_method == USERLIST_PWD_SHA1) {
      fprintf(out_f, "<i>Hashed with SHA1</i>");
    } else {
      fprintf(out_f, "<i>Unsupported method</i>");
    }
    fprintf(out_f, "</td><td%s>%s%s</a></td></tr>", cl,
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;contest_id=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_CNTS_PASSWORD_PAGE,
                          other_user_id, contest_id, group_id_str),
            "[Change]");
  }

  fprintf(out_f, "<tr class=\"UserInfoRow1\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleUserInfoVisibility(true)\">[%s]</a></td></tr>\n",
          cl, "Show more user info fields");
  fprintf(out_f, "<tr class=\"UserInfoRow2\" style=\"display: none;\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleUserInfoVisibility(false)\">[%s]</a></td></tr>\n", cl, "Hide user info fields");

  for (row = 0; user_info_rows[row].field_id > 0; ++row) {
    s = 0;
    if (user_info_rows[row].field_id == USERLIST_NC_INSTNUM) {
      if (ui && ui->instnum > 0) {
        snprintf(buf2, sizeof(buf2), "%d", ui->instnum);
        s = buf2;
      }
    } else if (ui) {
      unsigned char **ps = (unsigned char**) userlist_get_user_info_field_ptr(ui, user_info_rows[row].field_id);
      if (!ps) continue;
      s = *ps;
    }
    snprintf(hbuf, sizeof(hbuf), "%d", user_info_rows[row].field_id);
    string_row(out_f, "UserInfoRow2", 1, "b1", user_info_rows[row].field_desc, hbuf, s);
  }

  if (ui) {
    for (row = 0; user_info_stat_rows[row].field_id > 0; ++row) {
      fprintf(out_f, "<tr class=\"UserInfoRow2\" style=\"display: none;\"><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
              cl, user_info_stat_rows[row].field_desc, cl, cl);
      time_t *pt = (time_t*) userlist_get_user_info_field_ptr(ui, user_info_stat_rows[row].field_id);
      if (pt && *pt > 0) {
        fprintf(out_f, "%s</td><td%s>%s%s</a></td></tr>\n",
                xml_unparse_date(*pt), cl,
                html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                              NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;field_id=%d%s%s",
                              SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_CLEAR_FIELD_ACTION,
                              other_user_id, user_info_stat_rows[row].field_id,
                              contest_id_str, group_id_str),
                "[Reset]");
      } else if (pt) {
        fprintf(out_f, "<i>Not set</i></td><td%s>&nbsp;</td></tr>\n", cl);
      } else {
        fprintf(out_f, "<i>Invalid field</i></td><td%s>&nbsp;</td></tr>\n", cl);
      }
    }
  }

  fprintf(out_f, "<tr class=\"MemberInfoRow1\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleMemberInfoVisibility(true)\">[%s]</a></td></tr>\n",
          cl, "Show members");
  fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleMemberInfoVisibility(false)\">[%s]</a></td></tr>\n", cl, "Hide members");

  if (ui && ui->members) {
    for (role = 0; role < CONTEST_LAST_MEMBER; ++role) {
      int role_cnt = userlist_members_count(ui->members, role);
      if (role_cnt <= 0) continue;
      fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td colspan=\"4\"%s align=\"center\"><b>%s (%d)</b></td></tr>\n", cl, member_string_pl[role], role_cnt);
      for (pers = 0; pers < role_cnt; ++pers) {
        if (!(m = (struct userlist_member*) userlist_members_get_nth(ui->members, role, pers)))
          continue;

        fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td colspan=\"3\"%s align=\"center\"><b>%s %d (%d)</b></td><td%s>%s[%s]</a></tr>\n", cl, member_string[role], pers + 1, m->serial, cl,
                html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                              NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;serial=%d%s%s",
                              SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_DELETE_MEMBER_PAGE,
                              other_user_id, m->serial, contest_id_str, group_id_str),
                "Delete");

        fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td%s><b>%s</b></td><td%s>&nbsp;</td><td%s>%d</td><td%s>&nbsp;</td></tr>\n",
                cl, "Member serial Id", cl, cl, m->serial, cl);

        snprintf(hbuf, sizeof(hbuf), "field_%d_%d", m->serial, USERLIST_NM_STATUS);
        fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td%s><b>%s</b></td><td%s>&nbsp;</td><td%s>",
                cl, "Status", cl, cl);
        ss_select(out_f, hbuf, (const unsigned char* []) { "Undefined", "School student", "Student", "Magistrant", "PhD student", "School teacher", "Professor", "Scientist", "Other", NULL }, m->status);
        fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);
        snprintf(hbuf, sizeof(hbuf), "field_%d_%d", USERLIST_NM_GENDER, m->serial);
        fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td%s><b>%s</b></td><td%s>&nbsp;</td><td%s>",
                cl, "Status", cl, cl);
        ss_select(out_f, hbuf, (const unsigned char* []) { "Undefined", "Male", "Female", NULL }, m->gender);
        fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);

        s = 0;
        if (m->grade > 0) {
          snprintf(buf2, sizeof(buf2), "%d", m->grade);
          s = buf2;
        }
        snprintf(hbuf, sizeof(hbuf), "%d_%d", USERLIST_NM_GRADE, m->serial);
        string_row(out_f, "MemberInfoRow2", 1, "b1", "Grade", hbuf, s);

        for (row = 0; member_rows[row].field_id > 0; ++row) {
          unsigned char **ps = (unsigned char**) userlist_get_member_field_ptr(m, member_rows[row].field_id);
          if (!ps) continue;
          s = *ps;
          snprintf(hbuf, sizeof(hbuf), "%d_%d", member_rows[row].field_id, m->serial);
          string_row(out_f, "MemberInfoRow2", 1, "b1", member_rows[row].field_desc, hbuf, s);
        }

        for (row = 0; member_date_rows[row].field_id > 0; ++row) {
          time_t *pt = (time_t*) userlist_get_member_field_ptr(m, member_date_rows[row].field_id);
          if (!pt) continue;
          s = 0;
          if (*pt > 0) {
            userlist_get_member_field_str(buf2, sizeof(buf2), m, member_date_rows[row].field_id, 0, 0);
            s = buf2;
          }
          snprintf(hbuf, sizeof(hbuf), "%d_%d", member_date_rows[row].field_id, m->serial);
          string_row(out_f, "MemberInfoRow2", 1, "b1", member_date_rows[row].field_desc, hbuf, s);
        }

        for (row = 0; member_time_rows[row].field_id > 0; ++row) {
          fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
                  cl, member_time_rows[row].field_desc, cl, cl);
          time_t *pt = (time_t*) userlist_get_member_field_ptr(m, member_time_rows[row].field_id);
          if (pt && *pt > 0) {
            fprintf(out_f, "%s</td><td%s>%s%s</a></td></tr>\n",
                    xml_unparse_date(*pt), cl,
                    html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                  NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;member_id=%d&amp;field_id=%d%s%s",
                                  SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_CLEAR_FIELD_ACTION,
                                  other_user_id, m->serial, member_time_rows[row].field_id,
                                  contest_id_str, group_id_str),
                    "[Reset]");
          } else if (pt) {
            fprintf(out_f, "<i>Not set</i></td><td%s>&nbsp;</td></tr>\n", cl);
          } else {
            fprintf(out_f, "<i>Invalid field</i></td><td%s>&nbsp;</td></tr>\n", cl);
          }
        }
      }
    }
  }

  fprintf(out_f, "<tr><td%s colspan=\"4\" align=\"center\">", cl);
  fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_USER_SAVE_AND_PREV_ACTION, "Save and goto PREV user");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_USER_SAVE_ACTION, "Save and goto user list");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_USER_SAVE_AND_NEXT_ACTION, "Save and goto NEXT user");
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr><td%s colspan=\"4\" align=\"center\">", cl);
  fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_USER_CANCEL_AND_PREV_ACTION, "Cancel and goto PREV user");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_USER_CANCEL_ACTION, "Cancel and goto user list");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_USER_CANCEL_AND_NEXT_ACTION, "Cancel and goto NEXT user");
  fprintf(out_f, "</td></tr>\n");

  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "other_user_id", "%d", other_user_id);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  fprintf(out_f, "Create new member: ");
  ss_select(out_f, "role", (const unsigned char* []) { "", "Contestant", "Reserve", "Coach", "Advisor", "Guest", NULL }, 0);
  fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_USER_CREATE_MEMBER_ACTION, "Create member");
  fprintf(out_f, "</form>\n");

  reg_count = userlist_user_count_contests(u);
  if (reg_count > 0) {
    fprintf(out_f, "<h2>%s</h2>\n", "Contest registrations");

    fprintf(out_f, "<div id=\"ContestRegsShowLink\"><p><a onclick=\"showContestRegs()\">%s</a></p></div>\n",
            "Show Contest Registrations");
    fprintf(out_f, "<div id=\"ContestRegsTable\" style=\"display: none;\"><p><a onclick=\"hideContestRegs()\">%s</a></p>\n",
            "Hide Contest Registrations");
    fprintf(out_f, "<table%s>\n", cl);
    fprintf(out_f, "<tr><th%s align=\"center\"><b>Contest Id</b></th><th%s align=\"center\"><b>Contest name</b></th>"
            "<th%s align=\"center\"><b>Status</b></th><th%s align=\"center\"><b>Flags</b></th>"
            "<th%s align=\"center\"><b>Create date</b></th><th%s align=\"center\"><b>Last change date</b></th>"
            "<th%s align=\"center\"><b>Actions</b></th></tr>\n",
            cl, cl, cl, cl, cl, cl, cl);
    for (reg = FIRST_CONTEST(u); reg; reg = NEXT_CONTEST(reg)) {
      if (contests_get(reg->id, &cnts) < 0 || !cnts) continue;
      fprintf(out_f, "<tr>");
      fprintf(out_f, "<td%s>%d</td>", cl, reg->id);
      fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(cnts->name));
      r = reg->status;
      if (r < 0 || r >= USERLIST_REG_LAST) r = USERLIST_REG_LAST;
      fprintf(out_f, "<td%s>%s</td>", cl, reg_status_strs[r]);
      fprintf(out_f, "<td%s>", cl);
      r = 0;
      if ((reg->flags & USERLIST_UC_INVISIBLE)) {
        if (r++) fprintf(out_f, ", ");
        fprintf(out_f, "invisible");
      }
      if ((reg->flags & USERLIST_UC_BANNED)) {
        if (r++) fprintf(out_f, ", ");
        fprintf(out_f, "banned");
      }
      if ((reg->flags & USERLIST_UC_LOCKED)) {
        if (r++) fprintf(out_f, ", ");
        fprintf(out_f, "locked");
      }
      if ((reg->flags & USERLIST_UC_INCOMPLETE)) {
        if (r++) fprintf(out_f, ", ");
        fprintf(out_f, "incomplete");
      }
      if ((reg->flags & USERLIST_UC_DISQUALIFIED)) {
        if (r++) fprintf(out_f, ", ");
        fprintf(out_f, "disqualified");
      }
      fprintf(out_f, "</td>");
      if (reg->create_time > 0) {
        fprintf(out_f, "<td%s>%s</td>", cl, xml_unparse_date(reg->create_time));
      } else {
        fprintf(out_f, "<td%s><i>Not set</i></td>", cl);
      }
      if (reg->last_change_time > 0) {
        fprintf(out_f, "<td%s>%s</td>", cl, xml_unparse_date(reg->last_change_time));
      } else {
        fprintf(out_f, "<td%s><i>Not set</i></td>", cl);
      }
      fprintf(out_f, "<td%s>", cl);
      fprintf(out_f, "%s[%s]</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;contest_id=%d",
                                  SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_DETAIL_PAGE,
                                  other_user_id, reg->id),
              "User details");
      fprintf(out_f, "&nbsp;%s[%s]</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;next_op=%d&amp;other_user_id=%d&amp;other_contest_id=%d%s%s",
                            SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_EDIT_REG_PAGE,
                            SSERV_CMD_USER_DETAIL_PAGE,
                            other_user_id, reg->id, contest_id_str, group_id_str),
              "Change");
      fprintf(out_f, "&nbsp;%s[%s]</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;next_op=%d&amp;other_user_id=%d&amp;other_contest_id=%d%s%s",
                            SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_DELETE_REG_PAGE,
                            SSERV_CMD_USER_DETAIL_PAGE,
                            other_user_id, reg->id, contest_id_str, group_id_str),
              "Delete");

      fprintf(out_f, "</td>");
      fprintf(out_f, "</tr>\n");
    }
    fprintf(out_f, "</table>\n");
    fprintf(out_f, "<p>%s[%s]</a></p>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;other_user_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_CREATE_REG_PAGE,
                          other_user_id),
            "Create a registration");
    fprintf(out_f, "</div>\n");
  }

  cookie_count = userlist_user_count_cookies(u);
  if (cookie_count > 0) {
    fprintf(out_f, "<h2>%s</h2>\n", "Sessions");

    fprintf(out_f, "<div id=\"CookiesShowLink\"><p><a onclick=\"showCookies()\">%s</a></p></div>\n",
            "Show Cookies");
    fprintf(out_f, "<div id=\"CookiesTable\" style=\"display: none;\"><p><a onclick=\"hideCookies()\">%s</a></p>\n",
            "Hide Cookies");
    fprintf(out_f, "<table%s>\n", cl);

    fprintf(out_f, "<tr>");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "IP address");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "SSL?");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "Session ID");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "Expiry time");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "Contest ID");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "Locale ID");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "Privilege Level");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "Role");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "Recovery?");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "Team?");
    fprintf(out_f, "<td%s align=\"center\"><b>%s</b></td>", cl, "Actions");
    fprintf(out_f, "</tr>\n");

    for (cookie=FIRST_COOKIE(u);cookie;cookie=NEXT_COOKIE(cookie)) {
      fprintf(out_f, "<tr>");
      fprintf(out_f, "<td%s>%s</td>", cl, xml_unparse_ipv6(&cookie->ip));
      fprintf(out_f, "<td%s>%d</td>", cl, cookie->ssl);
      fprintf(out_f, "<td%s>%016llx</td>", cl, cookie->cookie);
      fprintf(out_f, "<td%s>%s</td>", cl, xml_unparse_date(cookie->expire));
      fprintf(out_f, "<td%s>%d</td>", cl, cookie->contest_id);
      fprintf(out_f, "<td%s>%d</td>", cl, cookie->locale_id);
      fprintf(out_f, "<td%s>%d</td>", cl, cookie->priv_level);
      fprintf(out_f, "<td%s>%d</td>", cl, cookie->role);
      fprintf(out_f, "<td%s>%d</td>", cl, cookie->recovery);
      fprintf(out_f, "<td%s>%d</td>", cl, cookie->team_login);
      fprintf(out_f, "<td%s>%s[%s]</a></td>", cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;other_SID=%016llx%s%s",
                            SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_DELETE_SESSION_ACTION,
                            other_user_id, cookie->cookie, contest_id_str, group_id_str),
              "Delete");
      fprintf(out_f, "</tr>");
    }

    fprintf(out_f, "</table>\n");
    fprintf(out_f, "<p>%s[%s]</a></p>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_DELETE_ALL_SESSIONS_ACTION,
                          other_user_id, contest_id_str, group_id_str),
            "Delete all sessions");
    fprintf(out_f, "</div>\n");
  }

  ss_write_html_footer(out_f);

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  html_armor_free(&ab);
  return retval;
}

static void
print_user_info(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        const struct userlist_user *u,
        const struct userlist_user_info *ui,
        const struct userlist_member *m,
        int role,
        int num)
{
  unsigned char *cl = " class=\"b1\"";
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s;
  int row = 0;
  unsigned char buf[1024];

  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s width=\"250px\" colspan=\"2\" align=\"center\"><b>%s %d</b></td></tr>\n", cl,
          "User information for user", u->id);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td></tr>\n",
          cl, "User ID", cl, u->id);
  s = u->login;
  if (!s) s = "";
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "User login", cl, ARMOR(s));
  s = u->email;
  if (!s) s = "";
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "User e-mail", cl, ARMOR(s));

  /*
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
          cl, "Password", cl, cl);
  if (!u->passwd) {
    fprintf(out_f, "<i>NULL</i>");
  } else if (u->passwd_method == USERLIST_PWD_PLAIN) {
    fprintf(out_f, "<tt>%s</tt>", ARMOR(u->passwd));
  } else if (u->passwd_method == USERLIST_PWD_SHA1) {
    fprintf(out_f, "<i>Hashed with SHA1</i>");
  } else {
    fprintf(out_f, "<i>Unsupported method</i>");
  }
  fprintf(out_f, "</td><td%s>%s%s</a></td></tr>", cl,
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;next_op=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_PASSWORD_PAGE,
                        other_user_id, SSERV_CMD_USER_DETAIL_PAGE, contest_id_str, group_id_str),
          "[Change]");
  */

  fprintf(out_f, "<tr><td colspan=\"2\"%s align=\"center\"><b>%s</b></td></tr>\n",
          cl, "User statistics");

  for (row = 0; user_timestamp_rows[row].field_id > 0; ++row) {
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>",
            cl, user_timestamp_rows[row].field_desc, cl);
    time_t *pt = (time_t*) userlist_get_user_field_ptr(u, user_timestamp_rows[row].field_id);
    if (pt && *pt > 0) {
      fprintf(out_f, "%s</td></tr>\n", xml_unparse_date(*pt));
    } else if (pt) {
      fprintf(out_f, "<i>Not set</i></td></tr>\n");
    }
  }

  for (row = 0; user_flag_rows[row].field_id > 0; ++row) {
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>",
            cl, user_flag_rows[row].field_desc, cl);
    int *pi = (int*) userlist_get_user_field_ptr(u, user_flag_rows[row].field_id);
    if (pi) {
      fprintf(out_f, "%s", (*pi)?"YES":"NO");
    } else {
      fprintf(out_f, "<i>Invalid field</i>");
    }
    fprintf(out_f, "</td></tr>\n");
  }

  if (!ui || !cnts) goto cleanup;

  fprintf(out_f, "<tr><td%s align=\"center\" colspan=\"2\"><b>%s %d</b></td></tr>\n",
          cl, "Contest-specific fields for contest", cnts->id);

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "User data is read-only", cl, ui->cnts_read_only?"YES":"NO");
  s = 0;
  if (ui) s = ui->name;
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "User name", cl, ARMOR(s));

  /*
  if (contest_id > 0 && cnts && !cnts->disable_team_password) {
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
            cl, "Contest password", cl, cl);
    if (!ui || !ui->team_passwd) {
      fprintf(out_f, "<i>NULL</i>");
    } else if (ui->team_passwd_method == USERLIST_PWD_PLAIN) {
      fprintf(out_f, "<tt>%s</tt>", ARMOR(ui->team_passwd));
    } else if (ui->team_passwd_method == USERLIST_PWD_SHA1) {
      fprintf(out_f, "<i>Hashed with SHA1</i>");
    } else {
      fprintf(out_f, "<i>Unsupported method</i>");
    }
    fprintf(out_f, "</td><td%s>%s%s</a></td></tr>", cl,
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;contest_id=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_CNTS_PASSWORD_PAGE,
                          other_user_id, contest_id, group_id_str),
            "[Change]");
  }
  */

  for (row = 0; user_info_rows[row].field_id > 0; ++row) {
    userlist_get_user_info_field_str(buf, sizeof(buf), ui, user_info_rows[row].field_id, 1);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
            cl, user_info_rows[row].field_desc, cl, ARMOR(buf));
  }

  for (row = 0; user_info_stat_rows[row].field_id > 0; ++row) {
    userlist_get_user_info_field_str(buf, sizeof(buf), ui, user_info_stat_rows[row].field_id, 1);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
            cl, user_info_stat_rows[row].field_desc, cl, ARMOR(buf));
  }
  
  if (!m) goto cleanup;

  fprintf(out_f, "<tr><td%s align=\"center\" colspan=\"2\"><b>%s %s::%d (%d)</b></td></tr>\n",
          cl, "Member", member_string[role], num + 1, m->serial);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td></tr>\n",
          cl, "Member serial Id", cl, m->serial);
  userlist_get_member_field_str(buf, sizeof(buf), m, USERLIST_NM_STATUS, 1, 0);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "Status", cl, ARMOR(buf));
  userlist_get_member_field_str(buf, sizeof(buf), m, USERLIST_NM_GENDER, 1, 0);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "Gender", cl, ARMOR(buf));
  userlist_get_member_field_str(buf, sizeof(buf), m, USERLIST_NM_GRADE, 1, 0);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "Grade", cl, ARMOR(buf));

  for (row = 0; member_rows[row].field_id > 0; ++row) {
    userlist_get_member_field_str(buf, sizeof(buf), m, member_rows[row].field_id, 1, 0);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
            cl, member_rows[row].field_desc, cl, ARMOR(buf));
  }

  for (row = 0; member_date_rows[row].field_id > 0; ++row) {
    userlist_get_member_field_str(buf, sizeof(buf), m, member_date_rows[row].field_id, 1, 0);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
            cl, member_date_rows[row].field_desc, cl, ARMOR(buf));
  }

  for (row = 0; member_time_rows[row].field_id > 0; ++row) {
    userlist_get_member_field_str(buf, sizeof(buf), m, member_time_rows[row].field_id, 1, 0);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
            cl, member_time_rows[row].field_desc, cl, ARMOR(buf));
  }

  fprintf(out_f, "</table>\n");

cleanup:
  html_armor_free(&ab);
}

int
super_serve_op_USER_PASSWORD_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  unsigned char buf[1024];
  int other_user_id = -1, contest_id = -1, group_id = -1, next_op = -1;
  const struct contest_desc *cnts = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const unsigned char *cl = 0;
  const unsigned char *s = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(SSERV_ERR_INV_USER_ID);
  }
  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "next_op", &next_op, 0);

  if (contest_id < 0) contest_id = 0;
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (group_id < 0) group_id = 0;

  if (!(u = get_user_info(phr, other_user_id, 0))) FAIL(SSERV_ERR_DB_ERROR);

  opcap_t caps = 0;
  if (get_global_caps(phr, &caps) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  int cap = OPCAP_EDIT_PASSWD;
  if (is_globally_privileged(phr, u) || is_contest_privileged(cnts, u))
    cap = OPCAP_PRIV_EDIT_PASSWD;
  if (opcaps_check(caps, cap) < 0) FAIL(SSERV_ERR_PERM_DENIED);

  snprintf(buf, sizeof(buf), "serve-control: %s, change registration password for user %d",
           phr->html_name, other_user_id);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<script language=\"javascript\">\n");
  fprintf(out_f,
          "function randomChar()\n"
          "{\n"
          "  var str = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\";\n"
          "  var ind = Math.floor(Math.random() * str.length);\n"
          "  if (ind < 0 || ind >= str.length) ind = 0;\n"
          "  return str.charAt(ind);\n"
          "}\n"
          "function randomString(length)\n"
          "{\n"
          "  var res = \"\";\n"
          "  for (var i = 0; i < length; ++i) {\n"
          "    res += randomChar();\n"
          "  }\n"
          "  return res;\n"
          "}\n"
          "function generateRandomRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"PasswordForm\");\n"
          "  form_obj.reg_random.value = randomString(16);\n"
          "}\n"
          "function copyRandomRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"PasswordForm\");\n"
          "  form_obj.reg_password1.value = form_obj.reg_random.value;\n"
          "  form_obj.reg_password2.value = form_obj.reg_random.value;\n"
          "}\n"
          "");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, other_user_id, NULL);

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  s = 0;
  if (u && u->cnts0) s = u->cnts0->name;
  if (!s) s = "";

  html_start_form_id(out_f, 1, phr->self_url, "PasswordForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "other_user_id", "%d", other_user_id);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  if (next_op > 0) {
    html_hidden(out_f, "next_op", "%d", next_op);
  }
  html_hidden(out_f, "op", "%d", SSERV_CMD_USER_CHANGE_PASSWORD_ACTION);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          cl, "User ID", cl, other_user_id, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
          cl, "User login", cl, ARMOR(u->login), cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
          cl, "User name", cl, ARMOR(s), cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s colspan=\"2\">",
          cl, "Current password", cl);
  if (!u->passwd) {
    fprintf(out_f, "<i>NULL</i>");
  } else if (u->passwd_method == USERLIST_PWD_PLAIN) {
    fprintf(out_f, "<tt>%s</tt>", ARMOR(u->passwd));
  } else if (u->passwd_method == USERLIST_PWD_SHA1) {
    fprintf(out_f, "Sha1 hash: <i>%s</i>", ARMOR(u->passwd));
  }
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"password\" name=\"reg_password1\" size=\"20\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "New password", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"password\" name=\"reg_password2\" size=\"20\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Confirm new password", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"reg_random\" size=\"40\" /></td><td%s><a onclick=\"generateRandomRegPassword()\">[%s]</a>&nbsp;<a onclick=\"copyRandomRegPassword()\">[%s]</a></td></tr>\n",
          cl, "Random password", cl, cl, "Generate", "Copy");
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"usesha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use SHA1", cl, cl);
  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"%s\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, cl, "Change password", cl);
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

do_footer:
  ss_write_html_footer(out_f);

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_USER_CNTS_PASSWORD_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  unsigned char buf[1024];
  int other_user_id = -1, contest_id = -1, group_id = -1;
  const struct contest_desc *cnts = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const unsigned char *cl = 0;
  const unsigned char *s = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(SSERV_ERR_INV_USER_ID);
  }
  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0) {
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) {
      FAIL(SSERV_ERR_INV_CONTEST);
    }
  }
  if (group_id < 0) group_id = 0;

  if (!(u = get_user_info(phr, other_user_id, contest_id))) FAIL(SSERV_ERR_DB_ERROR);

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  opcap_t gcaps = 0;
  get_global_caps(phr, &gcaps);
  opcap_t caps = 0;
  get_contest_caps(phr, cnts, &caps);

  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0 && opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(gcaps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0)
      FAIL(SSERV_ERR_PERM_DENIED);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, change contest password for user %d in contest %d",
           phr->html_name, other_user_id, contest_id);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<script language=\"javascript\">\n");
  fprintf(out_f,
          "function randomChar()\n"
          "{\n"
          "  var str = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\";\n"
          "  var ind = Math.floor(Math.random() * str.length);\n"
          "  if (ind < 0 || ind >= str.length) ind = 0;\n"
          "  return str.charAt(ind);\n"
          "}\n"
          "function randomString(length)\n"
          "{\n"
          "  var res = \"\";\n"
          "  for (var i = 0; i < length; ++i) {\n"
          "    res += randomChar();\n"
          "  }\n"
          "  return res;\n"
          "}\n"
          "function generateRandomCntsPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"PasswordForm\");\n"
          "  form_obj.cnts_random.value = randomString(16);\n"
          "}\n"
          "function copyRandomCntsPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"PasswordForm\");\n"
          "  form_obj.cnts_password1.value = form_obj.cnts_random.value;\n"
          "  form_obj.cnts_password2.value = form_obj.cnts_random.value;\n"
          "}\n"
          "");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, other_user_id, NULL);

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  s = 0;
  if (u && u->cnts0) s = u->cnts0->name;
  if (!s) s = "";

  html_start_form_id(out_f, 1, phr->self_url, "PasswordForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "other_user_id", "%d", other_user_id);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  html_hidden(out_f, "op", "%d", SSERV_CMD_USER_CHANGE_CNTS_PASSWORD_ACTION);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          cl, "User ID", cl, other_user_id, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
          cl, "User login", cl, ARMOR(u->login), cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
          cl, "User name", cl, ARMOR(s), cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          cl, "Contest ID", cl, contest_id, cl);
  if (cnts) {
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
            cl, "Contest name", cl, ARMOR(cnts->name), cl);
  }
  if (cnts && cnts->disable_team_password > 0) {
    fprintf(out_f, "<tr><td%s colspan=\"3\" align=\"center\"><b>%s</b></td></tr>\n",
            cl, "Contest password is disabled");
  } else {
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s colspan=\"2\">",
            cl, "Current password", cl);
    if (!u->passwd) {
      fprintf(out_f, "<i>NULL</i>");
    } else if (u->passwd_method == USERLIST_PWD_PLAIN) {
      fprintf(out_f, "<tt>%s</tt>", ARMOR(u->passwd));
    } else if (u->passwd_method == USERLIST_PWD_SHA1) {
      fprintf(out_f, "Sha1 hash: <i>%s</i>", ARMOR(u->passwd));
    }
    fprintf(out_f, "</td></tr>\n");
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"useregpasswd\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
            cl, "Copy from reg. password", cl, cl);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"settonull\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
            cl, "Set to NULL", cl, cl);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"password\" name=\"cnts_password1\" size=\"20\" /></td><td%s>&nbsp;</td></tr>\n",
            cl, "New password", cl, cl);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"password\" name=\"cnts_password2\" size=\"20\" /></td><td%s>&nbsp;</td></tr>\n",
            cl, "Confirm new password", cl, cl);
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"cnts_random\" size=\"40\" /></td><td%s><a onclick=\"generateRandomCntsPassword()\">[%s]</a>&nbsp;<a onclick=\"copyRandomCntsPassword()\">[%s]</a></td></tr>\n",
            cl, "Random password", cl, cl, "Generate", "Copy");
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"usesha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
            cl, "Use SHA1", cl, cl);
    fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"%s\" /></td><td%s>&nbsp;</td></tr>\n",
            cl, cl, "Change password", cl);
  }
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

do_footer:
  ss_write_html_footer(out_f);

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_USER_CREATE_REG_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int other_user_id = 0, contest_id = 0, group_id = 0;
  const struct contest_desc *cnts = 0;
  unsigned char buf[1024];
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const unsigned char *cl = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const int *cnts_id_list = 0;
  int cnts_id_count, i, other_contest_id_2;

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(SSERV_ERR_INV_USER_ID);
  }
  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (group_id < 0) group_id = 0;

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);

  snprintf(buf, sizeof(buf), "serve-control: %s, create a contest registration for user %d",
           phr->html_name, other_user_id);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<script language=\"javascript\">\n");
  fprintf(out_f,
          "function updateCnts1()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj1.value;\n"
          "  var i;\n"
          "  for (i = 0; i < obj2.options.length; ++i) {\n"
          "    if (obj2.options[i].value == value) {\n"
          "      obj2.options.selectedIndex = i;\n"
          "      break;\n"
          "    }\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function updateCnts2()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj2.options[obj2.selectedIndex].value;\n"
          "  obj1.value = value;\n"
          "}\n");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, other_user_id, NULL);

  if (!(u = get_user_info(phr, other_user_id, contest_id)))
    FAIL(SSERV_ERR_DB_ERROR);

  cnts_id_count = contests_get_list(&cnts_id_list);
  if (cnts_id_count <= 0 || !cnts_id_list) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No contests available</pre>\n");
    goto do_footer;
  }

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "other_user_id", "%d", other_user_id);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  html_hidden(out_f, "op", "%d", SSERV_CMD_USER_CREATE_REG_ACTION);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td></tr>\n",
          cl, "User ID", cl, other_user_id);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "User login", cl, ARMOR(u->login));
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input id=\"cnts1\" onchange=\"updateCnts1()\" type=\"text\" name=\"other_contest_id_1\" size=\"20\"/></td></tr>\n",
          cl, "Contest ID", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>", cl, "Contest name", cl);
  fprintf(out_f, "<select id=\"cnts2\" onchange=\"updateCnts2()\" name=\"other_contest_id_2\"><option value=\"0\"></option>");
  for (i = 0; i < cnts_id_count; ++i) {
    other_contest_id_2 = cnts_id_list[i];
    if (other_contest_id_2 <= 0) continue;
    if (contests_get(other_contest_id_2, &cnts) < 0 || !cnts) continue;
    if (cnts->closed) continue;
    fprintf(out_f, "<option value=\"%d\">%s</option>", other_contest_id_2, ARMOR(cnts->name));
  }
  fprintf(out_f, "</select>");
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>", cl, "Status", cl);
  ss_select(out_f, "status", (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, 1);
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Invisible?", cl, "is_invisible");
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Banned?", cl, "is_banned");
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Locked?", cl, "is_locked");
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Incomplete?", cl, "is_incomplete");
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Disqualified?", cl, "is_disqualified");
  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"Create registration\" /></td></tr>\n", cl, cl);
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

do_footer:
  ss_write_html_footer(out_f);

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_USER_EDIT_REG_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  int other_user_id = 0, other_contest_id = 0, contest_id = 0, group_id = 0, next_op = 0;
  const struct contest_desc *cnts = 0;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
  unsigned char next_op_str[128];
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const struct userlist_contest *reg;
  const unsigned char *cl = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int reg_count = 0;
  const unsigned char *checked = " checked=\"checked\"";
  const unsigned char *s = 0;

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(SSERV_ERR_INV_USER_ID);
  }
  if (hr_cgi_param_int(phr, "other_contest_id", &other_contest_id) < 0) {
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "next_op", &next_op, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  contest_id_str[0] = 0;
  if (contest_id > 0) {
    snprintf(contest_id_str, sizeof(contest_id_str), "&amp;contest_id=%d", contest_id);
  }
  if (group_id < 0) group_id = 0;
  group_id_str[0] = 0;
  if (group_id > 0) {
    snprintf(group_id_str, sizeof(group_id_str), "&amp;group_id=%d", group_id);
  }
  if (other_contest_id <= 0) {
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  if (contests_get(other_contest_id, &cnts) < 0 || !cnts) {
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  if (next_op != SSERV_CMD_USER_DETAIL_PAGE && next_op != SSERV_CMD_USER_BROWSE_PAGE) next_op = 0;
  next_op_str[0] = 0;
  if (next_op > 0) {
    snprintf(next_op_str, sizeof(next_op_str), "&amp;next_op=%d", next_op);
  }

  opcap_t gcaps = 0, caps = 0;
  get_global_caps(phr, &gcaps);
  if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_EDIT_REG;
  if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_EDIT_REG;
  get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  if (opcaps_check(caps, OPCAP_EDIT_REG) < 0 && opcaps_check(caps, OPCAP_PRIV_EDIT_REG) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  snprintf(buf, sizeof(buf), "serve-control: %s, edit the contest registration for user %d, contest %d",
           phr->html_name, other_user_id, other_contest_id);
  ss_write_html_header(out_f, phr, buf);
  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, other_user_id, NULL);

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  if (!(u = get_user_info(phr, other_user_id, 0)))
    FAIL(SSERV_ERR_DB_ERROR);

  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
    if (opcaps_check(caps, OPCAP_PRIV_EDIT_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(caps, OPCAP_EDIT_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  if ((reg_count = userlist_user_count_contests(u)) <= 0) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No contest registrations</pre>\n");
    goto do_footer;
  }
  for (reg = FIRST_CONTEST(u); reg; reg = NEXT_CONTEST(reg)) {
    if (reg->id == other_contest_id) break;
  }
  if (!reg) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>User is not registered for this contest</pre>\n");
    goto do_footer;
  }

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "other_user_id", "%d", other_user_id);
  html_hidden(out_f, "other_contest_id", "%d", other_contest_id);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  if (next_op > 0) {
    html_hidden(out_f, "next_op", "%d", next_op);
  }
  html_hidden(out_f, "op", "%d", SSERV_CMD_USER_EDIT_REG_ACTION);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td></tr>\n",
          cl, "User ID", cl, other_user_id);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "User login", cl, ARMOR(u->login));
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td></tr>\n",
          cl, "Contest ID", cl, other_contest_id);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "Contest name", cl, ARMOR(cnts->name));
  r = reg->status;
  if (r < 0 || r >= USERLIST_REG_LAST) r = USERLIST_REG_PENDING;
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>", cl, "Status", cl);
  ss_select(out_f, "status", (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, r);
  fprintf(out_f, "</td></tr>\n");
  s = "";
  if ((reg->flags & USERLIST_UC_INVISIBLE)) s = checked;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\"%s /></td></tr>\n",
          cl, "Invisible?", cl, "is_invisible", s);
  s = "";
  if ((reg->flags & USERLIST_UC_BANNED)) s = checked;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\"%s /></td></tr>\n",
          cl, "Banned?", cl, "is_banned", s);
  s = "";
  if ((reg->flags & USERLIST_UC_LOCKED)) s = checked;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\"%s /></td></tr>\n",
          cl, "Locked?", cl, "is_locked", s);
  s = "";
  if ((reg->flags & USERLIST_UC_INCOMPLETE)) s = checked;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\"%s /></td></tr>\n",
          cl, "Incomplete?", cl, "is_incomplete", s);
  s = "";
  if ((reg->flags & USERLIST_UC_DISQUALIFIED)) s = checked;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\"%s /></td></tr>\n",
          cl, "Disqualified?", cl, "is_disqualified", s);
  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"Save changes\" /></td></tr>\n", cl, cl);
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  fprintf(out_f, "<p>%s[%s]</a></p>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;other_contest_id=%d%s%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_DELETE_REG_PAGE,
                        other_user_id, other_contest_id, contest_id_str, group_id_str, next_op_str),
          "Delete");

do_footer:
  ss_write_html_footer(out_f);

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_USER_DELETE_REG_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  int other_user_id = 0, other_contest_id = 0, contest_id = 0, group_id = 0, next_op = 0;
  const struct contest_desc *cnts = 0;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
  unsigned char next_op_str[128];
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const struct userlist_contest *reg;
  const unsigned char *cl = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int reg_count = 0;
  const unsigned char *no = " no";
  const unsigned char *yes = " <b>YES</b>";
  const unsigned char *s = 0;

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(SSERV_ERR_INV_USER_ID);
  }
  if (hr_cgi_param_int(phr, "other_contest_id", &other_contest_id) < 0) {
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "next_op", &next_op, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  contest_id_str[0] = 0;
  if (contest_id > 0) {
    snprintf(contest_id_str, sizeof(contest_id_str), "&amp;contest_id=%d", contest_id);
  }
  if (group_id < 0) group_id = 0;
  group_id_str[0] = 0;
  if (group_id > 0) {
    snprintf(group_id_str, sizeof(group_id_str), "&amp;group_id=%d", group_id);
  }
  if (other_contest_id <= 0) {
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  if (contests_get(other_contest_id, &cnts) < 0 || !cnts) {
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  if (next_op != SSERV_CMD_USER_BROWSE_PAGE && next_op != SSERV_CMD_USER_DETAIL_PAGE) next_op = 0;
  next_op_str[0] = 0;
  if (next_op > 0) {
    snprintf(next_op_str, sizeof(next_op_str), "&amp;next_op=%d", next_op);
  }

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  opcap_t gcaps = 0, caps = 0;
  get_global_caps(phr, &gcaps);
  if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_DELETE_REG;
  if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_DELETE_REG;
  get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0 && opcaps_check(caps, OPCAP_DELETE_REG) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  snprintf(buf, sizeof(buf), "serve-control: %s, delete the contest registration for user %d, contest %d",
           phr->html_name, other_user_id, other_contest_id);
  ss_write_html_header(out_f, phr, buf);
  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, other_user_id, NULL);

  if (!(u = get_user_info(phr, other_user_id, 0))) FAIL(SSERV_ERR_DB_ERROR);

  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_DELETE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
    if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(caps, OPCAP_DELETE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  if ((reg_count = userlist_user_count_contests(u)) <= 0) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No contest registrations</pre>\n");
    goto do_footer;
  }
  for (reg = FIRST_CONTEST(u); reg; reg = NEXT_CONTEST(reg)) {
    if (reg->id == other_contest_id) break;
  }
  if (!reg) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>User is not registered for this contest</pre>\n");
    goto do_footer;
  }

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "other_user_id", "%d", other_user_id);
  html_hidden(out_f, "other_contest_id", "%d", other_contest_id);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  if (next_op > 0) {
    html_hidden(out_f, "next_op", "%d", next_op);
  }
  html_hidden(out_f, "op", "%d", SSERV_CMD_USER_DELETE_REG_ACTION);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td></tr>\n",
          cl, "User ID", cl, other_user_id);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "User login", cl, ARMOR(u->login));
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td></tr>\n",
          cl, "Contest ID", cl, other_contest_id);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>\n",
          cl, "Contest name", cl, ARMOR(cnts->name));

  r = reg->status;
  if (r < 0 || r >= USERLIST_REG_LAST) r = USERLIST_REG_LAST;
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%s</td></tr>",
          cl, "Status", cl, reg_status_strs[r]);
  s = no;
  if ((reg->flags & USERLIST_UC_INVISIBLE)) s = yes;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s>%s</td></tr>\n",
          cl, "Invisible?", cl, s);
  s = no;
  if ((reg->flags & USERLIST_UC_BANNED)) s = yes;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s>%s</td></tr>\n",
          cl, "Banned?", cl, s);
  s = no;
  if ((reg->flags & USERLIST_UC_LOCKED)) s = yes;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s>%s</td></tr>\n",
          cl, "Locked?", cl, s);
  s = no;
  if ((reg->flags & USERLIST_UC_INCOMPLETE)) s = yes;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s>%s</td></tr>\n",
          cl, "Incomplete?", cl, s);
  s = no;
  if ((reg->flags & USERLIST_UC_DISQUALIFIED)) s = yes;
  fprintf(out_f, "<tr><td%s><b>%s</td></td><td%s>%s</td></tr>\n",
          cl, "Disqualified?", cl, s);


  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"Confirm delete!\" /></td></tr>\n", cl, cl);
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  fprintf(out_f, "<p>%s[%s]</a></p>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;other_contest_id=%d%s%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_EDIT_REG_PAGE,
                        other_user_id, other_contest_id, contest_id_str, group_id_str, next_op_str),
          "Edit");

do_footer:
  ss_write_html_footer(out_f);

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_USER_CREATE_ONE_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, row, i;
  int contest_id = 0, group_id = 0, other_contest_id_2 = 0;
  const struct contest_desc *cnts = 0;
  unsigned char buf[1024], hbuf[1024];
  const unsigned char *cl = 0;
  const int *cnts_id_list = 0;
  int cnts_id_count = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s;
  opcap_t caps = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (group_id < 0) group_id = 0;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  cnts_id_count = contests_get_list(&cnts_id_list);
  if (cnts_id_count <= 0 || !cnts_id_list) {
    cnts_id_count = 0;
    cnts_id_list = 0;
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, create a new user",
           phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<script language=\"javascript\">\n");
  fprintf(out_f,
          "function changeEmail(form_obj)\n"
          "{\n"
          "  if (form_obj.other_email.value != null && form_obj.other_email.value != \"\") {\n"
          "    document.getElementById(\"SendEmailRow\").style.display = \"\";\n"
          "    changeSendEmail(form_obj);\n"
          "  } else {\n"
          "    document.getElementById(\"SendEmailRow\").style.display = \"none\";\n"
          "    document.getElementById(\"ConfirmEmailRow\").style.display = \"none\";\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function changeSendEmail(form_obj)\n"
          "{\n"
          "  if (form_obj.send_email.checked) {\n"
          "    document.getElementById(\"ConfirmEmailRow\").style.display = \"\";\n"
          "  } else {\n"
          "    document.getElementById(\"ConfirmEmailRow\").style.display = \"none\";\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function randomChar()\n"
          "{\n"
          "  var str = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\";\n"
          "  var ind = Math.floor(Math.random() * str.length);\n"
          "  if (ind < 0 || ind >= str.length) ind = 0;\n"
          "  return str.charAt(ind);\n"
          "}\n"
          "function randomString(length)\n"
          "{\n"
          "  var res = \"\";\n"
          "  for (var i = 0; i < length; ++i) {\n"
          "    res += randomChar();\n"
          "  }\n"
          "  return res;\n"
          "}\n"
          "function generateRandomRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.reg_random.value = randomString(16);\n"
          "}\n"
          "function copyRandomRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.reg_password1.value = form_obj.reg_random.value;\n"
          "  form_obj.reg_password2.value = form_obj.reg_random.value;\n"
          "}\n"
          "function generateRandomCntsPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.cnts_random.value = randomString(16);\n"
          "}\n"
          "function copyRandomCntsPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.cnts_password1.value = form_obj.cnts_random.value;\n"
          "  form_obj.cnts_password2.value = form_obj.cnts_random.value;\n"
          "}\n"
          "function copyRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.cnts_random.value = form_obj.reg_random.value;\n"
          "  form_obj.cnts_password1.value = form_obj.reg_password1.value;\n"
          "  form_obj.cnts_password2.value = form_obj.reg_password2.value;\n"
          "  form_obj.cnts_sha1.checked = form_obj.reg_sha1.checked;\n"
          "}\n");
  fprintf(out_f,
          "function toggleRowsVisibility2(value, tid, rowclass1, rowclass2)\n"
          "{\n"
          "  var vis1 = \"\";\n"
          "  var vis2 = \"\";\n"
          "  if (value == true) {\n"
          "    vis1 = \"none\";\n"
          "  } else {\n"
          "    vis2 = \"none\";\n"
          "  }\n"
          "  var tobj = document.getElementById(tid);\n"
          "  if (tobj == null) {\n"
          "    return;\n"
          "  }\n"
          "  var trows = tobj.rows;\n"
          "  if (trows != null) {\n"
          "    for (var row in trows) {\n"
          "      if (trows[row].className == rowclass1) {\n"
          "        trows[row].style.display = vis1;\n"
          "      } else if (trows[row].className == rowclass2) {\n"
          "        trows[row].style.display = vis2;\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "}\n"
          "function changeCntsRegCreate(obj)\n"
          "{\n"
          "  toggleRowsVisibility2(obj.checked, \"CreateUserTable\", \"CntsRegRow0\", \"CntsRegRow\");\n"
          "  updateCntsPasswdVisibility();\n"
          "}\n"
          "function changeGroupCreate(obj)\n"
          "{\n"
          "  toggleRowsVisibility2(obj.checked, \"CreateUserTable\", \"GroupRow0\", \"GroupRow\");\n"
          "}\n"
          "");
  fprintf(out_f,
          "function updateCnts1()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj1.value;\n"
          "  var i;\n"
          "  for (i = 0; i < obj2.options.length; ++i) {\n"
          "    if (obj2.options[i].value == value) {\n"
          "      obj2.options.selectedIndex = i;\n"
          "      break;\n"
          "    }\n"
          "  }\n"
          "  updateCntsPasswdVisibility();\n"
          "}\n");
  fprintf(out_f,
          "function updateCnts2()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj2.options[obj2.selectedIndex].value;\n"
          "  obj1.value = value;\n"
          "  updateCntsPasswdVisibility();\n"
          "}\n");
  fprintf(out_f, "var cnts_passwd_enabled = { ");
  row = 0;
  for (i = 0; i < cnts_id_count; ++i) {
    other_contest_id_2 = cnts_id_list[i];
    if (other_contest_id_2 <= 0) continue;
    if (contests_get(other_contest_id_2, &cnts) < 0 || !cnts) continue;
    if (!cnts->disable_team_password) {
      if (row) fprintf(out_f, ", ");
      ++row;
      fprintf(out_f, "%d : true", other_contest_id_2);
    }
  }
  fprintf(out_f, "};\n");
  // CntsRegRowUseRegPasswd cnts_use_reg_passwd
  // CntsRegRowSetToNull    cnts_rull_passwd
  // CntsRegRowPasswd1      cnts_password1
  // CntsRegRowPasswd2      cnts_password2
  // CntsRegRowPasswdRandom cnts_random
  // CntsRegRowPasswdSha1   cnts_sha1
  fprintf(out_f,
          "function updateCntsPasswdVisibility()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  if (!form_obj.reg_cnts_create.checked || !cnts_passwd_enabled[form_obj.other_contest_id_1.value]) {\n"
          "    form_obj.cnts_use_reg_passwd.checked = false;\n"
          "    form_obj.cnts_null_passwd.checked = false;\n"
          "    form_obj.cnts_password1.value = \"\";\n"
          "    form_obj.cnts_password2.value = \"\";\n"
          "    form_obj.cnts_random.value = \"\";\n"
          "    form_obj.cnts_sha1.checked = false;\n"
          "    document.getElementById(\"CntsRegRowUseRegPasswd\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowSetToNull\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowPasswd1\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowPasswd2\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowPasswdRandom\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "  } else {\n"
          "    document.getElementById(\"CntsRegRowUseRegPasswd\").style.display = \"\";\n"
          "    if (form_obj.cnts_use_reg_passwd.checked) {\n"
          "      form_obj.cnts_null_passwd.checked = false;\n"
          "      form_obj.cnts_password1.value = \"\";\n"
          "      form_obj.cnts_password2.value = \"\";\n"
          "      form_obj.cnts_random.value = \"\";\n"
          "      form_obj.cnts_sha1.checked = false;\n"
          "      document.getElementById(\"CntsRegRowSetToNull\").style.display = \"none\";\n"
          "      document.getElementById(\"CntsRegRowPasswd1\").style.display = \"none\";\n"
          "      document.getElementById(\"CntsRegRowPasswd2\").style.display = \"none\";\n"
          "      document.getElementById(\"CntsRegRowPasswdRandom\").style.display = \"none\";\n"
          "      document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "    } else {\n"
          "      document.getElementById(\"CntsRegRowSetToNull\").style.display = \"\";\n"
          "      if (form_obj.cnts_null_passwd.checked) {\n"
          "        form_obj.cnts_password1.value = \"\";\n"
          "        form_obj.cnts_password2.value = \"\";\n"
          "        form_obj.cnts_random.value = \"\";\n"
          "        form_obj.cnts_sha1.checked = false;\n"
          "        document.getElementById(\"CntsRegRowPasswd1\").style.display = \"none\";\n"
          "        document.getElementById(\"CntsRegRowPasswd2\").style.display = \"none\";\n"
          "        document.getElementById(\"CntsRegRowPasswdRandom\").style.display = \"none\";\n"
          "        document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "      } else {\n"
          "        document.getElementById(\"CntsRegRowPasswd1\").style.display = \"\";\n"
          "        document.getElementById(\"CntsRegRowPasswd2\").style.display = \"\";\n"
          "        document.getElementById(\"CntsRegRowPasswdRandom\").style.display = \"\";\n"
          "        document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"\";\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "}\n");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, 0, NULL);

  html_start_form_id(out_f, 1, phr->self_url, "CreateForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "op", "%d", SSERV_CMD_USER_CREATE_ONE_ACTION);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s id=\"CreateUserTable\">\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"text\" size=\"40\" name=\"other_login\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Login", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"text\" size=\"40\" onchange=\"changeEmail(this.form)\" name=\"other_email\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "E-mail", cl, cl);
  fprintf(out_f, "<tr id=\"SendEmailRow\" style=\"display: none;\"><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"changeSendEmail(this.form)\" name=\"send_email\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Send registration e-mail", cl, cl);
  fprintf(out_f, "<tr id=\"ConfirmEmailRow\" style=\"display: none;\"><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"confirm_email\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Confirm e-mail by user", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"password\" name=\"reg_password1\" size=\"40\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Registration password", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"password\" name=\"reg_password2\" size=\"40\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Confirm password", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"reg_random\" size=\"40\" /></td><td%s><a onclick=\"generateRandomRegPassword()\">[%s]</a>&nbsp;<a onclick=\"copyRandomRegPassword()\">[%s]</a></td></tr>\n",
          cl, "Random password", cl, cl, "Generate", "Copy");
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"reg_sha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use SHA1", cl, cl);

  for (row = 0; user_flag_rows[row].field_id > 0; ++row) {
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"field_%d\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
            cl, user_flag_rows[row].field_desc, cl, user_flag_rows[row].field_id, cl);
  }

  fprintf(out_f, "<tr><td%s colspan=\"3\" align=\"center\"><b>%s</b></td></tr>\n",
          cl, "Contest registration");

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"changeCntsRegCreate(this)\" name=\"reg_cnts_create\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Create a contest registration", cl, cl);

  hbuf[0] = 0;
  if (contest_id > 0) {
    snprintf(hbuf, sizeof(hbuf), "%d", contest_id);
  }
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input id=\"cnts1\" onchange=\"updateCnts1()\" type=\"text\" name=\"other_contest_id_1\" size=\"20\" value=\"%s\"/></td><td%s>&nbsp;</td></tr>\n",
          cl, "Contest ID", cl, hbuf, cl);
  if (cnts_id_count > 0) {
    fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s>", cl, "Contest name", cl);
    fprintf(out_f, "<select id=\"cnts2\" onchange=\"updateCnts2()\" name=\"other_contest_id_2\"><option value=\"0\"></option>");
    for (i = 0; i < cnts_id_count; ++i) {
      other_contest_id_2 = cnts_id_list[i];
      if (other_contest_id_2 <= 0) continue;
      if (contests_get(other_contest_id_2, &cnts) < 0 || !cnts) continue;
      if (cnts->closed) continue;
      s = "";
      if (contest_id > 0 && cnts->id == contest_id) {
        s = " selected=\"selected\"";
      }
      fprintf(out_f, "<option value=\"%d\"%s>%s</option>", other_contest_id_2, s, ARMOR(cnts->name));
    }
    fprintf(out_f, "</select>");
    fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);
  }
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s>", cl, "Status", cl);
  ss_select(out_f, "cnts_status", (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, 1);
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Invisible?", cl, "is_invisible");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Banned?", cl, "is_banned");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Locked?", cl, "is_locked");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Incomplete?", cl, "is_incomplete");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Disqualified?", cl, "is_disqualified");

  fprintf(out_f, "<tr class=\"CntsRegRow\" id=\"CntsRegRowUseRegPasswd\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" onchange=\"updateCntsPasswdVisibility()\" name=\"%s\" /></td></tr>\n",
          cl, "Use reg. password?", cl, "cnts_use_reg_passwd");
  fprintf(out_f, "<tr class=\"CntsRegRow\" id=\"CntsRegRowSetToNull\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" onchange=\"updateCntsPasswdVisibility()\" name=\"%s\" /></td></tr>\n",
          cl, "Set to null?", cl, "cnts_null_passwd");
  fprintf(out_f, "<tr class=\"CntsRegRow\" id=\"CntsRegRowPasswd1\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"password\" name=\"cnts_password1\" size=\"40\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Contest password", cl, cl);
  fprintf(out_f, "<tr class=\"CntsRegRow\" id=\"CntsRegRowPasswd2\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"password\" name=\"cnts_password2\" size=\"40\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Confirm password", cl, cl);
  fprintf(out_f, "<tr class=\"CntsRegRow\" id=\"CntsRegRowPasswdRandom\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"cnts_random\" size=\"40\" /></td><td%s><a onclick=\"generateRandomCntsPassword()\">[%s]</a>&nbsp;<a onclick=\"copyRandomCntsPassword()\">[%s]</a>&nbsp;<a onclick=\"copyRegPassword()\">[%s]</a></td></tr>\n",
          cl, "Random password", cl, cl, "Generate", "Copy", "Copy reg. password");
  fprintf(out_f, "<tr class=\"CntsRegRow\" id=\"CntsRegRowPasswdSha1\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_sha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use SHA1", cl, cl);

  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" size=\"40\" name=\"cnts_name\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "User name", cl, cl);

  fprintf(out_f, "<tr><td%s colspan=\"3\" align=\"center\"><b>%s</b></td></tr>\n",
          cl, "Group membership");

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"changeGroupCreate(this)\" name=\"group_create\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Add user to a group", cl, cl);
  hbuf[0] = 0;
  if (group_id > 0) {
    snprintf(hbuf, sizeof(hbuf), "%d", group_id);
  }
  fprintf(out_f, "<tr class=\"GroupRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"other_group_id\" size=\"20\" value=\"%s\"/></td><td%s>&nbsp;</td></tr>\n",
          cl, "Group ID", cl, hbuf, cl);

  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"%s\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, cl, "Create a user", cl);
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_USER_CREATE_MANY_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, row, i;
  int contest_id = 0, group_id = 0, other_contest_id_2 = 0;
  const struct contest_desc *cnts = 0;
  unsigned char buf[1024], hbuf[1024];
  const unsigned char *cl = 0;
  const int *cnts_id_list = 0;
  int cnts_id_count = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s;
  opcap_t caps = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (group_id < 0) group_id = 0;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  cnts_id_count = contests_get_list(&cnts_id_list);
  if (cnts_id_count <= 0 || !cnts_id_list) {
    cnts_id_count = 0;
    cnts_id_list = 0;
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, create many new users",
           phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<script language=\"javascript\" src=\"%ssprintf.js\" ></script>\n",
          CONF_STYLE_PREFIX);
  fprintf(out_f, "<script language=\"javascript\">\n");
  fprintf(out_f,
          "function changeEmail(form_obj)\n"
          "{\n"
          "  if (form_obj.other_email.value != null && form_obj.other_email.value != \"\") {\n"
          "    document.getElementById(\"SendEmailRow\").style.display = \"\";\n"
          "    changeSendEmail(form_obj);\n"
          "  } else {\n"
          "    document.getElementById(\"SendEmailRow\").style.display = \"none\";\n"
          "    document.getElementById(\"ConfirmEmailRow\").style.display = \"none\";\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function changeSendEmail(form_obj)\n"
          "{\n"
          "  if (form_obj.send_email.checked) {\n"
          "    document.getElementById(\"ConfirmEmailRow\").style.display = \"\";\n"
          "  } else {\n"
          "    document.getElementById(\"ConfirmEmailRow\").style.display = \"none\";\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function randomChar()\n"
          "{\n"
          "  var str = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\";\n"
          "  var ind = Math.floor(Math.random() * str.length);\n"
          "  if (ind < 0 || ind >= str.length) ind = 0;\n"
          "  return str.charAt(ind);\n"
          "}\n"
          "function randomString(length)\n"
          "{\n"
          "  var res = \"\";\n"
          "  for (var i = 0; i < length; ++i) {\n"
          "    res += randomChar();\n"
          "  }\n"
          "  return res;\n"
          "}\n"
          "function generateRandomRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.reg_random.value = randomString(16);\n"
          "}\n"
          "function copyRandomRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.reg_password1.value = form_obj.reg_random.value;\n"
          "  form_obj.reg_password2.value = form_obj.reg_random.value;\n"
          "}\n"
          "function generateRandomCntsPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.cnts_random.value = randomString(16);\n"
          "}\n"
          "function copyRandomCntsPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.cnts_password1.value = form_obj.cnts_random.value;\n"
          "  form_obj.cnts_password2.value = form_obj.cnts_random.value;\n"
          "}\n"
          "function copyRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.cnts_random.value = form_obj.reg_random.value;\n"
          "  form_obj.cnts_password1.value = form_obj.reg_password1.value;\n"
          "  form_obj.cnts_password2.value = form_obj.reg_password2.value;\n"
          "  form_obj.cnts_sha1.checked = form_obj.reg_sha1.checked;\n"
          "}\n");
  fprintf(out_f,
          "function toggleRowsVisibility2(value, tid, rowclass1, rowclass2)\n"
          "{\n"
          "  var vis1 = \"\";\n"
          "  var vis2 = \"\";\n"
          "  if (value == true) {\n"
          "    vis1 = \"none\";\n"
          "  } else {\n"
          "    vis2 = \"none\";\n"
          "  }\n"
          "  var tobj = document.getElementById(tid);\n"
          "  if (tobj == null) {\n"
          "    return;\n"
          "  }\n"
          "  var trows = tobj.rows;\n"
          "  if (trows != null) {\n"
          "    for (var row in trows) {\n"
          "      if (trows[row].className == rowclass1) {\n"
          "        trows[row].style.display = vis1;\n"
          "      } else if (trows[row].className == rowclass2) {\n"
          "        trows[row].style.display = vis2;\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "}\n"
          "function changeCntsRegCreate(obj)\n"
          "{\n"
          "  toggleRowsVisibility2(obj.checked, \"CreateUserTable\", \"CntsRegRow0\", \"CntsRegRow\");\n"
          "  updateCntsPasswdVisibility();\n"
          "}\n"
          "function changeGroupCreate(obj)\n"
          "{\n"
          "  toggleRowsVisibility2(obj.checked, \"CreateUserTable\", \"GroupRow0\", \"GroupRow\");\n"
          "}\n"
          "");
  fprintf(out_f,
          "function updateCnts1()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj1.value;\n"
          "  var i;\n"
          "  for (i = 0; i < obj2.options.length; ++i) {\n"
          "    if (obj2.options[i].value == value) {\n"
          "      obj2.options.selectedIndex = i;\n"
          "      break;\n"
          "    }\n"
          "  }\n"
          "  updateCntsPasswdVisibility();\n"
          "}\n");
  fprintf(out_f,
          "function updateCnts2()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj2.options[obj2.selectedIndex].value;\n"
          "  obj1.value = value;\n"
          "  updateCntsPasswdVisibility();\n"
          "}\n");
  fprintf(out_f, "var cnts_passwd_enabled = { ");
  row = 0;
  for (i = 0; i < cnts_id_count; ++i) {
    other_contest_id_2 = cnts_id_list[i];
    if (other_contest_id_2 <= 0) continue;
    if (contests_get(other_contest_id_2, &cnts) < 0 || !cnts) continue;
    if (!cnts->disable_team_password) {
      if (row) fprintf(out_f, ", ");
      ++row;
      fprintf(out_f, "%d : true", other_contest_id_2);
    }
  }
  fprintf(out_f, "};\n");
  // CntsRegRowUseRegPasswd   cnts_use_reg_passwd
  // CntsRegRowSetToNull      cnts_null_passwd
  // CntsRegRowUseRandom      cnts_random_passwd
  // CntsRegRowPasswdTemplate cnts_password_template
  // CntsRegRowPasswdSha1     cnts_sha1
  fprintf(out_f,
          "function updateCntsPasswdVisibility()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  if (!form_obj.reg_cnts_create.checked || !cnts_passwd_enabled[form_obj.other_contest_id_1.value]) {\n"
          "    form_obj.cnts_use_reg_passwd.checked = false;\n"
          "    form_obj.cnts_null_passwd.checked = false;\n"
          "    form_obj.cnts_random_passwd.checked = false;\n"
          "    form_obj.cnts_password_template.value = \"\";\n"
          "    form_obj.cnts_sha1.checked = false;\n"
          "    document.getElementById(\"CntsRegRowUseRegPasswd\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowSetToNull\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowUseRandom\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowPasswdTemplate\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "  } else {\n"
          "    document.getElementById(\"CntsRegRowUseRegPasswd\").style.display = \"\";\n"
          "    if (form_obj.cnts_use_reg_passwd.checked) {\n"
          "      form_obj.cnts_null_passwd.checked = false;\n"
          "      form_obj.cnts_random_passwd.checked = false;\n"
          "      form_obj.cnts_password_template.value = \"\";\n"
          "      form_obj.cnts_sha1.checked = false;\n"
          "      document.getElementById(\"CntsRegRowSetToNull\").style.display = \"none\";\n"
          "      document.getElementById(\"CntsRegRowUseRandom\").style.display = \"none\";\n"
          "      document.getElementById(\"CntsRegRowPasswdTemplate\").style.display = \"none\";\n"
          "      document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "    } else {\n"
          "      document.getElementById(\"CntsRegRowSetToNull\").style.display = \"\";\n"
          "      if (form_obj.cnts_null_passwd.checked) {\n"
          "        form_obj.cnts_random_passwd.checked = false;\n"
          "        form_obj.cnts_password_template.value = \"\";\n"
          "        form_obj.cnts_sha1.checked = false;\n"
          "        document.getElementById(\"CntsRegRowUseRandom\").style.display = \"none\";\n"
          "        document.getElementById(\"CntsRegRowPasswdTemplate\").style.display = \"none\";\n"
          "        document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "      } else {\n"
          "        document.getElementById(\"CntsRegRowUseRandom\").style.display = \"\";\n"
          "        if (form_obj.cnts_random_passwd.checked) {\n"
          "          form_obj.cnts_password_template.value = \"\";\n"
          "          form_obj.cnts_sha1.checked = false;\n"
          "          document.getElementById(\"CntsRegRowPasswdTemplate\").style.display = \"none\";\n"
          "          document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "        } else {\n"
          "          document.getElementById(\"CntsRegRowPasswdTemplate\").style.display = \"\";\n"
          "          document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"\";\n"
          "        }\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function formatLogins()\n"
          "{\n"
          "  var form_obj = document.getElementById(\"CreateForm\");\n"
          "  var div_obj = document.getElementById(\"LoginsCreated\");\n"
          "  if (div_obj.childNodes.length == 1) {\n"
          "    div_obj.removeChild(div_obj.childNodes[0]);\n"
          "  }\n"
          "  var str = \"\";\n"
          "  var first = parseInt(form_obj.first_serial.value);\n"
          "  var last = parseInt(form_obj.last_serial.value);\n"
          "  var format = form_obj.login_template.value;\n"
          "  if (first != null && first != NaN && last != null && last != NaN && first >= 0 && last >= 0 && first <= last && last - first + 1 <= 10000 && format != null && format.length > 0) {\n"
          "    if (last - first + 1 <= 5) {\n"
          "      for (var i = first; i <= last; ++i) {\n"
          "        str += \" \" + sprintf(format, i);\n"
          "      }\n"
          "    } else {\n"
          "      str += sprintf(format, first);\n"
          "      str += \" \" + sprintf(format, first + 1);\n"
          "      str += \" \" + sprintf(format, first + 2);\n"
          "      str += \" ...\";\n"
          "      str += \" \" + sprintf(format, last - 1);\n"
          "      str += \" \" + sprintf(format, last);\n"
          "    }\n"
          "  }\n"
          "  var node = document.createTextNode(str);\n"
          "  div_obj.appendChild(node);\n"
          "}\n"
          "");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, 0, NULL);

  html_start_form_id(out_f, 1, phr->self_url, "CreateForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "op", "%d", SSERV_CMD_USER_CREATE_MANY_ACTION);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s id=\"CreateUserTable\">\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"text\" size=\"40\" name=\"first_serial\" onchange=\"formatLogins()\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "First serial number", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"text\" size=\"40\" name=\"last_serial\" onchange=\"formatLogins()\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Last serial number", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"text\" size=\"40\" name=\"login_template\" onchange=\"formatLogins()\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Login template", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s colspan=\"2\"><div id=\"LoginsCreated\" style=\"display: inline;\"></div></td></tr>\n",
          cl, "Logins to be created", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"changeRandomRegPassword()\" name=\"reg_random\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use random password", cl, cl);
  fprintf(out_f, "<tr id=\"RegPasswordTemplateRow\"><td%s><b>%s:</b></td><td%s><input type=\"text\" size=\"40\" name=\"reg_password_template\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Password template", cl, cl);
  fprintf(out_f, "<tr id=\"RegPasswordSha1Row\"><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"reg_sha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use SHA1", cl, cl);

  for (row = 0; user_flag_rows[row].field_id > 0; ++row) {
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"field_%d\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
            cl, user_flag_rows[row].field_desc, cl, user_flag_rows[row].field_id, cl);
  }

  fprintf(out_f, "<tr><td%s colspan=\"3\" align=\"center\"><b>%s</b></td></tr>\n",
          cl, "Contest registration");

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"changeCntsRegCreate(this)\" name=\"reg_cnts_create\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Create a contest registration", cl, cl);

  hbuf[0] = 0;
  if (contest_id > 0) {
    snprintf(hbuf, sizeof(hbuf), "%d", contest_id);
  }
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input id=\"cnts1\" onchange=\"updateCnts1()\" type=\"text\" name=\"other_contest_id_1\" size=\"20\" value=\"%s\"/></td><td%s>&nbsp;</td></tr>\n",
          cl, "Contest ID", cl, hbuf, cl);
  if (cnts_id_count > 0) {
    fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s>", cl, "Contest name", cl);
    fprintf(out_f, "<select id=\"cnts2\" onchange=\"updateCnts2()\" name=\"other_contest_id_2\"><option value=\"0\"></option>");
    for (i = 0; i < cnts_id_count; ++i) {
      other_contest_id_2 = cnts_id_list[i];
      if (other_contest_id_2 <= 0) continue;
      if (contests_get(other_contest_id_2, &cnts) < 0 || !cnts) continue;
      if (cnts->closed) continue;
      s = "";
      if (contest_id > 0 && cnts->id == contest_id) {
        s = " selected=\"selected\"";
      }
      fprintf(out_f, "<option value=\"%d\"%s>%s</option>", other_contest_id_2, s, ARMOR(cnts->name));
    }
    fprintf(out_f, "</select>");
    fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);
  }
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s>", cl, "Status", cl);
  ss_select(out_f, "cnts_status", (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, 1);
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Invisible?", cl, "is_invisible");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Banned?", cl, "is_banned");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Locked?", cl, "is_locked");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Incomplete?", cl, "is_incomplete");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Disqualified?", cl, "is_disqualified");

  fprintf(out_f, "<tr id=\"CntsRegRowUseRegPasswd\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_use_reg_passwd\" onchange=\"updateCntsPasswdVisibility()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use registration password", cl, cl);
  fprintf(out_f, "<tr id=\"CntsRegRowSetToNull\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_null_passwd\" onchange=\"updateCntsPasswdVisibility()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Set to null", cl, cl);
  fprintf(out_f, "<tr id=\"CntsRegRowUseRandom\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_random_passwd\" onchange=\"updateCntsPasswdVisibility()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Random contest password", cl, cl);
  fprintf(out_f, "<tr id=\"CntsRegRowPasswdTemplate\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"cnts_password_template\" size=\"40\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Contest password template", cl, cl);
  fprintf(out_f, "<tr id=\"CntsRegRowPasswdSha1\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_sha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use SHA1", cl, cl);

  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" size=\"40\" name=\"cnts_name_template\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "User name template", cl, cl);

  fprintf(out_f, "<tr><td%s colspan=\"3\" align=\"center\"><b>%s</b></td></tr>\n",
          cl, "Group membership");

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"changeGroupCreate(this)\" name=\"group_create\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Add user to a group", cl, cl);
  hbuf[0] = 0;
  if (group_id > 0) {
    snprintf(hbuf, sizeof(hbuf), "%d", group_id);
  }
  fprintf(out_f, "<tr class=\"GroupRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"other_group_id\" size=\"20\" value=\"%s\"/></td><td%s>&nbsp;</td></tr>\n",
          cl, "Group ID", cl, hbuf, cl);

  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"%s\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, cl, "Create many users", cl);
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_USER_CREATE_FROM_CSV_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, row, i;
  int contest_id = 0, group_id = 0, other_contest_id_2 = 0;
  const struct contest_desc *cnts = 0;
  unsigned char buf[1024], hbuf[1024];
  const unsigned char *cl = 0;
  const int *cnts_id_list = 0;
  int cnts_id_count = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s;
  opcap_t caps = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (group_id < 0) group_id = 0;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  cnts_id_count = contests_get_list(&cnts_id_list);
  if (cnts_id_count <= 0 || !cnts_id_list) {
    cnts_id_count = 0;
    cnts_id_list = 0;
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, create users from a CSV file",
           phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<script language=\"javascript\">\n");
  fprintf(out_f,
          "function changeEmail(form_obj)\n"
          "{\n"
          "  if (form_obj.other_email.value != null && form_obj.other_email.value != \"\") {\n"
          "    document.getElementById(\"SendEmailRow\").style.display = \"\";\n"
          "    changeSendEmail(form_obj);\n"
          "  } else {\n"
          "    document.getElementById(\"SendEmailRow\").style.display = \"none\";\n"
          "    document.getElementById(\"ConfirmEmailRow\").style.display = \"none\";\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function changeSendEmail(form_obj)\n"
          "{\n"
          "  if (form_obj.send_email.checked) {\n"
          "    document.getElementById(\"ConfirmEmailRow\").style.display = \"\";\n"
          "  } else {\n"
          "    document.getElementById(\"ConfirmEmailRow\").style.display = \"none\";\n"
          "  }\n"
          "}\n");
  fprintf(out_f,
          "function randomChar()\n"
          "{\n"
          "  var str = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\";\n"
          "  var ind = Math.floor(Math.random() * str.length);\n"
          "  if (ind < 0 || ind >= str.length) ind = 0;\n"
          "  return str.charAt(ind);\n"
          "}\n"
          "function randomString(length)\n"
          "{\n"
          "  var res = \"\";\n"
          "  for (var i = 0; i < length; ++i) {\n"
          "    res += randomChar();\n"
          "  }\n"
          "  return res;\n"
          "}\n"
          "function generateRandomRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.reg_random.value = randomString(16);\n"
          "}\n"
          "function copyRandomRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.reg_password1.value = form_obj.reg_random.value;\n"
          "  form_obj.reg_password2.value = form_obj.reg_random.value;\n"
          "}\n"
          "function generateRandomCntsPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.cnts_random.value = randomString(16);\n"
          "}\n"
          "function copyRandomCntsPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.cnts_password1.value = form_obj.cnts_random.value;\n"
          "  form_obj.cnts_password2.value = form_obj.cnts_random.value;\n"
          "}\n"
          "function copyRegPassword()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  form_obj.cnts_random.value = form_obj.reg_random.value;\n"
          "  form_obj.cnts_password1.value = form_obj.reg_password1.value;\n"
          "  form_obj.cnts_password2.value = form_obj.reg_password2.value;\n"
          "  form_obj.cnts_sha1.checked = form_obj.reg_sha1.checked;\n"
          "}\n");
  fprintf(out_f,
          "function toggleRowsVisibility2(value, tid, rowclass1, rowclass2)\n"
          "{\n"
          "  var vis1 = \"\";\n"
          "  var vis2 = \"\";\n"
          "  if (value == true) {\n"
          "    vis1 = \"none\";\n"
          "  } else {\n"
          "    vis2 = \"none\";\n"
          "  }\n"
          "  var tobj = document.getElementById(tid);\n"
          "  if (tobj == null) {\n"
          "    return;\n"
          "  }\n"
          "  var trows = tobj.rows;\n"
          "  if (trows != null) {\n"
          "    for (var row in trows) {\n"
          "      if (trows[row].className == rowclass1) {\n"
          "        trows[row].style.display = vis1;\n"
          "      } else if (trows[row].className == rowclass2) {\n"
          "        trows[row].style.display = vis2;\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "}\n"
          "function changeCntsRegCreate(obj)\n"
          "{\n"
          "  toggleRowsVisibility2(obj.checked, \"CreateUserTable\", \"CntsRegRow0\", \"CntsRegRow\");\n"
          "  updateCntsPasswdVisibility();\n"
          "}\n"
          "function changeGroupCreate(obj)\n"
          "{\n"
          "  toggleRowsVisibility2(obj.checked, \"CreateUserTable\", \"GroupRow0\", \"GroupRow\");\n"
          "}\n"
          "");
  fprintf(out_f,
          "function updateCnts1()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj1.value;\n"
          "  var i;\n"
          "  for (i = 0; i < obj2.options.length; ++i) {\n"
          "    if (obj2.options[i].value == value) {\n"
          "      obj2.options.selectedIndex = i;\n"
          "      break;\n"
          "    }\n"
          "  }\n"
          "  updateCntsPasswdVisibility();\n"
          "}\n");
  fprintf(out_f,
          "function updateCnts2()\n"
          "{\n"
          "  var obj1 = document.getElementById(\"cnts1\");\n"
          "  var obj2 = document.getElementById(\"cnts2\");\n"
          "  var value = obj2.options[obj2.selectedIndex].value;\n"
          "  obj1.value = value;\n"
          "  updateCntsPasswdVisibility();\n"
          "}\n");
  fprintf(out_f, "var cnts_passwd_enabled = { ");
  row = 0;
  for (i = 0; i < cnts_id_count; ++i) {
    other_contest_id_2 = cnts_id_list[i];
    if (other_contest_id_2 <= 0) continue;
    if (contests_get(other_contest_id_2, &cnts) < 0 || !cnts) continue;
    if (!cnts->disable_team_password) {
      if (row) fprintf(out_f, ", ");
      ++row;
      fprintf(out_f, "%d : true", other_contest_id_2);
    }
  }
  fprintf(out_f, "};\n");
  // CntsRegRowUseRegPasswd   cnts_use_reg_passwd
  // CntsRegRowSetToNull      cnts_null_passwd
  // CntsRegRowUseRandom      cnts_random_passwd
  // CntsRegRowPasswdSha1     cnts_sha1
  fprintf(out_f,
          "function updateCntsPasswdVisibility()\n"
          "{\n"
          "  form_obj = document.getElementById(\"CreateForm\");\n"
          "  if (!form_obj.reg_cnts_create.checked || !cnts_passwd_enabled[form_obj.other_contest_id_1.value]) {\n"
          "    form_obj.cnts_use_reg_passwd.checked = false;\n"
          "    form_obj.cnts_null_passwd.checked = false;\n"
          "    form_obj.cnts_random_passwd.checked = false;\n"
          "    form_obj.cnts_sha1.checked = false;\n"
          "    document.getElementById(\"CntsRegRowUseRegPasswd\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowSetToNull\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowUseRandom\").style.display = \"none\";\n"
          "    document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "  } else {\n"
          "    document.getElementById(\"CntsRegRowUseRegPasswd\").style.display = \"\";\n"
          "    if (form_obj.cnts_use_reg_passwd.checked) {\n"
          "      form_obj.cnts_null_passwd.checked = false;\n"
          "      form_obj.cnts_random_passwd.checked = false;\n"
          "      form_obj.cnts_sha1.checked = false;\n"
          "      document.getElementById(\"CntsRegRowSetToNull\").style.display = \"none\";\n"
          "      document.getElementById(\"CntsRegRowUseRandom\").style.display = \"none\";\n"
          "      document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "    } else {\n"
          "      document.getElementById(\"CntsRegRowSetToNull\").style.display = \"\";\n"
          "      if (form_obj.cnts_null_passwd.checked) {\n"
          "        form_obj.cnts_random_passwd.checked = false;\n"
          "        form_obj.cnts_sha1.checked = false;\n"
          "        document.getElementById(\"CntsRegRowUseRandom\").style.display = \"none\";\n"
          "        document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "      } else {\n"
          "        document.getElementById(\"CntsRegRowUseRandom\").style.display = \"\";\n"
          "        if (form_obj.cnts_random_passwd.checked) {\n"
          "          form_obj.cnts_password_template.value = \"\";\n"
          "          form_obj.cnts_sha1.checked = false;\n"
          "          document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"none\";\n"
          "        } else {\n"
          "          document.getElementById(\"CntsRegRowPasswdSha1\").style.display = \"\";\n"
          "        }\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "}\n");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, 0, NULL);

  html_start_form_id(out_f, 2, phr->self_url, "CreateForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "op", "%d", SSERV_CMD_USER_CREATE_FROM_CSV_ACTION);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s id=\"CreateUserTable\">\n", cl);
  fprintf(out_f, "<tr id=\"SendEmailRow\"><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"changeSendEmail(this.form)\" name=\"send_email\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Send registration e-mail", cl, cl);
  fprintf(out_f, "<tr id=\"ConfirmEmailRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"confirm_email\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Confirm e-mail by user", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"reg_random\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use random password", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"reg_sha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use SHA1", cl, cl);

  for (row = 0; user_flag_rows[row].field_id > 0; ++row) {
    fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"field_%d\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
            cl, user_flag_rows[row].field_desc, cl, user_flag_rows[row].field_id, cl);
  }

  fprintf(out_f, "<tr><td%s colspan=\"3\" align=\"center\"><b>%s</b></td></tr>\n",
          cl, "Contest registration");

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"changeCntsRegCreate(this)\" name=\"reg_cnts_create\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Create a contest registration", cl, cl);

  hbuf[0] = 0;
  if (contest_id > 0) {
    snprintf(hbuf, sizeof(hbuf), "%d", contest_id);
  }
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input id=\"cnts1\" onchange=\"updateCnts1()\" type=\"text\" name=\"other_contest_id_1\" size=\"20\" value=\"%s\"/></td><td%s>&nbsp;</td></tr>\n",
          cl, "Contest ID", cl, hbuf, cl);
  if (cnts_id_count > 0) {
    fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s>", cl, "Contest name", cl);
    fprintf(out_f, "<select id=\"cnts2\" onchange=\"updateCnts2()\" name=\"other_contest_id_2\"><option value=\"0\"></option>");
    for (i = 0; i < cnts_id_count; ++i) {
      other_contest_id_2 = cnts_id_list[i];
      if (other_contest_id_2 <= 0) continue;
      if (contests_get(other_contest_id_2, &cnts) < 0 || !cnts) continue;
      if (cnts->closed) continue;
      s = "";
      if (contest_id > 0 && cnts->id == contest_id) {
        s = " selected=\"selected\"";
      }
      fprintf(out_f, "<option value=\"%d\"%s>%s</option>", other_contest_id_2, s, ARMOR(cnts->name));
    }
    fprintf(out_f, "</select>");
    fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);
  }
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s>", cl, "Status", cl);
  ss_select(out_f, "cnts_status", (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, 1);
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Invisible?", cl, "is_invisible");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Banned?", cl, "is_banned");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Locked?", cl, "is_locked");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Incomplete?", cl, "is_incomplete");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s</td></td><td%s><input type=\"checkbox\" value=\"1\" name=\"%s\" /></td></tr>\n",
          cl, "Disqualified?", cl, "is_disqualified");

  fprintf(out_f, "<tr id=\"CntsRegRowUseRegPasswd\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_use_reg_passwd\" onchange=\"updateCntsPasswdVisibility()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use registration password", cl, cl);
  fprintf(out_f, "<tr id=\"CntsRegRowSetToNull\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_null_passwd\" onchange=\"updateCntsPasswdVisibility()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Set to null", cl, cl);
  fprintf(out_f, "<tr id=\"CntsRegRowUseRandom\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_random_passwd\" onchange=\"updateCntsPasswdVisibility()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Random contest password", cl, cl);
  fprintf(out_f, "<tr id=\"CntsRegRowPasswdSha1\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_sha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use SHA1", cl, cl);

  fprintf(out_f, "<tr><td%s colspan=\"3\" align=\"center\"><b>%s</b></td></tr>\n",
          cl, "Group membership");

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" onchange=\"changeGroupCreate(this)\" name=\"group_create\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Add user to a group", cl, cl);
  hbuf[0] = 0;
  if (group_id > 0) {
    snprintf(hbuf, sizeof(hbuf), "%d", group_id);
  }
  fprintf(out_f, "<tr class=\"GroupRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"other_group_id\" size=\"20\" value=\"%s\"/></td><td%s>&nbsp;</td></tr>\n",
          cl, "Group ID", cl, hbuf, cl);

  fprintf(out_f, "<tr><td%s colspan=\"3\" align=\"center\"><b>%s</b></td></tr>\n",
          cl, "File");

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"register_existing\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Register existing users", cl, cl);

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"separator\" size=\"20\" value=\";\"/></td><td%s>&nbsp;</td></tr>\n",
          cl, "Field separator", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>", cl, "Charset", cl);
  charset_html_select(out_f, NULL, NULL);
  fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"file\" name=\"csv_file\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "CSV File", cl, cl);

  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"%s\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, cl, "Create users", cl);
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  return retval;
}

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
  unsigned char *reg_password1 = 0;
  unsigned char *reg_password2 = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  hr_cgi_param_int_opt(phr, "next_op", &next_op, 0);
  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }

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
  if (get_global_caps(phr, &caps) < 0) FAIL(SSERV_ERR_PERM_DENIED);
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
  if (is_globally_privileged(phr, u) && opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);
  else if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  r = ULS_PRIV_SET_REG_PASSWD_PLAIN;
  if (usesha1) r = ULS_PRIV_SET_REG_PASSWD_SHA1;

  r = userlist_clnt_set_passwd(phr->userlist_clnt, r, other_user_id, 0, "", reg_password1);
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
  const unsigned char *s = 0;
  opcap_t gcaps = 0, ccaps = 0, fcaps = 0;
  struct userlist_user *u = 0;
  unsigned char *xml_text = 0;

  if (hr_cgi_param_int(phr, "contest_id", &contest_id) <= 0) FAIL(SSERV_ERR_INV_CONTEST);
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
  get_global_caps(phr, &gcaps);
  get_contest_caps(phr, cnts, &ccaps);
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

  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
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

    r = userlist_clnt_set_passwd(phr->userlist_clnt, r, other_user_id, 0, "", cnts_password1);
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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }
  if (cnts) {
    if (get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_REG) < 0) {
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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }
  if (cnts) {
    if (get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_REG) < 0) {
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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }
  if (cnts) {
    if (get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_REG) < 0) {
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
  int login_idx = -1, email_idx = -1, reg_password_idx = -1, cnts_password_idx = -1, cnts_name_idx = -1;
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
    up.contest_id = params.other_contest_id_1;
    up.cnts_status = params.cnts_status;
    up.cnts_is_invisible_flag = params.is_invisible;
    up.cnts_is_banned_flag = params.is_banned;
    up.cnts_is_locked_flag = params.is_locked;
    up.cnts_is_incomplete_flag = params.is_incomplete;
    up.cnts_is_disqualified_flag = params.is_disqualified;
    up.cnts_use_reg_passwd_flag = params.cnts_use_reg_passwd;
    up.cnts_set_null_passwd_flag = params.cnts_null_passwd;
    up.cnts_random_password_flag = params.cnts_random_passwd;
    up.cnts_use_sha1_flag = params.cnts_sha1;
    up.group_id = params.other_group_id;
    up.register_existing_flag = params.register_existing;
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
  get_global_caps(phr, &gcaps);
  if (cnts) {
    get_contest_caps(phr, cnts, &caps);
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
    if (is_globally_privileged(phr, u)
        || (cnts && is_contest_privileged(cnts, u))
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
    if (is_globally_privileged(phr, u)) {
      if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0)
        FAIL(SSERV_ERR_PERM_DENIED);
    } else if (is_contest_privileged(cnts, u)) {
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
          if (is_globally_privileged(phr, u)) {
            if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0)
              FAIL(SSERV_ERR_PERM_DENIED);
          } else if (is_contest_privileged(cnts, u)) {
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
  get_global_caps(phr, &gcaps);
  get_contest_caps(phr, cnts, &caps);
  caps = (caps | gcaps) & ((1L << OPCAP_EDIT_USER) | (1L << OPCAP_PRIV_EDIT_USER));
  if (!caps) FAIL(SSERV_ERR_PERM_DENIED);

  if (userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, contest_id, &xml_text) < 0) {
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (!(u = userlist_parse_user_str(xml_text))) FAIL(SSERV_ERR_DB_ERROR);
  --role;
  if (role < 0 || role >= USERLIST_MB_LAST) FAIL(SSERV_ERR_INV_VALUE);

  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
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
super_serve_op_USER_DELETE_MEMBER_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int other_user_id = 0, contest_id = 0, group_id = 0, serial = 0;
  const struct contest_desc *cnts = 0;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
  opcap_t gcaps = 0, caps = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  struct userlist_member *m = 0;
  int role = 0, num = 0;
  unsigned char buf[1024];
  unsigned char hbuf[1024];

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0 || other_user_id <= 0) {
    FAIL(SSERV_ERR_INV_USER_ID);
  }
  if (hr_cgi_param_int(phr, "serial", &serial) < 0 || serial <= 0) {
    FAIL(SSERV_ERR_INV_SERIAL);
  }
  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0 || contest_id <= 0) {
    FAIL(SSERV_ERR_INV_CONTEST);
  }
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) {
      FAIL(SSERV_ERR_INV_CONTEST);
    }
  }
  contest_id_str[0] = 0;
  if (contest_id > 0) {
    snprintf(contest_id_str, sizeof(contest_id_str), "&amp;contest_id=%d", contest_id);
  }
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  if (group_id < 0) group_id = 0;
  group_id_str[0] = 0;
  if (group_id > 0) {
    snprintf(group_id_str, sizeof(group_id_str), "&amp;group_id=%d", group_id);
  }

  if (phr->priv_level <= 0) FAIL(SSERV_ERR_PERM_DENIED);
  get_global_caps(phr, &gcaps);
  get_contest_caps(phr, cnts, &caps);
  caps = (caps | gcaps) & ((1L << OPCAP_EDIT_USER) | (1L << OPCAP_PRIV_EDIT_USER));
  if (!caps) FAIL(SSERV_ERR_PERM_DENIED);

  if (userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, contest_id, &xml_text) < 0) {
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (!(u = userlist_parse_user_str(xml_text))) FAIL(SSERV_ERR_DB_ERROR);

  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
    if (opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else {
    if (opcaps_check(caps, OPCAP_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  }

  m = 0;
  if (u->cnts0 && u->cnts0->members) {
    m = userlist_get_member_nc(u->cnts0->members, serial, &role, &num);
  }
  if (!m) FAIL(SSERV_ERR_INV_SERIAL);
  if (role < 0 || role >= USERLIST_MB_LAST || num < 0) FAIL(SSERV_ERR_INV_SERIAL);

  snprintf(buf, sizeof(buf), "serve-control: %s, delete the member '%s'::%d (%d) of user %d, contest %d",
           phr->html_name, member_string[role], num + 1, serial,
           other_user_id, contest_id);
  ss_write_html_header(out_f, phr, buf);
  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, other_user_id, NULL);

  print_user_info(log_f, out_f, phr, cnts, u, u->cnts0, m, role, num);

  fprintf(out_f, "<p>%s[%s]</a>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_DETAIL_PAGE,
                        other_user_id, contest_id_str, group_id_str),
          "Cancel");

  fprintf(out_f, "&nbsp;%s[%s]</a></p>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;serial=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_DELETE_MEMBER_ACTION,
                        other_user_id, m->serial, contest_id_str, group_id_str),
          "Delete");

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
  get_global_caps(phr, &gcaps);
  get_contest_caps(phr, cnts, &caps);
  caps = (caps | gcaps) & ((1L << OPCAP_EDIT_USER) | (1L << OPCAP_PRIV_EDIT_USER));
  if (!caps) FAIL(SSERV_ERR_PERM_DENIED);

  if (userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, contest_id, &xml_text) < 0) {
    FAIL(SSERV_ERR_DB_ERROR);
  }
  if (!(u = userlist_parse_user_str(xml_text))) FAIL(SSERV_ERR_DB_ERROR);

  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
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
  get_global_caps(phr, &gcaps);
  if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_CREATE_REG;
  if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_CREATE_REG;
  get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (opcaps_check(caps, OPCAP_CREATE_REG) < 0 && opcaps_check(caps, OPCAP_PRIV_CREATE_REG) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (!(u = get_user_info(phr, params.other_user_id, cnts->id))) FAIL(SSERV_ERR_DB_ERROR);
  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_CREATE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
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
  get_global_caps(phr, &gcaps);
  if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_EDIT_REG;
  if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_EDIT_REG;
  get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (opcaps_check(caps, OPCAP_CREATE_REG) < 0 && opcaps_check(caps, OPCAP_PRIV_CREATE_REG) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (!(u = get_user_info(phr, params.other_user_id, cnts->id))) FAIL(SSERV_ERR_DB_ERROR);
  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
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
  get_global_caps(phr, &gcaps);
  if (opcaps_check(gcaps, OPCAP_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_DELETE_REG;
  if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) >= 0) gcaps |= 1LL << OPCAP_PRIV_DELETE_REG;
  get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (opcaps_check(caps, OPCAP_PRIV_DELETE_REG) < 0 && opcaps_check(caps, OPCAP_DELETE_REG) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (!(u = get_user_info(phr, other_user_id, cnts->id))) FAIL(SSERV_ERR_DB_ERROR);
  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_DELETE_REG) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
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
  get_global_caps(phr, &gcaps);
  get_contest_caps(phr, cnts, &caps);
  caps |= gcaps;
  if (opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0 && opcaps_check(caps, OPCAP_EDIT_USER) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (!(u = get_user_info(phr, other_user_id, cnts->id))) FAIL(SSERV_ERR_DB_ERROR);
  if (is_globally_privileged(phr, u)) {
    if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  } else if (is_contest_privileged(cnts, u)) {
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
super_serve_op_USER_SEL_VIEW_PASSWD_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r = 0;
  int contest_id = 0, group_id = 0;
  unsigned char *marked_str = 0;
  bitset_t marked = BITSET_INITIALIZER;
  const struct contest_desc *cnts = 0;
  opcap_t gcaps = 0, caps = 0;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  unsigned char buf[1024];
  const unsigned char *s = 0;
  const unsigned char *cl = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int user_id = 0, serial;
  const struct userlist_user *u = 0;
  const struct userlist_contest *reg = 0;
  const struct userlist_user_info *ui = 0;
  int allowed, passwd_method;
  const unsigned char *passwd;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  marked_str = collect_marked_set(phr, &marked);

  if (contest_id < 0) contest_id = 0;
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (group_id < 0) group_id = 0;

  /* check permissions */
  switch (phr->action) {
  case SSERV_CMD_USER_SEL_VIEW_PASSWD_PAGE:
    get_global_caps(phr, &gcaps);
    if (cnts) get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    break;
  case SSERV_CMD_USER_SEL_VIEW_CNTS_PASSWD_PAGE:
    if (!cnts) FAIL(SSERV_ERR_INV_CONTEST);
    if (cnts->disable_team_password) FAIL(SSERV_ERR_INV_CONTEST);
    get_global_caps(phr, &gcaps);
    get_contest_caps(phr, cnts, &caps);
    caps |= gcaps;
    break;
  default:
    abort();
  }
  if (opcaps_check(caps, OPCAP_GET_USER) < 0) FAIL(SSERV_ERR_PERM_DENIED);
  if (opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0 && opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0) FAIL(SSERV_ERR_PERM_DENIED);

  if (!phr->userlist_clnt) FAIL(SSERV_ERR_DB_ERROR);
  r = userlist_clnt_list_users_2(phr->userlist_clnt, ULS_LIST_ALL_USERS_4,
                                 contest_id, group_id, marked_str, 0, 0,
                                 // FIXME: fill the fields
                                 -1 /* page */, -1 /* sort_field */, 0 /* sort_order */,
                                 -1 /* filter_field */, 0 /* filter_op */,
                                 &xml_text);

  if (r < 0) FAIL(SSERV_ERR_DB_ERROR);
  users = userlist_parse_str(xml_text);
  if (!users) FAIL(SSERV_ERR_DB_ERROR);

  switch (phr->action) {
  case SSERV_CMD_USER_SEL_VIEW_PASSWD_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, view registration passwords", phr->html_name);
    break;
  case SSERV_CMD_USER_SEL_VIEW_CNTS_PASSWD_PAGE:
    snprintf(buf, sizeof(buf), "serve-control: %s, view contest passwords in contest %d", phr->html_name, contest_id);
    break;
  default:
    abort();
  }

  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);
  if (cnts && cnts->name) {
    fprintf(out_f, "<h2>Contest %d: %s</h2>\n", cnts->id, ARMOR(cnts->name));
  } else {
    fprintf(out_f, "<br/>\n");
  }

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, 0, marked_str);

  cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>", cl);
  fprintf(out_f, "<tr>");
  fprintf(out_f, "<th%s>%s</th><th%s>%s</th><th%s>%s</th>",
          cl, "NN", cl, "User ID", cl, "Login");
  s = "Registration password";
  if (phr->action == SSERV_CMD_USER_SEL_VIEW_CNTS_PASSWD_PAGE) s = "Contest password";
  fprintf(out_f, "<th%s>%s</th>", cl, s);
  if (cnts) {
    fprintf(out_f, "<th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th>",
            cl, "Name", cl, "Status", cl, "Flags", cl, "Location", cl, "Printer name");
  }
  fprintf(out_f, "</tr>\n");
  for (user_id = 1, serial = 0; user_id < marked.size; ++user_id) {
    if (!bitset_get(&marked, user_id)) continue;
    if (user_id >= users->user_map_size) continue;
    if (!(u = users->user_map[user_id])) continue;
    ui = u->cnts0;
    reg = 0;
    if (cnts) {
      reg = userlist_get_user_contest(u, contest_id);
      if (!reg) continue;
    }
    fprintf(out_f, "<tr><td%s>%d</td>", cl, ++serial);
    fprintf(out_f, "<td%s>%d</td>", cl, user_id);
    fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(u->login));
    fprintf(out_f, "<td%s>", cl);
    allowed = 0;
    passwd_method = -1;
    passwd = 0;
    switch (phr->action) {
    case SSERV_CMD_USER_SEL_VIEW_PASSWD_PAGE:
      if (is_globally_privileged(phr, u)) {
        if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) >= 0) allowed = 1;
      } else if (cnts && is_contest_privileged(cnts, u)) {
        if (opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) >= 0) allowed = 1;
      } else {
        if (opcaps_check(caps, OPCAP_EDIT_PASSWD) >= 0) allowed = 1;
      }
      if (allowed) {
        passwd_method = u->passwd_method;
        passwd = u->passwd;
      }
      break;
    case SSERV_CMD_USER_SEL_VIEW_CNTS_PASSWD_PAGE:
      if (is_globally_privileged(phr, u)) {
        if (opcaps_check(gcaps, OPCAP_PRIV_EDIT_PASSWD) >= 0) allowed = 1;
      } else if (is_contest_privileged(cnts, u)) {
        if (opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) >= 0) allowed = 1;
      } else {
        if (opcaps_check(caps, OPCAP_EDIT_PASSWD) >= 0) allowed = 1;
      }
      if (allowed && ui) {
        passwd_method = ui->team_passwd_method;
        passwd = ui->team_passwd;
      }
      break;
    default:
      break;
    }
    if (!allowed) {
      fprintf(out_f, "<i>hidden</i>");
    } else if (passwd_method < 0 || !passwd) {
      fprintf(out_f, "<i>null</i>");
    } else if (passwd_method == USERLIST_PWD_SHA1) {
      fprintf(out_f, "<i>changed</i>");
    } else if (passwd_method == USERLIST_PWD_PLAIN) {
      fprintf(out_f, "<tt>%s</tt>", ARMOR(passwd));
    } else {
      fprintf(out_f, "<i>unknown</i>");
    }
    fprintf(out_f, "</td>");
    if (cnts) {
      s = u->login;
      if (ui && ui->name && *ui->name) s = ui->name;
      fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(s));
      if (cnts && reg) {
        r = reg->status;
        if (r < 0 || r >= USERLIST_REG_LAST) r = USERLIST_REG_LAST;
        fprintf(out_f, "<td%s>%s</td>", cl, reg_status_strs[r]);
      } else {
        fprintf(out_f, "<td%s>&nbsp;</td>", cl);
      }
      fprintf(out_f, "<td%s>", cl);
      s = "";
      if (is_privileged(phr, cnts, u)) {
        fprintf(out_f, "%s%s", s, "privileged");
        s = ", ";
      }
      if (cnts && reg) {
        if ((reg->flags & USERLIST_UC_INVISIBLE)) {
          fprintf(out_f, "%s%s", s, "invisible");
          s = ", ";
        }
        if ((reg->flags & USERLIST_UC_BANNED)) {
          fprintf(out_f, "%s%s", s, "banned");
          s = ", ";
        }
        if ((reg->flags & USERLIST_UC_LOCKED)) {
          fprintf(out_f, "%s%s", s, "locked");
          s = ", ";
        }
        if ((reg->flags & USERLIST_UC_DISQUALIFIED)) {
          fprintf(out_f, "%s%s", s, "disqualified");
          s = ", ";
        }
      }
      if (!*s) fprintf(out_f, "&nbsp;");
      fprintf(out_f, "</td>");
      s = "";
      if (ui && ui->location) s = ui->location;
      fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(s));
      s = "";
      if (ui && ui->printer_name) s = ui->printer_name;
      fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(s));
    }
    fprintf(out_f, "</tr>\n");
  }
  fprintf(out_f, "</table>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  userlist_free(&users->b); users = 0;
  xfree(xml_text);
  bitset_free(&marked);
  xfree(marked_str);
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
  marked_str = collect_marked_set(phr, &marked);
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
super_serve_op_USER_IMPORT_CSV_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0, group_id = 0;
  const struct contest_desc *cnts = 0;
  opcap_t caps = 0LL;
  unsigned char buf[1024];
  const unsigned char *cl = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  hr_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (group_id < 0) group_id = 0;

  /* FIXME: refine caps */
  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, import user data from a CSV file",
           phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, contest_id, group_id, 0, NULL);

  html_start_form_id(out_f, 2, phr->self_url, "CreateForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "op", "%d", SSERV_CMD_USER_IMPORT_CSV_ACTION);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s id=\"CreateUserTable\">\n", cl);

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"separator\" size=\"20\" value=\";\"/></td><td%s>&nbsp;</td></tr>\n",
          cl, "Field separator", cl, cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>", cl, "Charset", cl);
  charset_html_select(out_f, NULL, NULL);
  fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"file\" name=\"csv_file\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "CSV File", cl, cl);

  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"%s\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, cl, "Import data", cl);
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  return retval;
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
  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
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
super_serve_op_GROUP_BROWSE_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  const struct userlist_group *g;
  const unsigned char *cl;
  int min_group_id = INT_MAX;
  int max_group_id = 0;
  int group_id, serial;
  struct userlist_list *users = 0;
  unsigned char *xml_text = 0;
  unsigned char hbuf[1024];
  unsigned char buf[1024];
  const unsigned char *group_filter = 0;
  int group_offset = 0;
  int group_count = 20;
  const unsigned char *s;
  opcap_t gcaps = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (get_global_caps(phr, &gcaps) < 0 && opcaps_check(gcaps, OPCAP_LIST_USERS) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, browsing groups", phr->html_name);
  ss_write_html_header(out_f, phr, buf);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, 0, 0, 0, NULL);

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  if (phr->ss->group_filter_set) {
    group_filter = phr->ss->group_filter;
    group_offset = phr->ss->group_offset;
    group_count = phr->ss->group_count;
  }

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  fprintf(out_f, "<table class=\"b0\">");
  s = group_filter;
  if (!s) s = "";
  fprintf(out_f, "<!--<tr><td class=\"b0\">Filter:</td><td class=\"b0\">%s</td></tr>-->",
          html_input_text(buf, sizeof(buf), "group_filter", 50, 0, "%s", ARMOR(s)));
  hbuf[0] = 0;
  if (phr->ss->group_filter_set) {
    snprintf(hbuf, sizeof(hbuf), "%d", group_offset);
  }
  fprintf(out_f, "<tr><td class=\"b0\">Offset:</td><td class=\"b0\">%s</td></tr>",
          html_input_text(buf, sizeof(buf), "group_offset", 10, 0, "%s", hbuf));
  hbuf[0] = 0;
  if (phr->ss->group_filter_set) {
    snprintf(hbuf, sizeof(hbuf), "%d", group_count);
  }
  fprintf(out_f, "<tr><td class=\"b0\">Count:</td><td class=\"b0\">%s</td></tr>",
          html_input_text(buf, sizeof(buf), "group_count", 10, 0, "%s", hbuf));
  fprintf(out_f, "<tr><td class=\"b0\">&nbsp;</td><td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td></tr>",
          SSERV_CMD_GROUP_FILTER_CHANGE_ACTION, "Change");
  fprintf(out_f, "</table>");
  fprintf(out_f, "<table class=\"b0\"><tr>");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_CMD_GROUP_FILTER_FIRST_PAGE_ACTION, "&lt;&lt;");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_CMD_GROUP_FILTER_PREV_PAGE_ACTION, "&lt;");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_CMD_GROUP_FILTER_NEXT_PAGE_ACTION, "&gt;");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_CMD_GROUP_FILTER_LAST_PAGE_ACTION, "&gt;&gt;");
  fprintf(out_f, "</tr></table>\n");

  r = userlist_clnt_list_users_2(phr->userlist_clnt, ULS_LIST_ALL_GROUPS_2,
                                 0, 0, group_filter, group_offset, group_count,
                                 // FIXME: fill the fields
                                 -1 /* page */, -1 /* sort_field */, 0 /* sort_order */,
                                 -1 /* filter_field */, 0 /* filter_op */,
                                 &xml_text);
  if (r < 0) {
    fprintf(out_f, "</form>\n");
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>Cannot get user list: %s</pre>\n",
            userlist_strerror(-r));
    goto do_footer;
  }
  users = userlist_parse_str(xml_text);
  if (!users) {
    fprintf(out_f, "</form>\n");
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>XML parse error</pre>\n");
    goto do_footer;
  }

  for (group_id = 1; group_id < users->group_map_size; ++group_id) {
    if (!(g = users->group_map[group_id])) continue;
    if (group_id >= max_group_id) max_group_id = group_id;
    if (group_id <= min_group_id) min_group_id = group_id;
  }
  html_hidden(out_f, "min_group_id", "%d", min_group_id);
  html_hidden(out_f, "max_group_id", "%d", max_group_id);

  cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr>");
  fprintf(out_f, "<th%s>NN</th>", cl);
  fprintf(out_f, "<th%s>Group Id</th>", cl);
  fprintf(out_f, "<th%s>Group Name</th>", cl);
  fprintf(out_f, "<th%s>Description</th>", cl);
  fprintf(out_f, "<th%s>Operations</th>", cl);
  fprintf(out_f, "</tr>\n");

  serial = group_offset - 1;
  for (group_id = 1; group_id < users->group_map_size; ++group_id) {
    if (!(g = users->group_map[group_id])) continue;

    ++serial;
    fprintf(out_f, "<tr>\n");
    fprintf(out_f, "<td class=\"b1\">%d</td>", serial);
    fprintf(out_f, "<td class=\"b1\">%d</td>", group_id);
    if (!g->group_name) {
      fprintf(out_f, "<td class=\"b1\"><i>NULL</i></td>");
    } else {
      fprintf(out_f, "<td class=\"b1\"><tt>%s</tt></td>", ARMOR(g->group_name));
    }
    if (!g->description) {
      fprintf(out_f, "<td class=\"b1\"><i>NULL</i></td>");
    } else {
      fprintf(out_f, "<td class=\"b1\"><tt>%s</tt></td>", ARMOR(g->description));
    }

    fprintf(out_f, "<td%s>", cl);
    fprintf(out_f, "%s%s</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;group_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_CMD_GROUP_MODIFY_PAGE,
                          group_id),
            "[Modify]");
    fprintf(out_f, "&nbsp;%s%s</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;group_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_BROWSE_PAGE,
                          group_id),
            "[Members]");
    fprintf(out_f, "&nbsp;%s%s</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;group_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_CMD_GROUP_DELETE_PAGE,
                          group_id),
            "[Delete]");
    fprintf(out_f, "</td>");
    fprintf(out_f, "</tr>\n");

  }
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  if (opcaps_check(gcaps, OPCAP_CREATE_USER) >= 0) {
    cl = " class=\"b0\"";
    fprintf(out_f, "<table%s><tr>", cl);
    fprintf(out_f, "<td%s>%s[%s]</a></td>", cl,
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_CMD_GROUP_CREATE_PAGE),
            "Create");
    fprintf(out_f, "</tr></table>\n");
  }

do_footer:
  ss_write_html_footer(out_f);

cleanup:
  xfree(xml_text); xml_text = 0;
  userlist_free(&users->b); users = 0;
  html_armor_free(&ab);
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

  if (get_global_caps(phr, &gcaps) < 0 && opcaps_check(gcaps, OPCAP_LIST_USERS) < 0) {
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
super_serve_op_GROUP_CREATE_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  unsigned char buf[1024];
  const unsigned char *cl = 0;
  opcap_t caps = 0;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, create a new group",
           phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, 0, 0, 0, NULL);

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "op", "%d", SSERV_CMD_GROUP_CREATE_ACTION);

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"text\" size=\"80\" name=\"group_name\" /></td></tr>\n",
          cl, "Group Name", cl);
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"text\" size=\"80\" name=\"description\" /></td></tr>\n",
          cl, "Description", cl);
  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"%s\" /></td></tr>\n",
          cl, cl, "Create a group");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  return retval;
}

int
super_serve_op_GROUP_MODIFY_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  int group_id = 0;
  struct userlist_group *g = 0;
  unsigned char buf[1024];
  const unsigned char *cl = 0;
  const unsigned char *s;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  opcap_t caps = 0;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_USER) < 0) {
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

  snprintf(buf, sizeof(buf), "serve-control: %s, modifying group %d",
           phr->html_name, group_id);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, 0, group_id, 0, NULL);

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "group_id", "%d", group_id);

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td></tr>\n",
          cl, "Group Id", cl, group_id);
  s = g->group_name;
  if (!s) s = "";
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"text\" size=\"80\" name=\"group_name\" value=\"%s\" /></td></tr>\n",
          cl, "Group Name", cl, ARMOR(s));
  s = g->description;
  if (!s) s = "";
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s><input type=\"text\" size=\"80\" name=\"description\" value=\"%s\" /></td></tr>\n",
          cl, "Description", cl, ARMOR(s));
  fprintf(out_f, "<tr><td%s colspan=\"2\">", cl);
  fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_GROUP_CANCEL_ACTION, "Cancel");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_GROUP_DELETE_PAGE_ACTION, "Delete the group!");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_GROUP_MODIFY_ACTION, "Save changes");
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  userlist_free(&users->b); users = 0;
  xfree(xml_text);
  return retval;
}

int
super_serve_op_GROUP_DELETE_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, r;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  int group_id = 0;
  struct userlist_group *g = 0;
  unsigned char buf[1024];
  const unsigned char *cl = 0;
  const unsigned char *s;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  opcap_t caps = 0;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_USER) < 0) {
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

  snprintf(buf, sizeof(buf), "serve-control: %s, modifying group %d",
           phr->html_name, group_id);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  print_top_navigation_links(log_f, out_f, phr, 0, group_id, 0, NULL);

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "group_id", "%d", group_id);

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>%d</td></tr>\n",
          cl, "Group Id", cl, group_id);
  s = g->group_name;
  if (!s) s = "";
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s>%s</td></tr>\n",
          cl, "Group Name", cl, ARMOR(s));
  s = g->description;
  if (!s) s = "";
  fprintf(out_f, "<tr><td%s><b>%s*:</b></td><td%s>%s</td></tr>\n",
          cl, "Description", cl, ARMOR(s));
  fprintf(out_f, "<tr><td%s colspan=\"2\">", cl);
  fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_GROUP_CANCEL_ACTION, "Cancel");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_GROUP_DELETE_ACTION, "Delete the group!");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_GROUP_MODIFY_PAGE_ACTION, "Modify the group");
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  userlist_free(&users->b); users = 0;
  xfree(xml_text);
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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_CREATE_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  s = 0;
  if (hr_cgi_param(phr, "group_name", &s) <= 0 || !s) FAIL(SSERV_ERR_INV_GROUP_NAME);
  group_name = fix_string(s);
  if (!group_name || !*group_name) FAIL(SSERV_ERR_INV_GROUP_NAME);
  if (strlen(group_name) > 1024) FAIL(SSERV_ERR_INV_GROUP_NAME);
  if (check_str(group_name, login_accept_chars) < 0) FAIL(SSERV_ERR_INV_GROUP_NAME);

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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_USER) < 0) {
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
  if (check_str(group_name, login_accept_chars) < 0) FAIL(SSERV_ERR_INV_GROUP_NAME);

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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_DELETE_USER) < 0) {
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

static void
find_elem_positions(
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

#define DEFAULT_CAPS_FILE "capabilities.xml"

static int
migration_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct ejudge_cfg *file_config = NULL;
  char *text = NULL;
  size_t size = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  char *new_map_t = NULL, *new_caps_t = NULL, *ext_caps_t = NULL, *new_full_t = NULL;
  size_t new_map_z = 0, new_caps_z = 0, ext_caps_z = 0, new_full_z = 0;
  FILE *f = NULL;
  int c;
  unsigned char ejudge_xml_tmp_path[PATH_MAX];
  unsigned char caps_xml_tmp_path[PATH_MAX];

  ejudge_xml_tmp_path[0] = 0;
  caps_xml_tmp_path[0] = 0;

  int sys_user_id = getuid();
  struct passwd *sys_pwd = getpwuid(sys_user_id);
  if (!sys_pwd || !sys_pwd->pw_name) {
    fprintf(log_f, "ejudge processes run as uid %d, which is nonexistant\n", sys_user_id);
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  const unsigned char *ejudge_login = ejudge_cfg_user_map_find(phr->config, sys_pwd->pw_name);
  if (!ejudge_login) {
    fprintf(log_f, "ejudge unix user %s is not mapped to ejudge internal user\n", sys_pwd->pw_name);
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (phr->config->caps_file) {
    fprintf(log_f, "configuration file is already updated\n");
    FAIL(SSERV_ERR_INV_OPER);
  }
  if (!phr->config->ejudge_xml_path) {
    fprintf(log_f, "ejudge.xml path is undefined\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  file_config = ejudge_cfg_parse(phr->config->ejudge_xml_path, 0);
  if (!file_config) {
    fprintf(log_f, "cannot parse ejudge.xml\n");
    FAIL(SSERV_ERR_INV_OPER);
  }
  if (file_config->caps_file) {
    ss_redirect(out_f, phr, SSERV_CMD_EJUDGE_XML_MUST_RESTART, NULL);
    goto cleanup;
  }
  file_config = ejudge_cfg_free(file_config);

  if (generic_read_file(&text, 0, &size, 0, 0, phr->config->ejudge_xml_path, 0) < 0) {
    fprintf(log_f, "failed to read ejudge.xml file from '%s'\n", phr->config->ejudge_xml_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }
  if (size != strlen(text)) {
    fprintf(log_f, "ejudge.xml '%s' contains \\0 byte\n", phr->config->ejudge_xml_path);
    FAIL(SSERV_ERR_INV_OPER);
  }

  int um_count = -1, um_begin = -1, um_end = -1, caps_count = -1, caps_begin = -1, caps_end = -1;
  find_elem_positions(text, (int) size, &um_count, &um_begin, &um_end,
                      &caps_count, &caps_begin, &caps_end);
  if (um_count != 1 || um_begin < 0 || um_end < 0 || caps_count != 1 || caps_begin < 0 || caps_end < 0) {
    fprintf(log_f, "sorry cannot process '%s'\n", phr->config->ejudge_xml_path);
    FAIL(SSERV_ERR_INV_OPER);
  }
  int p1_begin = um_begin, p1_end = um_end, p2_begin = caps_begin, p2_end = caps_end;
  if (caps_begin < um_begin) {
    p1_begin = caps_begin;
    p1_end = caps_end;
    p2_begin = um_begin;
    p2_end = um_end;
  }

  f = open_memstream(&new_map_t, &new_map_z);
  fprintf(f, "<user_map>\n"
          "    <map system_user=\"%s\" local_user=\"%s\" />\n"
          "  </user_map>",
          sys_pwd->pw_name, ejudge_login);
  fclose(f); f = NULL;
  f = open_memstream(&new_caps_t, &new_caps_z);
  fprintf(f, "<caps_file>%s</caps_file>\n"
          "  <caps>\n"
          "    <cap login=\"%s\">FULL_SET</cap>\n"
          "  </caps>", DEFAULT_CAPS_FILE, ejudge_login);
  fclose(f); f = NULL;
  f = open_memstream(&ext_caps_t, &ext_caps_z);
  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\"?>\n"
          "<config>\n", EJUDGE_CHARSET);
  fprintf(f, "  <user_map>\n");
  if (phr->config->user_map) {
    for (const struct xml_tree *p = phr->config->user_map->first_down; p; p = p->right) {
      const struct ejudge_cfg_user_map *m = (const struct ejudge_cfg_user_map*) p;
      if (strcmp(m->local_user_str, ejudge_login) != 0) {
        fprintf(f, "    <map system_user=\"%s\"", ARMOR(m->system_user_str));
        fprintf(f, " local_user=\"%s\" />\n", ARMOR(m->local_user_str));
      }
    }
  }
  fprintf(f, "  </user_map>\n");
  fprintf(f, "  <caps>\n");
  if (phr->config->capabilities.first) {
    for (const struct opcap_list_item *p = phr->config->capabilities.first; p;
         p = (const struct opcap_list_item*) p->b.right) {
      if (strcmp(p->login, ejudge_login) != 0) {
        fprintf(f, "    <cap login=\"%s\">\n", ARMOR(p->login));
        unsigned char *s = opcaps_unparse(6, 60, p->caps);
        fprintf(f, "%s", s);
        xfree(s);
        fprintf(f, "    </cap>\n");
      }
    }
  }
  fprintf(f, "  </caps>\n");
  fprintf(f, "</config>\n");
  fclose(f); f = NULL;
  f = open_memstream(&new_full_t, &new_full_z);
  c = text[p1_begin]; text[p1_begin] = 0;
  fprintf(f, "%s", text);
  text[p1_begin] = c;
  fprintf(f, "%s", new_map_t);
  c = text[p2_begin]; text[p2_begin] = 0;
  fprintf(f, "%s", text + p1_end);
  text[p2_begin] = c;
  fprintf(f, "%s", new_caps_t);
  fprintf(f, "%s", text + p2_end);
  fclose(f); f = NULL;

  // FIXME: check, that the new files are correct (can be parsed)

  if (phr->action == SSERV_CMD_EJUDGE_XML_UPDATE_ACTION) {
    unsigned char dirname[PATH_MAX];
    dirname[0] = 0;
    os_rDirName(phr->config->ejudge_xml_path, dirname, sizeof(dirname));
    if (!dirname[0] || !strcmp(dirname, ".")) FAIL(SSERV_ERR_FS_ERROR);
    int pid = getpid();
    time_t cur_time = time(0);
    struct tm *ptm = localtime(&cur_time);
    snprintf(ejudge_xml_tmp_path, sizeof(ejudge_xml_tmp_path),
             "%s.tmp.%04d%02d%02d.%d", phr->config->ejudge_xml_path,
             ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, pid);
    snprintf(caps_xml_tmp_path, sizeof(caps_xml_tmp_path),
             "%s/%s.tmp.%04d%02d%02d.%d", dirname, DEFAULT_CAPS_FILE,
             ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, pid);
    unsigned char ejudge_xml_bak_path[PATH_MAX];
    snprintf(ejudge_xml_bak_path, sizeof(ejudge_xml_bak_path),
             "%s.bak.%04d%02d%02d", phr->config->ejudge_xml_path,
             ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);
    if (generic_write_file(new_full_t, new_full_z, 0, NULL, ejudge_xml_tmp_path, NULL) < 0) {
      fprintf(log_f, "failed to write '%s'\n", ejudge_xml_tmp_path);
      FAIL(SSERV_ERR_FS_ERROR);
    }
    if (generic_write_file(ext_caps_t, ext_caps_z, 0, NULL, caps_xml_tmp_path, NULL) < 0) {
      fprintf(log_f, "failed to write '%s'\n", caps_xml_tmp_path);
      FAIL(SSERV_ERR_FS_ERROR);
    }
    chmod(caps_xml_tmp_path, 0600);
    struct stat stb;
    if (stat(phr->config->ejudge_xml_path, &stb) > 0 && S_ISREG(stb.st_mode)) {
      chown(ejudge_xml_tmp_path, -1, stb.st_gid);
      chmod(ejudge_xml_tmp_path, stb.st_mode & 07777);
    }
    unsigned char caps_xml_path[PATH_MAX];
    snprintf(caps_xml_path, sizeof(caps_xml_path), "%s/%s", dirname, DEFAULT_CAPS_FILE);
    if (rename(caps_xml_tmp_path, caps_xml_path) < 0) {
      fprintf(log_f, "failed to rename '%s' -> '%s'\n", caps_xml_tmp_path, caps_xml_path);
      FAIL(SSERV_ERR_FS_ERROR);
    }
    caps_xml_tmp_path[0] = 0;
    if (rename(phr->config->ejudge_xml_path, ejudge_xml_bak_path) < 0) {
      fprintf(log_f, "failed to rename '%s' -> '%s'\n", phr->config->ejudge_xml_path, ejudge_xml_bak_path);
      unlink(caps_xml_path);
      FAIL(SSERV_ERR_FS_ERROR);
    }
    if (rename(ejudge_xml_tmp_path, phr->config->ejudge_xml_path) < 0) {
      fprintf(log_f, "failed to rename '%s' -> '%s'\n", ejudge_xml_tmp_path, phr->config->ejudge_xml_path);
      rename(ejudge_xml_bak_path, phr->config->ejudge_xml_path);
      unlink(caps_xml_path);
      FAIL(SSERV_ERR_FS_ERROR);
    }
    ejudge_xml_tmp_path[0] = 0;

    ss_redirect(out_f, phr, SSERV_CMD_EJUDGE_XML_MUST_RESTART, NULL);
    goto cleanup;
  }

  unsigned char buf[1024];
  unsigned char hbuf[1024];

  snprintf(buf, sizeof(buf), "serve-control: %s, upgrade of ejudge.xml", phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_BROWSE_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_GROUP_BROWSE_PAGE),
          "Browse groups");
  fprintf(out_f, "</ul>\n");

  fprintf(out_f,
          "<p>This version of ejudge supports the improved format of the global ejudge.xml"
          " configuration file. Now, user mappings and global user capabilities are stored"
          " in a separate file, which can be edited using the web-interface. Updates to"
          " this file are read on-the-fly, so no ejudge restart will be necessary.</p>\n"
          "<p>In order to enable this new functionality the ejudge.xml global configuration"
          " file has to be modified as follows. Ejudge can now apply these updates.</p>\n"
          "<p>Please, review these updates.</p>\n"
          "<p>After the updates are applied you have to restart ejudge.</p>\n");

  fprintf(out_f, "<h3>Changes to ejudge.xml</h3>\n");

  const unsigned char *cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><th%s>Original ejudge.xml</th><th%s>New ejudge.xml</th></tr>\n", cl, cl);
  fprintf(out_f, "<tr><td%s valign=\"top\"><pre>", cl);
  c = text[p1_begin]; text[p1_begin] = 0;
  fprintf(out_f, "%s", ARMOR(text));
  text[p1_begin] = c; c = text[p1_end]; text[p1_end] = 0;
  fprintf(out_f, "<font color=\"red\">%s</font>", ARMOR(text + p1_begin));
  text[p1_end] = c; c = text[p2_begin]; text[p2_begin] = 0;
  fprintf(out_f, "%s", ARMOR(text + p1_end));
  text[p2_begin] = c; c = text[p2_end]; text[p2_end] = 0;
  fprintf(out_f, "<font color=\"red\">%s</font>", ARMOR(text + p2_begin));
  text[p2_end] = c;
  fprintf(out_f, "%s", ARMOR(text + p2_end));
  fprintf(out_f, "</pre></td><td%s valign=\"top\"><pre>", cl);
  c = text[p1_begin]; text[p1_begin] = 0;
  fprintf(out_f, "%s", ARMOR(text));
  text[p1_begin] = c;
  fprintf(out_f, "<font color=\"green\">%s</font>", ARMOR(new_map_t));
  c = text[p2_begin]; text[p2_begin] = 0;
  fprintf(out_f, "%s", ARMOR(text + p1_end));
  text[p2_begin] = c;
  fprintf(out_f, "<font color=\"green\">%s</font>", ARMOR(new_caps_t));
  fprintf(out_f, "%s", ARMOR(text + p2_end));
  fprintf(out_f, "</pre></td></tr>\n");
  fprintf(out_f, "</table>\n");

  fprintf(out_f, "<h3>New file %s</h3>\n", DEFAULT_CAPS_FILE);

  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s valign=\"top\"><pre><font color=\"green\">%s</font></pre></td></tr>\n",
          cl, ARMOR(ext_caps_t));
  fprintf(out_f, "</table>\n");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s>", cl);
  fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_EJUDGE_XML_CANCEL_ACTION, "No, cancel action");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_CMD_EJUDGE_XML_UPDATE_ACTION, "Yes, apply the updates!");
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  if (ejudge_xml_tmp_path[0]) unlink(ejudge_xml_tmp_path);
  if (caps_xml_tmp_path[0]) unlink(caps_xml_tmp_path);
  if (f) fclose(f);
  xfree(new_map_t);
  xfree(new_caps_t);
  xfree(ext_caps_t);
  xfree(new_full_t);
  html_armor_free(&ab);
  xfree(text);
  ejudge_cfg_free(file_config);
  return retval;
}

int
super_serve_op_USER_MAP_MAIN_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0;
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int serial = 0;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (!phr->config->caps_file) {
    return migration_page(log_f, out_f, phr);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, user map", phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "</ul>");

  ejudge_cfg_refresh_caps_file(phr->config, 1);

  const unsigned char *cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><th%s>System (unix) user</th><th%s>Ejudge user</th></tr>\n", cl, cl);
  if (phr->config->caps_file_info && phr->config->caps_file_info->root
      && phr->config->caps_file_info->root->user_map) {
    for (const struct xml_tree *p = phr->config->caps_file_info->root->user_map->first_down;
         p; p = p->right) {
      ++serial;
      const struct ejudge_cfg_user_map *m = (const struct ejudge_cfg_user_map*) p;
      fprintf(out_f, "<tr>");
      fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(m->system_user_str));
      fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(m->local_user_str));
      fprintf(out_f, "<td%s>%s%s</a>", cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;serial=%d",
                            SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_MAP_DELETE_ACTION,
                            serial),
              "[Delete]");
      fprintf(out_f, "</tr>\n");
    }
  }
  fprintf(out_f, "</table>\n");

  fprintf(out_f, "<h3>Create new mapping</h3>\n");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);

  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"text\" size=\"40\" name=\"unix_login\" /></td></tr>\n",
          cl, "Unix login", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"text\" size=\"40\" name=\"ejudge_login\" /></td></tr>\n",
          cl, "Ejudge login", cl);

  fprintf(out_f, "<tr><td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></tr></td>\n",
          cl, SSERV_CMD_USER_MAP_ADD_ACTION, "Create mapping");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_EJUDGE_XML_UPDATE_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  return migration_page(log_f, out_f, phr);

cleanup:
  return retval;
}

int
super_serve_op_EJUDGE_XML_CANCEL_ACTION(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  fprintf(out_f, "Location: %s?SID=%016llx\n", phr->self_url, phr->session_id);
  if (phr->client_key) {
    fprintf(out_f, "Set-Cookie: EJSID=%016llx; Path=/\n", phr->client_key);
  }
  putc('\n', out_f);
  return 0;
}

int
super_serve_op_EJUDGE_XML_MUST_RESTART(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  unsigned char buf[1024];
  unsigned char hbuf[1024];

  snprintf(buf, sizeof(buf), "serve-control: %s, you must restart ejudge", phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_BROWSE_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_GROUP_BROWSE_PAGE),
          "Browse groups");
  fprintf(out_f, "</ul>\n");

  fprintf(out_f, "<p>Now you must restart ejudge.</p>");

  return retval;
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
  if (stat(cfg->caps_file_info->path, &stb) > 0 && S_ISREG(stb.st_mode)) {
    chown(caps_xml_tmp_path, -1, stb.st_gid);
    chmod(caps_xml_tmp_path, stb.st_mode & 07777);
  } else {
    chmod(caps_xml_tmp_path, 0600);
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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
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
super_serve_op_CAPS_MAIN_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0;
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int serial = 0;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (!phr->config->caps_file) {
    return migration_page(log_f, out_f, phr);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, global user capabilities", phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "</ul>");

  ejudge_cfg_refresh_caps_file(phr->config, 1);
  const struct ejudge_cfg *root = phr->config->caps_file_info->root;

  const unsigned char *cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><th%s>User</th><th%s>Capabilities</th><th%s>Actions</th></tr>\n", cl, cl, cl);
  if (root) {
    for (const struct xml_tree *p = (struct xml_tree*) root->capabilities.first; p; p = p->right) {
      ++serial;
      const struct opcap_list_item *c = (const struct opcap_list_item*) p;
      fprintf(out_f, "<tr>");
      fprintf(out_f, "<td%s>%s</td>", cl, ARMOR(c->login));
      unsigned char *str = opcaps_unparse(0, 60, c->caps);
      fprintf(out_f, "<td%s><pre>%s</pre></td>", cl, str);
      xfree(str); str = NULL;
      fprintf(out_f, "<td%s>%s%s</a>", cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;serial=%d",
                            SSERV_CMD_HTTP_REQUEST, SSERV_CMD_CAPS_EDIT_PAGE,
                            serial),
              "[Edit]");
      fprintf(out_f, "&nbsp;%s%s</a></td>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;serial=%d",
                            SSERV_CMD_HTTP_REQUEST, SSERV_CMD_CAPS_DELETE_ACTION,
                            serial),
              "[Delete]");
      fprintf(out_f, "</tr>\n");
    }
  }
  fprintf(out_f, "</table>\n");

  fprintf(out_f, "<h3>Create new global user capability</h3>\n");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);

  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"text\" size=\"40\" name=\"ejudge_login\" /></td></tr>\n",
          cl, "Login", cl);

  fprintf(out_f, "<tr><td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></tr></td>\n",
          cl, SSERV_CMD_CAPS_ADD_ACTION, "Create");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
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

static const unsigned char * const global_cap_descs[OPCAP_LAST] =
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
super_serve_op_CAPS_EDIT_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
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

  unsigned char buf[1024];
  unsigned char hbuf[1024];

  snprintf(buf, sizeof(buf), "serve-control: %s, global capabilities for %s", phr->html_name, ARMOR(p->login));
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_CAPS_MAIN_PAGE),
          "Global user capabilities");
  fprintf(out_f, "</ul>");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "serial", "%d", serial);

  const unsigned char *cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>", cl);
  for (int cap = 0; cap < OPCAP_LAST; ++cap) {
    if (!global_cap_descs[cap]) continue;
    const unsigned char *s = "";
    if (opcaps_check(p->caps, cap) >= 0) s = " checked=\"yes\"";
    fprintf(out_f, "<tr>"
            "<td%s>%d</td>"
            "<td%s><input type=\"checkbox\" name=\"cap_%d\"%s /></td>"
            "<td%s><tt>%s</tt></td>"
            "<td%s>%s</td>"
            "</tr>\n",
            cl, cap, cl, cap, s, cl, opcaps_get_name(cap),
            cl, global_cap_descs[cap]);
  }
  fprintf(out_f, "</table>");

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);
  fprintf(out_f, "<tr><td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>\n",
          cl, SSERV_CMD_CAPS_EDIT_CANCEL_ACTION, "Cancel");
  fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td></tr>\n",
          cl, SSERV_CMD_CAPS_EDIT_SAVE_ACTION, "Save");
  fprintf(out_f, "</table>\n");

  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  return retval;
}

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

  if (get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_PRIV_EDIT_USER) < 0) {
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

static int
get_saved_auth(
        const unsigned char *ej_login,
        unsigned char **p_poly_login,
        unsigned char **p_poly_password,
        unsigned char **p_poly_url)
{
  unsigned char path[PATH_MAX];
  FILE *f = NULL;
  unsigned char lb[1024], pb[1024], ub[1024];

  lb[0] = 0;
  pb[0] = 0;
  ub[0] = 0;
  snprintf(path, sizeof(path), "%s/db/%s", EJUDGE_CONF_DIR, ej_login);
  if (!(f = fopen(path, "r"))) return -1;
  (void) (fgets(lb, sizeof(lb), f) && fgets(pb, sizeof(pb), f) && fgets(ub, sizeof(ub), f));
  fclose(f); f = NULL;
  int ll = strlen(lb);
  while (ll > 0 && isspace(lb[ll - 1])) --ll;
  lb[ll] = 0;
  ll = strlen(pb);
  while (ll > 0 && isspace(pb[ll - 1])) --ll;
  pb[ll] = 0;
  ll = strlen(ub);
  while (ll > 0 && isspace(ub[ll - 1])) --ll;
  ub[ll] = 0;

  *p_poly_login = xstrdup(lb);
  *p_poly_password = xstrdup(pb);
  *p_poly_url = xstrdup(ub);
  return 1;
}

static void
save_auth(
        const unsigned char *ej_login,
        const unsigned char *poly_login,
        const unsigned char *poly_password,
        const unsigned char *poly_url)
{
  unsigned char path[PATH_MAX];
  FILE *f = NULL;

  if (!poly_login) poly_login = "";
  if (!poly_password) poly_password = "";
  if (!poly_url) poly_url = "";

  snprintf(path, sizeof(path), "%s/db/%s", EJUDGE_CONF_DIR, ej_login);
  if (!(f = fopen(path, "w"))) {
    return;
  }
  fprintf(f, "%s\n%s\n%s\n", poly_login, poly_password, poly_url);
  fflush(f);
  if (ferror(f)) {
    fclose(f); unlink(path);
    return;
  }
  fclose(f);
  chmod(path, 0600);
}

static int
find_free_prob_id(const struct sid_state *ss)
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
super_serve_op_IMPORT_FROM_POLYGON_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0, lcaps = 0;
  struct sid_state *ss = phr->ss;
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  unsigned char prob_buf[64];
  const unsigned char *cl;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *saved_login = NULL;
  unsigned char *saved_password = NULL;
  unsigned char *saved_url = NULL;

  if (!ss->edited_cnts || !ss->global) {
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  }

  get_global_caps(phr, &caps);
  get_contest_caps(phr, ss->edited_cnts, &lcaps);
  caps |= lcaps;

  if (opcaps_check(lcaps, OPCAP_EDIT_CONTEST) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (ss->global->advanced_layout <= 0) {
    fprintf(log_f, "advanced_layout must be set\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (ss->update_state) {
    ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);
    goto cleanup;
  }

  int prob_id = find_free_prob_id(ss);
  problem_id_to_short_name(prob_id - 1, prob_buf);

  get_saved_auth(phr->login, &saved_login, &saved_password, &saved_url);
  if (!saved_login) saved_login = xstrdup("");
  if (!saved_password) saved_password = xstrdup("");
  if (!saved_url) saved_url = xstrdup("");

  snprintf(buf, sizeof(buf), "serve-control: %s, importing problem from polygon", phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE),
          "General settings (contest.xml)");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_EDIT_CUR_GLOBAL_PAGE),
          "Global settings (serve.cfg)");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE),
          "Language settings (serve.cfg)");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE),
          "Problems (serve.cfg)");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_START_EDIT_VARIANT_ACTION),
          "Variants (variant.map)");
  fprintf(out_f, "</ul>");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);

  fprintf(out_f, "<tr><td colspan=\"2\" align=\"center\"%s><b>Ejudge problem identification</b></td></tr>\n", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"text\" size=\"40\" name=\"ejudge_id\" /></td></tr>\n",
          cl, "Id", cl);
  fprintf(out_f, "<tr><td%s><b>%s</b> *:</td><td%s><input type=\"text\" size=\"40\" name=\"ejudge_short_name\" value=\"%s\" /></td></tr>\n",
          cl, "Short name", cl, prob_buf);

  fprintf(out_f, "<tr><td%s><b>%s</b>:</td><td%s>"
          "<select name=\"language_priority\">"
          "<option></option"
          "<option>ru,en</option>"
          "<option>en,ru</option>"
          "</select>"
          "</td></tr>\n",
          cl, "Language priority", cl);

  fprintf(out_f, "<tr><td colspan=\"2\" align=\"center\"%s><b>Polygon information</b></td></tr>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s</b> *:</td><td%s><input type=\"text\" size=\"40\" name=\"polygon_login\" value=\"%s\" /></td></tr>\n",
          cl, "Login", cl, ARMOR(saved_login));
  fprintf(out_f, "<tr><td%s><b>%s</b> *:</td><td%s><input type=\"password\" size=\"40\" name=\"polygon_password\" value=\"%s\"  /></td></tr>\n",
          cl, "Password", cl, ARMOR(saved_password));

  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" checked=\"checked\" /></td></tr>\n",
          cl, "Save auth info", cl, "save_auth");
  fprintf(out_f, "<tr><td%s><b>%s</b> *:</td><td%s><input type=\"text\" size=\"60\" name=\"polygon_id\" /></td></tr>\n",
          cl, "Problem id/name", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"text\" size=\"60\" name=\"polygon_url\" value=\"%s\" /></td></tr>\n",
          cl, "Polygon URL", cl, ARMOR(saved_url));
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" checked=\"checked\" /></td></tr>\n",
          cl, "Assume max_vm_size == max_stack_size", cl, "max_stack_size");
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" checked=\"checked\" /></td></tr>\n",
          cl, "Ignore additional solutions", cl, "ignore_solutions");
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" /></td></tr>\n",
          cl, "Fetch latest available packet (do not generate)", cl, "fetch_latest_available");
  
  fprintf(out_f, "<tr><td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></tr></td>\n",
          cl, SSERV_CMD_IMPORT_FROM_POLYGON_ACTION, "Import");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  xfree(saved_login);
  xfree(saved_password);
  xfree(saved_url);
  return retval;
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

  if (!ss->edited_cnts || !ss->global) {
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  }

  get_global_caps(phr, &caps);
  get_contest_caps(phr, ss->edited_cnts, &lcaps);
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

  if (hr_cgi_param(phr, "save_auth", &s) > 0) save_auth_flag = 1;

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

  if (hr_cgi_param(phr, "max_stack_size", &s) > 0) max_stack_size_flag = 1;
  if (hr_cgi_param(phr, "ignore_solutions", &s) > 0) ignore_solutions_flag = 1;
  if (hr_cgi_param(phr, "fetch_latest_available", &s) > 0) fetch_latest_available_flag = 1;

  if (hr_cgi_param(phr, "language_priority", &s) > 0 && *s) {
    if (!strcmp(s, "ru,en")
        || !strcmp(s, "en,ru")) {
      language_priority = s;
    }
  }

  if (save_auth_flag) {
    save_auth(phr->login, polygon_login, polygon_password, polygon_url);
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
  pp->enable_max_stack_size = max_stack_size_flag;
  pp->ignore_solutions = ignore_solutions_flag;
  pp->fetch_latest_available = fetch_latest_available_flag;
  pp->create_mode = 1;
  pp->polygon_url = polygon_url; polygon_url = NULL;
  pp->login = polygon_login; polygon_login = NULL;
  pp->password = polygon_password; polygon_password = NULL;
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

struct download_status
{
  unsigned char *key;
  unsigned char *status;
  unsigned char *polygon_id;
  unsigned char *polygon_name;
};

static int
read_download_status(
        FILE *log_f,
        const unsigned char *path,
        FILE *f,
        int *p_exit_code,
        int *p_count,
        struct download_status **p_statuses)
{
  unsigned char buf[1024];
  int len, exit_code = -1, n, count = 0;
  struct download_status *statuses = NULL;

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
super_serve_op_DOWNLOAD_PROGRESS_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct sid_state *ss = phr->ss;
  unsigned char buf[1024];
  time_t cur_time = time(NULL);
  struct update_state *us;
  FILE *f = NULL;
  int pid = 0;
  unsigned char hbuf[1024];
  int exit_code = -1, count = 0;
  struct download_status *statuses = NULL;
  const unsigned char *cl, *s;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct polygon_packet *pp = NULL;
  char *cfg_text = NULL;
  size_t cfg_size = 0;
  int start_mode = 0;
  int successes = 0, failures = 0;

  if (!(us = ss->update_state)) {
    snprintf(buf, sizeof(buf), "serve-control: %s, no download process", phr->html_name);
  } else {
    if (us->status_file && (f = fopen(us->status_file, "r"))) {
      read_download_status(stderr, us->status_file, f, &exit_code, &count, &statuses);
      fclose(f); f = NULL;
      snprintf(buf, sizeof(buf), "serve-control: %s, download complete", phr->html_name);
    } else if (us->pid_file && (f = fopen(us->pid_file, "r"))) {
      if (fscanf(f, "%d", &pid) <= 0 || pid <= 0) pid = 0;
      fclose(f); f = NULL;

      // check that the process still exists
      if (kill(pid, 0) < 0) {
        // the process does not exists, so create status file
        if (us->log_file) {
          if ((f = fopen(us->log_file, "a")) != NULL) {
            fprintf(f, "\nej-polygon process has terminated unexpectedly!\n");
            fclose(f); f = NULL;
          }
        }
        if (us->status_file) {
          if ((f = fopen(us->status_file, "w")) != NULL) {
            fprintf(f, "127\n0\n");
            fclose(f); f = NULL;
            return super_serve_op_DOWNLOAD_PROGRESS_PAGE(log_f, out_f, phr);
          }
        }
      }

      snprintf(buf, sizeof(buf), "serve-control: %s, download in progress", phr->html_name);
    } else if (us->start_time > 0 && cur_time < us->start_time + 5) {
      snprintf(buf, sizeof(buf), "serve-control: %s, download started", phr->html_name);
      start_mode = 1;
    } else {
      snprintf(buf, sizeof(buf), "serve-control: %s, download failed to start", phr->html_name);
    }
  }

  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  if (ss->edited_cnts) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d",
                          SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE),
            "General settings (contest.xml)");
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d",
                          SSERV_CMD_CNTS_EDIT_CUR_GLOBAL_PAGE),
            "Global settings (serve.cfg)");
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d",
                          SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE),
            "Language settings (serve.cfg)");
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d",
                          SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE),
            "Problems (serve.cfg)");
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d",
                          SSERV_CMD_CNTS_START_EDIT_VARIANT_ACTION),
            "Variants (variant.map)");
  }
  fprintf(out_f, "</ul>");

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE),
          "Refresh");
  fprintf(out_f, "</ul>");

  if (exit_code >= 0) {
    fprintf(out_f, "<h2>Download complete with code %d</h2>\n", exit_code);
    cl = " class=\"b1\"";
    fprintf(out_f, "<table%s>\n", cl);
    fprintf(out_f, "<tr><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th></tr>\n",
            cl, "Key", cl, "Status", cl, "Polygon Id", cl, "Polygon Name");
    for (int i = 0; i < count; ++i) {
      if (statuses[i].status &&
          (!strcmp(statuses[i].status, "ACTUAL") || !strcmp(statuses[i].status, "UPDATED") || !strcmp(statuses[i].status, "ALREADY_EXISTS"))) {
        s = " bgcolor=\"#ddffdd\"";
        ++successes;
      } else {
        s = " bgcolor=\"#ffdddd\"";
        ++failures;
      }

      fprintf(out_f, "<tr%s>", s);
      fprintf(out_f, "<td%s><tt>%s</tt></td>", cl, ARMOR(statuses[i].key));
      fprintf(out_f, "<td%s><tt>%s</tt></td>", cl, ARMOR(statuses[i].status));
      fprintf(out_f, "<td%s><tt>%s</tt></td>", cl, ARMOR(statuses[i].polygon_id));
      fprintf(out_f, "<td%s><tt>%s</tt></td>", cl, ARMOR(statuses[i].polygon_name));
      fprintf(out_f, "</tr>");
    }
    fprintf(out_f, "</table>\n");
    fprintf(out_f, "<p><b>Successes: %d, failures: %d.</b></p>\n", successes, failures);
  } if (pid > 0) {
    fprintf(out_f, "<h2>Download in progress (process pid %d)</h2>\n", pid);
  }

  if (us && us->conf_file) {
    f = fopen(us->conf_file, "r");
    if (f) {
      pp = polygon_packet_parse(us->conf_file, f);
      f = NULL;
      if (pp) {
        if (pp->password) {
          xfree(pp->password); pp->password = xstrdup("*");
        }
        f = open_memstream(&cfg_text, &cfg_size);
        polygon_packet_unparse(f, pp);
        fclose(f); f = NULL;
      }
    }
  }

  if (exit_code >= 0) {
    html_start_form(out_f, 1, phr->self_url, "");
    html_hidden(out_f, "SID", "%016llx", phr->session_id);
    html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
    if (failures > 0) {
      fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
              SSERV_CMD_DOWNLOAD_CLEANUP_ACTION, "Clean up");
    } else if (us->create_mode || ss->edited_cnts) {
      cl = " class=\"b0\"";
      fprintf(out_f, "<table%s><tr>", cl);
      fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
              cl, SSERV_CMD_DOWNLOAD_CLEANUP_ACTION, "Clean up");
      fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
              cl, SSERV_CMD_DOWNLOAD_CLEANUP_AND_IMPORT_ACTION, "Clean up and import settings");
      fprintf(out_f, "</tr></table>\n");
    } else {
      cl = " class=\"b0\"";
      fprintf(out_f, "<table%s><tr>", cl);
      fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
              cl, SSERV_CMD_DOWNLOAD_CLEANUP_ACTION, "Clean up");
      fprintf(out_f, "<td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>",
              cl, SSERV_CMD_DOWNLOAD_CLEANUP_AND_CHECK_ACTION, "Clean up and check settings");
      fprintf(out_f, "</tr></table>\n");
      fprintf(out_f, "<p>Note: problem settings, such as time limits, input/output file names, etc will not be updated!</p>");
    }
    fprintf(out_f, "</form>\n");
  } else if (pid > 0) {
    html_start_form(out_f, 1, phr->self_url, "");
    html_hidden(out_f, "SID", "%016llx", phr->session_id);
    html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
    fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
            SSERV_CMD_DOWNLOAD_KILL_ACTION, "Terminate download");
    fprintf(out_f, "</form>\n");
  } else if (us && !start_mode) {
    html_start_form(out_f, 1, phr->self_url, "");
    html_hidden(out_f, "SID", "%016llx", phr->session_id);
    html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
    fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
            SSERV_CMD_DOWNLOAD_CLEANUP_ACTION, "Clean up");
    fprintf(out_f, "</form>\n");
  }

  if (cfg_text && *cfg_text) {
    fprintf(out_f, "<h2>Request configuration file</h2>\n");
    fprintf(out_f, "<pre>%s</pre>\n", ARMOR(cfg_text));
    xfree(cfg_text); cfg_text = NULL; cfg_size = 0;
  }

  if (us && us->log_file && generic_read_file(&cfg_text, 0, &cfg_size, 0, 0, us->log_file, 0) >= 0 && cfg_text) {
    fprintf(out_f, "<h2>Log file</h2>\n");
    fprintf(out_f, "<pre>%s</pre>\n", ARMOR(cfg_text));
    xfree(cfg_text); cfg_text = NULL; cfg_size = 0;
  }

  ss_write_html_footer(out_f);

  xfree(cfg_text);
  polygon_packet_free((struct generic_section_config*) pp);
  html_armor_free(&ab);
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
    if (prob && prob->short_name && !strcmp(prob->short_name, internal_name)) {
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
      if (prob && prob->short_name && !strcmp(prob->short_name, cfg->short_name)) {
        fprintf(log_f, "short name '%s' is not unique in this contest\n", cfg->short_name);
        FAIL(SSERV_ERR_OPERATION_FAILED);
      }
      if (prob && prob->internal_name && !strcmp(prob->internal_name, cfg->short_name)) {
        fprintf(log_f, "short name '%s' matches internal name in this contest\n", cfg->short_name);
        FAIL(SSERV_ERR_OPERATION_FAILED);
      }
    }
    if (cfg->id <= 0) cfg->id = find_free_prob_id(ss);
  } else {
    if (cfg->id <= 0) cfg->id = find_free_prob_id(ss);
    unsigned char name_buf[32];
    problem_id_to_short_name(cfg->id - 1, name_buf);
    for (int prob_id = 1; prob_id < ss->prob_a; ++prob_id) {
      struct section_problem_data *prob = ss->probs[prob_id];
      if (prob && prob->short_name && !strcmp(prob->short_name, name_buf)) {
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
  snprintf(prob->internal_name, sizeof(prob->internal_name), "%s", cfg->internal_name);
  if (cfg->extid) prob->extid = xstrdup(cfg->extid);
  if (cfg->long_name) snprintf(prob->long_name, sizeof(prob->long_name), "%s", cfg->long_name);
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
    snprintf(prob->input_file, sizeof(prob->input_file), "%s", cfg->input_file);
  }
  if (cfg->use_stdout > 0) {
    prob->use_stdout = 1;
  } else if (!cfg->use_stdout) {
    prob->use_stdout = 0;
    snprintf(prob->output_file, sizeof(prob->output_file), "%s", cfg->output_file);
  }
  if (cfg->max_vm_size != (size_t) -1L && cfg->max_vm_size) {
    prob->max_vm_size = cfg->max_vm_size;
  }
  if (cfg->max_stack_size != (size_t) -1L && cfg->max_stack_size) {
    prob->max_stack_size = cfg->max_stack_size;
  }
  if (cfg->test_pat && cfg->test_pat[0]) {
    snprintf(prob->test_pat, sizeof(prob->test_pat), "%s", cfg->test_pat);
  }
  if (cfg->use_corr > 0) {
    prob->use_corr = 1;
  } else if (!cfg->use_corr) {
    prob->use_corr = 0;
  }
  if (cfg->corr_pat && cfg->corr_pat[0]) {
    snprintf(prob->corr_pat, sizeof(prob->corr_pat), "%s", cfg->corr_pat);
  }
  if (cfg->standard_checker && cfg->standard_checker[0]) {
    snprintf(prob->standard_checker, sizeof(prob->standard_checker), "%s", cfg->standard_checker);
  } else if (cfg->check_cmd && cfg->check_cmd[0]) {
    snprintf(prob->check_cmd, sizeof(prob->check_cmd), "%s", cfg->check_cmd);
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
    snprintf(prob->interactor_cmd, sizeof(prob->interactor_cmd), "%s", cfg->interactor_cmd);
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
  struct download_status *statuses = NULL;

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
  read_download_status(stderr, us->status_file, f, &exit_code, &count, &statuses);
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
super_serve_op_UPDATE_FROM_POLYGON_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0, lcaps = 0;
  struct sid_state *ss = phr->ss;
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  const unsigned char *cl;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *saved_login = NULL;
  unsigned char *saved_password = NULL;
  unsigned char *saved_url = NULL;
  int contest_id = 0;
  const struct contest_desc *cnts = NULL;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(SSERV_ERR_INV_CONTEST);

  get_global_caps(phr, &caps);
  get_contest_caps(phr, cnts, &lcaps);
  caps |= lcaps;

  if (opcaps_check(lcaps, OPCAP_EDIT_CONTEST) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (ss->update_state) {
    ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);
    goto cleanup;
  }

  get_saved_auth(phr->login, &saved_login, &saved_password, &saved_url);
  if (!saved_login) saved_login = xstrdup("");
  if (!saved_password) saved_password = xstrdup("");
  if (!saved_url) saved_url = xstrdup("");

  snprintf(buf, sizeof(buf), "serve-control: %s, updating problem from polygon", phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%sDetails</a></li>\n",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url, NULL,
                        "contest_id=%d&action=%d", contest_id,
                        SSERV_CMD_CONTEST_PAGE));
  fprintf(out_f, "</ul>");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_id", "%d", contest_id);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);

  fprintf(out_f, "<tr><td colspan=\"2\" align=\"center\"%s><b>Polygon information</b></td></tr>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s</b> *:</td><td%s><input type=\"text\" size=\"40\" name=\"polygon_login\" value=\"%s\" /></td></tr>\n",
          cl, "Login", cl, ARMOR(saved_login));
  fprintf(out_f, "<tr><td%s><b>%s</b> *:</td><td%s><input type=\"password\" size=\"40\" name=\"polygon_password\" value=\"%s\"  /></td></tr>\n",
          cl, "Password", cl, ARMOR(saved_password));

  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" checked=\"checked\" /></td></tr>\n",
          cl, "Save auth info", cl, "save_auth");
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"text\" size=\"60\" name=\"polygon_url\" value=\"%s\" /></td></tr>\n",
          cl, "Polygon URL", cl, ARMOR(saved_url));
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" checked=\"checked\" /></td></tr>\n",
          cl, "Ignore additional solutions", cl, "ignore_solutions");
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" /></td></tr>\n",
          cl, "Fetch latest available packet (do not generate)", cl, "fetch_latest_available");
  
  fprintf(out_f, "<tr><td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></tr></td>\n",
          cl, SSERV_CMD_UPDATE_FROM_POLYGON_ACTION, "Update");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  xfree(saved_login);
  xfree(saved_password);
  xfree(saved_url);
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
  int save_auth_flag = 0;
  int ignore_solutions_flag = 0;
  int fetch_latest_available_flag = 0;
  struct polygon_packet *pp = NULL;
  const struct contest_desc *cnts = NULL;
  struct update_state *us = NULL;
  FILE *f = NULL;
  int contest_id = 0;
  int free_edited_cnts_flag = 0;

  hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  if (contest_id <= 0) FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts) FAIL(SSERV_ERR_INV_CONTEST);

  get_global_caps(phr, &caps);
  get_contest_caps(phr, cnts, &lcaps);
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

  if (hr_cgi_param(phr, "save_auth", &s) > 0) save_auth_flag = 1;

  if (hr_cgi_param(phr, "ignore_solutions", &s) > 0) ignore_solutions_flag = 1;
  if (hr_cgi_param(phr, "fetch_latest_available", &s) > 0) fetch_latest_available_flag = 1;

  if ((r = hr_cgi_param(phr, "polygon_url", &s)) < 0) {
    fprintf(log_f, "polygon url is invalid\n");
    FAIL(SSERV_ERR_INV_OPER);
  } else if (r > 0) {
    polygon_url = fix_string_2(s);
  }

  if (save_auth_flag) {
    save_auth(phr->login, polygon_login, polygon_password, polygon_url);
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
  pp->ignore_solutions = ignore_solutions_flag;
  pp->fetch_latest_available = fetch_latest_available_flag;
  pp->polygon_url = polygon_url; polygon_url = NULL;
  pp->login = polygon_login; polygon_login = NULL;
  pp->password = polygon_password; polygon_password = NULL;
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

  get_global_caps(phr, &caps);

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
  get_global_caps(phr, &caps);

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

int
super_serve_op_IMPORT_CONTEST_FROM_POLYGON_PAGE(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  opcap_t caps = 0, lcaps = 0;
  struct sid_state *ss = phr->ss;
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  unsigned char prob_buf[64];
  const unsigned char *cl;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *saved_login = NULL;
  unsigned char *saved_password = NULL;
  unsigned char *saved_url = NULL;

  if (!ss->edited_cnts || !ss->global) {
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  }

  get_global_caps(phr, &caps);
  get_contest_caps(phr, ss->edited_cnts, &lcaps);
  caps |= lcaps;

  if (opcaps_check(lcaps, OPCAP_EDIT_CONTEST) < 0) {
    FAIL(SSERV_ERR_PERM_DENIED);
  }

  if (ss->global->advanced_layout <= 0) {
    fprintf(log_f, "advanced_layout must be set\n");
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (ss->update_state) {
    ss_redirect(out_f, phr, SSERV_CMD_DOWNLOAD_PROGRESS_PAGE, NULL);
    goto cleanup;
  }

  int prob_id = find_free_prob_id(ss);
  problem_id_to_short_name(prob_id - 1, prob_buf);

  get_saved_auth(phr->login, &saved_login, &saved_password, &saved_url);
  if (!saved_login) saved_login = xstrdup("");
  if (!saved_password) saved_password = xstrdup("");
  if (!saved_url) saved_url = xstrdup("");

  snprintf(buf, sizeof(buf), "serve-control: %s, importing contest from polygon", phr->html_name);
  ss_write_html_header(out_f, phr, buf);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE),
          "General settings (contest.xml)");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_EDIT_CUR_GLOBAL_PAGE),
          "Global settings (serve.cfg)");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE),
          "Language settings (serve.cfg)");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE),
          "Problems (serve.cfg)");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d",
                        SSERV_CMD_CNTS_START_EDIT_VARIANT_ACTION),
          "Variants (variant.map)");
  fprintf(out_f, "</ul>");

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "contest_mode", "%d", 1);
  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s>\n", cl);

  fprintf(out_f, "<tr><td%s><b>%s</b>:</td><td%s>"
          "<select name=\"language_priority\">"
          "<option></option"
          "<option>ru,en</option>"
          "<option>en,ru</option>"
          "</select>"
          "</td></tr>\n",
          cl, "Language priority", cl);

  fprintf(out_f, "<tr><td colspan=\"2\" align=\"center\"%s><b>Polygon information</b></td></tr>\n", cl);
  fprintf(out_f, "<tr><td%s><b>%s</b> *:</td><td%s><input type=\"text\" size=\"40\" name=\"polygon_login\" value=\"%s\" /></td></tr>\n",
          cl, "Login", cl, ARMOR(saved_login));
  fprintf(out_f, "<tr><td%s><b>%s</b> *:</td><td%s><input type=\"password\" size=\"40\" name=\"polygon_password\" value=\"%s\"  /></td></tr>\n",
          cl, "Password", cl, ARMOR(saved_password));

  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" checked=\"checked\" /></td></tr>\n",
          cl, "Save auth info", cl, "save_auth");
  fprintf(out_f, "<tr><td%s><b>%s</b> *:</td><td%s><input type=\"text\" size=\"60\" name=\"polygon_contest_id\" /></td></tr>\n",
          cl, "Contest id/name", cl);
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"text\" size=\"60\" name=\"polygon_url\" value=\"%s\" /></td></tr>\n",
          cl, "Polygon URL", cl, ARMOR(saved_url));
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" checked=\"checked\" /></td></tr>\n",
          cl, "Assume max_vm_size == max_stack_size", cl, "max_stack_size");
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" checked=\"checked\" /></td></tr>\n",
          cl, "Ignore additional solutions", cl, "ignore_solutions");
  fprintf(out_f, "<tr><td%s>%s:</td><td%s><input type=\"checkbox\" name=\"%s\" value=\"1\" /></td></tr>\n",
          cl, "Fetch latest available packet (do not generate)", cl, "fetch_latest_available");
  
  fprintf(out_f, "<tr><td%s><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></tr></td>\n",
          cl, SSERV_CMD_IMPORT_FROM_POLYGON_ACTION, "Import");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

cleanup:
  html_armor_free(&ab);
  xfree(saved_login);
  xfree(saved_password);
  xfree(saved_url);
  return retval;
}
