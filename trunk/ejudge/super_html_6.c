/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2011 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_limits.h"

#include "super_html.h"
#include "super-serve.h"
#include "super_proto.h"
#include "mischtml.h"
#include "userlist_proto.h"
#include "userlist_clnt.h"
#include "userlist.h"
#include "misctext.h"
#include "errlog.h"
#include "xml_utils.h"
#include "ejudge_cfg.h"

#include "reuse_xalloc.h"

#include <stdarg.h>

#define ARMOR(s)  html_armor_buf(&ab, (s))
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

#define FIRST_COOKIE(u) ((struct userlist_cookie*) (u)->cookies->first_down)
#define NEXT_COOKIE(c)  ((struct userlist_cookie*) (c)->b.right)
#define FIRST_CONTEST(u) ((struct userlist_contest*)(u)->contests->first_down)
#define NEXT_CONTEST(c)  ((struct userlist_contest*)(c)->b.right)

unsigned char *
ss_url_unescaped(
        unsigned char *buf,
        size_t size,
        const struct super_http_request_info *phr,
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
        struct super_http_request_info *phr,
        int new_op,
        const unsigned char *extra)
{
  unsigned char url[1024];

  if (extra && *extra) {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, "%s", extra);
  } else {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, 0);
  }

  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s\n\n", EJUDGE_CHARSET, url);
}

void
ss_redirect_2(
        FILE *fout,
        struct super_http_request_info *phr,
        int new_op,
        int contest_id,
        int group_id,
        int other_user_id)
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
  fclose(o_out); o_out = 0;

  if (o_str && *o_str) {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, "%s", o_str);
  } else {
    ss_url_unescaped(url, sizeof(url), phr, SSERV_CMD_HTTP_REQUEST, new_op, 0);
  }

  xfree(o_str); o_str = 0; o_len = 0;

  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s\n\n", EJUDGE_CHARSET, url);
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
get_global_caps(struct super_http_request_info *phr, opcap_t *pcap)
{
  return opcaps_find(&phr->config->capabilities, phr->login, pcap);
}

static int
is_globally_privileged(struct super_http_request_info *phr, const struct userlist_user *u)
{
  opcap_t caps = 0;
  if (u->is_privileged) return 1;
  if (opcaps_find(&phr->config->capabilities, u->login, &caps) >= 0) return 1;
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

int
super_serve_op_browse_users(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, r;
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  unsigned char *xml_text = 0;
  const unsigned char *user_filter = 0;
  int user_offset = 0;
  int user_count = 20;
  const unsigned char *s;
  struct userlist_list *users = 0;
  int user_id, serial;
  const struct userlist_user *u;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *cl;
  int contest_id = 0, group_id = 0;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
  const struct contest_desc *cnts = 0;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

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

  hbuf[0] = 0;
  if (contest_id > 0 && group_id > 0) {
    snprintf(hbuf, sizeof(hbuf), " for contest %d, group %d", contest_id, group_id);
  } else if (contest_id > 0) {
    snprintf(hbuf, sizeof(hbuf), " for contest %d", contest_id);
  } else if (group_id > 0) {
    snprintf(hbuf, sizeof(hbuf), " for group %d", group_id);
  }
  snprintf(buf, sizeof(buf), "serve-control: %s, browsing users%s",
           phr->html_name, hbuf);
  ss_write_html_header(out_f, phr, buf, 1, 0);

  fprintf(out_f, "<script language=\"javascript\">\n");
  fprintf(out_f,
          "function setAllCheckboxes(value)\n"
          "{\n"
          "  objs = document.forms[1].elements;\n"
          "  if (objs != null) {\n"
          "    for (var i = 0; i < objs.length; ++i) {\n"
          "      if (objs[i].type == \"checkbox\") {\n"
          "        objs[i].checked = value;\n"
          "      }\n"
          "    }\n"
          "  }\n"
          "}\n");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
            "Browse all users");
  }
  fprintf(out_f, "</ul>\n");

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  if (phr->ss->user_filter_set) {
    user_filter = phr->ss->user_filter;
    user_offset = phr->ss->user_offset;
    user_count = phr->ss->user_count;
  }

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  fprintf(out_f, "<table class=\"b0\">");
  s = user_filter;
  if (!s) s = "";
  fprintf(out_f, "<!--<tr><td class=\"b0\">Filter:</td><td class=\"b0\">%s</td></tr>-->",
          html_input_text(buf, sizeof(buf), "user_filter", 50, "%s", ARMOR(s)));
  hbuf[0] = 0;
  if (phr->ss->user_filter_set) {
    snprintf(hbuf, sizeof(hbuf), "%d", user_offset);
  }
  fprintf(out_f, "<tr><td class=\"b0\">Offset:</td><td class=\"b0\">%s</td></tr>",
          html_input_text(buf, sizeof(buf), "user_offset", 10, "%s", hbuf));
  hbuf[0] = 0;
  if (phr->ss->user_filter_set) {
    snprintf(hbuf, sizeof(hbuf), "%d", user_count);
  }
  fprintf(out_f, "<tr><td class=\"b0\">Count:</td><td class=\"b0\">%s</td></tr>",
          html_input_text(buf, sizeof(buf), "user_count", 10, "%s", hbuf));
  fprintf(out_f, "<tr><td class=\"b0\">&nbsp;</td><td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td></tr>",
          SSERV_OP_CHANGE_USER_FILTER_ACTION, "Change");
  fprintf(out_f, "</table>");
  fprintf(out_f, "<table class=\"b0\"><tr>");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_OP_USER_FILTER_FIRST_PAGE_ACTION, "&lt;&lt;");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_OP_USER_FILTER_PREV_PAGE_ACTION, "&lt;");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_OP_USER_FILTER_NEXT_PAGE_ACTION, "&gt;");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_OP_USER_FILTER_LAST_PAGE_ACTION, "&gt;&gt;");
  fprintf(out_f, "</tr></table>\n");
  fprintf(out_f, "</form>\n");

  r = userlist_clnt_list_users_2(phr->userlist_clnt, ULS_LIST_ALL_USERS_2,
                                 contest_id, group_id, user_filter, user_offset, user_count,
                                 &xml_text);
  if (r < 0) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>Cannot get user list: %s</pre>\n",
            userlist_strerror(-r));
    goto do_footer;
  }
  users = userlist_parse_str(xml_text);
  if (!users) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>XML parse error</pre>\n");
    goto do_footer;
  }

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  if (contest_id > 0) {
    html_hidden(out_f, "contest_id", "%d", contest_id);
  }
  if (group_id > 0) {
    html_hidden(out_f, "group_id", "%d", group_id);
  }
  cl = " class=\"b1\"";
  fprintf(out_f, "<table%s>\n", cl);

  fprintf(out_f, "<tr>");
  fprintf(out_f, "<th%s>&nbsp;</th>", cl);
  fprintf(out_f, "<th%s>NN</th>", cl);
  fprintf(out_f, "<th%s>User Id</th>", cl);
  fprintf(out_f, "<th%s>User Login</th>", cl);
  fprintf(out_f, "<th%s>E-mail</th>", cl);
  fprintf(out_f, "<th%s>Name</th>", cl);
  //fprintf(out_f, "<th%s>Flags</th>", cl);
  fprintf(out_f, "<th%s>Operations</th>", cl);
  fprintf(out_f, "</tr>\n");

  serial = user_offset - 1;
  for (user_id = 1; user_id < users->user_map_size; ++user_id) {
    if (!(u = users->user_map[user_id])) continue;
    ++serial;
    fprintf(out_f, "<tr>\n");
    fprintf(out_f, "<td class=\"b1\"><input type=\"checkbox\" name=\"user_%d\"/></td>", user_id);
    fprintf(out_f, "<td class=\"b1\">%d</td>", serial);
    fprintf(out_f, "<td class=\"b1\">%d</td>", user_id);
    if (!u->login) {
      fprintf(out_f, "<td class=\"b1\"><i>NULL</i></td>");
    } else {
      fprintf(out_f, "<td class=\"b1\"><tt>%s</tt></td>", ARMOR(u->login));
    }
    if (!u->email) {
      fprintf(out_f, "<td class=\"b1\"><i>NULL</i></td>");
    } else {
      fprintf(out_f, "<td class=\"b1\"><tt>%s</tt></td>", ARMOR(u->email));
    }
    if (!u->cnts0 || !u->cnts0->name) {
      fprintf(out_f, "<td class=\"b1\"><i>NULL</i></td>");
    } else {
      fprintf(out_f, "<td class=\"b1\"><tt>%s</tt></td>", ARMOR(u->cnts0->name));
    }
    /*
    int flags_count = 0;
    fprintf(out_f, "<td class=\"b1\">");
    if (u->is_privileged) {
      if (flags_count > 0) fprintf(out_f, ", ");
      fprintf(out_f, "privileged");
      ++flags_count;
    }
    if (u->is_invisible) {
      if (flags_count > 0) fprintf(out_f, ", ");
      fprintf(out_f, "invisible");
      ++flags_count;
    }
    if (u->is_banned) {
      if (flags_count > 0) fprintf(out_f, ", ");
      fprintf(out_f, "banned");
      ++flags_count;
    }
    if (u->is_locked) {
      if (flags_count > 0) fprintf(out_f, ", ");
      fprintf(out_f, "locked");
      ++flags_count;
    }
    if (u->show_login) {
      if (flags_count > 0) fprintf(out_f, ", ");
      fprintf(out_f, "show_login");
      ++flags_count;
    }
    if (u->show_email) {
      if (flags_count > 0) fprintf(out_f, ", ");
      fprintf(out_f, "show_email");
      ++flags_count;
    }
    if (u->read_only) {
      if (flags_count > 0) fprintf(out_f, ", ");
      fprintf(out_f, "read_only");
      ++flags_count;
    }
    if (u->never_clean) {
      if (flags_count > 0) fprintf(out_f, ", ");
      fprintf(out_f, "never_clean");
      ++flags_count;
    }
    if (u->simple_registration) {
      if (flags_count > 0) fprintf(out_f, ", ");
      fprintf(out_f, "simple_reg");
      ++flags_count;
    }
    if (!flags_count) {
      fprintf(out_f, "&nbsp;");
    }
    fprintf(out_f, "</td>");
    */
    fprintf(out_f, "<td%s>", cl);
    fprintf(out_f, "%s%s</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DETAIL_PAGE,
                          user_id, contest_id_str, group_id_str),
            "[Details]");
    fprintf(out_f, "&nbsp;%s%s</a>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_PASSWORD_PAGE,
                          user_id, contest_id_str, group_id_str),
            "[Reg. password]");
    if (contest_id > 0) {
      fprintf(out_f, "&nbsp;%s%s</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                            SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CNTS_PASSWORD_PAGE,
                            user_id, contest_id_str, group_id_str),
              "[Cnts. password]");
    }
    fprintf(out_f, "</td>");
    fprintf(out_f, "</tr>\n");
  }
  fprintf(out_f, "</table>\n");

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr>", cl);
  fprintf(out_f, "<td%s><a onclick=\"setAllCheckboxes(true)\">Mark All</a></td>", cl);
  fprintf(out_f, "<td%s><a onclick=\"setAllCheckboxes(false)\">Unmark All</a></td>", cl);
  fprintf(out_f, "</tr></table>\n");
  fprintf(out_f, "</form>\n");

  cl = " class=\"b0\"";
  fprintf(out_f, "<table%s><tr>", cl);
  fprintf(out_f, "<td%s>%s[%s]</a></td>", cl,
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CREATE_ONE_PAGE,
                        contest_id_str, group_id_str),
          "Create one new user");
  fprintf(out_f, "<td%s>%s[%s]</a></td>", cl,
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CREATE_MANY_PAGE,
                        contest_id_str, group_id_str),
          "Create MANY new users");
  fprintf(out_f, "<td%s>%s[%s]</a></td>", cl,
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CREATE_FROM_CSV_PAGE,
                        contest_id_str, group_id_str),
          "Create users from a CSV table");
  fprintf(out_f, "</tr></table>\n");

do_footer:
  ss_write_html_footer(out_f);

  userlist_free(&users->b); users = 0;
  xfree(xml_text); xml_text = 0;
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_set_user_filter(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  long long total_count = 0;
  int user_offset = 0;
  int user_count = 0;
  int value, r;
  int contest_id = 0, group_id = 0;
  const struct contest_desc *cnts = 0;
  unsigned char extra[256];

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id < 0) contest_id = 0;
  if (contest_id > 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }
  if (group_id < 0) group_id = 0;

  extra[0] = 0;
  if (contest_id > 0 && group_id > 0) {
    snprintf(extra, sizeof(extra), "contest_id=%d&group_id=%d",
             contest_id, group_id);
  } else if (contest_id > 0) {
    snprintf(extra, sizeof(extra), "contest_id=%d", contest_id);
  } else if (group_id > 0) {
    snprintf(extra, sizeof(extra), "group_id=%d", group_id);
  }

  if (!phr->userlist_clnt) {
    goto cleanup;
  }
  if ((r = userlist_clnt_get_count(phr->userlist_clnt, ULS_GET_USER_COUNT,
                                   contest_id, group_id, 0, &total_count)) < 0) {
    err("set_user_filter: get_count failed: %d", -r);
    goto cleanup;
  }
  if (total_count <= 0) goto cleanup;
  if (phr->ss->user_filter_set) {
    user_offset = phr->ss->user_offset;
    user_count = phr->ss->user_count;
  }

  switch (phr->opcode) {
  case SSERV_OP_CHANGE_USER_FILTER_ACTION:
    if (ss_cgi_param_int(phr, "user_offset", &value) >= 0) {
      user_offset = value;
    }
    if (ss_cgi_param_int(phr, "user_count", &value) >= 0) {
      user_count = value;
    }
    break;

  case SSERV_OP_USER_FILTER_FIRST_PAGE_ACTION:
    user_offset = 0;
    break;
  case SSERV_OP_USER_FILTER_PREV_PAGE_ACTION:
    user_offset -= user_count;
    break;
  case SSERV_OP_USER_FILTER_NEXT_PAGE_ACTION:
    user_offset += user_count;
    break;
  case SSERV_OP_USER_FILTER_LAST_PAGE_ACTION:
    user_offset = total_count;
    break;
  }

  if (user_count <= 0) user_count = 20;
  if (user_count > 200) user_count = 200;
  if (user_offset + user_count > total_count) {
    user_offset = total_count - user_count;
  }
  if (user_offset < 0) user_offset = 0;
  phr->ss->user_filter_set = 1;
  phr->ss->user_offset = user_offset;
  phr->ss->user_count = user_count;

cleanup:
  ss_redirect(out_f, phr, SSERV_OP_BROWSE_USERS_PAGE, extra);
  return retval;
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
  fprintf(out_f, "<td%s><input type=\"checkbox\" name=\"field_null_%s\" value=\"1\"%s /></td>",
          tdcl, param_suffix, checked);
  fprintf(out_f, "<td%s>%s</td>", tdcl,
          html_input_text(buf, sizeof(buf), param_name, 50, "%s", ARMOR(str)));
  fprintf(out_f, "<td%s>&nbsp;</td>", tdcl);
  fprintf(out_f, "</tr>\n");
  html_armor_free(&ab);
}

static const unsigned char * const reg_status_strs[] =
{
  "<font color=\"green\">OK</font>",
  "<font color=\"magenta\">Pending</font>",
  "<font color=\"red\">Rejected</font>",
  "<font color=\"red\"><b>Invalid status</b></font>",
};

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

int
super_serve_op_user_detail_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
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

  if (ss_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(S_ERR_INV_USER_ID);
  }
  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

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

  snprintf(buf, sizeof(buf), "serve-control: %s, viewing user %d",
           phr->html_name, other_user_id);
  ss_write_html_header(out_f, phr, buf, 1, 0);

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
          "}\n");
  fprintf(out_f, "</script>\n");

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_GROUPS_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          contest_id_str),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          group_id_str),
            "Browse users of group", group_id);
  }
  fprintf(out_f, "</ul>\n");

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  r = userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, contest_id, &xml_text);
  if (r < 0) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>Cannot get user information: %s</pre>\n",
            userlist_strerror(-r));
    goto do_footer;
  }
  if (!(u = userlist_parse_user_str(xml_text))) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>XML parse error</pre>\n");
    goto do_footer;
  }
  ui = u->cnts0;

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
  cl = " class=\"b1\"";
  fprintf(out_f, "<table%s id=\"UserData\">\n", cl);
  fprintf(out_f, "<tr><td%s colspan=\"4\" align=\"center\">", cl);
  fprintf(out_f, "%s%s</a>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id,
                        phr->self_url, NULL,
                        "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CANCEL_AND_PREV_ACTION,
                        other_user_id, contest_id_str, group_id_str),
          "Prev user");
  fprintf(out_f, "&nbsp;%s%s</a>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id,
                        phr->self_url, NULL,
                        "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CANCEL_AND_PREV_ACTION,
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
          html_input_text(buf, sizeof(hbuf), "other_login", 50, "%s", ARMOR(s)), cl);
  s = u->email;
  if (!s) s = "";
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
          cl, "User e-mail", cl, cl, 
          html_input_text(buf, sizeof(buf), "email", 50, "%s", ARMOR(s)), cl);
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
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_PASSWORD_PAGE,
                        other_user_id, SSERV_OP_USER_DETAIL_PAGE, contest_id_str, group_id_str),
          "[Change]");
  fprintf(out_f, "<tr class=\"StatRow1\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleStatVisibility(true)\">[%s]</a></td></tr>\n",
          cl, "Show user statistics");
  fprintf(out_f, "<tr class=\"StatRow2\" style=\"display: none;\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleStatVisibility(false)\">[%s]</a></td></tr>\n", cl, "Hide user statistics");

  static const struct user_row_info timestamp_rows[] =
  {
    { USERLIST_NN_REGISTRATION_TIME, "Registration time" },
    { USERLIST_NN_LAST_LOGIN_TIME, "Last login time" },
    { USERLIST_NN_LAST_CHANGE_TIME, "Last change time" },
    { USERLIST_NN_LAST_PWDCHANGE_TIME, "Last password change time" },
    { 0, 0 },
  };
  for (row = 0; timestamp_rows[row].field_id > 0; ++row) {
    fprintf(out_f, "<tr class=\"StatRow2\" style=\"display: none;\"><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
            cl, timestamp_rows[row].field_desc, cl, cl);
    time_t *pt = (time_t*) userlist_get_user_field_ptr(u, timestamp_rows[row].field_id);
    if (pt && *pt > 0) {
      fprintf(out_f, "%s</td><td%s>%s%s</a></td></tr>\n",
              xml_unparse_date(*pt), cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;field_id=%d%s%s",
                            SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CLEAR_FIELD_ACTION,
                            other_user_id, timestamp_rows[row].field_id,
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
  if (ui->cnts_read_only > 0) s = " checked=\"checked\"";
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s><input type=\"checkbox\" name=\"field_%d\" value=\"1\"%s /></td><td%s>&nbsp;</td></tr>\n",
          cl, "User data is read-only", cl, cl, USERLIST_NC_CNTS_READ_ONLY, s, cl);
  s = "";
  s2 = ui->name;
  if (!s2) {
    s = " checked=\"checked\"";
    s2 = "";
  }
  snprintf(hbuf, sizeof(hbuf), "field_%d", USERLIST_NC_NAME);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"field_null_%d\" value=\"1\"%s /></td><td%s>%s</td><td%s>&nbsp;</td></tr>\n",
          cl, "User name", cl, USERLIST_NC_NAME, s, cl, 
          html_input_text(buf, sizeof(buf), hbuf, 50, "%s", ARMOR(s2)), cl);
  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
          cl, "Contest password", cl, cl);
  if (!ui->team_passwd) {
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
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CNTS_PASSWORD_PAGE,
                        other_user_id, contest_id, group_id_str),
          "[Change]");

  fprintf(out_f, "<tr class=\"UserInfoRow1\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleUserInfoVisibility(true)\">[%s]</a></td></tr>\n",
          cl, "Show more user info fields");
  fprintf(out_f, "<tr class=\"UserInfoRow2\" style=\"display: none;\"><td colspan=\"4\"%s align=\"center\"><a onclick=\"toggleUserInfoVisibility(false)\">[%s]</a></td></tr>\n", cl, "Hide user info fields");

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
  for (row = 0; user_info_rows[row].field_id > 0; ++row) {
    s = 0;
    if (user_info_rows[row].field_id == USERLIST_NC_INSTNUM) {
      if (ui->instnum > 0) {
        snprintf(buf2, sizeof(buf2), "%d", ui->instnum);
        s = buf2;
      }
    } else {
      unsigned char **ps = (unsigned char**) userlist_get_user_info_field_ptr(ui, user_info_rows[row].field_id);
      if (!ps) continue;
      s = *ps;
    }
    snprintf(hbuf, sizeof(hbuf), "%d", user_info_rows[row].field_id);
    string_row(out_f, "UserInfoRow2", 1, "b1", user_info_rows[row].field_desc, hbuf, s);
  }

  static const struct user_row_info user_info_stat_rows[] =
  {
    { USERLIST_NC_CREATE_TIME, "Create time" },
    { USERLIST_NC_LAST_LOGIN_TIME, "Last login time" },
    { USERLIST_NC_LAST_CHANGE_TIME, "Last change time" },
    { USERLIST_NC_LAST_PWDCHANGE_TIME, "Last password change time" },

    { 0, 0 },
  };
  for (row = 0; user_info_stat_rows[row].field_id > 0; ++row) {
    fprintf(out_f, "<tr class=\"UserInfoRow2\" style=\"display: none;\"><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
            cl, user_info_stat_rows[row].field_desc, cl, cl);
    time_t *pt = (time_t*) userlist_get_user_info_field_ptr(ui, user_info_stat_rows[row].field_id);
    if (pt && *pt > 0) {
      fprintf(out_f, "%s</td><td%s>%s%s</a></td></tr>\n",
              xml_unparse_date(*pt), cl,
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;field_id=%d%s%s",
                            SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CLEAR_FIELD_ACTION,
                            other_user_id, user_info_stat_rows[row].field_id,
                            contest_id_str, group_id_str),
              "[Reset]");
    } else if (pt) {
      fprintf(out_f, "<i>Not set</i></td><td%s>&nbsp;</td></tr>\n", cl);
    } else {
      fprintf(out_f, "<i>Invalid field</i></td><td%s>&nbsp;</td></tr>\n", cl);
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
                              SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DELETE_MEMBER_PAGE,
                              other_user_id, m->serial, contest_id_str, group_id_str),
                "Delete");

        fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td%s><b>%s</b></td><td%s>&nbsp;</td><td%s>%d</td><td%s>&nbsp;</td></tr>\n",
                cl, "Member serial Id", cl, cl, m->serial, cl);

        snprintf(hbuf, sizeof(hbuf), "mfield_%d_%d", m->serial, USERLIST_NM_STATUS);
        fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td%s><b>%s</b></td><td%s>&nbsp;</td><td%s>",
                cl, "Status", cl, cl);
        ss_select(out_f, hbuf, (const unsigned char* []) { "Undefined", "School student", "Student", "Magistrant", "PhD student", "School teacher", "Professor", "Scientist", "Other", NULL }, m->status);
        fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);
        snprintf(hbuf, sizeof(hbuf), "mfield_%d_%d", m->serial, USERLIST_NM_GENDER);
        fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td%s><b>%s</b></td><td%s>&nbsp;</td><td%s>",
                cl, "Status", cl, cl);
        ss_select(out_f, hbuf, (const unsigned char* []) { "Undefined", "Male", "Female", NULL }, m->gender);
        fprintf(out_f, "</td><td%s>&nbsp;</td></tr>\n", cl);

        s = 0;
        if (m->grade > 0) {
          snprintf(buf2, sizeof(buf2), "%d", m->grade);
          s = buf2;
        }
        snprintf(hbuf, sizeof(hbuf), "%d_%d", m->serial, USERLIST_NM_GRADE);
        string_row(out_f, "MemberInfoRow2", 1, "b1", "Grade", hbuf, s);

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

        for (row = 0; member_rows[row].field_id > 0; ++row) {
          unsigned char **ps = (unsigned char**) userlist_get_member_field_ptr(m, member_rows[row].field_id);
          if (!ps) continue;
          s = *ps;
          snprintf(hbuf, sizeof(hbuf), "%d_%d", m->serial, member_rows[row].field_id);
          string_row(out_f, "MemberInfoRow2", 1, "b1", member_rows[row].field_desc, hbuf, s);
        }

        static const struct user_row_info member_date_rows[] =
        {
          { USERLIST_NM_BIRTH_DATE, "Date of birth" },
          { USERLIST_NM_ENTRY_DATE, "Date of entry" },
          { USERLIST_NM_GRADUATION_DATE, "Graduation date" },

          { 0, 0 },
        };

        for (row = 0; member_date_rows[row].field_id > 0; ++row) {
          time_t *pt = (time_t*) userlist_get_member_field_ptr(m, member_date_rows[row].field_id);
          if (!pt) continue;
          s = 0;
          if (*pt > 0) {
            userlist_get_member_field_str(buf2, sizeof(buf2), m, member_date_rows[row].field_id, 0, 0);
            s = buf2;
          }
          snprintf(hbuf, sizeof(hbuf), "%d_%d", m->serial, member_date_rows[row].field_id);
          string_row(out_f, "MemberInfoRow2", 1, "b1", member_date_rows[row].field_desc, hbuf, s);
        }

        static const struct user_row_info member_time_rows[] =
        {
          { USERLIST_NM_CREATE_TIME, "Create time" },
          { USERLIST_NM_LAST_CHANGE_TIME, "Last change time" },

          { 0, 0 },
        };

        for (row = 0; member_time_rows[row].field_id > 0; ++row) {
          fprintf(out_f, "<tr class=\"MemberInfoRow2\" style=\"display: none;\"><td%s><b>%s:</b></td><td%s>&nbsp;</td><td%s>",
                  cl, member_time_rows[row].field_desc, cl, cl);
          time_t *pt = (time_t*) userlist_get_member_field_ptr(m, member_time_rows[row].field_id);
          if (pt && *pt > 0) {
            fprintf(out_f, "%s</td><td%s>%s%s</a></td></tr>\n",
                    xml_unparse_date(*pt), cl,
                    html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                                  NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;field_id=%d%s%s",
                                  SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CLEAR_FIELD_ACTION,
                                  other_user_id, member_time_rows[row].field_id,
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
          SSERV_OP_USER_SAVE_AND_PREV_ACTION, "Save and goto PREV user");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_OP_USER_SAVE_ACTION, "Save and goto user list");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_OP_USER_SAVE_AND_NEXT_ACTION, "Save and goto NEXT user");
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "<tr><td%s colspan=\"4\" align=\"center\">", cl);
  fprintf(out_f, "<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_OP_USER_CANCEL_AND_PREV_ACTION, "Cancel and goto PREV user");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_OP_USER_CANCEL_ACTION, "Cancel and goto user list");
  fprintf(out_f, "&nbsp;<input type=\"submit\" name=\"op_%d\" value=\"%s\" />",
          SSERV_OP_USER_CANCEL_AND_NEXT_ACTION, "Cancel and goto NEXT user");
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
          SSERV_OP_USER_CREATE_MEMBER_ACTION, "Create member");
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
                                  SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DETAIL_PAGE,
                                  other_user_id, reg->id),
              "User details");
      fprintf(out_f, "&nbsp;%s[%s]</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;other_contest_id=%d%s%s",
                            SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_EDIT_REG_PAGE,
                            other_user_id, reg->id, contest_id_str, group_id_str),
              "Change");
      fprintf(out_f, "&nbsp;%s[%s]</a>",
              html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                            NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;other_contest_id=%d%s%s",
                            SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DELETE_REG_PAGE,
                            other_user_id, reg->id, contest_id_str, group_id_str),
              "Delete");

      fprintf(out_f, "</td>");
      fprintf(out_f, "</tr>\n");
    }
    fprintf(out_f, "</table>\n");
    fprintf(out_f, "<p>%s[%s]</a></p>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;other_user_id=%d",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_CREATE_REG_PAGE,
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
      fprintf(out_f, "<td%s>%s</td>", cl, xml_unparse_ip(cookie->ip));
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
                            SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DELETE_SESSION_ACTION,
                            other_user_id, cookie->cookie, contest_id_str, group_id_str),
              "Delete");
      fprintf(out_f, "</tr>");
    }

    fprintf(out_f, "</table>\n");
    fprintf(out_f, "<p>%s[%s]</a></p>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DELETE_ALL_SESSIONS_ACTION,
                          other_user_id, contest_id_str, group_id_str),
            "Delete all sessions");
    fprintf(out_f, "</div>\n");
  }

do_footer:
  ss_write_html_footer(out_f);

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_user_password_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, r;
  unsigned char buf[1024];
  int other_user_id = -1, contest_id = -1, group_id = -1, next_op = -1;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
  const struct contest_desc *cnts = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const unsigned char *cl = 0;
  const unsigned char *s = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024];

  if (ss_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(S_ERR_INV_USER_ID);
  }
  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  ss_cgi_param_int_opt(phr, "next_op", &next_op, 0);

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

  snprintf(buf, sizeof(buf), "serve-control: %s, change registration password for user %d",
           phr->html_name, other_user_id);
  ss_write_html_header(out_f, phr, buf, 1, 0);

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

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_GROUPS_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          contest_id_str),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          group_id_str),
            "Browse users of group", group_id);
  }
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DETAIL_PAGE,
                        other_user_id,
                        contest_id_str, group_id_str),
          "User details");
  fprintf(out_f, "</ul>\n");

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  r = userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, 0, &xml_text);
  if (r < 0) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>Cannot get user information: %s</pre>\n",
            userlist_strerror(-r));
    goto do_footer;
  }
  if (!(u = userlist_parse_user_str(xml_text))) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>XML parse error</pre>\n");
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
  html_hidden(out_f, "op", "%d", SSERV_OP_USER_CHANGE_PASSWORD_ACTION);
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
super_serve_op_user_cnts_password_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, r;
  unsigned char buf[1024];
  int other_user_id = -1, contest_id = -1, group_id = -1;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
  const struct contest_desc *cnts = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const unsigned char *cl = 0;
  const unsigned char *s = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024];

  if (ss_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(S_ERR_INV_USER_ID);
  }
  if (ss_cgi_param_int(phr, "contest_id", &contest_id) < 0) {
    FAIL(S_ERR_INV_CONTEST);
  }
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) {
      FAIL(S_ERR_INV_CONTEST);
    }
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

  snprintf(buf, sizeof(buf), "serve-control: %s, change contest password for user %d in contest %d",
           phr->html_name, other_user_id, contest_id);
  ss_write_html_header(out_f, phr, buf, 1, 0);

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

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_GROUPS_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          contest_id_str),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          group_id_str),
            "Browse users of group", group_id);
  }
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DETAIL_PAGE,
                        other_user_id,
                        contest_id_str, group_id_str),
          "User details");
  fprintf(out_f, "</ul>\n");

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  r = userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, contest_id, &xml_text);
  if (r < 0) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>Cannot get user information: %s</pre>\n",
            userlist_strerror(-r));
    goto do_footer;
  }
  if (!(u = userlist_parse_user_str(xml_text))) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>XML parse error</pre>\n");
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
  html_hidden(out_f, "op", "%d", SSERV_OP_USER_CHANGE_CNTS_PASSWORD_ACTION);
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
super_serve_op_user_create_reg_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, r;
  int other_user_id = 0, contest_id = 0, group_id = 0;
  const struct contest_desc *cnts = 0;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
  unsigned char buf[1024];
  unsigned char hbuf[1024];
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  const unsigned char *cl = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const int *cnts_id_list = 0;
  int cnts_id_count, i, other_contest_id_2;

  if (ss_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(S_ERR_INV_USER_ID);
  }
  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

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

  snprintf(buf, sizeof(buf), "serve-control: %s, create a contest registration for user %d",
           phr->html_name, other_user_id);
  ss_write_html_header(out_f, phr, buf, 1, 0);

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

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_GROUPS_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          contest_id_str),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          group_id_str),
            "Browse users of group", group_id);
  }
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DETAIL_PAGE,
                        other_user_id,
                        contest_id_str, group_id_str),
          "User details");
  fprintf(out_f, "</ul>\n");

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  r = userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, 0, &xml_text);
  if (r < 0) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>Cannot get user information: %s</pre>\n",
            userlist_strerror(-r));
    goto do_footer;
  }
  if (!(u = userlist_parse_user_str(xml_text))) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>XML parse error</pre>\n");
    goto do_footer;
  }

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
  html_hidden(out_f, "op", "%d", SSERV_OP_USER_CREATE_REG_ACTION);
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
  ss_select(out_f, hbuf, (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, 1);
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
super_serve_op_user_edit_reg_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, r;
  int other_user_id = 0, other_contest_id = 0, contest_id = 0, group_id = 0;
  const struct contest_desc *cnts = 0;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
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

  if (ss_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(S_ERR_INV_USER_ID);
  }
  if (ss_cgi_param_int(phr, "other_contest_id", &other_contest_id) < 0) {
    FAIL(S_ERR_INV_CONTEST);
  }
  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

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
    FAIL(S_ERR_INV_CONTEST);
  }
  if (contests_get(other_contest_id, &cnts) < 0 || !cnts) {
    FAIL(S_ERR_INV_CONTEST);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, edit the contest registration for user %d, contest %d",
           phr->html_name, other_user_id, other_contest_id);
  ss_write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_GROUPS_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          contest_id_str),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          group_id_str),
            "Browse users of group", group_id);
  }
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DETAIL_PAGE,
                        other_user_id,
                        contest_id_str, group_id_str),
          "User details");
  fprintf(out_f, "</ul>\n");

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  r = userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, 0, &xml_text);
  if (r < 0) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>Cannot get user information: %s</pre>\n",
            userlist_strerror(-r));
    goto do_footer;
  }
  if (!(u = userlist_parse_user_str(xml_text))) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>XML parse error</pre>\n");
    goto do_footer;
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
  html_hidden(out_f, "op", "%d", SSERV_OP_USER_EDIT_REG_ACTION);
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
  ss_select(out_f, hbuf, (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, r);
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
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;other_contest_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DELETE_REG_PAGE,
                        other_user_id, other_contest_id, contest_id_str, group_id_str),
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
super_serve_op_user_delete_reg_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, r;
  int other_user_id = 0, other_contest_id = 0, contest_id = 0, group_id = 0;
  const struct contest_desc *cnts = 0;
  unsigned char contest_id_str[128];
  unsigned char group_id_str[128];
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

  if (ss_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    FAIL(S_ERR_INV_USER_ID);
  }
  if (ss_cgi_param_int(phr, "other_contest_id", &other_contest_id) < 0) {
    FAIL(S_ERR_INV_CONTEST);
  }
  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

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
    FAIL(S_ERR_INV_CONTEST);
  }
  if (contests_get(other_contest_id, &cnts) < 0 || !cnts) {
    FAIL(S_ERR_INV_CONTEST);
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, delete the contest registration for user %d, contest %d",
           phr->html_name, other_user_id, other_contest_id);
  ss_write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_GROUPS_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          contest_id_str),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          group_id_str),
            "Browse users of group", group_id);
  }
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_DETAIL_PAGE,
                        other_user_id,
                        contest_id_str, group_id_str),
          "User details");
  fprintf(out_f, "</ul>\n");

  if (!phr->userlist_clnt) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>No connection to the server!</pre>\n");
    goto do_footer;
  }

  r = userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, 0, &xml_text);
  if (r < 0) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>Cannot get user information: %s</pre>\n",
            userlist_strerror(-r));
    goto do_footer;
  }
  if (!(u = userlist_parse_user_str(xml_text))) {
    fprintf(out_f, "<hr/><h2>Error</h2>\n");
    fprintf(out_f, "<pre>XML parse error</pre>\n");
    goto do_footer;
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
  html_hidden(out_f, "op", "%d", SSERV_OP_USER_EDIT_REG_ACTION);
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
                        NULL, "action=%d&amp;op=%d&amp;other_user_id=%d&amp;other_contest_id=%d%s%s",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_USER_EDIT_REG_PAGE,
                        other_user_id, other_contest_id, contest_id_str, group_id_str),
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
super_serve_op_user_create_one_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, row, i;
  int contest_id = 0, group_id = 0, other_contest_id_2 = 0;
  unsigned char contest_id_str[128], group_id_str[128];
  const struct contest_desc *cnts = 0;
  unsigned char buf[1024], hbuf[1024];
  const unsigned char *cl = 0;
  const int *cnts_id_list = 0;
  int cnts_id_count = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

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

  snprintf(buf, sizeof(buf), "serve-control: %s, create a new user",
           phr->html_name);
  ss_write_html_header(out_f, phr, buf, 1, 0);

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

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_GROUPS_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          contest_id_str),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          group_id_str),
            "Browse users of group", group_id);
  }
  fprintf(out_f, "</ul>\n");

  html_start_form_id(out_f, 1, phr->self_url, "CreateForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "op", "%d", SSERV_OP_USER_CREATE_ONE_ACTION);
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

  cnts_id_count = contests_get_list(&cnts_id_list);
  if (cnts_id_count <= 0 || !cnts_id_list) {
    cnts_id_count = 0;
    cnts_id_list = 0;
  }

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
  ss_select(out_f, hbuf, (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, 1);
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

  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"password\" name=\"cnts_password1\" size=\"40\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Contest password", cl, cl);
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"password\" name=\"cnts_password2\" size=\"40\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Confirm password", cl, cl);
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"cnts_random\" size=\"40\" /></td><td%s><a onclick=\"generateRandomCntsPassword()\">[%s]</a>&nbsp;<a onclick=\"copyRandomCntsPassword()\">[%s]</a>&nbsp;<a onclick=\"copyRegPassword()\">[%s]</a></td></tr>\n",
          cl, "Random password", cl, cl, "Generate", "Copy", "Copy reg. password");
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_sha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
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

  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_user_create_many_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, row, i;
  int contest_id = 0, group_id = 0, other_contest_id_2 = 0;
  unsigned char contest_id_str[128], group_id_str[128];
  const struct contest_desc *cnts = 0;
  unsigned char buf[1024], hbuf[1024];
  const unsigned char *cl = 0;
  const int *cnts_id_list = 0;
  int cnts_id_count = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

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

  snprintf(buf, sizeof(buf), "serve-control: %s, create many new users",
           phr->html_name);
  ss_write_html_header(out_f, phr, buf, 1, 0);

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
          "  if (obj.checked) {\n"
          "    changeCntsUseRegPassword();\n"
          "  }\n"
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
          "function changeRandomRegPassword()\n"
          "{\n"
          "  var form_obj = document.getElementById(\"CreateForm\");\n"
          "  var vis = \"\";\n"
          "  if (form_obj.reg_random.checked) vis = \"none\";\n"
          "  document.getElementById(\"RegPasswordTemplateRow\").style.display = vis;\n"
          "  document.getElementById(\"RegPasswordSha1Row\").style.display = vis;\n"
          "}\n"
          "function changeCntsUseRegPassword()\n"
          "{\n"
          "  var form_obj = document.getElementById(\"CreateForm\");\n"
          "  var vis = \"\";\n"
          "  if (form_obj.cnts_password_use_reg.checked) {\n"
          "    vis = \"none\";\n"
          "    document.getElementById(\"CntsPasswordTemplateRow\").style.display = vis;\n"
          "    document.getElementById(\"CntsPasswordSha1Row\").style.display = vis;\n"
          "  } else {\n"
          "    changeRandomCntsPassword()\n"
          "  }\n"
          "  document.getElementById(\"CntsPasswordRandomRow\").style.display = vis;\n"
          "}\n"
          "function changeRandomCntsPassword()\n"
          "{\n"
          "  var form_obj = document.getElementById(\"CreateForm\");\n"
          "  var vis = \"\";\n"
          "  if (form_obj.cnts_password_random.checked) vis = \"none\";\n"
          "  document.getElementById(\"CntsPasswordTemplateRow\").style.display = vis;\n"
          "  document.getElementById(\"CntsPasswordSha1Row\").style.display = vis;\n"
          "}\n"
          "");
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

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_GROUPS_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          contest_id_str),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          group_id_str),
            "Browse users of group", group_id);
  }
  fprintf(out_f, "</ul>\n");

  html_start_form_id(out_f, 1, phr->self_url, "CreateForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "op", "%d", SSERV_OP_USER_CREATE_MANY_ACTION);
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
  fprintf(out_f, "<tr id=\"RegPasswordTemplateRow\"><td%s><b>%s:</b></td><td%s><input type=\"text\" size=\"40\" name=\"password_template\" /></td><td%s>&nbsp;</td></tr>\n",
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

  cnts_id_count = contests_get_list(&cnts_id_list);
  if (cnts_id_count <= 0 || !cnts_id_list) {
    cnts_id_count = 0;
    cnts_id_list = 0;
  }

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
  ss_select(out_f, hbuf, (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, 1);
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

  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_password_use_reg\" onchange=\"changeCntsUseRegPassword()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use registration password", cl, cl);
  fprintf(out_f, "<tr id=\"CntsPasswordRandomRow\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_password_random\" onchange=\"changeRandomCntsPassword()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Random contest password", cl, cl);
  fprintf(out_f, "<tr id=\"CntsPasswordTemplateRow\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" name=\"cnts_password_template\" size=\"40\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Contest password template", cl, cl);
  fprintf(out_f, "<tr id=\"CntsPasswordSha1Row\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_sha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use SHA1", cl, cl);

  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"text\" size=\"40\" name=\"cnts_name\" /></td><td%s>&nbsp;</td></tr>\n",
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

  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_user_create_from_csv_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, row, i;
  int contest_id = 0, group_id = 0, other_contest_id_2 = 0;
  unsigned char contest_id_str[128], group_id_str[128];
  const struct contest_desc *cnts = 0;
  unsigned char buf[1024], hbuf[1024];
  const unsigned char *cl = 0;
  const int *cnts_id_list = 0;
  int cnts_id_count = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s;

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);

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

  snprintf(buf, sizeof(buf), "serve-control: %s, create users from a CSV file",
           phr->html_name);
  ss_write_html_header(out_f, phr, buf, 1, 0);

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

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE),
          "Browse users");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                        NULL, "action=%d&amp;op=%d",
                        SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_GROUPS_PAGE),
          "Browse groups");
  if (contest_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          contest_id_str),
            "Browse users of contest", contest_id);
  }
  if (group_id > 0) {
    fprintf(out_f, "<li>%s%s %d</a></li>",
            html_hyperref(hbuf, sizeof(hbuf), phr->session_id, phr->self_url,
                          NULL, "action=%d&amp;op=%d%s",
                          SSERV_CMD_HTTP_REQUEST, SSERV_OP_BROWSE_USERS_PAGE,
                          group_id_str),
            "Browse users of group", group_id);
  }
  fprintf(out_f, "</ul>\n");

  html_start_form_id(out_f, 2, phr->self_url, "CreateForm", "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "op", "%d", SSERV_OP_USER_CREATE_ONE_ACTION);
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

  cnts_id_count = contests_get_list(&cnts_id_list);
  if (cnts_id_count <= 0 || !cnts_id_list) {
    cnts_id_count = 0;
    cnts_id_list = 0;
  }

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
  ss_select(out_f, hbuf, (const unsigned char* []) { "OK", "Pending", "Rejected", NULL }, 1);
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

  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_password_use_reg\" onchange=\"changeCntsUseRegPassword()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Use registration password", cl, cl);
  fprintf(out_f, "<tr id=\"CntsPasswordRandomRow\" class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_password_random\" onchange=\"changeRandomCntsPassword()\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "Random contest password", cl, cl);
  fprintf(out_f, "<tr class=\"CntsRegRow\" style=\"display: none;\" ><td%s><b>%s:</b></td><td%s><input type=\"checkbox\" name=\"cnts_sha1\" value=\"1\" /></td><td%s>&nbsp;</td></tr>\n",
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

  fprintf(out_f, "<tr><td%s><b>%s:</b></td><td%s><input type=\"file\" name=\"csv_file\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, "CSV File", cl, cl);

  fprintf(out_f, "<tr><td%s>&nbsp;</td><td%s><input type=\"submit\" name=\"submit\" value=\"%s\" /></td><td%s>&nbsp;</td></tr>\n",
          cl, cl, "Create users", cl);
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  ss_write_html_footer(out_f);

  html_armor_free(&ab);
  return retval;
}

int
super_serve_op_user_change_password_action(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
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

  ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0);
  ss_cgi_param_int_opt(phr, "group_id", &group_id, 0);
  ss_cgi_param_int_opt(phr, "next_op", &next_op, 0);
  if (contest_id != 0) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) contest_id = 0;
  }

  s = 0;
  if (ss_cgi_param(phr, "reg_password1", &s) <= 0 || !s) FAIL(S_ERR_PASSWD1_UNDEF);
  reg_password1 = fix_string(s);
  if (!reg_password1 || !*reg_password1) FAIL(S_ERR_PASSWD1_UNDEF);
  if (strlen(reg_password1) > 1024) FAIL(S_ERR_INV_PASSWD1);
  s = 0;
  if (ss_cgi_param(phr, "reg_password2", &s) <= 0 || !s) FAIL(S_ERR_PASSWD2_UNDEF);
  reg_password2 = fix_string(s);
  if (!reg_password2 || !*reg_password2) FAIL(S_ERR_PASSWD2_UNDEF);
  if (strlen(reg_password2) > 1024) FAIL(S_ERR_INV_PASSWD2);
  if (strcmp(reg_password1, reg_password2) != 0) FAIL(S_ERR_PASSWDS_DIFFER);

  ss_cgi_param_int_opt(phr, "usesha1", &usesha1, 0);
  if (usesha1 != 1) usesha1 = 0;

  if (phr->priv_level <= 0) FAIL(S_ERR_PERM_DENIED);
  if (get_global_caps(phr, &caps) < 0) FAIL(S_ERR_PERM_DENIED);
  if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0 && opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0)
    FAIL(S_ERR_PERM_DENIED);

  if (ss_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) FAIL(S_ERR_INV_USER_ID);
  if (!phr->userlist_clnt) FAIL(S_ERR_NO_CONNECTION);
  r = userlist_clnt_get_info(phr->userlist_clnt, ULS_PRIV_GET_USER_INFO,
                             other_user_id, 0, &xml_text);
  if (r < 0) {
    if (r == -ULS_ERR_BAD_UID) FAIL(S_ERR_INV_USER_ID);
    FAIL(S_ERR_DB_ERROR);
  }
  if (!(u = userlist_parse_user_str(xml_text))) FAIL(S_ERR_DB_ERROR);
  if (is_globally_privileged(phr, u) && opcaps_check(caps, OPCAP_PRIV_EDIT_PASSWD) < 0)
    FAIL(S_ERR_PERM_DENIED);
  else if (opcaps_check(caps, OPCAP_EDIT_PASSWD) < 0)
    FAIL(S_ERR_PERM_DENIED);

  if (next_op == SSERV_OP_USER_DETAIL_PAGE) {
    ss_redirect_2(out_f, phr, SSERV_OP_USER_DETAIL_PAGE, contest_id, group_id, other_user_id);
  } else {
    ss_redirect_2(out_f, phr, SSERV_OP_BROWSE_USERS_PAGE, contest_id, group_id, 0);
  }

cleanup:
  userlist_free(&u->b); u = 0;
  xfree(xml_text); xml_text = 0;
  xfree(reg_password1); reg_password1 = 0;
  xfree(reg_password2); reg_password2 = 0;
  return retval;
}

int
super_serve_op_browse_groups(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  return retval;
}

int
super_serve_op_set_group_filter(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  return retval;
}
