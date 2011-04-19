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

#include "reuse_xalloc.h"

#define ARMOR(s)  html_armor_buf(&ab, (s))

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

  snprintf(buf, sizeof(buf), "serve-control: %s, browsing users",
           phr->html_name);
  ss_write_html_header(out_f, phr, buf, 1, 0);

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  fprintf(out_f, "<ul>");
  fprintf(out_f, "<li>%s%s</a></li>",
          html_hyperref(hbuf, sizeof(buf), phr->session_id, phr->self_url,
                        NULL, NULL),
          "Main page");
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
  fprintf(out_f, "<table class=\"b0\">");
  s = user_filter;
  if (!s) s = "";
  fprintf(out_f, "<tr><td class=\"b0\">Filter:</td><td class=\"b0\">%s</td></tr>",
          html_input_text(buf, sizeof(buf), "user_filter", 50, "%s", s));
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
          SSERV_OP_CHANGE_USER_FILTER, "Change");
  fprintf(out_f, "</table>");
  fprintf(out_f, "<table class=\"b0\"><tr>");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_OP_USER_FILTER_FIRST_PAGE, "&lt;&lt;");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_OP_USER_FILTER_PREV_PAGE, "&lt;");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_OP_USER_FILTER_NEXT_PAGE, "&gt;");
  fprintf(out_f, "<td class=\"b0\"><input type=\"submit\" name=\"op_%d\" value=\"%s\" /></td>", SSERV_OP_USER_FILTER_LAST_PAGE, "&gt;&gt;");
  fprintf(out_f, "</tr></table>\n");
  fprintf(out_f, "</form>\n");

  r = userlist_clnt_list_users_2(phr->userlist_clnt, ULS_LIST_ALL_USERS_2,
                                 0, user_filter, user_offset, user_count,
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

  fprintf(out_f, "<table class=\"b1\">\n");

  fprintf(out_f, "<tr>");
  fprintf(out_f, "<th class=\"b1\">NN</th>");
  fprintf(out_f, "<th class=\"b1\">User Id</th>");
  fprintf(out_f, "<th class=\"b1\">User Login</th>");
  fprintf(out_f, "<th class=\"b1\">E-mail</th>");
  fprintf(out_f, "</tr>\n");

  serial = user_offset - 1;
  for (user_id = 1; user_id < users->user_map_size; ++user_id) {
    if (!(u = users->user_map[user_id])) continue;
    ++serial;
    fprintf(out_f, "<tr>\n");
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
    fprintf(out_f, "</tr>\n");
  }

  fprintf(out_f, "</table>\n");

do_footer:
  ss_write_html_footer(out_f);

  userlist_free(&users->b); users = 0;
  xfree(xml_text); xml_text = 0;
  html_armor_free(&ab);
  return retval;
}
