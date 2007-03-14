/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_limits.h"

#include "new-server.h"
#include "new_server_proto.h"
#include "userlist_clnt.h"
#include "userlist_proto.h"
#include "contests.h"
#include "misctext.h"
#include "mischtml.h"
#include "xml_utils.h"
#include "l10n.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

#define ARMOR(s)  html_armor_buf(&ab, s)
#define URLARMOR(s)  url_armor_buf(&ab, s)
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)
#define FAIL2(c) do { retval = -(c); goto failed; } while (0)

static unsigned char *
get_client_url(
	unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const unsigned char *str)
{
  int i, len;

  if (cnts->team_url) {
    snprintf(buf, size, "%s", cnts->team_url);
    return buf;
  }

  if (!str) return "/new-client";
  len = strlen(str);
  for (i = len - 1; i >= 0 && str[i] != '/'; i--);
  if (i < 0) return "/new-client";
#if defined CGI_PROG_SUFFIX
  snprintf(buf, size, "%.*s/new-client%s", i, str, CGI_PROG_SUFFIX);
#else
  snprintf(buf, size, "%.*s/new-client", i, str);
#endif
  return buf;
}

static int
cgi_param_int(struct http_request_info *phr, const unsigned char *name,
              int *p_val)
{
  const unsigned char *s = 0;
  char *eptr = 0;
  int x;

  if (ns_cgi_param(phr, name, &s) <= 0) return -1;
  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno || *eptr) return -1;
  if (p_val) *p_val = x;
  return 0;
}

static int
check_str(const unsigned char *str, const unsigned char *map)
{
  if (!str) return 0;
  for (; *str; str++)
    if (!map[*str])
      return -1;
  return 0;
}

static void
html_refresh_page_2(FILE *fout, const unsigned char *url)
{
  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s\n\n", EJUDGE_CHARSET, url);
}

static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

static void
anon_select_contest_page(FILE *fout, struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *cntslist = 0;
  int cntsnum = 0;
  const unsigned char *cl;
  const struct contest_desc *cnts;
  time_t curtime = time(0);
  int row = 0, i, orig_locale_id;
  const unsigned char *s;
  const unsigned char *login = 0;
  unsigned char bb[1024];

  ns_cgi_param(phr, "login", &login);

  // defaulting to English as we have no contest chosen
  orig_locale_id = phr->locale_id;
  if (phr->locale_id < 0) phr->locale_id = 0;

  // even don't know about the contest specific settings
  l10n_setlocale(phr->locale_id);
  ns_header(fout, ns_fancy_header, 0, 0, 0, 0, phr->locale_id,
            _("Contest selection"));

  html_start_form(fout, 1, phr->self_url, "");
  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>\n");
  html_hidden(fout, "action", "%d", NEW_SRV_ACTION_CHANGE_LANGUAGE);
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: ",
          _("language"));
  l10n_html_locale_select(fout, phr->locale_id);
  fprintf(fout, "</div></td>\n");
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>\n", ns_submit_button(bb, sizeof(bb), "submit", 0, _("Change Language")));
  fprintf(fout, "</tr></table></div></form>\n");

  fprintf(fout,
          "<div class=\"white_empty_block\">&nbsp;</div>\n"
          "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");

  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td></tr></table></div>\n");

  fprintf(fout, "%s", ns_fancy_separator);

  fprintf(fout, "<h2>%s</h2>\n", _("Select one of available contests"));

  cntsnum = contests_get_list(&cntslist);
  cl = " class=\"summary\"";
  fprintf(fout, "<table%s><tr>"
          "<td%s>N</td><td%s>%s</td><td%s>%s</td><td%s>%s</td></tr>\n",
          cl, cl, cl, _("Contest name"), cl, _("Registration mode"),
          cl, _("Registration deadline"));
  for (i = 1; i < cntsnum; i++) {
    cnts = 0;
    if (contests_get(i, &cnts) < 0 || !cnts) continue;
    if (cnts->closed) continue;
    if (!contests_check_register_ip_2(cnts, phr->ip, phr->ssl_flag)) continue;
    if (cnts->reg_deadline > 0 && curtime >= cnts->reg_deadline) continue;

    fprintf(fout, "<tr%s><td%s>%d</td>", form_row_attrs[(row++) & 1], cl, i);
    fprintf(fout, "<td%s><a href=\"%s?contest_id=%d", cl, phr->self_url, i);

    if (orig_locale_id >= 0 && cnts->default_locale_val >= 0
        && orig_locale_id != cnts->default_locale_val) {
      fprintf(fout, "&amp;locale_id=%d", phr->locale_id);
    }

    if (login && *login) fprintf(fout, "&amp;login=%s", URLARMOR(login));
    s = 0;
    if (phr->locale_id == 0 && cnts->name_en) s = cnts->name_en;
    if (!s) s = cnts->name;
    fprintf(fout, "\">%s</a></td>", ARMOR(s));
    if (cnts->autoregister) s = _("open");
    else s = _("moderated");
    fprintf(fout, "<td%s>%s</td>", cl, s);
    if (cnts->reg_deadline > 0) {
      s = xml_unparse_date(cnts->reg_deadline);
    } else {
      s = "&nbsp;";
    }
    fprintf(fout, "<td%s>%s</td>", cl, s);
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "</table>\n");

  ns_footer(fout, ns_fancy_footer, 0, phr->locale_id);
  l10n_setlocale(0);

  html_armor_free(&ab);
  xfree(cntslist);
}

static void
login_page(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  const unsigned char *head_style = 0, *par_style = 0, *s;
  const unsigned char *login = 0, *password = 0, *email = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char bb[1024];
  int item_cnt = 0, created_mode = 0;
  unsigned char client_url[1024];

  if (cnts->register_head_style && *cnts->register_head_style)
    head_style = cnts->register_head_style;
  if (!head_style) head_style = "h2";
  if (cnts->register_par_style && *cnts->register_par_style)
    par_style = cnts->register_par_style;
  if (!par_style) par_style = "";
  get_client_url(client_url, sizeof(client_url), cnts, phr->self_url);

  ns_cgi_param(phr, "login", &login);
  if (!login) login = "";
  ns_cgi_param(phr, "password", &password);
  if (!password) password = "";
  ns_cgi_param(phr, "email", &email);
  if (!email) email = "";

  l10n_setlocale(phr->locale_id);
  switch (phr->action) {
  case NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE:
  case NEW_SRV_ACTION_REG_AUTOASSIGNED_ACCOUNT_CREATED_PAGE:
    s = _("Activate new user account");
    created_mode = 1;
    break;
  default:
  case NEW_SRV_ACTION_REG_LOGIN_PAGE:
    s = _("Log in to edit registration data");
    break;
  }
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s]", s, extra->contest_arm);

  html_start_form(fout, 1, phr->self_url, "");
  html_hidden(fout, "contest_id", "%d", phr->contest_id);
  html_hidden(fout, "next_action", "%d", phr->action);
  if (cnts->disable_locale_change)
    html_hidden(fout, "locale_id", "%d", phr->locale_id);
  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>\n");

  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: %s</div></td>", _("login"), html_input_text(bb, sizeof(bb), "login", 20, "%s", ARMOR(login)));
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: %s</div></td>", _("password"), html_input_password(bb, sizeof(bb), "password", 20, "%s", ARMOR(password)));
  if (!cnts->disable_locale_change) {
    fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: ",
            _("language"));
    l10n_html_locale_select(fout, phr->locale_id);
    fprintf(fout, "</div></td>\n");
    /*
    fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>\n", ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_CHANGE_LANGUAGE, _("Change Language")));
    */
  }
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>", ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_REG_LOGIN, _("Log in")));

  fprintf(fout, "</tr></table></div></form>\n");

  fprintf(fout,
          "<div class=\"white_empty_block\">&nbsp;</div>\n"
          "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");

  // "New account" "Forgot password?" "Enter contest"
  if (created_mode)
    s = _("Create another account");
  else
    s = _("Create account");
  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">%s</a></div></td>", phr->self_url, phr->contest_id, phr->locale_id, cnts->assign_logins?NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT_PAGE:NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE, s);
  item_cnt++;

  if (cnts->enable_forgot_password && cnts->disable_team_password
      && !cnts->simple_registration && !created_mode) {
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">%s</a></div></td>", client_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_FORGOT_PASSWORD_1, _("Recover forgot password"));
    item_cnt++;
  }

  /*
  if (client_url[0] && !created_mode) {
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d\">%s</a></div></td>", client_url, phr->contest_id, phr->locale_id, cnts->exam_mode?_("Take the exam"):_("Participate in the contest"));
    item_cnt++;
  }
  */

  if (!item_cnt)
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  fprintf(fout, "</tr></table></div>\n");

  fprintf(fout, "%s", extra->separator_txt);

  if (phr->action == NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE) {
    fprintf(fout, "<%s>%s</%s>\n", head_style,
            _("New user account is created"), head_style);
    fprintf(fout,
            _("<p%s>New account <tt>%s</tt> is successfully created. "
              "An e-mail messages is sent to the address <tt>%s</tt>. "
              "This message contains the password for the initial log in. You will be able to change the password later.</p>\n"
              "<p%s>Type the login and the password in to the form above and press the \"Log in\" button to activate the account.</p>\n"
              "<p%s><b>Note</b>, that you should log in to the system for "
              "the first time no later, than in 24 hours after this moment, "
              "or the new account is removed.</p>"),
            par_style, login, email, par_style, par_style);
  } else if (phr->action==NEW_SRV_ACTION_REG_AUTOASSIGNED_ACCOUNT_CREATED_PAGE){
    fprintf(fout, "<%s>%s</%s>\n", head_style,
            _("New user account is created"), head_style);

    fprintf(fout,
            _("<p%s>New account is successfully created. "
              "An e-mail messages is sent to the address <tt>%s</tt>. "
              "This message contains the login name, assigned to you, "
              "as well as your password for initial log in. You will be able to change the password later.</p>\n"
              "<p%s>Type the login and the password in to the form above and press the \"Log in\" button to activate the account.</p>\n"
              "<p%s><b>Note</b>, that you should log in to the system for "
              "the first time no later, than in 24 hours after this moment, "
              "or the new account is removed.</p>"),
            par_style, email, par_style, par_style);
  }

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

static void
create_autoassigned_account_page(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  const unsigned char *email = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char bb[1024];
  const unsigned char *head_style = 0, *par_style = 0;
  int item_cnt = 0, allowed_info_edit = 0;
  unsigned char client_url[1024] = { 0 };
  int i, j;
  int reg_error = 0, reg_ul_error = 0, regular_flag = 0;

  cgi_param_int(phr, "retval", &reg_error);
  cgi_param_int(phr, "ul_error", &reg_ul_error);
  cgi_param_int(phr, "regular", &regular_flag);

  if (cnts->register_head_style && *cnts->register_head_style)
    head_style = cnts->register_head_style;
  if (!head_style) head_style = "h2";
  if (cnts->register_par_style && *cnts->register_par_style)
    par_style = cnts->register_par_style;
  if (!par_style) par_style = "";

  if (!cnts->disable_name) allowed_info_edit = 1;
  if (!cnts->force_registration) allowed_info_edit = 1;
  if (!cnts->autoregister) allowed_info_edit = 1;
  for (j = 0; j < CONTEST_LAST_FIELD; j++)
    if (cnts->fields[j])
      allowed_info_edit = 1;
  for (i = 0; i < CONTEST_LAST_MEMBER; i++)
    if (cnts->members[i] && cnts->members[i]->max_count > 0)
      allowed_info_edit = 1;

  get_client_url(client_url, sizeof(client_url), cnts, phr->self_url);

  if (ns_cgi_param(phr, "email", &email) <= 0) email = 0;
  if (!email) email = "";

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s]", _("Create user account"),
            extra->contest_arm);

  html_start_form(fout, 1, phr->self_url, "");
  html_hidden(fout, "contest_id", "%d", phr->contest_id);
  html_hidden(fout, "next_action", "%d",
              NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT_PAGE);
  if (cnts->disable_locale_change)
    html_hidden(fout, "locale_id", "%d", phr->locale_id);
  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>\n");

  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">e-mail: %s</div></td>", html_input_text(bb, sizeof(bb), "email", 20, "%s", ARMOR(email)));

  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>", ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT, _("Create account")));

  if (!cnts->disable_locale_change) {
    fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: ",
            _("language"));
    l10n_html_locale_select(fout, phr->locale_id);
    fprintf(fout, "</div></td>\n");
    fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>\n", ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_CHANGE_LANGUAGE, _("Change language")));
  }

  fprintf(fout, "</tr></table></div></form>\n");

  fprintf(fout,
          "<div class=\"white_empty_block\">&nbsp;</div>\n"
          "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");

  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">%s</a></div></td>", phr->self_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_REG_LOGIN_PAGE, _("Use an existing account"));
  item_cnt++;
  if (!item_cnt)
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  fprintf(fout, "</tr></table></div>\n");

  fprintf(fout, "%s", extra->separator_txt);

  if (reg_error || reg_ul_error) {
    if (reg_error < 0) reg_error = -reg_error;
    if (reg_ul_error < 0) reg_ul_error = -reg_ul_error;

    fprintf(fout, "<%s><font color=\"red\">%s</font></%s>\n", head_style, _("Registration errors"),
            head_style);

    fprintf(fout, "<p%s><font color=\"red\">", par_style);
    if (reg_ul_error == ULS_ERR_EMAIL_FAILED) {
      fprintf(fout, "%s",
              _("The server was unable to send a registration e-mail\n"
                "to the specified address. This is probably due\n"
                "to heavy server load rather than to an invalid\n"
                "e-mail address. You should try to register later.\n"));
    } else if (reg_ul_error) {
      fprintf(fout, "%s.", gettext(userlist_strerror(-reg_ul_error)));
    } else if (reg_error) {
      fprintf(fout, "%s.", ns_strerror_2(reg_error));
    }
    fprintf(fout, "</font></p>\n");
  }

  fprintf(fout, "<%s>%s</%s>\n", head_style, _("Registration rules"),
          head_style);
  fprintf(fout, "<p%s>%s</p>\n", par_style,
          _("Please, enter your valid e-mail address and press the \"Create account\" button."));

  if (cnts->simple_registration && !regular_flag) {
    fprintf(fout, _("<p%s>This contest operates in \"simplified registration\" mode. You will get your login and password immediately after account is created. %s</p>"),
            par_style, cnts->send_passwd_email?_("An email message will be sent to you just for your convenience."):("No email message at all will be sent to you."));
    fprintf(fout, _("<p%s>Accounts created using simplified registration procedure cannot be used for participation in contests, which do not allow simplified registration. If you want a regular account, you may create an account using the <a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d&amp;regular=1\">regular registration</a>.</p>\n"),
            par_style,
            phr->self_url, phr->contest_id, phr->locale_id,
            NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT_PAGE);
  } else {
    if (cnts->simple_registration) {
      fprintf(fout, _("<p%s><a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">Simplified registration</a> is available for this contest. Note, however, that simplified registration imposes certain restrictions on further use of the account!</p>\n"), par_style, phr->self_url, phr->contest_id,
              phr->locale_id,
              NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT_PAGE);
    }

    if (!cnts->simple_registration || cnts->send_passwd_email) {
      fprintf(fout, "<p%s>%s</p>", par_style,
              _("Shortly after that you should receive an e-mail message "
                "with a password to the system. Use this password for the first"
                " log in. After the first login you will be able to change the password."));

      fprintf(fout, "<p%s>%s</p>", par_style,
              _("Be careful and type the e-mail address correctly. If you make a mistake, you will not receive a registration e-mail and be unable to complete the registration process."));
    }
  }

  fprintf(fout, "<p%s>%s</p>",
          par_style,
          _("<b>Note</b>, that you must log in "
            "24 hours after the form is filled and submitted, or "
            "your registration will be cancelled!"));

  fprintf(fout, _("<p%s>If you already have an ejudge account on this server, you may use it. If so, follow the <a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">\"Use an existing account\"</a> link.</p>"),
          par_style, phr->self_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_REG_LOGIN_PAGE);

  /*
  if (allowed_info_edit || client_url[0]) {
    fprintf(fout, "<p%s>%s", par_style, _("If you already have an ejudge account on this server, you may"));
    if (allowed_info_edit)
      fprintf(fout, " <a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">%s</a>", phr->self_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_REG_LOGIN_PAGE, cnts->personal?_("edit your personal information"):_("edit your team information"));
    if (allowed_info_edit && client_url[0]) fprintf(fout, _(" or"));
    if (client_url[0])
      fprintf(fout, " <a href=\"%s?contest_id=%d&amp;locale_id=%d\">%s</a>", client_url, phr->contest_id, phr->locale_id, cnts->exam_mode?_("take the exam"):_("participate in the contest"));
    fprintf(fout, ".</p>\n");
  }
  */

  fprintf(fout, "<p%s>&nbsp;</p>\n", par_style);

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

static void
create_account_page(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  const unsigned char *login = 0, *email = 0;
  int reg_error = 0, reg_ul_error = 0;
  const unsigned char *head_style = 0, *par_style = 0;
  unsigned char client_url[1024] = { 0 };
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char bb[1024];
  int item_cnt = 0, regular_flag = 0;

  cgi_param_int(phr, "retval", &reg_error);
  cgi_param_int(phr, "ul_error", &reg_ul_error);
  cgi_param_int(phr, "regular", &regular_flag);

  if (cnts->register_head_style && *cnts->register_head_style)
    head_style = cnts->register_head_style;
  if (!head_style) head_style = "h2";
  if (cnts->register_par_style && *cnts->register_par_style)
    par_style = cnts->register_par_style;
  if (!par_style) par_style = "";
  get_client_url(client_url, sizeof(client_url), cnts, phr->self_url);

  if (ns_cgi_param(phr, "login", &login) <= 0) login = 0;
  if (!login) login = "";
  if (ns_cgi_param(phr, "email", &email) <= 0) email = 0;
  if (!email) email = "";

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s]", _("Create user account"),
            extra->contest_arm);

  html_start_form(fout, 1, phr->self_url, "");
  html_hidden(fout, "contest_id", "%d", phr->contest_id);
  html_hidden(fout, "next_action", "%d",
              NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
  if (cnts->disable_locale_change)
    html_hidden(fout, "locale_id", "%d", phr->locale_id);
  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>\n");

  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: %s</div></td>", _("login"), html_input_text(bb, sizeof(bb), "login", 20, "%s", ARMOR(login)));
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">e-mail: %s</div></td>", html_input_text(bb, sizeof(bb), "email", 20, "%s", ARMOR(email)));

  if (!cnts->disable_locale_change) {
    fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: ",
            _("language"));
    l10n_html_locale_select(fout, phr->locale_id);
    fprintf(fout, "</div></td>\n");
    /*
    fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>\n", ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_CHANGE_LANGUAGE, _("Change language")));
    */
  }
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>", ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_REG_CREATE_ACCOUNT, _("Create account")));

  fprintf(fout, "</tr></table></div></form>\n");

  fprintf(fout,
          "<div class=\"white_empty_block\">&nbsp;</div>\n"
          "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");

  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">%s</a></div></td>", phr->self_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_REG_LOGIN_PAGE, _("Use an existing account"));
    item_cnt++;

  if (!item_cnt)
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  fprintf(fout, "</tr></table></div>\n");

  fprintf(fout, "%s", extra->separator_txt);

  if (reg_error || reg_ul_error) {
    if (reg_error < 0) reg_error = -reg_error;
    if (reg_ul_error < 0) reg_ul_error = -reg_ul_error;

    fprintf(fout, "<%s><font color=\"red\">%s</font></%s>\n", head_style, _("Registration errors"),
            head_style);

    fprintf(fout, "<p%s><font color=\"red\">", par_style);
    if (reg_ul_error == ULS_ERR_EMAIL_FAILED) {
      fprintf(fout, "%s",
              _("The server was unable to send a registration e-mail\n"
                "to the specified address. This is probably due\n"
                "to heavy server load rather than to an invalid\n"
                "e-mail address. You should try to register later.\n"));
    } else if (reg_ul_error) {
      fprintf(fout, "%s.", gettext(userlist_strerror(-reg_ul_error)));
    } else if (reg_error) {
      fprintf(fout, "%s.", ns_strerror_2(reg_error));
    }
    fprintf(fout, "</font></p>\n");
  }

  fprintf(fout, "<%s>%s</%s>\n", head_style, _("Registration rules"),
          head_style);

  fprintf(fout, _("<p%s>If you already have an ejudge account on this server, you may use it. If so, follow the <a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">\"Use an existing account\"</a> link.</p>"),
          par_style, phr->self_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_REG_LOGIN_PAGE);

  fprintf(fout, "<p%s>%s</p>\n", par_style,
          _("To create an account, please think out, a login and provide your valid e-mail address in the form above. Then press the \"Create account\" button."));
  fprintf(fout, "<p%s>%s</p>\n", par_style,
          _("Login may contain only latin letters, digits, <tt>.</tt> (dot), <tt>-</tt> (minus sign), <tt>_</tt> (undescore)."));

  if (cnts->simple_registration && !regular_flag) {
    fprintf(fout, _("<p%s>This contest operates in \"simplified registration\" mode. You will get your login and password immediately after account is created. %s</p>"),
            par_style, cnts->send_passwd_email?_("An email message will be sent to you just for your convenience."):("No email message at all will be sent to you."));
    fprintf(fout, _("<p%s>Accounts created using simplified registration procedure cannot be used for participation in contests, which do not allow simplified registration. If you want a regular account, you may create an account using the <a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d&amp;regular=1\">regular registration</a>.</p>\n"),
            par_style,
            phr->self_url, phr->contest_id, phr->locale_id,
            NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
  } else {
    if (cnts->simple_registration) {
      fprintf(fout, _("<p%s><a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">Simplified registration</a> is available for this contest. Note, however, that simplified registration imposes certain restrictions on further use of the account!</p>\n"), par_style, phr->self_url, phr->contest_id,
              phr->locale_id, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
    }

    if (!cnts->simple_registration || cnts->send_passwd_email) {
      fprintf(fout, "<p%s>%s</p>", par_style,
              _("Shortly after that you should receive an e-mail message "
                "with a password to the system. Use this password for the first"
                " log in. After the first login you will be able to change the password."));

      fprintf(fout, "<p%s>%s</p>", par_style,
              _("Be careful and type the e-mail address correctly. If you make a mistake, you will not receive a registration e-mail and be unable to complete the registration process."));
    }
  }

  fprintf(fout, "<p%s>%s</p>",
          par_style,
          _("<b>Note</b>, that you must log in "
            "24 hours after the form is filled and submitted, or "
            "your registration will be cancelled!"));

  fprintf(fout, "<p%s>&nbsp;</p>\n", par_style);

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

static unsigned char login_accept_chars[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1\0\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
static unsigned char email_accept_chars[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\0\0\0\1\0\0\0\0\0\1\0\1\1\0\1\1\1\1\1\1\1\1\1\1\0\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

static void
create_account(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *login = 0;
  const unsigned char *email = 0;
  int retval = 0, r, ul_error = 0, next_action;
  unsigned char urlbuf[1024];

  if (!cnts->assign_logins) {
    r = ns_cgi_param(phr, "login", &login);
    if (r < 0) FAIL2(NEW_SRV_ERR_LOGIN_BINARY);
    if (!r || !login) FAIL2(NEW_SRV_ERR_LOGIN_UNSPECIFIED);
    if (check_str(login, login_accept_chars) < 0)
      FAIL2(NEW_SRV_ERR_LOGIN_INV_CHARS);
  } else {
    login = "";
  }

  r = ns_cgi_param(phr, "email", &email);
  if (r < 0) FAIL2(NEW_SRV_ERR_EMAIL_BINARY);
  if (!r || !email) FAIL2(NEW_SRV_ERR_EMAIL_UNSPECIFIED);
  if (check_str(email, email_accept_chars) < 0)
    FAIL2(NEW_SRV_ERR_EMAIL_INV_CHARS);

  // if neither login nor email are specified, just change the locale
  if (!*login && !*email) {
    snprintf(urlbuf, sizeof(urlbuf), "%s?contest_id=%d&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, phr->locale_id,
             cnts->assign_logins?NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT_PAGE:NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
    html_refresh_page_2(fout, urlbuf);
    return;
  }

  if (!cnts->assign_logins) {
    if (!*login) FAIL2(NEW_SRV_ERR_LOGIN_UNSPECIFIED);
  }
  if (!*email) FAIL2(NEW_SRV_ERR_EMAIL_UNSPECIFIED);

  if (ns_open_ul_connection(phr->fw_state) < 0)
    FAIL2(NEW_SRV_ERR_UL_CONNECT_FAILED);

  next_action = NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE;
  if (phr->action == NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT)
    next_action = NEW_SRV_ACTION_REG_AUTOASSIGNED_ACCOUNT_CREATED_PAGE;

  ul_error = userlist_clnt_register_new(ul_conn, ULS_REGISTER_NEW,
                                        phr->ip, phr->ssl_flag,
                                        phr->contest_id, phr->locale_id,
                                        next_action,
                                        login, email, phr->self_url);
  if (ul_error < 0) goto failed;
  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s?contest_id=%d&action=%d",
          EJUDGE_CHARSET, phr->self_url, phr->contest_id, next_action);
  if (phr->locale_id > 0) fprintf(fout, "&locale_id=%d", phr->locale_id);
  if (login && *login) fprintf(fout, "&login=%s", URLARMOR(login));
  if (email && *email) fprintf(fout, "&email=%s", URLARMOR(email));
  fprintf(fout, "\n\n");
  goto cleanup;

 failed:
  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s?contest_id=%d&action=%d",
          EJUDGE_CHARSET, phr->self_url, phr->contest_id,
          (phr->action == NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT)?NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT_PAGE:NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
  if (phr->locale_id > 0) fprintf(fout, "&locale_id=%d", phr->locale_id);
  if (login && *login) fprintf(fout, "&login=%s", URLARMOR(login));
  if (email && *email) fprintf(fout, "&email=%s", URLARMOR(email));
  if (retval) fprintf(fout, "&retval=%d", retval);
  if (ul_error) fprintf(fout, "&ul_error=%d", ul_error);
  fprintf(fout, "\n\n");

 cleanup:
  html_armor_free(&ab);
}

static void
cmd_login(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  const unsigned char *login = 0;
  const unsigned char *password = 0;
  int r;
  unsigned char urlbuf[1024], bb[1024];

  if (ns_cgi_param(phr, "login", &login) <= 0)
    return ns_html_err_inv_param(fout, phr, 0, "login is invalid");
  phr->login = xstrdup(login);
  if (ns_cgi_param(phr, "password", &password) <= 0)
    return ns_html_err_inv_param(fout, phr, 0, "password is invalid");

  // if neither login, nor password is not specified, just change the locale
  if ((!login || !*login) && (!password || !*password)) {
    snprintf(urlbuf, sizeof(urlbuf), "%s?contest_id=%d&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, phr->locale_id,
             NEW_SRV_ACTION_REG_LOGIN_PAGE);
    html_refresh_page_2(fout, urlbuf);
    return;
  }

  /* check password action is here */
  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 0, 0);

  if ((r = userlist_clnt_login(ul_conn, ULS_CHECK_USER,
                               phr->ip, phr->ssl_flag, phr->contest_id,
                               phr->locale_id, phr->login, password,
                               &phr->user_id, &phr->session_id,
                               &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      return ns_html_err_no_perm(fout, phr, 0, "user_login failed: %s",
                                 userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return ns_html_err_ul_server_down(fout, phr, 0, 0);
    default:
      return ns_html_err_internal_error(fout, phr, 0, "user_login failed: %s",
                                        userlist_strerror(-r));
    }
  }

  // if there is no editable fields and autoregister flag is set,
  // then register immediately for the contest and redirect there
  if (cnts->force_registration && cnts->disable_name
      && cnts->autoregister && cnts->disable_team_password) {
    // FIXME: probably need new registration command
    r = userlist_clnt_register_contest(ul_conn, ULS_PRIV_REGISTER_CONTEST,
                                       phr->user_id, phr->contest_id);
    if (r < 0)
      return ns_html_err_no_perm(fout, phr, 0, "user_login failed: %s",
                                 userlist_strerror(-r));

    snprintf(urlbuf, sizeof(urlbuf), "%s?SID=%llx",
             get_client_url(bb, sizeof(bb), cnts, phr->self_url),
             phr->session_id);

    ns_get_session(phr->session_id, 0);
    html_refresh_page_2(fout, urlbuf);
  }

  /*
  ns_get_session(phr->session_id, 0);
  html_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);
  */
}

typedef void (*reg_action_handler_func_t)(FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
	time_t cur_time);
static reg_action_handler_func_t action_handlers[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT_PAGE] = create_autoassigned_account_page,
  [NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT] = create_account,
  [NEW_SRV_ACTION_REG_AUTOASSIGNED_ACCOUNT_CREATED_PAGE] = login_page,
  [NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE] = create_account_page,
  [NEW_SRV_ACTION_REG_CREATE_ACCOUNT] = create_account,
  [NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE] = login_page,
  [NEW_SRV_ACTION_REG_LOGIN_PAGE] = login_page,
  [NEW_SRV_ACTION_REG_LOGIN] = cmd_login,
};

static void
anon_register_pages(FILE *fout, struct http_request_info *phr)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = 0;

  // contest_id is reqired
  if (phr->contest_id <= 0 || contests_get(phr->contest_id,&cnts) < 0 || !cnts){
    return anon_select_contest_page(fout, phr);
  }

  if (phr->locale_id < 0) phr->locale_id = cnts->default_locale_val;
  if (phr->locale_id < 0) phr->locale_id = 0;

  // check permissions
  if (cnts->closed ||
      !contests_check_register_ip_2(cnts, phr->ip, phr->ssl_flag)) {
    return ns_html_err_no_perm(fout, phr, 0, "registration is not available");
  }

  // load style stuff
  extra = ns_get_contest_extra(phr->contest_id);
  cur_time = time(0);
  watched_file_update(&extra->header, cnts->team_header_file, cur_time);
  watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
  watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
  extra->header_txt = extra->header.text;
  extra->footer_txt = extra->footer.text;
  extra->separator_txt = "";
  extra->copyright_txt = extra->copyright.text;
  if (!extra->header_txt || !extra->footer_txt) {
    extra->header_txt = ns_fancy_header;
    extra->separator_txt = ns_fancy_separator;
    if (extra->copyright_txt) extra->footer_txt = ns_fancy_footer_2;
    else extra->footer_txt = ns_fancy_footer;
  }

  if (extra->contest_arm) xfree(extra->contest_arm);
  if (phr->locale_id == 0 && cnts->name_en) {
    extra->contest_arm = html_armor_string_dup(cnts->name_en);
  } else {
    extra->contest_arm = html_armor_string_dup(cnts->name);
  }

  // fool-proof...
  if (cnts->assign_logins) {
    if (phr->action == NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE)
      phr->action = NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT_PAGE;
    if (phr->action == NEW_SRV_ACTION_REG_CREATE_ACCOUNT)
      phr->action = NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT;
  } else {
    if (phr->action == NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT_PAGE)
      phr->action = NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE;
    if (phr->action == NEW_SRV_ACTION_REG_CREATE_AUTOASSIGNED_ACCOUNT)
      phr->action = NEW_SRV_ACTION_REG_CREATE_ACCOUNT;
  }

  if (phr->action < 0 || phr->action >= NEW_SRV_ACTION_LAST) phr->action = 0;
  if (action_handlers[phr->action])
    return (*action_handlers[phr->action])(fout, phr, cnts, extra, cur_time);

  if (cnts->assign_logins)
    return create_autoassigned_account_page(fout, phr, cnts, extra, cur_time);
  else
    return login_page(fout, phr, cnts, extra, cur_time);
}

static void
change_locale(FILE *fout, struct http_request_info *phr)
{
  int next_action = 0;
  const unsigned char *sep = "?";
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s = 0;

  cgi_param_int(phr, "next_action", &next_action);
  if (next_action < 0 || next_action >= NEW_SRV_ACTION_LAST) next_action = 0;

  // SID, contest_id, login are passed "as is"
  // next_action is passed as action
  if (phr->session_id) {
    // FIXME: update the session

    fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s?SID=%016llx", EJUDGE_CHARSET, phr->self_url,
            phr->session_id);
    if (next_action > 0) fprintf(fout, "&action=%d", next_action);
    fprintf(fout, "\n\n");
    return;
  }

  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s", EJUDGE_CHARSET, phr->self_url);
  if (phr->contest_id > 0) {
    fprintf(fout, "%scontest_id=%d", sep, phr->contest_id);
    sep = "&";
  }
  s = 0;
  if (ns_cgi_param(phr, "login", &s) > 0 && s && *s) {
    fprintf(fout, "%slogin=%s", sep, URLARMOR(s));
    sep = "&";
  }
  s = 0;
  if (ns_cgi_param(phr, "email", &s) > 0 && s && *s) {
    fprintf(fout, "%semail=%s", sep, URLARMOR(s));
    sep = "&";
  }
  if (phr->locale_id > 0) {
    fprintf(fout, "%slocale_id=%d", sep, phr->locale_id);
    sep = "&";
  }
  if (next_action > 0) {
    fprintf(fout, "%saction=%d", sep, next_action);
    sep = "&";
  }
  fprintf(fout, "\n\n");

  html_armor_free(&ab);
}

void
ns_register_pages(FILE *fout, struct http_request_info *phr)
{
  if (phr->action == NEW_SRV_ACTION_CHANGE_LANGUAGE)
    return change_locale(fout, phr);

  if (!phr->session_id) return anon_register_pages(fout, phr);

  // check session
  // get the contest_id and load the contest style stuff
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
