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
#include "userlist.h"
#include "contests.h"
#include "misctext.h"
#include "mischtml.h"
#include "xml_utils.h"
#include "l10n.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

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

static char *
ns_snprintf(unsigned char *buf, size_t size, const char *format, ...)
  __attribute__((format(printf, 3, 4)));
static char *
ns_snprintf(unsigned char *buf, size_t size, const char *format, ...)
{
  va_list args;

  va_start(args, format);
  vsnprintf(buf, size, format, args);
  va_end(args);
  return buf;
}

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
  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">%s</a></div></td>", phr->self_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE, s);
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

    switch (((cnts->simple_registration & 1) << 1) | (cnts->assign_logins&1)) {
    case 0:                     /* !simple_registration && !assign_logins */
      fprintf(fout,
              _("<p%s>New account <tt>%s</tt> is successfully created. "
                "An e-mail messages is sent to the address <tt>%s</tt>. "
                "This message contains the password for the initial log in. You will be able to change the password later.</p>\n"
                "<p%s>Type the login and the password in to the form above and press the \"Log in\" button to activate the account.</p>\n"
                "<p%s><b>Note</b>, that you should log in to the system for "
                "the first time no later, than in 24 hours after this moment, "
                "or the new account is removed.</p>"),
              par_style, login, email, par_style, par_style);
      break;
    case 1:                     /* !simple_registration &&  assign_logins */
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
      break;
    case 2:                     /*  simple_registration && !assign_logins */
    case 3:                     /*  simple_registration &&  assign_logins */
      fprintf(fout,
              _("<p%s>New account <tt>%s</tt> is successfully created. Initial password is generated automatically. You will be able to change your password later. "),
              par_style, ARMOR(login));
      if (cnts->send_passwd_email)
        fprintf(fout, _("An e-mail with your account parameters is sent to address <tt>%s</tt>. "), ARMOR(email));
      fprintf(fout, "</p>\n");

      fprintf(fout, _("<p%s>The account parameters are as follows:</p>\n"),
              par_style);
      fprintf(fout, "<table class=\"summary\">\n");
      fprintf(fout, "<tr><td>%s</td><td><tt>%s</tt></td></tr>\n",
              _("Login"), ARMOR(login));
      fprintf(fout, "<tr><td>%s</td><td><tt>%s</tt></td></tr>\n",
              _("E-mail"), ARMOR(email));
      fprintf(fout, "<tr><td>%s</td><td><tt>%s</tt></td></tr>\n",
              _("Password"), ARMOR(password));
      fprintf(fout, "</table>\n");

      fprintf(fout, _("<p%s><b>Remember or write down the password!</b></p>"),
              par_style);
    }
  }

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

static void
create_account_page( FILE *fout, struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra, time_t cur_time);

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

  if (!cnts->assign_logins)
    return create_account_page(fout, phr, cnts, extra, cur_time);

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
              NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
  if (cnts->disable_locale_change)
    html_hidden(fout, "locale_id", "%d", phr->locale_id);
  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>\n");

  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">e-mail: %s</div></td>", html_input_text(bb, sizeof(bb), "email", 20, "%s", ARMOR(email)));

  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>", ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_REG_CREATE_ACCOUNT, _("Create account")));

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
            NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
  } else {
    if (!cnts->simple_registration || cnts->send_passwd_email) {
      fprintf(fout, "<p%s>%s</p>", par_style,
              _("You should receive an e-mail message "
                "with a password to the system. Use this password for the first"
                " log in. After the first login you will be able to change the password."));

      fprintf(fout, "<p%s>%s</p>", par_style,
              _("Be careful and type the e-mail address correctly. If you make a mistake, you will not receive a registration e-mail and be unable to complete the registration process."));
    }

    if (cnts->simple_registration) {
      fprintf(fout, _("<p%s><a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">Simplified registration</a> is available for this contest. Note, however, that simplified registration imposes certain restrictions on further use of the account!</p>\n"), par_style, phr->self_url, phr->contest_id,
              phr->locale_id,
              NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
    }
  }

  fprintf(fout, "<p%s>%s</p>",
          par_style,
          _("<b>Note</b>, that you must log in "
            "24 hours after the form is filled and submitted, or "
            "your registration will be cancelled!"));

  fprintf(fout, _("<p%s>If you already have an ejudge account on this server, you may use it. If so, follow the <a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">\"Use an existing account\"</a> link.</p>"),
          par_style, phr->self_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_REG_LOGIN_PAGE);

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

  if (cnts->assign_logins)
    return create_autoassigned_account_page(fout, phr, cnts, extra, cur_time);

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
    if (!cnts->simple_registration || cnts->send_passwd_email) {
      fprintf(fout, "<p%s>%s</p>", par_style,
              _("You should receive an e-mail message "
                "with a password to the system. Use this password for the first"
                " log in. After the first login you will be able to change the password."));

      fprintf(fout, "<p%s>%s</p>", par_style,
              _("Be careful and type the e-mail address correctly. If you make a mistake, you will not receive a registration e-mail and be unable to complete the registration process."));
    }

    if (cnts->simple_registration) {
      fprintf(fout, _("<p%s><a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">Simplified registration</a> is available for this contest. Note, however, that simplified registration imposes certain restrictions on further use of the account!</p>\n"), par_style, phr->self_url, phr->contest_id,
              phr->locale_id, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
    }
  }

  fprintf(fout, "<p%s>%s</p>",
          par_style,
          _("<b>Note</b>, that you must log in "
            "24 hours after the form is filled and submitted, or "
            "your registration will be cancelled!"));

  fprintf(fout, _("<p%s>If you already have an ejudge account on this server, you may use it. If so, follow the <a href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">\"Use an existing account\"</a> link.</p>"),
          par_style, phr->self_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_REG_LOGIN_PAGE);

  fprintf(fout, "<p%s>&nbsp;</p>\n", par_style);

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

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
  unsigned char *new_login = 0;
  unsigned char *new_password = 0;

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
             NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
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

  if (cnts->simple_registration) {
    ul_error = userlist_clnt_register_new_2(ul_conn, phr->ip, phr->ssl_flag,
                                            phr->contest_id, phr->locale_id,
                                            next_action,
                                            login, email, phr->self_url,
                                            &new_login, &new_password);


  } else {
    ul_error = userlist_clnt_register_new(ul_conn, ULS_REGISTER_NEW,
                                          phr->ip, phr->ssl_flag,
                                          phr->contest_id, phr->locale_id,
                                          next_action,
                                          login, email, phr->self_url);
  }

  if (ul_error < 0) goto failed;
  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s?contest_id=%d&action=%d",
          EJUDGE_CHARSET, phr->self_url, phr->contest_id, next_action);
  if (phr->locale_id > 0) fprintf(fout, "&locale_id=%d", phr->locale_id);
  if (cnts->simple_registration) {
    if (new_login && *new_login) fprintf(fout,"&login=%s",URLARMOR(new_login));
    if (new_password && *new_password)
      fprintf(fout, "&password=%s", URLARMOR(new_password));
  } else {
    if (login && *login) fprintf(fout, "&login=%s", URLARMOR(login));
  }
  if (email && *email) fprintf(fout, "&email=%s", URLARMOR(email));
  fprintf(fout, "\n\n");
  goto cleanup;

 failed:
  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s?contest_id=%d&action=%d",
          EJUDGE_CHARSET, phr->self_url, phr->contest_id,
          NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
  if (phr->locale_id > 0) fprintf(fout, "&locale_id=%d", phr->locale_id);
  if (login && *login) fprintf(fout, "&login=%s", URLARMOR(login));
  if (email && *email) fprintf(fout, "&email=%s", URLARMOR(email));
  if (retval) fprintf(fout, "&retval=%d", retval);
  if (ul_error) fprintf(fout, "&ul_error=%d", ul_error);
  fprintf(fout, "\n\n");

 cleanup:
  html_armor_free(&ab);
  xfree(new_login);
  xfree(new_password);
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
    r = userlist_clnt_register_contest(ul_conn, ULS_REGISTER_CONTEST_2,
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

  snprintf(urlbuf, sizeof(urlbuf), "%s?SID=%llx", phr->self_url,
           phr->session_id);
  html_refresh_page_2(fout, urlbuf);
}

typedef void (*reg_action_handler_func_t)(FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
	time_t cur_time);
static reg_action_handler_func_t action_handlers[NEW_SRV_ACTION_LAST] =
{
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
  int create_flag = 0;

  cgi_param_int(phr, "create_account", &create_flag);

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

  if (create_flag) {
    phr->action = NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE;
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

static void
menu_item(FILE *fout, struct http_request_info *phr,
          int action,
          const unsigned char *text,
          const unsigned char *url)
{
  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">");
  if (action != phr->action && url) {
    fprintf(fout, "<a class=\"menu\" href=\"%s\">", url);
  }
  fprintf(fout, "%s", text);
  if (action != phr->action && url) {
    fprintf(fout, "</a>");
  }
  fprintf(fout, "</div></td>");
}

static void
info_table_row(FILE *fout, const unsigned char *s1, const unsigned char *s2,
               int is_empty, int is_mandatory, const unsigned char *valid_chars,
               struct html_armor_buffer *pb)
{
  const unsigned char *red_beg = "", *red_end = "";
  int strres = 0;

  if (is_empty && is_mandatory) {
    red_beg = "<font color=\"red\">";
    red_end = "</font>";
  } else if (s1 && valid_chars && (strres = check_str(s1, valid_chars)) < 0) {
    red_beg = "<font color=\"red\">";
    red_end = "</font>";
  }

  fprintf(fout, "<tr><td class=\"borderless\">%s%s%s:</td><td class=\"borderless\">", red_beg, s1, red_end);
  if (is_empty || !s1 || !*s1) {
    fprintf(fout, "&nbsp;");
  } else {
    fprintf(fout, "<tt>%s</tt>", html_armor_buf(pb, s2));
  }
  fprintf(fout, "</td><td class=\"borderless\">");
  if (is_empty && is_mandatory) {
    fprintf(fout, "%s<i>%s</i>%s", red_beg, _("Not set"), red_end);
  } else if (s1 && valid_chars && strres) {
    fprintf(fout, "%s<i>%s</i>%s", red_end, _("Invalid characters"), red_end);
  } else {
    fprintf(fout, "&nbsp;");
  }
  fprintf(fout, "</td></tr>\n");
}

static int
contest_fields_order[] =
{
  CONTEST_F_INST,
  CONTEST_F_INST_EN,
  CONTEST_F_INSTSHORT,
  CONTEST_F_INSTSHORT_EN,
  CONTEST_F_FAC,
  CONTEST_F_FAC_EN,
  CONTEST_F_FACSHORT,
  CONTEST_F_FACSHORT_EN,
  CONTEST_F_CITY,
  CONTEST_F_CITY_EN,
  CONTEST_F_REGION,
  CONTEST_F_COUNTRY,
  CONTEST_F_COUNTRY_EN,
  CONTEST_F_LANGUAGES,
  CONTEST_F_HOMEPAGE,
  CONTEST_F_PHONE,
  0,
};

static int
member_fields_order[] =
{
  CONTEST_MF_FIRSTNAME,
  CONTEST_MF_FIRSTNAME_EN,
  CONTEST_MF_MIDDLENAME,
  CONTEST_MF_MIDDLENAME_EN,
  CONTEST_MF_SURNAME,
  CONTEST_MF_SURNAME_EN,
  CONTEST_MF_STATUS,
  CONTEST_MF_GRADE,
  CONTEST_MF_GROUP,
  CONTEST_MF_GROUP_EN,
  CONTEST_MF_EMAIL,
  CONTEST_MF_HOMEPAGE,
  CONTEST_MF_PHONE,
  CONTEST_MF_INST,
  CONTEST_MF_INST_EN,
  CONTEST_MF_INSTSHORT,
  CONTEST_MF_INSTSHORT_EN,
  CONTEST_MF_FAC,
  CONTEST_MF_FAC_EN,
  CONTEST_MF_FACSHORT,
  CONTEST_MF_FACSHORT_EN,
  CONTEST_MF_OCCUPATION,
  CONTEST_MF_OCCUPATION_EN,
  CONTEST_MF_BIRTH_DATE,
  CONTEST_MF_ENTRY_DATE,
  CONTEST_MF_GRADUATION_DATE,
  0,
};

struct field_desc_s
{
  char *description;
  int repl_char;
  int maxlength;
  int size;
};

static struct field_desc_s contest_field_desc[CONTEST_LAST_FIELD] =
{
  [CONTEST_F_HOMEPAGE] = { __("Homepage"), '?', 128, 64 },
  [CONTEST_F_PHONE] = { __("Phone"), '?', 128, 64 },
  [CONTEST_F_INST] = { __("Institution"), '?', 128, 64 },
  [CONTEST_F_INST_EN] = { __("Institution (En)"), '?', 128, 64 },
  [CONTEST_F_INSTSHORT] = { __("Institution (abbreviated)"), '?', 32, 32 },
  [CONTEST_F_INSTSHORT_EN] = { __("Institution (abbreviated) (En)"), '?', 32, 32 },
  [CONTEST_F_FAC] = { __("Faculty"), '?', 128, 64 },
  [CONTEST_F_FAC_EN] = { __("Faculty (En)"), '?', 128, 64 },
  [CONTEST_F_FACSHORT] = { __("Faculty (abbreviated)"), '?', 32, 32 },
  [CONTEST_F_FACSHORT_EN] = { __("Faculty (abbreviated) (En)"), '?', 32, 32 },
  [CONTEST_F_CITY] = { __("City"), '?', 128, 64 },
  [CONTEST_F_CITY_EN] = { __("City (En)"), '?', 128, 64 },
  [CONTEST_F_COUNTRY] = { __("Country"), '?', 128, 64 },
  [CONTEST_F_COUNTRY_EN] = { __("Country (En)"),  '?', 128, 64 },
  [CONTEST_F_REGION] = { __("Region"), '?', 128, 64 },
  [CONTEST_F_LANGUAGES] = { __("Programming languages"), '?', 128, 64 },
};

static struct field_desc_s member_field_desc[CONTEST_LAST_MEMBER_FIELD] =
{
  [CONTEST_MF_FIRSTNAME] = { __("First name"), '?', 64, 64 },
  [CONTEST_MF_FIRSTNAME_EN] = { __("First name (En)"), '?', 64, 64 },
  [CONTEST_MF_MIDDLENAME] = { __("Middle name"), '?', 64, 64},
  [CONTEST_MF_MIDDLENAME_EN] = { __("Middle name (En)"), '?', 64, 64 },
  [CONTEST_MF_SURNAME] = { __("Family name"), '?', 64, 64 },
  [CONTEST_MF_SURNAME_EN] = { __("Family name (En)"), '?', 64, 64 },
  [CONTEST_MF_STATUS] = { __("Status"), '?', 64, 64 },
  [CONTEST_MF_GRADE] = { __("Grade"), '?', 16, 16 },
  [CONTEST_MF_GROUP] = { __("Group"), '?', 16, 16 },
  [CONTEST_MF_GROUP_EN] = { __("Group (En)"), '?', 16, 16 },
  [CONTEST_MF_EMAIL] = { __("E-mail"), '?', 64, 64 },
  [CONTEST_MF_HOMEPAGE] = { __("Homepage"), '?', 128, 64 },
  [CONTEST_MF_PHONE] = { __("Phone"), '?', 128, 64 },
  [CONTEST_MF_INST] = { __("Institution"), '?', 128, 64 },
  [CONTEST_MF_INST_EN] = { __("Institution (En)"), '?', 128, 64 },
  [CONTEST_MF_INSTSHORT] = { __("Institution (abbreviated)"), '?', 32, 32 },
  [CONTEST_MF_INSTSHORT_EN] = { __("Institution (abbreviated) (En)"), '?', 32, 32 },
  [CONTEST_MF_FAC] = { __("Faculty"), '?', 128, 64 },
  [CONTEST_MF_FAC_EN] = { __("Faculty (En)"), '?', 128, 64 },
  [CONTEST_MF_FACSHORT] = { __("Faculty (abbreviated)"), '?', 32, 32 },
  [CONTEST_MF_FACSHORT_EN] = { __("Faculty (abbreviated) (En)"), '?', 32, 32 },
  [CONTEST_MF_OCCUPATION] = { __("Occupation"), '?', 128, 64 },
  [CONTEST_MF_OCCUPATION_EN] = { __("Occupation (En)"), '?', 128, 64 },
  [CONTEST_MF_BIRTH_DATE] = { __("Birth Date"), '?', 128, 64 },
  [CONTEST_MF_ENTRY_DATE] = { __("Institution entry date"), '?', 128, 64 },
  [CONTEST_MF_GRADUATION_DATE] = { __("Institution graduation date"), '?', 128, 64 },
};

static int
tab_actions[] =
{
  NEW_SRV_ACTION_REG_VIEW_GENERAL,
  NEW_SRV_ACTION_REG_VIEW_CONTESTANTS,
  NEW_SRV_ACTION_REG_VIEW_RESERVES,
  NEW_SRV_ACTION_REG_VIEW_COACHES,
  NEW_SRV_ACTION_REG_VIEW_ADVISORS,
  NEW_SRV_ACTION_REG_VIEW_GUESTS,
  0,
};
static const unsigned char *tab_labels[] =
{
  __("General info"),
  __("Contestants"),
  __("Reserves"),
  __("Coaches"),
  __("Advisors"),
  __("Guests"),
};

static const unsigned char *no_role_allowed_str[] =
{
  __("No contestants are allowed in this contest"),
  __("No reserves are allowed in this contest"),
  __("No coaches are allowed in this contest"),
  __("No advisors are allowed in this contest"),
  __("No guests are allowed in this contest"),
};

static const unsigned char *role_labels[] =
{
  __("Contestant"),
  __("Reserve"),
  __("Coach"),
  __("Advisor"),
  __("Guest"),
};

static const unsigned char *role_move_direction[] =
{
  __("Move to reserves"),
  __("Move to contestants"),
  __("Move to advisors"),
  __("Move to coaches"),
  0
};

static void
main_page_view_info(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  unsigned char ub[1024];
  unsigned char bb[1024];
  int i, ff;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct userlist_user *u = 0;
  const unsigned char *s, *hh = 0, *cc = 0;
  unsigned char fbuf[1024];
  int tab_count, err_count, role_err_count[CONTEST_LAST_MEMBER + 1];
  int rr, mm, mmbound, main_area_span;
  const struct userlist_member *m;

  u = phr->session_extra->user_info;

  if (phr->action < NEW_SRV_ACTION_REG_VIEW_GENERAL
      || phr->action > NEW_SRV_ACTION_REG_VIEW_GUESTS) {
    phr->action = NEW_SRV_ACTION_REG_VIEW_GENERAL;
  }

  // check that we need tabs and how many
  tab_count = 1;
  for (i = 0; i < CONTEST_LAST_MEMBER; i++) {
    if (cnts->members[i] && cnts->members[i]->max_count > 0)
      tab_count++;
    else if (phr->action == NEW_SRV_ACTION_REG_VIEW_CONTESTANTS + i)
      phr->action = NEW_SRV_ACTION_REG_VIEW_GENERAL;
  }

  err_count = userlist_count_info_errors(cnts, u, role_err_count);

  // generate upper tabs
  fprintf(fout, "<br/>\n");
  fprintf(fout, "<table cellpadding=\"0\" cellspacing=\"0\">\n");
  main_area_span = 1;
  if (tab_count > 1) {
    main_area_span = 0;
    fprintf(fout, "<tr id=\"probNavTopList\">\n");
    for (i = 0; tab_actions[i]; i++) {
      if (i > 0 && (!cnts->members[i - 1]
                    || cnts->members[i - 1]->max_count <= 0))
        continue;

      if (main_area_span > 0) {
        fprintf(fout, "<td class=\"probNavSpaceTop\">&nbsp;</td>");
        main_area_span++;
      }

      hh = "probNavHidden";
      if (phr->action == tab_actions[i]) hh = "probNavActiveTop";
      cc = "probOk";
      if (phr->action == tab_actions[i]) {
        cc = "probCurrent";
      } else if (role_err_count[i] > 0) {
        cc = "probBad";
      }
      fprintf(fout, "<td class=\"%s\" onclick=\"displayRoleInfo(%d)\"><div class=\"%s\">", hh, tab_actions[i], cc);
      fprintf(fout, "%s%s</a>",
              ns_aref_2(bb, sizeof(bb), phr, "tab", tab_actions[i], 0),
              gettext(tab_labels[i]));
      fprintf(fout, "</div></td>\n");
      main_area_span++;
    }
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "<tr><td colspan=\"%d\" id=\"memberNavArea\"><div id=\"probNavTaskArea\">\n", main_area_span);

  if (phr->action == NEW_SRV_ACTION_REG_VIEW_GENERAL) {
    fprintf(fout, "<h2>%s", _("General information"));
    if (!u->read_only && !u->i.cnts_read_only) {
      fprintf(fout, " [%s%s</a>]",
              ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE, 0), _("Edit"));
    }
    fprintf(fout, "</h2>\n");
    fprintf(fout, "<table class=\"borderless\">\n");
    s = 0;
    if (u && u->login && *u->login) {
      s = u->login;
    }
    info_table_row(fout,  _("Login"), s, 0, 0, 0, &ab);
    s = 0;
    if (u && u->email && *u->email) {
      s = u->email;
    }
    info_table_row(fout,  _("E-mail"), s, 0, 0, 0, &ab);
    if (!cnts->disable_name) {
      s = 0;
      if (u && u->i.name && *u->i.name) {
        s = u->i.name;
      }
      info_table_row(fout, cnts->personal?_("User name (for standings)"):_("Team name"), s, 0, 0, name_accept_chars, &ab);
    }
    for (i = 0; (ff = contest_fields_order[i]); i++) {
      if (!cnts->fields[ff]) continue;
      userlist_get_user_info_field_str(fbuf, sizeof(fbuf), &u->i,
                                       userlist_contest_field_ids[ff], 0);
      info_table_row(fout, gettext(contest_field_desc[ff].description),
                     fbuf,
                     userlist_is_empty_user_info_field(&u->i, userlist_contest_field_ids[ff]),
                     cnts->fields[ff]->mandatory,
                     userlist_get_contest_accepting_chars(ff),
                     &ab);
    }
    fprintf(fout, "</table>\n");
  } else if (phr->action >= NEW_SRV_ACTION_REG_VIEW_CONTESTANTS
             && phr->action <= NEW_SRV_ACTION_REG_VIEW_GUESTS) {
    rr = phr->action - NEW_SRV_ACTION_REG_VIEW_CONTESTANTS;
    if (!cnts->members[rr] || cnts->members[rr]->max_count <= 0) {
      fprintf(fout, "<h2><font color=\"red\">%s</font></h2>\n", gettext(no_role_allowed_str[rr]));
    } else {
      mmbound = 0;
      if (u->i.members[rr]) mmbound = u->i.members[rr]->total;

      fprintf(fout, "<h2>%s", gettext(tab_labels[rr + 1]));
      if (!u->read_only && !u->i.cnts_read_only
          && mmbound < cnts->members[rr]->max_count) {
        fprintf(fout, " [%s%s</a>]",
                ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_ADD_MEMBER_PAGE, "role=%d", rr), _("Add new"));
      }
      fprintf(fout, "</h2>\n");

      if (mmbound < cnts->members[rr]->min_count) {
        fprintf(fout, _("<p><font color=\"red\">Minimal number for this contest is %d, but only %d are defined.</font></p>\n"),
                cnts->members[rr]->min_count,
                mmbound);
      }

      fprintf(fout, _("<p>You may define up to %d members.</p>"),
              cnts->members[rr]->max_count);

      if (cnts->members[rr]->max_count < mmbound)
        mmbound = cnts->members[rr]->max_count;
      for (mm = 0; mm < mmbound; mm++) {
        fprintf(fout, "<h3>%s %d", role_labels[rr], mm + 1);
        if (!u->read_only && !u->i.cnts_read_only) {
          fprintf(fout, " [%s%s</a>]",
                  ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE, "role=%d&amp;member=%d", rr, mm), _("Edit"));
        }
        if (!u->read_only && !u->i.cnts_read_only
            && !cnts->disable_member_delete) {
          fprintf(fout, " [%s%s</a>]",
                  ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_REMOVE_MEMBER, "role=%d&amp;member=%d", rr, mm), _("Remove"));
        }
        if (!u->read_only && !u->i.cnts_read_only
            && role_move_direction[rr]) {
          fprintf(fout, " [%s%s</a>]",
                  ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_MOVE_MEMBER, "role=%d&amp;member=%d", rr, mm), gettext(role_move_direction[rr]));
        }
        fprintf(fout, "</h3>\n");
        if (!(m = u->i.members[rr]->members[mm])) continue;
        fprintf(fout, "<table class=\"borderless\">\n");

        for (i = 0; (ff = member_fields_order[i]); i++) {
          if (!cnts->members[rr]->fields[ff]) continue;
          userlist_get_member_field_str(fbuf, sizeof(fbuf), m,
                                        userlist_member_field_ids[ff], 0);
          info_table_row(fout, gettext(member_field_desc[ff].description),
                         fbuf,
                         userlist_is_empty_member_field(m, userlist_member_field_ids[ff]),
                         cnts->members[rr]->fields[ff]->mandatory,
                         userlist_get_member_accepting_chars(ff),
                         &ab);
        }

        fprintf(fout, "</table>\n");
      }
    }
  }

  // generate tabs bottom
  fprintf(fout, "</div></td></tr></table>\n");

  html_armor_free(&ab);
}

static void
main_page_view_settings(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
}

static reg_action_handler_func_t main_page_action_handlers[NEW_SRV_ACTION_LAST]=
{
  [NEW_SRV_ACTION_VIEW_SETTINGS] = main_page_view_settings,
};

static void
main_page(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  unsigned char ub[1024];
  unsigned char bb[1024];
  int shown_items = 0, i;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *status_style;
  const unsigned char *status_info;
  const unsigned char *status_info_2;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s]", _("Good!"),
            extra->contest_arm);

  shown_items = 0;
  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>");
  menu_item(fout, phr, NEW_SRV_ACTION_VIEW_SETTINGS, _("Settings"),
            ns_url(ub, sizeof(ub), phr, NEW_SRV_ACTION_VIEW_SETTINGS, 0));
  shown_items++;
  menu_item(fout, phr, NEW_SRV_ACTION_LOGOUT,
            ns_snprintf(bb, sizeof(bb), "%s [%s]", _("Logout"),
                        ARMOR(phr->login)),
            ns_url(ub, sizeof(ub), phr, NEW_SRV_ACTION_LOGOUT, 0));
  shown_items++;
  if (!shown_items)
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  fprintf(fout, "</tr></table></div>\n");

  fprintf(fout, "<div class=\"white_empty_block\">&nbsp;</div>\n");

  shown_items = 0;
  fprintf(fout, "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");

  // lower row
  if (phr->action >= NEW_SRV_ACTION_REG_VIEW_GENERAL
      && phr->action <= NEW_SRV_ACTION_REG_VIEW_GUESTS)
    i = phr->action;
  menu_item(fout, phr, i, _("User info"),
            ns_url(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0));
  shown_items++;
  if (phr->reg_status == USERLIST_REG_OK
      && !(phr->reg_flags &~USERLIST_UC_INVISIBLE)
      && contests_check_team_ip_2(cnts, phr->ip, phr->ssl_flag)
      && !cnts->closed && !cnts->client_disable_team) {
    // "participate" link
    get_client_url(bb, sizeof(bb), cnts, phr->self_url);
    if (cnts->disable_team_password) {
      snprintf(ub, sizeof(ub), "%s?SID=%llx", bb, phr->session_id);
    } else {
      snprintf(ub, sizeof(ub),"%s?contest_id=%d&amp;login=%s&amp;locale_id=%d",
               bb, phr->contest_id, URLARMOR(phr->login), phr->locale_id);
    }
    menu_item(fout, phr, -1, _("Participate"), ub);
    shown_items++;
  }
  if (!shown_items)
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  fprintf(fout, "</tr></table></div>\n");
  if (extra->separator_txt && *extra->separator_txt) {
    fprintf(fout, "%s", extra->separator_txt);
  }

  // status row
  status_info_2 = "";
  if (phr->reg_status < 0) {
    status_style = "server_status_off";
    status_info = __("NOT REGISTERED");
  } else if (phr->reg_status == USERLIST_REG_PENDING) {
    status_style = "server_status_alarm";
    status_info= __("REGISTERED, PENDING APPROVAL");
    if ((phr->reg_flags & USERLIST_UC_INCOMPLETE)) {
      status_info_2 = __(", REGISTRATION DATA INCOMPLETE");
      status_style = "server_status_error";
    }
  } else if (phr->reg_status == USERLIST_REG_REJECTED) {
    status_style = "server_status_error";
    status_info = __("REGISTRATION REJECTED");
  } else if ((phr->reg_flags & USERLIST_UC_BANNED)) {
    status_style = "server_status_error";
    status_info = __("REGISTERED, BANNED");
  } else if ((phr->reg_flags & USERLIST_UC_LOCKED)) {
    status_style = "server_status_error";
    status_info = __("REGISTERED, LOCKED");
  } else if ((phr->reg_flags & USERLIST_UC_INVISIBLE)) {
    status_style = "server_status_on";
    status_info = __("REGISTERED (INVISIBLE)");
    if ((phr->reg_flags & USERLIST_UC_INCOMPLETE)) {
      status_info_2 = __(", REGISTRATION DATA INCOMPLETE");
      status_style = "server_status_error";
    }
  } else {
    status_style = "server_status_on";
    status_info = __("REGISTERED");
    if ((phr->reg_flags & USERLIST_UC_INCOMPLETE)) {
      status_info_2 = __(", REGISTRATION DATA INCOMPLETE");
      status_style = "server_status_error";
    }
  }
  fprintf(fout, "<div class=\"%s\">\n", status_style);
  fprintf(fout, "<b>%s%s</b>", gettext(status_info), gettext(status_info_2));
  fprintf(fout, "</div>\n");

  if (main_page_action_handlers[phr->action])
    (*main_page_action_handlers[phr->action])(fout, phr, cnts, extra, cur_time);
  else {
    main_page_view_info(fout, phr, cnts, extra, cur_time);
  }

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

static void
edit_general_form(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        const struct userlist_user *u)
{
  unsigned char bb[1024];
  unsigned char varname[1024];
  int i, ff, j;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *comment = 0, *s = 0, *ac;
  size_t allowed_languages_u = 0, allowed_regions_u = 0;
  unsigned char **allowed_languages = 0, **allowed_regions = 0;
  int *user_lang_map = 0;

  if (cnts->fields[CONTEST_F_LANGUAGES]) {
    allowed_list_parse(cnts->allowed_languages,
                       &allowed_languages, &allowed_languages_u);
  }
  if (cnts->fields[CONTEST_F_REGION]) {
    allowed_list_parse(cnts->allowed_regions,
                       &allowed_regions, &allowed_regions_u);
  }

  html_start_form(fout, 1, phr->self_url, "");
  html_hidden(fout, "SID", "%llx", phr->session_id);
  fprintf(fout, "<table class=\"borderless\">");

  bb[0] = 0;
  if (cnts->user_name_comment)
    snprintf(bb, sizeof(bb), "%s", cnts->user_name_comment);
  fprintf(fout, "<tr><td class=\"borderless\"><b>%s</b>%s:</td>",
          cnts->personal?_("User name (for standings)"):_("Team name"), bb);
  bb[0] = 0;
  if (u->i.name) snprintf(bb, sizeof(bb), "%s", u->i.name);
  comment = 0;
  if (check_str(bb, name_accept_chars) < 0) {
    comment = __("contains invalid characters");
  }
  fprintf(fout, "<td class=\"borderless\">%s</td>",
          html_input_text(bb, sizeof(bb), "name", 64, ARMOR(bb)));
  
  if (!comment) comment = "&nbsp;";
  fprintf(fout, "<td class=\"borderless\"><font color=\"red\"><i>%s</i></font></td>", comment);
  fprintf(fout, "</tr>\n");

  for (i = 0; (ff = contest_fields_order[i]); i++) {
    if (!cnts->fields[ff]) continue;
    fprintf(fout, "<tr>");
    fprintf(fout, "<td class=\"borderless\" valign=\"top\">");
    if (cnts->fields[ff]->mandatory) fprintf(fout, "<b>");
    fprintf(fout, "%s:", gettext(contest_field_desc[ff].description));
    if (cnts->fields[ff]->mandatory) fprintf(fout, "</b>");
    fprintf(fout, "</td>");
    userlist_get_user_info_field_str(bb, sizeof(bb), &u->i,
                                     userlist_contest_field_ids[ff], 0);
    comment = 0;
    if (cnts->fields[ff]->mandatory
        && (userlist_is_empty_user_info_field(&u->i,
                                              userlist_contest_field_ids[ff])
            || !bb[0])) {
      comment = __("must be specified");
    } else if ((ac = userlist_get_contest_accepting_chars(ff))
               && check_str(bb, ac) < 0) {
      comment = __("contains invalid characters");
    }

    if (ff == CONTEST_F_LANGUAGES && allowed_languages_u > 0) {
      allowed_list_map(bb, allowed_languages, allowed_languages_u,
                       &user_lang_map);

      fprintf(fout, "<td class=\"borderless\"><table class=\"borderless\">\n");
      for (j = 0; j < allowed_languages_u; j++) {
        fprintf(fout, "<tr><td class=\"borderless\"><input type=\"checkbox\" name=\"proglang_%d\"%s/></td>"
               "<td class=\"borderless\">%s</td></tr>\n",
               j, user_lang_map[j]?" checked=\"yes\"":"",
               ARMOR(allowed_languages[j]));
      }
      fprintf(fout, "</table></td>\n");
    } else if (ff == CONTEST_F_REGION && allowed_regions_u > 0) {
      fprintf(fout, "<td class=\"borderless\"><select name=\"region\"><option></option>");
      for (j = 0; j < allowed_regions_u; j++) {
        s = "";
        if (!strcmp(bb, allowed_regions[j]))
          s = " selected=\"yes\"";
        fprintf(fout, "<option%s>%s</option>", s, ARMOR(allowed_regions[j]));
      }
      fprintf(fout, "</select></td>\n");
    } else {
      snprintf(varname, sizeof(varname), "param_%d", ff);
      fprintf(fout, "<td class=\"borderless\">%s</td>",
              html_input_text(bb, sizeof(bb), varname,
                              contest_field_desc[ff].size,
                              ARMOR(bb)));
    }
  
    if (!comment) comment = "&nbsp;";
    fprintf(fout, "<td class=\"borderless\" valign=\"top\"><font color=\"red\"><i>%s</i></font></td>", comment);
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "</table>\n");
  fprintf(fout, "<table class=\"borderless\"><tr>");
  fprintf(fout, "<td class=\"borderless\">%s</td>",
          ns_submit_button(bb, sizeof(bb), 0,
                           NEW_SRV_ACTION_REG_CANCEL_GENERAL_EDITING, 0));
  fprintf(fout, "<td class=\"borderless\">%s</td>",
          ns_submit_button(bb, sizeof(bb), 0,
                           NEW_SRV_ACTION_REG_SUBMIT_GENERAL_EDITING, 0));
  fprintf(fout, "</tr></table>");
  fprintf(fout, "</form>\n");

  html_armor_free(&ab);
  allowed_list_free(allowed_languages, allowed_languages_u);
  allowed_list_free(allowed_regions, allowed_regions_u);
  xfree(user_lang_map);
}

static const unsigned char * const month_names[] =
{
  "",
  __("Jan"), __("Feb"), __("Mar"), __("Apr"), __("May"), __("Jun"),
  __("Jul"), __("Aug"), __("Sep"), __("Oct"), __("Nov"), __("Dec"),
};

static void
display_date_change_dialog(FILE *fout, int field, const unsigned char *val,
                           const unsigned char *beg_str,
                           const unsigned char *end_str)
{
  int day = 0, month = 0, year = 0, n;
  unsigned char vbuf[128];
  const unsigned char *sstr = " selected=\"selected\"";
  const unsigned char *s = "";

  fprintf(fout, "%s", beg_str);
  if (sscanf(val, "%d/%d/%d%n", &year, &month, &day, &n) != 3 || val[n]
      || year <= 1900 || year >= 10000 || month < 0 || month > 12
      || day < 0 || day > 31) {
    day = month = year = 0;
  }
  if (day == 1 && month == 1 && year == 1970) {
    day = month = year = 0;
  }

  // day selection
  s = "";
  if (!day) s = sstr;
  fprintf(fout, "<select name=\"day_%d\"><option%s></option>", field, s);
  for (n = 1; n <= 31; n++) {
    s = "";
    if (day == n) s = sstr;
    fprintf(fout, "<option%s>%d</option>", s, n);
  }
  fprintf(fout, "</select>\n");

  // month selection
  s = "";
  if (!month) s = sstr;
  fprintf(fout, "<select name=\"month_%d\"><option value=\"0\"%s></option>",
          field, s);
  for (n = 1; n <= 12; n++) {
    s = "";
    if (month == n) s = sstr;
    fprintf(fout, "<option value=\"%d\"%s>%s</option>", n, s,
            gettext(month_names[n]));
  }
  fprintf(fout, "</select>\n");

  vbuf[0] = 0;
  if (year > 0) snprintf(vbuf, sizeof(vbuf), "%d", year);
  fprintf(fout, "<input type=\"text\" name=\"year_%d\" value=\"%s\" maxlength=\"4\" size=\"4\"/></p>", field, vbuf);
  fprintf(fout, "%s", end_str);
}

static void
edit_member_form(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        const struct userlist_member *m,
        int role,
        int member)
{
  const struct contest_member *cm = cnts->members[role];
  unsigned char bb[1024];
  unsigned char varname[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int i, ff;
  const unsigned char *comment = 0, *ac;

  html_start_form(fout, 1, phr->self_url, "");
  html_hidden(fout, "SID", "%llx", phr->session_id);
  html_hidden(fout, "role", "%d", role);
  html_hidden(fout, "member", "%d", member);

  fprintf(fout, "<table class=\"borderless\">");
  for (i = 0; (ff = member_fields_order[i]); i++) {
    if (!cm->fields[ff]) continue;
    fprintf(fout, "<tr>");
    fprintf(fout, "<td class=\"borderless\" valign=\"top\">");
    if (cm->fields[ff]->mandatory) fprintf(fout, "<b>");
    fprintf(fout, "%s:", gettext(member_field_desc[ff].description));
    if (cm->fields[ff]->mandatory) fprintf(fout, "</b>");
    fprintf(fout, "</td>");
    userlist_get_member_field_str(bb, sizeof(bb), m,
                                  userlist_member_field_ids[ff], 0);
    comment = 0;
    if (cm->fields[ff]->mandatory
        && (userlist_is_empty_member_field(m, userlist_member_field_ids[ff])
            || !bb[0])) {
      comment = __("must be specified");
    } else if ((ac = userlist_get_member_accepting_chars(ff))
               && check_str(bb, ac) < 0) {
      comment = __("contains invalid characters");
    }

    switch (ff) {
    case CONTEST_MF_BIRTH_DATE:
    case CONTEST_MF_ENTRY_DATE:
    case CONTEST_MF_GRADUATION_DATE:
      display_date_change_dialog(fout, ff, bb, "<td class=\"borderless\">",
                                 "</td>");
      break;

    default:
      snprintf(varname, sizeof(varname), "param_%d", ff);
      fprintf(fout, "<td class=\"borderless\">%s</td>",
              html_input_text(bb, sizeof(bb), varname,
                              member_field_desc[ff].size,
                              ARMOR(bb)));
      break;
    }

    if (!comment) comment = "&nbsp;";
    fprintf(fout, "<td class=\"borderless\" valign=\"top\"><font color=\"red\"><i>%s</i></font></td>", comment);
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "</table>\n");

  fprintf(fout, "<table class=\"borderless\"><tr>");
  fprintf(fout, "<td class=\"borderless\">%s</td>",
          ns_submit_button(bb, sizeof(bb), 0,
                           NEW_SRV_ACTION_REG_CANCEL_MEMBER_EDITING, 0));
  fprintf(fout, "<td class=\"borderless\">%s</td>",
          ns_submit_button(bb, sizeof(bb), 0,
                           NEW_SRV_ACTION_REG_SUBMIT_MEMBER_EDITING, 0));
  fprintf(fout, "</table>");
  fprintf(fout, "</form>\n");

  html_armor_free(&ab);
}

static void
edit_page(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  unsigned char bb[1024];
  const unsigned char *status_style;
  const unsigned char *status_info;
  const struct userlist_user *u = phr->session_extra->user_info;
  int role = 0, member = 0;
  const struct userlist_member *m = 0;
  const unsigned char *s = 0, *n = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  // check that we are allowed to edit something
  if (!u || u->read_only || u->i.cnts_read_only) {
    goto redirect_back;
  }
  if (phr->action == NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE) {
    if (cgi_param_int(phr, "role", &role) < 0) goto redirect_back;
    if (cgi_param_int(phr, "member", &member) < 0) goto redirect_back;
    if (role < 0 || role >= CONTEST_M_GUEST) goto redirect_back;
    if (!cnts->members[role]) goto redirect_back;
    if (!u->i.members[role]) goto redirect_back;
    if (member < 0 || member >= u->i.members[role]->total) goto redirect_back;
    if (!(m = u->i.members[role]->members[member])) goto redirect_back;
  } else if (phr->action == NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE) {
  } else {
    goto redirect_back;
  }

  if (phr->action == NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE)
    s = _("Editing general info");
  else 
    s = _("Good!");

  n = phr->name;
  if (!n || !*n) n = phr->login;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %s]", s, ARMOR(n), extra->contest_arm);

  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>");
  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  fprintf(fout, "</tr></table></div>\n");

  fprintf(fout, "<div class=\"white_empty_block\">&nbsp;</div>\n");

  fprintf(fout, "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");
  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  fprintf(fout, "</tr></table></div>\n");
  if (extra->separator_txt && *extra->separator_txt) {
    fprintf(fout, "%s", extra->separator_txt);
  }

  // status row
  if (phr->reg_status < 0) {
    status_style = "server_status_off";
    status_info = __("NOT REGISTERED");
  } else if (phr->reg_status == USERLIST_REG_PENDING) {
    status_style = "server_status_alarm";
    status_info= __("REGISTERED, PENDING APPROVAL");
  } else if (phr->reg_status == USERLIST_REG_REJECTED) {
    status_style = "server_status_error";
    status_info = __("REGISTRATION REJECTED");
  } else if ((phr->reg_flags & USERLIST_UC_BANNED)) {
    status_style = "server_status_error";
    status_info = __("REGISTERED, BANNED");
  } else if ((phr->reg_flags & USERLIST_UC_LOCKED)) {
    status_style = "server_status_error";
    status_info = __("REGISTERED, LOCKED");
  } else if ((phr->reg_flags & USERLIST_UC_INVISIBLE)) {
    status_style = "server_status_on";
    status_info = __("REGISTERED (INVISIBLE)");
  } else {
    status_style = "server_status_on";
    status_info = __("REGISTERED");
  }
  fprintf(fout, "<div class=\"%s\">\n", status_style);
  fprintf(fout, "<b>%s</b>", gettext(status_info));
  fprintf(fout, "</div>\n");

  // main page goes here
  if (phr->action == NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE) {
    edit_member_form(fout, phr, cnts, m, role, member);
  } else {
    edit_general_form(fout, phr, cnts, u);
  }

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
  return;

 redirect_back:
  snprintf(bb, sizeof(bb), "%s?SID=%llx&action=%d",
           phr->self_url, phr->session_id,
           NEW_SRV_ACTION_REG_VIEW_GENERAL);
  html_armor_free(&ab);
  html_refresh_page_2(fout, bb);
}

static reg_action_handler_func_t reg_handlers[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE] = edit_page,
  [NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE] = edit_page,
};

void
ns_register_pages(FILE *fout, struct http_request_info *phr)
{
  int is_team = 0, r;
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = 0;
  unsigned char *user_info_xml = 0;

  if (phr->action == NEW_SRV_ACTION_CHANGE_LANGUAGE)
    return change_locale(fout, phr);

  if (!phr->session_id) return anon_register_pages(fout, phr);

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 0, 0);
  if ((r = userlist_clnt_get_cookie(ul_conn, ULS_GET_COOKIE,
                                    phr->ip, phr->ssl_flag,
                                    phr->session_id,
                                    &phr->user_id, &phr->contest_id,
                                    &phr->locale_id, 0, &phr->role, &is_team,
                                    &phr->reg_status, &phr->reg_flags,
                                    &phr->login, &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NOT_REGISTERED:
      return ns_html_err_inv_session(fout, phr, 0,
                                     "get_cookie failed: %s",
                                     userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return ns_html_err_ul_server_down(fout, phr, 0, 0);
    default:
      return ns_html_err_internal_error(fout, phr, 0, "get_cookie failed: %s",
                                        userlist_strerror(-r));
    }
  }

  if (phr->role > 0) {
    return ns_html_err_no_perm(fout, phr, 0, "role %d > 0", phr->role);
  }
  if (contests_get(phr->contest_id, &cnts) < 0 || !cnts) {
    return ns_html_err_no_perm(fout, phr, 0, "invalid contest_id %d",
                               phr->contest_id);
  }
  if (!cnts->disable_team_password && is_team) { 
    return ns_html_err_no_perm(fout, phr, 0, "participation cookie");
  }

  // check permissions
  if (cnts->closed ||
      !contests_check_register_ip_2(cnts, phr->ip, phr->ssl_flag)) {
    return ns_html_err_no_perm(fout, phr, 0, "registration is not available");
  }

  // check for local userlist_user structure and fetch it from the
  // server
  phr->session_extra = ns_get_session(phr->session_id, cur_time);

  if (!phr->session_extra->user_info) {
    if (userlist_clnt_get_info(ul_conn, ULS_PRIV_GET_USER_INFO,
                               phr->user_id, phr->contest_id,
                               &user_info_xml) < 0) {
      // FIXME: need better error reporting
      return ns_html_err_ul_server_down(fout, phr, 0, 0);
    }
    phr->session_extra->user_info = userlist_parse_user_str(user_info_xml);
    if (!phr->session_extra->user_info) {
      // FIXME: need better error reporting
      return ns_html_err_ul_server_down(fout, phr, 0, 0);
    }
    xfree(user_info_xml); user_info_xml = 0;
  }

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

  if (phr->action < 0 || phr->action >= NEW_SRV_ACTION_LAST) phr->action = 0;
  if (reg_handlers[phr->action])
    return (*reg_handlers[phr->action])(fout, phr, cnts, extra, cur_time);
  return main_page(fout, phr, cnts, extra, cur_time);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
