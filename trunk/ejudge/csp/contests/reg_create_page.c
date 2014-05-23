/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[34] = "\"/>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str2[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str3[83] = "</title></head>\n<body><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str4[8] = "</div>\n";
static const unsigned char csp_str5[2] = "\n";
static const unsigned char csp_str6[53] = "\n<div class=\"user_actions\"><table class=\"menu\"><tr>\n";
static const unsigned char csp_str7[48] = "<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str8[3] = ": ";
static const unsigned char csp_str9[12] = "</div></td>";
static const unsigned char csp_str10[57] = "\n<td class=\"menu\"><div class=\"user_action_item\">e-mail: ";
static const unsigned char csp_str11[13] = "</div></td>\n";
static const unsigned char csp_str12[60] = "</div></td>\n<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str13[21] = "\n</tr></table></div>";
static const unsigned char csp_str14[151] = "\n<div class=\"white_empty_block\">&nbsp;</div>\n<div class=\"contest_actions\"><table class=\"menu\"><tr>\n<td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str15[33] = "</div></td>\n</tr></table></div>\n";
static const unsigned char csp_str16[32] = "</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str17[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str18[24] = "\n<h2><font color=\"red\">";
static const unsigned char csp_str19[36] = "</font></h2>\n\n<p><font color=\"red\">";
static const unsigned char csp_str20[13] = "</font></p>\n";
static const unsigned char csp_str21[7] = "\n\n<h2>";
static const unsigned char csp_str22[8] = "</h2>\n\n";
static const unsigned char csp_str23[5] = "\n<p>";
static const unsigned char csp_str24[6] = "</p>\n";
static const unsigned char csp_str25[2] = " ";
static const unsigned char csp_str26[9] = "</p>\n<p>";
static const unsigned char csp_str27[7] = ".</p>\n";
static const unsigned char csp_str28[6] = "\n\n<p>";
static const unsigned char csp_str29[10] = "</p>\n\n<p>";
static const unsigned char csp_str30[4] = ": \n";
static const unsigned char csp_str31[18] = ".\n\n<p>&nbsp;</p>\n";
static const unsigned char csp_str32[18] = "<div id=\"footer\">";
static const unsigned char csp_str33[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

/* $Id: reg_create_page.csp 8243 2014-05-23 12:11:56Z cher $ */
#include "ejudge/new-server.h"
#include "ejudge/new_server_pi.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/external_action.h"
#include "ejudge/clarlog.h"
#include "ejudge/misctext.h"
#include "ejudge/runlog.h"
#include "ejudge/l10n.h"
#include "ejudge/prepare.h"
#include "ejudge/xml_utils.h"
#include "ejudge/teamdb.h"
#include "ejudge/copyright.h"
#include "ejudge/mischtml.h"
#include "ejudge/html.h"
#include "ejudge/userlist.h"
#include "ejudge/sformat.h"

#include "reuse/xalloc.h"

#include <libintl.h>
#define _(x) gettext(x)

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

void
unpriv_load_html_style(struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra **p_extra,
                       time_t *p_cur_time);
void
do_json_user_state(FILE *fout, const serve_state_t cs, int user_id,
                   int need_reload_check);
#include "ejudge/ejudge_cfg.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
int csp_view_reg_create_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_reg_create_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_reg_create_page(void)
{
    return &page_iface;
}

int csp_view_reg_create_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr?phr->extra:NULL;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr?phr->cnts:NULL;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
const unsigned char *login = 0, *email = 0;
  int reg_error = 0, reg_ul_error = 0;
  int regular_flag = 0;
  int allowed_info_edit = 0;
  int i, j;
  unsigned char title[1024];

  if (phr->config->disable_new_users > 0) {
    fprintf(phr->log_f, "registration is not available\n");
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }
if (hr_cgi_param_int_opt(phr, "retval", &(reg_error), 0) < 0) {
  FAIL(NEW_SRV_ERR_INV_PARAM);
}
if (hr_cgi_param_int_opt(phr, "ul_error", &(reg_ul_error), 0) < 0) {
  FAIL(NEW_SRV_ERR_INV_PARAM);
}
if (hr_cgi_param_int_opt(phr, "regular", &(regular_flag), 0) < 0) {
  FAIL(NEW_SRV_ERR_INV_PARAM);
}
if (cnts->assign_logins) {
    if (!cnts->disable_name) allowed_info_edit = 1;
    if (!cnts->force_registration) allowed_info_edit = 1;
    if (!cnts->autoregister) allowed_info_edit = 1;
    for (j = 0; j < CONTEST_LAST_FIELD; j++)
      if (cnts->fields[j])
        allowed_info_edit = 1;
    for (i = 0; i < CONTEST_LAST_MEMBER; i++)
      if (cnts->members[i] && cnts->members[i]->max_count > 0)
        allowed_info_edit = 1;
    
    (void) allowed_info_edit;
  } else {
hr_cgi_param(phr, "login", &(login));
if (!login) login = "";
  }
hr_cgi_param(phr, "email", &(email));
if (!email) email = "";

  l10n_setlocale(phr->locale_id);
  snprintf(title, sizeof(title), "%s [%s]", _("Create user account"), extra->contest_arm);
fwrite(csp_str0, 1, 183, out_f);
fwrite("utf-8", 1, 5, out_f);
fwrite(csp_str1, 1, 33, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str2, 1, 37, out_f);
fputs((title), out_f);
fwrite(csp_str3, 1, 82, out_f);
fputs((title), out_f);
fwrite(csp_str4, 1, 7, out_f);
fwrite(csp_str5, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str5, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"contest_id\"", out_f);
if ((phr->contest_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str5, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"next_action\"", out_f);
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE));
fputs("\"", out_f);
fputs(" />", out_f);
fwrite(csp_str5, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"regular\"", out_f);
if ((regular_flag)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(regular_flag));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str5, 1, 1, out_f);
if (cnts->disable_locale_change) {
fputs("<input type=\"hidden\" name=\"locale_id\"", out_f);
if ((phr->locale_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
}
fwrite(csp_str6, 1, 52, out_f);
if (!cnts->assign_logins) {
fwrite(csp_str7, 1, 47, out_f);
fputs(_("login"), out_f);
fwrite(csp_str8, 1, 2, out_f);
fputs("<input type=\"text\" name=\"login\" size=\"20\"", out_f);
if ((login) ) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (login)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 11, out_f);
}
fwrite(csp_str10, 1, 56, out_f);
fputs("<input type=\"text\" name=\"email\" size=\"20\"", out_f);
if ((email) ) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (email)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str11, 1, 12, out_f);
if (cnts->assign_logins) {
    if (phr->config->disable_new_users <= 0) {
fwrite(csp_str7, 1, 47, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_REG_CREATE_ACCOUNT, _("Create account")), out_f);
fwrite(csp_str9, 1, 11, out_f);
}
fwrite(csp_str5, 1, 1, out_f);
if (!cnts->disable_locale_change) {
fwrite(csp_str7, 1, 47, out_f);
fputs(_("language"), out_f);
fwrite(csp_str8, 1, 2, out_f);
l10n_html_locale_select(out_f, phr->locale_id);
fwrite(csp_str12, 1, 59, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CHANGE_LANGUAGE, _("Change language")), out_f);
fwrite(csp_str9, 1, 11, out_f);
}
  } else {
    if (!cnts->disable_locale_change) {
fwrite(csp_str7, 1, 47, out_f);
fputs(_("language"), out_f);
fwrite(csp_str8, 1, 2, out_f);
l10n_html_locale_select(out_f, phr->locale_id);
fwrite(csp_str9, 1, 11, out_f);
}
    if (phr->config->disable_new_users <= 0) {
fwrite(csp_str7, 1, 47, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_REG_CREATE_ACCOUNT, _("Create account")), out_f);
fwrite(csp_str9, 1, 11, out_f);
}
  }
fwrite(csp_str13, 1, 20, out_f);
fputs("</form>", out_f);
fwrite(csp_str14, 1, 150, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_LOGIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Use an existing account"), out_f);
fputs("</a>", out_f);
fwrite(csp_str15, 1, 32, out_f);
fwrite(csp_str16, 1, 31, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str17, 1, 44, out_f);
fwrite(csp_str5, 1, 1, out_f);
if (reg_error || reg_ul_error) {
    if (reg_error < 0) reg_error = -reg_error;
    if (reg_ul_error < 0) reg_ul_error = -reg_ul_error;
fwrite(csp_str18, 1, 23, out_f);
fputs(_("Registration errors"), out_f);
fwrite(csp_str19, 1, 35, out_f);
if (reg_ul_error == ULS_ERR_EMAIL_FAILED) {
fputs(_("The server was unable to send a registration e-mail\nto the specified address. This is probably due\nto heavy server load rather than to an invalid\ne-mail address. You should try to register later.\n"), out_f);
} else if (reg_ul_error) {
      fprintf(out_f, "%s.", gettext(userlist_strerror(reg_ul_error)));
    } else if (reg_error) {
      fprintf(out_f, "%s.", ns_strerror_2(reg_error));
    }
fwrite(csp_str20, 1, 12, out_f);
}
fwrite(csp_str21, 1, 6, out_f);
fputs(_("Registration rules"), out_f);
fwrite(csp_str22, 1, 7, out_f);
if (cnts->assign_logins) {
fwrite(csp_str23, 1, 4, out_f);
fputs(_("Please, enter your valid e-mail address and press the \"Create account\" button."), out_f);
fwrite(csp_str24, 1, 5, out_f);
if (cnts->simple_registration && !regular_flag) {
fwrite(csp_str23, 1, 4, out_f);
fputs(_("This contest operates in \"simplified registration\" mode. You will get your login and password immediately after account is created."), out_f);
fwrite(csp_str25, 1, 1, out_f);
if (cnts->send_passwd_email) {
fputs(_("An email message will be sent to you just for your convenience."), out_f);
} else {
fputs(_("No email message at all will be sent to you."), out_f);
}
fwrite(csp_str26, 1, 8, out_f);
fputs(_("Accounts created using simplified registration procedure cannot be used for participation in contests, which do not allow simplified registration. If you want a regular account, you may create an account using the"), out_f);
fwrite(csp_str25, 1, 1, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("regular=", out_f);
fprintf(out_f, "%d", (int)(1));
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
(void) sep;
fputs("\">", out_f);
fputs(_("regular registration"), out_f);
fputs("</a>", out_f);
fwrite(csp_str27, 1, 6, out_f);
} else {
fwrite(csp_str5, 1, 1, out_f);
if (!cnts->simple_registration || cnts->send_passwd_email) {
fwrite(csp_str23, 1, 4, out_f);
fputs(_("You should receive an e-mail message with a login and a password to the system. Use this password for the first log in. After the first login you will be able to change the password."), out_f);
fwrite(csp_str26, 1, 8, out_f);
fputs(_("Be careful and type the e-mail address correctly. If you make a mistake, you will not receive a registration e-mail and be unable to complete the registration process."), out_f);
fwrite(csp_str24, 1, 5, out_f);
}
fwrite(csp_str5, 1, 1, out_f);
if (cnts->simple_registration) {
fwrite(csp_str23, 1, 4, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Simplified registration"), out_f);
fputs("</a>", out_f);
fwrite(csp_str25, 1, 1, out_f);
fputs(_("is available for this contest. Note, however, that simplified registration imposes certain restrictions on further use of the account!"), out_f);
fwrite(csp_str24, 1, 5, out_f);
}
fwrite(csp_str5, 1, 1, out_f);
}
fwrite(csp_str5, 1, 1, out_f);
} else {
fwrite(csp_str23, 1, 4, out_f);
fputs(_("To create an account, please think out, a login and provide your valid e-mail address in the form above. Then press the \\\"Create account\\\" button."), out_f);
fwrite(csp_str26, 1, 8, out_f);
fputs(_("Login may contain only latin letters, digits, <tt>.</tt> (dot), <tt>-</tt> (minus sign), <tt>_</tt> (undescore)."), out_f);
fwrite(csp_str24, 1, 5, out_f);
if (cnts->simple_registration && !regular_flag) {
fwrite(csp_str23, 1, 4, out_f);
fputs(_("This contest operates in \\\"simplified registration\\\" mode. You will get your login and password immediately after account is created."), out_f);
fwrite(csp_str25, 1, 1, out_f);
if (cnts->send_passwd_email) {
fputs(_("An email message will be sent to you just for your convenience."), out_f);
} else {
fputs(_("No email message at all will be sent to you."), out_f);
}
fwrite(csp_str26, 1, 8, out_f);
fputs(_("Accounts created using simplified registration procedure cannot be used for participation in contests, which do not allow simplified registration. If you want a regular account, you may create an account using the"), out_f);
fwrite(csp_str25, 1, 1, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("regular=", out_f);
fprintf(out_f, "%d", (int)(1));
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
(void) sep;
fputs("\">", out_f);
fputs(_("regular registration"), out_f);
fputs("</a>", out_f);
fwrite(csp_str27, 1, 6, out_f);
} else {
fwrite(csp_str5, 1, 1, out_f);
if (!cnts->simple_registration || cnts->send_passwd_email) {
fwrite(csp_str23, 1, 4, out_f);
fputs(_("You should receive an e-mail message with a password to the system. Use this password for the first log in. After the first login you will be able to change the password."), out_f);
fwrite(csp_str26, 1, 8, out_f);
fputs(_("Be careful and type the e-mail address correctly. If you make a mistake, you will not receive a registration e-mail and be unable to complete the registration process."), out_f);
fwrite(csp_str24, 1, 5, out_f);
}
fwrite(csp_str5, 1, 1, out_f);
if (cnts->simple_registration) {
fwrite(csp_str23, 1, 4, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Simplified registration"), out_f);
fputs("</a>", out_f);
fwrite(csp_str25, 1, 1, out_f);
fputs(_("is available for this contest. Note, however, that simplified registration imposes certain restrictions on further use of the account!"), out_f);
fwrite(csp_str24, 1, 5, out_f);
}
fwrite(csp_str5, 1, 1, out_f);
}
fwrite(csp_str5, 1, 1, out_f);
}
fwrite(csp_str28, 1, 5, out_f);
fputs(_("<b>Note</b>, that you must log in 24 hours after the form is filled and submitted, or your registration will be cancelled!"), out_f);
fwrite(csp_str29, 1, 9, out_f);
fputs(_("If you already have an ejudge account on this server, you may use it. If so, follow the link"), out_f);
fwrite(csp_str30, 1, 3, out_f);
fwrite(csp_str5, 1, 1, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_LOGIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Use an existing account"), out_f);
fputs("</a>", out_f);
fwrite(csp_str31, 1, 17, out_f);
watched_file_update(&extra->reg_welcome, cnts->reg_welcome_file, phr->current_time);
  if (extra->reg_welcome.text && extra->reg_welcome.text[0])
    fprintf(out_f, "%s", extra->reg_welcome.text);
fwrite(csp_str5, 1, 1, out_f);
fwrite(csp_str32, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str33, 1, 37, out_f);
cleanup:;
  l10n_setlocale(0);
  html_armor_free(&ab);
  return retval;
}
