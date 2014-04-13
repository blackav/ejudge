/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[34] = "\"/>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str2[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str3[83] = "</title></head>\n<body><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str4[8] = "</div>\n";
static const unsigned char csp_str5[2] = "\n";
static const unsigned char csp_str6[104] = "\n<div class=\"user_actions\"><table class=\"menu\"><tr>\n    <td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str7[3] = ": ";
static const unsigned char csp_str8[64] = "</div></td>\n    <td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str9[13] = "</div></td>\n";
static const unsigned char csp_str10[48] = "<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str11[12] = "</div></td>";
static const unsigned char csp_str12[53] = "\n    <td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str13[32] = "</div></td>\n</tr></table></div>";
static const unsigned char csp_str14[101] = "\n\n<div class=\"white_empty_block\">&nbsp;</div>\n<div class=\"contest_actions\"><table class=\"menu\"><tr>\n";
static const unsigned char csp_str15[52] = "<td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str16[12] = "</div></tr>";
static const unsigned char csp_str17[69] = "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>";
static const unsigned char csp_str18[23] = "\n</tr></table></div>\n\n";
static const unsigned char csp_str19[32] = "</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str20[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str21[5] = "<h2>";
static const unsigned char csp_str22[6] = "</h2>";
static const unsigned char csp_str23[4] = "<p>";
static const unsigned char csp_str24[2] = " ";
static const unsigned char csp_str25[9] = "</p>\n<p>";
static const unsigned char csp_str26[6] = "</p>\n";
static const unsigned char csp_str27[38] = "</p>\n\n<table class=\"b1\">\n    <tr><td>";
static const unsigned char csp_str28[14] = "</td><td><tt>";
static const unsigned char csp_str29[29] = "</tt></td></tr>\n    <tr><td>";
static const unsigned char csp_str30[33] = "</tt></td></tr>\n</table>\n\n<p><b>";
static const unsigned char csp_str31[10] = "</b></p>\n";
static const unsigned char csp_str32[18] = "<div id=\"footer\">";
static const unsigned char csp_str33[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

/* $Id: reg_login_page.csp 8106 2014-04-13 13:35:31Z cher $ */
#include "new-server.h"
#include "new_server_pi.h"
#include "new_server_proto.h"
#include "external_action.h"
#include "clarlog.h"
#include "misctext.h"
#include "runlog.h"
#include "l10n.h"
#include "prepare.h"
#include "xml_utils.h"
#include "teamdb.h"
#include "copyright.h"
#include "mischtml.h"
#include "html.h"
#include "userlist.h"
#include "sformat.h"

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
#include "ejudge_cfg.h"
int csp_view_reg_login_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_reg_login_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_reg_login_page(void)
{
    return &page_iface;
}

int csp_view_reg_login_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr?phr->extra:NULL;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr?phr->cnts:NULL;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
const unsigned char *login = 0, *password = 0, *email = 0;
  int item_cnt = 0, created_mode = 0;
  unsigned char title[1024];

  hr_cgi_param(phr, "login", &login);
  if (!login) login = "";
  hr_cgi_param(phr, "password", &password);
  if (!password) password = "";
  hr_cgi_param(phr, "email", &email);
  if (!email) email = "";

  l10n_setlocale(phr->locale_id);
  switch (phr->action) {
  case NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE:
    snprintf(title, sizeof(title), "%s [%s]", _("Activate new user account"), extra->contest_arm);
    created_mode = 1;
    break;
  default:
  case NEW_SRV_ACTION_REG_LOGIN_PAGE:
    snprintf(title, sizeof(title), "%s [%s]", _("Log in to edit registration data"), extra->contest_arm);
    break;
  }
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
if ((phr->action)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(phr->action));
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
fwrite(csp_str6, 1, 103, out_f);
fputs(_("login"), out_f);
fwrite(csp_str7, 1, 2, out_f);
fputs("<input type=\"text\" name=\"login\" size=\"20\"", out_f);
if ((login)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (login)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str8, 1, 63, out_f);
fputs(_("password"), out_f);
fwrite(csp_str7, 1, 2, out_f);
fputs("<input type=\"password\" name=\"password\" size=\"20\"", out_f);
if ((password)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (password)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 12, out_f);
if (!cnts->disable_locale_change) {
fwrite(csp_str10, 1, 47, out_f);
fputs(_("language"), out_f);
fwrite(csp_str7, 1, 2, out_f);
l10n_html_locale_select(out_f, phr->locale_id);
fwrite(csp_str11, 1, 11, out_f);
}
fwrite(csp_str12, 1, 52, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_REG_LOGIN, _("Log in")), out_f);
fwrite(csp_str13, 1, 31, out_f);
fputs("</form>", out_f);
fwrite(csp_str14, 1, 100, out_f);
if (phr->config->disable_new_users <= 0) {
    // "New account" "Forgot password?" "Enter contest"
fwrite(csp_str15, 1, 51, out_f);
if (created_mode) {
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
fputs("\">", out_f);
fputs(_("Create another account"), out_f);
fputs("</a>", out_f);
} else {
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
fputs("\">", out_f);
fputs(_("Create account"), out_f);
fputs("</a>", out_f);
}
fwrite(csp_str11, 1, 11, out_f);
item_cnt++;
  }
fwrite(csp_str5, 1, 1, out_f);
if (cnts->enable_password_recovery && cnts->disable_team_password
      && !cnts->simple_registration && !created_mode) {
fwrite(csp_str15, 1, 51, out_f);
fputs("<a class=\"menu\" href=\"", out_f);
hr_client_url(out_f, phr);
sep = ns_url_4(out_f, phr, NEW_SRV_ACTION_FORGOT_PASSWORD_1);
fputs("\">", out_f);
fputs(_("Recover forgot password"), out_f);
fputs("</a>", out_f);
fwrite(csp_str16, 1, 11, out_f);
item_cnt++;
  }
fwrite(csp_str5, 1, 1, out_f);
if (!item_cnt) {
fwrite(csp_str17, 1, 68, out_f);
}
fwrite(csp_str18, 1, 22, out_f);
fwrite(csp_str19, 1, 31, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str20, 1, 44, out_f);
fwrite(csp_str5, 1, 1, out_f);
if (phr->action == NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE) {
fwrite(csp_str21, 1, 4, out_f);
fputs(_("New user account is created"), out_f);
fwrite(csp_str22, 1, 5, out_f);
switch (((cnts->simple_registration & 1) << 1) | (cnts->assign_logins&1)) {
    case 0:                     /* !simple_registration && !assign_logins */
fwrite(csp_str23, 1, 3, out_f);
fprintf(out_f, _("New account <tt>%s</tt> is successfully created."), html_armor_buf(&ab, login));
fwrite(csp_str24, 1, 1, out_f);
fprintf(out_f, _("An e-mail messages is sent to the address <tt>%s</tt>."), html_armor_buf(&ab, email));
fwrite(csp_str24, 1, 1, out_f);
fputs(_("This message contains the password for the initial log in. You will be able to change the password later."), out_f);
fwrite(csp_str25, 1, 8, out_f);
fputs(_("Type the login and the password in to the form above and press the \"Log in\" button to activate the account."), out_f);
fwrite(csp_str25, 1, 8, out_f);
fputs(_("<b>Note</b>, that you should log in to the system for the first time no later, than in 24 hours after this moment, or the new account is removed."), out_f);
fwrite(csp_str26, 1, 5, out_f);
break;
    case 1:                     /* !simple_registration &&  assign_logins */
fwrite(csp_str23, 1, 3, out_f);
fputs(_("New account is successfully created."), out_f);
fwrite(csp_str24, 1, 1, out_f);
fprintf(out_f, _("An e-mail messages is sent to the address <tt>%s</tt>."), html_armor_buf(&ab, login));
fwrite(csp_str24, 1, 1, out_f);
fputs(_("This message contains the login name, assigned to you, as well as your password for initial log in. You will be able to change the password later."), out_f);
fwrite(csp_str25, 1, 8, out_f);
fputs(_("Type the login and the password in to the form above and press the \"Log in\" button to activate the account."), out_f);
fwrite(csp_str25, 1, 8, out_f);
fputs(_("<b>Note</b>, that you should log in to the system for the first time no later, than in 24 hours after this moment, or the new account is removed."), out_f);
fwrite(csp_str26, 1, 5, out_f);
break;
    case 2:                     /*  simple_registration && !assign_logins */
    case 3:                     /*  simple_registration &&  assign_logins */
fprintf(out_f,
              _("<p%s>New account <tt>%s</tt> is successfully created. Initial password is generated automatically. You will be able to change your password later. "),
              "", html_armor_buf(&ab, login));
      if (cnts->send_passwd_email)
        fprintf(out_f, _("An e-mail with your account parameters is sent to address <tt>%s</tt>. "), html_armor_buf(&ab, email));
fwrite(csp_str25, 1, 8, out_f);
fputs(_("The account parameters are as follows:"), out_f);
fwrite(csp_str27, 1, 37, out_f);
fputs(_("Login"), out_f);
fwrite(csp_str28, 1, 13, out_f);
if ((login) ) {
fputs(html_armor_buf(&ab, (login)), out_f);
}
fwrite(csp_str29, 1, 28, out_f);
fputs(_("E-mail"), out_f);
fwrite(csp_str28, 1, 13, out_f);
if ((email) ) {
fputs(html_armor_buf(&ab, (email)), out_f);
}
fwrite(csp_str29, 1, 28, out_f);
fputs(_("Password"), out_f);
fwrite(csp_str28, 1, 13, out_f);
if ((password) ) {
fputs(html_armor_buf(&ab, (password)), out_f);
}
fwrite(csp_str30, 1, 32, out_f);
fputs(_("Remember or write down the password!"), out_f);
fwrite(csp_str31, 1, 9, out_f);
}
  }
fwrite(csp_str5, 1, 1, out_f);
fwrite(csp_str32, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str33, 1, 37, out_f);
//cleanup:;
  l10n_setlocale(0);
  html_armor_free(&ab);
  return retval;
}
