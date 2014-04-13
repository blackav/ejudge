/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[34] = "\"/>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str2[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str3[83] = "</title></head>\n<body><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str4[8] = "</div>\n";
static const unsigned char csp_str5[108] = "\n<div class=\"user_actions\"><table class=\"menu\"><tr>\n    <td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str6[68] = "</div></td>\n    <td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str7[3] = " [";
static const unsigned char csp_str8[2] = "]";
static const unsigned char csp_str9[79] = "</div></td>\n</tr></table></div>\n\n<div class=\"white_empty_block\">&nbsp;</div>\n\n";
static const unsigned char csp_str10[110] = "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n    <td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str11[12] = "</div></td>";
static const unsigned char csp_str12[52] = "<td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str13[6] = "\n    ";
static const unsigned char csp_str14[2] = "\n";
static const unsigned char csp_str15[69] = "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>";
static const unsigned char csp_str16[23] = "\n</tr></table></div>\n\n";
static const unsigned char csp_str17[32] = "</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str18[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str19[3] = "\n\n";
static const unsigned char csp_str20[35] = "<div class=\"server_status_off\"><b>";
static const unsigned char csp_str21[5] = "</b>";
static const unsigned char csp_str22[37] = "<div class=\"server_status_error\"><b>";
static const unsigned char csp_str23[37] = "<div class=\"server_status_alarm\"><b>";
static const unsigned char csp_str24[34] = "<div class=\"server_status_on\"><b>";
static const unsigned char csp_str25[4] = "<b>";
static const unsigned char csp_str26[6] = "/ <b>";
static const unsigned char csp_str27[6] = "\n<h2>";
static const unsigned char csp_str28[7] = "</h2>\n";
static const unsigned char csp_str29[44] = "\n<table class=\"b0\">\n    <tr><td class=\"b0\">";
static const unsigned char csp_str30[107] = ":</td><td class=\"b0\"><input type=\"password\" name=\"oldpasswd\" size=\"16\"/></td></tr>\n    <tr><td class=\"b0\">";
static const unsigned char csp_str31[108] = ":</td><td class=\"b0\"><input type=\"password\" name=\"newpasswd1\" size=\"16\"/></td></tr>\n    <tr><td class=\"b0\">";
static const unsigned char csp_str32[120] = ":</td><td class=\"b0\"><input type=\"password\" name=\"newpasswd2\" size=\"16\"/></td></tr>\n    <tr><td class=\"b0\" colspan=\"2\">";
static const unsigned char csp_str33[21] = "</td></tr>\n</table>\n";
static const unsigned char csp_str34[39] = "\n<table class=\"b0\"><tr><td class=\"b0\">";
static const unsigned char csp_str35[21] = "</td><td class=\"b0\">";
static const unsigned char csp_str36[20] = "</td></tr></table>\n";
static const unsigned char csp_str37[18] = "<div id=\"footer\">";
static const unsigned char csp_str38[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

/* $Id: reg_main_page.csp 8106 2014-04-13 13:35:31Z cher $ */
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
// local includes go here
void
ns_reg_main_page_view_info(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time);
int csp_view_reg_main_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_reg_main_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_reg_main_page(void)
{
    return &page_iface;
}

int csp_view_reg_main_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr?phr->extra:NULL;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr?phr->cnts:NULL;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
// local variables go here
  int shown_items = 0;
  const unsigned char *title2 = "", *n = 0;
  struct userlist_user *u = 0;
  const struct userlist_user_info *ui = 0;
  unsigned char title[1024];

// initial code goes here
  l10n_setlocale(phr->locale_id);

  switch (phr->action) {
  case NEW_SRV_ACTION_REG_VIEW_CONTESTANTS:
    title2 = _("Viewing contestants");
    break;

  case NEW_SRV_ACTION_REG_VIEW_RESERVES:
    title2 = _("Viewing reserves");
    break;

  case NEW_SRV_ACTION_REG_VIEW_COACHES:
    title2 = _("Viewing coaches");
    break;

  case NEW_SRV_ACTION_REG_VIEW_ADVISORS:
    title2 = _("Viewing advisors");
    break;

  case NEW_SRV_ACTION_REG_VIEW_GUESTS:
    title2 = _("Viewing guests");
    break;

  case NEW_SRV_ACTION_VIEW_SETTINGS:
    title2 = _("Viewing settings");
    break;

  case NEW_SRV_ACTION_REG_VIEW_GENERAL:
  default:
    title2 = _("Viewing general info");
    break;
  }

  n = phr->name;
  if (!n || !*n) n = phr->login;

  snprintf(title, sizeof(title), "%s [%s, %s]", title2, html_armor_buf(&ab, n), extra->contest_arm);
fwrite(csp_str0, 1, 183, out_f);
fwrite("utf-8", 1, 5, out_f);
fwrite(csp_str1, 1, 33, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str2, 1, 37, out_f);
fputs((title), out_f);
fwrite(csp_str3, 1, 82, out_f);
fputs((title), out_f);
fwrite(csp_str4, 1, 7, out_f);
fwrite(csp_str5, 1, 107, out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_SETTINGS) {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_SETTINGS);
fputs("\">", out_f);
}
fputs(_("Settings"), out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_SETTINGS) {
fputs("</a>", out_f);
}
fwrite(csp_str6, 1, 67, out_f);
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_LOGOUT);
fputs("\">", out_f);
fputs(_("Logout"), out_f);
fwrite(csp_str7, 1, 2, out_f);
fputs(html_armor_buf(&ab, (phr->login)), out_f);
fwrite(csp_str8, 1, 1, out_f);
fputs("</a>", out_f);
fwrite(csp_str9, 1, 78, out_f);
shown_items = 0;
fwrite(csp_str10, 1, 109, out_f);
if (!(phr->action >= NEW_SRV_ACTION_REG_VIEW_GENERAL && phr->action <= NEW_SRV_ACTION_REG_VIEW_GUESTS)) {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL);
fputs("\">", out_f);
}
fputs(_("User info"), out_f);
if (!(phr->action >= NEW_SRV_ACTION_REG_VIEW_GENERAL && phr->action <= NEW_SRV_ACTION_REG_VIEW_GUESTS)) {
fputs("</a>", out_f);
}
fwrite(csp_str11, 1, 11, out_f);
shown_items++;
if (phr->reg_status == USERLIST_REG_OK
      && !(phr->reg_flags &~USERLIST_UC_INVISIBLE)
      && contests_check_team_ip_2(cnts, &phr->ip, phr->ssl_flag)
      && !cnts->closed) {
fwrite(csp_str12, 1, 51, out_f);
if (cnts->disable_team_password) {
fputs("<a class=\"menu\" href=\"", out_f);
hr_client_url(out_f, phr);
sep = ns_url_3(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);
} else {
fwrite(csp_str13, 1, 5, out_f);
fputs("<a class=\"menu\" href=\"", out_f);
hr_client_url(out_f, phr);
sep = ns_url_4(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
if (phr->login) {
fputs(sep, out_f); sep = "&amp;";
fputs("login=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (phr->login));
fputs(hbuf, out_f);
}
(void) sep;
fputs("\">", out_f);
}
fputs(_("Participate"), out_f);
fputs("</a>", out_f);
shown_items++;
fwrite(csp_str11, 1, 11, out_f);
}
fwrite(csp_str14, 1, 1, out_f);
if (!shown_items) {
fwrite(csp_str15, 1, 68, out_f);
}
fwrite(csp_str16, 1, 22, out_f);
fwrite(csp_str17, 1, 31, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str18, 1, 44, out_f);
fwrite(csp_str19, 1, 2, out_f);
// status row
  if (phr->reg_status < 0) {
fwrite(csp_str20, 1, 34, out_f);
fputs(_("NOT REGISTERED"), out_f);
fwrite(csp_str21, 1, 4, out_f);
} else if (phr->reg_status == USERLIST_REG_PENDING) {
    if ((phr->reg_flags & USERLIST_UC_INCOMPLETE)) {
fwrite(csp_str22, 1, 36, out_f);
fputs(_("REGISTERED, PENDING APPROVAL"), out_f);
fputs(_(", REGISTRATION DATA INCOMPLETE"), out_f);
fwrite(csp_str21, 1, 4, out_f);
} else {
fwrite(csp_str23, 1, 36, out_f);
fputs(_("REGISTERED, PENDING APPROVAL"), out_f);
fwrite(csp_str21, 1, 4, out_f);
}
  } else if (phr->reg_status == USERLIST_REG_REJECTED) {
fwrite(csp_str22, 1, 36, out_f);
fputs(_("REGISTRATION REJECTED"), out_f);
fwrite(csp_str21, 1, 4, out_f);
} else if ((phr->reg_flags & USERLIST_UC_BANNED)) {
fwrite(csp_str22, 1, 36, out_f);
fputs(_("REGISTERED, BANNED"), out_f);
fwrite(csp_str21, 1, 4, out_f);
} else if ((phr->reg_flags & USERLIST_UC_LOCKED)) {
fwrite(csp_str22, 1, 36, out_f);
fputs(_("REGISTERED, LOCKED"), out_f);
fwrite(csp_str21, 1, 4, out_f);
} else if ((phr->reg_flags & USERLIST_UC_INVISIBLE)) {
    if ((phr->reg_flags & USERLIST_UC_INCOMPLETE)) {
fwrite(csp_str22, 1, 36, out_f);
fputs(_("REGISTERED (INVISIBLE)"), out_f);
fputs(_(", REGISTRATION DATA INCOMPLETE"), out_f);
fwrite(csp_str21, 1, 4, out_f);
} else {
fwrite(csp_str24, 1, 33, out_f);
fputs(_("REGISTERED (INVISIBLE)"), out_f);
fwrite(csp_str21, 1, 4, out_f);
}
  } else {
    if ((phr->reg_flags & USERLIST_UC_INCOMPLETE)) {
fwrite(csp_str22, 1, 36, out_f);
fputs(_("REGISTERED"), out_f);
fputs(_(", REGISTRATION DATA INCOMPLETE"), out_f);
fwrite(csp_str21, 1, 4, out_f);
} else {
fwrite(csp_str24, 1, 33, out_f);
fputs(_("REGISTERED"), out_f);
fwrite(csp_str21, 1, 4, out_f);
}
  }
if (phr->reg_status < 0) {
fwrite(csp_str25, 1, 3, out_f);
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_REGISTER);
fputs("\">", out_f);
fputs(_("Confirm registration"), out_f);
fputs("</a>", out_f);
fwrite(csp_str21, 1, 4, out_f);
}
u = phr->session_extra->user_info;
  if (u) ui = userlist_get_cnts0(u);
  if (u->read_only || (ui && ui->cnts_read_only)) {
fwrite(csp_str26, 1, 5, out_f);
fputs(_("READ-ONLY"), out_f);
fwrite(csp_str21, 1, 4, out_f);
}
fwrite(csp_str4, 1, 7, out_f);
if (phr->action == NEW_SRV_ACTION_VIEW_SETTINGS) {
if (!cnts->disable_password_change) {
    /* change the password */
fwrite(csp_str27, 1, 5, out_f);
fputs(_("Change password"), out_f);
fwrite(csp_str28, 1, 6, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str29, 1, 43, out_f);
fputs(_("Old password"), out_f);
fwrite(csp_str30, 1, 106, out_f);
fputs(_("New password"), out_f);
fwrite(csp_str31, 1, 107, out_f);
fputs(_("Retype new password"), out_f);
fwrite(csp_str32, 1, 119, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CHANGE_PASSWORD, _("Change!")), out_f);
fwrite(csp_str33, 1, 20, out_f);
fputs("</form>", out_f);
fwrite(csp_str14, 1, 1, out_f);
}
#if CONF_HAS_LIBINTL - 0 == 1
  if (!cnts->disable_locale_change) {
fwrite(csp_str27, 1, 5, out_f);
fputs(_("Change language"), out_f);
fwrite(csp_str28, 1, 6, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str14, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"next_action\"", out_f);
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(NEW_SRV_ACTION_VIEW_SETTINGS));
fputs("\"", out_f);
fputs(" />", out_f);
fwrite(csp_str34, 1, 38, out_f);
fputs(_("Change language"), out_f);
fwrite(csp_str35, 1, 20, out_f);
l10n_html_locale_select(out_f, phr->locale_id);
fwrite(csp_str35, 1, 20, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CHANGE_LANGUAGE, _("Change")), out_f);
fwrite(csp_str36, 1, 19, out_f);
fputs("</form>", out_f);
fwrite(csp_str14, 1, 1, out_f);
}
#endif /* CONF_HAS_LIBINTL */
} else {
    ns_reg_main_page_view_info(out_f, phr, cnts, extra, phr->current_time);
  }
fwrite(csp_str14, 1, 1, out_f);
fwrite(csp_str37, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str38, 1, 37, out_f);
//cleanup:;
  l10n_setlocale(0);
  html_armor_free(&ab);
  return retval;
}
