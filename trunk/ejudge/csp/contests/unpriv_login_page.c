/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[34] = "\"/>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str2[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str3[3] = " [";
static const unsigned char csp_str4[84] = "]</title></head>\n<body><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str5[9] = "]</div>\n";
static const unsigned char csp_str6[2] = "\n";
static const unsigned char csp_str7[100] = "\n<div class=\"user_actions\"><table class=\"menu\"><tr>\n<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str8[3] = ": ";
static const unsigned char csp_str9[60] = "</div></td>\n<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str10[13] = "</div></td>\n";
static const unsigned char csp_str11[48] = "<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str12[12] = "</div></td>";
static const unsigned char csp_str13[49] = "\n<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str14[33] = "</div></td>\n</tr></table></div>\n";
static const unsigned char csp_str15[99] = "\n<div class=\"white_empty_block\">&nbsp;</div>\n<div class=\"contest_actions\"><table class=\"menu\"><tr>";
static const unsigned char csp_str16[52] = "<td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str17[6] = "\n    ";
static const unsigned char csp_str18[53] = "\n<td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str19[69] = "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>";
static const unsigned char csp_str20[53] = "\n</tr></table></div>\n</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str21[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str22[4] = "\n%>";
static const unsigned char csp_str23[18] = "<div id=\"footer\">";
static const unsigned char csp_str24[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";


#line 2 "unpriv_login_page.csp"
/* $Id$ */

#line 2 "unpriv_includes.csp"
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

#line 5 "unpriv_login_page.csp"
#include "ejudge_cfg.h"
int csp_view_unpriv_login_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_unpriv_login_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_unpriv_login_page(void)
{
    return &page_iface;
}

int csp_view_unpriv_login_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "unpriv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr?phr->extra:NULL;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr?phr->cnts:NULL;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
  unsigned char time_buf[256] __attribute__((unused));
  int unread_clars __attribute__((unused)) = 0;
  int shown_items __attribute__((unused)) = 0;
  time_t sched_time __attribute__((unused)) = 0;
  time_t duration __attribute__((unused)) = 0;
  time_t fog_start_time __attribute__((unused)) = 0;
  struct teamdb_export tdb __attribute__((unused));
  struct sformat_extra_data fe __attribute__((unused));
  const struct section_global_data *global __attribute__((unused)) = cs?cs->global:NULL;
  time_t start_time __attribute__((unused)) = 0, stop_time __attribute__((unused)) = 0;

#line 11 "unpriv_login_page.csp"
time_t cur_time;
  int vis_flag = 0;
  const unsigned char *cnts_name = NULL;
  const unsigned char *login_str = NULL;
  const unsigned char *password_str = NULL;
  int orig_locale_id = phr->locale_id;

  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts) {
    FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
  }
  if (orig_locale_id < 0 && cnts->default_locale_num >= 0)
    phr->locale_id = cnts->default_locale_num;
  if (!contests_check_team_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
    fprintf(log_f, "%s://%s is not allowed for USER for contest %d\n",
            ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ipv6(&phr->ip), phr->contest_id);
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (cnts->closed) {
    fprintf(log_f, "contest %d is closed", cnts->id);
    FAIL(NEW_SRV_ERR_SERVICE_NOT_AVAILABLE);
  }
  if (!cnts->managed) {
    fprintf(log_f, "contest %d is not managed", cnts->id);
    FAIL(NEW_SRV_ERR_SERVICE_NOT_AVAILABLE);
  }

  extra = ns_get_contest_extra(phr->contest_id);
  if (!extra) FAIL(NEW_SRV_ERR_INTERNAL);

  cur_time = time(0);
  watched_file_update(&extra->header, cnts->team_header_file, cur_time);
  watched_file_update(&extra->menu_1, cnts->team_menu_1_file, cur_time);
  watched_file_update(&extra->menu_2, cnts->team_menu_2_file, cur_time);
  watched_file_update(&extra->separator, cnts->team_separator_file, cur_time);
  watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
  watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
  extra->header_txt = extra->header.text;
  extra->menu_1_txt = extra->menu_1.text;
  extra->menu_2_txt = extra->menu_2.text;
  extra->footer_txt = extra->footer.text;
  extra->separator_txt = extra->separator.text;
  extra->copyright_txt = extra->copyright.text;
  if (!extra->header_txt || !extra->footer_txt || !extra->separator_txt) {
    extra->header_txt = ns_fancy_header;
    if (extra->copyright_txt) extra->footer_txt = ns_fancy_footer_2;
    else extra->footer_txt = ns_fancy_footer;
    extra->separator_txt = ns_fancy_separator;
  }

  if (phr->locale_id == 0 && cnts->name_en) {
    cnts_name = html_armor_string_dup(cnts->name_en);
  } else {
    cnts_name = html_armor_string_dup(cnts->name);
  }

  ns_cgi_param(phr, "login", &login_str);
  ns_cgi_param(phr, "password", &password_str);

  l10n_setlocale(phr->locale_id);
fwrite(csp_str0, 1, 183, out_f);
fwrite("utf-8", 1, 5, out_f);
fwrite(csp_str1, 1, 33, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str2, 1, 37, out_f);
fputs(_("User login"), out_f);
fwrite(csp_str3, 1, 2, out_f);
fputs(html_armor_buf(&ab, (cnts_name)), out_f);
fwrite(csp_str4, 1, 83, out_f);
fputs(_("User login"), out_f);
fwrite(csp_str3, 1, 2, out_f);
fputs(html_armor_buf(&ab, (cnts_name)), out_f);
fwrite(csp_str5, 1, 8, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str6, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"contest_id\"", out_f);
if ((phr->contest_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str6, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"role\"", out_f);
if ((0)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%u", (unsigned)(0));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str6, 1, 1, out_f);

#line 80 "unpriv_login_page.csp"
if (cnts->disable_locale_change) {
fputs("<input type=\"hidden\" name=\"locale_id\"", out_f);
if ((phr->locale_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
fputs("\"", out_f);
}
fputs(" />", out_f);

#line 82 "unpriv_login_page.csp"
}
fwrite(csp_str7, 1, 99, out_f);
fputs(_("login"), out_f);
fwrite(csp_str8, 1, 2, out_f);
fputs("<input type=\"text\" name=\"login\" size=\"8\"", out_f);
if ((login_str)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (login_str)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 59, out_f);
fputs(_("password"), out_f);
fwrite(csp_str8, 1, 2, out_f);
fputs("<input type=\"password\" name=\"password\" size=\"8\"", out_f);
if ((password_str)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (password_str)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str10, 1, 12, out_f);

#line 86 "unpriv_login_page.csp"
if (!cnts->disable_locale_change) {
fwrite(csp_str11, 1, 47, out_f);
fputs(_("language"), out_f);
fwrite(csp_str8, 1, 2, out_f);

#line 87 "unpriv_login_page.csp"
l10n_html_locale_select(out_f, phr->locale_id);
fwrite(csp_str12, 1, 11, out_f);

#line 88 "unpriv_login_page.csp"
}
fwrite(csp_str13, 1, 48, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_MAIN_PAGE, _("Log in")), out_f);
fwrite(csp_str14, 1, 32, out_f);
fputs("</form>", out_f);
fwrite(csp_str15, 1, 98, out_f);

#line 95 "unpriv_login_page.csp"
if (cnts && cnts->assign_logins && cnts->force_registration
      && cnts->register_url
      && (cnts->reg_deadline <= 0 || cur_time < cnts->reg_deadline)) {
fwrite(csp_str16, 1, 51, out_f);

#line 99 "unpriv_login_page.csp"
if (phr->config->disable_new_users <= 0) {
      if (cnts->assign_logins) {
fwrite(csp_str17, 1, 5, out_f);
fwrite(csp_str17, 1, 5, out_f);
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Registration"), out_f);
fputs("</a>", out_f);

#line 105 "unpriv_login_page.csp"
} else {
fwrite(csp_str17, 1, 5, out_f);
fwrite(csp_str17, 1, 5, out_f);
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Registration"), out_f);
fputs("</a>", out_f);

#line 110 "unpriv_login_page.csp"
}
    }
fwrite(csp_str12, 1, 11, out_f);

#line 113 "unpriv_login_page.csp"
vis_flag++;
  } else if (cnts && cnts->register_url
             && (cnts->reg_deadline <= 0 || cur_time < cnts->reg_deadline)) {
fwrite(csp_str16, 1, 51, out_f);

#line 117 "unpriv_login_page.csp"
if (ejudge_config->disable_new_users <= 0) {
fwrite(csp_str17, 1, 5, out_f);
fwrite(csp_str17, 1, 5, out_f);
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Registration"), out_f);
fputs("</a>", out_f);

#line 122 "unpriv_login_page.csp"
}
fwrite(csp_str12, 1, 11, out_f);

#line 124 "unpriv_login_page.csp"
vis_flag++;
  }
fwrite(csp_str6, 1, 1, out_f);

#line 127 "unpriv_login_page.csp"
if (cnts && cnts->enable_password_recovery && cnts->disable_team_password) {
fwrite(csp_str6, 1, 1, out_f);
fwrite(csp_str17, 1, 5, out_f);
fwrite(csp_str17, 1, 5, out_f);
fwrite(csp_str18, 1, 52, out_f);
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_FORGOT_PASSWORD_1);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
(void) sep;
fputs("\">", out_f);
fputs(_("Forgot password?"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 12, out_f);

#line 134 "unpriv_login_page.csp"
vis_flag++;
  }
fwrite(csp_str6, 1, 1, out_f);

#line 137 "unpriv_login_page.csp"
if (!vis_flag) {
fwrite(csp_str19, 1, 68, out_f);

#line 139 "unpriv_login_page.csp"
}
fwrite(csp_str20, 1, 52, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str21, 1, 44, out_f);

#line 146 "unpriv_login_page.csp"
watched_file_update(&extra->welcome, cnts->welcome_file, cur_time);
  if (extra->welcome.text && extra->welcome.text[0]) {
    fprintf(out_f, "%s", extra->welcome.text);
  }
fwrite(csp_str22, 1, 3, out_f);
fwrite(csp_str23, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str24, 1, 37, out_f);

#line 153 "unpriv_login_page.csp"
l10n_setlocale(0);
cleanup:;
  html_armor_free(&ab);
  return retval;
}
