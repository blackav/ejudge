/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[34] = "\"/>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str2[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str3[83] = "</title></head>\n<body><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str4[8] = "</div>\n";
static const unsigned char csp_str5[53] = "\n<div class=\"user_actions\"><table class=\"menu\"><tr>\n";
static const unsigned char csp_str6[2] = "\n";
static const unsigned char csp_str7[48] = "<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str8[3] = ": ";
static const unsigned char csp_str9[12] = "</div></td>";
static const unsigned char csp_str10[49] = "\n<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str11[217] = "</div></td></tr></table></div>\n<div class=\"white_empty_block\">&nbsp;</div><div class=\"contest_actions\"><table class=\"menu\"><tr>\n<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td></tr></table></div>\n";
static const unsigned char csp_str12[32] = "</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str13[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str14[3] = "\n\n";
static const unsigned char csp_str15[31] = "\n<table>\n<tr><td class=\"menu\">";
static const unsigned char csp_str16[24] = ":</td><td class=\"menu\">";
static const unsigned char csp_str17[33] = "</td></tr>\n<tr><td class=\"menu\">";
static const unsigned char csp_str18[61] = "</td></tr>\n<tr><td class=\"menu\">&nbsp;</td><td class=\"menu\">";
static const unsigned char csp_str19[21] = "</td></tr>\n</table>\n";
static const unsigned char csp_str20[18] = "<div id=\"footer\">";
static const unsigned char csp_str21[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

/* $Id$ */
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
int csp_view_unpriv_recover_1_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_unpriv_recover_1_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_unpriv_recover_1_page(void)
{
    return &page_iface;
}

int csp_view_unpriv_recover_1_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
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
time_t cur_time = 0;
  unsigned char title[1024];

  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts) {
    FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
  }
  if (phr->locale_id < 0 && cnts->default_locale_num >= 0)
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
  if (!cnts->enable_password_recovery || (cnts->simple_registration && !cnts->send_passwd_email)) {
    fprintf(log_f, "contest %d password recovery disabled", cnts->id);
    FAIL(NEW_SRV_ERR_SERVICE_NOT_AVAILABLE);
  }

  unpriv_load_html_style(phr, cnts, &extra, &cur_time);
  l10n_setlocale(phr->locale_id);
  snprintf(title, sizeof(title), _("Lost password recovery [%s]"), extra->contest_arm);
fwrite(csp_str0, 1, 183, out_f);
fwrite("utf-8", 1, 5, out_f);
fwrite(csp_str1, 1, 33, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str2, 1, 37, out_f);
fputs((title), out_f);
fwrite(csp_str3, 1, 82, out_f);
fputs((title), out_f);
fwrite(csp_str4, 1, 7, out_f);
fwrite(csp_str5, 1, 52, out_f);
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
fputs("<input type=\"hidden\" name=\"action\"", out_f);
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(NEW_SRV_ACTION_FORGOT_PASSWORD_1));
fputs("\"", out_f);
fputs(" />", out_f);
fwrite(csp_str6, 1, 1, out_f);
if (cnts->disable_locale_change) {
fputs("<input type=\"hidden\" name=\"locale_id\"", out_f);
if ((phr->locale_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
}
if (!cnts->disable_locale_change) {
fwrite(csp_str7, 1, 47, out_f);
fputs(_("language"), out_f);
fwrite(csp_str8, 1, 2, out_f);
l10n_html_locale_select(out_f, phr->locale_id);
fwrite(csp_str9, 1, 11, out_f);
}
fwrite(csp_str10, 1, 48, out_f);
fwrite(csp_str11, 1, 216, out_f);
fwrite(csp_str12, 1, 31, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str13, 1, 44, out_f);
fwrite(csp_str6, 1, 1, out_f);
fputs(_("<p class=\"fixed_width\">Password recovery requires several steps. Now, please, specify the <b>login</b> and the <b>e-mail</b>, which was specified when the login was created.</p>\n<p class=\"fixed_width\">Note, that automatic password recovery is not possible for invisible, banned, locked, or privileged users!</p>"), out_f);
fwrite(csp_str14, 1, 2, out_f);
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
fwrite(csp_str15, 1, 30, out_f);
fputs(_("Login"), out_f);
fwrite(csp_str16, 1, 23, out_f);
fputs("<input type=\"text\" name=\"login\" size=\"16\" />", out_f);
fwrite(csp_str17, 1, 32, out_f);
fputs(_("E-mail"), out_f);
fwrite(csp_str16, 1, 23, out_f);
fputs("<input type=\"text\" name=\"email\" size=\"16\" />", out_f);
fwrite(csp_str18, 1, 60, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_FORGOT_PASSWORD_2, NULL), out_f);
fwrite(csp_str19, 1, 20, out_f);
fputs("</form>", out_f);
fwrite(csp_str6, 1, 1, out_f);
fwrite(csp_str20, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str21, 1, 37, out_f);
l10n_setlocale(0);
cleanup:;
  html_armor_free(&ab);
  return retval;
}
