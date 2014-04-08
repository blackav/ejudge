/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[34] = "\"/>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str2[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str3[83] = "</title></head>\n<body><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str4[8] = "</div>\n";
static const unsigned char csp_str5[361] = "\n<div class=\"user_actions\">\n    <table class=\"menu\">\n        <tr><td class=\"menu\"><div class=\"user_action_item\">&nbsp;</div></td></tr>\n    </table>\n</div>\n<div class=\"white_empty_block\">&nbsp;</div>\n<div class=\"contest_actions\">\n    <table class=\"menu\">\n        <tr><td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td></tr>\n    </table>\n</div>\n";
static const unsigned char csp_str6[32] = "</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str7[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str8[2] = "\n";
static const unsigned char csp_str9[5] = "\n<p>";
static const unsigned char csp_str10[29] = "</p>\n<font color=\"red\"><pre>";
static const unsigned char csp_str11[15] = "</pre></font>\n";
static const unsigned char csp_str12[18] = "<div id=\"footer\">";
static const unsigned char csp_str13[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

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
#include "userlist_clnt.h"
#include "userlist_proto.h"
int csp_view_unpriv_recover_2_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_unpriv_recover_2_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_unpriv_recover_2_page(void)
{
    return &page_iface;
}

int csp_view_unpriv_recover_2_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
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
time_t cur_time;
  const unsigned char *login = 0, *email = 0;
  int r;
  unsigned char title[1024];

  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts) {
    FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
  }
  if (phr->locale_id < 0 && cnts->default_locale_num >= 0)
    phr->locale_id = cnts->default_locale_num;
  if (!contests_check_team_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
    fprintf(log_f, "%s://%s is not allowed for USER for contest %d",
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

  if (hr_cgi_param(phr, "login", &login) <= 0) {
    fprintf(log_f, "login is not specified");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (hr_cgi_param(phr, "email", &email) <= 0) {
    fprintf(log_f, "email is not specified");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  }
  r = userlist_clnt_register_new(ul_conn, ULS_RECOVER_PASSWORD_1,
                                 &phr->ip, phr->ssl_flag,
                                 phr->contest_id,
                                 phr->locale_id,
                                 NEW_SRV_ACTION_FORGOT_PASSWORD_3,
                                 login, email, phr->self_url);

  unpriv_load_html_style(phr, cnts, &extra, &cur_time);
  l10n_setlocale(phr->locale_id);
  if (r < 0) {
    snprintf(title, sizeof(title), "%s", _("Password recovery error"));
  } else {
    snprintf(title, sizeof(title), _("Password recovery, stage 1 [%s, %s]"),
             html_armor_buf(&ab, login), extra->contest_arm);
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
fwrite(csp_str5, 1, 360, out_f);
fwrite(csp_str6, 1, 31, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str7, 1, 44, out_f);
fwrite(csp_str8, 1, 1, out_f);
if (r < 0) {
fwrite(csp_str9, 1, 4, out_f);
fputs(_("Password recovery is not possible because of the following error."), out_f);
fwrite(csp_str10, 1, 28, out_f);
if (r == -ULS_ERR_EMAIL_FAILED) {
fputs(_("The server was unable to send a registration e-mail\nto the specified address. This is probably due\nto heavy server load rather than to an invalid\ne-mail address. You should try to register later.\n"), out_f);
} else {
      fprintf(log_f, gettext(userlist_strerror(-r)));
    }
fwrite(csp_str11, 1, 14, out_f);
} else {
fwrite(csp_str8, 1, 1, out_f);
fputs(_("<p class=\"fixed_width\">First stage of password recovery is successful. You should receive an e-mail message with further instructions. <b>Note,</b> that you should confirm password recovery in 24 hours, or operation will be cancelled.</p>"), out_f);
fwrite(csp_str8, 1, 1, out_f);
}
fwrite(csp_str8, 1, 1, out_f);
fwrite(csp_str12, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str13, 1, 37, out_f);
l10n_setlocale(0);
cleanup:;
  html_armor_free(&ab);
  return retval;
}
