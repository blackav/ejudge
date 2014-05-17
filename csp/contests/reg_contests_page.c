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
static const unsigned char csp_str9[33] = "</div></td>\n</tr></table></div>\n";
static const unsigned char csp_str10[194] = "\n\n<div class=\"white_empty_block\">&nbsp;</div>\n<div class=\"contest_actions\"><table class=\"menu\"><tr>\n    <td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>\n</tr></table></div>\n";
static const unsigned char csp_str11[32] = "</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str12[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str13[6] = "\n<h2>";
static const unsigned char csp_str14[7] = "</h2>\n";
static const unsigned char csp_str15[83] = "\n<table class=\"b1\">\n    <tr>\n        <td class=\"b1\">N</td>\n        <td class=\"b1\">";
static const unsigned char csp_str16[30] = "</td>\n        <td class=\"b1\">";
static const unsigned char csp_str17[17] = "</td>\n    </tr>\n";
static const unsigned char csp_str18[9] = "\n    <tr";
static const unsigned char csp_str19[26] = ">\n        <td class=\"b1\">";
static const unsigned char csp_str20[7] = "</td>\n";
static const unsigned char csp_str21[6] = "\n    ";
static const unsigned char csp_str22[25] = "\n        <td class=\"b1\">";
static const unsigned char csp_str23[11] = "\n</table>\n";
static const unsigned char csp_str24[18] = "<div id=\"footer\">";
static const unsigned char csp_str25[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

/* $Id: reg_contests_page.csp 8161 2014-05-10 11:21:55Z cher $ */
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
// local includes go here
int csp_view_reg_contests_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_reg_contests_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_reg_contests_page(void)
{
    return &page_iface;
}

int csp_view_reg_contests_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr?phr->extra:NULL;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr?phr->cnts:NULL;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
// local variables go here
  const int *cntslist = 0;
  int cntsnum = 0;
  int row = 0, i, j;
  const unsigned char *login = 0;
  const unsigned char *title = NULL;
  const unsigned char *cnts_name = NULL;

static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

// initial code goes here
hr_cgi_param(phr, "login", &(login));
// defaulting to English as we have no contest chosen
  if (phr->locale_id < 0) phr->locale_id = 0;

  // even don't know about the contest specific settings
  l10n_setlocale(phr->locale_id);
  title = _("Contest selection");
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
fputs("<input type=\"hidden\" name=\"action\"", out_f);
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(NEW_SRV_ACTION_CHANGE_LANGUAGE));
fputs("\"", out_f);
fputs(" />", out_f);
fwrite(csp_str6, 1, 103, out_f);
fputs(_("language"), out_f);
fwrite(csp_str7, 1, 2, out_f);
l10n_html_locale_select(out_f, phr->locale_id);
fwrite(csp_str8, 1, 63, out_f);
fputs("<input type=\"submit\" name=\"button\" value=\"",out_f);
fputs(_("Change Language"), out_f);
fputs("\" />", out_f);
fwrite(csp_str9, 1, 32, out_f);
fputs("</form>", out_f);
fwrite(csp_str10, 1, 193, out_f);
fwrite(csp_str11, 1, 31, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str12, 1, 44, out_f);
fwrite(csp_str13, 1, 5, out_f);
fputs(_("Select one of available contests"), out_f);
fwrite(csp_str14, 1, 6, out_f);
cntsnum = contests_get_list(&cntslist);
fwrite(csp_str15, 1, 82, out_f);
fputs(_("Contest name"), out_f);
fwrite(csp_str16, 1, 29, out_f);
fputs(_("Registration mode"), out_f);
fwrite(csp_str16, 1, 29, out_f);
fputs(_("Registration deadline"), out_f);
fwrite(csp_str17, 1, 16, out_f);
for (j = 0; j < cntsnum; j++) {
    i = cntslist[j];
    cnts = 0;
    if (contests_get(i, &cnts) < 0 || !cnts) continue;
    if (cnts->closed) continue;
    if (!contests_check_register_ip_2(cnts, &phr->ip, phr->ssl_flag)) continue;
    if (cnts->reg_deadline > 0 && phr->current_time >= cnts->reg_deadline) continue;
fwrite(csp_str18, 1, 8, out_f);
fputs((form_row_attrs[(row++) & 1]), out_f);
fwrite(csp_str19, 1, 25, out_f);
fprintf(out_f, "%d", (int)(i));
fwrite(csp_str20, 1, 6, out_f);
fwrite(csp_str21, 1, 5, out_f);
fwrite(csp_str21, 1, 5, out_f);
fwrite(csp_str21, 1, 5, out_f);
cnts_name = NULL;
    if (phr->locale_id == 0 && cnts->name_en) cnts_name = cnts->name_en;
    if (!cnts_name) cnts_name = cnts->name;
fwrite(csp_str22, 1, 24, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_REG_LOGIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(i));
if (phr->locale_id > 0) {
fputs(sep, out_f); sep = "&amp;";
fputs("locale_id=", out_f);
fprintf(out_f, "%d", (int)(phr->locale_id));
}
if (login && *login) {
fputs(sep, out_f); sep = "&amp;";
fputs("login=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (login));
fputs(hbuf, out_f);
}
(void) sep;
fputs("\">", out_f);
fputs(html_armor_buf(&ab, (cnts_name)), out_f);
fwrite(csp_str16, 1, 29, out_f);
if (cnts->autoregister) {
fputs(_("open"), out_f);
} else {
fputs(_("moderated"), out_f);
}
fwrite(csp_str16, 1, 29, out_f);
if ((cnts->reg_deadline) > 0) {
fputs(xml_unparse_date((cnts->reg_deadline)), out_f);
} else {
fputs("&nbsp;", out_f);
}
fwrite(csp_str17, 1, 16, out_f);
}
fwrite(csp_str23, 1, 10, out_f);
fwrite(csp_str24, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str25, 1, 37, out_f);
//cleanup:;
  l10n_setlocale(0);
  html_armor_free(&ab);
  return retval;
}
