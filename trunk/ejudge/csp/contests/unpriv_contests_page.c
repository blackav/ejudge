/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[34] = "\"/>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str2[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str3[83] = "</title></head>\n<body><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str4[8] = "</div>\n";
static const unsigned char csp_str5[2] = "\n";
static const unsigned char csp_str6[100] = "\n<div class=\"user_actions\"><table class=\"menu\"><tr>\n<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str7[3] = ": ";
static const unsigned char csp_str8[60] = "</div></td>\n<td class=\"menu\"><div class=\"user_action_item\">";
static const unsigned char csp_str9[227] = "</div></td>\n</tr></table></div></form>\n\n<div class=\"white_empty_block\">&nbsp;</div>\n<div class=\"contest_actions\"><table class=\"menu\"><tr><td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td></tr></table></div>\n\n";
static const unsigned char csp_str10[32] = "</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str11[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str12[7] = "\n\n<h2>";
static const unsigned char csp_str13[8] = "</h2>\n\n";
static const unsigned char csp_str14[61] = "\n\n<table class=\"b1\"><tr><td class=\"b1\">N</td><td class=\"b1\">";
static const unsigned char csp_str15[12] = "</td></tr>\n";
static const unsigned char csp_str16[5] = "\n<tr";
static const unsigned char csp_str17[17] = "><td class=\"b1\">";
static const unsigned char csp_str18[7] = "</td>\n";
static const unsigned char csp_str19[4] = "\n  ";
static const unsigned char csp_str20[17] = "\n<td class=\"b1\">";
static const unsigned char csp_str21[12] = "\n</table>\n\n";
static const unsigned char csp_str22[18] = "<div id=\"footer\">";
static const unsigned char csp_str23[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

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
const int *cntslist = 0;
  int cntsnum = 0;
  time_t curtime = time(0);
  int row = 0, i, orig_locale_id, j;
  const unsigned char *s;
  const unsigned char *login = 0;
  const unsigned char *title = NULL;
  int need_locale_id = 0;

  static const unsigned char * const form_row_attrs[]=
  {
    " bgcolor=\"#d0d0d0\"",
    " bgcolor=\"#e0e0e0\"",
  };

  ns_cgi_param(phr, "login", &login);

  // defaulting to English as we have no contest chosen
  orig_locale_id = phr->locale_id;
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
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str5, 1, 1, out_f);
fwrite(csp_str6, 1, 99, out_f);
fputs(_("language"), out_f);
fwrite(csp_str7, 1, 2, out_f);
l10n_html_locale_select(out_f, phr->locale_id);
fwrite(csp_str8, 1, 59, out_f);
fwrite(csp_str9, 1, 226, out_f);
fwrite(csp_str10, 1, 31, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str11, 1, 44, out_f);
fwrite(csp_str12, 1, 6, out_f);
fputs(_("Select one of available contests"), out_f);
fwrite(csp_str13, 1, 7, out_f);
cntsnum = contests_get_list(&cntslist);
fwrite(csp_str14, 1, 60, out_f);
fputs(_("Contest name"), out_f);
fwrite(csp_str15, 1, 11, out_f);
for (j = 0; j < cntsnum; j++) {
    i = cntslist[j];
    cnts = 0;
    if (contests_get(i, &cnts) < 0 || !cnts) continue;
    if (cnts->closed) continue;
    if (!contests_check_register_ip_2(cnts, &phr->ip, phr->ssl_flag)) continue;
    if (cnts->reg_deadline > 0 && curtime >= cnts->reg_deadline) continue;
    need_locale_id = orig_locale_id >= 0 && cnts->default_locale_num >= 0 && orig_locale_id != cnts->default_locale_num;
    s = 0;
    if (phr->locale_id == 0 && cnts->name_en) s = cnts->name_en;
    if (!s) s = cnts->name;
fwrite(csp_str16, 1, 4, out_f);
fputs((form_row_attrs[(row++) & 1]), out_f);
fwrite(csp_str17, 1, 16, out_f);
fprintf(out_f, "%d", (int)(i));
fwrite(csp_str18, 1, 6, out_f);
fwrite(csp_str19, 1, 3, out_f);
fwrite(csp_str19, 1, 3, out_f);
fwrite(csp_str19, 1, 3, out_f);
fwrite(csp_str20, 1, 16, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("contest_id=", out_f);
fprintf(out_f, "%d", (int)(i));
if (need_locale_id) {
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
fputs(html_armor_buf(&ab, (s)), out_f);
fputs("</a>", out_f);
fwrite(csp_str15, 1, 11, out_f);
}
fwrite(csp_str21, 1, 11, out_f);
fwrite(csp_str22, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str23, 1, 37, out_f);
l10n_setlocale(0);
  html_armor_free(&ab);
  return retval;
}
