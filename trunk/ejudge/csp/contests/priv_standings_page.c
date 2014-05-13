/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\'text/html; charset=";
static const unsigned char csp_str1[35] = "\' />\n<link rel=\"stylesheet\" href=\'";
static const unsigned char csp_str2[82] = "priv.css\' type=\"text/css\" />\n<script type=\"text/javascript\" charset=\"UTF-8\" src=\"";
static const unsigned char csp_str3[27] = "priv.js\"></script>\n<title>";
static const unsigned char csp_str4[3] = " [";
static const unsigned char csp_str5[3] = ", ";
static const unsigned char csp_str6[4] = "]: ";
static const unsigned char csp_str7[29] = "</title>\n</head>\n<body>\n<h1>";
static const unsigned char csp_str8[7] = "</h1>\n";
static const unsigned char csp_str9[2] = "\n";
static const unsigned char csp_str10[29] = "\n<table border=\"0\">\n<tr><td>";
static const unsigned char csp_str11[11] = ":</td><td>";
static const unsigned char csp_str12[20] = "</td></tr>\n<tr><td>";
static const unsigned char csp_str13[35] = "</td></tr>\n<tr><td>&nbsp;</td><td>";
static const unsigned char csp_str14[44] = "</td></tr>\n<tr><td>&nbsp;</td><td><a href=\'";
static const unsigned char csp_str15[35] = "filter_expr.html\' target=\"_blank\">";
static const unsigned char csp_str16[26] = "</a></td></tr>\n\n</table>\n";
static const unsigned char csp_str17[9] = "\n<br/>\n\n";
static const unsigned char csp_str18[6] = "\n<h2>";
static const unsigned char csp_str19[33] = "</h2>\n<p><pre><font color=\"red\">";
static const unsigned char csp_str20[19] = "</font></pre></p>\n";
static const unsigned char csp_str21[41] = "\n\n<table class=\"b0\"><tr>\n<td class=\"b0\">";
static const unsigned char csp_str22[26] = "</a></td>\n<td class=\"b0\">";
static const unsigned char csp_str23[26] = "</a></td>\n</tr></table>\n\n";
static const unsigned char csp_str24[7] = "<hr/>\n";
static const unsigned char csp_str25[18] = "\n</body>\n</html>\n";

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
#include "ejudge/copyright.h"
#include "mischtml.h"
#include "html.h"
#include "userlist.h"

#include "reuse/xalloc.h"

#include <libintl.h>
#define _(x) gettext(x)

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)
int csp_view_priv_standings_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_standings_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_standings_page(void)
{
    return &page_iface;
}

int csp_view_priv_standings_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
struct user_filter_info *u = 0;
  const unsigned char *title = NULL;

  if (phr->role < USER_ROLE_JUDGE) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (opcaps_check(phr->caps, OPCAP_VIEW_STANDINGS) < 0) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  u = user_filter_info_allocate(cs, phr->user_id, phr->session_id);

  l10n_setlocale(phr->locale_id);
  title = _("Current standings");
fwrite(csp_str0, 1, 183, out_f);
fwrite("utf-8", 1, 5, out_f);
fwrite(csp_str1, 1, 34, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str2, 1, 81, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str3, 1, 26, out_f);
fputs((ns_unparse_role(phr->role)), out_f);
fwrite(csp_str4, 1, 2, out_f);
if ((phr->name_arm) ) {
fputs((phr->name_arm), out_f);
}
fwrite(csp_str5, 1, 2, out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fwrite(csp_str5, 1, 2, out_f);
if (extra) {
if ((extra->contest_arm) ) {
fputs((extra->contest_arm), out_f);
}
}
fwrite(csp_str6, 1, 3, out_f);
fputs((title), out_f);
fwrite(csp_str7, 1, 28, out_f);
fputs((ns_unparse_role(phr->role)), out_f);
fwrite(csp_str4, 1, 2, out_f);
if ((phr->name_arm) ) {
fputs((phr->name_arm), out_f);
}
fwrite(csp_str5, 1, 2, out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fwrite(csp_str5, 1, 2, out_f);
if (extra) {
if ((extra->contest_arm) ) {
fputs((extra->contest_arm), out_f);
}
}
fwrite(csp_str6, 1, 3, out_f);
fputs((title), out_f);
fwrite(csp_str8, 1, 6, out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str10, 1, 28, out_f);
fputs(_("User filter expression"), out_f);
fwrite(csp_str11, 1, 10, out_f);
fputs("<input type=\"text\" name=\"stand_user_expr\" size=\"64\"", out_f);
if ((u->stand_user_expr)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (u->stand_user_expr)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str12, 1, 19, out_f);
fputs(_("Problem filter expression"), out_f);
fwrite(csp_str11, 1, 10, out_f);
fputs("<input type=\"text\" name=\"stand_prob_expr\" size=\"64\"", out_f);
if ((u->stand_prob_expr)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (u->stand_prob_expr)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str12, 1, 19, out_f);
fputs(_("Run filter expression"), out_f);
fwrite(csp_str11, 1, 10, out_f);
fputs("<input type=\"text\" name=\"stand_run_expr\" size=\"64\"", out_f);
if ((u->stand_run_expr)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (u->stand_run_expr)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str13, 1, 34, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_SET_STAND_FILTER, NULL), out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_RESET_STAND_FILTER, NULL), out_f);
fwrite(csp_str14, 1, 43, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str15, 1, 34, out_f);
fputs(_("Help"), out_f);
fwrite(csp_str16, 1, 25, out_f);
fputs("</form>", out_f);
fwrite(csp_str17, 1, 8, out_f);
if (u->stand_error_msgs) {
fwrite(csp_str18, 1, 5, out_f);
fputs(_("Filter expression errors"), out_f);
fwrite(csp_str19, 1, 32, out_f);
fputs(html_armor_buf(&ab, (u->stand_error_msgs)), out_f);
fwrite(csp_str20, 1, 18, out_f);
}
fwrite(csp_str21, 1, 40, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);
fputs(_("Main page"), out_f);
fwrite(csp_str22, 1, 25, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_STANDINGS);
fputs("\">", out_f);
fputs(_("Refresh"), out_f);
fwrite(csp_str23, 1, 25, out_f);
if (cs->global->score_system == SCORE_KIROV || cs->global->score_system == SCORE_OLYMPIAD)
    do_write_kirov_standings(cs, cnts, out_f, 0, 1, 0, 0, 0, 0, 0, 0 /*accepting_mode*/, 1, 0, 0, u, 0 /* user_mode */);
  else if (cs->global->score_system == SCORE_MOSCOW)
    do_write_moscow_standings(cs, cnts, out_f, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, u);
  else
    do_write_standings(cs, cnts, out_f, 1, 0, 0, 0, 0, 0, 0, 1, 0, u);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str24, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str25, 1, 17, out_f);
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return retval;
}
