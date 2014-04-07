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
static const unsigned char csp_str9[53] = "\n<table class=\"b0\">\n    <tr>\n        <td class=\"b0\">";
static const unsigned char csp_str10[30] = "</td>\n        <td class=\"b0\">";
static const unsigned char csp_str11[84] = "</td>\n    </tr>\n</table>\n<hr/>\n\n<table class=\"b0\">\n    <tr>\n        <td class=\"b0\">";
static const unsigned char csp_str12[10] = "Default (";
static const unsigned char csp_str13[2] = ")";
static const unsigned char csp_str14[2] = "\n";
static const unsigned char csp_str15[49] = "</td>\n    </tr>\n    <tr>\n        <td class=\"b0\">";
static const unsigned char csp_str16[8] = "Default";
static const unsigned char csp_str17[3] = "No";
static const unsigned char csp_str18[4] = "Yes";
static const unsigned char csp_str19[18] = "</td>\n    </tr>\n\n";
static const unsigned char csp_str20[34] = "\n    <tr>\n        <td class=\"b0\">";
static const unsigned char csp_str21[17] = "</td>\n    </tr>\n";
static const unsigned char csp_str22[35] = "\n\n    <tr>\n        <td class=\"b0\">";
static const unsigned char csp_str23[86] = "</td>\n    </tr>\n</table>\n\n<hr />\n\n<table class=\"b0\">\n    <tr>\n        <td class=\"b0\">";
static const unsigned char csp_str24[26] = "</td>\n    </tr>\n</table>\n";
static const unsigned char csp_str25[7] = "<hr/>\n";
static const unsigned char csp_str26[18] = "\n</body>\n</html>\n";

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

#include "reuse/xalloc.h"

#include <libintl.h>
#define _(x) gettext(x)

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)
int csp_view_priv_settings_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_settings_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_settings_page(void)
{
    return &page_iface;
}

int csp_view_priv_settings_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
const struct section_global_data *global = cs->global;
    const unsigned char *title = NULL;

    if (phr->role != USER_ROLE_ADMIN) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

    l10n_setlocale(phr->locale_id);
    title = _("Contest settings");
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
if ((extra->contest_arm) ) {
fputs((extra->contest_arm), out_f);
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
if ((extra->contest_arm) ) {
fputs((extra->contest_arm), out_f);
}
fwrite(csp_str6, 1, 3, out_f);
fputs((title), out_f);
fwrite(csp_str8, 1, 6, out_f);
fwrite(csp_str9, 1, 52, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);
fputs(_("Main page"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_ADMIN_CONTEST_SETTINGS);
fputs("\">", out_f);
fputs(_("Refresh"), out_f);
fputs("</a>", out_f);
fwrite(csp_str11, 1, 83, out_f);
fputs(_("Participants can view their source code"), out_f);
fwrite(csp_str10, 1, 29, out_f);
if (!cs->online_view_source) {
fwrite(csp_str12, 1, 9, out_f);
if ((global->team_enable_src_view > 0)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str13, 1, 1, out_f);
} else {
if ((cs->online_view_source >= 0)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
}
fwrite(csp_str10, 1, 29, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fputs("<select name=\"param\"", out_f);
fputs(">", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (!cs->online_view_source) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%u", (unsigned)(0));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("Default"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (cs->online_view_source < 0) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(-1));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("No"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (cs->online_view_source > 0) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(1));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("Yes"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("</select>", out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_SOURCE, NULL), out_f);
fputs("</form>", out_f);
fwrite(csp_str15, 1, 48, out_f);
fputs(_("Participants can view testing reports"), out_f);
fwrite(csp_str10, 1, 29, out_f);
if (!cs->online_view_report) {
fwrite(csp_str16, 1, 7, out_f);
} else if (cs->online_view_report < 0) {
fwrite(csp_str17, 1, 2, out_f);
} else {
fwrite(csp_str18, 1, 3, out_f);
}
fwrite(csp_str10, 1, 29, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fputs("<select name=\"param\"", out_f);
fputs(">", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (!cs->online_view_report) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%u", (unsigned)(0));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("Default"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (cs->online_view_report < 0) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(-1));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("No"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (cs->online_view_report > 0) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(1));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("Yes"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("</select>", out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_REPORT, NULL), out_f);
fputs("</form>", out_f);
fwrite(csp_str19, 1, 17, out_f);
if (global->separate_user_score > 0) {
fwrite(csp_str20, 1, 33, out_f);
fputs(_("Participants view judge score"), out_f);
fwrite(csp_str10, 1, 29, out_f);
if ((cs->online_view_judge_score > 0)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str10, 1, 29, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fputs("<select name=\"param\"", out_f);
fputs(">", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (cs->online_view_judge_score <= 0) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%u", (unsigned)(0));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("No"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (cs->online_view_judge_score > 0) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(1));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("Yes"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("</select>", out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_JUDGE_SCORE, NULL), out_f);
fputs("</form>", out_f);
fwrite(csp_str21, 1, 16, out_f);
}
fwrite(csp_str22, 1, 34, out_f);
fputs(_("Final test visibility rules"), out_f);
fwrite(csp_str10, 1, 29, out_f);
if ((cs->online_final_visibility > 0)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str10, 1, 29, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fputs("<select name=\"param\"", out_f);
fputs(">", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (cs->online_final_visibility <= 0) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%u", (unsigned)(0));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("No"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("<option", out_f);
if (cs->online_final_visibility > 0) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(1));
fputs("\"", out_f);
fputs(">", out_f);
fputs(_("Yes"), out_f);
fputs("</option>", out_f);
fwrite(csp_str14, 1, 1, out_f);
fputs("</select>", out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_FINAL_VISIBILITY, NULL), out_f);
fputs("</form>", out_f);
fwrite(csp_str23, 1, 85, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);
fputs(_("Main page"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_ADMIN_CONTEST_SETTINGS);
fputs("\">", out_f);
fputs(_("Refresh"), out_f);
fputs("</a>", out_f);
fwrite(csp_str24, 1, 25, out_f);
fwrite(csp_str25, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str26, 1, 17, out_f);
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return retval;
}
