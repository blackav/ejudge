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
static const unsigned char csp_str9[15] = "\n<ul>\n    <li>";
static const unsigned char csp_str10[15] = "</li>\n    <li>";
static const unsigned char csp_str11[7] = "</li>\n";
static const unsigned char csp_str12[10] = "\n    <li>";
static const unsigned char csp_str13[25] = "\n</ul>\n\n<table>\n<tr><td>";
static const unsigned char csp_str14[11] = ":</td><td>";
static const unsigned char csp_str15[50] = "</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n<tr><td>";
static const unsigned char csp_str16[15] = ":</td><td><tt>";
static const unsigned char csp_str17[55] = "</tt></td><td>&nbsp;</td><td>&nbsp;</td></tr>\n<tr><td>";
static const unsigned char csp_str18[4] = "<i>";
static const unsigned char csp_str19[5] = "</i>";
static const unsigned char csp_str20[7] = "&nbsp;";
static const unsigned char csp_str21[42] = "</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n";
static const unsigned char csp_str22[10] = "\n<tr><td>";
static const unsigned char csp_str23[5] = "<tt>";
static const unsigned char csp_str24[6] = "</tt>";
static const unsigned char csp_str25[37] = "<td>&nbsp;</td><td>&nbsp;</td></tr>\n";
static const unsigned char csp_str26[6] = "</i> ";
static const unsigned char csp_str27[2] = "\n";
static const unsigned char csp_str28[11] = "\n\n<tr><td>";
static const unsigned char csp_str29[25] = "</td><td>&nbsp;</td><td>";
static const unsigned char csp_str30[12] = "</td></tr>\n";
static const unsigned char csp_str31[3] = "\n\n";
static const unsigned char csp_str32[43] = "</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n\n";
static const unsigned char csp_str33[4] = "N/A";
static const unsigned char csp_str34[7] = " - ???";
static const unsigned char csp_str35[4] = " - ";
static const unsigned char csp_str36[6] = "</td>";
static const unsigned char csp_str37[5] = "<td>";
static const unsigned char csp_str38[10] = "</td><td>";
static const unsigned char csp_str39[31] = "<td>&nbsp;</td><td>&nbsp;</td>";
static const unsigned char csp_str40[7] = "</tr>\n";
static const unsigned char csp_str41[9] = "<tr><td>";
static const unsigned char csp_str42[52] = "</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n</table>\n\n";
static const unsigned char csp_str43[5] = "\n<p>";
static const unsigned char csp_str44[5] = "<h2>";
static const unsigned char csp_str45[6] = "</h2>";
static const unsigned char csp_str46[7] = "</h2>\n";
static const unsigned char csp_str47[13] = "<h3>Warning ";
static const unsigned char csp_str48[11] = ": issued: ";
static const unsigned char csp_str49[14] = ": issued by: ";
static const unsigned char csp_str50[3] = " (";
static const unsigned char csp_str51[17] = "), issued from: ";
static const unsigned char csp_str52[11] = "</h3>\n\n<p>";
static const unsigned char csp_str53[9] = ":\\n<pre>";
static const unsigned char csp_str54[11] = "</pre>\n<p>";
static const unsigned char csp_str55[8] = "</pre>\n";
static const unsigned char csp_str56[6] = "\n<h2>";
static const unsigned char csp_str57[76] = ":<br/>\n<p><textarea name=\"warn_text\" rows=\"5\" cols=\"60\"></textarea></p>\n<p>";
static const unsigned char csp_str58[79] = ":<br/>\n<p><textarea name=\"warn_comment\" rows=\"5\" cols=\"60\"></textarea></p>\n<p>";
static const unsigned char csp_str59[6] = "</p>\n";
static const unsigned char csp_str60[7] = "\n\n<h2>";
static const unsigned char csp_str61[60] = ":<br/>\n<p><textarea name=\"disq_comment\" rows=\"5\" cols=\"60\">";
static const unsigned char csp_str62[55] = "</textarea></p>\n\n<table class=\"b0\"><tr><td class=\"b0\">";
static const unsigned char csp_str63[16] = "<td class=\"b0\">";
static const unsigned char csp_str64[15] = "</tr></table>\n";
static const unsigned char csp_str65[7] = "<hr/>\n";
static const unsigned char csp_str66[18] = "\n</body>\n</html>\n";

/* $Id$ */
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

#include "reuse/xalloc.h"

#include <libintl.h>
#define _(x) gettext(x)

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)
#include "ejudge/team_extra.h"
int csp_view_priv_user_info_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_user_info_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_user_info_page(void)
{
    return &page_iface;
}

int csp_view_priv_user_info_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
// variables...
    const struct section_global_data *global = cs->global;
    struct teamdb_export u_info;
    const struct team_extra *u_extra = 0;
    const struct team_warning *cur_warn = 0;
    int flags, pages_total;
    int runs_num = 0, clars_num = 0;
    size_t clars_total = 0, runs_total = 0;
    const struct userlist_user *u = 0;
    const struct userlist_contest *uc = 0;
    int allowed_edit = 0, needed_cap = 0, init_value, i;
    struct userlist_user_info *ui = 0;
    int view_user_id = 0;
    const unsigned char *title = NULL;
if (hr_cgi_param_int_2(phr, "user_id", &(view_user_id)) <= 0) {
  FAIL(NEW_SRV_ERR_INV_USER_ID);
}
if (!teamdb_lookup(cs->teamdb_state, view_user_id))
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  if (opcaps_check(phr->caps, OPCAP_GET_USER) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

    // initialization
    teamdb_export_team(cs->teamdb_state, view_user_id, &u_info);
    u_extra = team_extra_get_entry(cs->team_extra_state, view_user_id);
    run_get_team_usage(cs->runlog_state, view_user_id, &runs_num, &runs_total);
    clar_get_user_usage(cs->clarlog_state,view_user_id, &clars_num, &clars_total);
    pages_total = run_get_total_pages(cs->runlog_state, view_user_id);
    flags = teamdb_get_flags(cs->teamdb_state, view_user_id);
    u = u_info.user;
    if (u) uc = userlist_get_user_contest(u, phr->contest_id);
    if (u) ui = u->cnts0;

    l10n_setlocale(phr->locale_id);
    title = _("Details for user ");
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
fwrite(csp_str9, 1, 14, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);
fputs(_("Main page"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 14, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_USERS);
fputs("\">", out_f);
fputs(_("View regular users"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 14, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_REG_PWDS);
fputs("\">", out_f);
fputs(_("View registration passwords"), out_f);
fputs("</a>", out_f);
fwrite(csp_str11, 1, 6, out_f);
if (!cnts->disable_team_password) {
fwrite(csp_str12, 1, 9, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_CNTS_PWDS);
fputs("\">", out_f);
fputs(_("View contest passwords"), out_f);
fputs("</a>", out_f);
fwrite(csp_str11, 1, 6, out_f);
}
fwrite(csp_str13, 1, 24, out_f);
fputs(_("User Id"), out_f);
fwrite(csp_str14, 1, 10, out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fwrite(csp_str15, 1, 49, out_f);
fputs(_("User Login"), out_f);
fwrite(csp_str16, 1, 14, out_f);
fputs(html_armor_buf(&ab, (u_info.login)), out_f);
fwrite(csp_str17, 1, 54, out_f);
fputs(_("User Name"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if (u_info.name && *u_info.name) {
fputs(html_armor_buf(&ab, (u_info.name)), out_f);
} else {
fwrite(csp_str18, 1, 3, out_f);
fputs(_("Not set"), out_f);
fwrite(csp_str19, 1, 4, out_f);
}
fwrite(csp_str15, 1, 49, out_f);
fputs(_("Registration time"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if (uc && uc->create_time > 0) {
fputs(xml_unparse_date((uc->create_time)), out_f);
} else {
fwrite(csp_str20, 1, 6, out_f);
}
fwrite(csp_str15, 1, 49, out_f);
fputs(_("Last login time"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if (ui && ui->last_login_time > 0) {
fputs(xml_unparse_date((ui->last_login_time)), out_f);
} else {
fwrite(csp_str20, 1, 6, out_f);
}
fwrite(csp_str21, 1, 41, out_f);
if (/*opcaps_check(phr->caps, OPCAP_GENERATE_TEAM_PASSWORDS) >= 0*/ 1) {
fwrite(csp_str22, 1, 9, out_f);
fputs(_("Registration password"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if (u && !u->passwd) {
fwrite(csp_str18, 1, 3, out_f);
fputs(_("Not set"), out_f);
fwrite(csp_str19, 1, 4, out_f);
} else if (u && u->passwd_method != USERLIST_PWD_PLAIN) {
fwrite(csp_str18, 1, 3, out_f);
fputs(_("Changed by user"), out_f);
fwrite(csp_str19, 1, 4, out_f);
} else if (u) {
fwrite(csp_str23, 1, 4, out_f);
fputs(html_armor_buf(&ab, (u->passwd)), out_f);
fwrite(csp_str24, 1, 5, out_f);
}
fwrite(csp_str25, 1, 36, out_f);
if (!cnts->disable_team_password) {
fwrite(csp_str22, 1, 9, out_f);
fputs(_("Contest password"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if (ui && !ui->team_passwd) {
fwrite(csp_str18, 1, 3, out_f);
fputs(_("Not set"), out_f);
fwrite(csp_str19, 1, 4, out_f);
} else if (ui && ui->team_passwd_method != USERLIST_PWD_PLAIN) {
fwrite(csp_str18, 1, 3, out_f);
fputs(_("Changed by user"), out_f);
fwrite(csp_str26, 1, 5, out_f);
} else if (ui) {
fwrite(csp_str23, 1, 4, out_f);
fputs(html_armor_buf(&ab, (ui->team_passwd)), out_f);
fwrite(csp_str24, 1, 5, out_f);
} else {
fwrite(csp_str20, 1, 6, out_f);
}
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str22, 1, 9, out_f);
fputs(_("Privileged?"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if ((u && u->is_privileged)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str21, 1, 41, out_f);
// invisible, locked, banned status and change buttons
  // to make invisible EDIT_REG is enough for all users
  // to ban or lock DELETE_PRIV_REG required for privileged users
  allowed_edit = 0;
  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) >= 0) allowed_edit = 1;
  if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str28, 1, 10, out_f);
fputs(_("Invisible?"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if ((flags & TEAM_INVISIBLE)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str29, 1, 24, out_f);
if(allowed_edit) {
    if (flags & TEAM_INVISIBLE) {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_TOGGLE_VISIBILITY, _("Make visible")), out_f);
} else {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_TOGGLE_VISIBILITY, _("Make invisible")), out_f);
}
  } else {
fwrite(csp_str20, 1, 6, out_f);
}
fwrite(csp_str30, 1, 11, out_f);
if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("</form>", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str31, 1, 2, out_f);
allowed_edit = 0;
  if (u) {
    if (u->is_privileged) {
      if ((flags & TEAM_BANNED)) needed_cap = OPCAP_PRIV_CREATE_REG;
      else needed_cap = OPCAP_PRIV_DELETE_REG;
    } else {
      if ((flags & TEAM_BANNED)) needed_cap = OPCAP_CREATE_REG;
      else needed_cap = OPCAP_DELETE_REG;
    }
    if (opcaps_check(phr->caps, needed_cap) >= 0) allowed_edit = 1;
  }
  if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str22, 1, 9, out_f);
fputs(_("Banned?"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if ((flags & TEAM_BANNED)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str29, 1, 24, out_f);
if(allowed_edit) {
    if ((flags & TEAM_BANNED)) {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_TOGGLE_BAN, _("Remove ban")), out_f);
} else {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_TOGGLE_BAN, _("Ban")), out_f);
}
  } else {
fwrite(csp_str20, 1, 6, out_f);
}
fwrite(csp_str30, 1, 11, out_f);
if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("</form>", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str31, 1, 2, out_f);
allowed_edit = 0;
  if (u) {
    if (u->is_privileged) {
      if ((flags & TEAM_LOCKED)) needed_cap = OPCAP_PRIV_CREATE_REG;
      else needed_cap = OPCAP_PRIV_DELETE_REG;
    } else {
      if ((flags & TEAM_LOCKED)) needed_cap = OPCAP_CREATE_REG;
      else needed_cap = OPCAP_DELETE_REG;
    }
    if (opcaps_check(phr->caps, needed_cap) >= 0) allowed_edit = 1;
  }
  if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str22, 1, 9, out_f);
fputs(_("Locked?"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if ((flags & TEAM_LOCKED)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str29, 1, 24, out_f);
if(allowed_edit) {
    if ((flags & TEAM_LOCKED)) {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_TOGGLE_LOCK, _("Unlock")), out_f);
} else {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_TOGGLE_LOCK, _("Lock")), out_f);
}
  } else {
fwrite(csp_str20, 1, 6, out_f);
}
fwrite(csp_str30, 1, 11, out_f);
if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("</form>", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str31, 1, 2, out_f);
allowed_edit = 0;
  if (u) {
    if (u->is_privileged) {
      if ((flags & TEAM_INCOMPLETE)) needed_cap = OPCAP_PRIV_CREATE_REG;
      else needed_cap = OPCAP_PRIV_DELETE_REG;
    } else {
      if ((flags & TEAM_INCOMPLETE)) needed_cap = OPCAP_CREATE_REG;
      else needed_cap = OPCAP_DELETE_REG;
    }
    if (opcaps_check(phr->caps, needed_cap) >= 0) allowed_edit = 1;
  }
fwrite(csp_str27, 1, 1, out_f);
if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str22, 1, 9, out_f);
fputs(_("Incomplete?"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if ((flags & TEAM_INCOMPLETE)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str29, 1, 24, out_f);
if(allowed_edit) {
    if ((flags & TEAM_INCOMPLETE)) {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_TOGGLE_INCOMPLETENESS, _("Clear")), out_f);
} else {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_TOGGLE_INCOMPLETENESS, _("Clear")), out_f);
}
  } else {
fwrite(csp_str20, 1, 6, out_f);
}
fwrite(csp_str30, 1, 11, out_f);
if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("</form>", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str28, 1, 10, out_f);
fputs(_("Disqualified?"), out_f);
fwrite(csp_str14, 1, 10, out_f);
if ((flags & TEAM_DISQUALIFIED)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str15, 1, 49, out_f);
fputs(_("Number of Runs"), out_f);
fwrite(csp_str14, 1, 10, out_f);
fprintf(out_f, "%d", (int)(runs_num));
fwrite(csp_str15, 1, 49, out_f);
fputs(_("Total size of Runs"), out_f);
fwrite(csp_str14, 1, 10, out_f);
fprintf(out_f, "%zu", (size_t)(runs_total));
fwrite(csp_str15, 1, 49, out_f);
fputs(_("Number of Clars"), out_f);
fwrite(csp_str14, 1, 10, out_f);
fprintf(out_f, "%d", (int)(clars_num));
fwrite(csp_str15, 1, 49, out_f);
fputs(_("Total size of Clars"), out_f);
fwrite(csp_str14, 1, 10, out_f);
fprintf(out_f, "%zu", (size_t)(clars_total));
fwrite(csp_str15, 1, 49, out_f);
fputs(_("Number of printed pages"), out_f);
fwrite(csp_str14, 1, 10, out_f);
fprintf(out_f, "%d", (int)(pages_total));
fwrite(csp_str32, 1, 42, out_f);
if (global->contestant_status_num > 0) {
    // contestant status is editable when OPCAP_EDIT_REG is set
    allowed_edit = 0;
    if (opcaps_check(phr->caps, OPCAP_EDIT_REG) >= 0) allowed_edit = 1;
fwrite(csp_str27, 1, 1, out_f);
if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str22, 1, 9, out_f);
fputs(_("Status"), out_f);
fwrite(csp_str14, 1, 10, out_f);
init_value = 0;
    if (!u_extra) {
fwrite(csp_str33, 1, 3, out_f);
} else if (u_extra->status < 0
               || u_extra->status >= global->contestant_status_num) {
fprintf(out_f, "%d", (int)(u_extra->status));
fwrite(csp_str34, 1, 6, out_f);
} else {
fprintf(out_f, "%d", (int)(u_extra->status));
fwrite(csp_str35, 1, 3, out_f);
fputs(html_armor_buf(&ab, (global->contestant_status_legend[u_extra->status])), out_f);
init_value = u_extra->status;
    }
fwrite(csp_str36, 1, 5, out_f);
if (allowed_edit) {
fwrite(csp_str37, 1, 4, out_f);
fputs("<select name=\"status\"", out_f);
fputs(">", out_f);
for (i = 0; i < global->contestant_status_num; i++) {
fputs("<option", out_f);
if (i == init_value) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(i));
fputs("\"", out_f);
fputs(">", out_f);
fprintf(out_f, "%d", (int)(i));
fwrite(csp_str35, 1, 3, out_f);
fputs(html_armor_buf(&ab, (global->contestant_status_legend[i])), out_f);
fputs("</option>", out_f);
}
fputs("</select>", out_f);
fwrite(csp_str38, 1, 9, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USER_CHANGE_STATUS, NULL), out_f);
fwrite(csp_str36, 1, 5, out_f);
} else {
fwrite(csp_str39, 1, 30, out_f);
}
fwrite(csp_str40, 1, 6, out_f);
if (allowed_edit) {
fwrite(csp_str27, 1, 1, out_f);
fputs("</form>", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str31, 1, 2, out_f);
i = 0;
  if (u_extra) i = u_extra->warn_u;
fwrite(csp_str41, 1, 8, out_f);
fputs(_("Number of warnings"), out_f);
fwrite(csp_str14, 1, 10, out_f);
fprintf(out_f, "%d", (int)(i));
fwrite(csp_str42, 1, 51, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str43, 1, 4, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRINT_USER_PROTOCOL, NULL), out_f);
fwrite(csp_str27, 1, 1, out_f);
fputs("</form>", out_f);
fwrite(csp_str31, 1, 2, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str43, 1, 4, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRINT_USER_FULL_PROTOCOL, NULL), out_f);
fwrite(csp_str27, 1, 1, out_f);
fputs("</form>", out_f);
fwrite(csp_str31, 1, 2, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str43, 1, 4, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRINT_UFC_PROTOCOL, NULL), out_f);
fwrite(csp_str27, 1, 1, out_f);
fputs("</form>", out_f);
fwrite(csp_str31, 1, 2, out_f);
if (!u_extra || !u_extra->warn_u) {
fwrite(csp_str44, 1, 4, out_f);
fputs(_("No warnings"), out_f);
fwrite(csp_str45, 1, 5, out_f);
} else {
fwrite(csp_str44, 1, 4, out_f);
fputs(_("Warnings"), out_f);
fwrite(csp_str46, 1, 6, out_f);
for (i = 0; i < u_extra->warn_u; i++) {
      if (!(cur_warn = u_extra->warns[i])) continue;
fwrite(csp_str47, 1, 12, out_f);
fprintf(out_f, "%d", (int)(i + 1));
fwrite(csp_str48, 1, 10, out_f);
fputs(xml_unparse_date((cur_warn->date)), out_f);
fwrite(csp_str49, 1, 13, out_f);
fputs(html_armor_buf(&ab, (teamdb_get_login(cs->teamdb_state, cur_warn->issuer_id))), out_f);
fwrite(csp_str50, 1, 2, out_f);
fprintf(out_f, "%d", (int)(cur_warn->issuer_id));
fwrite(csp_str51, 1, 16, out_f);
fprintf(out_f, "%s", xml_unparse_ipv6(&(cur_warn->issuer_ip)));
fwrite(csp_str52, 1, 10, out_f);
fputs(_("Warning text for the user"), out_f);
fwrite(csp_str53, 1, 8, out_f);
fputs(html_armor_buf(&ab, (cur_warn->text)), out_f);
fwrite(csp_str54, 1, 10, out_f);
fputs(_("Judge\'s comment"), out_f);
fwrite(csp_str53, 1, 8, out_f);
fputs(html_armor_buf(&ab, (cur_warn->comment)), out_f);
fwrite(csp_str55, 1, 7, out_f);
}
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str31, 1, 2, out_f);
if (opcaps_check(phr->caps, OPCAP_EDIT_REG) >= 0) {
fwrite(csp_str56, 1, 5, out_f);
fputs(_("Issue a warning"), out_f);
fwrite(csp_str46, 1, 6, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str43, 1, 4, out_f);
fputs(_("Warning explanation for the user (mandatory)"), out_f);
fwrite(csp_str57, 1, 75, out_f);
fputs(_("Comment for other judges (optional)"), out_f);
fwrite(csp_str58, 1, 78, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_ISSUE_WARNING, NULL), out_f);
fwrite(csp_str59, 1, 5, out_f);
fputs("</form>", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str31, 1, 2, out_f);
if (opcaps_check(phr->caps, OPCAP_EDIT_REG) >= 0) {
fwrite(csp_str60, 1, 6, out_f);
fputs(_("Disqualify user"), out_f);
fwrite(csp_str46, 1, 6, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str27, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"user_id\"", out_f);
if ((view_user_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(view_user_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str43, 1, 4, out_f);
fputs(_("Disqualification explanation"), out_f);
fwrite(csp_str61, 1, 59, out_f);
if (u_extra->disq_comment) {
fputs(html_armor_buf(&ab, (u_extra->disq_comment)), out_f);
}
fwrite(csp_str62, 1, 54, out_f);
if ((flags & TEAM_DISQUALIFIED)) {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_SET_DISQUALIFICATION, _("Edit comment")), out_f);
} else {
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_SET_DISQUALIFICATION, _("Disqualify")), out_f);
}
fwrite(csp_str36, 1, 5, out_f);
if ((flags & TEAM_DISQUALIFIED)) {
fwrite(csp_str63, 1, 15, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CLEAR_DISQUALIFICATION, NULL), out_f);
fwrite(csp_str36, 1, 5, out_f);
}
fwrite(csp_str64, 1, 14, out_f);
fputs("</form>", out_f);
fwrite(csp_str27, 1, 1, out_f);
}
fwrite(csp_str31, 1, 2, out_f);
fwrite(csp_str65, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str66, 1, 17, out_f);
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return retval;
}
