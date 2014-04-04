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
static const unsigned char csp_str9[28] = "<h2>Registered users</h2>\n\n";
static const unsigned char csp_str10[297] = "\n<table class=\"b1\"><tr><th class=\"b1\">NN</th><th class=\"b1\">Id</th><th class=\"b1\">Login</th><th class=\"b1\">Name</th><th class=\"b1\">Status</th><th class=\"b1\">Flags</th><th class=\"b1\">Reg. date</th><th class=\"b1\">Login date</th><th class=\"b1\">No. of submits</th><th class=\"b1\">Size of submits</th>\n";
static const unsigned char csp_str11[28] = "\n<th class=\"b1\">Score</th>\n";
static const unsigned char csp_str12[34] = "\n<th class=\"b1\">Select</th></tr>\n";
static const unsigned char csp_str13[5] = "\n<tr";
static const unsigned char csp_str14[18] = ">\n<td class=\"b1\">";
static const unsigned char csp_str15[7] = "</td>\n";
static const unsigned char csp_str16[2] = "\n";
static const unsigned char csp_str17[6] = "\n    ";
static const unsigned char csp_str18[17] = "\n<td class=\"b1\">";
static const unsigned char csp_str19[8] = "</td>\n\n";
static const unsigned char csp_str20[29] = "\n<td class=\"b1\">&nbsp;</td>\n";
static const unsigned char csp_str21[21] = "</td><td class=\"b1\">";
static const unsigned char csp_str22[55] = "\n<td class=\"b1\">&nbsp;</td><td class=\"b1\">&nbsp;</td>\n";
static const unsigned char csp_str23[51] = "\n<td class=\"b1\"><input type=\"checkbox\" name=\'user_";
static const unsigned char csp_str24[16] = "\'/></td>\n</tr>\n";
static const unsigned char csp_str25[50] = "\n</table>\n\n<h2>Users range</h2>\n\n<table>\n<tr><td>";
static const unsigned char csp_str26[82] = ":</td><td><input type=\"text\" name=\"first_user_id\" size=\"16\" /></td></tr>\n<tr><td>";
static const unsigned char csp_str27[126] = "</td><td><input type=\"text\" name=\"last_user_id\" size=\"16\" /></td></tr>\n</table>\n\n<h2>Available actions</h2>\n\n<table>\n<tr><td>";
static const unsigned char csp_str28[10] = "</td><td>";
static const unsigned char csp_str29[20] = "</td></tr>\n<tr><td>";
static const unsigned char csp_str30[12] = "</td></tr>\n";
static const unsigned char csp_str31[10] = "\n<tr><td>";
static const unsigned char csp_str32[3] = "\n\n";
static const unsigned char csp_str33[16] = "\n</table>\n\n<h2>";
static const unsigned char csp_str34[10] = "</h2>\n<p>";
static const unsigned char csp_str35[115] = ":<br>\n<p><textarea name=\"disq_comment\" rows=\"5\" cols=\"60\">\n</textarea></p>\n\n<table class=\"b0\"><tr>\n<td class=\"b0\">";
static const unsigned char csp_str36[26] = "</td>\n</tr></table>\n\n<h2>";
static const unsigned char csp_str37[79] = "</h2>\n<table>\n<tr><td><input type=\"text\" size=\"32\" name=\"add_login\"/></td><td>";
static const unsigned char csp_str38[78] = "</td></tr>\n<tr><td><input type=\"text\" size=\"32\" name=\"add_user_id\"/></td><td>";
static const unsigned char csp_str39[21] = "</td></tr>\n</table>\n";
static const unsigned char csp_str40[7] = "<hr/>\n";
static const unsigned char csp_str41[18] = "\n</body>\n</html>\n";

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
#include "userlist_clnt.h"
#include "userlist.h"
#include "userlist_proto.h"
int csp_view_priv_users_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_users_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_users_page(void)
{
    return &page_iface;
}

int csp_view_priv_users_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
int r;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  const struct userlist_user *u = 0;
  const struct userlist_contest *uc = 0;
  int uid;
  int row = 1, serial = 1;
  int details_allowed = 0;
  unsigned char b1[1024];
  int new_contest_id = cnts->id;
  const struct section_global_data *global = extra->serve_state->global;
  int *run_counts = 0;
  size_t *run_sizes = 0;
  const unsigned char *title = _("Users page");

static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

  if (cnts->user_contest_num > 0) new_contest_id = cnts->user_contest_num;
  if (ns_open_ul_connection(phr->fw_state) < 0) {
    FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  }
  if ((r = userlist_clnt_list_all_users(ul_conn, ULS_LIST_ALL_USERS,
                                        phr->contest_id, &xml_text)) < 0) {
    FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  }
  users = userlist_parse_str(xml_text);
  xfree(xml_text); xml_text = 0;
  if (!users) {
    FAIL(NEW_SRV_ERR_INTERNAL);
  }

  if (users->user_map_size > 0) {
    XCALLOC(run_counts, users->user_map_size);
    XCALLOC(run_sizes, users->user_map_size);
    run_get_all_statistics(extra->serve_state->runlog_state,
                           users->user_map_size, run_counts, run_sizes);
  }

  if (opcaps_check(phr->caps, OPCAP_GET_USER) >= 0) details_allowed = 1;

  l10n_setlocale(phr->locale_id);
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
fwrite(csp_str9, 1, 27, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str10, 1, 296, out_f);
if (global->memoize_user_results > 0) {
fwrite(csp_str11, 1, 27, out_f);
}
fwrite(csp_str12, 1, 33, out_f);
for (uid = 1; uid < users->user_map_size; uid++) {
    if (!(u = users->user_map[uid])) continue;
    if (!(uc = userlist_get_user_contest(u, new_contest_id))) continue;
fwrite(csp_str13, 1, 4, out_f);
fputs((form_row_attrs[row ^= 1]), out_f);
fwrite(csp_str14, 1, 17, out_f);
fprintf(out_f, "%d", (int)(serial++));
fwrite(csp_str15, 1, 6, out_f);
snprintf(b1, sizeof(b1), "uid == %d", uid);
fwrite(csp_str16, 1, 1, out_f);
fwrite(csp_str17, 1, 5, out_f);
fwrite(csp_str18, 1, 16, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (b1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fprintf(out_f, "%d", (int)(uid));
fputs("</a>", out_f);
fwrite(csp_str19, 1, 7, out_f);
if (details_allowed) {
fwrite(csp_str18, 1, 16, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_USER_INFO);
fputs(sep, out_f); sep = "&amp;";
fputs("user_id=", out_f);
fprintf(out_f, "%d", (int)(uid));
(void) sep;
fputs("\">", out_f);
fputs(html_armor_buf(&ab, (u->login)), out_f);
fputs("</a>", out_f);
fwrite(csp_str15, 1, 6, out_f);
} else {
fwrite(csp_str18, 1, 16, out_f);
fputs(html_armor_buf(&ab, (u->login)), out_f);
fwrite(csp_str15, 1, 6, out_f);
}
fwrite(csp_str16, 1, 1, out_f);
if (u->cnts0 && u->cnts0->name && *u->cnts0->name) {
fwrite(csp_str18, 1, 16, out_f);
fputs(html_armor_buf(&ab, (u->cnts0->name)), out_f);
fwrite(csp_str15, 1, 6, out_f);
} else {
fwrite(csp_str20, 1, 28, out_f);
}
fwrite(csp_str18, 1, 16, out_f);
fputs((userlist_unparse_reg_status(uc->status)), out_f);
fwrite(csp_str15, 1, 6, out_f);
if ((uc->flags & USERLIST_UC_ALL)) {
      r = 0;
fwrite(csp_str18, 1, 16, out_f);
if ((uc->flags & USERLIST_UC_BANNED))
        fprintf(out_f, "%s%s", r++?",":"", "banned");
      if ((uc->flags & USERLIST_UC_INVISIBLE))
        fprintf(out_f, "%s%s", r++?",":"", "invisible");
      if ((uc->flags & USERLIST_UC_LOCKED))
        fprintf(out_f, "%s%s", r++?",":"", "locked");
      if ((uc->flags & USERLIST_UC_INCOMPLETE))
        fprintf(out_f, "%s%s", r++?",":"", "incomplete");
      if ((uc->flags & USERLIST_UC_DISQUALIFIED))
        fprintf(out_f, "%s%s", r++?",":"", "disqualified");
fwrite(csp_str15, 1, 6, out_f);
} else {
fwrite(csp_str20, 1, 28, out_f);
}
fwrite(csp_str16, 1, 1, out_f);
if (uc->create_time > 0) {
fwrite(csp_str18, 1, 16, out_f);
fputs(xml_unparse_date((uc->create_time)), out_f);
fwrite(csp_str15, 1, 6, out_f);
} else {
fwrite(csp_str20, 1, 28, out_f);
}
fwrite(csp_str16, 1, 1, out_f);
if (u->cnts0 && u->cnts0->last_login_time > 0) {
fwrite(csp_str18, 1, 16, out_f);
fputs(xml_unparse_date((u->cnts0->last_login_time)), out_f);
fwrite(csp_str15, 1, 6, out_f);
} else {
fwrite(csp_str20, 1, 28, out_f);
}
fwrite(csp_str16, 1, 1, out_f);
if (run_counts[uid] > 0) {
fwrite(csp_str18, 1, 16, out_f);
fprintf(out_f, "%d", (int)(run_counts[uid]));
fwrite(csp_str21, 1, 20, out_f);
fprintf(out_f, "%zu", (size_t)(run_sizes[uid]));
fwrite(csp_str15, 1, 6, out_f);
} else {
fwrite(csp_str22, 1, 54, out_f);
}
fwrite(csp_str16, 1, 1, out_f);
if (global->memoize_user_results > 0) {
fwrite(csp_str18, 1, 16, out_f);
fprintf(out_f, "%d", (int)(serve_get_user_result_score(extra->serve_state, uid)));
fwrite(csp_str15, 1, 6, out_f);
}
fwrite(csp_str23, 1, 50, out_f);
fprintf(out_f, "%d", (int)(uid));
fwrite(csp_str24, 1, 15, out_f);
}
fwrite(csp_str25, 1, 49, out_f);
fputs(_("First User_Id"), out_f);
fwrite(csp_str26, 1, 81, out_f);
fputs(_("Last User_Id (incl.)"), out_f);
fwrite(csp_str27, 1, 125, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);
fputs(_("Back"), out_f);
fputs("</a>", out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Return to the main page"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Remove the selected users from the list"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_SET_PENDING, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Set the registration status of the selected users to PENDING"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_SET_OK, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Set the registration status of the selected users to OK"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_SET_REJECTED, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Set the registration status of the selected users to REJECTED"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_SET_INVISIBLE, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Set the INVISIBLE flag for the selected users"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Clear the INVISIBLE flag for the selected users"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_SET_BANNED, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Set the BANNED flag for the selected users"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_CLEAR_BANNED, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Clear the BANNED flag for the selected users"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_SET_LOCKED, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Set the LOCKED flag for the selected users"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_CLEAR_LOCKED, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Clear the LOCKED flag for the selected users"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_SET_INCOMPLETE, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Set the INCOMPLETE flag for the selected users"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_CLEAR_INCOMPLETE, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Clear the INCOMPLETE flag for the selected users"), out_f);
fwrite(csp_str29, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_CLEAR_DISQUALIFIED, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Clear the DISQUALIFIED flag for the selected users"), out_f);
fwrite(csp_str30, 1, 11, out_f);
if (global->is_virtual) {
fwrite(csp_str31, 1, 9, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_FORCE_START_VIRTUAL, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Force virtual contest start for the selected users"), out_f);
fwrite(csp_str30, 1, 11, out_f);
}
fwrite(csp_str32, 1, 2, out_f);
if (global->user_exam_protocol_header_txt) {
fwrite(csp_str31, 1, 9, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRINT_SELECTED_USER_PROTOCOL, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Print the user examination protocols for the selected users"), out_f);
fwrite(csp_str30, 1, 11, out_f);
}
fwrite(csp_str16, 1, 1, out_f);
if (global->full_exam_protocol_header_txt) {
fwrite(csp_str31, 1, 9, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRINT_SELECTED_USER_FULL_PROTOCOL, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Print the user full examination protocols for the selected users"), out_f);
fwrite(csp_str30, 1, 11, out_f);
}
fwrite(csp_str16, 1, 1, out_f);
if (global->full_exam_protocol_header_txt) {
fwrite(csp_str31, 1, 9, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRINT_SELECTED_UFC_PROTOCOL, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Print the user full cyphered examination protocols for the selected users"), out_f);
fwrite(csp_str30, 1, 11, out_f);
}
fwrite(csp_str33, 1, 15, out_f);
fputs(_("Disqualify selected users"), out_f);
fwrite(csp_str34, 1, 9, out_f);
fputs(_("Disqualification explanation"), out_f);
fwrite(csp_str35, 1, 114, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_SET_DISQUALIFIED, NULL), out_f);
fwrite(csp_str36, 1, 25, out_f);
fputs(_("Add new user"), out_f);
fwrite(csp_str37, 1, 78, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_ADD_BY_LOGIN, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Add a new user specifying his/her login"), out_f);
fwrite(csp_str38, 1, 77, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_USERS_ADD_BY_USER_ID, NULL), out_f);
fwrite(csp_str28, 1, 9, out_f);
fputs(_("Add a new user specifying his/her User Id"), out_f);
fwrite(csp_str39, 1, 20, out_f);
fputs("</form>", out_f);
fwrite(csp_str40, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str41, 1, 17, out_f);
l10n_setlocale(0);

cleanup:
  if (users) userlist_free(&users->b);
  html_armor_free(&ab);
  xfree(run_counts);
  xfree(run_sizes);
  return retval;
}
