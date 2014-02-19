/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\'text/html; charset=";
static const unsigned char csp_str1[35] = "\' />\n<link rel=\"stylesheet\" href=\'";
static const unsigned char csp_str2[82] = "priv.css\' type=\"text/css\" />\n<script type=\"text/javascript\" charset=\"UTF-8\" src=\"";
static const unsigned char csp_str3[27] = "priv.js\"></script>\n<title>";
static const unsigned char csp_str4[3] = " [";
static const unsigned char csp_str5[3] = ", ";
static const unsigned char csp_str6[4] = "]: ";
static const unsigned char csp_str7[29] = "</title>\n</head>\n<body>\n<h1>";
static const unsigned char csp_str8[34] = "</h1>\n\n<h2>Privileged users</h2>\n";
static const unsigned char csp_str9[174] = "\n<table class=\"b1\"><tr><th class=\"b1\">NN</th><th class=\"b1\">Id</th><th class=\"b1\">Login</th><th class=\"b1\">Name</th><th class=\"b1\">Roles</th><th class=\"b1\">Select</th></tr>\n";
static const unsigned char csp_str10[5] = "\n<tr";
static const unsigned char csp_str11[22] = ">\n    <td class=\"b1\">";
static const unsigned char csp_str12[26] = "</td>\n    <td class=\"b1\">";
static const unsigned char csp_str13[7] = "</td>\n";
static const unsigned char csp_str14[18] = "\n<td class=\"b1\">\n";
static const unsigned char csp_str15[8] = "\n</td>\n";
static const unsigned char csp_str16[29] = "\n<td class=\"b1\">&nbsp;</td>\n";
static const unsigned char csp_str17[51] = "\n<td class=\"b1\"><input type=\"checkbox\" name=\'user_";
static const unsigned char csp_str18[16] = "\'/></td>\n</tr>\n";
static const unsigned char csp_str19[56] = "\n</table>\n\n<h2>Available actions</h2>\n\n<table>\n<tr><td>";
static const unsigned char csp_str20[10] = "</td><td>";
static const unsigned char csp_str21[20] = "</td></tr>\n<tr><td>";
static const unsigned char csp_str22[26] = "</td></tr>\n</table>\n\n<h2>";
static const unsigned char csp_str23[81] = "</h2>\n\n<table>\n<tr><td><input type=\"text\" size=\"32\" name=\"add_login\"/></td><td>\n";
static const unsigned char csp_str24[11] = "\n</td><td>";
static const unsigned char csp_str25[79] = "</td></tr>\n<tr><td><input type=\"text\" size=\"32\" name=\"add_user_id\"/></td><td>\n";
static const unsigned char csp_str26[28] = "</td></tr>\n</table>\n\n<hr/>\n";
static const unsigned char csp_str27[18] = "\n</body>\n</html>\n";
static const unsigned char csp_str28[2] = "\n";


#line 2 "priv_view_priv_users_page.csp"
/* $Id$ */

#include "new-server.h"
#include "misctext.h"
#include "mischtml.h"
#include "l10n.h"
#include "external_action.h"
#include "new_server_pi.h"
#include "copyright.h"

#include <stdio.h>

#include <libintl.h>
#define _(x) gettext(x)

void
html_role_select(FILE *fout, int role, int allow_admin,
                 const unsigned char *var_name);
int csp_view_priv_view_priv_users_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 24 "priv_view_priv_users_page.csp"
PrivViewPrivUsersPage *pvp = (PrivViewPrivUsersPage*) ps;
  PrivUserInfoArray *users = &pvp->users;
  struct contest_extra *extra = phr->extra;
  int i;
  unsigned int role_mask;
  int row = 1, cnt, r;
  unsigned char hbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

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
fputs((phr->name_arm), out_f);
fwrite(csp_str5, 1, 2, out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fwrite(csp_str5, 1, 2, out_f);
fputs((extra->contest_arm), out_f);
fwrite(csp_str6, 1, 3, out_f);
fputs(_("Privileged users page"), out_f);
fwrite(csp_str7, 1, 28, out_f);
fputs((ns_unparse_role(phr->role)), out_f);
fwrite(csp_str4, 1, 2, out_f);
fputs((phr->name_arm), out_f);
fwrite(csp_str5, 1, 2, out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fwrite(csp_str5, 1, 2, out_f);
fputs((extra->contest_arm), out_f);
fwrite(csp_str6, 1, 3, out_f);
fputs(_("Privileged users page"), out_f);
fwrite(csp_str8, 1, 33, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str9, 1, 173, out_f);

#line 54 "priv_view_priv_users_page.csp"
for (i = 0; i < users->u; i++) {
fwrite(csp_str10, 1, 4, out_f);
fputs((form_row_attrs[row ^= 1]), out_f);
fwrite(csp_str11, 1, 21, out_f);
fprintf(out_f, "%d", (int)(i + 1));
fwrite(csp_str12, 1, 25, out_f);
fprintf(out_f, "%d", (int)(users->v[i]->user_id));
fwrite(csp_str12, 1, 25, out_f);
fputs(html_armor_buf(&ab, (users->v[i]->login)), out_f);
fwrite(csp_str12, 1, 25, out_f);
fputs(html_armor_buf(&ab, (users->v[i]->name)), out_f);
fwrite(csp_str13, 1, 6, out_f);

#line 62 "priv_view_priv_users_page.csp"
if ((role_mask = users->v[i]->role_mask)) {
fwrite(csp_str14, 1, 17, out_f);

#line 66 "priv_view_priv_users_page.csp"
for (cnt = 0, r = USER_ROLE_OBSERVER; r <= USER_ROLE_ADMIN; r++)
        if ((role_mask & (1 << r)))
          fprintf(out_f, "%s%s", cnt++?",":"", ns_unparse_role(r));
fwrite(csp_str15, 1, 7, out_f);

#line 72 "priv_view_priv_users_page.csp"
} else {
fwrite(csp_str16, 1, 28, out_f);

#line 76 "priv_view_priv_users_page.csp"
}
fwrite(csp_str17, 1, 50, out_f);
fprintf(out_f, "%d", (int)(users->v[i]->user_id));
fwrite(csp_str18, 1, 15, out_f);

#line 81 "priv_view_priv_users_page.csp"
}
fwrite(csp_str19, 1, 55, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_MAIN_PAGE, 0), out_f);
fputs(_("Back"), out_f);
fputs("</a>", out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Return to the main page"), out_f);
fwrite(csp_str21, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_REMOVE, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Remove the selected users from the list (ADMINISTRATORs cannot be removed)"), out_f);
fwrite(csp_str21, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Add the OBSERVER role to the selected users"), out_f);
fwrite(csp_str21, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Remove the OBSERVER role from the selected users"), out_f);
fwrite(csp_str21, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Add the EXAMINER role to the selected users"), out_f);
fwrite(csp_str21, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Remove the EXAMINER role from the selected users"), out_f);
fwrite(csp_str21, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Add the CHIEF EXAMINER role to the selected users"), out_f);
fwrite(csp_str21, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Remove the CHIEF EXAMINER role from the selected users"), out_f);
fwrite(csp_str21, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Add the COORDINATOR role to the selected users"), out_f);
fwrite(csp_str21, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Remove the COORDINATOR role from the selected users"), out_f);
fwrite(csp_str22, 1, 25, out_f);
fputs(_("Add new user"), out_f);
fwrite(csp_str23, 1, 80, out_f);

#line 104 "priv_view_priv_users_page.csp"
html_role_select(out_f, USER_ROLE_OBSERVER, 0, "add_role_1");
fwrite(csp_str24, 1, 10, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_ADD_BY_LOGIN, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Add a new user specifying his/her login"), out_f);
fwrite(csp_str25, 1, 78, out_f);

#line 107 "priv_view_priv_users_page.csp"
html_role_select(out_f, USER_ROLE_OBSERVER, 0, "add_role_2");
fwrite(csp_str24, 1, 10, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_USERS_ADD_BY_USER_ID, NULL), out_f);
fwrite(csp_str20, 1, 9, out_f);
fputs(_("Add a new user specifying his/her User Id"), out_f);
fwrite(csp_str26, 1, 27, out_f);
write_copyright_short(out_f);
fwrite(csp_str27, 1, 17, out_f);

#line 116 "priv_view_priv_users_page.csp"
l10n_setlocale(0);
  html_armor_free(&ab);
fwrite(csp_str28, 1, 1, out_f);
  return 0;
}
