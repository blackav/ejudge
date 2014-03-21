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
static const unsigned char csp_str9[84] = "\n<table class=\"b1\">\n    <tr>\n        <th class=\"b1\">NN</th>\n        <th class=\"b1\">";
static const unsigned char csp_str10[30] = "</th>\n        <th class=\"b1\">";
static const unsigned char csp_str11[17] = "</th>\n    </tr>\n";
static const unsigned char csp_str12[34] = "\n    <tr>\n        <td class=\"b1\">";
static const unsigned char csp_str13[30] = "</td>\n        <td class=\"b1\">";
static const unsigned char csp_str14[7] = "</td>\n";
static const unsigned char csp_str15[29] = "\n        <td class=\"b1\"><tt>";
static const unsigned char csp_str16[12] = "</tt></td>\n";
static const unsigned char csp_str17[28] = "\n        <td class=\"b1\"><i>";
static const unsigned char csp_str18[11] = "</i></td>\n";
static const unsigned char csp_str19[25] = "\n        <td class=\"b1\">";
static const unsigned char csp_str20[2] = " ";
static const unsigned char csp_str21[17] = "</td>\n    </tr>\n";
static const unsigned char csp_str22[11] = "\n</table>\n";
static const unsigned char csp_str23[7] = "<hr/>\n";
static const unsigned char csp_str24[18] = "\n</body>\n</html>\n";


#line 2 "priv_user_ips_page.csp"
/* $Id$ */

#line 2 "priv_includes.csp"
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
int csp_view_priv_user_ips_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "priv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra->serve_state;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;

#line 8 "priv_user_ips_page.csp"
PrivViewUserIPsPage *pp = (PrivViewUserIPsPage*) pg;
    int i, max_user_id, serial = 1, j;
    PrivUserIPItem *ui;
    struct teamdb_export td;
    const unsigned char *title = NULL;

    if (phr->role < USER_ROLE_JUDGE) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

    l10n_setlocale(phr->locale_id);
    title = _("IP addresses for users");
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
fputs((title), out_f);
fwrite(csp_str7, 1, 28, out_f);
fputs((ns_unparse_role(phr->role)), out_f);
fwrite(csp_str4, 1, 2, out_f);
fputs((phr->name_arm), out_f);
fwrite(csp_str5, 1, 2, out_f);
fprintf(out_f, "%d", (int)(phr->contest_id));
fwrite(csp_str5, 1, 2, out_f);
fputs((extra->contest_arm), out_f);
fwrite(csp_str6, 1, 3, out_f);
fputs((title), out_f);
fwrite(csp_str8, 1, 6, out_f);
fwrite(csp_str9, 1, 83, out_f);
fputs(_("User Id"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("User login"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("User name"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("IP addresses"), out_f);
fwrite(csp_str11, 1, 16, out_f);

#line 29 "priv_user_ips_page.csp"
if (cs->global->disable_user_database > 0) {
    max_user_id = run_get_max_user_id(cs->runlog_state);
  } else {
    max_user_id = teamdb_get_max_team_id(cs->teamdb_state);
  }
  for (i = 1; i < pp->users.a && i <= max_user_id; ++i) {
    ui = pp->users.v[i];
    if (!ui) continue;
    if (!teamdb_lookup(cs->teamdb_state, i)) continue;
    if (teamdb_export_team(cs->teamdb_state, i, &td) < 0) continue;
fwrite(csp_str12, 1, 33, out_f);
fprintf(out_f, "%d", (int)(serial++));
fwrite(csp_str13, 1, 29, out_f);
fprintf(out_f, "%d", (int)(i));
fwrite(csp_str13, 1, 29, out_f);
fputs(html_armor_buf(&ab, (td.login)), out_f);
fwrite(csp_str14, 1, 6, out_f);

#line 44 "priv_user_ips_page.csp"
if (td.name && *td.name) {
fwrite(csp_str15, 1, 28, out_f);
fputs(html_armor_buf(&ab, (td.name)), out_f);
fwrite(csp_str16, 1, 11, out_f);

#line 46 "priv_user_ips_page.csp"
} else {
fwrite(csp_str17, 1, 27, out_f);
fputs(_("Not set"), out_f);
fwrite(csp_str18, 1, 10, out_f);

#line 48 "priv_user_ips_page.csp"
}
fwrite(csp_str19, 1, 24, out_f);

#line 49 "priv_user_ips_page.csp"
for (j = 0; j < ui->ip_u; ++j) {
      if (j > 0) {
fwrite(csp_str20, 1, 1, out_f);

#line 50 "priv_user_ips_page.csp"
}
fprintf(out_f, "%s", xml_unparse_ipv6(&(ui->ips[j])));

#line 50 "priv_user_ips_page.csp"
}
fwrite(csp_str21, 1, 16, out_f);

#line 52 "priv_user_ips_page.csp"
}
fwrite(csp_str22, 1, 10, out_f);
fwrite(csp_str23, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str24, 1, 17, out_f);

#line 56 "priv_user_ips_page.csp"
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return 0;
}
