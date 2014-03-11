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
static const unsigned char csp_str9[83] = "<table class=\"b1\">\n    <tr>\n        <th class=\"b1\">NN</th>\n        <th class=\"b1\">";
static const unsigned char csp_str10[30] = "</th>\n        <th class=\"b1\">";
static const unsigned char csp_str11[17] = "</th>\n    </tr>\n";
static const unsigned char csp_str12[34] = "\n    <tr>\n        <td class=\"b1\">";
static const unsigned char csp_str13[30] = "</td>\n        <td class=\"b1\">";
static const unsigned char csp_str14[2] = " ";
static const unsigned char csp_str15[3] = " (";
static const unsigned char csp_str16[2] = ")";
static const unsigned char csp_str17[17] = "</td>\n    </tr>\n";
static const unsigned char csp_str18[11] = "\n</table>\n";
static const unsigned char csp_str19[7] = "<hr/>\n";
static const unsigned char csp_str20[18] = "\n</body>\n</html>\n";


#line 2 "priv_ip_users_page.csp"
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

#line 5 "priv_ip_users_page.csp"
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)
int csp_view_priv_ip_users_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "priv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra->serve_state;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));

#line 10 "priv_ip_users_page.csp"
PrivViewIPUsersPage *pp = (PrivViewIPUsersPage*) pg;
    int i, j, serial = 0;
    const unsigned char *title = NULL;
    struct teamdb_export td;

    if (phr->role < USER_ROLE_JUDGE) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

    l10n_setlocale(phr->locale_id);
    title = _("Users for IP addresses");
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
fwrite(csp_str9, 1, 82, out_f);
fputs(_("IP address"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("Users"), out_f);
fwrite(csp_str11, 1, 16, out_f);

#line 26 "priv_ip_users_page.csp"
for (i = 0; i < pp->ips.u; ++i) {
fwrite(csp_str12, 1, 33, out_f);
fprintf(out_f, "%d", (int)(serial++));
fwrite(csp_str13, 1, 29, out_f);
fputs((pp->ips.v[i].ip_str), out_f);
fwrite(csp_str13, 1, 29, out_f);

#line 31 "priv_ip_users_page.csp"
for (j = 0; j < pp->ips.v[i].uid_u; ++j) {
      if (!teamdb_lookup(cs->teamdb_state, pp->ips.v[i].uids[j]))
        continue;
      if (teamdb_export_team(cs->teamdb_state, pp->ips.v[i].uids[j], &td) < 0)
        continue;
      if (j > 0) {
fwrite(csp_str14, 1, 1, out_f);

#line 36 "priv_ip_users_page.csp"
}
fputs(html_armor_buf(&ab, (td.login)), out_f);

#line 37 "priv_ip_users_page.csp"
if (td.name && *td.name) {
fwrite(csp_str15, 1, 2, out_f);
fputs(html_armor_buf(&ab, (td.name)), out_f);
fwrite(csp_str16, 1, 1, out_f);

#line 38 "priv_ip_users_page.csp"
}
    }
fwrite(csp_str17, 1, 16, out_f);

#line 41 "priv_ip_users_page.csp"
}
fwrite(csp_str18, 1, 10, out_f);
fwrite(csp_str19, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str20, 1, 17, out_f);

#line 45 "priv_ip_users_page.csp"
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return 0;
}
