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
static const unsigned char csp_str14[7] = "</td>\n";
static const unsigned char csp_str15[25] = "\n        <td class=\"b1\">";
static const unsigned char csp_str16[28] = "\n        <td class=\"b1\"><i>";
static const unsigned char csp_str17[11] = "</i></td>\n";
static const unsigned char csp_str18[37] = "\n        <td class=\"b1\">&nbsp;</td>\n";
static const unsigned char csp_str19[12] = "\n    </tr>\n";
static const unsigned char csp_str20[11] = "\n</table>\n";
static const unsigned char csp_str21[7] = "<hr/>\n";
static const unsigned char csp_str22[18] = "\n</body>\n</html>\n";

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
int csp_view_priv_exam_info_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_exam_info_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_exam_info_page(void)
{
    return &page_iface;
}

int csp_view_priv_exam_info_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
int i, j, max_user_id, serial = 1;
  struct teamdb_export td;
  struct userlist_members *mm = 0;
  struct userlist_member *m = 0;
  struct userlist_user_info *ui = 0;
  const unsigned char *title = NULL;

  if (phr->role < USER_ROLE_JUDGE) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  l10n_setlocale(phr->locale_id);
  title = _("Examination information");
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
fputs(_("User Id"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("User login"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("User name"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("Flags"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("First name"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("Family name"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("Location"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("Exam Id"), out_f);
fwrite(csp_str10, 1, 29, out_f);
fputs(_("Cypher"), out_f);
fwrite(csp_str11, 1, 16, out_f);
max_user_id = teamdb_get_max_team_id(cs->teamdb_state);
  for (i = 1; i <= max_user_id; i++) {
    if (!teamdb_lookup(cs->teamdb_state, i)) continue;
    if (teamdb_export_team(cs->teamdb_state, i, &td) < 0) continue;
    //if (td.flags) continue;
    if (!td.user) continue;

    ui = td.user->cnts0;
fwrite(csp_str12, 1, 33, out_f);
fprintf(out_f, "%d", (int)(serial++));
fwrite(csp_str13, 1, 29, out_f);
fprintf(out_f, "%d", (int)(i));
fwrite(csp_str13, 1, 29, out_f);
fputs(html_armor_buf(&ab, (td.login)), out_f);
fwrite(csp_str14, 1, 6, out_f);
if (td.name && *td.name) {
fwrite(csp_str15, 1, 24, out_f);
fputs(html_armor_buf(&ab, (td.name)), out_f);
fwrite(csp_str14, 1, 6, out_f);
} else {
fwrite(csp_str16, 1, 27, out_f);
fputs(_("Not set"), out_f);
fwrite(csp_str17, 1, 10, out_f);
}
fwrite(csp_str18, 1, 36, out_f);
m = 0;
    if (ui && (mm = ui->members) && mm->u > 0) {
      for (j = 0; j < mm->u; j++)
        if ((m = mm->m[j]) && m->team_role == USERLIST_MB_CONTESTANT)
          break;
    }

    if (m && m->firstname) {
fwrite(csp_str15, 1, 24, out_f);
fputs(html_armor_buf(&ab, (m->firstname)), out_f);
fwrite(csp_str14, 1, 6, out_f);
} else {
fwrite(csp_str18, 1, 36, out_f);
}
    if (m && m->surname) {
fwrite(csp_str15, 1, 24, out_f);
fputs(html_armor_buf(&ab, (m->surname)), out_f);
fwrite(csp_str14, 1, 6, out_f);
} else {
fwrite(csp_str18, 1, 36, out_f);
}

    if (ui && ui->location) {
fwrite(csp_str15, 1, 24, out_f);
fputs(html_armor_buf(&ab, (ui->location)), out_f);
fwrite(csp_str14, 1, 6, out_f);
} else {
fwrite(csp_str18, 1, 36, out_f);
}
    if (ui && ui->exam_id) {
fwrite(csp_str15, 1, 24, out_f);
fputs(html_armor_buf(&ab, (ui->exam_id)), out_f);
fwrite(csp_str14, 1, 6, out_f);
} else {
fwrite(csp_str18, 1, 36, out_f);
}
    if (ui && ui->exam_cypher) {
fwrite(csp_str15, 1, 24, out_f);
fputs(html_armor_buf(&ab, (ui->exam_cypher)), out_f);
fwrite(csp_str14, 1, 6, out_f);
} else {
fwrite(csp_str18, 1, 36, out_f);
}
fwrite(csp_str19, 1, 11, out_f);
}
fwrite(csp_str20, 1, 10, out_f);
fwrite(csp_str21, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str22, 1, 17, out_f);
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return retval;
  return retval;
}
