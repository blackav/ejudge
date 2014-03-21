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
static const unsigned char csp_str9[5] = "\n<p>";
static const unsigned char csp_str10[7] = "</p>\n\n";
static const unsigned char csp_str11[18] = "\n<table>\n<tr><td>";
static const unsigned char csp_str12[11] = ":</td><td>";
static const unsigned char csp_str13[20] = "</td></tr>\n<tr><td>";
static const unsigned char csp_str14[27] = "<option value=\"\"></option>";
static const unsigned char csp_str15[4] = " - ";
static const unsigned char csp_str16[21] = "</td></tr>\n\n<tr><td>";
static const unsigned char csp_str17[7] = ":</td>";
static const unsigned char csp_str18[7] = "</tr>\n";
static const unsigned char csp_str19[10] = "\n<tr><td>";
static const unsigned char csp_str20[12] = "</td></tr>\n";
static const unsigned char csp_str21[62] = ":</td><td><input type=\"file\" name=\"file\"/></td></tr>\n<tr><td>";
static const unsigned char csp_str22[36] = "</td><td>&nbsp;</td></tr>\n</table>\n";
static const unsigned char csp_str23[2] = "\n";
static const unsigned char csp_str24[7] = "<hr/>\n";
static const unsigned char csp_str25[18] = "\n</body>\n</html>\n";


#line 2 "priv_new_run_page.csp"
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
int csp_view_priv_new_run_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_new_run_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_new_run_page(void)
{
    return &page_iface;
}

int csp_view_priv_new_run_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "priv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra->serve_state;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;

#line 9 "priv_new_run_page.csp"
int i;
    const unsigned char *title = NULL;
    const struct section_global_data *global = cs->global;

  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) < 0
      || opcaps_check(phr->caps, OPCAP_EDIT_RUN)) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  l10n_setlocale(phr->locale_id);
  title = _("Add new run");
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
fwrite(csp_str9, 1, 4, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_MAIN_PAGE, 0), out_f);
fputs(_("To main page"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 6, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str11, 1, 17, out_f);
fputs(_("User ID"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<input type=\"text\" name=\"run_user_id\" size=\"10\" />", out_f);
fwrite(csp_str13, 1, 19, out_f);
fputs(_("User login"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<input type=\"text\" name=\"run_user_login\" size=\"10\" />", out_f);
fwrite(csp_str13, 1, 19, out_f);
fputs(_("Problem"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<select name=\"prob_id\"", out_f);
fputs(">", out_f);
fwrite(csp_str14, 1, 26, out_f);

#line 29 "priv_new_run_page.csp"
for (i = 1; i <= cs->max_prob; i++)
    if (cs->probs[i]) {
fputs("<option", out_f);
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(i));
fputs("\"", out_f);
fputs(">", out_f);
fputs((cs->probs[i]->short_name), out_f);
fwrite(csp_str15, 1, 3, out_f);
fputs(html_armor_buf(&ab, (cs->probs[i]->long_name)), out_f);
fputs("</option>", out_f);

#line 32 "priv_new_run_page.csp"
}
fputs("</select>", out_f);
fwrite(csp_str13, 1, 19, out_f);
fputs(_("Variant"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<input type=\"text\" name=\"variant\" size=\"10\" />", out_f);
fwrite(csp_str13, 1, 19, out_f);
fputs(_("Language"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<select name=\"language\"", out_f);
fputs(">", out_f);
fwrite(csp_str14, 1, 26, out_f);

#line 35 "priv_new_run_page.csp"
for (i = 1; i <= cs->max_lang; i++)
    if (cs->langs[i]) {
fputs("<option", out_f);
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(i));
fputs("\"", out_f);
fputs(">", out_f);
fputs((cs->langs[i]->short_name), out_f);
fwrite(csp_str15, 1, 3, out_f);
fputs(html_armor_buf(&ab, (cs->langs[i]->long_name)), out_f);
fputs("</option>", out_f);

#line 36 "priv_new_run_page.csp"
}
fputs("</select>", out_f);
fwrite(csp_str16, 1, 20, out_f);
fputs(_("Imported?"), out_f);
fwrite(csp_str12, 1, 10, out_f);
{
  unsigned char *s1 = "", *s2 = "";
fputs("<select name=\"is_imported\"><option value=\"0\"", out_f);
fputs(s1, out_f);
fputs(">", out_f);
fputs(_("No"), out_f);
fputs("</option><option value=\"1\"", out_f);
fputs(s2, out_f);
fputs(">", out_f);
fputs(_("Yes"), out_f);
fputs("</option></select>", out_f);
}
fwrite(csp_str13, 1, 19, out_f);
fputs(_("Hidden?"), out_f);
fwrite(csp_str12, 1, 10, out_f);
{
  unsigned char *s1 = "", *s2 = "";
fputs("<select name=\"is_hidden\"><option value=\"0\"", out_f);
fputs(s1, out_f);
fputs(">", out_f);
fputs(_("No"), out_f);
fputs("</option><option value=\"1\"", out_f);
fputs(s2, out_f);
fputs(">", out_f);
fputs(_("Yes"), out_f);
fputs("</option></select>", out_f);
}
fwrite(csp_str13, 1, 19, out_f);
fputs(_("Read-only?"), out_f);
fwrite(csp_str12, 1, 10, out_f);
{
  unsigned char *s1 = "", *s2 = "";
fputs("<select name=\"is_readonly\"><option value=\"0\"", out_f);
fputs(s1, out_f);
fputs(">", out_f);
fputs(_("No"), out_f);
fputs("</option><option value=\"1\"", out_f);
fputs(s2, out_f);
fputs(">", out_f);
fputs(_("Yes"), out_f);
fputs("</option></select>", out_f);
}
fwrite(csp_str13, 1, 19, out_f);
fputs(_("Status"), out_f);
fwrite(csp_str17, 1, 6, out_f);

#line 41 "priv_new_run_page.csp"
write_change_status_dialog(cs, out_f, 0, 0, 0, -1, 0);
fwrite(csp_str18, 1, 6, out_f);

#line 42 "priv_new_run_page.csp"
if (global->score_system == SCORE_KIROV
      || global->score_system == SCORE_OLYMPIAD) {
fwrite(csp_str19, 1, 9, out_f);
fputs(_("Tests passed"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<input type=\"text\" name=\"tests\" size=\"10\" />", out_f);
fwrite(csp_str13, 1, 19, out_f);
fputs(_("Score gained"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<input type=\"text\" name=\"score\" size=\"10\" />", out_f);
fwrite(csp_str20, 1, 11, out_f);

#line 46 "priv_new_run_page.csp"
} else if (global->score_system == SCORE_MOSCOW) {
fwrite(csp_str19, 1, 9, out_f);
fputs(_("Failed test"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<input type=\"text\" name=\"tests\" size=\"10\" />", out_f);
fwrite(csp_str13, 1, 19, out_f);
fputs(_("Score gained"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<input type=\"text\" name=\"score\" size=\"10\" />", out_f);
fwrite(csp_str20, 1, 11, out_f);

#line 49 "priv_new_run_page.csp"
} else {
fwrite(csp_str19, 1, 9, out_f);
fputs(_("Failed test"), out_f);
fwrite(csp_str12, 1, 10, out_f);
fputs("<input type=\"text\" name=\"tests\" size=\"10\" />", out_f);
fwrite(csp_str20, 1, 11, out_f);

#line 51 "priv_new_run_page.csp"
}
fwrite(csp_str19, 1, 9, out_f);
fputs(_("File"), out_f);
fwrite(csp_str21, 1, 61, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_NEW_RUN, NULL), out_f);
fwrite(csp_str22, 1, 35, out_f);
fputs("</form>", out_f);
fwrite(csp_str23, 1, 1, out_f);
fwrite(csp_str24, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str25, 1, 17, out_f);

#line 58 "priv_new_run_page.csp"
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return 0;
}
