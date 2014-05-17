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
static const unsigned char csp_str10[18] = "\n<table>\n<tr><td>";
static const unsigned char csp_str11[10] = "</td><td>";
static const unsigned char csp_str12[20] = "</td></tr>\n<tr><td>";
static const unsigned char csp_str13[36] = "</td><td>&nbsp;</td></tr>\n</table>\n";
static const unsigned char csp_str14[63] = "\n\n<p>The following formula is applied: mult * X + shift.</p>\n\n";
static const unsigned char csp_str15[7] = "<hr/>\n";
static const unsigned char csp_str16[18] = "\n</body>\n</html>\n";

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
int csp_view_priv_assign_cyphers_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_assign_cyphers_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_assign_cyphers_page(void)
{
    return &page_iface;
}

int csp_view_priv_assign_cyphers_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
const unsigned char *title = NULL;

  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);  

  l10n_setlocale(phr->locale_id);
  title = _("Assign cyphers");
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
fwrite(csp_str10, 1, 17, out_f);
fputs("<input type=\"text\" name=\"prefix\" size=\"16\" />", out_f);
fwrite(csp_str11, 1, 9, out_f);
fputs(_("Cypher prefix"), out_f);
fwrite(csp_str12, 1, 19, out_f);
fputs("<input type=\"text\" name=\"min_num\" size=\"16\" />", out_f);
fwrite(csp_str11, 1, 9, out_f);
fputs(_("Minimal random number"), out_f);
fwrite(csp_str12, 1, 19, out_f);
fputs("<input type=\"text\" name=\"max_num\" size=\"16\" />", out_f);
fwrite(csp_str11, 1, 9, out_f);
fputs(_("Maximal random number"), out_f);
fwrite(csp_str12, 1, 19, out_f);
fputs("<input type=\"text\" name=\"seed\" size=\"16\" />", out_f);
fwrite(csp_str11, 1, 9, out_f);
fputs(_("Random seed"), out_f);
fwrite(csp_str12, 1, 19, out_f);
fputs("<input type=\"text\" name=\"mult\" size=\"16\" />", out_f);
fwrite(csp_str11, 1, 9, out_f);
fputs(_("Mult parameter"), out_f);
fwrite(csp_str12, 1, 19, out_f);
fputs("<input type=\"text\" name=\"shift\" size=\"16\" />", out_f);
fwrite(csp_str11, 1, 9, out_f);
fputs(_("Shift parameter"), out_f);
fwrite(csp_str12, 1, 19, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_ASSIGN_CYPHERS_2, NULL), out_f);
fwrite(csp_str13, 1, 35, out_f);
fputs("</form>", out_f);
fwrite(csp_str14, 1, 62, out_f);
fwrite(csp_str15, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str16, 1, 17, out_f);
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return retval;
}
