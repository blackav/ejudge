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
static const unsigned char csp_str9[18] = "\n<table>\n<tr><td>";
static const unsigned char csp_str10[11] = ":</td><td>";
static const unsigned char csp_str11[20] = "</td></tr>\n<tr><td>";
static const unsigned char csp_str12[35] = "</td></tr>\n<tr><td>&nbsp;</td><td>";
static const unsigned char csp_str13[21] = "</td></tr>\n</table>\n";
static const unsigned char csp_str14[7] = "<hr/>\n";
static const unsigned char csp_str15[18] = "\n</body>\n</html>\n";

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
int csp_view_priv_login_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_login_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_login_page(void)
{
    return &page_iface;
}

int csp_view_priv_login_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
const unsigned char *s;
  int r, n;
  const unsigned char *login = NULL;
  const unsigned char *password = NULL;
  int contest_id = phr->contest_id;
  const unsigned char *title = _("Login page");
hr_cgi_param(phr, "login", &login);
  hr_cgi_param(phr, "password", &password);

  if (!phr->role) {
    phr->role = USER_ROLE_OBSERVER;
    if (hr_cgi_param(phr, "role", &s) > 0) {
      if (sscanf(s, "%d%n", &r, &n) == 1 && !s[n]
          && r >= USER_ROLE_CONTESTANT && r < USER_ROLE_LAST)
        phr->role = r;
    }
  }

  l10n_setlocale(phr->locale_id);
  phr->client_key = 0;
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
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
if (phr->hidden_vars) { fputs(phr->hidden_vars, out_f); }
fwrite(csp_str9, 1, 17, out_f);
fputs(_("Login"), out_f);
fwrite(csp_str10, 1, 10, out_f);
fputs("<input type=\"text\" name=\"login\" size=\"32\"", out_f);
if ((login)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (login)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str11, 1, 19, out_f);
fputs(_("Password"), out_f);
fwrite(csp_str10, 1, 10, out_f);
fputs("<input type=\"password\" name=\"password\" size=\"32\"", out_f);
if ((password)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (password)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str11, 1, 19, out_f);
fputs(_("Contest"), out_f);
fwrite(csp_str10, 1, 10, out_f);
fputs("<input type=\"text\" name=\"contest_id\" size=\"32\"", out_f);
if ((contest_id) > 0) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(contest_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str11, 1, 19, out_f);
fputs(_("Role"), out_f);
fwrite(csp_str10, 1, 10, out_f);
html_role_select(out_f, phr->role, 1, 0);
fwrite(csp_str11, 1, 19, out_f);
fputs(_("Language"), out_f);
fwrite(csp_str10, 1, 10, out_f);
l10n_html_locale_select(out_f, phr->locale_id);
fwrite(csp_str12, 1, 34, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_MAIN_PAGE, _("Submit")), out_f);
fwrite(csp_str13, 1, 20, out_f);
fputs("</form>", out_f);
fwrite(csp_str14, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str15, 1, 17, out_f);
l10n_setlocale(0);
  html_armor_free(&ab);
  return retval;
}
