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
static const unsigned char csp_str10[6] = "\n    ";
static const unsigned char csp_str11[45] = "\n\n<table class=\"b0\"><tr>\n    <td class=\"b0\">";
static const unsigned char csp_str12[26] = "</td>\n    <td class=\"b0\">";
static const unsigned char csp_str13[29] = "</td>\n</tr></table>\n\n<hr/>\n\n";
static const unsigned char csp_str14[8] = "\n<p><i>";
static const unsigned char csp_str15[10] = "</i></p>\n";
static const unsigned char csp_str16[7] = "\n<pre>";
static const unsigned char csp_str17[8] = "</pre>\n";
static const unsigned char csp_str18[3] = "\n\n";
static const unsigned char csp_str19[7] = "<hr/>\n";
static const unsigned char csp_str20[18] = "\n</body>\n</html>\n";

/* $Id: priv_assign_cyphers_page.csp 7996 2014-03-18 13:33:03Z cher $ */
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
#include "fileutl.h"

#include <sys/types.h>
#include <sys/stat.h>
int csp_view_priv_audit_log_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_audit_log_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_audit_log_page(void)
{
    return &page_iface;
}

int csp_view_priv_audit_log_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
int run_id;
  struct run_entry re;
  int rep_flag;
  path_t audit_log_path;
  struct stat stb;
  char *audit_text = 0;
  size_t audit_text_size = 0;
  unsigned char title[1024];

  if (ns_parse_run_id(out_f, phr, cnts, extra, &run_id, 0) < 0) {
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  }

  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)
      || run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  }

  if ((rep_flag = serve_make_audit_read_path(cs, audit_log_path, sizeof(audit_log_path), &re)) < 0) {
    FAIL(NEW_SRV_ERR_AUDIT_LOG_NONEXISTANT);
  }
  if (lstat(audit_log_path, &stb) < 0 || !S_ISREG(stb.st_mode)) {
    FAIL(NEW_SRV_ERR_AUDIT_LOG_NONEXISTANT);
  }

  if (generic_read_file(&audit_text, 0, &audit_text_size, 0, 0, audit_log_path, 0) < 0) {
    FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
  }

  l10n_setlocale(phr->locale_id);
  snprintf(title, sizeof(title), "%s %d", _("Viewing audit log for"), run_id);
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
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str11, 1, 44, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);
fputs(_("Main page"), out_f);
fputs("</a>", out_f);
fwrite(csp_str12, 1, 25, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_SOURCE);
fputs(sep, out_f); sep = "&amp;";
fputs("run_id=", out_f);
fprintf(out_f, "%d", (int)(run_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Source"), out_f);
fputs("</a>", out_f);
fwrite(csp_str12, 1, 25, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_REPORT);
fputs(sep, out_f); sep = "&amp;";
fputs("run_id=", out_f);
fprintf(out_f, "%d", (int)(run_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Report"), out_f);
fputs("</a>", out_f);
fwrite(csp_str12, 1, 25, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_USER_REPORT);
fputs(sep, out_f); sep = "&amp;";
fputs("run_id=", out_f);
fprintf(out_f, "%d", (int)(run_id));
(void) sep;
fputs("\">", out_f);
fputs(_("User report"), out_f);
fputs("</a>", out_f);
fwrite(csp_str12, 1, 25, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_AUDIT_LOG);
fputs(sep, out_f); sep = "&amp;";
fputs("run_id=", out_f);
fprintf(out_f, "%d", (int)(run_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Audit log"), out_f);
fputs("</a>", out_f);
fwrite(csp_str13, 1, 28, out_f);
if (!audit_text || !*audit_text) {
fwrite(csp_str14, 1, 7, out_f);
fputs(_("Audit log is empty"), out_f);
fwrite(csp_str15, 1, 9, out_f);
} else {
fwrite(csp_str16, 1, 6, out_f);
fputs(html_armor_buf(&ab, (audit_text)), out_f);
fwrite(csp_str17, 1, 7, out_f);
}
fwrite(csp_str18, 1, 2, out_f);
fwrite(csp_str19, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str20, 1, 17, out_f);
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return retval;
}
