/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[41] = "\"/>\n<script type=\"text/javascript\" src=\"";
static const unsigned char csp_str2[82] = "dojo/dojo.js\" djConfig=\"isDebug: false, parseOnLoad: true, dojoIframeHistoryUrl:\'";
static const unsigned char csp_str3[84] = "dojo/resources/iframe_history.html\'\"></script>\n<script type=\"text/javascript\" src=\"";
static const unsigned char csp_str4[65] = "unpriv.js\"></script>\n<script type=\"text/javascript\">\n  var SID=\"";
static const unsigned char csp_str5[41] = "\";\n  var NEW_SRV_ACTION_JSON_USER_STATE=";
static const unsigned char csp_str6[45] = ";\n  var NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY=";
static const unsigned char csp_str7[19] = ";\n  var self_url=\"";
static const unsigned char csp_str8[23] = "\";\n  var script_name=\"";
static const unsigned char csp_str9[35] = "\";\n  dojo.require(\"dojo.parser\");\n";
static const unsigned char csp_str10[19] = "  var jsonState = ";
static const unsigned char csp_str11[3] = ";\n";
static const unsigned char csp_str12[30] = "  var updateFailedMessage = \"";
static const unsigned char csp_str13[38] = "\";\n  var testingInProgressMessage = \"";
static const unsigned char csp_str14[30] = "\";\n  var testingCompleted = \"";
static const unsigned char csp_str15[28] = "\";\n  var waitingTooLong = \"";
static const unsigned char csp_str16[43] = "\";\n</script>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str17[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str18[3] = " [";
static const unsigned char csp_str19[4] = "]: ";
static const unsigned char csp_str20[22] = "</title></head>\n<body";
static const unsigned char csp_str21[23] = " onload=\"startClock()\"";
static const unsigned char csp_str22[62] = "><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str23[8] = "</div>\n";
static const unsigned char csp_str24[2] = "\n";
static const unsigned char csp_str25[5] = "\n<p>";
static const unsigned char csp_str26[29] = "</p>\n<font color=\"red\"><pre>";
static const unsigned char csp_str27[15] = "</pre></font>\n";
static const unsigned char csp_str28[18] = "<div id=\"footer\">";
static const unsigned char csp_str29[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";


#line 2 "unpriv_error_unknown.csp"
/* $Id$ */

#line 2 "unpriv_includes.csp"
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
#include "sformat.h"

#include "reuse/xalloc.h"

#include <libintl.h>
#define _(x) gettext(x)

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

void
unpriv_load_html_style(struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra **p_extra,
                       time_t *p_cur_time);
void
do_json_user_state(FILE *fout, const serve_state_t cs, int user_id,
                   int need_reload_check);
int csp_view_unpriv_error_unknown(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_unpriv_error_unknown, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_unpriv_error_unknown(void)
{
    return &page_iface;
}

int csp_view_unpriv_error_unknown(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "unpriv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr?phr->extra:NULL;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr?phr->cnts:NULL;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
  unsigned char time_buf[256] __attribute__((unused));
  int unread_clars __attribute__((unused)) = 0;
  int shown_items __attribute__((unused)) = 0;
  time_t sched_time __attribute__((unused)) = 0;
  time_t duration __attribute__((unused)) = 0;
  time_t fog_start_time __attribute__((unused)) = 0;
  struct teamdb_export tdb __attribute__((unused));
  struct sformat_extra_data fe __attribute__((unused));

#line 9 "unpriv_error_unknown.csp"
unsigned char title[1024];
  const unsigned char *error_title = NULL;

  l10n_setlocale(phr->locale_id);
  error_title = ns_error_title(phr->error_code);
  snprintf(title, sizeof(title), "%s: %s", _("Error"), error_title);
fwrite(csp_str0, 1, 183, out_f);
fwrite("utf-8", 1, 5, out_f);
fwrite(csp_str1, 1, 40, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str2, 1, 81, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str3, 1, 83, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str4, 1, 64, out_f);
fprintf(out_f, "%016llx", (phr->session_id));
fwrite(csp_str5, 1, 40, out_f);
fprintf(out_f, "%d", NEW_SRV_ACTION_JSON_USER_STATE);
fwrite(csp_str6, 1, 44, out_f);
fprintf(out_f, "%d", NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY);
fwrite(csp_str7, 1, 18, out_f);
fputs((phr->self_url), out_f);
fwrite(csp_str8, 1, 22, out_f);
fputs((phr->script_name), out_f);
fwrite(csp_str9, 1, 34, out_f);

#line 14 "unpriv_header.csp"
#if defined CONF_ENABLE_AJAX && CONF_ENABLE_AJAX
  if (cs && phr->user_id > 0 ) {
fwrite(csp_str10, 1, 18, out_f);

#line 17 "unpriv_header.csp"
do_json_user_state(out_f, cs, phr->user_id, 0);
fwrite(csp_str11, 1, 2, out_f);

#line 19 "unpriv_header.csp"
}
#endif
fwrite(csp_str12, 1, 29, out_f);
fputs(_("STATUS UPDATE FAILED!"), out_f);
fwrite(csp_str13, 1, 37, out_f);
fputs(_("TESTING IN PROGRESS..."), out_f);
fwrite(csp_str14, 1, 29, out_f);
fputs(_("TESTING COMPLETED"), out_f);
fwrite(csp_str15, 1, 27, out_f);
fputs(_("REFRESH PAGE MANUALLY!"), out_f);
fwrite(csp_str16, 1, 42, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str17, 1, 37, out_f);

#line 27 "unpriv_header.csp"
if (phr) {
fputs((phr->name_arm), out_f);

#line 27 "unpriv_header.csp"
}
fwrite(csp_str18, 1, 2, out_f);

#line 27 "unpriv_header.csp"
if (extra) {
fputs((extra->contest_arm), out_f);

#line 27 "unpriv_header.csp"
}
fwrite(csp_str19, 1, 3, out_f);
fputs((title), out_f);
fwrite(csp_str20, 1, 21, out_f);

#line 29 "unpriv_header.csp"
#if defined CONF_ENABLE_AJAX && CONF_ENABLE_AJAX
fwrite(csp_str21, 1, 22, out_f);

#line 31 "unpriv_header.csp"
#endif
fwrite(csp_str22, 1, 61, out_f);

#line 33 "unpriv_header.csp"
if (phr) {
fputs((phr->name_arm), out_f);

#line 33 "unpriv_header.csp"
}
fwrite(csp_str18, 1, 2, out_f);

#line 33 "unpriv_header.csp"
if (extra) {
fputs((extra->contest_arm), out_f);

#line 33 "unpriv_header.csp"
}
fwrite(csp_str19, 1, 3, out_f);
fputs((title), out_f);
fwrite(csp_str23, 1, 7, out_f);
fwrite(csp_str24, 1, 1, out_f);

#line 17 "unpriv_error_unknown.csp"
if (phr->log_t && *phr->log_t) {
fwrite(csp_str25, 1, 4, out_f);
fputs(_("Additional information about this error:"), out_f);
fwrite(csp_str26, 1, 28, out_f);
fputs(html_armor_buf(&ab, (phr->log_t)), out_f);
fwrite(csp_str27, 1, 14, out_f);

#line 20 "unpriv_error_unknown.csp"
}
fwrite(csp_str24, 1, 1, out_f);
fwrite(csp_str28, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str29, 1, 37, out_f);

#line 23 "unpriv_error_unknown.csp"
l10n_setlocale(0);
  html_armor_free(&ab);
  return retval;
}
