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
static const unsigned char csp_str9[53] = "\";\n  dojo.require(\"dojo.parser\");\n  var jsonState = ";
static const unsigned char csp_str10[32] = ";\n  var updateFailedMessage = \"";
static const unsigned char csp_str11[38] = "\";\n  var testingInProgressMessage = \"";
static const unsigned char csp_str12[30] = "\";\n  var testingCompleted = \"";
static const unsigned char csp_str13[28] = "\";\n  var waitingTooLong = \"";
static const unsigned char csp_str14[43] = "\";\n</script>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str15[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str16[105] = "</title></head>\n<body onload=\"startClock()\"><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str17[8] = "</div>\n";
static const unsigned char csp_str18[2] = "\n";
static const unsigned char csp_str19[7] = "\n\n<h2>";
static const unsigned char csp_str20[3] = " #";
static const unsigned char csp_str21[46] = "</h2>\n\n<table class=\"b0\">\n<tr><td class=\"b0\">";
static const unsigned char csp_str22[22] = ":</td><td class=\"b0\">";
static const unsigned char csp_str23[31] = "</td></tr>\n<tr><td class=\"b0\">";
static const unsigned char csp_str24[4] = "<b>";
static const unsigned char csp_str25[5] = "</b>";
static const unsigned char csp_str26[32] = "</td></tr>\n</table>\n<hr/>\n<pre>";
static const unsigned char csp_str27[15] = "</pre>\n<hr/>\n\n";
static const unsigned char csp_str28[18] = "<div id=\"footer\">";
static const unsigned char csp_str29[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";


#line 2 "unpriv_clar_page.csp"
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

#include "reuse/xalloc.h"

#include <libintl.h>
#define _(x) gettext(x)

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

#line 5 "unpriv_clar_page.csp"
#include "team_extra.h"

void
unpriv_load_html_style(struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra **p_extra,
                       time_t *p_cur_time);
void
unpriv_page_header(FILE *fout,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra,
                   time_t start_time, time_t stop_time);
int csp_view_unpriv_clar_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_unpriv_clar_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_unpriv_clar_page(void)
{
    return &page_iface;
}

int csp_view_unpriv_clar_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "unpriv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra->serve_state;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;

#line 24 "unpriv_clar_page.csp"
const struct section_global_data *global = cs->global;
  int n, clar_id, show_astr_time;
  const unsigned char *s;
  size_t clar_size = 0;
  struct clar_entry_v1 ce;
  time_t start_time, clar_time, stop_time;
  unsigned char *clar_text = 0;
  unsigned char dur_str[64];
  const unsigned char *clar_subj = 0;
  unsigned char title[1024];

  if ((n = ns_cgi_param(phr, "clar_id", &s)) <= 0) {
    fprintf(log_f, "'clar_id' parameter is missing or invalid");
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  }
  if (sscanf(s, "%d%n", &clar_id, &n) != 1 || s[n]) {
    fprintf(log_f, "'clar_id' parameter is missing or invalid");
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  }

  if (cs->clients_suspended) {
    FAIL(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  }
  if (global->disable_clars) {
    FAIL(NEW_SRV_ERR_CLARS_DISABLED);
  }
  if (clar_id < 0 || clar_id >= clar_get_total(cs->clarlog_state)
      || clar_get_record(cs->clarlog_state, clar_id, &ce) < 0
      || ce.id < 0) {
    fprintf(log_f, "'clar_id' parameter is missing or invalid");
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  }

  show_astr_time = global->show_astr_time;
  if (global->is_virtual) show_astr_time = 1;
  start_time = run_get_start_time(cs->runlog_state);
  stop_time = run_get_stop_time(cs->runlog_state);
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  }

  if ((ce.from > 0 && ce.from != phr->user_id)
      || (ce.to > 0 && ce.to != phr->user_id)
      || (start_time <= 0 && ce.hide_flag)) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  if (ce.from != phr->user_id) {
    team_extra_set_clar_status(cs->team_extra_state, phr->user_id, clar_id);
  }

  if (clar_get_text(cs->clarlog_state, clar_id, &clar_text, &clar_size) < 0) {
    FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
  }

  clar_subj = clar_get_subject(cs->clarlog_state, clar_id);

  clar_time = ce.time;
  if (start_time < 0) start_time = 0;
  if (!start_time) clar_time = start_time;
  if (clar_time < start_time) clar_time = start_time;
  duration_str(show_astr_time, clar_time, start_time, dur_str, 0);

  unpriv_load_html_style(phr, cnts, 0, 0);
  l10n_setlocale(phr->locale_id);
  snprintf(title, sizeof(title), "%s %d", _("Clarification"), clar_id);
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
fputs("NEW_SRV_ACTION_JSON_USER_STATE", out_f);
fwrite(csp_str6, 1, 44, out_f);
fputs("NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY", out_f);
fwrite(csp_str7, 1, 18, out_f);
fputs((phr->self_url), out_f);
fwrite(csp_str8, 1, 22, out_f);
fputs((phr->script_name), out_f);
fwrite(csp_str9, 1, 52, out_f);
fwrite(csp_str10, 1, 31, out_f);
fputs(_("STATUS UPDATE FAILED!"), out_f);
fwrite(csp_str11, 1, 37, out_f);
fputs(_("TESTING IN PROGRESS..."), out_f);
fwrite(csp_str12, 1, 29, out_f);
fputs(_("TESTING COMPLETED"), out_f);
fwrite(csp_str13, 1, 27, out_f);
fputs(_("REFRESH PAGE MANUALLY!"), out_f);
fwrite(csp_str14, 1, 42, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str15, 1, 37, out_f);
fputs((title), out_f);
fwrite(csp_str16, 1, 104, out_f);
fputs((title), out_f);
fwrite(csp_str17, 1, 7, out_f);
fwrite(csp_str18, 1, 1, out_f);

#line 94 "unpriv_clar_page.csp"
unpriv_page_header(out_f, phr, cnts, extra, start_time, stop_time);
fwrite(csp_str19, 1, 6, out_f);
fputs(_("Message"), out_f);
fwrite(csp_str20, 1, 2, out_f);
fprintf(out_f, "%d", (int)(clar_id));
fwrite(csp_str21, 1, 45, out_f);
fputs(_("Number"), out_f);
fwrite(csp_str22, 1, 21, out_f);
fprintf(out_f, "%d", (int)(clar_id));
fwrite(csp_str23, 1, 30, out_f);
fputs(_("Time"), out_f);
fwrite(csp_str22, 1, 21, out_f);
fputs((dur_str), out_f);
fwrite(csp_str23, 1, 30, out_f);
fputs(_("Size"), out_f);
fwrite(csp_str22, 1, 21, out_f);
fprintf(out_f, "%zu", (size_t)(ce.size));
fwrite(csp_str23, 1, 30, out_f);
fputs(_("Sender"), out_f);
fwrite(csp_str22, 1, 21, out_f);

#line 103 "unpriv_clar_page.csp"
if (!ce.from) {
fwrite(csp_str24, 1, 3, out_f);
fputs(_("judges"), out_f);
fwrite(csp_str25, 1, 4, out_f);

#line 105 "unpriv_clar_page.csp"
} else {
fputs(html_armor_buf(&ab, (teamdb_get_name(cs->teamdb_state, ce.from))), out_f);

#line 107 "unpriv_clar_page.csp"
}
fwrite(csp_str23, 1, 30, out_f);
fputs(_("To"), out_f);
fwrite(csp_str22, 1, 21, out_f);

#line 110 "unpriv_clar_page.csp"
if (!ce.to && !ce.from) {
fwrite(csp_str24, 1, 3, out_f);
fputs(_("all"), out_f);
fwrite(csp_str25, 1, 4, out_f);

#line 112 "unpriv_clar_page.csp"
} else if (!ce.to) {
fwrite(csp_str24, 1, 3, out_f);
fputs(_("judges"), out_f);
fwrite(csp_str25, 1, 4, out_f);

#line 114 "unpriv_clar_page.csp"
} else {
fputs(html_armor_buf(&ab, (teamdb_get_name(cs->teamdb_state, ce.to))), out_f);

#line 116 "unpriv_clar_page.csp"
}
fwrite(csp_str23, 1, 30, out_f);
fputs(_("Subject"), out_f);
fwrite(csp_str22, 1, 21, out_f);
fputs(html_armor_buf(&ab, (clar_subj)), out_f);
fwrite(csp_str26, 1, 31, out_f);
fputs(html_armor_buf(&ab, (clar_text)), out_f);
fwrite(csp_str27, 1, 14, out_f);
fwrite(csp_str28, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str29, 1, 37, out_f);

#line 126 "unpriv_clar_page.csp"
l10n_setlocale(0);
cleanup:;
  html_armor_free(&ab);
  return 0;
}
