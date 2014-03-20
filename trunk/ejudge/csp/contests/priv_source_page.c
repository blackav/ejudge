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
static const unsigned char csp_str13[22] = "</td>\n</tr></table>\n\n";
static const unsigned char csp_str14[7] = "\n\n<h2>";
static const unsigned char csp_str15[2] = " ";
static const unsigned char csp_str16[3] = "]\n";
static const unsigned char csp_str17[45] = "</h2>\n\n<table>\n<tr><td style=\"width: 10em;\">";
static const unsigned char csp_str18[11] = ":</td><td>";
static const unsigned char csp_str19[20] = "</td></tr>\n<tr><td>";
static const unsigned char csp_str20[2] = ":";
static const unsigned char csp_str21[12] = "</td></tr>\n";
static const unsigned char csp_str22[24] = "\n<tr><td>UUID:</td><td>";
static const unsigned char csp_str23[3] = "\n\n";
static const unsigned char csp_str24[10] = "\n<tr><td>";
static const unsigned char csp_str25[10] = "</td><td>";
static const unsigned char csp_str26[13] = "</td></tr>\n\n";
static const unsigned char csp_str27[21] = "</td></tr>\n\n<tr><td>";
static const unsigned char csp_str28[4] = " - ";
static const unsigned char csp_str29[2] = "[";
static const unsigned char csp_str30[2] = "]";
static const unsigned char csp_str31[12] = ":</td><td>#";
static const unsigned char csp_str32[12] = " (implicit)";
static const unsigned char csp_str33[39] = ":</td><td><i>unassigned</i></td></tr>\n";
static const unsigned char csp_str34[25] = ":</td><td>N/A</td></tr>\n";
static const unsigned char csp_str35[11] = "\n\n<tr><td>";
static const unsigned char csp_str36[444] = "</td></tr>\n</table>\n\n<script language=\"javascript\">\nfunction setDivVisibility(oper, value)\n{\n  obj1 = document.getElementById(\"Show\" + oper + \"Div\");\n  obj2 = document.getElementById(\"Hide\" + oper + \"Div\");\n  if (value) {\n    obj1.style.display = \"none\";\n    obj2.style.display = \"\";\n  } else {\n    obj1.style.display = \"\";\n    obj2.style.display = \"none\";\n  }\n}\n</script>\n<div id=\"ShowExtraDiv\">\n<a onclick=\"setDivVisibility(\'Extra\', true)\">[";
static const unsigned char csp_str37[108] = "]</a>\n</div>\n<div style=\"display: none;\" id=\"HideExtraDiv\">\n<a onclick=\"setDivVisibility(\'Extra\', false)\">[";
static const unsigned char csp_str38[24] = "]</a>\n\n<br/>\n\n<table>\n\n";
static const unsigned char csp_str39[32] = "\n\n<tr><td style=\"width: 10em;\">";
static const unsigned char csp_str40[29] = "</td></tr>\n</table>\n</div>\n\n";
static const unsigned char csp_str41[5] = "\n<p>";
static const unsigned char csp_str42[7] = "</p>\n\n";
static const unsigned char csp_str43[6] = "</p>\n";
static const unsigned char csp_str44[3] = ": ";
static const unsigned char csp_str45[36] = ": <input type=\"file\" name=\"file\" />";
static const unsigned char csp_str46[11] = "\n\n<hr />\n\n";
static const unsigned char csp_str47[4] = "<p>";
static const unsigned char csp_str48[25] = "\n<big><font color=\"red\">";
static const unsigned char csp_str49[15] = "</font></big>\n";
static const unsigned char csp_str50[20] = "\n<table class=\"b0\">";
static const unsigned char csp_str51[20] = "</table><br/><hr/>\n";
static const unsigned char csp_str52[6] = "\n<h2>";
static const unsigned char csp_str53[12] = "</h2>\n<pre>";
static const unsigned char csp_str54[8] = "</pre>\n";
static const unsigned char csp_str55[8] = "</h2>\n\n";
static const unsigned char csp_str56[41] = "\n\n<table class=\"b0\"><tr>\n<td class=\"b0\">";
static const unsigned char csp_str57[22] = "</td>\n<td class=\"b0\">";
static const unsigned char csp_str58[49] = "</td>\n</tr></table>\n\n<table class=\"b0\"><tr>\n<td>";
static const unsigned char csp_str59[140] = "</td>\n</tr></table>\n\n<p><textarea id=\"msg_text\" name=\"msg_text\" rows=\"20\" cols=\"60\"></textarea></p>\n\n<table class=\"b0\"><tr>\n<td class=\"b0\">";
static const unsigned char csp_str60[20] = "</td>\n</tr></table>";
static const unsigned char csp_str61[7] = "<hr/>\n";
static const unsigned char csp_str62[18] = "\n</body>\n</html>\n";


#line 2 "priv_source_page.csp"
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

#line 5 "priv_source_page.csp"
#include "ej_uuid.h"
#include "mime_type.h"
#include "charsets.h"
#include "fileutl.h"

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

int
ns_parse_run_id(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int *p_run_id,
        struct run_entry *pe);
int csp_view_priv_source_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_source_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_source_page(void)
{
    return &page_iface;
}

int csp_view_priv_source_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "priv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra->serve_state;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;

#line 25 "priv_source_page.csp"
path_t src_path;
  struct run_entry info;
  char *src_text = 0; //, *html_text;
  //unsigned char *numb_txt;
  size_t src_len; //, html_len, numb_len;
  time_t start_time;
  int variant, src_flags;
  unsigned char filtbuf1[128];
  time_t run_time;
  int run_id2;
  unsigned char bb[1024];
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;
  const unsigned char *ss;
  const struct section_global_data *global = cs->global;
  const unsigned char *run_charset = 0;
  int charset_id = 0;
  int txt_flags = 0;
  path_t txt_path = { 0 };
  char *txt_text = 0;
  size_t txt_size = 0;
  unsigned char title[1024];
  int run_id;

  if (ns_parse_run_id(out_f, phr, cnts, extra, &run_id, 0) < 0) goto cleanup;

  if (opcaps_check(phr->caps, OPCAP_VIEW_SOURCE) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  if (ns_cgi_param(phr, "run_charset", &ss) > 0 && ss && *ss)
    run_charset = ss;

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    return 0;
  }
  run_get_entry(cs->runlog_state, run_id, &info);
  if (info.status > RUN_LAST
      || (info.status > RUN_MAX_STATUS && info.status < RUN_TRANSIENT_FIRST)) {
    ns_error(log_f, NEW_SRV_ERR_SOURCE_UNAVAILABLE);
    return 0;
  }

  src_flags = serve_make_source_read_path(cs, src_path, sizeof(src_path), &info);
  if (src_flags < 0) {
    ns_error(log_f, NEW_SRV_ERR_SOURCE_NONEXISTANT);
    return 0;
  }

  if (info.prob_id > 0 && info.prob_id <= cs->max_prob)
    prob = cs->probs[info.prob_id];
  if (info.lang_id > 0 && info.lang_id <= cs->max_lang)
    lang = cs->langs[info.lang_id];

  run_time = info.time;
  if (run_time < 0) run_time = 0;
  start_time = run_get_start_time(cs->runlog_state);
  if (start_time < 0) start_time = 0;
  if (run_time < start_time) run_time = start_time;


  snprintf(title, sizeof(title), "%s %d", _("Viewing run"), run_id);
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
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str11, 1, 44, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_MAIN_PAGE, 0), out_f);
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
fwrite(csp_str13, 1, 21, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str14, 1, 6, out_f);
fputs(_("Information about run"), out_f);
fwrite(csp_str15, 1, 1, out_f);
fprintf(out_f, "%d", (int)(run_id));

#line 117 "priv_source_page.csp"
if (phr->role == USER_ROLE_ADMIN && opcaps_check(phr->caps, OPCAP_EDIT_RUN) >= 0) {
fwrite(csp_str4, 1, 2, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_PRIV_EDIT_RUN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("run_id=", out_f);
fprintf(out_f, "%d", (int)(run_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Edit"), out_f);
fputs("</a>", out_f);
fwrite(csp_str16, 1, 2, out_f);

#line 119 "priv_source_page.csp"
}
fwrite(csp_str17, 1, 44, out_f);
fputs(_("Run ID"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fprintf(out_f, "%d", (int)(info.run_id));
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Submission time"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs(xml_unparse_date((info.time)), out_f);
fwrite(csp_str20, 1, 1, out_f);
fprintf(out_f, "%d", (int)(info.nsec));
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Contest time"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs(duration_str_2(hbuf, sizeof(hbuf), run_time - start_time, info.nsec), out_f);
fwrite(csp_str21, 1, 11, out_f);

#line 125 "priv_source_page.csp"
#if CONF_HAS_LIBUUID - 0 != 0
fwrite(csp_str22, 1, 23, out_f);
fputs(ej_uuid_unparse((info.run_uuid), ""), out_f);
fwrite(csp_str21, 1, 11, out_f);

#line 127 "priv_source_page.csp"
#endif
fwrite(csp_str23, 1, 2, out_f);

#line 129 "priv_source_page.csp"
snprintf(filtbuf1, sizeof(filtbuf1), "ip == ip(%d)", run_id);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Originator IP"), out_f);
fwrite(csp_str25, 1, 9, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (filtbuf1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fprintf(out_f, "%s", xml_unparse_ip(info.a.ip));
fputs("</a>", out_f);
fwrite(csp_str26, 1, 12, out_f);

#line 135 "priv_source_page.csp"
snprintf(filtbuf1, sizeof(filtbuf1), "uid == %d", info.user_id);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str24, 1, 9, out_f);
fputs(_("User ID"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (filtbuf1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fprintf(out_f, "%d", (int)(info.user_id));
fputs("</a>", out_f);
fwrite(csp_str27, 1, 20, out_f);
fputs(_("User login"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs(html_armor_buf(&ab, (teamdb_get_login(cs->teamdb_state, info.user_id))), out_f);
fwrite(csp_str27, 1, 20, out_f);
fputs(_("User name"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs(html_armor_buf(&ab, (teamdb_get_name(cs->teamdb_state, info.user_id))), out_f);
fwrite(csp_str26, 1, 12, out_f);

#line 145 "priv_source_page.csp"
if (prob) {
fwrite(csp_str23, 1, 2, out_f);

#line 147 "priv_source_page.csp"
snprintf(filtbuf1, sizeof(filtbuf1), "prob == \"%s\"",  prob->short_name);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Problem"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (filtbuf1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fputs((prob->short_name), out_f);
fwrite(csp_str28, 1, 3, out_f);
fputs(html_armor_buf(&ab, (prob->long_name)), out_f);
fputs("</a>", out_f);

#line 152 "priv_source_page.csp"
if (prob->xml_file && prob->xml_file[0]) {
fwrite(csp_str15, 1, 1, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_PRIV_SUBMIT_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("problem=", out_f);
fprintf(out_f, "%d", (int)(prob->id));
(void) sep;
fputs("\">", out_f);
fwrite(csp_str29, 1, 1, out_f);
fputs(_("Statement"), out_f);
fwrite(csp_str30, 1, 1, out_f);
fputs("</a>", out_f);

#line 154 "priv_source_page.csp"
}
fwrite(csp_str21, 1, 11, out_f);

#line 156 "priv_source_page.csp"
} else {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Problem"), out_f);
fwrite(csp_str31, 1, 11, out_f);
fprintf(out_f, "%d", (int)(info.prob_id));
fwrite(csp_str21, 1, 11, out_f);

#line 158 "priv_source_page.csp"
}
fwrite(csp_str23, 1, 2, out_f);

#line 160 "priv_source_page.csp"
if (prob && prob->variant_num > 0) {
    variant = info.variant;
    if (!variant) variant = find_variant(cs, info.user_id, info.prob_id, 0);
    if (variant > 0) {
fwrite(csp_str9, 1, 1, out_f);

#line 165 "priv_source_page.csp"
snprintf(filtbuf1, sizeof(filtbuf1), "prob == \"%s\" && variant == %d", prob->short_name, variant);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Variant"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (filtbuf1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);

#line 170 "priv_source_page.csp"
if (info.variant > 0) {
fprintf(out_f, "%d", (int)((int) info.variant));

#line 172 "priv_source_page.csp"
} else {
fprintf(out_f, "%d", (int)(variant));
fwrite(csp_str32, 1, 11, out_f);

#line 174 "priv_source_page.csp"
}
fputs("</a>", out_f);
fwrite(csp_str21, 1, 11, out_f);

#line 176 "priv_source_page.csp"
} else {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Variant"), out_f);
fwrite(csp_str33, 1, 38, out_f);

#line 178 "priv_source_page.csp"
}
fwrite(csp_str9, 1, 1, out_f);

#line 179 "priv_source_page.csp"
}
fwrite(csp_str23, 1, 2, out_f);

#line 181 "priv_source_page.csp"
if (lang) {
fwrite(csp_str9, 1, 1, out_f);

#line 182 "priv_source_page.csp"
snprintf(filtbuf1, sizeof(filtbuf1), "lang == \"%s\"", lang->short_name);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Language"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (filtbuf1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fputs((lang->short_name), out_f);
fwrite(csp_str28, 1, 3, out_f);
fputs(html_armor_buf(&ab, (lang->long_name)), out_f);
fputs("</a>", out_f);
fwrite(csp_str21, 1, 11, out_f);

#line 187 "priv_source_page.csp"
} else if (!info.lang_id) {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Language"), out_f);
fwrite(csp_str34, 1, 24, out_f);

#line 189 "priv_source_page.csp"
} else {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Language"), out_f);
fwrite(csp_str31, 1, 11, out_f);
fprintf(out_f, "%d", (int)(info.lang_id));
fwrite(csp_str21, 1, 11, out_f);

#line 191 "priv_source_page.csp"
}
fwrite(csp_str35, 1, 10, out_f);
fputs(_("EOLN Type"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs(eoln_type_unparse_html((info.eoln_type)), out_f);
fwrite(csp_str26, 1, 12, out_f);

#line 196 "priv_source_page.csp"
run_status_to_str_short(bb, sizeof(bb), info.status);
  snprintf(filtbuf1, sizeof(filtbuf1), "status == %s", bb);
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Status"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (filtbuf1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fputs(run_status_str((info.status), 0, 0, 0, 0), out_f);
fputs("</a>", out_f);
fwrite(csp_str26, 1, 12, out_f);

#line 201 "priv_source_page.csp"
if (info.passed_mode > 0) {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Tests passed"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.test) >= 0) {
fprintf(out_f, "%d", (int)(info.test));
} else {
fputs("N/A", out_f);
}
fwrite(csp_str21, 1, 11, out_f);

#line 203 "priv_source_page.csp"
}
fwrite(csp_str23, 1, 2, out_f);

#line 205 "priv_source_page.csp"
if (global->score_system == SCORE_KIROV
      || global->score_system == SCORE_OLYMPIAD) {
    if (info.passed_mode <= 0) {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Tests passed"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.test - 1) >= 0) {
fprintf(out_f, "%d", (int)(info.test - 1));
} else {
fputs("N/A", out_f);
}
fwrite(csp_str21, 1, 11, out_f);

#line 210 "priv_source_page.csp"
}
fwrite(csp_str35, 1, 10, out_f);
fputs(_("Score gained"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.score) >= 0) {
fprintf(out_f, "%d", (int)(info.score));
} else {
fputs("N/A", out_f);
}
fwrite(csp_str21, 1, 11, out_f);

#line 213 "priv_source_page.csp"
} else if (global->score_system == SCORE_MOSCOW) {
    if (info.passed_mode <= 0) {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Failed test"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.test) > 0) {
fprintf(out_f, "%d", (int)(info.test));
} else {
fputs("N/A", out_f);
}
fwrite(csp_str21, 1, 11, out_f);

#line 217 "priv_source_page.csp"
}
fwrite(csp_str35, 1, 10, out_f);
fputs(_("Score gained"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.score) >= 0) {
fprintf(out_f, "%d", (int)(info.score));
} else {
fputs("N/A", out_f);
}
fwrite(csp_str21, 1, 11, out_f);

#line 220 "priv_source_page.csp"
} else {
fwrite(csp_str9, 1, 1, out_f);

#line 221 "priv_source_page.csp"
if (info.passed_mode <= 0) {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Failed test"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.test) > 0) {
fprintf(out_f, "%d", (int)(info.test));
} else {
fputs("N/A", out_f);
}
fwrite(csp_str21, 1, 11, out_f);

#line 223 "priv_source_page.csp"
}
  }
fwrite(csp_str35, 1, 10, out_f);
fputs(_("Marked?"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.is_marked)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str36, 1, 443, out_f);
fputs(_("More info"), out_f);
fwrite(csp_str37, 1, 107, out_f);
fputs(_("Hide extended info"), out_f);
fwrite(csp_str38, 1, 23, out_f);

#line 254 "priv_source_page.csp"
if (!info.lang_id) {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Content type"), out_f);
fwrite(csp_str25, 1, 9, out_f);
fputs(mime_type_get_type((info.mime_type)), out_f);
fwrite(csp_str21, 1, 11, out_f);

#line 256 "priv_source_page.csp"
}
fwrite(csp_str39, 1, 31, out_f);
fputs(_("Imported?"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.is_imported)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Hidden?"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.is_hidden)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Saved?"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.is_saved)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Read-only?"), out_f);
fwrite(csp_str18, 1, 10, out_f);
if ((info.is_readonly)) { fputs(_("Yes"), out_f); } else { fputs(_("No"), out_f); }
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Locale ID"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fprintf(out_f, "%d", (int)(info.locale_id));
fwrite(csp_str26, 1, 12, out_f);

#line 264 "priv_source_page.csp"
if (global->score_system != SCORE_ACM) {
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Score adjustment"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fprintf(out_f, "%d", (int)(info.score_adj));
fwrite(csp_str21, 1, 11, out_f);

#line 266 "priv_source_page.csp"
}
fwrite(csp_str23, 1, 2, out_f);

#line 268 "priv_source_page.csp"
snprintf(filtbuf1, sizeof(filtbuf1), "size == size(%d)", run_id);
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Size"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (filtbuf1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fprintf(out_f, "%zu", (size_t)(info.size));
fputs("</a>", out_f);
fwrite(csp_str26, 1, 12, out_f);

#line 271 "priv_source_page.csp"
snprintf(filtbuf1, sizeof(filtbuf1), "hash == hash(%d)", run_id);
fwrite(csp_str24, 1, 9, out_f);
fputs(_("Hash value"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (filtbuf1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fputs(unparse_sha1((info.sha1)), out_f);
fputs("</a>", out_f);
fwrite(csp_str27, 1, 20, out_f);
fputs(_("Pages printed"), out_f);
fwrite(csp_str18, 1, 10, out_f);
fprintf(out_f, "%d", (int)((int) info.pages));
fwrite(csp_str40, 1, 28, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str41, 1, 4, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_PRIV_DOWNLOAD_RUN);
fputs(sep, out_f); sep = "&amp;";
fputs("run_id=", out_f);
fprintf(out_f, "%d", (int)(run_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Download run"), out_f);
fputs("</a>", out_f);
fwrite(csp_str42, 1, 6, out_f);

#line 283 "priv_source_page.csp"
if (phr->role == USER_ROLE_ADMIN && opcaps_check(phr->caps, OPCAP_EDIT_RUN) >= 0 && info.is_readonly <= 0) {
fwrite(csp_str9, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"run_id\"", out_f);
if ((run_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(run_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str41, 1, 4, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CLEAR_RUN, NULL), out_f);
fwrite(csp_str43, 1, 5, out_f);
fputs("</form>", out_f);
fwrite(csp_str9, 1, 1, out_f);

#line 288 "priv_source_page.csp"
}
fwrite(csp_str23, 1, 2, out_f);

#line 290 "priv_source_page.csp"
if (opcaps_check(phr->caps, OPCAP_PRINT_RUN) >= 0) {
fwrite(csp_str9, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"run_id\"", out_f);
if ((run_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(run_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str41, 1, 4, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRINT_RUN, NULL), out_f);
fwrite(csp_str43, 1, 5, out_f);
fputs("</form>", out_f);
fwrite(csp_str9, 1, 1, out_f);

#line 295 "priv_source_page.csp"
}
fwrite(csp_str23, 1, 2, out_f);

#line 298 "priv_source_page.csp"
if (run_id > 0) {
    run_id2 = run_find(cs->runlog_state, run_id - 1, 0, info.user_id,
                       info.prob_id, info.lang_id, NULL, NULL);
  }
fwrite(csp_str23, 1, 2, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"run_id\"", out_f);
if ((run_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(run_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str41, 1, 4, out_f);
fputs(_("Compare this run with run"), out_f);
fwrite(csp_str44, 1, 2, out_f);
fputs("<input type=\"text\" name=\"run_id2\" size=\"10\"", out_f);
if ((run_id2) >= 0) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(run_id2));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str15, 1, 1, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_COMPARE_RUNS, NULL), out_f);
fwrite(csp_str43, 1, 5, out_f);
fputs("</form>", out_f);
fwrite(csp_str23, 1, 2, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"run_id\"", out_f);
if ((run_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(run_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str41, 1, 4, out_f);
fputs(_("Charset"), out_f);
fwrite(csp_str44, 1, 2, out_f);

#line 311 "priv_source_page.csp"
charset_html_select(out_f, "run_charset", run_charset);
fwrite(csp_str15, 1, 1, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_VIEW_SOURCE, NULL), out_f);
fwrite(csp_str43, 1, 5, out_f);
fputs("</form>", out_f);
fwrite(csp_str23, 1, 2, out_f);

#line 314 "priv_source_page.csp"
if (global->enable_report_upload) {
fwrite(csp_str9, 1, 1, out_f);
fputs("<form method=\"post\" enctype=\"multipart/form-data\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"run_id\"", out_f);
if ((run_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(run_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str41, 1, 4, out_f);
fputs(_("Upload judging protocol"), out_f);
fwrite(csp_str45, 1, 35, out_f);

#line 318 "priv_source_page.csp"
if (global->team_enable_rep_view) {
fwrite(csp_str15, 1, 1, out_f);
fputs("<input type=\"checkbox\" name=\"judge_report\" value=\"1\"", out_f);
fputs(" />", out_f);
fputs(_("Judge\'s report"), out_f);
fwrite(csp_str15, 1, 1, out_f);
fputs("<input type=\"checkbox\" name=\"user_report\" value=\"1\"", out_f);
fputs(" />", out_f);
fputs(_("User\'s report"), out_f);

#line 321 "priv_source_page.csp"
}
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_UPLOAD_REPORT, NULL), out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("</form>", out_f);
fwrite(csp_str9, 1, 1, out_f);

#line 323 "priv_source_page.csp"
}
fwrite(csp_str46, 1, 10, out_f);

#line 327 "priv_source_page.csp"
if (prob && prob->type > 0 && info.mime_type > 0) {
    if(info.mime_type >= MIME_TYPE_IMAGE_FIRST
       && info.mime_type <= MIME_TYPE_IMAGE_LAST) {
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str10, 1, 5, out_f);
fwrite(csp_str41, 1, 4, out_f);
fputs("<img src=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_PRIV_DOWNLOAD_RUN);
fputs(sep, out_f); sep = "&amp;";
fputs("run_id=", out_f);
fprintf(out_f, "%d", (int)(run_id));
fputs(sep, out_f); sep = "&amp;";
fputs("no_disp=", out_f);
fprintf(out_f, "%d", (int)(1));
(void) sep;
fputs("\"", out_f);
fputs(" alt=\"", out_f);
fputs(_("Submit image"), out_f);
fputs("\"", out_f);
fputs(" />", out_f);
fwrite(csp_str43, 1, 5, out_f);

#line 336 "priv_source_page.csp"
} else {
fwrite(csp_str41, 1, 4, out_f);
fputs(_("The submission is binary and thus is not shown."), out_f);
fwrite(csp_str43, 1, 5, out_f);

#line 338 "priv_source_page.csp"
}
  } else if (lang && lang->binary) {
fwrite(csp_str47, 1, 3, out_f);
fputs(_("The submission is binary and thus is not shown."), out_f);
fwrite(csp_str43, 1, 5, out_f);

#line 341 "priv_source_page.csp"
} else if (!info.is_imported) {
    if (src_flags < 0 || generic_read_file(&src_text, 0, &src_len, src_flags, 0, src_path, "") < 0) {
fwrite(csp_str48, 1, 24, out_f);
fputs(_("Cannot read source text!"), out_f);
fwrite(csp_str49, 1, 14, out_f);

#line 345 "priv_source_page.csp"
} else {
      if (run_charset && (charset_id = charset_get_id(run_charset)) > 0) {
        unsigned char *newsrc = charset_decode_to_heap(charset_id, src_text);
        xfree(src_text);
        src_text = newsrc;
        src_len = strlen(src_text);
      }
fwrite(csp_str50, 1, 19, out_f);

#line 353 "priv_source_page.csp"
text_table_number_lines(out_f, src_text, src_len, 0, " class=\"b0\"");
fwrite(csp_str51, 1, 19, out_f);

#line 355 "priv_source_page.csp"
xfree(src_text); src_text = 0;
    }
  }
fwrite(csp_str23, 1, 2, out_f);

#line 361 "priv_source_page.csp"
txt_flags = serve_make_report_read_path(cs, txt_path, sizeof(txt_path), &info);
  if (txt_flags >= 0) {
    if (generic_read_file(&txt_text, 0, &txt_size, txt_flags, 0,
                          txt_path, 0) >= 0) {
fwrite(csp_str52, 1, 5, out_f);
fputs(_("Style checker output"), out_f);
fwrite(csp_str53, 1, 11, out_f);
fputs(html_armor_buf(&ab, (txt_text)), out_f);
fwrite(csp_str54, 1, 7, out_f);

#line 369 "priv_source_page.csp"
xfree(txt_text); txt_text = 0; txt_size = 0;
    }
  }
fwrite(csp_str14, 1, 6, out_f);
fputs(_("Send a message about this run"), out_f);
fwrite(csp_str55, 1, 7, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" id=\"run_comment\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"run_id\"", out_f);
if ((run_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(run_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str56, 1, 40, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_IGNORE, NULL), out_f);
fwrite(csp_str57, 1, 21, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_OK, NULL), out_f);
fwrite(csp_str58, 1, 48, out_f);
fputs("<input type=\"button\"", out_f);
fputs(" value=\"", out_f);
fputs(_("Formatting rules violation"), out_f);
fputs("\"", out_f);
fputs(" onclick=\"formatViolation()\"", out_f);
fputs(" />", out_f);
fwrite(csp_str59, 1, 139, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT, NULL), out_f);
fwrite(csp_str57, 1, 21, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_IGNORE, NULL), out_f);
fwrite(csp_str57, 1, 21, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_OK, NULL), out_f);
fwrite(csp_str57, 1, 21, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_SET_RUN_REJECTED, NULL), out_f);
fwrite(csp_str60, 1, 19, out_f);
fputs("</form>", out_f);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str61, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str62, 1, 17, out_f);

#line 398 "priv_source_page.csp"
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return 0;
}
