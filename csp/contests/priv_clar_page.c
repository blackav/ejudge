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
static const unsigned char csp_str9[5] = "<h2>";
static const unsigned char csp_str10[2] = " ";
static const unsigned char csp_str11[2] = "\n";
static const unsigned char csp_str12[4] = "\n  ";
static const unsigned char csp_str13[4] = "\n [";
static const unsigned char csp_str14[3] = "]\n";
static const unsigned char csp_str15[35] = "\n</h2>\n<table border=\"0\">\n<tr><td>";
static const unsigned char csp_str16[11] = ":</td><td>";
static const unsigned char csp_str17[12] = "</td></tr>\n";
static const unsigned char csp_str18[10] = "\n<tr><td>";
static const unsigned char csp_str19[20] = "</td></tr>\n<tr><td>";
static const unsigned char csp_str20[8] = ":</td>\n";
static const unsigned char csp_str21[9] = "\n<td><b>";
static const unsigned char csp_str22[11] = "</b></td>\n";
static const unsigned char csp_str23[7] = "</b> (";
static const unsigned char csp_str24[8] = ")</td>\n";
static const unsigned char csp_str25[6] = "\n    ";
static const unsigned char csp_str26[6] = "\n<td>";
static const unsigned char csp_str27[3] = " (";
static const unsigned char csp_str28[2] = ")";
static const unsigned char csp_str29[7] = "</td>\n";
static const unsigned char csp_str30[16] = "\n</tr>\n<tr><td>";
static const unsigned char csp_str31[8] = "\n</tr>\n";
static const unsigned char csp_str32[27] = "</td></tr>\n</table>\n<hr/>\n";
static const unsigned char csp_str33[25] = "\n<big><font color=\"red\">";
static const unsigned char csp_str34[15] = "</font></big>\n";
static const unsigned char csp_str35[7] = "\n<pre>";
static const unsigned char csp_str36[8] = "</pre>\n";
static const unsigned char csp_str37[8] = "\n<hr/>\n";
static const unsigned char csp_str38[5] = "\n<p>";
static const unsigned char csp_str39[71] = "</p>\n<p><textarea name=\"reply\" rows=\"20\" cols=\"60\"></textarea></p>\n<p>";
static const unsigned char csp_str40[6] = "</p>\n";
static const unsigned char csp_str41[7] = "<hr/>\n";
static const unsigned char csp_str42[18] = "\n</body>\n</html>\n";


#line 2 "priv_clar_page.csp"
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
int csp_view_priv_clar_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_clar_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_clar_page(void)
{
    return &page_iface;
}

int csp_view_priv_clar_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "priv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra->serve_state;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));

#line 9 "priv_clar_page.csp"
struct clar_entry_v1 clar;
  time_t start_time;
  unsigned char *msg_txt = 0;
  size_t msg_len = 0;
  unsigned char b1[1024];
  const unsigned char *clar_subj = 0;
  int clar_id;
  const unsigned char *s = NULL, *sep = NULL;
  int n;

  if (ns_cgi_param(phr, "clar_id", &s) <= 0
      || sscanf(s, "%d%n", &clar_id, &n) != 1 || s[n]
      || clar_id < 0 || clar_id >= clar_get_total(cs->clarlog_state)) {
    ns_html_err_inv_param(out_f, phr, 1, "cannot parse clar_id");
    return -1;
  }

  if (clar_id < 0 || clar_id >= clar_get_total(cs->clarlog_state)
      || clar_get_record(cs->clarlog_state, clar_id, &clar) < 0
      || clar.id < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_CLAR_ID);
    goto done;
  }

  if (opcaps_check(phr->caps, OPCAP_VIEW_CLAR) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }

  start_time = run_get_start_time(cs->runlog_state);
  clar_subj = clar_get_subject(cs->clarlog_state, clar_id);

  l10n_setlocale(phr->locale_id);

  unsigned char title[1024];
  snprintf(title, sizeof(title), "%s %d", _("Viewing clar"), clar_id);
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
fputs(_("Message"), out_f);
fwrite(csp_str10, 1, 1, out_f);
fprintf(out_f, "%d", (int)(clar_id));
fwrite(csp_str11, 1, 1, out_f);

#line 47 "priv_clar_page.csp"
if (phr->role == USER_ROLE_ADMIN && opcaps_check(phr->caps, OPCAP_EDIT_RUN) >= 0) {
fwrite(csp_str11, 1, 1, out_f);
fwrite(csp_str12, 1, 3, out_f);
fwrite(csp_str13, 1, 3, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_PRIV_EDIT_CLAR_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("clar_id=", out_f);
fprintf(out_f, "%d", (int)(clar_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Edit"), out_f);
fputs("</a>", out_f);
fwrite(csp_str14, 1, 2, out_f);

#line 52 "priv_clar_page.csp"
}
fwrite(csp_str15, 1, 34, out_f);
fputs(_("Clar ID"), out_f);
fwrite(csp_str16, 1, 10, out_f);
fprintf(out_f, "%d", (int)(clar_id));
fwrite(csp_str17, 1, 11, out_f);

#line 56 "priv_clar_page.csp"
if (clar.hide_flag) {
fwrite(csp_str18, 1, 9, out_f);
fputs(_("Available only after contest start"), out_f);
fwrite(csp_str16, 1, 10, out_f);

#line 58 "priv_clar_page.csp"
fputs(clar.hide_flag?_("YES"):_("NO"), out_f);
fwrite(csp_str17, 1, 11, out_f);

#line 60 "priv_clar_page.csp"
}
fwrite(csp_str18, 1, 9, out_f);
fputs(_("Flags"), out_f);
fwrite(csp_str16, 1, 10, out_f);
fputs((clar_flags_html(cs->clarlog_state, clar.flags, clar.from, clar.to, 0, 0)), out_f);
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Time"), out_f);
fwrite(csp_str16, 1, 10, out_f);
fputs((duration_str(1, clar.time, 0, 0, 0)), out_f);
fwrite(csp_str17, 1, 11, out_f);

#line 63 "priv_clar_page.csp"
if (!cs->global->is_virtual && start_time > 0) {
fwrite(csp_str18, 1, 9, out_f);
fputs(_("Duration"), out_f);
fwrite(csp_str16, 1, 10, out_f);
fputs((duration_str(0, clar.time, start_time, 0, 0)), out_f);
fwrite(csp_str17, 1, 11, out_f);

#line 65 "priv_clar_page.csp"
}
fwrite(csp_str18, 1, 9, out_f);
fputs(_("IP address"), out_f);
fwrite(csp_str16, 1, 10, out_f);
fprintf(out_f, "%s", xml_unparse_ip(clar.a.ip));
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Size"), out_f);
fwrite(csp_str16, 1, 10, out_f);
fprintf(out_f, "%zu", (size_t)(clar.size));
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Sender"), out_f);
fwrite(csp_str20, 1, 7, out_f);

#line 69 "priv_clar_page.csp"
if (!clar.from) {
    if (!clar.j_from) {
fwrite(csp_str21, 1, 8, out_f);
fputs(_("judges"), out_f);
fwrite(csp_str22, 1, 10, out_f);

#line 72 "priv_clar_page.csp"
} else {
fwrite(csp_str21, 1, 8, out_f);
fputs(_("judges"), out_f);
fwrite(csp_str23, 1, 6, out_f);
fputs(html_armor_buf(&ab, (teamdb_get_name_2(cs->teamdb_state, clar.j_from))), out_f);
fwrite(csp_str24, 1, 7, out_f);

#line 74 "priv_clar_page.csp"
}
  } else {
fwrite(csp_str11, 1, 1, out_f);

#line 76 "priv_clar_page.csp"
snprintf(b1, sizeof(b1), "uid == %d", clar.from);
fwrite(csp_str11, 1, 1, out_f);
fwrite(csp_str25, 1, 5, out_f);
fwrite(csp_str26, 1, 5, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (b1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fputs(html_armor_buf(&ab, (teamdb_get_name_2(cs->teamdb_state, clar.from))), out_f);
fwrite(csp_str27, 1, 2, out_f);
fprintf(out_f, "%d", (int)(clar.from));
fwrite(csp_str28, 1, 1, out_f);
fputs("</a>", out_f);
fwrite(csp_str29, 1, 6, out_f);

#line 81 "priv_clar_page.csp"
}
fwrite(csp_str30, 1, 15, out_f);
fputs(_("To"), out_f);
fwrite(csp_str20, 1, 7, out_f);

#line 84 "priv_clar_page.csp"
if (!clar.to && !clar.from) {
fwrite(csp_str21, 1, 8, out_f);
fputs(_("all"), out_f);
fwrite(csp_str22, 1, 10, out_f);

#line 86 "priv_clar_page.csp"
} else if (!clar.to) {
fwrite(csp_str21, 1, 8, out_f);
fputs(_("judges"), out_f);
fwrite(csp_str22, 1, 10, out_f);

#line 88 "priv_clar_page.csp"
} else {
fwrite(csp_str11, 1, 1, out_f);

#line 89 "priv_clar_page.csp"
snprintf(b1, sizeof(b1), "uid == %d", clar.to);
fwrite(csp_str11, 1, 1, out_f);
fwrite(csp_str25, 1, 5, out_f);
fwrite(csp_str26, 1, 5, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs(sep, out_f); sep = "&amp;";
fputs("filter_expr=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (b1));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fputs(html_armor_buf(&ab, (teamdb_get_name_2(cs->teamdb_state, clar.to))), out_f);
fwrite(csp_str27, 1, 2, out_f);
fprintf(out_f, "%d", (int)(clar.to));
fwrite(csp_str28, 1, 1, out_f);
fputs("</a>", out_f);
fwrite(csp_str29, 1, 6, out_f);

#line 94 "priv_clar_page.csp"
}
fwrite(csp_str31, 1, 7, out_f);

#line 96 "priv_clar_page.csp"
if (clar.in_reply_to > 0) {
fwrite(csp_str11, 1, 1, out_f);
fwrite(csp_str12, 1, 3, out_f);
fwrite(csp_str18, 1, 9, out_f);
fputs(_("In reply to"), out_f);
fwrite(csp_str16, 1, 10, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_CLAR);
fputs(sep, out_f); sep = "&amp;";
fputs("clar_id=", out_f);
fprintf(out_f, "%d", (int)(clar.in_reply_to - 1));
(void) sep;
fputs("\">", out_f);
fprintf(out_f, "%d", (int)(clar.in_reply_to - 1));
fputs("</a>", out_f);
fwrite(csp_str17, 1, 11, out_f);

#line 101 "priv_clar_page.csp"
}
fwrite(csp_str18, 1, 9, out_f);
fputs(_("Locale code"), out_f);
fwrite(csp_str16, 1, 10, out_f);
fprintf(out_f, "%d", (int)(clar.locale_id));
fwrite(csp_str19, 1, 19, out_f);
fputs(_("Subject"), out_f);
fwrite(csp_str16, 1, 10, out_f);
fputs(html_armor_buf(&ab, (clar_subj)), out_f);
fwrite(csp_str32, 1, 26, out_f);

#line 106 "priv_clar_page.csp"
if (clar_get_text(cs->clarlog_state, clar_id, &msg_txt, &msg_len) < 0) {
fwrite(csp_str33, 1, 24, out_f);
fputs(_("Cannot read message text!"), out_f);
fwrite(csp_str34, 1, 14, out_f);

#line 108 "priv_clar_page.csp"
} else {
fwrite(csp_str35, 1, 6, out_f);
fputs(html_armor_buf(&ab, (msg_txt)), out_f);
fwrite(csp_str36, 1, 7, out_f);

#line 110 "priv_clar_page.csp"
}
fwrite(csp_str11, 1, 1, out_f);

#line 111 "priv_clar_page.csp"
if (phr->role >= USER_ROLE_JUDGE && clar.from
      && opcaps_check(phr->caps, OPCAP_REPLY_MESSAGE) >= 0) {
fwrite(csp_str37, 1, 7, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str11, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"in_reply_to\"", out_f);
if ((clar_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(clar_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str38, 1, 4, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CLAR_REPLY_READ_PROBLEM, NULL), out_f);
fwrite(csp_str11, 1, 1, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CLAR_REPLY_NO_COMMENTS, NULL), out_f);
fwrite(csp_str11, 1, 1, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CLAR_REPLY_YES, NULL), out_f);
fwrite(csp_str11, 1, 1, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CLAR_REPLY_NO, NULL), out_f);
fwrite(csp_str39, 1, 70, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CLAR_REPLY, NULL), out_f);
fwrite(csp_str11, 1, 1, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_CLAR_REPLY_ALL, NULL), out_f);
fwrite(csp_str40, 1, 5, out_f);
fputs("</form>", out_f);
fwrite(csp_str11, 1, 1, out_f);

#line 124 "priv_clar_page.csp"
}
fwrite(csp_str41, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str42, 1, 17, out_f);

#line 127 "priv_clar_page.csp"
l10n_setlocale(0);


 done:;
  html_armor_free(&ab);
  xfree(msg_txt);
  return 0;
}
