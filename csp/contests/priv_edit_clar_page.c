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
static const unsigned char csp_str10[4] = "\n  ";
static const unsigned char csp_str11[6] = "\n<h2>";
static const unsigned char csp_str12[2] = " ";
static const unsigned char csp_str13[2] = "]";
static const unsigned char csp_str14[8] = "</h2>\n\n";
static const unsigned char csp_str15[68] = "\n<table class=\"b0\">\n<tr><td class=\"b0\">Clar ID:</td><td class=\"b0\">";
static const unsigned char csp_str16[56] = "</td></tr>\n<tr><td class=\"b0\">Time:</td><td class=\"b0\">";
static const unsigned char csp_str17[2] = ".";
static const unsigned char csp_str18[56] = "</td></tr>\n<tr><td class=\"b0\">Size:</td><td class=\"b0\">";
static const unsigned char csp_str19[13] = "</td></tr>\n\n";
static const unsigned char csp_str20[62] = "\n\n<tr><td class=\"b0\">From (Login or #Id):</td><td class=\"b0\">";
static const unsigned char csp_str21[69] = "</td></tr>\n<tr><td class=\"b0\">To (Login or #Id):</td><td class=\"b0\">";
static const unsigned char csp_str22[68] = "\n\n<tr><td class=\"b0\">Judge from (Login or #Id):</td><td class=\"b0\">";
static const unsigned char csp_str23[57] = "</td></tr>\n<tr><td class=\"b0\">Flags:</td><td class=\"b0\">";
static const unsigned char csp_str24[4] = "New";
static const unsigned char csp_str25[7] = "Viewed";
static const unsigned char csp_str26[9] = "Answered";
static const unsigned char csp_str27[59] = "</td></tr>\n\n<tr><td class=\"b0\">Hidden?</td><td class=\"b0\">";
static const unsigned char csp_str28[62] = "</td></tr>\n<tr><td class=\"b0\">Apellation?</td><td class=\"b0\">";
static const unsigned char csp_str29[54] = "</td></tr>\n<tr><td class=\"b0\">IP:</td><td class=\"b0\">";
static const unsigned char csp_str30[55] = "</td></tr>\n<tr><td class=\"b0\">SSL?</td><td class=\"b0\">";
static const unsigned char csp_str31[58] = "</td></tr>\n<tr><td class=\"b0\">Locale:</td><td class=\"b0\">";
static const unsigned char csp_str32[63] = "</td></tr>\n<tr><td class=\"b0\">In reply to:</td><td class=\"b0\">";
static const unsigned char csp_str33[58] = "</td></tr>\n<tr><td class=\"b0\">Run ID:</td><td class=\"b0\">";
static const unsigned char csp_str34[59] = "</td></tr>\n<tr><td class=\"b0\">Charset:</td><td class=\"b0\">";
static const unsigned char csp_str35[59] = "</td></tr>\n<tr><td class=\"b0\">Subject:</td><td class=\"b0\">";
static const unsigned char csp_str36[22] = "</td></tr>\n</table>\n\n";
static const unsigned char csp_str37[47] = "\n<p><textarea name=\"text\" rows=\"20\" cols=\"60\">";
static const unsigned char csp_str38[207] = "</textarea></p>\n\n<table class=\"b0\">\n<tr>\n    <td class=\"b0\"><input type=\"submit\" name=\"save\" value=\"Save\" /></td>\n    <td class=\"b0\"><input type=\"submit\" name=\"cancel\" value=\"Cancel\" /></td>\n</tr>\n</table>\n";
static const unsigned char csp_str39[7] = "<hr/>\n";
static const unsigned char csp_str40[18] = "\n</body>\n</html>\n";

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
int csp_view_priv_edit_clar_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_edit_clar_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_edit_clar_page(void)
{
    return &page_iface;
}

int csp_view_priv_edit_clar_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
struct clar_entry_v1 clar;
  const unsigned char *from_str = NULL, *to_str = NULL;
  unsigned char from_buf[128], to_buf[128];
  const unsigned char *s;
  unsigned char *msg_txt = NULL;
  size_t msg_len = 0;
  int clar_id = 0;
  unsigned char title[1024];
  int n;

  if (ns_cgi_param(phr, "clar_id", &s) <= 0
      || sscanf(s, "%d%n", &clar_id, &n) != 1 || s[n]
      || clar_id < 0 || clar_id >= clar_get_total(cs->clarlog_state)) {
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  }

  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  if (clar_id < 0 || clar_id >= clar_get_total(cs->clarlog_state)
      || clar_get_record(cs->clarlog_state, clar_id, &clar) < 0
      || clar.id < 0) {
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  }

  l10n_setlocale(phr->locale_id);
  snprintf(title, sizeof(title), "%s %d", _("Editing clar"), clar_id);
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
fwrite(csp_str10, 1, 3, out_f);
fwrite(csp_str11, 1, 5, out_f);
fputs(_("Message"), out_f);
fwrite(csp_str12, 1, 1, out_f);
fprintf(out_f, "%d", (int)(clar_id));
if (opcaps_check(phr->caps, OPCAP_VIEW_CLAR) >= 0) {
fwrite(csp_str4, 1, 2, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_CLAR);
fputs(sep, out_f); sep = "&amp;";
fputs("clar_id=", out_f);
fprintf(out_f, "%d", (int)(clar_id));
(void) sep;
fputs("\">", out_f);
fputs(_("View"), out_f);
fputs("</a>", out_f);
fwrite(csp_str13, 1, 1, out_f);
}
fwrite(csp_str14, 1, 7, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"action\"", out_f);
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(NEW_SRV_ACTION_PRIV_EDIT_CLAR_ACTION));
fputs("\"", out_f);
fputs(" />", out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"clar_id\"", out_f);
if ((clar_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(clar_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str15, 1, 67, out_f);
fprintf(out_f, "%d", (int)(clar_id));
fwrite(csp_str16, 1, 55, out_f);
fputs(xml_unparse_date((clar.time)), out_f);
fwrite(csp_str17, 1, 1, out_f);
fprintf(out_f, "%d", (int)(clar.nsec / 1000));
fwrite(csp_str18, 1, 55, out_f);
fprintf(out_f, "%zu", (size_t)(clar.size));
fwrite(csp_str19, 1, 12, out_f);
if (clar.from <= 0 && clar.to <= 0) {
    from_str = "judges";
    to_str = "all";
  } else if (clar.from <= 0) {
    from_str = "judges";
  } else if (clar.to <= 0) {
    to_str = "judges";
  }
  if (clar.from > 0) {
    if (!(from_str = teamdb_get_login(cs->teamdb_state, clar.from))) {
      snprintf(from_buf, sizeof(from_buf), "#%d", clar.from);
      from_str = from_buf;
    }
  }
  if (clar.to > 0) {
    if (!(to_str = teamdb_get_login(cs->teamdb_state, clar.to))) {
      snprintf(to_buf, sizeof(to_buf), "#%d", clar.to);
      to_str = to_buf;
    }
  }
fwrite(csp_str20, 1, 61, out_f);
fputs("<input type=\"text\" name=\"from\" size=\"40\"", out_f);
if ((from_str)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (from_str)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str21, 1, 68, out_f);
fputs("<input type=\"text\" name=\"to\" size=\"40\"", out_f);
if ((to_str)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (to_str)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str19, 1, 12, out_f);
from_buf[0] = 0; from_str = from_buf;
  if (clar.j_from > 0) {
    if (!(from_str = teamdb_get_login(cs->teamdb_state, clar.j_from))) {
      snprintf(from_buf, sizeof(from_buf), "#%d", clar.j_from);
      from_str = from_buf;
    }
  }
fwrite(csp_str22, 1, 67, out_f);
fputs("<input type=\"text\" name=\"j_from\" size=\"40\"", out_f);
if ((from_str)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (from_str)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str23, 1, 56, out_f);
fputs("<select name=\"flags\"", out_f);
fputs(">", out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<option", out_f);
if (0 == clar.flags) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%u", (unsigned)(0));
fputs("\"", out_f);
fputs(">", out_f);
fwrite(csp_str24, 1, 3, out_f);
fputs("</option>", out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<option", out_f);
if (1 == clar.flags) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(1));
fputs("\"", out_f);
fputs(">", out_f);
fwrite(csp_str25, 1, 6, out_f);
fputs("</option>", out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<option", out_f);
if (2 == clar.flags) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(2));
fputs("\"", out_f);
fputs(">", out_f);
fwrite(csp_str26, 1, 8, out_f);
fputs("</option>", out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("</select>", out_f);
fwrite(csp_str27, 1, 58, out_f);
fputs("<input type=\"checkbox\" name=\"hide_flag\" value=\"1\"", out_f);
fputs(" />", out_f);
fwrite(csp_str28, 1, 61, out_f);
fputs("<input type=\"checkbox\" name=\"appeal_flag\" value=\"1\"", out_f);
fputs(" />", out_f);
fwrite(csp_str29, 1, 53, out_f);
fputs("<input type=\"text\" name=\"ip\" size=\"40\"", out_f);
if ((clar.a.ip)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%s", xml_unparse_ip(clar.a.ip));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str30, 1, 54, out_f);
fputs("<input type=\"checkbox\" name=\"ssl_flag\" value=\"1\"", out_f);
fputs(" />", out_f);
fwrite(csp_str31, 1, 57, out_f);
fputs("<input type=\"text\" name=\"locale_id\" size=\"40\"", out_f);
if ((clar.locale_id) >= 0) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(clar.locale_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str32, 1, 62, out_f);
fputs("<input type=\"text\" name=\"in_reply_to\" size=\"40\"", out_f);
if ((clar.in_reply_to - 1) > 0) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(clar.in_reply_to - 1));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str33, 1, 57, out_f);
fputs("<input type=\"text\" name=\"run_id\" size=\"40\"", out_f);
if ((clar.run_id - 1) > 0) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(clar.run_id - 1));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str34, 1, 58, out_f);
fputs("<input type=\"text\" name=\"charset\" size=\"40\"", out_f);
if ((clar.charset)) {
fputs(" value=\"", out_f);
fputs((clar.charset), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str35, 1, 58, out_f);
fputs("<input type=\"text\" name=\"subject\" size=\"80\"", out_f);
if ((clar.subj)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (clar.subj)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str36, 1, 21, out_f);
clar_get_text(cs->clarlog_state, clar_id, &msg_txt, &msg_len);
fwrite(csp_str37, 1, 46, out_f);
fputs(html_armor_buf(&ab, (msg_txt)), out_f);
fwrite(csp_str38, 1, 206, out_f);
fputs("</form>", out_f);
fwrite(csp_str9, 1, 1, out_f);
fwrite(csp_str39, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str40, 1, 17, out_f);
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  xfree(msg_txt);
  return retval;
}
