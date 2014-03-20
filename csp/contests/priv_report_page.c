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
static const unsigned char csp_str14[3] = "\n\n";
static const unsigned char csp_str15[7] = "<hr/>\n";
static const unsigned char csp_str16[18] = "\n</body>\n</html>\n";


#line 2 "priv_report_page.csp"
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

#line 5 "priv_report_page.csp"
#include "archive_paths.h"
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
int csp_view_priv_report_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_report_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_report_page(void)
{
    return &page_iface;
}

int csp_view_priv_report_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "priv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra->serve_state;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;

#line 23 "priv_report_page.csp"
path_t rep_path;
  char *rep_text = 0, *html_text;
  size_t rep_len = 0, html_len;
  int rep_flag, content_type;
  const unsigned char *start_ptr = 0;
  struct run_entry re;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  int run_id;
  int user_mode = 0;
  unsigned char title[1024];

  if (ns_parse_run_id(out_f, phr, cnts, extra, &run_id, 0) < 0) goto cleanup;

  if (opcaps_check(phr->caps, OPCAP_VIEW_REPORT) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }
  if (phr->action == NEW_SRV_ACTION_VIEW_USER_REPORT) user_mode = 1;

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)
      || run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.status > RUN_MAX_STATUS) {
    ns_error(log_f, NEW_SRV_ERR_REPORT_UNAVAILABLE);
    goto cleanup;
  }
  if (!run_is_report_available(re.status)) {
    ns_error(log_f, NEW_SRV_ERR_REPORT_UNAVAILABLE);
    goto cleanup;
  }
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob
      || !(prob = cs->probs[re.prob_id])) {
    ns_error(log_f, NEW_SRV_ERR_INV_PROB_ID);
    goto cleanup;
  }

  if (user_mode && global->team_enable_rep_view > 0) {
    user_mode = 1;
    if (global->team_show_judge_report > 0) {
      user_mode = 0;
    }
  } else {
    user_mode = 0;
  }

  rep_flag = serve_make_xml_report_read_path(cs, rep_path, sizeof(rep_path), &re);
  if (rep_flag >= 0) {
    if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0)<0){
      ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
      goto cleanup;
    }
    content_type = get_content_type(rep_text, &start_ptr);
  } else {
    if (user_mode) {
      rep_flag = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                        global->team_report_archive_dir, run_id, 0, 1);
    } else {
      rep_flag = serve_make_report_read_path(cs, rep_path, sizeof(rep_path), &re);
    }
    if (rep_flag < 0) {
      ns_error(log_f, NEW_SRV_ERR_REPORT_NONEXISTANT);
      goto cleanup;
    }
    if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0)<0){
      ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
      goto cleanup;
    }
    content_type = get_content_type(rep_text, &start_ptr);
  }

  if (user_mode) {
    snprintf(title, sizeof(title), "%s %d", _("Viewing user report"), run_id);
  } else {
    snprintf(title, sizeof(title), "%s %d", _("Viewing report"), run_id);
  }
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

#line 124 "priv_report_page.csp"
switch (content_type) {
  case CONTENT_TYPE_TEXT:
    html_len = html_armored_memlen(start_ptr, rep_len);
    if (html_len > 2 * 1024 * 1024) {
      html_text = xmalloc(html_len + 16);
      html_armor_text(rep_text, rep_len, html_text);
      html_text[html_len] = 0;
      fprintf(out_f, "<pre>%s</pre>", html_text);
      xfree(html_text);
    } else {
      html_text = alloca(html_len + 16);
      html_armor_text(rep_text, rep_len, html_text);
      html_text[html_len] = 0;
      fprintf(out_f, "<pre>%s</pre>", html_text);
    }
    break;
  case CONTENT_TYPE_HTML:
    fprintf(out_f, "%s", start_ptr);
    break;
  case CONTENT_TYPE_XML:
    if (prob->type == PROB_TYPE_TESTS) {
      if (user_mode) {
        write_xml_team_tests_report(cs, prob, out_f, start_ptr, "b1");
      } else {
        write_xml_tests_report(out_f, 0, start_ptr, phr->session_id, phr->self_url,
                               "", "b1", 0);
      }
    } else {
      if (user_mode) {
        write_xml_team_testing_report(cs, prob, out_f, phr, 0, re.is_marked, start_ptr, "b1");
      } else {
        write_xml_testing_report(out_f, phr, 0, start_ptr, "b1", 0);
      }
    }
    break;
  default:
    abort();
  }
fwrite(csp_str14, 1, 2, out_f);
fwrite(csp_str15, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str16, 1, 17, out_f);

#line 166 "priv_report_page.csp"
l10n_setlocale(0);
cleanup:
  xfree(rep_text);
  html_armor_free(&ab);
  return 0;
}
