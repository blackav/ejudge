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
static const unsigned char csp_str9[40] = "\n<table class=\"b0\"><tr>\n<td class=\"b0\">";
static const unsigned char csp_str10[22] = "</td>\n<td class=\"b0\">";
static const unsigned char csp_str11[22] = "</td>\n</tr></table>\n\n";
static const unsigned char csp_str12[122] = "\n<table class=\"b1\">\n    <tr>\n        <th class=\"b1\">NN</th>\n        <th class=\"b1\">ContestId</th>\n        <th class=\"b1\">";
static const unsigned char csp_str13[30] = "</th>\n        <th class=\"b1\">";
static const unsigned char csp_str14[64] = "</th>\n        <th class=\"b1\">RunId</th>\n        <th class=\"b1\">";
static const unsigned char csp_str15[66] = "</th>\n        <th class=\"b1\">JudgeId</th>\n        <th class=\"b1\">";
static const unsigned char csp_str16[17] = "</th>\n    </tr>\n";
static const unsigned char csp_str17[34] = "\n    <tr>\n        <td class=\"b1\">";
static const unsigned char csp_str18[30] = "</td>\n        <td class=\"b1\">";
static const unsigned char csp_str19[7] = "</td>\n";
static const unsigned char csp_str20[25] = "\n        <td class=\"b1\">";
static const unsigned char csp_str21[9] = "Problem ";
static const unsigned char csp_str22[6] = "User ";
static const unsigned char csp_str23[2] = "X";
static const unsigned char csp_str24[13] = "&nbsp;&nbsp;";
static const unsigned char csp_str25[3] = "Up";
static const unsigned char csp_str26[5] = "Down";
static const unsigned char csp_str27[17] = "</td>\n    </tr>\n";
static const unsigned char csp_str28[11] = "\n</table>\n";
static const unsigned char csp_str29[41] = "\n\n<table class=\"b0\"><tr>\n<td class=\"b0\">";
static const unsigned char csp_str30[7] = "<hr/>\n";
static const unsigned char csp_str31[18] = "\n</body>\n</html>\n";


#line 2 "priv_testing_queue_page.csp"
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

#line 5 "priv_testing_queue_page.csp"
#include "super_run_packet.h"
int csp_view_priv_testing_queue_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_testing_queue_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_testing_queue_page(void)
{
    return &page_iface;
}

int csp_view_priv_testing_queue_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "priv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra->serve_state;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;

#line 11 "priv_testing_queue_page.csp"
const unsigned char *title = NULL;
  const struct section_global_data *global = cs->global;
  struct TestingQueueArray vec;
  int i, prob_id, user_id;
  const unsigned char *arch;
  unsigned char run_queue_dir[PATH_MAX];
  const unsigned char *queue_dir = NULL;

  memset(&vec, 0, sizeof(vec));

  if (phr->role != USER_ROLE_ADMIN) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if(cnts && cnts->run_managed) {
    if (global->super_run_dir && global->super_run_dir[0]) {
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/var/queue", global->super_run_dir);
    } else {
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/super-run/var/queue", EJUDGE_CONTESTS_HOME_DIR);
    }
    queue_dir = run_queue_dir;
  } else {
    queue_dir = global->run_queue_dir;
  }
  ns_scan_run_queue(queue_dir, cnts->id, &vec);

  l10n_setlocale(phr->locale_id);
  title = _("Testing queue");
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
fwrite(csp_str9, 1, 39, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_MAIN_PAGE, 0), out_f);
fputs(_("Main page"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 21, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_TESTING_QUEUE, 0), out_f);
fputs(_("Refresh"), out_f);
fputs("</a>", out_f);
fwrite(csp_str11, 1, 21, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str12, 1, 121, out_f);
fputs(_("Packet name"), out_f);
fwrite(csp_str13, 1, 29, out_f);
fputs(_("Priority"), out_f);
fwrite(csp_str14, 1, 63, out_f);
fputs(_("Problem"), out_f);
fwrite(csp_str13, 1, 29, out_f);
fputs(_("User"), out_f);
fwrite(csp_str13, 1, 29, out_f);
fputs(_("Architecture"), out_f);
fwrite(csp_str15, 1, 65, out_f);
fputs(_("Create time"), out_f);
fwrite(csp_str13, 1, 29, out_f);
fputs(_("Actions"), out_f);
fwrite(csp_str16, 1, 16, out_f);

#line 59 "priv_testing_queue_page.csp"
for (i = 0; i < vec.u; ++i) {
    const struct super_run_in_global_packet *srgp = vec.v[i].packet->global;
    const struct super_run_in_problem_packet *srpp = vec.v[i].packet->problem;

    arch = srgp->arch;
    if (!arch) arch = "";
fwrite(csp_str17, 1, 33, out_f);
fprintf(out_f, "%d", (int)(i + 1));
fwrite(csp_str18, 1, 29, out_f);
fprintf(out_f, "%d", (int)(srgp->contest_id));
fwrite(csp_str18, 1, 29, out_f);
fputs((vec.v[i].entry_name), out_f);
fwrite(csp_str18, 1, 29, out_f);
fprintf(out_f, "%d", (int)(vec.v[i].priority));
fwrite(csp_str18, 1, 29, out_f);
fprintf(out_f, "%d", (int)(srgp->run_id));
fwrite(csp_str19, 1, 6, out_f);

#line 72 "priv_testing_queue_page.csp"
if (srgp->contest_id == cnts->id) {
fwrite(csp_str20, 1, 24, out_f);

#line 74 "priv_testing_queue_page.csp"
prob_id = srpp->id;
      if (prob_id > 0 && prob_id <= cs->max_prob && cs->probs[prob_id]) {
fputs((cs->probs[prob_id]->short_name), out_f);

#line 77 "priv_testing_queue_page.csp"
} else {
fwrite(csp_str21, 1, 8, out_f);
fprintf(out_f, "%d", (int)(prob_id));

#line 79 "priv_testing_queue_page.csp"
}
fwrite(csp_str19, 1, 6, out_f);

#line 81 "priv_testing_queue_page.csp"
user_id = srgp->user_id;
fwrite(csp_str20, 1, 24, out_f);
fputs(html_armor_buf(&ab, (teamdb_get_name_2(cs->teamdb_state, user_id))), out_f);
fwrite(csp_str19, 1, 6, out_f);

#line 83 "priv_testing_queue_page.csp"
} else {
fwrite(csp_str20, 1, 24, out_f);

#line 85 "priv_testing_queue_page.csp"
if (srpp->short_name && srpp->short_name[0]) {
fputs(html_armor_buf(&ab, (srpp->short_name)), out_f);

#line 87 "priv_testing_queue_page.csp"
} else {
fwrite(csp_str21, 1, 8, out_f);
fprintf(out_f, "%d", (int)(srpp->id));

#line 89 "priv_testing_queue_page.csp"
}
fwrite(csp_str18, 1, 29, out_f);

#line 92 "priv_testing_queue_page.csp"
if (srgp->user_name && srgp->user_name[0]) {
fputs(html_armor_buf(&ab, (srgp->user_name)), out_f);

#line 94 "priv_testing_queue_page.csp"
} else if (srgp->user_login && srgp->user_login[0]) {
fputs(html_armor_buf(&ab, (srgp->user_login)), out_f);

#line 96 "priv_testing_queue_page.csp"
} else {
fwrite(csp_str22, 1, 5, out_f);
fprintf(out_f, "%d", (int)(srgp->user_id));

#line 98 "priv_testing_queue_page.csp"
}
fwrite(csp_str19, 1, 6, out_f);

#line 100 "priv_testing_queue_page.csp"
}
fwrite(csp_str20, 1, 24, out_f);
fputs(html_armor_buf(&ab, (arch)), out_f);
fwrite(csp_str18, 1, 29, out_f);
fprintf(out_f, "%d", (int)(srgp->judge_id));
fwrite(csp_str18, 1, 29, out_f);
fputs(xml_unparse_date((vec.v[i].mtime)), out_f);
fwrite(csp_str18, 1, 29, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_TESTING_DELETE);
fputs(sep, out_f); sep = "&amp;";
fputs("packet=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (vec.v[i].entry_name));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fwrite(csp_str23, 1, 1, out_f);
fputs("</a>", out_f);
fwrite(csp_str24, 1, 12, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_TESTING_UP);
fputs(sep, out_f); sep = "&amp;";
fputs("packet=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (vec.v[i].entry_name));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fwrite(csp_str25, 1, 2, out_f);
fputs("</a>", out_f);
fwrite(csp_str24, 1, 12, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_TESTING_DOWN);
fputs(sep, out_f); sep = "&amp;";
fputs("packet=", out_f);
url_armor_string(hbuf, sizeof(hbuf), (vec.v[i].entry_name));
fputs(hbuf, out_f);
(void) sep;
fputs("\">", out_f);
fwrite(csp_str26, 1, 4, out_f);
fputs("</a>", out_f);
fwrite(csp_str27, 1, 16, out_f);

#line 113 "priv_testing_queue_page.csp"
}
fwrite(csp_str28, 1, 10, out_f);
fputs("</form>", out_f);
fwrite(csp_str29, 1, 40, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_MAIN_PAGE, 0), out_f);
fputs(_("Main page"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 21, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_TESTING_DELETE_ALL, 0), out_f);
fputs(_("Delete all"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 21, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_TESTING_UP_ALL, 0), out_f);
fputs(_("Up all"), out_f);
fputs("</a>", out_f);
fwrite(csp_str10, 1, 21, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_TESTING_DOWN_ALL, 0), out_f);
fputs(_("Down all"), out_f);
fputs("</a>", out_f);
fwrite(csp_str11, 1, 21, out_f);
fwrite(csp_str30, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str31, 1, 17, out_f);

#line 126 "priv_testing_queue_page.csp"
l10n_setlocale(0);
cleanup:
  for (i = 0; i < vec.u; ++i) {
    xfree(vec.v[i].entry_name);
    super_run_in_packet_free(vec.v[i].packet);
  }
  xfree(vec.v); vec.v = 0;
  vec.a = vec.u = 0;
  html_armor_free(&ab);
  return 0;
}
