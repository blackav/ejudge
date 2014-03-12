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
static const unsigned char csp_str10[84] = "\n<table class=\"b1\">\n    <tr>\n        <th class=\"b1\">Id</th>\n        <th class=\"b1\">";
static const unsigned char csp_str11[30] = "</th>\n        <th class=\"b1\">";
static const unsigned char csp_str12[17] = "</th>\n    </tr>\n";
static const unsigned char csp_str13[34] = "\n    <tr>\n        <td class=\"b1\">";
static const unsigned char csp_str14[30] = "</td>\n        <td class=\"b1\">";
static const unsigned char csp_str15[69] = "</td>\n        <td class=\"b1\"><input type=\"text\" size=\"4\" name=\"prio_";
static const unsigned char csp_str16[10] = "\" value=\"";
static const unsigned char csp_str17[34] = "\" /></td>\n        <td class=\"b1\">";
static const unsigned char csp_str18[17] = "</td>\n    </tr>\n";
static const unsigned char csp_str19[54] = "\n</table>\n\n<table class=\"b0\"><tr>\n    <td class=\"b0\">";
static const unsigned char csp_str20[26] = "</td>\n    <td class=\"b0\">";
static const unsigned char csp_str21[21] = "</td>\n</tr></table>\n";
static const unsigned char csp_str22[13] = "\n\n<br/>\n\n<p>";
static const unsigned char csp_str23[7] = "</p>\n\n";
static const unsigned char csp_str24[7] = "<hr/>\n";
static const unsigned char csp_str25[18] = "\n</body>\n</html>\n";


#line 2 "priv_priorities_page.csp"
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

#line 5 "priv_priorities_page.csp"
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

static int
fix_prio(int val)
{
  if (val < -16) val = -16;
  if (val > 15) val = 15;
  return val;
}
int csp_view_priv_priorities_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_priorities_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_priorities_page(void)
{
    return &page_iface;
}

int csp_view_priv_priorities_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 2 "priv_stdvars.csp"
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra->serve_state;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));

#line 19 "priv_priorities_page.csp"
const struct section_global_data *global = cs->global;
    const struct section_problem_data *prob;
    int glob_prio, prob_prio, static_prio, local_prio, total_prio;
    int prob_id;
    const unsigned char *title = NULL;

    glob_prio = fix_prio(global->priority_adjustment);

    if (phr->role != USER_ROLE_ADMIN) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

    l10n_setlocale(phr->locale_id);
    title = _("Judging priorities");
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
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str10, 1, 83, out_f);
fputs(_("Short name"), out_f);
fwrite(csp_str11, 1, 29, out_f);
fputs(_("Long name"), out_f);
fwrite(csp_str11, 1, 29, out_f);
fputs(_("Contest priority"), out_f);
fwrite(csp_str11, 1, 29, out_f);
fputs(_("Problem priority"), out_f);
fwrite(csp_str11, 1, 29, out_f);
fputs(_("Static priority"), out_f);
fwrite(csp_str11, 1, 29, out_f);
fputs(_("Priority adjustment"), out_f);
fwrite(csp_str11, 1, 29, out_f);
fputs(_("Total priority"), out_f);
fwrite(csp_str12, 1, 16, out_f);

#line 46 "priv_priorities_page.csp"
for (prob_id = 1;
       prob_id <= cs->max_prob && prob_id < EJ_SERVE_STATE_TOTAL_PROBS;
       ++prob_id) {
    if (!(prob = cs->probs[prob_id])) continue;
    prob_prio = fix_prio(prob->priority_adjustment);
    static_prio = fix_prio(glob_prio + prob_prio);
    local_prio = fix_prio(cs->prob_prio[prob_id]);
    total_prio = fix_prio(static_prio + local_prio);
fwrite(csp_str13, 1, 33, out_f);
fprintf(out_f, "%d", (int)(prob_id));
fwrite(csp_str14, 1, 29, out_f);
fputs(html_armor_buf(&ab, (prob->short_name)), out_f);
fwrite(csp_str14, 1, 29, out_f);
fputs(html_armor_buf(&ab, (prob->long_name)), out_f);
fwrite(csp_str14, 1, 29, out_f);
fprintf(out_f, "%d", (int)(glob_prio));
fwrite(csp_str14, 1, 29, out_f);
fprintf(out_f, "%d", (int)(prob_prio));
fwrite(csp_str14, 1, 29, out_f);
fprintf(out_f, "%d", (int)(static_prio));
fwrite(csp_str15, 1, 68, out_f);
fprintf(out_f, "%d", (int)(prob_id));
fwrite(csp_str16, 1, 9, out_f);
fprintf(out_f, "%d", (int)(local_prio));
fwrite(csp_str17, 1, 33, out_f);
fprintf(out_f, "%d", (int)(total_prio));
fwrite(csp_str18, 1, 16, out_f);

#line 65 "priv_priorities_page.csp"
}
fwrite(csp_str19, 1, 53, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_MAIN_PAGE, _("Main page")), out_f);
fwrite(csp_str20, 1, 25, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_SET_PRIORITIES, NULL), out_f);
fwrite(csp_str21, 1, 20, out_f);
fputs("</form>", out_f);
fwrite(csp_str22, 1, 12, out_f);
fputs(_("Priority value must be in range [-16, 15]. The less the priority value, the more the judging priority."), out_f);
fwrite(csp_str23, 1, 6, out_f);
fwrite(csp_str24, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str25, 1, 17, out_f);

#line 80 "priv_priorities_page.csp"
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return 0;
}
