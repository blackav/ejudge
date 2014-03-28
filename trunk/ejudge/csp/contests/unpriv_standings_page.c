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
static const unsigned char csp_str24[52] = "<div class=\"user_actions\">\n<table class=\"menu\"><tr>";
static const unsigned char csp_str25[52] = "<td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str26[12] = "</div></td>";
static const unsigned char csp_str27[17] = "]</a></div></td>";
static const unsigned char csp_str28[69] = "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>";
static const unsigned char csp_str29[171] = "</tr></table>\n</div>\n<div class=\"white_empty_block\">&nbsp;</div>\n<div class=\"contest_actions\">\n<table class=\"menu\"><tr><td class=\"menu\"><div class=\"contest_actions_item\">";
static const unsigned char csp_str30[39] = "<a:a class=\"menu\" ac=\"view-startstop\">";
static const unsigned char csp_str31[23] = "<a class=\"menu\" href=\"";
static const unsigned char csp_str32[19] = "\" target=\"_blank\">";
static const unsigned char csp_str33[5] = "</a>";
static const unsigned char csp_str34[53] = "</tr></table>\n</div>\n</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str35[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str36[12] = "<div class=";
static const unsigned char csp_str37[20] = "\"server_status_off\"";
static const unsigned char csp_str38[22] = "\"server_status_alarm\"";
static const unsigned char csp_str39[19] = "\"server_status_on\"";
static const unsigned char csp_str40[41] = " id=\"statusLine\">\n<div id=\"currentTime\">";
static const unsigned char csp_str41[7] = "</div>";
static const unsigned char csp_str42[7] = " / <b>";
static const unsigned char csp_str43[16] = "EXAM IS RUNNING";
static const unsigned char csp_str44[8] = "RUNNING";
static const unsigned char csp_str45[12] = "NOT STARTED";
static const unsigned char csp_str46[5] = "</b>";
static const unsigned char csp_str47[6] = "/ <b>";
static const unsigned char csp_str48[25] = " / <b><font color=\"red\">";
static const unsigned char csp_str49[12] = "</font></b>";
static const unsigned char csp_str50[4] = " / ";
static const unsigned char csp_str51[3] = ": ";
static const unsigned char csp_str52[27] = ": <div id=\"remainingTime\">";
static const unsigned char csp_str53[43] = "<div id=\"reloadButton\" style=\"visibility: ";
static const unsigned char csp_str54[8] = "visible";
static const unsigned char csp_str55[7] = "hidden";
static const unsigned char csp_str56[49] = "\">/ <a class=\"menu\" onclick=\"reloadPage()\"><b>[ ";
static const unsigned char csp_str57[80] = " ]</b></a></div><div id=\"statusString\" style=\"visibility: hidden\"></div></div>\n";
static const unsigned char csp_str58[6] = "\n<h2>";
static const unsigned char csp_str59[8] = "</h2>\n\n";
static const unsigned char csp_str60[4] = "<p>";
static const unsigned char csp_str61[5] = "</p>";
static const unsigned char csp_str62[18] = "<div id=\"footer\">";
static const unsigned char csp_str63[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";


#line 2 "unpriv_standings_page.csp"
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
  const struct section_global_data *global __attribute__((unused)) = cs?cs->global:NULL;
  time_t start_time __attribute__((unused)) = 0, stop_time __attribute__((unused)) = 0;

#line 10 "unpriv_standings_page.csp"
time_t cur_time, fog_stop_time = 0;
  unsigned char dur_buf[128];
  unsigned char title[1024];

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }
  run_get_times(cs->runlog_state, 0, &sched_time, &duration, 0, 0);
  if (duration > 0 && start_time > 0 && global->board_fog_time > 0)
    fog_start_time = start_time + duration - global->board_fog_time;
  if (fog_start_time < 0) fog_start_time = 0;
  if (fog_start_time > 0 && stop_time > 0) {
    if (global->board_unfog_time > 0)
      fog_stop_time = stop_time + global->board_unfog_time;
    else
      fog_stop_time = stop_time;
  }
  /* FIXME: if a virtual contest is over, display the final
   * standings at the current time! */

  l10n_setlocale(phr->locale_id);
  if (start_time <= 0) {
    snprintf(title, sizeof(title), _("Standings [not started]"));
  } else {
    cur_time = cs->current_time;
    if (cur_time < start_time) cur_time = start_time;
    if (duration <= 0) {
      if (stop_time > 0 && cur_time >= stop_time)
        snprintf(title, sizeof(title), _("Standings [over]"));
      else if (global->stand_ignore_after > 0 && cur_time >= global->stand_ignore_after) {
        cur_time = global->stand_ignore_after;
        snprintf(title, sizeof(title), _("Standings [%s, frozen]"), xml_unparse_date(cur_time));
      } else
        snprintf(title, sizeof(title), "%s [%s]", _("Standings"), xml_unparse_date(cur_time));
    } else {
      if (stop_time > 0 && cur_time >= stop_time) {
        if (fog_stop_time > 0 && cur_time < fog_stop_time) {
          cur_time = fog_start_time;
          snprintf(title, sizeof(title), _("Standings [over, frozen]"));
        } else
          snprintf(title, sizeof(title), _("Standings [over]"));
      } else {
        if (fog_start_time > 0 && cur_time >= fog_start_time) {
          cur_time = fog_start_time;
          snprintf(title, sizeof(title), _("Standings [%s, frozen]"),
                   duration_str(global->show_astr_time, cur_time, start_time,
                                dur_buf, sizeof(dur_buf)));
        } else
          snprintf(title, sizeof(title), "%s [%s]", _("Standings"),
                   duration_str(global->show_astr_time, cur_time, start_time,
                                dur_buf, sizeof(dur_buf)));
      }
    }
  }
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
fwrite(csp_str24, 1, 51, out_f);

#line 3 "unpriv_menu.csp"
shown_items = 0;
  if (cnts && cs && cnts->exam_mode <= 0) {
fwrite(csp_str25, 1, 51, out_f);

#line 6 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_SETTINGS) {
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_SETTINGS);
fputs("\">", out_f);

#line 8 "unpriv_menu.csp"
}
fputs(_("Settings"), out_f);

#line 10 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_SETTINGS) {
fputs("</a>", out_f);

#line 12 "unpriv_menu.csp"
}
fwrite(csp_str26, 1, 11, out_f);

#line 14 "unpriv_menu.csp"
shown_items++;

    // reg data edit
    if (cnts->allow_reg_data_edit > 0
        && contests_check_register_ip_2(cnts, &phr->ip, phr->ssl_flag) > 0
        && (cnts->reg_deadline <= 0 || cs->current_time < cnts->reg_deadline)) {
      ns_get_register_url(hbuf, sizeof(hbuf), cnts, phr);
      fprintf(out_f, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?SID=%016llx\">%s</a></div></td>",
              hbuf, phr->session_id, _("Registration data"));
      shown_items++;
    }

    // logout
fwrite(csp_str25, 1, 51, out_f);
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_LOGOUT);
fputs("\">", out_f);

#line 28 "unpriv_menu.csp"
if (cnts->exam_mode) {
fputs(_("Finish session"), out_f);

#line 30 "unpriv_menu.csp"
} else {
fputs(_("Logout"), out_f);

#line 32 "unpriv_menu.csp"
}
fwrite(csp_str18, 1, 2, out_f);
fputs((phr->login), out_f);
fwrite(csp_str27, 1, 16, out_f);

#line 34 "unpriv_menu.csp"
shown_items++;
  }

  if (!shown_items) {
fwrite(csp_str28, 1, 68, out_f);

#line 39 "unpriv_menu.csp"
}
fwrite(csp_str29, 1, 170, out_f);

#line 45 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_MAIN_PAGE) {
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);

#line 47 "unpriv_menu.csp"
}

#line 49 "unpriv_menu.csp"
if (cnts && cnts->exam_mode) {
fputs(_("Instructions"), out_f);

#line 51 "unpriv_menu.csp"
} else {
fputs(_("Info"), out_f);

#line 53 "unpriv_menu.csp"
}

#line 55 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_MAIN_PAGE) {
fputs("</a>", out_f);

#line 57 "unpriv_menu.csp"
}
fwrite(csp_str26, 1, 11, out_f);

#line 59 "unpriv_menu.csp"
if (global && global->is_virtual > 0 && ((start_time <= 0 && global->disable_virtual_start <= 0) || stop_time <= 0)) {
fwrite(csp_str25, 1, 51, out_f);

#line 61 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_STARTSTOP) {
fwrite(csp_str30, 1, 38, out_f);

#line 63 "unpriv_menu.csp"
}

#line 65 "unpriv_menu.csp"
if (start_time <= 0) {
      if (cnts->exam_mode) {
fputs(_("Start exam"), out_f);

#line 68 "unpriv_menu.csp"
} else {
fputs(_("Start virtual contest"), out_f);

#line 70 "unpriv_menu.csp"
}
    } else if (stop_time <= 0) {
      if (cnts->exam_mode) {
fputs(_("Stop exam"), out_f);

#line 74 "unpriv_menu.csp"
} else {
fputs(_("Stop virtual contest"), out_f);

#line 76 "unpriv_menu.csp"
}
    }

#line 79 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_STARTSTOP) {
fputs("</a>", out_f);

#line 81 "unpriv_menu.csp"
}
fwrite(csp_str26, 1, 11, out_f);

#line 83 "unpriv_menu.csp"
}

#line 85 "unpriv_menu.csp"
if (cnts && start_time > 0 && (cnts->exam_mode <= 0 || stop_time > 0)) {
fwrite(csp_str25, 1, 51, out_f);

#line 87 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY) {
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY);
fputs("\">", out_f);

#line 89 "unpriv_menu.csp"
}
fputs(_("Summary"), out_f);

#line 91 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY) {
fputs("</a>", out_f);

#line 93 "unpriv_menu.csp"
}
fwrite(csp_str26, 1, 11, out_f);

#line 95 "unpriv_menu.csp"
}

#line 97 "unpriv_menu.csp"
if (global && start_time > 0
      && (stop_time <= 0 || cnts->problems_url)
      && (global->problem_navigation <= 0 || cnts->problems_url)) {
fwrite(csp_str25, 1, 51, out_f);

#line 101 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS) {
      if (cnts->problems_url) {
fwrite(csp_str31, 1, 22, out_f);
fputs((cnts->problems_url), out_f);
fwrite(csp_str32, 1, 18, out_f);
fputs(_("Statements"), out_f);
fwrite(csp_str33, 1, 4, out_f);

#line 104 "unpriv_menu.csp"
} else {
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS);
fputs("\">", out_f);
fputs(_("Statements"), out_f);
fputs("</a>", out_f);

#line 106 "unpriv_menu.csp"
}
    } else {
fputs(_("Statements"), out_f);

#line 109 "unpriv_menu.csp"
}
fwrite(csp_str26, 1, 11, out_f);

#line 111 "unpriv_menu.csp"
}

#line 113 "unpriv_menu.csp"
if (global && start_time > 0 && stop_time <= 0 && global->problem_navigation <= 0) {
fwrite(csp_str25, 1, 51, out_f);

#line 115 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT) {
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT);
fputs("\">", out_f);

#line 117 "unpriv_menu.csp"
}
fputs(_("Submit"), out_f);

#line 119 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT) {
fputs("</a>", out_f);

#line 121 "unpriv_menu.csp"
}
fwrite(csp_str26, 1, 11, out_f);

#line 123 "unpriv_menu.csp"
}

#line 125 "unpriv_menu.csp"
if (cnts && start_time > 0 && (cnts->exam_mode <= 0 || stop_time > 0)) {
fwrite(csp_str25, 1, 51, out_f);

#line 127 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_SUBMISSIONS) {
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_SUBMISSIONS);
fputs("\">", out_f);

#line 129 "unpriv_menu.csp"
}
fputs(_("Submissions"), out_f);

#line 131 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_SUBMISSIONS) {
fputs("</a>", out_f);

#line 133 "unpriv_menu.csp"
}
fwrite(csp_str26, 1, 11, out_f);

#line 135 "unpriv_menu.csp"
}

#line 137 "unpriv_menu.csp"
if (global && start_time > 0 && global->disable_user_standings <= 0) {
fwrite(csp_str25, 1, 51, out_f);

#line 139 "unpriv_menu.csp"
if (phr->action == NEW_SRV_ACTION_STANDINGS) {

#line 141 "unpriv_menu.csp"
if (cnts->personal) {
fputs(_("User standings"), out_f);

#line 143 "unpriv_menu.csp"
} else {
fputs(_("Standings"), out_f);

#line 145 "unpriv_menu.csp"
}
    } else {
      if (cnts->standings_url) {
        memset(&tdb, 0, sizeof(tdb));
        teamdb_export_team(cs->teamdb_state, phr->user_id, &tdb);
        memset(&fe, 0, sizeof(fe));
        fe.locale_id = phr->locale_id;
        fe.sid = phr->session_id;
        sformat_message(hbuf, sizeof(hbuf), 0,
                        cnts->standings_url, global, 0, 0, 0, &tdb,
                        tdb.user, cnts, &fe);
fwrite(csp_str31, 1, 22, out_f);
fputs((hbuf), out_f);
fwrite(csp_str32, 1, 18, out_f);

#line 157 "unpriv_menu.csp"
if (cnts->personal) {
fputs(_("User standings"), out_f);

#line 159 "unpriv_menu.csp"
} else {
fputs(_("Standings"), out_f);

#line 161 "unpriv_menu.csp"
}
fwrite(csp_str33, 1, 4, out_f);

#line 163 "unpriv_menu.csp"
} else {
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_STANDINGS);
fputs("\">", out_f);

#line 165 "unpriv_menu.csp"
if (cnts->personal) {
fputs(_("User standings"), out_f);

#line 167 "unpriv_menu.csp"
} else {
fputs(_("Standings"), out_f);

#line 169 "unpriv_menu.csp"
}
fputs("</a>", out_f);

#line 171 "unpriv_menu.csp"
}
    }
fwrite(csp_str26, 1, 11, out_f);

#line 174 "unpriv_menu.csp"
}

#line 176 "unpriv_menu.csp"
if (global && global->disable_team_clars <= 0 && global->disable_clars <= 0 && start_time > 0
      && (stop_time <= 0 || (global->appeal_deadline > 0 && cs->current_time < global->appeal_deadline))) {
fwrite(csp_str25, 1, 51, out_f);

#line 179 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_CLAR_SUBMIT) {
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_CLAR_SUBMIT);
fputs("\">", out_f);

#line 181 "unpriv_menu.csp"
}
fputs(_("Submit clar"), out_f);

#line 183 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_CLAR_SUBMIT) {
fputs("</a>", out_f);

#line 185 "unpriv_menu.csp"
}
fwrite(csp_str26, 1, 11, out_f);

#line 187 "unpriv_menu.csp"
}

#line 189 "unpriv_menu.csp"
if (global && global->disable_clars <= 0) {
fwrite(csp_str25, 1, 51, out_f);

#line 191 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_CLARS) {
fputs("<a class=\"menu\" href=\"", out_f);
ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_CLARS);
fputs("\">", out_f);

#line 193 "unpriv_menu.csp"
}
fputs(_("Clars"), out_f);

#line 195 "unpriv_menu.csp"
if (phr->action != NEW_SRV_ACTION_VIEW_CLARS) {
fputs("</a>", out_f);

#line 197 "unpriv_menu.csp"
}
fwrite(csp_str26, 1, 11, out_f);

#line 199 "unpriv_menu.csp"
}
fwrite(csp_str34, 1, 52, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str35, 1, 44, out_f);

#line 2 "unpriv_status.csp"
run_get_times(cs->runlog_state, 0, &sched_time, &duration, 0, 0);
  if (duration > 0 && start_time && !stop_time && global->board_fog_time > 0)
    fog_start_time = start_time + duration - global->board_fog_time;
  if (fog_start_time < 0) fog_start_time = 0;
  if (!cs->global->disable_clars || !cs->global->disable_team_clars)
    unread_clars = serve_count_unread_clars(cs, phr->user_id, start_time);
fwrite(csp_str36, 1, 11, out_f);

#line 9 "unpriv_status.csp"
if (cs->clients_suspended) {
fwrite(csp_str37, 1, 19, out_f);

#line 11 "unpriv_status.csp"
} else if (unread_clars > 0) {
fwrite(csp_str38, 1, 21, out_f);

#line 13 "unpriv_status.csp"
} else {
fwrite(csp_str39, 1, 18, out_f);

#line 15 "unpriv_status.csp"
}
fwrite(csp_str40, 1, 40, out_f);
{
  struct tm *ptm = localtime(&(cs->current_time));
  fprintf(out_f, "%02d:%02d:%02d", ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}
fwrite(csp_str41, 1, 6, out_f);

#line 18 "unpriv_status.csp"
if (unread_clars > 0) {
    fprintf(out_f, _(" / <b>%d unread message(s)</b>"),
            unread_clars);
  }
fwrite(csp_str42, 1, 6, out_f);

#line 23 "unpriv_status.csp"
if (stop_time > 0) {
    if (duration > 0 && global->board_fog_time > 0
        && global->board_unfog_time > 0
        && cs->current_time < stop_time + global->board_unfog_time
        && !cs->standings_updated) {
fputs(_("OVER (frozen)"), out_f);

#line 29 "unpriv_status.csp"
} else {
fputs(_("OVER"), out_f);

#line 31 "unpriv_status.csp"
}
  } else if (start_time > 0) {
    if (fog_start_time > 0 && cs->current_time >= fog_start_time) {
      if (cnts->exam_mode) {
fputs(_("EXAM IS RUNNING (frozen)"), out_f);

#line 36 "unpriv_status.csp"
} else {
fputs(_("RUNNING (frozen)"), out_f);

#line 38 "unpriv_status.csp"
}
    } else {
      if (cnts->exam_mode) {
fwrite(csp_str43, 1, 15, out_f);

#line 42 "unpriv_status.csp"
} else {
fwrite(csp_str44, 1, 7, out_f);

#line 44 "unpriv_status.csp"
}
    }
  } else {
fwrite(csp_str45, 1, 11, out_f);

#line 48 "unpriv_status.csp"
}
fwrite(csp_str46, 1, 4, out_f);

#line 50 "unpriv_status.csp"
if (start_time > 0) {
    if (global->score_system == SCORE_OLYMPIAD && !global->is_virtual) {
fwrite(csp_str47, 1, 5, out_f);

#line 53 "unpriv_status.csp"
if (cs->accepting_mode) {
fputs(_("accepting"), out_f);

#line 55 "unpriv_status.csp"
} else if (!cs->testing_finished) {
fputs(_("judging"), out_f);

#line 57 "unpriv_status.csp"
} else {
fputs(_("judged"), out_f);

#line 59 "unpriv_status.csp"
}
fwrite(csp_str46, 1, 4, out_f);

#line 61 "unpriv_status.csp"
}
  }

#line 64 "unpriv_status.csp"
if (cs->upsolving_mode) {
fwrite(csp_str42, 1, 6, out_f);
fputs(_("UPSOLVING"), out_f);
fwrite(csp_str46, 1, 4, out_f);

#line 66 "unpriv_status.csp"
}

#line 68 "unpriv_status.csp"
if (cs->clients_suspended) {
fwrite(csp_str48, 1, 24, out_f);
fputs(_("clients suspended"), out_f);
fwrite(csp_str49, 1, 11, out_f);

#line 70 "unpriv_status.csp"
}

#line 72 "unpriv_status.csp"
if (start_time > 0) {
    if (cs->testing_suspended) {
fwrite(csp_str48, 1, 24, out_f);
fputs(_("testing suspended"), out_f);
fwrite(csp_str49, 1, 11, out_f);

#line 75 "unpriv_status.csp"
}
    if (cs->printing_suspended) {
fwrite(csp_str48, 1, 24, out_f);
fputs(_("printing suspended"), out_f);
fwrite(csp_str49, 1, 11, out_f);

#line 78 "unpriv_status.csp"
}
  }

#line 81 "unpriv_status.csp"
if (!global->is_virtual && start_time <= 0 && sched_time > 0) {
fwrite(csp_str50, 1, 3, out_f);
fputs(_("Start at"), out_f);
fwrite(csp_str51, 1, 2, out_f);
{
  struct tm *ptm = localtime(&(sched_time));
  fprintf(out_f, "%02d:%02d:%02d", ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}

#line 83 "unpriv_status.csp"
}

#line 85 "unpriv_status.csp"
if (start_time > 0 && stop_time <= 0 && duration > 0) {
    duration_str(0, start_time + duration - cs->current_time, 0, time_buf, 0);
fwrite(csp_str50, 1, 3, out_f);
fputs(_("Remaining"), out_f);
fwrite(csp_str52, 1, 26, out_f);
fputs((time_buf), out_f);
fwrite(csp_str41, 1, 6, out_f);

#line 88 "unpriv_status.csp"
}
fwrite(csp_str53, 1, 42, out_f);

#line 90 "unpriv_status.csp"
if (global->disable_auto_refresh > 0) {
fwrite(csp_str54, 1, 7, out_f);

#line 92 "unpriv_status.csp"
} else {
fwrite(csp_str55, 1, 6, out_f);

#line 94 "unpriv_status.csp"
}
fwrite(csp_str56, 1, 48, out_f);
fputs(_("REFRESH"), out_f);
fwrite(csp_str57, 1, 79, out_f);
fwrite(csp_str58, 1, 5, out_f);
fputs((title), out_f);
fwrite(csp_str59, 1, 7, out_f);

#line 75 "unpriv_standings_page.csp"
if (global->disable_user_standings > 0) {
fwrite(csp_str60, 1, 3, out_f);
fputs(_("Information is not available."), out_f);
fwrite(csp_str61, 1, 4, out_f);

#line 77 "unpriv_standings_page.csp"
} else if (global->is_virtual) {
    do_write_standings(cs, cnts, out_f, 1, 1, phr->user_id, 0, 0, 0, 0, 1,
                       cur_time, NULL);
  } else if (global->score_system == SCORE_ACM) {
    do_write_standings(cs, cnts, out_f, 1, 1, phr->user_id, 0, 0, 0, 0, 1,
                       cur_time, NULL);
  } else if (global->score_system == SCORE_OLYMPIAD && cs->accepting_mode) {
fwrite(csp_str60, 1, 3, out_f);
fputs(_("Information is not available."), out_f);
fwrite(csp_str61, 1, 4, out_f);

#line 85 "unpriv_standings_page.csp"
} else if (global->score_system == SCORE_OLYMPIAD) {
fwrite(csp_str60, 1, 3, out_f);
fputs(_("Information is not available."), out_f);
fwrite(csp_str61, 1, 4, out_f);

#line 87 "unpriv_standings_page.csp"
do_write_kirov_standings(cs, cnts, out_f, 0, 1, 1, phr->user_id, 0, 0, 0, 0, 1, cur_time,
                             0, NULL, 1 /* user_mode */);
  } else if (global->score_system == SCORE_KIROV) {
    do_write_kirov_standings(cs, cnts, out_f, 0, 1, 1, phr->user_id, 0, 0, 0, 0, 1, cur_time,
                             0, NULL, 1 /* user_mode */);
  } else if (global->score_system == SCORE_MOSCOW) {
    do_write_moscow_standings(cs, cnts, out_f, 0, 1, 1, phr->user_id,
                              0, 0, 0, 0, 1, cur_time, 0, NULL);
  }
fwrite(csp_str62, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str63, 1, 37, out_f);

#line 98 "unpriv_standings_page.csp"
l10n_setlocale(0);
//cleanup:;
  html_armor_free(&ab);
  return retval;
}
