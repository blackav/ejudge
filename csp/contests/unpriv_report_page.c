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
static const unsigned char csp_str58[6] = "<pre>";
static const unsigned char csp_str59[7] = "</pre>";
static const unsigned char csp_str60[18] = "<div id=\"footer\">";
static const unsigned char csp_str61[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

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
#include "ejudge/copyright.h"
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
#include "fileutl.h"
#include "archive_paths.h"

int
ns_unpriv_parse_run_id(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int *p_run_id,
        struct run_entry *pe);
int csp_view_unpriv_report_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_unpriv_report_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_unpriv_report_page(void)
{
    return &page_iface;
}

int csp_view_unpriv_report_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
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
const struct section_problem_data *prob;
  int run_id, flags, content_type;
  const unsigned char *rep_start = 0;
  char *rep_text = 0;
  size_t rep_size = 0;
  struct run_entry re;
  path_t rep_path;
  int accepting_mode = 0;
  int enable_rep_view = 0;
  int status = -1;
  unsigned char title[1024];

  start_time = run_get_start_time(cs->runlog_state);
  stop_time = run_get_stop_time(cs->runlog_state);
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
    if (global->score_system == SCORE_OLYMPIAD) {
      if (global->disable_virtual_auto_judge <= 0 && stop_time <= 0)
        accepting_mode = 1;
      else if (global->disable_virtual_auto_judge > 0
               && cs->testing_finished <= 0)
        accepting_mode = 1;
    }
  } else {
    accepting_mode = cs->accepting_mode;
  }

  if (ns_unpriv_parse_run_id(out_f, phr, cnts, extra, &run_id, &re) < 0)
    goto cleanup;

  enable_rep_view = (cs->online_view_report > 0 || (!cs->online_view_report && global->team_enable_rep_view > 0));

  if (cs->clients_suspended) {
    FAIL(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  }

  if (re.user_id != phr->user_id) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob || !(prob = cs->probs[re.prob_id])) {
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }

  status = re.status;
  if (global->separate_user_score > 0 && re.is_saved) {
    status = re.saved_status;
  }
  
  // check viewable statuses
  switch (status) {
  case RUN_OK:
  case RUN_COMPILE_ERR:
  case RUN_RUN_TIME_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_WALL_TIME_LIMIT_ERR:
  case RUN_PRESENTATION_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_PARTIAL:
  case RUN_ACCEPTED:
  case RUN_PENDING_REVIEW:
  case RUN_MEM_LIMIT_ERR:
  case RUN_SECURITY_ERR:
  case RUN_STYLE_ERR:
  case RUN_REJECTED:
    // these statuses have viewable reports
    break;
  default:
    FAIL(NEW_SRV_ERR_REPORT_UNAVAILABLE);
  }

  if (accepting_mode && prob->type != PROB_TYPE_STANDARD) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  if (enable_rep_view) enable_rep_view = prob->team_enable_rep_view;
  if (!enable_rep_view
      && (!prob->team_enable_ce_view
          || (status != RUN_COMPILE_ERR
              && status != RUN_STYLE_ERR
              && status != RUN_REJECTED))) {
    FAIL(NEW_SRV_ERR_REPORT_VIEW_DISABLED);
  }

  flags = serve_make_xml_report_read_path(cs, rep_path, sizeof(rep_path), &re);
  if (flags >= 0) {
    if (generic_read_file(&rep_text, 0, &rep_size, flags, 0, rep_path, 0) < 0) {
      FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
    }
    content_type = get_content_type(rep_text, &rep_start);
    if (content_type != CONTENT_TYPE_XML
        && status != RUN_COMPILE_ERR
        && status != RUN_STYLE_ERR
        && status != RUN_REJECTED) {
      FAIL(NEW_SRV_ERR_REPORT_UNAVAILABLE);
    }
  } else {
    int user_mode = 0;
    if (prob->team_enable_ce_view
        && (status == RUN_COMPILE_ERR
            || status == RUN_STYLE_ERR
            || status == RUN_REJECTED)) {
    } else if (prob->team_show_judge_report) {
    } else {
      user_mode = 1;
    }

    if (user_mode) {
      flags = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                     global->team_report_archive_dir, run_id, 0, 1);
    } else {
      flags = serve_make_report_read_path(cs, rep_path, sizeof(rep_path), &re);
      
    }
    if (flags < 0) {
      FAIL(NEW_SRV_ERR_REPORT_NONEXISTANT);
    }

    if (generic_read_file(&rep_text,0,&rep_size,flags,0,rep_path, 0) < 0) {
      FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
    }
    content_type = get_content_type(rep_text, &rep_start);
  }

  unpriv_load_html_style(phr, cnts, 0, 0);
  l10n_setlocale(phr->locale_id);
  snprintf(title, sizeof(title), "%s %d", _("Report for run"), run_id);
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
#if defined CONF_ENABLE_AJAX && CONF_ENABLE_AJAX
  if (cs && phr->user_id > 0 ) {
fwrite(csp_str10, 1, 18, out_f);
do_json_user_state(out_f, cs, phr->user_id, 0);
fwrite(csp_str11, 1, 2, out_f);
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
if (phr) {
if ((phr->name_arm) ) {
fputs((phr->name_arm), out_f);
}
}
fwrite(csp_str18, 1, 2, out_f);
if (extra) {
if ((extra->contest_arm) ) {
fputs((extra->contest_arm), out_f);
}
}
fwrite(csp_str19, 1, 3, out_f);
fputs((title), out_f);
fwrite(csp_str20, 1, 21, out_f);
#if defined CONF_ENABLE_AJAX && CONF_ENABLE_AJAX
fwrite(csp_str21, 1, 22, out_f);
#endif
fwrite(csp_str22, 1, 61, out_f);
if (phr) {
if ((phr->name_arm) ) {
fputs((phr->name_arm), out_f);
}
}
fwrite(csp_str18, 1, 2, out_f);
if (extra) {
if ((extra->contest_arm) ) {
fputs((extra->contest_arm), out_f);
}
}
fwrite(csp_str19, 1, 3, out_f);
fputs((title), out_f);
fwrite(csp_str23, 1, 7, out_f);
fwrite(csp_str24, 1, 51, out_f);
shown_items = 0;
  if (cnts && cs && cnts->exam_mode <= 0) {
fwrite(csp_str25, 1, 51, out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_SETTINGS) {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_SETTINGS);
fputs("\">", out_f);
}
fputs(_("Settings"), out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_SETTINGS) {
fputs("</a>", out_f);
}
fwrite(csp_str26, 1, 11, out_f);
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
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_LOGOUT);
fputs("\">", out_f);
if (cnts->exam_mode) {
fputs(_("Finish session"), out_f);
} else {
fputs(_("Logout"), out_f);
}
fwrite(csp_str18, 1, 2, out_f);
fputs((phr->login), out_f);
fwrite(csp_str27, 1, 16, out_f);
shown_items++;
  }

  if (!shown_items) {
fwrite(csp_str28, 1, 68, out_f);
}
fwrite(csp_str29, 1, 170, out_f);
if (phr->action != NEW_SRV_ACTION_MAIN_PAGE) {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);
}
if (cnts && cnts->exam_mode) {
fputs(_("Instructions"), out_f);
} else {
fputs(_("Info"), out_f);
}
if (phr->action != NEW_SRV_ACTION_MAIN_PAGE) {
fputs("</a>", out_f);
}
fwrite(csp_str26, 1, 11, out_f);
if (global && global->is_virtual > 0 && ((start_time <= 0 && global->disable_virtual_start <= 0) || stop_time <= 0)) {
fwrite(csp_str25, 1, 51, out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_STARTSTOP) {
fwrite(csp_str30, 1, 38, out_f);
}
if (start_time <= 0) {
      if (cnts->exam_mode) {
fputs(_("Start exam"), out_f);
} else {
fputs(_("Start virtual contest"), out_f);
}
    } else if (stop_time <= 0) {
      if (cnts->exam_mode) {
fputs(_("Stop exam"), out_f);
} else {
fputs(_("Stop virtual contest"), out_f);
}
    }
if (phr->action != NEW_SRV_ACTION_VIEW_STARTSTOP) {
fputs("</a>", out_f);
}
fwrite(csp_str26, 1, 11, out_f);
}
if (cnts && start_time > 0 && (cnts->exam_mode <= 0 || stop_time > 0)) {
fwrite(csp_str25, 1, 51, out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY) {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY);
fputs("\">", out_f);
}
fputs(_("Summary"), out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY) {
fputs("</a>", out_f);
}
fwrite(csp_str26, 1, 11, out_f);
}
if (global && start_time > 0 && stop_time <= 0 && cnts->problems_url) {
//      && (stop_time <= 0 || cnts->problems_url)
//      && (global->problem_navigation <= 0 || cnts->problems_url)) {
fwrite(csp_str25, 1, 51, out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS) {
      if (cnts->problems_url) {
fwrite(csp_str31, 1, 22, out_f);
fputs((cnts->problems_url), out_f);
fwrite(csp_str32, 1, 18, out_f);
fputs(_("Statements"), out_f);
fwrite(csp_str33, 1, 4, out_f);
} else {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS);
fputs("\">", out_f);
fputs(_("Statements"), out_f);
fputs("</a>", out_f);
}
    } else {
fputs(_("Statements"), out_f);
}
fwrite(csp_str26, 1, 11, out_f);
}
if (global && start_time > 0 && stop_time <= 0 && global->problem_navigation <= 0) {
fwrite(csp_str25, 1, 51, out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT) {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT);
fputs("\">", out_f);
}
fputs(_("Submit"), out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT) {
fputs("</a>", out_f);
}
fwrite(csp_str26, 1, 11, out_f);
}
if (cnts && start_time > 0 && (cnts->exam_mode <= 0 || stop_time > 0)) {
fwrite(csp_str25, 1, 51, out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_SUBMISSIONS) {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_SUBMISSIONS);
fputs("\">", out_f);
}
fputs(_("Submissions"), out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_SUBMISSIONS) {
fputs("</a>", out_f);
}
fwrite(csp_str26, 1, 11, out_f);
}
if (global && start_time > 0 && global->disable_user_standings <= 0) {
fwrite(csp_str25, 1, 51, out_f);
if (phr->action == NEW_SRV_ACTION_STANDINGS) {
if (cnts->personal) {
fputs(_("User standings"), out_f);
} else {
fputs(_("Standings"), out_f);
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
if (cnts->personal) {
fputs(_("User standings"), out_f);
} else {
fputs(_("Standings"), out_f);
}
fwrite(csp_str33, 1, 4, out_f);
} else {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_STANDINGS);
fputs("\">", out_f);
if (cnts->personal) {
fputs(_("User standings"), out_f);
} else {
fputs(_("Standings"), out_f);
}
fputs("</a>", out_f);
}
    }
fwrite(csp_str26, 1, 11, out_f);
}
if (global && global->disable_team_clars <= 0 && global->disable_clars <= 0 && start_time > 0
      && (stop_time <= 0 || (global->appeal_deadline > 0 && cs->current_time < global->appeal_deadline))) {
fwrite(csp_str25, 1, 51, out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_CLAR_SUBMIT) {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_CLAR_SUBMIT);
fputs("\">", out_f);
}
fputs(_("Submit clar"), out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_CLAR_SUBMIT) {
fputs("</a>", out_f);
}
fwrite(csp_str26, 1, 11, out_f);
}
if (global && global->disable_clars <= 0) {
fwrite(csp_str25, 1, 51, out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_CLARS) {
fputs("<a class=\"menu\" href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_CLARS);
fputs("\">", out_f);
}
fputs(_("Clars"), out_f);
if (phr->action != NEW_SRV_ACTION_VIEW_CLARS) {
fputs("</a>", out_f);
}
fwrite(csp_str26, 1, 11, out_f);
}
fwrite(csp_str34, 1, 52, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str35, 1, 44, out_f);
run_get_times(cs->runlog_state, 0, &sched_time, &duration, 0, 0);
  if (duration > 0 && start_time && !stop_time && global->board_fog_time > 0)
    fog_start_time = start_time + duration - global->board_fog_time;
  if (fog_start_time < 0) fog_start_time = 0;
  if (!cs->global->disable_clars || !cs->global->disable_team_clars)
    unread_clars = serve_count_unread_clars(cs, phr->user_id, start_time);
fwrite(csp_str36, 1, 11, out_f);
if (cs->clients_suspended) {
fwrite(csp_str37, 1, 19, out_f);
} else if (unread_clars > 0) {
fwrite(csp_str38, 1, 21, out_f);
} else {
fwrite(csp_str39, 1, 18, out_f);
}
fwrite(csp_str40, 1, 40, out_f);
{
  struct tm *ptm = localtime(&(cs->current_time));
  fprintf(out_f, "%02d:%02d:%02d", ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}
fwrite(csp_str41, 1, 6, out_f);
if (unread_clars > 0) {
    fprintf(out_f, _(" / <b>%d unread message(s)</b>"),
            unread_clars);
  }
fwrite(csp_str42, 1, 6, out_f);
if (stop_time > 0) {
    if (duration > 0 && global->board_fog_time > 0
        && global->board_unfog_time > 0
        && cs->current_time < stop_time + global->board_unfog_time
        && !cs->standings_updated) {
fputs(_("OVER (frozen)"), out_f);
} else {
fputs(_("OVER"), out_f);
}
  } else if (start_time > 0) {
    if (fog_start_time > 0 && cs->current_time >= fog_start_time) {
      if (cnts->exam_mode) {
fputs(_("EXAM IS RUNNING (frozen)"), out_f);
} else {
fputs(_("RUNNING (frozen)"), out_f);
}
    } else {
      if (cnts->exam_mode) {
fwrite(csp_str43, 1, 15, out_f);
} else {
fwrite(csp_str44, 1, 7, out_f);
}
    }
  } else {
fwrite(csp_str45, 1, 11, out_f);
}
fwrite(csp_str46, 1, 4, out_f);
if (start_time > 0) {
    if (global->score_system == SCORE_OLYMPIAD && !global->is_virtual) {
fwrite(csp_str47, 1, 5, out_f);
if (cs->accepting_mode) {
fputs(_("accepting"), out_f);
} else if (!cs->testing_finished) {
fputs(_("judging"), out_f);
} else {
fputs(_("judged"), out_f);
}
fwrite(csp_str46, 1, 4, out_f);
}
  }
if (cs->upsolving_mode) {
fwrite(csp_str42, 1, 6, out_f);
fputs(_("UPSOLVING"), out_f);
fwrite(csp_str46, 1, 4, out_f);
}
if (cs->clients_suspended) {
fwrite(csp_str48, 1, 24, out_f);
fputs(_("clients suspended"), out_f);
fwrite(csp_str49, 1, 11, out_f);
}
if (start_time > 0) {
    if (cs->testing_suspended) {
fwrite(csp_str48, 1, 24, out_f);
fputs(_("testing suspended"), out_f);
fwrite(csp_str49, 1, 11, out_f);
}
    if (cs->printing_suspended) {
fwrite(csp_str48, 1, 24, out_f);
fputs(_("printing suspended"), out_f);
fwrite(csp_str49, 1, 11, out_f);
}
  }
if (!global->is_virtual && start_time <= 0 && sched_time > 0) {
fwrite(csp_str50, 1, 3, out_f);
fputs(_("Start at"), out_f);
fwrite(csp_str51, 1, 2, out_f);
{
  struct tm *ptm = localtime(&(sched_time));
  fprintf(out_f, "%02d:%02d:%02d", ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}
}
if (start_time > 0 && stop_time <= 0 && duration > 0) {
    duration_str(0, start_time + duration - cs->current_time, 0, time_buf, 0);
fwrite(csp_str50, 1, 3, out_f);
fputs(_("Remaining"), out_f);
fwrite(csp_str52, 1, 26, out_f);
fputs((time_buf), out_f);
fwrite(csp_str41, 1, 6, out_f);
}
fwrite(csp_str53, 1, 42, out_f);
if (global->disable_auto_refresh > 0) {
fwrite(csp_str54, 1, 7, out_f);
} else {
fwrite(csp_str55, 1, 6, out_f);
}
fwrite(csp_str56, 1, 48, out_f);
fputs(_("REFRESH"), out_f);
fwrite(csp_str57, 1, 79, out_f);
switch (content_type) {
  case CONTENT_TYPE_TEXT:
fwrite(csp_str58, 1, 5, out_f);
fputs(html_armor_buf(&ab, (rep_text)), out_f);
fwrite(csp_str59, 1, 6, out_f);
break;
  case CONTENT_TYPE_HTML:
fputs((rep_start), out_f);
break;
  case CONTENT_TYPE_XML:
    if (prob->type == PROB_TYPE_TESTS) {
      if (prob->team_show_judge_report) {
        write_xml_tests_report(out_f, 1, rep_start, phr->session_id,
                                 phr->self_url, "", "b1", "b0"); 
      } else {
        write_xml_team_tests_report(cs, prob, out_f, rep_start, "b1");
      }
    } else {
      if (global->score_system == SCORE_OLYMPIAD && accepting_mode) {
        write_xml_team_accepting_report(out_f, phr, rep_start, run_id, &re, prob,
                                        cnts->exam_mode, "b1");
      } else if (prob->team_show_judge_report) {
        write_xml_testing_report(out_f, phr, 1, rep_start, "b1", "b0");
      } else {
        write_xml_team_testing_report(cs, prob, out_f, phr,
                                      prob->type != PROB_TYPE_STANDARD,
                                      re.is_marked,
                                      rep_start, "b1");
      }
    }
    break;
  default:
    abort();
  }
fwrite(csp_str60, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str61, 1, 37, out_f);
l10n_setlocale(0);
cleanup:;
  html_armor_free(&ab);
  xfree(rep_text);
  return retval;
}
