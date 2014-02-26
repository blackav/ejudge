/* === string pool === */

static const unsigned char csp_str0[31] = "<@include \"priv_header.csp\"\n%>";
static const unsigned char csp_str1[2] = "\n";
static const unsigned char csp_str2[4] = "\n  ";
static const unsigned char csp_str3[6] = "\n<h2>";
static const unsigned char csp_str4[2] = " ";
static const unsigned char csp_str5[3] = " [";
static const unsigned char csp_str6[8] = "]</h2>\n";
static const unsigned char csp_str7[40] = "\n<table class=\"b0\">\n<tr><td class=\"b0\">";
static const unsigned char csp_str8[22] = ":</td><td class=\"b0\">";
static const unsigned char csp_str9[12] = "</td></tr>\n";
static const unsigned char csp_str10[21] = "\n<tr><td class=\"b0\">";
static const unsigned char csp_str11[2] = ".";
static const unsigned char csp_str12[21] = "</td><td class=\"b0\">";
static const unsigned char csp_str13[3] = "\n\n";
static const unsigned char csp_str14[6] = "</td>";
static const unsigned char csp_str15[7] = "</tr>\n";
static const unsigned char csp_str16[44] = "\n<tr><td class=\"b0\">IP:</td><td class=\"b0\">";
static const unsigned char csp_str17[55] = "</td></tr>\n<tr><td class=\"b0\">SSL:</td><td class=\"b0\">";
static const unsigned char csp_str18[56] = "</td></tr>\n<tr><td class=\"b0\">Size:</td><td class=\"b0\">";
static const unsigned char csp_str19[56] = "</td></tr>\n<tr><td class=\"b0\">SHA1:</td><td class=\"b0\">";
static const unsigned char csp_str20[46] = "\n<tr><td class=\"b0\">UUID:</td><td class=\"b0\">";
static const unsigned char csp_str21[54] = "\n<tr><td class=\"b0\">Content type:</td><td class=\"b0\">";
static const unsigned char csp_str22[48] = "\n<tr><td class=\"b0\">Hidden:</td><td class=\"b0\">";
static const unsigned char csp_str23[60] = "</td></tr>\n<tr><td class=\"b0\">Imported:</td><td class=\"b0\">";
static const unsigned char csp_str24[61] = "</td></tr>\n<tr><td class=\"b0\">Read-only:</td><td class=\"b0\">";
static const unsigned char csp_str25[62] = "</td></tr>\n\n<tr><td class=\"b0\">Locale ID:</td><td class=\"b0\">";
static const unsigned char csp_str26[55] = "\n<tr><td class=\"b0\">Pages printed:</td><td class=\"b0\">";
static const unsigned char csp_str27[50] = "\n<table>\n\n<table class=\"b0\">\n<tr>\n<td class=\"b0\">";
static const unsigned char csp_str28[22] = "</td>\n<td class=\"b0\">";
static const unsigned char csp_str29[32] = "</td>\n</tr>\n</table>\n</form>\n%>";
static const unsigned char csp_str30[7] = "<hr/>\n";
static const unsigned char csp_str31[18] = "\n</body>\n</html>\n";


#line 2 "priv_edit_run_page.csp"
/* $Id$ */

#line 2 "priv_includes.csp"
#include "new-server.h"
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

#include "reuse/xalloc.h"

#include <libintl.h>
#define _(x) gettext(x)
int csp_view_priv_edit_run_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_edit_run_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_edit_run_page(void)
{
    return &page_iface;
}

int csp_view_priv_edit_run_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 8 "priv_edit_run_page.csp"
const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = NULL;
  const struct section_language_data *lang = NULL;
  time_t start_time = 0, run_time = 0;
  struct run_entry info;
  unsigned char hbuf[1024], buf[1024];
  const unsigned char *str = NULL;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s;
  const unsigned char *dis = "";
  int run_id = 0;

  if (ns_cgi_param(phr, "run_id", &s) <= 0
      || sscanf(s, "%d%n", &run_id, &n) != 1 || s[n]
      || run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    ns_html_err_inv_param(fout, phr, 1, "cannot parse run_id");
    return -1;
  }

  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto done;
  }
  if (run_get_entry(cs->runlog_state, run_id, &info) < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto done;
  }
  if (info.status < 0 || info.status > RUN_MAX_STATUS) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto done;
  }

  l10n_setlocale(phr->locale_id);

  unsigned char title[1024];
  snprintf(title, sizeof(title), "%s %d", _("Editing run"), run_id);
fwrite(csp_str0, 1, 30, out_f);

#line 51 "priv_edit_run_page.csp"
ns_write_run_view_menu(f, phr, cnts, extra, run_id);

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, info.user_id);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
  }
  if (start_time < 0) start_time = 0;
  run_time = info.time;
  if (run_time < 0) run_time = 0;
  if (run_time < start_time) run_time = start_time;

  if (info.is_readonly > 0) dis = " disabled=\"disabled\"";
fwrite(csp_str1, 1, 1, out_f);
fwrite(csp_str2, 1, 3, out_f);
fwrite(csp_str3, 1, 5, out_f);
fputs(_("Run"), out_f);
fwrite(csp_str4, 1, 1, out_f);
fprintf(out_f, "%d", (int)(run_id));
fwrite(csp_str5, 1, 2, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_VIEW_SOURCE);
fputs(sep, out_f); sep = "&amp;";
fputs("run_id=", out_f);
fprintf(out_f, "%d", (int)(run_id));
(void) sep;
fputs("\">", out_f);
fputs(_("Source"), out_f);
fputs("</a>", out_f);
fwrite(csp_str6, 1, 7, out_f);
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str1, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"action\"", out_f);
if ((0)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%u", (unsigned)(0));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str1, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"run_id\"", out_f);
if ((run_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(run_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str1, 1, 1, out_f);

#line 72 "priv_edit_run_page.csp"
unsigned char *cl = " class=\"b0\"";
fwrite(csp_str7, 1, 39, out_f);
fputs(_("Run ID"), out_f);
fwrite(csp_str8, 1, 21, out_f);
fprintf(out_f, "%d", (int)(run_id));
fwrite(csp_str9, 1, 11, out_f);

#line 75 "priv_edit_run_page.csp"
if (run_time != info.time) {
    if (info.time <= 0) {
fwrite(csp_str10, 1, 20, out_f);
fputs(_("DB timestamp"), out_f);
fwrite(csp_str8, 1, 21, out_f);
fprintf(out_f, "%d", (int)((long) info.time));
fwrite(csp_str11, 1, 1, out_f);
fprintf(out_f, "%d", (int)(info.nsec / 1000));
fwrite(csp_str9, 1, 11, out_f);

#line 78 "priv_edit_run_page.csp"
} else {
fwrite(csp_str10, 1, 20, out_f);
fputs(_("DB time"), out_f);
fwrite(csp_str12, 1, 20, out_f);
fputs(xml_unparse_date((info.time)), out_f);
fwrite(csp_str11, 1, 1, out_f);
fprintf(out_f, "%d", (int)(info.nsec / 1000));
fwrite(csp_str9, 1, 11, out_f);

#line 80 "priv_edit_run_page.csp"
}
  }
fwrite(csp_str1, 1, 1, out_f);

#line 82 "priv_edit_run_page.csp"
if (run_time <= 0) {
fwrite(csp_str10, 1, 20, out_f);
fputs(_("Timestamp"), out_f);
fwrite(csp_str8, 1, 21, out_f);
fprintf(out_f, "%d", (int)((long) run_time));
fwrite(csp_str11, 1, 1, out_f);
fprintf(out_f, "%d", (int)(info.nsec / 1000));
fwrite(csp_str9, 1, 11, out_f);

#line 84 "priv_edit_run_page.csp"
} else {
fwrite(csp_str10, 1, 20, out_f);
fputs(_("Time"), out_f);
fwrite(csp_str12, 1, 20, out_f);
fputs(xml_unparse_date((run_time)), out_f);
fwrite(csp_str11, 1, 1, out_f);
fprintf(out_f, "%d", (int)(info.nsec / 1000));
fwrite(csp_str9, 1, 11, out_f);

#line 86 "priv_edit_run_page.csp"
}
fwrite(csp_str10, 1, 20, out_f);
fputs(_("Contest time"), out_f);
fwrite(csp_str12, 1, 20, out_f);
fputs(html_armor_buf(&ab, (duration_str_2(hbuf, sizeof(hbuf), run_time - start_time, info.nsec))), out_f);
fwrite(csp_str9, 1, 11, out_f);

#line 88 "priv_edit_run_page.csp"
if (info.user_id <= 0 || !(str = teamdb_get_login(cs->teamdb_state, info.user_id))) {
    snprintf(buf, sizeof(buf), "#%d", info.user_id);
    str = buf;
  }
fwrite(csp_str10, 1, 20, out_f);
fputs(_("User login/ID"), out_f);
fwrite(csp_str12, 1, 20, out_f);
fputs("<input type=\"text\" name=\"user\" size=\"20\"", out_f);
if ((str)) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (str)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 11, out_f);

#line 93 "priv_edit_run_page.csp"
if ((str = teamdb_get_name(cs->teamdb_state, info.user_id))) {
fwrite(csp_str10, 1, 20, out_f);
fputs(_("User name"), out_f);
fwrite(csp_str12, 1, 20, out_f);
fputs(html_armor_buf(&ab, (str)), out_f);
fwrite(csp_str9, 1, 11, out_f);

#line 95 "priv_edit_run_page.csp"
}
fwrite(csp_str1, 1, 1, out_f);

#line 97 "priv_edit_run_page.csp"
fprintf(f, "<tr><td%s>%s:</td><td%s><select name=\"prob\"%s>", cl, "Prob name/ID", cl, dis);
  if (info.prob_id <= 0 || info.prob_id > cs->max_prob || !(prob = cs->probs[info.prob_id])) {
    fprintf(f, "<option value=\"%d\" selected=\"selected\">#%d</option>",
            info.prob_id, info.prob_id);
  }
  for (int prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
    if (cs->probs[prob_id]) {
      s = "";
      if (info.prob_id == prob_id) s = " selected=\"selected\"";
      fprintf(f, "<option value=\"%d\"%s>%s - %s</option>",
              prob_id, s, cs->probs[prob_id]->short_name,
              ARMOR(cs->probs[prob_id]->long_name));
    }
  }
  fprintf(f, "</select></td></tr>\n");

  if (prob && prob->variant_num > 0) {
    str = "";
    if (info.variant > 0) {
      snprintf(buf, sizeof(buf), "%d", info.variant);
      str = buf;
    }
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n", cl, "Variant",
            cl, html_input_text(hbuf, sizeof(hbuf), "variant", 20, info.is_readonly, "%s", str));
  }

  fprintf(f, "<tr><td%s>%s:</td><td%s><select name=\"lang\"%s>", cl, "Lang name/ID", cl, dis);
  if (info.lang_id == 0) {
    fprintf(f, "<option value=\"0\" selected=\"selected\"></option>");
    str = "";
  } else if (info.lang_id < 0 || info.lang_id > cs->max_lang || !(lang = cs->langs[info.lang_id])) {
    fprintf(f, "<option value=\"%d\" selected=\"selected\">#%d</option>", info.lang_id, info.lang_id);
  }
  for (int lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
    if (cs->langs[lang_id]) {
      s = "";
      if (info.lang_id == lang_id) s = " selected=\"selected\"";
      fprintf(f, "<option value=\"%d\"%s>%s - %s</option>",
              lang_id, s, cs->langs[lang_id]->short_name,
              ARMOR(cs->langs[lang_id]->long_name));
    }
  }
  fprintf(f, "</select></td></tr>\n");
fwrite(csp_str13, 1, 2, out_f);

#line 143 "priv_edit_run_page.csp"
fprintf(f, "<tr><td%s>%s:</td><td%s><select name=\"eoln_type\"%s>",
          cl, "EOLN Type", cl, dis);
  fprintf(f, "<option value=\"0\"></option>");
  s = "";
  if (info.eoln_type == 1) s = " selected=\"selected\"";
  fprintf(f, "<option value=\"1\"%s>LF (Unix/MacOS)</option>", s);
  s = "";
  if (info.eoln_type == 2) s = " selected=\"selected\"";
  fprintf(f, "<option value=\"2\"%s>CRLF (Windows/DOS)</option>", s);
  fprintf(f, "</select></td></tr>\n");
fwrite(csp_str10, 1, 20, out_f);
fputs(_("Status"), out_f);
fwrite(csp_str14, 1, 5, out_f);

#line 154 "priv_edit_run_page.csp"
write_change_status_dialog(cs, f, NULL, info.is_imported, "b0", info.status, info.is_readonly);
fwrite(csp_str15, 1, 6, out_f);

#line 156 "priv_edit_run_page.csp"
buf[0] = 0;
  if (info.passed_mode > 0) {
    if (info.test >= 0) {
      snprintf(buf, sizeof(buf), "%d", info.test);
    }
    s = "Tests passed";
  } else {
    if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD) {
      if (info.test > 0) {
        snprintf(buf, sizeof(buf), "%d", info.test - 1);
      }
      s = "Tests passed";
    } else if (global->score_system == SCORE_MOSCOW || global->score_system == SCORE_ACM) {
      if (info.test > 0) {
        snprintf(buf, sizeof(buf), "%d", info.test);
      }
      s = "Failed test";
    } else {
      abort();
    }
  }
  fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n", cl, s,
          cl, html_input_text(hbuf, sizeof(hbuf), "test", 20, info.is_readonly, "%s", buf));
fwrite(csp_str1, 1, 1, out_f);

#line 181 "priv_edit_run_page.csp"
if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD
      || global->score_system == SCORE_MOSCOW) {
    buf[0] = 0;
    if (info.score >= 0) {
      snprintf(buf, sizeof(buf), "%d", info.score);
    }
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n", cl, "Score",
            cl, html_input_text(hbuf, sizeof(hbuf), "score", 20, info.is_readonly, "%s", buf));

    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n", cl, "Score adjustment",
            cl, html_input_text(hbuf, sizeof(hbuf), "score_adj", 20, info.is_readonly, "%d", info.score_adj));
  }
fwrite(csp_str1, 1, 1, out_f);
fputs("<checkbox name=\"is_marked\" value=\"1\"", out_f);
fputs(" />", out_f);
fwrite(csp_str1, 1, 1, out_f);

#line 196 "priv_edit_run_page.csp"
if (global->separate_user_score > 0) {
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n", cl, "Has saved score",
            cl, html_checkbox(hbuf, sizeof(hbuf), "is_saved", "1", info.is_saved, info.is_readonly));
    fprintf(f, "<tr><td%s>%s:</td>", cl, "Saved status");
    write_change_status_dialog(cs, f, "saved_status", info.is_imported, "b0", info.saved_status,
                               info.is_readonly);
    fprintf(f, "</tr>\n");
    buf[0] = 0;
    if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD) {
      snprintf(buf, sizeof(buf), "%d", info.saved_test);
      s = "Saved tests passed";
    } else if (global->score_system == SCORE_MOSCOW || global->score_system == SCORE_ACM) {
      if (info.saved_test > 0) {
        snprintf(buf, sizeof(buf), "%d", info.saved_test);
      }
      s = "Saved failed test";
    } else {
      abort();
    }
    fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n", cl, s,
            cl, html_input_text(hbuf, sizeof(hbuf), "saved_test", 20, info.is_readonly, "%s", buf));
    if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD
        || global->score_system == SCORE_MOSCOW) {
      buf[0] = 0;
      if (info.saved_score >= 0) {
        snprintf(buf, sizeof(buf), "%d", info.saved_score);
      }
      fprintf(f, "<tr><td%s>%s:</td><td%s>%s</td></tr>\n", cl, "Saved score",
              cl, html_input_text(hbuf, sizeof(hbuf), "saved_score", 20, info.is_readonly, "%s", buf));
    }
  }
fwrite(csp_str16, 1, 43, out_f);
fputs("<input type=\"text\" name=\"ip\" size=\"20\"", out_f);
if ((info.a.ip)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%s", xml_unparse_ip(info.a.ip));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str17, 1, 54, out_f);
fputs("<checkbox name=\"ssl_flag\" value=\"1\"", out_f);
fputs(" />", out_f);
fwrite(csp_str18, 1, 55, out_f);
fputs("<input type=\"text\" name=\"size\" size=\"20\"", out_f);
if ((info.size)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%zu", (size_t)(info.size));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str19, 1, 55, out_f);
fputs("<input type=\"text\" name=\"sha1\" size=\"60\"", out_f);
if ((unparse_sha1(info.sha1))) {
fputs(" value=\"", out_f);
fputs((unparse_sha1(info.sha1)), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 11, out_f);

#line 232 "priv_edit_run_page.csp"
#if CONF_HAS_LIBUUID - 0 != 0
fwrite(csp_str20, 1, 45, out_f);
fputs("<input type=\"text\" name=\"sha1\" size=\"60\"", out_f);
if ((ej_uuid_unparse(info.run_uuid, ""))) {
fputs(" value=\"", out_f);
fputs((ej_uuid_unparse(info.run_uuid, "")), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 11, out_f);

#line 234 "priv_edit_run_page.csp"
#endif
fwrite(csp_str1, 1, 1, out_f);

#line 235 "priv_edit_run_page.csp"
if (!info.lang_id) {
fwrite(csp_str21, 1, 53, out_f);
fputs("<input type=\"text\" name=\"mime_type\" size=\"60\"", out_f);
if ((mime_type_get_type(info.mime_type))) {
fputs(" value=\"", out_f);
fputs(html_armor_buf(&ab, (mime_type_get_type(info.mime_type))), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 11, out_f);

#line 237 "priv_edit_run_page.csp"
}
fwrite(csp_str22, 1, 47, out_f);
fputs("<checkbox name=\"is_hidden\" value=\"1\"", out_f);
fputs(" />", out_f);
fwrite(csp_str23, 1, 59, out_f);
fputs("<checkbox name=\"is_imported\" value=\"1\"", out_f);
fputs(" />", out_f);
fwrite(csp_str24, 1, 60, out_f);
fputs("<checkbox name=\"is_readonly\" value=\"1\"", out_f);
fputs(" />", out_f);
fwrite(csp_str25, 1, 61, out_f);
fputs("<input type=\"text\" name=\"locale_id\" size=\"20\"", out_f);
if ((info.locale_id)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(info.locale_id));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 11, out_f);

#line 243 "priv_edit_run_page.csp"
if (global->enable_printing > 0) {
fwrite(csp_str26, 1, 54, out_f);
fputs("<input type=\"text\" name=\"pages\" size=\"20\"", out_f);
if (((int) info.pages)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)((int) info.pages));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 11, out_f);

#line 245 "priv_edit_run_page.csp"
}
fwrite(csp_str27, 1, 49, out_f);
fwrite(csp_str28, 1, 21, out_f);
fwrite(csp_str29, 1, 31, out_f);
fwrite(csp_str30, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str31, 1, 17, out_f);

#line 257 "priv_edit_run_page.csp"
l10n_setlocale(0);
done:;
  html_armor_free(&ab);
}
  return 0;
}
