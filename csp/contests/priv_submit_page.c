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
static const unsigned char csp_str10[6] = "\n<h2>";
static const unsigned char csp_str11[2] = " ";
static const unsigned char csp_str12[3] = ": ";
static const unsigned char csp_str13[7] = "</h2>\n";
static const unsigned char csp_str14[3] = "\n\n";
static const unsigned char csp_str15[45] = "\n\n<table class=\"b0\"><tr>\n<tr><td class=\"b0\">";
static const unsigned char csp_str16[22] = ":</td><td class=\"b0\">";
static const unsigned char csp_str17[4] = " - ";
static const unsigned char csp_str18[21] = "</td><td class=\"b0\">";
static const unsigned char csp_str19[12] = "</td></tr>\n";
static const unsigned char csp_str20[21] = "\n<tr><td class=\"b0\">";
static const unsigned char csp_str21[13] = "</td>\n</tr>\n";
static const unsigned char csp_str22[11] = "\n</table>\n";
static const unsigned char csp_str23[27] = "<big><font color=\"red\"><p>";
static const unsigned char csp_str24[18] = "</p></font></big>";
static const unsigned char csp_str25[23] = "\n\n<table class=\"b0\">\n\n";
static const unsigned char csp_str26[22] = "\n<tr>\n<td class=\"b0\">";
static const unsigned char csp_str27[27] = "<option value=\"\"></option>";
static const unsigned char csp_str28[13] = "</td></tr>\n\n";
static const unsigned char csp_str29[119] = "\n<option value=\"0\"></option>\n<option value=\"1\">LF (Unix/MacOS)</option>\n<option value=\"2\">CRLF (Windows/DOS)</option>\n";
static const unsigned char csp_str30[20] = "<tr><td class=\"b0\">";
static const unsigned char csp_str31[64] = "</td><td class=\"b0\"><input type=\"file\" name=\"file\" /></td></tr>";
static const unsigned char csp_str32[100] = "<tr><td colspan=\"2\" class=\"b0\"><textarea name=\"text_form\" rows=\"20\" cols=\"60\"></textarea></td></tr>";
static const unsigned char csp_str33[63] = "</td><td class=\"b0\"><input type=\"file\" name=\"file\"/></td></tr>";
static const unsigned char csp_str34[64] = "</td><td class=\"b0\"><input type=\"text\" name=\"file\" /></td></tr>";
static const unsigned char csp_str35[95] = "<tr><td colspan=\"2\" class=\"b0\"><textarea name=\"file\" rows=\"20\" cols=\"60\"></textarea></td></tr>";
static const unsigned char csp_str36[11] = "</td></tr>";
static const unsigned char csp_str37[54] = "</td><td class=\"b0\"><input type=\"checkbox\" name=\"ans_";
static const unsigned char csp_str38[25] = "\" /></td><td class=\"b0\">";
static const unsigned char csp_str39[47] = "\n<tr><td class=\"b0\">&nbsp;</td><td class=\"b0\">";
static const unsigned char csp_str40[57] = "</td></tr>\n<tr><td class=\"b0\">&nbsp;</td><td class=\"b0\">";
static const unsigned char csp_str41[21] = "</td></tr>\n</table>\n";
static const unsigned char csp_str42[7] = "<hr/>\n";
static const unsigned char csp_str43[18] = "\n</body>\n</html>\n";

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
void
ns_unparse_statement(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const struct section_problem_data *prob,
        int variant,
        problem_xml_t px,
        const unsigned char *bb,
        int is_submittable);

void
ns_unparse_answers(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const struct section_problem_data *prob,
        int variant,
        problem_xml_t px,
        const unsigned char *lang,
        int is_radio,
        int last_answer,
        int next_prob_id,
        int enable_js,
        const unsigned char *class_name);
int csp_view_priv_submit_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_submit_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_submit_page(void)
{
    return &page_iface;
}

int csp_view_priv_submit_page(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr->extra;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr->cnts;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
const struct section_problem_data *prob = 0;
  int prob_id = 0, variant = 0, i;
  problem_xml_t px = 0;
  struct watched_file *pw = 0;
  const unsigned char *pw_path = 0;
  path_t variant_stmt_file;
  unsigned char title[1024];

  if (ns_cgi_param_int_opt(phr, "problem", &prob_id, 0) < 0) {
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  }
  if (prob_id < 0 || prob_id > cs->max_prob) {
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }
  if (prob_id > 0 && !(prob = cs->probs[prob_id])) {
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }
  if (ns_cgi_param_int_opt(phr, "variant", &variant, 0) < 0) {
    FAIL(NEW_SRV_ERR_INV_VARIANT);
  }
  if (!prob) variant = 0;
  if (prob && prob->variant_num <= 0) variant = 0;
  if (variant < 0
      || (prob && prob->variant_num <= 0 && variant > 0)
      || (prob && prob->variant_num > 0 && variant > prob->variant_num)) {
    FAIL(NEW_SRV_ERR_INV_VARIANT);
  }
  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) < 0) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  l10n_setlocale(phr->locale_id);
  if (prob && variant > 0) {
    snprintf(title, sizeof(title), "%s %s-%d", _("Submit a solution for"), prob->short_name, variant);
  } else if (prob) {
    snprintf(title, sizeof(title), "%s %s", _("Submit a solution for"), prob->short_name);
  } else {
    snprintf(title, sizeof(title), "%s", _("Submit a solution"));
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
if (prob) {
fwrite(csp_str10, 1, 5, out_f);
fputs(_("Problem"), out_f);
fwrite(csp_str11, 1, 1, out_f);
fputs((prob->short_name), out_f);
fwrite(csp_str12, 1, 2, out_f);
fputs(html_armor_buf(&ab, (prob->long_name)), out_f);
fwrite(csp_str13, 1, 6, out_f);
}
fwrite(csp_str14, 1, 2, out_f);
fputs("<form method=\"post\" enctype=\"multipart/form-data\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str15, 1, 44, out_f);
fputs(_("Problem"), out_f);
fwrite(csp_str16, 1, 21, out_f);
fputs("<select name=\"problem\"", out_f);
fputs(">", out_f);
for (i = 1; i <= cs->max_prob; i++) {
    if (!(cs->probs[i])) continue;
fputs("<option", out_f);
if (prob_id > 0 && i == prob_id) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(i));
fputs("\"", out_f);
fputs(">", out_f);
fputs((cs->probs[i]->short_name), out_f);
fwrite(csp_str17, 1, 3, out_f);
fputs(html_armor_buf(&ab, (cs->probs[i]->long_name)), out_f);
fputs("</option>", out_f);
}
fputs("</select>", out_f);
fwrite(csp_str18, 1, 20, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_SUBMIT_PAGE, NULL), out_f);
fwrite(csp_str19, 1, 11, out_f);
if (prob && prob->variant_num > 0) {
fwrite(csp_str20, 1, 20, out_f);
fputs(_("Variant"), out_f);
fwrite(csp_str16, 1, 21, out_f);
fputs("<select name=\"variant\"", out_f);
fputs(">", out_f);
for (i = 0; i <= prob->variant_num; i++) {
fputs("<option", out_f);
if (i == variant) {
fputs(" selected=\"selected\"", out_f);
}
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(i));
fputs("\"", out_f);
fputs(">", out_f);
if ((i)  > 0) {
fprintf(out_f, "%d", (int)(i));
}
fputs("</option>", out_f);
}
fputs("</select>", out_f);
fwrite(csp_str18, 1, 20, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_PRIV_SUBMIT_PAGE, _("Select variant")), out_f);
fwrite(csp_str21, 1, 12, out_f);
}
fwrite(csp_str22, 1, 10, out_f);
/* output the problem statement */
  px = 0; pw = 0; pw_path = 0;
  if (prob && prob->variant_num > 0 && variant > 0 && prob->xml.a
      && prob->xml.a[variant - 1]) {
    px = prob->xml.a[variant - 1];
  } else if (prob && prob->variant_num <= 0 && prob->xml.p) {
    px = prob->xml.p;
  }
  if (px && px->stmts) {
    ns_unparse_statement(out_f, phr, cnts, extra, prob, variant, px, NULL, 1);
  }

  if (!px && prob && prob->statement_file[0]) {
    if (prob->variant_num > 0 && variant > 0) {
      prepare_insert_variant_num(variant_stmt_file,
                                 sizeof(variant_stmt_file),
                                 prob->statement_file, variant);
      pw = &cs->prob_extras[prob_id].v_stmts[variant];
      pw_path = variant_stmt_file;
    } else if (prob->variant_num <= 0) {
      pw = &cs->prob_extras[prob_id].stmt;
      pw_path = prob->statement_file;
    }
    watched_file_update(pw, pw_path, cs->current_time);
    if (!pw->text) {
fwrite(csp_str23, 1, 26, out_f);
fputs(_("The problem statement is not available"), out_f);
fwrite(csp_str24, 1, 17, out_f);
} else {
      fprintf(out_f, "%s", pw->text);
    }
  }
fwrite(csp_str25, 1, 22, out_f);
if (!prob || !prob->type) {
fwrite(csp_str26, 1, 21, out_f);
fputs(_("Language"), out_f);
fwrite(csp_str16, 1, 21, out_f);
fputs("<select name=\"lang_id\"", out_f);
fputs(">", out_f);
fwrite(csp_str27, 1, 26, out_f);
for (i = 1; i <= cs->max_lang; i++) {
      if (cs->langs[i]) {
fputs("<option", out_f);
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(i));
fputs("\"", out_f);
fputs(">", out_f);
fputs((cs->langs[i]->short_name), out_f);
fwrite(csp_str17, 1, 3, out_f);
fputs(html_armor_buf(&ab, (cs->langs[i]->long_name)), out_f);
fputs("</option>", out_f);
}
    }
fputs("</select>", out_f);
fwrite(csp_str28, 1, 12, out_f);
if (cs->global->enable_eoln_select > 0) {
fwrite(csp_str20, 1, 20, out_f);
fputs(_("EOLN Type"), out_f);
fwrite(csp_str16, 1, 21, out_f);
fputs("<select name=\"eoln_type\"", out_f);
fputs(">", out_f);
fwrite(csp_str29, 1, 118, out_f);
fputs("</select>", out_f);
fwrite(csp_str19, 1, 11, out_f);
}
fwrite(csp_str9, 1, 1, out_f);
}
fwrite(csp_str14, 1, 2, out_f);
if (!prob /*|| !prob->type*/) {
fwrite(csp_str30, 1, 19, out_f);
fputs(_("File"), out_f);
fwrite(csp_str31, 1, 63, out_f);
} else {
    switch (prob->type) {
    case PROB_TYPE_STANDARD:
    case PROB_TYPE_OUTPUT_ONLY:
    case PROB_TYPE_TESTS:
      if (prob->enable_text_form > 0) {
fwrite(csp_str32, 1, 99, out_f);
}
fwrite(csp_str30, 1, 19, out_f);
fputs(_("File"), out_f);
fwrite(csp_str33, 1, 62, out_f);
break;
    case PROB_TYPE_SHORT_ANSWER:
fwrite(csp_str30, 1, 19, out_f);
fputs(_("Answer"), out_f);
fwrite(csp_str34, 1, 63, out_f);
break;
    case PROB_TYPE_TEXT_ANSWER:
fwrite(csp_str35, 1, 94, out_f);
break;
    case PROB_TYPE_SELECT_ONE:
      if (px) {
        ns_unparse_answers(out_f, phr, cnts, extra, prob, variant,
                           px, 0 /* lang */, 1 /* is_radio */,
                           -1, prob_id, 0 /* js_flag */, "b0");
      } else if (prob->alternative) {
        for (i = 0; prob->alternative[i]; i++) {
fwrite(csp_str30, 1, 19, out_f);
fprintf(out_f, "%d", (int)(i + 1));
fwrite(csp_str18, 1, 20, out_f);
fputs("<input type=\"radio\" name=\"file\"", out_f);
if ((i+1)) {
fputs(" value=\"", out_f);
fprintf(out_f, "%d", (int)(i+1));
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str18, 1, 20, out_f);
fputs((prob->alternative[i]), out_f);
fwrite(csp_str36, 1, 10, out_f);
}
      }
      break;
    case PROB_TYPE_SELECT_MANY:
      if (prob->alternative) {
        for (i = 0; prob->alternative[i]; i++) {
fwrite(csp_str30, 1, 19, out_f);
fprintf(out_f, "%d", (int)(i + 1));
fwrite(csp_str37, 1, 53, out_f);
fprintf(out_f, "%d", (int)(i + 1));
fwrite(csp_str38, 1, 24, out_f);
fputs(html_armor_buf(&ab, (prob->alternative[i])), out_f);
fwrite(csp_str36, 1, 10, out_f);
}
      }
      break;
    case PROB_TYPE_CUSTOM:
      break;

    default:
      abort();
    }
  }
fwrite(csp_str39, 1, 46, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_SUBMIT_RUN, NULL), out_f);
fwrite(csp_str40, 1, 56, out_f);
fputs("<a href=\"", out_f);
sep = ns_url_2(out_f, phr, NEW_SRV_ACTION_MAIN_PAGE);
fputs("\">", out_f);
fputs(_("Main page"), out_f);
fputs("</a>", out_f);
fwrite(csp_str41, 1, 20, out_f);
fputs("</form>", out_f);
fwrite(csp_str14, 1, 2, out_f);
fwrite(csp_str42, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str43, 1, 17, out_f);
l10n_setlocale(0);
cleanup:
  html_armor_free(&ab);
  return retval;
}
