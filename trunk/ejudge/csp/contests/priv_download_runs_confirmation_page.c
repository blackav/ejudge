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
static const unsigned char csp_str11[98] = "</h2>\n<table>\n<tr><td><input type=\"radio\" name=\"run_selection\" value=\"0\" checked=\"yes\"/></td><td>";
static const unsigned char csp_str12[81] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"run_selection\" value=\"1\"/></td><td>";
static const unsigned char csp_str13[3] = " (";
static const unsigned char csp_str14[82] = ")</td></tr>\n<tr><td><input type=\"radio\" name=\"run_selection\" value=\"2\"/></td><td>";
static const unsigned char csp_str15[26] = "</td></tr>\n</table>\n\n<h2>";
static const unsigned char csp_str16[94] = "</h2>\n<table>\n<tr><td><input type=\"checkbox\" name=\"file_pattern_run\" checked=\"yes\"/></td><td>";
static const unsigned char csp_str17[77] = "</td></tr>\n<tr><td><input type=\"checkbox\" name=\"file_pattern_uid\"/></td><td>";
static const unsigned char csp_str18[79] = "</td></tr>\n<tr><td><input type=\"checkbox\" name=\"file_pattern_login\"/></td><td>";
static const unsigned char csp_str19[78] = "</td></tr>\n<tr><td><input type=\"checkbox\" name=\"file_pattern_name\"/></td><td>";
static const unsigned char csp_str20[78] = "</td></tr>\n<tr><td><input type=\"checkbox\" name=\"file_pattern_prob\"/></td><td>";
static const unsigned char csp_str21[78] = "</td></tr>\n<tr><td><input type=\"checkbox\" name=\"file_pattern_lang\"/></td><td>";
static const unsigned char csp_str22[94] = "</td></tr>\n<tr><td><input type=\"checkbox\" name=\"file_pattern_suffix\" checked=\"yes\"/></td><td>";
static const unsigned char csp_str23[95] = "</h2>\n<table>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"0\" checked=\"yes\"/></td><td>";
static const unsigned char csp_str24[78] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"1\"/></td><td>";
static const unsigned char csp_str25[78] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"2\"/></td><td>";
static const unsigned char csp_str26[78] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"3\"/></td><td>";
static const unsigned char csp_str27[78] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"8\"/></td><td>";
static const unsigned char csp_str28[78] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"4\"/></td><td>";
static const unsigned char csp_str29[78] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"5\"/></td><td>";
static const unsigned char csp_str30[78] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"9\"/></td><td>";
static const unsigned char csp_str31[78] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"6\"/></td><td>";
static const unsigned char csp_str32[78] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"7\"/></td><td>";
static const unsigned char csp_str33[79] = "</td></tr>\n<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"10\"/></td><td>";
static const unsigned char csp_str34[23] = "</h2>\n<table>\n<tr><td>";
static const unsigned char csp_str35[20] = "</td></tr>\n<tr><td>";
static const unsigned char csp_str36[21] = "</td></tr>\n</table>\n";
static const unsigned char csp_str37[7] = "<hr/>\n";
static const unsigned char csp_str38[18] = "\n</body>\n</html>\n";


#line 2 "priv_download_runs_confirmation_page.csp"
/* $Id$ */
#include "new-server.h"
#include "external_action.h"
#include "copyright.h"
#include "l10n.h"
#include "new_server_proto.h"

#include "reuse/xalloc.h"

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)
#define BUTTON(a) ns_submit_button(bb, sizeof(bb), 0, a, 0)

#include <libintl.h>
#define _(x) gettext(x)

int
ns_parse_run_mask(
        struct http_request_info *phr,
        const unsigned char **p_size_str,
        const unsigned char **p_mask_str,
        size_t *p_size,
        unsigned long **p_mask);
int csp_view_priv_download_runs_confirmation_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_priv_download_runs_confirmation_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_priv_download_runs_confirmation_page(void)
{
    return &page_iface;
}

int csp_view_priv_download_runs_confirmation_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{

#line 28 "priv_download_runs_confirmation_page.csp"
//const serve_state_t cs = extra->serve_state;
  struct contest_extra *extra = phr->extra;
  int retval = 0;
  unsigned long *mask = 0, mval;
  size_t mask_size = 0;
  const unsigned char *mask_size_str = 0;
  const unsigned char *mask_str = 0;
  size_t mask_count = 0;
  int i, j;
  unsigned char hbuf[1024];
  const unsigned char *title = _("Download runs configuration");

  if (opcaps_check(phr->caps, OPCAP_DUMP_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);  

  if (ns_parse_run_mask(phr, &mask_size_str, &mask_str, &mask_size, &mask) < 0)
    goto invalid_param;

  for (i = 0; i < mask_size; i++) {
    mval = mask[i];
    for (j = 0; j < 8 * sizeof(mask[0]); j++, mval >>= 1)
      if ((mval & 1)) mask_count++;
  }

  l10n_setlocale(phr->locale_id);
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
fputs("<form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"", out_f);
fputs(phr->self_url, out_f);
fputs("\">", out_f);
fputs(phr->hidden_vars, out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"run_mask_size\"", out_f);
if ((mask_size_str)) {
fputs(" value=\"", out_f);
fputs((mask_size_str), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str9, 1, 1, out_f);
fputs("<input type=\"hidden\" name=\"run_mask\"", out_f);
if ((mask_str)) {
fputs(" value=\"", out_f);
fputs((mask_str), out_f);
fputs("\"", out_f);
}
fputs(" />", out_f);
fwrite(csp_str10, 1, 5, out_f);
fputs(_("Run selection"), out_f);
fwrite(csp_str11, 1, 97, out_f);
fputs(_("Download all runs"), out_f);
fwrite(csp_str12, 1, 80, out_f);
fputs(_("Download selected runs"), out_f);
fwrite(csp_str13, 1, 2, out_f);
fprintf(out_f, "%zu", (size_t)(mask_count));
fwrite(csp_str14, 1, 81, out_f);
fputs(_("Download OK runs"), out_f);
fwrite(csp_str15, 1, 25, out_f);
fputs(_("File name pattern"), out_f);
fwrite(csp_str16, 1, 93, out_f);
fputs(_("Use run number"), out_f);
fwrite(csp_str17, 1, 76, out_f);
fputs(_("Use user Id"), out_f);
fwrite(csp_str18, 1, 78, out_f);
fputs(_("Use user Login"), out_f);
fwrite(csp_str19, 1, 77, out_f);
fputs(_("Use user Name"), out_f);
fwrite(csp_str20, 1, 77, out_f);
fputs(_("Use problem short name"), out_f);
fwrite(csp_str21, 1, 77, out_f);
fputs(_("Use programming language short name"), out_f);
fwrite(csp_str22, 1, 93, out_f);
fputs(_("Use source language or content type suffix"), out_f);
fwrite(csp_str15, 1, 25, out_f);
fputs(_("Directory structure"), out_f);
fwrite(csp_str23, 1, 94, out_f);
fputs(_("No directory structure"), out_f);
fwrite(csp_str24, 1, 77, out_f);
fputs(_("/&lt;Problem&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str25, 1, 77, out_f);
fputs(_("/&lt;User_Id&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str26, 1, 77, out_f);
fputs(_("/&lt;User_Login&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str27, 1, 77, out_f);
fputs(_("/&lt;User_Name&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str28, 1, 77, out_f);
fputs(_("/&lt;Problem&gt;/&lt;User_Id&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str29, 1, 77, out_f);
fputs(_("/&lt;Problem&gt;/&lt;User_Login&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str30, 1, 77, out_f);
fputs(_("/&lt;Problem&gt;/&lt;User_Name&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str31, 1, 77, out_f);
fputs(_("/&lt;User_Id&gt;/&lt;Problem&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str32, 1, 77, out_f);
fputs(_("/&lt;User_Login&gt;/&lt;Problem&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str33, 1, 78, out_f);
fputs(_("/&lt;User_Name&gt;/&lt;Problem&gt;/&lt;File&gt;"), out_f);
fwrite(csp_str15, 1, 25, out_f);
fputs(_("Download runs"), out_f);
fwrite(csp_str34, 1, 22, out_f);
fputs(ns_submit_button(hbuf, sizeof(hbuf), 0, NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_2, NULL), out_f);
fwrite(csp_str35, 1, 19, out_f);
fputs(ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_MAIN_PAGE, 0), out_f);
fputs(_("Main page"), out_f);
fputs("</a>", out_f);
fwrite(csp_str36, 1, 20, out_f);
fputs("</form>", out_f);
fwrite(csp_str37, 1, 6, out_f);
write_copyright_short(out_f);
fwrite(csp_str38, 1, 17, out_f);

#line 98 "priv_download_runs_confirmation_page.csp"
l10n_setlocale(0);

 cleanup:
  xfree(mask);
  return retval;

 invalid_param:
  ns_html_err_inv_param(out_f, phr, 0, 0);
  xfree(mask);
  return -1;
  return 0;
}
