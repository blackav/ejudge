/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[34] = "\"/>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str2[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str3[83] = "</title></head>\n<body><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str4[8] = "</div>\n";
static const unsigned char csp_str5[24] = "\n<h2><font color=\"red\">";
static const unsigned char csp_str6[14] = "</font></h2>\n";
static const unsigned char csp_str7[5] = "\n<p>";
static const unsigned char csp_str8[29] = "</p>\n<font color=\"red\"><pre>";
static const unsigned char csp_str9[15] = "</pre></font>\n";
static const unsigned char csp_str10[2] = "\n";
static const unsigned char csp_str11[18] = "<div id=\"footer\">";
static const unsigned char csp_str12[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

/* $Id: reg_error_unknown.csp 8111 2014-04-14 08:59:46Z cher $ */
#include "ejudge/new-server.h"
#include "ejudge/new_server_pi.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/external_action.h"
#include "ejudge/clarlog.h"
#include "ejudge/misctext.h"
#include "ejudge/runlog.h"
#include "ejudge/l10n.h"
#include "ejudge/prepare.h"
#include "ejudge/xml_utils.h"
#include "ejudge/teamdb.h"
#include "ejudge/copyright.h"
#include "ejudge/mischtml.h"
#include "ejudge/html.h"
#include "ejudge/userlist.h"
#include "ejudge/sformat.h"

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
int csp_view_reg_error_unknown(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_reg_error_unknown, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_reg_error_unknown(void)
{
    return &page_iface;
}

int csp_view_reg_error_unknown(PageInterface *pg, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr?phr->extra:NULL;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr?phr->cnts:NULL;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
unsigned char title[1024];
  const unsigned char *error_title = NULL;

  l10n_setlocale(phr->locale_id);
  error_title = ns_error_title(phr->error_code);
  snprintf(title, sizeof(title), "%s: %s", _("Error"), error_title);
fwrite(csp_str0, 1, 183, out_f);
fwrite("utf-8", 1, 5, out_f);
fwrite(csp_str1, 1, 33, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str2, 1, 37, out_f);
fputs((title), out_f);
fwrite(csp_str3, 1, 82, out_f);
fputs((title), out_f);
fwrite(csp_str4, 1, 7, out_f);
fwrite(csp_str5, 1, 23, out_f);
fputs((title), out_f);
fwrite(csp_str6, 1, 13, out_f);
if (phr->log_t && *phr->log_t) {
fwrite(csp_str7, 1, 4, out_f);
fputs(_("Additional information about this error:"), out_f);
fwrite(csp_str8, 1, 28, out_f);
fputs(html_armor_buf(&ab, (phr->log_t)), out_f);
fwrite(csp_str9, 1, 14, out_f);
}
fwrite(csp_str10, 1, 1, out_f);
fwrite(csp_str11, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str12, 1, 37, out_f);
l10n_setlocale(0);
  html_armor_free(&ab);
  return retval;
}
