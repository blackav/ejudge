/* === string pool === */

static const unsigned char csp_str0[184] = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=";
static const unsigned char csp_str1[34] = "\"/>\n<link rel=\"stylesheet\" href=\"";
static const unsigned char csp_str2[38] = "unpriv.css\" type=\"text/css\"/>\n<title>";
static const unsigned char csp_str3[83] = "</title></head>\n<body><div id=\"container\"><div id=\"l12\">\n<div class=\"main_phrase\">";
static const unsigned char csp_str4[8] = "</div>\n";
static const unsigned char csp_str5[469] = "\n<div class=\"user_actions\">\n    <table class=\"menu\">\n        <tr>\n            <td class=\"menu\">\n                <div class=\"contest_actions_item\">&nbsp;</div>\n            </td>\n        </tr>\n    </table>\n</div>\n<div class=\"white_empty_block\">&nbsp;</div>\n<div class=\"contest_actions\">\n    <table class=\"menu\">\n        <tr>\n            <td class=\"menu\">\n                <div class=\"contest_actions_item\">&nbsp;</div>\n            </td>\n        </tr>\n    </table>\n</div>\n";
static const unsigned char csp_str6[32] = "</div>\n<div id=\"l11\"><img src=\"";
static const unsigned char csp_str7[45] = "logo.gif\" alt=\"logo\"/></div>\n<div id=\"l13\">\n";
static const unsigned char csp_str8[2] = "\n";
static const unsigned char csp_str9[35] = "<div class=\"server_status_off\"><b>";
static const unsigned char csp_str10[11] = "</b></div>";
static const unsigned char csp_str11[37] = "<div class=\"server_status_alarm\"><b>";
static const unsigned char csp_str12[37] = "<div class=\"server_status_error\"><b>";
static const unsigned char csp_str13[34] = "<div class=\"server_status_on\"><b>";
static const unsigned char csp_str14[10] = "<br/><h2>";
static const unsigned char csp_str15[2] = " ";
static const unsigned char csp_str16[6] = "</h2>";
static const unsigned char csp_str17[18] = "<div id=\"footer\">";
static const unsigned char csp_str18[38] = "</div>\n</div>\n</div>\n</body>\n</html>\n";

/* $Id: reg_edit_page.csp 8158 2014-05-10 08:41:13Z cher $ */
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
// local includes go here
extern const unsigned char *ns_role_labels[];

void
ns_edit_member_form(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        const struct userlist_member *m,
        int role,
        int member,
        int skip_header,
        const unsigned char *var_prefix,
        int fields_order[]);
void
ns_edit_general_form(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        const struct userlist_user *u);
int csp_view_reg_edit_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr);
static PageInterfaceOps page_ops =
{
    NULL, // destroy
    NULL, // execute
    csp_view_reg_edit_page, // render
};
static PageInterface page_iface =
{
    &page_ops,
};
PageInterface *
csp_get_reg_edit_page(void)
{
    return &page_iface;
}

int csp_view_reg_edit_page(PageInterface *ps, FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
int retval __attribute__((unused)) = 0;
  struct contest_extra *extra __attribute__((unused)) = phr?phr->extra:NULL;
  serve_state_t cs __attribute__((unused)) = extra?extra->serve_state:NULL;
  const struct contest_desc *cnts __attribute__((unused)) = phr?phr->cnts:NULL;
  struct html_armor_buffer ab __attribute__((unused)) = HTML_ARMOR_INITIALIZER;
  unsigned char hbuf[1024] __attribute__((unused));
  const unsigned char *sep __attribute__((unused)) = NULL;
struct userlist_user *u = 0;
  int role = 0, member = 0;
  const struct userlist_member *m = 0;
  const unsigned char *s = 0, *n = 0;
  struct userlist_user_info *ui = 0;
  unsigned char title[1024];

  // check that we are allowed to edit something
  if (phr && phr->session_extra) u = phr->session_extra->user_info;
  if (!u || u->read_only) goto redirect_back;
  ui = userlist_get_cnts0(u);
  if (ui && ui->cnts_read_only) goto redirect_back;
  if (phr->action == NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE) {
if (hr_cgi_param_int_2(phr, "role", &(role)) <= 0) {
  goto redirect_back;
}
if (hr_cgi_param_int_2(phr, "member", &(member)) <= 0) {
  goto redirect_back;
}
if (role < 0 || role >= CONTEST_M_GUEST) goto redirect_back;
    if (!cnts->members[role]) goto redirect_back;
    if (!(m = userlist_members_get_nth(ui->members, role, member)))
      goto redirect_back;
  } else if (phr->action == NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE) {
  } else {
    goto redirect_back;
  }
 
  l10n_setlocale(phr->locale_id);

  if (phr->action == NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE)
    s = _("Editing general info");
  else if (phr->action == NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE)
    s = _("Editing member info");
  else 
    s = _("Good!");

  n = phr->name;
  if (!n || !*n) n = phr->login;

  snprintf(title, sizeof(title), "%s [%s, %s]", s, html_armor_buf(&ab, n), extra->contest_arm);
fwrite(csp_str0, 1, 183, out_f);
fwrite("utf-8", 1, 5, out_f);
fwrite(csp_str1, 1, 33, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str2, 1, 37, out_f);
fputs((title), out_f);
fwrite(csp_str3, 1, 82, out_f);
fputs((title), out_f);
fwrite(csp_str4, 1, 7, out_f);
fwrite(csp_str5, 1, 468, out_f);
fwrite(csp_str6, 1, 31, out_f);
fwrite("/ejudge/", 1, 8, out_f);
fwrite(csp_str7, 1, 44, out_f);
fwrite(csp_str8, 1, 1, out_f);
if (phr->reg_status < 0) {
fwrite(csp_str9, 1, 34, out_f);
fputs(_("NOT REGISTERED"), out_f);
fwrite(csp_str10, 1, 10, out_f);
} else if (phr->reg_status == USERLIST_REG_PENDING) {
fwrite(csp_str11, 1, 36, out_f);
fputs(_("REGISTERED, PENDING APPROVAL"), out_f);
fwrite(csp_str10, 1, 10, out_f);
} else if (phr->reg_status == USERLIST_REG_REJECTED) {
fwrite(csp_str12, 1, 36, out_f);
fputs(_("REGISTRATION REJECTED"), out_f);
fwrite(csp_str10, 1, 10, out_f);
} else if ((phr->reg_flags & USERLIST_UC_BANNED)) {
fwrite(csp_str12, 1, 36, out_f);
fputs(_("REGISTERED, BANNED"), out_f);
fwrite(csp_str10, 1, 10, out_f);
} else if ((phr->reg_flags & USERLIST_UC_LOCKED)) {
fwrite(csp_str12, 1, 36, out_f);
fputs(_("REGISTERED, LOCKED"), out_f);
fwrite(csp_str10, 1, 10, out_f);
} else if ((phr->reg_flags & USERLIST_UC_INVISIBLE)) {
fwrite(csp_str13, 1, 33, out_f);
fputs(_("REGISTERED (INVISIBLE)"), out_f);
fwrite(csp_str10, 1, 10, out_f);
} else {
fwrite(csp_str13, 1, 33, out_f);
fputs(_("REGISTERED"), out_f);
fwrite(csp_str10, 1, 10, out_f);
}
fwrite(csp_str8, 1, 1, out_f);
// main page goes here
  if (phr->action == NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE) {
fwrite(csp_str14, 1, 9, out_f);
fputs(gettext(ns_role_labels[role]), out_f);
fwrite(csp_str15, 1, 1, out_f);
fprintf(out_f, "%d", (int)(member + 1));
fwrite(csp_str16, 1, 5, out_f);
ns_edit_member_form(out_f, phr, cnts, m, role, member, 0, 0, 0);
  } else {
fwrite(csp_str14, 1, 9, out_f);
fputs(_("General information"), out_f);
fwrite(csp_str16, 1, 5, out_f);
ns_edit_general_form(out_f, phr, cnts, u);
  }
fwrite(csp_str8, 1, 1, out_f);
fwrite(csp_str17, 1, 17, out_f);
write_copyright_short(out_f);
fwrite(csp_str18, 1, 37, out_f);
//cleanup:;
  l10n_setlocale(0);
  html_armor_free(&ab);
  return retval;

redirect_back:
  phr->content_type[0] = 0;
  ns_refresh_page(out_f, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
  html_armor_free(&ab);
  return 0;
  return retval;
}
