/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2001-2007 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "config.h"
#include "settings.h"
#include "ej_types.h"

#include "expat_iface.h"
#include "pathutl.h"
#include "errlog.h"
#include "clntutil.h"
#include "cgi.h"
#include "contests.h"
#include "userlist_clnt.h"
#include "userlist_proto.h"
#include "misctext.h"
#include "userlist.h"
#include "l10n.h"
#include "fileutl.h"
#include "xml_utils.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>

#define __(x) x
#endif

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

#define FIRST_COOKIE(u) ((struct userlist_cookie*) (u)->cookies->first_down)
#define NEXT_COOKIE(c)  ((struct userlist_cookie*) (c)->b.right)
#define FIRST_CONTEST(u) ((struct userlist_contest*)(u)->contests->first_down)
#define NEXT_CONTEST(c)  ((struct userlist_contest*)(c)->b.right)

#define ARMOR(s)  html_armor_buf(&ab, s)

/* ACTIONS, that may be performed by client*/
enum
  {
    STATE_INITIAL = 1,
    STATE_REGISTER_NEW_USER,
    STATE_LOGIN,
    STATE_LOGIN_FORCED_REG,
    STATE_USER_REGISTERED,
    STATE_MAIN_PAGE,
    STATE_EDIT_REGISTRATION_DATA,

    ACTION_CHANGE_LANG_AT_INITIAL,
    ACTION_CHANGE_LANG_AT_LOGIN,
    ACTION_CHANGE_LANG_AT_LOGIN_FORCED_REG,
    ACTION_CHANGE_LANG_AT_REGISTER_NEW_USER,
    ACTION_CHANGE_LANG_AT_MAIN_PAGE,
    ACTION_NEW_LOGIN,
    ACTION_REGISTER_NEW_USER,
    ACTION_LOGIN,
    ACTION_LOGIN_FORCED_REG,
    ACTION_LOGOUT,
    ACTION_CHANGE_PASSWORD,
    ACTION_SAVE_REGISTRATION_DATA,
    ACTION_REGISTER_FOR_CONTEST,
    ACTION_ADD_NEW_CONTESTANT,
    ACTION_ADD_NEW_RESERVE,
    ACTION_ADD_NEW_COACH,
    ACTION_ADD_NEW_ADVISOR,
    ACTION_ADD_NEW_GUEST,
    ACTION_REMOVE_MEMBER,
    ACTION_REDISPLAY_EDIT_REGISTRATION_DATA,
    STATE_USER_REGISTERED_2,

    ACTION_LAST_ACTION
  };

enum
  {
    TG_CONFIG = 1,
    TG_ACCESS,
    TG_IP,
    TG_SOCKET_PATH,
    TG_CONTESTS_DIR,
    TG_L10N_DIR,
    TG_LAST_TAG,
  };
enum
  {
    AT_ENABLE_L10N = 1,
    AT_DISABLE_L10N,
    AT_L10N,
    AT_SHOW_GENERATION_TIME,
    AT_CHARSET,
    AT_DEFAULT,
    AT_ALLOW,
    AT_DENY,
    AT_ID,
    AT_LAST_ATTR,
  };

struct ip_node
{
  struct xml_tree b;
  int allow;
  unsigned int addr;
  unsigned int mask;
};
struct access_node
{
  struct xml_tree b;
  int default_is_allow;
};
struct config_node
{
  struct xml_tree b;
  int l10n;
  unsigned char *l10n_dir;
  int show_generation_time;
  unsigned char *charset;
  unsigned char *socket_path;
  unsigned char *contests_dir;
  struct access_node *access;
};

static struct config_node *config;

static int client_locale_id;

static unsigned char *self_url;
static int ssl_flag;
static unsigned char *user_login;
static unsigned char *user_password;
static int user_usecookies;
static int user_read_only;
static unsigned char *user_email;
static unsigned char *user_name;
static unsigned char *user_homepage;
static unsigned char *user_phone;
static unsigned char *user_inst;
static unsigned char *user_inst_en;
static unsigned char *user_instshort;
static unsigned char *user_instshort_en;
static unsigned char *user_fac;
static unsigned char *user_fac_en;
static unsigned char *user_facshort;
static unsigned char *user_facshort_en;
static unsigned char *user_city;
static unsigned char *user_city_en;
static unsigned char *user_country;
static unsigned char *user_country_en;
static unsigned char *user_region;
static unsigned char *user_languages;
static int user_show_email;
static int user_contest_id;
static struct userlist_clnt *server_conn;
static ej_ip_t user_ip;
static ej_cookie_t user_cookie;
static int user_id;
static unsigned char *user_name;
static int user_action;
static int user_use_cookies_default;
static int user_show_login;
static struct userlist_user *user_xml;
static time_t cur_time;
static int user_registering;
static int user_already_registered;

static char *header_txt, *footer_txt;
static size_t header_len, footer_len;

static unsigned char **allowed_languages;
static size_t allowed_languages_u;

static unsigned char **allowed_regions;
static size_t allowed_regions_u;

static unsigned char *head_style = "h2";
static unsigned char *par_style = "";
static unsigned char *table_style = "";
static unsigned char *contest_user_name_comment;
static int disable_member_delete;

static unsigned char ***member_info[CONTEST_LAST_MEMBER];

static unsigned char *error_log;

#define ARMOR_STR(out,in) do { int __tmplen = html_armored_strlen((in)); (out) = (unsigned char*) alloca(__tmplen + 16); html_armor_string((in), (out)); } while (0)

static char const login_accept_chars[] =
"._-0123456789?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char const email_accept_chars[] =
"@.%!+=_-0123456789?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char const name_accept_chars[] =
" :!#$%()*+,-./0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"abcdefghijklmnopqrstuvwxyz{|}~"
" ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß"
"àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";
static char const name_en_accept_chars[] =
" :!#$%()*+,-./0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"abcdefghijklmnopqrstuvwxyz{|}~";
static char const homepage_accept_chars[] =
" :!#$%*+,-./0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"abcdefghijklmnopqrstuvwxyz{|}~";
static char const password_accept_chars[] =
" !#$%\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"`abcdefghijklmnopqrstuvwxyz{|}~ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿"
"ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";

struct field_desc
{
  char *tag_name;
  char *orig_name;
  char *var_name;
  unsigned char **var;
  const unsigned char *accept_chars;
  int repl_char;
  int maxlength;
  int size;
  /* dynamic fields */
  int is_editable;
  int is_mandatory;
};

#define _(x) x
static struct field_desc field_descs[CONTEST_LAST_FIELD] = 
{
  { 0 },                        /* entry 0 is empty */

  { "homepage", _("Homepage"), "homepage", &user_homepage,
    homepage_accept_chars, '?', 128, 64 },
  { "phone", _("Phone"), "phone", &user_phone,
    homepage_accept_chars, '?', 128, 64 },
  { "inst", _("Institution"), "inst", &user_inst,
    name_accept_chars, '?', 128, 64 },
  { "inst_en", _("Institution (En)"), "inst_en", &user_inst_en,
    name_en_accept_chars, '?', 128, 64 },
  { "instshort", _("Institution (short)"), "instshort", &user_instshort,
    name_accept_chars, '?', 32, 32 },
  { "instshort_en", _("Institution (short) (En)"), "instshort_en", &user_instshort_en,
    name_en_accept_chars, '?', 32, 32 },
  { "fac", _("Faculty"), "fac", &user_fac,
    name_accept_chars, '?', 128, 64 },
  { "fac_en", _("Faculty (En)"), "fac_en", &user_fac_en,
    name_en_accept_chars, '?', 128, 64 },
  { "facshort", _("Faculty (short)"), "facshort", &user_facshort,
    name_accept_chars, '?', 32, 32 },
  { "facshort_en", _("Faculty (short) (En)"), "facshort_en", &user_facshort_en,
    name_en_accept_chars, '?', 32, 32 },
  { "city", _("City"), "city", &user_city, name_accept_chars, '?', 64, 64 },
  { "city_en", _("City (En)"), "city_en", &user_city_en, name_en_accept_chars, '?', 64, 64 },
  { "country", _("Country"), "country", &user_country,
    name_accept_chars, '?', 64, 64 },
  { "country_en", _("Country (En)"), "country_en", &user_country_en,
    name_en_accept_chars, '?', 64, 64 },
  { "region", _("Region"), "region", &user_region,
    name_accept_chars, '?', 64, 64 },
  { "languages", _("Programming languages"), "languages", &user_languages,
    name_accept_chars, '?', 64, 64 },
};
static struct field_desc member_field_descs[CONTEST_LAST_MEMBER_FIELD] =
{
  { 0 },

  { "firstname",_("First name"),0,0, name_accept_chars, '?', 64, 64 },
  { "firstname_en",_("First name (En)"),0,0, name_en_accept_chars, '?', 64, 64 },
  { "middlename",_("Middle name"), 0, 0, name_accept_chars, '?', 64, 64 },
  { "middlename_en",_("Middle name (En)"), 0, 0, name_accept_chars, '?', 64, 64 },
  { "surname",_("Family name"), 0, 0, name_accept_chars, '?', 64, 64 },
  { "surname_en",_("Family name (En)"), 0, 0, name_en_accept_chars, '?', 64, 64 },
  { "status", _("Status"), 0, 0, name_accept_chars, '?', 64, 64 },
  { "grade", _("Grade"), 0, 0, name_accept_chars, '?', 16, 16 },
  { "group", _("Group"), 0, 0, name_accept_chars, '?', 16, 16 },
  { "group_en", _("Group (En)"), 0, 0, name_en_accept_chars, '?', 16, 16 },
  { "email",_("E-mail"), 0, 0, name_accept_chars, '?', 64, 64 },
  { "homepage",_("Homepage"), 0, 0, homepage_accept_chars, '?', 128, 64 },
  { "phone",_("Phone"), 0, 0, homepage_accept_chars, '?', 128, 64 },
  { "inst", _("Institution"), 0, 0, name_accept_chars, '?', 128, 64 },
  { "inst_en", _("Institution (En)"), 0, 0, name_en_accept_chars, '?', 128, 64 },
  { "instshort", _("Institution (short)"),0,0,name_accept_chars, '?', 32, 32 },
  { "instshort_en", _("Institution (short) (En)"),0,0,name_en_accept_chars, '?', 32, 32 },
  { "fac", _("Faculty"), 0, 0, name_accept_chars, '?', 128, 64 },
  { "fac_en", _("Faculty (En)"), 0, 0, name_en_accept_chars, '?', 128, 64 },
  { "facshort", _("Faculty (short)"), 0, 0, name_accept_chars, '?', 32, 32 },
  { "facshort_en", _("Faculty (short) (En)"), 0, 0, name_en_accept_chars, '?', 32, 32 },
  { "occupation", _("Occupation"), 0, 0, name_accept_chars, '?', 128, 64 },
  { "occupation_en", _("Occupation (En)"), 0, 0, name_en_accept_chars, '?', 128, 64 },
  { "birth_date", _("Birth Date"), 0, 0, name_accept_chars, '?', 128, 64 },
  { "entry_date", _("Institution entry date"), 0, 0, name_accept_chars, '?', 128, 64 },
  { "graduation_date", _("Institution graduation date"), 0, 0, name_accept_chars, '?', 128, 64 },
};
static char const * const member_string[] =
{
  _("Contestant"),
  _("Reserve"),
  _("Coach"),
  _("Advisor"),
  _("Guest")
};
static char const * const member_string_pl[] =
{
  _("Contestants"),
  _("Reserves"),
  _("Coaches"),
  _("Advisors"),
  _("Guests")
};
static char const * const member_status_string[] =
{
  0,
  _("School student"),
  _("Student"),
  _("Magistrant"),
  _("PhD student"),
  _("School teacher"),
  _("Professor"),
  _("Scientist"),
  _("Other")
};
static unsigned char const * const status_str_map[] =
{
  _("<font color=\"green\">OK</font>"),
  _("<font color=\"magenta\">Pending</font>"),
  _("<font color=\"red\">Rejected</font>"),
};
#undef _

static unsigned char const * member_role_map[] =
{
  "contestants",
  "reserves",
  "coaches",
  "advisors",
  "guests"
};

#if CONF_HAS_LIBINTL - 0 == 1
#define _(x) gettext(x)
#else
#define _(x) x
#define gettext(x) x
#endif

struct edit_flags
{
  char is_editable;
  char is_mandatory;
};
static struct edit_flags member_edit_flags[CONTEST_LAST_MEMBER][CONTEST_LAST_MEMBER_FIELD];
static int member_min[CONTEST_LAST_MEMBER];
static int member_max[CONTEST_LAST_MEMBER];
static int member_init[CONTEST_LAST_MEMBER];
static int member_cur[CONTEST_LAST_MEMBER];

static char const * const elem_map[] =
{
  0,
  "register_config",
  "access",
  "ip",
  "socket_path",
  "contests_dir",
  "l10n_dir",

  0
};
static char const * const attr_map[] =
{
  0,

  "enable_l10n",
  "disable_l10n",
  "l10n",
  "show_generation_time",
  "charset",
  "default",
  "allow",
  "deny",
  "id",

  0
};

static const size_t elem_sizes[TG_LAST_TAG] =
{
  [TG_CONFIG] = sizeof(struct config_node),
  [TG_ACCESS] = sizeof(struct access_node),
  [TG_IP] = sizeof(struct ip_node),
};

static struct xml_parse_spec register_config_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = elem_sizes,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = NULL,
  .attr_free = NULL,
};

static struct config_node *
parse_config(char const *path, const unsigned char *default_config)
{
  struct xml_tree *tree = 0, *p, *p2;
  struct config_node *cfg = 0;
  struct xml_attr *a;
  struct ip_node *ip;

  xml_err_path = path;
  xml_err_spec = &register_config_parse_spec;

  if (default_config) {
    tree = xml_build_tree_str(default_config, &register_config_parse_spec);
  } else {
    tree = xml_build_tree(path, &register_config_parse_spec);
  }
  if (!tree) goto failed;
  if (tree->tag != TG_CONFIG) {
    xml_err_top_level(tree, TG_CONFIG);
    goto failed;
  }
  cfg = (struct config_node*) tree;
  tree = 0;
  cfg->l10n = -1;
  xfree(cfg->b.text);
  cfg->b.text = 0;

  for (a = cfg->b.first; a; a = a->next) {
    switch (a->tag) {
    case AT_ENABLE_L10N:
    case AT_L10N:
    case AT_DISABLE_L10N:
      if (xml_attr_bool(a, &cfg->l10n) < 0) goto failed;
      if (a->tag == AT_DISABLE_L10N) cfg->l10n = !cfg->l10n;
      break;
    case AT_SHOW_GENERATION_TIME:
      if (xml_attr_bool(a, &cfg->show_generation_time) < 0) goto failed;
      break;
    case AT_CHARSET:
      cfg->charset = a->text;
      /* FIXME: check charset for validity */
      break;
    default:
      xml_err_attr_not_allowed(&cfg->b, a);
      goto failed;
    }
  }

  /* process subnodes */
  for (p = cfg->b.first_down; p; p = p->right) {
    switch (p->tag) {
    case TG_SOCKET_PATH:
      if (xml_leaf_elem(p, &cfg->socket_path, 1, 0) < 0) goto failed;
      break;
    case TG_CONTESTS_DIR:
      if (xml_leaf_elem(p, &cfg->contests_dir, 1, 0) < 0) goto failed;
      break;
    case TG_L10N_DIR:
      if (xml_leaf_elem(p, &cfg->l10n_dir, 1, 0) < 0) goto failed;
      break;

    case TG_ACCESS:
      if (cfg->access) {
        xml_err_elem_redefined(p);
        goto failed;
      }
      cfg->access = (struct access_node*) p;
      xfree(p->text);
      p->text = 0;
      for (a = p->first; a; a = a->next) {
        switch (a->tag) {
        case AT_DEFAULT:
          if (!strcasecmp(a->text, "allow")) {
            cfg->access->default_is_allow = 1;
          } else if (!strcasecmp(a->text, "deny")) {
            cfg->access->default_is_allow = 0;
          } else {
            xml_err_attr_invalid(a);
            goto failed;
          }
          break;
        default:
          xml_err_attr_not_allowed(p, a);
          goto failed;
        }
      }

      /* now check the list of ip addresses */
      for (p2 = p->first_down; p2; p2 = p2->right) {
        if (p2->tag != TG_IP) {
          xml_err_elem_not_allowed(p2);
          goto failed;
        }
        ip = (struct ip_node*) p2;
        ip->allow = -1;
        for (a = ip->b.first; a; a = a->next) {
          if (a->tag != AT_ALLOW && a->tag != AT_DENY) {
            xml_err_attr_not_allowed(p2, a);
            goto failed;
          }
          if (xml_attr_bool(a, &ip->allow) < 0) goto failed;
          if (a->tag == AT_DENY) ip->allow = !ip->allow;
        }
        if (ip->allow == -1) ip->allow = 0;

        if (xml_parse_ip_mask(path, ip->b.line, ip->b.column, ip->b.text,
                              &ip->addr, &ip->mask) < 0)
          goto failed;
      }
      break;
    default:
      xml_err_elem_not_allowed(p);
      goto failed;
    }
  }

#if CONF_HAS_LIBINTL - 0 == 1
  if (cfg->l10n < 0) cfg->l10n = 1;
  if (cfg->l10n && !cfg->l10n_dir) {
    cfg->l10n_dir = xstrdup(EJUDGE_LOCALE_DIR);
  }
#else
  cfg->l10n = 0;
#endif

  if (!cfg->charset) {
    cfg->charset = xstrdup(EJUDGE_CHARSET);
  }
#if defined EJUDGE_SOCKET_PATH
  if (!cfg->socket_path) {
    cfg->socket_path = xstrdup(EJUDGE_SOCKET_PATH);
  }
#endif /* EJUDGE_SOCKET_PATH */
  if (!cfg->socket_path) {
    xml_err_elem_undefined(&cfg->b, TG_SOCKET_PATH);
    goto failed;
  }
#if defined EJUDGE_CONTESTS_DIR
  if (!cfg->contests_dir) {
    cfg->contests_dir = xstrdup(EJUDGE_CONTESTS_DIR);
  }
#endif /* EJUDGE_CONTESTS_DIR */
  if (!cfg->contests_dir) {
    xml_err_elem_undefined(&cfg->b, TG_CONTESTS_DIR);
    goto failed;
  }

  return cfg;

 failed:
  /* FIXME: free resources */
  return 0;
}

static int
parse_contest_id(void)
{
  unsigned char *s = cgi_param("contest_id");
  int v = 0, n = 0;

  if (!s) return 0;
  if (sscanf(s, "%d %n", &v, &n) != 1 || s[n] || v < 0) return 0;
  return v;
}

static int
parse_name_contest_id(unsigned char *basename)
{
  int v, n;

  if (!basename) return 0;
  if (sscanf(basename, "-%d %n", &v, &n)!=1 || basename[n] || v < 0) return 0;
  return v;
}

static int
check_config_exist(unsigned char const *path)
{
  struct stat sb;

  if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode) && access(path, R_OK) >= 0) {
    return 1;
  }
  return 0;
}

static void
parse_allowed_list(const unsigned char *str, unsigned char ***pv, size_t *pu)
{
  const unsigned char *s, *q;
  unsigned char *p;
  int i;
  size_t sz;
  unsigned char **v = 0;
  size_t u = 0;

  *pv = 0;
  *pu = 0;
  if (!str) return;

  for (s = str; *s; s++)
    if (*s == ',')
      u++;
  u++;

  XCALLOC(v, u);
  s = str;
  for (i = 0; i < u && *s;) {
    while (*s && isspace(*s)) s++;
    if (*s == ',') {
      s++;
      continue;
    }
    if (!*s) break;
    q = strchr(s, ',');
    if (!q) q = s + strlen(s);
    v[i] = p = xmemdup(s, q - s);
    sz = strlen(p);
    while (sz > 0 && isspace(p[sz - 1])) p[--sz] = 0;
    if (!sz) {
      xfree(p);
      v[i] = 0;
    } else {
      i++;
    }
    if (*s) s = q + 1;
  }
  u = i;
  if (!u) {
    xfree(v); v = 0;
  }
  *pv = v;
  *pu = u;
}

static const unsigned char default_config[] =
"<?xml version=\"1.0\" ?>\n"
"<register_config><access default=\"allow\"/></register_config>\n";

static void
initialize(int argc, char const *argv[])
{
  path_t fullname;
  path_t dirname;
  path_t basename;
  path_t cfgname;
  path_t cfgdir;
  path_t progname;
  path_t cfgname2;
  int namelen, cgi_contest_id, name_contest_id, name_ok, errcode = 0;
  char *s = getenv("SCRIPT_FILENAME");
  const struct contest_desc *cnts = 0;
  const unsigned char *default_config_str = 0;

  pathcpy(fullname, argv[0]);
  if (s) pathcpy(fullname, s);
  os_rDirName(fullname, dirname, PATH_MAX);
  os_rGetBasename(fullname, basename, PATH_MAX);
#if defined CGI_PROG_SUFFIX
 {
   size_t baselen = strlen(basename);
   size_t sufflen = strlen(CGI_PROG_SUFFIX);
   if (baselen>sufflen && !strcmp(basename+baselen-sufflen,CGI_PROG_SUFFIX)) {
     basename[baselen - sufflen] = 0;
   }
 }
#endif /* CGI_PROG_SUFFIX */
  strcpy(program_name, basename);
  if (strncmp(basename, "register", 8) != 0) {
    client_not_configured(0, "bad program name", 0);
    // never get here
  }
  namelen = 8;                  /* "register" */
  memset(progname, 0, sizeof(progname));
  strncpy(progname, basename, namelen);

  /* we need CGI parameters relatively early because of contest_id */
  cgi_read(0);
  cgi_contest_id = parse_contest_id();
  name_contest_id = parse_name_contest_id(basename + namelen);

  /*
   * if CGI_DATA_PATH is absolute, do not append the program start dir
   */
  if (CGI_DATA_PATH[0] == '/') {
    pathmake(cfgdir, CGI_DATA_PATH, "/", NULL);
  } else {
    pathmake(cfgdir, dirname, "/",CGI_DATA_PATH, "/", NULL);
  }

  /*
    Try different variants:
      o If basename has the form <prog>-<number>, then consider
        <number> as contest_id, ignoring the contest_id from
        CGI arguments. Try config file <prog>-<number>.xml
        first, and then try <prog>.xml.
      o If basename has the bare form <prog>, then read contest_id
        from CGI parameters. Try config file <prog>-<contest_id>.xml
        first, and then try <prog>.xml.
      o If basename has any other form, ignore contest_id from
        CGI parameters. Always use config file <prog>.xml.
  */
  if (name_contest_id > 0) {
    // first case
    cgi_contest_id = 0;
    snprintf(cfgname, sizeof(cfgname), "%s%s.xml", cfgdir, basename);
    name_ok = check_config_exist(cfgname);
    if (!name_ok) {
      snprintf(cfgname2, sizeof(cfgname2), "%s%s-%d.xml", cfgdir, progname,
               name_contest_id);
      if (strcmp(cfgname2, cfgname) != 0 && check_config_exist(cfgname2)) {
        name_ok = 1;
        strcpy(cfgname, cfgname2);
      }
    }
    if (!name_ok) {
      snprintf(cfgname2, sizeof(cfgname2), "%s%s-%06d.xml", cfgdir, progname,
               name_contest_id);
      if (strcmp(cfgname2, cfgname) != 0 && check_config_exist(cfgname2)) {
        name_ok = 1;
        strcpy(cfgname, cfgname2);
      }
    }
    if (!name_ok) {
      snprintf(cfgname, sizeof(cfgname), "%s%s.xml", cfgdir, progname);
      name_ok = check_config_exist(cfgname);
    }
    user_contest_id = name_contest_id;
  } else if (strlen(basename) == namelen && cgi_contest_id <= 0) {
    // contest_id is not set
    snprintf(cfgname, sizeof(cfgname), "%s%s.xml", cfgdir, progname);
    name_ok = check_config_exist(cfgname);
  } else if (strlen(basename) == namelen) {
    // second case
    snprintf(cfgname, sizeof(cfgname), "%s%s-%d.xml", cfgdir, progname,
             cgi_contest_id);
    name_ok = check_config_exist(cfgname);
    if (!name_ok) {
      snprintf(cfgname, sizeof(cfgname), "%s%s-%06d.xml", cfgdir, progname,
               cgi_contest_id);
      name_ok = check_config_exist(cfgname);
    }
    if (!name_ok) {
      snprintf(cfgname, sizeof(cfgname), "%s%s.xml", cfgdir, progname);
      name_ok = check_config_exist(cfgname);
    }
    user_contest_id = cgi_contest_id;
  } else {
    // third case
    cgi_contest_id = 0;
    snprintf(cfgname, sizeof(cfgname), "%s%s.xml", cfgdir, basename);
    name_ok = check_config_exist(cfgname);
  }

  if (!name_ok) {
    default_config_str = default_config;
  }
  if (!(config = parse_config(cfgname, default_config_str))) {
    client_not_configured(0, "config file not parsed", 0);
  }

  if (!config->contests_dir ||
      (errcode = contests_set_directory(config->contests_dir)) < 0) {
    fprintf(stderr, "cannot set contests directory '%s': %s\n",
            config->contests_dir, contests_strerror(-errcode));
    client_not_configured(0, "invalid contest information", 0);
  }

  l10n_prepare(config->l10n, config->l10n_dir);

  if (user_contest_id > 0 && contests_get(user_contest_id, &cnts) >= 0) {
    head_style = cnts->register_head_style;
    par_style = cnts->register_par_style;
    table_style = cnts->register_table_style;
    contest_user_name_comment = cnts->user_name_comment;
    disable_member_delete = cnts->disable_member_delete;
    parse_allowed_list(cnts->allowed_languages,
                       &allowed_languages, &allowed_languages_u);
    parse_allowed_list(cnts->allowed_regions,
                       &allowed_regions, &allowed_regions_u);
    logger_set_level(-1, LOG_WARNING);
    if (cnts->register_header_file) {
      generic_read_file(&header_txt, 0, &header_len, 0,
                        0, cnts->register_header_file, "");
    }
    if (cnts->register_footer_file) {
      generic_read_file(&footer_txt, 0, &footer_len, 0,
                        0, cnts->register_footer_file, "");
    }
  }

  if (!head_style) head_style = "h2";
  if (!par_style) par_style = "";
  if (!table_style) table_style = "";
  
  user_ip = parse_client_ip();

  // construct self-reference URL
  {
    unsigned char *http_host = getenv("HTTP_HOST");
    unsigned char *script_name = getenv("SCRIPT_NAME");
    unsigned char *protocol = "http";

    if (getenv("SSL_PROTOCOL") || getenv("HTTPS")) {
      ssl_flag = 1;
      protocol = "https";
    }
    if (!http_host) http_host = "localhost";
    if (!script_name) script_name = "/cgi-bin/register";
    snprintf(fullname, sizeof(fullname), "%s://%s%s", protocol, http_host, script_name);
    self_url = xstrdup(fullname);
  }
}

static int
check_source_ip(void)
{
  struct ip_node *p;

  if (!config->access) return 0;
  if (!user_ip) goto invalid_ip;
  for (p = (struct ip_node*) config->access->b.first_down;
       p; p = (struct ip_node*) p->b.right) {
    if ((user_ip & p->mask) == p->addr) return p->allow;
  }
  return config->access->default_is_allow;

 invalid_ip:
  if (config->access->default_is_allow) return 1;
  return 0;
}

static int
fix_string(unsigned char *buf, unsigned char const *accept_str, int c)
{
  unsigned char *s;
  unsigned char const *q;
  unsigned char flags[256];
  int cnt = 0;

  memset(flags, 0, sizeof(flags));
  for (q = accept_str; *q; q++)
    flags[*q] = 1;

  for (s = buf; *s; s++)
    if (!flags[*s]) {
      cnt++;
      *s = c;
    }
  return cnt;
}

static void
error(char const *format, ...)
{
  va_list args;
  unsigned char buf[1024];
  size_t len;

  va_start(args, format);
  len = vsnprintf(buf, 1000, format, args);
  va_end(args);
  strcpy(buf + len, "\n");
  error_log = xstrmerge1(error_log, buf);
}

static void
client_put_refresh_header(unsigned char const *coding,
                          unsigned char const *url,
                          int interval,
                          unsigned char const *format, ...)
{
  va_list args;

  if (!coding) coding = EJUDGE_CHARSET;

  va_start(args, format);
  fprintf(stdout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\n\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><meta http-equiv=\"Refresh\" content=\"%d; url=%s\"><title>\n", coding, coding, interval, url);
  vfprintf(stdout, format, args);
  fputs("\n</title></head><body><h1>\n", stdout);
  vfprintf(stdout, format, args);
  fputs("\n</h1>\n", stdout);
}

static void
print_choose_language_button(int hr_flag, int no_submit_flag,
                             int action, unsigned char const *label)
{
#if CONF_HAS_LIBINTL - 0 == 1
  if (!label) label = _("Change!");

  if (config->l10n) {
    if (hr_flag) printf("<hr>");
    printf("<%s>%s</%s>\n"
           "%s: <select name=\"locale_id\">"
           "<option value=\"-1\">%s</option>"
           "<option value=\"0\"%s>%s</option>"
           "<option value=\"1\"%s>%s</option>"
           "</select>\n",
           head_style, _("Change language"), head_style,
           _("Change language"),
           _("Default language"),
           client_locale_id==0?" selected=\"1\"":"", _("English"),
           client_locale_id==1?" selected=\"1\"":"", _("Russian"));
    if (!no_submit_flag) {
      printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"/>\n",
             action, label);

    }
  }
#endif /* CONF_HAS_LIBINTL */
}

static int
check_contest_eligibility(int id)
{
  const struct contest_desc *d = 0;

  if (contests_get(id, &d) < 0 || !d) return 0;
  if (d->closed) return 0;
  if (d->reg_deadline && cur_time > d->reg_deadline) return 0;
  return contests_check_register_ip(id, user_ip, ssl_flag);
}

static void
read_locale_id(void)
{
  int x = 0, n = 0;
  unsigned char *s;

  client_locale_id = -1;
  if (!(s = cgi_param("locale_id"))) return;
  if (sscanf(s, "%d %n", &x, &n) != 1 || s[n] || x < -1 || x > 127) return;
  client_locale_id = x;
}
static void
read_usecookies(void)
{
  int x = 0, n = 0;
  unsigned char *s;

  user_usecookies = -1;
  if (!(s = cgi_param("usecookies"))) return;
  if (sscanf(s, "%d %n", &x, &n) != 1 || s[n] || x < -1 || x > 1) return;
  user_usecookies = x;
}

static unsigned char const *
regstatus_str(int status)
{
  static unsigned char buf[64];
  if (status < 0 || status > USERLIST_REG_REJECTED) {
    snprintf(buf, sizeof(buf), "status %d", status);
    return buf;
  }
  return status_str_map[status];
}

static void
prepare_var_table(const struct contest_desc *cnts)
{
  int i, j;

  // initialize field_descs array
  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    if (!field_descs[i].orig_name) continue;
    if (!user_contest_id) {
      field_descs[i].is_editable = 1;
      field_descs[i].is_mandatory = 0;
    } else {
      if (cnts->fields[i]) {
        field_descs[i].is_editable = 1;
        if (cnts->fields[i]->mandatory) {
          field_descs[i].is_mandatory = 1;
        }
      }
    }
  }

  for (i = 0; i < CONTEST_LAST_MEMBER; i++) {
    if (!cnts->members[i]) continue;
    member_min[i] = cnts->members[i]->min_count;
    member_max[i] = cnts->members[i]->max_count;
    member_init[i] = cnts->members[i]->init_count;
    if (member_max[i] <= 0) continue;
    if (!cnts->members[i]->fields) continue;

    for (j = 1; j < CONTEST_LAST_MEMBER_FIELD; j++) {
      if (!cnts->members[i]->fields[j]) continue;
      member_edit_flags[i][j].is_editable = 1;
      if (cnts->members[i]->fields[j]->mandatory) {
        member_edit_flags[i][j].is_mandatory = 1;
      }
    }
  }
}

static unsigned char *
parse_date_from_form(int role, int pers, int field)
{
  unsigned char varname[64];
  unsigned char *val;
  int day, month, year, n;
  struct tm ttm;
  // member_info_%d_%d_%d

  snprintf(varname, sizeof(varname), "member_info_%d_%d_%d_d",
           role, pers, field);
  if (!(val = cgi_param(varname))) goto failed;
  if (sscanf(val, "%d %n", &day, &n) != 1 || val[n] || day <= 0 || day > 31)
    goto failed;

  snprintf(varname, sizeof(varname), "member_info_%d_%d_%d_m",
           role, pers, field);
  if (!(val = cgi_param(varname))) goto failed;
  if (sscanf(val, "%d %n", &month, &n) != 1 || val[n] || month<=0 || month>12)
    goto failed;

  snprintf(varname, sizeof(varname), "member_info_%d_%d_%d_y",
           role, pers, field);
  if (!(val = cgi_param(varname))) goto failed;
  if (sscanf(val, "%d %n", &year, &n) != 1 || val[n] || year<=1900|| year>10000)
    goto failed;

  memset(&ttm, 0, sizeof(ttm));
  ttm.tm_isdst = -1;
  ttm.tm_hour = 12;
  ttm.tm_mday = day;
  ttm.tm_mon = month - 1;
  ttm.tm_year = year - 1900;
  if (mktime(&ttm) == (time_t) -1) goto failed;

  snprintf(varname, sizeof(varname), "%04d/%02d/%02d",
           year, month, day);
  return xstrdup(varname);

 failed:
  return xstrdup("");
}

static void
read_user_info_from_form(void)
{
  int role, pers;
  unsigned char varbuf[128];
  unsigned char *val = 0;
  int x, n, i;
  FILE *lang_f = 0;
  char *lang_s = 0;
  size_t lang_l = 0;
  int lang_t = 0;

  user_show_login = 0;
  user_show_email = 0;
  user_use_cookies_default = 1;

  if ((val = cgi_param("user_registering"))) {
    x = n = 0;
    if (sscanf(val, "%d %n", &x, &n) == 1 && !val[n] && x == 1) {
      user_registering = x;
    }
  }

  user_name = xstrdup(cgi_param("name"));
  if (fix_string(user_name, name_accept_chars, '?')) {
    error("%s", _("Field \"User name\" contained invalid characters, which were replaced with '?'."));
  }
  if (strlen(user_name) >= 128) {
    error("%s", _("Field \"User name\" was too long."));
    user_name[127] = 0;
  }
  user_email = xstrdup(cgi_param("user_email"));
  if (fix_string(user_email, email_accept_chars, '?')) {
    error("%s", _("Field \"User email\" contained invalid characters, which were replaced with '?'."));
  }
  if (strlen(user_email) > 64) {
    error("%s", _("Field \"User email\" was too long."));
    user_email[64] = 0;
  }                       

  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    if (!field_descs[i].orig_name) continue;
    ASSERT(field_descs[i].var);
    ASSERT(field_descs[i].var_name);
    *field_descs[i].var = val = xstrdup(cgi_param(field_descs[i].var_name));
    if (fix_string(val, field_descs[i].accept_chars,
                   field_descs[i].repl_char)) {
      error(_("Field \"%s\" contained invalid characters, which were replaced with '%c'."), gettext(field_descs[i].orig_name), field_descs[i].repl_char);
    }
    if (strlen(val) > field_descs[i].maxlength) {
      error(_("Field \"%s\" was too long."), gettext(field_descs[i].orig_name));
    }
  }

  if (field_descs[CONTEST_F_LANGUAGES].orig_name
      && field_descs[CONTEST_F_LANGUAGES].is_editable
      && allowed_languages
      && allowed_languages_u > 0) {
    lang_f = open_memstream(&lang_s, &lang_l);
    for (i = 0; i < allowed_languages_u; i++) {
      snprintf(varbuf, sizeof(varbuf), "proglang_%d", i);
      if (cgi_param(varbuf)) {
        if (lang_t) fprintf(lang_f, ", ");
        fprintf(lang_f, "%s", allowed_languages[i]);
        lang_t++;
      }
    }
    fclose(lang_f); lang_f = 0;
    if (lang_t) {
      user_languages = lang_s;
    } else {
      xfree(lang_s);
    }
    lang_s = 0;
    lang_l = 0;
  }

  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;
    snprintf(varbuf, sizeof(varbuf), "member_cur_%d", role);
    if (!(val = cgi_param(varbuf))) continue;
    if (sscanf(val, "%d %n", &x, &n) != 1 || val[n]
        || x < 0 || x > member_max[role]) continue;
    member_cur[role] = x;
  }

  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;
    for (pers = 0; pers < member_cur[role]; pers++) {
      // read member serial
      snprintf(varbuf, sizeof(varbuf), "member_info_%d_%d_0", role, pers);
      val = cgi_param(varbuf);
      if (!val || sscanf(val, "%d %n", &x, &n) != 1 || val[n]
          || x <= 0) {
        val = "";
      }
      member_info[role][pers][0] = xstrdup(val);
      for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
        if (!member_edit_flags[role][i].is_editable) continue;
        switch (i) {
        case CONTEST_MF_BIRTH_DATE:
        case CONTEST_MF_ENTRY_DATE:
        case CONTEST_MF_GRADUATION_DATE:
          member_info[role][pers][i] = parse_date_from_form(role, pers, i);
          continue;
        }
        snprintf(varbuf, sizeof(varbuf), "member_info_%d_%d_%d",
                 role, pers, i);
        val = cgi_param(varbuf);
        if (val && i == CONTEST_MF_STATUS) {
          if (sscanf(val, "%d %n", &x, &n) != 1 || val[n]
              || x <= 0 || x >= USERLIST_ST_LAST) {
            val = "";
          }
        } else if (val && i == CONTEST_MF_GRADE) {
          if (sscanf(val, "%d %n", &x, &n) != 1 || val[n]
              || x <= 0 || x >= 100000) {
            val = "";
          }
        }
        member_info[role][pers][i] = val = xstrdup(val);
        if (fix_string(val, member_field_descs[i].accept_chars,
                       member_field_descs[i].repl_char)) {
          error(_("Field \"%s.%d.%s\" contained invalid characters, which were replaced with '%c'."),
                    gettext(member_string[role]), pers + 1,
                    gettext(member_field_descs[i].orig_name),
                    member_field_descs[i].repl_char);
        }
        if (strlen(val) > member_field_descs[i].maxlength) {
          error(_("Field \"%s.%d.%s\" was too long."),
                    gettext(member_string[role]), pers + 1,
                    gettext(member_field_descs[i].orig_name));
        }
      }
    }
  }
}

static void
check_mandatory(const struct contest_desc *cnts)
{
  int i, role, pers;
  unsigned char const *val;

  if (!cnts || !cnts->disable_name) {
    if (!user_name || !*user_name) {
      error("%s", _("Mandatory \"User name\" field is empty."));
    }
  }
  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    if (!field_descs[i].orig_name) continue;
    if (!field_descs[i].is_editable) continue;
    val = *field_descs[i].var;
    if (field_descs[i].is_mandatory && (!val || !*val)) {
      error(_("Mandatory field \"%s\" is empty."),
            gettext(field_descs[i].orig_name));
    }
  }
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;
    if (member_cur[role] < member_min[role]) {
      error(_("Only %d members \"%s\" are specified instead of minimum %d."),
            member_cur[role], gettext(member_string[role]), member_min[role]);
    }
    for (pers = 0; pers < member_cur[role]; pers++) {
      for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
        if (!member_edit_flags[role][i].is_editable) continue;
        val = member_info[role][pers][i];
        if (member_edit_flags[role][i].is_mandatory && (!val || !*val)) {
          error(_("Mandatory field \"%s.%d.%s\" is empty."),
                gettext(member_string[role]), pers + 1,
                gettext(member_field_descs[i].orig_name));
        }
      }
    }
  }
}

static unsigned char const *
unparse_member_status(int s)
{
  static char const * const member_status_map[] =
  {
    "", "schoolchild", "student", "magistrant",
    "phdstudent", "teacher", "professor", "scientist", "other"
  };
  ASSERT(s >= 0 && s <= USERLIST_ST_OTHER);
  return member_status_map[s];
}
static void
do_make_user_xml(FILE *f)
{
  int i, role, pers;
  int x, n;
  unsigned char const *val;

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\"?>\n", EJUDGE_CHARSET);
  fprintf(f, "<user id=\"%d\" use_cookies=\"%s\">\n",
          user_id, xml_unparse_bool(user_use_cookies_default));
  fprintf(f, "  <login public=\"%s\">%s</login>\n",
          xml_unparse_bool(user_show_login), user_login);
  fprintf(f, "  <email public=\"%s\">%s</email>\n",
          xml_unparse_bool(user_show_email), user_email);
  if (user_name && *user_name) {
    fprintf(f, "  <name>%s</name>\n", user_name);
  }
  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    if (!field_descs[i].orig_name) continue;
    if (!field_descs[i].is_editable) continue;
    val = *field_descs[i].var;
    if (!val) val = "";
    fprintf(f, "  <%s>%s</%s>\n",
            field_descs[i].tag_name, val, field_descs[i].tag_name);
  }
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;
    if (member_cur[role] <= 0) continue;
    fprintf(f, "  <%s>\n", member_role_map[role]);
    for (pers = 0; pers < member_cur[role]; pers++) {
      val = member_info[role][pers][0];
      if (!val || sscanf(val, "%d %n", &x, &n) != 1 || val[n]
          || x <= 0) {
        val = "";
      }
      if (!*val) {
        fprintf(f, "    <member>\n");
      } else {
        fprintf(f, "    <member serial=\"%s\">\n", val);
      }
      for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
        if (!member_edit_flags[role][i].is_editable) continue;
        val = member_info[role][pers][i];
        if (!val) val = "";
        switch (i) {
        case CONTEST_MF_BIRTH_DATE:
        case CONTEST_MF_ENTRY_DATE:
        case CONTEST_MF_GRADUATION_DATE:
          if (!val || !*val) continue;
          break;
        case CONTEST_MF_STATUS:
          x = 0;
          if (sscanf(val, "%d %n", &x, &n) != 1 || val[n] ||
              x < 0 || x > USERLIST_ST_OTHER) {
            x = 0;
          }
          val = unparse_member_status(x);
          break;
        }
        fprintf(f, "      <%s>%s</%s>\n",
                member_field_descs[i].tag_name, val,
                member_field_descs[i].tag_name);
      }
      fprintf(f, "    </member>\n");
    }
    fprintf(f, "  </%s>\n", member_role_map[role]);    
  }
  fputs("</user>\n", f);
}

static unsigned char *
make_user_xml(void)
{
  FILE *f = 0;
  char *xml_ptr = 0;
  size_t xml_size = 0;

  if (!(f = open_memstream(&xml_ptr, &xml_size)))
    goto out_of_mem;
  do_make_user_xml(f);
  if (ferror(f)) goto out_of_mem;
  fclose(f);
  return xml_ptr;

 out_of_mem:
  error("%s", _("Internal error: insufficient memory."));
  if (f) fclose(f);
  if (xml_ptr) xfree(xml_ptr);
  return 0;
}

static int
read_user_info_from_server(void)
{
  unsigned char *user_info_xml = 0;
  struct userlist_user *u = 0;
  struct userlist_member *m;
  struct userlist_contest *reg;
  int role, pers, errcode;
  unsigned char buf[512];
  unsigned char dbuf[64];

  error_log = 0;
  if ((errcode = userlist_clnt_get_info(server_conn, ULS_GET_USER_INFO,
                                        user_id, user_contest_id,
                                        &user_info_xml)) < 0) {
    error("%s", gettext(userlist_strerror(-errcode)));
  }
  if (!error_log && !(u = userlist_parse_user_str(user_info_xml))) {
    error("%s", _("XML parse error"));
  }
  if (error_log) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id, _("Fatal error"));
    printf("<p%s>%s.</p><font color=\"red\"><pre>%s</pre></font>\n",
           par_style,
           _("Failed to read information from the server"), error_log);
    return -1;
  }

  ASSERT(u->id == user_id);
  user_xml = u;
  user_show_email = 0;
  user_use_cookies_default = 1;
  user_show_login = 0;
  user_read_only = u->read_only;
  user_email = u->email;
  user_name = u->i.name;
  user_homepage = u->i.homepage;
  user_phone = u->i.phone;
  user_inst = u->i.inst;
  user_inst_en = u->i.inst_en;
  user_instshort = u->i.instshort;
  user_instshort_en = u->i.instshort_en;
  user_fac = u->i.fac;
  user_fac_en = u->i.fac_en;
  user_facshort = u->i.facshort;
  user_facshort_en = u->i.facshort_en;
  user_city = u->i.city;
  user_city_en = u->i.city_en;
  user_country = u->i.country;
  user_country_en = u->i.country_en;
  user_languages = u->i.languages;
  user_region = u->i.region;

  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;
    if (!u->i.members[role]) {
      if (member_cur[role] < member_init[role]) {
        member_cur[role] = member_init[role];
      }
      continue;
    }
    member_cur[role] = u->i.members[role]->total;
    if (member_cur[role] < 0) member_cur[role] = 0;
    if (member_cur[role] > member_max[role])
      member_cur[role] = member_max[role];
    for (pers = 0; pers < member_cur[role]; pers++) {
      m = u->i.members[role]->members[pers];
      if (!m) continue;

      buf[0] = 0;
      if (m->serial > 0) {
        snprintf(buf, sizeof(buf), "%d", m->serial);
      }
      member_info[role][pers][CONTEST_MF_SERIAL] = xstrdup(buf);
      if (member_edit_flags[role][CONTEST_MF_FIRSTNAME].is_editable) {
        member_info[role][pers][CONTEST_MF_FIRSTNAME] = m->firstname;
      }
      if (member_edit_flags[role][CONTEST_MF_FIRSTNAME_EN].is_editable) {
        member_info[role][pers][CONTEST_MF_FIRSTNAME_EN] = m->firstname_en;
      }
      if (member_edit_flags[role][CONTEST_MF_MIDDLENAME].is_editable) {
        member_info[role][pers][CONTEST_MF_MIDDLENAME] = m->middlename;
      }
      if (member_edit_flags[role][CONTEST_MF_MIDDLENAME_EN].is_editable) {
        member_info[role][pers][CONTEST_MF_MIDDLENAME_EN] = m->middlename_en;
      }
      if (member_edit_flags[role][CONTEST_MF_SURNAME].is_editable) {
        member_info[role][pers][CONTEST_MF_SURNAME] = m->surname;
      }
      if (member_edit_flags[role][CONTEST_MF_SURNAME_EN].is_editable) {
        member_info[role][pers][CONTEST_MF_SURNAME_EN] = m->surname_en;
      }
      if (member_edit_flags[role][CONTEST_MF_STATUS].is_editable) {
        buf[0] = 0;
        if (m->status > 0 && m->status < USERLIST_ST_LAST) {
          snprintf(buf, sizeof(buf), "%d", m->status);
        }
        member_info[role][pers][CONTEST_MF_STATUS] = xstrdup(buf);
      }
      if (member_edit_flags[role][CONTEST_MF_GRADE].is_editable) {
        buf[0] = 0;
        if (m->grade > 0 && m->grade < 100000) {
          snprintf(buf, sizeof(buf), "%d", m->grade);
        }
        member_info[role][pers][CONTEST_MF_GRADE] = xstrdup(buf);
      }
      if (member_edit_flags[role][CONTEST_MF_GROUP].is_editable) {
        member_info[role][pers][CONTEST_MF_GROUP] = m->group;
      }
      if (member_edit_flags[role][CONTEST_MF_GROUP_EN].is_editable) {
        member_info[role][pers][CONTEST_MF_GROUP_EN] = m->group_en;
      }
      if (member_edit_flags[role][CONTEST_MF_EMAIL].is_editable) {
        member_info[role][pers][CONTEST_MF_EMAIL] = m->email;
      }
      if (member_edit_flags[role][CONTEST_MF_HOMEPAGE].is_editable) {
        member_info[role][pers][CONTEST_MF_HOMEPAGE] = m->homepage;
      }
      if (member_edit_flags[role][CONTEST_MF_PHONE].is_editable) {
        member_info[role][pers][CONTEST_MF_PHONE] = m->phone;
      }
      if (member_edit_flags[role][CONTEST_MF_INST].is_editable) {
        member_info[role][pers][CONTEST_MF_INST] = m->inst;
      }
      if (member_edit_flags[role][CONTEST_MF_INST_EN].is_editable) {
        member_info[role][pers][CONTEST_MF_INST_EN] = m->inst_en;
      }
      if (member_edit_flags[role][CONTEST_MF_INSTSHORT].is_editable) {
        member_info[role][pers][CONTEST_MF_INSTSHORT] = m->instshort;
      }
      if (member_edit_flags[role][CONTEST_MF_INSTSHORT_EN].is_editable) {
        member_info[role][pers][CONTEST_MF_INSTSHORT_EN] = m->instshort_en;
      }
      if (member_edit_flags[role][CONTEST_MF_FAC].is_editable) {
        member_info[role][pers][CONTEST_MF_FAC] = m->fac;
      }
      if (member_edit_flags[role][CONTEST_MF_FAC_EN].is_editable) {
        member_info[role][pers][CONTEST_MF_FAC_EN] = m->fac_en;
      }
      if (member_edit_flags[role][CONTEST_MF_FACSHORT].is_editable) {
        member_info[role][pers][CONTEST_MF_FACSHORT] = m->facshort;
      }
      if (member_edit_flags[role][CONTEST_MF_FACSHORT_EN].is_editable) {
        member_info[role][pers][CONTEST_MF_FACSHORT_EN] = m->facshort_en;
      }
      if (member_edit_flags[role][CONTEST_MF_OCCUPATION].is_editable) {
        member_info[role][pers][CONTEST_MF_OCCUPATION] = m->occupation;
      }
      if (member_edit_flags[role][CONTEST_MF_OCCUPATION_EN].is_editable) {
        member_info[role][pers][CONTEST_MF_OCCUPATION_EN] = m->occupation_en;
      }
      if (member_edit_flags[role][CONTEST_MF_BIRTH_DATE].is_editable) {
        if (!m->birth_date)
          member_info[role][pers][CONTEST_MF_BIRTH_DATE] = xstrdup("");
        else
          member_info[role][pers][CONTEST_MF_BIRTH_DATE] = xstrdup(userlist_unparse_date_2(dbuf, sizeof(dbuf), m->birth_date, 0));
      }
      if (member_edit_flags[role][CONTEST_MF_ENTRY_DATE].is_editable) {
        if (!m->entry_date)
          member_info[role][pers][CONTEST_MF_ENTRY_DATE] = xstrdup("");
        else
          member_info[role][pers][CONTEST_MF_ENTRY_DATE] = xstrdup(userlist_unparse_date_2(dbuf, sizeof(dbuf), m->entry_date, 0));
      }
      if (member_edit_flags[role][CONTEST_MF_GRADUATION_DATE].is_editable) {
        if (!m->graduation_date)
          member_info[role][pers][CONTEST_MF_GRADUATION_DATE] = xstrdup("");
        else
          member_info[role][pers][CONTEST_MF_GRADUATION_DATE] = xstrdup(userlist_unparse_date_2(dbuf, sizeof(dbuf), m->graduation_date, 0));
      }
    }
    if (!member_cur[role]) member_cur[role] = member_init[role];
    /*
    if (member_cur[role] < member_init[role]) {
      member_cur[role] = member_init[role];
    }
    */
  }

  user_already_registered = 0;
  if (u->contests && user_contest_id > 0) {
    for (reg = FIRST_CONTEST(u); reg; reg = NEXT_CONTEST(reg)) {
      if (reg->id == user_contest_id) break;
    }
    if (reg) user_already_registered = 1;
  }
  return 0;
}

static int
authentificate(void)
{
  unsigned char *sid_str = 0;
  ej_cookie_t sid_value = 0;
  int n = 0, errcode;
  int new_user_id = 0, new_locale_id = 0, new_contest_id = 0;
  unsigned char *new_login = 0, *new_name = 0;

  if (!(sid_str = cgi_param("SID"))) goto failed;
  if (sscanf(sid_str, "%llx%n", &sid_value, &n) != 1) goto failed;
  if (sid_str[n] || !sid_value) goto failed;
  if (!server_conn) {
    server_conn = userlist_clnt_open(config->socket_path);
  }
  if (!server_conn) {
    fprintf(stderr, "connection to server failed\n");
    goto failed;
  }
  errcode = userlist_clnt_lookup_cookie(server_conn, user_ip, ssl_flag,
                                        sid_value,
                                        &new_user_id,
                                        &new_login,
                                        &new_name,
                                        &new_locale_id,
                                        &new_contest_id);
  if (errcode != ULS_LOGIN_COOKIE) {
    fprintf(stderr, "login failed: %s", userlist_strerror(-errcode));
    goto failed;
  }

  user_login = new_login;
  user_id = new_user_id;
  user_name = new_name;
  user_cookie = sid_value;
  if (client_locale_id == -1) client_locale_id = new_locale_id;
  if (client_locale_id == -1) client_locale_id = 0;
  /*
  if (user_contest_id <= 0 && new_contest_id > 0)
    user_contest_id = new_contest_id;
  */
  return 1;

 failed:
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, _("Authentification failed"));
  printf("<p%s>%s.</p>\n", par_style,
         _("Authentification failed for some reason"));
  return 0;
}

static void
map_user_languages(const unsigned char *user_langs, int **pmap)
{
  int *map = 0;
  unsigned char **langs = 0;
  size_t langs_u = 0;
  int i, j;

  *pmap = 0;
  if (!allowed_languages || !allowed_languages_u) return;
  XCALLOC(map, allowed_languages_u);
  *pmap = map;

  parse_allowed_list(user_langs, &langs, &langs_u);
  if (!langs || !langs_u) return;
  for (i = 0; i < allowed_languages_u; i++) {
    for (j = 0; j < langs_u; j++)
      if (!strcmp(allowed_languages[i], langs[j]))
        break;
    if (j < langs_u)
      map[i] = 1;
  }
}

static const unsigned char * const month_names[] =
{
  "",
  __("Jan"), __("Feb"), __("Mar"), __("Apr"), __("May"), __("Jun"),
  __("Jul"), __("Aug"), __("Sep"), __("Oct"), __("Nov"), __("Dec"),
};

static void
display_date_change_dialog(int role, int pers, int field)
{
  unsigned char *val;
  int day = 0, month = 0, year = 0, n;
  unsigned char vbuf[128];
  const unsigned char *sstr = " selected=\"1\"";
  const unsigned char *s = "";

  printf("<p%s>%s%s: ",
         par_style, gettext(member_field_descs[field].orig_name),
         member_edit_flags[role][field].is_mandatory?" (*)":"");
  val = member_info[role][pers][field];
  if (!val) val = "";
  if (user_read_only) {
    printf("<tt>%s</tt></p>", val);
    return;
  }
  if (sscanf(val, "%d/%d/%d%n", &year, &month, &day, &n) != 3 || val[n]
      || year <= 1900 || year >= 10000 || month < 0 || month > 12
      || day < 0 || day > 31) {
    day = month = year = 0;
  }

  // day selection
  s = "";
  if (!day) s = sstr;
  printf("<select name=\"member_info_%d_%d_%d_d\"><option%s></option>",
         role, pers, field, s);
  for (n = 1; n <= 31; n++) {
    s = "";
    if (day == n) s = sstr;
    printf("<option%s>%d</option>", s, n);
  }
  printf("</select>\n");

  // month selection
  s = "";
  if (!month) s = sstr;
  printf("<select name=\"member_info_%d_%d_%d_m\"><option value=\"0\"%s></option>",
         role, pers, field, s);
  for (n = 1; n <= 12; n++) {
    s = "";
    if (month == n) s = sstr;
    printf("<option value=\"%d\"%s>%s</option>", n, s,
           gettext(month_names[n]));
  }
  printf("</select>\n");

  vbuf[0] = 0;
  if (year > 0) snprintf(vbuf, sizeof(vbuf), "%d", year);
  printf("<input type=\"text\" name=\"member_info_%d_%d_%d_y\" value=\"%s\" maxlength=\"4\" size=\"4\"/></p>", role, pers, field, vbuf);
}

static void
display_edit_registration_data_page(void)
{
  const struct contest_desc *cnts = 0;
  int errcode, role, pers, i, user_show_all = 0, j;
  unsigned char *user_name_arm;
  unsigned char *cnts_name_arm, *cnts_name_loc;
  char const *dis_str = " disabled=\"yes\"";
  unsigned char s1[128], url[512];
  int *user_lang_map = 0;
  unsigned char *s;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (!authentificate()) goto done;

  /* ??? */
  if (cgi_param("show_all")) {
    user_show_all = 1;
  }

  /* FIXME: not sure, whether this will work with user_contest_id == 0... */
  if (user_contest_id <= 0) {
    client_put_header(stdout, header_txt, config->charset, 0, 1,
                      client_locale_id, "%s", _("Invalid contest identifier"));
    goto done;
  }

  if (user_contest_id > 0) {
    if ((errcode = contests_get(user_contest_id, &cnts)) < 0) {
      fprintf(stderr, "invalid contest %d: %s", user_contest_id,
              contests_strerror(-errcode));
      client_put_header(stdout, header_txt, 0, config->charset, 1,
                        client_locale_id, "%s", _("Invalid contest"));
      printf("<p>%s</p>.", _("Invalid contest identifier specified"));
      goto done;
    }
  }
  ASSERT(cnts);

  if (!check_contest_eligibility(cnts->id)) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id, "%s", _("Permission denied"));
    printf("<p>%s</p>.", _("You cannot participate in this contest"));
    goto done;
  }

  prepare_var_table(cnts);
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;
    member_info[role] = xcalloc(member_max[role],
                                sizeof(member_info[0][0]));
    for (pers = 0; pers < member_max[role]; pers++) {
      member_info[role][pers] = xcalloc(CONTEST_LAST_MEMBER_FIELD,
                                        sizeof(member_info[0][0][0]));
    }
  }

  /* request the necessary information from server */
  /* or read the information from form variables */
  switch (user_action) {
  case STATE_EDIT_REGISTRATION_DATA:
    if (read_user_info_from_server() < 0) goto done;
    break;
  default:
    read_user_info_from_form();
    break;
  }

  if (user_action >= ACTION_ADD_NEW_CONTESTANT
      && user_action <= ACTION_ADD_NEW_GUEST) {
    role = user_action - ACTION_ADD_NEW_CONTESTANT;
    if (member_cur[role] >= member_max[role]) {
      client_put_header(stdout, header_txt, 0, config->charset, 1,
                        client_locale_id, "%s", _("Cannot add a new member"));
      printf("<p%s>%s %s: %s.</p>\n",
             par_style, _("Cannot add a new"),
             gettext(member_string[role]),
             _("maximal number reached"));
      goto done;
    }

    member_cur[role]++;
  }

  /* make empty strings for the remaining */
  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    if (!field_descs[i].is_editable) continue;
    if (!*field_descs[i].var) {
      *field_descs[i].var = xstrdup("");
    }
  }
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    for (pers = 0; pers < member_cur[role]; pers++) {
      if (!member_info[role][pers][0]) {
        member_info[role][pers][0] = xstrdup("");
      }
      for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
        if (!member_edit_flags[role][i].is_editable) continue;
        if (!member_info[role][pers][i]) {
          member_info[role][pers][i] = xstrdup("");
        }
      }
    }
  }

  {
    unsigned char *disp_name = user_name;
    if (!disp_name || !*disp_name) disp_name = user_login;
    ARMOR_STR(user_name_arm, disp_name);
  }
  cnts_name_loc = 0;
  if (!client_locale_id) {
    cnts_name_loc = cnts->name_en;
    if (!cnts_name_loc) cnts_name_loc = cnts->name;
  } else {
    cnts_name_loc = cnts->name;
    if (!cnts_name_loc) cnts_name_loc = cnts->name_en;
  }
  ARMOR_STR(cnts_name_arm, cnts->name);

  //l10n_setlocale(client_locale_id);

  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, _("User %s: registration for %s"),
                    user_name_arm, cnts_name_arm);
  {
    unsigned char *s1, *s2 ,*s3;

    if (user_already_registered) {
      s1 = _("You have already registered for this contest.");
    } else {
      s1 = _("You may register for this contest.");
    }
    if (user_read_only) {
      s2 = _("You may not edit your personal information.");
    } else {
      s2 = _("You may edit your personal information.");
    }
    if (!user_already_registered && !user_read_only) {
      s3 = _("Please fill up blank fields in this form. Mandatory fields "
             "are marked with (*).");
    } else {
      s3 = "";
    }

    printf("<h3>%s</h3>\n<h3>%s</h3>\n<p%s>%s</p>\n", s1, s2, par_style, s3);
  }

  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  printf("<input type=\"hidden\" name=\"SID\" value=\"%llx\"/>\n"
         "<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n"
         "<input type=\"hidden\" name=\"locale_id\" value=\"%d\"/>\n",
         user_cookie, user_contest_id, client_locale_id);

  printf("<hr><%s>%s</%s>", head_style, _("General user information"),
         head_style);
  printf("<p%s>%s: <input type=\"text\" disabled=\"1\" name=\"user_login\" value=\"%s\" size=\"16\"/>\n", par_style, _("Login"), user_login);

  printf("<input type=\"hidden\" name=\"user_email\" value=\"%s\"/>\n",
         user_email);
  printf("<p%s>%s: <a href=\"mailto:%s\">%s</a>\n", par_style, _("E-mail"),
         user_email, user_email);

  if (!cnts || !cnts->disable_name) {
    printf("<p%s>%s</p>\n", par_style, _("In the next field type the name, which will be used in standings, personal information display, etc."));
    if (contest_user_name_comment) {
      printf("<p%s>%s</p>\n", par_style, contest_user_name_comment);
    }
    printf("<p%s>%s%s: <input type=\"text\" name=\"name\" value=\"%s\" maxlength=\"64\" size=\"64\"%s/>\n", par_style, _("User name"), user_contest_id>0?" (*)":"", user_name, user_read_only?dis_str:"");
  }

  /* display change forms */
  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    if (!field_descs[i].is_editable) continue;
    if (i == CONTEST_F_LANGUAGES && allowed_languages_u > 0) {
      map_user_languages(user_languages, &user_lang_map);
      printf("<p%s>%s%s:\n", par_style, gettext(field_descs[i].orig_name),
             field_descs[i].is_mandatory?" (*)":"");

      printf("<table border=\"0\">\n");
      for (j = 0; j < allowed_languages_u; j++) {
        printf("<tr><td><input type=\"checkbox\" name=\"proglang_%d\"%s%s/></td>"
               "<td>%s</td></tr>\n",
               j, user_lang_map[j]?" checked=\"yes\"":"",
               user_read_only? dis_str : "",
               ARMOR(allowed_languages[j]));
      }
      printf("</table>\n");
      continue;
    }
    if (i == CONTEST_F_REGION && allowed_regions_u > 0) {
      printf("<p%s>%s%s:\n", par_style, gettext(field_descs[i].orig_name),
             field_descs[i].is_mandatory?" (*)":"");
      printf("<select name=\"region\"><option></option>");
      for (j = 0; j < allowed_regions_u; j++) {
        s = "";
        if (!strcmp(user_region, allowed_regions[j]))
          s = " selected=\"yes\"";
        printf("<option%s>%s</option>", s, ARMOR(allowed_regions[j]));
      }
      printf("</select>\n");
      continue;
    }

    printf("<p%s>%s%s: <input type=\"text\" name=\"%s\" value=\"%s\" maxlength=\"%d\" size=\"%d\"%s/>\n",
           par_style,
           gettext(field_descs[i].orig_name),
           field_descs[i].is_mandatory?" (*)":"",
           field_descs[i].var_name,
           *field_descs[i].var,
           field_descs[i].maxlength,
           field_descs[i].size,
           user_read_only?dis_str:"");

    if (i == CONTEST_F_INST) {
      printf("<p%s>%s</p>", par_style, 
             _("For schools, liceums, etc, please, specify its number."));
    }
  }

  /* */
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;

    printf("<%s>%s: %s</%s>\n", head_style, _("Member information"),
           gettext(member_string_pl[role]), head_style);
    if (member_cur[role] != member_min[role] || member_cur[role] != member_max[role]) {
      printf(_("<p%s>The current number of %s is %d.</p>\n"), par_style,
             gettext(member_string_pl[role]), member_cur[role]);
      printf(_("<p%s>The minimal number of %s is %d.</p>\n"), par_style,
             gettext(member_string_pl[role]), member_min[role]);
      printf(_("<p%s>The maximal number of %s is %d.</p>\n"), par_style,
             gettext(member_string_pl[role]), member_max[role]);
    }
    printf("<input type=\"hidden\" name=\"member_cur_%d\" value=\"%d\"/>\n",
           role, member_cur[role]);

    for (pers = 0; pers < member_cur[role]; pers++) {
      printf("<h3>%s %d</h3>\n", gettext(member_string[role]), pers + 1);
      if (!user_read_only && !disable_member_delete) {
        printf("<p%s><input type=\"submit\" name=\"remove_%d_%d\" value=\"%s\"/>%s</p>\n",
               par_style,
               role, pers,
               _("Remove member"),
               _("<b>Note!</b> All uncommited changes will be lost!"));
      }
      if (*member_info[role][pers][0]) {
        printf("<p%s>%s %s.</p>", par_style,
               _("Member serial number is"), member_info[role][pers][0]);
        printf("<input type=\"hidden\" name=\"member_info_%d_%d_0\" value=\"%s\"/>\n", role, pers, member_info[role][pers][0]);
      }

      for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
        if (!member_edit_flags[role][i].is_editable) continue;
        if (i == CONTEST_MF_STATUS) {
          int x, n;
          unsigned char const *val;

          printf("<p%s>%s%s: <select name=\"member_info_%d_%d_%d\"%s>\n"
                 "<option value=\"\"></option>\n",
                 par_style, gettext(member_field_descs[i].orig_name),
                 member_edit_flags[role][i].is_mandatory?" (*)":"",
                 role, pers, i,
                 user_read_only?dis_str:"");
          x = 0; n = 0;
          val = member_info[role][pers][i];
          if (!val || sscanf(val, "%d %n", &x, &n) != 1 || val[n]
              || x <= 0 || x >= USERLIST_ST_LAST) {
            x = 0;
          }
          for (n = 1; n < USERLIST_ST_LAST; n++) {
            printf("<option value=\"%d\"%s>%s</option>\n",
                   n, n == x?" selected=\"1\"":"",
                   gettext(member_status_string[n]));
          }
          printf("</select>");
          continue;
        }
        switch (i) {
        case CONTEST_MF_BIRTH_DATE:
        case CONTEST_MF_ENTRY_DATE:
        case CONTEST_MF_GRADUATION_DATE:
          display_date_change_dialog(role, pers, i);
          continue;
        }
        printf("<p%s>%s%s: <input type=\"text\" name=\"member_info_%d_%d_%d\" value=\"%s\" maxlength=\"%d\" size=\"%d\"%s/>\n",
               par_style, gettext(member_field_descs[i].orig_name),
               member_edit_flags[role][i].is_mandatory?" (*)":"",
               role, pers, i,
               member_info[role][pers][i],
               member_field_descs[i].maxlength,
               member_field_descs[i].size,
               user_read_only?dis_str:"");
      }
    }

    if (member_cur[role] < member_max[role]) {
      printf("<p%s><input type=\"submit\" name=\"action_%d\" value=\"%s\"/></p>\n",
             par_style, ACTION_ADD_NEW_CONTESTANT + role, _("Add new member"));
    }
  }

  printf("<%s>%s</%s>\n", head_style, _("Finalize registration"), head_style);

  printf("<input type=\"hidden\" name=\"user_already_registered\" value=\"%d\"/>\n", user_already_registered);
  if (user_show_all) {
    printf("<input type=\"hidden\" name=\"show_all\" value=\"1\"/>\n");
  }

  if (!user_already_registered) {
    printf("<p%s>%s</p>\n", par_style,
           _("Press on the \"Register\" button to commit the entered values to server and register for participation for the chosen contest."));
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"/>\n",
           ACTION_REGISTER_FOR_CONTEST, _("REGISTER!"));
  }
  if (!user_read_only && user_already_registered) {
    printf("<p%s>%s</p>\n", par_style, _("Press on the \"Save\" button to save the entered values on the server."));
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"/>\n",
           ACTION_SAVE_REGISTRATION_DATA, _("Save"));
  }
  printf("</form>\n");

  printf("<p%s>%s</p>\n", par_style, _("Press on the \"Back\" button to return to the previous page without saving all your changes."));
  *s1 = 0;
  if (!user_show_all) {
    snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?action=%d&SID=%llx&locale_id=%d%s",
           self_url, STATE_MAIN_PAGE, user_cookie, client_locale_id, s1);
  printf("<p%s><a href=\"%s\">%s</a></p>\n", par_style, url, _("Back"));

  printf("<%s>%s</%s>\n", head_style, _("Quit the system"), head_style);
  snprintf(url, sizeof(url), "%s?action=%d&SID=%llx&locale_id=%d%s",
           self_url, ACTION_LOGOUT, user_cookie, client_locale_id, s1);
  printf("<p%s><a href=\"%s\">%s</a></p>\n", par_style, url, _("Logout"));

#if 0
  print_choose_language_button(0, 1, 0, 0);
  printf("</form>");
#endif

 done:
  html_armor_free(&ab);
}

/* contains "change language", "login", "register new" buttons */
/* default page */
static void
display_initial_page(void)
{
  unsigned char s1[128], s2[128], url[1024];

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);

  //printf("Set-cookie: ID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, "%s", _("Log into the system"));

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, name_accept_chars, '?');
  user_password = xstrdup("");

  /* change language */
  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n",
           user_contest_id);
  }
  if (user_login && *user_login) {
    printf("<input type=\"hidden\" name=\"login\" value=\"%s\"/>\n",
           user_login);
  }
  print_choose_language_button(0, 0, ACTION_CHANGE_LANG_AT_INITIAL, 0);
  printf("</form>\n");

  /* login */
  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n",
           user_contest_id);
  }
  if (client_locale_id >= 0) {
    printf("<input type=\"hidden\" name=\"locale_id\" value=\"%d\"/>\n",
           client_locale_id);
  }
  printf("<input type=\"hidden\" name=\"usecookies\" value=\"1\"/>\n");
  printf("<%s>%s</%s><p%s>%s</p>\n",
         head_style, _("For registered users"), head_style, par_style,
         _("If you have registered before, please enter your "
           "login and password in the corresponding fields. "
           "Then press the \"Submit\" button."));
  printf("<p%s>%s: <input type=\"text\" name=\"login\" value=\"%s\""
         " size=\"16\" maxlength=\"16\"/>\n",
         par_style, _("Login"), user_login);
  printf("<p%s>%s: <input type=\"password\" name=\"password\" value=\"%s\""
         " size=\"16\" maxlength=\"16\"/>\n",
         par_style, _("Password"), user_password);

  printf("<p%s><input type=\"submit\" name=\"action_%d\" value=\"%s\"/>",
         par_style, ACTION_LOGIN, _("Submit"));
  printf("</form>");

  *s1 = 0;
  if (user_login && *user_login) {
    snprintf(s1, sizeof(s1), "&login=%s", user_login);
  }
  *s2 = 0;
  if (user_contest_id > 0) {
    snprintf(s2, sizeof(s2), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?action=%d&locale_id=%d%s%s",
           self_url, STATE_REGISTER_NEW_USER, client_locale_id, s1, s2);
  printf("<%s>%s</%s>\n", head_style, _("For new users"), head_style);
  printf(_("<p%s>If you have not registered before, please <a href=\"%s\">register</a>.</p>\n"), par_style, url);
}

/* contains "change language", "login" */
/* page code: STATE_LOGIN */
static void
display_login_page(void)
{
  int next_action;

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);

  //printf("Set-cookie: ID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id,
                    "%s", _("Log into the system"));

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, name_accept_chars, '?');
  user_password = xstrdup("");

  /* change language */
  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n",
           user_contest_id);
  }
  if (user_login && *user_login) {
    printf("<input type=\"hidden\" name=\"login\" value=\"%s\"/>\n",
           user_login);
  }
  next_action = ACTION_CHANGE_LANG_AT_LOGIN;
  if (user_action == STATE_LOGIN_FORCED_REG)
    next_action = ACTION_CHANGE_LANG_AT_LOGIN_FORCED_REG;
  print_choose_language_button(0, 0, next_action, 0);
  printf("</form>\n");

  /* login */
  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n",
           user_contest_id);
  }
  printf("<input type=\"hidden\" name=\"locale_id\" value=\"%d\"/>\n",
         client_locale_id);
  printf("<p%s>%s</p>\n", par_style,
         _("Type your login and password and then press \"Submit\" button"));
  printf("<p%s>%s: <input type=\"text\" name=\"login\" value=\"%s\""
           " size=\"16\" maxlength=\"16\"/>\n",
         par_style, _("Login"), user_login);
  printf("<p%s>%s: <input type=\"password\" name=\"password\" value=\"%s\""
         " size=\"16\" maxlength=\"16\"/>\n",
         par_style, _("Password"), user_password);

  next_action = ACTION_LOGIN;
  if (user_action == STATE_LOGIN_FORCED_REG)
    next_action = ACTION_LOGIN_FORCED_REG;
  printf("<p%s><input type=\"submit\" name=\"action_%d\" value=\"%s\"/>",
         par_style, next_action, _("Submit"));
  printf("</form>");
}

/* contains "change language", "register new" */
/* page code: STATE_REGISTER_NEW_USER */
static void
display_register_new_user_page(void)
{
  const struct contest_desc *cnts = 0;

  if (user_contest_id > 0) {
    contests_get(user_contest_id, &cnts);
  }

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, login_accept_chars, '?');
  if (!(user_email = cgi_param("email"))) {
    user_email = xstrdup("");
  }
  fix_string(user_email, email_accept_chars, '?');

  //printf("Set-cookie: ID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, "%s", _("Register a new user"));

  /* change language */
  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n",
           user_contest_id);
  }
  if (user_login && *user_login) {
    printf("<input type=\"hidden\" name=\"login\" value=\"%s\"/>\n",
           user_login);
  }
  if (user_email && *user_email) {
    printf("<input type=\"hidden\" name=\"email\" value=\"%s\"/>\n",
           user_email);
  }
  print_choose_language_button(0,0,ACTION_CHANGE_LANG_AT_REGISTER_NEW_USER,0);
  printf("</form>\n");

  /* register new user */
  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n",
           user_contest_id);
  }
  printf("<input type=\"hidden\" name=\"locale_id\" value=\"%d\"/>\n",
         client_locale_id);

  printf("<%s>%s</%s><p%s>%s</p><p%s>%s</p>\n",
         head_style, _("Registration rules"), head_style, par_style,
         _("Please, fill up all the fields in the form below. "
           "Fields, marked with (*), are mandatory. "
           "When the form is completed, press \"Register\" button."),
         par_style,
         _("Shortly after that you should receive an e-mail message "
           "with a password to the system. Use this password for the first "
           " login. "
           "<b>Note</b>, that you must log in "
           "24 hours after the form is filled and submitted, or "
           "your registration will be void!"));
  if (!cnts || !cnts->assign_logins) {
    printf("<p%s>%s</p>", par_style,
           _("Type in a desirable login identifier. <b>Note</b>, "
             "that your login still <i>may be</i> (in some cases) assigned "
             "automatically."));
    printf("<p%s>%s (*): <input type=\"text\" name=\"login\" value=\"%s\""
           " size=\"16\" maxlength=\"16\"/>\n",
           par_style, _("Login"), user_login);
  }
  printf("<p%s>%s</p>", par_style, _("Type your valid e-mail address"));
  printf("<p%s>%s (*): <input type=\"text\" name=\"email\" value=\"%s\""
         " size=\"64\" maxlength=\"64\"/>\n",
         par_style, _("E-mail"), user_email);
  printf("<p%s><input type=\"submit\" name=\"action_%d\" value=\"%s\"/>",
         par_style, ACTION_REGISTER_NEW_USER, _("Register"));

  printf("</form>");

  if (cnts && cnts->assign_logins && cnts->force_registration
      && cnts->team_url) {
    printf(_("<p%s>If you are already registered, you may proceed to <a href=\"%s?contest_id=%d&locale_id=%d\">personal page</a>.</p>"),
           par_style, cnts->team_url, user_contest_id, client_locale_id);
  }
}

static void
display_user_registered_page(void)
{
  unsigned char s1[128], url[512];
  const struct contest_desc *cnts = 0;
  int action = ACTION_LOGIN;

  if (user_contest_id > 0 && contests_get(user_contest_id, &cnts) >= 0
      && cnts && cnts->force_registration)
    action = ACTION_LOGIN_FORCED_REG;

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, login_accept_chars, '?');
  if (!(user_email = cgi_param("email"))) {
    user_email = xstrdup("");
  }
  fix_string(user_email, email_accept_chars, '?');

  *s1 = 0;
  if (user_contest_id > 0) {
    snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?login=%s&action=%d%s&locale_id=%d",
           self_url, user_login, action, s1, client_locale_id);

  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id,"%s", _("User registration is complete"));

  printf(_("<p%s>Registration of a new user is completed successfully. "
           "An e-mail messages is sent to the address <tt>%s</tt>. "
           "This message contains the login name, assigned to you, "
           "as well as your password for initial login. "
           "To proceed with registration, clink <a href=\"%s\">on this link</a>.</p>"
           "<p%s><b>Note</b>, that you should login to the system for "
           "the first time no later, than in 24 hours after the initial "
           "user registration, or the registration is void."),
         par_style, user_email, url, par_style);
}

static void
display_user_registered_page_2(void)
{
  unsigned char *txt1, *txt2, *txt3;
  const struct contest_desc *cnts = 0;

  if (user_contest_id <= 0 || contests_get(user_contest_id, &cnts) < 0
      || !cnts || !cnts->simple_registration) {
    // permission denied
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id, "%s", _("Permission denied"));
    printf("<h1>You don't fool me!</h1>\n");
    client_put_footer(stdout, footer_txt);
    exit(0);
  }

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  txt1 = html_armor_string_dup(user_login);
  fix_string(user_login, login_accept_chars, '?');
  if (!(user_email = cgi_param("email"))) {
    user_email = xstrdup("");
  }
  txt2 = html_armor_string_dup(user_email);
  fix_string(user_email, email_accept_chars, '?');
  if (!(user_password = cgi_param("password"))) {
    user_password = xstrdup("");
  }
  txt3 = html_armor_string_dup(user_password);

  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id,"%s", _("Step 1 of registration is complete"));

  printf(_("<p%s>New user account is created successfully. "
           "An initial password is generated automatically, "
           "you will be able to change it later.\n"
           "<p%s>The new account is as follows:\n"), par_style, par_style);
  printf("<table border=\"0\">\n"
         "<tr><td>%s</td><td><tt>%s</tt></td></tr>\n"
         "<tr><td>%s</td><td><tt>%s</tt></td></tr>\n"
         "<tr><td>%s</td><td><tt>%s</tt></td></tr>\n"
         "</table>\n", _("Login"), txt1, _("E-mail"), txt2,
         _("Password"), txt3);

  printf(_("<p%s>Remember or write down the password!."), par_style);

  printf(_("<p%s>Press the &quot;Next&quot; button to continue registration."),
         par_style);

  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n",
         user_contest_id);
  printf("<input type=\"hidden\" name=\"locale_id\" value=\"%d\"/>\n",
         client_locale_id);
  printf("<input type=\"hidden\" name=\"login\" value=\"%s\"/>\n",
         user_login);
  printf("<input type=\"hidden\" name=\"password\" value=\"%s\"/>\n",
         user_password);
  printf("<p%s><input type=\"submit\" name=\"action_%d\" value=\"%s\"/>",
         par_style, ACTION_LOGIN, _("Next"));
  printf("</form>");
}

static void
display_main_page(void)
{
  int errcode, armored_len = 0, need_team_btn = 0, i;
  unsigned char *act_name, *armored_str, *xml_text;
  struct xml_tree *regs, *reg;
  struct userlist_contest *regx;
  const struct contest_desc *cnts;
  unsigned char s1[64], url[512];
  int cnts_total = 0, cnts_used = 0;
  int *cnts_ids = 0;
  unsigned char *cnts_map = 0;
  unsigned char *cnts_name_loc;

  if (!authentificate()) return;
  ASSERT(server_conn);

  act_name = user_name;
  if (!act_name || !*act_name) {
    act_name = user_login;
  }
  armored_len = html_armored_strlen(act_name);
  armored_str = alloca(armored_len + 16);
  html_armor_string(act_name, armored_str);
  if (user_contest_id < 0) user_contest_id = 0;

  error_log = 0;
  errcode = userlist_clnt_get_contests(server_conn, user_id, &xml_text);
  if (errcode < 0) {
    error("%s", userlist_strerror(-errcode));
    goto failed;
  }
  if (!(regs = userlist_parse_contests_str(xml_text))) {
    /* FIXME: maybe this is normal? */
    error("%s", _("XML parse error"));
    goto failed;
  }

  if (regs) {
    ASSERT(regs->tag == USERLIST_T_CONTESTS);
    regs = regs->first_down;
  }
  //l10n_setlocale(client_locale_id);
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, _("Personal page of %s"), armored_str);

  printf(_("<p%s>Hello, %s!</p>\n"), par_style, armored_str);

  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  printf("<input type=\"hidden\" name=\"SID\" value=\"%llx\"/>\n"
         "<input type=\"hidden\" name=\"locale_id\" value=\"%d\"/>\n",
         user_cookie, client_locale_id);
  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n",
           user_contest_id);
  }
  printf("<%s>%s</%s>\n", head_style, _("Change the password"), head_style);
  printf("<p%s>%s: <input type=\"password\" name=\"chg_old_passwd\" maxlength=\"16\" size=\"16\"/></p>\n", par_style, _("Old password"));
  printf("<p%s>%s: <input type=\"password\" name=\"chg_new_passwd_1\" maxlength=\"16\" size=\"16\"/></p>\n", par_style, _("New password (1)"));
  printf("<p%s>%s: <input type=\"password\" name=\"chg_new_passwd_2\" maxlength=\"16\" size=\"16\"/></p>\n", par_style, _("New password (2)"));
  printf("<p%s><input type=\"submit\" name=\"action_%d\" value=\"%s\"/></p>\n",
         par_style, ACTION_CHANGE_PASSWORD, _("Change!"));
  printf("</form>\n");

  if (regs) {
    printf("<%s>%s</%s>\n", head_style,
           _("Check the registration status"), head_style);

    for (reg = regs; reg; reg = reg->right) {
      ASSERT(reg->tag == USERLIST_T_CONTEST);
      regx = (struct userlist_contest*) reg;
      cnts = 0;
      if (contests_get(regx->id, &cnts) < 0 || !cnts) continue;
      if (cnts->team_url && regx->status == USERLIST_REG_OK) {
        need_team_btn = 1;
      }
    }

    printf("<table width=\"100%%\"><tr><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th></tr>\n",
           table_style, _("Contest ID"),
           table_style, _("Contest name"),
           table_style, _("Status"),
           table_style, _("Edit personal data"),
           table_style, need_team_btn?(_("Submit solution")):"&nbsp;");
    for (reg = regs; reg; reg = reg->right) {
      ASSERT(reg->tag == USERLIST_T_CONTEST);
      regx = (struct userlist_contest*) reg;
      cnts = 0;
      if (contests_get(regx->id, &cnts) < 0 || !cnts) continue;
      cnts_name_loc = cnts->name;
      if (!client_locale_id && cnts->name_en)
        cnts_name_loc = cnts->name_en;
      printf("<tr><td%s>%d</td><td%s>%s</td><td%s>%s</td>",
             table_style, regx->id, table_style, cnts_name_loc, 
             table_style, gettext(regstatus_str(regx->status)));
      *s1 = 0;
      if (!user_contest_id) {
        snprintf(s1, sizeof(s1), "&show_all=1");
      }
      snprintf(url, sizeof(url),
               "%s?action=%d&SID=%llx&contest_id=%d&locale_id=%d%s",
               self_url, STATE_EDIT_REGISTRATION_DATA,
               user_cookie, regx->id, client_locale_id, s1);
      printf("<td%s><a href=\"%s\">%s</a></td>\n", table_style,
             url, _("Edit"));
      if (cnts->team_url && regx->status == USERLIST_REG_OK && !cnts->closed) {
        /* FIXME: need to set client mode correctly */
        snprintf(url, sizeof(url),
                 "%s?locale_id=%d&contest_id=%d&SID=%llx",
                 cnts->team_url, client_locale_id, regx->id, user_cookie);
        printf("<td%s><a href=\"%s\">%s</a></td>\n", table_style,
               url, _("Submit solution"));
      } else {
        printf("<td%s>&nbsp;</td>", table_style);
      }
      printf("</tr>\n");
    }
    printf("</table>\n");
  }

  fflush(stdout);

  // check available contests
  cnts_total = contests_get_list(&cnts_map);
  cnts_ids = (int*) alloca(sizeof(cnts_ids[0]) * (cnts_total + 1));
  memset(cnts_ids, 0, sizeof(cnts_ids[0]) * (cnts_total + 1));
  cnts_used = 0;
  if (user_contest_id > 0) {
    if (check_contest_eligibility(user_contest_id)) {
      for (reg = regs; reg; reg = reg->right) {
        ASSERT(reg->tag == USERLIST_T_CONTEST);
        regx = (struct userlist_contest*) reg;
        if (regx->id == user_contest_id) break;
      }
      if (!reg) {
        cnts_ids[cnts_used++] = user_contest_id;
      }
    }
  } else {
    for (i = 1; i < cnts_total; i++) {
      if (check_contest_eligibility(i)) {
        for (reg = regs; reg; reg = reg->right) {
          ASSERT(reg->tag == USERLIST_T_CONTEST);
          regx = (struct userlist_contest*) reg;
          if (regx->id == i) break;
        }
        if (!reg) {
          cnts_ids[cnts_used++] = i;
        }
      }
    }
  }
  printf("<%s>%s</%s>\n", head_style, _("Available contests"), head_style);
  if (!cnts_used) {
    printf("<p%s>%s</p>\n", par_style, _("No contests available."));
  } else {
    printf("<table width=\"100%%\"><tr><th%s>%s</th><th%s>%s</th><th%s>%s</th></tr>\n",
           table_style, _("Contest ID"),
           table_style, _("Contest name"),
           table_style, _("Register"));
    for (i = 0; i < cnts_used; i++) {
      if (contests_get(cnts_ids[i], &cnts) < 0 || !cnts) continue;
      cnts_name_loc = cnts->name;
      if (!client_locale_id && cnts->name_en)
        cnts_name_loc = cnts->name_en;
      *s1 = 0;
      if (!user_contest_id) {
        snprintf(s1, sizeof(s1), "&show_all=1");
      }
      snprintf(url, sizeof(url),
               "%s?action=%d&SID=%llx&locale_id=%d&contest_id=%d%s",
               self_url, STATE_EDIT_REGISTRATION_DATA, user_cookie,
               client_locale_id, cnts->id, s1);
      printf("<tr><td%s>%d</td><td%s>%s</td>"
             "<td%s><a href=\"%s\">%s</a></td></tr>\n",
             table_style, cnts->id, table_style,
             cnts_name_loc, table_style, url, _("Register"));
    }
    printf("</table>\n");
  }

  s1[0] = 0;
  if (user_contest_id > 0) {
    snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
  }
  printf("<%s>%s</%s>\n", head_style, _("Quit the system"), head_style);
  snprintf(url, sizeof(url),
           "%s?action=%d&SID=%llx&locale_id=%d%s",
           self_url, ACTION_LOGOUT, user_cookie, client_locale_id, s1);
  printf("<p%s><a href=\"%s\">%s</a></p>\n", par_style, url, _("Logout"));

  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  printf("<input type=\"hidden\" name=\"SID\" value=\"%llx\"/>\n", user_cookie);
  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>\n",
           user_contest_id);
  }
  print_choose_language_button(0, 0, ACTION_CHANGE_LANG_AT_MAIN_PAGE, 0);
  printf("</form>\n");
  goto done;

 failed:
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, "%s", _("Fatal error"));
  printf("<pre>%s</pre>\n", error_log);

 done:;
}

static void
action_change_lang_at_initial(void)
{
  unsigned char url[1024];
  unsigned char s1[128], s2[128];
  int newstate = 0;

  if (user_action == ACTION_CHANGE_LANG_AT_LOGIN)
    newstate = STATE_LOGIN;
  else if (user_action == ACTION_CHANGE_LANG_AT_LOGIN_FORCED_REG)
    newstate = STATE_LOGIN_FORCED_REG;

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, name_accept_chars, '?');
  read_usecookies();

  /* FIXME: need to encode "login" for URL? */

  *s1 = 0;
  if (user_login && *user_login) {
    snprintf(s1, sizeof(s1), "&login=%s", user_login);
  }
  *s2 = 0;
  if (user_contest_id > 0) {
    snprintf(s2, sizeof(s2), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?action=%d&locale_id=%d%s%s",
           self_url, newstate, client_locale_id, s1, s2);
  client_put_refresh_header(config->charset, url, 0,
                            "%s", _("Log into the system"));
  exit(0);
}

static void
action_change_lang_at_register_new_user(void)
{
  unsigned char url[1024];
  unsigned char s1[128], s2[128], s3[128];

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, name_accept_chars, '?');
  if (!(user_email = cgi_param("email"))) {
    user_email = xstrdup("");
  }
  fix_string(user_email, email_accept_chars, '?');

  /* FIXME: need to encode "login", "email" for URL? */

  *s1 = 0;
  if (user_login && *user_login) {
    snprintf(s1, sizeof(s1), "&login=%s", user_login);
  }
  *s2 = 0;
  if (user_email && *user_email) {
    snprintf(s2, sizeof(s2), "&email=%s", user_email);
  }
  *s3 = 0;
  if (user_contest_id > 0) {
    snprintf(s3, sizeof(s3), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?action=%d&locale_id=%d%s%s%s",
           self_url, STATE_REGISTER_NEW_USER, client_locale_id, s1, s2, s3);
  client_put_refresh_header(config->charset, url, 0,
                            "%s", _("Language is changed"));
  exit(0);
}

static void
action_change_lang_at_main_page(void)
{
  unsigned char s1[128], url[512];

  if (!authentificate()) return;

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);

  *s1 = 0;
  if (user_contest_id > 0) {
    snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?action=%d&locale_id=%d&SID=%llx%s",
           self_url, STATE_MAIN_PAGE, client_locale_id, user_cookie, s1);
  client_put_refresh_header(config->charset, url, 0,
                            "%s", _("Language is changed"));
  exit(0);
}

static void
action_register_new_user(void)
{
  int errcode;
  unsigned char s1[128], url[512];
  const struct contest_desc *cnts = 0;

  if (user_contest_id > 0) contests_get(user_contest_id, &cnts);

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);
  error_log = 0;

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  if (fix_string(user_login, login_accept_chars, '?') > 0) {
    error("%s: %s.", _("\"Login\" field contains invalid characters"),
          user_login);
  }
  if (!(user_email = cgi_param("email"))) {
    user_email = xstrdup("");
  }
  if (fix_string(user_email, email_accept_chars, '?') > 0) {
    error("%s: %s.", _("\"E-mail\" field contains invalid characters"),
          user_email);
  }
  if (!cnts || !cnts->assign_logins) {
    if (!user_login || !*user_login) {
      error("%s", _("Mandatory \"Login\" field is empty."));
    }
  }
  if (!user_email || !*user_email) {
    error("%s", _("Mandatory \"E-mail\" field is empty."));
  }

  // initial validation is passed, so may try to register
  if (!error_log) {
    if (!server_conn) {
      server_conn = userlist_clnt_open(config->socket_path);
    }
    if (!server_conn) {
      error("%s", _("Connection to the server is broken."));
    } else if (cnts && cnts->simple_registration) {
      errcode = userlist_clnt_register_new_2(server_conn, user_ip,
                                             ssl_flag,
                                             user_contest_id,
                                             client_locale_id,
                                             user_login, user_email,
                                             &user_password);
      if (errcode == ULS_PASSWORD) errcode = 0;
      if (errcode < 0) {
        error("%s", gettext(userlist_strerror(-errcode)));
      }
    } else {
      errcode = userlist_clnt_register_new(server_conn,
                                           ULS_REGISTER_NEW,
                                           user_ip,
                                           ssl_flag,
                                           user_contest_id,
                                           client_locale_id, 0,
                                           user_login, user_email, 0);
      if (errcode == -ULS_ERR_EMAIL_FAILED) {
        error("%s", _("The server was unable to send a registration e-mail\n"
                      "to the specified address. This is probably due\n"
                      "to heavy server load rather than to an invalid\n"
                      "e-mail address. You should try to register later.\n"));
      } else if (errcode < 0) {
        error("%s", gettext(userlist_strerror(-errcode)));
      }
    }
  }

  if (!error_log) {
    /* registration is successful */
    if (cnts && cnts->simple_registration) {
      url_armor_string(s1, sizeof(s1), user_password);
      snprintf(url, sizeof(url), "%s?action=%d&login=%s&email=%s&password=%s&locale_id=%d&contest_id=%d",
               self_url, STATE_USER_REGISTERED_2, user_login, user_email,
               s1, client_locale_id, user_contest_id);
    } else {
      *s1 = 0;
      if (user_contest_id > 0) {
        snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
      }
      snprintf(url, sizeof(url),"%s?action=%d&login=%s&email=%s&locale_id=%d%s",
               self_url, STATE_USER_REGISTERED, user_login, user_email,
               client_locale_id, s1);
    }
    client_put_refresh_header(config->charset, url, 0,
                              "%s", _("New user is registered"));
    exit(0);
  }

  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, "%s", _("Registration failed"));
  printf("<%s>%s</%s><p%s>%s<br><pre><font color=\"red\">%s</font></pre></p>\n",
         head_style, _("The form contains error(s)"), head_style, par_style,
         _("Unfortunately, your form cannot be accepted, since "
           "it contains several errors. The list of errors is given "
           "below."),
         error_log);
  printf("<p%s>%s</p>", par_style, 
         _("Now please press the \"Back\" button of your browser "
           "and fix the error(s)."));
}

/* here we must check login & password */
static void
action_login(void)
{
  int errcode;
  unsigned char s1[128], url[512];
  int new_user_id, new_locale_id;
  ej_cookie_t new_cookie;
  unsigned char *new_name;
  const struct contest_desc *cnts = 0;

  if (client_locale_id == -1) client_locale_id = 0;
  //l10n_setlocale(client_locale_id);

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, name_accept_chars, '?');
  if (!(user_password = cgi_param("password"))) {
    user_password = xstrdup("");
  }
  fix_string(user_password, password_accept_chars, '?');

  if (!server_conn) {
    server_conn = userlist_clnt_open(config->socket_path);
  }
  if (!server_conn) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id, _("Login failed"));
    printf("<p%s>%s</p>\n", par_style,
           _("Connection to the server is broken."));
    return;
  }

  errcode = userlist_clnt_login(server_conn, ULS_DO_LOGIN,
                                user_ip, ssl_flag, user_contest_id,
                                client_locale_id,
                                user_login, user_password,
                                &new_user_id, &new_cookie, &new_name,
                                &new_locale_id);
  if (errcode != ULS_LOGIN_COOKIE) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id, _("Login failed"));
    printf("<p%s>%s</p>\n", par_style,
           _("You have specified incorrect login or password."));
    return;
  }

  user_id = new_user_id;
  user_name = new_name;
  if (client_locale_id == -1) client_locale_id = new_locale_id;
  if (client_locale_id == -1) client_locale_id = 0;
  user_cookie = new_cookie;

  if (user_contest_id > 0) contests_get(user_contest_id, &cnts);
  if (user_action==ACTION_LOGIN_FORCED_REG && cnts && cnts->force_registration){
    errcode = userlist_clnt_register_contest(server_conn,
                                             ULS_REGISTER_CONTEST,
                                             user_id,
                                             user_contest_id);
    if (errcode < 0) {
      client_put_header(stdout, header_txt, 0, config->charset, 1,
                        client_locale_id, _("Registration failed"));
      printf("<p%s>%s</p>\n", par_style, userlist_strerror(-errcode));
      return;
    }

    if (cnts->team_url)
      snprintf(url, sizeof(url),
               "%s?SID=%llx&locale_id=%d&contest_id=%d",
               cnts->team_url, user_cookie, client_locale_id, user_contest_id);
    else
      snprintf(url, sizeof(url),
               "%s?action=%d&SID=%llx&locale_id=%d&contest_id=%d",
               self_url, STATE_MAIN_PAGE, user_cookie, client_locale_id,
               user_contest_id);

    client_put_refresh_header(config->charset, url, 0,
                              "%s", _("Login successful"));
    exit(0);
  }

  *s1 = 0;
  if (user_contest_id > 0) {
    snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?action=%d&SID=%llx%s&locale_id=%d",
           self_url, STATE_MAIN_PAGE, user_cookie, s1, client_locale_id);

  client_put_refresh_header(config->charset, url, 0,
                            "%s", _("Login successful"));
  exit(0);
}

static void
action_logout(void)
{
  unsigned char *user_str = user_name;
  unsigned char *armored_str;
  int armored_len;
  unsigned char s1[128], url[512];

  if (!authentificate()) return;

  if (!user_str || !*user_str) user_str = user_login;
  armored_len = html_armored_strlen(user_str);
  armored_str = alloca(armored_len + 16);
  html_armor_string(user_str, armored_str);

  *s1 = 0;
  if (user_contest_id > 0) {
    snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?action=%d&locale_id=%d%s",
           self_url, STATE_LOGIN, client_locale_id, s1);

  //l10n_setlocale(client_locale_id);
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, "%s, %s!", _("Good-bye"), armored_str);
  printf(_("<p%s>Click <a href=\"%s\">on this link</a> to login again.</p>\n"),
         par_style, url);
}

static void
action_change_password(void)
{
  unsigned char *old_pwd, *new_pwd1, *new_pwd2;
  int errcode;
  unsigned char s1[128], url[512];

  /* contest_id, locale_id, sid already read */
  if (!authentificate()) return;
  ASSERT(server_conn);

  error_log = 0;
  old_pwd = xstrdup(cgi_param("chg_old_passwd"));
  new_pwd1 = xstrdup(cgi_param("chg_new_passwd_1"));
  new_pwd2 = xstrdup(cgi_param("chg_new_passwd_2"));

  if (!old_pwd || !*old_pwd) {
    error("%s", _("old password not specified"));
  }
  if (!new_pwd1 || !*new_pwd1) {
    error("%s", _("new password (1) not specified"));
  }
  if (!new_pwd2 || !*new_pwd2) {
    error("%s", _("new password (2) not specified"));
  }
  if (old_pwd && strlen(old_pwd) > 64) {
    error("%s", _("old password is too long"));
  }
  if (old_pwd && fix_string(old_pwd, password_accept_chars, '?') > 0) {
    error("%s", _("old password contain invalid characters"));
  }
  if (new_pwd1 && new_pwd2 && strcmp(new_pwd1, new_pwd2)) {
    error("%s", _("new passwords does not match"));
  }
  if (new_pwd1 && fix_string(new_pwd1, password_accept_chars, '?') > 0) {
    error("%s", _("new password contain invalid characters"));
  }
  if (new_pwd1 && strlen(new_pwd1) > 64) {
    error("%s", _("new password is too long"));
  }
  if (!error_log) {
    errcode = userlist_clnt_set_passwd(server_conn, ULS_SET_PASSWD,
                                       user_id, 0, old_pwd, new_pwd1);
    if (errcode < 0) {
      error("%s", gettext(userlist_strerror(-errcode)));
    }
  }

  *s1 = 0;
  if (user_contest_id > 0) {
    snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?locale_id=%d&action=%d%s",
           self_url, client_locale_id, STATE_LOGIN, s1);

  if (!error_log) {
    client_put_refresh_header(config->charset, url, 0,
                              "%s", _("Password changed successfully"));
    printf("<p%s>%s</p>\n", par_style, _("Password changed successfully."));
    exit(0);
  }

  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, _("Failed to change password"));
  printf("<p%s>%s<br><pre><font color=\"red\">%s</font></pre></p>\n",
         par_style,
         _("Password changing failed due to the following reasons."),
         error_log);
}

static void
action_remove_member(void)
{
  unsigned char *cgi_cmd = 0;
  int role = 0, pers = 0, n = 0, serial = 0, errcode;
  unsigned char ser_var_name[64];
  unsigned char *ser_var = 0;
  unsigned char s1[64], url[512];
  const struct contest_desc *cnts = 0;

  if (!authentificate()) return;
  ASSERT(server_conn);

  *s1 = 0;
  if (user_contest_id > 0) {
    snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?action=%d&SID=%llx&locale_id=%d%s",
           self_url, STATE_EDIT_REGISTRATION_DATA, user_cookie,
           client_locale_id, s1);

  if (user_contest_id > 0) {
    if ((errcode = contests_get(user_contest_id, &cnts)) < 0) {
      fprintf(stderr, "invalid contest: %s", contests_strerror(-errcode));
      error("%s", _("Invalid contest identifier."));
      goto failed;
    }
    ASSERT(cnts);
  }

  prepare_var_table(cnts);
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;
    member_info[role] = xcalloc(member_max[role],
                                sizeof(member_info[0][0]));
    for (pers = 0; pers < member_max[role]; pers++) {
      member_info[role][pers] = xcalloc(CONTEST_LAST_MEMBER_FIELD,
                                        sizeof(member_info[0][0][0]));
    }
  }

  error_log = 0;
  if (!(cgi_cmd = cgi_nname("remove_", 7))) {
    error("%s", _("Role/person parameters are not defined."));
    goto failed;
  }
  role = pers = n = 0;
  if (sscanf(cgi_cmd, "remove_%d_%d%n", &role, &pers, &n) != 2 || cgi_cmd[n]) {
    error("%s", _("Cannot parse role/person."));
    goto failed;
  }
  if (role < 0 || role >= CONTEST_LAST_MEMBER) {
    error("%s", _("Invalid role parameter."));
    goto failed;
  }
  if (member_max[role] <= 0) {
    error("%s", _("Members of this role are not allowed."));
    goto failed;
  }
  if (pers < 0) {
    error("%s", _("Invalid person."));
    goto failed;
  }
  snprintf(ser_var_name, sizeof(ser_var_name),
           "member_info_%d_%d_0", role, pers);
  ser_var = cgi_param(ser_var_name);
  if (!ser_var || !*ser_var) goto silently_reload;
  n = 0;
  if (sscanf(ser_var, "%d%n", &serial, &n) != 1 || ser_var[n]) {
    error("%s", _("Cannot parse serial number."));
    goto failed;
  }
  if (!serial) goto silently_reload;
  if (serial < 0) {
    error("%s", _("Invalid serial number."));
    goto failed;
  }

  errcode = userlist_clnt_delete_info(server_conn, ULS_DELETE_MEMBER,
                                      user_id, user_contest_id, serial);
  if (errcode < 0) {
    error("%s", gettext(userlist_strerror(-errcode)));
    goto failed;
  }

  client_put_refresh_header(config->charset, url, 0,
                            "%s", _("Team member is removed"));
  exit(0);

 silently_reload:
  client_put_refresh_header(config->charset, url, 0,
                            "%s", _("No server request performed"));
  exit(0);

 failed:
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, "%s", _("Cannot remove team member"));
  printf("<p%s>%s.</p>\n<font color=\"red\"><pre>%s</pre></font>\n",
         par_style,
         _("Cannot remove a member due a reason given below"), error_log);
}

static void
action_register_for_contest(void)
{
  int user_show_all = 0, errcode = 0, role, pers, i, n;
  unsigned char *user_xml_text = 0;
  unsigned char s1[64], url[512];
  const struct contest_desc *cnts = 0;
  unsigned char *par_name, *par_value, *arm_value;
  int arm_len;

  if (!authentificate()) return;
  if (cgi_param("show_all")) {
    user_show_all = 1;
  }

  if (user_contest_id <= 0) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id, "%s", _("Invalid contest identifier"));
    return;
  }
  if (user_contest_id > 0) {
    if ((errcode = contests_get(user_contest_id, &cnts)) < 0) {
      fprintf(stderr, "invalid contest %d: %s", user_contest_id,
              contests_strerror(-errcode));
      client_put_header(stdout, header_txt, 0, config->charset, 1,
                        client_locale_id, "%s", _("Invalid contest"));
      printf("<p%s>%s</p>.", par_style, _("Invalid contest identifier specified"));
      return;
    }
  }
  ASSERT(cnts);

  if (!check_contest_eligibility(cnts->id)) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id, "%s", _("Permission denied"));
    printf("<p%s>%s</p>.", par_style, _("You cannot participate in this contest"));
    return;
  }

  prepare_var_table(cnts);
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;
    member_info[role] = xcalloc(member_max[role],
                                sizeof(member_info[0][0]));
    for (pers = 0; pers < member_max[role]; pers++) {
      member_info[role][pers] = xcalloc(CONTEST_LAST_MEMBER_FIELD,
                                        sizeof(member_info[0][0][0]));
    }
  }

  read_user_info_from_form();

  /* make empty strings for the remaining */
  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    if (!field_descs[i].is_editable) continue;
    if (!*field_descs[i].var) {
      *field_descs[i].var = xstrdup("");
    }
  }
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    for (pers = 0; pers < member_cur[role]; pers++) {
      if (!member_info[role][pers][0]) {
        member_info[role][pers][0] = xstrdup("");
      }
      for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
        if (!member_edit_flags[role][i].is_editable) continue;
        if (!member_info[role][pers][i]) {
          member_info[role][pers][i] = xstrdup("");
        }
      }
    }
  }

  check_mandatory(cnts);
  if (error_log) goto failed;
  user_xml_text = make_user_xml();
  if (error_log) goto failed;
  errcode = userlist_clnt_set_info(server_conn, user_id,
                                   user_contest_id, user_xml_text);
  if (errcode < 0) {
    error("%s", gettext(userlist_strerror(-errcode)));
    goto failed;
  }
  if (user_action == ACTION_REGISTER_FOR_CONTEST) {
    errcode = userlist_clnt_register_contest(server_conn,
                                             ULS_REGISTER_CONTEST,
                                             user_id,
                                             user_contest_id);
    if (errcode < 0) {
      error("%s", gettext(userlist_strerror(-errcode)));
      goto failed;
    }
  }

  *s1 = 0;
  if (!user_show_all) {
    snprintf(s1, sizeof(s1), "&contest_id=%d", user_contest_id);
  }
  snprintf(url, sizeof(url), "%s?action=%d&SID=%llx&locale_id=%d%s",
           self_url, STATE_MAIN_PAGE, user_cookie, client_locale_id, s1);
  client_put_refresh_header(config->charset, url, 0,
                            "%s", _("Registration is successful"));
  exit(0);

 failed:
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, _("Operation failed"));
  printf("<p%s>%s</p><font color=\"red\"><pre>%s</pre></font>\n",
         par_style,
         _("Registration failed by the following reason:"), error_log);

  /* display "Back" button */
  printf("<form method=\"post\" action=\"%s\" "
         "enctype=\"application/x-www-form-urlencoded\">\n",
         self_url);
  n = cgi_get_param_num();
  for (i = 0; i < n; i++) {
    cgi_get_nth_param(i, &par_name, &par_value);
    if (!strcmp(par_name, "action")) continue;
    if (!strncmp(par_name, "action_", 7)) continue;
    arm_len = html_armored_strlen(par_value);
    arm_value = (unsigned char*) xmalloc(arm_len + 1);
    html_armor_string(par_value, arm_value);
    printf("<input type=\"hidden\" name=\"%s\" value=\"%s\"/>\n",
           par_name, arm_value);
    xfree(arm_value);
  }
  printf("<p%s><input type=\"submit\" name=\"action_%d\" value=\"%s\"/>",
         par_style,
         ACTION_REDISPLAY_EDIT_REGISTRATION_DATA,
         _("Back"));
  printf("</form>");
}

static void
parse_user_action(void)
{
  char *s = 0;
  int x, n;

  user_action = 0;

  if ((s = cgi_nname("remove_", 7))) {
    user_action = ACTION_REMOVE_MEMBER;
    return;
  }

  s = cgi_param("action");
  if (s && sscanf(s, "%d %n", &x, &n) == 1 && !s[n]
      && x >= 0 && x < ACTION_LAST_ACTION) {
    user_action = x;
    return;
  }
  s = cgi_nname("action_", 7);
  if (!s) return;
  if (sscanf(s, "action_%d%n", &x, &n) != 1 || s[n]) return;
  if (x < 0 || x >= ACTION_LAST_ACTION) return;
  user_action = x;
}

int
main(int argc, char const *argv[])
{
  struct timeval begin_time, end_time;

  cur_time = time(0);
  gettimeofday(&begin_time, 0);
  initialize(argc, argv);

  if (!check_source_ip()) {
    client_access_denied(config->charset, client_locale_id);
  }

  read_locale_id();
  parse_user_action();
  l10n_setlocale(client_locale_id);

  switch (user_action) {
    /* actions */
  case ACTION_CHANGE_LANG_AT_INITIAL:
  case ACTION_CHANGE_LANG_AT_LOGIN:
  case ACTION_CHANGE_LANG_AT_LOGIN_FORCED_REG:
    action_change_lang_at_initial();
    break;
  case ACTION_CHANGE_LANG_AT_REGISTER_NEW_USER:
    action_change_lang_at_register_new_user();
    break;
  case ACTION_REGISTER_NEW_USER:
    action_register_new_user();
    break;
  case ACTION_LOGIN:
  case ACTION_LOGIN_FORCED_REG:
    action_login();
    break;
  case ACTION_CHANGE_LANG_AT_MAIN_PAGE:
    action_change_lang_at_main_page();
    break;
  case ACTION_LOGOUT:
    action_logout();
    break;
  case ACTION_CHANGE_PASSWORD:
    action_change_password();
    break;
  case ACTION_REMOVE_MEMBER:
    action_remove_member();
    break;
  case ACTION_SAVE_REGISTRATION_DATA:
  case ACTION_REGISTER_FOR_CONTEST:
    action_register_for_contest();
    break;

    /* pages */
  case STATE_LOGIN:
  case STATE_LOGIN_FORCED_REG:
    display_login_page();
    break;
  case STATE_REGISTER_NEW_USER:
    display_register_new_user_page();
    break;
  case STATE_USER_REGISTERED:
    display_user_registered_page();
    break;
  case STATE_USER_REGISTERED_2:
    display_user_registered_page_2();
    break;
  case STATE_MAIN_PAGE:
    display_main_page();
    break;
  case STATE_EDIT_REGISTRATION_DATA:
  case ACTION_ADD_NEW_CONTESTANT:
  case ACTION_ADD_NEW_RESERVE:
  case ACTION_ADD_NEW_COACH:
  case ACTION_ADD_NEW_ADVISOR:
  case ACTION_ADD_NEW_GUEST:
  case ACTION_REDISPLAY_EDIT_REGISTRATION_DATA:
    display_edit_registration_data_page();
    break;

  default:
    display_initial_page();
    break;
  }

#if 0
  {
    int i;

    puts("<hr><pre>");
    puts("");
    for (i = 0; i < argc; i++) {
      printf("argv[%d] = '%s'\n", i, argv[i]);
    }
    puts("");
    cgi_print_param();
    fflush(stdout);
    system("printenv");
  }
#endif

  if (config->show_generation_time) {
    gettimeofday(&end_time, 0);
    end_time.tv_sec -= begin_time.tv_sec;
    if ((end_time.tv_usec -= begin_time.tv_usec) < 0) {
      end_time.tv_usec += 1000000;
      end_time.tv_sec--;
    }
    printf("<hr><p%s>%s: %ld %s\n", par_style,
           _("Page generation time"),
           end_time.tv_usec / 1000 + end_time.tv_sec * 1000,
           _("msec"));
  }
  client_put_footer(stdout, footer_txt);
  if (server_conn) {
    userlist_clnt_close(server_conn);
  }

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
