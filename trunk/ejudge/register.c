/* -*- mode: c -*-; coding: koi8-r */
/* $Id$ */

/* Copyright (C) 2001,2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "expat_iface.h"
#include "pathutl.h"
#include "clntutil.h"
#include "cgi.h"
#include "contests.h"
#include "userlist_clnt.h"
#include "userlist_proto.h"
#include "misctext.h"
#include "userlist.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#endif

/* ACTIONS, that may be performed by client*/
enum
  {
    ACTION_CHANGE_LANG_ENTRY_PAGE = 1,
    ACTION_LOGIN,               /* 2 */
    ACTION_REGISTER_ENTRY_PAGE, /* 3 */
    ACTION_CHANGE_LANG_REGISTER_PAGE, /* 4 */
    ACTION_REGISTER_REGISTER_PAGE, /* 5 */
    ACTION_LOGIN_ONLY_PAGE,     /* 6 */
    ACTION_CHANGE_LANG_LOGIN_ONLY_PAGE, /* 7 */
    ACTION_LOGOUT,              /* 8 */
    ACTION_EDIT_PERSONAL_PAGE,  /* 9 */
    ACTION_REGISTER_CONTEST_PAGE, /* 10 */
    ACTION_CHANGE_PASSWORD,     /* 11 */
    ACTION_ADD_NEW_CONTESTANT,  /* 12 */
    ACTION_ADD_NEW_RESERVE,     /* 13 */
    ACTION_ADD_NEW_COACH,       /* 14 */
    ACTION_ADD_NEW_ADVISOR,     /* 15 */
    ACTION_ADD_NEW_GUEST,       /* 16 */
    ACTION_REMOVE_MEMBER,       /* 17 */
    ACTION_RELOAD_PERSONAL_DATA, /* 18 */
    ACTION_COMMIT_PERSONAL_DATA, /* 19 */
    ACTION_REGISTER_FOR_CONTEST, /* 20 */
    ACTION_MAIN_PAGE,           /* 21 */
    ACTION_LAST_ACTION
  };

enum
  {
    TG_CONFIG = 1,
    TG_ACCESS,
    TG_IP,
    TG_SOCKET_PATH,
    TG_CONTESTS_PATH,
  };
enum
  {
    AT_ENABLE_L10N = 1,
    AT_DISABLE_L10N,
    AT_L10N,
    AT_L10N_DIR,
    AT_SHOW_GENERATION_TIME,
    AT_CHARSET,
    AT_DEFAULT,
    AT_ALLOW,
    AT_DENY,
    AT_ID,
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
  unsigned char *contests_path;
  struct access_node *access;
};

static struct config_node *config;
static struct contest_list *contests;

static int client_locale_id;

static unsigned char *self_url;
static unsigned char *user_login;
static unsigned char *user_password;
static int user_usecookies;
static unsigned char *user_email;
static unsigned char *user_name;
static unsigned char *user_homepage;
static unsigned char *user_inst;
static unsigned char *user_instshort;
static unsigned char *user_fac;
static unsigned char *user_facshort;
static int user_show_email;
static int user_contest_id;
static struct userlist_clnt *server_conn;
static unsigned long user_ip;
static unsigned long long client_cookie;
static int client_cookie_bad;
static unsigned long long user_cookie;
static int user_id;
static unsigned char *user_name;
static int user_action;
static int user_use_cookies_default;
static int user_show_login;
static struct userlist_user *user_xml;

static unsigned char ***member_info[CONTEST_LAST_MEMBER];

static unsigned char *error_log;


static char const login_accept_chars[] =
"._-0123456789?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char const email_accept_chars[] =
"@.%!+=_-0123456789?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char const name_accept_chars[] =
" !#$%()*+,-./0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"abcdefghijklmnopqrstuvwxyz{|}~"
"═║╒ё╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡Ё╢╣╤╥╦╧╨╩╪╫╬©юабцдефгхийклмнопярстужвьызшэщчъ"
"ЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ";
static char const homepage_accept_chars[] =
" :!#$%*+,-./0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"abcdefghijklmnopqrstuvwxyz{|}~";
static char const password_accept_chars[] =
" !#$%\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"`abcdefghijklmnopqrstuvwxyz{|}~═║╒ё╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡Ё╢╣╤╥╦╧╨╩╪╫╬©"
"юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ";

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
  { "inst", _("Institution"), "inst", &user_inst,
    name_accept_chars, '?', 128, 64 },
  { "instshort", _("Institution (short)"), "instshort", &user_instshort,
    name_accept_chars, '?', 32, 32 },
  { "fac", _("Faculty"), "fac", &user_fac,
    name_accept_chars, '?', 128, 64 },
  { "facshort", _("Faculty (short)"), "facshort", &user_facshort,
    name_accept_chars, '?', 32, 32 },
};
static struct field_desc member_field_descs[CONTEST_LAST_MEMBER_FIELD] =
{
  { 0 },

  { "firstname",_("First name"),0,0, name_accept_chars, '?', 64, 64 },
  { "middlename",_("Middle name"), 0, 0, name_accept_chars, '?', 64, 64 },
  { "surname",_("Family name"), 0, 0, name_accept_chars, '?', 64, 64 },
  { "status", _("Status"), 0, 0, name_accept_chars, '?', 64, 64 },
  { "grade", _("Grade"), 0, 0, name_accept_chars, '?', 16, 16 },
  { "group", _("Group"), 0, 0, name_accept_chars, '?', 16, 16 },
  { "email",_("E-mail"), 0, 0, name_accept_chars, '?', 64, 64 },
  { "homepage",_("Homepage"), 0, 0, homepage_accept_chars, '?', 128, 64 },
  { "inst", _("Institution"), 0, 0, name_accept_chars, '?', 128, 64 },
  { "instshort", _("Institution (short)"),0,0,name_accept_chars, '?', 32, 32 },
  { "fac", _("Faculty"), 0, 0, name_accept_chars, '?', 128, 64 },
  { "facshort", _("Faculty (short)"), 0, 0, name_accept_chars, '?', 32, 32 },
  { "occupation", _("Occupation"), 0, 0, name_accept_chars, '?', 128, 64 },
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
#endif

struct edit_flags
{
  char is_editable;
  char is_mandatory;
};
static struct edit_flags member_edit_flags[CONTEST_LAST_MEMBER][CONTEST_LAST_MEMBER_FIELD];
static int member_min[CONTEST_LAST_MEMBER];
static int member_max[CONTEST_LAST_MEMBER];
static int member_cur[CONTEST_LAST_MEMBER];

static char const * const tag_map[] =
{
  0,
  "register_config",
  "access",
  "ip",
  "socket_path",
  "contests_path",

  0
};
static char const * const attn_map[] =
{
  0,

  "enable_l10n",
  "disable_l10n",
  "l10n",
  "l10n_dir",
  "show_generation_time",
  "charset",
  "default",
  "allow",
  "deny",
  "id",

  0
};

static void *
node_alloc(int tag)
{
  switch (tag) {
  case TG_CONFIG: return xcalloc(1, sizeof(struct config_node));
  case TG_ACCESS: return xcalloc(1, sizeof(struct access_node));
  case TG_IP: return xcalloc(1, sizeof(struct ip_node));
  case TG_SOCKET_PATH: return xcalloc(1, sizeof(struct xml_tree));
  case TG_CONTESTS_PATH: return xcalloc(1, sizeof(struct xml_tree));
    //    return xcalloc(1, sizeof(struct xml_tree));
  default:
    SWERR(("unhandled tag: %d", tag));
  }
  return 0;
}
static void *
attn_alloc(int tag)
{
  return xcalloc(1, sizeof(struct xml_attn));
}
static int
parse_bool(char const *str)
{
  if (!str) return -1;
  if (!strcasecmp(str, "true")
      || !strcasecmp(str, "yes")
      || !strcasecmp(str, "1")) return 1;
  if (!strcasecmp(str, "false")
      || !strcasecmp(str, "no")
      || !strcasecmp(str, "0")) return 0;
  return -1;
}
static struct config_node *
parse_config(char const *path)
{
  struct xml_tree *tree = 0, *p, *p2;
  struct config_node *cfg = 0;
  struct xml_attn *a;
  struct ip_node *ip;
  unsigned int b1, b2, b3, b4;
  int n;

  tree = xml_build_tree(path, tag_map, attn_map, node_alloc, attn_alloc);
  if (!tree) goto failed;
  if (tree->tag != TG_CONFIG) {
    err("%s: %d: top-level tag must be <register_config>", path, tree->line);
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
#if CONF_HAS_LIBINTL - 0 == 1
      if (cfg->l10n != -1) {
        err("%s:%d: attribute \"l10n\" already defined", path, a->line);
        goto failed;
      }
      if ((cfg->l10n = parse_bool(a->text)) < 0) {
        err("%s:%d: invalid boolean value", path, a->line);
        goto failed;
      }
      if (a->tag == AT_DISABLE_L10N) cfg->l10n = !cfg->l10n;
      break;
#else
      err("%s:%d: localization support is not compiled", path, a->line);
      goto failed;
#endif /* CONF_HAS_LIBINTL */
    case AT_L10N_DIR:
#if CONF_HAS_LIBINTL - 0 == 1
      cfg->l10n_dir = a->text;
      break;
#else
      err("%s:%d: localization support is not compiled", path, a->line);
      goto failed;
#endif /* CONF_HAS_LIBINTL */
    case AT_SHOW_GENERATION_TIME:
      if ((cfg->show_generation_time = parse_bool(a->text)) < 0) {
        err("%s:%d: invalid boolean value", path, a->line);
        goto failed;
      }
      break;
    case AT_CHARSET:
      cfg->charset = a->text;
      /* FIXME: check charset for validity */
      break;
    default:
      err("%s:%d: attribute \"%s\" is invalid here",
          path, a->line, attn_map[a->tag]);
      goto failed;
    }
  }

  if (cfg->l10n == -1) cfg->l10n = 0;
  if (cfg->l10n && !cfg->l10n_dir) {
    /* FIXME: the locale dir should be guessed... */
    err("%s: locale directory (\"l10n_dir\" attribute) is not defined", path);
    goto failed;
  }

  /* process subnodes */
  for (p = cfg->b.first_down; p; p = p->right) {
    switch (p->tag) {
    case TG_SOCKET_PATH:
      if (cfg->socket_path) {
        err("%s:%d:%d: <socket_path> tag may be defined only once",
            path, p->line, p->column);
        goto failed;
      }
      if (p->first_down) {
        err("%s:%d:%d: nested tags are not allowed",
            path, p->line, p->column);
        goto failed;
      }
      if (p->first) {
        err("%s:%d:%d: attributes are not allowed",
            path, p->line, p->column);
        goto failed;
      }
      cfg->socket_path = p->text;
      break;
    case TG_CONTESTS_PATH:
      if (cfg->contests_path) {
        err("%s:%d:%d: <contests_path> tag may be defined only once",
            path, p->line, p->column);
        goto failed;
      }
      if (p->first_down) {
        err("%s:%d:%d: nested tags are not allowed",
            path, p->line, p->column);
        goto failed;
      }
      if (p->first) {
        err("%s:%d:%d: attributes are not allowed",
            path, p->line, p->column);
        goto failed;
      }
      cfg->contests_path = p->text;
      break;
    case TG_ACCESS:
      if (cfg->access) {
        err("%s:%d: <access> tag may be defined only once", path, p->line);
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
            err("%s:%d: invalid value for attribute", path, a->line);
            goto failed;
          }
          break;
        default:
          err("%s:%d: attribute \"%s\" is invalid here",
              path, a->line, attn_map[a->tag]);
          goto failed;
        }
      }

      /* now check the list of ip addresses */
      for (p2 = p->first_down; p2; p2 = p2->right) {
        if (p2->tag != TG_IP) {
          err("%s:%d:%d: tag <%s> is invalid here",
              path, p2->line, p2->column, tag_map[p2->tag]);
          goto failed;
        }
        ip = (struct ip_node*) p2;
        ip->allow = -1;
        for (a = ip->b.first; a; a = a->next) {
          if (a->tag != AT_ALLOW && a->tag != AT_DENY) {
            err("%s:%d:%d: attribute \"%s\" is invalid here",
                path, a->line, a->column, attn_map[a->tag]);
            goto failed;
          }
          if (ip->allow != -1) {
            err("%s:%d:%d: attribute \"allow\" already defined",
                path, a->line, a->column);
            goto failed;
          }
          if ((ip->allow = parse_bool(a->text)) < 0) {
            err("%s:%d:%d invalid boolean value",
                path, a->line, a->column);
            goto failed;
          }
          if (a->tag == AT_DENY) ip->allow = !ip->allow;
        }
        if (ip->allow == -1) ip->allow = 0;

        n = 0;
        if (sscanf(ip->b.text, "%u.%u.%u.%u %n", &b1, &b2, &b3, &b4, &n) == 4
            && !ip->b.text[n]
            && b1 <= 255 && b2 <= 255 && b3 <= 255 && b4 <= 255) {
          ip->addr = b1 << 24 | b2 << 16 | b3 << 8 | b4;
          ip->mask = 0xFFFFFFFF;
        } else if (sscanf(ip->b.text, "%u.%u.%u. %n", &b1, &b2, &b3, &n) == 3
                   && !ip->b.text[n] && b1 <= 255 && b2 <= 255 && b3 <= 255) {
          ip->addr = b1 << 24 | b2 << 16 | b3 << 8;
          ip->mask = 0xFFFFFF00;
        } else if (sscanf(ip->b.text, "%u.%u. %n", &b1, &b2, &n) == 2
                   && !ip->b.text[n] && b1 <= 255 && b2 <= 255) {
          ip->addr = b1 << 24 | b2 << 16;
          ip->mask = 0xFFFF0000;
        } else if (sscanf(ip->b.text, "%u. %n", &b1, &n) == 1
                   && !ip->b.text[n] && b1 <= 255) {
          ip->addr = b1 << 24;
          ip->mask = 0xFF000000;
        } else {
          err("%s:%d:%d: invalid IP-address",
              path, ip->b.line, ip->b.column);
          goto failed;
        }
      }
      break;
    default:
      err("%s: %d: tag <%s> is invalid here", path, p->line,
          tag_map[p->tag]);
      goto failed;
    }
  }

  if (!cfg->socket_path) {
    err("%s: <socket_path> tag must be specified", path);
    goto failed;
  }
  if (!cfg->contests_path) {
    err("%s: <contests_path> tag must be specified", path);
    goto failed;
  }

  return cfg;

 failed:
  /* FIXME: free resources */
  return 0;
}

static void
parse_user_ip(void)
{
  unsigned int b1, b2, b3, b4;
  int n;
  unsigned char *s = getenv("REMOTE_ADDR");

  user_ip = 0;
  if (!s) return;
  n = 0;
  if (sscanf(s, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || s[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
    user_ip = 0xffffffff;
    return;
  }
  user_ip = b1 << 24 | b2 << 16 | b3 << 8 | b4;
}

static void
initialize(int argc, char const *argv[])
{
  path_t fullname;
  path_t dirname;
  path_t basename;
  path_t cfgname;
  char *s = getenv("SCRIPT_FILENAME");

  pathcpy(fullname, argv[0]);
  if (s) pathcpy(fullname, s);
  os_rDirName(fullname, dirname, PATH_MAX);
  os_rGetBasename(fullname, basename, PATH_MAX);
  strcpy(program_name, basename);

  /*
   * if CGI_DATA_PATH is absolute, do not append the program start dir
   */
  if (CGI_DATA_PATH[0] == '/') {
    pathmake(cfgname, CGI_DATA_PATH, "/", basename, ".xml", NULL);
  } else {
    pathmake(cfgname, dirname, "/",CGI_DATA_PATH, "/", basename, ".xml", NULL);
  }

  if (!(config = parse_config(cfgname))) {
    client_not_configured(0, "config file not parsed");
  }
  if (!config->contests_path ||
      !(contests = parse_contest_xml(config->contests_path))) {
    client_not_configured(0, "contests database not parsed");
  }
  parse_user_ip();

  // construct self-reference URL
  {
    unsigned char *http_host = getenv("HTTP_HOST");
    unsigned char *server_port = getenv("SERVER_PORT");
    unsigned char *script_name = getenv("SCRIPT_NAME");

    if (!http_host) http_host = "localhost";
    if (!server_port) server_port = "80";
    if (!script_name) script_name = "/cgi-bin/register";
    snprintf(fullname, sizeof(fullname),
             "http://%s:%s%s", http_host, server_port, script_name);
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
print_choose_language_button(int hr_flag, int no_submit_flag,
                             int action, unsigned char const *label)
{
#if CONF_HAS_LIBINTL - 0 == 1
  if (!label) label = _("Change!");

  if (config->l10n) {
    if (hr_flag) printf("<hr>");
    printf("<h2>%s</h2>\n"
           "%s: <select name=\"locale_id\">"
           "<option value=\"-1\">%s</option>"
           "<option value=\"0\"%s>%s</option>"
           "<option value=\"1\"%s>%s</option>"
           "</select>\n",
           _("Change language"), _("Change language"),
           _("Default language"),
           client_locale_id==0?" selected=\"1\"":"", _("English"),
           client_locale_id==1?" selected=\"1\"":"", _("Russian"));
    if (!no_submit_flag) {
      printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n",
             action, label);

    }
  }
#endif /* CONF_HAS_LIBINTL */
}
static void
read_contest_id(void)
{
  int x = 0, n = 0;
  unsigned char *s;

  user_contest_id = 0;
  if (!(s = cgi_param("contest_id"))) return;
  if (sscanf(s, "%d %n", &x, &n) != 1 || s[n] || x < 0 || x > 1000) return;
  user_contest_id = x;
}

static int
check_contest_eligibility(int id)
{
  struct contest_desc *d;

  if (id <= 0 || id >= contests->id_map_size) return 0;
  d = contests->id_map[id];
  if (!d) return 0;
  // Check the latest date of registration
  // Check the IP
  if (!contests_check_ip(d, user_ip)) return 0;


  return 1;
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

static void
set_locale_by_id(int id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  char *e = 0;
  char env_buf[512];

  if (!config->l10n) return;
  if (!config->l10n_dir) return;
  if (client_locale_id == -1) return;

  switch (client_locale_id) {
  case 1:
    e = "ru_RU.KOI8-R";
    break;
  case 0:
  default:
    client_locale_id = 0;
    e = "C";
    break;
  }

  sprintf(env_buf, "LC_ALL=%s", e);
  putenv(env_buf);
  setlocale(LC_ALL, "");
  bindtextdomain("ejudge", config->l10n_dir);
  textdomain("ejudge");
#endif /* CONF_HAS_LIBINTL */
}

static int
parse_cookies(unsigned char const *cookie)
{
  unsigned char *c_name, *c_value;
  unsigned char const *s;
  size_t len;
  int n;
  unsigned long long val;

  if (!cookie) return -1;
  len = strlen(cookie);
  c_name = (unsigned char *) alloca(len + 1);
  c_value = (unsigned char *) alloca(len + 1);
  s = cookie;
  while (1) {
    if (sscanf(s, " %[^= ] = %[^; ] %n", c_name, c_value, &n) != 2)
      return 0;
    if (!strcmp(c_name, "ID")) {
      if (sscanf(c_value, "%llx %n", &val, &n) != 1 || c_value[n])
        return 0;
      client_cookie = val;
      return 1;
    }
    s += n;
    if (*s == ';') s++;
  }
}

static void put_cookie_header(int force_put, int clear_cookie)
{
  time_t t;
  struct tm gt;
  char buf[128];

  if (clear_cookie || (!user_cookie && client_cookie)) {
    if (client_cookie == user_cookie) client_cookie = 0;
    printf("Set-cookie: ID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
    /*
    fprintf(stderr,
            "Set-cookie: ID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
    */
    client_cookie = user_cookie = 0;
    return;
  }

  if (!user_cookie) return;
  if (!force_put && client_cookie == user_cookie) return;
  client_cookie = user_cookie;
  t = time(0);
  t += 24 * 60 * 60;
  gmtime_r(&t, &gt);
  strftime(buf, sizeof(buf), "%A, %d-%b-%Y %H:%M:%S GMT", &gt);
  printf("Set-cookie: ID=%llx; expires=%s\n", user_cookie, buf);
  //fprintf(stderr, "Set-cookie: ID=%llx; expires=%s\n", user_cookie, buf);
}

static int
check_password(void)
{
  unsigned char *cookie_str = 0;
  int err;
  int new_user_id;
  unsigned long long new_cookie;
  unsigned char *new_name;
  int new_locale_id;
  int new_contest_id;
  unsigned char *new_login;

  read_usecookies();
  if (user_usecookies != 0) cookie_str = getenv("HTTP_COOKIE");
  if (cookie_str && user_action != ACTION_LOGIN) {
    //fprintf(stderr, "Got cookie string: <%s>\n", cookie_str);
    if (parse_cookies(cookie_str)) {
      if (!server_conn) {
        server_conn = userlist_clnt_open(config->socket_path);
      }
      err = userlist_clnt_lookup_cookie(server_conn, user_ip,
                                        client_cookie,
                                        &new_user_id,
                                        &new_login,
                                        &new_name,
                                        &new_locale_id,
                                        &new_contest_id);
      if (err == ULS_LOGIN_COOKIE) {
        // cookie is identified. Good.
        user_login = new_login;
        user_contest_id = new_contest_id;
        user_id = new_user_id;
        user_name = new_name;
        user_cookie = client_cookie;
        if (client_locale_id == -1)
          client_locale_id = new_locale_id;
        if (client_locale_id == -1)
          client_locale_id = 0;
        return 1;
      }
    }
    client_cookie_bad = 1;
  }

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, name_accept_chars, '?');
  if (!(user_password = cgi_param("password"))) {
    user_password = xstrdup("");
  }
  fix_string(user_password, password_accept_chars, '?');
  read_contest_id();  
  
  if (!server_conn) {
    server_conn = userlist_clnt_open(config->socket_path);
  }
  err = userlist_clnt_login(server_conn, user_ip, user_contest_id,
                            client_locale_id,
                            user_usecookies, user_login, user_password,
                            &new_user_id, &new_cookie, &new_name,
                            &new_locale_id);
  if (err != ULS_LOGIN_OK && err != ULS_LOGIN_COOKIE) {
    return 0;
  }
  ASSERT(new_user_id > 0);
  user_id = new_user_id;
  user_name = new_name;
  if (client_locale_id == -1)
    client_locale_id = new_locale_id;
  if (client_locale_id == -1)
    client_locale_id = 0;
  if (err == ULS_LOGIN_COOKIE) {
    user_cookie = new_cookie;
  }
  return 1;
}

static void
logout_page(void)
{
  char *armored_str;
  int armored_len;

  if (!check_password()) {
    put_cookie_header(0, 1);
    set_locale_by_id(client_locale_id);
    /* FIXME: construct self-reference URL */
    printf("Refresh=0; url=%s?locale_id=%d\nContent-type: text/html\n\n", self_url, client_locale_id);
    printf("<html><head><META HTTP-EQUIV=\"Refresh\" content=\"0; url=%s?locale_id=%d\"></head><body><A href=\"%s?locale_id=%d\">Redirecting to %s?locale_id=%d</A>\n", self_url, client_locale_id, self_url, client_locale_id, self_url, client_locale_id);
    return;
  }

  armored_len = html_armored_strlen(user_name);
  armored_str = alloca(armored_len + 16);
  html_armor_string(user_name, armored_str);

  put_cookie_header(0, 1);
  set_locale_by_id(client_locale_id);
  client_put_header(config->charset, "%s, %s!",
                    _("Good-bye"), armored_str);
  printf(_("<p>Click <a href=\"%s?locale_id=%d\">on this link</a> to login again.</p>\n"),
         self_url,
         client_locale_id);
}

static int
authentificate(void)
{
  if (check_password()) return 1;

  if (client_cookie) {
    put_cookie_header(0, 1);
  }

  set_locale_by_id(client_locale_id);
  client_put_header(config->charset, "%s", _("Login failed"));
  printf("<p>%s</p>",
         _("You have provided incorrect login and/or password."));
  return 0;
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
register_for_contest_page(void)
{
  struct contest_desc **farr;
  int fused, i;
  char *armored_str;
  int armored_len;
  unsigned char *act_name;
  unsigned char *xml_text;
  struct xml_tree *regs, *reg;
  struct userlist_contest *regx;
  struct contest_desc *cnts;

  if (!authentificate()) return;

  act_name = user_name;
  if (!act_name || !*act_name) {
    act_name = user_login;
  }
  armored_len = html_armored_strlen(act_name);
  armored_str = alloca(armored_len + 16);
  html_armor_string(act_name, armored_str);

  put_cookie_header(0, 0);

  if (user_contest_id < 0) user_contest_id = 0;
  if (user_contest_id >= contests->id_map_size) user_contest_id = 0;
  if (user_contest_id && !contests->id_map[user_contest_id])
    user_contest_id = 0;

  if (userlist_clnt_get_contests(server_conn, user_id, &xml_text) < 0) {
    return;
  }
  if (!(regs = userlist_parse_contests_str(xml_text))) {
    return;
  }
  if (regs) {
    ASSERT(regs->tag == USERLIST_T_CONTESTS);
    regs = regs->first_down;
  }

  set_locale_by_id(client_locale_id);
  client_put_header(config->charset, _("Personal page of %s"), armored_str);

  printf(_("<p>Hello, %s!</p>\n"), armored_str);

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);
  if (!user_cookie) {
    printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"password\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"usecookies\" value=\"%d\">\n"
           "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">\n",
           user_login, user_password, user_usecookies, client_locale_id);
  }
  printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
         user_contest_id);
  printf("<h2>%s</h2>\n", _("Change the password"));
  printf("<p>%s: <input type=\"password\" name=\"chg_old_passwd\" maxlength=\"16\" size=\"16\"></p>\n", _("Old password"));
  printf("<p>%s: <input type=\"password\" name=\"chg_new_passwd_1\" maxlength=\"16\" size=\"16\"></p>\n", _("New password (1)"));
  printf("<p>%s: <input type=\"password\" name=\"chg_new_passwd_2\" maxlength=\"16\" size=\"16\"></p>\n", _("New password (2)"));
  printf("<p><input type=\"submit\" name=\"action_%d\" value=\"%s\"></p>\n",
         ACTION_CHANGE_PASSWORD, _("Change!"));
  printf("</form>\n");

  if (regs) {
    printf("<h2>%s</h2>\n", _("Check the registration status"));
    printf("<table><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>\n",
           _("Contest ID"), _("Contest name"), _("Status"),
           _("Edit personal data"));
    for (reg = regs; reg; reg = reg->right) {
      ASSERT(reg->tag == USERLIST_T_CONTEST);
      regx = (struct userlist_contest*) reg;
      if (regx->id <= 0 || regx->id >= contests->id_map_size) continue;
      if (!contests->id_map[regx->id]) continue;
      cnts = contests->id_map[regx->id];
      printf("<form method=\"POST\" action=\"%s\" "
             "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
             program_name);
      if (!user_cookie) {
        printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
               "<input type=\"hidden\" name=\"password\" value=\"%s\">\n"
               "<input type=\"hidden\" name=\"usecookies\" value=\"%d\">\n"
               "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">\n",
               user_login, user_password, user_usecookies, client_locale_id);
      }
      printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
             regx->id);
      printf("<tr><td>%d</td><td>%s</td><td>%s</td>"
             "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>"
             "</tr>\n",
             regx->id, cnts->name, 
             gettext(regstatus_str(regx->status)),
             ACTION_REGISTER_CONTEST_PAGE,
             _("Edit"));
      printf("</form>");
    }
    printf("</table>\n");
  }

  // check available contests
  farr = (struct contest_desc**) alloca(sizeof(farr[0]) * (contests->id_map_size + 1));
  memset(farr, 0, sizeof(farr[0]) * (contests->id_map_size + 1));
  fused = 0;
  if (user_contest_id > 0) {
    if (user_contest_id < contests->id_map_size
        && contests->id_map[user_contest_id]
        && check_contest_eligibility(user_contest_id)) {
      for (reg = regs; reg; reg = reg->right) {
        ASSERT(reg->tag == USERLIST_T_CONTEST);
        regx = (struct userlist_contest*) reg;
        if (regx->id == user_contest_id) break;
      }
      if (!reg) {
        farr[fused++] = contests->id_map[user_contest_id];
      }
    }
  } else {
    for (i = 1; i < contests->id_map_size; i++) {
      if (check_contest_eligibility(i)) {
        for (reg = regs; reg; reg = reg->right) {
          ASSERT(reg->tag == USERLIST_T_CONTEST);
          regx = (struct userlist_contest*) reg;
          if (regx->id == i) break;
        }
        if (!reg) {
          farr[fused++] = contests->id_map[i];
        }
      }
    }
  }
  printf("<h2>%s</h2>\n", _("Available contests"));
  if (!fused) {
    printf("<p>%s</p>\n", _("No contests available."));
  } else {
    printf("<table><tr><th>%s</th><th>%s</th><th>%s</th></tr>\n",
           _("Contest ID"), _("Contest name"), _("Register"));
    for (i = 0; i < fused; i++) {
      cnts = farr[i];
      printf("<form method=\"POST\" action=\"%s\" "
             "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
             program_name);
      if (!user_cookie) {
        printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
               "<input type=\"hidden\" name=\"password\" value=\"%s\">\n"
               "<input type=\"hidden\" name=\"usecookies\" value=\"%d\">\n"
               "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">\n",
               user_login, user_password, user_usecookies, client_locale_id);
      }
      printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
             cnts->id);
      printf("<tr><td>%d</td><td>%s</td>"
             "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>"
             "</tr>\n",
             cnts->id, cnts->name, 
             ACTION_REGISTER_CONTEST_PAGE,
             _("Register"));
      printf("</form>");
    }
    printf("</table>\n");
  }

  if (user_cookie) {
    printf("<h2>%s</h2>\n", _("Quit the system"));
    printf("<form method=\"POST\" action=\"%s\" "
           "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
           program_name);
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n",
           ACTION_LOGOUT, _("Logout"));
    printf("</form>");
  }

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);
  if (!user_cookie) {
    printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"password\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"usecookies\" value=\"%d\">\n",
           user_login, user_password, user_usecookies);
  }
  printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
         user_contest_id);
  print_choose_language_button(0, 0, ACTION_MAIN_PAGE, 0);
  printf("</form>\n");
  return;
}

static void
change_password(void)
{
  unsigned char *old_pwd, *new_pwd1, *new_pwd2;
  int res;

  if (!authentificate()) return;
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
  if (!server_conn) {
    error("%s", _("not connected to server"));
  }
  if (!error_log) {
    res = userlist_clnt_set_passwd(server_conn, user_id, old_pwd, new_pwd1);
    if (res < 0) {
      error("%s", gettext(userlist_strerror(-res)));
    }
  }

  set_locale_by_id(client_locale_id);
  if (!error_log) {
    client_put_header(config->charset, _("Password changed successfully"));
    printf("<p>%s</p>\n", _("Password changed successfully."));
  } else {
    client_put_header(config->charset, _("Password changing failed"));
    printf("<p>%s<br><pre><font color=\"red\">%s</font></pre></p>\n",
           _("Password changing failed due to the following reasons."),
           error_log);
  }

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);
  if (!user_cookie) {
    printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"password\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"usecookies\" value=\"%d\">\n",
           user_login,
           error_log?user_password:new_pwd1,
           user_usecookies);
  }
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n",
         ACTION_MAIN_PAGE,
         _("Back"));
  if (user_cookie) {
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n",
           ACTION_LOGOUT, _("Logout"));
  }
  print_choose_language_button(0, 1, 0 ,0);
  printf("</form>\n");
  return;
}

static void
prepare_var_table(struct contest_desc *cnts)
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

static void
read_user_info_from_form(void)
{
  int role, pers;
  unsigned char varbuf[128];
  unsigned char *val = 0;
  int x, n, i;

  if (cgi_param("show_login")) {
    user_show_login = 1;
  }
  if (cgi_param("show_email")) {
    user_show_email = 1;
  }
  if (cgi_param("use_cookies_default")) {
    user_use_cookies_default = 1;
  }

  user_name = xstrdup(cgi_param("name"));
  if (fix_string(user_name, name_accept_chars, '?')) {
    error("%s", _("Field \"User name\" contained invalid characters, which were replaced with '?'."));
  }
  if (strlen(user_name) > 64) {
    error("%s", _("Field \"User name\" was too long."));
    user_name[64] = 0;
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
              || x <= 0 || x > 20) {
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
check_mandatory(void)
{
  int i, role, pers;
  unsigned char const *val;

  if (!user_name || !*user_name) {
    error("%s", _("Mandatory \"User name\" field is empty."));
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
static unsigned char *
unparse_bool(int b)
{
  if (b) return "yes";
  return "no";
}
static void
do_make_user_xml(FILE *f)
{
  int i, role, pers;
  int x, n;
  unsigned char const *val;

  fputs("<?xml version=\"1.0\" encoding=\"koi8-r\"?>\n", f);
  fprintf(f, "<user id=\"%d\" use_cookies=\"%s\">\n",
          user_id, unparse_bool(user_use_cookies_default));
  fprintf(f, "  <login public=\"%s\">%s</login>\n",
          unparse_bool(user_show_login), user_login);
  fprintf(f, "  <email public=\"%s\">%s</email>\n",
          unparse_bool(user_show_email), user_email);
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
        if (i == CONTEST_MF_STATUS) {
          x = 0;
          if (sscanf(val, "%d %n", &x, &n) != 1 || val[n] ||
              x < 0 || x > USERLIST_ST_OTHER) {
            x = 0;
          }
          val = unparse_member_status(x);
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
  unsigned char *xml_ptr = 0;
  size_t xml_size = 0;

  if (!(f = open_memstream((char**) &xml_ptr, &xml_size)))
    goto out_of_mem;
  do_make_user_xml(f);
  if (ferror(f)) goto out_of_mem;
  fclose(f);
  //fprintf(stderr, ">>%s\n", xml_ptr);
  return xml_ptr;

 out_of_mem:
  error("%s", _("Internal error: insufficient memory."));
  if (f) fclose(f);
  if (xml_ptr) xfree(xml_ptr);
  return 0;
}

static void
read_user_info_from_server(void)
{
  unsigned char *user_info_xml = 0;
  struct userlist_user *u = 0;
  struct userlist_member *m;
  int role, pers;
  unsigned char buf[512];

  if (userlist_clnt_get_info(server_conn, user_id, &user_info_xml) < 0) {
    /* FIXME: report a server error */
    return;
  }
  if (!(u = userlist_parse_user_str(user_info_xml))) {
    return;
  }

  ASSERT(u->id == user_id);
  user_xml = u;
  user_show_email = u->show_email;
  user_use_cookies_default = u->default_use_cookies;
  user_show_login = u->show_login;
  user_email = u->email;
  user_name = u->name;
  user_homepage = u->homepage;
  user_inst = u->inst;
  user_instshort = u->instshort;
  user_fac = u->fac;
  user_facshort = u->facshort;

  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;
    if (!u->members[role]) continue;
    member_cur[role] = u->members[role]->total;
    if (member_cur[role] < 0) member_cur[role] = 0;
    if (member_cur[role] > member_max[role])
      member_cur[role] = member_max[role];
    for (pers = 0; pers < member_cur[role]; pers++) {
      m = u->members[role]->members[pers];
      if (!m) continue;

      buf[0] = 0;
      if (m->serial > 0) {
        snprintf(buf, sizeof(buf), "%d", m->serial);
      }
      member_info[role][pers][CONTEST_MF_SERIAL] = xstrdup(buf);
      if (member_edit_flags[role][CONTEST_MF_FIRSTNAME].is_editable) {
        member_info[role][pers][CONTEST_MF_FIRSTNAME] = m->firstname;
      }
      if (member_edit_flags[role][CONTEST_MF_MIDDLENAME].is_editable) {
        member_info[role][pers][CONTEST_MF_MIDDLENAME] = m->middlename;
      }
      if (member_edit_flags[role][CONTEST_MF_SURNAME].is_editable) {
        member_info[role][pers][CONTEST_MF_SURNAME] = m->surname;
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
        if (m->grade > 0 && m->grade < 20) {
          snprintf(buf, sizeof(buf), "%d", m->grade);
        }
        member_info[role][pers][CONTEST_MF_GRADE] = xstrdup(buf);
      }
      if (member_edit_flags[role][CONTEST_MF_GROUP].is_editable) {
        member_info[role][pers][CONTEST_MF_GROUP] = m->group;
      }
      if (member_edit_flags[role][CONTEST_MF_EMAIL].is_editable) {
        member_info[role][pers][CONTEST_MF_EMAIL] = m->email;
      }
      if (member_edit_flags[role][CONTEST_MF_HOMEPAGE].is_editable) {
        member_info[role][pers][CONTEST_MF_HOMEPAGE] = m->homepage;
      }
      if (member_edit_flags[role][CONTEST_MF_INST].is_editable) {
        member_info[role][pers][CONTEST_MF_INST] = m->inst;
      }
      if (member_edit_flags[role][CONTEST_MF_INSTSHORT].is_editable) {
        member_info[role][pers][CONTEST_MF_INSTSHORT] = m->instshort;
      }
      if (member_edit_flags[role][CONTEST_MF_FAC].is_editable) {
        member_info[role][pers][CONTEST_MF_FAC] = m->fac;
      }
      if (member_edit_flags[role][CONTEST_MF_FACSHORT].is_editable) {
        member_info[role][pers][CONTEST_MF_FACSHORT] = m->facshort;
      }
      if (member_edit_flags[role][CONTEST_MF_OCCUPATION].is_editable) {
        member_info[role][pers][CONTEST_MF_OCCUPATION] = m->occupation;
      }
    }
  }
}

static void
action_completed_page(void)
{
  set_locale_by_id(client_locale_id);
  client_put_header(config->charset, "%s", _("Action completed"));
  printf("<p>%s</p>\n", _("Action completed successfully"));

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);
  if (!user_cookie) {
    printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"password\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"usecookies\" value=\"%d\">\n",
           user_login, user_password, user_usecookies);
  }
  printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
         user_contest_id);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n",
         ACTION_MAIN_PAGE,
         _("Back"));
  if (user_cookie) {
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n",
           ACTION_LOGOUT, _("Logout"));
  }
  print_choose_language_button(0, 1, ACTION_MAIN_PAGE ,0);
  printf("</form>");
}

static void
edit_registration_data(void)
{
  int cnts_arm_len;
  char *cnts_arm = 0, *name_arm = 0;
  struct contest_desc *cnts = 0;
  int i, role, pers;
  int errcode;
  unsigned char *user_xml_text;

  if (!check_password()) {
    if (client_cookie) {
      // we probably have to reset the cookie
      put_cookie_header(0, 1);
    }

    set_locale_by_id(client_locale_id);
    client_put_header(config->charset, "%s", _("Login failed"));
    printf("<p>%s</p>",
           _("You have provided incorrect login and/or password."));
    return;
  }

  put_cookie_header(0, 0);
  read_contest_id();
  if (user_contest_id < 0 || user_contest_id >= contests->id_map_size
      || (user_contest_id > 0 && !contests->id_map[user_contest_id])) {
    set_locale_by_id(client_locale_id);
    client_put_header(config->charset, "%s", _("Invalid contest"));
    printf("<p>%s</p>",
           _("The contest identifier is invalid"));
    return;
  }
  if (user_contest_id > 0 && !check_contest_eligibility(user_contest_id)) {
    set_locale_by_id(client_locale_id);
    client_put_header(config->charset, "%s", _("You cannot participate"));
    printf("<p>%s</p>",
           _("You cannot participate in this contest"));
    return;
  }

  name_arm = user_name;
  if (!user_name) {
    name_arm = user_login;
  }

  if (user_contest_id > 0) {
    cnts = contests->id_map[user_contest_id];
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

  while (user_action == ACTION_REMOVE_MEMBER) {
    unsigned char *s = cgi_nname("remove_", 7);
    int n = 0, serial = 0;
    unsigned char name_buf[64];
 
    if (!s) break;
    if (sscanf(s, "remove_%d_%d%n", &role, &pers, &n) != 2) break;
    if (s[n]) break;
    if (role < 0 || role >= CONTEST_LAST_MEMBER) break;
    if (member_max[role] <= 0) break;
    if (pers < 0) break;
    snprintf(name_buf, sizeof(name_buf), "member_info_%d_%d_0", role, pers);
    if (!(s = cgi_param(name_buf))
        || sscanf(s, "%d%n", &serial, &n) != 1 || s[n]
        || serial <= 0) {
      user_action = ACTION_EDIT_PERSONAL_PAGE;
      break;
    }

    n = userlist_clnt_remove_member(server_conn, user_id,
                                    role, pers, serial);
    if (n < 0) {
      error("%s", gettext(userlist_strerror(-n)));
      break;
    }

    // removal is commited, so we must re-read all
    user_action = ACTION_EDIT_PERSONAL_PAGE;
  }

  /* request the necessary information from server */
  /* or read the information from form variables */
  switch (user_action) {
  case ACTION_EDIT_PERSONAL_PAGE:
  case ACTION_REGISTER_CONTEST_PAGE:
  case ACTION_RELOAD_PERSONAL_DATA:
    read_user_info_from_server();
    break;
  default:
    read_user_info_from_form();
    break;
  }

  if (user_action >= ACTION_ADD_NEW_CONTESTANT
      && user_action <= ACTION_ADD_NEW_GUEST) {
    role = user_action - ACTION_ADD_NEW_CONTESTANT;
    if (member_cur[role] >= member_max[role]) {
      error(_("Cannot add a new %s: maximal number reached."),
            gettext(member_string[role]));
    } else {
      member_cur[role]++;
    }
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

  if (!error_log) {
    switch (user_action) {
    case ACTION_REGISTER_FOR_CONTEST:
    case ACTION_COMMIT_PERSONAL_DATA:
      check_mandatory();
      if (error_log) break;
      user_xml_text = make_user_xml();
      if (error_log) break;
      errcode = userlist_clnt_set_info(server_conn, user_id, user_xml_text);
      if (errcode) {
        error("%s", gettext(userlist_strerror(-errcode)));
      }
      if (user_action == ACTION_REGISTER_FOR_CONTEST && !errcode) {
        errcode = userlist_clnt_register_contest(server_conn, user_id,
                                                 user_contest_id);
        if (errcode) {
          error("%s", gettext(userlist_strerror(-errcode)));
        }
      }
      if (!errcode) {
        action_completed_page();
        return;
      }
      break;
    }
  }

  set_locale_by_id(client_locale_id);
  if (user_contest_id > 0) {
    cnts_arm_len = html_armored_strlen(cnts->name);
    cnts_arm = alloca(cnts_arm_len + 16);
    html_armor_string(cnts->name, cnts_arm);
    client_put_header(config->charset,
                      _("Registration form for contest \"%s\""),
                      cnts_arm);
    printf("<p>%s</p>\n",
           _("Please fill up blank fields in this form. Mandatory fields "
             "are marked with (*)."));
  } else {
    client_put_header(config->charset,
                      _("Personal information for \"%s\""), name_arm);
    printf("<p>%s</p>\n",
           _("You may edit your personal information"));
  }

  if (error_log) {
    printf("<h2>%s</h2>\n", _("Form checking results"));
    printf("<p>%s<br>", _("Your form has the following problems"));
    printf("<pre><font color=\"red\">%s</font></pre></p>\n",
           error_log);
  }

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);
  if (!user_cookie) {
    printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"password\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"usecookies\" value=\"%d\">\n",
           user_login, user_password, user_usecookies);
  }
  printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
         user_contest_id);

  printf("<hr><h2>General user information</h2>");
  printf("<p>%s: <input type=\"text\" disabled=\"1\" name=\"user_login\" value=\"%s\" size=\"16\">\n", _("Login"), user_login);
  printf("<br><input type=\"checkbox\" name=\"show_login\"%s>%s",
         user_show_login?" checked=\"yes\"":"",
         _("Show your login to the public?"));
  printf("<br><input type=\"checkbox\" name=\"use_cookies_default\"%s>%s",
         user_use_cookies_default?" checked=\"yes\"":"",
         _("Use cookies by default?"));

  printf("<input type=\"hidden\" name=\"user_email\" value=\"%s\">\n",
         user_email);
  printf("<p>%s: <a href=\"mailto:%s\">%s</a>\n", _("E-mail"), user_email,
         user_email);
  printf("<br><input type=\"checkbox\" name=\"show_email\"%s> %s",
         user_show_email?" checked=\"yes\"":"",
         _("Show your e-mail address to public?"));

  printf("<p>%s%s: <input type=\"text\" name=\"name\" value=\"%s\" maxlength=\"64\" size=\"64\">\n", _("User name"), user_contest_id>0?" (*)":"", user_name);

  /* display change forms */
  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    if (!field_descs[i].is_editable) continue;
    printf("<p>%s%s: <input type=\"text\" name=\"%s\" value=\"%s\" maxlength=\"%d\" size=\"%d\">\n",
           gettext(field_descs[i].orig_name),
           field_descs[i].is_mandatory?" (*)":"",
           field_descs[i].var_name,
           *field_descs[i].var,
           field_descs[i].maxlength,
           field_descs[i].size);
  }

  /* */
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (member_max[role] <= 0) continue;

    printf("<h2>%s: %s</h2>\n", _("Member information"),
           gettext(member_string_pl[role]));
    printf(_("<p>The current number of %s is %d.</p>\n"),
           gettext(member_string_pl[role]), member_cur[role]);
    printf(_("<p>The minimal number of %s is %d.</p>\n"),
           gettext(member_string_pl[role]), member_min[role]);
    printf(_("<p>The maximal number of %s is %d.</p>\n"),
           gettext(member_string_pl[role]), member_max[role]);
    printf("<input type=\"hidden\" name=\"member_cur_%d\" value=\"%d\">\n",
           role, member_cur[role]);

    for (pers = 0; pers < member_cur[role]; pers++) {
      printf("<h3>%s %d</h3><p><input type=\"submit\" name=\"remove_%d_%d\" value=\"%s\">%s</p>\n",
             gettext(member_string[role]), pers + 1,
             role, pers,
             _("Remove member"),
             _("<b>Note!</b> All uncommited changes will be lost!"));
      if (*member_info[role][pers][0]) {
        printf("<p>%s %s.</p>",
               _("Member serial number is"), member_info[role][pers][0]);
        printf("<input type=\"hidden\" name=\"member_info_%d_%d_0\" value=\"%s\">\n", role, pers, member_info[role][pers][0]);
      }

      for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
        if (!member_edit_flags[role][i].is_editable) continue;
        if (i == CONTEST_MF_STATUS) {
          int x, n;
          unsigned char const *val;

          printf("<p>%s%s: <select name=\"member_info_%d_%d_%d\">\n"
                 "<option value=\"\"></option>\n",
                 gettext(member_field_descs[i].orig_name),
                 member_edit_flags[role][i].is_mandatory?" (*)":"",
                 role, pers, i);
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
        printf("<p>%s%s: <input type=\"text\" name=\"member_info_%d_%d_%d\" value=\"%s\" maxlength=\"%d\" size=\"%d\">\n",
               gettext(member_field_descs[i].orig_name),
               member_edit_flags[role][i].is_mandatory?" (*)":"",
               role, pers, i,
               member_info[role][pers][i],
               member_field_descs[i].maxlength,
               member_field_descs[i].size);
      }
    }

    if (member_cur[role] < member_max[role]) {
      printf("<p><input type=\"submit\" name=\"action_%d\" value=\"%s\"></p>\n",
             ACTION_ADD_NEW_CONTESTANT + role, _("Add new member"));
    }
  }

  /* end of form */
  printf("<p><input type=\"reset\" value=\"%s\">\n"
         "<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n"
         "<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n"
         "<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n"
         "<input type=\"submit\" name=\"action_%d\" value=\"%s\">\n",
         _("Reset the form"),
         ACTION_MAIN_PAGE, _("Back"),
         ACTION_RELOAD_PERSONAL_DATA, _("Reload from server"),
         ACTION_COMMIT_PERSONAL_DATA, _("Commit changes"),
         ACTION_REGISTER_FOR_CONTEST, _("Register"));

  if (user_cookie) {
    printf("<h2>%s</h2>\n", _("Quit the system"));
    printf("<p><input type=\"submit\" name=\"action_%d\" value=\"%s\"></p>\n",
           ACTION_LOGOUT,
           _("Logout"));
  }
  print_choose_language_button(0, 1, 0, 0);
  printf("</form>");
}

static void
initial_login_page(void)
{
  char change_lang_btn[64];
  int login_only_flag = 0;

  if (user_action == ACTION_LOGIN_ONLY_PAGE ||
      user_action == ACTION_CHANGE_LANG_LOGIN_ONLY_PAGE) {
    login_only_flag = 1;
  }
  snprintf(change_lang_btn, sizeof(change_lang_btn),
           "action_%d",
           login_only_flag?ACTION_CHANGE_LANG_LOGIN_ONLY_PAGE:
           ACTION_CHANGE_LANG_ENTRY_PAGE);

  if (client_locale_id == -1) client_locale_id = 0;
  set_locale_by_id(client_locale_id);

  printf("Set-cookie: ID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
  client_put_header(config->charset, "%s", _("Log into the system"));

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, name_accept_chars, '?');
  user_password = xstrdup("");
  read_usecookies();
  read_contest_id();  

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);

  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
           user_contest_id);
  }

  if (!login_only_flag) {
    print_choose_language_button(0, 0, ACTION_CHANGE_LANG_ENTRY_PAGE, 0);
    printf("<h2>%s</h2><p>%s</p>\n",
           _("For registered users"),
           _("If you have registered before, please enter your "
             "login and password in the corresponding fields. "
             "Then press the \"Submit\" button."));
  } else {
    printf("<p>%s</p>\n",
           _("Type your login and password and then press \"Submit\" button"));
  }

  printf("<p>%s: <input type=\"text\" name=\"login\" value=\"%s\""
           " size=\"16\" maxlength=\"16\">\n",
         _("Login"), user_login);
  printf("<p>%s: <input type=\"password\" name=\"password\" value=\"%s\""
         " size=\"16\" maxlength=\"16\">\n",
         _("Password"), user_password);

  printf("<p>%s: <input type=\"radio\" name=\"usecookies\" value=\"-1\"%s>%s,"
         " <input type=\"radio\" name=\"usecookies\" value=\"0\"%s>%s,"
         " <input type=\"radio\" name=\"usecookies\" value=\"1\"%s>%s.</p>",
         _("Use cookies"),
         user_usecookies == -1?" checked=\"yes\"":"",
         _("default"),
         user_usecookies == 0?" checked=\"yes\"":"",
         _("no"),
         user_usecookies == 1?" checked=\"yes\"":"",
         _("yes"));

  printf("<p><input type=\"submit\" name=\"action_%d\" value=\"%s\">", ACTION_LOGIN, _("Submit"));

  if (!login_only_flag) {
    printf("<h2>%s</h2><p>%s</p>\n",
           _("For new users"),
           _("If you have not registered before, please press "
             "the \"Register new\" button."));
    
    printf("<p><input type=\"submit\" name=\"action_%d\" value=\"%s\">\n",
           ACTION_REGISTER_ENTRY_PAGE,
           _("Register new"));
  }

  if (login_only_flag) {
    print_choose_language_button(0, 0, ACTION_CHANGE_LANG_ENTRY_PAGE, 0);
  }

  printf("</form>");
}

static void
registration_is_complete(void)
{
  char buf[512];
  char *p = buf;

  p += sprintf(p, "%s?login=%s&action=%d", self_url, user_login,
               ACTION_LOGIN_ONLY_PAGE);
  if (client_locale_id >= 0)
    p += sprintf(p, "&locale_id=%d", client_locale_id);
  if (user_contest_id > 0)
    p += sprintf(p, "&contest_id=%d", user_contest_id);
  if (user_usecookies != -1)
    p += sprintf(p, "&usecookies=%d", user_usecookies);

  printf("Set-cookie: ID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
  client_put_header(config->charset, "%s", _("User registration is complete"));

  printf(_("<p>Registration of a new user is completed successfully. "
           "An e-mail messages is sent to the address <tt>%s</tt>. "
           "This message contains the login name, assigned to you, "
           "as well as your password for initial login. "
           "To proceed with registration, clink <a href=\"%s\">on this link</a>.</p>"
           "<p><b>Note</b>, that you should login to the system for "
           "the first time no later, than in 24 hours after the initial "
           "user registration, or the registration is void."),
         user_email, buf);
}

static void
register_new_user_page(void)
{
  if (client_locale_id == -1) client_locale_id = 0;
  set_locale_by_id(client_locale_id);
  error_log = 0;

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  if (fix_string(user_login, login_accept_chars, '?') > 0) {
    error("%s", _("\"Login\" has invalid characters, which were replaced with '?'."));
  }
  if (!(user_email = cgi_param("email"))) {
    user_email = xstrdup("");
  }
  if (fix_string(user_email, email_accept_chars, '?') > 0) {
    error("%s", _("\"E-mail\" has invalid characters, which were replaced with '?'."));
  }
  if (user_action == ACTION_REGISTER_REGISTER_PAGE && !*user_email) {
    error("%s", _("Mandatory \"E-mail\" is empty."));
  }
  read_usecookies();
  read_contest_id();  

  // initial validation is passed, so may try to register
  if (!error_log && user_action == ACTION_REGISTER_REGISTER_PAGE) {
    int err;

    if (!server_conn) {
      server_conn = userlist_clnt_open(config->socket_path);
    }
    err = userlist_clnt_register_new(server_conn, user_ip, user_contest_id, client_locale_id, user_usecookies, user_login, user_email);
    if (!err) {
      // registration is successful
      registration_is_complete();
      return;
    }
    error("%s", gettext(userlist_strerror(-err)));
  }

  printf("Set-cookie: ID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
  client_put_header(config->charset, "%s", _("Register a new user"));

  if (error_log) {
    printf("<h2>%s</h2><p>%s<br><pre><font color=\"red\">%s</font></pre></p>\n",
           _("The form contains error(s)"),
           _("Unfortunately, your form cannot be accepted as is, since "
             "it contains several errors. The list of errors is given "
             "below."),
           error_log);
  }

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);

  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
           user_contest_id);
  }

  print_choose_language_button(0, 0, ACTION_CHANGE_LANG_REGISTER_PAGE, 0);

  printf("<h2>%s</h2><p>%s</p><p>%s</p>\n",
         _("Registration rules"),
         _("Please, fill up all the fields in the form below. "
           "Fields, marked with (*), are mandatory. "
           "When the form is completed, press \"Register\" button."),
         _("Shortly after that you should receive an e-mail message "
           "with a password to the system. Use this password for the first "
           " login. "
           "<b>Note</b>, that you must log in "
           "24 hours after the form is filled and submitted, or "
           "your registration will be void!"));
  printf("<p>%s</p>",
         _("Type in a desirable login identifier. <b>Note</b>, "
           "that your login still <i>may be</i> (in some cases) assigned "
           "automatically."));
  printf("<p>%s: <input type=\"text\" name=\"login\" value=\"%s\""
           " size=\"16\" maxlength=\"16\">\n",
         _("Login"), user_login);
  printf("<p>%s</p>", _("Type your valid e-mail address"));
  printf("<p>%s (*): <input type=\"text\" name=\"email\" value=\"%s\""
         " size=\"64\" maxlength=\"64\">\n",
         _("E-mail"), user_email);
  printf("<p>%s</p>\n", _("Please, specify, whether you want to use cookies to support session. Generally, it is more convenient to use, than not to use cookies."));
  printf("<p>%s: <input type=\"radio\" name=\"usecookies\" value=\"-1\"%s>%s,"
         " <input type=\"radio\" name=\"usecookies\" value=\"0\"%s>%s,"
         " <input type=\"radio\" name=\"usecookies\" value=\"1\"%s>%s.</p>",
         _("Use cookies"),
         user_usecookies == -1?" checked=\"yes\"":"",
         _("server default"),
         user_usecookies == 0?" checked=\"yes\"":"",
         _("no"),
         user_usecookies == 1?" checked=\"yes\"":"",
         _("yes"));
  printf("<p><input type=\"reset\" value=\"%s\">",
         _("Reset the form"));
  printf("<p><input type=\"submit\" name=\"action_%d\" value=\"%s\">",
         ACTION_REGISTER_REGISTER_PAGE,
         _("Register"));

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

  gettimeofday(&begin_time, 0);
  initialize(argc, argv);

  if (!check_source_ip()) {
    client_access_denied(config->charset);
  }

  cgi_read(config->charset);
  read_locale_id();
  parse_user_action();

  switch (user_action) {
  case ACTION_LOGOUT:
    logout_page();
    break;
  case ACTION_MAIN_PAGE:
  case ACTION_LOGIN:
    register_for_contest_page();
    break;
  case ACTION_REGISTER_ENTRY_PAGE:
  case ACTION_REGISTER_REGISTER_PAGE:
  case ACTION_CHANGE_LANG_REGISTER_PAGE:
    register_new_user_page();
    break;
  case ACTION_EDIT_PERSONAL_PAGE:
  case ACTION_REGISTER_CONTEST_PAGE:
  case ACTION_ADD_NEW_CONTESTANT:
  case ACTION_ADD_NEW_RESERVE:
  case ACTION_ADD_NEW_COACH:
  case ACTION_ADD_NEW_ADVISOR:
  case ACTION_ADD_NEW_GUEST:
  case ACTION_REMOVE_MEMBER:
  case ACTION_RELOAD_PERSONAL_DATA:
  case ACTION_COMMIT_PERSONAL_DATA:
  case ACTION_REGISTER_FOR_CONTEST:
    edit_registration_data();
    break;
  case ACTION_CHANGE_PASSWORD:
    change_password();
    break;
  case ACTION_CHANGE_LANG_ENTRY_PAGE:
  case ACTION_LOGIN_ONLY_PAGE:
  case ACTION_CHANGE_LANG_LOGIN_ONLY_PAGE:
  default:
    initial_login_page();
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
    printf("<hr><p>%s: %ld %s\n",
           _("Page generation time"),
           end_time.tv_usec / 1000 + end_time.tv_sec * 1000,
           _("msec"));
  }
  client_put_footer();
  if (server_conn) {
    userlist_clnt_close(server_conn);
  }

  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
