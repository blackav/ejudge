/* -*- mode: c -*- */
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

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#endif

enum
  {
    TG_CONFIG = 1,
    TG_ACCESS,
    TG_IP,
    TG_FIELD,
    TG_SOCKET_PATH,
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
    AT_MANDATORY,
    AT_OPTIONAL,
    AT_SIZE,
    AT_MAXLENGTH,
  };
enum
  {
    F_LOGIN = 1,
    F_EMAIL,
    F_NAME,
    F_HOMEPAGE,

    F_ARRAY_SIZE
  };

struct field_node
{
  struct xml_tree b;
  int mandatory;
  int id;
  int size;
  int maxlength;
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
  struct access_node *access;
  struct field_node *fields[F_ARRAY_SIZE];
};

static struct config_node *config;
static struct contest_list *contests;

static int client_locale_id;

static unsigned char *user_login;
static unsigned char *user_password;
static unsigned char *user_usecookies;
static unsigned char *user_email;
static unsigned char *user_name;
static unsigned char *user_homepage;
static int user_contest_id;
static struct userlist_clnt *server_conn;
static unsigned long user_ip;
static unsigned long long client_cookie;
static int client_cookie_bad;
static unsigned long long user_cookie;
static int user_id;
static unsigned char *user_name;

static unsigned char *submission_log;

struct field_desc
{
  char *orig_name;
  char *var_name;
  unsigned char **var;
  const unsigned char *accept_chars;
  int repl_char;
  char *loc_name;              /* localized name of the field */
};

static char const login_accept_chars[] =
"._-0123456789?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char const email_accept_chars[] =
"@.%!+=_-0123456789?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char const name_accept_chars[] =
" !#$%*+,-./0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"abcdefghijklmnopqrstuvwxyz{|}~"
" ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß"
"àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";
static char const homepage_accept_chars[] =
" :!#$%*+,-./0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"abcdefghijklmnopqrstuvwxyz{|}~";
static char const password_accept_chars[] =
" !#$%\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"`abcdefghijklmnopqrstuvwxyz{|}~ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿"
"ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"
;

#define _(x) x
static struct field_desc field_descs[F_ARRAY_SIZE] = 
{
  { 0 },                        /* entry 0 is empty */

  { _("Login"), "login", &user_login, login_accept_chars, '?' },
  { _("E-mail"), "email", &user_email, email_accept_chars, '_' },
  { _("Name"), "name", &user_name, name_accept_chars, '?' },
  { _("Homepage"), "homepage", &user_homepage, homepage_accept_chars, '?' },
};
#undef _
#if CONF_HAS_LIBINTL - 0 == 1
#define _(x) gettext(x)
#else
#define _(x) x
#endif

static char const * const tag_map[] =
{
  0,
  "register_config",
  "access",
  "ip",
  "field",
  "socket_path",

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
  "mandatory",
  "optional",
  "size",
  "maxlength",

  0
};
static char const * const field_map[] =
{
  0,
  "login",
  "email",
  "name",
  "homepage",

  0
};

static void *
node_alloc(int tag)
{
  switch (tag) {
  case TG_CONFIG: return xcalloc(1, sizeof(struct config_node));
  case TG_ACCESS: return xcalloc(1, sizeof(struct access_node));
  case TG_IP: return xcalloc(1, sizeof(struct ip_node));
  case TG_FIELD: return xcalloc(1, sizeof(struct field_node));
  case TG_SOCKET_PATH: return xcalloc(1, sizeof(struct xml_tree));
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
  struct field_node *pf;
  unsigned int b1, b2, b3, b4;
  int i, n;

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
    case TG_FIELD:
      // nested tags are not allowed
      for (p2 = p->first_down; p2; p2 = p2->right) {
        err("%s:%d:%d: tag <%s> is invalid here", path, p2->line,
            p2->column, tag_map[p2->tag]);
        goto failed;
      }
      // text is not allowed
      if (p->text && p->text[0]) {
        err("%s:%d:%d: <field> tag cannot contain text",
            path, p->line, p->column);
        goto failed;
      }
      xfree(p->text);
      p->text = 0;
      pf = (struct field_node*) p;
      pf->mandatory = -1;
      for (a = p->first; a; a = a->next) {
        switch (a->tag) {
        case AT_ID:
          for (i = 1; field_map[i]; i++)
            if (!strcmp(a->text, field_map[i])) break;
          if (!field_map[i] || i >= F_ARRAY_SIZE) {
            err("%s:%d:%d: invalid field id \"%s\"",
                path, a->line, a->column, a->text);
            goto failed;
          }
          if (cfg->fields[i]) {
            err("%s:%d:%d: field \"%s\" already defined",
                path, a->line, a->column, a->text);
            goto failed;
          }
          cfg->fields[i] = pf;
          break;
        case AT_MANDATORY:
        case AT_OPTIONAL:
          if (pf->mandatory != -1) {
            err("%s:%d:%d: attribute \"mandatory\" already defined",
                path, a->line, a->column);
            goto failed;
          }
          if ((pf->mandatory = parse_bool(a->text)) < 0) {
            err("%s:%d:%d: invalid boolean value",
                path, a->line, a->column);
            goto failed;
          }
          if (a->tag == AT_OPTIONAL) pf->mandatory = !pf->mandatory;
          break;
        case AT_SIZE:
          i = n = 0;
          if (sscanf(a->text, "%d %n", &i, &n) != 1 || a->text[n]
              || i <= 0 || i >= 100000) {
            err("%s:%d:%d: invalid value", path, a->line, a->column);
            goto failed;
          }
          pf->size = i;
          break;
        case AT_MAXLENGTH:
          i = n = 0;
          if (sscanf(a->text, "%d %n", &i, &n) != 1 || a->text[n]
              || i <= 0 || i >= 100000) {
            err("%s:%d:%d: invalid value", path, a->line, a->column);
            goto failed;
          }
          pf->maxlength = i;
          break;
        default:
          err("%s:%d:%d: attribute \"%s\" is invalid here",
              path, a->line, a->column, attn_map[a->tag]);
          goto failed;
        }
      }
      if (pf->mandatory == -1) pf->mandatory = 0;
      if (!pf->size) pf->size = 64;
      if (!pf->maxlength) pf->maxlength = 64;
      if (pf->size > pf->maxlength) pf->size = pf->maxlength;
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
  path_t cntsname;
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
    pathmake(cntsname, CGI_DATA_PATH, "/", "contests.xml", NULL);
  } else {
    pathmake(cfgname, dirname, "/",CGI_DATA_PATH, "/", basename, ".xml", NULL);
    pathmake(cntsname, dirname, "/",CGI_DATA_PATH,"/", "contests.xml", NULL);
  }

  if (!(config = parse_config(cfgname))) {
    client_not_configured(0, "config file not parsed");
  }
  if (!(contests = parse_contest_xml(cntsname))) {
    client_not_configured(0, "config file not parsed");
  }
  parse_user_ip();
}

static void
prepare_var_table(void)
{
  int i;

  // initialize field_descs array
  for (i = 1; i < F_ARRAY_SIZE; i++) {
    if (!field_descs[i].orig_name) continue;
#if CONF_HAS_LIBINTL - 0 == 1
    field_descs[i].loc_name = gettext(field_descs[i].orig_name);
#else
    field_descs[i].loc_name = field_descs[i].orig_name;
#endif /* CONF_HAS_LIBINTL */
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
verify_form_and_submit(void)
{
  char tmpbuf[1024];
  int errors = 0;
  struct field_node *p;
  char *log = 0;
  int i;
  unsigned char *var;

  for (i = 1; i < F_ARRAY_SIZE; i++) {
    if (!(p = config->fields[i])) continue;
    var = *field_descs[i].var;
    if (p->mandatory && !var[0]) {
      snprintf(tmpbuf, sizeof(tmpbuf),
               _("Mandatory field \"%s\" not specified\n"),
               field_descs[i].loc_name);
      log = xstrmerge1(log, tmpbuf);
      errors++;
    }
    if (fix_string(var, field_descs[i].accept_chars,
                   field_descs[i].repl_char) > 0) {
      snprintf(tmpbuf, sizeof(tmpbuf),
               _("Field \"%s\" contains invalid characters, which were converted to '%c'\n"), field_descs[i].loc_name, field_descs[i].repl_char);
      log = xstrmerge1(log, tmpbuf);
      errors++;
    }
    if (strlen(var) > p->maxlength) {
      snprintf(tmpbuf, sizeof(tmpbuf),
               _("Field \"%s\" is too long and truncated\n"),
               field_descs[i].loc_name);
      var[p->maxlength] = 0;
      log = xstrmerge1(log, tmpbuf);
      errors++;
    }
  }

  submission_log = log;
  if (errors > 0) return;
  // submit form
  submission_log = xstrdup("not implemented yet!");
}

static void
print_choose_language_button(char const *name, int hr_flag)
{
#if CONF_HAS_LIBINTL - 0 == 1
  if (!name) name = "refresh";

  if (config->l10n) {
    if (hr_flag) printf("<hr>");
    printf("<h2>%s</h2>\n"
           "%s: <select name=\"locale_id\">"
           "<option value=\"-1\">%s</option>"
           "<option value=\"0\"%s>%s</option>"
           "<option value=\"1\"%s>%s</option>"
           "</select>"
           "<input type=\"submit\" name=\"%s\" value=\"%s\">\n",
           _("Change language"), _("Change language"),
           _("Default language"),
           client_locale_id==0?" selected=\"1\"":"", _("English"),
           client_locale_id==1?" selected=\"1\"":"", _("Russian"),
           name,
           _("Change!"));
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
      if (sscanf(c_value, "%llu %n", &val, &n) != 1 || c_value[n])
        return 0;
      client_cookie = val;
      return 1;
    }
    s += n;
    if (*s == ';') s++;
  }
}

static int
check_password(void)
{
  unsigned char *cookie_str;
  int err;
  int new_user_id;
  unsigned long long new_cookie;
  unsigned char *new_name;
  int new_locale_id;
  int new_contest_id;
  unsigned char *new_login;

  user_usecookies = 0;
  if (cgi_param("usecookies")) {
    user_usecookies = xstrdup("1");
  }

  cookie_str = getenv("HTTP_COOKIE");
  if (cookie_str) {
    fprintf(stderr, "Got cookie string: <%s>\n", cookie_str);
    if (parse_cookies(cookie_str)) {
      server_conn = userlist_clnt_open(config->socket_path);
      err = userlist_clnt_lookup_cookie(server_conn, user_ip,
                                        client_cookie,
                                        &new_user_id,
                                        &new_login,
                                        &new_name,
                                        &new_locale_id,
                                        &new_contest_id);
      server_conn = userlist_clnt_close(server_conn);
      if (!err) {
        // cookie is identified. Good.
        user_login = new_login;
        user_contest_id = new_contest_id;
        user_id = new_user_id;
        user_name = new_name;
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
  
  server_conn = userlist_clnt_open(config->socket_path);
  err = userlist_clnt_login(server_conn, user_ip, user_contest_id,
                            client_locale_id,
                            !!user_usecookies, user_login, user_password,
                            &new_user_id, &new_cookie, &new_name,
                            &new_locale_id);
  server_conn = userlist_clnt_close(server_conn);
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
  if (ULS_LOGIN_COOKIE) {
    user_cookie = new_cookie;
  }
  return 1;
}

static void
initial_login_page(int login_only)
{
  if (client_locale_id == -1) client_locale_id = 0;
  set_locale_by_id(client_locale_id);

  client_put_header(config->charset, "%s", _("Log into the system"));

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  fix_string(user_login, name_accept_chars, '?');
  user_password = xstrdup("");
  user_usecookies = 0;
  if (cgi_param("usecookies")) {
    user_usecookies = xstrdup("1");
  }
  read_contest_id();  

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);

  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
           user_contest_id);
  }
  if (login_only) {
    printf("<input type=\"hidden\" name=\"login_dlg\" value=\"1\">\n");
  }

  if (!login_only)
    print_choose_language_button(0, 0);

  if (!login_only) {
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

  printf("<p><input type=\"checkbox\" name=\"usecookies\" value=\"%s\"%s>%s\n",
         "1",
         user_usecookies?" checked=\"yes\"":"",
         _("Use cookies"));

  printf("<p><input type=\"submit\" name=\"do_login\" value=\"%s\">", _("Submit"));

  if (!login_only) {
    printf("<h2>%s</h2><p>%s</p>\n",
           _("For new users"),
           _("If you have not registered before, please press "
             "the \"Register new\" button."));
    
    printf("<p><input type=\"submit\" name=\"register\" value=\"%s\">\n",
           _("Register new"));
  }

  if (login_only)
    print_choose_language_button(0, 0);

  printf("</form>");
}

static void
registration_is_complete(void)
{
  char buf[512];
  char *p = buf;

  p += sprintf(p, "%s?login=%s&login_dlg=1", program_name, user_login);
  if (client_locale_id >= 0)
    p += sprintf(p, "&locale_id=%d", client_locale_id);
  if (user_contest_id > 0)
    p += sprintf(p, "&contest_id=%d", user_contest_id);
  if (user_usecookies)
    p += sprintf(p, "&usecookies=1");

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
register_new_user(int commit_flag)
{
  char msgbuf[1024];

  if (client_locale_id == -1) client_locale_id = 0;
  set_locale_by_id(client_locale_id);
  submission_log = 0;

  if (!(user_login = cgi_param("login"))) {
    user_login = xstrdup("");
  }
  if (fix_string(user_login, login_accept_chars, '?') > 0) {
    submission_log = xstrmerge1(submission_log, _("\"Login\" has invalid characters, which were replaced with '?'\n"));
  }
  if (!(user_email = cgi_param("email"))) {
    user_email = xstrdup("");
  }
  if (fix_string(user_email, email_accept_chars, '?') > 0) {
    submission_log = xstrmerge1(submission_log, _("\"E-mail\" has invalid characters, which were replaced with '?'\n"));
  }
  if (commit_flag && !*user_email) {
    submission_log = xstrmerge1(submission_log, _("Mandatory \"E-mail\" is empty\n"));
  }
  if ((user_usecookies = cgi_param("usecookies"))) {
    xfree(user_usecookies);
    user_usecookies = xstrdup("1");
  }
  read_contest_id();  

  while (!submission_log && commit_flag) {
    int err;

    server_conn = userlist_clnt_open(config->socket_path);
    err = userlist_clnt_register_new(server_conn, user_ip, user_contest_id, client_locale_id, !!user_usecookies, user_login, user_email);
    server_conn = userlist_clnt_close(server_conn);
    if (!err) {
      registration_is_complete();
      return;
    }
    switch (err) {
    case ULS_ERR_LOGIN_USED:
      sprintf(msgbuf, _("Login \"%s\" is used by someone else\n"),
              user_login);
      submission_log = xstrmerge1(submission_log, msgbuf);
      break;
    default:
      sprintf(msgbuf, _("Registration error %d\n"), err);
      submission_log = xstrmerge1(submission_log, msgbuf);
      break;
    }
  }

  client_put_header(config->charset, "%s", _("Register a new user"));

  if (submission_log) {
    printf("<h2>%s</h2><p>%s<br><pre><font color=\"red\">%s</font></pre></p>\n",
           _("The form contains error(s)"),
           _("Unfortunately, your form cannot be accepted as is, since "
             "it contains several errors. The list of errors is given "
             "below."),
           submission_log);
  }

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);

  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
           user_contest_id);
  }

  print_choose_language_button("register", 0);

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
  printf("<p>%s</p>", _("Check this box to enable cookies"));
  printf("<p><input type=\"checkbox\" name=\"usecookies\" value=\"%s\"%s>%s\n",
         "1",
         user_usecookies?" checked=\"yes\"":"",
         _("Use cookies"));
  printf("<p><input type=\"reset\" value=\"%s\">",
         _("Reset the form"));
  printf("<p><input type=\"submit\" name=\"do_register\" value=\"%s\">",
         _("Register"));

  printf("</form>");
}

int
main(int argc, char const *argv[])
{
  struct timeval begin_time, end_time;
  int i;
  unsigned char *var;

  gettimeofday(&begin_time, 0);
  initialize(argc, argv);

  if (!check_source_ip()) {
    client_access_denied(config->charset);
  }

  cgi_read(config->charset);
  read_locale_id();

  if (cgi_param("login_dlg")) {
    initial_login_page(1);
  } else if (cgi_param("do_login")) {
    //perform_login();
  } else if (cgi_param("register")) {
    register_new_user(0);
  } else if (cgi_param("do_register")) {
    register_new_user(1);
  } else {
    initial_login_page(0);
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

  return 0;













  /*
  prepare_var_table();

  for (i = 1; i < F_ARRAY_SIZE; i++) {
    if (config->fields[i]) {
      var = cgi_param(field_descs[i].var_name);
    }
    if (!var) var = xstrdup("");
    *field_descs[i].var = var;
  }

  if (cgi_param("submit")) {
    verify_form_and_submit();
  }
  */


  client_put_header(config->charset, "%s", _("Registration form"));

  if (submission_log) {
    printf("<h2>%s</h2><p>%s<p><pre>%s</pre>\n",
           _("Form is filled incorrectly"),
           _("Unfortunately, your form cannot be accepted as is. "
             "Here is the list of problems found in it. "
             "Please, correct the form and submit it again."),
           submission_log);
  } else {
    printf("<h2>%s</h2><p>%s</p><p>%s</p>\n",
           _("Registration rules"),
           _("Please, fill up all the fields in the form below. "
             "Fields, marked with (*), are mandatory. "
             "When the form is completed, press \"Submit\" button."),
           _("Shortly after that you should receive an e-mail message "
             "with a password to the system. Use this password for the first "
             " login. "
             "<b>Note</b>, that you must log in "
             "24 hours after the form is filled and submitted, or "
             "your registration will be void!"));
  }

  // form header
  printf("<hr><form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);

  for (i = 1; i < F_ARRAY_SIZE; i++) {
    if (!config->fields[i]) continue;
    var = *field_descs[i].var;
    printf("<p>%s%s: <input type=\"text\" name=\"%s\" value=\"%s\""
           " size=\"%d\" maxlength=\"%d\">\n",
           field_descs[i].loc_name,
           config->fields[i]->mandatory?" (*)" : "",
           field_descs[i].var_name,
           var,
           config->fields[i]->size,
           config->fields[i]->maxlength);
  }

  printf("<p><input type=\"submit\" name=\"submit\" value=\"%s\">\n",
         _("Register"));
  printf("<p><input type=\"reset\" value=\"%s\">\n",
         _("Reset the form"));

#if CONF_HAS_LIBINTL - 0 == 1
  if (config->l10n) {
    printf("<hr><h2>%s</h2>\n"
           "%s: <select name=\"locale_id\">"
           "<option value=\"0\"%s>%s</option>"
           "<option value=\"1\"%s>%s</option>"
           "</select>"
           "<input type=\"submit\" name=\"refresh\" value=\"%s\">\n",
           _("Change language"), _("Change language"),
           client_locale_id==0?" selected=\"1\"":"", _("English"),
           client_locale_id==1?" selected=\"1\"":"", _("Russian"),
           _("Change!"));
  }
#endif /* CONF_HAS_LIBINTL */

  // form footer
  printf("</form>");

  client_put_footer();

  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
