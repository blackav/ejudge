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
#include "misctext.h"

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

enum
  {
    TG_CONFIG = 1,
    TG_ACCESS,
    TG_IP,
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
};

static struct config_node *config;
static struct contest_list *contests;

static int client_locale_id;

static unsigned char *user_login;
static unsigned char *user_password;
static int user_usecookies;
static unsigned char *user_email;
static unsigned char *user_name;
static unsigned char *user_homepage;
static int user_show_email;
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
static struct field_desc field_descs[CONTEST_LAST_FIELD] = 
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
  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
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

#if 0
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
#endif

static void
print_choose_language_button(char const *name, int hr_flag, int no_submit_flag)
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
           "</select>\n",
           _("Change language"), _("Change language"),
           _("Default language"),
           client_locale_id==0?" selected=\"1\"":"", _("English"),
           client_locale_id==1?" selected=\"1\"":"", _("Russian"));
    if (!no_submit_flag) {
      printf("<input type=\"submit\" name=\"%s\" value=\"%s\">\n",
             name, _("Change!"));

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
  if (cookie_str) {
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
      if (!err) {
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
  if (ULS_LOGIN_COOKIE) {
    user_cookie = new_cookie;
  }
  return 1;
}

static void
logout_page(void)
{
  char *armored_str;
  int armored_len;
  char *self_url = "contest.cmc.msu.ru/cgi-bin/register";

  if (!check_password()) {
    put_cookie_header(0, 1);
    set_locale_by_id(client_locale_id);
    /* FIXME: construct self-reference URL */
    printf("Refresh=0; url=http://%s?locale_id=%d\nContent-type: text/html\n\n", self_url, client_locale_id);
    printf("<html><head><META HTTP-EQUIV=\"Refresh\" content=\"0; url=http://%s?locale_id=%d\"></head><body><A href=\"http://%s?locale_id=%d\">Redirecting to http://%s?locale_id=%d</A>\n", self_url, client_locale_id, self_url, client_locale_id, self_url, client_locale_id);
    return;
  }

  armored_len = html_armored_strlen(user_name);
  armored_str = alloca(armored_len + 16);
  html_armor_string(user_name, armored_str);

  put_cookie_header(0, 1);
  set_locale_by_id(client_locale_id);
  client_put_header(config->charset, "%s, %s!",
                    _("Good-bye"), armored_str);
  printf(_("<p>Clink <a href=\"http://%s?locale_id=%d\">on this link</a> to login again.</p>\n"),
         self_url,
         client_locale_id);
}

static void
register_for_contest_page(void)
{
  struct contest_desc **farr;
  int fused, i;
  char *armored_str;
  int armored_len;
  int acn_len;
  char *acn;

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

  armored_len = html_armored_strlen(user_name);
  armored_str = alloca(armored_len + 16);
  html_armor_string(user_name, armored_str);

  put_cookie_header(0, 0);

  if (user_contest_id < 0) user_contest_id = 0;
  if (user_contest_id >= contests->id_map_size) user_contest_id = 0;
  if (user_contest_id && !contests->id_map[user_contest_id])
    user_contest_id = 0;

  farr = (struct contest_desc**) alloca(sizeof(farr[0]) * (contests->id_map_size + 1));
  memset(farr, 0, sizeof(farr[0]) * (contests->id_map_size + 1));
  fused = 0;

  if (user_contest_id != 0) {
    if (check_contest_eligibility(user_contest_id)) {
      farr[fused++] = contests->id_map[user_contest_id];
    } else {
      user_contest_id = 0;
    }
  }

  if (user_contest_id == 0) {
    for (i = 1; i < contests->id_map_size; i++) {
      if (check_contest_eligibility(i)) {
        farr[fused++] = contests->id_map[i];
      }
    }
  }

  if (!fused) {
    set_locale_by_id(client_locale_id);
    client_put_header(config->charset, "%s",
                      _("No contests available"));
    printf("<form method=\"POST\" action=\"%s\" "
           "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
           program_name);
    if (!user_cookie) {
      printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
             "<input type=\"hidden\" name=\"password\" value=\"%s\">\n",
             user_login, user_password);
    }
    printf(_("<p>Hello, %s!</p>"), armored_str);
    printf("<p>%s</p>\n",
           _("Unfortunately, there are no contests, available for you. "
             "You may proceed to edit personal information."));
    printf("<input type=\"submit\" name=\"edit_personal\" value=\"%s\">\n"
           "<input type=\"submit\" name=\"action_logout\" value=\"%s\">\n",
           _("Edit personal information"), _("Logout"));
    print_choose_language_button(0, 0, 1);
    printf("</form>\n");
    return;
  }

  if (fused == 1) {
    acn_len = html_armored_strlen(farr[0]->name);
    acn = alloca(acn_len + 16);
    html_armor_string(farr[0]->name, acn);

    set_locale_by_id(client_locale_id);
    client_put_header(config->charset,
                      _("Register for contest \"%s\""), acn);
    printf("<form method=\"POST\" action=\"%s\" "
           "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
           program_name);
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
           farr[0]->id);
    if (!user_cookie) {
      printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
             "<input type=\"hidden\" name=\"password\" value=\"%s\">\n",
             user_login, user_password);
    }
    printf(_("<p>Hello, %s!</p>"), armored_str);
    printf(_("<p>You may register for participation in contest \"%s\".</p>"),
           acn);
    printf("<input type=\"submit\" name=\"action_register_contest\" value=\"%s\">\n"
           "<input type=\"submit\" name=\"action_logout\" value=\"%s\">\n",
           _("Register for this contest"), _("Logout"));                      
    print_choose_language_button(0, 0, 1);
    printf("</form>\n");
    return;
  }

  set_locale_by_id(client_locale_id);
  client_put_header(config->charset,
                    _("Choose a contest to register"));
  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);
  if (!user_cookie) {
    printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
           "<input type=\"hidden\" name=\"password\" value=\"%s\">\n",
           user_login, user_password);
  }
  printf("<select name=\"contest_id\">\n"
         "<option value=\"0\">%s</option>", _("View/edit personal info"));
  for (i = 0; i < fused; i++) {
    acn_len = html_armored_strlen(farr[i]->name);
    acn = alloca(acn_len + 16);
    html_armor_string(farr[i]->name, acn);
    printf("<option value=\"%d\">%s</option>\n",
           farr[i]->id, acn);
  }
  printf("</select>\n");
  printf("<input type=\"submit\" name=\"action_register_contest\" value=\"%s\">\n"
         "<input type=\"submit\" name=\"action_logout\" value=\"%s\">\n",
         _("Register for the chosen contest"), _("Logout"));
  print_choose_language_button(0, 0, 1);
  printf("</form>\n");
  return;
}

static void
edit_registration_data(void)
{
  int cnts_arm_len;
  char *cnts_arm = 0, *name_arm = 0;
  struct contest_desc *cnts = 0;

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
  set_locale_by_id(client_locale_id);
  if (user_contest_id > 0) {
    cnts_arm_len = html_armored_strlen(cnts->name);
    cnts_arm = alloca(cnts_arm_len + 16);
    html_armor_string(cnts->name, cnts_arm);
    client_put_header(config->charset,
                      _("Registration form for contest \"%s\""),
                      cnts_arm);
    printf("<p>%s</p>",
           _("Please fill up blank fields in this form. Mandatory fields "
             "are marked with (*)."));

    printf("<form method=\"POST\" action=\"%s\" "
           "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
           program_name);
    if (!user_cookie) {
      printf("<input type=\"hidden\" name=\"login\" value=\"%s\">\n"
             "<input type=\"hidden\" name=\"password\" value=\"%s\">\n",
             user_login, user_password);
    }
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
           user_contest_id);


    printf("<hr><h2>General user information</h2>");
    printf("<p>%s: <input type=\"text\" disabled=\"1\" name=\"user_login\" value=\"%s\" size=\"16\">\n", _("Login"), user_login);

    userlist_clnt_get_email(server_conn, user_id, &user_email,
                            &user_show_email);
    printf("<p>%s: <input type=\"text\" disabled=\"1\" name=\"user_email\" value=\"%s\" size=\"64\">\n", _("E-mail"), user_email);
    printf("<br><input type=\"checkbox\" name=\"show_email\"%s> %s",
           user_show_email?" checked=\"yes\"":"",
           _("Show your e-mail address to public?"));

    printf("<p>%s: <input type=\"text\" name=\"name\", value=\"%s\" maxlength=\"64\" size=\"64\">\n", _("User name"), user_name);

    printf("<p><input type=\"reset\" value=\"%s\">\n"
           "<input type=\"submit\" name=\"action_logout\" value=\"%s\">\n"
           "<input type=\"submit\" name=\"do_register\" value=\"%s\">\n",
           _("Reset the form"), _("Logout"), _("Register"));
    print_choose_language_button(0, 0, 1);
    printf("</form>");
  } else {
    client_put_header(config->charset,
                      _("Personal information for \"%s\""), name_arm);
  }
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
  read_usecookies();
  read_contest_id();  

  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
         program_name);

  if (user_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n",
           user_contest_id);
  }
  if (login_only) {
    //printf("<input type=\"hidden\" name=\"login_dlg\" value=\"1\">\n");
  }

  if (!login_only)
    print_choose_language_button(0, 0, 0);

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
    print_choose_language_button(0, 0, 0);

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
  if (user_usecookies != -1)
    p += sprintf(p, "&usecookies=%d", user_usecookies);

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
  read_usecookies();
  read_contest_id();  

  while (!submission_log && commit_flag) {
    int err;

    if (!server_conn) {
      server_conn = userlist_clnt_open(config->socket_path);
    }
    err = userlist_clnt_register_new(server_conn, user_ip, user_contest_id, client_locale_id, user_usecookies, user_login, user_email);
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

  print_choose_language_button("register", 0, 0);

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

  if (cgi_param("action_register_contest")) {
    edit_registration_data();
  } else if (cgi_param("action_logout")) {
    logout_page();
  } else if (cgi_param("login_dlg")) {
    initial_login_page(1);
  } else if (cgi_param("do_login")) {
    register_for_contest_page();
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
  if (server_conn) {
    userlist_clnt_close(server_conn);
  }

  return 0;












#if 0
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
#endif

  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
