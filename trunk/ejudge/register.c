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

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <sys/time.h>
#include <unistd.h>

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
  struct access_node *access;
  struct field_node *fields[F_ARRAY_SIZE];
};

static struct config_node *config;
static struct contest_list *contests;

static int client_locale_id;

static unsigned char *user_login;
static unsigned char *user_email;
static unsigned char *user_name;
static unsigned char *user_homepage;

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

  return cfg;

 failed:
  /* FIXME: free resources */
  return 0;
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
  char *s = getenv("REMOTE_ADDR");
  unsigned int b1, b2, b3, b4, n;
  struct ip_node *p;
  unsigned int addr;

  if (!config->access) return 0;
  if (!s) goto invalid_ip;
  n = 0;
  if (sscanf(s, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || s[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255)
    goto invalid_ip;
  addr = b1 << 24 | b2 << 16 | b3 << 8 | b4;
  for (p = (struct ip_node*) config->access->b.first_down;
       p; p = (struct ip_node*) p->b.right) {
    if ((addr & p->mask) == p->addr) return p->allow;
  }
  return config->access->default_is_allow;

 invalid_ip:
  if (s) err("invalid IP-address: <%s>", s);
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

#if CONF_HAS_LIBINTL - 0 == 1
  /* load the language used */
  if (config->l10n) {
    char *e = cgi_param("locale_id");
    int n = 0;
    char env_buf[1024];

    if (e) {
      if (sscanf(e, "%d%n", &client_locale_id, &n) != 1 || e[n])
        client_locale_id = 0;
      if (client_locale_id < 0 || client_locale_id > 1)
        client_locale_id = 0;
    }

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
  }
#endif /* CONF_HAS_LIBINTL */

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
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
