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
#include "cgi.h"
#include "userlist_clnt.h"
#include "clntutil.h"
#include "pathutl.h"
#include "contests.h"
#include "userlist_proto.h"
#include "misctext.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <stdarg.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif /* CONF_HAS_LIBINTL */

enum
  {
    TG_CONFIG = 1,
    TG_ACCESS,
    TG_IP,
    TG_SOCKET_PATH,
    TG_CONTESTS_PATH,

    TG_LAST_ELEM
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

    TG_LAST_ATTN
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

static char const * const elem_map[] =
{
  0,
  "users_config",
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

static size_t const elem_sizes[TG_LAST_ELEM] =
{
  0,
  sizeof(struct config_node),
  sizeof(struct access_node),
  sizeof(struct ip_node),
  sizeof(struct xml_tree),
  sizeof(struct xml_tree),
};

static void *
elem_alloc(int tag)
{
  size_t sz;

  ASSERT(tag > 0 && tag < TG_LAST_ELEM);
  sz = elem_sizes[tag];
  if (!sz) {
    SWERR(("xml tree has zero size for elem %d (%s)", tag, elem_map[tag]));
  }
  return xcalloc(1, sz);
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

  tree = xml_build_tree(path, elem_map, attn_map, elem_alloc, attn_alloc);
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
              path, p2->line, p2->column, elem_map[p2->tag]);
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
          elem_map[p->tag]);
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

static struct config_node *config;
static struct contest_list *contests;
static struct userlist_clnt *server_conn;
static unsigned long user_ip;
static int user_contest_id;
static int client_locale_id;

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
}

static void
put_header(char const *coding, char const *format, ...)
{
  va_list args;

  if (!coding) coding = "iso8859-1";

  va_start(args, format);
  fprintf(stdout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\n\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>\n", coding, coding);
  vfprintf(stdout, format, args);
  fputs("\n</title></head><body>\n", stdout);
}

int
main(int argc, char const *argv[])
{
  struct timeval begin_time, end_time;
  struct contest_desc *cnts = 0;
  int r;

  gettimeofday(&begin_time, 0);
  initialize(argc, argv);

  if (!check_source_ip()) {
    client_access_denied(config->charset);
  }

  cgi_read(config->charset);
  read_locale_id();
  read_contest_id();

  if (user_contest_id > 0 && user_contest_id < contests->id_map_size) {
    cnts = contests->id_map[user_contest_id];
  }
  if (cnts) {
    int name_len;
    unsigned char *name_str;

    name_len = html_armored_strlen(cnts->name);
    name_str = alloca(name_len + 16);
    html_armor_string(cnts->name, name_str);
    
    put_header(config->charset, "%s", _("List of registered users (teams)"));
    if (cnts->header_file) {
      /* FIXME: use header and footer */
    } else {
      printf(_("<h1>List of registered users (teams) for contest &quot;%s&quot;</h1>\n"), name_str);
    }

    server_conn = userlist_clnt_open(config->socket_path);
    if (!server_conn) {
      printf("<p>%s</p>\n", _("Information is not available"));
    } else {
      fflush(stdout);
      r = userlist_list_users(server_conn, user_ip, user_contest_id,
                              client_locale_id);
      if (r < 0) {
        printf("<p>%s</p>\n", _("Information is not available"));
        printf("<pre>%s</pre>\n", gettext(userlist_strerror(-r)));
      }
    }
  } else {
    client_put_header(config->charset, "%s", _("List of users (teams)"));
    printf("<p>%s</p>\n", _("Information is not available"));
  }

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
