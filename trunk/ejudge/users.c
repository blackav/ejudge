/* -*- mode: c -*-; coding: koi8-r */
/* $Id$ */

/* Copyright (C) 2001-2003 Alexander Chernov <cher@ispras.ru> */

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

#include "expat_iface.h"
#include "cgi.h"
#include "userlist_clnt.h"
#include "clntutil.h"
#include "pathutl.h"
#include "contests.h"
#include "userlist_proto.h"
#include "misctext.h"
#include "fileutl.h"
#include "l10n.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>

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
    TG_CONTESTS_DIR,
    TG_L10N_DIR,

    TG_LAST_ELEM
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
  unsigned char *contests_dir;
  struct access_node *access;
};

static char const * const elem_map[] =
{
  0,
  "users_config",
  "access",
  "ip",
  "socket_path",
  "contests_dir",
  "l10n_dir",

  0
};
static char const * const attn_map[] =
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

static size_t const elem_sizes[TG_LAST_ELEM] =
{
  0,
  sizeof(struct config_node),
  sizeof(struct access_node),
  sizeof(struct ip_node),
  sizeof(struct xml_tree),
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
err_dupl_elem(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: element <%s> may appear only once", path, t->line, t->column,
      elem_map[t->tag]);
  return -1;
}
static int
err_attr_not_allowed(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: attributes are not allowed for element <%s>",
      path, t->line, t->column, elem_map[t->tag]);
  return -1;
}
static int
err_empty_elem(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: element <%s> is empty",
      path, t->line, t->column, elem_map[t->tag]);
  return -1;
}
static int
err_nested_not_allowed(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: nested elements are not allowed for element <%s>",
      path, t->line, t->column, elem_map[t->tag]);
  return -1;
}
static int
err_invalid_elem(char const *path, struct xml_tree *tag)
{
  err("%s:%d:%d: element <%s> is invalid here", path, tag->line, tag->column,
      elem_map[tag->tag]);
  return -1;
}
static int
err_invalid_attn(char const *path, struct xml_attn *a)
{
  err("%s:%d:%d: attribute \"%s\" is invalid here", path, a->line, a->column,
      attn_map[a->tag]);
  return -1;
}

static int
handle_final_tag(char const *path, struct xml_tree *t, unsigned char **ps)
{
  if (*ps) return err_dupl_elem(path, t);
  if (!t->text || !*t->text) return err_empty_elem(path, t);
  if (t->first_down) return err_nested_not_allowed(path, t);
  if (t->first) return err_attr_not_allowed(path, t);
  *ps = t->text; t->text = 0;
  return 0;
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
    err("%s: %d: top-level tag must be <users_config>", path, tree->line);
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
      err_invalid_attn(path, a);
      goto failed;
    }
  }

  /* process subnodes */
  for (p = cfg->b.first_down; p; p = p->right) {
    switch (p->tag) {
    case TG_SOCKET_PATH:
      if (handle_final_tag(path, p, &cfg->socket_path) < 0) goto failed;
      break;
    case TG_CONTESTS_DIR:
      if (handle_final_tag(path, p, &cfg->contests_dir) < 0) goto failed;
      break;

    case TG_L10N_DIR:
#if CONF_HAS_LIBINTL - 0 == 1
      if (handle_final_tag(path, p, &cfg->l10n_dir) < 0) goto failed;
      break;
#else
      err("%s:%d:%d: localization support is not compiled",
          path, p->line, p->column);
      goto failed;
#endif /* CONF_HAS_LIBINTL */

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
          err_invalid_attn(path, a);
          goto failed;
        }
      }

      /* now check the list of ip addresses */
      for (p2 = p->first_down; p2; p2 = p2->right) {
        if (p2->tag != TG_IP) {
          err_invalid_elem(path, p2);
          goto failed;
        }
        ip = (struct ip_node*) p2;
        ip->allow = -1;
        for (a = ip->b.first; a; a = a->next) {
          if (a->tag != AT_ALLOW && a->tag != AT_DENY) {
            err_invalid_attn(path, a);
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
      err_invalid_elem(path, p);
      goto failed;
    }
  }

  if (cfg->l10n == -1) cfg->l10n = 0;
  if (cfg->l10n && !cfg->l10n_dir) {
    /* FIXME: the locale dir should be guessed... */
    err("%s: locale directory (\"l10n_dir\" attribute) is not defined", path);
    goto failed;
  }

  if (!cfg->socket_path) {
    err("%s: <socket_path> tag must be specified", path);
    goto failed;
  }
  if (!cfg->contests_dir) {
    err("%s: <contests_path> tag must be specified", path);
    goto failed;
  }

  return cfg;

 failed:
  /* FIXME: free resources */
  return 0;
}

static struct config_node *config;
static struct userlist_clnt *server_conn;
static unsigned long user_ip;
static int user_contest_id = 0;
static int client_locale_id;
static unsigned char *self_url;
static int user_id;

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
read_user_id(void)
{
  int x = 0, n = 0;
  unsigned char *s;

  user_id = 0;
  if (!(s = cgi_param("user_id"))) return;
  if (sscanf(s, "%d %n", &x, &n) != 1 || s[n] || x <= 0) return;
  user_id = x;
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
initialize(int argc, char const *argv[])
{
  path_t fullname;
  path_t dirname;
  path_t basename;
  path_t cfgname;
  path_t progname;
  path_t cfgdir;
  path_t cfgname2;
  char *s = getenv("SCRIPT_FILENAME");
  int namelen, cgi_contest_id, name_contest_id, name_ok;

  pathcpy(fullname, argv[0]);
  if (s) pathcpy(fullname, s);
  os_rDirName(fullname, dirname, PATH_MAX);
  os_rGetBasename(fullname, basename, PATH_MAX);
  strcpy(program_name, basename);
  if (strncmp(basename, "users", 5) != 0) {
    client_not_configured(0, "bad program name");
    // never get here
  }
  namelen = 5;                  /* "users" */
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
    client_not_configured(0, "client is not configured");
    // never get here
  }
  if (!(config = parse_config(cfgname))) {
    client_not_configured(0, "config file not parsed");
  }

  /*
  if (!config->contests_path ||
      !(contests = parse_contest_xml(config->contests_path))) {
    client_not_configured(0, "contests database not parsed");
  }
  */
  parse_user_ip();

  // construct self-reference URL
  {
    unsigned char *http_host = getenv("HTTP_HOST");
    unsigned char *server_port = getenv("SERVER_PORT");
    unsigned char *script_name = getenv("SCRIPT_NAME");

    if (!http_host) http_host = "localhost";
    if (!server_port) server_port = "80";
    if (!script_name) script_name = "/cgi-bin/users";
    snprintf(fullname, sizeof(fullname),
             "http://%s:%s%s", http_host, server_port, script_name);
    self_url = xstrdup(fullname);
  }
}

static void
information_not_available(unsigned char const *header_txt,
                          unsigned char const *footer_txt)
{
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    _("Information is not available"));
  printf("<p>%s</p>\n",
         _("Information by your request is not available."));
  client_put_footer(stdout, footer_txt);
  exit(0);
}

int
main(int argc, char const *argv[])
{
  struct timeval begin_time, end_time;
  struct contest_desc *cnts = 0;
  int r;
  char *header_txt = 0;
  size_t header_len = 0;
  char *footer_txt = 0;
  size_t footer_len = 0;
  int errcode = 0;
  int name_len = 0;
  unsigned char *name_str = 0;

  gettimeofday(&begin_time, 0);
  initialize(argc, argv);

  if (!check_source_ip()) {
    client_access_denied(config->charset);
  }

  read_locale_id();
  read_user_id();
  l10n_prepare(config->l10n, config->l10n_dir);
  l10n_setlocale(client_locale_id);

  if ((errcode = contests_set_directory(config->contests_dir)) < 0) {
    fprintf(stderr, "cannot set contest directory '%s': %s\n",
            config->contests_dir, contests_strerror(-errcode));
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      _("Invalid configuration"));
    printf("<h2>%s</h2>\n<p>%s</p>\n",
           _("Configuration error"),
           _("This program is configured incorrectly and cannot perform normal operation. Please contact the site (or contest) administrator."));
    client_put_footer(stdout, footer_txt);
    return 0;
  }

  if (user_contest_id <= 0) {
    // refuse to run
    information_not_available(header_txt, footer_txt);
  }

  cnts = 0;
  if ((errcode = contests_get(user_contest_id, &cnts)) < 0) {
    fprintf(stderr, "cannot load contest %d: %s\n",
            user_contest_id, contests_strerror(-errcode));
    information_not_available(header_txt, footer_txt);
  }
  ASSERT(cnts);

  logger_set_level(-1, LOG_WARNING);
  if (cnts->users_header_file) {
    generic_read_file(&header_txt, 0, &header_len, 0,
                      0, cnts->users_header_file, "");
  }
  if (cnts->users_footer_file) {
    generic_read_file(&footer_txt, 0, &footer_len, 0,
                      0, cnts->users_footer_file, "");
  }

  name_len = html_armored_strlen(cnts->name);
  name_str = alloca(name_len + 16);
  html_armor_string(cnts->name, name_str);

  if (!contests_check_users_ip(user_contest_id, user_ip)) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      _("Permission denied"));
    printf("<h2>%s</h2>\n",_("You have no permissions to view this contest."));
    client_put_footer(stdout, footer_txt);
    return 0;
  }

  if (user_id > 0) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      _("Detailed information about participant"));
  } else {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      _("List of registered participants"));
    printf("<h2>%s: %s</h2>\n", _("Contest"), name_str);
  }

  server_conn = userlist_clnt_open(config->socket_path);
  if (!server_conn) {
    printf("<p>%s</p>\n", _("Information is not available"));
  } else {
    fflush(stdout);
    r = userlist_clnt_list_users(server_conn, user_ip, user_contest_id,
                                 client_locale_id, user_id, 
                                 0, self_url, "");
    if (r < 0) {
      printf("<p>%s</p>\n", _("Information is not available"));
      printf("<pre>%s</pre>\n", gettext(userlist_strerror(-r)));
    }
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

  client_put_footer(stdout, footer_txt);

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
