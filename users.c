/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2001-2006 Alexander Chernov <cher@ejudge.ru> */

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
#include "cgi.h"
#include "userlist_clnt.h"
#include "clntutil.h"
#include "pathutl.h"
#include "errlog.h"
#include "contests.h"
#include "userlist_proto.h"
#include "misctext.h"
#include "fileutl.h"
#include "l10n.h"
#include "xml_utils.h"

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
#define gettext(x) x
#endif /* CONF_HAS_LIBINTL */

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

enum
  {
    TG_CONFIG = 1,
    TG_ACCESS,
    TG_IP,
    TG_SOCKET_PATH,
    TG_CONTESTS_DIR,
    TG_L10N_DIR,

    TG_LAST_TAG
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

    TG_LAST_ATTR
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

static size_t const elem_sizes[TG_LAST_TAG] =
{
  [TG_CONFIG] = sizeof(struct config_node),
  [TG_ACCESS] = sizeof(struct access_node),
  [TG_IP] = sizeof(struct ip_node),
};

static struct xml_parse_spec users_config_parse_spec =
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
  xml_err_spec = &users_config_parse_spec;

  if (default_config) {
    tree = xml_build_tree_str(default_config, &users_config_parse_spec);
  } else {
    tree = xml_build_tree(path, &users_config_parse_spec);
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
            xml_err_attr_not_allowed(&ip->b, a);
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

static struct config_node *config;
static struct userlist_clnt *server_conn;
static ej_ip_t user_ip;
static int user_contest_id = 0;
static int client_locale_id;
static unsigned char *self_url;
static int ssl_flag;
static int user_id;

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

static const unsigned char default_config[] =
"<?xml version=\"1.0\" ?>\n"
"<users_config><access default=\"allow\"/></users_config>\n";

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
  if (strncmp(basename, "users", 5) != 0) {
    client_not_configured(0, "bad program name", 0);
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
    default_config_str = default_config;
  }
  if (!(config = parse_config(cfgname, default_config_str))) {
    client_not_configured(0, "config file not parsed", 0);
  }

  /*
  if (!config->contests_path ||
      !(contests = parse_contest_xml(config->contests_path))) {
    client_not_configured(0, "contests database not parsed");
  }
  */
  user_ip = parse_client_ip();

  // construct self-reference URL
  {
    unsigned char *http_host = getenv("HTTP_HOST");
    unsigned char *script_name = getenv("SCRIPT_NAME");
    unsigned char *protocol = "http";

    if (getenv("SSL_PROTOCOL")) {
      ssl_flag = 1;
      protocol = "https";
    }
    if (!http_host) http_host = "localhost";
    if (!script_name) script_name = "/cgi-bin/users";
    snprintf(fullname, sizeof(fullname), "%s://%s%s", protocol, http_host, script_name);
    self_url = xstrdup(fullname);
  }
}

static void
information_not_available(unsigned char const *header_txt,
                          unsigned char const *footer_txt)
{
  client_put_header(stdout, header_txt, 0, config->charset, 1,
                    client_locale_id, _("Information is not available"));
  printf("<p>%s</p>\n",
         _("Information by your request is not available."));
  client_put_footer(stdout, footer_txt);
  exit(0);
}

int
main(int argc, char const *argv[])
{
  struct timeval begin_time, end_time;
  const struct contest_desc *cnts = 0;
  int r;
  char *header_txt = 0;
  size_t header_len = 0;
  char *footer_txt = 0;
  size_t footer_len = 0;
  int errcode = 0;
  int name_len = 0;
  unsigned char *name_str = 0;
  unsigned char *in_name_str = 0;

  gettimeofday(&begin_time, 0);
  initialize(argc, argv);

  if (!check_source_ip()) {
    client_access_denied(config->charset, client_locale_id);
  }

  read_locale_id();
  read_user_id();
  l10n_prepare(config->l10n, config->l10n_dir);
  l10n_setlocale(client_locale_id);

  if ((errcode = contests_set_directory(config->contests_dir)) < 0) {
    fprintf(stderr, "cannot set contest directory '%s': %s\n",
            config->contests_dir, contests_strerror(-errcode));
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id, _("Invalid configuration"));
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

  in_name_str = 0;
  if (!client_locale_id) {
    in_name_str = cnts->name_en;
    if (!in_name_str) in_name_str = cnts->name;
  } else {
    in_name_str = cnts->name;
    if (!in_name_str) in_name_str = cnts->name_en;
  }
  if (!in_name_str) in_name_str = "";

  name_len = html_armored_strlen(in_name_str);
  name_str = alloca(name_len + 16);
  html_armor_string(in_name_str, name_str);

  if (!contests_check_users_ip(user_contest_id, user_ip, ssl_flag)) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id, _("Permission denied"));
    printf("<h2>%s</h2>\n",_("You have no permissions to view this contest."));
    client_put_footer(stdout, footer_txt);
    return 0;
  }

  if (user_id > 0) {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id,
                      _("Detailed information about participant"));
  } else {
    client_put_header(stdout, header_txt, 0, config->charset, 1,
                      client_locale_id,
                      _("List of registered participants"));
    printf("<%s>%s: %s</%s>\n",
           cnts->users_head_style,
           _("Contest"), name_str, cnts->users_head_style);
  }

  server_conn = userlist_clnt_open(config->socket_path);
  if (!server_conn) {
    printf("<p>%s</p>\n", _("Information is not available"));
  } else {
    fflush(stdout);
    r = userlist_clnt_list_users(server_conn, user_ip, ssl_flag,
                                 user_contest_id,
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

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
