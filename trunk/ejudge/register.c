/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2001 Alexander Chernov <cher@ispras.ru> */

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

#include "cgi.h"
#include "fileutl.h"
#include "pathutl.h"
#include "xalloc.h"
#include "logger.h"
#include "base64.h"
#include "osdeps.h"
#include "parsecfg.h"
#include "clntutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define DEFAULT_VAR_DIR        "var"
#define DEFAULT_CONF_DIR       "conf"
#define DEFAULT_PIPE_DIR       "pipe"
#define DEFAULT_REG_DIR        "team"
#define DEFAULT_REG_CMD_DIR    "cmd"
#define DEFAULT_REG_DATA_DIR   "data"
#define DEFAULT_STATUS_FILE    "status/dir/status"
#define DEFAULT_CHARSET        "iso8859-1"

struct section_global_data
{
  struct generic_section_config g;

  int    allow_deny;
  int    enabled;

  path_t contest_name;
  path_t root_dir;
  path_t conf_dir;
  path_t var_dir;
  path_t pipe_dir;
  path_t reg_dir;
  path_t reg_cmd_dir;
  path_t reg_data_dir;
  path_t status_file;
  path_t allow_from;
  path_t deny_from;
  path_t charset;
};

static struct generic_section_config *config;
static struct section_global_data    *global;

#define GLOBAL_OFFSET(x)   XOFFSET(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(allow_deny, "d"),
  GLOBAL_PARAM(enabled, "d"),

  GLOBAL_PARAM(root_dir, "s"),
  GLOBAL_PARAM(var_dir, "s"),
  GLOBAL_PARAM(pipe_dir, "s"),
  GLOBAL_PARAM(reg_dir, "s"),
  GLOBAL_PARAM(reg_cmd_dir, "s"),
  GLOBAL_PARAM(reg_data_dir, "s"),
  GLOBAL_PARAM(status_file, "s"),
  GLOBAL_PARAM(allow_from, "s"),
  GLOBAL_PARAM(deny_from, "s"),
  GLOBAL_PARAM(charset, "s"),

  { 0, 0, 0, 0 }
};

static struct config_section_info params[] =
{
  { "global" ,sizeof(struct section_global_data), section_global_params },
  { NULL, 0, NULL }
};

static int
set_defaults(void)
{
  if (!global->root_dir[0]) {
    err(_("root_dir must be set"));
    return -1;
  }
  path_init(global->var_dir, global->root_dir, DEFAULT_VAR_DIR);
  path_init(global->pipe_dir, global->var_dir, DEFAULT_PIPE_DIR);
  path_init(global->reg_dir, global->var_dir, DEFAULT_REG_DIR);
  path_init(global->reg_cmd_dir, global->reg_dir, DEFAULT_REG_CMD_DIR);
  path_init(global->reg_data_dir, global->reg_dir, DEFAULT_REG_DATA_DIR);
  path_init(global->status_file, global->var_dir, DEFAULT_STATUS_FILE);
  if (!global->charset[0]) {
    pathcpy(global->charset, DEFAULT_CHARSET);
  }
  return 0;
}

static void
initialize(int argc, char const *argv[])
{
  path_t  fullname;
  path_t  dirname;
  path_t  basename;
  path_t  cfgname;
  struct generic_section_config *p;
  char   *s = getenv("SCRIPT_FILENAME");
  
  pathcpy(fullname, argv[0]);
  if (s) pathcpy(fullname, s);
  os_rDirName(fullname, dirname, PATH_MAX);
  os_rGetBasename(fullname, basename, PATH_MAX);
  strcpy(program_name, basename);
  if (strncmp(basename, "register", 8)) {
    client_not_configured(0, _("bad program name"));
  }

  pathmake(cfgname, dirname, "/", "..", "/", "cgi-data", "/", basename,
           ".cfg", NULL);
  config = parse_param(cfgname, 0, params, 1);
  if (!config)
    client_not_configured(0, _("config file not parsed"));

  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  }
  if (!p)
    client_not_configured(0, _("no global section"));
  global = (struct section_global_data *) p;

  if (set_defaults() < 0)
    client_not_configured(global->charset, _("bad configuration"));
  logger_set_level(-1, LOG_WARNING);

  /* copy this to help client utility functions */
  pathcpy(client_pipe_dir, global->pipe_dir);
  pathcpy(client_cmd_dir, global->reg_cmd_dir);
}

int
main(int argc, char const *argv[])
{
  initialize(argc, argv);

  if (!client_check_source_ip(global->allow_deny,
                              global->allow_from,
                              global->deny_from))
    client_access_denied(global->charset);

  cgi_read(global->charset);

  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
