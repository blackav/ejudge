/* -*- mode: c -*- */

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/common_mongo_plugin.h"
#include "ejudge/xml_utils.h"
#include "ejudge/errlog.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <mongo.h>

#include <string.h>
#include <limits.h>
#include <ctype.h>

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);

struct common_mongo_iface plugin_common_mongo =
{
    {
        {
            sizeof (struct common_mongo_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "common",
            "mongo",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    COMMON_MONGO_PLUGIN_IFACE_VERSION,
};

static struct common_plugin_data *
init_func(void)
{
    struct common_mongo_state *state = 0;
    XCALLOC(state, 1);
    state->i = &plugin_common_mongo;
    return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  return 0;
}

static int
parse_passwd_file(
        struct common_mongo_state *state,
        const unsigned char *path)
{
  FILE *f = 0;
  const unsigned char *fname = __FUNCTION__;
  unsigned char buser[1024];
  unsigned char bpwd[1024];
  int len, c;

  if (!(f = fopen(path, "r"))) {
    err("%s: cannot open password file %s", fname, path);
    goto cleanup;
  }
  if (!fgets(buser, sizeof(buser), f)) {
    err("%s: cannot read the user line from %s", fname, path);
    goto cleanup;
  }
  if ((len = strlen(buser)) > sizeof(buser) - 24) {
    err("%s: user is too long in %s", fname, path);
    goto cleanup;
  }
  while (len > 0 && isspace(buser[--len]));
  buser[++len] = 0;

  if (!fgets(bpwd, sizeof(bpwd), f)) {
    err("%s: cannot read the password line from %s", fname, path);
    goto cleanup;
  }
  if ((len = strlen(bpwd)) > sizeof(bpwd) - 24) {
    err("%s: password is too long in %s", fname, path);
    goto cleanup;
  }
  while (len > 0 && isspace(bpwd[--len]));
  bpwd[++len] = 0;
  while ((c = getc(f)) && isspace(c));
  if (c != EOF) {
    err("%s: garbage in %s", fname, path);
    goto cleanup;
  }
  fclose(f); f = 0;
  state->user = xstrdup(buser);
  state->password = xstrdup(bpwd);

  // debug
  //fprintf(stderr, "login: %s\npassword: %s\n", state->user, state->password);
  return 0;

 cleanup:
  if (f) fclose(f);
  return -1;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    struct common_mongo_state *state = (struct common_mongo_state *) data;

    // this plugin configuration subtree is pointed by 'tree'

    for (struct xml_tree *p = tree->first_down; p; p = p->right) {
        if (!strcmp(p->name[0], "host")) {
            if (xml_leaf_elem(p, &state->host, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "port")) {
            if (xml_parse_int(NULL, "", p->line, p->column, p->text, &state->port) < 0) return -1;
            if (state->port < 0 || state->port > 65535) {
                xml_err_elem_invalid(p);
                return -1;
            }
        } else if (!strcmp(p->name[0], "database")) {
            if (xml_leaf_elem(p, &state->database, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "table_prefix")) {
            if (xml_leaf_elem(p, &state->table_prefix, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "password_file")) {
            if (xml_leaf_elem(p, &state->password_file, 1, 0) < 0) return -1;
        } else {
            return xml_err_elem_not_allowed(p);
        }
    }

    if (state->password_file) {
        unsigned char ppath[PATH_MAX];
        ppath[0] = 0;
        if (os_IsAbsolutePath(state->password_file)) {
            snprintf(ppath, sizeof(ppath), "%s", state->password_file);
        }
#if defined EJUDGE_CONF_DIR
        if (!ppath[0]) {
            snprintf(ppath, sizeof(ppath), "%s/%s", EJUDGE_CONF_DIR,
                     state->password_file);
        }
#endif
        if (!ppath[0]) {
            snprintf(ppath, sizeof(ppath), "%s", state->password_file);
        }
        if (parse_passwd_file(state, ppath) < 0) return -1;
    }

    if (!state->database) state->database = xstrdup("ejudge");
    if (!state->host) state->host = xstrdup("localhost");
    if (state->port <= 0) state->port = 27017;
    if (!state->table_prefix) state->table_prefix = xstrdup("");

    state->conn = mongo_sync_connect(state->host, state->port, 0);
    if (!state->conn) {
        err("cannot connect to mongodb: %s", os_ErrorMsg());
        return -1;
    }
    if (state->user && state->password) {
        if (!mongo_sync_cmd_authenticate(state->conn, state->database, state->user, state->password)) {
            err("authentification failed: %s", os_ErrorMsg());
            return -1;
        }
    }

    return 0;
}


/*
 * Local variables:
 *  c-basic-offset: 4
 *  compile-command: "make"
 * End:
 */
