/* -*- mode: c -*- */

/* Copyright (C) 2015-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/bson_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
#include <mongo.h>
#endif

#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);
static int
query_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        int skip,
        int count,
        const ej_bson_t *query,
        const ej_bson_t *sel,
        ej_bson_t ***p_res);
static int
insert_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *b);
static int
insert_and_free_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        ej_bson_t **b);
static int
update_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *selector,
        const ej_bson_t *update);
static int
update_and_free_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        ej_bson_t **pselector,
        ej_bson_t **pupdate);
static int
index_create_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *b);
static int
remove_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *selector);
static int
upsert_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *selector,
        const ej_bson_t *update);
static int
upsert_and_free_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        ej_bson_t **pselector,
        ej_bson_t **pupdate);

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
    query_func,
    insert_func,
    insert_and_free_func,
    update_func,
    update_and_free_func,
    index_create_func,
    remove_func,
    upsert_func,
    upsert_and_free_func,
};

static struct common_plugin_data *
init_func(void)
{
    struct common_mongo_state *state = 0;
    XCALLOC(state, 1);
    state->i = &plugin_common_mongo;

#if HAVE_LIBMONGOC - 0 > 0
    mongoc_init();
#endif

    return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
    if (data) {
        struct common_mongo_state *state = (struct common_mongo_state *) data;
        xfree(state->host);
        xfree(state->database);
        xfree(state->table_prefix);
        xfree(state->password_file);
        xfree(state->user);
        xfree(state->password);
        memset(state, 0, sizeof(*state));
        xfree(state);
    }
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
    //state->show_queries = 1;

#if HAVE_LIBMONGOC - 0 > 0
    {
        unsigned char uri[1024];
        if (state->user && state->password) {
            if (snprintf(uri, sizeof(uri), "mongodb://%s:%s@%s:%d", state->user, state->password, state->host, state->port) >= sizeof(uri)) {
                err("mongodb URI is too long");
                return -1;
            }
        } else {
            if (snprintf(uri, sizeof(uri), "mongodb://%s:%d", state->host, state->port) >= sizeof(uri)) {
                err("mongodb URI is too long");
                return -1;
            }
        }

        state->conn = mongoc_client_new(uri);
        if (!state->conn) {
            err("cannot create mongoc client");
            return -1;
        }
    }
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    state->conn = mongo_sync_connect(state->host, state->port, 0);
    if (!state->conn) {
        err("cannot connect to mongodb: %s", os_ErrorMsg());
        return -1;
    }
    mongo_sync_conn_set_safe_mode(state->conn, 1);
    mongo_sync_conn_set_auto_reconnect(state->conn, 1);
    if (state->user && state->password) {
        if (!mongo_sync_cmd_authenticate(state->conn, state->database, state->user, state->password)) {
            err("authentification failed: %s", os_ErrorMsg());
            return -1;
        }
    }
#endif

    return 0;
}

static int
query_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        int skip,
        int count,
        const ej_bson_t *query,
        const ej_bson_t *sel,
        ej_bson_t ***p_res)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (state->show_queries > 0) {
        fprintf(stderr, "query: "); ej_bson_unparse_new(stderr, query, 0); fprintf(stderr, "\n");
    }

    int retval = -1;
    mongoc_collection_t *coll = NULL;
    mongoc_cursor_t *cursor = NULL;
    const bson_t *doc = NULL;
    bson_t **res = NULL;
    int a = 0, u = 0;
    char *full_table_name = NULL;
    const unsigned char *table_name_ptr = table;
    __attribute__((unused)) int _;

    if (state->table_prefix && state->table_prefix[0]) {
        _ = asprintf(&full_table_name, "%s%s", state->table_prefix, table);
    }
    if (!(coll = mongoc_client_get_collection(state->conn, state->database, table_name_ptr))) {
        err("common_mongo::query: get_collection failed");
        goto cleanup;
    }
    if (!(cursor = mongoc_collection_find_with_opts(coll, query, sel, NULL))) {
        retval = 0;
        goto cleanup;
    }

    while (mongoc_cursor_next(cursor, &doc)) {
        if (a == u) {
            if (!(a *= 2)) a = 8;
            XREALLOC(res, a);
        }
        res[u++] = bson_copy(doc);
        if (state->show_queries > 0) {
            fprintf(stderr, "result: "); ej_bson_unparse_new(stderr, doc, 0); fprintf(stderr, "\n");
        }
    }

    *p_res = res;
    retval = u;

cleanup:
    if (cursor) mongoc_cursor_destroy(cursor);
    if (coll) mongoc_collection_destroy(coll);
    free(full_table_name);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    mongo_packet *pkt = NULL;
    mongo_sync_cursor *cursor = NULL;
    unsigned char ns[1024];
    bson **res = NULL;
    int a = 0, u = 0;
    bson *result = NULL;

    if (state->show_queries > 0) {
        fprintf(stderr, "query: "); ej_bson_unparse(stderr, query, 0); fprintf(stderr, "\n");
    }

    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, table);
    if (!(pkt = mongo_sync_cmd_query(state->conn, ns, 0, skip, count, query, sel))) {
        if (errno == ENOENT) {
            // empty result set
            *p_res = NULL;
            return 0;
        }
        err("common_mongo::query: failed: %s", os_ErrorMsg());
        return -1;
    }

    if (!(cursor = mongo_sync_cursor_new(state->conn, ns, pkt))) {
        err("common_mongo::query: cannot create cursor: %s", os_ErrorMsg());
        mongo_wire_packet_free(pkt);
        return -1;
    }
    pkt = NULL;
    while (mongo_sync_cursor_next(cursor)) {
        result = mongo_sync_cursor_get_data(cursor);
        if (state->show_queries > 0) {
            fprintf(stderr, "result: "); ej_bson_unparse(stderr, result, 0); fprintf(stderr, "\n");
        }
        if (u == a) {
            if (!(a *= 2)) a = 8;
            XREALLOC(res, a);
        }
        res[u++] = result;
        result = NULL;
    }
    mongo_sync_cursor_free(cursor);
    *p_res = res;
    return u;
#else
    return 0;
#endif
}

static int
insert_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *b)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (state->show_queries > 0) {
        fprintf(stderr, "insert: "); ej_bson_unparse_new(stderr, b, 0); fprintf(stderr, "\n");
    }

    char *full_table_name = NULL;
    const unsigned char *table_name_ptr = table;
    __attribute__((unused)) int _;
    if (state->table_prefix && state->table_prefix[0]) {
        _ = asprintf(&full_table_name, "%s%s", state->table_prefix, table);
    }

    mongoc_collection_t *coll = mongoc_client_get_collection(state->conn, state->database, table_name_ptr);
    if (!coll) {
        err("common_mongo::insert: get_collection for %s %s failed", state->database, table);
        free(full_table_name);
        return -1;
    }

    bson_error_t error;
    if (!mongoc_collection_insert_one(coll, b, NULL, NULL, &error)) {
        err("common_mongo::insert: failed for %s %s: %s", state->database, table, error.message);
        mongoc_collection_destroy(coll);
        free(full_table_name);
        return -1;
    }

    mongoc_collection_destroy(coll);
    free(full_table_name);
    return 0;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    unsigned char ns[1024];

    if (state->show_queries > 0) {
        fprintf(stderr, "insert: "); ej_bson_unparse(stderr, b, 0); fprintf(stderr, "\n");
    }
    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, table);
    if (!mongo_sync_cmd_insert(state->conn, ns, b, NULL)) {
        err("common_mongo::insert: failed: %s", os_ErrorMsg());
        return -1;
    }
    return 0;
#else
    return 0;
#endif
}

static int
insert_and_free_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        ej_bson_t **b)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (state->show_queries > 0 && b) {
        fprintf(stderr, "insert: "); ej_bson_unparse_new(stderr, *b, 0); fprintf(stderr, "\n");
    }

    char *full_table_name = NULL;
    const unsigned char *table_name_ptr = table;
    __attribute__((unused)) int _;
    if (state->table_prefix && state->table_prefix[0]) {
        _ = asprintf(&full_table_name, "%s%s", state->table_prefix, table);
    }

    mongoc_collection_t *coll = mongoc_client_get_collection(state->conn, state->database, table_name_ptr);
    if (!coll) {
        err("common_mongo::insert: get_collection for %s %s failed", state->database, table_name_ptr);
        free(full_table_name);
        return -1;
    }

    bson_error_t error;
    bson_t *bb = *b;
    if (!mongoc_collection_insert_one(coll, bb, NULL, NULL, &error)) {
        err("common_mongo::insert: failed for %s %s: %s", state->database, table_name_ptr, error.message);
        mongoc_collection_destroy(coll);
        bson_destroy(bb);
        *b = NULL;
        free(full_table_name);
        return -1;
    }

    free(full_table_name);
    mongoc_collection_destroy(coll);
    bson_destroy(bb);
    *b = NULL;
    return 0;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson *p = NULL;
    if (b) p = *b;
    int res = insert_func(state, table, p);
    if (p) {
        bson_free(p);
        *b = NULL;
    }
    return res;
#else
    return 0;
#endif
}

static int
update_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *selector,
        const ej_bson_t *update)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (state->show_queries > 0) {
        fprintf(stderr, "update selector: "); ej_bson_unparse_new(stderr, selector, 0); fprintf(stderr, "\n");
        fprintf(stderr, "update update: "); ej_bson_unparse_new(stderr, update, 0); fprintf(stderr, "\n");
    }

    char *full_table_name = NULL;
    const unsigned char *table_name_ptr = table;
    __attribute__((unused)) int _;
    if (state->table_prefix && state->table_prefix[0]) {
        _ = asprintf(&full_table_name, "%s%s", state->table_prefix, table);
    }

    mongoc_collection_t *coll = mongoc_client_get_collection(state->conn, state->database, table_name_ptr);
    if (!coll) {
        err("common_mongo::update: get_collection for %s %s failed", state->database, table_name_ptr);
        free(full_table_name);
        return -1;
    }

    bson_error_t error;
    if (!mongoc_collection_update(coll, 0, selector, update, NULL, &error)) {
        err("common_mongo::update: failed for %s %s: %s", state->database, table_name_ptr, error.message);
        mongoc_collection_destroy(coll);
        free(full_table_name);
        return -1;
    }

    mongoc_collection_destroy(coll);
        free(full_table_name);
    return 0;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    unsigned char ns[1024];

    if (state->show_queries > 0) {
        fprintf(stderr, "update selector: "); ej_bson_unparse(stderr, selector, 0); fprintf(stderr, "\n");
        fprintf(stderr, "update update: "); ej_bson_unparse(stderr, update, 0); fprintf(stderr, "\n");
    }
    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, table);
    if (!mongo_sync_cmd_update(state->conn, ns, 0, selector, update)) {
        err("common_mongo::update: failed: %s", os_ErrorMsg());
        return -1;
    }
    return 0;
#else
    return 0;
#endif
}

static int
update_and_free_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        ej_bson_t **pselector,
        ej_bson_t **pupdate)
{
#if HAVE_LIBMONGOC - 0 > 0
    ej_bson_t *selector = NULL;
    ej_bson_t *update = NULL;
    mongoc_collection_t *coll = NULL;
    int retval = -1;
    char *full_table_name = NULL;
    const unsigned char *table_name_ptr = table;
    __attribute__((unused)) int _;

    if (state->table_prefix && state->table_prefix[0]) {
        _ = asprintf(&full_table_name, "%s%s", state->table_prefix, table);
    }

    if (pselector) selector = *pselector;
    if (pupdate) update = *pupdate;

    if (state->show_queries > 0) {
        fprintf(stderr, "update selector: "); ej_bson_unparse_new(stderr, selector, 0); fprintf(stderr, "\n");
        fprintf(stderr, "update update: "); ej_bson_unparse_new(stderr, update, 0); fprintf(stderr, "\n");
    }

    coll = mongoc_client_get_collection(state->conn, state->database, table_name_ptr);
    if (!coll) {
        err("common_mongo::update: get_collection for %s %s failed", state->database, table_name_ptr);
        goto cleanup;
    }

    bson_error_t error;
    if (!mongoc_collection_update(coll, 0, selector, update, NULL, &error)) {
        err("common_mongo::update: failed for %s %s: %s", state->database, table_name_ptr, error.message);
        goto cleanup;
    }
    retval = 0;

cleanup:
    mongoc_collection_destroy(coll);
    if (selector) bson_destroy(selector);
    if (update) bson_destroy(update);
    if (*pselector) *pselector = NULL;
    if (*pupdate) *pupdate = NULL;
    free(full_table_name);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson *selector = NULL;
    bson *update = NULL;
    if (pselector) selector = *pselector;
    if (pupdate) update = *pupdate;
    int res = update_func(state, table, selector, update);
    if (selector) {
        bson_free(selector);
        *pselector = NULL;
    }
    if (update) {
        bson_free(update);
        *pupdate = NULL;
    }
    return res;
#else
    return 0;
#endif
}

static int
index_create_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *b)
{
#if HAVE_LIBMONGOC - 0 > 0
    char *full_table_name = NULL;
    const unsigned char *table_name_ptr = table;
    __attribute__((unused)) int _;
    if (state->table_prefix && state->table_prefix[0]) {
        _ = asprintf(&full_table_name, "%s%s", state->table_prefix, table);
    }
    char *index_name = mongoc_collection_keys_to_index_string(b);
    bson_t *index_bson = BCON_NEW("createIndexes", BCON_UTF8(table_name_ptr),
                                  "indexes", "[", "{", "key", BCON_DOCUMENT(b),
                                  "name", BCON_UTF8(index_name), "}", "]");

    mongoc_database_t *db = NULL;
    if ((db = mongoc_client_get_database(state->conn, state->database))) {
        mongoc_database_write_command_with_opts(db, index_bson, NULL, NULL, NULL);
    }

    mongoc_database_destroy(db);
    bson_destroy(index_bson);
    bson_free(index_name);
    free(full_table_name);

    return 0;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    unsigned char ns[1024];

    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, table);
    if (!mongo_sync_cmd_index_create(state->conn, ns, b, 0)) {
        err("common_mongo::index_create: failed: %s", os_ErrorMsg());
        return -1;
    }
    return 0;
#else
    return 0;
#endif
}

static int
remove_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *selector)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (state->show_queries > 0) {
        fprintf(stderr, "delete selector: "); ej_bson_unparse_new(stderr, selector, 0); fprintf(stderr, "\n");
    }

    char *full_table_name = NULL;
    const unsigned char *table_name_ptr = table;
    __attribute__((unused)) int _;
    if (state->table_prefix && state->table_prefix[0]) {
        _ = asprintf(&full_table_name, "%s%s", state->table_prefix, table);
    }

    mongoc_collection_t *coll = mongoc_client_get_collection(state->conn, state->database, table_name_ptr);
    if (!coll) {
        err("common_mongo::remove: get_collection for %s %s failed", state->database, table_name_ptr);
        free(full_table_name);
        return -1;
    }

    bson_error_t error;
    if (!mongoc_collection_delete_many(coll, selector, NULL, NULL, &error)) {
        err("common_mongo::remove: failed for %s %s: %s", state->database, table_name_ptr, error.message);
        mongoc_collection_destroy(coll);
        free(full_table_name);
        return -1;
    }

    mongoc_collection_destroy(coll);
    free(full_table_name);
    return 0;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    unsigned char ns[1024];

    if (state->show_queries > 0) {
        fprintf(stderr, "delete selector: "); ej_bson_unparse(stderr, selector, 0); fprintf(stderr, "\n");
    }
    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, table);
    if (!mongo_sync_cmd_delete(state->conn, ns, 0, selector)) {
        err("common_mongo::delete: failed: %s", os_ErrorMsg());
        return -1;
    }
    return 0;
#else
    return 0;
#endif
}

static int
upsert_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *selector,
        const ej_bson_t *update)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (state->show_queries > 0) {
        fprintf(stderr, "update selector: "); ej_bson_unparse_new(stderr, selector, 0); fprintf(stderr, "\n");
        fprintf(stderr, "update update: "); ej_bson_unparse_new(stderr, update, 0); fprintf(stderr, "\n");
    }

    char *full_table_name = NULL;
    const unsigned char *table_name_ptr = table;
    __attribute__((unused)) int _;
    if (state->table_prefix && state->table_prefix[0]) {
        _ = asprintf(&full_table_name, "%s%s", state->table_prefix, table);
    }

    mongoc_collection_t *coll = mongoc_client_get_collection(state->conn, state->database, table_name_ptr);
    if (!coll) {
        err("common_mongo::upsert: get_collection for %s %s failed", state->database, table_name_ptr);
        free(full_table_name);
        return -1;
    }

    bson_error_t error;
    if (!mongoc_collection_update(coll, MONGOC_UPDATE_UPSERT, selector, update, NULL, &error)) {
        err("common_mongo::upsert: failed for %s %s: %s", state->database, table_name_ptr, error.message);
        mongoc_collection_destroy(coll);
        free(full_table_name);
        return -1;
    }

    mongoc_collection_destroy(coll);
    free(full_table_name);
    return 0;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    unsigned char ns[1024];

    if (state->show_queries > 0) {
        fprintf(stderr, "update selector: "); ej_bson_unparse(stderr, selector, 0); fprintf(stderr, "\n");
        fprintf(stderr, "update update: "); ej_bson_unparse(stderr, update, 0); fprintf(stderr, "\n");
    }
    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, table);
    if (!mongo_sync_cmd_update(state->conn, ns, MONGO_WIRE_FLAG_UPDATE_UPSERT, selector, update)) {
        err("common_mongo::update: failed: %s", os_ErrorMsg());
        return -1;
    }
    return 0;
#else
    return 0;
#endif
}

static int
upsert_and_free_func(
        struct common_mongo_state *state,
        const unsigned char *table,
        ej_bson_t **pselector,
        ej_bson_t **pupdate)
{
#if HAVE_LIBMONGOC - 0 > 0
    ej_bson_t *selector = NULL;
    ej_bson_t *update = NULL;
    mongoc_collection_t *coll = NULL;
    int retval = -1;
    char *full_table_name = NULL;
    const unsigned char *table_name_ptr = table;
    __attribute__((unused)) int _;

    if (state->table_prefix && state->table_prefix[0]) {
        _ = asprintf(&full_table_name, "%s%s", state->table_prefix, table);
    }

    if (pselector) selector = *pselector;
    if (pupdate) update = *pupdate;

    if (state->show_queries > 0) {
        fprintf(stderr, "update selector: "); ej_bson_unparse_new(stderr, selector, 0); fprintf(stderr, "\n");
        fprintf(stderr, "update update: "); ej_bson_unparse_new(stderr, update, 0); fprintf(stderr, "\n");
    }

    coll = mongoc_client_get_collection(state->conn, state->database, table_name_ptr);
    if (!coll) {
        err("common_mongo::upsert: get_collection for %s %s failed", state->database, table_name_ptr);
        goto cleanup;
    }

    bson_error_t error;
    if (!mongoc_collection_update(coll, MONGOC_UPDATE_UPSERT, selector, update, NULL, &error)) {
        err("common_mongo::upsert: failed for %s %s: %s", state->database, table_name_ptr, error.message);
        goto cleanup;
    }
    retval = 0;

cleanup:
    mongoc_collection_destroy(coll);
    if (selector) bson_destroy(selector);
    if (update) bson_destroy(update);
    if (*pselector) *pselector = NULL;
    if (*pupdate) *pupdate = NULL;
    free(full_table_name);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson *selector = NULL;
    bson *update = NULL;
    if (pselector) selector = *pselector;
    if (pupdate) update = *pupdate;
    int res = upsert_func(state, table, selector, update);
    if (selector) {
        bson_free(selector);
        *pselector = NULL;
    }
    if (update) {
        bson_free(update);
        *pupdate = NULL;
    }
    return res;
#else
    return 0;
#endif
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
