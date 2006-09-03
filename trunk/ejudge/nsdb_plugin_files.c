/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "nsdb_plugin.h"
#include "expat_iface.h"
#include "xml_utils.h"
#include "errlog.h"
#include "pathutl.h"
#include "new-server.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static void *init_func(const struct ejudge_cfg *config);
static int parse_func(void *data, const struct ejudge_cfg *config, struct xml_tree *tree);
static int open_func(void *data);
static int close_func(void *data);
static int check_func(void *data);
static int create_func(void *data);
static int check_role_func(void *, int, int, int);

struct nsdb_plugin_iface nsdb_plugin_files =
{
  {
    sizeof (struct nsdb_plugin_iface),
    EJUDGE_PLUGIN_IFACE_VERSION,
    "userdb",
    "nsdb_xml",
  },

  NSDB_PLUGIN_IFACE_VERSION,

  init_func,
  parse_func,
  open_func,
  close_func,
  check_func,
  create_func,

  check_role_func,
};

struct user_priv_header
{
  unsigned char signature[12];
  unsigned char byte_order;
  unsigned char version;
};
struct user_priv_entry
{
  int user_id;
  int contest_id;
  unsigned int priv_bits;
  char pad[4];
};
struct user_priv_table
{
  struct user_priv_header header;
  size_t a, u;
  struct user_priv_entry *v;
  int header_dirty, data_dirty;
  int fd;
};

static int user_priv_create(struct user_priv_table *pt, const unsigned char *);
static int user_priv_load(struct user_priv_table *pt, const unsigned char *dir);
static int user_priv_flush(struct user_priv_table *pt);

struct nsdb_files_state
{
  unsigned char *data_dir;

  struct user_priv_table user_priv;
};

static void *
init_func(const struct ejudge_cfg *config)
{
  struct nsdb_files_state *state;

  XCALLOC(state, 1);
  return (void*) state;
}

static int
parse_func(void *data, const struct ejudge_cfg *config, struct xml_tree *tree)
{
  struct nsdb_files_state *state = (struct nsdb_files_state*) data;
  struct xml_tree *p;

  if (!tree) {
    err("configuration for files plugin is not specified");
    return -1;
  }
  ASSERT(tree->tag == xml_err_spec->default_elem);
  ASSERT(!strcmp(tree->name[0], "config"));

  if (xml_empty_text(tree) < 0) return -1;
  if (tree->first) return xml_err_attrs(tree);

  for (p = tree->first_down; p; p = p->right) {
    ASSERT(p->tag == xml_err_spec->default_elem);
    if (!strcmp(p->name[0], "data_dir")) {
      if (xml_leaf_elem(p, &state->data_dir, 1, 0) < 0) return -1;
    } else {
      return xml_err_elem_not_allowed(p);
    }
  }

  if (!state->data_dir) return xml_err_elem_undefined_s(tree, "data_dir");

  return 0;
}

static int
open_func(void *data)
{
  return 0;
}

static int
close_func(void *data)
{
  struct nsdb_files_state *state = (struct nsdb_files_state*) data;

  user_priv_flush(&state->user_priv);
  return 0;
}

static int
check_func(void *data)
{
  struct nsdb_files_state *state = (struct nsdb_files_state*) data;
  struct stat stb;
  
  if (stat(state->data_dir, &stb) < 0) {
    err("data_dir `%s' does not exist. create it with --create",
        state->data_dir);
    return 0;
  }
  if (!S_ISDIR(stb.st_mode)) {
    err("`%s' is not a directory", state->data_dir);
    return -1;
  }

  if (user_priv_load(&state->user_priv, state->data_dir) < 0)
    return -1;
  
  return 1;
}

static int
create_func(void *data)
{
  struct nsdb_files_state *state = (struct nsdb_files_state*) data;

  if (mkdir(state->data_dir, 0700) < 0 && errno != EEXIST) {
    err("mkdir failed on `%s': %s", state->data_dir, os_ErrorMsg());
    return -1;
  }

  if (user_priv_create(&state->user_priv, state->data_dir) < 0)
    return -1;

  return 0;
}

static ssize_t
full_read(int fd, void *buf, size_t size)
{
  unsigned char *p = (unsigned char*) buf;
  int r;

  while (size > 0) {
    if ((r = read(fd, p, size)) < 0) return r;
    if (!r) return p - (unsigned char*) buf;
    p += r;
    size -= r;
  }
  return p - (unsigned char*) buf;
}
static ssize_t
full_write(int fd, const void *buf, size_t size)
{
  const unsigned char *p = (const unsigned char *) buf;
  int r;

  while (size > 0) {
    if ((r = write(fd, p, size)) <= 0) return r;
    p += r;
    size -= r;
  }
  return p - (const unsigned char*) buf;
}

static const unsigned char user_priv_signature[12] = "Ej.userpriv";

static int
user_priv_load(struct user_priv_table *pt, const unsigned char *dir)
{
  path_t path;
  struct stat stb;
  int n;

  snprintf(path, sizeof(path), "%s/user_priv.dat", dir);
  if ((pt->fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) {
    err("cannot open %s: %s", path, os_ErrorMsg());
    return -1;
  }
  fstat(pt->fd, &stb);
  if (!stb.st_size) {
    // new file
    memcpy(&pt->header.signature, user_priv_signature, sizeof(pt->header.signature));
    pt->header.byte_order = 0;
    pt->header.version = 1;
    pt->header_dirty = 1;
    return 0;
  }

  if (stb.st_size < sizeof(struct user_priv_header)) {
    err("invalid size of %s", path);
    return -1;
  }
  if (full_read(pt->fd, &pt->header, sizeof(pt->header)) != sizeof(pt->header)){
    err("cannot read header from %s", path);
    return -1;
  }
  if (memcmp(pt->header.signature, user_priv_signature, sizeof(user_priv_signature)) != 0) {
    err("invalid file format of %s", path);
    return -1;
  }
  if (pt->header.byte_order != 0) {
    err("cannot handle byte_order %d in %s", pt->header.byte_order, path);
    return -1;
  }
  if (pt->header.version != 1) {
    err("cannot handle version %d in %s", pt->header.version, path);
    return -1;
  }

  if ((stb.st_size - sizeof(struct user_priv_header)) % sizeof(struct user_priv_entry) != 0) {
    err("invalid file size of %s", path);
    return -1;
  }
  n = (stb.st_size - sizeof(struct user_priv_header)) / sizeof(struct user_priv_entry);
  pt->a = 16;
  while (pt->a < n) pt->a *= 2;
  XCALLOC(pt->v, pt->a);
  if (full_read(pt->fd, pt->v, n * sizeof(struct user_priv_entry)) != n * sizeof(struct user_priv_entry)) {
    err("cannot read data from %s", path);
    return -1;
  }
  pt->u = n;
  return 0;
}

static int
user_priv_create(struct user_priv_table *pt, const unsigned char *dir)
{
  path_t path;

  snprintf(path, sizeof(path), "%s/user_priv.dat", dir);
  if ((pt->fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) {
    err("cannot open %s: %s", path, os_ErrorMsg());
    return -1;
  }
  if (ftruncate(pt->fd, 0) < 0) {
    err("ftruncate failed: %s", os_ErrorMsg());
    return -1;
  }
  memcpy(&pt->header.signature, user_priv_signature, sizeof(pt->header.signature));
  pt->header.byte_order = 0;
  pt->header.version = 1;
  pt->header_dirty = 1;
  return 0;
}

static int
user_priv_flush(struct user_priv_table *pt)
{
  if (pt->header_dirty) {
    if (lseek(pt->fd, 0, SEEK_SET) < 0) {
      err("lseek failed: %s", os_ErrorMsg());
      return -1;
    }
    if (full_write(pt->fd, &pt->header, sizeof(pt->header)) != sizeof(pt->header)) {
      err("write failed: %s", os_ErrorMsg());
      return -1;
    }
    pt->header_dirty = 0;
  }
  if (pt->data_dirty) {
    if (lseek(pt->fd, sizeof(struct user_priv_header), SEEK_SET) < 0) {
      err("lseek failed: %s", os_ErrorMsg());
      return -1;
    }
    if (full_write(pt->fd, pt->v, pt->u * sizeof(struct user_priv_entry)) != pt->u * sizeof(struct user_priv_entry)) {
      err("write failed: %s", os_ErrorMsg());
      return -1;
    }
    if (ftruncate(pt->fd, sizeof(struct user_priv_header) + pt->u * sizeof(struct user_priv_entry)) < 0) {
      err("ftruncate failed: %s", os_ErrorMsg());
      return -1;
    }
    pt->data_dirty = 0;
  }
  return 0;
}

static int
check_role_func(void *data, int user_id, int contest_id, int role)
{
  struct nsdb_files_state *state = (struct nsdb_files_state*) data;
  unsigned int b;
  int i;

  if (user_id <= 0) return -1;
  if (contest_id <= 0) return -1;
  if (role <= USER_ROLE_CONTESTANT || role >= USER_ROLE_ADMIN) return -1;
  b = 1 << role;

  for (i = 0; i < state->user_priv.u; i++)
    if (state->user_priv.v[i].user_id == user_id
        && state->user_priv.v[i].contest_id == contest_id) {
      if ((b & state->user_priv.v[i].priv_bits)) return 0;
      return -1;
    }
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
