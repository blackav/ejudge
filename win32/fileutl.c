/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ispras.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "settings.h"

#include "fileutl.h"
#include "pathutl.h"
#include "errlog.h"

#include <reuse/logger.h>
#include <reuse/osdeps.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <windows.h>
#include <malloc.h>

void
get_uniq_prefix(char *prefix)
{
  sprintf(prefix, "%lu_%s_", GetCurrentProcessId(), os_NodeName());
}

struct ignored_items
{
  unsigned char *dir;
  size_t a, u;
  unsigned char **items;
};
static struct ignored_items *ign;
static size_t ign_a, ign_u;

void
scan_dir_add_ignored(const unsigned char *dir, const unsigned char *filename)
{
  int i;
  struct ignored_items *cur_ign = 0;

  if (!dir || !*dir) return;
  for (i = 0; i < ign_u; i++)
    if (!strcmp(dir, ign[i].dir))
      break;
  if (i == ign_u) {
    if (ign_u == ign_a) {
      if (!ign_a) ign_a = 4;
      ign_a *= 2;
      XREALLOC(ign, ign_a);
    }
    memset(&ign[ign_u], 0, sizeof(ign[0]));
    ign[ign_u++].dir = xstrdup(dir);
  }
  cur_ign = &ign[i];

  if (!filename || !*filename) return;
  for (i = 0; i < cur_ign->u; i++)
    if (!strcmp(filename, cur_ign->items[i]))
      return;

  if (cur_ign->u == cur_ign->a) {
    if (!cur_ign->a) cur_ign->a = 8;
    cur_ign->a *= 2;
    XREALLOC(cur_ign->items, cur_ign->a);
  }
  cur_ign->items[cur_ign->u++] = xstrdup(filename);
}

struct q_dir_entry
{
  unsigned char *name;
  signed char    prio;
  unsigned char  ign;
};

/* scans 'dir' directory and returns the filename found */
int
scan_dir(char const *partial_path, char *found_item)
{
  path_t          full_path;
  path_t          dir_path;
  HANDLE          sh;
  WIN32_FIND_DATA result;
  int             b, i, got_quit = 0, prio, found = 0, j;
  struct ignored_items *cur_ign = 0;
  unsigned char *del_map = 0;
  unsigned char *items[32];

  for (i = 0; i < ign_u; i++)
    if (!strcmp(partial_path, ign[i].dir))
      break;
  if (i < ign_u) cur_ign = &ign[i];

  if (cur_ign && cur_ign->u > 0) {
    XALLOCAZ(del_map, cur_ign->u);
  }

  pathcpy(dir_path, partial_path);
  pathcat(dir_path, "\\dir");
  pathcpy(full_path, dir_path);
  pathcat(full_path, "\\*.*");

  sh = FindFirstFile(full_path, &result);
  // there must be files . and ..
  if (sh == INVALID_HANDLE_VALUE) {
    write_log(0, LOG_ERR, "directory %s does not exist?", dir_path);
    return -1;
  }

  while ((b = FindNextFile(sh, &result))) {
    if (!strcmp(result.cFileName, ".") || !strcmp(result.cFileName, ".."))
      continue;

        if (cur_ign) {
      for (i = 0; i < cur_ign->u; i++)
        if (!strcmp(cur_ign->items[i], result.cFileName))
          break;
      if (i < cur_ign->u) {
        del_map[i] = 1;
        continue;
      }
    }

    if (!strcmp("QUIT", result.cFileName)) {
      got_quit = 1;
      continue;
    }

    if (strlen(result.cFileName) != SERVE_PACKET_NAME_SIZE - 1) {
      prio = 0;
    } else if (result.cFileName[0] >= '0' && result.cFileName[0] <= '9') {
      prio = -16 + (result.cFileName[0] - '0');
    } else if (result.cFileName[0] >= 'A' && result.cFileName[0] <= 'V') {
      prio = -6 + (result.cFileName[0] - 'A');
    } else {
      prio = 0;
    }
    if (prio < -16) prio = -16;
    if (prio > 15) prio = 15;
    prio += 16;
    if (items[prio]) continue;

    items[prio] = (unsigned char*) alloca(strlen(result.cFileName) + 1);
    strcpy(items[prio], result.cFileName);
    found++;
  }
  FindClose(sh);

  // cleanup ignored files
  if (cur_ign) {
    for (j = 0; j < cur_ign->u && del_map[j]; j++);
    for (i = j; i < cur_ign->u; i++) {
      if (del_map[i]) {
        cur_ign->items[j++] = cur_ign->items[i];
      } else {
        xfree(cur_ign->items[i]);
      }
    }
    cur_ign->u = j;
  }

  if (got_quit) {
    pathcpy(found_item, "QUIT");
    info("scan_dir: found QUIT packet");
    return 1;
  }

  if (!found) return 0;

  for (i = 0; i < 32; i++) {
    if (items[i]) {
      pathcpy(found_item, items[i]);
      info("scan_dir: found '%s' (priority %d)", found_item, i - 16);
      return 1;
    }
  }
  err("scan_dir: found == %d, but no items found!!!", found);
  return 0;
}

int
safe_outcopy_file(char const *dir, char const *name, char const *out)
{
  path_t tmpstorage;
  path_t srcstorage;
  path_t prefix;

  pathcpy(tmpstorage, dir);
  pathcat(tmpstorage, "\\out\\");
  get_uniq_prefix(prefix);
  pathcat(tmpstorage, prefix);
  pathcat(tmpstorage, name);

  pathcpy(srcstorage, dir);
  pathcat(srcstorage, "\\dir\\");
  pathcat(srcstorage, name);

  write_log(0, LOG_INFO, "Move: %s -> %s", srcstorage, tmpstorage);
  if (!MoveFile(srcstorage, tmpstorage)) {
    write_log(0, LOG_WARN, "MoveFile failed. Somebody stole our file?");
    return 0; // transient error
  }

  // now we can copy this file to the working directory
  // assuming, that copying is not atomic
  write_log(0, LOG_INFO, "Copy: %s -> %s", tmpstorage, out);
  if (!CopyFile(tmpstorage, out, FALSE)) {
    write_log(0, LOG_ERR, "CopyFile failed");
    return -1; // fatal error
  }

  if (!DeleteFile(tmpstorage)) {
    write_log(0, LOG_ERR, "DeleteFile failed");
    return -1;
  }

  return 1;
}

int
safe_incopy_file(char const *in, char const *dir, char const *name)
{
  path_t tmpfile;
  path_t outfile;
  path_t prefix;

  get_uniq_prefix(prefix);

  pathcpy(tmpfile, dir);
  pathcat(tmpfile, "\\in\\");
  pathcat(tmpfile, prefix);
  pathcat(tmpfile, name);

  pathcpy(outfile, dir);
  pathcat(outfile, "\\dir\\");
  pathcat(outfile, name);

  write_log(0, LOG_INFO, "Copy: %s -> %s", in, tmpfile);
  if (!CopyFile(in, tmpfile, FALSE)) {
    write_log(0, LOG_ERR, "CopyFile failed %d", GetLastError());
    return -1; // fatal error
  }

  write_log(0, LOG_INFO, "Move: %s -> %s", tmpfile, outfile);
  if (!MoveFile(tmpfile, outfile)) {
    write_log(0, LOG_ERR, "MoveFile failed: %d", GetLastError());
    return -1;
  }
  return 0;
}

int
safe_write_file(char const *buf, size_t size,
                char const *dir, char const *name)
{
  path_t  tmpfile;
  path_t  outfile;
  path_t  prefix;
  FILE   *f;

  get_uniq_prefix(prefix);

  pathcpy(tmpfile, dir);
  pathcat(tmpfile, "\\in\\");
  pathcat(tmpfile, prefix);
  pathcat(tmpfile, name);

  pathcpy(outfile, dir);
  pathcat(outfile, "\\dir\\");
  pathcat(outfile, name);

  if (!(f = fopen(tmpfile, "wb"))) {
    write_log(0, LOG_ERR, "fopen(%s) failed", tmpfile);
    return -1;
  }
  if (fwrite(buf, 1, size, f) != size) {
    write_log(0, LOG_ERR, "fwrite failed");
    return -1;
  }
  if (fclose(f) != 0) {
    write_log(0, LOG_ERR, "fclose failed");
    return -1;
  }

  write_log(0, LOG_INFO, "Move: %s -> %s", tmpfile, outfile);
  if (!MoveFile(tmpfile, outfile)) {
    write_log(0, LOG_ERR, "MoveFile failed");
    return -1;
  }
  return 0;  
}

/* remove all files in the specified directory */
int
clear_directory(char const *path)
{
  WIN32_FIND_DATA data;
  HANDLE          hnd;
  int             r = TRUE;
  int             errc;
  path_t          patt;
  path_t          fdel;

  strcpy(patt, path);
  strcat(patt, "\\*.*");

  hnd = FindFirstFile(patt, &data);
  if (hnd == INVALID_HANDLE_VALUE) {
    write_log(0, LOG_ERR, "FindFirstFile failed");
    return -1;
  }
  while (r) {
    if (strcmp(data.cFileName, ".") && strcmp(data.cFileName, "..")) {
      //printf(">>%s\n", data.cFileName);
      pathcpy(fdel, path);
      pathcat(fdel, "\\");
      pathcat(fdel, data.cFileName);
      if (!DeleteFile(fdel)) {
        write_log(0, LOG_INFO, "DeleteFile('%s') failed: %d", fdel,
                  GetLastError());
      }
    }
    r = FindNextFile(hnd, &data);
  }
  errc = GetLastError();
  if (errc != ERROR_NO_MORE_FILES) {
    write_log(0, LOG_INFO, "FindNextFile failed");
    CloseHandle(hnd);
    return -1;
  }
  CloseHandle(hnd);

  write_log(0, LOG_INFO, "Directory %s cleared", path);
  return 0;
}

int
make_dir(char const *path, int access)
{
  if (!CreateDirectory(path, NULL)) {
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
      write_log(0, LOG_INFO, "Directory %s exists", path);
    } else {
      write_log(0, LOG_ERR, "CreateDirectory(%s) failed: %d",
                path, GetLastError());
      return -1;
    }
  } else {
    write_log(0, LOG_INFO, "Created directory %s", path);
  }
  return 0;
}

int
make_all_dir(char const *path, int access)
{
  path_t inpath;
  path_t dirpath;
  path_t outpath;

  pathcpy(inpath, path);
  pathcat(inpath, "\\in");
  pathcpy(dirpath, path);
  pathcat(dirpath, "\\dir");
  pathcpy(outpath, path);
  pathcat(outpath, "\\out");

  if (make_dir(path, 0) < 0) return -1;
  if (make_dir(inpath, access) < 0) return -1;
  if (make_dir(dirpath, access) < 0) return -1;
  if (make_dir(outpath, access) < 0) return -1;

  return 0;
}

static int
do_rename(char const *src, char const *dst)
{
  /* MoveFile fails when the destination already exists */
  if (!DeleteFile(dst) && GetLastError() != ERROR_FILE_NOT_FOUND) {
    write_log(0, LOG_ERR, "do_rename: DeleteFile(%s) failed: %s",
              dst, os_ErrorMsg());
    return -1;
  }

  if (!MoveFile(src, dst)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      write_log(0, LOG_WARN, "do_rename: MoveFile: %s do not exist: %s",
                src, os_ErrorMsg());
      return 0;
    }
    write_log(0, LOG_ERR, "do_rename: MoveFile(%s,%s) failed: %s",
              src, dst, os_ErrorMsg());
    return -1;
  }

  return 1;
}

static int
do_unlink(char const *src)
{
  if (!DeleteFile(src)) {
    write_log(0, LOG_ERR, "do_unlink: DeleteFile(%s) failed: %s",
              src, os_ErrorMsg());
    return -1;
  }
  return 0;
}

static int
do_copy_file(char const *sn, int sf, char const *dn, int df)
{
  char *orf = "rb";
  char *owf = "wb";
  FILE *s = 0, *d = 0;
  int  count = 0;
  int  c;

  if ((sf & CONVERT)) orf = "r";
  if ((df & CONVERT)) owf = "w";

  if (!(s = fopen(sn, orf))) {
    write_log(0, LOG_ERR, "do_copy_file: fopen(%s,r) failed: %s",
              sn, os_ErrorMsg());
    goto cleanup;
  }
  if (!(d = fopen(dn, owf))) {
    write_log(0, LOG_ERR, "do_copy_file: fopen(%s,w) failed: %s",
              dn, os_ErrorMsg());
    goto cleanup;
  }
  while ((c = getc(s)) != EOF) {
    count++;
    if (putc(c, d) == EOF) {
      write_log(0, LOG_ERR, "do_copy_file: write_error: %s", os_ErrorMsg());
      goto cleanup;
    }
  }
  if (ferror(s)) {
    write_log(0, LOG_ERR, "do_copy_file: read error: %s", os_ErrorMsg());
    goto cleanup;
  }
  fclose(s); s = 0;
  if (fclose(d) < 0) {
    write_log(0, LOG_ERR, "do_copy_file: close error: %s", os_ErrorMsg());
    goto cleanup;
  }

  return count;

 cleanup:
  if (s) fclose(s);
  if (d) fclose(d);
  return -1;
}

static int
do_write_file(char const *buf, size_t size, char const *path)
{
  FILE       *d;
  char const *s;

  if (!(d = fopen(path, "wb"))) {
    write_log(0, LOG_ERR, "do_write_file: fopen(%s,wb) failed: %s",
              path, os_ErrorMsg());
    goto cleanup;
  }

  for (s = buf; size; s++, size--) {
    if (putc(*s, d) == EOF) {
      write_log(0, LOG_ERR, "do_copy_file: write_error: %s", os_ErrorMsg());
      goto cleanup;
    }
  }

  if (fclose(d) < 0) {
    d = 0;
    write_log(0, LOG_ERR, "do_write_file: close error: %s", os_ErrorMsg());
    goto cleanup;
  }
  return size;

 cleanup:
  if (d) fclose(d);
  return -1;
}

int
do_read_file(char **pbuf, size_t maxsz, size_t *prsz, char const *path)
{
  FILE *s;
  int   size = 0;
  char *p;
  int   c;

  if (!(s = fopen(path, "r"))) {
    write_log(0, LOG_ERR, "do_read_file: fopen(%s,r) failed: %s",
              path, os_ErrorMsg());
    return -1;
  }

  if (*pbuf) {
    ASSERT(maxsz);
    for (p = *pbuf; (c = getc(s)) != EOF && size < maxsz - 1; size++, p++) {
      *p = c;
    }
    if (ferror(s)) {
      write_log(0, LOG_ERR, "do_read_file: read error: %s",
                os_ErrorMsg());
      fclose(s);
      return -1;
    }
    if (c != EOF && size >= maxsz - 1) {
      write_log(0, LOG_ERR, "do_read_file: file is too long: %d", maxsz);
      fclose(s);
      return -1;
    }
    *p = 0;
  } else {
    char *mem = xmalloc(16);
    int   mem_a = 256;
    int   size = 0;

    while ((c = getc(s)) != EOF) {
      if (size >= mem_a) {
        mem_a *= 2;
        mem = xrealloc(mem, mem_a);
      }
      mem[size++] = c;
    }
    if (ferror(s)) {
      write_log(0, LOG_ERR, "do_read_file: read_error: %s", os_ErrorMsg());
      fclose(s);
      xfree(mem);
      return -1;
    }
    if (size >= mem_a) {
      mem_a *= 2;
      mem = xrealloc(mem, mem_a);
    }
    mem[size] = 0;
    *pbuf = mem;
  }

  if (prsz) *prsz = size;
  fclose(s);
  return 0;
}

int
generic_read_file(char **pbuf, size_t maxsz, size_t *prsz, int flags,
                  char const *dir, char const *name, char const *sfx)
{
  path_t uniq_pfx = { 0 };
  path_t read_path;
  path_t in_path;

  int    r = 0;

  ASSERT(pbuf);
  ASSERT(maxsz >= 0);
  ASSERT(name);

  if ((flags & SAFE)) {
    ASSERT(dir);
    get_uniq_prefix(uniq_pfx);
    pathmake(in_path, dir, "/", "dir", "/", name, sfx, NULL);
    pathmake(read_path, dir, "/", "out", "/",  uniq_pfx, name, sfx, NULL);
    write_log(0, LOG_INFO, "Move: %s -> %s", in_path, read_path);
    if ((r = do_rename(in_path, read_path)) < 0) return r;
  } else {
    if (!dir || !*dir) {
      pathmake(read_path, name, sfx, NULL);
    } else {
      pathmake(read_path, dir, "/", name, sfx, NULL);
    }
  }

  write_log(0, LOG_INFO, "reading file %s", read_path);
  if (do_read_file(pbuf, maxsz, prsz, read_path) < 0) return -1;

  if ((flags & REMOVE)) {
    if (do_unlink(read_path) < 0) return -1;
  }
  return 1;

}

int
generic_write_file(char const *buf, size_t size, int flags,
                   char const *dir, char const *name, char const *sfx)
{
  path_t wrt_path;
  path_t uniq_pfx;
  path_t out_path;

  ASSERT(buf);
  ASSERT(name);
  ASSERT(*name);
  *uniq_pfx = 0;

  if ((flags & SAFE)) {
    ASSERT(dir);
    get_uniq_prefix(uniq_pfx);
    pathmake(wrt_path, dir, "/", "in", "/", uniq_pfx, name, sfx, NULL);
  } else {
    if (!dir || !*dir) {
      pathmake(wrt_path, name, sfx, NULL);
    } else {
      pathmake(wrt_path, dir, "/", name, sfx, NULL);
    }
  }

  write_log(0, LOG_INFO, "writing file %s", wrt_path);
  if (do_write_file(buf, size, wrt_path) < 0) return -1;
  if ((flags & SAFE)) {
    pathmake(out_path, dir, "/", "dir", "/", name, sfx, NULL);
    write_log(0, LOG_INFO, "Move: %s -> %s", wrt_path, out_path);
    if (do_rename(wrt_path, out_path) < 0) return -1;
  }
  return size;
}

int
generic_copy_file(int sflags, char const *sdir, char const *sname, char const *ssfx,
                  int dflags, char const *ddir, char const *dname, char const *dsfx)
{
  path_t uniq_pfx;
  path_t copy_src;
  path_t copy_dst;
  path_t move_src;
  path_t move_dst;

  int r = 0;

  ASSERT(sname);
  ASSERT(dname);

  if ((sflags & SAFE) || (dflags & SAFE)) {
    get_uniq_prefix(uniq_pfx);
  }

  if ((sflags & SAFE)) {
    ASSERT(sdir);
    pathmake(move_src, sdir, "/", "dir", "/", sname, ssfx, NULL);
    pathmake(copy_src, sdir, "/", "out", "/", uniq_pfx, sname, ssfx, NULL);

    write_log(0, LOG_INFO, "Move: %s -> %s", move_src, copy_src);
    if ((r = do_rename(move_src, copy_src)) <= 0) return r;
  } else {
    if (!sdir || !*sdir) {
      pathmake(copy_src, sname, ssfx, NULL);
    } else {
      pathmake(copy_src, sdir, "/", sname, ssfx, NULL);
    }
  }

  if ((dflags & SAFE)) {
    ASSERT(ddir);
    pathmake(copy_dst, ddir, "/", "in", "/", uniq_pfx, dname, dsfx, NULL);
    pathmake(move_dst, ddir, "/", "dir", "/", dname, dsfx, NULL);
  } else {
    if (!ddir || !*ddir) {
      pathmake(copy_dst, dname, dsfx, NULL);
    } else {
      pathmake(copy_dst, ddir, "/", dname, dsfx, NULL);
    }
  }

  write_log(0, LOG_INFO, "Copy: %s -> %s", copy_src, copy_dst);
  if ((r = do_copy_file(copy_src, sflags, copy_dst, dflags)) < 0) return r;

  if ((dflags & SAFE)) {
    write_log(0, LOG_INFO, "Move: %s -> %s", copy_dst, move_dst);
    if (do_rename(copy_dst, move_dst) <= 0) return -1;
  }
  if ((sflags & REMOVE)) {
    if (do_unlink(copy_src) < 0) return -1;
  }
  return 1;
}

int
make_executable(char const *path)
{
  /* nothing to do */
  return 0;
}

int
make_writable(char const *path)
{
  /* nothing to do */
  return 0;
}

int
check_executable(char const *path)
{
  int s = os_IsFile(path);
  if (s < 0) {
    err("script '%s' does not exist", path);
    return -1;
  }
  if (s != OSPK_REG) {
    err("'%s' is not a regular file", path);
    return -1;
  }
  /* everything is executable? */
  return 1;
}

int
check_readable_dir(char const *path)
{
  int status = os_IsFile(path);
  if (status < 0) {
    err("directory '%s' does not exist", path);
    return -1;
  }
  if (status != OSPK_DIR) {
    err("'%s' is not a directory", path);
    return -1;
  }
  /* everything is readable? */
  return 1;
}

int
check_writable_dir(char const *path)
{
  int status = os_IsFile(path);
  if (status < 0) {
    err("directory '%s' does not exist", path);
    return -1;
  }
  if (status != OSPK_DIR) {
    err("'%s' is not a directory", path);
    return -1;
  }
  /* everything is writable? */
  return 1;
}

int
check_writable_spool(char const *path, int mode)
{
  path_t in_dir;
  path_t dir_dir;
  path_t out_dir;

  pathmake(in_dir, path, "/", "in", 0);
  pathmake(out_dir, path, "/", "out", 0);
  pathmake(dir_dir, path, "/", "dir", 0);

  if (mode == SPOOL_IN && check_writable_dir(in_dir) < 0) return -1;
  if (mode == SPOOL_OUT && check_writable_dir(out_dir) < 0) return -1;
  if (check_writable_dir(dir_dir) < 0) return -1;
  return 0;
}

int
make_symlink(unsigned char const *dest, unsigned char const *path)
{
  SWERR(("Not implemented"));
}

ssize_t
generic_file_size(const unsigned char *dir, const unsigned char *name,
                  const unsigned char *sfx)
{
  path_t path;
  HANDLE h;
  DWORD lo;
  ssize_t retval;

  ASSERT(name);
  if (!dir) dir = "";
  if (!sfx) sfx = "";

  if (!strcmp(dir, "") || !strcmp(dir, "/")) {
    snprintf(path, sizeof(path), "%s%s%s", dir, name, sfx);
  } else {
    snprintf(path, sizeof(path), "%s/%s%s", dir, name, sfx);
  }

  h = CreateFile(path, GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,0);
  if (h == INVALID_HANDLE_VALUE) {
    err("generic_file_size: CreateFile failed on `%s'", path);
    return -1;
  }

  lo = GetFileSize(h, NULL);
  CloseHandle(h);

  if (lo == INVALID_FILE_SIZE) {
    err("generic_file_size: GetFileSize failed on `%s'", path);
    return -1;
  }    

  // avoid unsigned overflow
  if ((retval = (ssize_t) lo) < 0) {
    err("generic_file_size: GetFileSize returned negative value on %s", path);
    return -1;
  }

  return retval;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "HANDLE" "STARTUPINFO" "PROCESS_INFORMATION" "SECURITY_ATTRIBUTES" "WIN32_FIND_DATA" "FILETIME" "DWORD")
 * End:
 */
