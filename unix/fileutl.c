/* -*- c -*- */

/* Copyright (C) 2000-2024 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/fileutl.h"
#include "unix/unix_fileutl.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/ej_limits.h"
#include "ejudge/random.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <zlib.h>
#include <paths.h>

#if HAVE_FERROR_UNLOCKED - 0 == 0
#define ferror_unlocked(x) ferror(x)
#endif

static int name_sort_func(const void *p1, const void *p2);

void
get_uniq_prefix(char *prefix)
{
  sprintf(prefix, "%d_%s_", getpid(), os_NodeName());
}

struct direlem_node
{
  struct direlem_node *next;
  unsigned char *name;
};

/* remove all files in the specified directory */
int
clear_directory(char const *path)
{
  DIR           *d;
  struct dirent *de;
  path_t         fdel;
  struct stat    sb;
  int saved_errno, r;
  struct direlem_node *first = 0, **plast = &first, *p;

  if (!(d = opendir(path))) {
    saved_errno = errno;
    err("clear_directory: opendir(\"%s\") failed: %s", path, os_ErrorMsg());
    errno = saved_errno;
    return -saved_errno;
  }
  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".")) continue;
    if (!strcmp(de->d_name, "..")) continue;
    p = (struct direlem_node*) alloca(sizeof(*p));
    p->next = 0;
    p->name = (unsigned char*) alloca(strlen(de->d_name) + 1);
    strcpy(p->name, de->d_name);
    *plast = p;
    plast = &p->next;
  }
  closedir(d);

  saved_errno = 0;
  for (p = first; p; p = p->next) {
    pathmake(fdel, path, "/", p->name, NULL);
    if (lstat(fdel, &sb) < 0) continue;
    if (S_ISDIR(sb.st_mode)) {
      if ((r = remove_directory_recursively(fdel, 0)) < 0) {
        saved_errno = -r;
      }
    } else {
      if (unlink(fdel) < 0 && errno != ENOENT) {
        saved_errno = errno;
        err("unlink(\"%s\") failed: %s", fdel, os_ErrorMsg());
      }
    }
  }

  info("clear_directory: %s cleared", path);
  return -saved_errno;
}

int
make_dir(char const *path, int access)
{
  int saved_errno, r;
  int prev_umask = umask(0);

  if (!access) access = 0775 & ~prev_umask;
  if ((r = mkdir(path, access)) < 0 && errno != EEXIST) {
    saved_errno = errno;
    umask(prev_umask);
    err("make_dir: mkdir(\"%s\") failed: %s", path, os_ErrorMsg());
    errno = saved_errno;
    return -saved_errno;
  }
  umask(prev_umask);
  if (r >= 0) info("make_dir: %s created", path);
  return 0;
}

int
make_all_dir(char const *path, int access)
{
  path_t inpath;
  path_t dirpath;
  path_t outpath;
  int r;

  pathcpy(inpath, path);
  pathcat(inpath, "/in");
  pathcpy(dirpath, path);
  pathcat(dirpath, "/dir");
  pathcpy(outpath, path);
  pathcat(outpath, "/out");

  if ((r = make_dir(path, 0)) < 0) return r;
  if ((r = make_dir(inpath, access)) < 0) return r;
  if ((r = make_dir(dirpath, access)) < 0) return r;
  if ((r = make_dir(outpath, access)) < 0) return r;

  return 0;
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
scan_dir(char const *partial_path, char *found_item, size_t fi_size, int random_mode)
{
  path_t         dir_path;
  DIR           *d;
  struct dirent *de;
  int saved_errno;
  int prio, found = 0, i, got_quit = 0, j;
  unsigned char *items[32];
  unsigned char *del_map = 0;
  struct ignored_items *cur_ign = 0;
  int low_prio = 32, high_prio = -1;

  for (i = 0; i < ign_u; i++)
    if (!strcmp(partial_path, ign[i].dir))
      break;
  if (i < ign_u) cur_ign = &ign[i];

  memset(items, 0, sizeof(items));
  pathmake(dir_path, partial_path, "/", "dir", NULL);
  if (!(d = opendir(dir_path))) {
    saved_errno = errno;
    err("scan_dir: opendir(\"%s\") failed: %s", dir_path, os_ErrorMsg());
    errno = saved_errno;
    return -saved_errno;
  }

  if (cur_ign && cur_ign->u > 0) {
    XALLOCAZ(del_map, cur_ign->u);
  }

  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;

    if (cur_ign) {
      for (i = 0; i < cur_ign->u; i++)
        if (!strcmp(cur_ign->items[i], de->d_name))
          break;
      if (i < cur_ign->u) {
        del_map[i] = 1;
        continue;
      }
    }

    if (!strcmp("QUIT", de->d_name)) {
      got_quit = 1;
      continue;
    }

    /* if (strlen(de->d_name) != EJ_SERVE_PACKET_NAME_SIZE - 1) {
      prio = 0;
      } else */
    if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
      prio = -16 + (de->d_name[0] - '0');
    } else if (de->d_name[0] >= 'A' && de->d_name[0] <= 'V') {
      prio = -6 + (de->d_name[0] - 'A');
    } else {
      prio = 0;
    }
    if (prio < -16) prio = -16;
    if (prio > 15) prio = 15;
    prio += 16;

    if (prio < low_prio) low_prio = prio;
    if (prio > high_prio) high_prio = prio;

    if (items[prio]) {
      if (strcmp(items[prio], de->d_name) <= 0) continue;
      items[prio] = (unsigned char*) alloca(strlen(de->d_name) + 1);
      strcpy(items[prio], de->d_name);
      continue;
    }

    items[prio] = (unsigned char*) alloca(strlen(de->d_name) + 1);
    strcpy(items[prio], de->d_name);
    found++;
  }
  closedir(d);

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
    snprintf(found_item, fi_size, "%s", "QUIT");
    info("scan_dir: found QUIT packet");
    return 1;
  }

  if (!found) return 0;

  if (low_prio >= 32 || high_prio < 0) {
    err("scan_dir: found == %d, but no items found!!!", found);
    return 0;
  }

  if (random_mode && low_prio != high_prio) {
    int range = high_prio - low_prio + 1;
    unsigned long long mask = (1ULL << range) - 1;
    unsigned long long value = 0;

    random_init();

    if (range < 16) {
      value = random_u16() & mask;
    } else if (range == 16) {
      value = random_u16();
    } else if (range < 32) {
      value = random_u32() & mask;
    } else if (range == 32) {
      value = random_u32();
    } else {
      value = random_u64() & mask;
    }
    for (i = high_prio; i > low_prio; --i) {
      if (items[i]) {
        if (!value) {
          low_prio = i;
          break;
        }
        --value;
      }
      value >>= 1;
    }
  }

  ASSERT(items[low_prio]);
  snprintf(found_item, fi_size, "%s", items[low_prio]);
  info("scan_dir: found '%s' (priority %d)", found_item, low_prio - 16);
  return 1;
}

int
get_file_list(const char *partial_path, strarray_t *files)
{
  path_t         dir_path;
  DIR           *d = NULL;
  struct dirent *de;

  snprintf(dir_path, sizeof(dir_path), "%s/dir", partial_path);
  files->u = 0;

  if (!(d = opendir(dir_path))) {
    return -1;
  }
  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
    xexpand(files);
    files->v[files->u++] = xstrdup(de->d_name);
  }
  closedir(d); d = NULL;

  if (files->u > 0) {
    qsort(files->v, files->u, sizeof(files->v[0]), name_sort_func);
  }

  return 0;
}

int
get_file_list_unsorted(const char *dir_path, strarray_t *files)
{
  DIR           *d = NULL;
  struct dirent *de;

  files->u = 0;
  if (!(d = opendir(dir_path))) {
    return -1;
  }
  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
    xexpand(files);
    files->v[files->u++] = xstrdup(de->d_name);
  }
  closedir(d); d = NULL;

  return 0;
}

static int
do_write_file(char const *buf, size_t sz, char const *dst, int flags)
{
  char const *p;
  int         wsz;
  int         dfd = -1;
  int         errcode;
  int         open_flags = O_WRONLY | ((flags & PIPE)?0:(O_CREAT|O_TRUNC));

  if ((dfd = errcode = sf_open(dst, open_flags, 0644)) < 0) goto _cleanup;
  p = buf;
  while (sz > 0) {
    if ((wsz = errcode = sf_write(dfd, p, sz, dst)) <= 0) goto _cleanup;
    p += wsz;
    sz -= wsz;
  }
  if ((errcode = sf_close(dfd, dst)) < 0) {
    dfd = -1;
    goto _cleanup;
  }
  return 0;

 _cleanup:
  if (dfd >= 0) close(dfd);
  errno = -errcode;
  return errcode;
}

static int
gzip_write_file(const unsigned char *buf, size_t size,
                const unsigned char *path, int flags)
{
  gzFile gz_dst = 0;
  int wsz, do_conv = 1;
  int saved_errno;
  const unsigned char *z_msg;

  if (!(gz_dst = gzopen(path, "wb9"))) {
    saved_errno = errno;
    if (!saved_errno) saved_errno = 1000 - Z_MEM_ERROR;
    err("gzip_write_file: cannot open file `%s'", path);
    goto cleanup;
  }

  if ((flags & CONVERT)) {
    while (size > 0) {
      if (*buf == '\r') do_conv = 0;
      if (*buf == '\n' && do_conv) {
        if (gzputc(gz_dst, '\r') < 0) goto write_error;
      }
      if (gzputc(gz_dst, *buf) < 0) goto write_error;
      buf++;
      size--;
    }
  } else {
    while (size > 0) {
      if ((wsz = gzwrite(gz_dst, (void*) buf, size)) <= 0)
        goto write_error;
      buf += wsz;
      size -= wsz;
    }
  }

  if (gzclose(gz_dst) < 0) {
    gz_dst = 0;
    goto write_error;
  }
  return 0;

 write_error:
  z_msg = gzerror(gz_dst, &saved_errno);
  if (saved_errno == Z_ERRNO) {
    saved_errno = errno;
    z_msg = strerror(errno);
  } else {
    saved_errno = 1000 - saved_errno;
  }
  err("gzip_write_file: write error: %s", z_msg);
  goto cleanup;

 cleanup:
  if (gz_dst) gzclose(gz_dst);
  errno = saved_errno;
  return -saved_errno;
}

int
generic_write_file(char const *buf, size_t size, int flags,
                   char const *dir, char const *name, char const *sfx)
{
  path_t wrt_path;
  path_t uniq_pfx;
  path_t out_path;
  int    r;

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
  //info("writing file %s", wrt_path);
  if ((flags & GZIP)) {
    r = gzip_write_file(buf, size, wrt_path, flags);
  } else {
    r = do_write_file(buf, size, wrt_path,flags);
  }
  if (r < 0) {
    if (!(flags & (PIPE | KEEP_ON_FAIL))) unlink(wrt_path);
    errno = -r;
    return r;
  }
  if ((flags & SAFE)) {
    pathmake(out_path, dir, "/", "dir", "/", name, sfx, NULL);
    //info("Move: %s -> %s", wrt_path, out_path);
    if (rename(wrt_path, out_path) < 0) {
      r = errno;
      err("rename failed: %s", os_ErrorMsg());
      if (!(flags & PIPE)) unlink(wrt_path);
      errno = r;
      return -r;
    }
  }
  return size;
}

static int
do_read_file(char **pbuf, size_t maxsz, size_t *prsz,
             const unsigned char *path)
{
  char *buf = *pbuf;
  int fd = -1, errcode = 0;
  int rsz;
  unsigned char *hbuf = 0;
  unsigned char sbuf[4096];
  size_t hbuf_a = 0, hbuf_u = 0;

  if ((fd = errcode = sf_open(path, O_RDONLY, 0)) < 0) goto cleanup;

  /* fixed-size buffer */
  if (buf) {
    if (!maxsz) {
      close(fd);
      if (prsz) *prsz = 0;
      return 0;
    }
    if ((rsz = errcode = sf_read(fd, buf, maxsz, path)) < 0) goto cleanup;
    if (rsz + 1 <= maxsz) buf[rsz] = 0;
    if (prsz) *prsz = rsz;
    close(fd);
    return 0;
  }

  /* variable-size buffer: maxsz is ignored */
  while (1) {
    if ((rsz = errcode = sf_read(fd,sbuf,sizeof(sbuf),path)) < 0) goto cleanup;
    if (!rsz) break;
    if (hbuf_u + rsz > hbuf_a) {
      if (!hbuf_a) hbuf_a = 128;
      while (hbuf_u + rsz > hbuf_a) hbuf_a *= 2;
      hbuf = xrealloc(hbuf, hbuf_a);
    }
    memcpy(hbuf + hbuf_u, sbuf, rsz);
    hbuf_u += rsz;
  }
  if (hbuf_u == hbuf_a) {
    if (!hbuf_a) hbuf_a = 8;
    hbuf_a *= 2;
    hbuf = xrealloc(hbuf, hbuf_a);
  }
  hbuf[hbuf_u] = 0;

  if (prsz) *prsz = hbuf_u;
  *pbuf = hbuf;
  close(fd);
  return 0;

 cleanup:
  if (fd >= 0) close(fd);
  if (!hbuf) xfree(hbuf);
  return errcode;
}

static int
gzip_read_file(char **pbuf, size_t maxsz, size_t *prsz, int flags,
               const unsigned char *path)
{
  int rsz = 0, c = 0, bsz, sz;
  gzFile gz_src = 0;
  unsigned char *rbuf;
  size_t rbuf_a, rbuf_u;
  unsigned char zbuf[2048];
  const unsigned char *msg;
  int saved_errno;

  if (!(gz_src = gzopen(path, "rb"))) {
    saved_errno = errno;
    if (!saved_errno) saved_errno = 1000 - Z_MEM_ERROR;
    err("gzip_read_file: cannot open file `%s'", path);
    goto cleanup;
  }

  /* flags honored: CONVERT */

  if (maxsz > 1 && *pbuf) {
    /* read into a fixed buffer */
    rbuf = (unsigned char*) *pbuf;
    if ((flags & CONVERT)) {
      rsz = 0;
      while (rsz < maxsz - 1 && (c = gzgetc(gz_src)) != EOF) {
        if (c != '\r') {
          *rbuf++ = c, rsz++;
        }
      }
      if (c == EOF) {
        msg = gzerror(gz_src, &saved_errno);
        if (saved_errno < 0) goto read_error;
      }

      *rbuf = 0;
      if (c != EOF) {
        while ((c = gzgetc(gz_src)) != EOF) {
          if (c != '\r') rsz++;
        }
      }
      msg = gzerror(gz_src, &saved_errno);
      if (saved_errno < 0) goto read_error;
      if (prsz) *prsz = rsz;
    } else {
      bsz = maxsz - 1;
      sz = 0;
      while (bsz > 0 && (rsz = gzread(gz_src, rbuf, bsz)) > 0) {
        rbuf += rsz;
        sz += rsz;
        bsz -= rsz;
      }
      if (rsz < 0) {
        msg = gzerror(gz_src, &saved_errno);
        goto read_error;
      }
      *rbuf = 0;
      if (!bsz) {
        while ((c = gzgetc(gz_src)) != EOF) sz++;
      }
      if (prsz) *prsz = sz;
    }
  } else {
    rbuf_a = 4096;
    rbuf_u = 0;
    rbuf = xmalloc(rbuf_a);

    /* read into a variable-size buffer */
    if ((flags & CONVERT)) {
      while ((c = gzgetc(gz_src)) != EOF) {
        if (c == '\r') continue;
        if (rbuf_u + 1 == rbuf_a) {
          rbuf_a *= 2;
          rbuf = xrealloc(rbuf, rbuf_a);
        }
        rbuf[rbuf_u++] = c;
      }
      msg = gzerror(gz_src, &saved_errno);
      if (saved_errno < 0) {
        xfree(rbuf);
        goto read_error;
      }
    } else {
      while ((rsz = gzread(gz_src, zbuf, sizeof(zbuf))) > 0) {
        if (rbuf_u + 1 + rsz >= rbuf_a) {
          while (rbuf_u + 1 + rsz >= rbuf_a) rbuf_a *= 2;
          rbuf = xrealloc(rbuf, rbuf_a);
        }
        memcpy(rbuf + rbuf_u, zbuf, rsz);
        rbuf_u += rsz;
      }
      if (rsz < 0) {
        msg = gzerror(gz_src, &saved_errno);
        xfree(rbuf);
        goto read_error;
      }
    }

    rbuf[rbuf_u] = 0;
    *pbuf = rbuf;
    if (prsz) *prsz = rbuf_u;
  }

  if (gz_src) gzclose(gz_src);
  return 0;

 read_error:
  if (saved_errno == Z_ERRNO) {
    saved_errno = errno;
    msg = strerror(errno);
  } else {
    // note, that gzip's error codes are negative
    saved_errno = 1000 - saved_errno;
  }
  err("gzip_read_file: GZIP read error: %s", msg);

 cleanup:
  if (gz_src) gzclose(gz_src);
  errno = saved_errno;
  return -saved_errno;
}

int
generic_read_file(char **pbuf, size_t maxsz, size_t *prsz, int flags,
                  char const *dir, char const *name, char const *sfx)
{
  path_t uniq_pfx = { 0 };
  path_t read_path;
  path_t in_path;

  int    r = 0, saved_errno;

  ASSERT(pbuf);
  ASSERT(maxsz >= 0);
  //ASSERT(prsz);
  ASSERT(name);

  if ((flags & SAFE)) {
    ASSERT(dir);
    get_uniq_prefix(uniq_pfx);
    pathmake(in_path, dir, "/", "dir", "/", name, sfx, NULL);
    pathmake(read_path, dir, "/", "out", "/",  uniq_pfx, name, sfx, NULL);
    //write_log(0, LOG_INFO, "Move: %s -> %s", in_path, read_path);
    if (rename(in_path, read_path) < 0) {
      if (errno == ENOENT) {
        write_log(0, LOG_WARN, "rename: no source file %s", in_path);
        return 0;
      }
      saved_errno = errno;
      if ((flags & REMOVE)) unlink(in_path);
      err("rename failed: %s", os_ErrorMsg());
      errno = saved_errno;
      return -saved_errno;
    }
  } else {
    if (!dir || !*dir) {
      pathmake(read_path, name, sfx, NULL);
    } else {
      pathmake(read_path, dir, "/", name, sfx, NULL);
    }
  }
  //info("reading file %s", read_path);
  if ((flags & GZIP)) {
    r = gzip_read_file(pbuf, maxsz, prsz, flags, read_path);
  } else {
    r = do_read_file(pbuf, maxsz, prsz, read_path);
  }

  if (r < 0) {
    if ((flags & REMOVE)) unlink(read_path);
    errno = -r;
    return r;
  }

  if ((flags & REMOVE)) {
    if (unlink(read_path) < 0) {
      saved_errno = errno;
      err("unlink failed: %s", os_ErrorMsg());
      errno = saved_errno;
      return -saved_errno;
    }
  }
  return 1;
}

static int
dumb_copy_file_to_dos(FILE *s, FILE *d)
{
  int do_conv = 1;
  int c;

  c = getc_unlocked(s);
  while (c != EOF) {
    if (c == '\r') do_conv = 0;
    if (c == '\n' && do_conv) {
      if (putc_unlocked('\r', d) < 0) return -errno;
    }
    if (putc_unlocked(c, d) < 0) return -errno;
    c = getc_unlocked(s);
  }
  if (ferror_unlocked(s)) return -errno;
  return 0;
}

static int
dumb_copy_file_from_dos(FILE *s, FILE *d)
{
  int c;

  while ((c = getc_unlocked(s)) != EOF) {
    if (c != '\r') {
      if (putc_unlocked(c, d) < 0) return -errno;
    }
  }
  if (ferror_unlocked(s)) return -errno;
  return 0;
}

static int
dumb_copy_file(int sfd, int sf, int dfd, int df)
{
  FILE *fs = 0, *fd = 0;
  int saved_errno, e;

  if (!(fs = fdopen(sfd, "rb"))) {
    saved_errno = errno;
    err("dumb_copy_file: fdopen(rb) failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  sfd = -1;
  if (!(fd = fdopen(dfd, "wb"))) {
    saved_errno = errno;
    err("dumb_copy_file: fdopen(wb) failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  dfd = -1;
  if ((sf & CONVERT)) {
    if ((e = dumb_copy_file_from_dos(fs, fd)) < 0) {
      saved_errno = -e;
      goto cleanup;
    }
  } else {
    if ((e = dumb_copy_file_to_dos(fs, fd)) < 0) {
      saved_errno = -e;
      goto cleanup;
    }
  }
  if (fclose(fs) < 0) {
    fs = 0;
    saved_errno = errno;
    err("dumb_copy_file: fclose(rb) failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  fs = 0;
  if (fclose(fd) < 0) {
    fd = 0;
    saved_errno = errno;
    err("dumb_copy_file: fclose(wb) failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  return 0;

 cleanup:
  if (fs) fclose(fs);
  if (fd) fclose(fd);
  if (sfd >= 0) close(sfd);
  if (dfd >= 0) close(dfd);
  errno = saved_errno;
  return -saved_errno;
}

static int
gzip_copy_file(int sfd, int sf, int dfd, int df)
{
  gzFile gz_src = 0, gz_dst = 0;
  FILE *f_src = 0, *f_dst = 0;
  int c, do_conv = 1, saved_errno;
  unsigned char buf[4096], *p;
  int sz, wsz;
  const unsigned char *z_msg = 0, *z_func = 0;

  /* (sf & CONVERT) do dos->unix conversion sfd - DOS file, dfd - UNIX file */
  /* (df & CONVERT) vice versa */

  if ((sf & GZIP)) {
    if (!(gz_src = gzdopen(sfd, "rb"))) {
      saved_errno = errno;
      if (!saved_errno) saved_errno = 1000 - Z_MEM_ERROR;
      err("gzip_copy_file: cannot attach input stream");
      goto cleanup;
    }
    sfd = -1;
  }
  if (sf == CONVERT) {
    if (!(f_src = fdopen(sfd, "rb"))) {
      saved_errno = errno;
      err("gzip_copy_file: cannot attach input stream");
      goto cleanup;
    }
    sfd = -1;
  }
  if ((df & GZIP)) {
    if (!(gz_dst = gzdopen(dfd, "wb9"))) {
      saved_errno = errno;
      if (!saved_errno) saved_errno = 1000 - Z_MEM_ERROR;
      err("gzip_copy_file: cannot attach output stream");
      goto cleanup;
    }
    dfd = -1;
  }
  if (df == CONVERT) {
    if (!(f_dst = fdopen(dfd, "wb"))) {
      saved_errno = errno;
      err("gzip_copy_file: cannot attach output stream");
      goto cleanup;
    }
    dfd = -1;
  }

  if (sf == (GZIP|CONVERT) && df == GZIP) {
    while ((c = gzgetc(gz_src)) != EOF) {
      if (c != '\r') {
        if (gzputc(gz_dst, c) < 0) goto gzputc_error;
      }
    }
    gzerror(gz_src, &saved_errno);
    if (saved_errno < 0) goto gzgetc_error;
  } else if (sf == (GZIP|CONVERT) && df == 0) {
    while ((c = gzgetc(gz_src)) != EOF) {
      if (c != '\r') {
        if (putc_unlocked(c, f_dst) < 0) goto putc_error;
      }
    }
    gzerror(gz_src, &saved_errno);
    if (saved_errno < 0) goto gzgetc_error;
  } else if (sf == GZIP && df == (GZIP | CONVERT)) {
    while ((c = gzgetc(gz_src)) != EOF) {
      if (c == '\r') do_conv = 0;
      if (c == '\n' && do_conv) {
        if (gzputc(gz_dst, '\r') < 0) goto gzputc_error;
      }
      if (gzputc(gz_dst, c) < 0) goto gzputc_error;
    }
    gzerror(gz_src, &saved_errno);
    if (saved_errno < 0) goto gzgetc_error;
  } else if (sf == GZIP && df == CONVERT) {
    while ((c = gzgetc(gz_src)) != EOF) {
      if (c == '\r') do_conv = 0;
      if (c == '\n' && do_conv) {
        if (putc_unlocked('\r', f_dst) < 0) goto putc_error;
      }
      if (putc_unlocked(c, f_dst) < 0) goto putc_error;
    }
    gzerror(gz_src, &saved_errno);
    if (saved_errno < 0) goto gzgetc_error;
  } else if (sf == GZIP && df == 0) {
    while ((sz = gzread(gz_src, buf, sizeof(buf))) > 0) {
      p = buf;
      while (sz > 0) {
        if ((wsz = write(dfd, p, sz)) <= 0) {
          saved_errno = errno;
          err("gzip_copy_file: write error: %s", os_ErrorMsg());
          goto cleanup;
        }
        p += wsz;
        sz -= wsz;
      }
    }
    if (sz < 0) {
      z_func = "gzread";
      goto z_error;
    }
  } else if (sf == CONVERT && df == GZIP) {
    while ((c = getc_unlocked(f_src)) != EOF) {
      if (c != '\r') {
        if (gzputc(gz_dst, c) < 0) goto gzputc_error;
      }
    }
    if (ferror_unlocked(f_src)) {
      saved_errno = errno;
      err("gzip_copy_file: getc failed: %s", os_ErrorMsg());
      goto cleanup;
    }
  } else if (sf == 0 && df == (GZIP|CONVERT)) {
    while ((c = getc(f_src)) != EOF) {
      if (c == '\r') do_conv = 0;
      if (c == '\n' && do_conv) {
        if (gzputc(gz_dst, '\r') < 0) goto gzputc_error;
      }
      if (gzputc(gz_dst, c) < 0) goto gzputc_error;
    }
    if (ferror_unlocked(f_src)) {
      saved_errno = errno;
      err("gzip_copy_file: getc failed: %s", os_ErrorMsg());
      goto cleanup;
    }
  } else if (sf == 0 && df == GZIP) {
    while ((sz = read(sfd, buf, sizeof(buf))) > 0) {
      p = buf;
      while (sz > 0) {
        if ((wsz = gzwrite(gz_dst, p, sz)) <= 0) {
          z_func = "gzwrite";
          goto z_error;
        }
        p += wsz;
        sz -= wsz;
      }
    }
    if (sz < 0) {
      saved_errno = errno;
      err("gzip_copy_file: read error: %s", os_ErrorMsg());
      goto cleanup;
    }
  } else {
    SWERR(("gzip_copy_file: unhandled case: sf = %d, df = %d", sf, df));
  }

  if (gz_src) gzclose(gz_src);
  gz_src = 0;
  if (gz_dst) {
    if ((saved_errno = gzclose(gz_dst)) < 0) {
      if (saved_errno == Z_ERRNO) {
        saved_errno = errno;
        z_msg = strerror(saved_errno);
      } else {
        z_msg = zError(saved_errno);
        saved_errno = 1000 - saved_errno;
      }
      gz_dst = 0;
      err("gzip_copy_file: gzclose failed: %s", z_msg);
      goto cleanup;
    }
  }
  gz_dst = 0;
  if (f_src) fclose(f_src);
  f_src = 0;
  if (f_dst) {
    if (fclose(f_dst) < 0) {
      saved_errno = errno;
      f_dst = 0;
      err("gzip_copy_file: fclose failed: %s", os_ErrorMsg());
      goto cleanup;
    }
  }
  f_dst = 0;
  if (sfd >= 0) close(sfd);
  sfd = -1;
  if (dfd >= 0) {
    if (close(dfd) < 0) {
      saved_errno = errno;
      dfd = -1;
      err("gzip_copy_file: close failed: %s", os_ErrorMsg());
      goto cleanup;
    }
  }
  return 0;

 putc_error:
  saved_errno = errno;
  err("gzip_copy_file: putc failed: %s", os_ErrorMsg());
  goto cleanup;

 gzgetc_error:
  z_func = "gzgetc";
  goto z_error;

 gzputc_error:
  z_func = "gzputc";
  goto z_error;

 z_error:
  z_msg = gzerror(gz_dst, &saved_errno);
  if (saved_errno == Z_ERRNO) {
    saved_errno = errno;
    z_msg = strerror(saved_errno);
  } else {
    saved_errno = 1000 - saved_errno;
  }
  err("gzip_copy_file: %s failed: %s", z_func, z_msg);
  goto cleanup;

 cleanup:
  if (gz_src) gzclose(gz_src);
  if (gz_dst) gzclose(gz_dst);
  if (f_src) fclose(f_src);
  if (f_dst) fclose(f_dst);
  if (sfd >= 0) close(sfd);
  if (dfd >= 0) close(dfd);
  errno = saved_errno;
  return -saved_errno;
}

static int
do_copy_file(char const *src, int sf, char const *dst, int df)
{
  int   sfd = -1;
  int   dfd = -1;
  char  buf[4096];
  char *p;
  int   sz;
  int   wsz;
  int   errcode;

  if ((sfd = errcode = sf_open(src, O_RDONLY, 0)) < 0) goto _cleanup;
  if ((dfd = errcode = sf_open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0)
    goto _cleanup;

  sf &= (GZIP | CONVERT);
  df &= (GZIP | CONVERT);
  if ((sf || df) && sf != df) {
    /* if compression requested, work differently */
    if ((sf & GZIP) || (df & GZIP)) {
      if ((errcode = gzip_copy_file(sfd, sf, dfd, df)) >= 0) return errcode;
      sfd = dfd = -1;
      goto _unlink_and_cleanup;
    }

    /* if conversion requested, use dumb copy method */
    if ((sf & CONVERT) || (df & CONVERT)) {
      if ((errcode = dumb_copy_file(sfd, sf, dfd, df)) >= 0) return errcode;
      sfd = dfd = -1;
      goto _unlink_and_cleanup;
    }
  }

  while ((sz = errcode = sf_read(sfd, buf, sizeof(buf), src)) > 0) {
    p = buf;
    while (sz > 0) {
      if ((wsz = errcode = sf_write(dfd, p, sz, dst)) <= 0)
        goto _unlink_and_cleanup;
      p += wsz;
      sz -= wsz;
    }
  }
  if (sz < 0) goto _unlink_and_cleanup;

  close(sfd); sfd = -1;
  if ((errcode = sf_close(dfd, dst)) < 0) goto _unlink_and_cleanup;
  return 0;

 _unlink_and_cleanup:
  unlink(dst);

 _cleanup:
  if (sfd >= 0) close(sfd);
  if (dfd >= 0) close(dfd);
  errno = errcode;
  return -errcode;
}

int
generic_copy_file(int sflags,
                  char const *sdir, char const *sname, char const *ssfx,
                  int dflags,
                  char const *ddir, char const *dname, char const *dsfx)
{
  path_t uniq_pfx;
  path_t copy_src;
  path_t copy_dst;
  path_t move_src;
  path_t move_dst;
  int r, saved_errno;

  ASSERT(sname);
  ASSERT(dname);

  if ((sflags & CONVERT) && (dflags & CONVERT)) {
    sflags &= ~CONVERT;
    dflags &= ~CONVERT;
  }

  if ((sflags & SAFE) || (dflags & SAFE)) {
    get_uniq_prefix(uniq_pfx);
  }

  if ((sflags & SAFE)) {
    ASSERT(sdir);
    pathmake(move_src, sdir, "/", "dir", "/", sname, ssfx, NULL);
    pathmake(copy_src, sdir, "/", "out", "/", uniq_pfx, sname, ssfx, NULL);

    //write_log(0, LOG_INFO, "Move: %s -> %s", move_src, copy_src);
    if (rename(move_src, copy_src) < 0) {
      if (errno == ENOENT) {
        write_log(0, LOG_WARN, "rename: no source file %s", move_src);
        return 0;
      }
      saved_errno = errno;
      err("rename failed: %s", os_ErrorMsg());
      errno = saved_errno;
      return -saved_errno;
    }
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

  //write_log(0, LOG_INFO, "Copy: %s -> %s", copy_src, copy_dst);
  if ((r = do_copy_file(copy_src, sflags, copy_dst, dflags)) < 0) {
    if ((sflags & SAFE)) rename(copy_src, move_src);
    return r;
  }

  if ((dflags & SAFE)) {
    //write_log(0, LOG_INFO, "Move: %s -> %s", copy_dst, move_dst);
    if (rename(copy_dst, move_dst) < 0) {
      saved_errno = errno;
      err("rename failed: %s", os_ErrorMsg());
      if ((sflags & SAFE)) rename(copy_src, move_src);
      unlink(copy_dst);
      errno = saved_errno;
      return -saved_errno;
    }
  }
  if ((sflags & REMOVE)) {
    if (unlink(copy_src) < 0) {
      saved_errno = errno;
      err("generic_copy_file: unlink failed: %s", os_ErrorMsg());
      if ((sflags & SAFE)) rename(copy_src, move_src);
      if ((dflags & SAFE)) unlink(move_dst);
      else unlink(copy_dst);
      errno = saved_errno;
      return -saved_errno;
    }
  }
  return 1;
}

int
make_executable(char const *path)
{
  if (chmod(path, 0555) < 0) return -1;
  return 0;
}

int
make_writable(char const *path)
{
  if (chmod(path, 0775) < 0) {
    write_log(0, LOG_ERR, "chmod(%s) failed: %d, %s",
              path, errno, strerror(errno));
    return -1;
  }
  return 0;
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
  if (os_CheckAccess(path, REUSE_R_OK | REUSE_X_OK) < 0) {
    err("directory '%s' is not readable", path);
    return -1;
  }
  return 0;
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
  if (os_CheckAccess(path, REUSE_R_OK | REUSE_W_OK | REUSE_X_OK) < 0) {
    err("directory '%s' is not writable", path);
    return -1;
  }
  return 0;
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
  if (os_CheckAccess(path, REUSE_X_OK) < 0) {
    err("script '%s' is not executable", path);
    return -1;
  }
  return 0;
}

int
relaxed_remove(char const *dir, char const *name)
{
  path_t path;

  if (dir) pathmake(path, dir, "/", name, 0);
  else pathcpy(path, name);

  if (unlink(path) >= 0) return 0;
  if (errno == ENOENT) return 0;
  err("relaxed_remove: unlink(\"%s\") failed: %s", path, os_ErrorMsg());
  return -1;
}

ssize_t
sf_read(int fd, void *buf, size_t count, char const *name)
{
  ssize_t r = read(fd, buf, count);
  int     e = errno;

  if (r >= 0) return r;
  if (name) err("read from %s failed: %s", name, os_ErrorMsg());
  else err("read failed: %s", os_ErrorMsg());
  errno = e;
  return -e;
}

ssize_t
sf_write(int fd, void const *buf, size_t count, char const *name)
{
  ssize_t r = write(fd, buf, count);
  int     e = errno;

  if (r > 0) return r;
  if (r == 0) {
    e = 0;
    if (name) err("write to %s returned 0", name);
    else err("write returned 0");
  } else {
    if (name) err("write to %s failed: %s", name, os_ErrorMsg());
    else err("write failed: %s", os_ErrorMsg());
  }
  return -e;
}

int
sf_close(int fd, char const *name)
{
  int r = close(fd);
  int e = errno;

  if (r >= 0) return r;
  if (name) err("close of %s failed: %s", name, os_ErrorMsg());
  else err("close failed: %s", os_ErrorMsg());
  return -e;
}

int
sf_open(char const *path, int flags, mode_t mode)
{
  int r = open(path, flags, mode);
  if (r >= 0) return r;

  {
    int  e = errno;
    char sflags[256];

    /* decode flags */
    switch ((flags & O_ACCMODE)) {
    case O_RDONLY: strcpy(sflags, "O_RDONLY"); break;
    case O_WRONLY: strcpy(sflags, "O_WRONLY"); break;
    case O_RDWR:   strcpy(sflags, "O_RDWR");   break;
    default:
      strcpy(sflags, "<unknown open mode>");
    }
    if ((flags & O_CREAT)) strcat(sflags, "O_CREAT");
    if ((flags & O_EXCL)) strcat(sflags, "O_EXCL");
    if ((flags & O_NOCTTY)) strcat(sflags, "O_NOCTTY");
    if ((flags & O_TRUNC)) strcat(sflags, "O_TRUNC");
    if ((flags & O_APPEND)) strcat(sflags, "O_APPEND");
    if ((flags & O_NONBLOCK)) strcat(sflags, "O_NONBLOCK");

    if ((flags & O_CREAT))
      err("open(\"%s\", %s, 0%o) failed: %s", path,sflags,mode,os_ErrorMsg());
    else
      err("open(\"%s\", %s) failed: %s", path, sflags, os_ErrorMsg());
    errno = e;
    return -e;
  }
}

off_t
sf_lseek(int fd, off_t offset, int whence, char const *str)
{
  off_t r = lseek(fd, offset, whence);
  if (r != (off_t) -1) return r;

  {
    char *s = "unknown";
    switch (whence) {
    case SEEK_SET: s = "SEEK_SET"; break;
    case SEEK_CUR: s = "SEEK_CUR"; break;
    case SEEK_END: s = "SEEK_END"; break;
    }

    if (str) err("%s: lseek(%d,%ld,%s) failed: %s", str, fd, (long) offset, s,
                 os_ErrorMsg());
    else err("lseek(%d,%ld,%s) failed: %s", fd, (long) offset, s,
             os_ErrorMsg());
    return r;
  }
}

int
sf_chmod(char const *path, mode_t mode)
{
  if (!mode) return 0;
  if (chmod(path, mode) >= 0) return 0;
  err("chmod(\"%s\", 0%o) failed: %s", path, mode, os_ErrorMsg());
  return -1;
}

int
sf_mkfifo(char const *path, mode_t mode)
{
  if (mkfifo(path, mode) >= 0) return 0;
  err("mkfifo(\"%s\", 0%o) failed: %s", path, mode, os_ErrorMsg());
  return -1;
}

struct dirtree_node
{
  unsigned char *name;
  int is_dir;
  size_t a, u;
  struct dirtree_node **v;
};
struct dirqueue_node
{
  struct dirqueue_node *next;
  struct dirtree_node *node;
  unsigned char *fullpath;
};

static void
do_remove_recursively(const unsigned char *fullpath,
                      const struct dirtree_node *node)
{
  unsigned char curpath[PATH_MAX];
  int i;


  for (i = 0; i < node->u; i++) {
    snprintf(curpath, PATH_MAX, "%s/%s", fullpath, node->v[i]->name);
    if (node->v[i]->is_dir) {
      do_remove_recursively(curpath, node->v[i]);
      rmdir(curpath);
    } else {
      unlink(curpath);
    }
  }
}

static void
free_file_hierarchy(struct dirtree_node *node)
{
  int i;

  for (i = 0; i < node->u; i++)
    free_file_hierarchy(node->v[i]);
  xfree(node->v);
  xfree(node->name);
  xfree(node);
}

/* remove the specified directory and all its contents */
int
remove_directory_recursively(
        const unsigned char *path,
        int preserve_root)
{
  struct stat sb;
  struct dirtree_node *root = 0, *pt;
  struct dirqueue_node *head = 0, **ptail = &head, *pq;
  DIR *d;
  struct dirent *dd;
  unsigned char fullpath[PATH_MAX];
  unsigned char rootpath[PATH_MAX];
  size_t fp_len;

  snprintf(rootpath, PATH_MAX, "%s", path);
  fp_len = strlen(rootpath);
  while (fp_len > 1 && rootpath[fp_len - 1] == '/')
    rootpath[--fp_len] = 0;

  if (lstat(rootpath, &sb) < 0) {
    err("rm-rf: lstat(\"%s\") failed: %s", rootpath, os_ErrorMsg());
    return -1;
  }
  if (!S_ISDIR(sb.st_mode)) {
    err("rm-rf: '%s' is not a directory", rootpath);
    return -1;
  }
  XCALLOC(root, 1);
  root->name = xstrdup(rootpath);
  root->is_dir = 1;
  root->a = 8;
  XCALLOC(root->v, root->a);
  XCALLOC(head, 1);
  ptail = &head->next;
  head->fullpath = xstrdup(rootpath);
  head->node = root;

  while (head) {
    /* ignore the errors */
    chmod(head->fullpath, 0770);

    if ((d = opendir(head->fullpath))) {
      while ((dd = readdir(d))) {
        if (!strcmp(dd->d_name, ".")) continue;
        if (!strcmp(dd->d_name, "..")) continue;
        snprintf(fullpath, PATH_MAX, "%s/%s", head->fullpath, dd->d_name);
        if (lstat(fullpath, &sb) < 0) continue;
        XCALLOC(pt, 1);
        pt->name = xstrdup(dd->d_name);
        if (head->node->u >= head->node->a) {
          if (!head->node->a) head->node->a = 8;
          head->node->a *= 2;
          XREALLOC(head->node->v, head->node->a);
        }
        head->node->v[head->node->u++] = pt;
        if (S_ISDIR(sb.st_mode)) {
          pt->is_dir = 1;
          pt->a = 8;
          XCALLOC(pt->v, pt->a);
          XCALLOC(pq, 1);
          pq->node = pt;
          pq->fullpath = xstrdup(fullpath);
          *ptail = pq;
          ptail = &pq->next;
        }
      }
      closedir(d);
    }

    /* remove the head from the queue */
    pq = head;
    head = head->next;
    if (!head) ptail = &head;
    xfree(pq->fullpath);
    xfree(pq);
  }

  do_remove_recursively(rootpath, root);
  free_file_hierarchy(root);

  if (!preserve_root) {
    if (rmdir(rootpath) < 0) {
      err("rm-rf: rmdir(\"%s\") failed: %s", rootpath, os_ErrorMsg());
      return -1;
    }
  }

  return 0;
}

ssize_t
generic_file_size(const unsigned char *dir,
                  const unsigned char *name,
                  const unsigned char *sfx)
{
  path_t path;
  struct stat sb;

  ASSERT(name);
  if (!dir) dir = "";
  if (!sfx) sfx = "";

  if (!strcmp(dir, "") || !strcmp(dir, "/")) {
    snprintf(path, sizeof(path), "%s%s%s", dir, name, sfx);
  } else {
    snprintf(path, sizeof(path), "%s/%s%s", dir, name, sfx);
  }

  if (stat(path, &sb) < 0) {
    err("generic_file_size: stat failed on `%s'", path);
    return -1;
  }
  if (!S_ISREG(sb.st_mode)) {
    err("generic_file_size: file `%s' is not a regular file", path);
    return -1;
  }
  return sb.st_size;
}

static size_t
split_path(const unsigned char *path, strarray_t *parr)
{
  unsigned char **s_v = 0;
  size_t s_u = 0, s_a = 0;
  const unsigned char *p = path, *q;

  memset(parr, 0, sizeof(*parr));
  if (*p == '/') {
    s_a = 8;
    s_v = xcalloc(s_a, sizeof(s_v[0]));
    s_v[0] = xstrdup("/");
    s_u++;
    while (*p == '/') p++;
  }
  while (*p) {
    q = p;
    while (*q && *q != '/') q++;
    if (s_u == s_a) {
      if (!s_a) s_a = 4;
      s_a *= 2;
      s_v = xrealloc(s_v, s_a * sizeof(s_v[0]));
    }
    s_v[s_u++] = xmemdup(p, q - p);
    p = q;
    while (*p == '/') p++;
  }
  parr->v = (char**) s_v;
  parr->a = s_a;
  parr->u = s_u;
  return s_u;
}

static void
make_relative_path(const unsigned char *dest, strarray_t *pdest,
                   const unsigned char *path, strarray_t *ppath,
                   unsigned char *res, size_t reslen)
{
  int i, j, k = 0;
  size_t bound = reslen - 1;
  const unsigned char *q;

  ASSERT(res);
  ASSERT(reslen > 1);
  memset(res, 0, reslen);

  /*
  fprintf(stderr, "Dest:\n");
  for (i = 0; i < pdest->u; i++)
    fprintf(stderr, "[%d]: >>%s<<\n", i, pdest->v[i]);
  fprintf(stderr, "Path:\n");
  for (i = 0; i < ppath->u; i++)
    fprintf(stderr, "[%d]: >>%s<<\n", i, ppath->v[i]);
  */

  /* calculate number of common elements */
  for (i=0;i<pdest->u&&i<ppath->u&&!strcmp(pdest->v[i],ppath->v[i]);i++);
  if (i == ppath->u) {
    snprintf(res, reslen, "%s", dest);
    return;
  }
  for (j = i; j < ppath->u - 1; j++) {
    if (k > 0) res[k++] = '/';
    if (k >= bound) return;
    res[k++] = '.';
    if (k >= bound) return;
    res[k++] = '.';
    if (k >= bound) return;
  }
  for (j = i; j < pdest->u; j++) {
    if (k > 0) res[k++] = '/';
    if (k >= bound) return;
    q = pdest->v[j];
    while (*q) {
      res[k++] = *q++;
      if (k >= bound) return;
    }
  }
  if (!k) res[k++] = '.';
}

int
make_symlink(unsigned char const *dest, unsigned char const *path)
{
  struct stat si;
  int r;
  unsigned char *cwd = 0;
  unsigned char *t = 0;
  unsigned char *l = 0;
  path_t lpath;
  strarray_t adest, apath;

  if (dest[0] != '/' || path[0] != '/') {
    cwd = alloca(PATH_MAX);
    if (!getcwd(cwd, PATH_MAX)) {
      err("make_symlink: getcwd failed: %s", os_ErrorMsg());
      return -1;
    }
    if (dest[0] != '/') {
      t = alloca(PATH_MAX);
      snprintf(t, PATH_MAX, "%s/%s", cwd, dest);
      dest = t;
    }
    if (path[0] != '/') {
      t = alloca(PATH_MAX);
      snprintf(t, PATH_MAX, "%s/%s", cwd, path);
      path = t;
    }
  }
  ASSERT(dest[0] == '/');
  ASSERT(path[0] == '/');

  /* prefer relative path over absolute */
  split_path(dest, &adest);
  split_path(path, &apath);
  make_relative_path(dest, &adest, path, &apath, lpath, sizeof(lpath));
  xstrarrayfree(&adest);
  xstrarrayfree(&apath);

  if ((r = lstat(path, &si)) >= 0 && !S_ISLNK(si.st_mode)) {
    err("make_symlink: %s already exists, but not a symlink", path);
    return -1;
  }

  if (r >= 0) {
    // symlink already exists
    l = alloca(PATH_MAX);
    if (readlink(path, l, PATH_MAX) < 0) {
      err("make_symlink: readlink(%s) failed: %s", path, os_ErrorMsg());
      return -1;
    }
    if (!strcmp(l, lpath)) return 0;
    if (unlink(path) < 0) {
      err("make_symlink: unlink(%s) failed: %s", path, os_ErrorMsg());
      return -1;
    }
  }

  if (symlink(lpath, path) < 0) {
    err("make_symlink: symlink(%s,%s) failed: %s", lpath, path, os_ErrorMsg());
    return -1;
  }
  return 0;
}

int
fast_copy_file(const unsigned char *oldname, const unsigned char *newname)
{
  return do_copy_file(oldname, 0, newname, 0);
}

int
generic_truncate(const char *path, ssize_t size)
{
  return truncate(path, size);
}

int
make_hardlink(const unsigned char *oldname, const unsigned char *newname)
{
  return do_copy_file(oldname, 0, newname, 0);

#if 0
  if (link(oldname, newname) >= 0) return 0;
  if (errno == EEXIST || errno == EXDEV || errno == EPERM) {
    return do_copy_file(oldname, 0, newname, 0);
  }
  err("make_hardlink: link(%s,%s) failed: %s",
      oldname, newname, os_ErrorMsg());
  return -1;
#endif
}

const unsigned char *
get_tmp_dir(unsigned char *buf, size_t size)
{
  const unsigned char *s = getenv("TMPDIR");
  if (s && *s) {
    snprintf(buf, size, "%s", s);
    return buf;
  }
#if defined P_tmpdir
  s = P_tmpdir;
  if (s && *s) {
    snprintf(buf, size, "%s", s);
    return buf;
  }
#endif
  snprintf(buf, size, "%s", "/tmp");
  return buf;
}

static int
name_sort_func(const void *p1, const void *p2)
{
  const unsigned char *s1 = *(const unsigned char **) p1;
  const unsigned char *s2 = *(const unsigned char **) p2;
  return strcmp(s1, s2);
}

int
scan_executable_files(
        const unsigned char *dir,
        int *p_count,
        unsigned char ***p_files)
{
  int count = 0;
  int alloc = 0;
  unsigned char **files = 0;
  int i;
  DIR *d;
  struct dirent *dd;
  path_t path;
  struct stat stb;

  if (p_count) *p_count = 0;
  if (p_files) *p_files = 0;

  if (!(d = opendir(dir))) {
    err("scan_executable_file: no directory %s", dir);
    goto fail;
  }
  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
    snprintf(path, sizeof(path), "%s/%s", dir, dd->d_name);
    if (stat(path, &stb) < 0) continue;
    if (!S_ISREG(stb.st_mode)) continue;
    if (access(path, X_OK) < 0) continue;

    if (count >= alloc) {
      int new_alloc = alloc * 2;
      unsigned char **new_files = 0;
      if (!new_alloc) new_alloc = 32;
      XCALLOC(new_files, new_alloc);
      if (count > 0) {
        memcpy(new_files, files, count * sizeof(new_files[0]));
      }
      xfree(files);
      files = new_files;
      alloc = new_alloc;
    }
    files[count++] = xstrdup(dd->d_name);
  }
  closedir(d);

  if (count > 1) {
    qsort(files, count, sizeof(files[0]), name_sort_func);
  }

  if (p_count) *p_count = count;
  if (p_files) *p_files = files;
  return 0;

fail:
  if (d) closedir(d);
  for (i = 0; i < count; ++i)
    xfree(files[i]);
  xfree(files);
  return -1;
}

int
write_tmp_file(
        unsigned char *path,
        size_t path_size,
        const unsigned char *bytes,
        size_t bytes_count)
{
  const unsigned char *tmpdir = 0;
  int fd, r;
  size_t w;
  const unsigned char *p;

  if (!tmpdir) tmpdir = getenv("TMPDIR");
#if defined P_tmpdir
  if (!tmpdir) tmpdir = P_tmpdir;
#endif
  if (!tmpdir) tmpdir = "/tmp";

  snprintf(path, path_size, "%s/ejf_XXXXXX", tmpdir);
  if ((fd = mkstemp(path)) < 0) {
    err("write_tmp_file: mkstemp() failed: %s", os_ErrorMsg());
    return -1;
  }

  p = bytes; w = bytes_count;
  while (w > 0) {
    if ((r = write(fd, p, w)) <= 0) {
      err("write_tmp_file: write() error: %s", os_ErrorMsg());
      goto failed;
    }
    w -= r; p += r;
  }
  if (close(fd) < 0) {
    err("write_tmp_file: close() failed: %s", os_ErrorMsg());
    goto failed;
  }
  fd = -1;
  return 0;

failed:
  if (fd >= 0) close(fd);
  if (path[0]) unlink(path);
  return -1;
}

enum { MAX_TMP_TRIES = 10 };

int
write_tmp_file_2(
        FILE *log_f,
        const unsigned char *tmp_dir,
        const unsigned char *name_prefix,
        const unsigned char *name_suffix,
        char *path,
        size_t path_size,
        const unsigned char *data,
        size_t size)
{
  int retval = -1;
  int fd = -1;
  int need_unlink = 0;

  ASSERT(path);
  ASSERT(path_size > 0);

  if (!name_prefix) name_prefix = "ejf_";
  if (!name_suffix) name_suffix = "";
  if (!data) {
    data = "";
    size = 0;
  }

  path[0] = 0;
  if (random_init() < 0) {
    if (log_f) {
      fprintf(log_f, "random generator initialization failure");
    }
    err("random generator initialization failure");
    goto cleanup;
  }

  if (!tmp_dir) tmp_dir = getenv("TMPDIR");
#if defined P_tmpdir
  if (!tmp_dir) tmp_dir = P_tmpdir;
#endif
#if defined _PATH_TMP
  if (!tmp_dir) tmp_dir = _PATH_TMP;
#endif
  if (!tmp_dir) tmp_dir = "/tmp";

  int tries = 0;
  while (tries < MAX_TMP_TRIES) {
    unsigned rr = random_u32();
    snprintf(path, path_size, "%s/%s%u%s", tmp_dir, name_prefix, rr, name_suffix);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0600);
    if (fd >= 0) break;
    if (errno != EEXIST) {
      if (log_f) {
        fprintf(log_f, "cannot create temporary file: %s", strerror(errno));
      }
      err("cannot create temporary file: %s", strerror(errno));
      goto cleanup;
    }
    ++tries;
  }
  if (tries >= MAX_TMP_TRIES) {
    if (log_f) {
      fprintf(log_f, "too many attempts to create a temporary file");
    }
    err("too many attempts to create a temporary file");
    goto cleanup;
  }

  need_unlink = 1;
  while (size) {
    size_t bz = size;
    if (bz > PIPE_BUF) bz = PIPE_BUF;
    const unsigned char *p = data;
    size_t z = bz;
    while (bz) {
      ssize_t w = write(fd, p, bz);
      if (w < 0) {
        if (log_f) {
          fprintf(log_f, "write error: %s", strerror(errno));
        }
        err("write error: %s", strerror(errno));
        goto cleanup;
      }
      p += w;
      bz -= w;
    }
    data += z;
    size -= z;
  }
  if (close(fd) < 0) {
    fd = -1;
    if (log_f) {
      fprintf(log_f, "write error: %s", strerror(errno));
    }
    err("write error: %s", strerror(errno));
    goto cleanup;
  }
  fd = -1;
  need_unlink = 0;
  retval = 0;

cleanup:;
  if (fd >= 0) {
    close(fd);
  }
  if (need_unlink) {
    unlink(path);
  }
  return retval;
}

int
fast_read_file_with_size(
        const unsigned char *path,
        size_t size,
        unsigned char **p_buf)
{
  unsigned char *buf = malloc(size + 1);
  buf[size] = 0;

  int fd = open(path, O_RDONLY | O_NOCTTY, 0);
  if (fd < 0) {
    int r = errno;
    err("%s: open '%s' failed: %s", __FUNCTION__, path, os_ErrorMsg());
    free(buf);
    return -r;
  }
  unsigned char *p = buf;
  size_t rem = size;
  while (rem > 0) {
    ssize_t rr = read(fd, p, rem);
    if (rr < 0) {
      int r = errno;
      err("%s: read '%s' failed: %s", __FUNCTION__, path, os_ErrorMsg());
      free(buf);
      close(fd);
      return -r;
    }
    if (!rr) {
      err("%s: unexpected EOF in '%s'", __FUNCTION__, path);
      free(buf);
      close(fd);
      return -EINVAL;
    }
    p += rr;
    rem -= rr;
  }
  close(fd);
  *p_buf = buf;
  return 1;
}

struct file_to_copy
{
  unsigned char *full_src_path;
  unsigned char *full_dst_path;
  long long st_ino;
  long long st_dev;
  int st_mode;
  gid_t st_gid;
  struct timespec st_atim;
  struct timespec st_mtim;
};

struct file_to_copy_vec
{
  struct file_to_copy *v;
  int a, u;
};

static int
collect_files(
        struct file_to_copy_vec *ff,
        const unsigned char *src_dir,
        const unsigned char *dst_dir)
{
  int start_idx = ff->u;
  __attribute__((unused)) int _;
  DIR *dsrc = opendir(src_dir);
  if (!dsrc) {
    err("%s: open directory '%s' failed: %s", __FUNCTION__, src_dir, os_ErrorMsg());
    goto fail;
  }
  struct dirent *dd;
  while ((dd = readdir(dsrc))) {
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) {
      continue;
    }
    char *fullpath = NULL;
    _ = asprintf(&fullpath, "%s/%s", src_dir, dd->d_name);
    struct stat stb;
    if (lstat(fullpath, &stb) < 0) {
      info("%s: lstat failed for '%s': %s", __FUNCTION__, fullpath, os_ErrorMsg());
      free(fullpath);
      continue;
    }
    if (!S_ISDIR(stb.st_mode) && !S_ISLNK(stb.st_mode) && !S_ISREG(stb.st_mode)) {
      free(fullpath);
      continue;
    }
    if (ff->u == ff->a) {
      if (!ff->a) {
        ff->a = 32;
      } else {
        ff->a *= 2;
      }
      XREALLOC(ff->v, ff->a);
    }
    struct file_to_copy *fff = &ff->v[ff->u++];
    memset(fff, 0, sizeof(*fff));
    fff->full_src_path = fullpath;
    fullpath = NULL;
    _ = asprintf(&fullpath, "%s/%s", dst_dir, dd->d_name);
    fff->full_dst_path = fullpath;
    fff->st_ino = stb.st_ino;
    fff->st_dev = stb.st_dev;
    fff->st_mode = stb.st_mode;
    fff->st_gid = stb.st_gid;
    fff->st_atim = stb.st_atim;
    fff->st_mtim = stb.st_mtim;
  }
  closedir(dsrc); dsrc = NULL;

  int end_idx = ff->u;
  for (; start_idx < end_idx; ++start_idx) {
    struct file_to_copy *fff = &ff->v[start_idx];
    if (S_ISDIR(fff->st_mode)) {
      int r = collect_files(ff, fff->full_src_path, fff->full_dst_path);
      if (r < 0) {
        goto fail;
      }
    }
  }

  return 0;

fail:;
  return -1;
}

static ssize_t
copy_file_with_perms(
        const unsigned char *src_path,
        const unsigned char *dst_path)
{
  ssize_t retval = -1;
  int rfd = -1;
  int wfd = -1;
  int __attribute__((unused)) _;

  if ((rfd = open(src_path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0)) < 0) {
    err("%s: open '%s' failed: %s", __FUNCTION__, src_path, os_ErrorMsg());
    goto done;
  }
  struct stat stb;
  if (fstat(rfd, &stb) < 0) {
    err("%s: fstat failed: %s", __FUNCTION__, os_ErrorMsg());
    goto done;
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s: file '%s' is not regular", __FUNCTION__, src_path);
    goto done;
  }

  if ((wfd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL | O_CLOEXEC
                  | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, stb.st_mode & 0777)) < 0) {
    err("%s: open for write '%s' failed: %s", __FUNCTION__, dst_path, os_ErrorMsg());
    goto done;
  }
  struct stat stb2;
  if (fstat(wfd, &stb2) < 0) {
    err("%s: fstat failed: %s", __FUNCTION__, os_ErrorMsg());
    goto done;
  }
  if (!S_ISREG(stb2.st_mode)) {
    err("%s: file '%s' is not regular", __FUNCTION__, dst_path);
    goto done;
  }

  unsigned char buf[65536];
  ssize_t cnt = 0;
  while (1) {
    int r = read(rfd, buf, sizeof(buf));
    if (r < 0) {
      err("%s: read error: %s", __FUNCTION__, os_ErrorMsg());
      goto done;
    }
    if (!r) break;
    cnt += r;

    unsigned char *p = buf;
    while (r > 0) {
      int w = write(wfd, p, r);
      if (w < 0) {
        err("%s: write error: %s", __FUNCTION__, os_ErrorMsg());
        goto done;
      }
      if (!w) abort();
      r -= w;
      p += w;
    }
  }
  close(rfd); rfd = -1;

  struct timespec tss[2] =
  {
    stb.st_atim,
    stb.st_mtim,
  };
  _ = futimens(wfd, tss);               // error is ignored
  _ = fchown(wfd, -1, stb.st_gid);      // error is ignored
  _ = fchmod(wfd, stb.st_mode & 07777); // error is ignored
  close(wfd); wfd = -1;
  retval = cnt;

done:;
  if (rfd >= 0) close(rfd);
  if (wfd >= 0) close(wfd);
  return retval;
}

// content of `src_dir` is copied to `dst_dir`
// copying is recursive
// regular files, symlinks and hardlinks are supported
// file mode and group are preserved, but error is ok
// other file types are ignored
int
copy_directory_recursively(
        FILE *log_f,
        const unsigned char *src_dir,
        const unsigned char *dst_dir)
{
  __attribute__((unused)) int _;
  int retval = -1;
  struct file_to_copy_vec ff = {};
  if (collect_files(&ff, src_dir, dst_dir) < 0) {
    goto done;
  }

  int old_umask = umask(0);
  for (int i = 0; i < ff.u; ++i) {
    struct file_to_copy *fff = &ff.v[i];
    if (S_ISDIR(fff->st_mode)) {
      if (mkdir(fff->full_dst_path, 0700) < 0) {
        err("%s: mkdir %s failed: %s", __FUNCTION__, fff->full_dst_path, os_ErrorMsg());
        goto done;
      }
    } else if (S_ISREG(fff->st_mode)) {
      // TODO: use map?
      int j;
      for (j = 0; j < i; ++j) {
        if (ff.v[j].st_dev == fff->st_dev && ff.v[j].st_ino == fff->st_ino) {
          break;
        }
      }
      if (j < i) {
        // hardlink
        if (link(ff.v[j].full_dst_path, fff->full_dst_path) < 0) {
          err("%s: link %s -> %s failed: %s", __FUNCTION__, fff->full_dst_path, ff.v[j].full_dst_path, os_ErrorMsg());
          goto done;
        }
      } else {
        if (copy_file_with_perms(fff->full_src_path, fff->full_dst_path) < 0) {
          goto done;
        }
      }
    } else if (S_ISLNK(fff->st_mode)) {
      unsigned char lnkbuf[PATH_MAX];
      int r;
      if ((r = readlink(fff->full_src_path, lnkbuf, sizeof(lnkbuf))) < 0) {
        err("%s: readlink %s failed: %s", __FUNCTION__, fff->full_src_path, os_ErrorMsg());
        goto done;
      }
      if (r == sizeof(lnkbuf)) {
        err("%s: symlink %s is too long", __FUNCTION__, fff->full_src_path);
        goto done;
      }
      lnkbuf[r] = 0;
      if (symlink(fff->full_dst_path, lnkbuf) < 0) {
        err("%s: symlink %s -> %s failed: %s", __FUNCTION__, fff->full_src_path, fff->full_src_path, os_ErrorMsg());
        goto done;
      }
      struct timespec tss[2] =
      {
        fff->st_atim,
        fff->st_mtim,
      };
      _ = utimensat(AT_FDCWD, fff->full_dst_path, tss, 0); // error is ignored
      _ = chown(fff->full_dst_path, -1, fff->st_gid);      // error is ignored
      _ = chmod(fff->full_dst_path, fff->st_mode & 07777); // error is ignored
    }
  }
  for (int i = ff.u - 1; i >= 0; --i) {
    struct file_to_copy *fff = &ff.v[i];
    if (S_ISDIR(fff->st_mode)) {
      struct timespec tss[2] =
      {
        fff->st_atim,
        fff->st_mtim,
      };
      _ = utimensat(AT_FDCWD, fff->full_dst_path, tss, 0); // error is ignored
      _ = chown(fff->full_dst_path, -1, fff->st_gid);      // error is ignored
      _ = chmod(fff->full_dst_path, fff->st_mode & 07777); // error is ignored
    }
  }
  umask(old_umask);
  retval = 0;

done:;
  for (int i = 0; i < ff.u; ++i) {
    struct file_to_copy *fff = &ff.v[i];
    xfree(fff->full_src_path);
    xfree(fff->full_dst_path);
  }
  xfree(ff.v);
  return retval;
}
