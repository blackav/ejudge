/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2005 Alexander Chernov <cher@ispras.ru> */

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

#include "fileutl.h"
#include "unix/unix_fileutl.h"
#include "pathutl.h"
#include "settings.h"

#include <reuse/logger.h>
#include <reuse/osdeps.h>
#include <reuse/xalloc.h>

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <zlib.h>

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
      if ((r = remove_directory_recursively(fdel)) < 0) {
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

  if (!access) access = 0755 & ~prev_umask;
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

/* scans 'dir' directory and returns the filename found */
int
scan_dir(char const *partial_path, char *found_item)
{
  path_t         dir_path;
  DIR           *d;
  struct dirent *de;
  int saved_errno;
  int prio, found = 0, i;
  unsigned char *items[32];

  memset(items, 0, sizeof(items));
  pathmake(dir_path, partial_path, "/", "dir", NULL);
  if (!(d = opendir(dir_path))) {
    saved_errno = errno;
    err("scan_dir: opendir(\"%s\") failed: %s", dir_path, os_ErrorMsg());
    errno = saved_errno;
    return -saved_errno;
  }

  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;

    if (strlen(de->d_name) != SERVE_PACKET_NAME_SIZE - 1) {
      prio = 0;
    } else if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
      prio = -16 + (de->d_name[0] - '0');
    } else if (de->d_name[0] >= 'A' && de->d_name[0] <= 'V') {
      prio = -6 + (de->d_name[0] - 'A');
    } else {
      prio = 0;
    }
    if (prio < -16) prio = -16;
    if (prio > 15) prio = 15;
    prio += 16;
    if (items[prio]) continue;

    items[prio] = (unsigned char*) alloca(strlen(de->d_name) + 1);
    strcpy(items[prio], de->d_name);
    found++;
  }
  closedir(d);
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
  info("writing file %s", wrt_path);
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
    info("Move: %s -> %s", wrt_path, out_path);
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
    write_log(0, LOG_INFO, "Move: %s -> %s", in_path, read_path);
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
  info("reading file %s", read_path);
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
    while ((c = getc(gz_src)) != EOF) {
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

    write_log(0, LOG_INFO, "Move: %s -> %s", move_src, copy_src);
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

  write_log(0, LOG_INFO, "Copy: %s -> %s", copy_src, copy_dst);
  if ((r = do_copy_file(copy_src, sflags, copy_dst, dflags)) < 0) {
    if ((sflags & SAFE)) rename(copy_src, move_src);
    return r;
  }

  if ((dflags & SAFE)) {
    write_log(0, LOG_INFO, "Move: %s -> %s", copy_dst, move_dst);
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
  if (chmod(path, 0755) < 0) {
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

    if (str) err("%s: lseek(%d,%ld,%s) failed: %s", str, fd, offset, s, os_ErrorMsg());
    else err("lseek(%d,%ld,%s) failed: %s", fd, offset, s, os_ErrorMsg());
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
remove_directory_recursively(const unsigned char *path)
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
    chmod(head->fullpath, 0700);

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
  if (rmdir(rootpath) < 0) {
    err("rm-rf: rmdir(\"%s\") failed: %s", rootpath, os_ErrorMsg());
    return -1;
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

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR" "gzFile")
 * End:
 */
