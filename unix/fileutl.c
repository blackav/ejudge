/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include "fileutl.h"
#include "unix/unix_fileutl.h"
#include "pathutl.h"

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

void
get_uniq_prefix(char *prefix)
{
  sprintf(prefix, "%d_%s_", getpid(), os_NodeName());
}

/* remove all files in the specified directory */
int
clear_directory(char const *path)
{
  DIR           *d;
  struct dirent *de;
  path_t         fdel;

  if (!(d = opendir(path))) {
    err("clear_directory: opendir(\"%s\") failed: %s", path, os_ErrorMsg());
    return -1;
  }
  while ((de = readdir(d))) {
    if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
      pathmake(fdel, path, "/", de->d_name, NULL);
      if (unlink(fdel) < 0) {
        err("unlink(\"%s\") failed: %s", fdel, os_ErrorMsg());
      }
    }
  }

  info("clear_directory: %s cleared", path);
  closedir(d);
  return 0;
}

int
make_dir(char const *path, int access)
{
  if (mkdir(path, 0755) < 0) {
    if (errno == EEXIST) {
      info("make_dir: %s exists", path);
    } else {
      err("make_dir: mkdir(\"%s\") failed: %s", path, os_ErrorMsg());
      return -1;
    }
  } else {
    if (sf_chmod(path, access) < 0) return -1;
    info("make_dir: %s created", path);
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
  pathcat(inpath, "/in");
  pathcpy(dirpath, path);
  pathcat(dirpath, "/dir");
  pathcpy(outpath, path);
  pathcat(outpath, "/out");

  if (make_dir(path, 0) < 0) return -1;
  if (make_dir(inpath, access) < 0) return -1;
  if (make_dir(dirpath, access) < 0) return -1;
  if (make_dir(outpath, access) < 0) return -1;

  return 0;
}

/* scans 'dir' directory and returns the filename found */
int
scan_dir(char const *partial_path, char *found_item)
{
  path_t         dir_path;
  DIR           *d;
  struct dirent *de;

  pathmake(dir_path, partial_path, "/", "dir", NULL);
  if (!(d = opendir(dir_path))) {
    err("scan_dir: opendir(\"%s\") failed: %s", dir_path, os_ErrorMsg());
    return -1;
  }

  while ((de = readdir(d))) {
    if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
      break;
  }
  if (!de) {
    closedir(d);
    return 0;
  }

  pathcpy(found_item, de->d_name);
  info("scan_dir: found '%s'", found_item);
  closedir(d);
  return 1;
}

static int
do_write_file(char const *buf, size_t sz, char const *dst, int flags)
{
  char const *p;
  int         wsz;
  int         dfd = -1;
  int         open_flags = O_WRONLY | ((flags & PIPE)?0:(O_CREAT|O_TRUNC));

  if ((dfd = sf_open(dst, open_flags, 0644)) < 0) goto _cleanup;
  p = buf;
  while (sz > 0) {
    if ((wsz = sf_write(dfd, p, sz, dst)) <= 0) goto _cleanup;
    p += wsz;
    sz -= wsz;
  }
  if (sf_close(dfd, dst) < 0) return -1;
  return 0;

 _cleanup:
  if (dfd >= 0) close(dfd);
  return -1;
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
  if ((r = do_write_file(buf, size, wrt_path,flags)) < 0) return r;
  if ((flags & SAFE)) {
    pathmake(out_path, dir, "/", "dir", "/", name, sfx, NULL);
    info("Move: %s -> %s", wrt_path, out_path);
    if (rename(wrt_path, out_path) < 0) {
      err("rename failed: %s", os_ErrorMsg());
      return -1;
    }
  }
  return size;
}

static int
do_read_file(char **pbuf, size_t maxsz, size_t *prsz, char const *path)
{
  int   fd = -1;
  char *buf = *pbuf;
  char *hptr = 0;
  int   rsz;
  char *p;

  size_t      lsize, bsize;
  struct stat stat_info;

  if ((fd = sf_open(path, O_RDONLY, 0)) < 0) goto _cleanup;
  if (!buf) {
    if (fstat(fd, &stat_info) < 0) {
      err("do_read_file: fstat failed: %s", os_ErrorMsg());
      goto _cleanup;
    }
    hptr = buf = xcalloc(stat_info.st_size + 16, 1);
    p = buf; lsize = stat_info.st_size;
    while (1) {
      bsize = 4096;
      if (lsize < bsize) bsize = lsize;
      if (bsize == 0) bsize = 1;
      if ((rsz = sf_read(fd, p, bsize, path)) < 0) goto _cleanup;
      if (!rsz) break;
      p += rsz;
      lsize -= rsz;
      if (lsize == -1) break;
    }
    if (lsize > 0) {
      info("do_read_file: file shrunk");
    } else if (lsize < 0) {
      info("do_read_file: file extended");
    }
    if (prsz) *prsz = p - buf;
  } else {
    /* read a size limited packet */
    if ((rsz = sf_read(fd, buf, maxsz, path)) < 0) goto _cleanup;
    if (rsz == maxsz) {
      err("do_read_file: oversized packet: %d", rsz);
      goto _cleanup;
    }
    if (prsz) *prsz = rsz;
  }

  *pbuf = buf;
  close(fd);
  return 0;

 _cleanup:
  if (fd >= 0) close(fd);
  xfree(hptr);
  return -1;
}

int
do_fixed_pipe_read_file(char **pbuf, size_t maxsz, size_t *prsz,
                        char const *path)
{
  SWERR(("sorry, not implemented"));
}

int
do_alloc_pipe_read_file(char **pbuf, size_t maxsz, size_t *prsz,
                        char const *path)
{
  char          read_buf[4096];
  char         *mem = 0;
  unsigned int  cursz = 0;
  int           fd = -1;
  int           rsz;

  if ((fd = sf_open(path, O_RDONLY, 0)) < 0) goto cleanup;
  while ((rsz = sf_read(fd, read_buf, sizeof(read_buf), path)) > 0) {
    mem = (char*) xrealloc(mem, cursz + rsz + 1);
    memcpy(mem + cursz, read_buf, rsz);
    cursz += rsz;
    mem[cursz] = 0;
  }
  if (rsz < 0) goto cleanup;

  *pbuf = mem;
  if (prsz) *prsz = cursz;
  close(fd);
  return 0;

 cleanup:
  xfree(mem);
  if (fd >= 0) close(fd);
  return -1;
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
      err("rename failed: %s", os_ErrorMsg());
      return -1;
    }
  } else {
    if (!dir || !*dir) {
      pathmake(read_path, name, sfx, NULL);
    } else {
      pathmake(read_path, dir, "/", name, sfx, NULL);
    }
  }
  info("reading file %s", read_path);
  if ((flags & PIPE)) {
    if (*pbuf) r = do_fixed_pipe_read_file(pbuf, maxsz, prsz, read_path);
    else r = do_alloc_pipe_read_file(pbuf, maxsz, prsz, read_path);
  } else {
    r = do_read_file(pbuf, maxsz, prsz, read_path);
  }
  if (r < 0) return r;

  if ((flags & REMOVE)) {
    if (unlink(read_path) < 0) {
      err("unlink failed: %s", os_ErrorMsg());
      return -1;
    }
  }
  return 1;
}

static int
dumb_copy_file_to_dos(FILE *s, FILE *d)
{
  int do_conv = 1;
  int c;

  c = getc(s);
  while (c != EOF) {
    if (c == '\r') do_conv = 0;
    if (c == '\n' && do_conv) {
      putc('\r', d);
    }
    putc(c, d);
  }
  return 0;
}

static int
dumb_copy_file_from_dos(FILE *s, FILE *d)
{
  int c;

  while ((c = getc(s)) != EOF) {
    if (c != '\r') putc(c, d);
  }
  return 0;
}

static int
dumb_copy_file(int sfd, int sf, int dfd, int df)
{
  FILE *fs = 0, *fd = 0;

  if (!(fs = fdopen(sfd, "rb"))) {
    err("dumb_copy_file: fdopen(rb) failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  if (!(fd = fdopen(dfd, "wb"))) {
    err("dumb_copy_file: fdopen(wb) failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  if ((sf | CONVERT)) {
    if (dumb_copy_file_from_dos(fs, fd) < 0) goto cleanup;
  } else {
    if (dumb_copy_file_to_dos(fs, fd) < 0) goto cleanup;
  }
  if (fclose(fs) < 0) {
    fs = 0;
    err("dumb_copy_file: fclose(rb) failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  if (fclose(fd) < 0) {
    fd = 0;
    err("dumb_copy_file: fclose(wb) failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  return 0;

 cleanup:
  if (fs) fclose(fs);
  fs = 0;
  if (fd) fclose(fd);
  fd = 0;
  return -1;
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

  if ((sfd = sf_open(src, O_RDONLY, 0)) < 0) goto _cleanup;
  if ((dfd = sf_open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0) goto _cleanup;

  /* if conversion requested, use dumb copy method */
  if ((sf & CONVERT) || (df & CONVERT))
    return dumb_copy_file(sfd, sf, dfd, df);

  while ((sz = sf_read(sfd, buf, sizeof(buf), src)) > 0) {
    p = buf;
    while (sz > 0) {
      if ((wsz = sf_write(dfd, p, sz, dst)) <= 0) goto _cleanup;
      p += wsz;
      sz -= wsz;
    }
  }
  if (sz < 0) goto _cleanup;

  close(sfd); sfd = -1;
  if (sf_close(dfd, dst) < 0) return -1;
  return 0;

 _cleanup:
  if (sfd >= 0) close(sfd);
  if (dfd >= 0) close(dfd);
  return -1;
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

  int r;

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
    if (rename(move_src, copy_src) < 0) {
      if (errno == ENOENT) {
        write_log(0, LOG_WARN, "rename: no source file %s", move_src);
        return 0;
      }
      err("rename failed: %s", os_ErrorMsg());
      return -1;
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
  if ((r = do_copy_file(copy_src, sflags, copy_dst, dflags)) < 0) return r;

  if ((dflags & SAFE)) {
    write_log(0, LOG_INFO, "Move: %s -> %s", copy_dst, move_dst);
    if (rename(copy_dst, move_dst) < 0) {
      err("rename failed: %s", os_ErrorMsg());
      return -1;
    }
  }
  if ((sflags & REMOVE)) {
    if (unlink(copy_src) < 0) {
      err("generic_copy_file: unlink failed: %s", os_ErrorMsg());
      return -1;
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

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
