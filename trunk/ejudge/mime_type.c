/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "mime_type.h"
#include "pathutl.h"
#include "errlog.h"

#include <reuse/osdeps.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

struct mime_type_info
{
  const unsigned char * const mime_type;
  const unsigned char * const suffix;
  const unsigned char * const file_output;
};

static const struct mime_type_info mime_types[MIME_TYPE_LAST] =
{
  [MIME_TYPE_TEXT] = 
  { "text/plain", ".txt", "" },
  [MIME_TYPE_BINARY] =
  { "application/octet-stream", "", "" },
  [MIME_TYPE_APPL_MSWORD] =
  { "application/msword", ".doc", "Microsoft" },
  [MIME_TYPE_APPL_RTF] =
  { "application/rtf", ".rtf", "Rich Text Format data" },
  [MIME_TYPE_APPL_PDF] =
  { "application/pdf", ".pdf", "PDF document" },
  [MIME_TYPE_APPL_MSEXCEL] = 
  { "application/vnd.ms-excel", ".xls", "" },
  [MIME_TYPE_APPL_MSPOWERPOINT] = 
  { "application/vnd.ms-powerpoint", ".ppt", "" },
  [MIME_TYPE_APPL_MSPROJECT] = 
  { "application/vnd.ms-project", "", "" },
  [MIME_TYPE_APPL_MSEQ] =
  { "application/vnd.mseq", "", "" },
  [MIME_TYPE_APPL_VISIO] = 
  { "application/vnd.visio", "", "" },
  [MIME_TYPE_APPL_COMPRESS] =
  { "application/x-compress", ".Z", "" },
  [MIME_TYPE_APPL_CPIO] =
  { "application/x-cpio", ".cpio", "" },
  [MIME_TYPE_APPL_DVI] =
  { "application/x-dvi", ".dvi", "" },
  [MIME_TYPE_APPL_GZIP] =
  { "application/x-gzip", ".gz", "gzip compressed data" },
  [MIME_TYPE_APPL_FLASH] =
  { "application/x-shockwave-flash", ".swf", "" },
  [MIME_TYPE_APPL_TAR] =
  { "application/x-tar", ".tar", "POSIX tar archive" },
  [MIME_TYPE_APPL_ZIP] =
  { "application/zip", ".zip", "Zip archive data" },
  [MIME_TYPE_APPL_BZIP2] =
  { "application/x-bzip2", ".bz2", "bzip2 compressed data" },
  [MIME_TYPE_IMAGE_BMP] =
  { "image/bmp", ".bmp", "PC bitmap data" },
  [MIME_TYPE_IMAGE_GIF] =
  { "image/gif", ".gif", "GIF image data" },
  [MIME_TYPE_IMAGE_JPEG] =
  { "image/jpeg", ".jpg", "JPEG image data" },
  [MIME_TYPE_IMAGE_PNG] =
  { "image/png", ".png", "PNG image data" },
  [MIME_TYPE_IMAGE_TIFF] =
  { "image/tiff", ".tif", "TIFF image data" },
  [MIME_TYPE_IMAGE_DJVU] =
  { "image/vnd.djvu", ".djvu", "" },
  [MIME_TYPE_IMAGE_ICON] =
  { "image/x-icon", ".ico", "" },
};

const unsigned char *
mime_type_get_type(int mt)
{
  if (mt < 0 || mt >= MIME_TYPE_LAST) return "application/octet-stream";
  return mime_types[mt].mime_type;
}

const unsigned char *
mime_type_get_suffix(int mt)
{
  if (mt < 0 || mt >= MIME_TYPE_LAST) return "";
  return mime_types[mt].suffix;
}

int
mime_type_parse(const unsigned char *str)
{
  int i;

  if (!str) return -1;

  for (i = 0; i < MIME_TYPE_LAST; i++)
    if (!strcasecmp(mime_types[i].mime_type, str))
      return i;
  return -1;
}

int
mime_type_guess(const unsigned char *tmpdir,
                const unsigned char *bytes,
                size_t size)
{
  path_t tmppath;
  int fd = -1, i;
  size_t w;
  ssize_t r;
  const unsigned char *p;
  FILE *ff = 0;
  unsigned char fbuf[1024];
  path_t cmdline;
  size_t flen;

  if (!tmpdir) tmpdir = getenv("TMPDIR");
#if defined P_tmpdir
  if (!tmpdir) tmpdir = P_tmpdir;
#endif
  if (!tmpdir) tmpdir = "/tmp";
  snprintf(tmppath, sizeof(tmppath), "%s/ejf_XXXXXX", tmpdir);
  if ((fd = mkstemp(tmppath)) < 0) {
    err("mime_type_guess: mkstemp() failed: %s", os_ErrorMsg());
    return -1;
  }
  p = bytes; w = size;
  while (w > 0) {
    if ((r = write(fd, p, w)) <= 0) {
      err("mime_type_guess: write() error: %s", os_ErrorMsg());
      goto failed;
    }
    w -= r; p += r;
  }
  if (close(fd) < 0) {
    err("mime_type_guess: close() failed: %s", os_ErrorMsg());
    goto failed;
  }
  fd = -1;

  snprintf(cmdline, sizeof(cmdline), "/usr/bin/file -b \"%s\"", tmppath);
  if (!(ff = popen(cmdline, "r"))) {
    err("mime_type_guess: popen() failed: %s", os_ErrorMsg());
    goto failed;
  }
  if (!fgets_unlocked(fbuf, sizeof(fbuf), ff)) {
    err("mime_type_guess: unexpected EOF from pipe");
    goto failed;
  }
  if (getc_unlocked(ff) != EOF) {
    err("mime_type_guess: garbage in pipe");
    while (getc_unlocked(ff) != EOF);
    goto failed;
  }
  pclose(ff); ff = 0;
  if ((flen = strlen(fbuf)) > sizeof(fbuf) - 10) {
    err("mime_type_guess: string is too long");
    goto failed;
  }
  unlink(tmppath);
  while (flen > 0 && isspace(fbuf[flen - 1])) fbuf[--flen] = 0;
  if (flen > 0) {
    for (i = 0; i < MIME_TYPE_LAST; i++)
      if (mime_types[i].file_output[0]
	  && strstr(fbuf, mime_types[i].file_output))
        return i;
  }
  for (i = 0; i < size; i++)
    if (!bytes[i])
      return MIME_TYPE_BINARY;
  return MIME_TYPE_TEXT;

 failed:
  if (fd >= 0) close(fd);
  if (ff) pclose(ff);
  unlink(tmppath);
  return -1;
}

int
mime_type_parse_suffix(const unsigned char *str)
{
  int i;

  if (!str) return -1;

  for (i = 0; i < MIME_TYPE_LAST; i++)
    if (!strcasecmp(mime_types[i].suffix, str))
      return i;
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
