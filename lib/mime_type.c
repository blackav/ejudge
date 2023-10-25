/* -*- mode: c -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/mime_type.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/fileutl.h"

#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#if HAVE_FGETS_UNLOCKED - 0 == 0
#define fgets_unlocked(a,b,c) fgets(a,b,c)
#define getc_unlocked(a) getc(a)
#endif

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
  [MIME_TYPE_APPL_7ZIP] =
  { "application/x-7zip", ".7z", "7-zip archive data" },
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
  [MIME_TYPE_BSON] =
  { "application/bson", ".bson", "" },
  [MIME_TYPE_TEXT_HTML] =
  { "text/html", ".html", "" },
  [MIME_TYPE_OFFICE_PPTX] =
  {
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".pptx",
    "Microsoft PowerPoint 2007+",
  },
  [MIME_TYPE_OFFICE_XLSX] =
  {
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xlsx",
    "Microsoft Excel 2007+",
  },
  [MIME_TYPE_OFFICE_DOCX] =
  {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".docx",
    "Microsoft Word 2007+",
  },
};

static const int mime_check_order[] =
{
  MIME_TYPE_OFFICE_PPTX,
  MIME_TYPE_OFFICE_XLSX,
  MIME_TYPE_OFFICE_DOCX,
  MIME_TYPE_APPL_MSWORD,
  MIME_TYPE_APPL_RTF,
  MIME_TYPE_APPL_PDF,
  MIME_TYPE_APPL_MSEXCEL,
  MIME_TYPE_APPL_MSPOWERPOINT,
  MIME_TYPE_APPL_MSPROJECT,
  MIME_TYPE_APPL_MSEQ,
  MIME_TYPE_APPL_VISIO,
  MIME_TYPE_APPL_COMPRESS,
  MIME_TYPE_APPL_CPIO,
  MIME_TYPE_APPL_DVI,
  MIME_TYPE_APPL_GZIP,
  MIME_TYPE_APPL_FLASH,
  MIME_TYPE_APPL_TAR,
  MIME_TYPE_APPL_ZIP,
  MIME_TYPE_APPL_BZIP2,
  MIME_TYPE_APPL_7ZIP,
  MIME_TYPE_IMAGE_BMP,
  MIME_TYPE_IMAGE_GIF,
  MIME_TYPE_IMAGE_JPEG,
  MIME_TYPE_IMAGE_PNG,
  MIME_TYPE_IMAGE_TIFF,
  MIME_TYPE_IMAGE_DJVU,
  MIME_TYPE_IMAGE_ICON,
  MIME_TYPE_BSON,
  MIME_TYPE_TEXT_HTML,
  MIME_TYPE_TEXT,
  MIME_TYPE_BINARY,
  -1,
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
mime_type_guess_file(const unsigned char *path, int check_text)
{
  unsigned char cmdline[1024];
  FILE *ff = 0;
  unsigned char fbuf[1024];
  size_t flen;
  int c;
  int binary_flag = 1;

  snprintf(cmdline, sizeof(cmdline), "/usr/bin/file -b \"%s\"", path);
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
  while (flen > 0 && isspace(fbuf[flen - 1])) fbuf[--flen] = 0;
  if (flen > 0) {
    for (int j = 0; mime_check_order[j] >= 0; ++j) {
      int i = mime_check_order[j];
      if (mime_types[i].file_output[0]
          && strstr(fbuf, mime_types[i].file_output))
        return i;
    }
  }

  if (check_text > 0) {
    if (!(ff = fopen(path, "r"))) {
      return MIME_TYPE_BINARY;
    }
    while ((c = getc_unlocked(ff)) != EOF) {
      if (c == 0 || c == 26 || c == 27) {
        binary_flag = 1;
        break;
      }
    }
    fclose(ff); ff = 0;
    if (!binary_flag) return MIME_TYPE_TEXT;
  }
  return MIME_TYPE_BINARY;

failed:
  if (ff) pclose(ff);
  return -1;
}

int
mime_type_guess(const unsigned char *tmpdir,
                const unsigned char *bytes,
                size_t size)
{
  path_t tmppath;
  int i;
  FILE *ff = 0;
  unsigned char fbuf[1024];
  path_t cmdline;
  size_t flen;

  tmppath[0] = 0;
  if (write_tmp_file(tmppath, sizeof(tmppath), bytes, size) < 0)
    goto failed;

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
    for (int j = 0; mime_check_order[j] >= 0; ++j) {
      int i = mime_check_order[j];
      if (mime_types[i].file_output[0]
          && strstr(fbuf, mime_types[i].file_output))
        return i;
    }
  }
  for (i = 0; i < size; i++)
    if (!bytes[i])
      return MIME_TYPE_BINARY;
  return MIME_TYPE_TEXT;

 failed:
  if (ff) pclose(ff);
  if (tmppath[0]) unlink(tmppath);
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
