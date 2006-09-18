/* -*- c -*- */
/* $Id$ */
#ifndef __MIME_TYPE_H__
#define __MIME_TYPE_H__

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

#include <stdio.h>

/* supported mime types for binary content */
enum
{
  MIME_TYPE_TEXT = 0,
  MIME_TYPE_BINARY,             // application/octet-stream
  MIME_TYPE_APPL_MSWORD,        // application/msword
  MIME_TYPE_APPL_PDF,           // application/pdf
  MIME_TYPE_APPL_MSEXCEL,       // application/vnd.ms-excel
  MIME_TYPE_APPL_MSPOWERPOINT,  // application/vnd.ms-powerpoint
  MIME_TYPE_APPL_MSPROJECT,     // application/vnd.ms-project
  MIME_TYPE_APPL_MSEQ,          // application/vnd.mseq
  MIME_TYPE_APPL_VISIO,         // application/vnd.visio
  MIME_TYPE_APPL_COMPRESS,      // application/x-compress
  MIME_TYPE_APPL_CPIO,          // application/x-cpio
  MIME_TYPE_APPL_DVI,           // application/x-dvi
  MIME_TYPE_APPL_GZIP,          // application/x-gzip
  MIME_TYPE_APPL_FLASH,         // application/x-shockwave-flash
  MIME_TYPE_APPL_TAR,           // application/x-tar
  MIME_TYPE_APPL_ZIP,           // application/zip
  MIME_TYPE_IMAGE_BMP,          // image/bmp
  MIME_TYPE_IMAGE_GIF,          // image/gif
  MIME_TYPE_IMAGE_JPEG,         // image/jpeg
  MIME_TYPE_IMAGE_PNG,          // image/png
  MIME_TYPE_IMAGE_TIFF,         // image/tiff
  MIME_TYPE_IMAGE_DJVU,         // image/vnd.djvu
  MIME_TYPE_IMAGE_ICON,         // image/x-icon

  MIME_TYPE_LAST,
};

const unsigned char *mime_type_get_type(int mt);
const unsigned char *mime_type_get_suffix(int mt);
int mime_type_parse(const unsigned char *str);

int mime_type_guess(const unsigned char *tmpdir,
                    const unsigned char *bytes,
                    size_t size);

#endif /* __MIME_TYPE_H__ */
