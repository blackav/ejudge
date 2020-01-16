/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2010-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/zip_utils.h"

#include "ejudge/xalloc.h"

#include <zlib.h>
#include <string.h>

int
gzip_uncompress_to_memory(
        unsigned char **p_out_buf,
        int *p_out_size,
        const unsigned char *in_buf,
        int in_size)
{
  z_stream zf;
  gz_header gzh;
  int r, zf_initialized = 0, retval = -1;
  unsigned char *wb = 0;
  int wz = 0, zz = 0;

  wz = 4096;
  wb = (unsigned char *) xmalloc(wz);

  memset(&zf, 0, sizeof(zf));
  memset(&gzh, 0, sizeof(gzh));
  zf.zalloc = Z_NULL;
  zf.zfree = Z_NULL;
  zf.next_in = (unsigned char*) in_buf;
  zf.avail_in = in_size;
  zf.next_out = wb;
  zf.avail_out = wz;

  if (inflateInit2(&zf, 16 + MAX_WBITS) != Z_OK) {
    goto cleanup;
  }
  zf_initialized = 1;

  /*
  if (inflateGetHeader(&zf, &gzh) != Z_OK) {
    logerr("inflateGetHeader error");
    goto cleanup;
  }
  */

  while (1) {
    r = inflate(&zf, Z_NO_FLUSH);
    if (r == Z_STREAM_END) break;
    if (r != Z_OK) {
      goto cleanup;
    }
    zz = wz - zf.avail_out;
    if (zz < 0 || zz > wz) {
      goto cleanup;
    }

    wz *= 2;
    wb = (unsigned char*) xrealloc(wb, wz);
    zf.next_out = wb + zz;
    zf.avail_out = wz - zz;
  }

  // append \0 to the end of file
  if (zf.avail_out < 1) {
    zz = wz - zf.avail_out;
    if (zz < 0 || zz > wz) {
      goto cleanup;
    }

    wz *= 2;
    wb = (unsigned char*) xrealloc(wb, wz);
    zf.next_out = wb + zz;
    zf.avail_out = wz - zz;
  }
  *zf.next_out = 0;

  *p_out_buf = wb;
  *p_out_size = wz - zf.avail_out;

  wb = 0;
  retval = 0;

 cleanup:;
  if (zf_initialized) {
    inflateEnd(&zf);
  }
  xfree(wb);
  return retval;
}
