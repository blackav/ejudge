/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

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

#include "full_archive.h"

#include "pathutl.h"
#include "errlog.h"
#include "fileutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

static const unsigned char file_sig[8] = "Ej. Ar.";

full_archive_t
full_archive_open_write(const unsigned char *path)
{
}

full_archive_t
full_archive_close(full_archive_t af)
{
}

int
full_archive_append_file(full_archive_t af,
                         const unsigned char *entry_name,
                         unsigned int flags,
                         const unsigned char *path)
{
}

full_archive_t
full_archive_open_read(const unsigned char *path)
{
}

int
full_archive_find_file(full_archive_t af,
                       const unsigned char *name,
                       long *p_size,
                       long *p_raw_size,
                       unsigned int *p_flags,
                       const unsigned char **p_data)
{
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
