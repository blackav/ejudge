/* -*- c -*- */

/* Copyright (C) 2016 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/version.h"
#include "ejudge/ej_libzip.h"
#include "ejudge/fileutl.h"

#include "ejudge/xalloc.h"

#if defined CONF_HAS_LIBZIP
#include <zip.h>
#endif

#include <fcntl.h>
#include <errno.h>

#if defined CONF_HAS_LIBZIP

static struct ZipData *
close_func(
        struct ZipData *zdata);
static int
read_file_func(
        struct ZipData *zdata,
        const unsigned char *name,
        unsigned char **p_data,
        ssize_t *p_size);
static int
add_file_func(
        struct ZipData *zdata,
        const unsigned char *name,
        const unsigned char *path);

struct RealZipData
{
    struct ZipData b;

    unsigned char *path;
    FILE *log_f;
    struct zip *z;
};

static const struct ZipInterface zip_functions =
{
    close_func,
    read_file_func,
    add_file_func,
};

static struct ZipData *
close_func(
        struct ZipData *zdata)
{
    struct RealZipData *rz = (struct RealZipData*) zdata;

    if (rz) {
        if (rz->z) {
            if (zip_close(rz->z) < 0) {
                /*
                if (rz->log_f) {
                    fprintf(rz->log_f, "'%s': zip file close failed: %s\n", rz->path, zip_strerror(rz->z));
                }
                */
            }
            rz->z = NULL;
        }
        rz->log_f = NULL;
        xfree(rz->path); rz->path = NULL;
        xfree(rz);
    }

    return NULL;
}

static int
read_file_func(
        struct ZipData *zdata,
        const unsigned char *name,
        unsigned char **p_data,
        ssize_t *p_size)
{
    struct RealZipData *rz = (struct RealZipData*) zdata;

    int file_ind = zip_name_locate(rz->z, name, 0);
    if (file_ind < 0) {
        if (rz->log_f) {
            fprintf(rz->log_f, "'%s': archive entry '%s' does not exist\n", rz->path, name);
        }
        return 0;
    }

    struct zip_stat zs;
    zip_stat_init(&zs);
    if (zip_stat_index(rz->z, file_ind, 0, &zs) < 0) {
        if (rz->log_f) {
            fprintf(rz->log_f, "'%s': archive entry '%s' stat failed\n", rz->path, name);
        }
        return -1;
    }

    if ((ssize_t) zs.size <= 0) {
        *p_size = 0;
        *p_data = xmalloc(1);
        **p_data = 0;
        return 1;
    }

    struct zip_file *zf = zip_fopen_index(rz->z, file_ind, 0);
    if (!zf) {
        if (rz->log_f) {
            fprintf(rz->log_f, "'%s': failed to open entry '%s': %s\n", rz->path, name, zip_strerror(rz->z));
        }
        return -1;
    }

    unsigned char *data = xmalloc(zs.size + 1);
    unsigned char *ptr = data;
    ssize_t remz = zs.size;

    while (remz > 0) {
        ssize_t rr = zip_fread(zf, ptr, remz);
        if (rr < 0) {
            if (rz->log_f) {
                fprintf(rz->log_f, "'%s': read error: %s\n", rz->path, zip_file_strerror(zf));
            }
            zip_fclose(zf);
            xfree(data);
            return -1;
        }
        if (!rr) {
            if (rz->log_f) {
                fprintf(rz->log_f, "'%s': read returned 0\n", rz->path);
            }
            zip_fclose(zf);
            xfree(data);
            return -1;
        }
        ptr += rr;
        remz -= rr;
    }

    zip_fclose(zf); zf = NULL;
    data[zs.size] = 0;
    *p_data = data;
    *p_size = zs.size;
    return 1;
}

static int
add_file_func(
        struct ZipData *zdata,
        const unsigned char *name,
        const unsigned char *path)
{
    struct RealZipData *rz = (struct RealZipData*) zdata;

    char *file_buf = NULL;
    size_t file_size = 0;
    if (generic_read_file(&file_buf, 0, &file_size, 0, 0, path, 0) < 0) {
        if (rz->log_f) {
            fprintf(rz->log_f, "'%s': read of '%s' failed", rz->path, path);
        }
        return -1;
    }

    struct zip_source *zsrc = zip_source_buffer(rz->z, file_buf, file_size, 1);
    if (!zsrc) {
        if (rz->log_f) {
            fprintf(rz->log_f, "'%s': append of '%s' failed: %s", rz->path, path, zip_strerror(rz->z));
        }
        xfree(file_buf);
        return -1;
    }
    file_buf = NULL; file_size = 0;

    if (zip_add(rz->z, name, zsrc) < 0) {
        if (rz->log_f) {
            fprintf(rz->log_f, "'%s': append of '%s' failed: %s", rz->path, path, zip_strerror(rz->z));
        }
        zip_source_free(zsrc);
        return -1;
    }

    return 0;
}

struct ZipData *
ej_libzip_open(FILE *log_f, const unsigned char *path, int flags)
{
    struct RealZipData *rz = NULL;
    XCALLOC(rz, 1);
    rz->b.ops = &zip_functions;
    rz->log_f = log_f;
    rz->path = xstrdup(path);

    int zf = 0;
#ifdef ZIP_RDONLY
    if ((flags & O_ACCMODE) == O_RDONLY) zf |= ZIP_RDONLY;
#endif
    if ((flags & O_CREAT)) zf |= ZIP_CREATE;
    if ((flags & O_EXCL)) zf |= ZIP_EXCL;
#ifdef ZIP_TRUNCATE
    if ((flags & O_TRUNC)) zf |= ZIP_TRUNCATE;
#endif

    int zip_err = 0;
    struct zip *zz = zip_open(path, zf, &zip_err);
    if (!zz) {
        char errbuf[1024];
        zip_error_to_str(errbuf, sizeof(errbuf), zip_err, errno);
        if (log_f) {
            fprintf(log_f, "'%s': cannot open zip file: %s\n", path, errbuf);
        }
        goto cleanup;
    }

    rz->z = zz;

    return (struct ZipData *) rz;

cleanup:
    rz->b.ops->close(&rz->b);
    return NULL;
}

#else

struct ZipData *
ej_libzip_open(FILE *log_f, const unsigned char *path, int flags)
{
    if (log_f) {
        fprintf(log_f, "libzip library is not supported");
    }
    return NULL;
}

#endif

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
