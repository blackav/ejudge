/* -*- mode: c -*- */

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/imagemagick.h"
#include "ejudge/fileutl.h"
#include "ejudge/ej_process.h"
#include "ejudge/mime_type.h"

#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

static const unsigned char * const identify_program = "/usr/bin/identify";
static const unsigned char * const convert_program = "/usr/bin/convert";

int
image_identify(
        FILE *log_f,
        const unsigned char *tmp_dir,
        const unsigned char *data,
        size_t size,
        int *p_width,
        int *p_height)
{
    int retval = -1;
    unsigned char tmp_path[PATH_MAX];
    unsigned char *stdout_text = NULL;
    unsigned char *stderr_text = NULL;

    tmp_path[0] = 0;
    if (write_tmp_file_2(log_f, tmp_dir, "ejimg_", NULL, tmp_path, sizeof(tmp_path),
                         data, size) < 0) {
        goto cleanup;
    }

    if (access(identify_program, X_OK) < 0) {
        if (log_f) {
            fprintf(log_f, "ImageMagick is not installed (%s is not executable)", identify_program);
        }
        goto cleanup;
    }

    char *args[] = { (char*) identify_program, "-format", "%m %w %h", tmp_path, NULL };

    int r = ejudge_invoke_process(args, NULL, NULL, NULL, "", 0, &stdout_text, &stderr_text);
    if (r < 0) {
        if (log_f) {
            fprintf(log_f, "failed to start ImageMagick %s", identify_program);
        }
        goto cleanup;
    }
    if (r > 0) {
        if (log_f) {
            fprintf(log_f, "ImageMagick failed to recognize image");
        }
        retval = MIME_TYPE_BINARY;
        goto cleanup;
    }
    if (!stdout_text) stdout_text = xstrdup("");

    unsigned char *p1 = strchr(stdout_text, ' ');
    if (!p1) {
        if (log_f) {
            fprintf(log_f, "ImageMagick returned unexpected result: %s", stdout_text);
        }
        goto cleanup;
    }
    *p1 = 0;
    int len2 = 0, width = 0, height = 0;
    if (sscanf(p1 + 1, "%d%d%n", &width, &height, &len2) != 2 || width < 0 || height < 0) {
        if (log_f) {
            fprintf(log_f, "ImageMagick returned unexpected result: %s", stdout_text);
        }
        goto cleanup;
    }

    if (!strcmp(stdout_text, "PNG")) {
        retval = MIME_TYPE_IMAGE_PNG;
    } else if (!strcmp(stdout_text, "GIF")) {
        retval = MIME_TYPE_IMAGE_GIF;
    } else if (!strcmp(stdout_text, "JPEG")) {
        retval = MIME_TYPE_IMAGE_JPEG;
    } else {
        if (log_f) {
            fprintf(log_f, "image format %s is not supported", stdout_text);
        }
        retval = MIME_TYPE_BINARY;
        goto cleanup;
    }
    if (p_width) *p_width = width;
    if (p_height) *p_height = height;

cleanup:;
    if (tmp_path[0]) {
        unlink(tmp_path);
    }
    xfree(stdout_text);
    xfree(stderr_text);
    return retval;
}

int
image_convert(
        FILE *log_f,
        const unsigned char *tmp_dir,
        int in_mime_type,
        int in_left,
        int in_top,
        int in_width,
        int in_height,
        const unsigned char *in_data,
        size_t in_size,
        int out_mime_type,
        int out_width,
        int out_height,
        unsigned char **p_out_data,
        size_t *p_out_size)
{
    int retval = -1;
    unsigned char in_tmp_path[PATH_MAX];
    unsigned char out_tmp_path[PATH_MAX];
    unsigned char format1[128];
    unsigned char format2[128];
    unsigned char *stdout_text = NULL;
    unsigned char *stderr_text = NULL;
    char *out_data = NULL;
    size_t out_size = 0;
    FILE *out_file = NULL;
    FILE *in_file = NULL;

    in_tmp_path[0] = 0;
    out_tmp_path[0] = 0;

    if (access(convert_program, X_OK) < 0) {
        if (log_f) {
            fprintf(log_f, "ImageMagick is not installed (%s is not executable)", convert_program);
        }
        goto cleanup;
    }

    if (write_tmp_file_2(log_f, tmp_dir, "ejimg_", mime_type_get_suffix(in_mime_type),
                         in_tmp_path, sizeof(in_tmp_path), in_data, in_size) < 0) {
        goto cleanup;
    }
    if (write_tmp_file_2(log_f, tmp_dir, "ejimg_", mime_type_get_suffix(out_mime_type),
                         out_tmp_path, sizeof(out_tmp_path), "", 0) < 0) {
        goto cleanup;
    }

    snprintf(format1, sizeof(format1), "%dx%d+%d+%d", in_width, in_height, in_left, in_top);
    snprintf(format2, sizeof(format2), "%dx%d", out_width, out_height);

    char *args[] =
    {
        (char*) convert_program,
        "-extract",
        format1,
        "-resize",
        format2,
        in_tmp_path,
        out_tmp_path,
        NULL
    };

    int r = ejudge_invoke_process(args, NULL, NULL, NULL, "", 0, &stdout_text, &stderr_text);
    if (r < 0) {
        if (log_f) {
            fprintf(log_f, "failed to start ImageMagick %s", convert_program);
        }
        goto cleanup;
    }
    if (r > 0) {
        if (log_f) {
            fprintf(log_f, "ImageMagick failed to convert image");
        }
        goto cleanup;
    }

    if (!(in_file = fopen(out_tmp_path, "r"))) {
        if (log_f) {
            fprintf(log_f, "failed to open output file");
        }
        goto cleanup;
    }
    out_file = open_memstream(&out_data, &out_size);
    int c;
    while ((c = getc_unlocked(in_file)) != EOF) {
        putc_unlocked(c, out_file);
    }
    if (ferror(in_file)) {
        if (log_f) {
            fprintf(log_f, "read error");
        }
        goto cleanup;
    }
    fclose(in_file); in_file = NULL;
    fclose(out_file); out_file = NULL;

    if (p_out_data) {
        *p_out_data = out_data;
        out_data = NULL;
    }
    if (p_out_size) {
        *p_out_size = out_size;
    }
    retval = 0;

cleanup:;
    if (in_tmp_path[0]) {
        unlink(in_tmp_path);
    }
    if (out_tmp_path[0]) {
        unlink(out_tmp_path);
    }
    xfree(stdout_text);
    xfree(stderr_text);
    if (out_file) fclose(out_file);
    xfree(out_data);
    if (in_file) fclose(in_file);
    return retval;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
