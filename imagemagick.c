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

    int len1 = 0, len2 = 0, width = 0, height = 0;
    if (sscanf(stdout_text, "%*s%n%d%d%n", &len1, &width, &height, &len2) != 2 || width < 0 || height < 0 || stdout_text[len2]) {
        if (log_f) {
            fprintf(log_f, "ImageMagick returned unexpected result: %s", stdout_text);
        }
        goto cleanup;
    }
    stdout_text[len1] = 0;

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

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
