/* -*- mode: c; c-basic-offset: 4 -*- */

#ifndef __LOGROTATE_H__
#define __LOGROTATE_H__

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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

void
rotate_log_files(
        const unsigned char *log_dir,
        const unsigned char *log_file,
        const unsigned char *back_suffix,
        const unsigned char *log_user,
        const unsigned char *log_group,
        int log_perms);

#endif /* __LOGROTATE_H__ */
