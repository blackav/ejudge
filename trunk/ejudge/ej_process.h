/* -*- c -*- */
/* $Id$ */

#ifndef __EJ_PROCESS_H__
#define __EJ_PROCESS_H__

/* Copyright (C) 2005-2010 Alexander Chernov <cher@ejudge.ru> */

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

unsigned char *read_process_output(const unsigned char *cmd,
                                   const unsigned char *workdir,
                                   int max_ok_code,
                                   int redirect_stderr);

int
ejudge_invoke_process(
        char **args,
        char **envs,
        const unsigned char *workdir,
        const unsigned char *stdin_text,
        int merge_out_flag,
        unsigned char **stdout_text,
        unsigned char **stderr_text);

#endif /* __EJ_PROCESS_H__ */
