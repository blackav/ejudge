/* -*- c -*- */
/* $Id$ */
#ifndef __SETTINGS_H__
#define __SETTINGS_H__

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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

/* compile-time settings, which cannot be changed at runtime or via
 * configuration files
 */

/* maximal length of a CGI parameter value */
#define MAX_CGI_VALUE_LEN 1048576

/* maximal length of a `serve' command packet */
#define MAX_SERVE_PACKET_LEN 1048576

/* maximal length of a `userlist-server' command packet */
#define MAX_USERLIST_PACKET_LEN 1048576

#endif /* __SETTINGS_H__ */

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
