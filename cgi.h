/* -*- c -*- */
/* $Id$ */
#ifndef __CGI_H__
#define __CGI_H__

/* Copyright (C) 2000 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

int   cgi_read(void);
char *cgi_param(char const *);
char *cgi_nparam(char const *, int);
char *cgi_nname(char const *, int);
void  cgi_print_param(void);

#endif /* __CGI_H__ */
