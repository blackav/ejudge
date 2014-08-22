/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_ARPA_INET_H__
#define __RCC_ARPA_INET_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <features.h>

#ifndef RCC_SIZE_T_DEFINED
#define RCC_SIZE_T_DEFINED 1
typedef unsigned long size_t;
#endif /* RCC_SIZE_T_DEFINED */

#include <netinet/in.h>

unsigned int inet_addr(const char *);
int inet_aton(const char *, struct in_addr *);
unsigned int inet_lnaof(struct in_addr);
struct in_addr inet_makeaddr(unsigned int, unsigned int);
char *inet_neta(unsigned int, char *, size_t);
unsigned int inet_netof(struct in_addr);
unsigned int inet_network(const char *);
char *inet_net_ntop(int, const void *, int, char *, size_t);
int inet_net_pton(int, const char *, void *, size_t);
char *inet_ntoa(struct in_addr);
int inet_pton(int, const char *, void *);
const char *inet_ntop(int, const void *, char *, unsigned int);
unsigned int inet_nsap_addr(const char *, unsigned char *, int);
char *inet_nsap_ntoa(int, const unsigned char *, char *);

#endif /* __RCC_ARPA_INET_H__ */
