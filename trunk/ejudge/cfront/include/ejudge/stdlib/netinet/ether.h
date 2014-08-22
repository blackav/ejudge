/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `netinet/ether.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Functions for storing Ethernet addresses in ASCII and mapping to hostnames.
   Copyright (C) 1996, 1997, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __RCC_NETINET_ETHER_H__
#define __RCC_NETINET_ETHER_H__ 1

/* Get definition of `struct ether_addr'.  */
#include <features.h>
#include <netinet/if_ether.h>

/* Convert 48 bit Ethernet ADDRess to ASCII.  */
char *ether_ntoa(const struct ether_addr *addr);
char *ether_ntoa_r(const struct ether_addr *addr, char *buf);

/* Convert ASCII string S to 48 bit Ethernet address.  */
struct ether_addr *ether_aton(const char *asc);
struct ether_addr *ether_aton_r(const char *asc, struct ether_addr *addr);

/* Map 48 bit Ethernet number ADDR to HOSTNAME.  */
int ether_ntohost(char *hostname, const struct ether_addr *addr);

/* Map HOSTNAME to 48 bit Ethernet address.  */
int ether_hostton(const char *hostname, struct ether_addr *addr);

/* Scan LINE and set ADDR and HOSTNAME.  */
int ether_line(const char *line, struct ether_addr *addr, char *hostname);

#endif /* __RCC_NETINET_ETHER_H__ */
