/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `net/if.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* net/if.h -- declarations for inquiring about network interfaces
   Copyright (C) 1997,98,99,2000,2001 Free Software Foundation, Inc.
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

#ifndef __RCC_NET_IF_H__
#define __RCC_NET_IF_H__ 1

#include <features.h>
#include <sys/types.h>
#include <sys/socket.h>

/* Length of interface name.  */
int enum { IF_NAMESIZE = 16 };
#define IF_NAMESIZE IF_NAMESIZE

struct if_nameindex
{
  unsigned int if_index;
  char *if_name;
};

/* Standard interface flags. */
int enum
{
#defconst IFF_UP 0x1
#defconst IFF_BROADCAST 0x2
#defconst IFF_DEBUG 0x4
#defconst IFF_LOOPBACK 0x8
#defconst IFF_POINTOPOINT 0x10
#defconst IFF_NOTRAILERS 0x20
#defconst IFF_RUNNING 0x40
#defconst IFF_NOARP 0x80
#defconst IFF_PROMISC 0x100
#defconst IFF_ALLMULTI 0x200
#defconst IFF_MASTER 0x400
#defconst IFF_SLAVE 0x800
#defconst IFF_MULTICAST 0x1000
#defconst IFF_PORTSEL 0x2000
#defconst IFF_AUTOMEDIA 0x4000
};

/* The ifaddr structure contains information about one address of an
   interface.  They are maintained by the different address families,
   are allocated and attached when an address is set, and are linked
   together so all addresses for an interface can be located.  */
struct ifaddr
{
  struct sockaddr ifa_addr;   /* Address of interface.  */
  union
  {
    struct sockaddr ifu_broadaddr;
    struct sockaddr ifu_dstaddr;
  } ifa_ifu;
  struct iface *ifa_ifp;      /* Back-pointer to interface.  */
  struct ifaddr *ifa_next;    /* Next address for interface.  */
};

# define ifa_broadaddr  ifa_ifu.ifu_broadaddr   /* broadcast address    */
# define ifa_dstaddr    ifa_ifu.ifu_dstaddr     /* other end of link    */

/* Device mapping structure. I'd just gone off and designed a
   beautiful scheme using only loadable modules with arguments for
   driver options and along come the PCMCIA people 8)

   Ah well. The get() side of this is good for WDSETUP, and it'll be
   handy for debugging things. The set side is fine for now and being
   very small might be worth keeping for clean configuration.  */

struct ifmap
{
  unsigned long int mem_start;
  unsigned long int mem_end;
  unsigned short int base_addr;
  unsigned char irq;
  unsigned char dma;
  unsigned char port;
  /* 3 bytes spare */
};

/* Interface request structure used for socket ioctl's.  All interface
   ioctl's must have parameter definitions which begin with ifr_name.
   The remainder may be interface specific.  */

#ifndef IFHWADDRLEN
int enum {
#defconst IFHWADDRLEN 6
};
#endif /* IFHWADDRLEN */

#ifndef IFNAMSIZ
int enum {
#defconst IFNAMSIZ 16
};
#endif /* IFNAMSIZ */

struct ifreq
{
  union
  {
    char ifrn_name[IFNAMSIZ];
  } ifr_ifrn;

  union
  {
    struct sockaddr ifru_addr;
    struct sockaddr ifru_dstaddr;
    struct sockaddr ifru_broadaddr;
    struct sockaddr ifru_netmask;
    struct sockaddr ifru_hwaddr;
    short int ifru_flags;
    int ifru_ivalue;
    int ifru_mtu;
    struct ifmap ifru_map;
    char ifru_slave[IFNAMSIZ];
    char ifru_newname[IFNAMSIZ];
    __caddr_t ifru_data;
  } ifr_ifru;
};

#define ifr_name       ifr_ifrn.ifrn_name
#define ifr_hwaddr     ifr_ifru.ifru_hwaddr
#define ifr_addr       ifr_ifru.ifru_addr
#define ifr_dstaddr    ifr_ifru.ifru_dstaddr
#define ifr_broadaddr  ifr_ifru.ifru_broadaddr
#define ifr_netmask    ifr_ifru.ifru_netmask
#define ifr_flags      ifr_ifru.ifru_flags
#define ifr_metric     ifr_ifru.ifru_ivalue
#define ifr_mtu        ifr_ifru.ifru_mtu
#define ifr_map        ifr_ifru.ifru_map
#define ifr_slave      ifr_ifru.ifru_slave
#define ifr_data       ifr_ifru.ifru_data
#define ifr_ifindex    ifr_ifru.ifru_ivalue
#define ifr_bandwidth  ifr_ifru.ifru_ivalue
#define ifr_qlen       ifr_ifru.ifru_ivalue
#define ifr_newname    ifr_ifru.ifru_newname

#define _IOT_ifreq     _IOT(_IOTS(char),IFNAMSIZ,_IOTS(char),16,0,0)
#define _IOT_ifreq_short _IOT(_IOTS(char),IFNAMSIZ,_IOTS(short),1,0,0)
#define _IOT_ifreq_int _IOT(_IOTS(char),IFNAMSIZ,_IOTS(int),1,0,0)


/* Structure used in SIOCGIFCONF request.  Used to retrieve interface
   configuration for machine (useful for programs which must know all
   networks accessible).  */
struct ifconf
{
  int ifc_len;
  union
  {
    __caddr_t ifcu_buf;
    struct ifreq *ifcu_req;
  } ifc_ifcu;
};

#define ifc_buf        ifc_ifcu.ifcu_buf
#define ifc_req        ifc_ifcu.ifcu_req

#define _IOT_ifconf _IOT(_IOTS(struct ifconf),1,0,0,0,0)

/* Convert an interface name to an index, and vice versa.  */
unsigned int if_nametoindex(const char *ifname);
char *if_indextoname(unsigned int ifindex, char *ifname);

/* Return a list of all interfaces and their indices.  */
struct if_nameindex *if_nameindex(void);

/* Free the data returned from if_nameindex.  */
void if_freenameindex(struct if_nameindex *ptr);

#endif /* __RCC_NET_IF_H__ */
