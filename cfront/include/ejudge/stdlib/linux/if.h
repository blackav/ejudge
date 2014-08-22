/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/if.h' of the Linux Kernel.
   The original copyright follows. */
/*
 * INET         An implementation of the TCP/IP protocol suite for the LINUX
 *              operating system.  INET is implemented using the  BSD Socket
 *              interface as the means of communication with the user level.
 *
 *              Global definitions for the INET interface module.
 *
 * Version:     @(#)if.h        1.0.2   04/18/93
 *
 * Authors:     Original taken from Berkeley UNIX 4.3, (c) UCB 1982-1988
 *              Ross Biro, <bir7@leland.Stanford.Edu>
 *              Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#ifndef __RCC_LINUX_IF_H__
#define __RCC_LINUX_IF_H__

#include <linux/types.h>
#include <linux/socket.h>

/* Standard interface flags. */
int enum
{
#defconst IFF_UP          0x1
#defconst IFF_BROADCAST   0x2
#defconst IFF_DEBUG       0x4
#defconst IFF_LOOPBACK    0x8
#defconst IFF_POINTOPOINT 0x10
#defconst IFF_NOTRAILERS  0x20
#defconst IFF_RUNNING     0x40
#defconst IFF_NOARP       0x80
#defconst IFF_PROMISC     0x100
#defconst IFF_ALLMULTI    0x200
#defconst IFF_MASTER      0x400
#defconst IFF_SLAVE       0x800
#defconst IFF_MULTICAST   0x1000
#defconst IFF_VOLATILE    (IFF_LOOPBACK|IFF_POINTOPOINT|IFF_BROADCAST|IFF_MASTER|IFF_SLAVE|IFF_RUNNING)
#defconst IFF_PORTSEL     0x2000
#defconst IFF_AUTOMEDIA   0x4000
#defconst IFF_DYNAMIC     0x8000
};

/*
 *      Device mapping structure. I'd just gone off and designed a 
 *      beautiful scheme using only loadable modules with arguments
 *      for driver options and along come the PCMCIA people 8)
 *
 *      Ah well. The get() side of this is good for WDSETUP, and it'll
 *      be handy for debugging things. The set side is fine for now and
 *      being very small might be worth keeping for clean configuration.
 */

struct ifmap 
{
  unsigned long mem_start;
  unsigned long mem_end;
  unsigned short base_addr; 
  unsigned char irq;
  unsigned char dma;
  unsigned char port;
  /* 3 bytes spare */
};

/*
 * Interface request structure used for socket
 * ioctl's.  All interface ioctl's must have parameter
 * definitions which begin with ifr_name.  The
 * remainder may be interface specific.
 */

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
    char    ifrn_name[IFNAMSIZ];
  } ifr_ifrn;
        
  union
  {
    struct  sockaddr ifru_addr;
    struct  sockaddr ifru_dstaddr;
    struct  sockaddr ifru_broadaddr;
    struct  sockaddr ifru_netmask;
    struct  sockaddr ifru_hwaddr;
    short   ifru_flags;
    int     ifru_ivalue;
    int     ifru_mtu;
    struct  ifmap ifru_map;
    char    ifru_slave[IFNAMSIZ];
    char    ifru_newname[IFNAMSIZ];
    char *  ifru_data;
  } ifr_ifru;
};

#define ifr_name        ifr_ifrn.ifrn_name      /* interface name       */
#define ifr_hwaddr      ifr_ifru.ifru_hwaddr    /* MAC address          */
#define ifr_addr        ifr_ifru.ifru_addr      /* address              */
#define ifr_dstaddr     ifr_ifru.ifru_dstaddr   /* other end of p-p lnk */
#define ifr_broadaddr   ifr_ifru.ifru_broadaddr /* broadcast address    */
#define ifr_netmask     ifr_ifru.ifru_netmask   /* interface net mask   */
#define ifr_flags       ifr_ifru.ifru_flags     /* flags                */
#define ifr_metric      ifr_ifru.ifru_ivalue    /* metric               */
#define ifr_mtu         ifr_ifru.ifru_mtu       /* mtu                  */
#define ifr_map         ifr_ifru.ifru_map       /* device map           */
#define ifr_slave       ifr_ifru.ifru_slave     /* slave device         */
#define ifr_data        ifr_ifru.ifru_data      /* for use by interface */
#define ifr_ifindex     ifr_ifru.ifru_ivalue    /* interface index      */
#define ifr_bandwidth   ifr_ifru.ifru_ivalue    /* link bandwidth       */
#define ifr_qlen        ifr_ifru.ifru_ivalue    /* Queue length         */
#define ifr_newname     ifr_ifru.ifru_newname   /* New name             */

/*
 * Structure used in SIOCGIFCONF request.
 * Used to retrieve interface configuration
 * for machine (useful for programs which
 * must know all networks accessible).
 */

struct ifconf 
{
  int ifc_len;
  union 
  {
    char *ifcu_buf;
    struct  ifreq *ifcu_req;
  } ifc_ifcu;
};
#define ifc_buf ifc_ifcu.ifcu_buf
#define ifc_req ifc_ifcu.ifcu_req

#endif /* __RCC_LINUX_IF_H__ */
