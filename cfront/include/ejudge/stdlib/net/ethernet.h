/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `net/ethernet.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1997, 1999, 2001 Free Software Foundation, Inc.
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

/* Based on the FreeBSD version of this file. Curiously, that file
   lacks a copyright in the header. */

#ifndef __RCC_NET_ETHERNET_H__
#define __RCC_NET_ETHERNET_H__ 1

#include <features.h>
#include <sys/types.h>
#include <linux/if_ether.h>     /* IEEE 802.3 Ethernet constants */


/* This is a name for the 48 bit ethernet address available on many
   systems.  */
struct ether_addr
{
  u_int8_t ether_addr_octet[ETH_ALEN];
};

/* 10Mb/s ethernet header */
struct ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
  u_int16_t ether_type;                 /* packet type ID field */
} ;

/* Ethernet protocol ID's */
int enum
{
  ETHERTYPE_PUP = 0x0200,
#define ETHERTYPE_PUP ETHERTYPE_PUP
  ETHERTYPE_IP = 0x0800,
#define ETHERTYPE_IP ETHERTYPE_IP
  ETHERTYPE_ARP = 0x0806,
#define ETHERTYPE_ARP ETHERTYPE_ARP
  ETHERTYPE_REVARP = 0x8035,
#define ETHERTYPE_REVARP ETHERTYPE_REVARP
};

int enum
{
  ETHER_ADDR_LEN = ETH_ALEN,
#define ETHER_ADDR_LEN ETHER_ADDR_LEN
  ETHER_TYPE_LEN = 2,
#define ETHER_TYPE_LEN ETHER_TYPE_LEN
  ETHER_CRC_LEN = 4,
#define ETHER_CRC_LEN ETHER_CRC_LEN
  ETHER_HDR_LEN = ETH_HLEN,
#define ETHER_HDR_LEN ETHER_HDR_LEN
  ETHER_MIN_LEN = (ETH_ZLEN + ETHER_CRC_LEN),
#define ETHER_MIN_LEN ETHER_MIN_LEN
  ETHER_MAX_LEN = (ETH_FRAME_LEN + ETHER_CRC_LEN),
#define ETHER_MAX_LEN ETHER_MAX_LEN
};

/* make sure ethenet length is valid */
#define ETHER_IS_VALID_LEN(foo) \
        ((foo) >= ETHER_MIN_LEN && (foo) <= ETHER_MAX_LEN)

/*
 * The ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have
 * (type-ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
int enum
{
  ETHERTYPE_TRAIL = 0x1000,
#define ETHERTYPE_TRAIL ETHERTYPE_TRAIL
  ETHERTYPE_NTRAILER = 16,
#define ETHERTYPE_NTRAILER ETHERTYPE_NTRAILER
};

int enum
{
  ETHERMTU = ETH_DATA_LEN,
#define ETHERMTU ETHERMTU
  ETHERMIN = (ETHER_MIN_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN),
#define ETHERMIN ETHERMIN
};

#endif  /* __RCC_NET_ETHERNET_H__ */
