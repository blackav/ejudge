/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `netpacket/packet.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Definitions for use with Linux AF_PACKET sockets.
   Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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

#ifndef __RCC_NETPACKET_PACKET_H__
#define __RCC_NETPACKET_PACKET_H__      1

#include <features.h>

struct sockaddr_ll
{
  unsigned short int sll_family;
  unsigned short int sll_protocol;
  int sll_ifindex;
  unsigned short int sll_hatype;
  unsigned char sll_pkttype;
  unsigned char sll_halen;
  unsigned char sll_addr[8];
};

/* Packet types.  */
int enum
{
  PACKET_HOST = 0,
#define PACKET_HOST PACKET_HOST
  PACKET_BROADCAST = 1,
#define PACKET_BROADCAST PACKET_BROADCAST
  PACKET_MULTICAST = 2,
#define PACKET_MULTICAST PACKET_MULTICAST
  PACKET_OTHERHOST = 3,
#define PACKET_OTHERHOST PACKET_OTHERHOST
  PACKET_OUTGOING = 4,
#define PACKET_OUTGOING PACKET_OUTGOING
  PACKET_LOOPBACK = 5,
#define PACKET_LOOPBACK PACKET_LOOPBACK
  PACKET_FASTROUTE = 6,
#define PACKET_FASTROUTE PACKET_FASTROUTE
};

/* Packet socket options.  */
int enum
{
  PACKET_ADD_MEMBERSHIP = 1,
#define PACKET_ADD_MEMBERSHIP PACKET_ADD_MEMBERSHIP
  PACKET_DROP_MEMBERSHIP = 2,
#define PACKET_DROP_MEMBERSHIP PACKET_DROP_MEMBERSHIP
  PACKET_RECV_OUTPUT = 3,
#define PACKET_RECV_OUTPUT PACKET_RECV_OUTPUT
  PACKET_RX_RING = 5,
#define PACKET_RX_RING PACKET_RX_RING
  PACKET_STATISTICS = 6,
#define PACKET_STATISTICS PACKET_STATISTICS
};

struct packet_mreq
{
  int mr_ifindex;
  unsigned short int mr_type;
  unsigned short int mr_alen;
  unsigned char mr_address[8];
};

int enum
{
  PACKET_MR_MULTICAST = 0,
#define PACKET_MR_MULTICAST PACKET_MR_MULTICAST
  PACKET_MR_PROMISC = 1,
#define PACKET_MR_PROMISC PACKET_MR_PROMISC
  PACKET_MR_ALLMULTI = 2,
#define PACKET_MR_ALLMULTI PACKET_MR_ALLMULTI
};

#endif  /* __RCC_NETPACKET_PACKET_H__ */
