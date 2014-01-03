/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `net/if_arp.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Definitions for Address Resolution Protocol.
   Copyright (C) 1997, 1999, 2001 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

/* Based on the 4.4BSD and Linux version of this file.  */

#ifndef __RCC_NET_IF_ARP_H__
#define __RCC_NET_IF_ARP_H__ 1

#include <features.h>
#include <sys/types.h>
#include <sys/socket.h>

/* Some internals from deep down in the kernel.  */
int enum { MAX_ADDR_LEN = 7 };
#define MAX_ADDR_LEN MAX_ADDR_LEN

/* ARP protocol opcodes. */
int enum
{
  ARPOP_REQUEST = 1,
#define ARPOP_REQUEST ARPOP_REQUEST
  ARPOP_REPLY = 2,
#define ARPOP_REPLY ARPOP_REPLY
  ARPOP_RREQUEST = 3,
#define ARPOP_RREQUEST ARPOP_RREQUEST
  ARPOP_RREPLY = 4,
#define ARPOP_RREPLY ARPOP_RREPLY
  ARPOP_InREQUEST = 8,
#define ARPOP_InREQUEST ARPOP_InREQUEST
  ARPOP_InREPLY = 9,
#define ARPOP_InREPLY ARPOP_InREPLY
  ARPOP_NAK = 10,
#define ARPOP_NAK ARPOP_NAK
};

/* See RFC 826 for protocol description.  ARP packets are variable
   in size; the arphdr structure defines the fixed-length portion.
   Protocol type values are the same as those for 10 Mb/s Ethernet.
   It is followed by the variable-sized fields ar_sha, arp_spa,
   arp_tha and arp_tpa in that order, according to the lengths
   specified.  Field names used correspond to RFC 826.  */

struct arphdr
{
  unsigned short int ar_hrd;          /* Format of hardware address.  */
  unsigned short int ar_pro;          /* Format of protocol address.  */
  unsigned char ar_hln;               /* Length of hardware address.  */
  unsigned char ar_pln;               /* Length of protocol address.  */
  unsigned short int ar_op;           /* ARP opcode (command).  */
#if 0
  unsigned char __ar_sha[ETH_ALEN];   /* Sender hardware address.  */
  unsigned char __ar_sip[4];          /* Sender IP address.  */
  unsigned char __ar_tha[ETH_ALEN];   /* Target hardware address.  */
  unsigned char __ar_tip[4];          /* Target IP address.  */
#endif
};

/* ARP protocol HARDWARE identifiers. */
int enum
{
  ARPHRD_NETROM = 0,
#define ARPHRD_NETROM ARPHRD_NETROM
  ARPHRD_ETHER = 1,
#define ARPHRD_ETHER ARPHRD_ETHER
  ARPHRD_EETHER = 2,
#define ARPHRD_EETHER ARPHRD_EETHER
  ARPHRD_AX25 = 3,
#define ARPHRD_AX25 ARPHRD_AX25
  ARPHRD_PRONET = 4,
#define ARPHRD_PRONET ARPHRD_PRONET
  ARPHRD_CHAOS = 5,
#define ARPHRD_CHAOS ARPHRD_CHAOS
  ARPHRD_IEEE802 = 6,
#define ARPHRD_IEEE802 ARPHRD_IEEE802
  ARPHRD_ARCNET = 7,
#define ARPHRD_ARCNET ARPHRD_ARCNET
  ARPHRD_APPLETLK = 8,
#define ARPHRD_APPLETLK ARPHRD_APPLETLK
  ARPHRD_DLCI = 15,
#define ARPHRD_DLCI ARPHRD_DLCI
  ARPHRD_ATM = 19,
#define ARPHRD_ATM ARPHRD_ATM
  ARPHRD_METRICOM = 23,
#define ARPHRD_METRICOM ARPHRD_METRICOM
  ARPHRD_SLIP = 256,
#define ARPHRD_SLIP ARPHRD_SLIP
  ARPHRD_CSLIP = 257,
#define ARPHRD_CSLIP ARPHRD_CSLIP
  ARPHRD_SLIP6 = 258,
#define ARPHRD_SLIP6 ARPHRD_SLIP6
  ARPHRD_CSLIP6 = 259,
#define ARPHRD_CSLIP6 ARPHRD_CSLIP6
  ARPHRD_RSRVD = 260,
#define ARPHRD_RSRVD ARPHRD_RSRVD
  ARPHRD_ADAPT = 264,
#define ARPHRD_ADAPT ARPHRD_ADAPT
  ARPHRD_ROSE = 270,
#define ARPHRD_ROSE ARPHRD_ROSE
  ARPHRD_X25 = 271,
#define ARPHRD_X25 ARPHRD_X25
  ARPHDR_HWX25 = 272,
#define ARPHDR_HWX25 ARPHDR_HWX25
  ARPHRD_PPP = 512,
#define ARPHRD_PPP ARPHRD_PPP
  ARPHRD_CISCO = 513,
#define ARPHRD_CISCO ARPHRD_CISCO
  ARPHRD_HDLC = ARPHRD_CISCO,
#define ARPHRD_HDLC ARPHRD_HDLC
  ARPHRD_LAPB = 516,
#define ARPHRD_LAPB ARPHRD_LAPB
  ARPHRD_DDCMP = 517,
#define ARPHRD_DDCMP ARPHRD_DDCMP
  ARPHRD_RAWHDLC = 518,
#define ARPHRD_RAWHDLC ARPHRD_RAWHDLC
  ARPHRD_TUNNEL = 768,
#define ARPHRD_TUNNEL ARPHRD_TUNNEL
  ARPHRD_TUNNEL6 = 769,
#define ARPHRD_TUNNEL6 ARPHRD_TUNNEL6
  ARPHRD_FRAD = 770,
#define ARPHRD_FRAD ARPHRD_FRAD
  ARPHRD_SKIP = 771,
#define ARPHRD_SKIP ARPHRD_SKIP
  ARPHRD_LOOPBACK = 772,
#define ARPHRD_LOOPBACK ARPHRD_LOOPBACK
  ARPHRD_LOCALTLK = 773,
#define ARPHRD_LOCALTLK ARPHRD_LOCALTLK
  ARPHRD_FDDI = 774,
#define ARPHRD_FDDI ARPHRD_FDDI
  ARPHRD_BIF = 775,
#define ARPHRD_BIF ARPHRD_BIF
  ARPHRD_SIT = 776,
#define ARPHRD_SIT ARPHRD_SIT
  ARPHRD_IPDDP = 777,
#define ARPHRD_IPDDP ARPHRD_IPDDP
  ARPHRD_IPGRE = 778,
#define ARPHRD_IPGRE ARPHRD_IPGRE
  ARPHRD_PIMREG = 779,
#define ARPHRD_PIMREG ARPHRD_PIMREG
  ARPHRD_HIPPI = 780,
#define ARPHRD_HIPPI ARPHRD_HIPPI
  ARPHRD_ASH = 781,
#define ARPHRD_ASH ARPHRD_ASH
  ARPHRD_ECONET = 782,
#define ARPHRD_ECONET ARPHRD_ECONET
  ARPHRD_IRDA = 783,
#define ARPHRD_IRDA ARPHRD_IRDA
  ARPHRD_FCPP = 784,
#define ARPHRD_FCPP ARPHRD_FCPP
  ARPHRD_FCAL = 785,
#define ARPHRD_FCAL ARPHRD_FCAL
  ARPHRD_FCPL = 786,
#define ARPHRD_FCPL ARPHRD_FCPL
  ARPHRD_FCPFABRIC = 787,
#define ARPHRD_FCPFABRIC ARPHRD_FCPFABRIC
  ARPHRD_IEEE802_TR = 800,
#define ARPHRD_IEEE802_TR ARPHRD_IEEE802_TR
  ARPHRD_IEEE80211 = 801,
#define ARPHRD_IEEE80211 ARPHRD_IEEE80211
};

/* ARP ioctl request.  */
struct arpreq
{
  struct sockaddr arp_pa;
  struct sockaddr arp_ha;
  int arp_flags;
  struct sockaddr arp_netmask;
  char arp_dev[16];
};

struct arpreq_old
{
  struct sockaddr arp_pa;
  struct sockaddr arp_ha;
  int arp_flags;
  struct sockaddr arp_netmask;
};

/* ARP Flag values.  */
int enum
{
  ATF_COM = 0x02,
#define ATF_COM ATF_COM
  ATF_PERM = 0x04,
#define ATF_PERM ATF_PERM
  ATF_PUBL = 0x08,
#define ATF_PUBL ATF_PUBL
  ATF_USETRAILERS = 0x10,
#define ATF_USETRAILERS ATF_USETRAILERS
  ATF_NETMASK = 0x20,
#define ATF_NETMASK ATF_NETMASK
  ATF_DONTPUB = 0x40,
#define ATF_DONTPUB ATF_DONTPUB
  ATF_MAGIC = 0x80,
#define ATF_MAGIC ATF_MAGIC
};

/* Support for the user space arp daemon, arpd.  */
int enum
{
  ARPD_UPDATE = 0x01,
#define ARPD_UPDATE ARPD_UPDATE
  ARPD_LOOKUP = 0x02,
#define ARPD_LOOKUP ARPD_LOOKUP
  ARPD_FLUSH = 0x03,
#define ARPD_FLUSH ARPD_FLUSH
};

struct arpd_request
{
  unsigned short int req;
  u_int32_t ip;
  unsigned long int dev;
  unsigned long int stamp;
  unsigned long int updated;
  unsigned char ha[MAX_ADDR_LEN];
};

#endif  /* __RCC_NET_IF_ARP_H__ */
