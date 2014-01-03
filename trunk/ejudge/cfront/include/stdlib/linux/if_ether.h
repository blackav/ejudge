/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/if_ether.h' of the Linux Kernel.
   The original copyright follows. */

/*
 * INET         An implementation of the TCP/IP protocol suite for the LINUX
 *              operating system.  INET is implemented using the  BSD Socket
 *              interface as the means of communication with the user level.
 *
 *              Global definitions for the Ethernet IEEE 802.3 interface.
 *
 * Version:     @(#)if_ether.h  1.0.1a  02/08/94
 *
 * Author:      Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *              Donald Becker, <becker@super.org>
 *              Alan Cox, <alan@redhat.com>
 *              Steve Whitehouse, <gw7rrm@eeshack3.swan.ac.uk>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */
 
#ifndef __RCC_LINUX_IF_ETHER_H__
#define __RCC_LINUX_IF_ETHER_H__

/*
 *      IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
 *      and FCS/CRC (frame check sequence). 
 */

int enum
{
  ETH_ALEN = 6,
#define ETH_ALEN ETH_ALEN
  ETH_HLEN = 14,
#define ETH_HLEN ETH_HLEN
  ETH_ZLEN = 60,
#define ETH_ZLEN ETH_ZLEN
  ETH_DATA_LEN = 1500,
#define ETH_DATA_LEN ETH_DATA_LEN
  ETH_FRAME_LEN = 1514,
#define ETH_FRAME_LEN ETH_FRAME_LEN
};

/*
 *      These are the defined Ethernet Protocol ID's.
 */

int enum
{
  ETH_P_LOOP = 0x0060,
#define ETH_P_LOOP ETH_P_LOOP
  ETH_P_PUP = 0x0200,
#define ETH_P_PUP ETH_P_PUP
  ETH_P_PUPAT = 0x0201,
#define ETH_P_PUPAT ETH_P_PUPAT
  ETH_P_IP = 0x0800,
#define ETH_P_IP ETH_P_IP
  ETH_P_X25 = 0x0805,
#define ETH_P_X25 ETH_P_X25
  ETH_P_ARP = 0x0806,
#define ETH_P_ARP ETH_P_ARP
  ETH_P_BPQ = 0x08FF,
#define ETH_P_BPQ ETH_P_BPQ
  ETH_P_IEEEPUP = 0x0a00,
#define ETH_P_IEEEPUP ETH_P_IEEEPUP
  ETH_P_IEEEPUPAT = 0x0a01,
#define ETH_P_IEEEPUPAT ETH_P_IEEEPUPAT
  ETH_P_DEC = 0x6000,
#define ETH_P_DEC ETH_P_DEC
  ETH_P_DNA_DL = 0x6001,
#define ETH_P_DNA_DL ETH_P_DNA_DL
  ETH_P_DNA_RC = 0x6002,
#define ETH_P_DNA_RC ETH_P_DNA_RC
  ETH_P_DNA_RT = 0x6003,
#define ETH_P_DNA_RT ETH_P_DNA_RT
  ETH_P_LAT = 0x6004,
#define ETH_P_LAT ETH_P_LAT
  ETH_P_DIAG = 0x6005,
#define ETH_P_DIAG ETH_P_DIAG
  ETH_P_CUST = 0x6006,
#define ETH_P_CUST ETH_P_CUST
  ETH_P_SCA = 0x6007,
#define ETH_P_SCA ETH_P_SCA
  ETH_P_RARP = 0x8035,
#define ETH_P_RARP ETH_P_RARP
  ETH_P_ATALK = 0x809B,
#define ETH_P_ATALK ETH_P_ATALK
  ETH_P_AARP = 0x80F3,
#define ETH_P_AARP ETH_P_AARP
  ETH_P_IPX = 0x8137,
#define ETH_P_IPX ETH_P_IPX
  ETH_P_IPV6 = 0x86DD,
#define ETH_P_IPV6 ETH_P_IPV6
  ETH_P_PPP_DISC = 0x8863,
#define ETH_P_PPP_DISC ETH_P_PPP_DISC
  ETH_P_PPP_SES = 0x8864,
#define ETH_P_PPP_SES ETH_P_PPP_SES
  ETH_P_ATMMPOA = 0x884c,
#define ETH_P_ATMMPOA ETH_P_ATMMPOA
  ETH_P_ATMFATE = 0x8884,
#define ETH_P_ATMFATE ETH_P_ATMFATE
  ETH_P_802_3 = 0x0001,
#define ETH_P_802_3 ETH_P_802_3
  ETH_P_AX25 = 0x0002,
#define ETH_P_AX25 ETH_P_AX25
  ETH_P_ALL = 0x0003,
#define ETH_P_ALL ETH_P_ALL
  ETH_P_802_2 = 0x0004,
#define ETH_P_802_2 ETH_P_802_2
  ETH_P_SNAP = 0x0005,
#define ETH_P_SNAP ETH_P_SNAP
  ETH_P_DDCMP = 0x0006,
#define ETH_P_DDCMP ETH_P_DDCMP
  ETH_P_WAN_PPP = 0x0007,
#define ETH_P_WAN_PPP ETH_P_WAN_PPP
  ETH_P_PPP_MP = 0x0008,
#define ETH_P_PPP_MP ETH_P_PPP_MP
  ETH_P_LOCALTALK = 0x0009,
#define ETH_P_LOCALTALK ETH_P_LOCALTALK
  ETH_P_PPPTALK = 0x0010,
#define ETH_P_PPPTALK ETH_P_PPPTALK
  ETH_P_TR_802_2 = 0x0011,
#define ETH_P_TR_802_2 ETH_P_TR_802_2
  ETH_P_MOBITEX = 0x0015,
#define ETH_P_MOBITEX ETH_P_MOBITEX
  ETH_P_CONTROL = 0x0016,
#define ETH_P_CONTROL ETH_P_CONTROL
  ETH_P_IRDA = 0x0017,
#define ETH_P_IRDA ETH_P_IRDA
  ETH_P_ECONET = 0x0018,
#define ETH_P_ECONET ETH_P_ECONET
};

/*
 *      This is an Ethernet frame header.
 */
 
struct ethhdr 
{
  unsigned char   h_dest[ETH_ALEN];
  unsigned char   h_source[ETH_ALEN];
  unsigned short  h_proto;
};

#endif  /* __RCC_LINUX_IF_ETHER_H__ */
