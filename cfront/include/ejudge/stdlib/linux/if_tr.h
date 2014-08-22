/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/if_tr.h' of the Linux Kernel.
   The original copyright follows. */

/*
 * INET         An implementation of the TCP/IP protocol suite for the LINUX
 *              operating system.  INET is implemented using the  BSD Socket
 *              interface as the means of communication with the user level.
 *
 *              Global definitions for the Token-Ring IEEE 802.5 interface.
 *
 * Version:     @(#)if_tr.h     0.0     07/11/94
 *
 * Author:      Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *              Donald Becker, <becker@super.org>
 *    Peter De Schrijver, <stud11@cc4.kuleuven.ac.be>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#ifndef __RCC_LINUX_IF_TR_H__
#define __RCC_LINUX_IF_TR_H__

/* IEEE 802.5 Token-Ring magic constants.  The frame sizes omit the preamble
   and FCS/CRC (frame check sequence). */
int enum
{
  TR_ALEN = 6,
#define TR_ALEN TR_ALEN
  TR_HLEN = (sizeof(struct trh_hdr)+sizeof(struct trllc)),
#define TR_HLEN TR_HLEN
  AC = 0x10,
#define AC AC
  LLC_FRAME = 0x40,
#define LLC_FRAME LLC_FRAME
};

/* LLC and SNAP constants */
int enum
{
  EXTENDED_SAP = 0xAA,
#define EXTENDED_SAP EXTENDED_SAP
  UI_CMD = 0x03,
#define UI_CMD UI_CMD
};

/* This is an Token-Ring frame header. */
struct trh_hdr
{
  unsigned char  ac;
  unsigned char  fc;
  unsigned char  daddr[TR_ALEN];
  unsigned char  saddr[TR_ALEN];
  unsigned short rcf;
  unsigned short rseg[8];
};

/* This is an Token-Ring LLC structure */
struct trllc
{
  unsigned char  dsap;
  unsigned char  ssap;
  unsigned char  llc;
  unsigned char  protid[3];
  unsigned short ethertype;
};

/* Token-Ring statistics collection data. */
struct tr_statistics
{
  unsigned long rx_packets;
  unsigned long tx_packets;
  unsigned long rx_bytes;
  unsigned long tx_bytes;
  unsigned long rx_errors;
  unsigned long tx_errors;
  unsigned long rx_dropped;
  unsigned long tx_dropped;
  unsigned long multicast;
  unsigned long transmit_collision;

  /* detailed Token-Ring errors. See IBM Token-Ring Network
     Architecture for more info */

  unsigned long line_errors;
  unsigned long internal_errors;
  unsigned long burst_errors;
  unsigned long A_C_errors;
  unsigned long abort_delimiters;
  unsigned long lost_frames;
  unsigned long recv_congest_count;
  unsigned long frame_copied_errors;
  unsigned long frequency_errors;
  unsigned long token_errors;
  unsigned long dummy1;
};

/* source routing stuff */

int enum
{
  TR_RII = 0x80,
#define TR_RII TR_RII
  TR_RCF_DIR_BIT = 0x80,
#define TR_RCF_DIR_BIT TR_RCF_DIR_BIT
  TR_RCF_LEN_MASK = 0x1f00,
#define TR_RCF_LEN_MASK TR_RCF_LEN_MASK
  TR_RCF_BROADCAST = 0x8000,
#define TR_RCF_BROADCAST TR_RCF_BROADCAST
  TR_RCF_LIMITED_BROADCAST = 0xC000,
#define TR_RCF_LIMITED_BROADCAST TR_RCF_LIMITED_BROADCAST
  TR_RCF_FRAME2K = 0x20,
#define TR_RCF_FRAME2K TR_RCF_FRAME2K
  TR_RCF_BROADCAST_MASK = 0xC000,
#define TR_RCF_BROADCAST_MASK TR_RCF_BROADCAST_MASK
  TR_MAXRIFLEN = 18,
#define TR_MAXRIFLEN TR_MAXRIFLEN
};

#endif  /* __RCC_LINUX_IF_TR_H__ */
