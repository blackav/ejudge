/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/if_fddi.h' of the Linux Kernel.
   The original copyright follows. */

/*
 * INET         An implementation of the TCP/IP protocol suite for the LINUX
 *              operating system.  INET is implemented using the BSD Socket
 *              interface as the means of communication with the user level.
 *
 *              Global definitions for the ANSI FDDI interface.
 *
 * Version:     @(#)if_fddi.h   1.0.1   09/16/96
 *
 * Author:      Lawrence V. Stefani, <stefani@lkg.dec.com>
 *
 *              if_fddi.h is based on previous if_ether.h and if_tr.h work by
 *                      Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *                      Donald Becker, <becker@super.org>
 *                      Alan Cox, <alan@redhat.com>
 *                      Steve Whitehouse, <gw7rrm@eeshack3.swan.ac.uk>
 *                      Peter De Schrijver, <stud11@cc4.kuleuven.ac.be>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#ifndef __RCC_LINUX_IF_FDDI_H__
#define __RCC_LINUX_IF_FDDI_H__

/*
 *  Define max and min legal sizes.  The frame sizes do not include
 *  4 byte FCS/CRC (frame check sequence).
 */
int enum
{
  FDDI_K_ALEN = 6,
#define FDDI_K_ALEN FDDI_K_ALEN
  FDDI_K_8022_HLEN = 16,
#define FDDI_K_8022_HLEN FDDI_K_8022_HLEN
  FDDI_K_SNAP_HLEN = 21,
#define FDDI_K_SNAP_HLEN FDDI_K_SNAP_HLEN
  FDDI_K_8022_ZLEN = 16,
#define FDDI_K_8022_ZLEN FDDI_K_8022_ZLEN
  FDDI_K_SNAP_ZLEN = 21,
#define FDDI_K_SNAP_ZLEN FDDI_K_SNAP_ZLEN
  FDDI_K_8022_DLEN = 4475,
#define FDDI_K_8022_DLEN FDDI_K_8022_DLEN
  FDDI_K_SNAP_DLEN = 4470,
#define FDDI_K_SNAP_DLEN FDDI_K_SNAP_DLEN
  FDDI_K_LLC_ZLEN = 13,
#define FDDI_K_LLC_ZLEN FDDI_K_LLC_ZLEN
  FDDI_K_LLC_LEN = 4491,
#define FDDI_K_LLC_LEN FDDI_K_LLC_LEN
};

/* Define FDDI Frame Control (FC) Byte values */
int enum
{
  FDDI_FC_K_VOID = 0x00,
#define FDDI_FC_K_VOID FDDI_FC_K_VOID
  FDDI_FC_K_NON_RESTRICTED_TOKEN = 0x80,
#define FDDI_FC_K_NON_RESTRICTED_TOKEN FDDI_FC_K_NON_RESTRICTED_TOKEN
  FDDI_FC_K_RESTRICTED_TOKEN = 0xC0,
#define FDDI_FC_K_RESTRICTED_TOKEN FDDI_FC_K_RESTRICTED_TOKEN
  FDDI_FC_K_SMT_MIN = 0x41,
#define FDDI_FC_K_SMT_MIN FDDI_FC_K_SMT_MIN
  FDDI_FC_K_SMT_MAX = 0x4F,
#define FDDI_FC_K_SMT_MAX FDDI_FC_K_SMT_MAX
  FDDI_FC_K_MAC_MIN = 0xC1,
#define FDDI_FC_K_MAC_MIN FDDI_FC_K_MAC_MIN
  FDDI_FC_K_MAC_MAX = 0xCF,
#define FDDI_FC_K_MAC_MAX FDDI_FC_K_MAC_MAX
  FDDI_FC_K_ASYNC_LLC_MIN = 0x50,
#define FDDI_FC_K_ASYNC_LLC_MIN FDDI_FC_K_ASYNC_LLC_MIN
  FDDI_FC_K_ASYNC_LLC_DEF = 0x54,
#define FDDI_FC_K_ASYNC_LLC_DEF FDDI_FC_K_ASYNC_LLC_DEF
  FDDI_FC_K_ASYNC_LLC_MAX = 0x5F,
#define FDDI_FC_K_ASYNC_LLC_MAX FDDI_FC_K_ASYNC_LLC_MAX
  FDDI_FC_K_SYNC_LLC_MIN = 0xD0,
#define FDDI_FC_K_SYNC_LLC_MIN FDDI_FC_K_SYNC_LLC_MIN
  FDDI_FC_K_SYNC_LLC_MAX = 0xD7,
#define FDDI_FC_K_SYNC_LLC_MAX FDDI_FC_K_SYNC_LLC_MAX
  FDDI_FC_K_IMPLEMENTOR_MIN = 0x60,
#define FDDI_FC_K_IMPLEMENTOR_MIN FDDI_FC_K_IMPLEMENTOR_MIN
  FDDI_FC_K_IMPLEMENTOR_MAX = 0x6F,
#define FDDI_FC_K_IMPLEMENTOR_MAX FDDI_FC_K_IMPLEMENTOR_MAX
  FDDI_FC_K_RESERVED_MIN = 0x70,
#define FDDI_FC_K_RESERVED_MIN FDDI_FC_K_RESERVED_MIN
  FDDI_FC_K_RESERVED_MAX = 0x7F,
#define FDDI_FC_K_RESERVED_MAX FDDI_FC_K_RESERVED_MAX
};

/* Define LLC and SNAP constants */
int enum
{
  FDDI_EXTENDED_SAP = 0xAA,
#define FDDI_EXTENDED_SAP FDDI_EXTENDED_SAP
  FDDI_UI_CMD = 0x03,
#define FDDI_UI_CMD FDDI_UI_CMD
};

/* Define 802.2 Type 1 header */
struct fddi_8022_1_hdr
{
  unsigned char   dsap;
  unsigned char   ssap;
  unsigned char   ctrl;
};

/* Define 802.2 Type 2 header */
struct fddi_8022_2_hdr
{
  unsigned char   dsap;
  unsigned char   ssap;
  unsigned char   ctrl_1;
  unsigned char   ctrl_2;
};

/* Define 802.2 SNAP header */
int enum { FDDI_K_OUI_LEN = 3 };
#define FDDI_K_OUI_LEN FDDI_K_OUI_LEN

struct fddi_snap_hdr
{
  unsigned char   dsap;
  unsigned char   ssap;
  unsigned char   ctrl;
  unsigned char   oui[FDDI_K_OUI_LEN];
  unsigned short  ethertype;
};

/* Define FDDI LLC frame header */
struct fddihdr
{
  unsigned char   fc;
  unsigned char   daddr[FDDI_K_ALEN];
  unsigned char   saddr[FDDI_K_ALEN];
  union
  {
    struct fddi_8022_1_hdr          llc_8022_1;
    struct fddi_8022_2_hdr          llc_8022_2;
    struct fddi_snap_hdr            llc_snap;
  } hdr;
};

/* Define FDDI statistics structure */
struct fddi_statistics
{
  unsigned int    rx_packets;
  unsigned int    tx_packets;
  unsigned int    rx_bytes;
  unsigned int    tx_bytes;
  unsigned int    rx_errors;
  unsigned int    tx_errors;
  unsigned int    rx_dropped;
  unsigned int    tx_dropped;
  unsigned int    multicast;
  unsigned int    transmit_collision;
  
  /* detailed rx_errors */
  unsigned int    rx_length_errors;
  unsigned int    rx_over_errors;
  unsigned int    rx_crc_errors;
  unsigned int    rx_frame_errors;
  unsigned int    rx_fifo_errors;
  unsigned int    rx_missed_errors;

  /* detailed tx_errors */
  unsigned int    tx_aborted_errors;
  unsigned int    tx_carrier_errors;
  unsigned int    tx_fifo_errors;
  unsigned int    tx_heartbeat_errors;
  unsigned int    tx_window_errors;

  /* for cslip etc */
  unsigned int    rx_compressed;
  unsigned int    tx_compressed;

  /* Detailed FDDI statistics.  Adopted from RFC 1512 */

  unsigned char   smt_station_id[8];
  unsigned int    smt_op_version_id;
  unsigned int    smt_hi_version_id;
  unsigned int    smt_lo_version_id;
  unsigned char   smt_user_data[32];
  unsigned int    smt_mib_version_id;
  unsigned int    smt_mac_cts;
  unsigned int    smt_non_master_cts;
  unsigned int    smt_master_cts;
  unsigned int    smt_available_paths;
  unsigned int    smt_config_capabilities;
  unsigned int    smt_config_policy;
  unsigned int    smt_connection_policy;
  unsigned int    smt_t_notify;
  unsigned int    smt_stat_rpt_policy;
  unsigned int    smt_trace_max_expiration;
  unsigned int    smt_bypass_present;
  unsigned int    smt_ecm_state;
  unsigned int    smt_cf_state;
  unsigned int    smt_remote_disconnect_flag;
  unsigned int    smt_station_status;
  unsigned int    smt_peer_wrap_flag;
  unsigned int    smt_time_stamp;
  unsigned int    smt_transition_time_stamp;
  unsigned int    mac_frame_status_functions;
  unsigned int    mac_t_max_capability;
  unsigned int    mac_tvx_capability;
  unsigned int    mac_available_paths;
  unsigned int    mac_current_path;
  unsigned char   mac_upstream_nbr[FDDI_K_ALEN];
  unsigned char   mac_downstream_nbr[FDDI_K_ALEN];
  unsigned char   mac_old_upstream_nbr[FDDI_K_ALEN];
  unsigned char   mac_old_downstream_nbr[FDDI_K_ALEN];
  unsigned int    mac_dup_address_test;
  unsigned int    mac_requested_paths;
  unsigned int    mac_downstream_port_type;
  unsigned char   mac_smt_address[FDDI_K_ALEN];
  unsigned int    mac_t_req;
  unsigned int    mac_t_neg;
  unsigned int    mac_t_max;
  unsigned int    mac_tvx_value;
  unsigned int    mac_frame_cts;
  unsigned int    mac_copied_cts;
  unsigned int    mac_transmit_cts;
  unsigned int    mac_error_cts;
  unsigned int    mac_lost_cts;
  unsigned int    mac_frame_error_threshold;
  unsigned int    mac_frame_error_ratio;
  unsigned int    mac_rmt_state;
  unsigned int    mac_da_flag;
  unsigned int    mac_una_da_flag;
  unsigned int    mac_frame_error_flag;
  unsigned int    mac_ma_unitdata_available;
  unsigned int    mac_hardware_present;
  unsigned int    mac_ma_unitdata_enable;
  unsigned int    path_tvx_lower_bound;
  unsigned int    path_t_max_lower_bound;
  unsigned int    path_max_t_req;
  unsigned int    path_configuration[8];
  unsigned int    port_my_type[2];
  unsigned int    port_neighbor_type[2];
  unsigned int    port_connection_policies[2];
  unsigned int    port_mac_indicated[2];
  unsigned int    port_current_path[2];
  unsigned char   port_requested_paths[3*2];
  unsigned int    port_mac_placement[2];
  unsigned int    port_available_paths[2];
  unsigned int    port_pmd_class[2];
  unsigned int    port_connection_capabilities[2];
  unsigned int    port_bs_flag[2];
  unsigned int    port_lct_fail_cts[2];
  unsigned int    port_ler_estimate[2];
  unsigned int    port_lem_reject_cts[2];
  unsigned int    port_lem_cts[2];
  unsigned int    port_ler_cutoff[2];
  unsigned int    port_ler_alarm[2];
  unsigned int    port_connect_state[2];
  unsigned int    port_pcm_state[2];
  unsigned int    port_pc_withhold[2];
  unsigned int    port_ler_flag[2];
  unsigned int    port_hardware_present[2];
};

#endif  /* __RCC_LINUX_IF_FDDI_H__ */
