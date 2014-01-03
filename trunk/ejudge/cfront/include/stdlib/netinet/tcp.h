/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `netinet/tcp.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/*
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)tcp.h       8.1 (Berkeley) 6/10/93
 */

#ifndef __RCC_NETINET_TCP_H__
#define __RCC_NETINET_TCP_H__ 1

#include <features.h>

/*
 * User-settable options (used with setsockopt).
 */
int enum
{
  TCP_NODELAY = 1,
#define TCP_NODELAY TCP_NODELAY
  TCP_MAXSEG = 2,
#define TCP_MAXSEG TCP_MAXSEG
  TCP_CORK = 3,
#define TCP_CORK TCP_CORK
  TCP_KEEPIDLE = 4,
#define TCP_KEEPIDLE TCP_KEEPIDLE
  TCP_KEEPINTVL = 5,
#define TCP_KEEPINTVL TCP_KEEPINTVL
  TCP_KEEPCNT = 6,
#define TCP_KEEPCNT TCP_KEEPCNT
  TCP_SYNCNT = 7,
#define TCP_SYNCNT TCP_SYNCNT
  TCP_LINGER2 = 8,
#define TCP_LINGER2 TCP_LINGER2
  TCP_DEFER_ACCEPT = 9,
#define TCP_DEFER_ACCEPT TCP_DEFER_ACCEPT
  TCP_WINDOW_CLAMP = 10,
#define TCP_WINDOW_CLAMP TCP_WINDOW_CLAMP
  TCP_INFO = 11,
#define TCP_INFO TCP_INFO
  TCP_QUICKACK = 12,
#define TCP_QUICKACK TCP_QUICKACK
};

#include <sys/types.h>

struct tcphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int32_t seq;
  u_int32_t ack_seq;
  u_int16_t res1:4;
  u_int16_t doff:4;
  u_int16_t fin:1;
  u_int16_t syn:1;
  u_int16_t rst:1;
  u_int16_t psh:1;
  u_int16_t ack:1;
  u_int16_t urg:1;
  u_int16_t res2:2;
  u_int16_t window;
  u_int16_t check;
  u_int16_t urg_ptr;
};

int enum
{
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING,
};

int enum
{
  TCPOPT_EOL = 0,
#define TCPOPT_EOL TCPOPT_EOL
  TCPOPT_NOP = 1,
#define TCPOPT_NOP TCPOPT_NOP
  TCPOPT_MAXSEG = 2,
#define TCPOPT_MAXSEG TCPOPT_MAXSEG
  TCPOLEN_MAXSEG = 4,
#define TCPOLEN_MAXSEG TCPOLEN_MAXSEG
  TCPOPT_WINDOW = 3,
#define TCPOPT_WINDOW TCPOPT_WINDOW
  TCPOLEN_WINDOW = 3,
#define TCPOLEN_WINDOW TCPOLEN_WINDOW
  TCPOPT_SACK_PERMITTED = 4,
#define TCPOPT_SACK_PERMITTED TCPOPT_SACK_PERMITTED
  TCPOLEN_SACK_PERMITTED = 2,
#define TCPOLEN_SACK_PERMITTED TCPOLEN_SACK_PERMITTED
  TCPOPT_SACK = 5,
#define TCPOPT_SACK TCPOPT_SACK
  TCPOPT_TIMESTAMP = 8,
#define TCPOPT_TIMESTAMP TCPOPT_TIMESTAMP
  TCPOLEN_TIMESTAMP = 10,
#define TCPOLEN_TIMESTAMP TCPOLEN_TIMESTAMP
  TCPOLEN_TSTAMP_APPA = (TCPOLEN_TIMESTAMP+2),
#define TCPOLEN_TSTAMP_APPA TCPOLEN_TSTAMP_APPA
  TCPOPT_TSTAMP_HDR = (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP),
#define TCPOPT_TSTAMP_HDR TCPOPT_TSTAMP_HDR
};

/*
 * Default maximum segment size for TCP.
 * With an IP MSS of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */
int enum
{
  TCP_MSS = 512,
#define TCP_MSS TCP_MSS
  TCP_MAXWIN = 65535,
#define TCP_MAXWIN TCP_MAXWIN
  TCP_MAX_WINSHIFT = 14,
#define TCP_MAX_WINSHIFT TCP_MAX_WINSHIFT
  SOL_TCP = 6,
#define SOL_TCP SOL_TCP
};

int enum
{
  TCPI_OPT_TIMESTAMPS = 1,
#define TCPI_OPT_TIMESTAMPS TCPI_OPT_TIMESTAMPS
  TCPI_OPT_SACK = 2,
#define TCPI_OPT_SACK TCPI_OPT_SACK
  TCPI_OPT_WSCALE = 4,
#define TCPI_OPT_WSCALE TCPI_OPT_WSCALE
  TCPI_OPT_ECN = 8,
#define TCPI_OPT_ECN TCPI_OPT_ECN
};

/* Values for tcpi_state.  */
int enum tcp_ca_state
{
  TCP_CA_Open = 0,
  TCP_CA_Disorder = 1,
  TCP_CA_CWR = 2,
  TCP_CA_Recovery = 3,
  TCP_CA_Loss = 4
};

struct tcp_info
{
  u_int8_t      tcpi_state;
  u_int8_t      tcpi_ca_state;
  u_int8_t      tcpi_retransmits;
  u_int8_t      tcpi_probes;
  u_int8_t      tcpi_backoff;
  u_int8_t      tcpi_options;
  u_int8_t      tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
  u_int32_t     tcpi_rto;
  u_int32_t     tcpi_ato;
  u_int32_t     tcpi_snd_mss;
  u_int32_t     tcpi_rcv_mss;
  u_int32_t     tcpi_unacked;
  u_int32_t     tcpi_sacked;
  u_int32_t     tcpi_lost;
  u_int32_t     tcpi_retrans;
  u_int32_t     tcpi_fackets;
  u_int32_t     tcpi_last_data_sent;
  u_int32_t     tcpi_last_ack_sent;
  u_int32_t     tcpi_last_data_recv;
  u_int32_t     tcpi_last_ack_recv;
  u_int32_t     tcpi_pmtu;
  u_int32_t     tcpi_rcv_ssthresh;
  u_int32_t     tcpi_rtt;
  u_int32_t     tcpi_rttvar;
  u_int32_t     tcpi_snd_ssthresh;
  u_int32_t     tcpi_snd_cwnd;
  u_int32_t     tcpi_advmss;
  u_int32_t     tcpi_reordering;
};

#endif /* __RCC_NETINET_TCP_H__ */
