/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/if_slip.h' of the Linux Kernel.
   The original copyright follows. */

/*
 *      Swansea University Computer Society     NET3
 *      
 *      This file declares the constants of special use with the SLIP/CSLIP/
 *      KISS TNC driver.
 */
 
#ifndef __RCC_LINUX_SLIP_H__
#define __RCC_LINUX_SLIP_H__

int enum
{
  SL_MODE_SLIP = 0,
#define SL_MODE_SLIP SL_MODE_SLIP
  SL_MODE_CSLIP = 1,
#define SL_MODE_CSLIP SL_MODE_CSLIP
  SL_MODE_KISS = 4,
#define SL_MODE_KISS SL_MODE_KISS
  SL_OPT_SIXBIT = 2,
#define SL_OPT_SIXBIT SL_OPT_SIXBIT
  SL_OPT_ADAPTIVE = 8,
#define SL_OPT_ADAPTIVE SL_OPT_ADAPTIVE
};

/*
 *      VSV = ioctl for keepalive & outfill in SLIP driver 
 */

int enum
{ 
  SIOCSKEEPALIVE = (SIOCDEVPRIVATE),
#define SIOCSKEEPALIVE SIOCSKEEPALIVE
  SIOCGKEEPALIVE = (SIOCDEVPRIVATE+1),
#define SIOCGKEEPALIVE SIOCGKEEPALIVE
  SIOCSOUTFILL = (SIOCDEVPRIVATE+2),
#define SIOCSOUTFILL SIOCSOUTFILL
  SIOCGOUTFILL = (SIOCDEVPRIVATE+3),
#define SIOCGOUTFILL SIOCGOUTFILL
  SIOCSLEASE = (SIOCDEVPRIVATE+4),
#define SIOCSLEASE SIOCSLEASE
  SIOCGLEASE = (SIOCDEVPRIVATE+5),
#define SIOCGLEASE SIOCGLEASE
};

#endif /* __RCC_LINUX_SLIP_H__ */
