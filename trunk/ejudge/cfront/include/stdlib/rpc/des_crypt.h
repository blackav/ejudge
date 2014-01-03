/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/des_crypt.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/*
 * @(#)des_crypt.h      2.1 88/08/11 4.0 RPCSRC;        from 1.4 88/02/08 (C) 1986 SMI
 *
 * des_crypt.h, des library routine interface
 * Copyright (C) 1986, Sun Microsystems, Inc.
 */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 *
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

#ifndef __RCC_RPC_DES_CRYPT_H__
#define __RCC_RPC_DES_CRYPT_H__ 1

#include <features.h>

int enum
{
  DES_MAXDATA = 8192,
#define DES_MAXDATA DES_MAXDATA
  DES_DIRMASK = (1 << 0),
#define DES_DIRMASK DES_DIRMASK
  DES_ENCRYPT = (0*DES_DIRMASK),
#define DES_ENCRYPT DES_ENCRYPT
  DES_DECRYPT = (1*DES_DIRMASK),
#define DES_DECRYPT DES_DECRYPT
  DES_DEVMASK = (1 << 1),
#define DES_DEVMASK DES_DEVMASK
  DES_HW = (0*DES_DEVMASK),
#define DES_HW DES_HW
  DES_SW = (1*DES_DEVMASK),
#define DES_SW DES_SW
  DESERR_NONE = 0,
#define DESERR_NONE DESERR_NONE
  DESERR_NOHWDEVICE = 1,
#define DESERR_NOHWDEVICE DESERR_NOHWDEVICE
  DESERR_HWERROR = 2,
#define DESERR_HWERROR DESERR_HWERROR
  DESERR_BADPARAM = 3,
#define DESERR_BADPARAM DESERR_BADPARAM
};

#define DES_FAILED(err) \
        ((err) > DESERR_NOHWDEVICE)

/*
 * cbc_crypt()
 * ecb_crypt()
 *
 * Encrypt (or decrypt) len bytes of a buffer buf.
 * The length must be a multiple of eight.
 * The key should have odd parity in the low bit of each byte.
 * ivec is the input vector, and is updated to the new one (cbc only).
 * The mode is created by oring together the appropriate parameters.
 * DESERR_NOHWDEVICE is returned if DES_HW was specified but
 * there was no hardware to do it on (the data will still be
 * encrypted though, in software).
 */

int cbc_crypt(char *key, char *buf, unsigned len, unsigned mode, char *ivec);
int ecb_crypt(char *key, char *buf, unsigned len, unsigned mode);
void des_setparity(char *key);

#endif /* __RCC_RPC_DES_CRYPT_H__ */
