/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `asm/byteorder.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

#ifndef __RCC_I386_BYTEORDER_H__
#define __RCC_I386_BYTEORDER_H__

//#include <asm/types.h>

unsigned ___arch__swab32(unsigned x);
unsigned short ___arch__swab16(unsigned short x);

#define __arch__swab32(x) ___arch__swab32(x)
#define __arch__swab16(x) ___arch__swab16(x)

//#include <linux/byteorder/little_endian.h>

#endif /* __RCC_I386_BYTEORDER_H__ */
