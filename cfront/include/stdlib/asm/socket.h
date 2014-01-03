/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_ASM_SOCKET_H__
#define __RCC_ASM_SOCKET_H__ 1

/* Copyright (C) 2003,2004 Alexander Chernov <cher@ispras.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <features.h>

int enum
{
  FIOSETOWN = 0x8901,
#define FIOSETOWN  FIOSETOWN
  SIOCSPGRP = 0x8902,
#define SIOCSPGRP  SIOCSPGRP
  FIOGETOWN = 0x8903,
#define FIOGETOWN  FIOGETOWN
  SIOCGPGRP = 0x8904,
#define SIOCGPGRP  SIOCGPGRP
  SIOCATMARK = 0x8905,
#define SIOCATMARK SIOCATMARK
  SIOCGSTAMP = 0x8906,
#define SIOCGSTAMP SIOCGSTAMP
};

#include <sys/socket.h>

#endif /* __RCC_ASM_SOCKET_H__ */
