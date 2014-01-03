/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_TYPES_H__
#define __RCC_SYS_TYPES_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

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

typedef unsigned int dev_t;
typedef unsigned int __dev_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int id_t;
typedef unsigned long ino_t;
typedef unsigned long __ino_t;
typedef unsigned int mode_t;
typedef unsigned int nlink_t;
typedef int pid_t;
typedef long time_t;
typedef long clock_t;
typedef int key_t;

typedef long blkcnt_t;
typedef long long blkcnt64_t;

typedef unsigned long fsblkcnt_t;
typedef unsigned long long fsblkcnt64_t;

typedef unsigned long fsfilcnt_t;
typedef unsigned long long fsfilcnt64_t;

typedef unsigned long ino64_t;

typedef long int rlim_t;
typedef long long rlim64_t;

typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned long u_long;
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;


typedef unsigned long long u_int64_t;

typedef long long quad_t;
typedef unsigned long long u_quad_t;

typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned long ulong;
typedef char *__caddr_t;
typedef char * caddr_t;
typedef int __daddr_t;
typedef int daddr_t;

#ifndef RCC_SIZE_T_DEFINED
#define RCC_SIZE_T_DEFINED 1
typedef unsigned long size_t;
#endif /* RCC_SIZE_T_DEFINED */

#ifndef RCC_SSIZE_T_DEFINED
#define RCC_SSIZE_T_DEFINED 1
typedef long ssize_t;
#endif /* RCC_SSIZE_T_DEFINED */

#ifndef __ptr_t
#define __ptr_t void *
#endif

#ifndef __RCC_OFF_T_DEFINED__
#define __RCC_OFF_T_DEFINED__
typedef long off_t;
#endif

#ifndef __RCC_LOFF_T_DEFINED__
#define __RCC_LOFF_T_DEFINED__
typedef long long loff_t;
typedef loff_t off64_t;
#endif /* __RCC_LOFF_T_DEFINED__ */

#if !defined __RCC_INTX_T_DEFINED__
#define __RCC_INTX_T_DEFINED__ 1
typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned           uint32_t;
typedef unsigned long long uint64_t;
#endif /* __RCC_INTX_T_DEFINED__ */

#include <sys/select.h>
typedef int __SWORD_TYPE;

typedef unsigned int  __fsblkcnt_t;
typedef unsigned int  __fsfilcnt_t;
typedef unsigned long long  __fsblkcnt64_t;
typedef unsigned long long  __fsfilcnt64_t;

typedef  struct { int __val[2]; } __fsid_t;

#endif /* __RCC_SYS_TYPES_H__ */
