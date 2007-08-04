/* -*- c -*- */
/* $Id$ */
#ifndef __TSC_H__
#define __TSC_H__

/* Copyright (C) 2003,2005 Alexander Chernov <cher@ispras.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ej_types.h"

/* taken from linux/include/asm-i386/msr.h */
/* corresponds to the kernel 2.6.22.1 */

#if defined __i386__
static inline unsigned long long native_read_tsc(void)
{
        unsigned long long val;
        asm volatile("rdtsc" : "=A" (val));
        return val;
}
#define rdtscll(val) ((val) = native_read_tsc())
#elif defined __x86_64__
#define rdtscll(val) do { \
     unsigned int __a,__d; \
     asm volatile("rdtsc" : "=a" (__a), "=d" (__d)); \
     (val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
} while(0)
#else
#define rdtscll(val) ((val) = 0)
#endif

extern ej_tsc_t cpu_frequency;

int tsc_init(void);

#endif /* __TSC_H__ */

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
