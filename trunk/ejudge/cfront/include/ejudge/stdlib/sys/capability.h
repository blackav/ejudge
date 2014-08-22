/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `sys/capability.h' of the libcap library.
   The original copyright follows. */

/*
 * <sys/capability.h>
 *
 * 
 * Copyright (C) 1997   Aleph One
 * Copyright (C) 1997-8 Andrew G. Morgan <morgan@linux.kernel.org>
 *
 * defunct POSIX.1e Standard: 25.2 Capabilities           <sys/capability.h>
 */

#ifndef __RCC_SYS_CAPABILITY_H__
#define __RCC_SYS_CAPABILITY_H__

/*
 * This file complements the kernel file by providing prototype
 * information for the user library.
 */
#include <sys/types.h>
#include <linux/capability.h>

/*
 * POSIX capability types
 */

/*
 * Opaque capability handle (defined internally by libcap)
 * internal capability representation
 */
typedef struct _cap_struct *cap_t;

/* "external" capability representation is a (void *) */

/*
 * This is the type used to identify capabilities
 */

typedef int cap_value_t;

/*
 * Set identifiers
 */
int enum
{
  CAP_EFFECTIVE = 0,
  CAP_PERMITTED = 1,
  CAP_INHERITABLE = 2
};
typedef int cap_flag_t;

/*
 * These are the states available to each capability
 */
int enum
{
    CAP_CLEAR = 0,
    CAP_SET = 1
};
typedef int cap_flag_value_t;

/*
 * User-space capability manipulation routines
 */

/* libcap/cap_alloc.c */
cap_t   cap_dup(cap_t);
int     cap_free(void *);
cap_t   cap_init(void);

/* libcap/cap_flag.c */
int     cap_get_flag(cap_t, cap_value_t, cap_flag_t, cap_flag_value_t *);
int     cap_set_flag(cap_t, cap_flag_t, int, cap_value_t *, cap_flag_value_t);
int     cap_clear(cap_t);

/* libcap/cap_file.c */
cap_t   cap_get_fd(int);
cap_t   cap_get_file(const char *);
int     cap_set_fd(int, cap_t);
int     cap_set_file(const char *, cap_t);

/* libcap/cap_proc.c */
cap_t   cap_get_proc(void);
int     cap_set_proc(cap_t);

/* libcap/cap_extint.c */
ssize_t cap_size(cap_t);
ssize_t cap_copy_ext(void *, cap_t, ssize_t);
cap_t   cap_copy_int(const void *);

/* libcap/cap_text.c */
cap_t   cap_from_text(const char *);
char *  cap_to_text(cap_t, ssize_t *);

/*
 * Linux capability system calls: defined in libcap but only available
 * if the following _POSIX_SOURCE is _undefined_
 */

extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);
extern int capgetp(pid_t pid, cap_t cap_d);
extern int capsetp(pid_t pid, cap_t cap_d);
extern char const *_cap_names[];

#endif /* __RCC_SYS_CAPABILITY_H__ */
