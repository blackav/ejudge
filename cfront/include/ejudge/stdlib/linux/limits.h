/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/limit.h' of the Linux Kernel. */

#ifndef __RCC_LINUX_LIMITS_H__
#define __RCC_LINUX_LIMITS_H__

int enum
{
  NR_OPEN = 1024,
#define NR_OPEN NR_OPEN
  ARG_MAX = 131072,
#define ARG_MAX ARG_MAX
  CHILD_MAX = 999,
#define CHILD_MAX CHILD_MAX
  OPEN_MAX = 256,
#define OPEN_MAX OPEN_MAX
  LINK_MAX = 127,
#define LINK_MAX LINK_MAX
  MAX_CANON = 255,
#define MAX_CANON MAX_CANON
  MAX_INPUT = 255,
#define MAX_INPUT MAX_INPUT
  NAME_MAX = 255,
#define NAME_MAX NAME_MAX
  PATH_MAX = 4096,
#define PATH_MAX PATH_MAX
  PIPE_BUF = 4096,
#define PIPE_BUF PIPE_BUF
  RTSIG_MAX = 32,
#define RTSIG_MAX RTSIG_MAX
};

#ifndef NGROUPS_MAX
int enum
{
#defconst NGROUPS_MAX 32
};
#endif

#endif /* __RCC_LINUX_LIMITS_H__ */
