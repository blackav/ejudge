/* -*- mode: c -*- */
/* $Id$ */

#ifndef __REUSE_FP_PROPS_H__
#define __REUSE_FP_PROPS_H__

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

void reuse_set_zero_ld(int, long double *);
void reuse_set_infinity_ld(int, long double *);
void reuse_set_nan_ld(long double *);
int reuse_get_sign_bit_ld(const long double *);
int reuse_is_infinity_ld(const long double *);
int reuse_is_nan_ld(const long double *);

void reuse_set_zero_f(int, float *);
void reuse_set_infinity_f(int, float *);
void reuse_set_nan_f(float *);
int reuse_get_sign_bit_f(const float *);
int reuse_is_infinity_f(const float *);
int reuse_is_nan_f(const float *);

void reuse_set_zero_d(int, double *);
void reuse_set_infinity_d(int, double *);
void reuse_set_nan_d(double *);
int reuse_get_sign_bit_d(const double *);
int reuse_is_infinity_d(const double *);
int reuse_is_nan_d(const double *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_FP_PROPS_H__ */
