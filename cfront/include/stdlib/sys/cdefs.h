/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

#ifndef __RCC_SYS_CDEFS__
#define __RCC_SYS_CDEFS__

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

#ifndef __RCC_FEATURES_H__
#include <features.h>
#endif /* __RCC_FEATURES_H__ */

#define __THROW
#define __inline

#define __P(x) x
#define __PMT(x) x

#define __const const
#define __const__ const
#define __signed signed
#define __signed__ signed
#define __volatile volatile
#define __restrict restrict
#define __restrict_arr restrict

#ifndef __ptr_t
#define __ptr_t void *
#endif /* __ptr_t */

#ifndef __long_double_t
#define __long_double_t long double
#endif /* __long_double_t */

#define __attribute__(x)
#define __attribute_malloc__
#define __attribute_pure__
#define __attribute_used__
#define __attribute_noinline__
#define __attribute_deprecated__
#define __attribute_format_arg__(x)
#define __attribute_format_strfmon__(a,b)

#define __extension__

#ifndef __cplusplus
#define __BEGIN_DECLS
#define __END_DECLS
#endif /* __cplusplus */

#define __BEGIN_NAMESPACE_STD
#define __END_NAMESPACE_STD
#define __BEGIN_NAMESPACE_C99
#define __END_NAMESPACE_C99

#endif /* __RCC_SYS_CDEFS__ */
