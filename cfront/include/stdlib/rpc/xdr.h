/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `rpc/xdr.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

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

/*
 * xdr.h, External Data Representation Serialization Routines.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#ifndef __RCC_RPC_XDR_H__
#define __RCC_RPC_XDR_H__ 1

#include <features.h>
#include <sys/types.h>
#include <rpc/types.h>
#include <stdio.h>

/*
 * XDR provides a conventional way for converting between C data
 * types and an external bit-string representation.  Library supplied
 * routines provide for the conversion on built-in C data types.  These
 * routines and utility routines defined here are used to help implement
 * a type encode/decode routine for each user-defined type.
 *
 * Each data type provides a single procedure which takes two arguments:
 *
 *      bool_t
 *      xdrproc(xdrs, argresp)
 *              XDR *xdrs;
 *              <type> *argresp;
 *
 * xdrs is an instance of a XDR handle, to which or from which the data
 * type is to be converted.  argresp is a pointer to the structure to be
 * converted.  The XDR handle contains an operation field which indicates
 * which of the operations (ENCODE, DECODE * or FREE) is to be performed.
 *
 * XDR_DECODE may allocate space if the pointer argresp is null.  This
 * data can be freed with the XDR_FREE operation.
 *
 * We write only one procedure per data type to make it easy
 * to keep the encode and decode procedures for a data type consistent.
 * In many cases the same code performs all operations on a user defined type,
 * because all the hard work is done in the component type routines.
 * decode as a series of calls on the nested data types.
 */

/*
 * Xdr operations.  XDR_ENCODE causes the type to be encoded into the
 * stream.  XDR_DECODE causes the type to be extracted from the stream.
 * XDR_FREE can be used to release the space allocated by an XDR_DECODE
 * request.
 */
int enum xdr_op
{
  XDR_ENCODE = 0,
  XDR_DECODE = 1,
  XDR_FREE = 2
};

/*
 * This is the number of bytes per unit of external data.
 */
#define BYTES_PER_XDR_UNIT      (4)

/*
 * This only works if the above is a power of 2.  But it's defined to be
 * 4 by the appropriate RFCs.  So it will work.  And it's normally quicker
 * than the old routine.
 */
#define RNDUP(x)  (((x) + BYTES_PER_XDR_UNIT - 1) & ~(BYTES_PER_XDR_UNIT - 1))
#else /* this is the old routine */
#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
                    * BYTES_PER_XDR_UNIT)

/*
 * The XDR handle.
 * Contains operation which is being applied to the stream,
 * an operations vector for the particular implementation (e.g. see xdr_mem.c),
 * and two private fields for the use of the particular implementation.
 */
typedef struct XDR XDR;
struct XDR
{
  enum xdr_op x_op;
  struct xdr_ops
  {
    bool_t (*x_getlong)(XDR *xdrs, long *lp);
    bool_t (*x_putlong)(XDR *xdrs, const long *lp);
    bool_t (*x_getbytes)(XDR *xdrs, caddr_t addr, u_int len);
    bool_t (*x_putbytes)(XDR *xdrs, const char *addr, u_int len);
    u_int (*x_getpostn)(const XDR *xdrs);
    bool_t (*x_setpostn)(XDR *xdrs, u_int pos);
    int32_t *(*x_inline)(XDR *xdrs, u_int len);
    void (*x_destroy)(XDR *xdrs);
    bool_t (*x_getint32)(XDR *xdrs, int32_t *ip);
    bool_t (*x_putint32)(XDR *xdrs, const int32_t *ip);
  } *x_ops;
  caddr_t x_public;
  caddr_t x_private;
  caddr_t x_base;
  u_int x_handy;
};

/*
 * A xdrproc_t exists for each data type which is to be encoded or decoded.
 *
 * The second argument to the xdrproc_t is a pointer to an opaque pointer.
 * The opaque pointer generally points to a structure of the data type
 * to be decoded.  If this pointer is 0, then the type routines should
 * allocate dynamic storage of the appropriate size and return it.
 * bool_t       (*xdrproc_t)(XDR *, caddr_t *);
 */
typedef bool_t (*xdrproc_t)(XDR *, void *,...);


/*
 * Operations defined on a XDR handle
 *
 * XDR          *xdrs;
 * int32_t      *int32p;
 * long         *longp;
 * caddr_t       addr;
 * u_int         len;
 * u_int         pos;
 */
#define XDR_GETINT32(xdrs, int32p)                      \
        (*(xdrs)->x_ops->x_getint32)(xdrs, int32p)
#define xdr_getint32(xdrs, int32p)                      \
        (*(xdrs)->x_ops->x_getint32)(xdrs, int32p)

#define XDR_PUTINT32(xdrs, int32p)                      \
        (*(xdrs)->x_ops->x_putint32)(xdrs, int32p)
#define xdr_putint32(xdrs, int32p)                      \
        (*(xdrs)->x_ops->x_putint32)(xdrs, int32p)

#define XDR_GETLONG(xdrs, longp)                        \
        (*(xdrs)->x_ops->x_getlong)(xdrs, longp)
#define xdr_getlong(xdrs, longp)                        \
        (*(xdrs)->x_ops->x_getlong)(xdrs, longp)

#define XDR_PUTLONG(xdrs, longp)                        \
        (*(xdrs)->x_ops->x_putlong)(xdrs, longp)
#define xdr_putlong(xdrs, longp)                        \
        (*(xdrs)->x_ops->x_putlong)(xdrs, longp)

#define XDR_GETBYTES(xdrs, addr, len)                   \
        (*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)
#define xdr_getbytes(xdrs, addr, len)                   \
        (*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)

#define XDR_PUTBYTES(xdrs, addr, len)                   \
        (*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)
#define xdr_putbytes(xdrs, addr, len)                   \
        (*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)

#define XDR_GETPOS(xdrs)                                \
        (*(xdrs)->x_ops->x_getpostn)(xdrs)
#define xdr_getpos(xdrs)                                \
        (*(xdrs)->x_ops->x_getpostn)(xdrs)

#define XDR_SETPOS(xdrs, pos)                           \
        (*(xdrs)->x_ops->x_setpostn)(xdrs, pos)
#define xdr_setpos(xdrs, pos)                           \
        (*(xdrs)->x_ops->x_setpostn)(xdrs, pos)

#define XDR_INLINE(xdrs, len)                           \
        (*(xdrs)->x_ops->x_inline)(xdrs, len)
#define xdr_inline(xdrs, len)                           \
        (*(xdrs)->x_ops->x_inline)(xdrs, len)

#define XDR_DESTROY(xdrs)                                       \
        do {                                                    \
                if ((xdrs)->x_ops->x_destroy)                   \
                        (*(xdrs)->x_ops->x_destroy)(xdrs);      \
        } while (0)
#define xdr_destroy(xdrs)                                       \
        do {                                                    \
                if ((xdrs)->x_ops->x_destroy)                   \
                        (*(xdrs)->x_ops->x_destroy)(xdrs);      \
        } while (0)

/*
 * Support struct for discriminated unions.
 * You create an array of xdrdiscrim structures, terminated with
 * a entry with a null procedure pointer.  The xdr_union routine gets
 * the discriminant value and then searches the array of structures
 * for a matching value.  If a match is found the associated xdr routine
 * is called to handle that part of the union.  If there is
 * no match, then a default routine may be called.
 * If there is no match and no default routine it is an error.
 */
#define NULL_xdrproc_t ((xdrproc_t)0)
struct xdr_discrim
{
  int value;
  xdrproc_t proc;
};

/*
 * Inline routines for fast encode/decode of primitive data types.
 * Caveat emptor: these use single memory cycles to get the
 * data from the underlying buffer, and will fail to operate
 * properly if the data is not aligned.  The standard way to use these
 * is to say:
 *      if ((buf = XDR_INLINE(xdrs, count)) == NULL)
 *              return (FALSE);
 *      <<< macro calls >>>
 * where ``count'' is the number of bytes of data occupied
 * by the primitive data types.
 *
 * N.B. and frozen for all time: each data type here uses 4 bytes
 * of external representation.
 */

#define IXDR_GET_INT32(buf)           ((int32_t)ntohl((uint32_t)*(buf)++))
#define IXDR_PUT_INT32(buf, v)        (*(buf)++ = (int32_t)htonl((uint32_t)(v)))
#define IXDR_GET_U_INT32(buf)         ((uint32_t)IXDR_GET_INT32(buf))
#define IXDR_PUT_U_INT32(buf, v)      IXDR_PUT_INT32(buf, (int32_t)(v))

/* WARNING: The IXDR_*_LONG defines are removed by Sun for new platforms
 * and shouldn't be used any longer. Code which use this defines or longs
 * in the RPC code will not work on 64bit Solaris platforms !
 */
#define IXDR_GET_LONG(buf) \
        ((long)ntohl((u_long)*__extension__((u_int32_t*)(buf))++))
#define IXDR_PUT_LONG(buf, v) \
        (*__extension__((u_int32_t*)(buf))++ = (long)htonl((u_long)(v)))
#define IXDR_GET_U_LONG(buf)          ((u_long)IXDR_GET_LONG(buf))
#define IXDR_PUT_U_LONG(buf, v)       IXDR_PUT_LONG(buf, (long)(v))


#define IXDR_GET_BOOL(buf)            ((bool_t)IXDR_GET_LONG(buf))
#define IXDR_GET_ENUM(buf, t)         ((t)IXDR_GET_LONG(buf))
#define IXDR_GET_SHORT(buf)           ((short)IXDR_GET_LONG(buf))
#define IXDR_GET_U_SHORT(buf)         ((u_short)IXDR_GET_LONG(buf))

#define IXDR_PUT_BOOL(buf, v)         IXDR_PUT_LONG(buf, (long)(v))
#define IXDR_PUT_ENUM(buf, v)         IXDR_PUT_LONG(buf, (long)(v))
#define IXDR_PUT_SHORT(buf, v)        IXDR_PUT_LONG(buf, (long)(v))
#define IXDR_PUT_U_SHORT(buf, v)      IXDR_PUT_LONG(buf, (long)(v))

/*
 * These are the "generic" xdr routines.
 * None of these can have const applied because it's not possible to
 * know whether the call is a read or a write to the passed parameter
 * also, the XDR structure is always updated by some of these calls.
 */
bool_t xdr_void(void);
bool_t xdr_short(XDR *xdrs, short *sp);
bool_t xdr_u_short(XDR *xdrs, u_short *usp);
bool_t xdr_int(XDR *xdrs, int *ip);
bool_t xdr_u_int(XDR *xdrs, u_int *up);
bool_t xdr_long(XDR *xdrs, long *lp);
bool_t xdr_u_long(XDR *xdrs, u_long *ulp);
bool_t xdr_hyper(XDR *xdrs, quad_t *llp);
bool_t xdr_u_hyper(XDR *xdrs, u_quad_t *ullp);
bool_t xdr_longlong_t(XDR *xdrs, quad_t *llp);
bool_t xdr_u_longlong_t(XDR *xdrs, u_quad_t *ullp);
bool_t xdr_int8_t(XDR *xdrs, int8_t *ip);
bool_t xdr_uint8_t(XDR *xdrs, uint8_t *up);
bool_t xdr_int16_t(XDR *xdrs, int16_t *ip);
bool_t xdr_uint16_t(XDR *xdrs, uint16_t *up);
bool_t xdr_int32_t(XDR *xdrs, int32_t *ip);
bool_t xdr_uint32_t(XDR *xdrs, uint32_t *up);
bool_t xdr_int64_t(XDR *xdrs, int64_t *ip);
bool_t xdr_uint64_t(XDR *xdrs, uint64_t *up);
bool_t xdr_bool(XDR *xdrs, bool_t *bp);
bool_t xdr_enum(XDR *xdrs, enum_t *ep);
bool_t xdr_array(XDR * _xdrs, caddr_t *addrp, u_int *sizep,
                 u_int maxsize, u_int elsize, xdrproc_t elproc);
bool_t xdr_bytes(XDR *xdrs, char **cpp, u_int *sizep, u_int maxsize);
bool_t xdr_opaque(XDR *xdrs, caddr_t cp, u_int cnt);
bool_t xdr_string(XDR *xdrs, char **cpp, u_int maxsize);
bool_t xdr_union(XDR *xdrs, enum_t *dscmp, char *unp,
                 const struct xdr_discrim *choices, xdrproc_t dfault);
bool_t xdr_char(XDR *xdrs, char *cp);
bool_t xdr_u_char(XDR *xdrs, u_char *cp);
bool_t xdr_vector(XDR *xdrs, char *basep, u_int nelem,
                  u_int elemsize, xdrproc_t xdr_elem);
bool_t xdr_float(XDR *xdrs, float *fp);
bool_t xdr_double(XDR *xdrs, double *dp);
bool_t xdr_reference(XDR *xdrs, caddr_t *xpp, u_int size, xdrproc_t proc);
bool_t xdr_pointer(XDR *xdrs, char **objpp,
                   u_int obj_size, xdrproc_t xdr_obj);
bool_t xdr_wrapstring(XDR *xdrs, char **cpp);
u_long xdr_sizeof(xdrproc_t, void *);

/*
 * Common opaque bytes objects used by many rpc protocols;
 * declared here due to commonality.
 */
#define MAX_NETOBJ_SZ 1024
struct netobj
{
  u_int n_len;
  char *n_bytes;
};
typedef struct netobj netobj;
bool_t xdr_netobj(XDR *xdrs, struct netobj *np);

/*
 * These are the public routines for the various implementations of
 * xdr streams.
 */
void xdrmem_create(XDR *xdrs, const caddr_t addr, u_int size, enum xdr_op xop);
void xdrstdio_create(XDR *xdrs, FILE *file, enum xdr_op xop);
void xdrrec_create(XDR *xdrs, u_int sendsize, u_int recvsize,
                   caddr_t tcp_handle, int (*readit)(char *, char *, int),
                   int (*writeit)(char *, char *, int));
bool_t xdrrec_endofrecord(XDR *xdrs, bool_t sendnow);
bool_t xdrrec_skiprecord(XDR *xdrs);
bool_t xdrrec_eof(XDR *xdrs);
void xdr_free(xdrproc_t proc, char *objp);

#endif /* __RCC_RPC_XDR_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "des_block" "XDR" "u_int" "AUTH" "netobj" "u_long" "CLIENT" "u_char" "u_short")
 * End:
 */
