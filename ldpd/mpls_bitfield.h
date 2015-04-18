/*
 *  Copyright (C) James R. Leu 2003
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef MPLS_BITFIELD_H
#define MPLS_BITFILED_H

#include <endian.h>

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#define LITTLE_ENDIAN_BYTE_ORDER 1
#endif

/* macros to handle different byte orders (little endian or big endian) */
#ifdef LITTLE_ENDIAN_BYTE_ORDER
#define BITFIELDS_ASCENDING_2(X, Y)                Y; X;
#define BITFIELDS_ASCENDING_3(X, Y, Z)             Z; Y; X;
#define BITFIELDS_ASCENDING_4(X, Y, Z, W)          W; Z; Y; X;
#define BITFIELDS_ASCENDING_7(X, Y, Z, W, U, A, B) B; A; U; W; Z; Y; X;
# else
#define BITFIELDS_ASCENDING_2(X, Y)                X; Y;
#define BITFIELDS_ASCENDING_3(X, Y, Z)             X; Y; Z;
#define BITFIELDS_ASCENDING_4(X, Y, Z, W)          X; Y; Z; W;
#define BITFIELDS_ASCENDING_7(X, Y, Z, W, U, A, B) X; Y; Z; W; U; A; B;
#endif /* LITTLE_ENDIAN_BYTE_ORDER */

#endif
