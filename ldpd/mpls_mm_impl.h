
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_MM_IMPL_H_
#define _MPLS_MM_IMPL_H_

#include "mpls_struct.h"

/*
 * in: size
 * return: void*
 */
extern void *mpls_malloc(const mpls_size_type size);

/*
 * in: mem
 */
extern void mpls_free(void *mem);

#endif
