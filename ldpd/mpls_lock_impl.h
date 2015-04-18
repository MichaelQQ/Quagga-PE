
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_LOCK_IMPL_H_
#define _MPLS_LOCK_IMPL_H_

#include "mpls_struct.h"

/*
 * in: key
 * return: mpls_lock_handle
 */
extern mpls_lock_handle mpls_lock_create(const mpls_lock_key_type key);

/*
 * in: handle
 */
extern void mpls_lock_get(mpls_lock_handle handle);

/*
 * in: handle
 */
extern void mpls_lock_release(mpls_lock_handle handle);

/*
 * in: handle
 */
extern void mpls_lock_delete(mpls_lock_handle handle);

#endif
