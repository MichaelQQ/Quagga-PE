
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_FIB_IMPL_H_
#define _MPLS_FIB_IMPL_H_

#include "mpls_struct.h"

/*
 * in: handle, cfg, callback, 
 * return: mpls_fib_handle
 */
extern mpls_fib_handle mpls_fib_open(const mpls_instance_handle handle,
  const mpls_cfg_handle cfg);

/*
 * in: handle
 */
extern void mpls_fib_close(mpls_fib_handle handle);

/*
 * in: handle,num_entry,dest,entry
 * out: entry
 * return: int (number of routes returned in entry)
 */
extern int mpls_fib_get_route(const mpls_fib_handle handle, const int num_entry,
  const mpls_fec * dest, mpls_fec * entry);

/*
 * in: handle,num_entry,dest,entry
 * out: entry
 * return: int (number of routes returned in entry)
 */
extern int mpls_fib_get_best_route(const mpls_fib_handle handle,
  const int num_entry, const mpls_fec * dest, mpls_fec * entry);

/*
 * in: handle
 * out: fec, nexthop
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_fib_getfirst_route(const mpls_fib_handle handle,
  mpls_fec * fec, mpls_nexthop *nexthop);

/*
 * in: handle, fec, nexthop
 * out: fec, nexthop
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_fib_getnext_route(const mpls_fib_handle handle,
  mpls_fec * fec, mpls_nexthop *nexthop);

/*
 * in: handle, fec, owner, data
 * out:
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_fib_set_data(mpls_fib_handle handle, mpls_fec *fec,
  mpls_owners_enum owner, void *data);

/*
 * in: handle, fec, owner
 * out: data
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_fib_get_data(mpls_fib_handle handle, mpls_fec *fec,
  mpls_owners_enum owner, void **data);

#endif
