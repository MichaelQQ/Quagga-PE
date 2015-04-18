
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_IFMGR_IMPL_H_
#define _MPLS_IFMGR_IMPL_H_

#include "mpls_struct.h"
#include "mpls_handle_type.h"

/*
 * in: handle,cfg
 * return: mpls_ifmgr_handle
 */
extern mpls_ifmgr_handle mpls_ifmgr_open(const mpls_instance_handle handle,
  const mpls_cfg_handle cfg);

/*
 * in: handle
 */
extern void mpls_ifmgr_close(const mpls_ifmgr_handle handle);

/*
 * in: handle,iff,mtu
 * out: mtu
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_ifmgr_get_mtu(const mpls_ifmgr_handle,
  const mpls_if_handle iff, int *mtu);

/*
 * in: handle,iff,name,size
 * out: name
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_ifmgr_get_name(const mpls_ifmgr_handle,
  const mpls_if_handle iff, char *name, int len);

/*
 * in: handle, handle, addr
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_ifmgr_getfirst_address(const mpls_ifmgr_handle,
  mpls_if_handle*, mpls_inet_addr*);

/*
 * in: handle, handle, addr
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_ifmgr_getnext_address(const mpls_ifmgr_handle,
  mpls_if_handle*, mpls_inet_addr*);

#endif
