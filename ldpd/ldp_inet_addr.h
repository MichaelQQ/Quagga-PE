
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_INET_ADDR_H_
#define _LDP_INET_ADDR_H_

extern mpls_inet_addr *mpls_inet_addr_create();
extern mpls_bool mpls_inet_addr_is_equal(mpls_inet_addr *, mpls_inet_addr *);
extern int mpls_inet_addr_compare(mpls_inet_addr *, mpls_inet_addr *);

#endif
