
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_POLICY_IMPL_H_
#define _MPLS_POLICY_IMPL_H_

extern mpls_bool mpls_policy_import_check(mpls_instance_handle handle,
  mpls_fec * f, mpls_nexthop * nh);
extern mpls_bool mpls_policy_ingress_check(mpls_instance_handle handle,
  mpls_fec * f, mpls_nexthop * nh);
extern mpls_bool mpls_policy_egress_check(mpls_instance_handle handle,
  mpls_fec * p, mpls_nexthop *nh);
extern mpls_bool mpls_policy_export_check(mpls_instance_handle handle,
  mpls_fec * p, mpls_nexthop * nh);
extern mpls_bool mpls_policy_address_export_check(mpls_instance_handle handle,
  mpls_inet_addr * addr);

#endif
