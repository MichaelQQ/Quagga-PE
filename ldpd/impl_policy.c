#include <zebra.h>

#include "ldp_struct.h"
#include "ldp_interface.h"
#include "ldp_zebra.h"
#include "impl_fib.h"
#include "table.h"

mpls_bool mpls_policy_import_check(mpls_instance_handle handle, mpls_fec * f,
  ldp_addr * nh)
{
  return MPLS_BOOL_TRUE;
}

mpls_bool mpls_policy_ingress_check(mpls_instance_handle handle, mpls_fec * f, ldp_addr * nh)
{
  return MPLS_BOOL_TRUE;
}

mpls_bool mpls_policy_egress_check(mpls_instance_handle handle, mpls_fec * fec,
  mpls_nexthop *nexthop)
{
  struct ldp *ldp = handle;
  int result = MPLS_BOOL_FALSE;

  switch(ldp->egress) {
    case LDP_EGRESS_ALL:
    {
      result = MPLS_BOOL_TRUE;
      break;
    }
    case LDP_EGRESS_LSRID:
    {
      if (lookup_fec_nexthop(fec, nexthop)) {
         result = MPLS_BOOL_TRUE;
      }
      break;
    }
    case LDP_EGRESS_CONNECTED:
    {
      result = is_fec_attached(fec, nexthop);
      break;
    }
    default:
      break;
  }
  return result;
}

mpls_bool mpls_policy_export_check(mpls_instance_handle handle, mpls_fec  * f, ldp_addr * nh)
{
  return MPLS_BOOL_TRUE;
}

mpls_bool mpls_policy_address_export_check(mpls_instance_handle handle,
  mpls_inet_addr *addr) {
  struct ldp *ldp = handle;
  mpls_bool flag = MPLS_BOOL_FALSE; 
  struct interface *ifp;
  struct in_addr in;

  in.s_addr = htonl(addr->u.ipv4);


  switch (ldp->address) {
    case LDP_ADDRESS_LDP:
      if ((ifp = if_lookup_exact_address(in)) && 
         (struct ldp_interface*)(ifp->info)) {
        flag = MPLS_BOOL_TRUE;
      }
      /* fall through */
    case LDP_ADDRESS_LSRID:
      if (in.s_addr == router_id.u.prefix4.s_addr) {
        flag = MPLS_BOOL_TRUE;
      }
      break;
    case LDP_ADDRESS_ALL:
      flag = MPLS_BOOL_TRUE;
      break;
  }
  return flag;
}
