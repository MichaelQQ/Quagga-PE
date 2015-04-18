#include <zebra.h>
#include "if.h"

#include "ldp.h"
#include "ldp_struct.h"

static int opened = 0;

mpls_ifmgr_handle mpls_ifmgr_open(mpls_instance_handle handle,
  mpls_cfg_handle cfg)
{
  opened = 1;
  return 0xdeadbeef;
}

void mpls_ifmgr_close(mpls_ifmgr_handle ifmgr_handle)
{
  opened = 0;
}

mpls_return_enum mpls_ifmgr_get_mtu(mpls_ifmgr_handle ifmgr_handle,
  mpls_if_handle if_handle, int *mtu)
{
  *mtu = if_handle->mtu;
  return MPLS_SUCCESS;
}

mpls_return_enum mpls_ifmgr_get_name(const mpls_ifmgr_handle handle,
  const mpls_if_handle if_handle, char *name, int len)
{
  strncpy(name, if_handle->name, len);
  return MPLS_SUCCESS;
}

mpls_return_enum mpls_ifmgr_getnext_address(mpls_ifmgr_handle ifmgr_handle,
  mpls_if_handle *handle, mpls_inet_addr *addr)
{
  struct connected *ifc;
  listnode node;
  int next = 0;

  while ((*handle)) {
    for (node = listhead((*handle)->connected); node; nextnode(node)) {
      ifc = getdata(node);
      if (ifc->address->family == AF_INET &&
	ifc->address->u.prefix4.s_addr != htonl(INADDR_LOOPBACK)) {
        if (next) {
          addr->type = MPLS_FAMILY_IPV4;
          addr->u.ipv4 = ntohl(ifc->address->u.prefix4.s_addr);
          return MPLS_SUCCESS;
        } else if (addr->u.ipv4 == ntohl(ifc->address->u.prefix4.s_addr)) {
          next = 1;
        }
      }
    }
    (*handle) = if_getnext(*handle);
    next = 1;
  }
  return MPLS_END_OF_LIST;
}

mpls_return_enum mpls_ifmgr_getfirst_address(mpls_ifmgr_handle ifmgr_handle,
  mpls_if_handle *handle, mpls_inet_addr *addr)
{
  struct connected *ifc;
  listnode node;

  (*handle) = if_getfirst();
  while ((*handle)) {
    for (node = listhead((*handle)->connected); node; nextnode(node)) {
      ifc = getdata(node);
      if (ifc->address->family == AF_INET &&
	ifc->address->u.prefix4.s_addr != htonl(INADDR_LOOPBACK)) {
        addr->type = MPLS_FAMILY_IPV4;
        addr->u.ipv4 = ntohl(ifc->address->u.prefix4.s_addr);
        return MPLS_SUCCESS;
      }
    }
    (*handle) = if_getnext(*handle);
  }
  return MPLS_END_OF_LIST;
}
