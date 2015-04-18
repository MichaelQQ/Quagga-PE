
/*
 *  Copyright (C) James R. Leu 2001
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_resource.h"
#include "ldp_tunnel.h"

#include "mpls_assert.h"
#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"

static uint32_t _ldp_resource_next_index = 1;

ldp_resource *ldp_resource_create()
{
  ldp_resource *r = (ldp_resource *) mpls_malloc(sizeof(ldp_resource));

  if (r) {
    memset(r, 0, sizeof(ldp_resource));
    MPLS_REFCNT_INIT(r, 0);
    MPLS_LIST_ELEM_INIT(r, _global);

    r->index = _ldp_resource_get_next_index();
  }
  return r;
}

void ldp_resource_delete(ldp_resource * r)
{
  // LDP_PRINT(g->user_data,"resource delete\n");
  MPLS_REFCNT_ASSERT(r, 0);
  mpls_free(r);
}

uint32_t _ldp_resource_get_next_index()
{
  uint32_t retval = _ldp_resource_next_index;

  _ldp_resource_next_index++;
  if (retval > _ldp_resource_next_index) {
    _ldp_resource_next_index = 1;
  }
  return retval;
}

mpls_return_enum _ldp_resource_add_tunnel(ldp_resource * r, ldp_tunnel * t)
{
  if (r && t) {
    MPLS_REFCNT_HOLD(t);
    r->tunnel = t;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum _ldp_resource_del_tunnel(ldp_resource * r)
{
  if (r && r->tunnel) {
    MPLS_REFCNT_RELEASE(r->tunnel, ldp_tunnel_delete);
    r->tunnel = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_bool ldp_resource_in_use(ldp_resource * r)
{
  if (r->tunnel && (r->tunnel->admin_state == MPLS_ADMIN_ENABLE)) {
    return MPLS_BOOL_TRUE;
  }
  return MPLS_BOOL_FALSE;
}
