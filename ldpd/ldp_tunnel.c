
/*
 *  Copyright (C) James R. Leu 2001
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_tunnel.h"
#include "ldp_hop_list.h"
#include "ldp_resource.h"
#include "ldp_outlabel.h"

#include "mpls_assert.h"
#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"

static uint32_t _ldp_tunnel_next_index = 1;

ldp_tunnel *ldp_tunnel_create()
{
  ldp_tunnel *t = (ldp_tunnel *) mpls_malloc(sizeof(ldp_tunnel));

  if (t) {
    memset(t, 0, sizeof(ldp_tunnel));
    MPLS_REFCNT_INIT(t, 0);
    MPLS_LIST_ELEM_INIT(t, _global);
    MPLS_LIST_ELEM_INIT(t, _outlabel);

    t->index = _ldp_tunnel_get_next_index();
  }
  return t;
}

void ldp_tunnel_delete(ldp_tunnel * t)
{
  // LDP_PRINT(g->user_data,"tunnel delete\n");
  MPLS_REFCNT_ASSERT(t, 0);
  mpls_free(t);
}

uint32_t _ldp_tunnel_get_next_index()
{
  uint32_t retval = _ldp_tunnel_next_index;

  _ldp_tunnel_next_index++;
  if (retval > _ldp_tunnel_next_index) {
    _ldp_tunnel_next_index = 1;
  }
  return retval;
}

mpls_bool ldp_tunnel_is_active(ldp_tunnel * t)
{
  if (t->admin_state == MPLS_ADMIN_ENABLE) {
    return MPLS_BOOL_TRUE;
  }
  return MPLS_BOOL_FALSE;
}

mpls_bool ldp_tunnel_is_ready(ldp_tunnel * t)
{
  return MPLS_BOOL_TRUE;
}

mpls_return_enum ldp_tunnel_add_resource(ldp_tunnel * t, ldp_resource * r)
{
  if (t && r) {
    MPLS_REFCNT_HOLD(r);
    MPLS_ASSERT(t->resource == NULL);
    t->resource = r;
    _ldp_resource_add_tunnel(r, t);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_tunnel_del_resource(ldp_tunnel * t)
{
  if (t && t->resource) {
    _ldp_resource_del_tunnel(t->resource);
    MPLS_REFCNT_RELEASE(t->resource, ldp_resource_delete);
    t->resource = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_tunnel_add_hop_list(ldp_tunnel * t, ldp_hop_list * h)
{
  if (t && h) {
    MPLS_REFCNT_HOLD(h);
    MPLS_ASSERT(t->hop_list == NULL);
    t->hop_list = h;
    _ldp_hop_list_add_tunnel(h, t);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_tunnel_del_hop_list(ldp_tunnel * t)
{
  if (t && t->hop_list) {
    _ldp_hop_list_del_tunnel(t->hop_list);
    MPLS_REFCNT_RELEASE(t->hop_list, ldp_hop_list_delete);
    t->hop_list = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_tunnel_add_outlabel(ldp_tunnel * t, ldp_outlabel * o)
{
  if (t && o) {
    MPLS_REFCNT_HOLD(o);
    MPLS_ASSERT(t->outlabel == NULL);
    t->outlabel = o;
    _ldp_outlabel_add_tunnel(o, t);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_tunnel_del_outlabel(ldp_tunnel * t)
{
  if (t && t->outlabel) {
    _ldp_outlabel_del_tunnel(t->outlabel, t);
    MPLS_REFCNT_RELEASE(t->outlabel, ldp_outlabel_delete);
    t->outlabel = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_tunnel_startup(ldp_global * global, ldp_tunnel * tunnel)
{
  return MPLS_FAILURE;
}

mpls_return_enum ldp_tunnel_shutdown(ldp_global * global, ldp_tunnel * tunnel,
  int flag)
{
  return MPLS_SUCCESS;
}
