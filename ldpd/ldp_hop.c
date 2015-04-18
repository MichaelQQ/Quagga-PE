
/*
 *  Copyright (C) James R. Leu 2001
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_hop_list.h"
#include "ldp_hop.h"

#include "mpls_assert.h"
#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"

ldp_hop *ldp_hop_create()
{
  ldp_hop *h = (ldp_hop *) mpls_malloc(sizeof(ldp_hop));

  if (h) {
    memset(h, 0, sizeof(ldp_hop));
    MPLS_REFCNT_INIT(h, 0);
    MPLS_LIST_ELEM_INIT(h, _hop_list);
  }
  return h;
}

void ldp_hop_delete(ldp_hop * h)
{
  // LDP_PRINT(g->user_data,"hop delete\n");
  MPLS_REFCNT_ASSERT(h, 0);
  mpls_free(h);
}

mpls_return_enum _ldp_hop_add_hop_list(ldp_hop * h, ldp_hop_list * hl)
{
  if (h && hl) {
    MPLS_REFCNT_HOLD(hl);
    h->hop_list = hl;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum _ldp_hop_del_hop_list(ldp_hop * h)
{
  if (h && h->hop_list) {
    MPLS_REFCNT_RELEASE(h->hop_list, ldp_hop_list_delete);
    h->hop_list = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_bool ldp_hop_in_use(ldp_hop * h)
{
  if (h->hop_list && h->hop_list->tunnel &&
    (h->hop_list->tunnel->admin_state == MPLS_ADMIN_ENABLE)) {
    return MPLS_BOOL_TRUE;
  }
  return MPLS_BOOL_FALSE;
}
