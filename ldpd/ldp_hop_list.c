
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
#include "ldp_tunnel.h"

#include "mpls_assert.h"
#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"

static uint32_t _ldp_hop_list_next_index = 1;

ldp_hop_list *ldp_hop_list_create()
{
  ldp_hop_list *h = (ldp_hop_list *) mpls_malloc(sizeof(ldp_hop_list));

  if (h) {
    memset(h, 0, sizeof(ldp_hop_list));
    MPLS_REFCNT_INIT(h, 0);
    MPLS_LIST_ELEM_INIT(h, _global);
    MPLS_LIST_INIT(&h->hop, ldp_hop);

    h->index = _ldp_hop_list_get_next_index();
  }
  return h;
}

void ldp_hop_list_delete(ldp_hop_list * h)
{
  // LDP_PRINT(g->user_data,"hop_list delete\n");
  MPLS_REFCNT_ASSERT(h, 0);
  mpls_free(h);
}

uint32_t _ldp_hop_list_get_next_index()
{
  uint32_t retval = _ldp_hop_list_next_index;

  _ldp_hop_list_next_index++;
  if (retval > _ldp_hop_list_next_index) {
    _ldp_hop_list_next_index = 1;
  }
  return retval;
}

mpls_return_enum ldp_hop_list_find_hop_index(ldp_hop_list * hl, uint32_t index,
  ldp_hop ** hop)
{
  ldp_hop *h = NULL;

  if (hl && index > 0) {
    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    h = MPLS_LIST_TAIL(&hl->hop);
    if (h == NULL || h->index < index) {
      *hop = NULL;
      return MPLS_END_OF_LIST;
    }

    h = MPLS_LIST_HEAD(&hl->hop);
    while (h != NULL) {
      if (h->index == index) {
        *hop = h;
        return MPLS_SUCCESS;
      }
      h = MPLS_LIST_NEXT(&hl->hop, h, _hop_list);
    }
  }
  *hop = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_hop_list_add_hop(ldp_hop_list * hl, ldp_hop * h)
{
  ldp_hop *hp = NULL;

  if (hl && h) {
    MPLS_REFCNT_HOLD(h);
    hp = MPLS_LIST_HEAD(&hl->hop);
    while (hp != NULL) {
      if (hp->index > h->index) {
        MPLS_LIST_INSERT_BEFORE(&hl->hop, hp, h, _hop_list);
        _ldp_hop_add_hop_list(h, hl);
        return MPLS_SUCCESS;
      }
      hp = MPLS_LIST_NEXT(&hl->hop, hp, _hop_list);
    }
    MPLS_LIST_ADD_TAIL(&hl->hop, h, _hop_list, ldp_hop);
    _ldp_hop_add_hop_list(h, hl);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_hop_list_del_hop(ldp_hop_list * hl, ldp_hop * h)
{
  if (hl && h) {
    MPLS_LIST_REMOVE(&hl->hop, h, _hop_list);
    _ldp_hop_del_hop_list(h);
    MPLS_REFCNT_RELEASE(h, ldp_hop_delete);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum _ldp_hop_list_add_tunnel(ldp_hop_list * h, ldp_tunnel * t)
{
  if (h && t) {
    MPLS_REFCNT_HOLD(t);
    h->tunnel = t;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum _ldp_hop_list_del_tunnel(ldp_hop_list * h)
{
  if (h && h->tunnel) {
    MPLS_REFCNT_RELEASE(h->tunnel, ldp_tunnel_delete);
    h->tunnel = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}
