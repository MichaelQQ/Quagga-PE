
/*
 *  Copyright (C) James R. Leu 2003
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_fec.h"
#include "ldp_if.h"
#include "ldp_addr.h"
#include "ldp_session.h"
#include "ldp_outlabel.h"
#include "ldp_global.h"
#include "mpls_assert.h"
#include "mpls_compare.h"
#include "mpls_mm_impl.h"
#include "mpls_tree_impl.h"
#include "mpls_policy_impl.h"
#include "mpls_trace_impl.h"

#if MPLS_USE_LSR
#include "lsr_cfg.h"
#else
#include "mpls_mpls_impl.h"
#endif

static uint32_t _ldp_nexthop_next_index = 1;
static uint32_t _ldp_nexthop_get_next_index();

void mpls_nexthop2ldp_nexthop(mpls_nexthop *mnh, ldp_nexthop *lnh)
{
  memcpy(&lnh->info, mnh, sizeof(mpls_nexthop));
}

ldp_nexthop *ldp_nexthop_for_fec_session(ldp_fec *fec, ldp_session *s)
{
  ldp_nexthop *nh = MPLS_LIST_HEAD(&fec->nh_root);
  ldp_session *sp;
  while (nh) {
    sp = ldp_session_for_nexthop(nh);
    if (sp && (sp->index == s->index)) {
      return nh;
    }
    nh = MPLS_LIST_NEXT(&fec->nh_root, nh, _fec);
  }
  return NULL;
}

ldp_nexthop *ldp_nexthop_create(ldp_global *g, mpls_nexthop *n)
{
  ldp_nexthop *nh = (ldp_nexthop *) mpls_malloc(sizeof(ldp_nexthop));

  if (nh != NULL) {
    memset(nh, 0, sizeof(ldp_nexthop));
    MPLS_REFCNT_INIT(nh, 0);
    MPLS_LIST_INIT(&nh->outlabel_root, ldp_outlabel);
    MPLS_LIST_ELEM_INIT(nh, _fec);
    MPLS_LIST_ELEM_INIT(nh, _addr);
    MPLS_LIST_ELEM_INIT(nh, _if);
    MPLS_LIST_ELEM_INIT(nh, _outlabel);
    nh->index = _ldp_nexthop_get_next_index();
    mpls_nexthop2ldp_nexthop(n, nh);
    _ldp_global_add_nexthop(g, nh);
  }
  return nh;
}

void ldp_nexthop_delete(ldp_global *g, ldp_nexthop *nh)
{
  fprintf(stderr, "nexthop delete: %p\n", nh);
  MPLS_REFCNT_ASSERT(nh, 0);
  _ldp_global_del_nexthop(g, nh);
  mpls_free(nh);
}

void ldp_nexthop_add_if(ldp_nexthop * nh, ldp_if * i)
{
  MPLS_ASSERT(nh && i);
  MPLS_REFCNT_HOLD(i);
  nh->info.if_handle = i->handle;
  nh->iff = i;
}

void ldp_nexthop_del_if(ldp_global *g, ldp_nexthop * nh)
{
  MPLS_ASSERT(nh);
  MPLS_REFCNT_RELEASE2(g, nh->iff, ldp_if_delete);
  nh->iff = NULL;
}

void ldp_nexthop_add_addr(ldp_nexthop * nh, ldp_addr * a)
{
  MPLS_ASSERT(nh && a);
  MPLS_REFCNT_HOLD(a);
  nh->addr = a;
}

void ldp_nexthop_del_addr(ldp_global *g, ldp_nexthop * nh)
{
  MPLS_ASSERT(nh);
  MPLS_REFCNT_RELEASE2(g, nh->addr, ldp_addr_delete);
  nh->addr = NULL;
}

void ldp_nexthop_add_outlabel(ldp_nexthop * nh, ldp_outlabel * o)
{
  MPLS_ASSERT(nh && o);
  MPLS_REFCNT_HOLD(o);
  nh->outlabel = o;
}

void ldp_nexthop_del_outlabel(ldp_nexthop * nh)
{
  MPLS_ASSERT(nh);
  MPLS_REFCNT_RELEASE(nh->outlabel, ldp_outlabel_delete);
  nh->outlabel = NULL;
}

void ldp_nexthop_add_outlabel2(ldp_nexthop * n, ldp_outlabel * o)
{
  MPLS_ASSERT(n && o);
  MPLS_REFCNT_HOLD(o);
  MPLS_LIST_ADD_HEAD(&n->outlabel_root, o, _nexthop, ldp_outlabel);
  memcpy(&o->info.nexthop, &n->info, sizeof(mpls_nexthop));
}

void ldp_nexthop_del_outlabel2(ldp_global *g, ldp_nexthop * n, ldp_outlabel * o)
{
  MPLS_ASSERT(n && o);
  MPLS_LIST_REMOVE(&n->outlabel_root, o, _nexthop);
  ldp_outlabel_del_nexthop2(g, o);
  MPLS_REFCNT_RELEASE(o, ldp_outlabel_delete);
}

void ldp_nexthop_add_fec(ldp_nexthop *nh, ldp_fec *f)
{
  MPLS_ASSERT(nh && f);
  MPLS_REFCNT_HOLD(f);
  nh->fec = f;
}

void ldp_nexthop_del_fec(ldp_global *g, ldp_nexthop * nh)
{
  MPLS_ASSERT(nh);
  MPLS_REFCNT_RELEASE2(g, nh->fec, ldp_fec_delete);
  nh->fec = NULL;
}

static uint32_t _ldp_nexthop_get_next_index()
{
  uint32_t retval = _ldp_nexthop_next_index;

  _ldp_nexthop_next_index++;
  if (retval > _ldp_nexthop_next_index) {
    _ldp_nexthop_next_index = 1;
  }
  return retval;
}
