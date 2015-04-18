
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdlib.h>
#include "ldp_struct.h"
#include "ldp_outlabel.h"
#include "ldp_inlabel.h"
#include "ldp_session.h"
#include "ldp_entity.h"
#include "ldp_attr.h"
#include "ldp_global.h"

#include "mpls_assert.h"
#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"

#if MPLS_USE_LSR
#include "lsr_cfg.h"
#else
#include "mpls_mpls_impl.h"
#endif

static uint32_t _ldp_inlabel_next_index = 1;

ldp_inlabel *ldp_inlabel_create()
{
  ldp_inlabel *i = (ldp_inlabel *) mpls_malloc(sizeof(ldp_inlabel));

  if (i) {
    memset(i, 0, sizeof(ldp_inlabel));
    MPLS_REFCNT_INIT(i, 0);
    mpls_link_list_init(&i->session_root);
    mpls_link_list_init(&i->attr_root);
    MPLS_LIST_ELEM_INIT(i, _global);
    MPLS_LIST_ELEM_INIT(i, _outlabel);
    i->index = _ldp_inlabel_get_next_index();
    i->info.label.type = MPLS_LABEL_TYPE_NONE;
  }
  return i;
}

void ldp_inlabel_delete_complete(ldp_global * g, ldp_inlabel * in,
  ldp_session * s, ldp_attr * a)
{
  ldp_attr_del_inlabel(a);
  ldp_session_del_inlabel(s, in);
  _ldp_global_del_inlabel(g, in);
  ldp_inlabel_del_outlabel(g, in);
}

ldp_inlabel *ldp_inlabel_create_complete(ldp_global * g, ldp_session * s,
  ldp_attr * a)
{
  ldp_inlabel *in = ldp_inlabel_create();
  mpls_return_enum result;

  if (in != NULL) {

    in->info.labelspace = s->cfg_label_space;
    in->info.npop = 1;
    in->info.family = MPLS_FAMILY_IPV4;
    in->info.owner = MPLS_OWNER_LDP;
    result = _ldp_global_add_inlabel(g, in);

    if (result == MPLS_FAILURE) {
      _ldp_global_del_inlabel(g, in);
      return NULL;
    }

    if (ldp_session_add_inlabel(s, in) == MPLS_FAILURE) {
      _ldp_global_del_inlabel(g, in);
      return NULL;
    }

    mpls_label_struct2ldp_attr(&in->info.label, a);
    ldp_attr_add_inlabel(a, in);
  }
  return in;
}

void ldp_inlabel_delete(ldp_inlabel * i)
{
  LDP_PRINT(g->user_data,"inlabel delete\n");
  MPLS_REFCNT_ASSERT(i, 0);
  mpls_free(i);
}

mpls_return_enum ldp_inlabel_add_outlabel(ldp_global *g, ldp_inlabel *i,
  ldp_outlabel *o) {
  mpls_return_enum result;

  MPLS_ASSERT(i && o);
  MPLS_ASSERT(i->outlabel == NULL);

#if MPLS_USE_LSR
  {
    lsr_xconnect xcon;
    xcon.insegment_index = i->info.handle;
    xcon.outsegment_index = o->info.handle;
    xcon.info.owner = MPLS_OWNER_LDP;
    result = lsr_cfg_xconnect_set2(g->lsr_handle, &xcon, LSR_CFG_ADD|
      LSR_XCONNECT_CFG_OUTSEGMENT|LSR_XCONNECT_CFG_INSEGMENT|
      LSR_XCONNECT_CFG_LSPID|LSR_XCONNECT_CFG_OWNER);
  }
#else
  result = mpls_mpls_xconnect_add(g->mpls_handle, &i->info, &o->info);
#endif
  if (result == MPLS_SUCCESS) {
    MPLS_REFCNT_HOLD(o);
    i->outlabel = o;
    _ldp_outlabel_add_inlabel(o, i);
  }
  return result;
}

mpls_return_enum ldp_inlabel_del_outlabel(ldp_global *g, ldp_inlabel * i)
{
  MPLS_ASSERT(i && i->outlabel);
  {
#if MPLS_USE_LSR
    lsr_xconnect xcon;
    xcon.insegment_index = i->info.handle;
    xcon.outsegment_index = i->outlabel->info.handle;
    lsr_cfg_xconnect_set2(g->lsr_handle, &xcon, LSR_CFG_DEL);
#else
    mpls_mpls_xconnect_del(g->mpls_handle, &i->info, &i->outlabel->info);
#endif
    _ldp_outlabel_del_inlabel(i->outlabel, i);
    MPLS_REFCNT_RELEASE(i->outlabel, ldp_outlabel_delete);
    i->outlabel = NULL;
  }
  return MPLS_SUCCESS;
}

mpls_return_enum _ldp_inlabel_add_attr(ldp_inlabel * i, ldp_attr * a)
{
  MPLS_ASSERT(i && a);

  MPLS_REFCNT_HOLD(a);
  if (mpls_link_list_add_tail(&i->attr_root, a) == MPLS_SUCCESS) {
    i->reuse_count++;
    return MPLS_SUCCESS;
  }
  MPLS_REFCNT_RELEASE(a, ldp_attr_delete);
  return MPLS_FAILURE;
}

void _ldp_inlabel_del_attr(ldp_inlabel * i, ldp_attr * a)
{
  MPLS_ASSERT(i && a);
  mpls_link_list_remove_data(&i->attr_root, a);
  MPLS_REFCNT_RELEASE(a, ldp_attr_delete);
  i->reuse_count--;
}

mpls_return_enum _ldp_inlabel_add_session(ldp_inlabel * i, ldp_session * s)
{
  MPLS_ASSERT(i && s);

  MPLS_REFCNT_HOLD(s);
  if (mpls_link_list_add_tail(&i->session_root, s) == MPLS_SUCCESS) {
    return MPLS_SUCCESS;
  }
  MPLS_REFCNT_RELEASE(s, ldp_session_delete);
  return MPLS_FAILURE;
}

void _ldp_inlabel_del_session(ldp_inlabel * i, ldp_session * s)
{
  MPLS_ASSERT(i && s);
  mpls_link_list_remove_data(&i->session_root, s);
  MPLS_REFCNT_RELEASE(s, ldp_session_delete);
}

uint32_t _ldp_inlabel_get_next_index()
{
  uint32_t retval = _ldp_inlabel_next_index;

  _ldp_inlabel_next_index++;
  if (retval > _ldp_inlabel_next_index) {
    _ldp_inlabel_next_index = 1;
  }
  return retval;
}
