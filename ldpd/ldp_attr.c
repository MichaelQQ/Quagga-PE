
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_label_mapping.h"
#include "ldp_attr.h"
#include "ldp_if.h"
#include "ldp_addr.h"
#include "ldp_fec.h"
#include "ldp_global.h"
#include "ldp_inlabel.h"
#include "ldp_outlabel.h"
#include "ldp_session.h"
#include "mpls_refcnt.h"
#include "mpls_mm_impl.h"
#include "mpls_tree_impl.h"
#include "mpls_trace_impl.h"

#if MPLS_USE_LSR
#include "lsr_cfg.h"
#else
#include "mpls_mpls_impl.h"
#endif

static ldp_fec *_ldp_attr_get_fec2(ldp_global * g, mpls_fec * f, mpls_bool flag);
static ldp_fec *_ldp_attr_get_fec(ldp_global * g, ldp_attr * a, mpls_bool flag);
static ldp_fs *_ldp_fec_add_fs_ds(ldp_fec * fec, ldp_session * s);
static ldp_fs *_ldp_fec_add_fs_us(ldp_fec * fec, ldp_session * s);
static ldp_fs *_ldp_fec_find_fs_us(ldp_fec * fec, ldp_session * s,
  mpls_bool flag);
static ldp_fs *_ldp_fec_find_fs_ds(ldp_fec * fec, ldp_session * s,
  mpls_bool flag);
static void _ldp_fec_del_fs_us(ldp_fec * fec, ldp_fs * fs);
static void _ldp_fec_del_fs_ds(ldp_fec * fec, ldp_fs * fs);
static ldp_fs *_ldp_fs_create(ldp_session * s);
static void _ldp_fs_delete(ldp_fs * fs);
static ldp_attr *_ldp_fs_find_attr(ldp_fs * fs, ldp_attr * a);
static mpls_return_enum _ldp_fs_add_attr(ldp_fs * fs, ldp_attr * a);
static mpls_bool _ldp_fs_del_attr(ldp_fs * fs, ldp_attr * a);
static uint32_t _ldp_attr_get_next_index();

static uint32_t _ldp_attr_next_index = 1;

int ldp_attr_num_us2ds(ldp_attr * ds)
{
  ldp_attr *attr = NULL;
  int count = 0;

  attr = MPLS_LIST_HEAD(&ds->us_attr_root);
  while (attr) {
    count++;
    attr = MPLS_LIST_NEXT(&ds->us_attr_root, attr, _ds_attr);
  }
  return count;
}

mpls_bool ldp_attr_us_partof_ds(ldp_attr * us, ldp_attr * ds)
{
  if (us->ds_attr == ds) {
    return MPLS_BOOL_TRUE;
  }
  return MPLS_BOOL_FALSE;
}

void ldp_attr_del_us2ds(ldp_attr * us, ldp_attr * ds)
{
  if (!us || !ds) {
    return;
  }
  if (ldp_attr_us_partof_ds(us, ds) == MPLS_BOOL_TRUE) {
    us->ds_attr = NULL;
    MPLS_REFCNT_RELEASE(ds, ldp_attr_delete);
    MPLS_LIST_REMOVE(&ds->us_attr_root, us, _ds_attr);
    MPLS_REFCNT_RELEASE(us, ldp_attr_delete);
  } else {
    MPLS_ASSERT(0);
  }
}

void ldp_attr_add_fec(ldp_attr *a, ldp_fec *fec) {
  MPLS_ASSERT(a && fec);
  MPLS_REFCNT_HOLD(fec);
  a->fec = fec;
}

void ldp_attr_del_fec(ldp_global *g, ldp_attr *a) {
  MPLS_ASSERT(a);
  if (a->fec) {
    MPLS_REFCNT_RELEASE2(g, a->fec, ldp_fec_delete);
    a->fec = NULL;
  }
}

void ldp_attr_add_us2ds(ldp_attr * us, ldp_attr * ds)
{

  if (!us || !ds) {
    return;
  }
  if (ldp_attr_us_partof_ds(us, ds) == MPLS_BOOL_TRUE) {
    return;
  }
  MPLS_REFCNT_HOLD(us);
  MPLS_LIST_ADD_TAIL(&ds->us_attr_root, us, _ds_attr, ldp_attr);
  MPLS_REFCNT_HOLD(ds);
  us->ds_attr = ds;
}

void ldp_attr_action_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle g)
{
}

ldp_attr *ldp_attr_find_downstream_state_any2(ldp_global * g, ldp_fec * f,
  ldp_lsp_state state)
{
  ldp_attr *attr = NULL;
  ldp_fs *fs = NULL;

  fs = MPLS_LIST_HEAD(&f->fs_root_ds);
  while (fs != NULL) {
    attr = MPLS_LIST_HEAD(&fs->attr_root);
    while (attr != NULL) {
      if (attr->state == state) {
        return attr;
      }
      attr = MPLS_LIST_NEXT(&fs->attr_root, attr, _fs);
    }
    fs = MPLS_LIST_NEXT(&f->fs_root_ds, fs, _fec);
  }
  return NULL;
}

ldp_attr *ldp_attr_find_downstream_state_any(ldp_global * g, mpls_fec * f,
  ldp_lsp_state state)
{
  ldp_fec *fnode = _ldp_attr_get_fec2(g, f, MPLS_BOOL_FALSE);

  if (!fnode) {
    return NULL;
  }

  return ldp_attr_find_downstream_state_any2(g, fnode, state);
}

ldp_attr *ldp_attr_find_upstream_state_any2(ldp_global * g, ldp_fec * f,
  ldp_lsp_state state)
{
  ldp_attr *attr = NULL;
  ldp_fs *fs = NULL;

  fs = MPLS_LIST_HEAD(&f->fs_root_us);
  while (fs != NULL) {
    attr = MPLS_LIST_HEAD(&fs->attr_root);
    while (attr != NULL) {
      if (attr->state == state) {
        return attr;
      }
      attr = MPLS_LIST_NEXT(&fs->attr_root, attr, _fs);
    }
    fs = MPLS_LIST_NEXT(&f->fs_root_us, fs, _fec);
  }
  return NULL;
}

ldp_attr *ldp_attr_find_upstream_state_any(ldp_global * g, mpls_fec * f,
  ldp_lsp_state state)
{
  ldp_fec *fnode = _ldp_attr_get_fec2(g, f, MPLS_BOOL_FALSE);

  if (!fnode) {
    return NULL;
  }

  return ldp_attr_find_upstream_state_any2(g, fnode, state);
}

static ldp_attr *_ldp_attr_find_downstream_state(ldp_attr_list *ds_list,
  ldp_lsp_state state)
{
  if (ds_list != NULL) {
    ldp_attr *ds_attr = MPLS_LIST_HEAD(ds_list);

    while (ds_attr != NULL) {
      if (ds_attr->state == state) {
        return ds_attr;
      }
      ds_attr = MPLS_LIST_NEXT(ds_list, ds_attr, _fs);
    }
  }
  return NULL;
}

ldp_attr *ldp_attr_find_downstream_state2(ldp_global * g, ldp_session * s,
  ldp_fec * f, ldp_lsp_state state)
{
  ldp_attr_list *ds_list = ldp_attr_find_downstream_all2(g, s, f);
  return _ldp_attr_find_downstream_state(ds_list, state);
}

ldp_attr *ldp_attr_find_downstream_state(ldp_global * g, ldp_session * s,
  mpls_fec * f, ldp_lsp_state state)
{
  ldp_attr_list *ds_list = ldp_attr_find_downstream_all(g, s, f);
  return _ldp_attr_find_downstream_state(ds_list, state);
}

static ldp_attr *_ldp_attr_find_upstream_state(ldp_attr_list *us_list,
    ldp_lsp_state state)
{
  if (us_list != NULL) {
    ldp_attr *us_attr = MPLS_LIST_HEAD(us_list);

    while (us_attr != NULL) {
      if (us_attr->state == state) {
        return us_attr;
      }
      us_attr = MPLS_LIST_NEXT(us_list, us_attr, _fs);
    }
  }
  return NULL;
}

ldp_attr *ldp_attr_find_upstream_state2(ldp_global * g, ldp_session * s,
  ldp_fec * f, ldp_lsp_state state)
{
  ldp_attr_list *us_list = ldp_attr_find_upstream_all2(g, s, f);
  return _ldp_attr_find_upstream_state(us_list, state);
}

ldp_attr *ldp_attr_find_upstream_state(ldp_global * g, ldp_session * s,
  mpls_fec * f, ldp_lsp_state state)
{
  ldp_attr_list *us_list = ldp_attr_find_upstream_all(g, s, f);
  return _ldp_attr_find_upstream_state(us_list, state);
}

void ldp_attr_remove_complete(ldp_global * g, ldp_attr * attr,
		mpls_bool complete)
{
  ldp_session *session = attr->session;
  ldp_outlabel *out = NULL;
  ldp_inlabel *in = NULL;
  ldp_attr *us_temp = NULL;
  mpls_fec fec;
  int i;

  switch (attr->state) {
    case LDP_LSP_STATE_MAP_RECV:
      if (attr->ingress == MPLS_BOOL_TRUE) {
        out = attr->outlabel;
        MPLS_ASSERT(out != NULL);
        while ((in = MPLS_LIST_HEAD(&out->inlabel_root)) != NULL) {
          ldp_inlabel_del_outlabel(g, in);
        }

        if (out->merge_count > 0) {
          for (i = 0; i < attr->fecTlv.numberFecElements; i++) {
            fec_tlv2mpls_fec(&attr->fecTlv, i, &fec);
            out->merge_count--;
#if MPLS_USE_LSR
            {
              lsr_ftn ftn;
              memcpy(&ftn.fec, &fec, sizeof(mpls_fec));
              ftn.outsegment_index = out->info.handle;
              lsr_cfg_ftn_set2(g->lsr_handle, &ftn, LSR_CFG_DEL);
            }
#else
            mpls_mpls_fec2out_del(g->mpls_handle, &fec, &out->info);
#endif
          }
        }
        MPLS_ASSERT(out->merge_count == 0);
        ldp_attr_del_outlabel(attr);
        ldp_session_del_outlabel(session, out);
        _ldp_global_del_outlabel(g, out);
      }
      while ((us_temp = MPLS_LIST_HEAD(&attr->us_attr_root)) != NULL) {
        ldp_attr_del_us2ds(us_temp, attr);
      }
      ldp_attr_delete_downstream(g, session, attr);
      break;
    case LDP_LSP_STATE_MAP_SENT:
      in = attr->inlabel;
      out = in->outlabel;

      if (out != NULL) {
        if (in->reuse_count == 1) {
          ldp_inlabel_del_outlabel(g, in);
        }
      }

      ldp_attr_del_inlabel(attr);
      ldp_attr_delete_upstream(g, session, attr);
      ldp_attr_del_us2ds(attr, attr->ds_attr);
      ldp_session_del_inlabel(session, in);

      if (in->reuse_count == 0) {
        _ldp_global_del_inlabel(g, in);
      }
      break;
    case LDP_LSP_STATE_ABORT_SENT:
    case LDP_LSP_STATE_NOTIF_SENT:
    case LDP_LSP_STATE_REQ_RECV:
    case LDP_LSP_STATE_WITH_SENT:
    case LDP_LSP_STATE_NO_LABEL_RESOURCE_SENT:
      {
        ldp_attr_del_us2ds(attr, attr->ds_attr);
        ldp_attr_delete_upstream(g, session, attr);
        break;
      }
    case LDP_LSP_STATE_ABORT_RECV:
    case LDP_LSP_STATE_NOTIF_RECV:
    case LDP_LSP_STATE_REQ_SENT:
    case LDP_LSP_STATE_WITH_RECV:
    case LDP_LSP_STATE_NO_LABEL_RESOURCE_RECV:
      {
        while ((us_temp = MPLS_LIST_HEAD(&attr->us_attr_root)) != NULL) {
          ldp_attr_del_us2ds(us_temp, attr);
        }
        ldp_attr_delete_downstream(g, session, attr);
        break;
      }
  }
}

ldp_attr *ldp_attr_create(mpls_fec * fec)
{
  ldp_attr *a = (ldp_attr *) mpls_malloc(sizeof(ldp_attr));

  if (a != NULL) {
    memset(a, 0, sizeof(ldp_attr));
    MPLS_LIST_ELEM_INIT(a, _session);
    MPLS_LIST_ELEM_INIT(a, _global);
    MPLS_LIST_ELEM_INIT(a, _fs);
    MPLS_LIST_INIT(&a->us_attr_root, ldp_attr);
    MPLS_REFCNT_INIT(a, 0);
    a->index = _ldp_attr_get_next_index();
    a->in_tree = MPLS_BOOL_FALSE;
    a->ingress = MPLS_BOOL_FALSE;
    a->filtered = MPLS_BOOL_FALSE;

    if (fec != NULL) {
      mpls_fec2fec_tlv(fec, &a->fecTlv, 0);
      a->fecTlv.numberFecElements = 1;
      a->fecTlvExists = 1;
    }
  }
  return a;
}

void ldp_attr_delete(ldp_attr * a)
{
  LDP_PRINT(g->user_data,"attr delete\n");
  MPLS_ASSERT(a->in_tree == MPLS_BOOL_FALSE);
  mpls_free(a);
}

void ldp_attr2ldp_attr(ldp_attr * a, ldp_attr * b, uint32_t flag)
{
  if (a->fecTlvExists && flag & LDP_ATTR_FEC) {
    memcpy(&b->fecTlv, &a->fecTlv, sizeof(mplsLdpFecTlv_t));
    b->fecTlvExists = 1;
  }
  if (a->genLblTlvExists && flag & LDP_ATTR_LABEL) {
    memcpy(&b->genLblTlv, &a->genLblTlv, sizeof(mplsLdpGenLblTlv_t));
    b->genLblTlvExists = 1;
  } else if (a->atmLblTlvExists && flag & LDP_ATTR_LABEL) {
    memcpy(&b->atmLblTlv, &a->atmLblTlv, sizeof(mplsLdpAtmLblTlv_t));
    b->atmLblTlvExists = 1;
  } else if (a->frLblTlvExists && flag & LDP_ATTR_LABEL) {
    memcpy(&b->frLblTlv, &a->frLblTlv, sizeof(mplsLdpFrLblTlv_t));
    b->frLblTlvExists = 1;
  }
  if (a->hopCountTlvExists && flag & LDP_ATTR_HOPCOUNT) {
    memcpy(&b->hopCountTlv, &a->hopCountTlv, sizeof(mplsLdpHopTlv_t));
    b->hopCountTlvExists = 1;
  }
  if (a->pathVecTlvExists && flag & LDP_ATTR_PATH) {
    memcpy(&b->pathVecTlv, &a->pathVecTlv, sizeof(mplsLdpPathTlv_t));
    b->pathVecTlvExists = 1;
  }
  if (a->lblMsgIdTlvExists && flag & LDP_ATTR_MSGID) {
    memcpy(&b->lblMsgIdTlv, &a->lblMsgIdTlv, sizeof(mplsLdpLblMsgIdTlv_t));
    b->lblMsgIdTlvExists = 1;
  }
  if (a->lspidTlvExists && flag & LDP_ATTR_LSPID) {
    memcpy(&b->lspidTlv, &a->lspidTlv, sizeof(mplsLdpLspIdTlv_t));
    b->lspidTlvExists = 1;
  }
  if (a->trafficTlvExists && flag & LDP_ATTR_TRAFFIC) {
    memcpy(&b->trafficTlv, &a->trafficTlv, sizeof(mplsLdpTrafficTlv_t));
    b->trafficTlvExists = 1;
  }
}

mpls_return_enum ldp_attr_add_inlabel(ldp_attr * a, ldp_inlabel * i)
{
  if (a && i) {
    MPLS_REFCNT_HOLD(i);
    a->inlabel = i;
    _ldp_inlabel_add_attr(i, a);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_attr_del_inlabel(ldp_attr * a)
{
  if (a && a->inlabel) {
    _ldp_inlabel_del_attr(a->inlabel, a);
    MPLS_REFCNT_RELEASE(a->inlabel, ldp_inlabel_delete);
    a->inlabel = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_attr_add_outlabel(ldp_attr * a, ldp_outlabel * o)
{
  if (a && o) {
    MPLS_REFCNT_HOLD(o);
    a->outlabel = o;
    _ldp_outlabel_add_attr(o, a);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_attr_del_outlabel(ldp_attr * a)
{
  if (a && a->outlabel) {
    _ldp_outlabel_del_attr(a->outlabel);
    MPLS_REFCNT_RELEASE(a->outlabel, ldp_outlabel_delete);
    a->outlabel = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_attr_add_session(ldp_attr * a, ldp_session * s)
{
  if (a && s) {
    MPLS_REFCNT_HOLD(s);
    a->session = s;
    _ldp_session_add_attr(s, a);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum ldp_attr_del_session(ldp_attr * a)
{
  if (a && a->session) {
    _ldp_session_del_attr(a->session, a);
    MPLS_REFCNT_RELEASE(a->session, ldp_session_delete);
    a->session = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_bool ldp_attr_is_equal(ldp_attr * a, ldp_attr * b, uint32_t flag)
{
  if (flag & LDP_ATTR_LABEL) {
    if (a->genLblTlvExists && b->genLblTlvExists) {
      if (a->genLblTlv.label != b->genLblTlv.label) {
        return MPLS_BOOL_FALSE;
      }
    } else if (a->atmLblTlvExists && b->atmLblTlvExists) {
      if (a->atmLblTlv.flags.flags.vpi != b->atmLblTlv.flags.flags.vpi ||
        a->atmLblTlv.vci != b->atmLblTlv.vci) {
        return MPLS_BOOL_FALSE;
      }
    } else if (a->frLblTlvExists && b->frLblTlvExists) {
      if (a->frLblTlv.flags.flags.len != b->frLblTlv.flags.flags.len ||
        a->frLblTlv.flags.flags.dlci != b->frLblTlv.flags.flags.dlci) {
        return MPLS_BOOL_FALSE;
      }
    } else {
      return MPLS_BOOL_FALSE;
    }
  }
  if (flag & LDP_ATTR_HOPCOUNT) {
    if (a->hopCountTlvExists && b->hopCountTlvExists) {
      if (a->hopCountTlv.hcValue != b->hopCountTlv.hcValue) {
        return MPLS_BOOL_FALSE;
      }
    } else {
      if (a->hopCountTlvExists != b->hopCountTlvExists) {
        return MPLS_BOOL_FALSE;
      }
    }
  }
  if (flag & LDP_ATTR_PATH) {
    int i;

    if (a->pathVecTlvExists && b->pathVecTlvExists) {
      for (i = 0; i < MPLS_MAXHOPSNUMBER; i++) {
        if (a->pathVecTlv.lsrId[i] != b->pathVecTlv.lsrId[i]) {
          return MPLS_BOOL_FALSE;
        }
      }
    } else {
      if (a->hopCountTlvExists != b->hopCountTlvExists) {
        return MPLS_BOOL_FALSE;
      }
    }
  }
  if (flag & LDP_ATTR_FEC) {
    int i;

    if (a->fecTlvExists && b->fecTlvExists) {
      if (a->fecTlv.numberFecElements != b->fecTlv.numberFecElements) {
        return MPLS_BOOL_FALSE;
      }
      for (i = 0; i < a->fecTlv.numberFecElements; i++) {
        if (a->fecTlv.fecElemTypes[i] != b->fecTlv.fecElemTypes[i]) {
          return MPLS_BOOL_FALSE;
        }
        switch (a->fecTlv.fecElemTypes[i]) {
          case MPLS_CRLSP_FEC:
          case MPLS_WC_FEC:
            /* nothing of interest to compare */
            break;
          case MPLS_PREFIX_FEC:
          case MPLS_HOSTADR_FEC:
            if (a->fecTlv.fecElArray[i].addressEl.addressFam !=
              b->fecTlv.fecElArray[i].addressEl.addressFam ||
              a->fecTlv.fecElArray[i].addressEl.preLen !=
              b->fecTlv.fecElArray[i].addressEl.preLen ||
              a->fecTlv.fecElArray[i].addressEl.address !=
              b->fecTlv.fecElArray[i].addressEl.address) {
              return MPLS_BOOL_FALSE;
            }
            break;
          default:
            MPLS_ASSERT(0);
        }
      }
    } else {
      return MPLS_BOOL_FALSE;
    }
  }
  if (flag & LDP_ATTR_MSGID) {
    if (a->lblMsgIdTlvExists && b->lblMsgIdTlvExists) {
      if (a->lblMsgIdTlv.msgId != b->lblMsgIdTlv.msgId) {
        return MPLS_BOOL_FALSE;
      }
    } else {
      return MPLS_BOOL_FALSE;
    }
  }
  if (flag & LDP_ATTR_LSPID) {
    if (a->lspidTlvExists && b->lspidTlvExists) {
      if (a->lspidTlv.localCrlspId != b->lspidTlv.localCrlspId ||
        a->lspidTlv.routerId != b->lspidTlv.routerId) {
        return MPLS_BOOL_FALSE;
      }
    } else {
      return MPLS_BOOL_FALSE;
    }
  }
  if (flag & LDP_ATTR_TRAFFIC) {
  }
  return MPLS_BOOL_TRUE;
}

mpls_return_enum ldp_attr_insert_upstream2(ldp_global * g, ldp_session * s,
  ldp_attr * a, ldp_fec *f)
{
  ldp_fs *fs = NULL;
  mpls_return_enum retval;

  MPLS_ASSERT(g && s && a && (a->in_tree == MPLS_BOOL_FALSE) && f);

  /* find the upstream fs for this session */
  if ((fs = _ldp_fec_find_fs_us(f, s, MPLS_BOOL_TRUE)) == NULL) {
    /* this session isn't in the list and cannot be added */
    return MPLS_FAILURE;
  }

  ldp_attr_add_session(a, s);
  ldp_attr_add_fec(a, f);

  retval = _ldp_fs_add_attr(fs, a);
  _ldp_global_add_attr(g, a);
  a->in_tree = MPLS_BOOL_TRUE;
  return retval;
}

mpls_return_enum ldp_attr_insert_upstream(ldp_global * g, ldp_session * s,
  ldp_attr * a)
{
  ldp_fec *fnode = NULL;

  MPLS_ASSERT(g && s && a && (a->in_tree == MPLS_BOOL_FALSE));

  if ((fnode = _ldp_attr_get_fec(g, a, MPLS_BOOL_TRUE)) == NULL) {
    /* we couldn't get/add a node from/to the tree! */
    return MPLS_FAILURE;
  }

  return ldp_attr_insert_upstream2(g, s, a, fnode);
}

mpls_return_enum ldp_attr_insert_downstream2(ldp_global * g, ldp_session * s,
  ldp_attr * a, ldp_fec *f)
{
  ldp_fs *fs = NULL;
  mpls_return_enum retval;

  MPLS_ASSERT(g && s && a && (a->in_tree == MPLS_BOOL_FALSE) && f);

  /* find the downstream fs for this session */
  if ((fs = _ldp_fec_find_fs_ds(f, s, MPLS_BOOL_TRUE)) == NULL) {
    /* this session isn't in the list and cannot be added */
    return MPLS_FAILURE;
  }

  ldp_attr_add_session(a, s);
  ldp_attr_add_fec(a, f);

  retval = _ldp_fs_add_attr(fs, a);
  _ldp_global_add_attr(g, a);
  a->in_tree = MPLS_BOOL_TRUE;
  return retval;
}

mpls_return_enum ldp_attr_insert_downstream(ldp_global * g, ldp_session * s,
  ldp_attr * a)
{
  ldp_fec *fnode = NULL;
  MPLS_ASSERT(g && s && a && (a->in_tree == MPLS_BOOL_FALSE));
  if ((fnode = _ldp_attr_get_fec(g, a, MPLS_BOOL_TRUE)) == NULL) {
    /* we couldn't get/add a node from/to the tree! */
    return MPLS_FAILURE;
  }
  return ldp_attr_insert_downstream2(g, s, a, fnode);
}

ldp_attr_list *ldp_attr_find_upstream_all2(ldp_global * g, ldp_session * s,
  ldp_fec * f)
{
  ldp_fs *fs = NULL;

  MPLS_ASSERT(f && g);

  if (!s) {
    return NULL;
  }

  /* find the upstream fs for this session */
  if ((fs = _ldp_fec_find_fs_us(f, s, MPLS_BOOL_FALSE)) == NULL) {
    /* this session isn't in the list */
    return NULL;
  }
  return &fs->attr_root;
}

ldp_attr_list *ldp_attr_find_upstream_all(ldp_global * g, ldp_session * s,
  mpls_fec * f)
{
  ldp_fec *fnode = NULL;

  MPLS_ASSERT(f && g);

  if (!s) {
    return NULL;
  }

  if ((fnode = _ldp_attr_get_fec2(g, f, MPLS_BOOL_FALSE)) == NULL) {
    /* we couldn't get the node from the tree! */
    return NULL;
  }

  return ldp_attr_find_upstream_all2(g, s, fnode);
}

ldp_attr_list *ldp_attr_find_downstream_all2(ldp_global * g, ldp_session * s,
  ldp_fec * f)
{
  ldp_fs *fs = NULL;

  MPLS_ASSERT(f && g);

  if (!s) {
    return NULL;
  }

  /* find the downstream fs for this session */
  if ((fs = _ldp_fec_find_fs_ds(f, s, MPLS_BOOL_FALSE)) == NULL) {
    /* this session isn't in the list */
    return NULL;
  }
  return &fs->attr_root;
}

ldp_attr_list *ldp_attr_find_downstream_all(ldp_global * g, ldp_session * s,
  mpls_fec * f)
{
  ldp_fec *fnode = NULL;

  MPLS_ASSERT(f && g);

  if (!s) {
    return NULL;
  }

  if ((fnode = _ldp_attr_get_fec2(g, f, MPLS_BOOL_FALSE)) == NULL) {
    /* we couldn't get the node from the tree! */
    return NULL;
  }

  return ldp_attr_find_downstream_all2(g, s, fnode);
}

void ldp_attr_delete_upstream(ldp_global * g, ldp_session * s, ldp_attr * a)
{
  ldp_fec *fnode = NULL;
  ldp_fs *fs = NULL;

  MPLS_ASSERT(a->in_tree == MPLS_BOOL_TRUE);

  if ((fnode = _ldp_attr_get_fec(g, a, MPLS_BOOL_FALSE)) == NULL) {
    /* we couldn't get the node from the tree! */
    return;
  }

  /* find the upstream fs for this session */
  if ((fs = _ldp_fec_find_fs_us(fnode, s, MPLS_BOOL_FALSE)) == NULL) {
    /* this session isn't in the list */
    return;
  }

  ldp_attr_del_session(a);
  ldp_attr_del_fec(g, a);

  if (_ldp_fs_del_attr(fs, a) == MPLS_BOOL_TRUE) {
    _ldp_fec_del_fs_us(fnode, fs);
  }
  a->in_tree = MPLS_BOOL_FALSE;
  _ldp_global_del_attr(g, a);
}

void ldp_attr_delete_downstream(ldp_global * g, ldp_session * s, ldp_attr * a)
{
  ldp_fec *fnode = NULL;
  ldp_fs *fs = NULL;

  MPLS_ASSERT(a->in_tree == MPLS_BOOL_TRUE);

  if ((fnode = _ldp_attr_get_fec(g, a, MPLS_BOOL_FALSE)) == NULL) {
    /* we couldn't get the node from the tree! */
    return;
  }

  /* find the downstream fs for this session */
  if ((fs = _ldp_fec_find_fs_ds(fnode, s, MPLS_BOOL_FALSE)) == NULL) {
    /* this session isn't in the list */
    return;
  }

  ldp_attr_del_session(a);
  ldp_attr_del_fec(g, a);

  if (_ldp_fs_del_attr(fs, a) == MPLS_BOOL_TRUE) {
    _ldp_fec_del_fs_ds(fnode, fs);
  }
  a->in_tree = MPLS_BOOL_FALSE;
  _ldp_global_del_attr(g, a);
}

void ldp_attr2mpls_label_struct(ldp_attr * a, mpls_label_struct * l)
{
  if (a->genLblTlvExists) {
    l->type = MPLS_LABEL_TYPE_GENERIC;
    l->u.gen = a->genLblTlv.label;
  } else if (a->atmLblTlvExists) {
    l->type = MPLS_LABEL_TYPE_ATM;
    l->u.atm.vpi = a->atmLblTlv.flags.flags.vpi;
    l->u.atm.vci = a->atmLblTlv.vci;
  } else if (a->frLblTlvExists) {
    l->type = MPLS_LABEL_TYPE_FR;
    l->u.fr.len = a->frLblTlv.flags.flags.len;
    l->u.fr.dlci = a->frLblTlv.flags.flags.dlci;
  } else {
    MPLS_ASSERT(0);
  }
}

void mpls_label_struct2ldp_attr(mpls_label_struct * l, ldp_attr * a)
{
  switch (l->type) {
    case MPLS_LABEL_TYPE_GENERIC:
      a->genLblTlvExists = 1;
      a->atmLblTlvExists = 0;
      a->frLblTlvExists = 0;
      a->genLblTlv.label = l->u.gen;
      break;
    case MPLS_LABEL_TYPE_ATM:
      a->genLblTlvExists = 0;
      a->atmLblTlvExists = 1;
      a->frLblTlvExists = 0;
      a->atmLblTlv.flags.flags.vpi = l->u.atm.vpi;
      a->atmLblTlv.vci = l->u.atm.vci;
    case MPLS_LABEL_TYPE_FR:
      a->genLblTlvExists = 0;
      a->atmLblTlvExists = 0;
      a->frLblTlvExists = 1;
      a->frLblTlv.flags.flags.len = l->u.fr.len;
      a->frLblTlv.flags.flags.dlci = l->u.fr.dlci;
    default:
      MPLS_ASSERT(0);
  }
}

#if 0
void ldp_attr2ldp_attr(ldp_attr * src, ldp_attr * dst, u_int32 flag)
{
  if (flag & LDP_ATTR_FEC) {
    memcpy(&dst->fecTlv, &src->fecTlv, sizeof(mplsLdpFecTlv_t));
    dst->fecTlvExists = src->fecTlvExists;
  }
  if (flag & LDP_ATTR_LABEL) {
    memcpy(&dst->genLblTlv, &src->genLblTlv, sizeof(mplsLdpGenLblTlv_t));
    memcpy(&dst->atmLblTlv, &src->atmLblTlv, sizeof(mplsLdpAtmLblTlv_t));
    memcpy(&dst->frLblTlv, &src->frLblTlv, sizeof(mplsLdpFrLblTlv_t));
    dst->genLblTlvExists = src->genLblTlvExists
      dst->atmLblTlvExists = src->atmLblTlvExists
      dst->frLblTlvExists = src->frLblTlvExists}
  if (flag & LDP_ATTR_HOPCOUNT) {
    memcpy(&dst->hopCountTlv, &src->hopCountTlv, sizeof(mplsLdpHopTlv_t));
    dst->hopCountTlvExists = src->hopCountTlvExists;
  }
  if (flag & LDP_ATTR_PATH) {
    memcpy(&dst->pathVecTlv, &src->pathVecTlv, sizeof(mplsLdpPathTlv_t));
    dst->pathVecTlvExists = src->pathVecTlvExists;
  }
  if (flag & LDP_ATTR_MSGID) {
    memcpy(&dst->lblMsgIdTlv, &src->lblMsgIdTlv, sizeof(mplsLdpLblMsgIdTlv_t));
    dst->lblMsgIdTlvExists = src->lblMsgIdTlvExists;
  }
  if (flag & LDP_ATTR_LSPID) {
    memcpy(&dst->lspidTlv, &src->lspidTlv, sizeof(mplsLdpLspIdTlv_t));
    dst->lspidTlvExists = src->lspidTlvExists;
  }
  if (flag & LDP_ATTR_TRAFFIC) {
    memcpy(&dst->trafficTlv, &src->trafficTlv, sizeof(mplsLdpTrafficTlv_t));
    dst->trafficTlvExists = src->trafficTlvExists;
  }
}
#endif

ldp_fec *_ldp_attr_get_fec2(ldp_global * g, mpls_fec * f, mpls_bool flag)
{
  ldp_fec *fnode = NULL;

  if (!(fnode = ldp_fec_find(g,f))) {
    if (flag == MPLS_BOOL_FALSE) {
      return NULL;
    }

    /* this FEC doesn't exist in the tree yet, create one ... */
    if (!(fnode = ldp_fec_create(g, f))) {
      /* insert failed */
      return NULL;
    }
  }
  return fnode;
}

static ldp_fec *_ldp_attr_get_fec(ldp_global * g, ldp_attr * a, mpls_bool flag)
{
  mpls_fec fec;

  /* get FEC from attr */
  fec_tlv2mpls_fec(&a->fecTlv, 0, &fec);
  return _ldp_attr_get_fec2(g, &fec, flag);
}

static ldp_fs *_ldp_fec_add_fs_ds(ldp_fec * fec, ldp_session * s)
{
  ldp_fs *fs = _ldp_fec_find_fs_ds(fec, s, MPLS_BOOL_FALSE);

  if (fs == NULL) {
    fs = _ldp_fs_create(s);
    if (fs == NULL) {
      return NULL;
    }
    MPLS_LIST_ADD_HEAD(&fec->fs_root_ds, fs, _fec, ldp_fs);
  }
  return fs;
}

static ldp_fs *_ldp_fec_add_fs_us(ldp_fec * fec, ldp_session * s)
{
  ldp_fs *fs = _ldp_fec_find_fs_us(fec, s, MPLS_BOOL_FALSE);

  if (fs == NULL) {
    fs = _ldp_fs_create(s);
    if (fs == NULL) {
      return NULL;
    }
    MPLS_LIST_ADD_HEAD(&fec->fs_root_us, fs, _fec, ldp_fs);
  }
  return fs;
}

static ldp_fs *_ldp_fec_find_fs_us(ldp_fec * fec, ldp_session * s,
  mpls_bool flag)
{
  ldp_fs *fs = MPLS_LIST_HEAD(&fec->fs_root_us);

  while (fs != NULL) {
    if (fs->session->index == s->index) {
      return fs;
    }
    fs = MPLS_LIST_NEXT(&fec->fs_root_us, fs, _fec);
  }
  if (flag == MPLS_BOOL_FALSE) {
    return NULL;
  }
  return _ldp_fec_add_fs_us(fec, s);
}

static ldp_fs *_ldp_fec_find_fs_ds(ldp_fec * fec, ldp_session * s,
  mpls_bool flag)
{
  ldp_fs *fs = MPLS_LIST_HEAD(&fec->fs_root_ds);

  while (fs != NULL) {
    if (fs->session->index == s->index) {
      return fs;
    }
    fs = MPLS_LIST_NEXT(&fec->fs_root_ds, fs, _fec);
  }
  if (flag == MPLS_BOOL_FALSE) {
    return NULL;
  }
  return _ldp_fec_add_fs_ds(fec, s);
}

static void _ldp_fec_del_fs_us(ldp_fec * fec, ldp_fs * fs)
{
  if (fs == NULL) {
    return;
  }
  MPLS_LIST_REMOVE(&fec->fs_root_us, fs, _fec);
  _ldp_fs_delete(fs);
}

static void _ldp_fec_del_fs_ds(ldp_fec * fec, ldp_fs * fs)
{
  if (fs == NULL) {
    return;
  }
  MPLS_LIST_REMOVE(&fec->fs_root_ds, fs, _fec);
  _ldp_fs_delete(fs);
}

static ldp_fs *_ldp_fs_create(ldp_session * s)
{
  ldp_fs *fs = (ldp_fs *) mpls_malloc(sizeof(ldp_fs));

  if (fs != NULL) {
    memset(fs, 0, sizeof(ldp_fs));
    MPLS_LIST_INIT(&fs->attr_root, ldp_attr);
    MPLS_LIST_ELEM_INIT(fs, _fec);
    if (s != NULL) {
      MPLS_REFCNT_HOLD(s);
      fs->session = s;
    }
  }
  return fs;
}

static void _ldp_fs_delete(ldp_fs * fs)
{
  LDP_PRINT(g->user_data,"fs delete\n");
  if (fs->session != NULL) {
    MPLS_REFCNT_RELEASE(fs->session, ldp_session_delete);
  }
  mpls_free(fs);
}

static ldp_attr *_ldp_fs_find_attr(ldp_fs * fs, ldp_attr * a)
{
  ldp_attr *ptr = MPLS_LIST_HEAD(&fs->attr_root);

  while (ptr != NULL) {
    if (ldp_attr_is_equal(a, ptr, LDP_ATTR_LABEL | LDP_ATTR_FEC) == MPLS_BOOL_TRUE) {
      return ptr;
    }
    ptr = MPLS_LIST_NEXT(&fs->attr_root, ptr, _fs);
  }
  return NULL;
}

static mpls_return_enum _ldp_fs_add_attr(ldp_fs * fs, ldp_attr * a)
{
  ldp_attr *ptr = _ldp_fs_find_attr(fs, a);

  MPLS_ASSERT(ptr == NULL);
  MPLS_REFCNT_HOLD(a);
  MPLS_LIST_ADD_HEAD(&fs->attr_root, a, _fs, ldp_attr);
  return MPLS_SUCCESS;
}

static mpls_bool _ldp_fs_del_attr(ldp_fs * fs, ldp_attr * a)
{
  ldp_attr *ptr = _ldp_fs_find_attr(fs, a);

  if (ptr != NULL) {
    MPLS_LIST_REMOVE(&fs->attr_root, ptr, _fs);
    MPLS_REFCNT_RELEASE(ptr, ldp_attr_delete);
  }
  if (MPLS_LIST_HEAD(&fs->attr_root) == NULL)
    return MPLS_BOOL_TRUE;
  return MPLS_BOOL_FALSE;
}

ldp_attr *ldp_attr_find_upstream_map_in_labelspace(ldp_fec *f, int labelspace)
{
  ldp_fs *fs = MPLS_LIST_HEAD(&f->fs_root_us);

  fprintf(stderr, "ldp_attr_find_upstream_map_in_labelspace: enter\n");
  while (fs) {
    ldp_attr *attr = MPLS_LIST_HEAD(&fs->attr_root);
    fprintf(stderr, "FS: %p\n", fs);
    while (attr) {
      fprintf(stderr, "ATTR: %p\n", fs);
      if (attr->state == LDP_LSP_STATE_MAP_SENT) {
        fprintf(stderr, "SESSION: %p\n", attr->session);
        if (attr->session->cfg_label_space == labelspace) {
          fprintf(stderr, "ldp_attr_find_upstream_map_in_labelspace: exit\n");
          return attr;
        }
      }
      attr = MPLS_LIST_NEXT(&fs->attr_root, attr, _fs);
    }
    fs = MPLS_LIST_NEXT(&f->fs_root_us, fs, _fec);
  }
  fprintf(stderr, "ldp_attr_find_upstream_map_in_labelspace: exit\n");
  return NULL;
}

static uint32_t _ldp_attr_get_next_index()
{
  uint32_t retval = _ldp_attr_next_index;

  _ldp_attr_next_index++;
  if (retval > _ldp_attr_next_index) {
    _ldp_attr_next_index = 1;
  }
  return retval;
}
