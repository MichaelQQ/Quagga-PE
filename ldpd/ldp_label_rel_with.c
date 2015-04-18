
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_attr.h"
#include "ldp_session.h"
#include "ldp_global.h"
#include "ldp_inlabel.h"
#include "ldp_entity.h"
#include "ldp_outlabel.h"
#include "ldp_label_rel_with.h"
#include "ldp_nexthop.h"
#include "ldp_label_mapping.h"
#include "ldp_fec.h"
#include "ldp_mesg.h"
#include "ldp_pdu_setup.h"

#include "mpls_trace_impl.h"

mpls_bool rel_with2attr(mplsLdpLbl_W_R_Msg_t * rw, ldp_attr * attr)
{
  mpls_bool retval = MPLS_BOOL_FALSE;

  if (rw->fecTlvExists) {
    memcpy(&attr->fecTlv, &rw->fecTlv, sizeof(mplsLdpFecTlv_t));
    attr->fecTlvExists = 1;
  }
  if (rw->genLblTlvExists) {
    retval = MPLS_BOOL_TRUE;
    memcpy(&attr->genLblTlv, &rw->genLblTlv, sizeof(mplsLdpGenLblTlv_t));
    attr->genLblTlvExists = 1;
  } else if (rw->atmLblTlvExists) {
    retval = MPLS_BOOL_TRUE;
    memcpy(&attr->atmLblTlv, &rw->atmLblTlv, sizeof(mplsLdpAtmLblTlv_t));
    attr->atmLblTlvExists = 1;
  } else if (rw->frLblTlvExists) {
    retval = MPLS_BOOL_TRUE;
    memcpy(&attr->frLblTlv, &rw->frLblTlv, sizeof(mplsLdpFrLblTlv_t));
    attr->frLblTlvExists = 1;
  }
  return retval;
}

void ldp_label_rel_with_prepare_msg(ldp_mesg * msg, uint32_t msgid,
  ldp_attr * a, ldp_notif_status status, uint16_t type)
{
  mplsLdpLbl_W_R_Msg_t *rw = NULL;

  ldp_mesg_prepare(msg, type, msgid);
  rw = &msg->u.release;
  if (a->fecTlvExists) {
    rw->fecTlvExists = 1;
    rw->baseMsg.msgLength += setupFecTlv(&rw->fecTlv);
    rw->baseMsg.msgLength += addFecElem2FecTlv(&rw->fecTlv,
      &a->fecTlv.fecElArray[0]);
  }
  if (a->genLblTlvExists) {
    rw->genLblTlvExists = 1;
    rw->baseMsg.msgLength += setupGenLblTlv(&rw->genLblTlv, a->genLblTlv.label);
  }
  if (a->atmLblTlvExists) {
    rw->atmLblTlvExists = 1;
    rw->baseMsg.msgLength += setupAtmLblTlv(&rw->atmLblTlv, 0, 0,
      a->atmLblTlv.flags.flags.vpi, a->atmLblTlv.vci);
  }
  if (a->frLblTlvExists) {
    rw->frLblTlvExists = 1;
    rw->baseMsg.msgLength += setupFrLblTlv(&rw->frLblTlv, 0,
      a->frLblTlv.flags.flags.len, a->frLblTlv.flags.flags.dlci);
  }
  if (a->lspidTlvExists) {
    rw->lspidTlvExists = 1;
    rw->baseMsg.msgLength += setupLspidTlv(&rw->lspidTlv, 0,
      a->lspidTlv.localCrlspId, a->lspidTlv.routerId);
  }
}

mpls_return_enum ldp_label_rel_with_send(ldp_global * g, ldp_session * s,
  ldp_attr * a, ldp_notif_status status, uint16_t type)
{
  LDP_ENTER(g->user_data, "ldp_label_rel_with_send");

  ldp_label_rel_with_prepare_msg(s->tx_message, g->message_identifier++, a,
    status, type);

  ldp_mesg_send_tcp(g, s, s->tx_message);

  LDP_EXIT(g->user_data, "ldp_label_rel_with_send");

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_label_release_send(ldp_global * g, ldp_session * s,
  ldp_attr * a, ldp_notif_status status)
{

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_LABEL,
    "Release Sent: session(%d)\n", s->index);

  return ldp_label_rel_with_send(g, s, a, status, MPLS_LBLREL_MSGTYPE);
}

mpls_return_enum ldp_label_withdraw_send(ldp_global * g, ldp_session * s,
  ldp_attr * us_attr, ldp_notif_status status)
{

  us_attr->state = LDP_LSP_STATE_WITH_SENT;
  if (ldp_label_rel_with_send(g, s, us_attr, status, MPLS_LBLWITH_MSGTYPE) ==
    MPLS_FAILURE) {
    return MPLS_FAILURE;
  }

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_LABEL,
    "Withdraw Sent: session(%d)\n", s->index);

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_label_release_process(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, ldp_attr * r_attr, ldp_fec * f)
{
  mpls_bool label_exists = MPLS_BOOL_FALSE;
  ldp_attr *us_attr = NULL;
  ldp_attr *ds_attr = NULL;
  mpls_return_enum retval = MPLS_SUCCESS;

  LDP_ENTER(g->user_data, "ldp_label_release_process");

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
    "Release Recv from %s\n", s->session_name);

  if (r_attr->genLblTlvExists || r_attr->atmLblTlvExists
    || r_attr->frLblTlvExists) {
    label_exists = MPLS_BOOL_TRUE;
  }

  if (f) {
    /* LRl.1 is accomplished at LRl.10 */
    us_attr = ldp_attr_find_upstream_state2(g, s, f, LDP_LSP_STATE_MAP_SENT);
    if (!us_attr) {
      us_attr =
        ldp_attr_find_upstream_state2(g, s, f, LDP_LSP_STATE_WITH_SENT);
      if (!us_attr) {           /* LRl.2 */
        goto LRl_13;
      }
      /* LRl.3 is accomplished at LRl.10 */
    }

    if (g->label_merge == MPLS_BOOL_FALSE) { /* LR1.4 */
      goto LRl_6;
    }
    /* LR1.5 */
    if (ldp_attr_find_upstream_state_any2(g, f, LDP_LSP_STATE_MAP_SENT)) {
      goto LRl_10;
    }

  LRl_6:
    /* we can only propogate a release to the downstream attached to
       the upstream we found up top */
    /* LRl.6,7 */
    if (us_attr->ds_attr && us_attr->ds_attr->state == LDP_LSP_STATE_MAP_RECV) {
      ds_attr = us_attr->ds_attr;
    } else {
      goto LRl_10;
    }

    if (g->propagate_release == MPLS_BOOL_FALSE) { /* LRl.8 */
      goto LRl_10;
    }

    if (ldp_label_release_send(g, ds_attr->session, ds_attr,
      LDP_NOTIF_NONE) != MPLS_SUCCESS) { /* LRl.9 */
      retval = MPLS_FAILURE;
    }
    ldp_attr_remove_complete(g, ds_attr, MPLS_BOOL_FALSE);

  LRl_10:
    ldp_attr_remove_complete(g, us_attr, MPLS_BOOL_FALSE); /* LRl.10,11 */

  } else {
    LDP_PRINT(g->user_data, "No FEC in release, need to implement\n");
    MPLS_ASSERT(0);
  }

LRl_13:
  LDP_EXIT(g->user_data, "ldp_label_release_process");
  return retval;
}

mpls_return_enum ldp_label_withdraw_process(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, ldp_attr * r_attr, ldp_fec * f)
{
  mpls_bool label_exists = MPLS_BOOL_FALSE;
  ldp_attr_list *ds_list = NULL;
  ldp_attr *ds_attr = NULL;
  ldp_attr *ds_temp = NULL;
  ldp_attr *us_temp = NULL;
  ldp_nexthop *nh = NULL;
  mpls_return_enum retval = MPLS_SUCCESS;

  LDP_ENTER(g->user_data, "ldp_label_withdraw_process");

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
    "Withdraw Recv for %s\n", s->session_name);

  if (r_attr->genLblTlvExists || r_attr->atmLblTlvExists
    || r_attr->frLblTlvExists) {
    label_exists = MPLS_BOOL_TRUE;
  } else {
    MPLS_ASSERT(0);
  }

  if (f) {
    if ((ds_list = ldp_attr_find_downstream_all2(g, s, f)) != NULL) {
      ds_temp = MPLS_LIST_HEAD(ds_list);
      while (ds_temp) {
        if (ds_temp->state == LDP_LSP_STATE_MAP_RECV) { /* LWd.3 */
          if (ldp_attr_is_equal(r_attr, ds_temp, LDP_ATTR_LABEL)) {
            ds_attr = ds_temp;
	    break;
          }
        }
        ds_temp = MPLS_LIST_NEXT(ds_list, ds_temp, _fs);
      }
    }

    if (!ds_attr) {
      retval = MPLS_FAILURE;
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
        "Withdraw Recv for a non-existant mapping from %s\n",s->session_name);
      goto LWd_13;
    }

    /*
     * we want to remove it from the tree, but not delete it yet
     * so hold a refcnt, we will release that refcnt at the end, thus
     * deleting it if no one else it holding a refcnt
     */
    MPLS_REFCNT_HOLD(ds_attr);
    ldp_attr_remove_complete(g, ds_attr, MPLS_BOOL_FALSE); /* LWd.4 */

    /* LWd.2 */
    if (ldp_label_release_send(g, s, ds_attr, LDP_NOTIF_NONE) != MPLS_SUCCESS) {
      retval = MPLS_FATAL;
      goto LWd_13;
    }

    if (g->lsp_control_mode == LDP_CONTROL_ORDERED) { /* LWd.5 */
      goto LWd_8;
    }

    if (s->oper_distribution_mode != LDP_DISTRIBUTION_ONDEMAND) { /* LWd.6 */
      goto LWd_13;
    }

    MPLS_ASSERT((nh = ldp_nexthop_for_fec_session(f, s)));
    retval = ldp_fec_process_add(g, f, nh, s);	/* LWd.7 */
    goto LWd_13;

  LWd_8:
    /* I can only propogate a label withdraw to the upstreams attached
       to the downstream found above */

    us_temp = MPLS_LIST_HEAD(&ds_attr->us_attr_root);
    while (us_temp) {
      if (us_temp->state == LDP_LSP_STATE_MAP_SENT) {
        if (ldp_label_withdraw_send(g, us_temp->session, us_temp,
            LDP_NOTIF_NONE) != MPLS_SUCCESS) { /* LWd.11 */
          retval = MPLS_FATAL;
          goto LWd_13;
        }
      }
      us_temp = MPLS_LIST_NEXT(&ds_attr->us_attr_root, us_temp, _ds_attr);
    }
  } else {
    /* JLEU: process wildcard FEC stuff here */
    MPLS_ASSERT(0);
  }

LWd_13:
  if (ds_attr) {
    MPLS_REFCNT_RELEASE(ds_attr, ldp_attr_delete);
  }

  LDP_EXIT(g->user_data, "ldp_label_withdraw_process");

  return retval;
}
