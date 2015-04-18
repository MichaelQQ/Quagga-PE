
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_session.h"
#include "ldp_attr.h"
#include "ldp_fec.h"
#include "ldp_mesg.h"
#include "ldp_notif.h"
#include "ldp_entity.h"
#include "ldp_inlabel.h"
#include "ldp_outlabel.h"
#include "ldp_nexthop.h"
#include "ldp_global.h"
#include "ldp_pdu_setup.h"
#include "ldp_label_rel_with.h"
#include "ldp_label_mapping.h"
#include "ldp_label_request.h"

#include "mpls_timer_impl.h"
#include "mpls_fib_impl.h"
#include "mpls_lock_impl.h"
#include "mpls_tree_impl.h"
#include "mpls_trace_impl.h"
#include "mpls_mm_impl.h"
#include "mpls_policy_impl.h"

#if MPLS_USE_LSR
#include "lsr_cfg.h"
#else
#include "mpls_mpls_impl.h"
#endif

mpls_return_enum ldp_label_mapping_with_xc(ldp_global * g, ldp_session * s,
  ldp_fec * f, ldp_attr ** us_attr, ldp_attr * ds_attr)
{
  mpls_return_enum result = MPLS_SUCCESS;
  mpls_bool propogating = MPLS_BOOL_TRUE;
  mpls_bool egress = MPLS_BOOL_TRUE;
  mpls_bool created = MPLS_BOOL_FALSE;

  MPLS_ASSERT(us_attr);

  if (!(*us_attr)) {
    if (!((*us_attr) = ldp_attr_create(&f->info))) {
      return MPLS_FAILURE;
    }
    created = MPLS_BOOL_TRUE;
  }
  if (!ds_attr) {
    propogating = MPLS_BOOL_FALSE;
    egress = MPLS_BOOL_TRUE;
  }

  Prepare_Label_Mapping_Attributes(g, s, &f->info, ds_attr, (*us_attr),
    propogating, MPLS_BOOL_TRUE, egress);

  result = ldp_label_mapping_send(g, s, f, (*us_attr), ds_attr);
  if (result != MPLS_SUCCESS) {
    if (created == MPLS_BOOL_TRUE) {
      ldp_attr_delete(*us_attr);
    }
    return result;
  }

  if (created == MPLS_BOOL_TRUE) {
    result = ldp_attr_insert_upstream2(g, s, (*us_attr), f);
    if (result != MPLS_SUCCESS) {
      ldp_attr_delete(*us_attr);
      return result;
    }
  }

  /*
   * If we have a downstream mapping (not neccessarily installed) and
   * the downstream and upstream session are not the same....
   */
  if (ds_attr && ((*us_attr)->session->index != ds_attr->session->index)) {
    /* then link the attra */
    ldp_attr_add_us2ds((*us_attr), ds_attr);

    /* if we just created the upstream, and we have install the
     * downstream, then cross connect them */
    if ((created == MPLS_BOOL_TRUE) && ds_attr->outlabel) {

      if ((*us_attr)->inlabel->outlabel) {
        /*
         * if we use an existing upstream mapping (in ldp_label_mapping_send())
         * the inlabel will already be be connected to an outlabel;
         */
        MPLS_ASSERT((*us_attr)->inlabel->outlabel == ds_attr->outlabel);
      } else {
        LDP_TRACE_LOG(g->user_data,MPLS_TRACE_STATE_ALL,LDP_TRACE_FLAG_BINDING,
          "Cross Connect Added for %08x/%d from %s -> %s\n",
          f->info.u.prefix.network.u.ipv4, f->info.u.prefix.length,
          (*us_attr)->session->session_name, ds_attr->session->session_name);

        result = ldp_inlabel_add_outlabel(g,(*us_attr)->inlabel,
          ds_attr->outlabel);
        if (result != MPLS_SUCCESS) {
          return result;
        }
      }
    }
  }
  return MPLS_SUCCESS;
}

ldp_session *ldp_get_next_hop_session_for_fec2(ldp_fec * f, ldp_nexthop *nh) {
  ldp_session *session = NULL;
  /*
   * find the info about the next hop for this FEC
   */
  if (nh->addr && nh->addr->session_root.count > 0) {
    session = mpls_link_list_head_data(&nh->addr->session_root);
  } else if (nh->iff && nh->iff->is_p2p == MPLS_BOOL_TRUE &&
    &nh->iff->entity) {
    ldp_adj *adj = MPLS_LIST_HEAD(&nh->iff->entity->adj_root);
    session = adj ? adj->session : NULL;
  }
  return session;
}

mpls_return_enum ldp_get_next_hop_session_for_fec(ldp_global * g,
  mpls_fec * fec, mpls_nexthop *nh, ldp_session ** next_hop_session)
{
  ldp_fec *f = NULL;
  ldp_nexthop *n = NULL;

  MPLS_ASSERT(next_hop_session);

  if (!(f = ldp_fec_find(g, fec))) {
    return MPLS_NO_ROUTE;
  }

  if (!(n = ldp_fec_nexthop_find(f, nh))) {
    return MPLS_NO_ROUTE;
  }

  *next_hop_session = ldp_get_next_hop_session_for_fec2(f,n);
  return (*next_hop_session) ? MPLS_SUCCESS : MPLS_FAILURE;
}

mpls_return_enum Check_Received_Attributes(ldp_global * g, ldp_session * s,
  ldp_attr * r_attr, uint16_t type)
{
  int count = 0;
  int i;

  if (!r_attr->hopCountTlvExists) { /* CRa.1 */
    goto Check_Received_Attributes_5;
  }

  if (r_attr->hopCountTlv.hcValue >= s->cfg_hop_count_limit) { /* CRa.2 */
    LDP_PRINT(g->user_data, "CRa.2\n");
    goto Check_Received_Attributes_6;
  }

  if (!r_attr->pathVecTlvExists) { /* CRa.3 */
    goto Check_Received_Attributes_5;
  }

  for (i = 0; i < MPLS_MAXHOPSNUMBER; i++) { /* CRa.4 */
    if (r_attr->pathVecTlv.lsrId[i]) {
      count++;
      if (r_attr->pathVecTlv.lsrId[i] == g->lsr_identifier.u.ipv4) {
        goto Check_Received_Attributes_6;
        LDP_PRINT(g->user_data, "CRa.4a\n");
      }
      if (count > s->oper_path_vector_limit) {
        goto Check_Received_Attributes_6;
        LDP_PRINT(g->user_data, "CRa.4b\n");
      }
    }
  }

Check_Received_Attributes_5:
  return MPLS_SUCCESS;

Check_Received_Attributes_6:
  if (type != MPLS_LBLMAP_MSGTYPE) {
    ldp_notif_send(g, s, r_attr, LDP_NOTIF_LOOP_DETECTED); /* CRa.7 */
  }
  return MPLS_FAILURE;           /* CRa.8 */
}

void Prepare_Label_Mapping_Attributes(ldp_global * g, ldp_session * s,
  mpls_fec * fec, ldp_attr * r_attr, ldp_attr * s_attr, mpls_bool propogating,
  mpls_bool already, mpls_bool egress)
{
  ldp_attr dummy;
  int i;

  /* NOTE: PMpA.21 is the end of the procedure (ie return) */
  /* this function uses goto quite extensivly for a REASON!! */
  /* Check Appedix A of the LDP draft */

  LDP_ENTER(g->user_data, "Prepare_Label_Mapping_Attributes");

  if (!r_attr) {
    memset(&dummy, 0, sizeof(ldp_attr));
    mpls_fec2fec_tlv(fec, &dummy.fecTlv, 0);
    dummy.fecTlvExists = 1;
    dummy.fecTlv.numberFecElements = 1;
    r_attr = &dummy;
  }

  if (!(s->oper_loop_detection == LDP_LOOP_HOPCOUNT ||
    s->oper_loop_detection == LDP_LOOP_HOPCOUNT_PATHVECTOR ||
    r_attr->hopCountTlvExists)) { /* PMpA.1 */
    LDP_EXIT(g->user_data, "Prepare_Label_Mapping_Attributes");
    return;
  }

  if (egress) {/* PMpA.2 */
    /* I'm egress (for now) */
    s_attr->hopCountTlvExists = 1;
    s_attr->hopCountTlv.hcValue = 1; /* PMpA.3 */
    LDP_EXIT(g->user_data, "Prepare_Label_Mapping_Attributes");
    return;
  }

  if (!(r_attr->hopCountTlvExists)) { /* PMpA.4 */
    goto Prepare_Label_Mapping_Attributes_8;
  }

  if (!(g->ttl_less_domain == MPLS_BOOL_TRUE &&
    s->cfg_remote_in_ttl_less_domain == MPLS_BOOL_TRUE)) { /* PMpA.5 */
    goto Prepare_Label_Mapping_Attributes_7;
  }

  s_attr->hopCountTlvExists = 1;
  s_attr->hopCountTlv.hcValue = 1; /* PMpA.6 */
  goto Prepare_Label_Mapping_Attributes_9;

Prepare_Label_Mapping_Attributes_7:
  s_attr->hopCountTlvExists = 1;
  s_attr->hopCountTlv.hcValue = (r_attr->hopCountTlv.hcValue) ?
    (r_attr->hopCountTlv.hcValue + 1) : 0;
  goto Prepare_Label_Mapping_Attributes_9;

Prepare_Label_Mapping_Attributes_8:
  s_attr->hopCountTlvExists = 1;
  s_attr->hopCountTlv.hcValue = 0;

Prepare_Label_Mapping_Attributes_9:
  if (s->oper_loop_detection == LDP_LOOP_NONE) {
    LDP_EXIT(g->user_data, "Prepare_Label_Mapping_Attributes");
    return;
  }

  if (r_attr->pathVecTlvExists) { /* PMpA.10 */
    goto Prepare_Label_Mapping_Attributes_19;
  }

  if (propogating == MPLS_BOOL_FALSE) { /* PMpA.11 */
    goto Prepare_Label_Mapping_Attributes_20;
  }

  if (g->label_merge != MPLS_BOOL_TRUE) { /* PMpA.12 */
    goto Prepare_Label_Mapping_Attributes_14;
  }

  if (already == MPLS_BOOL_FALSE) {   /* PMpA.13 */
    goto Prepare_Label_Mapping_Attributes_20;
  }

Prepare_Label_Mapping_Attributes_14:
  if (!r_attr->hopCountTlvExists) {
    LDP_EXIT(g->user_data, "Prepare_Label_Mapping_Attributes");
    return;
  }

  if (r_attr->hopCountTlv.hcValue == 0) { /* PMpA.15 */
    goto Prepare_Label_Mapping_Attributes_20;
  }

  if (already == MPLS_BOOL_FALSE) {   /* PMpA.16 */
    LDP_EXIT(g->user_data, "Prepare_Label_Mapping_Attributes");
    return;
  }

  /* r_attr contain PrevHopCount _IF_ we had one */
  LDP_EXIT(g->user_data, "Prepare_Label_Mapping_Attributes");
  return;                       /* PMpA.17 */

  if (r_attr->hopCountTlv.hcValue != 0) { /* PMpA.18 */
    LDP_EXIT(g->user_data, "Prepare_Label_Mapping_Attributes");
    return;
  }

Prepare_Label_Mapping_Attributes_19:
  s_attr->pathVecTlvExists = 1;
  s_attr->pathVecTlv.lsrId[0] = g->lsr_identifier.u.ipv4;
  for (i = 1; i < (MPLS_MAXHOPSNUMBER - 1); i++) {
    if (r_attr->pathVecTlv.lsrId[i - 1]) {
      s_attr->pathVecTlv.lsrId[0] = r_attr->pathVecTlv.lsrId[i - 1];
    }
  }

  LDP_EXIT(g->user_data, "Prepare_Label_Mapping_Attributes");
  return;

Prepare_Label_Mapping_Attributes_20:
  s_attr->pathVecTlvExists = 1;
  s_attr->pathVecTlv.lsrId[0] = g->lsr_identifier.u.ipv4;

  LDP_EXIT(g->user_data, "Prepare_Label_Mapping_Attributes");
  return;
}

void map2attr(mplsLdpLblMapMsg_t * map, ldp_attr * attr, uint32_t flag)
{
  attr->msg_id = map->baseMsg.msgId;
  if (map->fecTlvExists && flag & LDP_ATTR_FEC) {
    memcpy(&attr->fecTlv, &map->fecTlv, sizeof(mplsLdpFecTlv_t));
    attr->fecTlvExists = 1;
  }
  if (map->genLblTlvExists && flag & LDP_ATTR_LABEL) {
    memcpy(&attr->genLblTlv, &map->genLblTlv, sizeof(mplsLdpGenLblTlv_t));
    attr->genLblTlvExists = 1;
  } else if (map->atmLblTlvExists && flag & LDP_ATTR_LABEL) {
    memcpy(&attr->atmLblTlv, &map->atmLblTlv, sizeof(mplsLdpAtmLblTlv_t));
    attr->atmLblTlvExists = 1;
  } else if (map->frLblTlvExists && flag & LDP_ATTR_LABEL) {
    memcpy(&attr->frLblTlv, &map->frLblTlv, sizeof(mplsLdpFrLblTlv_t));
    attr->frLblTlvExists = 1;
  }
  if (map->hopCountTlvExists && flag & LDP_ATTR_HOPCOUNT) {
    memcpy(&attr->hopCountTlv, &map->hopCountTlv, sizeof(mplsLdpHopTlv_t));
    attr->hopCountTlvExists = 1;
  }
  if (map->pathVecTlvExists && flag & LDP_ATTR_PATH) {
    memcpy(&attr->pathVecTlv, &map->pathVecTlv, sizeof(mplsLdpPathTlv_t));
    attr->pathVecTlvExists = 1;
  }
  if (map->lblMsgIdTlvExists && flag & LDP_ATTR_MSGID) {
    memcpy(&attr->lblMsgIdTlv, &map->lblMsgIdTlv, sizeof(mplsLdpLblMsgIdTlv_t));
    attr->lblMsgIdTlvExists = 1;
  }
  if (map->lspidTlvExists && flag & LDP_ATTR_LSPID) {
    memcpy(&attr->lspidTlv, &map->lspidTlv, sizeof(mplsLdpLspIdTlv_t));
    attr->lspidTlvExists = 1;
  }
  if (map->trafficTlvExists && flag & LDP_ATTR_TRAFFIC) {
    memcpy(&attr->trafficTlv, &map->trafficTlv, sizeof(mplsLdpTrafficTlv_t));
    attr->trafficTlvExists = 1;
  }
}

void attr2map(ldp_attr * attr, mplsLdpLblMapMsg_t * map)
{
  if (attr->fecTlvExists) {
    memcpy(&map->fecTlv, &attr->fecTlv, sizeof(mplsLdpFecTlv_t));
    map->fecTlvExists = 1;
  }
  if (attr->genLblTlvExists) {
    memcpy(&map->genLblTlv, &attr->genLblTlv, sizeof(mplsLdpGenLblTlv_t));
    map->genLblTlvExists = 1;
  }
  if (attr->atmLblTlvExists) {
    memcpy(&map->atmLblTlv, &attr->atmLblTlv, sizeof(mplsLdpAtmLblTlv_t));
    map->atmLblTlvExists = 1;
  }
  if (attr->frLblTlvExists) {
    memcpy(&map->frLblTlv, &attr->frLblTlv, sizeof(mplsLdpFrLblTlv_t));
    map->frLblTlvExists = 1;
  }
  if (attr->hopCountTlvExists) {
    memcpy(&map->hopCountTlv, &attr->hopCountTlv, sizeof(mplsLdpHopTlv_t));
    map->hopCountTlvExists = 1;
  }
  if (attr->pathVecTlvExists) {
    memcpy(&map->pathVecTlv, &attr->pathVecTlv, sizeof(mplsLdpPathTlv_t));
    map->pathVecTlvExists = 1;
  }
  if (attr->lblMsgIdTlvExists) {
    memcpy(&map->lblMsgIdTlv, &attr->lblMsgIdTlv, sizeof(mplsLdpLblMsgIdTlv_t));
    map->lblMsgIdTlvExists = 1;
  }
  if (attr->lspidTlvExists) {
    memcpy(&map->lspidTlv, &attr->lspidTlv, sizeof(mplsLdpLspIdTlv_t));
    map->lspidTlvExists = 1;
  }
  if (attr->trafficTlvExists) {
    memcpy(&map->trafficTlv, &attr->trafficTlv, sizeof(mplsLdpTrafficTlv_t));
    map->trafficTlvExists = 1;
  }
}

void ldp_label_mapping_initial_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle handle)
{
  ldp_session *s = (ldp_session *) extra;
  ldp_global *g = (ldp_global*)handle;
  ldp_attr *ds_attr = NULL;
  ldp_attr *us_attr = NULL;
  ldp_session *nh_session = NULL;
  mpls_bool done = MPLS_BOOL_FALSE;
  ldp_fec *f;
  ldp_nexthop *nh;

  LDP_ENTER(g->user_data, "ldp_label_mapping_initial_callback");

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_TIMER,
    "Initial Label Mapping fired: session(%d)\n", s->index);

  mpls_lock_get(g->global_lock);

  mpls_timer_stop(g->timer_handle, timer);

  f = MPLS_LIST_HEAD(&g->fec);
  while (f) {
    nh = MPLS_LIST_HEAD(&f->nh_root);
    while (nh) {
      switch (f->info.type) {
	case MPLS_FEC_PREFIX:
          LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
            LDP_TRACE_FLAG_ROUTE, "Processing prefix FEC: %08x/%d ",
	    f->info.u.prefix.network.u.ipv4, f->info.u.prefix.length);
	  break;
	case MPLS_FEC_HOST:
          LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
            LDP_TRACE_FLAG_ROUTE, "Processing host FEC: %08x ",
	    f->info.u.host.u.ipv4);
	  break;
	case MPLS_FEC_L2CC:
          LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
            LDP_TRACE_FLAG_ROUTE, "Processingu L2CC FEC: %d %d %d ",
	    f->info.u.l2cc.connection_id, f->info.u.l2cc.group_id, 
	    f->info.u.l2cc.type);
	  break;
	default:
	  MPLS_ASSERT(0);
      }

      if (nh->info.type & MPLS_NH_IP) {
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
          LDP_TRACE_FLAG_ROUTE, "via %08x\n", nh->addr->address.u.ipv4);
      }
      if (nh->info.type & MPLS_NH_IF && nh->iff) {
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
          LDP_TRACE_FLAG_ROUTE, "via %p\n", nh->iff->handle);
      }

      /* are we allowed to export this route from the rib */
      if (mpls_policy_export_check(g->user_data, &f->info, &nh->info) ==
        MPLS_BOOL_FALSE) {
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
	  LDP_TRACE_FLAG_POLICY, "Rejected by export policy\n");
        goto ldp_label_mapping_initial_callback_end_nh;
      }

      /* have we already sent a mapping for this fec to the new session? */
      if ((us_attr = ldp_attr_find_upstream_state2(g, s, f,
        LDP_LSP_STATE_MAP_SENT))) {
        /* no need to sent another mapping */
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
          LDP_TRACE_FLAG_ROUTE, "Already sent this FEC to session %d\n",
	  s->index);
        goto ldp_label_mapping_initial_callback_end_nh;
      }

      if (!(nh_session = ldp_get_next_hop_session_for_fec2(f,nh))) {
        ds_attr = NULL;
      } else {
        if (nh_session->index == s->index) {
          LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
            LDP_TRACE_FLAG_ROUTE, "Nexthop session(%d) == session(%d)\n",
            nh_session->index, s->index);
          goto ldp_label_mapping_initial_callback_end_nh;
        }
        ds_attr = ldp_attr_find_downstream_state2(g, nh_session, f,
          LDP_LSP_STATE_MAP_RECV);
      }

      if ((g->label_merge != MPLS_BOOL_TRUE) &&
        ldp_attr_num_us2ds(ds_attr)) {
        /* we have a ds label, but can't use it */
        ds_attr = NULL;
      }

      us_attr = NULL;
      if (ds_attr) {
        /* we can use it, merge on baby */
        ldp_label_mapping_with_xc(g, s, f, &us_attr, ds_attr);
      } else {
        /* we don't have a ds label */

        /* we will be egress? */
        if (g->lsp_control_mode == LDP_CONTROL_ORDERED) {
          if (mpls_policy_egress_check(g->user_data, &f->info,
	    &nh->info) == MPLS_BOOL_TRUE) {
            ldp_label_mapping_with_xc(g, s, f, &us_attr, NULL);
          }
        } else {
          ldp_label_mapping_with_xc(g, s, f, &us_attr, NULL);
        }
      }
ldp_label_mapping_initial_callback_end_nh:
      nh = MPLS_LIST_NEXT(&f->nh_root, nh, _fec);
    }
    f = MPLS_LIST_NEXT(&g->fec, f, _global);
  }
  done = MPLS_BOOL_TRUE;

  if (done == MPLS_BOOL_TRUE) {
    mpls_timer_delete(g->timer_handle, timer);
    MPLS_REFCNT_RELEASE(s, ldp_session_delete);
    s->initial_distribution_timer = (mpls_timer_handle) 0;
  } else {
    mpls_timer_start(g->timer_handle, timer, MPLS_TIMER_ONESHOT);
    /* need to mark the session with where it left off */
  }

  mpls_lock_release(g->global_lock);

  LDP_EXIT(g->user_data, "ldp_label_mapping_initial_callback");
}

mpls_return_enum ldp_label_mapping_send(ldp_global * g, ldp_session * s,
  ldp_fec *f, ldp_attr * us_attr, ldp_attr * ds_attr)
{
  ldp_inlabel *in = NULL;
  ldp_attr *us_temp, *existing = NULL;

  LDP_ENTER(g->user_data, "ldp_label_mapping_send");
  MPLS_ASSERT(us_attr);

#if 0
  /*
   * before we can enable this, inlabels need to keep track of all of
   * the attr that link to it.  Then when running in DU independent mode we
   * can correctly attach the us and ds attrs involved when propogating a
   * new mapping for a FEC we've already distributed labels for
   */
  existing = ldp_attr_find_upstream_map_in_labelspace(f, s->cfg_label_space);
#endif

  if (existing) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_BINDING,
      "Using an existing label\n");
    in = existing->inlabel;
    ldp_attr_add_inlabel(us_attr, in);
  } else {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_BINDING,
      "Generating a label\n");
    in = ldp_inlabel_create_complete(g, s, us_attr);
  }

  if (!in) { /* SL.1-3 */
    goto Send_Label_9;
  }

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_BINDING,
    "In Label Added\n");

  us_attr->state = LDP_LSP_STATE_MAP_SENT;

  us_attr->msg_id = g->message_identifier;
  ldp_label_mapping_prepare_msg(s->tx_message, g->message_identifier++,
    us_attr);

  if (ldp_mesg_send_tcp(g, s, s->tx_message) != MPLS_SUCCESS) { /* SL.4 */
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_ERROR,
      "Failed sending Label Mapping to %s\n",
      s->session_name);
    goto ldp_label_mapping_send_error;
  }

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_LABEL,
    "Label Mapping Sent to %s for %08x/%d\n",
    s->session_name,
    us_attr->fecTlv.fecElArray[0].addressEl.address,
    us_attr->fecTlv.fecElArray[0].addressEl.preLen);

  us_attr->state = LDP_LSP_STATE_MAP_SENT; /* SL.6,7 */

  LDP_EXIT(g->user_data, "ldp_label_mapping_send");
  return MPLS_SUCCESS;           /* SL.8 */

Send_Label_9:
  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_STATE,
    "No Label Resources\n");

  while ((us_temp = ldp_attr_find_upstream_state2(g, s, us_attr->fec,
        LDP_LSP_STATE_REQ_RECV)) != NULL) { /* SL.9 */
    ldp_notif_send(g, s, us_temp, LDP_NOTIF_NO_LABEL_RESOURCES_AVAILABLE);
    /* SL.10 */
    s->no_label_resource_sent = MPLS_BOOL_TRUE; /* SL.12 */
    us_temp->state = LDP_LSP_STATE_NO_LABEL_RESOURCE_SENT; /* SL.13 */
  }

  LDP_EXIT(g->user_data, "ldp_label_mapping_send");

  return MPLS_SUCCESS;

ldp_label_mapping_send_error:

  LDP_EXIT(g->user_data, "ldp_label_mapping_send-error");
  return MPLS_FAILURE;
}

void ldp_label_mapping_prepare_msg(ldp_mesg * msg, uint32_t msgid,
  ldp_attr * s_attr)
{
  mplsLdpLblMapMsg_t *map = NULL;
  int i;

  MPLS_ASSERT(msg);

  ldp_mesg_prepare(msg, MPLS_LBLMAP_MSGTYPE, msgid);
  map = &msg->u.map;

  if (s_attr->fecTlvExists) {
    /* JLEU: only 1 FEC is allowed!! */
    map->fecTlvExists = 1;
    map->baseMsg.msgLength += setupFecTlv(&map->fecTlv);
    map->baseMsg.msgLength += addFecElem2FecTlv(&map->fecTlv,
      &s_attr->fecTlv.fecElArray[0]);
  }
  if (s_attr->genLblTlvExists) {
    map->genLblTlvExists = 1;
    map->baseMsg.msgLength += setupGenLblTlv(&map->genLblTlv,
      s_attr->genLblTlv.label);
  }
  if (s_attr->atmLblTlvExists) {
    map->atmLblTlvExists = 1;
    map->baseMsg.msgLength += setupAtmLblTlv(&map->atmLblTlv, 0, 0,
      s_attr->atmLblTlv.flags.flags.vpi, s_attr->atmLblTlv.vci);
  }
  if (s_attr->frLblTlvExists) {
    map->frLblTlvExists = 1;
    map->baseMsg.msgLength += setupFrLblTlv(&map->frLblTlv, 0,
      s_attr->frLblTlv.flags.flags.len, s_attr->frLblTlv.flags.flags.dlci);
  }
  if (s_attr->hopCountTlvExists) {
    map->hopCountTlvExists = 1;
    map->baseMsg.msgLength += setupHopCountTlv(&map->hopCountTlv,
      s_attr->hopCountTlv.hcValue);
  }
  if (s_attr->pathVecTlvExists) {
    map->pathVecTlvExists = 1;
    map->baseMsg.msgLength += setupPathTlv(&map->pathVecTlv);
    for (i = 0; i < MPLS_MAXHOPSNUMBER; i++) {
      if (s_attr->pathVecTlv.lsrId[i]) {
        map->baseMsg.msgLength += addLsrId2PathTlv(&map->pathVecTlv,
          s_attr->pathVecTlv.lsrId[i]);
      }
    }
  }
#if 0
  if (s_attr->lblMsgIdTlvExists) {
  }
  if (s_attr->lspidTlvExists) {
  }
  if (s_attr->trafficTlvExists) {
  }
#endif
}

mpls_return_enum ldp_label_mapping_process(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, ldp_attr * r_attr, ldp_fec * f)
{
  mpls_return_enum retval = MPLS_SUCCESS;
  ldp_session *peer = NULL;
  ldp_attr_list *us_list = NULL;
  ldp_attr_list *ds_list = NULL;
  ldp_attr *ds_attr = NULL;
  ldp_attr *ds_temp = NULL;
  ldp_attr *us_attr = NULL;
  ldp_attr *us_temp = NULL;
  ldp_attr dumb_attr;
  ldp_nexthop *nh = NULL;

  ldp_outlabel *out = NULL;
  mpls_bool requested = MPLS_BOOL_FALSE;
  ldp_attr *existing = NULL;
  mpls_bool need_request = MPLS_BOOL_FALSE;

  LDP_ENTER(g->user_data, "ldp_label_mapping_process");

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
    "Label Mapping Recv from %s for %08x/%d\n",
    s->session_name,
    r_attr->fecTlv.fecElArray[0].addressEl.address,
    r_attr->fecTlv.fecElArray[0].addressEl.preLen);

  if ((ds_attr = ldp_attr_find_downstream_state2(g, s, f,
        LDP_LSP_STATE_REQ_SENT)) != NULL) { /* LMp.1 */
    /* just remove the req from the tree, we will use the r_attr sent to us */
    ldp_attr_delete_downstream(g, s, ds_attr);
    requested = MPLS_BOOL_TRUE;
  } else {
    requested = MPLS_BOOL_FALSE;
  }

  ds_attr = r_attr;
  ds_attr->state = LDP_LSP_STATE_MAP_RECV; /* LMp.2 */

  /*
   * ds_attr is the mapping we will keep and is NOT in the tree, unless
   * it is an update mapping ...
   */
  if (Check_Received_Attributes(g, s, ds_attr, MPLS_LBLMAP_MSGTYPE) ==
    MPLS_SUCCESS) { /* LMp.3 */
    goto LMp_9;
  }

  /*
   * A loop was detected
   */
  if ((ds_list = ldp_attr_find_downstream_all2(g, s, f))) {
    ds_temp = MPLS_LIST_HEAD(ds_list);
    /*
     * check all the labels this session has received from "s" for "fec"
     * do we have a duplicat?
     */
    while (ds_temp) {
      if ((ds_temp->state == LDP_LSP_STATE_MAP_RECV) && /* LMp.4 */
        ldp_attr_is_equal(ds_temp, ds_attr, LDP_ATTR_LABEL) == /* LMp.5 */
        MPLS_BOOL_TRUE) {
        /* remove record of the label and remove it switching */
        ldp_attr_remove_complete(g, ds_temp, MPLS_BOOL_TRUE); /* LMp.6,7 */
        /*
         * I think this is supposed to be 32 NOT 33, we need to release
         * it don't we?
         */
        goto LMp_33;
      }
      ds_temp = MPLS_LIST_NEXT(ds_list, ds_temp, _fs);
    }
  }

  LDP_PRINT(g->user_data, "Receive_Label_Map_8: send release");
  if (ldp_label_release_send(g, s, ds_attr, LDP_NOTIF_LOOP_DETECTED) !=
    MPLS_SUCCESS) { /* LMp.8 */
    retval = MPLS_FAILURE;
  }
  goto LMp_33;

LMp_9:
  /*
   * No Loop Detected
   */
  ds_temp = ldp_attr_find_downstream_state2(g, s, f, LDP_LSP_STATE_MAP_RECV);
  if (requested == MPLS_BOOL_TRUE ||
      g->label_merge == MPLS_BOOL_FALSE || !ds_temp) {
    /* !merging then this is always a new LSP
     * merging w/o a recv'd mapping is a new LSP
     * this check comes from Note 6
     */
    goto LMp_11;
  }

  /* searching all recv'd attrs for matched mappings,
   * stop after finding 1st match
   */
  if ((ds_list = ldp_attr_find_downstream_all2(g, s, f))) {
    ds_temp = MPLS_LIST_HEAD(ds_list);
    while (ds_temp) {
      if (ds_temp->state == LDP_LSP_STATE_MAP_RECV) { /* LMp.9 */
        if (ldp_attr_is_equal(ds_attr, ds_temp, LDP_ATTR_LABEL) ==
          MPLS_BOOL_TRUE) { /* LMp.10 */
          /*
           * this mapping matches an existing mapping, but it
           * could contain updated attributes
           */
          existing = ds_temp;
          break;
        } else {
          /*
           * we have been given another label for the same FEC and we
           * didn't request it, release it
           */
          LDP_PRINT(g->user_data, "LMp.10 dup without req\n");
          goto LMp_32;
        }
      }
      ds_temp = MPLS_LIST_NEXT(ds_list, ds_temp, _fs);
    }
  }
  if (existing) {
    ldp_attr2ldp_attr(ds_attr, existing, LDP_ATTR_HOPCOUNT | LDP_ATTR_PATH |
      LDP_ATTR_MSGID | LDP_ATTR_LSPID | LDP_ATTR_TRAFFIC);
    ds_attr = existing;
    /*
     * no need to free ds_attr, since it was not added to the tree it
     * will be deleted when we exit ldp_label_mapping_process(), see
     * ldp_state_process().
     */
  }
  /*
   * from this point on.... if this is an updated mapping then ds_attr
   * is the existing mapping which has now been update, else ds_attr
   * is the new mapping
   */

LMp_11:
  /*
   * existing ONLY has a value for updated label mapping
   */
  nh = ldp_nexthop_for_fec_session(f,s);			 /* LMp.11 */

  /*
   * the following departs from the procedure, it allows for filtering
   * of label mappings
   *
   * Are we configured to accept and INSTALL this mapping?
   */
  if (mpls_policy_import_check(g->user_data, &f->info, &nh->info) ==
    MPLS_BOOL_FALSE) {
    /*
     * policy has rejected it, store it away
     */
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
      "Label Mapping for %08x/%d from %s filtered by import policy\n",
      r_attr->fecTlv.fecElArray[0].addressEl.address,
      r_attr->fecTlv.fecElArray[0].addressEl.preLen, s->session_name);

    if (existing) {
      ds_attr->filtered = MPLS_BOOL_TRUE;
      if (ds_attr->outlabel && ds_attr->outlabel->switching == MPLS_BOOL_TRUE) {
        /* the mapping has been filtered, but the original wasn't? */
        MPLS_ASSERT(0);
      }
    } else {
      ds_attr->filtered = MPLS_BOOL_TRUE;
      if (ldp_attr_insert_downstream(g, s, ds_attr) != MPLS_SUCCESS) {
        retval = MPLS_FAILURE;
      }
    } 
    goto LMp_33;
  }

  if (!nh) {							 /* LMp.12 */
    /*
     * if we did not find a nh hop for this FEC that corresponded to the
     * MsgSource then the MsgSource is not a nexthop for the FEC
     */
    if (g->label_retention_mode == LDP_RETENTION_CONSERVATIVE) { /* LMp.13C */
      LDP_PRINT(g->user_data, "LMp.13C conservative\n");
      goto LMp_32;
    }

    /*
     * store it away
     */
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
      "Session %s is not a valid nexthop for %08x/%d\n", s->session_name,
      r_attr->fecTlv.fecElArray[0].addressEl.address,
      r_attr->fecTlv.fecElArray[0].addressEl.preLen);

      if (!existing) {
      /* LMp.13L */
      if (ldp_attr_insert_downstream(g, s, ds_attr) != MPLS_SUCCESS) {
        retval = MPLS_FAILURE;
      }
    }
    goto LMp_33;
  }

  /*
   * this is slightly different form the procedure, we can still be
   * transit for a FEC we are not configured to be ingress for.
   * Either way we only need to do the "install for fwd/switching"
   * only once.  We could arrive here multiple times due to updates,
   * only install it the first time
   */
  if ((!existing) || (!existing->outlabel)) {
    /*
     * we haven't installed it yet.
     * Either new (!existing), or a result of a "Detect FEC Nexthop Change"
     * and we had this mapping in our database (!existing->outlabel))
     */

    if (!(out = ldp_outlabel_create_complete(g, s, ds_attr, nh))) {
      LDP_PRINT(g->user_data, "LMp.15 failure creating outlabel\n");
      goto LMp_32;
    }

    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_BINDING,
      "Out Label Added\n");
  }

  /*
   * are we configured to act as ingress for this FEC?
   */
  if (mpls_policy_ingress_check(g->user_data, &f->info, &nh->info) ==
    MPLS_BOOL_TRUE) { /* LMp.14 */
    /*
     * yep, bind the label to the FEC
     */
    if (ds_attr->ingress != MPLS_BOOL_TRUE) {
#if MPLS_USE_LSR
      lsr_ftn ftn;
      ftn.outsegment_index = ds_attr->outlabel->info.handle;
      memcpy(&ftn.fec, &f->info, sizeof(mpls_fec));
      lsr_cfg_ftn_set2(g->lsr_handle, &ftn, LSR_CFG_ADD|LSR_FTN_CFG_FEC|
        LSR_FTN_CFG_OUTSEGMENT);
#else
      mpls_mpls_fec2out_add(g->mpls_handle, &f->info, &ds_attr->outlabel->info);
#endif
      ds_attr->ingress = MPLS_BOOL_TRUE;
      ds_attr->outlabel->merge_count++;
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_BINDING,
        "Acting as ingress for %08x/%d from %s\n",
        r_attr->fecTlv.fecElArray[0].addressEl.address,
        r_attr->fecTlv.fecElArray[0].addressEl.preLen, s->session_name);
    }
  }

  /* create a set of attrs that we will fill and compare against
   * if this mapping were to be propogate these are the attrs it would have
   * by comparing what we did sent in the past to these, we con figure out
   * if we need to send an updated mapping
   */
  memset(&dumb_attr, 0, sizeof(ldp_attr));
  mpls_fec2fec_tlv(&f->info, &dumb_attr.fecTlv, 0);
  dumb_attr.fecTlvExists = 1;
  dumb_attr.fecTlv.numberFecElements = 1;

  /*
   * by definition (we received a label mapping that will be used) this
   * LSR is _not_ the egress, so calculate a hop and path based on the
   * mapping we received.  We will compare this with mapping that have
   * already been sent.  If they differ, we will send an updated mapping
   */
  Prepare_Label_Mapping_Attributes(g, s, &f->info, ds_attr, &dumb_attr,
    MPLS_BOOL_TRUE, MPLS_BOOL_TRUE, MPLS_BOOL_FALSE);

  if (!existing) {
    /*
     * this is the first time we've seen this mapping, add it to the database.
     * all future updates will modify this entry in place
     */
    /* LMp.16 */ printf("!!!LMp16!!!\n");
    if (ldp_attr_insert_downstream(g, s, ds_attr) != MPLS_SUCCESS) {
      retval = MPLS_FAILURE;
      goto LMp_33;
    }
  }

  peer = MPLS_LIST_HEAD(&g->session);
  while (peer) {					/* LMp.17 */

    if (peer->state != LDP_STATE_OPERATIONAL) {
      goto next_peer;
    }

    /*
     * it is just as easy to walk the list of all upstream attr for this
     * peer as it is to the individual check to see if we have sent a
     * label mapping for this FEC LSP
     */

// #error this whole section is f ed

    /* LMp.22 - 27 */
    if ((us_list = ldp_attr_find_upstream_all2(g, peer, f))) {	/* LMp.23 */
      us_temp = MPLS_LIST_HEAD(us_list);
      while (us_temp) {
	/*
	 * if we have sent a label mapping for the FEC and that label mapping
	 * was an done in independent mode or it is part of an LSP created
         * due as part of an existing received label mapping
	 */
	/* LMp.18 */
        if (us_temp->state == LDP_LSP_STATE_MAP_SENT) {
          LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
            LDP_TRACE_FLAG_BINDING, "Already sent mapping for %08x/%d to %s\n",
            r_attr->fecTlv.fecElArray[0].addressEl.address,
            r_attr->fecTlv.fecElArray[0].addressEl.preLen, peer->session_name);
          if ((!existing) || (existing->index == us_temp->ds_attr->index)) {
            LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
              LDP_TRACE_FLAG_BINDING, "Part of same LSP\n");
            /* are the received attrs the same as the ones we've already sent */
            if (ldp_attr_is_equal(us_temp, &dumb_attr,
                LDP_ATTR_HOPCOUNT | LDP_ATTR_PATH) != MPLS_BOOL_TRUE) {
              LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
                LDP_TRACE_FLAG_BINDING, "Propogating updated attrs\n");
              /* send an updated label mapping */
              if (ldp_label_mapping_with_xc(g, us_temp->session, f, &us_temp,
                  ds_attr) != MPLS_SUCCESS) {			/* LMp.24-26 */
                retval = MPLS_FAILURE;
                goto LMp_33;
              }
            }
          }
        }
        us_temp = MPLS_LIST_NEXT(us_list, us_temp, _fs);
      }
    }

    if ((peer->oper_distribution_mode == LDP_DISTRIBUTION_UNSOLICITED) &&
      (g->lsp_control_mode == LDP_CONTROL_ORDERED)) { /* LMp.19 */

      /*
       * if we're not merging and we have multiple ORDERED DU sessions,
       * we will to start requesting labels after we propogate the mapping to
       * the first peer
       */
      if (need_request == MPLS_BOOL_TRUE) {
        if (ldp_attr_find_downstream_state2(g, peer, f,
            LDP_LSP_STATE_REQ_SENT) == NULL) {
          /*
           * we don't have a request for FEC to peer outstanding, make one
           */
          ds_temp = NULL;
          if (ldp_label_request_for_xc(g, peer, &f->info, NULL, &ds_temp) !=
            MPLS_SUCCESS) {
            retval = MPLS_FAILURE;
            goto LMp_33;
          }
        }
      } else {
        /*
         * We're in DU more, either we're merging, or we're not merging and
         * this is the first peer we're propogating this mapping to
         */
        /* LMp.20-21,30 */
        us_attr = NULL;
        if (ldp_label_mapping_with_xc(g, peer, f, &us_attr, ds_attr) !=
          MPLS_SUCCESS) {
          retval = MPLS_FAILURE;
          goto LMp_33;
        }
        /*
         * if we're not merging, we will need to request a label for
         * the next DU peer
         */
        if (g->label_merge == MPLS_BOOL_FALSE) {
          need_request = MPLS_BOOL_TRUE;
        }
      }
    }

    /* LMp.28 */
    while ((us_temp = ldp_attr_find_upstream_state2(g, peer, f,
      LDP_LSP_STATE_REQ_RECV))) {

      if (peer->oper_distribution_mode == LDP_DISTRIBUTION_UNSOLICITED) {
        if (need_request == MPLS_BOOL_TRUE) {
          if (ldp_attr_find_downstream_state2(g, peer, f,
            LDP_LSP_STATE_REQ_SENT) == NULL) {
            /* 
             * we don't have a request for FEC to peer outstanding
             */
            ds_temp = NULL;
            if (ldp_label_request_for_xc(g, peer, &f->info, us_temp,
                &ds_temp) != MPLS_SUCCESS) {
              retval = MPLS_FAILURE;
              goto LMp_33;
            }
          }
        } else {
          if (ldp_label_mapping_with_xc(g, peer, f, &us_temp,
            ds_attr) != MPLS_SUCCESS) {
            retval = MPLS_FAILURE;
            goto LMp_33;
          }
        }
      } else {
        if ((us_list = ldp_attr_find_upstream_all2(g, peer, f))) {
          us_temp = MPLS_LIST_HEAD(ds_list);
          while (us_temp) {
            if (us_temp->state == LDP_LSP_STATE_REQ_RECV) {
              if (need_request == MPLS_BOOL_TRUE) {
                if (ldp_attr_find_downstream_state2(g, peer, f,
                  LDP_LSP_STATE_REQ_SENT) == NULL) {
                  /*
                   * we don't have a request for FEC to peer outstanding
                   */
                  ds_temp = NULL;
                  if (ldp_label_request_for_xc(g, peer, &f->info, us_temp,
                      &ds_temp) != MPLS_SUCCESS) {
                    retval = MPLS_FAILURE;
                    goto LMp_33;
                  }
                }
              } else {
                if (ldp_label_mapping_with_xc(g, peer, f, &us_temp,
                    ds_attr) != MPLS_SUCCESS) {
                  retval = MPLS_FAILURE;
                  goto LMp_33;
                }
                /*
                 * if we're not merging, we will need to request a label for
                 * the next DU peer
                 */
                if (g->label_merge == MPLS_BOOL_FALSE) {
                  need_request = MPLS_BOOL_TRUE;
                }
              }
            }
            us_temp = MPLS_LIST_NEXT(us_list, us_temp, _fs);
          }
        }
      }
    }

  next_peer:
    peer = MPLS_LIST_NEXT(&g->session, peer, _global);
  }

LMp_33:
  LDP_EXIT(g->user_data, "ldp_label_mapping_process");
  return retval;

LMp_32:
  LDP_PRINT(g->user_data, "Receive_Label_Map_32: send release");
  if (ldp_label_release_send(g, s, ds_attr, LDP_NOTIF_NONE) != MPLS_SUCCESS) {
    retval = MPLS_FAILURE;
  }
  LDP_EXIT(g->user_data, "ldp_label_mapping_process");
  return retval;
}
