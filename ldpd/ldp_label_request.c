
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_attr.h"
#include "ldp_fec.h"
#include "ldp_mesg.h"
#include "ldp_pdu_setup.h"
#include "ldp_notif.h"
#include "ldp_session.h"
#include "ldp_entity.h"
#include "ldp_label_mapping.h"
#include "ldp_label_request.h"

#include "mpls_timer_impl.h"
#include "mpls_policy_impl.h"
#include "mpls_tree_impl.h"
#include "mpls_trace_impl.h"
#include "mpls_fib_impl.h"
#include "mpls_lock_impl.h"

mpls_return_enum ldp_label_request_for_xc(ldp_global * g, ldp_session * s,
  mpls_fec * fec, ldp_attr * us_attr, ldp_attr ** ds_attr)
{

  LDP_ENTER(g->user_data, "ldp_label_request_for_xc");

  if (!(*ds_attr)) {
    if (!((*ds_attr) = ldp_attr_create(fec))) {
      return MPLS_FATAL;
    }
  }
  Prepare_Label_Request_Attributes(g, s, fec, (*ds_attr), us_attr);
  (*ds_attr)->state = LDP_LSP_STATE_REQ_SENT;
  if (ldp_label_request_send(g, s, us_attr, ds_attr) != MPLS_SUCCESS) {
    return MPLS_FAILURE;
  }

  LDP_EXIT(g->user_data, "ldp_label_request_for_xc");

  return MPLS_SUCCESS;
}

void ldp_label_request_prepare_msg(ldp_mesg * msg, uint32_t msgid,
  ldp_attr * s_attr)
{
  mplsLdpLblReqMsg_t *req = NULL;
  int i;

  ldp_mesg_prepare(msg, MPLS_LBLREQ_MSGTYPE, msgid);
  req = &msg->u.request;

  if (s_attr->fecTlvExists) {
    req->fecTlvExists = 1;
    req->baseMsg.msgLength += setupFecTlv(&req->fecTlv);
    req->baseMsg.msgLength += addFecElem2FecTlv(&req->fecTlv,
      &s_attr->fecTlv.fecElArray[0]);
  }
  if (s_attr->hopCountTlvExists) {
    req->hopCountTlvExists = 1;
    req->baseMsg.msgLength += setupHopCountTlv(&req->hopCountTlv,
      s_attr->hopCountTlv.hcValue);
  }
  if (s_attr->pathVecTlvExists) {
    req->pathVecTlvExists = 1;
    req->baseMsg.msgLength += setupPathTlv(&req->pathVecTlv);
    for (i = 0; i < MPLS_MAXHOPSNUMBER; i++) {
      if (s_attr->pathVecTlv.lsrId[i]) {
        req->baseMsg.msgLength += addLsrId2PathTlv(&req->pathVecTlv,
          s_attr->pathVecTlv.lsrId[i]);
      }
    }
  }
}

mpls_return_enum ldp_label_request_send(ldp_global * g, ldp_session * s,
  ldp_attr * us_attr, ldp_attr ** ds_attr)
{
  ldp_attr *ds_temp;
  mpls_fec fec;

  LDP_ENTER(g->user_data, "ldp_label_request_send");
  MPLS_ASSERT(ds_attr && *ds_attr);

  fec_tlv2mpls_fec(&((*ds_attr)->fecTlv), 0, &fec);

  if ((ds_temp = ldp_attr_find_downstream_state(g, s, &fec,
        LDP_LSP_STATE_REQ_SENT)) != NULL) { /* SLRq.1 */

    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_LABEL,
      "Label Request Send: request already pending(%d)\n", ds_temp->index);

    ldp_attr_add_us2ds(us_attr, ds_temp);

    /* we do not need the one passed in, but make sure that the caller
       is using this one from here forth */
    ldp_attr_remove_complete(g, *ds_attr, MPLS_BOOL_TRUE);
    *ds_attr = ds_temp;
    return MPLS_SUCCESS;
  }

  if (s->no_label_resource_recv == MPLS_BOOL_TRUE) { /* SLRq.2 */
    goto ldp_label_request_send_error;
  }

  (*ds_attr)->msg_id = g->message_identifier++;
  ldp_label_request_prepare_msg(s->tx_message, (*ds_attr)->msg_id, *ds_attr);

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_LABEL,
    "Label Request Sent: session(%d)\n", s->index);

  if (ldp_mesg_send_tcp(g, s, s->tx_message) == MPLS_FAILURE) { /* SLRq.3 */
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_ERROR,
      "Label Request send failed\n");
    goto ldp_label_request_send_error;
  }

  (*ds_attr)->state = LDP_LSP_STATE_REQ_SENT;
  if (ldp_attr_insert_downstream(g, s, (*ds_attr)) == MPLS_FAILURE) { /* SLRq.4 */
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_ERROR,
      "Couldn't insert sent attributes in tree\n");
    goto ldp_label_request_send_error;
  }
  if (us_attr) {
    ldp_attr_add_us2ds(us_attr, *ds_attr);
  }

  LDP_EXIT(g->user_data, "ldp_label_request_send");

  return MPLS_SUCCESS;           /* SLRq.5 */

ldp_label_request_send_error:

  LDP_PRINT(g->user_data, "SLRq.6\n");
  (*ds_attr)->state = LDP_LSP_STATE_NO_LABEL_RESOURCE_SENT;
  ldp_attr_insert_downstream(g, s, (*ds_attr)); /* SLRq.6 */

  LDP_EXIT(g->user_data, "ldp_label_request_send-error");

  return MPLS_FAILURE;           /* SLRq.7 */
}

void req2attr(mplsLdpLblReqMsg_t * req, ldp_attr * attr, uint32_t flag)
{
  attr->msg_id = req->baseMsg.msgId;

  if (req->fecTlvExists && flag & LDP_ATTR_FEC) {
    memcpy(&attr->fecTlv, &req->fecTlv, sizeof(mplsLdpFecTlv_t));
    attr->fecTlvExists = 1;
  }
  if (req->hopCountTlvExists && flag & LDP_ATTR_HOPCOUNT) {
    memcpy(&attr->hopCountTlv, &req->hopCountTlv, sizeof(mplsLdpHopTlv_t));
    attr->hopCountTlvExists = 1;
  }
  if (req->pathVecTlvExists && flag & LDP_ATTR_PATH) {
    memcpy(&attr->pathVecTlv, &req->pathVecTlv, sizeof(mplsLdpPathTlv_t));
    attr->pathVecTlvExists = 1;
  }
  if (req->lblMsgIdTlvExists && flag & LDP_ATTR_MSGID) {
    memcpy(&attr->lblMsgIdTlv, &req->lblMsgIdTlv, sizeof(mplsLdpLblMsgIdTlv_t));
    attr->lblMsgIdTlvExists = 1;
  }
  if (req->lspidTlvExists && flag & LDP_ATTR_LSPID) {
    memcpy(&attr->lspidTlv, &req->lspidTlv, sizeof(mplsLdpLspIdTlv_t));
    attr->lspidTlvExists = 1;
  }
  if (req->trafficTlvExists && flag & LDP_ATTR_TRAFFIC) {
    memcpy(&attr->trafficTlv, &req->trafficTlv, sizeof(mplsLdpTrafficTlv_t));
    attr->trafficTlvExists = 1;
  }
}

void ldp_label_request_initial_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle handle)
{
  ldp_session *s = (ldp_session *)extra;
  ldp_global *g = (ldp_global*)handle;
  ldp_nexthop *nh = NULL;
  ldp_fec *f = NULL;

  ldp_session *nh_session = NULL;
  mpls_bool done = MPLS_BOOL_FALSE;

  ldp_attr *attr = NULL;
  ldp_fs *fs = NULL;
  ldp_attr *ds_attr = NULL;

  LDP_ENTER(g->user_data, "ldp_label_request_initial_callback");

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_TIMER,
    "Initial Label Request Callback fired: session(%d)\n", s->index);

  mpls_lock_get(g->global_lock);

  mpls_timer_stop(g->timer_handle, timer);

  if ((f = MPLS_LIST_HEAD(&g->fec))) {
    do {
      if ((nh = MPLS_LIST_HEAD(&f->nh_root))) {
        do {
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
              LDP_TRACE_FLAG_ROUTE, "Processing L2CC FEC: %d %d %d ",
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
          if (nh->info.type & MPLS_NH_IF) {
            LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
              LDP_TRACE_FLAG_ROUTE, "via %p\n", nh->iff->handle);
          }

          /* check to see if export policy allows us to 'see' this route */
          if (mpls_policy_export_check(g->user_data, &f->info, &nh->info)
              == MPLS_BOOL_FALSE) {
            LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
              LDP_TRACE_FLAG_DEBUG, "Rejected by export policy\n");
            continue;
          }

	  /* find the next hop session corresponding to this FEC */
	  nh_session = ldp_session_for_nexthop(nh);

          /* do we have a valid next hop session, and is the nexp hop session
           * this session? */
          if ((!nh_session) || (nh_session->index != s->index)) {
            continue;
          }

          /* have we already sent a label request to this peer for this FEC? */
          if (ldp_attr_find_downstream_state(g, s, &f->info,
	    LDP_LSP_STATE_REQ_SENT)) {
            continue;
          }

          /* clear out info from the last FEC */
          ds_attr = NULL;

          /* jleu: duplicate code from ldp_attr_find_upstream_state_any */
          fs = MPLS_LIST_HEAD(&f->fs_root_us);
          while (fs) {
            attr = MPLS_LIST_HEAD(&fs->attr_root);
            while (attr) {
              if (attr->state == LDP_LSP_STATE_REQ_RECV ||
	        attr->state == LDP_LSP_STATE_MAP_SENT) {
	        if (!ds_attr) {
                  /* this is not neccessarily going to be XC'd to something */
                  ldp_label_request_for_xc(g, s, &f->info, attr, &ds_attr);
	        }
	      }
              attr = MPLS_LIST_NEXT(&fs->attr_root, attr, _fs);
            }
            fs = MPLS_LIST_NEXT(&f->fs_root_us, fs, _fec);
          }
      
          if (!ds_attr) {
            /*
	     * we did not find any received requests or sent mappings so
	     * send a request and xc it to nothing
	     */
            ldp_label_request_for_xc(g, s, &f->info, NULL, &ds_attr);
          }
        } while ((nh = MPLS_LIST_NEXT(&f->nh_root, nh, _fec)));
      }
    } while ((f = MPLS_LIST_NEXT(&g->fec, f, _global)));
    done = MPLS_BOOL_TRUE;
  }

  if (done == MPLS_BOOL_TRUE) {
    mpls_timer_delete(g->timer_handle, timer);
    MPLS_REFCNT_RELEASE(s, ldp_session_delete);
    s->initial_distribution_timer = (mpls_timer_handle) 0;
  } else {
    mpls_timer_start(g->timer_handle, timer, MPLS_TIMER_ONESHOT);
    /* need to mark the session with where it left off */
  }

  mpls_lock_release(g->global_lock);

  LDP_EXIT(g->user_data, "ldp_label_request_initial_callback");
}

void Prepare_Label_Request_Attributes(ldp_global * g, ldp_session * s,
  mpls_fec * fec, ldp_attr * r_attr, ldp_attr * s_attr)
{
  int i;

  MPLS_ASSERT(s && r_attr);

  if (!(s->oper_loop_detection == LDP_LOOP_HOPCOUNT ||
    s->oper_loop_detection == LDP_LOOP_HOPCOUNT_PATHVECTOR ||
    r_attr->hopCountTlvExists)) { /* PRqA.1 */
    return;
  }

/* is this LSR allowed to be an LER for FEC? *//* PRqA.2 */
  /* some policy gunk needs to be checked here */
  /* if not goto PRqA.6 */

  s_attr->hopCountTlvExists = 1; /* PRqA.3 */
  s_attr->hopCountTlv.hcValue = 1;

  if (s->oper_loop_detection == LDP_LOOP_NONE) { /* PRqA.4 */
    return;
  }

  if (g->label_merge == MPLS_BOOL_TRUE) { /* PRqA.5 */
    return;
  }
  goto Prepare_Label_Request_Attributes_13;

  if (r_attr && r_attr->hopCountTlvExists) { /* PRqA.6 */
    s_attr->hopCountTlvExists = 1; /* PRqA.7 */
    s_attr->hopCountTlv.hcValue = (r_attr->hopCountTlv.hcValue) ?
      (r_attr->hopCountTlv.hcValue + 1) : 0;
  } else {
    s_attr->hopCountTlvExists = 1; /* PRqA.8 */
    s_attr->hopCountTlv.hcValue = 0;
  }

  if (s->oper_loop_detection == LDP_LOOP_NONE) { /* PRqA.9 */
    return;
  }

  if (r_attr && r_attr->pathVecTlvExists) { /* PRqA.10 */
    goto Prepare_Label_Request_Attributes_12;
  }

  if (g->label_merge == MPLS_BOOL_TRUE) { /* PRqA.11 */
    return;
  }
  goto Prepare_Label_Request_Attributes_13;

Prepare_Label_Request_Attributes_12:
  /* we only get to PRqA.12 if we have verified we have a r_attr */
  s_attr->pathVecTlvExists = 1;
  s_attr->pathVecTlv.lsrId[0] = g->lsr_identifier.u.ipv4;
  for (i = 1; i < (MPLS_MAXHOPSNUMBER - 1); i++) {
    if (r_attr->pathVecTlv.lsrId[i - 1]) {
      s_attr->pathVecTlv.lsrId[i] = r_attr->pathVecTlv.lsrId[i - 1];
    }
  }
  return;

Prepare_Label_Request_Attributes_13:
  s_attr->pathVecTlvExists = 1;
  s_attr->pathVecTlv.lsrId[0] = g->lsr_identifier.u.ipv4;
}

mpls_return_enum ldp_label_request_process(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, ldp_attr * us_attr, ldp_fec * f)
{
  ldp_session *nh_session = NULL;
  ldp_nexthop *nh = NULL;
  ldp_attr_list *us_list = NULL;
  mpls_bool egress = MPLS_BOOL_FALSE;
  ldp_attr *ds_attr = NULL;
  ldp_attr *us_temp = NULL;

  if (Check_Received_Attributes(g, s, us_attr, MPLS_LBLREQ_MSGTYPE) != MPLS_SUCCESS) { /* LRp.1 */
    goto LRq_13;
  }

  if (f == NULL) {
    ldp_notif_send(g, s, us_attr, LDP_NOTIF_NO_ROUTE); /* LRq.5 */
    goto LRq_13;
  }

  /* just find one valid nexthop session for now */
  nh = MPLS_LIST_HEAD(&f->nh_root);
  while (nh) {
    nh_session = ldp_session_for_nexthop(nh);
    if (nh_session) {
      break;
    }
    nh = MPLS_LIST_NEXT(&f->nh_root, nh, _fec);
  }

  if (!nh_session) {
    egress = MPLS_BOOL_TRUE;
  }
  if (nh_session != NULL && s->index == nh_session->index) { /* LRq.3 */
    ldp_notif_send(g, s, us_attr, LDP_NOTIF_LOOP_DETECTED); /* LRq.4 */
    goto LRq_13;
  }

  if ((us_list = ldp_attr_find_upstream_all2(g, s, f)) != NULL) {
    us_temp = MPLS_LIST_HEAD(us_list);
    while (us_temp != NULL) {
      if (us_temp->state == LDP_LSP_STATE_REQ_RECV && /* LRq.6 */
        us_temp->msg_id == us_attr->msg_id) { /* LRq.7 */
        goto LRq_13;
      }
      us_temp = MPLS_LIST_NEXT(us_list, us_temp, _fs);
    }
  }

  us_attr->state = LDP_LSP_STATE_REQ_RECV; /* LRq.8 */

  if (ldp_attr_insert_upstream2(g, s, us_attr, f) != MPLS_SUCCESS) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_ERROR,
      "Couldn't insert recv attributes in tree\n");
    goto ldp_label_request_process_error;
  }

  if (nh_session) {
    ds_attr = ldp_attr_find_downstream_state2(g, nh_session, f,
      LDP_LSP_STATE_MAP_RECV);
  } else {
    ds_attr = NULL;
  }

  if (g->lsp_control_mode == LDP_CONTROL_INDEPENDENT) { /* LRq.9 */
    if (ldp_label_mapping_with_xc(g, s, f, &us_attr, ds_attr) != MPLS_SUCCESS) {
      goto ldp_label_request_process_error;
    }

    if (egress == MPLS_BOOL_TRUE || ds_attr) {
      goto LRq_11;
    }
  } else {
    if ((!(egress == MPLS_BOOL_TRUE || ds_attr)) || (g->label_merge == MPLS_BOOL_FALSE)) {
      goto LRq_10;
    }

    if (ldp_label_mapping_with_xc(g, s, f, &us_attr, ds_attr) != MPLS_SUCCESS) {
      goto ldp_label_request_process_error;
    }
    goto LRq_11;
  }

LRq_10:
  ds_attr = NULL;
  if (ldp_label_request_for_xc(g, nh_session, &f->info, us_attr, &ds_attr) !=
    MPLS_SUCCESS) {
    goto ldp_label_request_process_error;
  }

LRq_11:
  /* the work done by LRq_11 is handled in ldp_label_mapping_with_xc() */
LRq_13:
  if (ds_attr != NULL && ds_attr->in_tree == MPLS_BOOL_FALSE) {
    ldp_attr_remove_complete(g, ds_attr, MPLS_BOOL_FALSE);
  }
  return MPLS_SUCCESS;

ldp_label_request_process_error:
  return MPLS_FAILURE;
}
