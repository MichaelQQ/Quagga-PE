
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_notif.h"
#include "ldp_attr.h"
#include "ldp_session.h"
#include "ldp_nexthop.h"
#include "ldp_entity.h"
#include "ldp_mesg.h"
#include "ldp_pdu_setup.h"
#include "ldp_label_request.h"
#include "ldp_label_mapping.h"
#include "ldp_fec.h"

#include "mpls_trace_impl.h"
#include "mpls_timer_impl.h"

void ldp_notif_prepare_msg(ldp_mesg * msg, uint32_t msgid, ldp_attr * r_attr,
  ldp_notif_status status)
{
  mplsLdpNotifMsg_t *notif = NULL;
  int error, forward = 0;
  uint32_t msg_type = 0;
  uint32_t msg_id = 0;

  ldp_mesg_prepare(msg, MPLS_NOT_MSGTYPE, msgid);
  notif = &msg->u.notif;

  notif->statusTlvExists = 1;

  /* we have to pass two more parameters one is F bit and other is E bit
     E = 1 if it is a fatal error, 0 is for advisory notification
     F = 1 then notification has to be forwarded. */

  /* check to set the E bit */
  if (status == LDP_NOTIF_SUCCESS ||
    status == LDP_NOTIF_UNKNOWN_MESG ||
    status == LDP_NOTIF_UNKNOWN_TVL ||
    status == LDP_NOTIF_LOOP_DETECTED ||
    status == LDP_NOTIF_UNKNOWN_FEC ||
    status == LDP_NOTIF_NO_ROUTE ||
    status == LDP_NOTIF_NO_LABEL_RESOURCES_AVAILABLE ||
    status == LDP_NOTIF_LABEL_RESOURCES_AVAILABLE ||
    status == LDP_NOTIF_LABEL_ABORT ||
    status == LDP_NOTIF_MISSING_MSG_PARAMS || status == LDP_NOTIF_UNSUPORTED_AF) {
    error = 0;
  } else {
    error = 1;
  }

  /* check to set the F bit */
  if (status == LDP_NOTIF_LOOP_DETECTED ||
    status == LDP_NOTIF_UNKNOWN_FEC || status == LDP_NOTIF_NO_ROUTE) {
    forward = 1;
  } else {
    forward = 0;
  }

  if (r_attr) {
    switch (r_attr->state) {
      case LDP_LSP_STATE_ABORT_RECV:
        msg_type = MPLS_LBLABORT_MSGTYPE;
	msg_id = r_attr->msg_id;
        break;
      default:
        msg_type = 0;
    }
  }
  notif->baseMsg.msgLength += setupStatusTlv(&notif->status, error, forward,
    status, msg_id, msg_type);

  /* We have to insert other tlv's like retpdu,extended status, returned
     message 
     notif->exStatusTlvExists = 1;
     notif->retPduTlvExists = 1;
   */
}

mpls_return_enum ldp_notif_send(ldp_global * g, ldp_session * s,
  ldp_attr * r_attr, ldp_notif_status status)
{
  LDP_ENTER(g->user_data, "ldp_notif_send");

  ldp_notif_prepare_msg(s->tx_message, g->message_identifier++, r_attr, status);

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_LABEL,
    "Notification Sent(%d)\n", s->index);

  if (ldp_mesg_send_tcp(g, s, s->tx_message) == MPLS_FAILURE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_ERROR,
      "Notification Send failed\n");
    goto ldp_notif_send_error;
  }

  LDP_EXIT(g->user_data, "ldp_notif_send");
  return MPLS_SUCCESS;

ldp_notif_send_error:

  LDP_EXIT(g->user_data, "ldp_notif_send_error");
  return MPLS_FAILURE;
}

void not2attr(mplsLdpNotifMsg_t * not, ldp_attr * attr, uint32_t flag)
{
  attr->msg_id = not->baseMsg.msgId;

  if (not->statusTlvExists && flag & LDP_ATTR_STATUS) {
    memcpy(&attr->statusTlv, &not->status, sizeof(mplsLdpStatusTlv_t));
    attr->statusTlvExists = 1;
  }
  if (not->lspidTlvExists && flag & LDP_ATTR_LSPID) {
    memcpy(&attr->lspidTlv, &not->lspidTlv, sizeof(mplsLdpLspIdTlv_t));
    attr->lspidTlvExists = 1;
  }

  if (not->retMsgTlvExists && flag & LDP_ATTR_MSGID) {
    memcpy(&attr->retMsgTlv, &not->retMsg, sizeof(mplsLdpLblMsgIdTlv_t));
    attr->retMsgTlvExists = 1;
  }
  /* Attribute types are not defined in ldp_attr.h file need to 
     define these optional Tlv types */

  /*if(not->exStatusTlvExists && flag & LDP_ATTR_HOPCOUNT) {
     memcpy(&attr->exStatus,&not->exStatus,sizeof(mplsLdpHopTlv_t));
     attr->exStatusTlvExists = 1;
     }
     if(not->retPduTlvExists && flag & LDP_ATTR_PATH) {
     memcpy(&attr->retPdu,&not->retPdu,sizeof(mplsLdpPathTlv_t));
     attr->retPduTlvExists = 1;
     } */
}

mpls_return_enum ldp_notif_process(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, ldp_attr * r_attr)
{
  mpls_return_enum retval = MPLS_SUCCESS;
  int status;

  LDP_ENTER(g->user_data, "ldp_notif_process");

  status = r_attr->statusTlv.flags.flags.status;

  switch (status) {
    case LDP_NOTIF_LABEL_ABORT:
      retval = ldp_notif_label_request_aborted(g, s, r_attr);
      break;
    case LDP_NOTIF_NO_LABEL_RESOURCES_AVAILABLE:
      retval = ldp_notif_no_label_resources(g, s, r_attr);
      break;
    case LDP_NOTIF_NO_ROUTE:
    case LDP_NOTIF_LOOP_DETECTED:
      retval = ldp_notif_no_route(g, s, e, r_attr);
      break;
    case LDP_NOTIF_LABEL_RESOURCES_AVAILABLE:
      retval = ldp_notif_label_resources_available(g, s, r_attr);
      break;
    case LDP_NOTIF_SUCCESS:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_SUCCESS:\n");
      break;
    case LDP_NOTIF_BAD_LDP_ID:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_BAD_LDP_ID:\n");
      break;
    case LDP_NOTIF_BAD_PROTO:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_BAD_PROTO:\n");
      break;
    case LDP_NOTIF_BAD_PDU_LEN:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_BAD_PDU_LEN:\n");
      break;
    case LDP_NOTIF_UNKNOWN_MESG:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_UNKNOWN_MESG:\n");
      break;
    case LDP_NOTIF_BAD_MESG_LEN:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_BAD_MESG_LEN:\n");
      break;
    case LDP_NOTIF_UNKNOWN_TVL:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_UNKNOWN_TVL:\n");
      break;
    case LDP_NOTIF_BAD_TLV_LEN:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_BAD_TLV_LEN:\n");
      break;
    case LDP_NOTIF_MALFORMED_TLV:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_MALFORMED_TLV:\n");
      break;
    case LDP_NOTIF_HOLD_TIMER_EXPIRED:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_HOLD_TIMER_EXPIRED:\n");
      break;
    case LDP_NOTIF_SHUTDOWN:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_SHUTDOWN:\n");
      break;
    case LDP_NOTIF_UNKNOWN_FEC:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_UNKNOWN_FEC:\n");
      break;
    case LDP_NOTIF_SESSION_REJECTED_NO_HELLO:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_SESSION_REJECTED_NO_HELLO:\n");
      break;
    case LDP_NOTIF_SESSION_REJECTED_PARAMETERS_ADVERTISEMENT_MODE:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_SESSION_REJECTED_PARAMETERS_ADVERTISEMENT_MODE:\n");
      break;
    case LDP_NOTIF_SESSION_REJECTED_PARAMETERS_MAX_PDU_LEN:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_SESSION_REJECTED_PARAMETERS_MAX_PDU_LEN:\n");
      break;
    case LDP_NOTIF_SESSION_REJECTED_PARAMETERS_LABEL_RANGE:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_SESSION_REJECTED_PARAMETERS_LABEL_RANGE:\n");
      break;
    case LDP_NOTIF_KEEPALIVE_TIMER_EXPIRED:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_KEEPALIVE_TIMER_EXPIRED:\n");
      break;
    case LDP_NOTIF_MISSING_MSG_PARAMS:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_MISSING_MSG_PARAMS:\n");
      break;
    case LDP_NOTIF_UNSUPORTED_AF:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_UNSUPORTED_AF:\n");
      break;
    case LDP_NOTIF_SESSION_REJECTED_BAD_KEEPALIVE_TIME:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_SESSION_REJECTED_BAD_KEEPALIVE_TIME:\n");
      break;
    case LDP_NOTIF_INTERNAL_ERROR:
      LDP_TRACE_OUT(g->user_data, "LDP_NOTIF_INTERNAL_ERROR\n");
      break;
    default:
      LDP_TRACE_OUT(g->user_data, "Receive an unknown notification: %08x\n",
	status);
      retval = MPLS_SUCCESS;
      break;
  }

  LDP_EXIT(g->user_data, "ldp_notif_process");
  return retval;
}

mpls_return_enum ldp_notif_label_request_aborted(ldp_global * g, ldp_session * s,
  ldp_attr * r_attr)
{
  ldp_attr *ds_attr = NULL;

  LDP_ENTER(g->user_data, "ldp_notif_label_request_aborted");

  ds_attr = MPLS_LIST_HEAD(&s->attr_root);
  while (ds_attr != NULL) {
    if (ds_attr->state == LDP_LSP_STATE_ABORT_SENT &&
      ds_attr->msg_id == r_attr->msg_id) {
      break;
    }
    ds_attr = MPLS_LIST_NEXT(&s->attr_root, ds_attr, _fs);
  }

  if (ds_attr) {                /* LRqA.1 */
    ldp_attr_remove_complete(g, ds_attr, MPLS_BOOL_FALSE); /* LRqA.2 */

    LDP_EXIT(g->user_data, "ldp_notif_label_request_aborted");
    return MPLS_SUCCESS;
  }

  LDP_EXIT(g->user_data, "ldp_notif_label_request_abort_error");
  return MPLS_FAILURE;
}

mpls_return_enum ldp_notif_no_label_resources(ldp_global * g, ldp_session * s,
  ldp_attr * s_attr)
{
  ldp_attr_list *ds_list = NULL;
  ldp_attr *ds_attr = NULL;
  mpls_fec nfec;

  LDP_ENTER(g->user_data, "ldp_notif_no_label_resources");

  fec_tlv2mpls_fec(&s_attr->fecTlv, 0, &nfec);
  /* NoRes.1 do not actually remove from tree, just change it's state */

  if ((ds_list = ldp_attr_find_downstream_all(g, s, &nfec))) {
    ds_attr = MPLS_LIST_HEAD(&s->attr_root);
    while (ds_attr) {
      if (ds_attr->state == LDP_LSP_STATE_REQ_SENT) {
        ds_attr->state = LDP_LSP_STATE_NO_LABEL_RESOURCE_RECV; /* NoRes.2 */
      }
      ds_attr = MPLS_LIST_NEXT(&s->attr_root, ds_attr, _fs);
    }
  }

  s->no_label_resource_recv = MPLS_BOOL_TRUE; /* NoRes.3 */

  LDP_EXIT(g->user_data, "ldp_notif_no_label_resource_error");
  return MPLS_SUCCESS;
}

mpls_return_enum ldp_notif_no_route(ldp_global * g, ldp_session * s,
  ldp_entity * e, ldp_attr * s_attr)
{
  ldp_attr *ds_attr = NULL;
  ldp_attr_list *ds_list = NULL;
  mpls_fec nfec;
  mpls_return_enum retval = MPLS_FAILURE;

  LDP_ENTER(g->user_data, "ldp_notif_no_route\n");

  fec_tlv2mpls_fec(&s_attr->fecTlv, 0, &nfec);

  if ((ds_list = ldp_attr_find_downstream_all(g, s, &nfec))) {
    ds_attr = MPLS_LIST_HEAD(&s->attr_root);
    while (ds_attr) {
      if (ds_attr->state == LDP_LSP_STATE_REQ_SENT) {
        if (e->label_request_count) {
          if (ds_attr->attempt_count < e->label_request_count) {
            if (mpls_timer_handle_verify(g->timer_handle,
                ds_attr->action_timer) == MPLS_BOOL_FALSE) {
              ds_attr->action_timer =
                mpls_timer_create(g->timer_handle, MPLS_UNIT_SEC,
                s->cfg_label_request_timer, (void *)ds_attr, g,
                ldp_attr_action_callback);
            }
            mpls_timer_start(g->timer_handle, ds_attr->action_timer,
              MPLS_TIMER_ONESHOT);
          }
          retval = MPLS_SUCCESS;
        } else {
          ldp_attr_remove_complete(g, ds_attr, MPLS_BOOL_FALSE);
          retval = MPLS_FAILURE;
        }
      }
      ds_attr = MPLS_LIST_NEXT(&s->attr_root, ds_attr, _fs);
    }
  }

  LDP_EXIT(g->user_data, "ldp_notif_no_route\n");
  return retval;
}

/* IV. Receive Notification/ Loop Detected */

/* Algo: Same as receive Notification/No Route */

mpls_return_enum ldp_notif_label_resources_available(ldp_global * g,
  ldp_session * s, ldp_attr * r_attr)
{
  ldp_session *nh_session = NULL;
  ldp_attr *ds_attr = NULL;
  ldp_nexthop *nh = NULL;
  ldp_fec *f = NULL;

  LDP_ENTER(g->user_data, "ldp_notif_label_resources_available");

  s->no_label_resource_recv = MPLS_BOOL_FALSE;			/* Res.1 */

  ds_attr = MPLS_LIST_HEAD(&s->attr_root);
  while (ds_attr != NULL) {					/* Res.2 */
    if (ds_attr->state == LDP_LSP_STATE_NO_LABEL_RESOURCE_RECV) {
      f = ds_attr->fec;
      nh = MPLS_LIST_HEAD(&f->nh_root);
      while (nh) {
	nh_session = ldp_session_for_nexthop(nh);
        if (nh_session && (nh_session->index == s->index)) {
								/* Res.4 */
          if (ldp_label_request_send(g, s, ds_attr, NULL) != MPLS_SUCCESS) {
	    MPLS_ASSERT(0);
	  }
	} else {
          ldp_attr_remove_complete(g, ds_attr, MPLS_BOOL_FALSE);/* Res.5 */
	}
	nh = MPLS_LIST_NEXT(&f->nh_root, nh, _fec);
      }
    }
    ds_attr = MPLS_LIST_NEXT(&s->attr_root, ds_attr, _fs);
  }								/* Res.6 */

  LDP_EXIT(g->user_data, "ldp_notif_label_resources_available");
  return MPLS_SUCCESS;
}
