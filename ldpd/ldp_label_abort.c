
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
#include "ldp_entity.h"
#include "ldp_session.h"
#include "ldp_notif.h"
#include "ldp_label_abort.h"
#include "ldp_label_rel_with.h"
#include "ldp_label_mapping.h"

#include "mpls_trace_impl.h"

void ldp_label_abort_prepare_msg(ldp_mesg * msg, uint32_t msgid,
  ldp_attr * s_attr)
{
  mplsLdpLblAbortMsg_t *abrt = NULL;

  ldp_mesg_prepare(msg, MPLS_LBLABORT_MSGTYPE, msgid);

  abrt = &msg->u.abort;

  if (s_attr->fecTlvExists) {
    abrt->fecTlvExists = 1;
    abrt->baseMsg.msgLength += setupFecTlv(&abrt->fecTlv);
    abrt->baseMsg.msgLength +=
      addFecElem2FecTlv(&abrt->fecTlv, &s_attr->fecTlv.fecElArray[0]);
  }

  if (s_attr->lblMsgIdTlvExists) {
    abrt->lblMsgIdTlvExists = 1;
    abrt->baseMsg.msgLength +=
      setupLblMsgIdTlv(&abrt->lblMsgIdTlv, s_attr->msg_id);
  }
}

mpls_return_enum ldp_label_abort_send(ldp_global * g, ldp_session * s,
  ldp_attr * s_attr)
{
  mpls_fec fec;
  ldp_attr *ds_attr = NULL;

  LDP_ENTER(g->user_data, "ldp_label_abort_send");

  fec_tlv2mpls_fec(&s_attr->fecTlv, 0, &fec);
  if ((ds_attr = ldp_attr_find_downstream_state(g, s, &fec,
        LDP_LSP_STATE_ABORT_SENT)) != NULL) {
    return MPLS_SUCCESS;
  }

  ldp_label_abort_prepare_msg(s->tx_message, g->message_identifier++, s_attr);

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_LABEL,
    "Label Abort Sent: session (%d) \n", s->index);

  s_attr->state = LDP_LSP_STATE_ABORT_SENT;

  if (ldp_mesg_send_tcp(g, s, s->tx_message) == MPLS_FAILURE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_ERROR,
      "Label Abort Sent Failed .\n");
    goto ldp_label_abort_send_error;
  }

  LDP_EXIT(g->user_data, "ldp_label_abort_send");
  return MPLS_SUCCESS;

ldp_label_abort_send_error:

  if (s_attr) {
    ldp_attr_remove_complete(g, s_attr, MPLS_BOOL_FALSE);
  }
  LDP_EXIT(g->user_data, "ldp_label_abort_send-error");

  return MPLS_FAILURE;
}

mpls_return_enum ldp_label_abort_process(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, ldp_attr * r_attr, ldp_fec * f)
{
  ldp_attr_list *us_list = NULL;
  ldp_attr *us_temp = NULL;
  ldp_attr *us_attr = NULL;
  ldp_attr *ds_req_attr = NULL;
  ldp_attr *ds_map_attr = NULL;
  mpls_return_enum retval = MPLS_SUCCESS;

  if ((us_list = ldp_attr_find_upstream_all2(g, s, f))) {
    us_temp = MPLS_LIST_HEAD(us_list);
    while (us_temp) {
      if (((us_temp->state == LDP_LSP_STATE_REQ_RECV) &&
          (us_temp->msg_id == r_attr->msg_id)) ||
        (us_temp->state == LDP_LSP_STATE_MAP_SENT)) {
        us_attr = us_temp;
        break;
      }
      us_temp = MPLS_LIST_NEXT(us_list, us_temp, _fs);
    }
  }
  if ((!us_attr) || (us_attr->state == LDP_LSP_STATE_MAP_SENT)) { /* LAbR.1,2 */
    retval = MPLS_FAILURE;
    goto LAbR_12;
  }
  /* LAbR.3 */
  if (ldp_notif_send(g, s, us_attr, LDP_NOTIF_LABEL_ABORT) != MPLS_SUCCESS) {
    retval = MPLS_FAILURE;
    goto LAbR_12;
  }
  /* LAbR.4 */
  if (us_attr->ds_attr && (us_attr->ds_attr->state == LDP_LSP_STATE_REQ_SENT)) {
    ds_req_attr = us_attr->ds_attr;
    goto LAbR_7;
  }
  /* LAbR.5 */
  if (us_attr->ds_attr && (us_attr->ds_attr->state == LDP_LSP_STATE_MAP_RECV)) {
    ds_map_attr = us_attr->ds_attr;
  } else {
    goto LAbR_11;
  }

  /* this may results in us sending a label withdraw to s and possibly
     propogating a release */
  if (ldp_label_release_process(g, s, NULL, e, us_attr, f) != MPLS_SUCCESS) { /* LAbR.6 */
    retval = MPLS_FAILURE;
  }
  goto LAbR_11;

LAbR_7:

  if (g->label_merge == MPLS_BOOL_TRUE) { /* LAbR.7 */
    /* by now us_attr has been removed from the downstream us_attr_root
       so any left overs (reflect by count > 0) are from other peers */
    if (ds_req_attr && ldp_attr_num_us2ds(ds_req_attr)) { /* LAbR.8 */
      goto LAbR_11;
    }
  }

  if (ldp_label_abort_send(g, ds_req_attr->session, ds_req_attr) != MPLS_SUCCESS) { /* LAbR.9,10 */
    retval = MPLS_FAILURE;
  }

LAbR_11:

  if (us_attr) {
    ldp_attr_remove_complete(g, us_attr, MPLS_BOOL_FALSE);
  }

LAbR_12:

  LDP_EXIT(g->user_data, "ldp_label_abort_processed");
  return retval;
}

void abort2attr(mplsLdpLblAbortMsg_t * abrt, ldp_attr * a, uint32_t flag)
{
}
