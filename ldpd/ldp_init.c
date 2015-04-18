
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_mesg.h"
#include "ldp_entity.h"
#include "ldp_nortel.h"
#include "ldp_buf.h"
#include "ldp_pdu_setup.h"

#include "mpls_assert.h"
#include "mpls_socket_impl.h"
#include "mpls_trace_impl.h"
#if MPLS_USE_LSR
#include "lsr_cfg.h"
#else
#include "mpls_mpls_impl.h"
#endif

void ldp_init_prepare(ldp_mesg * msg, ldp_global * g, uint32_t msgid,
  ldp_session * s)
{
  mplsLdpInitMsg_t *init = NULL;
  uint32_t remote_labelspace;
  uint32_t path_vector_limit;
  uint32_t remote_lsraddr;
  uint8_t direction = 0;
  ldp_adj *a = MPLS_LIST_HEAD(&s->adj_root);
  uint32_t loop = 0;
  uint8_t merge = 0;
  mpls_range range;
  uint8_t len = 0;

  MPLS_ASSERT(s && a);

  LDP_ENTER(g->user_data, "ldp_init_create");

  ldp_mesg_prepare(msg, MPLS_INIT_MSGTYPE, msgid);
  init = &msg->u.init;

  remote_lsraddr = a->remote_lsr_address.u.ipv4;
  remote_labelspace = a->remote_label_space;

  loop = (s->cfg_loop_detection_mode == LDP_LOOP_NONE) ? (0) : (1);
  if (loop == LDP_LOOP_NONE) {
    path_vector_limit = 0;
  } else {
    path_vector_limit = s->cfg_path_vector_limit;
  }

  init->cspExists = 1;

  init->baseMsg.msgLength += setupCspTlv(&(init->csp), s->cfg_keepalive,
    s->cfg_distribution_mode, loop, path_vector_limit, s->cfg_max_pdu,
    remote_lsraddr, remote_labelspace, 0);

  init->aspExists = 0;
  init->fspExists = 0;

  range.label_space = s->cfg_label_space;
#if MPLS_USE_LSR
#else
  mpls_mpls_get_label_space_range(g->mpls_handle,&range);
#endif

  switch (range.type) {
    case MPLS_LABEL_RANGE_ATM_VP:
      MPLS_ASSERT(0);
    case MPLS_LABEL_RANGE_ATM_VC:
    case MPLS_LABEL_RANGE_ATM_VP_VC:
      init->aspExists = 1;
      init->baseMsg.msgLength += setupAspTlv(&(init->asp), merge, direction);
      init->baseMsg.msgLength += addLblRng2AspTlv(&(init->asp),
        range.min.u.atm.vpi, range.min.u.atm.vci, range.max.u.atm.vpi,
        range.max.u.atm.vci);
      break;
    case MPLS_LABEL_RANGE_FR_10:
      len = 0;                /* Section 3.5.3 fspTlv */
    case MPLS_LABEL_RANGE_FR_24:
      init->fspExists = 1;

      if (range.type == MPLS_LABEL_RANGE_FR_24) {
        len = 2;              /* Section 3.5.3 fspTlv */
      }

      init->baseMsg.msgLength += setupFspTlv(&(init->fsp), merge, direction);
      init->baseMsg.msgLength += addLblRng2FspTlv(&(init->fsp), 0, len,
        range.min.u.fr.dlci, 0, range.max.u.fr.dlci);
      break;
    case MPLS_LABEL_RANGE_GENERIC:
      break;
  }
  LDP_EXIT(g->user_data, "ldp_init_create");
}

mpls_return_enum ldp_init_send(ldp_global * g, ldp_session * s)
{
  mpls_return_enum result = MPLS_FAILURE;

  MPLS_ASSERT(s);

  LDP_ENTER(g->user_data, "ldp_init_send");

  ldp_init_prepare(s->tx_message, g, g->message_identifier++, s);

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_INIT,
    "Init Send: session(%d)\n", s->index);

  result = ldp_mesg_send_tcp(g, s, s->tx_message);

  LDP_EXIT(g->user_data, "ldp_init_send");

  return result;
}

mpls_return_enum ldp_init_process(ldp_global * g, ldp_session * s,
  ldp_mesg * msg)
{
  mpls_range range;

  MPLS_MSGPTR(Init);

  MPLS_ASSERT(s);

  LDP_ENTER(g->user_data, "ldp_init_process");

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_INIT,
    "Init Recv: session(%d)\n", s->index);

  MPLS_MSGPARAM(Init) = &msg->u.init;

  range.label_space = s->cfg_label_space;

#if MPLS_USE_LSR
  range.type = MPLS_LABEL_RANGE_GENERIC;
#else
  mpls_mpls_get_label_space_range(g->mpls_handle, &range);
#endif

  if (MPLS_MSGPARAM(Init)->csp.rcvLsrAddress != g->lsr_identifier.u.ipv4 ||
    MPLS_MSGPARAM(Init)->csp.rcvLsId != range.label_space) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_INIT,
      "Init failed(%d): sending bad LDP-ID\n", s->index);
    LDP_EXIT(g->user_data, "ldp_init_process-error");
    s->shutdown_notif = LDP_NOTIF_BAD_LDP_ID;
    s->shutdown_fatal = MPLS_BOOL_FALSE;
    return MPLS_FAILURE;
  }

  if (MPLS_MSGPARAM(Init)->csp.holdTime == 0) {
    LDP_EXIT(g->user_data, "ldp_init_process-error");
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_INIT,
      "Init failed(%d): sending bad Keepalive Time\n", s->index);
    s->shutdown_notif = LDP_NOTIF_SESSION_REJECTED_BAD_KEEPALIVE_TIME;
    s->shutdown_fatal = MPLS_BOOL_FALSE;
    return MPLS_FAILURE;
  }

  if (MPLS_MSGPARAM(Init)->csp.maxPduLen <= 255)
    MPLS_MSGPARAM(Init)->csp.maxPduLen = 4096; /* Section 3.5.3. */

  s->remote_max_pdu = MPLS_MSGPARAM(Init)->csp.maxPduLen;
  s->remote_keepalive = MPLS_MSGPARAM(Init)->csp.holdTime;
  s->remote_path_vector_limit = MPLS_MSGPARAM(Init)->csp.flags.flags.pvl;
  s->remote_distribution_mode =
    (ldp_distribution_mode) MPLS_MSGPARAM(Init)->csp.flags.flags.lad;

  if (s->remote_keepalive < s->cfg_keepalive) {
    s->oper_keepalive = s->remote_keepalive;
  } else {
    s->oper_keepalive = s->cfg_keepalive;
  }

  /* JLEU: eventually this should be configured by the user */
  s->oper_keepalive_interval = s->oper_keepalive / 3;

  if (MPLS_MSGPARAM(Init)->csp.flags.flags.ld == 0) {
    s->remote_loop_detection = MPLS_BOOL_FALSE;
  } else {
    s->remote_loop_detection = MPLS_BOOL_TRUE;
  }

  if (s->remote_max_pdu < s->cfg_max_pdu) {
    s->oper_max_pdu = s->remote_max_pdu;
  }

  if (s->remote_distribution_mode != s->cfg_distribution_mode) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_INIT,
      "Init(%d): distribution modes do not match, using default\n", s->index);
    if (range.type == MPLS_LABEL_RANGE_GENERIC) {
      s->oper_distribution_mode = LDP_DISTRIBUTION_UNSOLICITED;
    } else {
      s->oper_distribution_mode = LDP_DISTRIBUTION_ONDEMAND;
    }
  }

  if ((s->remote_loop_detection == MPLS_BOOL_TRUE) &&
    (g->loop_detection_mode != LDP_LOOP_NONE)) {
    s->oper_loop_detection = s->cfg_loop_detection_mode;
  } else {
    s->oper_loop_detection = LDP_LOOP_NONE;
  }

  if (MPLS_MSGPARAM(Init)->aspExists) {
    if (range.type >= MPLS_LABEL_RANGE_ATM_VP && range.type <= MPLS_LABEL_RANGE_ATM_VP_VC) {
      MPLS_ASSERT(0);
    } else {
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_INIT,
        "Init Failed(%d): sending bad Label Range (ATM)\n", s->index);
      s->shutdown_notif = LDP_NOTIF_SESSION_REJECTED_PARAMETERS_LABEL_RANGE;
      s->shutdown_fatal = MPLS_BOOL_FALSE;
      return MPLS_FAILURE;
    }
  } else if (MPLS_MSGPARAM(Init)->fspExists) {
    if (range.type >= MPLS_LABEL_RANGE_FR_10 && range.type <= MPLS_LABEL_RANGE_FR_24) {
      MPLS_ASSERT(0);
    } else {
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_INIT,
        "Init Failed(%d): sending bad Label Range (FR)\n", s->index);
      s->shutdown_notif = LDP_NOTIF_SESSION_REJECTED_PARAMETERS_LABEL_RANGE;
      s->shutdown_fatal = MPLS_BOOL_FALSE;
      return MPLS_FAILURE;
    }
  }

  LDP_EXIT(g->user_data, "ldp_init_process");

  return MPLS_SUCCESS;
}
