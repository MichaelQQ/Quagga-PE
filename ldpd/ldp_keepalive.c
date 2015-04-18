
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_mesg.h"
#include "ldp_nortel.h"
#include "ldp_buf.h"
#include "ldp_keepalive.h"
#include "ldp_session.h"
#include "ldp_pdu_setup.h"

#include "mpls_assert.h"
#include "mpls_socket_impl.h"
#include "mpls_timer_impl.h"
#include "mpls_lock_impl.h"
#include "mpls_trace_impl.h"

void ldp_keepalive_timeout_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle handle)
{
  ldp_session *s = (ldp_session *) extra;
  ldp_global *g = (ldp_global*)handle;

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_TIMER,
    "Keepalive Timeout fired: session(%d)\n", s->index);

  mpls_lock_get(g->global_lock);

  s->shutdown_notif = LDP_NOTIF_KEEPALIVE_TIMER_EXPIRED;
  s->shutdown_fatal = MPLS_BOOL_FALSE;
  /* we should go into backoff, so don't completly kill the session */
  ldp_session_shutdown(g, s, MPLS_BOOL_FALSE);
  MPLS_REFCNT_RELEASE(s, ldp_session_delete);

  mpls_lock_release(g->global_lock);
}

void ldp_keepalive_send_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle handle)
{
  ldp_session *s = (ldp_session *) extra;
  ldp_global *g = (ldp_global*)handle;

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_TIMER,
    "Keepalive Send fired: session(%d)\n", s->index);

  mpls_lock_get(g->global_lock);
  ldp_keepalive_send(g, s);
  mpls_lock_release(g->global_lock);
}

ldp_mesg *ldp_keepalive_create(uint32_t msgid)
{
  ldp_mesg *msg = NULL;

  msg = ldp_mesg_create();
  ldp_mesg_prepare(msg, MPLS_KEEPAL_MSGTYPE, msgid);

  return msg;
}

void ldp_keepalive_set_message_id(ldp_mesg * msg, uint32_t msgid)
{
  mplsLdpKeepAlMsg_t *keep;

  MPLS_ASSERT(msg);
  keep = &msg->u.keep;
  setBaseMsgId(&(keep->baseMsg), msgid);
}

mpls_return_enum ldp_keepalive_send(ldp_global * g, ldp_session * s)
{
  MPLS_ASSERT(s);

  if (s->keepalive == NULL) {
    if ((s->keepalive = ldp_keepalive_create(g->message_identifier++)) == NULL) {
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
        "ldp_keepalive_send: error creating keepalve\n");
      return MPLS_FAILURE;
    }
  } else {
    ldp_keepalive_set_message_id(s->keepalive, g->message_identifier++);
  }

  if (mpls_timer_handle_verify(g->timer_handle, s->keepalive_recv_timer) ==
    MPLS_BOOL_FALSE) {
    MPLS_REFCNT_HOLD(s);
    s->keepalive_recv_timer = mpls_timer_create(g->timer_handle, MPLS_UNIT_SEC,
      s->oper_keepalive, (void *)s, g, ldp_keepalive_timeout_callback);
    if (mpls_timer_handle_verify(g->timer_handle, s->keepalive_recv_timer) ==
      MPLS_BOOL_FALSE) {
      MPLS_REFCNT_RELEASE(s, ldp_session_delete);
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
        "ldp_keepalive_send: error creating timer\n");
      return MPLS_FAILURE;
    }
    mpls_timer_start(g->timer_handle, s->keepalive_recv_timer, MPLS_TIMER_ONESHOT);
  }

  if (mpls_timer_handle_verify(g->timer_handle, s->keepalive_send_timer) ==
    MPLS_BOOL_FALSE) {
    MPLS_REFCNT_HOLD(s);
    s->keepalive_send_timer = mpls_timer_create(g->timer_handle, MPLS_UNIT_SEC,
      s->oper_keepalive_interval, (void *)s, g, ldp_keepalive_send_callback);
    if (mpls_timer_handle_verify(g->timer_handle, s->keepalive_send_timer) ==
      MPLS_BOOL_FALSE) {
      MPLS_REFCNT_RELEASE(s, ldp_session_delete);
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
        "ldp_keepalive_send: error creating timer\n");
      return MPLS_FAILURE;
    }
    mpls_timer_start(g->timer_handle, s->keepalive_send_timer, MPLS_TIMER_REOCCURRING);
  }

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_PERIODIC,
    "Keepalive Send: session(%d)\n", s->index);

  ldp_mesg_send_tcp(g, s, s->keepalive);

  return MPLS_SUCCESS;
}
