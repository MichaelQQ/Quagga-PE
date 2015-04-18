
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdio.h>
#include <sys/socket.h>

#include "ldp_struct.h"
#include "ldp_hello.h"
#include "ldp_mesg.h"
#include "ldp_buf.h"
#include "ldp_adj.h"
#include "ldp_hello.h"
#include "ldp_entity.h"
#include "ldp_session.h"
#include "ldp_inet_addr.h"
#include "ldp_pdu_setup.h"

#include "mpls_assert.h"
#include "mpls_socket_impl.h"
#include "mpls_timer_impl.h"
#include "mpls_lock_impl.h"
#include "mpls_trace_impl.h"

void ldp_hello_timeout_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle handle)
{
  ldp_adj *a = (ldp_adj *) extra;
  ldp_global *g = (ldp_global*)handle;

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_TIMER,
    "Hello Timout fired: adj(%d)\n", a->index);

  mpls_lock_get(g->global_lock);

  if (a->session) {
    a->session->shutdown_notif = LDP_NOTIF_HOLD_TIMER_EXPIRED;
    a->session->shutdown_fatal = MPLS_BOOL_FALSE;
  }
  ldp_adj_shutdown(g, a);
  /* timer is deleted inside of ldp_adj_shutdown */
  /* the refcount release for the time is done in ldp_adj_shutdown as well */

  mpls_lock_release(g->global_lock);
}

void ldp_hello_send_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle handle)
{
  ldp_entity *e = (ldp_entity*)extra;
  ldp_global *g = (ldp_global*)handle;

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_TIMER,
    "Hello Send fired: entity(%d)\n", e->index);

  mpls_lock_get(g->global_lock);

  ldp_hello_send(g, e);

  mpls_lock_release(g->global_lock);
}

mpls_return_enum ldp_hello_send(ldp_global * g, ldp_entity * e)
{
  ldp_mesg **hello = NULL;
  mpls_timer_handle *timer;
  int *oper_duration = 0;
  int targeted = 0;
  int duration = 0;
  int request = 0;

  MPLS_ASSERT(g != NULL && e != NULL);

  switch (e->entity_type) {
    case LDP_DIRECT:
      MPLS_ASSERT(e->p.iff != NULL);
      hello = &e->p.iff->hello;
      oper_duration = &e->p.iff->hellotime_send_timer_duration;
      timer = &e->p.iff->hellotime_send_timer;
      targeted = 0;
      request = 0;
      break;
    case LDP_INDIRECT:
      MPLS_ASSERT(e->p.peer != NULL);
      hello = &e->p.peer->hello;
      oper_duration = &e->p.peer->hellotime_send_timer_duration;
      timer = &e->p.peer->hellotime_send_timer;
      targeted = 1;
      if (e->p.peer->target_role == LDP_ACTIVE) {
        request = 1;
      } else {
        request = 0;
      }
      break;
    default:
      MPLS_ASSERT(0);
  }
  if (!*hello) {
    *hello = ldp_hello_create(g->message_identifier++,
      e->hellotime_timer, &e->transport_address,
      g->configuration_sequence_number, targeted, request);
  }

  duration = e->hellotime_interval;

  if (mpls_timer_handle_verify(g->timer_handle, *timer) == MPLS_BOOL_FALSE) {
    MPLS_REFCNT_HOLD(e);
    *timer = mpls_timer_create(g->timer_handle, MPLS_UNIT_SEC,
      duration, (void *)e, g, ldp_hello_send_callback);
    if (mpls_timer_handle_verify(g->timer_handle, *timer) == MPLS_BOOL_FALSE) {
      *oper_duration = 0;
      MPLS_REFCNT_RELEASE(e, ldp_entity_delete);
      return MPLS_FAILURE;
    }
    *oper_duration = duration;
    mpls_timer_start(g->timer_handle, *timer, MPLS_TIMER_REOCCURRING);
  } else {
    if ((*oper_duration) != duration) {
      mpls_timer_stop(g->timer_handle, *timer);
      *oper_duration = duration;
      mpls_timer_modify(g->timer_handle, *timer, duration);
      mpls_timer_start(g->timer_handle, *timer, MPLS_TIMER_REOCCURRING);
    }
  }

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_PERIODIC,
    "Hello Send: entity(%d)\n", e->index);

  return ldp_mesg_send_udp(g, e, *hello);
}

ldp_mesg *ldp_hello_create(uint32_t msgid, int holdtime, mpls_inet_addr * traddr,
  uint32_t confnum, int targeted, int request)
{
  mplsLdpHelloMsg_t *hello = NULL;
  ldp_mesg *msg = NULL;

  msg = ldp_mesg_create();
  ldp_mesg_prepare(msg, MPLS_HELLO_MSGTYPE, msgid);
  if (msg != NULL) {
    hello = &msg->u.hello;

    hello->trAdrTlvExists = 0;
    hello->csnTlvExists = 0;

    hello->chpTlvExists = 1;

    /* this assumes we always want to receive updates for targeted hellos */
    hello->baseMsg.msgLength += setupChpTlv(&(hello->chp), targeted,
      request, 0, holdtime);

    if (traddr && traddr->type == MPLS_FAMILY_IPV4 && traddr->u.ipv4 > 0) {
      hello->trAdrTlvExists = 1;
      hello->baseMsg.msgLength +=
        setupTrAddrTlv(&(hello->trAdr), traddr->u.ipv4);
    }

    if (confnum > 0) {
      hello->csnTlvExists = 1;
      hello->baseMsg.msgLength += setupCsnTlv(&(hello->csn), confnum);
    }
  }
  return msg;
}

mpls_return_enum ldp_hello_process(ldp_global * g, ldp_adj * a, ldp_entity *e,
  int hellotime, uint32_t csn, mpls_inet_addr * traddr, int targeted,
  int request)
{
  mpls_inet_addr *local = NULL, *remote = NULL;

  MPLS_ASSERT(a && e);

  LDP_ENTER(g->user_data, "ldp_hello_process: a = %p, e = %p", a, e);

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_PERIODIC,
    "Hello Recv: entity(%d)\n", e->index);

  switch (e->entity_type) {
    case LDP_DIRECT:
      /* ldp-11 3.5.2. Hello Message */
      if (hellotime == 0) {
        hellotime = 15;
      }

      if (MPLS_LIST_HEAD(&e->p.iff->addr_root)) {
	local = &(MPLS_LIST_HEAD(&e->p.iff->addr_root)->address);
      } else {
        local = &g->lsr_identifier;
      }

      break;
    case LDP_INDIRECT:
      /* ldp-11 3.5.2. Hello Message */
      if (hellotime == 0) {
        hellotime = 45;
      }

      local = &g->lsr_identifier;
      break;
    default:
      MPLS_ASSERT(0);
  }

  if (hellotime < e->hellotime_timer) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_NORMAL,
      "ldp_hello_process: adjusting hellotime_timer to match adj\n");
    e->hellotime_timer = hellotime;
  }

  if (traddr != NULL) {
    memcpy(&a->remote_transport_address, traddr, sizeof(struct mpls_inet_addr));
  }

  if (csn != a->remote_csn) {
    /* the remote csn changes all we can do is clear the backoff time */
    /* this will only enable a lsr in the active role to try again */
    a->remote_csn = csn;
    if (a->session && mpls_timer_handle_verify(g->timer_handle,
      a->session->backoff_timer) == MPLS_BOOL_TRUE) {
      ldp_session_backoff_stop(g, a->session);
    }
  }

  /* JLEU should verify that the hello hasn't changed */

  if (a->session) {
    /*  && a->session->state == LDP_STATE_OPERATIONAL) */
    /* all that matters is that we have a session in progress */
    /* we already have an established session */
    LDP_EXIT(g->user_data, "ldp_hello_process");
    return MPLS_SUCCESS;
  }

  if (e->transport_address.type != MPLS_FAMILY_NONE) {
    local = &e->transport_address;
  }

  if (a->remote_transport_address.type != MPLS_FAMILY_NONE) {
    remote = &a->remote_transport_address;
  } else {
    remote = &a->remote_source_address;
  }

  switch (mpls_inet_addr_compare(local, remote)) {
    case 1:
      /* if at one point we through WE were passive */
      if (a->role == LDP_PASSIVE && a->session) {
        ldp_session_shutdown(g, a->session, MPLS_BOOL_TRUE);
      }
      a->role = LDP_ACTIVE;

      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_STATE,
        "ldp_hello_process: ACTIVE(%d)\n", a->index);

      if (ldp_session_create_active(g, a) != MPLS_SUCCESS) {
	LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_NORMAL,
	  "ldp_hello_process: creating an active session failed(%d)\n",
	  a->index);
        /* return FAILURE so we don't try to continue with the new adj */
	return MPLS_FAILURE;
      }
      break;
    case -1:
      /* if at one point we through WE were active */
      if (a->role == LDP_ACTIVE && a->session) {
	ldp_session_shutdown(g, a->session, MPLS_BOOL_TRUE);
      }
      a->role = LDP_PASSIVE;

      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_STATE,
        "ldp_hello_process: PASSIVE(%d)\n", a->index);

      break;
    default:
      LDP_PRINT(g->user_data,
        "ldp_hello_process: exit(%d) configuration error\n", a->index);

      if (a->session) {
	ldp_session_shutdown(g, a->session, MPLS_BOOL_TRUE);
      }
      a->role = LDP_NONE;
      MPLS_ASSERT(a->session == NULL);

      /* return FAILURE so we don't try to continue with the new adj */
      LDP_EXIT(g->user_data, "ldp_hello_process: FAILURE");
      return MPLS_FAILURE;
  }
  LDP_EXIT(g->user_data, "ldp_hello_process");

  return MPLS_SUCCESS;
}
