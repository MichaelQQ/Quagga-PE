
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdlib.h>
#include <sys/socket.h>
#include "ldp_struct.h"
#include "ldp_global.h"
#include "ldp_session.h"
#include "ldp_hello.h"
#include "ldp_global.h"
#include "ldp_entity.h"
#include "ldp_adj.h"
#include "ldp_peer.h"
#include "mpls_mm_impl.h"
#include "mpls_assert.h"
#include "mpls_timer_impl.h"
#include "mpls_lock_impl.h"
#include "mpls_trace_impl.h"

static uint32_t _ldp_adj_next_index = 1;

ldp_adj *ldp_adj_create(mpls_inet_addr * source, mpls_inet_addr * lsraddr,
  int labelspace, int remote_hellotime,
  mpls_inet_addr * remote_transport_address, uint32_t remote_csn)
{
  ldp_adj *a = (ldp_adj *) mpls_malloc(sizeof(ldp_adj));
  struct in_addr addr;

  if (lsraddr == NULL || source == NULL)
    return NULL;

  if (a) {
    memset(a, 0, sizeof(ldp_adj));
    MPLS_REFCNT_INIT(a, 0);
    MPLS_LIST_ELEM_INIT(a, _global);
    MPLS_LIST_ELEM_INIT(a, _session);
    MPLS_LIST_ELEM_INIT(a, _entity);

    a->index = _ldp_adj_get_next_index();

    /* these are operational values */
    /* JLEU: where do I grab these values from */

    /* these values are learned form the remote peer */
    memcpy(&a->remote_source_address, source, sizeof(mpls_inet_addr));
    memcpy(&a->remote_lsr_address, lsraddr, sizeof(mpls_inet_addr));

    addr.s_addr = htonl(lsraddr->u.ipv4);
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_PERIODIC,
	"Adj(%d) created for %s/",a->index, inet_ntoa(addr));
    addr.s_addr = htonl(source->u.ipv4);
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_PERIODIC,
	"%s\n",inet_ntoa(addr));

    if (remote_transport_address) {
      memcpy(&a->remote_transport_address, remote_transport_address,
        sizeof(mpls_inet_addr));
    } else {
      memset(&a->remote_transport_address, 0, sizeof(mpls_inet_addr));
    }

    a->remote_hellotime = remote_hellotime;
    a->remote_csn = remote_csn;
    a->state = MPLS_OPER_DOWN;
    a->role = LDP_NONE;
  }
  return a;
}

void ldp_adj_delete(ldp_adj * a)
{
  fprintf(stderr,"adj delete\n");
  MPLS_REFCNT_ASSERT(a, 0);
  mpls_free(a);
}

mpls_return_enum ldp_adj_startup(ldp_global * g, ldp_adj * a, int request)
{
  ldp_entity *e;

  MPLS_ASSERT(a && (e = a->entity));
  /* with recent changes to when the session gets created I think this
   * assert is not longer valid - jleu 2003-02-20
  MPLS_ASSERT(!a->session);
   */
  MPLS_ASSERT(a->state != LDP_NONE);

  LDP_ENTER(g->user_data, "ldp_adj_startup");

  /* ldp-11 3.5.2. Hello Message */
  if (e->hellotime_timer != 0xFFFF) {
    MPLS_REFCNT_HOLD(a);
    a->hellotime_recv_timer = mpls_timer_create(g->timer_handle, MPLS_UNIT_SEC,
      e->hellotime_timer, (void *)a, g, ldp_hello_timeout_callback);

    if (mpls_timer_handle_verify(g->timer_handle, a->hellotime_recv_timer) ==
      MPLS_BOOL_FALSE) {
      MPLS_REFCNT_RELEASE(a, ldp_adj_delete);
      goto ldp_adj_startup_error;
    }
  }

  if (request && mpls_timer_handle_verify(g->timer_handle,
      e->p.peer->hellotime_send_timer) == MPLS_BOOL_FALSE) {
    /* request is ONLY specific with indirect adj */
    ldp_hello_send(g, e);
  }

  a->state = MPLS_OPER_UP;

  if (e->hellotime_timer != 0xFFFF) {
    mpls_timer_start(g->timer_handle, a->hellotime_recv_timer,
      MPLS_TIMER_ONESHOT);
  }

  LDP_EXIT(g->user_data, "ldp_adj_startup");

  return MPLS_SUCCESS;

ldp_adj_startup_error:

  LDP_EXIT(g->user_data, "ldp_adj_startup: error");

  return MPLS_FAILURE;
}

#if 0                           /* no one used this? */
mpls_return_enum ldp_adj_restart(ldp_global * g, ldp_adj * a)
{

  LDP_ENTER(g->user_data, "ldp_adj_restart");

  if (a->session != NULL) {
    ldp_session_shutdown(g, a->session);
    /* session_shutdown does this already ldp_adj_del_session(a); */
  }
  mpls_timer_stop(g->timer_handle, a->hellotime_recv_timer);
  mpls_timer_start(g->timer_handle, a->hellotime_recv_timer, MPLS_TIMER_ONESHOT);

  LDP_EXIT(g->user_data, "ldp_adj_restart");

  return MPLS_SUCCESS;
}
#endif

mpls_return_enum ldp_adj_shutdown(ldp_global * g, ldp_adj * a)
{
  ldp_entity *e;

  MPLS_ASSERT(g && a && (e = a->entity));

  LDP_ENTER(g->user_data, "ldp_adj_shutdown");

  MPLS_REFCNT_HOLD(a);

  if (a->session) {
    ldp_session_shutdown(g, a->session, MPLS_BOOL_TRUE);
    /* session_shutdown does ldp_adj_del_session(a); */
  }

  ldp_adj_recv_stop(g, a);

  if (e->entity_type == LDP_INDIRECT &&
    e->p.peer->target_role == LDP_PASSIVE) {
    /* we started sending due to a targeted hello with "request"
     * now that the adj is down we can stop
     */
    ldp_peer_send_stop(g, e->p.peer);
  }

  ldp_entity_del_adj(e, a);
  if (a->state == MPLS_OPER_UP) {
    _ldp_global_del_adj(g, a);
  }

  LDP_EXIT(g->user_data, "ldp_adj_shutdown");

  MPLS_REFCNT_RELEASE(a, ldp_adj_delete);

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_adj_maintain_timer(ldp_global * g, ldp_adj * a)
{
  mpls_return_enum retval;

  LDP_ENTER(g->user_data, "ldp_adj_maintain_timer");

  mpls_timer_stop(g->timer_handle, a->hellotime_recv_timer);
  retval =
    mpls_timer_start(g->timer_handle, a->hellotime_recv_timer, MPLS_TIMER_ONESHOT);

  LDP_EXIT(g->user_data, "ldp_adj_maintain_timer");

  return retval;
}

mpls_return_enum ldp_adj_recv_start(ldp_global * g, ldp_adj * a)
{
  mpls_return_enum result = MPLS_SUCCESS;

  LDP_ENTER(g->user_data, "ldp_adj_recv_start");

  MPLS_REFCNT_HOLD(a);
  a->hellotime_recv_timer = mpls_timer_create(g->timer_handle, MPLS_UNIT_SEC,
    a->entity->hellotime_timer, (void *)a, g, ldp_hello_timeout_callback);

  if (mpls_timer_handle_verify(g->timer_handle, a->hellotime_recv_timer) ==
    MPLS_BOOL_FALSE) {
    MPLS_REFCNT_RELEASE(a, ldp_adj_delete);
    result = MPLS_FAILURE;
  }

  LDP_EXIT(g->user_data, "ldp_adj_recv_start");

  return result;
}

mpls_return_enum ldp_adj_recv_stop(ldp_global * g, ldp_adj * a)
{

  LDP_ENTER(g->user_data, "ldp_adj_recv_stop");

  if (mpls_timer_handle_verify(g->timer_handle, a->hellotime_recv_timer) ==
    MPLS_BOOL_TRUE) {
    mpls_timer_stop(g->timer_handle, a->hellotime_recv_timer);
    mpls_timer_delete(g->timer_handle, a->hellotime_recv_timer);
    a->hellotime_recv_timer = (mpls_timer_handle) 0;
    MPLS_REFCNT_RELEASE(a, ldp_adj_delete);
  }

  LDP_EXIT(g->user_data, "ldp_adj_recv_stop");

  return MPLS_SUCCESS;
}

void _ldp_adj_add_entity(ldp_adj * a, ldp_entity * e)
{
  MPLS_ASSERT(a && e);
  MPLS_REFCNT_HOLD(e);
  a->entity = e;
}

void _ldp_adj_del_entity(ldp_adj * a, ldp_entity *e)
{
  MPLS_ASSERT(a && e);
  MPLS_REFCNT_RELEASE(e, ldp_entity_delete);
  a->entity = NULL;
}

void ldp_adj_add_session(ldp_adj * a, ldp_session * s)
{
  MPLS_ASSERT(a && s);

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_PERIODIC,
	"Adj(%d) bound to sesssion(%d)\n",a->index,s->index);

  MPLS_REFCNT_HOLD(s);
  a->session = s;
  _ldp_session_add_adj(s, a);
}

void ldp_adj_del_session(ldp_adj * a, ldp_session * s)
{
  MPLS_ASSERT(a && s);
  _ldp_session_del_adj(s, a);
  MPLS_REFCNT_RELEASE(s, ldp_session_delete);
  a->session = NULL;
}

uint32_t _ldp_adj_get_next_index()
{
  uint32_t retval = _ldp_adj_next_index;

  _ldp_adj_next_index++;
  if (retval > _ldp_adj_next_index) {
    _ldp_adj_next_index = 1;
  }
  return retval;
}
