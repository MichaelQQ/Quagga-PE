
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
#include "ldp_entity.h"
#include "ldp_peer.h"
#include "ldp_hello.h"
#include "ldp_buf.h"
#include "ldp_mesg.h"

#include "mpls_assert.h"
#include "mpls_fib_impl.h"
#include "mpls_ifmgr_impl.h"
#include "mpls_lock_impl.h"
#include "mpls_timer_impl.h"
#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"

uint32_t _ldp_sub_entity_next_index = 1;

void ldp_peer_retry_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle handle)
{
  ldp_peer *p = (ldp_peer *) extra;
  ldp_global *g = (ldp_global*)handle;

  LDP_ENTER(g->user_data, "ldp_peer_retry_callback");

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_TIMER,
    "Peer Retry Timer fired: peer(%d)\n", p->index);

  mpls_lock_get(g->global_lock);

  /* JLEU: should I hold a copy to make sure this doens't fail? */
  ldp_peer_retry_stop(g, p);
  if (ldp_peer_startup(g, p) == MPLS_FAILURE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
      "Peer startup retry failure: peer (%d)\n", p->index);
  }

  mpls_lock_release(g->global_lock);

  LDP_EXIT(g->user_data, "ldp_peer_retry_callback");
}

ldp_peer *ldp_peer_create()
{
  ldp_peer *p = (ldp_peer *) mpls_malloc(sizeof(ldp_peer));

  if (p) {
    memset(p, 0, sizeof(ldp_peer));
    MPLS_REFCNT_INIT(p, 0);
    MPLS_LIST_ELEM_INIT(p, _global);
    p->label_space = -1;
    p->tx_buffer = ldp_buf_create(MPLS_PDUMAXLEN);
    p->tx_message = ldp_mesg_create();
    p->index = _ldp_peer_get_next_index();

    p->oper_state = MPLS_OPER_DOWN;
    p->target_role = LDP_ACTIVE;
  }
  return p;
}

void ldp_peer_delete(ldp_peer * p)
{
  // LDP_PRINT(g->user_data,"peer delete\n");
  MPLS_REFCNT_ASSERT(p, 0);
  mpls_free(p->tx_buffer);
  mpls_free(p->tx_message);
  mpls_free(p);
}

mpls_return_enum ldp_peer_startup(ldp_global * g, ldp_peer * p)
{
  ldp_entity *e = NULL;

  MPLS_ASSERT(p != NULL && ((e = p->entity) != NULL));

  LDP_ENTER(g->user_data, "ldp_peer_startup");

  p->dest.port = e->remote_udp_port;

  if (p->target_role == LDP_ACTIVE) {
    if (ldp_hello_send(g, e) == MPLS_FAILURE) {
      goto ldp_peer_startup_retry;
    }
  }

  p->oper_state = MPLS_OPER_UP;

  LDP_EXIT(g->user_data, "ldp_peer_startup");

  return MPLS_SUCCESS;

ldp_peer_startup_retry:

  /* start a timer which will retry peer startup */
  MPLS_REFCNT_HOLD(p);
  p->oper_state = MPLS_OPER_DOWN;
  p->no_route_to_peer_timer = mpls_timer_create(g->timer_handle, MPLS_UNIT_SEC,
    g->no_route_to_peer_time, (void *)p, g, ldp_peer_retry_callback);

  if (mpls_timer_handle_verify(g->timer_handle, p->no_route_to_peer_timer) ==
    MPLS_BOOL_FALSE) {
    MPLS_REFCNT_RELEASE(p, ldp_peer_delete);
    LDP_EXIT(g->user_data, "ldp_peer_startup-error");
    return MPLS_FAILURE;
  }
  mpls_timer_start(g->timer_handle, p->no_route_to_peer_timer, MPLS_TIMER_ONESHOT);

  LDP_EXIT(g->user_data, "ldp_peer_startup");

  return MPLS_SUCCESS;
}

void ldp_peer_retry_stop(ldp_global * g, ldp_peer * p)
{
  MPLS_ASSERT(p != NULL);

  LDP_ENTER(g->user_data, "ldp_peer_retry_stop");

  if (mpls_timer_handle_verify(g->timer_handle, p->no_route_to_peer_timer) ==
    MPLS_BOOL_TRUE) {
    mpls_timer_stop(g->timer_handle, p->no_route_to_peer_timer);
    mpls_timer_delete(g->timer_handle, p->no_route_to_peer_timer);
    p->no_route_to_peer_timer = 0;
    MPLS_REFCNT_RELEASE(p, ldp_peer_delete);
    MPLS_ASSERT(p != NULL);
  }

  LDP_EXIT(g->user_data, "ldp_peer_retry_stop");
}

void ldp_peer_send_stop(ldp_global * g, ldp_peer * p)
{
  ldp_entity *e = NULL;

  MPLS_ASSERT(p != NULL && (e = p->entity) != NULL);

  LDP_ENTER(g->user_data, "ldp_peer_send_stop");

  if (mpls_timer_handle_verify(g->timer_handle, p->hellotime_send_timer) ==
    MPLS_BOOL_TRUE) {
    mpls_timer_stop(g->timer_handle, p->hellotime_send_timer);
    mpls_timer_delete(g->timer_handle, p->hellotime_send_timer);
    p->hellotime_send_timer_duration = 0;
    p->hellotime_send_timer = 0;
    MPLS_REFCNT_RELEASE(e, ldp_entity_delete);
    MPLS_ASSERT(e != NULL);
  }
  if (p->hello != NULL) {
    ldp_mesg_delete(p->hello);
    p->hello = NULL;
  }

  LDP_EXIT(g->user_data, "ldp_peer_send_stop");
}

mpls_return_enum ldp_peer_shutdown(ldp_global * g, ldp_peer * p)
{
  LDP_ENTER(g->user_data, "ldp_peer_shutdown");

  p->oper_state = MPLS_OPER_DOWN;
  ldp_peer_send_stop(g, p);
  ldp_peer_retry_stop(g, p);

  LDP_EXIT(g->user_data, "ldp_peer_shutdown");
  return MPLS_SUCCESS;
}

mpls_bool ldp_peer_is_active(ldp_peer * p)
{
  if (p && p->entity && p->entity->admin_state == MPLS_ADMIN_ENABLE)
    return MPLS_BOOL_TRUE;

  return MPLS_BOOL_FALSE;
}

mpls_return_enum _ldp_peer_add_entity(ldp_peer * p, ldp_entity * e)
{
  if (p && e) {
    MPLS_REFCNT_HOLD(e);
    p->entity = e;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum _ldp_peer_del_entity(ldp_peer * p)
{
  if (p && p->entity) {
    MPLS_REFCNT_RELEASE(p->entity, ldp_entity_delete);
    p->entity = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

ldp_entity *ldp_peer_get_entity(ldp_peer * p)
{
  return p->entity;
}

uint32_t _ldp_peer_get_next_index()
{
  uint32_t retval = _ldp_sub_entity_next_index;

  _ldp_sub_entity_next_index++;
  if (retval > _ldp_sub_entity_next_index) {
    _ldp_sub_entity_next_index = 1;
  }
  return retval;
}
