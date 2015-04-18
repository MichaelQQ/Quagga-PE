
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdlib.h>
#include "ldp_struct.h"
#include "ldp_outlabel.h"
#include "ldp_session.h"
#include "ldp_entity.h"
#include "ldp_inlabel.h"
#include "ldp_outlabel.h"
#include "ldp_addr.h"
#include "ldp_attr.h"
#include "ldp_adj.h"
#include "ldp_mesg.h"
#include "ldp_buf.h"
#include "ldp_inet_addr.h"
#include "ldp_global.h"
#include "ldp_state_machine.h"
#include "ldp_label_rel_with.h"
#include "ldp_label_request.h"
#include "ldp_label_mapping.h"

#include "mpls_refcnt.h"
#include "mpls_assert.h"
#include "mpls_mm_impl.h"
#include "mpls_timer_impl.h"
#include "mpls_socket_impl.h"
#include "mpls_trace_impl.h"
#include "mpls_ifmgr_impl.h"
#include "mpls_policy_impl.h"
#include "mpls_lock_impl.h"

static uint32_t _ldp_session_next_index = 1;

mpls_return_enum ldp_session_attempt_setup(ldp_global *g, ldp_session *s);
mpls_return_enum ldp_session_backoff_stop(ldp_global * g, ldp_session * s);

static void ldp_session_backoff_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle handle)
{
  ldp_session *s = (ldp_session *)extra;
  ldp_global *g = (ldp_global*)handle;

  LDP_ENTER(g->user_data, "ldp_session_backoff");

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_TIMER,
    "Session Backoff Timer fired: session(%s)\n", s->session_name);

  mpls_lock_get(g->global_lock);

  s->backoff_timer = 0;

  if (s->oper_role == LDP_ACTIVE) {
    if (ldp_session_attempt_setup(g, s) != MPLS_SUCCESS) {
      s->backoff += g->backoff_step;
      s->backoff_timer = timer;
      mpls_timer_start(g->timer_handle, timer, MPLS_TIMER_ONESHOT);

      LDP_EXIT(g->user_data, "ldp_session_backoff-error");

      goto ldp_session_backoff_end;
    }
  } else if (s->oper_role == LDP_PASSIVE) {
    /* this is a passive session that never received an init, kill it
     * session current on the global list and the timer holds a refcnt.
     * shutdown takes this session off of the global list, so when the
     * timer refcnt is released the session will be deleted */
    ldp_session_shutdown(g, s, MPLS_BOOL_TRUE);
  } else {
    MPLS_ASSERT(0);
  }

  mpls_timer_stop(g->timer_handle, timer);
  mpls_timer_delete(g->timer_handle, timer);
  MPLS_REFCNT_RELEASE(s, ldp_session_delete);

ldp_session_backoff_end:

  mpls_lock_release(g->global_lock);

  LDP_EXIT(g->user_data, "ldp_session_backoff");
}

ldp_session *ldp_session_create()
{
  ldp_session *s = (ldp_session *) mpls_malloc(sizeof(ldp_session));

  if (s) {
    memset(s, 0, sizeof(ldp_session));
    MPLS_REFCNT_INIT(s, 0);
    MPLS_LIST_ELEM_INIT(s, _global);
    MPLS_LIST_INIT(&s->outlabel_root, ldp_outlabel);
    MPLS_LIST_INIT(&s->attr_root, ldp_attr);
    MPLS_LIST_INIT(&s->adj_root, ldp_adj);
    mpls_link_list_init(&s->inlabel_root);
    mpls_link_list_init(&s->addr_root);

    s->on_global = MPLS_BOOL_FALSE;
    s->tx_buffer = ldp_buf_create(MPLS_PDUMAXLEN);
    s->tx_message = ldp_mesg_create();
    s->index = _ldp_session_get_next_index();
    s->oper_role = LDP_NONE;
  }
  return s;
}

mpls_return_enum ldp_session_attempt_setup(ldp_global *g, ldp_session *s) {
  mpls_socket_handle socket = mpls_socket_create_tcp(g->socket_handle);
  mpls_return_enum retval;

  LDP_ENTER(g->user_data, "ldp_session_attempt_setup");

  if (mpls_socket_handle_verify(g->socket_handle, socket) == MPLS_BOOL_FALSE) {
    return MPLS_FAILURE;
  }
  if (mpls_socket_options(g->socket_handle, socket, MPLS_SOCKOP_NONBLOCK) ==
    MPLS_FAILURE) {
    goto ldp_session_attempt_setup_error;
  }

  retval = mpls_socket_tcp_connect(g->socket_handle, socket, &s->remote_dest);

  switch (retval) {
    case MPLS_NON_BLOCKING:
      {
	LDP_TRACE_OUT(g->user_data,
	  "ldp_session_attempt_setup: MPLS_NON_BLOCKING\n");
        mpls_socket_writelist_add(g->socket_handle, socket, (void *)s,
          MPLS_SOCKET_TCP_CONNECT);
        break;
      }
    case MPLS_SUCCESS:
      {
	LDP_TRACE_OUT(g->user_data,
	  "ldp_session_attempt_setup: MPLS_SUCCESS\n");
        if (ldp_state_machine(g, s, NULL, NULL, LDP_EVENT_CONNECT, NULL,
            NULL) == MPLS_FAILURE) {
          goto ldp_session_attempt_setup_error;
        }
        break;
      }
    default:
      {
	LDP_TRACE_OUT(g->user_data,
	  "ldp_session_attempt_setup: MPLS_FAILURE\n");
        goto ldp_session_attempt_setup_error;
      }
      break;
  }

  s->socket = socket;
  LDP_EXIT(g->user_data, "ldp_session_attempt_setup");
  return MPLS_SUCCESS;

ldp_session_attempt_setup_error:

  mpls_socket_close(g->socket_handle, socket);
  LDP_EXIT(g->user_data, "ldp_session_attempt_setup");
  return MPLS_FAILURE;
}

mpls_return_enum ldp_session_create_active(ldp_global * g, ldp_adj * a)
{
  mpls_return_enum retval = MPLS_FAILURE;
  mpls_inet_addr *addr = NULL;
  ldp_session *s = NULL;
  ldp_adj* ap;

  MPLS_ASSERT(g && a && (!a->session));

  LDP_ENTER(g->user_data, "ldp_session_create_active");

  ap = MPLS_LIST_HEAD(&g->adj);
  while (ap) {
    if ((!mpls_inet_addr_compare(&ap->remote_lsr_address,
      &a->remote_lsr_address)) &&
      ap->remote_label_space == a->remote_label_space &&
      a->index != ap->index && ap->session) {
      ldp_adj_add_session(a, ap->session);
      retval = MPLS_SUCCESS;
      goto ldp_session_create_active;
    }
    ap = MPLS_LIST_NEXT(&g->adj, ap, _global);
  }

  if ((s = ldp_session_create())) {
    if (a->remote_transport_address.type != MPLS_FAMILY_NONE) {
      addr = &a->remote_transport_address;
    } else {
      addr = &a->remote_source_address;
    }

    _ldp_global_add_session(g, s);
    ldp_adj_add_session(a, s);
    s->state = LDP_STATE_NON_EXIST;

    memcpy(&s->remote_dest.addr, addr, sizeof(mpls_inet_addr));
    s->remote_dest.port = s->cfg_peer_tcp_port;

    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_session_create_active: (%d) changed to NON_EXIST\n", s->index);

    if (ldp_session_attempt_setup(g, s) != MPLS_SUCCESS) {
      /* go into backoff */
      ldp_session_backoff_start(g, s);
    }
    retval = MPLS_SUCCESS;
  }

ldp_session_create_active:

  LDP_EXIT(g->user_data, "ldp_session_create_active");
  return retval;
}

ldp_session *ldp_session_create_passive(ldp_global * g,
  mpls_socket_handle socket, mpls_dest * from)
{
  ldp_session *s = NULL;

  MPLS_ASSERT(g);

  LDP_ENTER(g->user_data, "ldp_session_create_passive");

  if ((s = ldp_session_create())) {
    s->socket = socket;
    s->state = LDP_STATE_NON_EXIST;

    if (mpls_socket_options(g->socket_handle, socket, MPLS_SOCKOP_NONBLOCK) ==
      MPLS_SUCCESS) {
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
        "ldp_session_create_passive: (%d) changed to NON_EXIST\n", s->index);
      _ldp_global_add_session(g, s);
    } else {
      ldp_session_delete(s);
      s = NULL;
    }
  }

  LDP_EXIT(g->user_data, "ldp_session_create_passive (%p)", s);

  return s;
}

void ldp_session_delete(ldp_session * s)
{
  fprintf(stderr,"session delete\n");
  MPLS_REFCNT_ASSERT(s, 0);
  mpls_free(s);
}

mpls_return_enum ldp_session_startup(ldp_global * g, ldp_session * s)
{
  //edit by tim under this line
  //mpls_inet_addr addr;
  //mpls_return_enum retval;
  mpls_return_enum retval=MPLS_FAILURE;
  ldp_addr *addr;
  //mpls_if_handle handle;

  void (*callback) (mpls_timer_handle timer, void *extra, mpls_cfg_handle g);

  MPLS_ASSERT(s && g && (s->oper_role != LDP_NONE));

  LDP_ENTER(g->user_data, "ldp_session_startup");

  /* when we make it to operational, get rid of any backoff timers */
  ldp_session_backoff_stop(g, s);
  s->state = LDP_STATE_OPERATIONAL;
  s->oper_up = time(NULL);

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
    "ldp_session_startup: (%d) changed to OPERATIONAL\n", s->index);

  /*
   * if configured to distribute addr messages walk the if table
   * and send an addr message for each
   */
  if (g->send_address_messages) {
    //addr.u.ipv4 = 0L;
    //edit by tim under this line
    addr = MPLS_LIST_HEAD(&g->addr);
    //retval = mpls_ifmgr_getfirst_address(g->ifmgr_handle, &handle, &addr);
    //while (retval == MPLS_SUCCESS) {
      //if (mpls_policy_address_export_check(g->user_data, &addr) ==
        //MPLS_BOOL_TRUE) {
        //ldp_addr_send(g, s, &addr);
      //}
      //retval = mpls_ifmgr_getnext_address(g->ifmgr_handle, &handle, &addr);
    //}
    //if (retval != MPLS_END_OF_LIST) {
      while (addr) {
      /* only locally attached addrs will have a valid iff */
      if (addr->iff) {
        if (ldp_addr_send(g, s, &addr->address) != MPLS_SUCCESS)
      goto ldp_session_startup_end;
      }
      addr = MPLS_LIST_NEXT(&g->addr, addr, _global);
    }
  }

  /* depending on the mode, grab a pointer to the correct callback */
  switch (s->oper_distribution_mode) {
    case LDP_DISTRIBUTION_ONDEMAND:
      callback = ldp_label_request_initial_callback;
      break;
    case LDP_DISTRIBUTION_UNSOLICITED:
      callback = ldp_label_mapping_initial_callback;
      break;
    default:
      MPLS_ASSERT(0);
  }

  /*
   * create a timer which will go about "chunking" the initial
   * set of requests or mappings
   */
  MPLS_REFCNT_HOLD(s);
  s->initial_distribution_timer = mpls_timer_create(g->timer_handle,
    MPLS_UNIT_SEC, LDP_REQUEST_CHUNK, (void *)s, g, callback);

  if (mpls_timer_handle_verify(g->timer_handle,
      s->initial_distribution_timer) == MPLS_BOOL_FALSE) {
    MPLS_REFCNT_RELEASE(s, ldp_session_delete);

    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_session_startup: initial distrib error(%d)\n", s->index);

    /* timer error, we might as well shutdown the session, it's usless */
    s->shutdown_notif = LDP_NOTIF_INTERNAL_ERROR;
    s->shutdown_fatal = MPLS_BOOL_TRUE;
    retval = MPLS_FAILURE;
  } else {
    mpls_timer_start(g->timer_handle, s->initial_distribution_timer,
      MPLS_TIMER_ONESHOT);
    retval = MPLS_SUCCESS;
  }

ldp_session_startup_end:

  LDP_EXIT(g->user_data, "ldp_session_startup");

  return retval;
}

void ldp_session_shutdown(ldp_global * g, ldp_session * s, mpls_bool complete)
{
  ldp_addr *a = NULL;
  ldp_attr *attr = NULL;
  ldp_attr *temp_attr = NULL;
  ldp_adj* ap;

  MPLS_ASSERT(s);

  LDP_ENTER(g->user_data, "ldp_session_shutdown");

  /*
   * hold a refcount so this session doesn't disappear on us
   * while cleaning up
   */
  MPLS_REFCNT_HOLD(s);

  s->state = LDP_STATE_NONE;
  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
    "ldp_session_shutdown: (%d) changed to NONE\n", s->index);

  /*
   * kill the timers for the session
   */
  if (mpls_timer_handle_verify(g->timer_handle, s->keepalive_recv_timer) ==
    MPLS_BOOL_TRUE) {
    mpls_timer_stop(g->timer_handle, s->keepalive_recv_timer);
    mpls_timer_delete(g->timer_handle, s->keepalive_recv_timer);
    MPLS_REFCNT_RELEASE(s, ldp_session_delete);
    s->keepalive_recv_timer = (mpls_timer_handle) 0;
  }
  if (mpls_timer_handle_verify(g->timer_handle, s->keepalive_send_timer) ==
    MPLS_BOOL_TRUE) {
    mpls_timer_stop(g->timer_handle, s->keepalive_send_timer);
    mpls_timer_delete(g->timer_handle, s->keepalive_send_timer);
    MPLS_REFCNT_RELEASE(s, ldp_session_delete);
    s->keepalive_send_timer = (mpls_timer_handle) 0;
  }
  if (mpls_timer_handle_verify(g->timer_handle,s->initial_distribution_timer) ==
    MPLS_BOOL_TRUE) {
    mpls_timer_stop(g->timer_handle, s->initial_distribution_timer);
    mpls_timer_delete(g->timer_handle, s->initial_distribution_timer);
    MPLS_REFCNT_RELEASE(s, ldp_session_delete);
    s->initial_distribution_timer = (mpls_timer_handle) 0;
  }

  /*
   * get rid of the socket
   */
  if (mpls_socket_handle_verify(g->socket_handle, s->socket) ==
    MPLS_BOOL_TRUE) {
    mpls_socket_readlist_del(g->socket_handle, s->socket);
    mpls_socket_close(g->socket_handle, s->socket);
  }

  /*
   * get rid of out cached keepalive
   */
  if (s->keepalive != NULL) {
    ldp_mesg_delete(s->keepalive);
    s->keepalive = NULL;
  }

  ldp_session_backoff_stop(g,s);

  attr = MPLS_LIST_HEAD(&g->attr);
  while (attr != NULL) {
    if (attr->session && attr->session->index == s->index) {
      temp_attr = attr;
      MPLS_REFCNT_HOLD(temp_attr);
      /*
       * ldp_attr_remove_complete removed everythig associated with the attr.
       * in and out labels, and cross connects as well
       */
      ldp_attr_remove_complete(g, attr, complete);
    } else {
      temp_attr = NULL;
    }
    attr = MPLS_LIST_NEXT(&g->attr, attr, _global);
    if (temp_attr)
      MPLS_REFCNT_RELEASE(temp_attr, ldp_attr_delete);
  }

  /*
   * clean up the addrs we created
   */
  while ((a = (ldp_addr*)mpls_link_list_head_data(&s->addr_root))) {
    ldp_session_del_addr(g, s, a);
  }

  /*
   * if we have an adj AND we are shuting down for a protocol reason, start a
   * backoff timer, so we can try again in the near future
   */
  if ((complete == MPLS_BOOL_TRUE) || (s->oper_role != LDP_ACTIVE)) {
    while ((ap = MPLS_LIST_HEAD(&s->adj_root))) {
      ldp_adj_del_session(ap, s);
    }

    if (s->on_global == MPLS_BOOL_TRUE) {
      _ldp_global_del_session(g, s);
    }
  } else {
    if (s->oper_role == LDP_ACTIVE) {
      ldp_session_backoff_start(g, s);
    }
  }

  /*
   * it is safe to release this refcnt now, if it is the last one, the
   * session will be deleted (this will be the last one in the case of
   * 'complete' == MPLS_BOOL_TRUE
   */
  MPLS_REFCNT_RELEASE(s, ldp_session_delete);

  LDP_EXIT(g->user_data, "ldp_session_shutdown");
}

mpls_return_enum ldp_session_maintain_timer(ldp_global * g, ldp_session * s,
  int flag)
{
  mpls_return_enum result = MPLS_FAILURE;

  LDP_ENTER(g->user_data, "ldp_session_maintain_timer");

  /*
   * all session keepalive maintainance comes through here (SEND and RECV)
   */
  if (flag == LDP_KEEPALIVE_RECV) {
    mpls_timer_stop(g->timer_handle, s->keepalive_recv_timer);
    result = mpls_timer_start(g->timer_handle, s->keepalive_recv_timer,
      MPLS_TIMER_ONESHOT);
  } else {
    mpls_timer_stop(g->timer_handle, s->keepalive_send_timer);
    result = mpls_timer_start(g->timer_handle, s->keepalive_send_timer,
      MPLS_TIMER_REOCCURRING);
  }

  LDP_EXIT(g->user_data, "ldp_session_maintain_timer");

  return result;
}

void ldp_session_add_outlabel(ldp_session * s, ldp_outlabel * o)
{
  MPLS_ASSERT(s && o);
  MPLS_REFCNT_HOLD(o);
  MPLS_LIST_ADD_HEAD(&s->outlabel_root, o, _session, ldp_outlabel);
  _ldp_outlabel_add_session(o, s);
}

void ldp_session_del_outlabel(ldp_session * s, ldp_outlabel * o)
{
  MPLS_ASSERT(s && o);
  MPLS_LIST_REMOVE(&s->outlabel_root, o, _session);
  _ldp_outlabel_del_session(o);
  MPLS_REFCNT_RELEASE(o, ldp_outlabel_delete);
}

mpls_return_enum ldp_session_add_inlabel(ldp_session * s, ldp_inlabel * i)
{
  MPLS_ASSERT(s && i);
  MPLS_REFCNT_HOLD(i);
  if (mpls_link_list_add_tail(&s->inlabel_root, i) == MPLS_SUCCESS) {
    if (_ldp_inlabel_add_session(i, s) == MPLS_SUCCESS) {
      return MPLS_SUCCESS;
    }
    mpls_link_list_remove_data(&s->inlabel_root, i);
  }
  MPLS_REFCNT_RELEASE(i, ldp_inlabel_delete);
  return MPLS_FAILURE;
}

void ldp_session_del_inlabel(ldp_session * s, ldp_inlabel * i)
{
  MPLS_ASSERT(s && i);
  mpls_link_list_remove_data(&s->inlabel_root, i);
  _ldp_inlabel_del_session(i, s);
  MPLS_REFCNT_RELEASE(i, ldp_inlabel_delete)
}

void _ldp_session_add_attr(ldp_session * s, ldp_attr * a)
{
  MPLS_ASSERT(s && a);
  MPLS_REFCNT_HOLD(a);
  MPLS_LIST_ADD_HEAD(&s->attr_root, a, _session, ldp_attr);
}

void _ldp_session_del_attr(ldp_session * s, ldp_attr * a)
{
  MPLS_ASSERT(s && a);
  MPLS_LIST_REMOVE(&s->attr_root, a, _session);
  MPLS_REFCNT_RELEASE(a, ldp_attr_delete);
}

mpls_return_enum ldp_session_add_addr(ldp_global *g, ldp_session * s,
  ldp_addr * a)
{
  struct mpls_link_list_node *lln;
  struct mpls_link_list_node *llnp;
  ldp_addr *data;

  MPLS_ASSERT(s && a);

  MPLS_REFCNT_HOLD(a);
  lln = mpls_link_list_node_create(a);
  if (lln) {
    if (_ldp_addr_add_session(a, s) == MPLS_SUCCESS) {
      MPLS_LINK_LIST_LOOP(&s->addr_root, data, llnp) {
        if (data->index > a->index) {
          mpls_link_list_add_node_before(&s->addr_root, llnp, lln);
          return MPLS_SUCCESS;
        }
      }

      mpls_link_list_add_node_tail(&s->addr_root, lln);
      return MPLS_SUCCESS;
    }
    mpls_link_list_node_delete(lln);
  }
  MPLS_REFCNT_RELEASE2(g, a, ldp_addr_delete);
  return MPLS_FAILURE;
}

void ldp_session_del_addr(ldp_global *g, ldp_session * s, ldp_addr * a) {
  MPLS_ASSERT(s && a);
  mpls_link_list_remove_data(&s->addr_root, a);
  _ldp_addr_del_session(a, s);
  MPLS_REFCNT_RELEASE2(g, a, ldp_addr_delete);
}

void _ldp_session_add_adj(ldp_session * s, ldp_adj * a)
{
  ldp_adj *ap = NULL;
  struct in_addr lsr_address;

  MPLS_ASSERT(s && a);
  MPLS_REFCNT_HOLD(a);

  s->cfg_remote_in_ttl_less_domain = a->entity->remote_in_ttl_less_domain;
  s->cfg_distribution_mode = a->entity->label_distribution_mode;
  s->cfg_loop_detection_mode = a->entity->loop_detection_mode;
  s->cfg_label_request_count = a->entity->label_request_count;
  s->cfg_label_request_timer = a->entity->label_request_timer;
  s->cfg_label_space = ldp_entity_label_space(a->entity);
  s->cfg_path_vector_limit = a->entity->path_vector_limit;
  s->cfg_hop_count_limit = a->entity->hop_count_limit;
  s->cfg_peer_tcp_port = a->entity->remote_tcp_port;
  s->cfg_keepalive = a->entity->keepalive_timer;
  s->cfg_max_pdu = a->entity->max_pdu;

  lsr_address.s_addr = htonl(a->remote_lsr_address.u.ipv4);
  sprintf(s->session_name, "%s:%d", inet_ntoa(lsr_address),
    a->remote_label_space);
  s->oper_role = a->role;

  ap = MPLS_LIST_HEAD(&s->adj_root);
  while (ap) {
    if (ap->index > a->index) {
      MPLS_LIST_INSERT_BEFORE(&s->adj_root, ap, a, _session);
      return;
    }
    ap = MPLS_LIST_NEXT(&s->adj_root, ap, _session);
  }
  MPLS_LIST_ADD_TAIL(&s->adj_root, a, _session, ldp_adj);
}

void _ldp_session_del_adj(ldp_session * s, ldp_adj * a)
{
  MPLS_ASSERT(s && a);
  MPLS_LIST_REMOVE(&s->adj_root, a, _session);
  MPLS_REFCNT_RELEASE(a, ldp_adj_delete);
}

uint32_t _ldp_session_get_next_index()
{
  uint32_t retval = _ldp_session_next_index;

  _ldp_session_next_index++;
  if (retval > _ldp_session_next_index) {
    _ldp_session_next_index = 1;
  }
  return retval;
}

mpls_return_enum ldp_session_find_raddr_index(ldp_session * s, uint32_t index,
  ldp_addr ** addr)
{
  struct mpls_link_list_node *lln;
  ldp_addr *a = NULL;

  if (s && index > 0) {
    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    if (mpls_link_list_isempty(&s->addr_root)) {
      *addr = NULL;
      return MPLS_END_OF_LIST;
    }

    if ((a = (ldp_addr*)mpls_link_list_tail_data(&s->addr_root))) {
      if (a->index < index) {
        *addr = NULL;
        return MPLS_END_OF_LIST;
      }
    }

    MPLS_LINK_LIST_LOOP(&s->addr_root, a, lln) {
      if (a->index == index) {
        *addr = a;
        return MPLS_SUCCESS;
      }
    }
  }
  *addr = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_session_backoff_stop(ldp_global * g, ldp_session * s)
{

  LDP_ENTER(g->user_data, "ldp_session_backoff_stop");

  s->backoff = 0;
  if (mpls_timer_handle_verify(g->timer_handle, s->backoff_timer) ==
    MPLS_BOOL_TRUE) {

    mpls_timer_stop(g->timer_handle, s->backoff_timer);
    mpls_timer_delete(g->timer_handle, s->backoff_timer);
    s->backoff_timer = (mpls_timer_handle) 0;
    MPLS_REFCNT_RELEASE(s, ldp_session_delete);
  }

  LDP_EXIT(g->user_data, "ldp_session_backoff_stop");

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_session_backoff_start(ldp_global * g, ldp_session * s)
{
  mpls_bool valid;

  MPLS_ASSERT(s);

  LDP_ENTER(g->user_data, "ldp_session_backoff_start");

  valid = mpls_timer_handle_verify(g->timer_handle,s->backoff_timer);

  MPLS_ASSERT(valid == MPLS_BOOL_FALSE);

  s->backoff += g->backoff_step;

#if 0 /* if the above assert shouldn't be made this code should be executed */
  {
    /* this should never happen, but if so */
    mpls_timer_stop(g->timer_handle, s->backoff_timer);
    mpls_timer_delete(g->timer_handle, s->backoff_timer);
    s->backoff_timer = (mpls_timer_handle) 0;
    MPLS_REFCNT_RELEASE(s, ldp_session_delete);
  }

  if (!s) {              /* if we deleted session due to the above RELEASE */
    LDP_EXIT(g->user_data, "ldp_session_backoff_start-error");
    return MPLS_FAILURE;
  }
#endif

  MPLS_REFCNT_HOLD(s);
  s->backoff_timer = mpls_timer_create(g->timer_handle, MPLS_UNIT_SEC,
    s->backoff, (void *)s, g, ldp_session_backoff_callback);
  if (mpls_timer_handle_verify(g->timer_handle, s->backoff_timer) ==
    MPLS_BOOL_FALSE) {

    MPLS_REFCNT_RELEASE(s, ldp_session_delete);
    LDP_EXIT(g->user_data, "ldp_session_backoff_start-error");
    return MPLS_FAILURE;
  }

  if (mpls_timer_start(g->timer_handle, s->backoff_timer,
    MPLS_TIMER_ONESHOT) != MPLS_SUCCESS) {

    mpls_timer_delete(g->timer_handle, s->backoff_timer);
    MPLS_REFCNT_RELEASE(s, ldp_session_delete);
    LDP_EXIT(g->user_data, "ldp_session_backoff_start-error");
    return MPLS_FAILURE;
  }

  LDP_EXIT(g->user_data, "ldp_session_backoff_start");

  return MPLS_SUCCESS;
}

ldp_session *ldp_session_for_nexthop(ldp_nexthop *nh)
{
  MPLS_ASSERT(nh);

  if (nh->info.type & MPLS_NH_IP) {
    MPLS_ASSERT(mpls_link_list_count(&nh->addr->session_root) < 2);
    ldp_session *s = mpls_link_list_head_data(&nh->addr->session_root);
    if (s) {
      return s;
    }
  }
  if (nh->info.type & MPLS_NH_IF) {
    ldp_session *s = NULL;
    if (nh->iff && (s = mpls_link_list_head_data(&nh->iff->session_root))) {
      return s;
    }
  }
  if (nh->info.type & MPLS_NH_OUTSEGMENT) {
    MPLS_ASSERT(0);
  }
  return NULL;
}
