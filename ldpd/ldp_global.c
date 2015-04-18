
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdlib.h>
#include <netinet/in.h>
#include "ldp_struct.h"
#include "ldp_inet_addr.h"
#include "ldp_session.h"
#include "ldp_entity.h"
#include "ldp_global.h"
#include "ldp_nexthop.h"
#include "ldp_outlabel.h"
#include "ldp_inlabel.h"
#include "ldp_hello.h"
#include "ldp_peer.h"
#include "ldp_attr.h"
#include "ldp_addr.h"
#include "ldp_adj.h"
#include "ldp_fec.h"
#include "ldp_if.h"
#include "ldp_label_mapping.h"
#include "ldp_tunnel.h"
#include "ldp_resource.h"
#include "ldp_hop_list.h"

#include "mpls_compare.h"

#include "mpls_socket_impl.h"
#include "mpls_timer_impl.h"
#include "mpls_ifmgr_impl.h"
#include "mpls_tree_impl.h"
#include "mpls_lock_impl.h"
#include "mpls_fib_impl.h"
#include "mpls_policy_impl.h"
#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"

#if MPLS_USE_LSR
#include "lsr_cfg.h"
#else
#include "mpls_mpls_impl.h"
#endif

void _ldp_global_ifmgr_callback(mpls_cfg_handle handle, const mpls_update_enum type, mpls_inet_addr *addr)
{
  ldp_session *s = NULL;
  ldp_global *cfg = (ldp_global*)handle;

  LDP_ENTER(cfg->user_data, "_ldp_global_ifmgr_callback");

  mpls_lock_get(cfg->global_lock);

  if (mpls_policy_address_export_check(cfg->user_data, addr) == MPLS_BOOL_TRUE) {
    s = MPLS_LIST_HEAD(&cfg->session);
    while (s != NULL) {
      switch (type) {
        case MPLS_UPDATE_ADD:
          LDP_TRACE_LOG(cfg->user_data, MPLS_TRACE_STATE_ALL,
            LDP_TRACE_FLAG_EVENT, "ADD\n");
          ldp_addr_send(cfg, s, addr);
          break;
        case MPLS_UPDATE_DEL:
          LDP_TRACE_LOG(cfg->user_data, MPLS_TRACE_STATE_ALL,
            LDP_TRACE_FLAG_EVENT, "DEL\n");
          ldp_waddr_send(cfg, s, addr);
          break;
        default:
          MPLS_ASSERT(0);
      }
      s = MPLS_LIST_NEXT(&cfg->session, s, _global);
    }
  }

  mpls_lock_release(cfg->global_lock);

  LDP_EXIT(cfg->user_data, "_ldp_global_ifmgr_callback");
}

ldp_global *ldp_global_create(mpls_instance_handle data)
{
  ldp_global *g = (ldp_global *) mpls_malloc(sizeof(ldp_global));

  if (g) {
    memset(g, 0, sizeof(ldp_global));

    LDP_ENTER(g->user_data, "ldp_global_create");

    g->global_lock = mpls_lock_create("_ldp_global_lock_");
    mpls_lock_get(g->global_lock);

    MPLS_LIST_INIT(&g->hop_list, ldp_hop_list);
    MPLS_LIST_INIT(&g->outlabel, ldp_outlabel);
    MPLS_LIST_INIT(&g->resource, ldp_resource);
    MPLS_LIST_INIT(&g->inlabel, ldp_inlabel);
    MPLS_LIST_INIT(&g->session, ldp_session);
    MPLS_LIST_INIT(&g->nexthop, ldp_nexthop);
    MPLS_LIST_INIT(&g->tunnel, ldp_tunnel);
    MPLS_LIST_INIT(&g->entity, ldp_entity);
    MPLS_LIST_INIT(&g->addr, ldp_addr);
    MPLS_LIST_INIT(&g->attr, ldp_attr);
    MPLS_LIST_INIT(&g->peer, ldp_peer);
    MPLS_LIST_INIT(&g->fec, ldp_fec);
    MPLS_LIST_INIT(&g->adj, ldp_adj);
    MPLS_LIST_INIT(&g->iff, ldp_if);

    g->message_identifier = 1;
    g->configuration_sequence_number = 1;
    g->lsp_control_mode = LDP_GLOBAL_DEF_CONTROL_MODE;
    g->label_retention_mode = LDP_GLOBAL_DEF_RETENTION_MODE;
    g->lsp_repair_mode = LDP_GLOBAL_DEF_REPAIR_MODE;
    g->propagate_release = LDP_GLOBAL_DEF_PROPOGATE_RELEASE;
    g->label_merge = LDP_GLOBAL_DEF_LABEL_MERGE;
    g->loop_detection_mode = LDP_GLOBAL_DEF_LOOP_DETECTION_MODE;
    g->ttl_less_domain = LDP_GLOBAL_DEF_TTLLESS_DOMAIN;
    g->local_tcp_port = LDP_GLOBAL_DEF_LOCAL_TCP_PORT;
    g->local_udp_port = LDP_GLOBAL_DEF_LOCAL_UDP_PORT;
    g->send_address_messages = LDP_GLOBAL_DEF_SEND_ADDR_MSG;
    g->backoff_step = LDP_GLOBAL_DEF_BACKOFF_STEP;
    g->send_lsrid_mapping = LDP_GLOBAL_DEF_SEND_LSRID_MAPPING;
    g->no_route_to_peer_time = LDP_GLOBAL_DEF_NO_ROUTE_RETRY_TIME;

    g->keepalive_timer = LDP_ENTITY_DEF_KEEPALIVE_TIMER;
    g->keepalive_interval = LDP_ENTITY_DEF_KEEPALIVE_INTERVAL;
    g->hellotime_timer = LDP_ENTITY_DEF_HELLOTIME_TIMER;
    g->hellotime_interval = LDP_ENTITY_DEF_HELLOTIME_INTERVAL;

    g->admin_state = MPLS_ADMIN_DISABLE;
    g->user_data = data;

    mpls_lock_release(g->global_lock);

    LDP_EXIT(g->user_data, "ldp_global_create");
  }

  return g;
}

mpls_return_enum ldp_global_startup(ldp_global * g)
{
  ldp_entity *e = NULL;
  mpls_dest dest;

  MPLS_ASSERT(g != NULL);

  LDP_ENTER(g->user_data, "ldp_global_startup");

  if (g->lsr_identifier.type == MPLS_FAMILY_NONE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
      "ldp_global_startup: invalid LSRID\n");
    goto ldp_global_startup_cleanup;
  }

  g->timer_handle = mpls_timer_open(g->user_data);
  if (mpls_timer_mgr_handle_verify(g->timer_handle) == MPLS_BOOL_FALSE) {
    goto ldp_global_startup_cleanup;
  }

  g->socket_handle = mpls_socket_mgr_open(g->user_data);
  if (mpls_socket_mgr_handle_verify(g->socket_handle) == MPLS_BOOL_FALSE) {
    goto ldp_global_startup_cleanup;
  }

  g->ifmgr_handle = mpls_ifmgr_open(g->user_data, g);
  if (mpls_ifmgr_handle_verify(g->ifmgr_handle) == MPLS_BOOL_FALSE) {
    goto ldp_global_startup_cleanup;
  }

  g->fib_handle = mpls_fib_open(g->user_data, g);
  if (mpls_fib_handle_verify(g->fib_handle) == MPLS_BOOL_FALSE) {
    goto ldp_global_startup_cleanup;
  }

#if MPLS_USE_LSR
  if (!g->lsr_handle) {
    goto ldp_global_startup_cleanup;
  }
#else
  g->mpls_handle = mpls_mpls_open(g->user_data);
  if (mpls_mpls_handle_verify(g->mpls_handle) == MPLS_BOOL_FALSE) {
    goto ldp_global_startup_cleanup;
  }
#endif

  g->addr_tree = mpls_tree_create(32);
  g->fec_tree = mpls_tree_create(32);

  g->hello_socket = mpls_socket_create_udp(g->socket_handle);
  if (mpls_socket_handle_verify(g->socket_handle, g->hello_socket) == MPLS_BOOL_FALSE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_global_startup: error creating UDP socket\n");
    goto ldp_global_startup_cleanup;
  }

  dest.addr.type = MPLS_FAMILY_IPV4;
  dest.port = g->local_udp_port;
  dest.addr.u.ipv4 = INADDR_ANY;
  // dest.addr.u.ipv4 = INADDR_ALLRTRS_GROUP;

  if (mpls_socket_bind(g->socket_handle, g->hello_socket, &dest) == MPLS_FAILURE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_global_startup: error binding UDP socket\n");
    goto ldp_global_startup_cleanup;
  }

  if (mpls_socket_options(g->socket_handle, g->hello_socket,
      MPLS_SOCKOP_NONBLOCK | MPLS_SOCKOP_REUSE) == MPLS_FAILURE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_global_startup: error setting UDP socket options\n");
    goto ldp_global_startup_cleanup;
  }
  if (mpls_socket_multicast_options(g->socket_handle, g->hello_socket, 1, 0) ==
    MPLS_FAILURE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_global_startup: error setting UDP socket multicast options\n");
    goto ldp_global_startup_cleanup;
  }
  mpls_socket_readlist_add(g->socket_handle, g->hello_socket, 0, MPLS_SOCKET_UDP_DATA);

  g->listen_socket = mpls_socket_create_tcp(g->socket_handle);
  if (mpls_socket_handle_verify(g->socket_handle, g->listen_socket) == MPLS_BOOL_FALSE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_global_startup: error creating TCP socket\n");
    goto ldp_global_startup_cleanup;
  }
  if (mpls_socket_options(g->socket_handle, g->listen_socket,
      MPLS_SOCKOP_NONBLOCK | MPLS_SOCKOP_REUSE) == MPLS_FAILURE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_global_startup: error setting TCP socket options\n");
    goto ldp_global_startup_cleanup;
  }

  dest.addr.type = MPLS_FAMILY_IPV4;
  dest.port = g->local_tcp_port;
  dest.addr.u.ipv4 = INADDR_ANY;

  if (mpls_socket_bind(g->socket_handle, g->listen_socket, &dest) == MPLS_FAILURE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_global_startup: error binding TCP socket\n");
    goto ldp_global_startup_cleanup;
  }

  if (mpls_socket_tcp_listen(g->socket_handle, g->listen_socket, 15) ==
    MPLS_FAILURE) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
      "ldp_global_startup: error setting listen buffer for TCP socket\n");
    goto ldp_global_startup_cleanup;
  }

  mpls_socket_readlist_add(g->socket_handle, g->listen_socket, 0,
    MPLS_SOCKET_TCP_LISTEN);

#if 0
  {
    mpls_if_handle iff;
    mpls_inet_addr addr;
    mpls_return_enum retval;

    retval = mpls_ifmgr_getfirst_address(g->ifmgr_handle, &iff, &addr);
    if (retval == MPLS_FATAL) {
      goto ldp_global_startup_cleanup;
    }
    if (retval == MPLS_SUCCESS) {
      do {
	ldp_addr *a;
	ldp_if *i;
	if (!(a = ldp_addr_create(g, &addr))) {
          goto ldp_global_startup_cleanup;
	}
	a->if_handle = iff;
	if ((i = ldp_global_find_if_handle(g, iff))) {
	  ldp_if_add_addr(i, a);
	}
      } while (mpls_ifmgr_getnext_address(g->ifmgr_handle, &iff, &addr) ==
        MPLS_SUCCESS);
    }
  }
  {
    mpls_fec fec;
    mpls_nexthop nexthop;
    mpls_return_enum retval;

    retval = mpls_fib_getfirst_route(g->fib_handle, &fec, &nexthop);
    if (retval == MPLS_FATAL) {
      goto ldp_global_startup_cleanup;
    }
    if (retval == MPLS_SUCCESS) {
      do {
	ldp_nexthop *n;
	ldp_fec *f;

	if (!(f = ldp_fec_find(g, &fec))) {
	    f = ldp_fec_create(g, &fec);
	    if (!f) {
              goto ldp_global_startup_cleanup;
	    }
	}

        n = ldp_nexthop_create();
	if (!n) {
          goto ldp_global_startup_cleanup;
	}

	memcpy(&n->info, &nexthop, sizeof(mpls_nexthop));
	if (ldp_fec_add_nexthop(g, f, n) != MPLS_SUCCESS) {
          goto ldp_global_startup_cleanup;
	}
	_ldp_global_add_nexthop(g, n);
      } while (mpls_fib_getnext_route(g->fib_handle, &fec, &nexthop) ==
        MPLS_SUCCESS);
    }
  }
#endif

  e = MPLS_LIST_HEAD(&g->entity);
  while (e != NULL) {
    ldp_entity_startup(g, e);
    e = MPLS_LIST_NEXT(&g->entity, e, _global);
  }

  g->admin_state = MPLS_ADMIN_ENABLE;

  LDP_EXIT(g->user_data, "ldp_global_startup");
  return MPLS_SUCCESS;

ldp_global_startup_cleanup:
  ldp_global_shutdown(g);
  mpls_socket_close(g->socket_handle, g->hello_socket);
  mpls_socket_close(g->socket_handle, g->listen_socket);
  g->hello_socket = 0;
  g->listen_socket = 0;

  LDP_EXIT(g->user_data, "ldp_global_startup-error");

  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_shutdown(ldp_global * g)
{
  ldp_entity *e = NULL;
  ldp_nexthop *n;
  ldp_fec *f;
  ldp_addr *a;
  ldp_if *i;

  MPLS_ASSERT(g);

  LDP_ENTER(g->user_data, "ldp_global_shutdown");

  e = MPLS_LIST_HEAD(&g->entity);
  while (e != NULL) {
    ldp_entity_shutdown(g, e, 1);
    e = MPLS_LIST_NEXT(&g->entity, e, _global);
  }

  g->admin_state = MPLS_ADMIN_DISABLE;

  while ((f = MPLS_LIST_HEAD(&g->fec))) {
    while ((n = MPLS_LIST_HEAD(&f->nh_root))) {
      ldp_fec_del_nexthop(g, f, n);
    }
    MPLS_REFCNT_RELEASE2(g, f, ldp_fec_delete);
  }

  while ((i = MPLS_LIST_HEAD(&g->iff))) {
    while ((a = MPLS_LIST_HEAD(&i->addr_root))) {
      ldp_if_del_addr(g, i, a);
    }
    MPLS_REFCNT_RELEASE2(g, i, ldp_if_delete);
  }

  mpls_socket_readlist_del(g->socket_handle, g->hello_socket);
  mpls_socket_close(g->socket_handle, g->hello_socket);

  mpls_socket_readlist_del(g->socket_handle, g->listen_socket);
  mpls_socket_close(g->socket_handle, g->listen_socket);

  mpls_tree_delete(g->addr_tree);
  mpls_tree_delete(g->fec_tree);

  mpls_lock_release(g->global_lock);
  mpls_timer_close(g->timer_handle);
  mpls_lock_get(g->global_lock);

  mpls_socket_mgr_close(g->socket_handle);
  mpls_ifmgr_close(g->ifmgr_handle);
  mpls_fib_close(g->fib_handle);

#if MPLS_USE_LSR
#else
  mpls_mpls_close(g->mpls_handle);
#endif

  LDP_EXIT(g->user_data, "ldp_global_shutdown");

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_global_delete(ldp_global * g)
{
  if (g) {
    mpls_lock_delete(g->global_lock);
    LDP_PRINT(g->user_data, "global delete\n");
    mpls_free(g);
  }
  return MPLS_SUCCESS;
}

void _ldp_global_add_attr(ldp_global * g, ldp_attr * a)
{
  ldp_attr *ap = NULL;

  MPLS_ASSERT(g && a);
  MPLS_REFCNT_HOLD(a);
  ap = MPLS_LIST_HEAD(&g->attr);
  while (ap != NULL) {
    if (ap->index > a->index) {
      MPLS_LIST_INSERT_BEFORE(&g->attr, ap, a, _global);
      return;
    }
    ap = MPLS_LIST_NEXT(&g->attr, ap, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->attr, a, _global, ldp_attr);
}

void _ldp_global_del_attr(ldp_global * g, ldp_attr * a)
{
  MPLS_ASSERT(g && a);
  MPLS_LIST_REMOVE(&g->attr, a, _global);
  MPLS_REFCNT_RELEASE(a, ldp_attr_delete);
}

void _ldp_global_add_peer(ldp_global * g, ldp_peer * p)
{
  ldp_peer *pp = NULL;

  MPLS_ASSERT(g && p);
  MPLS_REFCNT_HOLD(p);
  pp = MPLS_LIST_HEAD(&g->peer);
  while (pp != NULL) {
    if (pp->index > p->index) {
      MPLS_LIST_INSERT_BEFORE(&g->peer, pp, p, _global);
      return;
    }
    pp = MPLS_LIST_NEXT(&g->peer, pp, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->peer, p, _global, ldp_peer);
}

void _ldp_global_del_peer(ldp_global * g, ldp_peer * p)
{
  MPLS_ASSERT(g && p);
  MPLS_LIST_REMOVE(&g->peer, p, _global);
  MPLS_REFCNT_RELEASE(p, ldp_peer_delete);
}

/*
 * _ldp_global_add_if/del_if and _ldp_global_add_addr/del_addr are
 * not the same as the rest of the global_add/del functions.  They
 * do not hold refcnts, they are used as part of the create and delete
 * process of these structures
 */

void _ldp_global_add_if(ldp_global * g, ldp_if * i)
{
  ldp_if *ip = NULL;

  MPLS_ASSERT(g && i);
  ip = MPLS_LIST_HEAD(&g->iff);
  while (ip != NULL) {
    if (ip->index > i->index) {
      MPLS_LIST_INSERT_BEFORE(&g->iff, ip, i, _global);
      return;
    }
    ip = MPLS_LIST_NEXT(&g->iff, ip, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->iff, i, _global, ldp_if);
}

void _ldp_global_del_if(ldp_global * g, ldp_if * i)
{
  MPLS_ASSERT(g && i);
  MPLS_LIST_REMOVE(&g->iff, i, _global);
}

void _ldp_global_add_addr(ldp_global * g, ldp_addr * a)
{
  ldp_addr *ap = NULL;

  MPLS_ASSERT(g && a);
  ap = MPLS_LIST_HEAD(&g->addr);
  while (ap != NULL) {
    if (ap->index > a->index) {
      MPLS_LIST_INSERT_BEFORE(&g->addr, ap, a, _global);
      return;
    }
    ap = MPLS_LIST_NEXT(&g->addr, ap, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->addr, a, _global, ldp_addr);
}

void _ldp_global_del_addr(ldp_global * g, ldp_addr * a)
{
  MPLS_ASSERT(g && a);
  MPLS_LIST_REMOVE(&g->addr, a, _global);
}



void _ldp_global_add_adj(ldp_global * g, ldp_adj * a)
{
  ldp_adj *ap = NULL;

  MPLS_ASSERT(g && a);
  MPLS_REFCNT_HOLD(a);
  ap = MPLS_LIST_HEAD(&g->adj);
  while (ap != NULL) {
    if (ap->index > a->index) {
      MPLS_LIST_INSERT_BEFORE(&g->adj, ap, a, _global);
      return;
    }
    ap = MPLS_LIST_NEXT(&g->adj, ap, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->adj, a, _global, ldp_adj);
}

void _ldp_global_del_adj(ldp_global * g, ldp_adj * a)
{
  MPLS_ASSERT(g && a);
  MPLS_LIST_REMOVE(&g->adj, a, _global);
  MPLS_REFCNT_RELEASE(a, ldp_adj_delete);
}

void _ldp_global_add_entity(ldp_global * g, ldp_entity * e)
{
  ldp_entity *ep = NULL;

  MPLS_ASSERT(g && e);
  MPLS_REFCNT_HOLD(e);
  ep = MPLS_LIST_HEAD(&g->entity);
  while (ep != NULL) {
    if (ep->index > e->index) {
      MPLS_LIST_INSERT_BEFORE(&g->entity, ep, e, _global);
      return;
    }
    ep = MPLS_LIST_NEXT(&g->entity, ep, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->entity, e, _global, ldp_entity);
}

void _ldp_global_del_entity(ldp_global * g, ldp_entity * e)
{
  MPLS_ASSERT(g && e);
  MPLS_LIST_REMOVE(&g->entity, e, _global);
  MPLS_REFCNT_RELEASE(e, ldp_entity_delete);
}

void _ldp_global_add_session(ldp_global * g, ldp_session * s)
{
  ldp_session *sp = NULL;

  MPLS_ASSERT(g && s);
  MPLS_REFCNT_HOLD(s);
  s->on_global = MPLS_BOOL_TRUE;
  sp = MPLS_LIST_HEAD(&g->session);
  while (sp != NULL) {
    if (sp->index > s->index) {
      MPLS_LIST_INSERT_BEFORE(&g->session, sp, s, _global);
      return;
    }
    sp = MPLS_LIST_NEXT(&g->session, sp, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->session, s, _global, ldp_session);
}

void _ldp_global_del_session(ldp_global * g, ldp_session * s)
{
  MPLS_ASSERT(g && s);
  MPLS_ASSERT(s->on_global == MPLS_BOOL_TRUE);
  MPLS_LIST_REMOVE(&g->session, s, _global);
  s->on_global = MPLS_BOOL_FALSE;
  MPLS_REFCNT_RELEASE(s, ldp_session_delete);
}

mpls_return_enum _ldp_global_add_inlabel(ldp_global * g, ldp_inlabel * i)
{
  ldp_inlabel *ip = NULL;
  mpls_return_enum result;

  MPLS_ASSERT(g && i);

#if MPLS_USE_LSR
  {
    lsr_insegment iseg;
    memcpy(&iseg.info,&i->info,sizeof(mpls_insegment));
    result = lsr_cfg_insegment_set(g->lsr_handle, &iseg, LSR_CFG_ADD|
      LSR_INSEGMENT_CFG_NPOP|LSR_INSEGMENT_CFG_FAMILY|
      LSR_INSEGMENT_CFG_LABELSPACE|LSR_INSEGMENT_CFG_LABEL|
      LSR_INSEGMENT_CFG_OWNER);
    memcpy(&i->info, &iseg.info, sizeof(mpls_insegment));
    i->info.handle = iseg.index;
  }
#else
  result = mpls_mpls_insegment_add(g->mpls_handle, &i->info);
#endif
  if (result != MPLS_SUCCESS) {
    return result;
  }

  MPLS_REFCNT_HOLD(i);
  ip = MPLS_LIST_HEAD(&g->inlabel);
  while (ip != NULL) {
    if (ip->index > i->index) {
      MPLS_LIST_INSERT_BEFORE(&g->inlabel, ip, i, _global);
      return MPLS_SUCCESS;
    }
    ip = MPLS_LIST_NEXT(&g->inlabel, ip, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->inlabel, i, _global, ldp_inlabel);
  return MPLS_SUCCESS;
}

mpls_return_enum _ldp_global_del_inlabel(ldp_global * g, ldp_inlabel * i)
{
  MPLS_ASSERT(g && i);
  MPLS_ASSERT(i->reuse_count == 0);
#if MPLS_USE_LSR
  {
    lsr_insegment iseg;
    iseg.index = i->info.handle;
    lsr_cfg_insegment_set(g->lsr_handle, &iseg, LSR_CFG_DEL);
  }
#else
  mpls_mpls_insegment_del(g->mpls_handle, &i->info);
#endif
  MPLS_LIST_REMOVE(&g->inlabel, i, _global);
  MPLS_REFCNT_RELEASE(i, ldp_inlabel_delete);
  return MPLS_SUCCESS;
}

mpls_return_enum _ldp_global_add_outlabel(ldp_global * g, ldp_outlabel * o)
{
  ldp_outlabel *op = NULL;
  mpls_return_enum result;

  MPLS_ASSERT(g && o);
#if MPLS_USE_LSR
  {
    lsr_outsegment oseg;
    memcpy(&oseg.info, &o->info, sizeof(mpls_outsegment));
    result = lsr_cfg_outsegment_set(g->lsr_handle, &oseg, LSR_CFG_ADD|
      LSR_OUTSEGMENT_CFG_PUSH_LABEL|LSR_OUTSEGMENT_CFG_OWNER|
      LSR_OUTSEGMENT_CFG_INTERFACE|LSR_OUTSEGMENT_CFG_LABEL|
      LSR_OUTSEGMENT_CFG_NEXTHOP);
    o->info.handle = oseg.index;
  }
#else
  result = mpls_mpls_outsegment_add(g->mpls_handle, &o->info);
#endif

  if (result != MPLS_SUCCESS) {
    return result;
  }

  MPLS_REFCNT_HOLD(o);
  o->switching = MPLS_BOOL_TRUE;
  op = MPLS_LIST_HEAD(&g->outlabel);
  while (op != NULL) {
    if (op->index > o->index) {
      MPLS_LIST_INSERT_BEFORE(&g->outlabel, op, o, _global);
      return MPLS_SUCCESS;
    }
    op = MPLS_LIST_NEXT(&g->outlabel, op, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->outlabel, o, _global, ldp_outlabel);
  return MPLS_SUCCESS;
}

mpls_return_enum _ldp_global_del_outlabel(ldp_global * g, ldp_outlabel * o)
{
  MPLS_ASSERT(g && o);
#if MPLS_USE_LSR
  {
    lsr_outsegment oseg;
    oseg.index = o->info.handle;
    lsr_cfg_outsegment_set(g->lsr_handle, &oseg, LSR_CFG_DEL);
  }
#else
  mpls_mpls_outsegment_del(g->mpls_handle, &o->info);
#endif

  o->switching = MPLS_BOOL_FALSE;
  MPLS_ASSERT(o->merge_count == 0);
  MPLS_LIST_REMOVE(&g->outlabel, o, _global);
  MPLS_REFCNT_RELEASE(o, ldp_outlabel_delete);
  return MPLS_SUCCESS;
}

mpls_return_enum ldp_global_find_attr_index(ldp_global * g, uint32_t index,
  ldp_attr ** attr)
{
  ldp_attr *a = NULL;

  if (g && index > 0) {

    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    a = MPLS_LIST_TAIL(&g->attr);
    if (a == NULL || a->index < index) {
      return MPLS_END_OF_LIST;
      *attr = NULL;
    }

    a = MPLS_LIST_HEAD(&g->attr);
    while (a != NULL) {
      if (a->index == index) {
        *attr = a;
        return MPLS_SUCCESS;
      }
      a = MPLS_LIST_NEXT(&g->attr, a, _global);
    }
  }
  *attr = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_session_index(ldp_global * g, uint32_t index,
  ldp_session ** session)
{
  ldp_session *s = NULL;

  if (g && index > 0) {

    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    s = MPLS_LIST_TAIL(&g->session);
    if (s == NULL || s->index < index) {
      *session = NULL;
      return MPLS_END_OF_LIST;
    }

    s = MPLS_LIST_HEAD(&g->session);
    while (s != NULL) {
      if (s->index == index) {
        *session = s;
        return MPLS_SUCCESS;
      }
      s = MPLS_LIST_NEXT(&g->session, s, _global);
    }
  }
  *session = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_inlabel_index(ldp_global * g, uint32_t index,
  ldp_inlabel ** inlabel)
{
  ldp_inlabel *i = NULL;

  if (g && index > 0) {

    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    i = MPLS_LIST_TAIL(&g->inlabel);
    if (i == NULL || i->index < index) {
      *inlabel = NULL;
      return MPLS_END_OF_LIST;
    }

    i = MPLS_LIST_HEAD(&g->inlabel);
    while (i != NULL) {
      if (i->index == index) {
        *inlabel = i;
        return MPLS_SUCCESS;
      }
      i = MPLS_LIST_NEXT(&g->inlabel, i, _global);
    }
  }
  *inlabel = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_outlabel_index(ldp_global * g, uint32_t index,
  ldp_outlabel ** outlabel)
{
  ldp_outlabel *o = NULL;

  if (g && index > 0) {

    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    o = MPLS_LIST_TAIL(&g->outlabel);
    if (o == NULL || o->index < index) {
      *outlabel = NULL;
      return MPLS_END_OF_LIST;
    }

    o = MPLS_LIST_HEAD(&g->outlabel);
    while (o != NULL) {
      if (o->index == index) {
        *outlabel = o;
        return MPLS_SUCCESS;
      }
      o = MPLS_LIST_NEXT(&g->outlabel, o, _global);
    }
  }
  *outlabel = NULL;
  return MPLS_FAILURE;
}

ldp_outlabel *ldp_global_find_outlabel_handle(ldp_global * g,
  mpls_outsegment_handle handle)
{
  ldp_outlabel *o = MPLS_LIST_HEAD(&g->outlabel);

  if (g) {
    while (o != NULL) {
      if (!mpls_outsegment_handle_compare(o->info.handle, handle))
        return o;

      o = MPLS_LIST_NEXT(&g->outlabel, o, _global);
    }
  }
  return NULL;
}

mpls_return_enum ldp_global_find_entity_index(ldp_global * g, uint32_t index,
  ldp_entity ** entity)
{
  ldp_entity *e = NULL;

  if (g && index > 0) {

    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    e = MPLS_LIST_TAIL(&g->entity);
    if (e == NULL || e->index < index) {
      *entity = NULL;
      return MPLS_END_OF_LIST;
    }

    e = MPLS_LIST_HEAD(&g->entity);
    while (e != NULL) {
      if (e->index == index) {
        *entity = e;
        return MPLS_SUCCESS;
      }
      e = MPLS_LIST_NEXT(&g->entity, e, _global);
    }
  }
  *entity = NULL;
  return MPLS_FAILURE;
}

ldp_peer *ldp_global_find_peer_addr(ldp_global * g, mpls_inet_addr * addr)
{
  ldp_peer *p;

  MPLS_ASSERT(g && addr);

  /* JLEU: we will need to add a tree to optimize this search,
     known peers will be in tree, unknown will take a "slow path" to
     verify them, then be added to tree */

  p = MPLS_LIST_HEAD(&g->peer);
  while (p) {
    LDP_PRINT(g->user_data,
      "ldp_global_find_peer_lsrid: peer: %08x lsrid: %08x\n",
      p->dest.addr.u.ipv4, addr->u.ipv4);
    if (!mpls_inet_addr_compare(&p->dest.addr, addr)) {
      return p;
    }
    p = MPLS_LIST_NEXT(&g->peer, p, _global);
  }
  return NULL;
}

mpls_return_enum ldp_global_find_adj_index(ldp_global * g, uint32_t index,
  ldp_adj ** adj)
{
  ldp_adj *a = NULL;

  if (g && index > 0) {
    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    a = MPLS_LIST_TAIL(&g->adj);
    if (a == NULL || a->index < index) {
      return MPLS_END_OF_LIST;
      *adj = NULL;
    }

    a = MPLS_LIST_HEAD(&g->adj);
    while (a != NULL) {
      if (a->index == index) {
        *adj = a;
        return MPLS_SUCCESS;
      }
      a = MPLS_LIST_NEXT(&g->adj, a, _global);
    }
  }
  *adj = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_peer_index(ldp_global * g, uint32_t index,
  ldp_peer ** peer)
{
  ldp_peer *p = NULL;

  if (g && index > 0) {
    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    p = MPLS_LIST_TAIL(&g->peer);
    if (p == NULL || p->index < index) {
      *peer = NULL;
      return MPLS_END_OF_LIST;
    }

    p = MPLS_LIST_HEAD(&g->peer);
    while (p != NULL) {
      if (p->index == index) {
        *peer = p;
        return MPLS_SUCCESS;
      }
      p = MPLS_LIST_NEXT(&g->peer, p, _global);
    }
  }
  *peer = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_fec_index(ldp_global * g, uint32_t index,
  ldp_fec ** fec)
{
  ldp_fec *f = NULL;

  if (g && index > 0) {
    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    f = MPLS_LIST_TAIL(&g->fec);
    if (f == NULL || f->index < index) {
      *fec = NULL;
      return MPLS_END_OF_LIST;
    }

    f = MPLS_LIST_HEAD(&g->fec);
    while (f != NULL) {
      if (f->index == index) {
        *fec = f;
        return MPLS_SUCCESS;
      }
      f = MPLS_LIST_NEXT(&g->fec, f, _global);
    }
  }
  *fec = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_fec(ldp_global * g, mpls_fec * m,
  ldp_fec ** fec)
{
  ldp_fec *f = NULL;

  MPLS_ASSERT(g && m);

  f = MPLS_LIST_HEAD(&g->fec);
  do {
    if (!mpls_fec_compare(m, &f->info)) {
      *fec = f;
      return MPLS_SUCCESS;
    }
  } while((f = MPLS_LIST_NEXT(&g->fec, f, _global)));
  *fec = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_addr_index(ldp_global * g, uint32_t index,
  ldp_addr ** addr)
{
  ldp_addr *a = NULL;

  if (g && index > 0) {

    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    a = MPLS_LIST_TAIL(&g->addr);
    if (a == NULL || a->index < index) {
      *addr = NULL;
      return MPLS_END_OF_LIST;
    }

    a = MPLS_LIST_HEAD(&g->addr);
    while (a != NULL) {
      if (a->index == index) {
        *addr = a;
        return MPLS_SUCCESS;
      }
      a = MPLS_LIST_NEXT(&g->addr, a, _global);
    }
  }
  *addr = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_if_index(ldp_global * g, uint32_t index,
  ldp_if ** iff)
{
  ldp_if *i = NULL;

  if (g && index > 0) {

    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    i = MPLS_LIST_TAIL(&g->iff);
    if (i == NULL || i->index < index) {
      *iff = NULL;
      return MPLS_END_OF_LIST;
    }

    i = MPLS_LIST_HEAD(&g->iff);
    while (i != NULL) {
      if (i->index == index) {
        *iff = i;
        return MPLS_SUCCESS;
      }
      i = MPLS_LIST_NEXT(&g->iff, i, _global);
    }
  }
  *iff = NULL;
  return MPLS_FAILURE;
}

ldp_if *ldp_global_find_if_handle(ldp_global * g, mpls_if_handle handle)
{
  ldp_if *i = MPLS_LIST_HEAD(&g->iff);

  if (g) {
    while (i != NULL) {
      if (!mpls_if_handle_compare(i->handle, handle))
        return i;

      i = MPLS_LIST_NEXT(&g->iff, i, _global);
    }
  }
  return NULL;
}

ldp_adj *ldp_global_find_adj_ldpid(ldp_global * g, mpls_inet_addr * lsraddr,
  int labelspace)
{

  ldp_adj *a = MPLS_LIST_HEAD(&g->adj);

  while (a != NULL) {
    if ((!mpls_inet_addr_compare(lsraddr, &a->remote_lsr_address)) &&
      labelspace == a->remote_label_space)
      return a;

    a = MPLS_LIST_NEXT(&g->adj, a, _global);
  }
  return NULL;
}

mpls_return_enum ldp_global_find_tunnel_index(ldp_global * g, uint32_t index,
  ldp_tunnel ** tunnel)
{
  ldp_tunnel *t = NULL;

  if (g && index > 0) {
    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    t = MPLS_LIST_TAIL(&g->tunnel);
    if (t == NULL || t->index < index) {
      *tunnel = NULL;
      return MPLS_END_OF_LIST;
    }

    t = MPLS_LIST_HEAD(&g->tunnel);
    while (t != NULL) {
      if (t->index == index) {
        *tunnel = t;
        return MPLS_SUCCESS;
      }
      t = MPLS_LIST_NEXT(&g->tunnel, t, _global);
    }
  }
  *tunnel = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_resource_index(ldp_global * g, uint32_t index,
  ldp_resource ** resource)
{
  ldp_resource *r = NULL;

  if (g && index > 0) {
    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    r = MPLS_LIST_TAIL(&g->resource);
    if (r == NULL || r->index < index) {
      *resource = NULL;
      return MPLS_END_OF_LIST;
    }

    r = MPLS_LIST_HEAD(&g->resource);
    while (r != NULL) {
      if (r->index == index) {
        *resource = r;
        return MPLS_SUCCESS;
      }
      r = MPLS_LIST_NEXT(&g->resource, r, _global);
    }
  }
  *resource = NULL;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_global_find_hop_list_index(ldp_global * g, uint32_t index,
  ldp_hop_list ** hop_list)
{
  ldp_hop_list *h = NULL;

  if (g && index > 0) {
    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    h = MPLS_LIST_TAIL(&g->hop_list);
    if (h == NULL || h->index < index) {
      *hop_list = NULL;
      return MPLS_END_OF_LIST;
    }

    h = MPLS_LIST_HEAD(&g->hop_list);
    while (h != NULL) {
      if (h->index == index) {
        *hop_list = h;
        return MPLS_SUCCESS;
      }
      h = MPLS_LIST_NEXT(&g->hop_list, h, _global);
    }
  }
  *hop_list = NULL;
  return MPLS_FAILURE;
}

void _ldp_global_add_tunnel(ldp_global * g, ldp_tunnel * t)
{
  ldp_tunnel *tp = NULL;

  MPLS_ASSERT(g && t);
  MPLS_REFCNT_HOLD(t);
  tp = MPLS_LIST_HEAD(&g->tunnel);
  while (tp != NULL) {
    if (tp->index > t->index) {
      MPLS_LIST_INSERT_BEFORE(&g->tunnel, tp, t, _global);
      return;
    }
    tp = MPLS_LIST_NEXT(&g->tunnel, tp, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->tunnel, t, _global, ldp_tunnel);
}

void _ldp_global_del_tunnel(ldp_global * g, ldp_tunnel * t)
{
  MPLS_ASSERT(g && t);
  MPLS_LIST_REMOVE(&g->tunnel, t, _global);
  MPLS_REFCNT_RELEASE(t, ldp_tunnel_delete);
}

void _ldp_global_add_resource(ldp_global * g, ldp_resource * r)
{
  ldp_resource *rp = NULL;

  MPLS_ASSERT(g && r);
  MPLS_REFCNT_HOLD(r);
  rp = MPLS_LIST_HEAD(&g->resource);
  while (rp != NULL) {
    if (rp->index > r->index) {
      MPLS_LIST_INSERT_BEFORE(&g->resource, rp, r, _global);
      return;
    }
    rp = MPLS_LIST_NEXT(&g->resource, rp, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->resource, r, _global, ldp_resource);
}

void _ldp_global_del_resource(ldp_global * g, ldp_resource * r)
{
  MPLS_ASSERT(g && r);
  MPLS_LIST_REMOVE(&g->resource, r, _global);
  MPLS_REFCNT_RELEASE(r, ldp_resource_delete);
}

void _ldp_global_add_hop_list(ldp_global * g, ldp_hop_list * h)
{
  ldp_hop_list *hp = NULL;

  MPLS_ASSERT(g && h);
  MPLS_REFCNT_HOLD(h);
  hp = MPLS_LIST_HEAD(&g->hop_list);
  while (hp != NULL) {
    if (hp->index > h->index) {
      MPLS_LIST_INSERT_BEFORE(&g->hop_list, hp, h, _global);
      return;
    }
    hp = MPLS_LIST_NEXT(&g->hop_list, hp, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->hop_list, h, _global, ldp_hop_list);
}

void _ldp_global_del_hop_list(ldp_global * g, ldp_hop_list * h)
{
  MPLS_ASSERT(g && h);
  MPLS_LIST_REMOVE(&g->hop_list, h, _global);
  MPLS_REFCNT_RELEASE(h, ldp_hop_list_delete);
}

void _ldp_global_add_fec(ldp_global * g, ldp_fec * f)
{
  ldp_fec *fp = NULL;

  MPLS_ASSERT(g && f);
  /*
   * TESTING: jleu 6/7/2004, since I want the FEC to be cleaned up
   * when it no longer has a nexthop, addr, or label, the only things that
   * should increment the ref are those (nh, addr, label etc), not global
   * nor inserting into the tree.  I also added this comment in
   * ldp_fec_create()
  MPLS_REFCNT_HOLD(f);
   */
  fp = MPLS_LIST_HEAD(&g->fec);
  while (fp != NULL) {
    if (fp->index > f->index) {
      MPLS_LIST_INSERT_BEFORE(&g->fec, fp, f, _global);
      return;
    }
    fp = MPLS_LIST_NEXT(&g->fec, fp, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->fec, f, _global, ldp_fec);
}

void _ldp_global_del_fec(ldp_global * g, ldp_fec * f)
{
  MPLS_ASSERT(g && f);
  MPLS_LIST_REMOVE(&g->fec, f, _global);
}

void _ldp_global_add_nexthop(ldp_global * g, ldp_nexthop * nh)
{
  ldp_nexthop *nhp = NULL;

  MPLS_ASSERT(g && nh);
  nhp = MPLS_LIST_HEAD(&g->nexthop);
  while (nhp != NULL) {
    if (nhp->index > nh->index) {
      MPLS_LIST_INSERT_BEFORE(&g->nexthop, nhp, nh, _global);
      return;
    }
    nhp = MPLS_LIST_NEXT(&g->nexthop, nhp, _global);
  }
  MPLS_LIST_ADD_TAIL(&g->nexthop, nh, _global, ldp_nexthop);
}

void _ldp_global_del_nexthop(ldp_global * g, ldp_nexthop * nh)
{
  MPLS_ASSERT(g && nh);
  MPLS_LIST_REMOVE(&g->nexthop, nh, _global);
}
