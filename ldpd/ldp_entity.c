
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include "ldp_struct.h"
#include "mpls_assert.h"
#include "ldp_session.h"
#include "ldp_global.h"
#include "ldp_entity.h"
#include "ldp_hello.h"
#include "ldp_peer.h"
#include "ldp_adj.h"
#include "ldp_if.h"
#include "ldp_inet_addr.h"
#include "ldp_mesg.h"
#include "ldp_cfg.h"

#include "mpls_mm_impl.h"
#include "mpls_timer_impl.h"
#include "mpls_socket_impl.h"
#include "mpls_trace_impl.h"

static uint32_t _ldp_entity_next_index = 1;

void ldp_entity_set_defaults(ldp_entity *e) {
    memset(e, 0, sizeof(ldp_entity));

    e->entity_type = LDP_UNKNOWN;

    if (LDP_ENTITY_DEF_TRANS_ADDR != 0) {
      e->transport_address.type = MPLS_FAMILY_IPV4;
      e->transport_address.u.ipv4 = LDP_ENTITY_DEF_TRANS_ADDR;
    }
    e->protocol_version = LDP_ENTITY_DEF_PROTO_VER;
    e->remote_tcp_port = LDP_ENTITY_DEF_REMOTE_TCP;
    e->remote_udp_port = LDP_ENTITY_DEF_REMOTE_UDP;
    e->max_pdu = LDP_ENTITY_DEF_MAX_PDU;
    e->keepalive_timer = LDP_ENTITY_DEF_KEEPALIVE_TIMER;
    e->keepalive_interval = LDP_ENTITY_DEF_KEEPALIVE_INTERVAL;
    e->hellotime_timer = LDP_ENTITY_DEF_HELLOTIME_TIMER;
    e->hellotime_interval = LDP_ENTITY_DEF_HELLOTIME_INTERVAL;
    e->session_setup_count = LDP_ENTITY_DEF_SESSIONSETUP_COUNT;
    e->session_backoff_timer = LDP_ENTITY_DEF_SESSION_BACKOFF_TIMER;
    e->label_distribution_mode = LDP_ENTITY_DEF_DISTRIBUTION_MODE;
    e->path_vector_limit = LDP_ENTITY_DEF_PATHVECTOR_LIMIT;
    e->hop_count_limit = LDP_ENTITY_DEF_HOPCOUNT_LIMIT;
    e->label_request_timer = LDP_ENTITY_DEF_REQUEST_TIMER;
    e->label_request_count = LDP_ENTITY_DEF_REQUEST_COUNT;
    e->inherit_flag = LDP_ENTITY_DEF_INHERIT_FLAG;
    e->admin_state = MPLS_ADMIN_DISABLE;
    e->remote_in_ttl_less_domain = MPLS_BOOL_FALSE;
    e->request_retry = LDP_ENTITY_DEF_REQUEST_RETRY;
}

ldp_entity *ldp_entity_create()
{
  ldp_entity *e = (ldp_entity *) mpls_malloc(sizeof(ldp_entity));

  if (e) {
    memset(e, 0, sizeof(ldp_entity));
    ldp_entity_set_defaults(e);

    MPLS_REFCNT_INIT(e, 0);
    MPLS_LIST_ELEM_INIT(e, _global);
    MPLS_LIST_INIT(&e->adj_root, ldp_adj);

    e->index = _ldp_entity_get_next_index();
  }
  return e;
}

void ldp_entity_delete(ldp_entity * e)
{
  fprintf(stderr,"entity delete\n");
  MPLS_REFCNT_ASSERT(e, 0);
  mpls_free(e);
}

int ldp_entity_label_space(ldp_entity * e)
{
  if (e) {
    switch (e->entity_type) {
      case LDP_DIRECT:
        return e->p.iff->label_space;
      case LDP_INDIRECT:
        return e->p.peer->label_space;
      default:
        MPLS_ASSERT(0);
    }
  }
  return -1;
}

mpls_bool ldp_entity_is_active(ldp_entity * e)
{
  if (e && e->admin_state == MPLS_ADMIN_ENABLE)
    return MPLS_BOOL_TRUE;

  return MPLS_BOOL_FALSE;
}

mpls_bool ldp_entity_is_ready(ldp_entity * e)
{
  if (e) {
    switch (e->entity_type) {
      case LDP_DIRECT:
        if (e->p.iff)
          return MPLS_BOOL_TRUE;
        break;
      case LDP_INDIRECT:
        if (e->p.peer)
          return MPLS_BOOL_TRUE;
        break;
      default:
        MPLS_ASSERT(0);
    }
  }
  return MPLS_BOOL_FALSE;
}

mpls_return_enum ldp_entity_startup(ldp_global * g, ldp_entity * e)
{
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(g && e && e->p.iff);

  LDP_ENTER(g->user_data, "ldp_entity_startup");

  if (e->inherit_flag & LDP_ENTITY_CFG_TRANS_ADDR) {
    memcpy(&e->transport_address,&g->transport_address,sizeof(mpls_inet_addr));
  }
  if (e->inherit_flag & LDP_ENTITY_CFG_KEEPALIVE_TIMER) {
    e->keepalive_timer = g->keepalive_timer;
  }
  if (e->inherit_flag & LDP_ENTITY_CFG_KEEPALIVE_INTERVAL) {
    e->keepalive_interval = g->keepalive_interval;
  }
  if (e->inherit_flag & LDP_ENTITY_CFG_HELLOTIME_TIMER) {
    e->hellotime_timer = g->hellotime_timer;
  }
  if (e->inherit_flag & LDP_ENTITY_CFG_HELLOTIME_INTERVAL) {
    e->hellotime_interval = g->hellotime_interval;
  }

  e->loop_detection_mode = g->loop_detection_mode;

  switch (e->entity_type) {
    case LDP_DIRECT:
      retval = ldp_if_startup(g, e->p.iff);
      break;
    case LDP_INDIRECT:
      retval = ldp_peer_startup(g, e->p.peer);
      break;
    default:
      MPLS_ASSERT(0);
  }

  if (retval == MPLS_SUCCESS) {
    e->admin_state = MPLS_ADMIN_ENABLE;
  }

  LDP_EXIT(g->user_data, "ldp_entity_startup");

  return retval;
}

mpls_return_enum ldp_entity_shutdown(ldp_global * g, ldp_entity * e, int flag)
{
  ldp_adj *adj = NULL;

  MPLS_ASSERT(g && e);

  LDP_ENTER(g->user_data, "ldp_entity_shutdown");

  /* flag is only set if the global entity is being disabled */
  if (!flag) {
    e->admin_state = MPLS_ADMIN_DISABLE;
  }

  switch (e->entity_type) {
    case LDP_DIRECT:
      if (ldp_if_shutdown(g, e->p.iff) != MPLS_SUCCESS) {
        LDP_PRINT(g->user_data, "ldp_entity_shutdown: shut down of if failed\n");
      }
      break;
    case LDP_INDIRECT:
      if (ldp_peer_shutdown(g, e->p.peer) != MPLS_SUCCESS) {
        LDP_PRINT(g->user_data, "ldp_entity_shutdown: shut down of peer failed\n");
      }
      break;
    default:
      MPLS_ASSERT(0);
  }

  while ((adj = MPLS_LIST_HEAD(&e->adj_root))) {
    /* ldp_adj_shutdown() does a ldp_entity_del_adj(e,adj) */
    ldp_adj_shutdown(g, adj);
  }

  LDP_EXIT(g->user_data, "ldp_entity_shutdown");

  return MPLS_SUCCESS;
}

uint32_t _ldp_entity_get_next_index()
{
  uint32_t retval = _ldp_entity_next_index;

  _ldp_entity_next_index++;
  if (retval > _ldp_entity_next_index) {
    _ldp_entity_next_index = 1;
  }
  return retval;
}

void ldp_entity_add_if(ldp_entity * e, ldp_if * i)
{
  MPLS_ASSERT(e && i && e->entity_type == LDP_UNKNOWN);

  e->entity_type = LDP_DIRECT;
  MPLS_REFCNT_HOLD(i);
  e->p.iff = i;
  e->sub_index = i->index;
  _ldp_if_add_entity(i, e);
}

void ldp_entity_del_if(ldp_global * g, ldp_entity * e)
{
  MPLS_ASSERT(e && e->entity_type == LDP_DIRECT && e->p.iff);
  _ldp_if_del_entity(e->p.iff);
  MPLS_REFCNT_RELEASE2(g, e->p.iff, ldp_if_delete);
  e->p.iff = NULL;
  e->entity_type = LDP_UNKNOWN;
  e->sub_index = 0;
}

void ldp_entity_add_peer(ldp_entity * e, ldp_peer * p)
{
  MPLS_ASSERT(e && e->entity_type == LDP_UNKNOWN);

  e->entity_type = LDP_INDIRECT;
  MPLS_REFCNT_HOLD(p);
  e->p.peer = p;
  e->sub_index = p->index;
  _ldp_peer_add_entity(p, e);
}

void ldp_entity_del_peer(ldp_entity * e)
{
  MPLS_ASSERT(e && e->entity_type == LDP_INDIRECT && e->p.peer);
  _ldp_peer_del_entity(e->p.peer);
  MPLS_REFCNT_RELEASE(e->p.peer, ldp_peer_delete);
  e->p.peer = NULL;
  e->entity_type = LDP_UNKNOWN;
  e->sub_index = 0;
}

void ldp_entity_add_adj(ldp_entity * e, ldp_adj * a)
{
  ldp_adj *ap = NULL;

  MPLS_ASSERT(e && a);
  MPLS_REFCNT_HOLD(a);

  _ldp_adj_add_entity(a, e);
  ap = MPLS_LIST_HEAD(&e->adj_root);
  while (ap) {
    if (ap->index > a->index) {
      MPLS_LIST_INSERT_BEFORE(&e->adj_root, ap, a, _entity);
      return;
    }
    ap = MPLS_LIST_NEXT(&e->adj_root, ap, _entity);
  }
  MPLS_LIST_ADD_TAIL(&e->adj_root, a, _entity, ldp_adj);
}

void ldp_entity_del_adj(ldp_entity * e, ldp_adj * a)
{
  MPLS_ASSERT(e && a);
  MPLS_LIST_REMOVE(&e->adj_root, a, _entity);
  _ldp_adj_del_entity(a, e);
  MPLS_REFCNT_RELEASE(a, ldp_adj_delete);
}

ldp_adj *ldp_entity_find_adj(ldp_entity * e, ldp_mesg * msg)
{
  ldp_adj *a = NULL;
  mpls_inet_addr lsraddr;
  int labelspace;

  MPLS_ASSERT(e);

  ldp_mesg_hdr_get_labelspace(msg, &labelspace);
  ldp_mesg_hdr_get_lsraddr(msg, &lsraddr);

  a = MPLS_LIST_HEAD(&e->adj_root);
  while (a != NULL) {
    if (a->remote_label_space == labelspace &&
      (!mpls_inet_addr_compare(&lsraddr, &a->remote_lsr_address))) {
      return a;
    }
    a = MPLS_LIST_NEXT(&e->adj_root, a, _entity);
  }

  return NULL;
}
