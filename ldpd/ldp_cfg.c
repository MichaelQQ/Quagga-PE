
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_cfg.h"
#include "ldp_global.h"
#include "ldp_entity.h"
#include "ldp_attr.h"
#include "ldp_if.h"
#include "ldp_peer.h"
#include "ldp_fec.h"
#include "ldp_addr.h"
#include "ldp_nexthop.h"
#include "ldp_tunnel.h"
#include "ldp_resource.h"
#include "mpls_ifmgr_impl.h"
#include "ldp_label_mapping.h"
#include "ldp_hop.h"
#include "ldp_hop_list.h"
#include "mpls_lock_impl.h"
#include "mpls_trace_impl.h"
#include "mpls_tree_impl.h"

mpls_cfg_handle ldp_cfg_open(mpls_instance_handle data)
{
  ldp_global *g = ldp_global_create(data);

  LDP_ENTER(data, "ldp_cfg_open");
  LDP_EXIT(data, "ldp_cfg_open");

  return (mpls_cfg_handle) g;
}

void ldp_cfg_close(mpls_cfg_handle g)
{
  LDP_ENTER((mpls_instance_handle) g->user_data, "ldp_cfg_close");
  ldp_global_delete(g);
  LDP_EXIT((mpls_instance_handle) g->user_data, "ldp_cfg_close");
}

/******************* GLOBAL **********************/

void ldp_cfg_global_attr(mpls_cfg_handle handle) {
  ldp_global *global = (ldp_global *) handle;
  ldp_attr *attr = MPLS_LIST_HEAD(&global->attr);
  while (attr) {
    if (attr->state == LDP_LSP_STATE_MAP_SENT && attr->ds_attr) {
      fprintf(stderr, "%p(%s) xc to %p(%s)\n", attr,
        attr->session->session_name, attr->ds_attr,
        attr->ds_attr->session->session_name);
    }
    attr = MPLS_LIST_NEXT(&global->attr, attr, _global);
  }
}

mpls_return_enum ldp_cfg_global_get(mpls_cfg_handle handle, ldp_global * g,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_global_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_GLOBAL_CFG_LSR_IDENTIFIER) {
    memcpy(&(g->lsr_identifier), &(global->lsr_identifier),
      sizeof(mpls_inet_addr));
  }
  if (flag & LDP_GLOBAL_CFG_ADMIN_STATE) {
    g->admin_state = global->admin_state;
  }
  if (flag & LDP_GLOBAL_CFG_CONTROL_MODE) {
    g->lsp_control_mode = global->lsp_control_mode;
  }
  if (flag & LDP_GLOBAL_CFG_RETENTION_MODE) {
    g->label_retention_mode = global->label_retention_mode;
  }
  if (flag & LDP_GLOBAL_CFG_REPAIR_MODE) {
    g->lsp_repair_mode = global->lsp_repair_mode;
  }
  if (flag & LDP_GLOBAL_CFG_PROPOGATE_RELEASE) {
    g->propagate_release = global->propagate_release;
  }
  if (flag & LDP_GLOBAL_CFG_LABEL_MERGE) {
    g->label_merge = global->label_merge;
  }
  if (flag & LDP_GLOBAL_CFG_LOOP_DETECTION_MODE) {
    g->loop_detection_mode = global->loop_detection_mode;
  }
  if (flag & LDP_GLOBAL_CFG_TTLLESS_DOMAIN) {
    g->ttl_less_domain = global->ttl_less_domain;
  }
  if (flag & LDP_GLOBAL_CFG_LOCAL_TCP_PORT) {
    g->local_tcp_port = global->local_tcp_port;
  }
  if (flag & LDP_GLOBAL_CFG_LOCAL_UDP_PORT) {
    g->local_udp_port = global->local_udp_port;
  }
  if (flag & LDP_GLOBAL_CFG_TRANS_ADDR) {
    memcpy(&(g->transport_address), &(global->transport_address),
      sizeof(mpls_inet_addr));
  }
  if (flag & LDP_GLOBAL_CFG_KEEPALIVE_TIMER) {
    g->keepalive_timer = global->keepalive_timer;
  }
  if (flag & LDP_GLOBAL_CFG_KEEPALIVE_INTERVAL) {
    g->keepalive_interval = global->keepalive_interval;
  }
  if (flag & LDP_GLOBAL_CFG_HELLOTIME_TIMER) {
    g->hellotime_timer = global->hellotime_timer;
  }
  if (flag & LDP_GLOBAL_CFG_HELLOTIME_INTERVAL) {
    g->hellotime_interval = global->hellotime_interval;
  }
#if MPLS_USE_LSR
  if (flag & LDP_GLOBAL_CFG_LSR_HANDLE) {
    g->lsr_handle = global->lsr_handle;
  }
#endif

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_global_get");

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_cfg_global_test(mpls_cfg_handle handle, ldp_global * g,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_SUCCESS;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_global_test");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (global->admin_state == MPLS_ADMIN_ENABLE && (flag & LDP_GLOBAL_CFG_WHEN_DOWN))
    retval = MPLS_FAILURE;

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_global_test");

  return retval;
}

mpls_return_enum ldp_cfg_global_set(mpls_cfg_handle handle, ldp_global * g,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_global_set");

  mpls_lock_get(global->global_lock); /* LOCK */

  if ((global->admin_state == MPLS_ADMIN_ENABLE && (flag & LDP_GLOBAL_CFG_WHEN_DOWN)))
    goto ldp_cfg_global_set_end;

  if (flag & LDP_GLOBAL_CFG_CONTROL_MODE) {
    global->lsp_control_mode = g->lsp_control_mode;
  }
  if (flag & LDP_GLOBAL_CFG_RETENTION_MODE) {
    global->label_retention_mode = g->label_retention_mode;
  }
  if (flag & LDP_GLOBAL_CFG_REPAIR_MODE) {
    global->lsp_repair_mode = g->lsp_repair_mode;
  }
  if (flag & LDP_GLOBAL_CFG_PROPOGATE_RELEASE) {
    global->propagate_release = g->propagate_release;
  }
  if (flag & LDP_GLOBAL_CFG_LABEL_MERGE) {
    global->label_merge = g->label_merge;
  }
  if (flag & LDP_GLOBAL_CFG_LOOP_DETECTION_MODE) {
    global->loop_detection_mode = g->loop_detection_mode;
  }
  if (flag & LDP_GLOBAL_CFG_TTLLESS_DOMAIN) {
    global->ttl_less_domain = g->ttl_less_domain;
  }
  if (flag & LDP_GLOBAL_CFG_LOCAL_TCP_PORT) {
    global->local_tcp_port = g->local_tcp_port;
  }
  if (flag & LDP_GLOBAL_CFG_LOCAL_UDP_PORT) {
    global->local_udp_port = g->local_udp_port;
  }
  if (flag & LDP_GLOBAL_CFG_LSR_IDENTIFIER) {
    memcpy(&(global->lsr_identifier), &(g->lsr_identifier),
      sizeof(mpls_inet_addr));
  }
#if MPLS_USE_LSR
  if (flag & LDP_GLOBAL_CFG_LSR_HANDLE) {
    global->lsr_handle = g->lsr_handle;
  }
#endif
  if (flag & LDP_GLOBAL_CFG_ADMIN_STATE) {
    if (global->admin_state == MPLS_ADMIN_ENABLE && g->admin_state == MPLS_ADMIN_DISABLE) {
      ldp_global_shutdown(global);
    } else if (global->admin_state == MPLS_ADMIN_DISABLE && g->admin_state ==
      MPLS_ADMIN_ENABLE) {
      ldp_global_startup(global);
    }
  }
  if (flag & LDP_GLOBAL_CFG_TRANS_ADDR) {
    memcpy(&(global->transport_address), &(g->transport_address),
      sizeof(mpls_inet_addr));
  }
  if (flag & LDP_GLOBAL_CFG_KEEPALIVE_TIMER) {
    if (g->keepalive_timer == 0) {
      global->keepalive_timer = LDP_ENTITY_DEF_KEEPALIVE_TIMER;
    } else {
      global->keepalive_timer = g->keepalive_timer;
    }
  }
  if (flag & LDP_GLOBAL_CFG_KEEPALIVE_INTERVAL) {
    if (g->keepalive_interval == 0) {
      global->keepalive_interval = LDP_ENTITY_DEF_KEEPALIVE_INTERVAL;
    } else {
      global->keepalive_interval = g->keepalive_interval;
    }
  }
  if (flag & LDP_GLOBAL_CFG_HELLOTIME_TIMER) {
    if (g->hellotime_timer == 0) {
      global->hellotime_timer = LDP_ENTITY_DEF_HELLOTIME_TIMER;
    } else {
      global->hellotime_timer = g->hellotime_timer;
    }
  }
  if (flag & LDP_GLOBAL_CFG_HELLOTIME_INTERVAL) {
    if (g->hellotime_interval == 0) {
      global->hellotime_interval = LDP_ENTITY_DEF_HELLOTIME_INTERVAL;
    } else {
      global->hellotime_interval = g->hellotime_interval;
    }
  }
#if MPLS_USE_LSR
  if (flag & LDP_GLOBAL_CFG_LSR_HANDLE) {
    global->lsr_handle = g->lsr_handle ;
  }
#endif
  global->configuration_sequence_number++;

  retval = MPLS_SUCCESS;

ldp_cfg_global_set_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_global_set");

  return retval;
}

/******************* ENTITY **********************/

/* must set ldp_entity->index */
mpls_return_enum ldp_cfg_entity_get(mpls_cfg_handle handle, ldp_entity * e,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_entity *entity = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && e != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_entity_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (ldp_global_find_entity_index(global, e->index, &entity) != MPLS_SUCCESS)
      goto ldp_cfg_entity_get_end;

  if (flag & LDP_ENTITY_CFG_ADMIN_STATE) {
    e->admin_state = entity->admin_state;
  }
  if (flag & LDP_ENTITY_CFG_TRANS_ADDR) {
    e->transport_address = entity->transport_address;
  }
  if (flag & LDP_ENTITY_CFG_PROTO_VER) {
    e->protocol_version = entity->protocol_version;
  }
  if (flag & LDP_ENTITY_CFG_REMOTE_TCP) {
    e->remote_tcp_port = entity->remote_tcp_port;
  }
  if (flag & LDP_ENTITY_CFG_REMOTE_UDP) {
    e->remote_udp_port = entity->remote_udp_port;
  }
  if (flag & LDP_ENTITY_CFG_MAX_PDU) {
    e->max_pdu = entity->max_pdu;
  }
  if (flag & LDP_ENTITY_CFG_KEEPALIVE_TIMER) {
    e->keepalive_timer = entity->keepalive_timer;
  }
  if (flag & LDP_ENTITY_CFG_KEEPALIVE_INTERVAL) {
    e->keepalive_interval = entity->keepalive_interval;
  }
  if (flag & LDP_ENTITY_CFG_HELLOTIME_TIMER) {
    e->hellotime_timer = entity->hellotime_timer;
  }
  if (flag & LDP_ENTITY_CFG_HELLOTIME_INTERVAL) {
    e->hellotime_interval = entity->hellotime_interval;
  }
  if (flag & LDP_ENTITY_CFG_SESSION_SETUP_COUNT) {
    e->session_setup_count = entity->session_setup_count;
  }
  if (flag & LDP_ENTITY_CFG_SESSION_BACKOFF_TIMER) {
    e->session_backoff_timer = entity->session_backoff_timer;
  }
  if (flag & LDP_ENTITY_CFG_DISTRIBUTION_MODE) {
    e->label_distribution_mode = entity->label_distribution_mode;
  }
  if (flag & LDP_ENTITY_CFG_PATHVECTOR_LIMIT) {
    e->path_vector_limit = entity->path_vector_limit;
  }
  if (flag & LDP_ENTITY_CFG_HOPCOUNT_LIMIT) {
    e->hop_count_limit = entity->hop_count_limit;
  }
  if (flag & LDP_ENTITY_CFG_REQUEST_COUNT) {
    e->label_request_count = entity->label_request_count;
  }
  if (flag & LDP_ENTITY_CFG_REQUEST_TIMER) {
    e->label_request_timer = entity->label_request_timer;
  }
  if (flag & LDP_ENTITY_CFG_TYPE) {
    e->entity_type = entity->entity_type;
  }
  if (flag & LDP_ENTITY_CFG_SUB_INDEX) {
    e->sub_index = entity->sub_index;
  }
  if (flag & LDP_ENTITY_CFG_MESG_TX) {
    e->mesg_tx = entity->mesg_tx;
  }
  if (flag & LDP_ENTITY_CFG_MESG_RX) {
    e->mesg_rx = entity->mesg_rx;
  }
  if (flag & LDP_ENTITY_CFG_ADJ_COUNT) {
    e->adj_count = entity->adj_root.count;
  }
  if (flag & LDP_ENTITY_CFG_ADJ_INDEX) {
    ldp_adj *a = MPLS_LIST_HEAD(&entity->adj_root);
    e->adj_index = a ? a->index : 0;
  }
  if (flag & LDP_ENTITY_CFG_INHERIT_FLAG) {
    e->inherit_flag = entity->inherit_flag;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_entity_get_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_entity_get");

  return retval;
}

mpls_return_enum ldp_cfg_entity_getnext(mpls_cfg_handle handle, ldp_entity * e,
  uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_entity *entity = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_entity_getnext");

  if (e->index == 0) {
    index = 1;
  } else {
    index = e->index + 1;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_entity_index(g, index, &entity))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    e->index = entity->index;
    LDP_EXIT(g->user_data, "ldp_cfg_entity_getnext");
    return ldp_cfg_entity_get(g, e, flag);
  }
  LDP_EXIT(g->user_data, "ldp_cfg_entity_getnext");
  return r;
}

mpls_return_enum ldp_cfg_entity_test(mpls_cfg_handle handle, ldp_entity * e,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_entity *entity = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_entity_test");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (!(flag & LDP_CFG_ADD)) {
    if (e == NULL)
      goto ldp_cfg_entity_test_end;

    ldp_global_find_entity_index(global, e->index, &entity);
  } else {
    retval = MPLS_SUCCESS;
    goto ldp_cfg_entity_test_end;
  }

  if (entity == NULL) {
     goto ldp_cfg_entity_test_end;
  }

  if ((ldp_entity_is_active(entity) == MPLS_BOOL_TRUE) &&
      (flag & LDP_ENTITY_CFG_WHEN_DOWN)) {
     goto ldp_cfg_entity_test_end;
  }

  retval = MPLS_SUCCESS;

ldp_cfg_entity_test_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_entity_test");

  return retval;
}

/* must set ldp_entity->index if not an add */
mpls_return_enum ldp_cfg_entity_set(mpls_cfg_handle handle, ldp_entity * e,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_entity *entity = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && e != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_entity_set");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_CFG_ADD) {
    entity = ldp_entity_create();
    _ldp_global_add_entity(global, entity);

    e->index = entity->index;
  } else {
    ldp_global_find_entity_index(global, e->index, &entity);
  }

  if (entity == NULL) {
    LDP_PRINT(global->user_data, "ldp_cfg_entity_set: can't find entity\n");
    goto ldp_cfg_entity_set_end;
  }

  if ((ldp_entity_is_active(entity) == MPLS_BOOL_TRUE) &&
      (flag & LDP_ENTITY_CFG_WHEN_DOWN)) {
    LDP_PRINT(global->user_data, "ldp_cfg_entity_set: entity is active\n");
    goto ldp_cfg_entity_set_end;
  }

  if (flag & LDP_CFG_DEL) {
    switch (entity->entity_type) {
      case LDP_DIRECT:
        ldp_entity_del_if(global, entity);
        break;
      case LDP_INDIRECT:
        ldp_entity_del_peer(entity);
        break;
      default:
        MPLS_ASSERT(0);
    }
    _ldp_global_del_entity(global, entity);

    retval = MPLS_SUCCESS;
    goto ldp_cfg_entity_set_end;
  }

  if (flag & LDP_ENTITY_CFG_SUB_INDEX) {
    if (entity->sub_index != 0) {
      /* unlink the old sub object */
      switch (entity->entity_type) {
        case LDP_DIRECT:
          ldp_entity_del_if(global, entity);
          break;
        case LDP_INDIRECT:
          ldp_entity_del_peer(entity);
          break;
        default:
          MPLS_ASSERT(0);
      }
    }

    /* link the new sub object */
    switch (e->entity_type) {
      case LDP_DIRECT:
        {
          ldp_if *iff = NULL;
          if (ldp_global_find_if_index(global, e->sub_index,
              &iff) != MPLS_SUCCESS) {
            LDP_PRINT(global->user_data,
              "ldp_cfg_entity_set: no such interface\n");

            if (flag & LDP_CFG_ADD) {
              _ldp_global_del_entity(global, entity);
            }
            goto ldp_cfg_entity_set_end;
          }
          ldp_entity_add_if(entity, iff);
          break;
        }
      case LDP_INDIRECT:
        {
          ldp_peer *peer = NULL;

          if (ldp_global_find_peer_index(global, e->sub_index, &peer) !=
            MPLS_SUCCESS) {
            LDP_PRINT(global->user_data, "ldp_cfg_entity_set: no such peer\n");

            if (flag & LDP_CFG_ADD) {
              _ldp_global_del_entity(global, entity);
            }
            goto ldp_cfg_entity_set_end;
          }
          ldp_entity_add_peer(entity, peer);
          break;
        }
      default:
        MPLS_ASSERT(0);
    }
  }

  if (flag & LDP_ENTITY_CFG_TRANS_ADDR) {
    if (e->transport_address.type == MPLS_FAMILY_NONE) {
      entity->inherit_flag |= LDP_ENTITY_CFG_TRANS_ADDR;
    } else {
      entity->inherit_flag &= ~LDP_ENTITY_CFG_TRANS_ADDR;
    }
    memcpy(&entity->transport_address, &e->transport_address,
      sizeof(mpls_inet_addr));;
  }
  if (flag & LDP_ENTITY_CFG_PROTO_VER) {
    entity->protocol_version = e->protocol_version;
  }
  if (flag & LDP_ENTITY_CFG_REMOTE_TCP) {
    entity->remote_tcp_port = e->remote_tcp_port;
  }
  if (flag & LDP_ENTITY_CFG_REMOTE_UDP) {
    entity->remote_udp_port = e->remote_udp_port;
  }
  if (flag & LDP_ENTITY_CFG_MAX_PDU) {
    entity->max_pdu = e->max_pdu;
  }
  if (flag & LDP_ENTITY_CFG_KEEPALIVE_TIMER) {
    if (e->transport_address.type == MPLS_FAMILY_NONE) {
      entity->inherit_flag |= LDP_ENTITY_CFG_KEEPALIVE_TIMER;
    } else {
      entity->inherit_flag &= ~LDP_ENTITY_CFG_KEEPALIVE_TIMER;
    }
    entity->keepalive_timer = e->keepalive_timer;
  }
  if (flag & LDP_ENTITY_CFG_KEEPALIVE_INTERVAL) {
    if (e->transport_address.type == MPLS_FAMILY_NONE) {
      entity->inherit_flag |= LDP_ENTITY_CFG_KEEPALIVE_INTERVAL;
    } else {
      entity->inherit_flag &= ~LDP_ENTITY_CFG_KEEPALIVE_INTERVAL;
    }
    entity->keepalive_interval = e->keepalive_interval;
  }
  if (flag & LDP_ENTITY_CFG_HELLOTIME_TIMER) {
    if (e->transport_address.type == MPLS_FAMILY_NONE) {
      entity->inherit_flag |= LDP_ENTITY_CFG_HELLOTIME_TIMER;
    } else {
      entity->inherit_flag &= ~LDP_ENTITY_CFG_HELLOTIME_TIMER;
    }
    entity->hellotime_timer = e->hellotime_timer;
  }
  if (flag & LDP_ENTITY_CFG_HELLOTIME_INTERVAL) {
    if (e->transport_address.type == MPLS_FAMILY_NONE) {
      entity->inherit_flag |= LDP_ENTITY_CFG_HELLOTIME_INTERVAL;
    } else {
      entity->inherit_flag &= ~LDP_ENTITY_CFG_HELLOTIME_INTERVAL;
    }
    entity->hellotime_interval = e->hellotime_interval;
  }
  if (flag & LDP_ENTITY_CFG_SESSION_SETUP_COUNT) {
    entity->session_setup_count = e->session_setup_count;
  }
  if (flag & LDP_ENTITY_CFG_SESSION_BACKOFF_TIMER) {
    entity->session_backoff_timer = e->session_backoff_timer;
  }
  if (flag & LDP_ENTITY_CFG_DISTRIBUTION_MODE) {
    entity->label_distribution_mode = e->label_distribution_mode;
  }
  if (flag & LDP_ENTITY_CFG_PATHVECTOR_LIMIT) {
    entity->path_vector_limit = e->path_vector_limit;
  }
  if (flag & LDP_ENTITY_CFG_HOPCOUNT_LIMIT) {
    entity->hop_count_limit = e->hop_count_limit;
  }
  if (flag & LDP_ENTITY_CFG_REQUEST_COUNT) {
    entity->label_request_count = e->label_request_count;
  }
  if (flag & LDP_ENTITY_CFG_REQUEST_TIMER) {
    entity->label_request_timer = e->label_request_timer;
  }
  if (flag & LDP_ENTITY_CFG_TYPE) {
    entity->entity_type = e->entity_type;
  }
  if (flag & LDP_ENTITY_CFG_ADMIN_STATE) {
    if (ldp_entity_is_active(entity) == MPLS_BOOL_TRUE &&
      e->admin_state == MPLS_ADMIN_DISABLE) {
      if (ldp_entity_shutdown(global, entity, 0) == MPLS_FAILURE) {
        goto ldp_cfg_entity_set_end;
      }
    } else if (ldp_entity_is_active(entity) == MPLS_BOOL_FALSE &&
      e->admin_state == MPLS_ADMIN_ENABLE && ldp_entity_is_ready(entity) == MPLS_BOOL_TRUE) {
      if (ldp_entity_startup(global, entity) == MPLS_FAILURE) {
        goto ldp_cfg_entity_set_end;
      }
    } else {
      LDP_PRINT(global->user_data, "ldp_cfg_entity_set: entity not ready\n");

      goto ldp_cfg_entity_set_end;
    }
  }
  if (flag & LDP_ENTITY_CFG_INHERIT_FLAG) {
    entity->inherit_flag = e->inherit_flag;
  }
  global->configuration_sequence_number++;

  retval = MPLS_SUCCESS;

ldp_cfg_entity_set_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_entity_set");

  return retval;
}

mpls_return_enum ldp_cfg_entity_adj_getnext(mpls_cfg_handle handle,
  ldp_entity * e)
{
  ldp_global *g = (ldp_global *) handle;
  mpls_bool this_one = MPLS_BOOL_FALSE;
  mpls_return_enum r = MPLS_FAILURE;
  ldp_adj *adj_next = NULL;
  ldp_adj *adj = NULL;
  ldp_entity *entity = NULL;

  LDP_ENTER(g->user_data, "ldp_cfg_entity_adj_getnext");

  /* if an adj_index of zero is sent, get the index of
   * the first adj in the list
   */
  if (!e->adj_index) {
    this_one = MPLS_BOOL_TRUE;
  }

  mpls_lock_get(g->global_lock); /* LOCK */

  if (ldp_global_find_entity_index(g, e->index, &entity) == MPLS_SUCCESS) {
    adj = MPLS_LIST_HEAD(&entity->adj_root);
    while (adj) {
      if (this_one == MPLS_BOOL_TRUE) {
        adj_next = adj;
        break;
      }

      /* since the entities are sort in the list ... */
      if (adj->index > e->adj_index) {
        break;
      } else if (adj->index == e->adj_index) {
        this_one = MPLS_BOOL_TRUE;
      }
      adj = MPLS_LIST_NEXT(&entity->adj_root, adj, _entity);
    }
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (adj_next) {
    e->adj_index = adj_next->index;
    r = MPLS_SUCCESS;
  }

  LDP_EXIT(g->user_data, "ldp_cfg_entity_adj_getnext");
  return r;
}

/******************* INTERFACE **********************/

mpls_return_enum ldp_cfg_if_get(mpls_cfg_handle handle, ldp_if * i, uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_if *iff = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && i != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_if_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_IF_CFG_BY_INDEX) {
    ldp_global_find_if_index(global, i->index, &iff);
  } else {
    iff = ldp_global_find_if_handle(global, i->handle);
  }
  if (!iff)
      goto ldp_cfg_if_get_end;

  if (flag & LDP_IF_CFG_LABEL_SPACE) {
    i->label_space = iff->label_space;
  }
  if (flag & LDP_IF_CFG_ENTITY_INDEX) {
    i->entity_index = iff->entity ? iff->entity->index : 0;
  }
  if (flag & LDP_IF_CFG_OPER_STATE) {
    i->oper_state = iff->oper_state;
  }
  if (flag & LDP_IF_CFG_HANDLE) {
    memcpy(&i->handle, &iff->handle, sizeof(mpls_if_handle));
  }
  retval = MPLS_SUCCESS;

ldp_cfg_if_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_if_get");

  return retval;
}

mpls_return_enum ldp_cfg_if_getnext(mpls_cfg_handle handle, ldp_if * i,
  uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_if *iff = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_if_getnext");

  if (i->index == 0) {
    index = 1;
  } else {
    index = i->index + 1;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_if_index(g, index, &iff))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    i->index = iff->index;
    LDP_EXIT(g->user_data, "ldp_cfg_if_getnext");
    return ldp_cfg_if_get(g, i, flag);
  }
  LDP_EXIT(g->user_data, "ldp_cfg_if_getnext");
  return r;
}

mpls_return_enum ldp_cfg_if_test(mpls_cfg_handle handle, ldp_if * i,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_if *iff = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && i != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_if_test");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (!(flag & LDP_CFG_ADD)) {
    ldp_global_find_if_index(global, i->index, &iff);
  } else {
    retval = MPLS_SUCCESS;
    goto ldp_cfg_if_test_end;
  }

  if ((!iff) || ((ldp_if_is_active(iff) == MPLS_BOOL_TRUE) &&
    (flag & LDP_IF_CFG_WHEN_DOWN))) {
    goto ldp_cfg_if_test_end;
  }

  if (flag & LDP_CFG_DEL) {
    if (iff->entity != NULL) {
      goto ldp_cfg_if_test_end;
    }
  }
  retval = MPLS_SUCCESS;

ldp_cfg_if_test_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_if_test");

  return retval;
}

mpls_return_enum ldp_cfg_if_set(mpls_cfg_handle handle, ldp_if * i, uint32_t flag)
{
  ldp_global *global = (ldp_global*)handle;
  ldp_if *iff = NULL;
  ldp_addr *ap;
  ldp_nexthop *np;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && i != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_if_set");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_CFG_ADD) {
    /* duplicate interface handles are not allowed */
    /* ADDs require a valid interface handle */
    if (((iff = ldp_global_find_if_handle(global, i->handle)) != NULL) ||
      (mpls_if_handle_verify(global->ifmgr_handle, i->handle) ==
      MPLS_BOOL_FALSE) || ((iff = ldp_if_create(global)) == NULL)) {
      goto ldp_cfg_if_set_end;
    }

    /* copy the handle from the user */
    iff->handle = i->handle;

    /* search for addrs and nexthops that are waiting for this interface */
    ap = MPLS_LIST_HEAD(&global->addr);
    while (ap) {
      if (ap->if_handle == iff->handle && (!MPLS_LIST_IN_LIST(ap, _if))) {
        ldp_if_add_addr(iff, ap);
      }
      ap = MPLS_LIST_NEXT(&global->addr, ap, _global);
    }

    np = MPLS_LIST_HEAD(&global->nexthop);
    while (np) {
      if ((np->info.type & MPLS_NH_IF) &&
	(np->info.if_handle == iff->handle) && (!MPLS_LIST_IN_LIST(np, _if))) {
        ldp_if_add_nexthop(iff, np);
      }
      np = MPLS_LIST_NEXT(&global->nexthop, np, _global);
    }

    /* send the newly created index back to the user */
    i->index = iff->index;
    MPLS_REFCNT_HOLD(iff);

  } else {
    if (flag & LDP_IF_CFG_BY_INDEX) {
      ldp_global_find_if_index(global, i->index, &iff);
    } else {
      iff = ldp_global_find_if_handle(global, i->handle);
    }
  }

  /*
   * if we can't find this interface or if the interface is active and
   * we are trying to change propertises that can not be changed on a
   * active interface
   */
  if ((!iff) || ((ldp_if_is_active(iff) == MPLS_BOOL_TRUE) &&
    (flag & LDP_IF_CFG_WHEN_DOWN))) {
    goto ldp_cfg_if_set_end;
  }

  if (flag & LDP_IF_CFG_LABEL_SPACE) {
    iff->label_space = i->label_space;
  }

  if (flag & LDP_CFG_DEL) {
    /*
     * if this interface is still attached to a entity that it is not ready
     * to be removed
     */
    if (iff->entity != NULL) {
      goto ldp_cfg_if_set_end;
    }

    np = MPLS_LIST_HEAD(&iff->nh_root);
    while ((np = MPLS_LIST_HEAD(&iff->nh_root))) {
      ldp_if_del_nexthop(global, iff, np);
    }

    ap = MPLS_LIST_HEAD(&iff->addr_root);
    while ((ap = MPLS_LIST_HEAD(&iff->addr_root))) {
      ldp_if_del_addr(global, iff, ap);
    }

    MPLS_REFCNT_RELEASE2(global, iff, ldp_if_delete);
  }

  global->configuration_sequence_number++;

  retval = MPLS_SUCCESS;

ldp_cfg_if_set_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_if_set");

  return retval;
}

/******************* ATTR **********************/

mpls_return_enum ldp_cfg_attr_get(mpls_cfg_handle handle, ldp_attr * a,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_attr *attr = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && a != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_attr_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (ldp_global_find_attr_index(global, a->index, &attr) != MPLS_SUCCESS)
      goto ldp_cfg_attr_get_end;

  if (flag & LDP_ATTR_CFG_STATE) {
    a->state = attr->state;
  }
  if (flag & LDP_ATTR_CFG_FEC) {
    ldp_attr2ldp_attr(attr, a, LDP_ATTR_FEC);
  }
  if (flag & LDP_ATTR_CFG_LABEL) {
    ldp_attr2ldp_attr(attr, a, LDP_ATTR_LABEL);
  }
  if (flag & LDP_ATTR_CFG_HOP_COUNT) {
    ldp_attr2ldp_attr(attr, a, LDP_ATTR_HOPCOUNT);
  }
  if (flag & LDP_ATTR_CFG_PATH) {
    ldp_attr2ldp_attr(attr, a, LDP_ATTR_PATH);
  }
  if (flag & LDP_ATTR_CFG_SESSION_INDEX) {
    a->session_index = (attr->session) ? (attr->session->index) : 0;
  }
  if (flag & LDP_ATTR_CFG_INLABEL_INDEX) {
    a->inlabel_index = (attr->inlabel) ? (attr->inlabel->index) : 0;
  }
  if (flag & LDP_ATTR_CFG_OUTLABEL_INDEX) {
    a->outlabel_index = (attr->outlabel) ? (attr->outlabel->index) : 0;
  }
  if (flag & LDP_ATTR_CFG_INGRESS) {
    a->ingress = attr->ingress;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_attr_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_attr_get");

  return retval;
}

mpls_return_enum ldp_cfg_attr_getnext(mpls_cfg_handle handle, ldp_attr * a,
  uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_attr *attr = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_attr_getnext");

  if (a->index == 0) {
    index = 1;
  } else {
    index = a->index + 1;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_attr_index(g, index, &attr))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    a->index = attr->index;
    LDP_EXIT(g->user_data, "ldp_cfg_attr_getnext");
    return ldp_cfg_attr_get(g, a, flag);
  }
  LDP_EXIT(g->user_data, "ldp_cfg_attr_getnext");
  return r;
}

/******************* PEER **********************/

mpls_return_enum ldp_cfg_peer_get(mpls_cfg_handle handle, ldp_peer * p,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_peer *peer = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && p != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_peer_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (ldp_global_find_peer_index(global, p->index, &peer) != MPLS_SUCCESS)
      goto ldp_cfg_peer_get_end;

  if (flag & LDP_PEER_CFG_LABEL_SPACE) {
    p->label_space = peer->label_space;
  }
  if (flag & LDP_PEER_CFG_TARGET_ROLE) {
    p->target_role = peer->target_role;
  }
  if (flag & LDP_PEER_CFG_DEST_ADDR) {
    memcpy(&p->dest.addr, &peer->dest.addr, sizeof(mpls_inet_addr));
  }
  if (flag & LDP_PEER_CFG_ENTITY_INDEX) {
    p->entity_index = peer->entity->index;
  }
  if (flag & LDP_PEER_CFG_OPER_STATE) {
    p->oper_state = peer->oper_state;
  }
  if (flag & LDP_PEER_CFG_PEER_NAME) {
    strncpy(p->peer_name, peer->peer_name, MPLS_MAX_IF_NAME);
  }
  retval = MPLS_SUCCESS;

ldp_cfg_peer_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_peer_get");

  return retval;
}

mpls_return_enum ldp_cfg_peer_getnext(mpls_cfg_handle handle, ldp_peer * p,
  uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_peer *peer = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_peer_getnext");

  if (p->index == 0) {
    index = 1;
  } else {
    index = p->index + 1;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_peer_index(g, index, &peer))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    p->index = peer->index;
    LDP_EXIT(g->user_data, "ldp_cfg_peer_getnext");
    return ldp_cfg_peer_get(g, p, flag);
  }
  LDP_EXIT(g->user_data, "ldp_cfg_peer_getnext");
  return r;
}

mpls_return_enum ldp_cfg_peer_test(mpls_cfg_handle handle, ldp_peer * p,
  uint32_t flag)
{
  // ldp_global* g = (ldp_global*)handle;
  return MPLS_SUCCESS;
}

mpls_return_enum ldp_cfg_peer_set(mpls_cfg_handle handle, ldp_peer * p,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_peer *peer = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && p != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_peer_set");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_CFG_ADD) {
    if ((peer = ldp_peer_create()) == NULL) {
      goto ldp_cfg_peer_set_end;
    }
    p->index = peer->index;
    _ldp_global_add_peer(global, peer);
  } else {
    ldp_global_find_peer_index(global, p->index, &peer);
  }

  if (peer == NULL) {
    LDP_PRINT(global->user_data, "ldp_cfg_peer_set: no such peer\n");

    goto ldp_cfg_peer_set_end;
  }
  if ((ldp_peer_is_active(peer) == MPLS_BOOL_TRUE) && (flag & LDP_PEER_CFG_WHEN_DOWN)) {
    LDP_PRINT(global->user_data, "ldp_cfg_peer_set: peer is activer\n");

    goto ldp_cfg_peer_set_end;
  }

  if (flag & LDP_CFG_DEL) {
    if (peer->entity != NULL) {
      LDP_PRINT(global->user_data,
        "ldp_cfg_peer_set: not cleanup correctly is activer\n");

      goto ldp_cfg_peer_set_end;
    }

    _ldp_global_del_peer(global, peer);

    retval = MPLS_SUCCESS;
    goto ldp_cfg_peer_set_end;
  }
  if (flag & LDP_PEER_CFG_LABEL_SPACE) {
    peer->label_space = p->label_space;
  }
  if (flag & LDP_PEER_CFG_TARGET_ROLE) {
    peer->target_role = p->target_role;
  }
  if (flag & LDP_PEER_CFG_DEST_ADDR) {
    memcpy(&peer->dest.addr, &p->dest.addr, sizeof(mpls_inet_addr));
  }
  if (flag & LDP_PEER_CFG_PEER_NAME) {
    LDP_PRINT(global->user_data, "ldp_cfg_peer_set: peer_name = %s\n",

      p->peer_name);
    strncpy(peer->peer_name, p->peer_name, MPLS_MAX_IF_NAME);
  }
  global->configuration_sequence_number++;

  retval = MPLS_SUCCESS;

ldp_cfg_peer_set_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_peer_set");

  return retval;
}
/******************* FEC **********************/

mpls_return_enum ldp_cfg_fec_get(mpls_cfg_handle handle, mpls_fec * f,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_fec *fec = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && f != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_fec_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_FEC_CFG_BY_INDEX) {
    ldp_global_find_fec_index(global, f->index, &fec);
  } else {
    fec = ldp_fec_find(global, f);
  }
  if (!fec)
      goto ldp_cfg_fec_get_end;

  memcpy(f, &fec->info, sizeof(mpls_fec));
  f->index = fec->index;
  retval = MPLS_SUCCESS;

ldp_cfg_fec_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_fec_get");

  return retval;
}

mpls_return_enum ldp_cfg_fec_getnext(mpls_cfg_handle handle, mpls_fec * f,
  uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_fec *fec = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_fec_getnext");

  if (f->index == 0) {
    index = 1;
  } else {
    index = f->index + 1;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_fec_index(g, index, &fec))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    f->index = fec->index;
    LDP_EXIT(g->user_data, "ldp_cfg_fec_getnext");
    return ldp_cfg_fec_get(g, f, flag);
  }
  LDP_EXIT(g->user_data, "ldp_cfg_fec_getnext");
  return r;
}

mpls_return_enum ldp_cfg_fec_test(mpls_cfg_handle handle, mpls_fec * f,
  uint32_t flag)
{
  // ldp_global* g = (ldp_global*)handle;
  return MPLS_SUCCESS;
}

mpls_return_enum ldp_cfg_fec_set(mpls_cfg_handle handle, mpls_fec * f,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_fec *fec = NULL;
  ldp_nexthop *nh;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && f != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_fec_set");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_CFG_ADD) {
    if (ldp_fec_find(global, f) || (fec = ldp_fec_create(global, f)) == NULL) {
      goto ldp_cfg_fec_set_end;
    }
    MPLS_REFCNT_HOLD(fec);
    f->index = fec->index;
  } else {
    if (flag & LDP_FEC_CFG_BY_INDEX) {
      ldp_global_find_fec_index(global, f->index, &fec);
    } else {
      fec = ldp_fec_find(global, f);
    }
  }

  if (fec == NULL) {
    LDP_PRINT(global->user_data, "ldp_cfg_fec_set: no such fec\n");
    goto ldp_cfg_fec_set_end;
  }

  if (flag & LDP_CFG_DEL) {

    while ((nh = MPLS_LIST_HEAD(&fec->nh_root))) {
      ldp_fec_del_nexthop(global, fec, nh);
    }

    MPLS_REFCNT_RELEASE2(global, fec, ldp_fec_delete);
  }

  retval = MPLS_SUCCESS;

ldp_cfg_fec_set_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_fec_set");

  return retval;
}

mpls_return_enum ldp_cfg_fec_nexthop_get(mpls_cfg_handle handle, mpls_fec * f,
  mpls_nexthop *n, uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_fec *fec = NULL;
  ldp_nexthop *nh = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && f != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_fec_nexthop_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_FEC_CFG_BY_INDEX) {
    ldp_global_find_fec_index(global, f->index, &fec);
  } else {
    fec = ldp_fec_find(global, f);
  }
  if (!fec)
      goto ldp_cfg_fec_nexthop_get_end;

  if (flag & LDP_FEC_NEXTHOP_CFG_BY_INDEX) {
    ldp_fec_find_nexthop_index(fec, n->index, &nh);
  } else {
    nh = ldp_fec_nexthop_find(fec, n);
  }
  if (!nh)
    goto ldp_cfg_fec_nexthop_get_end;

  memcpy(n, &nh->info, sizeof(mpls_nexthop));
  n->index = nh->index;
  retval = MPLS_SUCCESS;

ldp_cfg_fec_nexthop_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_fec_nexthop_get");

  return retval;
}

mpls_return_enum ldp_cfg_fec_nexthop_getnext(mpls_cfg_handle handle,
  mpls_fec * f, mpls_nexthop *n, uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_fec *fec = NULL;
  ldp_nexthop *nh = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(global->user_data, "ldp_cfg_fec_nexthop_getnext");

  if (n->index == 0) {
    index = 1;
  } else {
    index = n->index + 1;
  }

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_FEC_CFG_BY_INDEX) {
    ldp_global_find_fec_index(global, f->index, &fec);
  } else {
    fec = ldp_fec_find(global, f);
  }
  if (!fec)
      goto ldp_cfg_fec_nexthop_getnext_end;

  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_fec_find_nexthop_index(fec, index, &nh))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(global->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    n->index = nh->index;
    LDP_EXIT(global->user_data, "ldp_cfg_fec_nexthop_getnext");
    return ldp_cfg_fec_nexthop_get(global, f, n, flag);
  }

ldp_cfg_fec_nexthop_getnext_end:

  LDP_EXIT(global->user_data, "ldp_cfg_fec_nexthop_getnext");
  return r;
}

mpls_return_enum ldp_cfg_fec_nexthop_test(mpls_cfg_handle handle, mpls_fec * f,
  mpls_nexthop *n, uint32_t flag)
{
  // ldp_global* g = (ldp_global*)handle;
  return MPLS_SUCCESS;
}

mpls_return_enum ldp_cfg_fec_nexthop_set(mpls_cfg_handle handle, mpls_fec * f,
  mpls_nexthop *n, uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_fec *fec = NULL;
  ldp_nexthop *nh = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && f != NULL && n != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_fec_nexthop_set");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_FEC_CFG_BY_INDEX) {
    ldp_global_find_fec_index(global, f->index, &fec);
  } else {
    fec = ldp_fec_find(global, f);
  }
  if (!fec)
      goto ldp_cfg_fec_nexthop_set_end;

  if (flag & LDP_CFG_ADD) {
    if (ldp_fec_nexthop_find(fec, n) ||
      (nh = ldp_nexthop_create(global, n)) == NULL) {
      goto ldp_cfg_fec_nexthop_set_end;
    }
    n->index = nh->index;
    ldp_fec_add_nexthop(global, fec, nh);
    ldp_fec_process_add(global, fec, nh, NULL);
  } else {
    if (flag & LDP_FEC_NEXTHOP_CFG_BY_INDEX) {
      ldp_fec_find_nexthop_index(fec, n->index, &nh);
    } else {
      nh = ldp_fec_nexthop_find(fec, n);
    }
  }

  if (nh == NULL) {
    LDP_PRINT(global->user_data, "ldp_cfg_fec_nexthop_set: no such nh\n");
    goto ldp_cfg_fec_nexthop_set_end;
  }

  if (flag & LDP_CFG_DEL) {
    ldp_fec_del_nexthop(global, fec, nh);
    if (ldp_fec_process_change(global, fec, MPLS_LIST_HEAD(&fec->nh_root),
      nh, NULL) != MPLS_SUCCESS) {
      MPLS_ASSERT(0);
    }
    _ldp_global_del_nexthop(global, nh);
  }

  retval = MPLS_SUCCESS;

ldp_cfg_fec_nexthop_set_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_fec_nexthop_set");

  return retval;
}

/******************* ADDR **********************/

mpls_return_enum ldp_cfg_addr_get(mpls_cfg_handle handle, ldp_addr * a,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_session *session = NULL;
  ldp_nexthop *nexthop = NULL;
  ldp_addr *addr = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && a != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_addr_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  ldp_global_find_addr_index(global, a->index, &addr);

  if (!addr)
    goto ldp_cfg_addr_get_end;

  memcpy(&a->address, &addr->address, sizeof(mpls_inet_addr));
  a->index = addr->index;

  if ((session = mpls_link_list_head_data(&addr->session_root))) {
    a->session_index = session->index;
  }

  if ((nexthop = MPLS_LIST_HEAD(&addr->nh_root))) {
    a->nexthop_index = nexthop->index;
  }

  if (addr->iff) {
    a->if_index = addr->iff->index;
  }

  retval = MPLS_SUCCESS;

ldp_cfg_addr_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_addr_get");

  return retval;
}

mpls_return_enum ldp_cfg_addr_getnext(mpls_cfg_handle handle, ldp_addr *a,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_addr *addr = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(global->user_data, "ldp_cfg_addr_getnext");

  if (a->index == 0) {
    index = 1;
  } else {
    index = a->index + 1;
  }

  mpls_lock_get(global->global_lock); /* LOCK */

  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_addr_index(global, index, &addr))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(global->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    a->index = addr->index;
    LDP_EXIT(global->user_data, "ldp_cfg_addr_getnext");
    return ldp_cfg_addr_get(global, a, flag);
  }

  LDP_EXIT(global->user_data, "ldp_cfg_addr_getnext");
  return r;
}

/******************* IF ADDR **********************/

mpls_return_enum ldp_cfg_if_addr_get(mpls_cfg_handle handle, ldp_if * i,
  ldp_addr * a, uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_addr *addr = NULL;
  ldp_if *iff = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && i != NULL && a != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_if_addr_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_IF_CFG_BY_INDEX) {
    ldp_global_find_if_index(global, i->index, &iff);
  } else {
    iff = ldp_global_find_if_handle(global, i->handle);
  }
  if (!iff)
      goto ldp_cfg_if_addr_get_end;

  if (flag & LDP_IF_ADDR_CFG_BY_INDEX) {
    ldp_if_find_addr_index(iff, a->index, &addr);
  } else {
    addr = ldp_if_addr_find(iff, &a->address);
  }
  if (!addr)
    goto ldp_cfg_if_addr_get_end;

  memcpy(&a->address, &addr->address, sizeof(mpls_inet_addr));
  a->index = addr->index;

  retval = MPLS_SUCCESS;

ldp_cfg_if_addr_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_if_addr_get");

  return retval;
}

mpls_return_enum ldp_cfg_if_addr_getnext(mpls_cfg_handle handle,
  ldp_if * i, ldp_addr *a, uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_if *iff = NULL;
  ldp_addr *addr = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(global->user_data, "ldp_cfg_if_addr_getnext");

  if (a->index == 0) {
    index = 1;
  } else {
    index = a->index + 1;
  }

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_IF_CFG_BY_INDEX) {
    ldp_global_find_if_index(global, i->index, &iff);
  } else {
    iff = ldp_global_find_if_handle(global, i->handle);
  }
  if (!iff)
      goto ldp_cfg_if_addr_getnext_end;

  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_if_find_addr_index(iff, index, &addr))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(global->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    a->index = addr->index;
    LDP_EXIT(global->user_data, "ldp_cfg_if_addr_getnext");
    return ldp_cfg_if_addr_get(global, i, a, flag);
  }

ldp_cfg_if_addr_getnext_end:

  LDP_EXIT(global->user_data, "ldp_cfg_if_addr_getnext");
  return r;
}

mpls_return_enum ldp_cfg_if_addr_set(mpls_cfg_handle handle, ldp_if * i,
  ldp_addr *a, uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_if *iff = NULL;
  ldp_addr *addr = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && i != NULL && a != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_if_addr_set");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_FEC_CFG_BY_INDEX) {
    ldp_global_find_if_index(global, i->index, &iff);
  } else {
    iff = ldp_global_find_if_handle(global, i->handle);
  }
  if (!iff)
      goto ldp_cfg_if_addr_set_end;

  if (flag & LDP_CFG_ADD) {
    if (ldp_if_addr_find(iff, &a->address) || (addr = ldp_addr_create(global,
      &a->address)) == NULL) {
      goto ldp_cfg_if_addr_set_end;
    }
    a->index = addr->index;
    ldp_if_add_addr(iff, addr);
  } else {
    if (flag & LDP_FEC_NEXTHOP_CFG_BY_INDEX) {
      ldp_if_find_addr_index(iff, a->index, &addr);
    } else {
      addr = ldp_if_addr_find(iff, &a->address);
    }
  }

  if (addr == NULL) {
    LDP_PRINT(global->user_data, "ldp_cfg_if_addr_set: no such addr\n");
    goto ldp_cfg_if_addr_set_end;
  }

  if (flag & LDP_CFG_DEL) {
    ldp_if_del_addr(global, iff ,addr);
  }

  retval = MPLS_SUCCESS;

ldp_cfg_if_addr_set_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_if_addr_set");

  return retval;
}

/******************* ADJACENCY **********************/

mpls_return_enum ldp_cfg_adj_get(mpls_cfg_handle handle, ldp_adj * a,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_adj *adj = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && a != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_adj_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (ldp_global_find_adj_index(global, a->index, &adj) != MPLS_SUCCESS)
      goto ldp_cfg_adj_get_end;

  if (flag & LDP_ADJ_CFG_REMOTE_TRADDR) {
    memcpy(&a->remote_transport_address, &adj->remote_transport_address,
      sizeof(mpls_inet_addr));
  }
  if (flag & LDP_ADJ_CFG_REMOTE_SRCADDR) {
    memcpy(&a->remote_source_address, &adj->remote_source_address,
      sizeof(mpls_inet_addr));
  }
  if (flag & LDP_ADJ_CFG_REMOTE_LSRADDR) {
    memcpy(&a->remote_lsr_address, &adj->remote_lsr_address,
      sizeof(mpls_inet_addr));
  }
  if (flag & LDP_ADJ_CFG_REMOTE_CSN) {
    a->remote_csn = adj->remote_csn;
  }
  if (flag & LDP_ADJ_CFG_REMOTE_LABELSPACE) {
    a->remote_label_space = adj->remote_label_space;
  }
  if (flag & LDP_ADJ_CFG_REMOTE_HELLOTIME) {
    a->remote_hellotime = adj->remote_hellotime;
  }
  if (flag & LDP_ADJ_CFG_ENTITY_INDEX) {
    a->entity_index = adj->entity ? adj->entity->index : 0;
  }
  if (flag & LDP_ADJ_CFG_REMOTE_SESSION_INDEX) {
    a->session_index = (adj->session) ? (adj->session->index) : 0;
  }
  if (flag & LDP_ADJ_CFG_ROLE) {
    a->role = adj->role;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_adj_get_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_adj_get");

  return retval;
}

mpls_return_enum ldp_cfg_adj_getnext(mpls_cfg_handle handle, ldp_adj * a,
  uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_adj *adj = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_adj_getnext");

  if (a->index == 0) {
    index = 1;
  } else {
    index = a->index + 1;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_adj_index(g, index, &adj))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    a->index = adj->index;
    LDP_EXIT(g->user_data, "ldp_cfg_adj_getnext");
    return ldp_cfg_adj_get(g, a, flag);
  }
  LDP_EXIT(g->user_data, "ldp_cfg_adj_getnext");
  return r;
}

/******************* SESSION **********************/

mpls_return_enum ldp_cfg_session_get(mpls_cfg_handle handle, ldp_session * s,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_session *session = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && s != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_session_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (ldp_global_find_session_index(global, s->index, &session) != MPLS_SUCCESS)
      goto ldp_cfg_session_get_end;

  if (flag & LDP_SESSION_CFG_STATE) {
    s->state = session->state;
  }
  if (flag & LDP_SESSION_CFG_OPER_UP) {
    s->oper_up = session->oper_up;
  }
  if (flag & LDP_SESSION_CFG_MAX_PDU) {
    s->oper_max_pdu = session->oper_max_pdu;
  }
  if (flag & LDP_SESSION_CFG_KEEPALIVE) {
    s->oper_keepalive = session->oper_keepalive;
  }
  if (flag & LDP_SESSION_CFG_PATH_LIMIT) {
    s->oper_path_vector_limit = session->oper_path_vector_limit;
  }
  if (flag & LDP_SESSION_CFG_DIST_MODE) {
    s->oper_distribution_mode = session->oper_distribution_mode;
  }
  if (flag & LDP_SESSION_CFG_LOOP_DETECTION) {
    s->oper_loop_detection = session->oper_loop_detection;
  }
  if (flag & LDP_SESSION_CFG_REMOTE_MAX_PDU) {
    s->remote_max_pdu = session->remote_max_pdu;
  }
  if (flag & LDP_SESSION_CFG_REMOTE_KEEPALIVE) {
    s->remote_keepalive = session->remote_keepalive;
  }
  if (flag & LDP_SESSION_CFG_REMOTE_PATH_LIMIT) {
    s->remote_path_vector_limit = session->remote_path_vector_limit;
  }
  if (flag & LDP_SESSION_CFG_REMOTE_DIST_MODE) {
    s->remote_distribution_mode = session->remote_distribution_mode;
  }
  if (flag & LDP_SESSION_CFG_REMOTE_LOOP_DETECTION) {
    s->remote_loop_detection = session->remote_loop_detection;
  }
  if (flag & LDP_SESSION_CFG_REMOTE_ADDR) {
    s->remote_dest.addr.type = session->remote_dest.addr.type;
    s->remote_dest.addr.u.ipv4 = session->remote_dest.addr.u.ipv4;
  }
  if (flag & LDP_SESSION_CFG_REMOTE_PORT) {
    s->remote_dest.port = session->remote_dest.port;
  }
  if (flag & LDP_SESSION_CFG_LABEL_RESOURCE_STATE_LOCAL) {
    s->no_label_resource_sent = session->no_label_resource_sent;
  }
  if (flag & LDP_SESSION_CFG_LABEL_RESOURCE_STATE_REMOTE) {
    s->no_label_resource_recv = session->no_label_resource_recv;
  }
  if (flag & LDP_SESSION_CFG_ADJ_INDEX) {
    ldp_adj *a = MPLS_LIST_HEAD(&session->adj_root);
    s->adj_index = a ? a->index : 0;
  }
  if (flag & LDP_SESSION_CFG_MESG_TX) {
    s->mesg_tx = session->mesg_tx;
  }
  if (flag & LDP_SESSION_CFG_MESG_RX) {
    s->mesg_rx = session->mesg_rx;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_session_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_session_get");

  return retval;
}

mpls_return_enum ldp_cfg_session_getnext(mpls_cfg_handle handle, ldp_session * s,
  uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_session *ses = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_session_getnext");

  if (s->index == 0) {
    index = 1;
  } else {
    index = s->index + 1;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_session_index(g, index, &ses))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    s->index = ses->index;

    LDP_EXIT(g->user_data, "ldp_cfg_session_getnext");
    return ldp_cfg_session_get(g, s, flag);
  }

  LDP_EXIT(g->user_data, "ldp_cfg_session_getnext");

  return r;
}

mpls_return_enum ldp_cfg_session_adj_getnext(mpls_cfg_handle handle,
  ldp_session * s)
{
  ldp_global *g = (ldp_global *) handle;
  mpls_bool this_one = MPLS_BOOL_FALSE;
  mpls_return_enum r = MPLS_FAILURE;
  ldp_adj *adj_next = NULL;
  ldp_adj *adj = NULL;
  ldp_session *session = NULL;

  LDP_ENTER(g->user_data, "ldp_cfg_session_adj_getnext");

  /* if an adj_index of zero is sent, get the index of
   * the first adj in the list
   */
  if (!s->adj_index) {
    this_one = MPLS_BOOL_TRUE;
  }

  mpls_lock_get(g->global_lock); /* LOCK */

  if (ldp_global_find_session_index(g, s->index, &session) == MPLS_SUCCESS) {
    adj = MPLS_LIST_HEAD(&session->adj_root);
    while (adj) {
      if (this_one == MPLS_BOOL_TRUE) {
        adj_next = adj;
        break;
      }

      /* since the entities are sort in the list ... */
      if (adj->index > s->adj_index) {
        break;
      } else if (adj->index == s->adj_index) {
        this_one = MPLS_BOOL_TRUE;
      }
      adj = MPLS_LIST_NEXT(&session->adj_root, adj, _session);
    }
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (adj_next) {
    s->adj_index = adj_next->index;
    r = MPLS_SUCCESS;
  }

  LDP_EXIT(g->user_data, "ldp_cfg_session_adj_getnext");
  return r;
}

mpls_return_enum ldp_cfg_session_raddr_get(mpls_cfg_handle handle,
  ldp_session * s, ldp_addr * a, uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_session *session = NULL;
  ldp_addr *addr = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && s != NULL && a != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_session_raddr_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (ldp_global_find_session_index(global, s->index, &session) != MPLS_SUCCESS) 
      goto ldp_cfg_session_raddr_get_end;

  if (ldp_session_find_raddr_index(session, a->index, &addr) != MPLS_SUCCESS)
      goto ldp_cfg_session_raddr_get_end;

  if (flag & LDP_SESSION_RADDR_CFG_ADDR) {
    memcpy(&a->address,&addr->address,sizeof(struct mpls_inet_addr));
  }
  if (flag & LDP_SESSION_RADDR_CFG_INDEX) {
    a->index = addr->index;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_session_raddr_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_session_raddr_get");

  return retval;
}

mpls_return_enum ldp_cfg_session_raddr_getnext(mpls_cfg_handle handle,
  ldp_session * s, ldp_addr * a, uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_addr *addr = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  ldp_session *sp = NULL;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_session_raddr_getnext");

  if (a->index == 0) {
    index = 1;
  } else {
    index = a->index + 1;
  }

  r = ldp_global_find_session_index(g, s->index, &sp);
  if (r != MPLS_SUCCESS) {
    return r;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_session_find_raddr_index(sp, index, &addr))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    a->index = addr->index;
    r = ldp_cfg_session_raddr_get(handle, sp, a, flag);
  }

  LDP_EXIT(g->user_data, "ldp_cfg_session_getnext");
  return r;
}

/******************* IN LABEL **********************/

mpls_return_enum ldp_cfg_inlabel_get(mpls_cfg_handle handle, ldp_inlabel * i,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_inlabel *inlabel = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && i != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_inlabel_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (ldp_global_find_inlabel_index(global, i->index, &inlabel) != MPLS_SUCCESS)
      goto ldp_cfg_inlabel_get_end;

  if (flag & LDP_INLABEL_CFG_LABELSPACE) {
    i->info.labelspace = inlabel->info.labelspace;
  }
  if (flag & LDP_INLABEL_CFG_LABEL) {
    memcpy(&i->info.label, &inlabel->info.label, sizeof(mpls_label_struct));
  }
  if (flag & LDP_INLABEL_CFG_OUTLABEL_INDEX) {
    i->outlabel_index = (inlabel->outlabel) ? (inlabel->outlabel->index) : 0;
  }

  retval = MPLS_SUCCESS;

ldp_cfg_inlabel_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_inlabel_get");

  return retval;
}

mpls_return_enum ldp_cfg_inlabel_getnext(mpls_cfg_handle handle, ldp_inlabel * i,
  uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_inlabel *inlabel = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_inlabel_getnext");

  if (i->index == 0) {
    index = 1;
  } else {
    index = i->index + 1;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_inlabel_index(g, index, &inlabel))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    i->index = inlabel->index;

    LDP_EXIT(g->user_data, "ldp_cfg_inlabel_getnext");
    return ldp_cfg_inlabel_get(g, i, flag);
  }

  LDP_EXIT(g->user_data, "ldp_cfg_inlabel_getnext");

  return r;
}

/******************* OUT LABEL **********************/

mpls_return_enum ldp_cfg_outlabel_get(mpls_cfg_handle handle, ldp_outlabel * o,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  ldp_outlabel *outlabel = NULL;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(global !=NULL && o != NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_outlabel_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (ldp_global_find_outlabel_index(global, o->index,
      &outlabel) != MPLS_SUCCESS) goto ldp_cfg_outlabel_get_end;

  if (flag & LDP_OUTLABEL_CFG_NH_INDEX) {
    if (outlabel->nh) {
      o->nh_index = outlabel->nh->index;
    } else {
      o->nh_index = 0;
    }
  }
  if (flag & LDP_OUTLABEL_CFG_SESSION_INDEX) {
    o->session_index = (outlabel->session) ? (outlabel->session->index) : 0;
  }
  if (flag & LDP_OUTLABEL_CFG_LABEL) {
    memcpy(&o->info.label, &outlabel->info.label, sizeof(mpls_label_struct));
  }
  if (flag & LDP_OUTLABEL_CFG_MERGE_COUNT) {
    o->merge_count = outlabel->merge_count;
  }

  retval = MPLS_SUCCESS;

ldp_cfg_outlabel_get_end:
  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_outlabel_get");

  return retval;
}

mpls_return_enum ldp_cfg_outlabel_getnext(mpls_cfg_handle handle,
  ldp_outlabel * o, uint32_t flag)
{
  ldp_global *g = (ldp_global *) handle;
  ldp_outlabel *outlabel = NULL;
  mpls_return_enum r = MPLS_FAILURE;
  mpls_bool done = MPLS_BOOL_FALSE;
  int index;

  LDP_ENTER(g->user_data, "ldp_cfg_outlabel_getnext");

  if (o->index == 0) {
    index = 1;
  } else {
    index = o->index + 1;
  }

  mpls_lock_get(g->global_lock); /* LOCK */
  while (done == MPLS_BOOL_FALSE) {
    switch ((r = ldp_global_find_outlabel_index(g, index, &outlabel))) {
      case MPLS_SUCCESS:
      case MPLS_END_OF_LIST:
        done = MPLS_BOOL_TRUE;
        break;
      case MPLS_FAILURE:
        break;
      default:
        MPLS_ASSERT(0);
    }
    index++;
  }
  mpls_lock_release(g->global_lock); /* UNLOCK */

  if (r == MPLS_SUCCESS) {
    o->index = outlabel->index;

    LDP_EXIT(g->user_data, "ldp_cfg_outlabel_getnext");
    return ldp_cfg_outlabel_get(g, o, flag);
  }

  LDP_EXIT(g->user_data, "ldp_cfg_outlabel_getnext");

  return r;
}

/******************* TUNNEL **********************/

mpls_return_enum ldp_cfg_tunnel_set(mpls_cfg_handle handle, ldp_tunnel * t,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;
  ldp_tunnel *tunnel = NULL;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_tunnel_set");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_CFG_ADD) {
    if (!(tunnel = ldp_tunnel_create())) {
      goto ldp_cfg_tunnel_set_end;
    }
    _ldp_global_add_tunnel(global, tunnel);

    t->index = tunnel->index;
  } else {
    ldp_global_find_tunnel_index(global, t->index, &tunnel);
  }

  if (!tunnel) {
    LDP_PRINT(global->user_data,

      "ldp_cfg_tunnel_set:could not create tunnel\n");
    goto ldp_cfg_tunnel_set_end;
  }

  if ((ldp_tunnel_is_active(tunnel) == MPLS_BOOL_TRUE) &&
    (flag & LDP_TUNNEL_CFG_WHEN_DOWN)) {
    LDP_PRINT(global->user_data, "ldp_cfg_tunnel_set: tunnel is active\n");

    goto ldp_cfg_tunnel_set_end;
  }

  if (flag & LDP_CFG_DEL) {
    if (tunnel->outlabel)
      ldp_tunnel_del_outlabel(tunnel);
    if (tunnel->resource)
      ldp_tunnel_del_resource(tunnel);
    if (tunnel->hop_list)
      ldp_tunnel_del_hop_list(tunnel);
    _ldp_global_del_tunnel(global, tunnel);

    retval = MPLS_SUCCESS;
    goto ldp_cfg_tunnel_set_end;
  }

  if (flag & LDP_TUNNEL_CFG_INGRESS) {
    memcpy(&tunnel->ingress_lsrid, &t->ingress_lsrid, sizeof(ldp_addr));
  }
  if (flag & LDP_TUNNEL_CFG_EGRESS) {
    memcpy(&tunnel->egress_lsrid, &t->egress_lsrid, sizeof(ldp_addr));
  }
  if (flag & LDP_TUNNEL_CFG_NAME) {
    memcpy(&tunnel->name, &t->name, MPLS_MAX_IF_NAME);
  }
  if (flag & LDP_TUNNEL_CFG_IS_IF) {
    tunnel->is_interface = t->is_interface;
  }
  if (flag & LDP_TUNNEL_CFG_OUTLABEL) {
    ldp_outlabel *outlabel = NULL;

    if (t->outlabel_index) {
      ldp_global_find_outlabel_index(global, t->outlabel_index, &outlabel);

      if (!outlabel) {
        goto ldp_cfg_tunnel_set_end;
      }
      ldp_tunnel_add_outlabel(tunnel, outlabel);
    } else {
      ldp_tunnel_del_outlabel(tunnel);
    }
  }
  if (flag & LDP_TUNNEL_CFG_SETUP_PRIO) {
    tunnel->setup_prio = t->setup_prio;
  }
  if (flag & LDP_TUNNEL_CFG_HOLD_PRIO) {
    tunnel->hold_prio = t->hold_prio;
  }
  if (flag & LDP_TUNNEL_CFG_INSTANCE_PRIO) {
    tunnel->instance_prio = t->instance_prio;
  }
  if (flag & LDP_TUNNEL_CFG_LOCAL_PROTECT) {
    tunnel->local_protect = t->local_protect;
  }
  if (flag & LDP_TUNNEL_CFG_RESOURCE_INDEX) {
    ldp_resource *resource = NULL;

    if (t->resource_index) {
      ldp_global_find_resource_index(global, t->resource_index, &resource);

      if (!resource) {
        goto ldp_cfg_tunnel_set_end;
      }
      ldp_tunnel_add_resource(tunnel, resource);
    } else {
      ldp_tunnel_del_resource(tunnel);
    }
  }
  if (flag & LDP_TUNNEL_CFG_HOP_LIST_INDEX) {
    ldp_hop_list *hop_list = NULL;

    if (t->hop_list_index) {
      ldp_global_find_hop_list_index(global, t->hop_list_index, &hop_list);

      if (!hop_list) {
        goto ldp_cfg_tunnel_set_end;
      }
      ldp_tunnel_add_hop_list(tunnel, hop_list);
    } else {
      ldp_tunnel_del_hop_list(tunnel);
    }
  }
  if (flag & LDP_TUNNEL_CFG_FEC) {
    memcpy(&tunnel->fec, &t->fec, sizeof(ldp_fec));
  }
  if (flag & LDP_TUNNEL_CFG_ADMIN_STATE) {
    if (ldp_tunnel_is_active(tunnel) == MPLS_BOOL_TRUE) {
      if (t->admin_state == MPLS_ADMIN_DISABLE) {
        if (ldp_tunnel_shutdown(global, tunnel, 0) == MPLS_FAILURE) {
          goto ldp_cfg_tunnel_set_end;
        }
      }
    } else {
      if (t->admin_state == MPLS_ADMIN_ENABLE) {
        if (ldp_tunnel_is_ready(tunnel) == MPLS_BOOL_TRUE) {
          if (ldp_tunnel_startup(global, tunnel) == MPLS_FAILURE) {
            goto ldp_cfg_tunnel_set_end;
          }
        } else {
          LDP_PRINT(global->user_data,

            "ldp_cfg_tunnel_set: tunnel not ready\n");
          goto ldp_cfg_tunnel_set_end;
        }
      }
    }
  }
  retval = MPLS_SUCCESS;

ldp_cfg_tunnel_set_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_tunnel_set");

  return retval;
}

mpls_return_enum ldp_cfg_tunnel_test(mpls_cfg_handle handle, ldp_tunnel * t,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;
  ldp_tunnel *tunnel = NULL;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_tunnel_test");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_CFG_ADD) {
    retval = MPLS_SUCCESS;
    goto ldp_cfg_tunnel_test_end;
  }

  ldp_global_find_tunnel_index(global, t->index, &tunnel);

  if (!tunnel) {
    goto ldp_cfg_tunnel_test_end;
  }

  if (flag & LDP_TUNNEL_CFG_RESOURCE_INDEX) {
    ldp_resource *resource = NULL;

    if (t->resource_index) {
      ldp_global_find_resource_index(global, t->resource_index, &resource);

      if (!resource) {
        goto ldp_cfg_tunnel_test_end;
      }
    }
  }
  if (flag & LDP_TUNNEL_CFG_HOP_LIST_INDEX) {
    ldp_hop_list *hop_list = NULL;

    if (t->hop_list_index) {
      ldp_global_find_hop_list_index(global, t->hop_list_index, &hop_list);

      if (!hop_list) {
        goto ldp_cfg_tunnel_test_end;
      }
    }
  }
  if (flag & LDP_TUNNEL_CFG_OUTLABEL) {
    ldp_outlabel *outlabel = NULL;

    if (t->outlabel_index) {
      ldp_global_find_outlabel_index(global, t->outlabel_index, &outlabel);

      if (!outlabel) {
        goto ldp_cfg_tunnel_test_end;
      }
    }
  }
  if ((flag & LDP_TUNNEL_CFG_ADMIN_STATE) &&
    (ldp_tunnel_is_active(tunnel) == MPLS_BOOL_FALSE) &&
    (t->admin_state == MPLS_ADMIN_ENABLE) && (ldp_tunnel_is_ready(tunnel) != MPLS_BOOL_TRUE)) {
    goto ldp_cfg_tunnel_test_end;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_tunnel_test_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_tunnel_test");

  return retval;
}

mpls_return_enum ldp_cfg_tunnel_get(mpls_cfg_handle handle, ldp_tunnel * t,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;
  ldp_tunnel *tunnel = NULL;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_tunnel_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  ldp_global_find_tunnel_index(global, t->index, &tunnel);

  if (!tunnel) {
    goto ldp_cfg_tunnel_get_end;
  }
  if (flag & LDP_TUNNEL_CFG_INGRESS) {
    memcpy(&t->ingress_lsrid, &tunnel->ingress_lsrid, sizeof(ldp_addr));
  }
  if (flag & LDP_TUNNEL_CFG_EGRESS) {
    memcpy(&t->egress_lsrid, &tunnel->egress_lsrid, sizeof(ldp_addr));
  }
  if (flag & LDP_TUNNEL_CFG_NAME) {
    memcpy(&t->name, &tunnel->name, MPLS_MAX_IF_NAME);
  }
  if (flag & LDP_TUNNEL_CFG_IS_IF) {
    t->is_interface = tunnel->is_interface;
  }
  if (flag & LDP_TUNNEL_CFG_OUTLABEL) {
    if (tunnel->outlabel) {
      t->outlabel_index = tunnel->outlabel->index;
    } else {
      t->outlabel_index = 0;
    }
  }
  if (flag & LDP_TUNNEL_CFG_SETUP_PRIO) {
    t->setup_prio = tunnel->setup_prio;
  }
  if (flag & LDP_TUNNEL_CFG_HOLD_PRIO) {
    t->hold_prio = tunnel->hold_prio;
  }
  if (flag & LDP_TUNNEL_CFG_INSTANCE_PRIO) {
    tunnel->instance_prio = t->instance_prio;
  }
  if (flag & LDP_TUNNEL_CFG_LOCAL_PROTECT) {
    tunnel->local_protect = t->local_protect;
  }
  if (flag & LDP_TUNNEL_CFG_RESOURCE_INDEX) {
    if (tunnel->resource) {
      t->resource_index = tunnel->resource->index;
    } else {
      t->resource_index = 0;
    }
  }
  if (flag & LDP_TUNNEL_CFG_HOP_LIST_INDEX) {
    if (tunnel->hop_list) {
      t->hop_list_index = tunnel->hop_list->index;
    } else {
      t->hop_list_index = 0;
    }
  }
  if (flag & LDP_TUNNEL_CFG_FEC) {
    memcpy(&t->fec, &tunnel->fec, sizeof(ldp_fec));
  }
  if (flag & LDP_TUNNEL_CFG_ADMIN_STATE) {
    t->admin_state = tunnel->admin_state;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_tunnel_get_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_tunnel_get");

  return retval;
}

/******************* RESOURCE **********************/

mpls_return_enum ldp_cfg_resource_set(mpls_cfg_handle handle, ldp_resource * r,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;
  ldp_resource *resource = NULL;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_resource_set");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_CFG_ADD) {
    resource = ldp_resource_create();
    _ldp_global_add_resource(global, resource);

    r->index = resource->index;
  } else {
    ldp_global_find_resource_index(global, r->index, &resource);
  }

  if (!resource) {
    goto ldp_cfg_resource_set_end;
  }

  if (flag & LDP_RESOURCE_CFG_MAXBPS) {
    resource->max_rate = r->max_rate;
  }
  if (flag & LDP_RESOURCE_CFG_MEANBPS) {
    resource->mean_rate = r->mean_rate;
  }
  if (flag & LDP_RESOURCE_CFG_BURSTSIZE) {
    resource->burst_size = r->burst_size;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_resource_set_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_resource_set");

  return retval;
}

mpls_return_enum ldp_cfg_resource_test(mpls_cfg_handle handle, ldp_resource * r,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;
  ldp_resource *resource = NULL;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_resource_test");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_CFG_ADD) {
    retval = MPLS_SUCCESS;
    goto ldp_cfg_resource_test_end;
  }

  ldp_global_find_resource_index(global, r->index, &resource);

  if (!resource) {
    goto ldp_cfg_resource_test_end;
  }

  if (ldp_resource_in_use(resource) == MPLS_BOOL_TRUE) {
    goto ldp_cfg_resource_test_end;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_resource_test_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_resource_test");

  return retval;
}

mpls_return_enum ldp_cfg_resource_get(mpls_cfg_handle handle, ldp_resource * r,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;
  ldp_resource *resource = NULL;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_resource_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  ldp_global_find_resource_index(global, r->index, &resource);

  if (!resource) {
    goto ldp_cfg_resource_get_end;
  }

  if (flag & LDP_RESOURCE_CFG_MAXBPS) {
    r->max_rate = resource->max_rate;
  }
  if (flag & LDP_RESOURCE_CFG_MEANBPS) {
    r->mean_rate = resource->mean_rate;
  }
  if (flag & LDP_RESOURCE_CFG_BURSTSIZE) {
    r->burst_size = resource->burst_size;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_resource_get_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_resource_get");

  return retval;
}

/******************* HOP **********************/

mpls_return_enum ldp_cfg_hop_set(mpls_cfg_handle handle, ldp_hop * h,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;
  ldp_hop_list *hop_list = NULL;
  ldp_hop *hop = NULL;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_hop_set");

  if (!h->hop_list_index && !h->index) {
    return retval;
  }

  mpls_lock_get(global->global_lock); /* LOCK */

  ldp_global_find_hop_list_index(global, h->hop_list_index, &hop_list);

  if (!hop_list) {
    if (flag & LDP_CFG_ADD) {
      if (!(hop_list = ldp_hop_list_create())) {
        goto ldp_cfg_hop_set_end;
      }
      _ldp_global_add_hop_list(global, hop_list);

      h->hop_list_index = hop_list->index;
    } else {
      goto ldp_cfg_hop_set_end;
    }
  }

  ldp_hop_list_find_hop_index(hop_list, h->index, &hop);
  if (!hop) {
    if (h->index && (flag & LDP_CFG_ADD)) {
      if (!(hop = ldp_hop_create())) {
        goto ldp_cfg_hop_set_end;
      }
      hop->index = h->index;
      ldp_hop_list_add_hop(hop_list, hop);
    } else {
      goto ldp_cfg_hop_set_end;
    }
  }

  if (flag & LDP_HOP_CFG_PATH_OPTION) {
    hop->path_option = h->path_option;
  }
  if (flag & LDP_HOP_CFG_ADDR) {
    memcpy(&hop->addr, &h->addr, sizeof(ldp_addr));
  }
  if (flag & LDP_HOP_CFG_TYPE) {
    hop->type = h->type;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_hop_set_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_hop_set");

  return retval;
}

mpls_return_enum ldp_cfg_hop_test(mpls_cfg_handle handle, ldp_hop * h,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;
  ldp_hop_list *hop_list = NULL;
  ldp_hop *hop = NULL;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_hop_test");

  mpls_lock_get(global->global_lock); /* LOCK */

  if (flag & LDP_CFG_ADD) {
    retval = MPLS_SUCCESS;
    goto ldp_cfg_hop_test_end;
  }

  ldp_global_find_hop_list_index(global, h->hop_list_index, &hop_list);

  if (!hop_list) {
    goto ldp_cfg_hop_test_end;
  }

  ldp_hop_list_find_hop_index(hop_list, h->index, &hop);
  if (!hop) {
    goto ldp_cfg_hop_test_end;
  }

  if (ldp_hop_in_use(hop) == MPLS_BOOL_TRUE) {
    goto ldp_cfg_hop_test_end;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_hop_test_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_hop_test");

  return retval;
}

mpls_return_enum ldp_cfg_hop_get(mpls_cfg_handle handle, ldp_hop * h,
  uint32_t flag)
{
  ldp_global *global = (ldp_global *) handle;
  mpls_return_enum retval = MPLS_FAILURE;
  ldp_hop_list *hop_list = NULL;
  ldp_hop *hop = NULL;

  MPLS_ASSERT(global !=NULL);

  LDP_ENTER(global->user_data, "ldp_cfg_hop_get");

  mpls_lock_get(global->global_lock); /* LOCK */

  ldp_global_find_hop_list_index(global, h->hop_list_index, &hop_list);

  if (!hop_list) {
    goto ldp_cfg_hop_get_end;
  }

  ldp_hop_list_find_hop_index(hop_list, h->index, &hop);
  if (!hop) {
    goto ldp_cfg_hop_get_end;
  }

  if (flag & LDP_HOP_CFG_PATH_OPTION) {
    h->path_option = hop->path_option;
  }
  if (flag & LDP_HOP_CFG_ADDR) {
    memcpy(&h->addr, &hop->addr, sizeof(ldp_addr));
  }
  if (flag & LDP_HOP_CFG_TYPE) {
    h->type = hop->type;
  }
  retval = MPLS_SUCCESS;

ldp_cfg_hop_get_end:

  mpls_lock_release(global->global_lock); /* UNLOCK */

  LDP_EXIT(global->user_data, "ldp_cfg_hop_get");

  return retval;
}
