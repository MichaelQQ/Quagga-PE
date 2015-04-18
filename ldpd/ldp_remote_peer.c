#include <zebra.h>
#include "memory.h"

#include "ldp.h"
#include "ldp_cfg.h"
#include "ldp_struct.h"
#include "mpls_compare.h"
#include "ldp_remote_peer.h"

struct ldp_remote_peer *ldp_remote_peer_find(struct ldp *ldp,
	struct mpls_dest *dest) {
  	struct ldp_remote_peer *rp;
  	struct listnode *ln;

  	for (ALL_LIST_ELEMENTS_RO (ldp->peer_list, ln, rp)) {
    		rp->peer.dest.if_handle = 0;
    		dest->if_handle = 0;
    		if (!mpls_dest_compare(&rp->peer.dest,dest)) {
      			return rp;
    		}
  	}
  	return NULL;
}

struct ldp_remote_peer *ldp_remote_peer_new(struct ldp *ldp) {
    struct ldp_remote_peer *rp;

    rp = XMALLOC(MTYPE_LDP, sizeof(struct ldp_remote_peer));
    memset(rp, 0, sizeof(struct ldp_remote_peer));
    rp->ldp = ldp;

    rp->admin_up = MPLS_BOOL_TRUE;
    ldp_entity_set_defaults(&rp->entity);

    return rp;
}

void ldp_remote_peer_free(struct ldp_remote_peer *rp) {
    XFREE(MTYPE_LDP, rp);
}

void ldp_remote_peer_create(struct ldp_remote_peer *rp,
  struct mpls_dest *dest) {
    struct in_addr addr;
    char *dest_name;

    addr.s_addr = htonl(dest->addr.u.ipv4);
    dest_name = inet_ntoa(addr);
    strncpy(rp->peer.peer_name,dest_name,IFNAMSIZ);
    rp->peer.label_space = 0;
    memcpy(&rp->peer.dest,dest,sizeof(struct mpls_dest));

    ldp_cfg_peer_set(rp->ldp->h, &rp->peer, LDP_CFG_ADD |
      LDP_IF_CFG_LABEL_SPACE | LDP_PEER_CFG_DEST_ADDR | LDP_PEER_CFG_PEER_NAME);

    rp->entity.sub_index = rp->peer.index;
    rp->entity.entity_type = LDP_INDIRECT;
    rp->entity.admin_state = MPLS_OPER_DOWN;
    rp->entity.transport_address.type = MPLS_FAMILY_NONE;

    ldp_cfg_entity_set(rp->ldp->h, &rp->entity,
	LDP_CFG_ADD | LDP_ENTITY_CFG_SUB_INDEX |
	LDP_ENTITY_CFG_ADMIN_STATE | LDP_ENTITY_CFG_TRANS_ADDR);

    ldp_cfg_entity_get(rp->ldp->h, &rp->entity, 0xFFFFFFFF);
    ldp_cfg_peer_get(rp->ldp->h, &rp->peer, 0xFFFFFFFF);

    ldp_remote_peer_admin_state_finish(rp);
}

void ldp_remote_peer_delete(struct ldp_remote_peer *rp) {
    rp->entity.admin_state = MPLS_OPER_DOWN;

    if (rp->ldp) {
	ldp_remote_peer_admin_state_start(rp);
	ldp_cfg_entity_set(rp->ldp->h, &rp->entity, LDP_CFG_DEL);
	ldp_cfg_peer_set(rp->ldp->h, &rp->peer, LDP_CFG_DEL);
    }
    rp->entity.index = 0;
    rp->peer.index = 0;
}

int ldp_remote_peer_startup(struct ldp_remote_peer *rp) {
    if (!rp->peer.index) {
	return MPLS_FAILURE;
    }

    rp->entity.admin_state = MPLS_OPER_UP;
    ldp_cfg_entity_set(rp->ldp->h, &rp->entity, LDP_ENTITY_CFG_ADMIN_STATE);

    return MPLS_SUCCESS;
}

int ldp_remote_peer_shutdown(struct ldp_remote_peer *rp) {
    if (!rp->peer.index) {
	return MPLS_FAILURE;
    }

    rp->entity.admin_state = MPLS_ADMIN_DISABLE;
    ldp_cfg_entity_set(rp->ldp->h, &rp->entity, LDP_ENTITY_CFG_ADMIN_STATE);

    return MPLS_SUCCESS;
}

int ldp_remote_peer_admin_state_start(struct ldp_remote_peer *rp) {
  if (rp->admin_up == MPLS_BOOL_TRUE) {
    return ldp_remote_peer_shutdown(rp);
  }
  return MPLS_SUCCESS;
}

int ldp_remote_peer_admin_state_finish(struct ldp_remote_peer *rp) {
  if (rp->admin_up == MPLS_BOOL_TRUE) {
    return ldp_remote_peer_startup(rp);
  }
  return MPLS_SUCCESS;
}

void ldp_remote_peer_up(struct ldp_remote_peer *rp) {
    if (rp->ldp && rp->admin_up == MPLS_BOOL_TRUE) {
	ldp_remote_peer_startup(rp);
    }
}

void ldp_remote_peer_down(struct ldp_remote_peer *rp) {
    if (rp->ldp && rp->admin_up == MPLS_BOOL_TRUE) {
	ldp_remote_peer_shutdown(rp);
    }
}
