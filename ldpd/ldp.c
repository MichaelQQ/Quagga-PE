#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "thread.h"
#include "prefix.h"
#include "table.h"
#include "linklist.h"
#include "filter.h"
#include "vty.h"
#include "plist.h"

#include "ldp.h"
#include "ldp_cfg.h"
#include "ldp_struct.h"
#include "ldp_interface.h"
#include "ldp_zebra.h"

#include "impl_fib.h"

int ldp_shutdown(struct ldp *ldp) {
  ldp_global g;

  g.admin_state = MPLS_ADMIN_DISABLE;
  return ldp_cfg_global_set(ldp->h,&g,LDP_GLOBAL_CFG_ADMIN_STATE);
}

int ldp_startup(struct ldp *ldp) {
  ldp_global g;

  g.admin_state = MPLS_ADMIN_ENABLE;
  return ldp_cfg_global_set(ldp->h,&g,LDP_GLOBAL_CFG_ADMIN_STATE);
}

int ldp_admin_state_start(struct ldp *ldp) {
  if (ldp->admin_up == MPLS_BOOL_TRUE) {
    return ldp_shutdown(ldp);
  }
  return MPLS_SUCCESS;
}

int ldp_admin_state_finish(struct ldp *ldp) {
  if (ldp->admin_up == MPLS_BOOL_TRUE) {
    return ldp_startup(ldp);
  }
  return MPLS_SUCCESS;
}

int do_ldp_router_id_update(struct ldp *ldp, unsigned int router_id) {
    ldp_global g;
    g.lsr_identifier.type = MPLS_FAMILY_IPV4;
    g.lsr_identifier.u.ipv4 = router_id;
    g.transport_address.type = MPLS_FAMILY_IPV4;
    g.transport_address.u.ipv4 = router_id;
    return ldp_cfg_global_set(ldp->h,&g,
	LDP_GLOBAL_CFG_LSR_IDENTIFIER|LDP_GLOBAL_CFG_TRANS_ADDR);
}

int ldp_router_id_update(struct ldp *ldp, struct prefix *router_id) {

  zlog_info("router-id update %s", inet_ntoa(router_id->u.prefix4));

  if (!ldp->lsr_id_is_static) {
    ldp_admin_state_start(ldp);

    do_ldp_router_id_update(ldp, ntohl(router_id->u.prefix4.s_addr));

    ldp_admin_state_finish(ldp);
  }
  return 0;
}

/* LDP instance top. */
struct ldp *ldp_top = NULL;

struct ldp *ldp_new(void) {
    struct ldp *new = XMALLOC(MTYPE_LDP, sizeof(struct ldp));
    ldp_global g;
    struct route_node *rn;

    struct interface *ifp;
    struct connected *c;
    struct listnode *node, *cnode;
    struct ldp_interface *li;
    struct ldp_addr addr;
    struct prefix *p;

    memset(new,0,sizeof(*new));

    new->h = ldp_cfg_open(new);
    new->admin_up = MPLS_BOOL_TRUE;
    new->lsr_id_is_static = 0;

    new->egress = LDP_EGRESS_CONNECTED;
    new->address = LDP_ADDRESS_ALL;
    new->peer_list = list_new();

    ldp_top = new;

    do_ldp_router_id_update(new, ntohl(router_id.u.prefix4.s_addr));
    g.admin_state = MPLS_ADMIN_ENABLE;

    ldp_cfg_global_set(new->h,&g, LDP_GLOBAL_CFG_LSR_HANDLE|
	LDP_GLOBAL_CFG_ADMIN_STATE);

    for (node = listhead(iflist); node; listnextnode(node)) {
        ifp = listgetdata(node);
        MPLS_ASSERT(ifp->info);
	li = ifp->info;

        ldp_interface_create(li);

	for (cnode = listhead (ifp->connected); cnode; listnextnode (cnode)) {
	    c = listgetdata (cnode);
	    p = c->address;
	    if (p->family == AF_INET) {
		prefix2mpls_inet_addr(p, &addr.address);
		ldp_cfg_if_addr_set(new->h, &li->iff, &addr, LDP_CFG_ADD);
	    }
	}
    }

    rn = route_top(table);
    while (rn) {
      if (rn->info) {
        struct mpls_node *mn;
        struct listnode* ln;
        struct mpls_nh *nh;
        mpls_fec fec;

        zebra_prefix2mpls_fec(&rn->p, &fec);
        mn = rn->info;
	for (ALL_LIST_ELEMENTS_RO (mn->list, ln, nh)) {
          mpls_nexthop nexthop;
          memcpy(&nexthop, &nh->info, sizeof(struct mpls_nexthop));
          ldp_add_ipv4(new, &fec, &nexthop);
        }
      }
      rn = route_next2(rn);
    }
    return new;
}

struct ldp *ldp_get() {
    if (ldp_top) {
	return ldp_top;
    }
    return NULL;
}

void ldp_finish(struct ldp *ldp) {
    struct ldp_interface *li;
    struct interface *ifp;
    struct listnode *node;

    ldp_admin_state_start(ldp);

#if 0
    rn = route_top(table);
    while (rn) {
      if (rn->info) {
        mpls_fec fec;
                                                                                
        zebra_prefix2mpls_fec(&rn->p, &fec);
	ldp_cfg_fec_get(ldp->h, &fec, 0);
	ldp_cfg_fec_set(ldp->h, &fec, LDP_FEC_CFG_BY_INDEX|LDP_CFG_DEL);
      }
      rn = route_next2(rn);
    }
#endif

    ldp_cfg_close(ldp->h);
    list_free(ldp->peer_list);

    XFREE(MTYPE_LDP,ldp);

    ldp_top = NULL;

    /* it is key that ldp_interface_delete is called _after_ we
     * set ldp_top to NULL.  This is so the check for ldp fails
     * and we do not try and send config changes into ldp */
    for (node = listhead(iflist); node; listnextnode(node)) {
        ifp = listgetdata(node);
        li = (struct ldp_interface*)ifp->info;
        if (li) {
            ldp_interface_delete(li);
        }
#if 0
        if (li->l2cc && li->l2cc->l2cc.index) {
            l2cc_interface_delete(li);
        }
#endif
    }

}

int ldp_add_ipv4(struct ldp *ldp, mpls_fec *fec,
    mpls_nexthop *nexthop) {
    if (ldp_cfg_fec_get(ldp->h, fec, 0) != MPLS_SUCCESS) {
	if (ldp_cfg_fec_set(ldp->h, fec, LDP_CFG_ADD) != MPLS_SUCCESS) {
	    MPLS_ASSERT(0);
	}
    }

    if (ldp_cfg_fec_nexthop_get(ldp->h, fec, nexthop,
	LDP_FEC_CFG_BY_INDEX) != MPLS_SUCCESS) {
	if (ldp_cfg_fec_nexthop_set(ldp->h, fec, nexthop,
	    LDP_CFG_ADD|LDP_FEC_CFG_BY_INDEX) != MPLS_SUCCESS) {
	    MPLS_ASSERT(0);
	}
    } else {
	MPLS_ASSERT(0);
    }
    return 0;
}

int ldp_delete_ipv4(struct ldp *ldp, mpls_fec *fec,
    mpls_nexthop *nexthop) {
    if (ldp_cfg_fec_get(ldp->h, fec, 0) == MPLS_SUCCESS) {
	if (ldp_cfg_fec_nexthop_get(ldp->h, fec, nexthop,
	    LDP_FEC_CFG_BY_INDEX) == MPLS_SUCCESS) {
	    if (ldp_cfg_fec_nexthop_set(ldp->h, fec, nexthop,
		LDP_FEC_CFG_BY_INDEX|LDP_CFG_DEL|
		LDP_FEC_NEXTHOP_CFG_BY_INDEX) != MPLS_SUCCESS) {
		MPLS_ASSERT(0);
	    }
	} else {
	    MPLS_ASSERT(0);
	}
    } else {
	//MPLS_ASSERT(0); //mark by here
	return 0;//add by here
    }
    return 0;
}

#if 0
/* Update access-list list. */
void mpls_access_list_update(struct access_list *access) {
}

/* Update prefix-list list. */
void mpls_prefix_list_update(struct prefix_list *plist) {
}
#endif

void ldp_init() {

#if 0
    access_list_init();
    access_list_add_hook(mpls_access_list_update);
    access_list_delete_hook(mpls_access_list_update);
#endif

}
