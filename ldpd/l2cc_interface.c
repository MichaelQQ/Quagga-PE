#include <zebra.h>
#include "memory.h"

#include "ldp.h"
#include "ldp_cfg.h"
#include "ldp_struct.h"

#include "ldp_interface.h"

struct l2cc_interface *l2cc_if_new(struct ldp_interface *mi) {
    struct l2cc_interface *li;

    li = XMALLOC(MTYPE_LDP, sizeof(struct l2cc_interface));
    memset(li, 0, sizeof(struct l2cc_interface));
    li->mi = mi;

    li->admin_up = MPLS_BOOL_TRUE;
    li->create_on_hold = MPLS_BOOL_FALSE;

    return li;
}

void l2cc_if_free(struct l2cc_interface *li) {
    XFREE(MTYPE_LDP, li);
}

void l2cc_interface_create(struct ldp_interface *mi) {
    struct ldp *ldp = ldp_get();

    mi->l2cc->create_on_hold = MPLS_BOOL_FALSE;

    ldp_cfg_fec_set(ldp->h, &mi->l2cc->l2cc, LDP_CFG_ADD);
    ldp_cfg_fec_get(ldp->h, &mi->l2cc->l2cc, 0xFFFFFFFF);

    l2cc_interface_admin_state_finish(mi);
}

void l2cc_interface_delete(struct ldp_interface *mi) {
    struct ldp *ldp = ldp_get();

    mi->l2cc->create_on_hold = MPLS_BOOL_TRUE;

    if (ldp) {
	l2cc_interface_admin_state_start(mi);
	ldp_cfg_fec_set(ldp->h, &mi->l2cc->l2cc, LDP_CFG_DEL);
    }
    mi->l2cc->l2cc.index = 0;
}

int l2cc_interface_startup(struct ldp_interface *mi) {
    struct ldp *ldp = ldp_get();

    if (!mi->l2cc->l2cc.index) {
	return MPLS_FAILURE;
    }

    ldp_cfg_fec_set(ldp->h, &mi->l2cc->l2cc, LDP_CFG_ADD);

    return MPLS_SUCCESS;
}

int l2cc_interface_shutdown(struct ldp_interface *mi) {
    struct ldp *ldp = ldp_get();

    if (!mi->l2cc->l2cc.index) {
	return MPLS_FAILURE;
    }

    ldp_cfg_fec_set(ldp->h, &mi->l2cc->l2cc, LDP_CFG_DEL);

    return MPLS_SUCCESS;
}

int l2cc_interface_admin_state_start(struct ldp_interface *mi) {
  if (mi->l2cc->admin_up == MPLS_BOOL_TRUE && ldp_interface_is_up(mi)) {
    return l2cc_interface_shutdown(mi);
  }
  return MPLS_SUCCESS;
}

int l2cc_interface_admin_state_finish(struct ldp_interface *mi) {
  if (mi->l2cc->admin_up == MPLS_BOOL_TRUE && ldp_interface_is_up(mi)) {
    return l2cc_interface_startup(mi);
  }
  return MPLS_SUCCESS;
}

void l2cc_if_up(struct ldp_interface *mi) {
    if (mi->l2cc && mi->l2cc->admin_up == MPLS_BOOL_TRUE) {
	l2cc_interface_startup(mi);
    }
}

void l2cc_if_down(struct ldp_interface *mi) {
    if (mi->l2cc && mi->l2cc->admin_up == MPLS_BOOL_TRUE) {
	l2cc_interface_shutdown(mi);
    }
}
