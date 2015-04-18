#ifndef LDP_H
#define LDP_H

#include <zebra.h>
#include "sockunion.h"
#include "prefix.h"
#include "zclient.h"
#include "linklist.h"
#include "if.h"

#include "ldp_struct.h"

#define LDP_DEFAULT_CONFIG "ldpd.conf"
#define LDP_VTY_PORT                2610

typedef enum {
    LDP_EGRESS_ALL,
    LDP_EGRESS_LSRID,
    LDP_EGRESS_CONNECTED
} ldp_egress_mode;

typedef enum {
    LDP_ADDRESS_ALL,
    LDP_ADDRESS_LSRID,
    LDP_ADDRESS_LDP
} ldp_address_mode;

struct ldp {
    struct list *peer_list;
    mpls_cfg_handle h;
    mpls_bool admin_up;
    mpls_bool lsr_id_is_static;
    ldp_egress_mode egress;
    ldp_address_mode address;
};

struct ldp *ldp_get();
struct ldp *ldp_new();
void ldp_init();
int ldp_router_id_update(struct ldp *ldp, struct prefix *router_id);
int do_ldp_router_id_update(struct ldp *ldp, unsigned int router_id);
void ldp_finish(struct ldp *ldp);

int ldp_admin_state_start(struct ldp *ldp);
int ldp_admin_state_finish(struct ldp *ldp);
int ldp_add_ipv4(struct ldp *ldp, mpls_fec *fec, mpls_nexthop *nexthop);
int ldp_delete_ipv4(struct ldp *ldp, mpls_fec *fec, mpls_nexthop *nexthop);

#endif
