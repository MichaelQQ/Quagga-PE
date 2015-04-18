#ifndef LDP_REMOTE_PEER_H
#define LDP_REMOTE_PEER_H

#include "ldp_struct.h"

struct ldp_remote_peer {
    struct ldp *ldp;
    ldp_entity entity;
    ldp_peer peer;
    mpls_bool admin_up;
};

struct ldp_remote_peer *ldp_remote_peer_find(struct ldp*, struct mpls_dest*);
struct ldp_remote_peer *ldp_remote_peer_new(struct ldp *ldp);
void ldp_remote_peer_free(struct ldp_remote_peer *rp);

void ldp_remote_peer_up(struct ldp_remote_peer *rp);
void ldp_remote_peer_down(struct ldp_remote_peer *rp);

int ldp_remote_peer_startup(struct ldp_remote_peer *rp);
int ldp_remote_peer_shutdown(struct ldp_remote_peer *rp);

void ldp_remote_peer_create(struct ldp_remote_peer*, struct mpls_dest*);
void ldp_remote_peer_delete(struct ldp_remote_peer *rp);
int ldp_remote_peer_admin_state_start(struct ldp_remote_peer *rp);
int ldp_remote_peer_admin_state_finish(struct ldp_remote_peer *rp);

#endif
