#ifndef L2CC_IF_H
#define L2CC_IF_H

#include "ldp_struct.h"

struct ldp_interface;

struct l2cc_interface {
    struct ldp_interface *mi;
    mpls_fec l2cc;
    mpls_bool admin_up;
    mpls_bool create_on_hold;
};

struct l2cc_interface *l2cc_if_new(struct ldp_interface *mi);
void l2cc_if_free(struct l2cc_interface *li);

void l2cc_if_up(struct ldp_interface *mi);
void l2cc_if_down(struct ldp_interface *mi);

int l2cc_interface_startup(struct ldp_interface *mi);
int l2cc_interface_shutdown(struct ldp_interface *mi);

void l2cc_interface_create(struct ldp_interface *mi);
void l2cc_interface_delete(struct ldp_interface *mi);
int l2cc_interface_admin_state_start(struct ldp_interface *mi);
int l2cc_interface_admin_state_finish(struct ldp_interface *mi);

#endif
