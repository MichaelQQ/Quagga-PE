#ifndef LDP_IF_H
#define LDP_IF_H

#include <zebra.h>
                                                                                
#include "if.h"
#include "command.h"
#include "prefix.h"
#include "zclient.h"

#include "ldp_struct.h"
#include "l2cc_interface.h"

struct ldp_interface {
    struct interface *ifp;
    struct connected *connected;
    struct l2cc_interface *l2cc;

    ldp_entity entity;
    ldp_if iff;
    mpls_bool configured;
    mpls_bool admin_up;
    mpls_bool create_on_hold;
    int labelspace;
};

struct ldp_interface *ldp_interface_new(struct interface *ifp);
void ldp_interface_free(struct ldp_interface *li);

void ldp_interface_up(struct ldp_interface *li);
void ldp_interface_down(struct ldp_interface *li);

int ldp_interface_startup(struct ldp_interface *li);
int ldp_interface_shutdown(struct ldp_interface *li);

int ldp_interface_create(struct ldp_interface *li);
void ldp_interface_delete(struct ldp_interface *li);
int ldp_interface_admin_state_start(struct ldp_interface *li);
int ldp_interface_admin_state_finish(struct ldp_interface *li);
int ldp_interface_is_up(struct ldp_interface *li);

void ldp_interface_init();

#endif
