
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_ENTITY_H_
#define _LDP_ENTITY_H_

#include "ldp_struct.h"

extern void ldp_entity_set_defaults(ldp_entity *e);
extern ldp_entity *ldp_entity_create();
extern void ldp_entity_delete(ldp_entity * e);
extern mpls_bool ldp_entity_is_active(ldp_entity * e);
extern mpls_bool ldp_entity_is_ready(ldp_entity * e);
extern int ldp_entity_label_space(ldp_entity * e);
extern ldp_mesg *ldp_entity_get_message(ldp_entity * e);

extern mpls_return_enum ldp_entity_startup(ldp_global * g, ldp_entity * e);
extern mpls_return_enum ldp_entity_shutdown(ldp_global * g, ldp_entity * e,
  int flag);

extern void ldp_entity_register(ldp_global * g, ldp_entity * e);
extern void ldp_entity_unregister(ldp_global * g, ldp_entity * e);

extern void ldp_entity_add_if(ldp_entity * e, ldp_if * i);
extern void ldp_entity_del_if(ldp_global * g, ldp_entity * e);

extern void ldp_entity_add_peer(ldp_entity * e, ldp_peer * p);
extern void ldp_entity_del_peer(ldp_entity * e);

extern void ldp_entity_add_adj(ldp_entity * e, ldp_adj * a);
extern void ldp_entity_del_adj(ldp_entity * e, ldp_adj * a);
extern ldp_adj *ldp_entity_find_adj(ldp_entity * e, ldp_mesg * msg);

extern mpls_return_enum ldp_entity_set_admin_state(ldp_global * g,
  ldp_entity * e, mpls_admin_state_enum state);

extern uint32_t _ldp_entity_get_next_index();

#endif
