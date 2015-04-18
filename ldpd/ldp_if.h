
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_IF_H_
#define _LDP_IF_H_

#include "ldp_struct.h"

extern ldp_if *ldp_if_create(ldp_global *g);
extern void ldp_if_delete(ldp_global *g, ldp_if * i);
extern ldp_if *ldp_if_insert(ldp_global *g, mpls_if_handle handle);
extern void ldp_if_remove(ldp_global *g, ldp_if *iff);
extern void ldp_if_add_nexthop(ldp_if * i, ldp_nexthop * n);
extern void ldp_if_del_nexthop(ldp_global *g, ldp_if * i, ldp_nexthop * n);
extern ldp_addr *ldp_if_addr_find(ldp_if *i, mpls_inet_addr *a);
extern mpls_return_enum ldp_if_find_addr_index(ldp_if *i, int index,
    ldp_addr **a);
extern void ldp_if_del_addr(ldp_global *g, ldp_if * i, ldp_addr * a);
extern void ldp_if_add_addr(ldp_if * i, ldp_addr * a);
extern mpls_return_enum ldp_if_startup(ldp_global * g, ldp_if * i);
extern mpls_return_enum ldp_if_shutdown(ldp_global * g, ldp_if * i);
extern mpls_bool ldp_if_is_active(ldp_if * i);
extern mpls_return_enum _ldp_if_add_entity(ldp_if * i, ldp_entity * e);
extern ldp_entity *ldp_if_get_entity(ldp_if * i);
extern mpls_return_enum _ldp_if_del_entity(ldp_if * i);
extern uint32_t _ldp_if_get_next_index();

#endif
