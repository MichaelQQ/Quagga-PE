
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_ADDR_H_
#define _LDP_ADDR_H_

#include "ldp_struct.h"

extern ldp_addr *ldp_addr_find(ldp_global *g, mpls_inet_addr * address);
extern mpls_return_enum ldp_addr_insert2(ldp_global *g, ldp_addr *addr);
extern ldp_addr *ldp_addr_insert(ldp_global *g, mpls_inet_addr * address);
extern void ldp_addr_remove(ldp_global *g, mpls_inet_addr * address);
extern ldp_addr *ldp_addr_create(ldp_global *g, mpls_inet_addr * inet);
extern void ldp_addr_delete(ldp_global *g, ldp_addr * a);
extern void ldp_addr_add_if(ldp_addr * a, ldp_if * i);
extern void ldp_addr_del_if(ldp_global *g, ldp_addr * a);
extern mpls_bool ldp_addr_is_empty(ldp_addr *a);
extern mpls_return_enum _ldp_addr_add_session(ldp_addr * a, ldp_session * s);
extern void _ldp_addr_del_session(ldp_addr * a, ldp_session * s);
extern void ldp_addr_add_nexthop(ldp_addr * a, ldp_nexthop * nh);
extern void ldp_addr_del_nexthop(ldp_global *g, ldp_addr * a, ldp_nexthop * nh);
extern uint32_t _ldp_addr_get_next_index();

extern void ldp_addr_mesg_prepare(ldp_mesg * msg, ldp_global * g,
  uint32_t msgid, mpls_inet_addr * a);

extern mpls_return_enum ldp_addr_send(ldp_global * g, ldp_session * s,
  mpls_inet_addr * a);
extern mpls_return_enum ldp_waddr_send(ldp_global * g, ldp_session * s,
  mpls_inet_addr * a);
extern mpls_return_enum ldp_addr_process(ldp_global * g, ldp_session * s,
  ldp_entity * e, ldp_mesg * msg);

#endif
