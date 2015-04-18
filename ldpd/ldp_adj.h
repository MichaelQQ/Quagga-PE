
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_ADJ_H_
#define _LDP_ADJ_H_

#include "ldp_struct.h"

extern ldp_adj *ldp_adj_create(mpls_inet_addr * source,
  mpls_inet_addr * lsraddr, int labelspace, int remote_hellotime,
  mpls_inet_addr * remote_transport_address, uint32_t remote_csn);

extern void ldp_adj_delete(ldp_adj * a);
extern mpls_return_enum ldp_adj_startup(ldp_global * g, ldp_adj * a,
  int request);
extern mpls_return_enum ldp_adj_restart(ldp_global * g, ldp_adj * a);
extern mpls_return_enum ldp_adj_shutdown(ldp_global * g, ldp_adj * a);
extern mpls_return_enum ldp_adj_maintain_timer(ldp_global * g, ldp_adj * a);
extern mpls_return_enum ldp_adj_recv_stop(ldp_global * g, ldp_adj * a);

extern void _ldp_adj_add_entity(ldp_adj * a, ldp_entity * e);
extern void _ldp_adj_del_entity(ldp_adj * a, ldp_entity * e);
extern void ldp_adj_add_session(ldp_adj * a, ldp_session * s);
extern void ldp_adj_del_session(ldp_adj * a, ldp_session * s);
extern uint32_t _ldp_adj_get_next_index();

#endif
