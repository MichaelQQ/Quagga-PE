
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_SESSION_H_
#define _LDP_SESSION_H_

#include "ldp_struct.h"

extern mpls_return_enum ldp_session_backoff_start(ldp_global * g,
  ldp_session * s);
extern mpls_return_enum ldp_session_backoff_stop(ldp_global * g,
  ldp_session * s);
extern mpls_return_enum ldp_session_create_active(ldp_global * g, ldp_adj * a);
extern ldp_session *ldp_session_create_passive(ldp_global * g,
  mpls_socket_handle socket, mpls_dest * from);
extern ldp_session *ldp_session_create();
extern void ldp_session_delete(ldp_session * s);
extern mpls_return_enum ldp_session_startup(ldp_global * g, ldp_session * s);
extern void ldp_session_shutdown(ldp_global * g, ldp_session * s, mpls_bool);

extern void _ldp_session_add_attr(ldp_session * s, ldp_attr * a);
extern void _ldp_session_del_attr(ldp_session * s, ldp_attr * a);

extern void ldp_session_add_outlabel(ldp_session * s, ldp_outlabel * o);
extern void ldp_session_del_outlabel(ldp_session * s, ldp_outlabel * o);

extern mpls_return_enum ldp_session_add_inlabel(ldp_session * s,
  ldp_inlabel * i);
extern void ldp_session_del_inlabel(ldp_session * s, ldp_inlabel * i);

extern mpls_return_enum ldp_session_add_addr(ldp_global *g, ldp_session * s, ldp_addr * a);
extern void ldp_session_del_addr(ldp_global *g, ldp_session * s, ldp_addr * a);

extern void _ldp_session_add_adj(ldp_session * s, ldp_adj * a);
extern void _ldp_session_del_adj(ldp_session * s, ldp_adj * a);

extern uint32_t _ldp_session_get_next_index();
extern mpls_return_enum ldp_session_maintain_timer(ldp_global * g,
  ldp_session * s, int flag);

extern mpls_return_enum ldp_session_find_raddr_index(ldp_session * s,
  uint32_t index, ldp_addr ** addr);

extern ldp_session *ldp_session_for_nexthop(ldp_nexthop *nh);

#endif
