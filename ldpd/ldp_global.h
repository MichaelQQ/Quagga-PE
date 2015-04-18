
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_GLOBAL_H_
#define _LDP_GLOBAL_H_

#include "ldp_struct.h"

extern ldp_global *ldp_global_create(mpls_instance_handle data);
extern mpls_return_enum ldp_global_delete(ldp_global * g);
extern mpls_return_enum ldp_global_startup(ldp_global * g);
extern mpls_return_enum ldp_global_shutdown(ldp_global * g);

extern ldp_peer *ldp_global_find_peer_addr(ldp_global * g,
  mpls_inet_addr * addr);
extern ldp_if *ldp_global_find_if_handle(ldp_global * g, mpls_if_handle handle);
extern ldp_adj *ldp_global_find_adj_ldpid(ldp_global * g,
  mpls_inet_addr * lsraddr, int labelspace);

extern mpls_return_enum ldp_global_find_adj_index(ldp_global * g, uint32_t index, ldp_adj ** adj);
extern mpls_return_enum ldp_global_find_if_index(ldp_global * g, uint32_t index,
  ldp_if **);
extern mpls_return_enum ldp_global_find_addr_index(ldp_global * g,
  uint32_t index, ldp_addr ** addr);
extern mpls_return_enum ldp_global_find_attr_index(ldp_global * g,
  uint32_t index, ldp_attr **);
extern mpls_return_enum ldp_global_find_session_index(ldp_global * g,
  uint32_t index, ldp_session **);
extern mpls_return_enum ldp_global_find_peer_index(ldp_global * g,
  uint32_t index, ldp_peer ** peer);
extern mpls_return_enum ldp_global_find_entity_index(ldp_global * g,
  uint32_t index, ldp_entity ** entity);
extern mpls_return_enum ldp_global_find_fec_index(ldp_global * g,
  uint32_t index, ldp_fec ** fec);
extern mpls_return_enum ldp_global_find_fec(ldp_global * g, mpls_fec * m,
  ldp_fec ** fec);

extern mpls_return_enum ldp_global_find_inlabel_index(ldp_global * g, uint32_t,
  ldp_inlabel ** inlabel);
extern mpls_return_enum ldp_global_find_outlabel_index(ldp_global * g, uint32_t,
  ldp_outlabel ** outlabel);
extern ldp_outlabel *ldp_global_find_outlabel_handle(ldp_global * g,
  mpls_outsegment_handle handle);

extern mpls_return_enum ldp_global_find_tunnel_index(ldp_global * g,
  uint32_t index, ldp_tunnel ** tunnel);
extern mpls_return_enum ldp_global_find_resource_index(ldp_global * g,
  uint32_t index, ldp_resource ** resource);
extern mpls_return_enum ldp_global_find_hop_list_index(ldp_global * g,
  uint32_t index, ldp_hop_list ** hop_list);

extern void _ldp_global_add_entity(ldp_global * g, ldp_entity * e);
extern void _ldp_global_del_entity(ldp_global * g, ldp_entity * e);

extern void _ldp_global_add_session(ldp_global * g, ldp_session * s);
extern void _ldp_global_del_session(ldp_global * g, ldp_session * s);

extern void _ldp_global_add_peer(ldp_global * g, ldp_peer * p);
extern void _ldp_global_del_peer(ldp_global * g, ldp_peer * p);

extern void _ldp_global_add_fec(ldp_global * g, ldp_fec * l);
extern void _ldp_global_del_fec(ldp_global * g, ldp_fec * l);

extern void _ldp_global_add_nexthop(ldp_global * g, ldp_nexthop * l);
extern void _ldp_global_del_nexthop(ldp_global * g, ldp_nexthop * l);

extern void _ldp_global_add_attr(ldp_global * g, ldp_attr * a);
extern void _ldp_global_del_attr(ldp_global * g, ldp_attr * a);

extern void _ldp_global_add_if(ldp_global * g, ldp_if * i);
extern void _ldp_global_del_if(ldp_global * g, ldp_if * i);

extern void _ldp_global_add_addr(ldp_global * g, ldp_addr * a);
extern void _ldp_global_del_addr(ldp_global * g, ldp_addr * a);

extern void _ldp_global_add_adj(ldp_global * g, ldp_adj * a);
extern void _ldp_global_del_adj(ldp_global * g, ldp_adj * a);

extern mpls_return_enum _ldp_global_add_inlabel(ldp_global * g, ldp_inlabel * i);
extern mpls_return_enum _ldp_global_del_inlabel(ldp_global * g, ldp_inlabel * i);

extern mpls_return_enum _ldp_global_add_outlabel(ldp_global * g,
  ldp_outlabel * o);
extern mpls_return_enum _ldp_global_del_outlabel(ldp_global * g,
  ldp_outlabel * o);

extern void _ldp_global_add_tunnel(ldp_global * g, ldp_tunnel * t);
extern void _ldp_global_del_tunnel(ldp_global * g, ldp_tunnel * t);

extern void _ldp_global_add_resource(ldp_global * g, ldp_resource * r);
extern void _ldp_global_del_resource(ldp_global * g, ldp_resource * r);

extern void _ldp_global_add_hop_list(ldp_global * g, ldp_hop_list * h);
extern void _ldp_global_del_hop_list(ldp_global * g, ldp_hop_list * h);

#endif
