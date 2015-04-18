
/*
 *  Copyright (C) James R. Leu 2001
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_TUNNEL_H_
#define _LDP_TUNNEL_H_

#include "ldp_struct.h"

extern ldp_tunnel *ldp_tunnel_create();
extern void ldp_tunnel_delete(ldp_tunnel * t);
extern uint32_t _ldp_tunnel_get_next_index();

extern mpls_return_enum ldp_tunnel_add_resource(ldp_tunnel * t,

  ldp_resource * r);
extern mpls_return_enum ldp_tunnel_del_resource(ldp_tunnel * t);

extern mpls_return_enum ldp_tunnel_add_hop_list(ldp_tunnel * t,

  ldp_hop_list * h);
extern mpls_return_enum ldp_tunnel_del_hop_list(ldp_tunnel * t);

extern mpls_return_enum ldp_tunnel_add_outlabel(ldp_tunnel * t,

  ldp_outlabel * o);
extern mpls_return_enum ldp_tunnel_del_outlabel(ldp_tunnel * t);

extern mpls_bool ldp_tunnel_is_active(ldp_tunnel * t);
extern mpls_bool ldp_tunnel_is_ready(ldp_tunnel * t);

extern mpls_return_enum ldp_tunnel_startup(ldp_global * global,

  ldp_tunnel * tunnel);
extern mpls_return_enum ldp_tunnel_shutdown(ldp_global * global,
  ldp_tunnel * tunnel, int flag);

#endif
