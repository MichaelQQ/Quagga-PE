
/*
 *  Copyright (C) James R. Leu 2001
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_HOP_LIST_H_
#define _LDP_HOP_LIST_H_

#include "ldp_struct.h"

extern ldp_hop_list *ldp_hop_list_create();
extern void ldp_hop_list_delete(ldp_hop_list * h);
extern uint32_t _ldp_hop_list_get_next_index();

extern mpls_return_enum ldp_hop_list_find_hop_index(ldp_hop_list * hl,
  uint32_t index, ldp_hop ** hop);

extern mpls_return_enum ldp_hop_list_add_hop(ldp_hop_list * hl, ldp_hop * e);
extern mpls_return_enum ldp_hop_list_del_hop(ldp_hop_list * hl, ldp_hop * e);

extern mpls_return_enum _ldp_hop_list_add_tunnel(ldp_hop_list * h,

  ldp_tunnel * t);
extern mpls_return_enum _ldp_hop_list_del_tunnel(ldp_hop_list * h);

#endif
