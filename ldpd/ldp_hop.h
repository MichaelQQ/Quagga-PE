
/*
 *  Copyright (C) James R. Leu 2001
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_HOP_H_
#define _LDP_HOP_H_

#include "ldp_struct.h"

extern ldp_hop *ldp_hop_create();
extern void ldp_hop_delete(ldp_hop * h);

extern mpls_return_enum _ldp_hop_add_hop_list(ldp_hop * h, ldp_hop_list * hl);
extern mpls_return_enum _ldp_hop_del_hop_list(ldp_hop * h);

extern mpls_bool ldp_hop_in_use(ldp_hop * h);

#endif
