
/*
 *  Copyright (C) James R. Leu 2001
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_RESOURCE_H_
#define _LDP_RESOURCE_H_

#include "ldp_struct.h"

extern ldp_resource *ldp_resource_create();
extern void ldp_resource_delete(ldp_resource * r);
extern uint32_t _ldp_resource_get_next_index();

extern mpls_return_enum _ldp_resource_add_tunnel(ldp_resource * r,

  ldp_tunnel * t);
extern mpls_return_enum _ldp_resource_del_tunnel(ldp_resource * r);

extern mpls_bool ldp_resource_in_use(ldp_resource * r);

#endif
