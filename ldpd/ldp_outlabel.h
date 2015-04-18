
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_OUTLABEL_H_
#define _LDP_OUTLABEL_H_

#include "ldp_struct.h"

extern ldp_outlabel *ldp_outlabel_create();
extern void ldp_outlabel_delete(ldp_outlabel * i);

extern ldp_outlabel *ldp_outlabel_create_complete(ldp_global * g,
  ldp_session * s, ldp_attr * a, ldp_nexthop *nh);
extern void ldp_outlabel_delete_complete(ldp_global * g, ldp_outlabel * out);

extern void _ldp_outlabel_add_inlabel(ldp_outlabel *, ldp_inlabel *);
extern void _ldp_outlabel_del_inlabel(ldp_outlabel *, ldp_inlabel *);

extern void _ldp_outlabel_add_session(ldp_outlabel *, ldp_session *);
extern void _ldp_outlabel_del_session(ldp_outlabel * o);

extern void _ldp_outlabel_add_attr(ldp_outlabel * o, ldp_attr * a);
extern void _ldp_outlabel_del_attr(ldp_outlabel * o);

extern void ldp_outlabel_add_nexthop(ldp_outlabel * o, ldp_nexthop * nh);
extern void ldp_outlabel_del_nexthop(ldp_global *g, ldp_outlabel * o, ldp_nexthop * nh);

extern void ldp_outlabel_add_nexthop2(ldp_outlabel * o, ldp_nexthop * nh);
extern void ldp_outlabel_del_nexthop2(ldp_global *g, ldp_outlabel * o);

extern void _ldp_outlabel_add_tunnel(ldp_outlabel * o, ldp_tunnel * t);
extern void _ldp_outlabel_del_tunnel(ldp_outlabel * o, ldp_tunnel * t);

extern uint32_t _ldp_outlabel_get_next_index();
#endif
