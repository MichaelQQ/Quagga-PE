
/*
 *  Copyright (C) James R. Leu 2003
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_NEXTHOP_H_
#define _LDP_NEXTHOP_H_

extern ldp_nexthop *ldp_nexthop_create(ldp_global *g, mpls_nexthop *n);
extern ldp_nexthop *ldp_nexthop_for_fec_session(ldp_fec *fec, ldp_session *s);
extern void ldp_nexthop_delete(ldp_global *g, ldp_nexthop *nh);
extern void ldp_nexthop_add_if(ldp_nexthop * nh, ldp_if * i);
extern void ldp_nexthop_del_if(ldp_global *g, ldp_nexthop * nh);
extern void ldp_nexthop_add_addr(ldp_nexthop * nh, ldp_addr * a);
extern void ldp_nexthop_del_addr(ldp_global *g, ldp_nexthop * nh);
extern void ldp_nexthop_add_outlabel(ldp_nexthop * nh, ldp_outlabel * o);
extern void ldp_nexthop_del_outlabel(ldp_nexthop * nh);
extern void ldp_nexthop_add_outlabel2(ldp_nexthop * nh, ldp_outlabel * o);
extern void ldp_nexthop_del_outlabel2(ldp_global *g, ldp_nexthop * nh, ldp_outlabel * o);
extern void ldp_nexthop_add_fec(ldp_nexthop * nh, ldp_fec * f);
extern void ldp_nexthop_del_fec(ldp_global * g, ldp_nexthop * nh);
extern void mpls_nexthop2ldp_nexthop(mpls_nexthop *mnh, ldp_nexthop *lnh);


#endif
