
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_FEC_H_
#define _LDP_FEC_H_

extern ldp_fec *ldp_fec_create(ldp_global *g, mpls_fec *fec);
extern void ldp_fec_delete(ldp_global *g, ldp_fec * fec);
extern ldp_fec *ldp_fec_find(ldp_global *g, mpls_fec *fec);
extern ldp_fec *ldp_fec_find2(ldp_global *g, mpls_fec *fec);
extern ldp_nexthop *ldp_fec_nexthop_find(ldp_fec *f, mpls_nexthop *n);
extern mpls_return_enum ldp_fec_find_nexthop_index(ldp_fec *f, int index,
  ldp_nexthop **n);
extern mpls_return_enum ldp_fec_add_nexthop(ldp_global *g, ldp_fec *f,
  ldp_nexthop *n);
extern void ldp_fec_del_nexthop(ldp_global *g, ldp_fec *f, ldp_nexthop *n);

extern mpls_return_enum ldp_fec_process_add(ldp_global * g, ldp_fec * f,
  ldp_nexthop *nh, ldp_session *nh_session);
extern mpls_return_enum ldp_fec_process_change(ldp_global * g, ldp_fec * f,
  ldp_nexthop *nh, ldp_nexthop *nh_old, ldp_session * nh_session_old);

extern mpls_bool ldp_fec_empty(ldp_fec *fec);
extern void mpls_fec2ldp_fec(mpls_fec * a, ldp_fec * b);
extern void fec_tlv2mpls_fec(mplsLdpFecTlv_t * tlv, int num, mpls_fec * lf);
extern void mpls_fec2fec_tlv(mpls_fec * lf, mplsLdpFecTlv_t * tlv, int num);

#endif
