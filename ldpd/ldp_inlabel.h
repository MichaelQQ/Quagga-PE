
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_INLABEL_H_
#define _LDP_INLABEL_H_

#include "ldp_struct.h"

extern ldp_inlabel *ldp_inlabel_create();
extern void ldp_inlabel_delete(ldp_inlabel * i);

extern ldp_inlabel *ldp_inlabel_create_complete(ldp_global * g, ldp_session * s,
  ldp_attr * a);
extern void ldp_inlabel_delete_complete(ldp_global * g, ldp_inlabel * in,
  ldp_session * s, ldp_attr * a);

extern mpls_return_enum ldp_inlabel_add_outlabel(ldp_global *g,
  ldp_inlabel *i, ldp_outlabel *o);
extern mpls_return_enum ldp_inlabel_del_outlabel(ldp_global *g,
  ldp_inlabel *i);

extern mpls_return_enum _ldp_inlabel_add_session(ldp_inlabel * i,
  ldp_session * s);
extern void _ldp_inlabel_del_session(ldp_inlabel * i, ldp_session * s);

extern uint32_t _ldp_inlabel_get_next_index();

extern mpls_return_enum _ldp_inlabel_add_attr(ldp_inlabel * i, ldp_attr * a);
extern void _ldp_inlabel_del_attr(ldp_inlabel * i, ldp_attr * a);

#endif
