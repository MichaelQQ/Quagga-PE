
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_ATTR_H_
#define _LDP_ATTR_H_
#include "ldp_struct.h"

#define LDP_ATTR_LABEL          0x01
#define LDP_ATTR_HOPCOUNT       0x02
#define LDP_ATTR_PATH           0x04
#define LDP_ATTR_FEC            0x08
#define LDP_ATTR_MSGID          0x10
#define LDP_ATTR_LSPID          0x20
#define LDP_ATTR_TRAFFIC        0x40
#define LDP_ATTR_STATUS		0x80
#define LDP_ATTR_ALL            0xFF

extern void ldp_attr_action_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle g);

extern void ldp_attr_add_fec(ldp_attr *a, ldp_fec *fec);
extern void ldp_attr_del_fec(ldp_global *g, ldp_attr *a);

extern void ldp_attr_add_us2ds(ldp_attr * us, ldp_attr * ds);
extern void ldp_attr_del_us2ds(ldp_attr * us, ldp_attr * ds);
extern mpls_bool ldp_attr_us_partof_ds(ldp_attr * us, ldp_attr * ds);
extern int ldp_attr_num_us2ds(ldp_attr * ds);

extern ldp_attr *ldp_attr_create(mpls_fec * fec);
extern void ldp_attr_delete(ldp_attr * a);
extern void ldp_attr2ldp_attr(ldp_attr * a, ldp_attr * b, uint32_t flag);
extern void ldp_attr_remove_complete(ldp_global * g, ldp_attr * attr, mpls_bool);

extern ldp_attr *ldp_attr_find_downstream_state2(ldp_global * g,ldp_session * s,
  ldp_fec * f, ldp_lsp_state state);
extern ldp_attr *ldp_attr_find_downstream_state(ldp_global * g, ldp_session * s,
  mpls_fec * f, ldp_lsp_state state);
extern ldp_attr *ldp_attr_find_upstream_state2(ldp_global * g, ldp_session * s,
  ldp_fec * f, ldp_lsp_state state);
extern ldp_attr *ldp_attr_find_upstream_state(ldp_global * g, ldp_session * s,
  mpls_fec * f, ldp_lsp_state state);

extern ldp_attr *ldp_attr_find_downstream_state_any2(ldp_global *g, ldp_fec *f,
  ldp_lsp_state state);
extern ldp_attr *ldp_attr_find_downstream_state_any(ldp_global *g, mpls_fec *f,
  ldp_lsp_state state);
extern ldp_attr *ldp_attr_find_upstream_state_any2(ldp_global * g, ldp_fec * f,
  ldp_lsp_state state);
extern ldp_attr *ldp_attr_find_upstream_state_any(ldp_global * g, mpls_fec * f,
  ldp_lsp_state state);
extern ldp_attr *ldp_attr_find_upstream_map_in_labelspace(ldp_fec *f,
  int labelspace);


extern mpls_return_enum ldp_attr_del_outlabel(ldp_attr * a);
extern mpls_return_enum ldp_attr_add_outlabel(ldp_attr * a, ldp_outlabel * o);
extern mpls_return_enum ldp_attr_add_inlabel(ldp_attr * a, ldp_inlabel * i);
extern mpls_return_enum ldp_attr_del_inlabel(ldp_attr * a);
extern mpls_return_enum ldp_attr_add_session(ldp_attr * a, ldp_session * s);
extern mpls_return_enum ldp_attr_del_session(ldp_attr * a);

extern mpls_bool ldp_attr_is_equal(ldp_attr * a, ldp_attr * b, uint32_t flag);
extern ldp_attr_list *ldp_attr_find_upstream_all2(ldp_global * g,
  ldp_session * s, ldp_fec * f);
extern ldp_attr_list *ldp_attr_find_upstream_all(ldp_global * g,
  ldp_session * s, mpls_fec * f);
extern ldp_attr_list *ldp_attr_find_downstream_all2(ldp_global * g,
  ldp_session * s, ldp_fec * f);
extern ldp_attr_list *ldp_attr_find_downstream_all(ldp_global * g,
  ldp_session * s, mpls_fec * f);
extern void ldp_attr_delete_upstream(ldp_global *, ldp_session *, ldp_attr *);
extern void ldp_attr_delete_downstream(ldp_global *, ldp_session *, ldp_attr *);
extern mpls_return_enum ldp_attr_insert_upstream2(ldp_global *g,ldp_session *s,
  ldp_attr * a, ldp_fec *f);
extern mpls_return_enum ldp_attr_insert_upstream(ldp_global *g, ldp_session *s,
  ldp_attr * a);
extern mpls_return_enum ldp_attr_insert_downstream2(ldp_global * g,
  ldp_session * s, ldp_attr * a, ldp_fec *f);
extern mpls_return_enum ldp_attr_insert_downstream(ldp_global * g,
  ldp_session * s, ldp_attr * a);

extern void mpls_label_struct2ldp_attr(mpls_label_struct * l, ldp_attr * a);
extern void ldp_attr2mpls_label_struct(ldp_attr * a, mpls_label_struct * l);

#endif
