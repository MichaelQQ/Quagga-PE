
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_LABEL_MAPPING_H_
#define _LDP_LABEL_MAPPING_H_
#include "ldp_struct.h"

extern mpls_return_enum ldp_label_mapping_with_xc(ldp_global * g,
  ldp_session * s, ldp_fec * fec, ldp_attr ** us_attr, ldp_attr * ds_attr);

extern void map2attr(mplsLdpLblMapMsg_t * map, ldp_attr * attr, uint32_t flag);
extern void attr2map(ldp_attr * attr, mplsLdpLblMapMsg_t * map);

extern void ldp_label_mapping_initial_callback(mpls_timer_handle timer,
  void *extra, mpls_cfg_handle g);

extern void ldp_label_mapping_prepare_msg(ldp_mesg * msg, uint32_t msgid,
  ldp_attr * s_attr);
extern mpls_return_enum ldp_label_mapping_send(ldp_global * g, ldp_session * s,
  ldp_fec *f, ldp_attr * us_attr, ldp_attr * ds_attr);

extern mpls_return_enum ldp_label_mapping_process(ldp_global * g,
  ldp_session * s, ldp_adj * a, ldp_entity * e, ldp_attr * r_attr,
  ldp_fec * fec);

extern mpls_return_enum Check_Received_Attributes(ldp_global * g,
  ldp_session * s, ldp_attr * r_attr, uint16_t type);

extern ldp_session *ldp_get_next_hop_session_for_fec2(ldp_fec *f,
  ldp_nexthop *nh);
extern mpls_return_enum ldp_get_next_hop_session_for_fec(ldp_global * g,
  mpls_fec * fec, mpls_nexthop *nh, ldp_session ** next_hop_session);

extern void Prepare_Label_Mapping_Attributes(ldp_global * g, ldp_session * s,
  mpls_fec * fec, ldp_attr * r_attr, ldp_attr * s_attr, mpls_bool propogating,
  mpls_bool already, mpls_bool egress);

#endif
