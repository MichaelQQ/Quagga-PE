
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_LABEL_RELEASE_H_
#define _LDP_LABEL_RELEASE_H_

extern mpls_return_enum ldp_label_release_send(ldp_global *, ldp_session *,
  ldp_attr *, ldp_notif_status);
extern mpls_return_enum ldp_label_withdraw_send(ldp_global *, ldp_session *,
  ldp_attr *, ldp_notif_status);
extern mpls_bool rel_with2attr(mplsLdpLbl_W_R_Msg_t * rw, ldp_attr * attr);
extern ldp_mesg *ldp_label_rel_with_create_msg(uint32_t msgid, ldp_attr * a,
  ldp_notif_status status, uint16_t type);
extern mpls_return_enum ldp_label_release_process(ldp_global * g,
  ldp_session * s, ldp_adj * a, ldp_entity * e, ldp_attr * r_attr,
  ldp_fec * fec);
extern mpls_return_enum ldp_label_withdraw_process(ldp_global * g,
  ldp_session * s, ldp_adj * a, ldp_entity * e, ldp_attr * r_attr,
  ldp_fec * fec);

#endif
