
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_LABEL_REQUEST_H_
#define _LDP_LABEL_REQUEST_H_
#include "ldp_struct.h"

extern void ldp_label_request_initial_callback(mpls_timer_handle timer,
  void *extra, mpls_cfg_handle g);

extern mpls_return_enum ldp_label_request_send(ldp_global * g, ldp_session * s,
  ldp_attr * us_attr, ldp_attr ** ds_attr);

extern mpls_return_enum ldp_label_request_process(ldp_global * g,
  ldp_session * s, ldp_adj * a, ldp_entity * e, ldp_attr * r_attr,
  ldp_fec * fec);

extern void Prepare_Label_Request_Attributes(ldp_global * g, ldp_session * s,
  mpls_fec * fec, ldp_attr * r_attr, ldp_attr * s_attr);

extern mpls_return_enum ldp_label_request_for_xc(ldp_global * g, ldp_session * s, mpls_fec * fec, ldp_attr * us_attr, ldp_attr ** ds_attr);

extern void req2attr(mplsLdpLblReqMsg_t * req, ldp_attr * attr, uint32_t flag);
#endif
