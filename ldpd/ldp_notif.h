
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_NOTIF_H_
#define _LDP_NOTIF_H_

#include "ldp_struct.h"

extern mpls_return_enum ldp_notif_send(ldp_global *, ldp_session *, ldp_attr *,

  ldp_notif_status);

extern mpls_return_enum ldp_notif_process(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, ldp_attr * r_attr);

extern void not2attr(mplsLdpNotifMsg_t * not, ldp_attr * attr, uint32_t flag);

extern mpls_return_enum ldp_notif_no_route(ldp_global * g, ldp_session * s,
  ldp_entity * e, ldp_attr * attr);

extern mpls_return_enum ldp_notif_no_label_resources(ldp_global * g,
  ldp_session * s, ldp_attr * s_attr);

extern mpls_return_enum ldp_notif_label_request_aborted(ldp_global * g,
  ldp_session * s, ldp_attr * s_attr);

extern mpls_return_enum ldp_notif_label_resources_available(ldp_global * g,
  ldp_session * s, ldp_attr * s_attr);

#endif
