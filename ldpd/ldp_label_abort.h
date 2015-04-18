
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_LABEL_ABORT_H_
#define _LDP_LABEL_ABORT_H_
#include "ldp_struct.h"

extern ldp_mesg *ldp_label_abort_create_msg(uint32_t msgid, ldp_attr * s_attr);

extern mpls_return_enum ldp_label_abort_send(ldp_global * g, ldp_session * s,
  ldp_attr * a);

extern mpls_return_enum ldp_label_abort_process(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, ldp_attr * r_attr, ldp_fec * fec);

extern void Prepare_Label_Abort_Attributes(ldp_global * g, ldp_session * s,
  mpls_fec * fec, ldp_attr * r_attr, ldp_attr * s_attr);

extern void abort2attr(mplsLdpLblAbortMsg_t * abrt, ldp_attr * a,
  uint32_t flag);

#endif
