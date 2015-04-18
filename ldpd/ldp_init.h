
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_INIT_H_
#define _LDP_INIT_H_

#include "ldp_struct.h"

extern ldp_mesg *ldp_init_create(ldp_global * g, uint32_t msgid,
  ldp_session * session);
extern mpls_return_enum ldp_init_send(ldp_global * g, ldp_session * s);
extern mpls_return_enum ldp_init_process(ldp_global * g, ldp_session * s,
  ldp_mesg * msg);

#endif
