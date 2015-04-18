
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_KEEPALIVE_H_
#define _LDP_KEEPALIVE_H_

#include "ldp_struct.h"

extern ldp_mesg *ldp_keepalive_create(uint32_t msgid);
extern mpls_return_enum ldp_keepalive_send(ldp_global * g, ldp_session * s);
extern void ldp_keepalive_send_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle g);
extern void ldp_keepalive_timeout_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle g);
extern void ldp_keepalive_set_message_id(ldp_mesg * keep, uint32_t msgid);

#endif
