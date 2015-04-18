
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_HELLO_H_
#define _LDP_HELLO_H_

extern void ldp_hello_timeout_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle g);

extern void ldp_hello_send_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle g);
extern mpls_return_enum ldp_hello_send(ldp_global * g, ldp_entity * e);

extern ldp_mesg *ldp_hello_create(uint32_t msgid, int holdtime,
  mpls_inet_addr * traddr, uint32_t confnum, int targeted, int request);

extern mpls_return_enum ldp_hello_process(ldp_global * g, ldp_adj * a,
  ldp_entity *e, int hellotime, uint32_t csn, mpls_inet_addr * traddr,
  int target, int request);

#endif
