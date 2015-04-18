
/*
 *  Copyright (C) James R. Leu 2001
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_MESG_H_
#define _LDP_MESG_H_

#include "ldp_struct.h"

extern ldp_mesg *ldp_mesg_create();
extern void ldp_mesg_prepare(ldp_mesg * msg, uint16_t type, uint32_t id);
extern void ldp_mesg_delete(ldp_mesg * msg);
extern uint16_t ldp_mesg_get_type(ldp_mesg * mesg);
extern void ldp_mesg_hdr_get_lsraddr(ldp_mesg * mesg, mpls_inet_addr * lsraddr);
extern void ldp_mesg_hdr_get_labelspace(ldp_mesg * mesg, int *labelspace);

extern mpls_return_enum ldp_mesg_hello_get_traddr(ldp_mesg * mesg,
  mpls_inet_addr * traddr);
extern mpls_return_enum ldp_mesg_hello_get_hellotime(ldp_mesg * mesg,

  int *hellotime);
extern mpls_return_enum ldp_mesg_hello_get_csn(ldp_mesg * mesg, uint32_t * csn);
extern mpls_return_enum ldp_mesg_hello_get_targeted(ldp_mesg * mesg, int *tar);
extern mpls_return_enum ldp_mesg_hello_get_request(ldp_mesg * mesg, int *req);

extern mpls_return_enum ldp_mesg_send_tcp(ldp_global * g, ldp_session * s,
  ldp_mesg * mesg);
extern mpls_return_enum ldp_mesg_send_udp(ldp_global * g, ldp_entity * s,
  ldp_mesg * mesg);

#endif
