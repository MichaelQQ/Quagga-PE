
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_PDU_H_
#define _LDP_PDU_H_

#include "ldp_mm_impl.h"

#define MPLS_MSGMALLOC( e ) mplsLdp ## e ## Msg_t *test ## e ## Msg = (mplsLdp ## e ## Msg_t*)ldp_malloc(sizeof(mplsLdp ## e ## Msg_t))
#define MPLS_MSGSTRUCT( e ) mplsLdp ## e ## Msg_t test ## e ## Msg
#define MPLS_MSGPTR( e ) mplsLdp ## e ## Msg_t *test ## e ## Msg
#define MPLS_MSGCAST( e , f ) test ## e ## Msg = (mplsLdp ## e ## Msg_t*) f
#define MPLS_MSGPARAM( e ) test ## e ## Msg

#include "ldp_struct.h"

extern ldp_pdu *ldp_pdu_create();
extern ldp_pdu *ldp_pdu_create_decode(ldp_global * g, uint8_t * buf,
  int buf_size, int data_size);
extern void ldp_pdu_delete(ldp_pdu * p);
extern int Mpls_encodeLdpPDU(ldp_global * g, uint32_t lsraddr, int label_space,
  ldp_msg * msg, uint8_t * buf, int buf_size);
extern mpls_return_enum Mpls_decodeLdpPDU(ldp_global * g, ldp_pdu * pdu,
  uint8_t * buf, int size, int n);

#endif
