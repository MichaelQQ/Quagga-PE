
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_BUF_H_
#define _LDP_BUF_H_

#include "mpls_mm_impl.h"

#define MPLS_MSGMALLOC( e ) mplsLdp ## e ## Msg_t *test ## e ## Msg = (mplsLdp ## e ## Msg_t*)ldp_malloc(sizeof(mplsLdp ## e ## Msg_t))
#define MPLS_MSGSTRUCT( e ) mplsLdp ## e ## Msg_t test ## e ## Msg
#define MPLS_MSGPTR( e ) mplsLdp ## e ## Msg_t *test ## e ## Msg
#define MPLS_MSGCAST( e , f ) test ## e ## Msg = (mplsLdp ## e ## Msg_t*) f
#define MPLS_MSGPARAM( e ) test ## e ## Msg

#include "ldp_struct.h"

extern ldp_buf *ldp_buf_create(int);
extern void ldp_buf_delete(ldp_buf *);
extern int ldp_encode_one_mesg(ldp_global * g, uint32_t lsraddr,
  int label_space, ldp_buf * b, ldp_mesg * msg);
extern int ldp_decode_one_mesg(ldp_global * g, ldp_buf * pdu, ldp_mesg * msg);
extern mpls_return_enum ldp_decode_header(ldp_global * g, ldp_buf * b,

  ldp_mesg * msg);

#endif
