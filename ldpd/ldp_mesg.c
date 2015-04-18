
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdio.h>
#include <sys/socket.h>
#include "ldp_struct.h"
#include "ldp_mesg.h"
#include "ldp_buf.h"

#include "mpls_assert.h"
#include "mpls_mm_impl.h"
#include "mpls_socket_impl.h"
#include "mpls_trace_impl.h"

mpls_return_enum ldp_mesg_send_tcp(ldp_global * g, ldp_session * s,
  ldp_mesg * msg)
{
  int32_t result = 0;

  MPLS_ASSERT(s);

  result = ldp_encode_one_mesg(g, g->lsr_identifier.u.ipv4,
    s->cfg_label_space, s->tx_buffer, msg);

  if (result <= 0)
    return MPLS_FAILURE;

  s->mesg_tx++;

  result = mpls_socket_tcp_write(g->socket_handle, s->socket,
    s->tx_buffer->buffer, s->tx_buffer->size);

  if (result <= 0) {
    LDP_PRINT(g->user_data, "send failed(%d)\n", result);
    perror("send");
    return MPLS_FAILURE;
  }
  return MPLS_SUCCESS;
}

mpls_return_enum ldp_mesg_send_udp(ldp_global * g, ldp_entity * e,
  ldp_mesg * msg)
{
  ldp_buf *buf = NULL;
  mpls_dest *dest = NULL;
  int32_t result = 0;
  uint16_t label_space = 0;

  MPLS_ASSERT(e);

  switch (e->entity_type) {
    case LDP_DIRECT:
      MPLS_ASSERT(e->p.iff != NULL);
      if (mpls_socket_multicast_if_tx(g->socket_handle, g->hello_socket,
          e->p.iff) == MPLS_FAILURE) {
        LDP_PRINT(g->user_data, "ldp_mesg_send_udp: muticast tx error(%d)\n",
          mpls_socket_get_errno(g->socket_handle, g->hello_socket));
        return MPLS_FAILURE;
      }
      dest = &e->p.iff->dest;
      buf = e->p.iff->tx_buffer;
      label_space = e->p.iff->label_space;
      break;
    case LDP_INDIRECT:
      MPLS_ASSERT(e->p.peer != NULL);
      dest = &e->p.peer->dest;
      buf = e->p.peer->tx_buffer;
      label_space = e->p.peer->label_space;
      break;
    default:
      MPLS_ASSERT(0);
  }
  result =
    ldp_encode_one_mesg(g, g->lsr_identifier.u.ipv4, label_space, buf, msg);

  if (result <= 0)
    return MPLS_FAILURE;

  e->mesg_tx++;

  result = mpls_socket_udp_sendto(g->socket_handle, g->hello_socket,
    buf->buffer, buf->size, dest);

  switch (e->entity_type) {
    case LDP_DIRECT:
      mpls_socket_multicast_if_tx(g->socket_handle, g->hello_socket, NULL);
      break;
    case LDP_INDIRECT:
      break;
    default:
      MPLS_ASSERT(0);
  }

  if (result <= 0) {
    LDP_PRINT(g->user_data, "sendto failed(%d)\n", result);
    perror("sendto");
    return MPLS_FAILURE;
  }
  return MPLS_SUCCESS;
}

ldp_mesg *ldp_mesg_create()
{
  ldp_mesg *msg = (ldp_mesg *) mpls_malloc(sizeof(ldp_mesg));

  if (!msg) {
    return NULL;
  }
  return msg;
}

void ldp_mesg_prepare(ldp_mesg * msg, uint16_t type, uint32_t id)
{
  memset(msg, 0, sizeof(ldp_mesg));
  printf("%d\n", type);
  msg->u.generic.flags.flags.msgType = type;
  msg->u.generic.msgId = id;
  msg->u.generic.msgLength = MPLS_MSGIDFIXLEN;
}

void ldp_mesg_delete(ldp_mesg * msg)
{
  MPLS_ASSERT(msg);
  mpls_free(msg);
}

void ldp_mesg_hdr_get_lsraddr(ldp_mesg * msg, mpls_inet_addr * lsraddr)
{
  MPLS_ASSERT(msg && lsraddr);

  lsraddr->type = MPLS_FAMILY_IPV4;
  lsraddr->u.ipv4 = msg->header.lsrAddress;
}

void ldp_mesg_hdr_get_labelspace(ldp_mesg * msg, int *labelspace)
{
  MPLS_ASSERT(msg && labelspace);
  *labelspace = msg->header.labelSpace;
}

uint16_t ldp_mesg_get_type(ldp_mesg * msg)
{
  MPLS_ASSERT(msg);
  return msg->u.generic.flags.flags.msgType;
}

mpls_return_enum ldp_mesg_hello_get_traddr(ldp_mesg * msg,
  mpls_inet_addr * traddr)
{
  MPLS_MSGPTR(Hello);
  MPLS_ASSERT(msg && traddr);

  MPLS_MSGPARAM(Hello) = &msg->u.hello;
  if (!MPLS_MSGPARAM(Hello)->trAdrTlvExists)
    return MPLS_FAILURE;

  traddr->type = MPLS_FAMILY_IPV4;
  traddr->u.ipv4 = MPLS_MSGPARAM(Hello)->trAdr.address;

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_mesg_hello_get_hellotime(ldp_mesg * msg, int *hellotime)
{
  MPLS_MSGPTR(Hello);
  MPLS_ASSERT(msg && hellotime);

  MPLS_MSGPARAM(Hello) = &msg->u.hello;
  if (!MPLS_MSGPARAM(Hello)->chpTlvExists) {
    fprintf(stderr, "No chp!\n");
    return MPLS_FAILURE;
  }

  *hellotime = MPLS_MSGPARAM(Hello)->chp.holdTime;

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_mesg_hello_get_csn(ldp_mesg * msg, uint32_t * csn)
{
  MPLS_MSGPTR(Hello);
  MPLS_ASSERT(msg && csn);

  MPLS_MSGPARAM(Hello) = &msg->u.hello;
  if (!MPLS_MSGPARAM(Hello)->csnTlvExists)
    return MPLS_FAILURE;

  *csn = MPLS_MSGPARAM(Hello)->csn.seqNumber;

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_mesg_hello_get_request(ldp_mesg * msg, int *req)
{
  MPLS_MSGPTR(Hello);
  MPLS_ASSERT(msg && req);

  MPLS_MSGPARAM(Hello) = &msg->u.hello;

  *req = MPLS_MSGPARAM(Hello)->chp.flags.flags.request;

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_mesg_hello_get_targeted(ldp_mesg * msg, int *tar)
{
  MPLS_MSGPTR(Hello);
  MPLS_ASSERT(msg && tar);

  MPLS_MSGPARAM(Hello) = &msg->u.hello;

  *tar = MPLS_MSGPARAM(Hello)->chp.flags.flags.target;

  return MPLS_SUCCESS;
}
