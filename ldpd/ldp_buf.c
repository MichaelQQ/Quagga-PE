
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdio.h>
#include <netinet/in.h>
#include "ldp_struct.h"
#include "ldp_nortel.h"
#include "ldp_buf.h"
#include "ldp_mesg.h"
#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"
#include <errno.h>

int debug = 0;

ldp_buf *ldp_buf_create(int size)
{
  ldp_buf *b = (ldp_buf *) mpls_malloc(sizeof(ldp_buf));
  char *c = NULL;

  if (!b) {
    return NULL;
  }
  memset(b, 0 , sizeof(ldp_buf));
  c = (char*) mpls_malloc(size);

  if (!c) {
    mpls_free(b);
    return NULL;
  }

  memset(c, 0, size);

  b->buffer = c;
  b->total = size;
  b->size = 0;
  b->current_size = 0;
  b->current = b->buffer;

  return b;
}

void ldp_buf_delete(ldp_buf * b)
{
  MPLS_ASSERT(b);
  mpls_free(b);
}

void ldp_buf_dump(mpls_instance_handle handle, ldp_buf * b, int size)
{
  unsigned char *buf = b->current;
  int i;
  int j = 0;

  for (i = 0; i < size; i++) {
    LDP_TRACE_OUT(handle, "%02x ", buf[i]);
    j++;
    if (j == 16) {
      LDP_TRACE_OUT(handle, "\n");
      j = 0;
    }
  }
  LDP_TRACE_OUT(handle, "\n");
}

int ldp_encode_one_mesg(ldp_global * g, uint32_t lsraddr, int label_space,
  ldp_buf * b, ldp_mesg * msg)
{
  ldp_trace_flags type = LDP_TRACE_FLAG_INIT;

  unsigned char *hdrBuf = b->buffer;
  unsigned char *bodyBuf = hdrBuf + MPLS_LDP_HDRSIZE;

  int bodyBuf_size = b->total - MPLS_LDP_HDRSIZE;
  int hdrBuf_size = MPLS_LDP_HDRSIZE;

  int hdr_size;
  int body_size;

  switch (msg->u.generic.flags.flags.msgType) {
    case MPLS_INIT_MSGTYPE:
      body_size = Mpls_encodeLdpInitMsg(&msg->u.init, bodyBuf, bodyBuf_size);
      break;
    case MPLS_NOT_MSGTYPE:
      body_size = Mpls_encodeLdpNotMsg(&msg->u.notif, bodyBuf, bodyBuf_size);
      break;
    case MPLS_KEEPAL_MSGTYPE:
      body_size =
        Mpls_encodeLdpKeepAliveMsg(&msg->u.keep, bodyBuf, bodyBuf_size);
      break;
    case MPLS_HELLO_MSGTYPE:
      body_size = Mpls_encodeLdpHelloMsg(&msg->u.hello, bodyBuf, bodyBuf_size);
      break;
    case MPLS_LBLREQ_MSGTYPE:
      body_size =
        Mpls_encodeLdpLblReqMsg(&msg->u.request, bodyBuf, bodyBuf_size);
      break;
    case MPLS_LBLMAP_MSGTYPE:
      body_size = Mpls_encodeLdpLblMapMsg(&msg->u.map, bodyBuf, bodyBuf_size);
      break;
    case MPLS_ADDR_MSGTYPE:
    case MPLS_ADDRWITH_MSGTYPE:
      body_size = Mpls_encodeLdpAdrMsg(&msg->u.addr, bodyBuf, bodyBuf_size);
      break;
    case MPLS_LBLWITH_MSGTYPE:
    case MPLS_LBLREL_MSGTYPE:
      body_size =
        Mpls_encodeLdpLbl_W_R_Msg(&msg->u.release, bodyBuf, bodyBuf_size);
      break;
    case MPLS_LBLABORT_MSGTYPE:
      body_size =
        Mpls_encodeLdpLblAbortMsg(&msg->u.abort, bodyBuf, bodyBuf_size);
      break;
    default:
      MPLS_ASSERT(0);
  }

  if (body_size < 0) {
    return body_size;
  }

  msg->header.protocolVersion = 1;
  msg->header.pduLength = body_size;
  msg->header.pduLength = body_size + MPLS_LDPIDLEN;
  msg->header.lsrAddress = lsraddr;
  msg->header.labelSpace = label_space;

  switch (msg->u.generic.flags.flags.msgType) {
    case MPLS_INIT_MSGTYPE:
      type = LDP_TRACE_FLAG_INIT;
      LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_INIT,
        printHeader(g->user_data, &msg->header),
        printInitMsg(g->user_data, &msg->u.init));
      break;
    case MPLS_NOT_MSGTYPE:
      type = LDP_TRACE_FLAG_NOTIF;
      LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_NOTIF,
        printHeader(g->user_data, &msg->header),
        printNotMsg(g->user_data, &msg->u.notif));
      break;
    case MPLS_KEEPAL_MSGTYPE:
      type = LDP_TRACE_FLAG_PERIODIC;
      LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_PERIODIC,
        printHeader(g->user_data, &msg->header),
        printKeepAliveMsg(g->user_data, &msg->u.keep));
      break;
    case MPLS_HELLO_MSGTYPE:
      type = LDP_TRACE_FLAG_PERIODIC;
      LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_PERIODIC,
        printHeader(g->user_data, &msg->header),
        printHelloMsg(g->user_data, &msg->u.hello));
      break;
    case MPLS_LBLREQ_MSGTYPE:
      type = LDP_TRACE_FLAG_LABEL;
      LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
        printHeader(g->user_data, &msg->header),
        printLlbReqMsg(g->user_data, &msg->u.request));
      break;
    case MPLS_LBLMAP_MSGTYPE:
      type = LDP_TRACE_FLAG_LABEL;
      LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
        printHeader(g->user_data, &msg->header),
        printLlbMapMsg(g->user_data, &msg->u.map));
      break;
    case MPLS_ADDR_MSGTYPE:
    case MPLS_ADDRWITH_MSGTYPE:
      type = LDP_TRACE_FLAG_ADDRESS;
      LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_ADDRESS,
        printHeader(g->user_data, &msg->header),
        printAddressMsg(g->user_data, &msg->u.addr));
      break;
    case MPLS_LBLWITH_MSGTYPE:
    case MPLS_LBLREL_MSGTYPE:
      type = LDP_TRACE_FLAG_LABEL;
      LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
        printHeader(g->user_data, &msg->header),
        printLbl_W_R_Msg(g->user_data, &msg->u.release));
      break;
    case MPLS_LBLABORT_MSGTYPE:
      type = LDP_TRACE_FLAG_LABEL;
      LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_LABEL,
        printHeader(g->user_data, &msg->header),
        printLlbAbortMsg(g->user_data, &msg->u.abort));
      break;
  }

  if ((hdr_size =
      Mpls_encodeLdpMsgHeader(&msg->header, hdrBuf, hdrBuf_size)) < 0) {
    return hdr_size;
  }

  b->current_size = hdr_size + body_size;
  b->current = b->buffer;
  b->size = b->current_size;

  LDP_DUMP_PKT(g->user_data, type, MPLS_TRACE_STATE_SEND,
    ldp_buf_dump(g->user_data, b, b->size));

  return b->size;
}

mpls_return_enum ldp_decode_header(ldp_global * g, ldp_buf * b, ldp_mesg * msg)
{
  int encodedSize;

  LDP_ENTER(g->user_data, "ldp_decode_header");

  encodedSize =
    Mpls_decodeLdpMsgHeader(&msg->header, b->current, b->current_size);

  if (encodedSize < 0) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_PACKET,
      "Failed while decoding HEADER:%d\n", encodedSize);
    LDP_EXIT(g->user_data, "ldp_decode_header - failure");
    return MPLS_FAILURE;
  }

  LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_PACKET, MPLS_TRACE_STATE_RECV,
    ldp_buf_dump(g->user_data, b, encodedSize));

  b->current_size -= encodedSize;
  b->current += encodedSize;

  LDP_EXIT(g->user_data, "ldp_decode_header");
  return MPLS_SUCCESS;
}

int ldp_decode_one_mesg(ldp_global * g, ldp_buf * b, ldp_mesg * msg)
{
  int max_mesg_size;
  int encodedSize = 0;
  u_short type = 0;
  int mesgSize = 0;

  MPLS_ASSERT(b);

  LDP_ENTER(g->user_data, "ldp_decode_one_mesg");

  if (msg->header.pduLength > (b->size - 4)) {
    LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
      LDP_TRACE_FLAG_PACKET, "Buffer too small. Decoding failed\n");
    LDP_EXIT(g->user_data, "ldp_decode_one_mesg - failure");
    return MPLS_FAILURE;
  }

  max_mesg_size = b->current_size;

  /* found the message type */
  memcpy((u_char *) & type, b->current, 2);
  type = ntohs(type) & 0x7fff;  /* ignore the U bit for now */

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_PACKET,
    "Found type %x\n", type);

  switch (type) {
    case MPLS_INIT_MSGTYPE:
      {
        MPLS_MSGPTR(Init) = &msg->u.init;
        encodedSize = Mpls_decodeLdpInitMsg(MPLS_MSGPARAM(Init),
          b->current, max_mesg_size);
        LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_INIT, MPLS_TRACE_STATE_RECV,
          ldp_buf_dump(g->user_data, b, encodedSize));
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_INIT, "decodedSize for Init msg = %d\n", encodedSize);
        if (encodedSize < 0) {
          goto ldp_decode_one_mesg;
        }
        LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_INIT,
          printHeader(g->user_data, &msg->header),
          printInitMsg(g->user_data, MPLS_MSGPARAM(Init)));
        b->current += encodedSize;
        mesgSize += encodedSize;
        break;
      }
    case MPLS_NOT_MSGTYPE:
      {
        MPLS_MSGPTR(Notif) = &msg->u.notif;
        encodedSize = Mpls_decodeLdpNotMsg(MPLS_MSGPARAM(Notif),
          b->current, max_mesg_size);
        LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_NOTIF, MPLS_TRACE_STATE_RECV,
          ldp_buf_dump(g->user_data, b,
            (encodedSize < 0) ? max_mesg_size : encodedSize));
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_NOTIF,
          "decodedSize for Notif msg = %d\n", encodedSize);
        if (encodedSize < 0) {
          goto ldp_decode_one_mesg;
        }
        LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_NOTIF,
          printHeader(g->user_data, &msg->header),
          printNotMsg(g->user_data, MPLS_MSGPARAM(Notif)));
        b->current += encodedSize;
        mesgSize += encodedSize;
        break;
      }
    case MPLS_KEEPAL_MSGTYPE:
      {
        MPLS_MSGPTR(KeepAl) = &msg->u.keep;
        encodedSize = Mpls_decodeLdpKeepAliveMsg(MPLS_MSGPARAM(KeepAl),
          b->current, max_mesg_size);
        LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_PERIODIC,
          MPLS_TRACE_STATE_RECV, ldp_buf_dump(g->user_data, b, encodedSize));
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_PERIODIC,
          "decodedSize for KeepAlive msg = %d\n", encodedSize);
        if (encodedSize < 0) {
          goto ldp_decode_one_mesg;
        }
        LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_PERIODIC,
          printHeader(g->user_data, &msg->header),
          printKeepAliveMsg(g->user_data, MPLS_MSGPARAM(KeepAl)));
        b->current += encodedSize;
        mesgSize += encodedSize;
        break;
      }
    case MPLS_HELLO_MSGTYPE:
      {
        MPLS_MSGPTR(Hello) = &msg->u.hello;
        encodedSize = Mpls_decodeLdpHelloMsg(MPLS_MSGPARAM(Hello),
          b->current, max_mesg_size);
        LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_PERIODIC,
          MPLS_TRACE_STATE_RECV, ldp_buf_dump(g->user_data, b, encodedSize));
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_PERIODIC, "decodedSize for Hello msg = %d\n",
          encodedSize);
        if (encodedSize < 0) {
          goto ldp_decode_one_mesg;
        }
        LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_PERIODIC,
          printHeader(g->user_data, &msg->header),
          printHelloMsg(g->user_data, MPLS_MSGPARAM(Hello)));
        b->current += encodedSize;
        mesgSize += encodedSize;
        break;
      }
    case MPLS_LBLREQ_MSGTYPE:
      {
        MPLS_MSGPTR(LblReq) = &msg->u.request;
        encodedSize = Mpls_decodeLdpLblReqMsg(MPLS_MSGPARAM(LblReq),
          b->current, max_mesg_size);
        LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_LABEL, MPLS_TRACE_STATE_RECV,
          ldp_buf_dump(g->user_data, b, encodedSize));
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_LABEL, "decodedSize for Req msg = %d\n", encodedSize);
        if (encodedSize < 0) {
          goto ldp_decode_one_mesg;
        }
        LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_LABEL,
          printHeader(g->user_data, &msg->header),
          printLlbReqMsg(g->user_data, MPLS_MSGPARAM(LblReq)));
        b->current += encodedSize;
        mesgSize += encodedSize;
        break;
      }
    case MPLS_LBLMAP_MSGTYPE:
      {
        MPLS_MSGPTR(LblMap) = &msg->u.map;
        encodedSize = Mpls_decodeLdpLblMapMsg(MPLS_MSGPARAM(LblMap),
          b->current, max_mesg_size);
        LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_LABEL, MPLS_TRACE_STATE_RECV,
          ldp_buf_dump(g->user_data, b, encodedSize));
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_LABEL, "decodedSize for Map msg = %d\n", encodedSize);
        if (encodedSize < 0) {
          goto ldp_decode_one_mesg;
        }
        LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_LABEL,
          printHeader(g->user_data, &msg->header),
          printLlbMapMsg(g->user_data, MPLS_MSGPARAM(LblMap)));
        b->current += encodedSize;
        mesgSize += encodedSize;
        break;
      }
    case MPLS_ADDR_MSGTYPE:
    case MPLS_ADDRWITH_MSGTYPE:
      {
        MPLS_MSGPTR(Adr) = &msg->u.addr;
        encodedSize = Mpls_decodeLdpAdrMsg(MPLS_MSGPARAM(Adr),
          b->current, max_mesg_size);
        LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_ADDRESS,
          MPLS_TRACE_STATE_RECV, ldp_buf_dump(g->user_data, b, encodedSize));
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_ADDRESS, "decodedSize for Adr msg = %d\n",
          encodedSize);
        if (encodedSize < 0) {
          goto ldp_decode_one_mesg;
        }
        LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_ADDRESS,
          printHeader(g->user_data, &msg->header),
          printAddressMsg(g->user_data, MPLS_MSGPARAM(Adr)));
        b->current += encodedSize;
        mesgSize += encodedSize;
        break;
      }
    case MPLS_LBLWITH_MSGTYPE:
    case MPLS_LBLREL_MSGTYPE:
      {
        MPLS_MSGPTR(Lbl_W_R_) = &msg->u.release;
        encodedSize = Mpls_decodeLdpLbl_W_R_Msg(MPLS_MSGPARAM(Lbl_W_R_),
          b->current, max_mesg_size);
        LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_LABEL, MPLS_TRACE_STATE_RECV,
          ldp_buf_dump(g->user_data, b, encodedSize));
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_LABEL,
          "decodedSize for Lbl Release/Mapping msg = %d\n", encodedSize);
        if (encodedSize < 0) {
          goto ldp_decode_one_mesg;
        }
        LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_LABEL,
          printHeader(g->user_data, &msg->header),
          printLbl_W_R_Msg(g->user_data, MPLS_MSGPARAM(Lbl_W_R_)));
        b->current += encodedSize;
        mesgSize += encodedSize;
        break;
      }
    case MPLS_LBLABORT_MSGTYPE:
      {
        MPLS_MSGPTR(LblAbort) = &msg->u.abort;
        encodedSize = Mpls_decodeLdpLblAbortMsg(MPLS_MSGPARAM(LblAbort),
          b->current, max_mesg_size);
        LDP_DUMP_PKT(g->user_data, LDP_TRACE_FLAG_LABEL, MPLS_TRACE_STATE_RECV,
          ldp_buf_dump(g->user_data, b, encodedSize));
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_LABEL, "decodedSize for Abort msg = %d\n",
          encodedSize);
        if (encodedSize < 0) {
          goto ldp_decode_one_mesg;
        }
        LDP_TRACE_PKT(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_LABEL,
          printHeader(g->user_data, &msg->header),
          printLlbAbortMsg(g->user_data, MPLS_MSGPARAM(LblAbort)));
        b->current += encodedSize;
        mesgSize += encodedSize;
        break;
      }
    default:
      {
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
          LDP_TRACE_FLAG_PACKET, "Unknown message type = %x\n", type);
        goto ldp_decode_one_mesg;
      }
  }                             /* switch */

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV,
    LDP_TRACE_FLAG_PACKET, "Mesg size: %d (%d)\n", mesgSize, b->size);

  b->current_size -= mesgSize;

  LDP_EXIT(g->user_data, "ldp_decode_one_mesg");
  return MPLS_SUCCESS;

ldp_decode_one_mesg:

  LDP_EXIT(g->user_data, "ldp_decode_one_mesg - failure");
  return MPLS_FAILURE;
}
