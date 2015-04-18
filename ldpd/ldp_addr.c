
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "ldp_struct.h"
#include "ldp_global.h"
#include "ldp_session.h"
#include "ldp_entity.h"
#include "ldp_pdu_setup.h"
#include "ldp_addr.h"
#include "ldp_nexthop.h"
#include "ldp_if.h"
#include "ldp_buf.h"
#include "ldp_mesg.h"
#include "mpls_list.h"
#include "mpls_ifmgr_impl.h"
#include "mpls_mm_impl.h"
#include "mpls_trace_impl.h"
#include "mpls_tree_impl.h"

static uint32_t _ldp_addr_next_index = 1;

ldp_addr *ldp_addr_create(ldp_global *g, mpls_inet_addr * address)
{
  ldp_addr *a = (ldp_addr *) mpls_malloc(sizeof(ldp_addr));

  if (a) {
   /*
    * note: this is init to 1 for a reason!
    * We're placing it in the global list, so this is our refcnt
    * when this refcnt gets to zero, it will be removed from the
    * global list and deleted
    */
    /*
     * TESTING: jleu 6/7/2004, since I want the addr to be cleaned up
     * when it no longer has a nexthop, fec, or label, the only things that
     * should increment the ref are those (nh, fec, label etc), not global
     * nor inserting into the tree.
    MPLS_REFCNT_INIT(a, 1);
     */
    mpls_link_list_init(&a->session_root);
    MPLS_LIST_INIT(&a->nh_root, ldp_nexthop);
    MPLS_LIST_ELEM_INIT(a, _global);
    MPLS_LIST_ELEM_INIT(a, _if);
    memcpy(&a->address, address, sizeof(mpls_inet_addr));
    a->index = _ldp_addr_get_next_index();
    _ldp_global_add_addr(g, a);
    ldp_addr_insert2(g, a);
  }
  return a;
}

void ldp_addr_delete(ldp_global *g, ldp_addr * a)
{
  fprintf(stderr, "addr delete: %p\n", a);
  MPLS_REFCNT_ASSERT(a, 0);
  ldp_addr_remove(g, &a->address);
  _ldp_global_del_addr(g, a);
  mpls_free(a);
}

ldp_addr *ldp_addr_find(ldp_global *g, mpls_inet_addr * address)
{
  ldp_addr *addr = NULL;

  if (mpls_tree_get(g->addr_tree, address->u.ipv4, 32, (void **)&addr) !=
    MPLS_SUCCESS) {
    return NULL;
  }
  return addr;
}

ldp_addr *ldp_addr_insert(ldp_global *g, mpls_inet_addr * address)
{
  ldp_addr *addr = NULL;

  if ((addr = ldp_addr_create(g, address)) == NULL) {
    LDP_PRINT(g->user_data, "ldp_addr_insert: error creating address\n");
    return NULL;
  }
  return addr;
}

mpls_return_enum ldp_addr_insert2(ldp_global *g, ldp_addr *addr)
{
  if (mpls_tree_insert(g->addr_tree, addr->address.u.ipv4, 32, (void *)addr) !=
    MPLS_SUCCESS) {
    LDP_PRINT(g->user_data, "ldp_addr_insert2: error adding addr\n");
    MPLS_REFCNT_RELEASE2(g, addr, ldp_addr_delete);
    return MPLS_FATAL;
  }
  return MPLS_SUCCESS;
}

void ldp_addr_remove(ldp_global *g, mpls_inet_addr * address)
{
  ldp_addr *addr = NULL;
  mpls_tree_remove(g->addr_tree, address->u.ipv4, 32, (void **)&addr);
}

void ldp_addr_add_if(ldp_addr * a, ldp_if * i)
{
  MPLS_ASSERT(a && i);
  MPLS_REFCNT_HOLD(i);
  a->iff = i;
}

void ldp_addr_del_if(ldp_global *g, ldp_addr * a)
{
  MPLS_ASSERT(a);
  MPLS_REFCNT_RELEASE2(g, a->iff, ldp_if_delete);
  a->iff = NULL;
}

mpls_bool ldp_addr_is_empty(ldp_addr *a)
{
    if (a->iff == NULL && MPLS_LIST_EMPTY(&a->nh_root) &&
      MPLS_LIST_EMPTY(&a->session_root)) {
      return MPLS_BOOL_TRUE;
    }
    return MPLS_BOOL_FALSE;
}

mpls_return_enum _ldp_addr_add_session(ldp_addr * a, ldp_session * s)
{
  MPLS_ASSERT(a && s);
  MPLS_REFCNT_HOLD(s);
  if (mpls_link_list_add_tail(&a->session_root, s) == MPLS_SUCCESS) {
    return MPLS_SUCCESS;
  }
  MPLS_REFCNT_RELEASE(s, ldp_session_delete);
  return MPLS_FAILURE;
}

void _ldp_addr_del_session(ldp_addr * a, ldp_session * s)
{
  MPLS_ASSERT(a && s);
  mpls_link_list_remove_data(&a->session_root, s);
  MPLS_REFCNT_RELEASE(s, ldp_session_delete);
}

void ldp_addr_add_nexthop(ldp_addr * a, ldp_nexthop * nh)
{
  ldp_nexthop *np = NULL;

  MPLS_ASSERT(a && nh);
  MPLS_REFCNT_HOLD(nh);

  ldp_nexthop_add_addr(nh,a);

  np = MPLS_LIST_HEAD(&a->nh_root);
  while (np != NULL) {
    if (np->index > nh->index) {
       MPLS_LIST_INSERT_BEFORE(&a->nh_root, np, nh, _addr);
       return;
    }
    np = MPLS_LIST_NEXT(&a->nh_root, np, _addr);
  }
  MPLS_LIST_ADD_TAIL(&a->nh_root, nh, _addr, ldp_nexthop);
}

void ldp_addr_del_nexthop(ldp_global *g, ldp_addr * a, ldp_nexthop * nh)
{
  MPLS_ASSERT(a && nh);
  MPLS_LIST_REMOVE(&a->nh_root, nh, _addr);
  ldp_nexthop_del_addr(g, nh);
  MPLS_REFCNT_RELEASE2(g, nh, ldp_nexthop_delete);
}

uint32_t _ldp_addr_get_next_index()
{
  uint32_t retval = _ldp_addr_next_index;

  _ldp_addr_next_index++;
  if (retval > _ldp_addr_next_index) {
    _ldp_addr_next_index = 1;
  }
  return retval;
}

void ldp_addr_mesg_prepare(ldp_mesg * msg, ldp_global * g, uint32_t msgid,
  mpls_inet_addr * addr)
{
  MPLS_MSGPTR(Adr);

  LDP_ENTER(g->user_data, "ldp_addr_mesg_prepare");

  ldp_mesg_prepare(msg, MPLS_ADDR_MSGTYPE, msgid);
  MPLS_MSGPARAM(Adr) = &msg->u.addr;

  MPLS_MSGPARAM(Adr)->adrListTlvExists = 1;
  MPLS_MSGPARAM(Adr)->baseMsg.msgLength +=
    setupAddrTlv(&(MPLS_MSGPARAM(Adr)->addressList));

  MPLS_MSGPARAM(Adr)->baseMsg.msgLength +=
    addAddrElem2AddrTlv(&(MPLS_MSGPARAM(Adr)->addressList), addr->u.ipv4);

  LDP_EXIT(g->user_data, "ldp_addr_mesg_prepare");
}

void ldp_waddr_mesg_prepare(ldp_mesg * msg, ldp_global * g, uint32_t msgid,
  mpls_inet_addr * addr)
{
  MPLS_MSGPTR(Adr);

  LDP_ENTER(g->user_data, "ldp_waddr_mesg_prepare");

  ldp_mesg_prepare(msg, MPLS_ADDRWITH_MSGTYPE, msgid);
  MPLS_MSGPARAM(Adr) = &msg->u.addr;

  MPLS_MSGPARAM(Adr)->adrListTlvExists = 1;
  MPLS_MSGPARAM(Adr)->baseMsg.msgLength +=
    setupAddrTlv(&(MPLS_MSGPARAM(Adr)->addressList));

  MPLS_MSGPARAM(Adr)->baseMsg.msgLength +=
    addAddrElem2AddrTlv(&(MPLS_MSGPARAM(Adr)->addressList), addr->u.ipv4);

  LDP_EXIT(g->user_data, "ldp_waddr_mesg_prepare");
}

mpls_return_enum ldp_addr_send(ldp_global * g, ldp_session * s,
  mpls_inet_addr * a)
{
  mpls_return_enum result = MPLS_FAILURE;

  MPLS_ASSERT(s && a);

  LDP_ENTER(g->user_data, "ldp_addr_send");

  ldp_addr_mesg_prepare(s->tx_message, g, g->message_identifier++, a);

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_ADDRESS,
    "Addr Send: session(%d)\n", s->index);

  result = ldp_mesg_send_tcp(g, s, s->tx_message);

  LDP_EXIT(g->user_data, "ldp_addr_send");

  return result;
}

mpls_return_enum ldp_waddr_send(ldp_global * g, ldp_session * s,
  mpls_inet_addr * a)
{
  mpls_return_enum result = MPLS_FAILURE;

  MPLS_ASSERT(s && a);

  LDP_ENTER(g->user_data, "ldp_waddr_send");

  ldp_waddr_mesg_prepare(s->tx_message, g, g->message_identifier++, a);

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_SEND, LDP_TRACE_FLAG_ADDRESS,
    "Addr Withdraw Send: session(%d)\n", s->index);

  result = ldp_mesg_send_tcp(g, s, s->tx_message);

  LDP_EXIT(g->user_data, "ldp_waddr_send");

  return result;
}

mpls_return_enum ldp_addr_process(ldp_global * g, ldp_session * s,
  ldp_entity * e, ldp_mesg * msg)
{
  mplsLdpAdrMsg_t *body = &msg->u.addr;
  mpls_inet_addr inet;
  ldp_addr *addr = NULL;
  ldp_nexthop *nh = NULL;
  ldp_fec *fec = NULL;
  int len = (body->addressList.baseTlv.length - MPLS_ADDFAMFIXLEN) /
    MPLS_IPv4LEN;
  int i;

  LDP_ENTER(g->user_data, "ldp_addr_process");

  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_RECV, LDP_TRACE_FLAG_ADDRESS,
    "Addr Recv: session(%d)\n", s->index);

  for (i = 0; i < len; i++) {
    inet.type = MPLS_FAMILY_IPV4;
    inet.u.ipv4 = body->addressList.address[i];

    if (msg->u.generic.flags.flags.msgType == MPLS_ADDR_MSGTYPE) {
      if (!(addr = ldp_addr_find(g, &inet))) {
        /* it's not in the tree, put it there! */
	if ((addr = ldp_addr_insert(g, &inet)) == NULL) {
          LDP_PRINT(g->user_data, "ldp_addr_process: error adding addr\n");
          goto ldp_addr_process_end;
        }
      }

      /* the addr is in the tree */
      if (ldp_session_add_addr(g, s, addr) == MPLS_FAILURE) {
        LDP_PRINT(g->user_data,
          "ldp_addr_process: error adding address to session\n");
        return MPLS_FAILURE;
      }

      nh = MPLS_LIST_HEAD(&addr->nh_root);
      while (nh != NULL) {
        fec = nh->fec;
	/* create cross connect */
	/* send label mapping */
        nh = MPLS_LIST_NEXT(&addr->nh_root, nh, _addr);
      }
    } else {
      /* addr withdrawl */
      if ((addr = ldp_addr_find(g, &inet))) {
        nh = MPLS_LIST_HEAD(&addr->nh_root);
        while (fec != NULL) {
          /* send label withdrawl */
          /* delete cross connect */
          nh = MPLS_LIST_NEXT(&addr->nh_root, nh, _addr);
        }

        ldp_session_del_addr(g, s, addr);
      }
    }
  }

  LDP_EXIT(g->user_data, "ldp_addr_process");

  return MPLS_SUCCESS;

ldp_addr_process_end:

  LDP_EXIT(g->user_data, "ldp_addr_process-error");

  return MPLS_FAILURE;
}
