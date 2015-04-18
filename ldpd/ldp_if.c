
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "ldp_struct.h"
#include "ldp_global.h"
#include "ldp_entity.h"
#include "ldp_nexthop.h"
#include "ldp_nortel.h"
#include "ldp_addr.h"
#include "ldp_if.h"
#include "ldp_fec.h"
#include "ldp_mesg.h"
#include "ldp_buf.h"
#include "ldp_hello.h"

#include "mpls_assert.h"
#include "mpls_mm_impl.h"
#include "mpls_compare.h"
#include "mpls_socket_impl.h"
#include "mpls_timer_impl.h"
#include "mpls_ifmgr_impl.h"
#include "mpls_trace_impl.h"

extern uint32_t _ldp_sub_entity_next_index;

ldp_if *ldp_if_create(ldp_global *g)
{
  ldp_if *i = (ldp_if *) mpls_malloc(sizeof(ldp_if));

  if (i) {
    memset(i, 0, sizeof(ldp_if));
    /*
     * note: this is init to 1 for a reason!
     * We're placing it in the global list, so this is our refcnt
     * when this refcnt gets to zero, it will be removed from the
     * global list and deleted
     */
    /*
     * TESTING: jleu 6/7/2004, since I want the iff to be cleaned up
     * when it no longer has a nexthop, fec, or label, the only things that
     * should increment the ref are those (nh, fec, label etc), not global
     * nor inserting into the tree.
    MPLS_REFCNT_INIT(i, 1);
     */
    MPLS_LIST_ELEM_INIT(i, _global);
    MPLS_LIST_INIT(&i->nh_root, ldp_nexthop);
    MPLS_LIST_INIT(&i->addr_root, ldp_addr);
    i->label_space = -1;
    i->dest.addr.type = MPLS_FAMILY_IPV4;
    i->dest.addr.u.ipv4 = INADDR_ALLRTRS_GROUP;
    i->tx_buffer = ldp_buf_create(MPLS_PDUMAXLEN);
    i->tx_message = ldp_mesg_create();
    i->index = _ldp_if_get_next_index();
    i->oper_state = MPLS_OPER_DOWN;
    i->is_p2p = MPLS_BOOL_FALSE;
    _ldp_global_add_if(g, i);
  }
  return i;
}

void ldp_if_delete(ldp_global *g, ldp_if * i)
{
  fprintf(stderr, "if delete: %p\n", i);
  MPLS_REFCNT_ASSERT(i, 0);
  mpls_free(i->tx_buffer);
  mpls_free(i->tx_message);
  i->tx_buffer = NULL;
  i->tx_message = NULL;
  _ldp_global_del_if(g, i);
  mpls_free(i);
}

/*
 * ldp_if_insert and ldp_if_remove should ONLY be used in conjuction with
 * adding and removing nexthops (or fecs).
 */

ldp_if *ldp_if_insert(ldp_global *g, mpls_if_handle handle)
{
  ldp_if *iff = NULL;

  MPLS_ASSERT(g);
  MPLS_ASSERT(mpls_if_handle_verify(g->ifmgr_handle, handle) == MPLS_BOOL_TRUE);

  if ((iff = ldp_if_create(g)) == NULL) {
    LDP_PRINT(g->user_data,"ldp_if_insert: unable to alloc ldp_if\n");
    return NULL;
  }
  iff->handle = handle;
  return iff;
}

#if 0
void ldp_if_remove(ldp_global *g, ldp_if *iff)
{
  MPLS_ASSERT(g && iff);
  MPLS_REFCNT_RELEASE2(g, iff, ldp_if_delete);
}
#endif

void ldp_if_add_nexthop(ldp_if * i, ldp_nexthop * n)
{
  ldp_nexthop *np = NULL;

  MPLS_ASSERT(i && n);
  MPLS_REFCNT_HOLD(n);

  ldp_nexthop_add_if(n,i);

  np = MPLS_LIST_HEAD(&i->nh_root);
  while (np != NULL) {
    if (np->index > n->index) {
       MPLS_LIST_INSERT_BEFORE(&i->nh_root, np, n, _if);
       return;
    }
    np = MPLS_LIST_NEXT(&i->nh_root, np, _if);
  }
  MPLS_LIST_ADD_TAIL(&i->nh_root, n, _if, ldp_nexthop);
}

void ldp_if_del_nexthop(ldp_global *g, ldp_if * i, ldp_nexthop * n)
{
  MPLS_ASSERT(i && n);
  MPLS_LIST_REMOVE(&i->nh_root, n, _if);
  ldp_nexthop_del_if(g, n);
  MPLS_REFCNT_RELEASE2(g, n, ldp_nexthop_delete);
}

void ldp_if_add_addr(ldp_if * i, ldp_addr * a)
{
  ldp_addr *ap = NULL;

  MPLS_ASSERT(i && a);
  MPLS_REFCNT_HOLD(a);

  ldp_addr_add_if(a,i);

  ap = MPLS_LIST_HEAD(&i->addr_root);
  while (ap != NULL) {
    if (ap->index > a->index) {
       MPLS_LIST_INSERT_BEFORE(&i->addr_root, ap, a, _if);
       return;
    }
    ap = MPLS_LIST_NEXT(&i->addr_root, ap, _if);
  }
  MPLS_LIST_ADD_TAIL(&i->addr_root, a, _if, ldp_addr);
}

void ldp_if_del_addr(ldp_global *g, ldp_if * i, ldp_addr * a)
{
  MPLS_ASSERT(i && a);
  MPLS_LIST_REMOVE(&i->addr_root, a, _if);
  ldp_addr_del_if(g, a);
  MPLS_REFCNT_RELEASE2(g, a, ldp_addr_delete);
}

mpls_return_enum ldp_if_find_addr_index(ldp_if *i, int index, ldp_addr **a)
{
  ldp_addr *ap = NULL;

  MPLS_ASSERT(i);

  if (index > 0) {

    /* because we sort our inserts by index, this lets us know
       if we've "walked" past the end of the list */

    ap = MPLS_LIST_TAIL(&i->addr_root);
    if (!ap || ap->index < index) {
      *a = NULL;
      return MPLS_END_OF_LIST;
    }

    ap = MPLS_LIST_HEAD(&i->addr_root);
    do {
      if (ap->index == index) {
        *a = ap;
        return MPLS_SUCCESS;
      }
    } while((ap = MPLS_LIST_NEXT(&i->addr_root, ap, _if)));
  }
  *a = NULL;
  return MPLS_FAILURE;
}

ldp_addr *ldp_if_addr_find(ldp_if *i, mpls_inet_addr *a)
{
  ldp_addr *ap = NULL;

  MPLS_ASSERT(i && a);

  ap = MPLS_LIST_HEAD(&i->addr_root);
  
  while(ap) {
    if (!mpls_inet_addr_compare(&ap->address, a)) {
      return ap;
    }
    ap = MPLS_LIST_NEXT(&i->addr_root, ap, _if);
  }
  return NULL;
}

mpls_return_enum ldp_if_startup(ldp_global * g, ldp_if * i)
{
  ldp_entity *e = NULL;

  LDP_ENTER(g->user_data, "ldp_if_startup");

  MPLS_ASSERT(i != NULL);
  e = i->entity;
  MPLS_ASSERT(e != NULL);
  MPLS_ASSERT(e->p.iff != NULL);

  if (mpls_socket_multicast_if_join(g->socket_handle, g->hello_socket, i,
      &i->dest.addr) == MPLS_FAILURE) {
    goto ldp_if_startup_delay;
  }

  i->dest.port = e->remote_udp_port;
  if (ldp_hello_send(g, e) == MPLS_FAILURE) {
    ldp_if_shutdown(g, i);
    return MPLS_FAILURE;
  }
  i->oper_state = MPLS_OPER_UP;

  LDP_EXIT(g->user_data, "ldp_if_startup");

  return MPLS_SUCCESS;

ldp_if_startup_delay:

  /*
   * when a interface update comes in, it will search the global 
   * list of interfaces, and start up the interface then
   */
  i->oper_state = MPLS_OPER_DOWN;

  LDP_EXIT(g->user_data, "ldp_if_startup-delayed");

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_if_shutdown(ldp_global * g, ldp_if * i)
{
  ldp_entity *e = NULL;

  MPLS_ASSERT(i != NULL && ((e = i->entity) != NULL));

  LDP_ENTER(g->user_data, "ldp_if_shutdown");

  i->oper_state = MPLS_OPER_DOWN;

  mpls_socket_multicast_if_drop(g->socket_handle, g->hello_socket, i,
    &i->dest.addr);

  mpls_timer_stop(g->timer_handle, i->hellotime_send_timer);
  mpls_timer_delete(g->timer_handle, i->hellotime_send_timer);
  i->hellotime_send_timer_duration = 0;
  i->hellotime_send_timer = 0;

 /*
  * jleu: I'm not sure why these were here, I'm commenting them out,
  * because I do not see a corresponding HOLD in ldp_if_startup
  MPLS_REFCNT_RELEASE(e, ldp_entity_delete);
  MPLS_ASSERT(e != NULL);
  */

  if (i->hello) {
    ldp_mesg_delete(i->hello);
    i->hello = NULL;
  }

  LDP_EXIT(g->user_data, "ldp_if_shutdown");

  return MPLS_SUCCESS;
}

mpls_bool ldp_if_is_active(ldp_if * i)
{
  if (i && i->entity && i->entity->admin_state == MPLS_ADMIN_ENABLE)
    return MPLS_BOOL_TRUE;

  return MPLS_BOOL_FALSE;
}

mpls_return_enum _ldp_if_add_entity(ldp_if * i, ldp_entity * e)
{
  if (i && e) {
    MPLS_REFCNT_HOLD(e);
    i->entity = e;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

ldp_entity *ldp_if_get_entity(ldp_if * i)
{
  return i->entity;
}

mpls_return_enum _ldp_if_del_entity(ldp_if * i)
{
  if (i && i->entity) {
    MPLS_REFCNT_RELEASE(i->entity, ldp_entity_delete);
    i->entity = NULL;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

uint32_t _ldp_if_get_next_index()
{
  uint32_t retval = _ldp_sub_entity_next_index;

  _ldp_sub_entity_next_index++;
  if (retval > _ldp_sub_entity_next_index) {
    _ldp_sub_entity_next_index = 1;
  }
  return retval;
}
