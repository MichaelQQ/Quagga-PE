
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include <sys/socket.h>
#include "ldp_struct.h"
#include "ldp_global.h"
#include "ldp_session.h"
#include "ldp_entity.h"
#include "ldp_fec.h"
#include "ldp_adj.h"
#include "ldp_attr.h"
#include "ldp_mesg.h"
#include "ldp_hello.h"
#include "ldp_init.h"
#include "ldp_label_rel_with.h"
#include "ldp_label_mapping.h"
#include "ldp_label_request.h"
#include "ldp_addr.h"
#include "ldp_keepalive.h"
#include "ldp_label_request.h"
#include "ldp_label_mapping.h"
#include "ldp_notif.h"
#include "ldp_label_abort.h"
#include "ldp_inet_addr.h"

#include "mpls_assert.h"
#include "mpls_tree_impl.h"
#include "mpls_trace_impl.h"
#include "mpls_socket_impl.h"
//#include "vpn_mesg.h" //add by timothy at 05.05.23
//#include "common.h"
#include "connect_daemon.h" //add by here
#include "ldp_via_vpnm.h"

mpls_return_enum ldp_state_new_adjacency(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, uint32_t event, ldp_mesg * msg, mpls_dest * from)
{
  mpls_inet_addr traddr, lsraddr, *addr;
  ldp_adj *local_a = NULL;
  int labelspace;
  int hellotime;
  int request = 0;
  int target = 0;
  uint32_t csn = 0;
  mpls_return_enum retval = MPLS_FAILURE;

  MPLS_ASSERT(msg && e);

  LDP_ENTER(g->user_data, "ldp_state_new_adjacency");

  ldp_mesg_hdr_get_labelspace(msg, &labelspace);
  ldp_mesg_hdr_get_lsraddr(msg, &lsraddr);
  ldp_mesg_hello_get_hellotime(msg, &hellotime);
  ldp_mesg_hello_get_request(msg, &request);
  ldp_mesg_hello_get_targeted(msg, &target);
  ldp_mesg_hello_get_csn(msg, &csn);

  if (ldp_mesg_hello_get_traddr(msg, &traddr) == MPLS_FAILURE) {
    addr = NULL;
  } else {
    addr = &traddr;
  }

  e->mesg_rx++;

  if ((local_a = ldp_adj_create(&from->addr, &lsraddr, labelspace,
    hellotime, addr, csn)) == NULL) {
    goto ldp_state_new_adjacency_end;
  }
  ldp_entity_add_adj(e, local_a);
  _ldp_global_add_adj(g, local_a);
  if (ldp_hello_process(g, local_a, e, hellotime, csn, addr, target,
    request) != MPLS_SUCCESS) {
    /* this can fail if we could not create an active session, or
     * we're getting errored hellos, 
     * if this fails then undo the e<->a linking (which will delete a) */
    ldp_entity_del_adj(e, local_a);
    _ldp_global_del_adj(g, local_a);
  } else if (ldp_adj_startup(g, local_a, request) != MPLS_SUCCESS) {
    /* the only way this fail is if a timer could not be created
     * if this fails then undo the e<->a linking (which will delete a) */
    ldp_entity_del_adj(e, local_a);
    _ldp_global_del_adj(g, local_a);
  } else {
    /* by this time, we will have a e<->a binding, and some timers,
     * if we're active, there will also be an active session */
    retval = MPLS_SUCCESS;
  }

ldp_state_new_adjacency_end:

  LDP_EXIT(g->user_data, "ldp_state_new_adjacency");
  return retval;
}

mpls_return_enum ldp_state_maintainance(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, uint32_t event, ldp_mesg * msg, mpls_dest * from)
{
  mpls_inet_addr traddr, *addr;
  int hellotime;
  int request = 0;
  int target = 0;
  uint32_t csn = 0;
  mpls_return_enum retval = MPLS_SUCCESS;

  MPLS_ASSERT(msg && e);

  LDP_ENTER(g->user_data, "ldp_state_maintainance");

  if (ldp_mesg_hello_get_hellotime(msg, &hellotime) != MPLS_SUCCESS) {
    retval = MPLS_FAILURE;
    goto ldp_state_maintainance_end;
  }

  ldp_mesg_hello_get_request(msg, &request);
  ldp_mesg_hello_get_targeted(msg, &target);
  /* if there isn't a csn in the msg, then csn stays 0 */
  ldp_mesg_hello_get_csn(msg, &csn);
  if (ldp_mesg_hello_get_traddr(msg, &traddr) != MPLS_SUCCESS) {
    addr = NULL;
  } else {
    addr = &traddr;
  }

  if (ldp_hello_process(g, a, e, hellotime, csn, addr, target,
      request) != MPLS_SUCCESS) {
    retval = MPLS_FAILURE;
    goto ldp_state_maintainance_end;
  }
  retval = ldp_adj_maintain_timer(g, a);
  e->mesg_rx++;

ldp_state_maintainance_end:

  LDP_EXIT(g->user_data, "ldp_state_maintainance");

  return retval;
}

mpls_return_enum ldp_state_recv_init(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, uint32_t event, ldp_mesg * msg, mpls_dest * from)
{
  mpls_inet_addr lsraddr;
  ldp_adj* ap;
  int labelspace = 0;
  mpls_bool match = MPLS_BOOL_FALSE;

  MPLS_ASSERT(msg && s);

  LDP_ENTER(g->user_data, "ldp_state_recv_init");

  /* we haven't tied this session to an adj yet, at a minimum we can
   * now stop the backoff timer we started while waiting for this
   * init to arrive */
  ldp_session_backoff_stop(g, s);

  ldp_mesg_hdr_get_lsraddr(msg, &lsraddr);
  ldp_mesg_hdr_get_labelspace(msg, &labelspace);

  if (s->oper_role != LDP_ACTIVE) {
    /* sessions being created from the ACTIVE side of an ADJ have already
     * bound to the session */
    /* there may be multiple ADJ that are matched! */
    ap = MPLS_LIST_HEAD(&g->adj);
    while (ap != NULL) {
      if ((!mpls_inet_addr_compare(&lsraddr, &ap->remote_lsr_address)) &&
        labelspace == ap->remote_label_space && !ap->session) {
        ldp_adj_add_session(ap, s);
        match = MPLS_BOOL_TRUE;
      }
      ap = MPLS_LIST_NEXT(&g->adj, ap, _global);
    }

    if (match == MPLS_BOOL_FALSE) {
      LDP_PRINT(g->user_data, "ldp_state_recv_init: cannot find adj\n");
      s->shutdown_notif = LDP_NOTIF_SESSION_REJECTED_NO_HELLO;
      s->shutdown_fatal = MPLS_BOOL_FALSE;
      goto ldp_state_recv_init_shutdown;
    }
  }

  if (ldp_init_process(g, s, msg) == MPLS_FAILURE) {
    LDP_PRINT(g->user_data, "ldp_state_recv_init: invalid INIT parameters\n");
    /* session shutdown notif info set inside init_process */
    goto ldp_state_recv_init_shutdown;
  }

  s->state = LDP_STATE_OPENREC;
  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
    "ldp_state_recv_init: (%d) changed to OPENREC\n", s->index);

  if (s->oper_role == LDP_PASSIVE) {
    if (ldp_init_send(g, s) == MPLS_FAILURE) {
      LDP_PRINT(g->user_data, "ldp_state_recv_init: unable to send INIT\n");
      s->shutdown_notif = LDP_NOTIF_INTERNAL_ERROR;
      s->shutdown_fatal = MPLS_BOOL_TRUE;
      goto ldp_state_recv_init_shutdown;
    }
  }
  ldp_keepalive_send(g, s);

  LDP_EXIT(g->user_data, "ldp_state_recv_init");
  return MPLS_SUCCESS;

ldp_state_recv_init_shutdown:

  LDP_EXIT(g->user_data, "ldp_state_recv_init-error");
  return MPLS_FAILURE;
}

mpls_return_enum ldp_state_connect(ldp_global * g, ldp_session * s, ldp_adj * a,
  ldp_entity * e, uint32_t event, ldp_mesg * msg, mpls_dest * from)
{
  mpls_return_enum retval = MPLS_SUCCESS;

  LDP_ENTER(g->user_data, "ldp_state_connect");

  mpls_socket_readlist_add(g->socket_handle, s->socket, (void *)s,
    MPLS_SOCKET_TCP_DATA);
  s->state = LDP_STATE_INITIALIZED;
  LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
    "ldp_state_connect: (%d) changed to INITIALIZED\n", s->index);

  /* even though as part of creating an active session, the remote_dest
   * was filled in, it had port 646 specified. 'from' now contains the
   * real port info that our TCP session is connected to */
  if (from) {
    memcpy(&s->remote_dest, from, sizeof(mpls_dest));
  }

  if (s->oper_role == LDP_ACTIVE) {
    if (ldp_init_send(g, s) == MPLS_SUCCESS) {
      s->state = LDP_STATE_OPENSENT;
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_DEBUG,
        "ldp_state_connect: (%d) changed to OPENSENT\n", s->index);
    } else {
      s->shutdown_notif = LDP_NOTIF_INTERNAL_ERROR;
      s->shutdown_fatal = MPLS_BOOL_TRUE;
      retval = MPLS_FAILURE;
    }
  } else {
    /* if this session is passive, we still are not associated with an
     * adj.  That will happen when we receive an init. There are no timers
     * running yet, so we need to create a timer, to clean this socket
     * up, if we do not receive a Init mesg, we'll overload the backoff
     * timer for this purpose */
    retval = ldp_session_backoff_start(g, s);
  }

  LDP_EXIT(g->user_data, "ldp_state_connect");

  return retval;
}

mpls_return_enum ldp_state_finish_init(ldp_global * g, ldp_session * s,
  ldp_adj * a, ldp_entity * e, uint32_t event, ldp_mesg * msg, mpls_dest * from)
{
  mpls_return_enum retval;
  MPLS_ASSERT(s);

  LDP_ENTER(g->user_data, "ldp_state_finish_init");

  retval = ldp_session_startup(g, s);

  LDP_EXIT(g->user_data, "ldp_state_finish_init");

  return MPLS_SUCCESS;
}

mpls_return_enum ldp_state_process(ldp_global * g, ldp_session * s, ldp_adj * a,
  ldp_entity * e, uint32_t event, ldp_mesg * msg, mpls_dest * from)
{
  mpls_return_enum retval = MPLS_SUCCESS;
  ldp_attr *r_attr;
  mpls_fec fec;
  int i;
  char buf[200];//add by here
  int retval_here;//add by here
  struct in_addr tmp_addr;//add by here

  MPLS_ASSERT(s && msg);

  LDP_ENTER(g->user_data, "ldp_state_process");

  switch (msg->u.generic.flags.flags.msgType) {
    case MPLS_LBLWITH_MSGTYPE:
      {
        mplsLdpLbl_W_R_Msg_t *rw = &msg->u.release;
				ldp_fec *f;

        for (i = 0; i < rw->fecTlv.numberFecElements; i++) {
          if(rw->fecTlv.fecElArray[i].pwidEl.pw_tlv==MPLS_PW_ID_FEC)//add by timothy at 05.05.23
          {
            //send vpnmd the message.
            tmp_addr.s_addr=htonl(msg->header.lsrAddress);
            VPNM_Command cmd;
     				cmd=vpnmRcvLdpWithdrawMsg;
      			connect_daemon(VTYSH_INDEX_VPNMD);
      			sprintf(buf,"ldpCmd_type %d arg0 %d arg1 %s arg2 %s arg3 %s\n",cmd,rw->fecTlv.fecElArray[i].pwidEl.pw_id,inet_ntoa(tmp_addr),"NULL","NULL");
      			printf("Debug msg(labelwithdraw) :%s\n",buf);
      			vtysh_client_execute(&vtysh_client[VTYSH_INDEX_VPNMD], buf, stdout);
      			exit_daemon(VTYSH_INDEX_VPNMD);
            break;
          }
          fec_tlv2mpls_fec(&rw->fecTlv, i, &fec);
          if (!(r_attr = ldp_attr_create(&fec))) {
            goto ldp_state_process_error;
          }

          MPLS_REFCNT_HOLD(r_attr);

          rel_with2attr(rw, r_attr);
	  f = ldp_fec_find2(g, &fec);
          retval = ldp_label_withdraw_process(g, s, a, e, r_attr, f);

          MPLS_REFCNT_RELEASE(r_attr, ldp_attr_delete);
          if (retval != MPLS_SUCCESS)
            break;
        }
        break;
      }
    case MPLS_LBLREL_MSGTYPE:
      {
        mplsLdpLbl_W_R_Msg_t *rw = &msg->u.release;
	ldp_fec *f;

        for (i = 0; i < rw->fecTlv.numberFecElements; i++) {
          if(rw->fecTlv.fecElArray[i].pwidEl.pw_tlv==MPLS_PW_ID_FEC)//add by timothy at 05.06.10
          {

            connect_daemon(VTYSH_INDEX_LMD);
    				sprintf(buf,"releaseLabelToPool pool_id %d label %d\n",LDP_POOL_ID,rw->genLblTlv.label);
    				retval_here=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LMD], buf, stdout);
    				printf("Debug msg(releaseLabelToPool) retval:%d\n",retval);
    				exit_daemon(VTYSH_INDEX_LMD);
 
            tmp_addr.s_addr=htonl(msg->header.lsrAddress);
            VPNM_Command cmd;
     				cmd=vpnmRcvLdpReleaseMsg;
      			connect_daemon(VTYSH_INDEX_VPNMD);
      			sprintf(buf,"ldpCmd_type %d arg0 %d arg1 %s arg2 %s arg3 %s\n",cmd,rw->fecTlv.fecElArray[i].pwidEl.pw_id,inet_ntoa(tmp_addr),"NULL","NULL");
      			printf("Debug msg (labelrelease):%s\n",buf);
      			vtysh_client_execute(&vtysh_client[VTYSH_INDEX_VPNMD], buf, stdout);
      			exit_daemon(VTYSH_INDEX_VPNMD);
            break;
          }

          fec_tlv2mpls_fec(&rw->fecTlv, i, &fec);
          if (!(r_attr = ldp_attr_create(&fec))) {
            goto ldp_state_process_error;
          }

          MPLS_REFCNT_HOLD(r_attr);

          rel_with2attr(rw, r_attr);
	  f = ldp_fec_find2(g, &fec);
          retval = ldp_label_release_process(g, s, a, e, r_attr, f);

          MPLS_REFCNT_RELEASE(r_attr, ldp_attr_delete);
          if (retval != MPLS_SUCCESS)
            break;
        }
        break;
      }
    case MPLS_LBLREQ_MSGTYPE:
      {
        mplsLdpLblReqMsg_t *req = &msg->u.request;
	ldp_fec *f;

        MPLS_ASSERT(req->fecTlv.numberFecElements == 1);

        for (i = 0; i < req->fecTlv.numberFecElements; i++) {
          fec_tlv2mpls_fec(&req->fecTlv, i, &fec);
          if (!(r_attr = ldp_attr_create(&fec))) {
            goto ldp_state_process_error;
          }

          MPLS_REFCNT_HOLD(r_attr);

          req2attr(req, r_attr, LDP_ATTR_ALL & ~LDP_ATTR_FEC);
	  f = ldp_fec_find2(g, &fec);
          retval = ldp_label_request_process(g, s, a, e, r_attr, f);

          MPLS_REFCNT_RELEASE(r_attr, ldp_attr_delete);
          if (retval != MPLS_SUCCESS)
            break;
        }
        break;
      }
    case MPLS_LBLMAP_MSGTYPE:
      {
        mplsLdpLblMapMsg_t *map = &msg->u.map;
	ldp_fec *f;
        for (i = 0; i < map->fecTlv.numberFecElements; i++) {
          if(map->fecTlv.fecElArray[i].pwidEl.pw_tlv==MPLS_PW_ID_FEC)//add by timothy at 05.05.24
          {
            tmp_addr.s_addr=htonl(msg->header.lsrAddress);
            VPNM_Command cmd;
     				cmd=vpnmOutPwLabel;
      			connect_daemon(VTYSH_INDEX_VPNMD);
      			sprintf(buf,"ldpCmd_type %d arg0 %d arg1 %s arg2 %d arg3 %s\n",cmd,map->fecTlv.fecElArray[i].pwidEl.pw_id,inet_ntoa(tmp_addr),map->genLblTlv.label,"NULL");
      			printf("Debug Message :%s\n",buf);
      			vtysh_client_execute(&vtysh_client[VTYSH_INDEX_VPNMD], buf, stdout);
      			exit_daemon(VTYSH_INDEX_VPNMD);
            break;
          }
          fec_tlv2mpls_fec(&map->fecTlv, i, &fec);
          if (!(r_attr = ldp_attr_create(&fec))) { 
            goto ldp_state_process_error;
          }
          MPLS_REFCNT_HOLD(r_attr);

          map2attr(map, r_attr, LDP_ATTR_ALL & ~LDP_ATTR_FEC);
	  f = ldp_fec_find2(g, &fec);
          retval = ldp_label_mapping_process(g, s, a, e, r_attr, f);

          MPLS_REFCNT_RELEASE(r_attr, ldp_attr_delete);
          if (retval != MPLS_SUCCESS)
            break;
        }
        break;
      }
    case MPLS_LBLABORT_MSGTYPE:
      {
        mplsLdpLblAbortMsg_t *abrt = &msg->u.abort;
	ldp_fec *f;

        for (i = 0; i < abrt->fecTlv.numberFecElements; i++) {
          fec_tlv2mpls_fec(&abrt->fecTlv, i, &fec);
          if (!(r_attr = ldp_attr_create(&fec))) {
            goto ldp_state_process_error;
          }

          MPLS_REFCNT_HOLD(r_attr);
          abort2attr(abrt, r_attr, LDP_ATTR_ALL & ~LDP_ATTR_FEC);
	  f = ldp_fec_find2(g, &fec);
          retval = ldp_label_abort_process(g, s, a, e, r_attr, f);

          MPLS_REFCNT_RELEASE(r_attr, ldp_attr_delete);
          if (retval != MPLS_SUCCESS)
            break;
        }
        break;
      }
    case MPLS_ADDRWITH_MSGTYPE:
    case MPLS_ADDR_MSGTYPE:
      {
        retval = ldp_addr_process(g, s, e, msg);
        break;
      }
    default:
      {
        MPLS_ASSERT(0);
        break;
      }
  }

  LDP_EXIT(g->user_data, "ldp_state_process");

  return retval;

ldp_state_process_error:

  LDP_EXIT(g->user_data, "ldp_state_process");

  s->shutdown_notif = LDP_NOTIF_INTERNAL_ERROR;
  s->shutdown_fatal = MPLS_BOOL_TRUE;
  return MPLS_FAILURE;
}

mpls_return_enum ldp_state_ignore(ldp_global * g, ldp_session * session,
  ldp_adj * adj, ldp_entity * entity, uint32_t event, ldp_mesg * msg,
  mpls_dest * from)
{
  return MPLS_SUCCESS;
}

mpls_return_enum ldp_state_close(ldp_global * g, ldp_session * s, ldp_adj * a,
  ldp_entity * e, uint32_t event, ldp_mesg * msg, mpls_dest * from)
{

  LDP_ENTER(g->user_data, "ldp_state_close: a = %p, e = %p s = %p",a,e,s);

  /* JLEU: this need more work */
  if (s) {
    /* not sure why we got here but we should tear it completely down */
    if (s->shutdown_fatal != MPLS_BOOL_TRUE) {
      ldp_notif_send(g,s,NULL,s->shutdown_notif);
    }
    ldp_session_shutdown(g, s, MPLS_BOOL_TRUE);
  }

  LDP_EXIT(g->user_data, "ldp_state_close");
  return MPLS_SUCCESS;
}

mpls_return_enum ldp_state_keepalive_maintainance(ldp_global * g,
  ldp_session * s, ldp_adj * a, ldp_entity * e, uint32_t event, ldp_mesg * msg,
  mpls_dest * from)
{
  mpls_return_enum result;

  MPLS_ASSERT(s);

  LDP_ENTER(g->user_data, "ldp_state_keepalive_maintainance");
  result = ldp_session_maintain_timer(g, s, LDP_KEEPALIVE_RECV);

  LDP_EXIT(g->user_data, "ldp_state_keepalive_maintainance");

  return result;
}

mpls_return_enum ldp_state_notif(ldp_global * g, ldp_session * s, ldp_adj * adj,
  ldp_entity * entity, uint32_t event, ldp_mesg * msg, mpls_dest * from)
{

  mpls_return_enum retval = MPLS_SUCCESS;
  ldp_attr *r_attr = NULL;
  mplsLdpNotifMsg_t *not = &msg->u.notif;

  MPLS_ASSERT(s && msg);

  LDP_ENTER(g->user_data, "ldp_state_notif");

  if (!(r_attr = ldp_attr_create(NULL))) {
    retval = MPLS_FAILURE;
    goto ldp_state_notif_end;
  }

  MPLS_REFCNT_HOLD(r_attr);

  not2attr(not, r_attr, LDP_ATTR_ALL);
  retval = ldp_notif_process(g, s, adj, entity, r_attr);

  MPLS_REFCNT_RELEASE(r_attr, ldp_attr_delete);

ldp_state_notif_end:

  LDP_EXIT(g->user_data, "ldp_state_notif");

  return retval;
}
