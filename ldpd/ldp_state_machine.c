
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_global.h"
#include "ldp_session.h"
#include "ldp_entity.h"
#include "ldp_peer.h"
#include "ldp_if.h"
#include "ldp_adj.h"
#include "ldp_mesg.h"
#include "ldp_buf.h"
#include "ldp_state_machine.h"

#include "mpls_assert.h"
#include "mpls_socket_impl.h"
#include "mpls_lock_impl.h"
#include "mpls_trace_impl.h"

/*                  HELLO CONNECT   INIT      KEEP   ADDR    LABEL   NOTIF   CLOSE  HTIMER KTIMER */
/* SES_NONE         new   ignore    ignore    ignore ignore  ignore  ignore  close  ignore ignore */
/* SES_NON_EXISTENT maint connect   close     close  close   close   close   close  close  ignore */
/* SES_INITIALIZED  maint close     recv_init close  close   close   notif   close  close  ignore */
/* SES_OPENSENT     maint close     recv_init close  close   close   notif   close  close  ignore */
/* SES_OPENREC      maint close     close     finish close   close   notif   close  close  close  */
/* SES_OPERATIONAL  maint close     kmaint    kmaint process process notif   close  close  close  */

int ldp_state_table[LDP_STATE_NUM][LDP_EVENT_NUM] = {
  {0, 6, 6, 6, 6, 6, 6, 7, 6, 6},
  {1, 3, 7, 7, 7, 7, 7, 7, 7, 6},
  {1, 7, 2, 7, 7, 7, 9, 7, 7, 6},
  {1, 7, 2, 7, 7, 7, 9, 7, 7, 6},
  {1, 7, 7, 4, 7, 7, 9, 7, 7, 7},
  {1, 7, 8, 8, 5, 5, 9, 7, 7, 7}};

mpls_return_enum ldp_buf_process(ldp_global * g, mpls_socket_handle socket,
  ldp_buf * buf, void *extra, ldp_event_enum event, mpls_dest * from,
  mpls_bool * more);

mpls_return_enum(*ldp_state_func[LDP_FUNC_NUM]) (ldp_global *, ldp_session *,
  ldp_adj *, ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *) = {
  ldp_state_new_adjacency,		/* 0 */
  ldp_state_maintainance,		/* 1 */
  ldp_state_recv_init,			/* 2 */
  ldp_state_connect,			/* 3 */
  ldp_state_finish_init,		/* 4 */
  ldp_state_process,			/* 5 */
  ldp_state_ignore,			/* 6 */
  ldp_state_close,			/* 7 */
  ldp_state_keepalive_maintainance,	/* 8 */
  ldp_state_notif			/* 9 */
};

#define LDP_FUNC_CLOSE 7

mpls_return_enum ldp_event(mpls_cfg_handle handle, mpls_socket_handle socket,
  void *extra, ldp_event_enum event)
{
  mpls_return_enum retval = MPLS_SUCCESS;
  ldp_global *g = (ldp_global*)handle;

  mpls_socket_handle socket_new = (mpls_socket_handle)0;
  ldp_session *session = NULL;
  ldp_entity *entity = NULL;
  ldp_adj *adj = NULL;

  uint8_t buffer[MPLS_PDUMAXLEN];
  mpls_dest from;
  ldp_mesg mesg;
  ldp_buf buf;

  LDP_ENTER(g->user_data, "ldp_event");

  mpls_lock_get(g->global_lock);

  switch (event) {
    case LDP_EVENT_TCP_DATA:
    case LDP_EVENT_UDP_DATA:
    {
      mpls_bool more;

      buf.current = buffer;
      buf.buffer = buffer;
      buf.total = MPLS_PDUMAXLEN;
      buf.size = 0;
      buf.current_size = 0;
      buf.want = 0;

      /* do this so a failure will know which session caused it */
      if (event == LDP_EVENT_TCP_DATA) {
        session = extra;
      }

      do {
        retval = ldp_buf_process(g, socket, &buf, extra, event, &from, &more);
      } while (retval == MPLS_SUCCESS && more == MPLS_BOOL_TRUE);
      break;
    }
    case LDP_EVENT_TCP_LISTEN:
    {
      socket_new = mpls_socket_tcp_accept(g->socket_handle, socket, &from);

      if (mpls_socket_handle_verify(g->socket_handle, socket_new) ==
        MPLS_BOOL_FALSE) {
        LDP_PRINT(g->user_data, "Failed accepting socket\n");
        retval = MPLS_FAILURE;
      } else if (!(session = ldp_session_create_passive(g, socket_new,
        &from))) {
        mpls_socket_close(g->socket_handle, socket_new);
        LDP_PRINT(g->user_data, "Failure creating passive session\n");
        retval = MPLS_FATAL;
      } else {
        retval = ldp_state_machine(g, session, NULL, NULL,
          LDP_EVENT_CONNECT, &mesg, &from);
      }
      break;
    }
    case LDP_EVENT_TCP_CONNECT:
    {
      retval = mpls_socket_connect_status(g->socket_handle, socket);
      session = (ldp_session *)extra;

      if (retval == MPLS_SUCCESS) {
        /* only get this case if we did a non-block connect */
        mpls_socket_writelist_del(g->socket_handle, socket);
        retval = ldp_state_machine(g, session, NULL, NULL,
          LDP_EVENT_CONNECT, &mesg, &from);
      } else if (retval != MPLS_NON_BLOCKING) {
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
          "ldp_event: LDP_EVENT_TCP_CONNECT errno = %d\n",
          mpls_socket_get_errno(g->socket_handle, socket));
      } else {
	/* non-blocking connect is still blocking, we'll try again in a bit */
	retval = MPLS_SUCCESS;
      }
      break;
    }
    case LDP_EVENT_CLOSE:
    {
      retval = ldp_state_machine(g, session, adj, entity,
        LDP_EVENT_CLOSE, &mesg, &from);
      break;
    }
    default:
    {
      MPLS_ASSERT(0);
    }
  }

  /* ldp_state_machine return MPLS_SUCCESS when it has handled the event
     to completion. If the handling off the event results in the session
     needing to be shutdown MPLS_FAILURE is returned.  If the handling of
     the event requires the LDP be shutdown LD_FATAL is returned, and
     passed back to the user.  other values are invalid */

  switch (retval) {
    case MPLS_FAILURE:
    {
      /* if shutting down the session results in LDP_FATAL, then pass it
       * back to the user */

      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
        "ldp_event: FAILURE executing a CLOSE\n");

      retval = ldp_state_machine(g, session, adj, entity, LDP_EVENT_CLOSE,
        NULL, &from);

      if (retval == MPLS_FATAL) {
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
          "ldp_event: CLOSE failed: FATAL propogated to the environemnt\n");
      }
      break;
    }
    case MPLS_FATAL:
    {
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
        "ldp_event: FATAL propogated to the environemnt\n");
      break;
    }
    case MPLS_SUCCESS:
    {
      break;
    }
    default:
    {
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_ERROR,
        "ldp_event: invalid return value of %d\n", retval);
      break;
    }
  }

  mpls_lock_release(g->global_lock);

  LDP_EXIT(g->user_data, "ldp_event");

  return retval;
}

mpls_return_enum ldp_state_machine(ldp_global * g, ldp_session * session,
  ldp_adj * adj, ldp_entity * entity, uint32_t event, ldp_mesg * msg,
  mpls_dest * from)
{
  int state = LDP_STATE_NONE;
  int func = 0;   extern int PW_SIGNALING_FLAG;//testing
  mpls_return_enum retval = MPLS_FAILURE;

  LDP_ENTER(g->user_data, "ldp_state_machine");

  if (session) {
    state = session->state;
  } else if (adj) {
    state = LDP_STATE_NON_EXIST;
  }

  if (state >= LDP_STATE_NONE && state <= LDP_STATE_OPERATIONAL) {
    if (event <= LDP_EVENT_KTIMER) {
      LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL, LDP_TRACE_FLAG_STATE,
        "FSM: state %d, event %d\n", state, event);  
        //printf("State: %d\n",state);//testing
      func = ldp_state_table[state][event];
        //printf("Fun: %d\n",func);//testing
      retval = ldp_state_func[func] (g, session, adj, entity, event, msg, from);
    }
  }

  LDP_EXIT(g->user_data, "ldp_state_machine");
  return retval;
}

mpls_return_enum ldp_buf_process(ldp_global * g, mpls_socket_handle socket,
  ldp_buf * buf, void *extra, ldp_event_enum event, mpls_dest * from,
  mpls_bool * more)
{

  mpls_return_enum retval = MPLS_SUCCESS;
  ldp_session *session = NULL;
  ldp_entity *entity = NULL;
  ldp_adj *adj = NULL;
  ldp_mesg mesg;

  int size = 0;

  LDP_ENTER(g->user_data, "ldp_buf_process");

  *more = MPLS_BOOL_TRUE;

  memset(&mesg, 0, sizeof(mesg));
  if (!buf->want) {
    buf->want = MPLS_LDP_HDRSIZE;
  }

read_again:

  switch (event) {
    case LDP_EVENT_TCP_DATA:
    {
      session = (ldp_session *) extra;
      MPLS_ASSERT(session);
      session->mesg_rx++;

      size = mpls_socket_tcp_read(g->socket_handle, socket,
        buf->buffer + buf->size, buf->want - buf->size);

      if (!size) {
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
        LDP_TRACE_FLAG_ERROR, "ldp_event: LDP_EVENT_TCP_DATA errno = %d\n",
          mpls_socket_get_errno(g->socket_handle, socket));

        retval = MPLS_FAILURE;
        session->shutdown_notif = LDP_NOTIF_SHUTDOWN;
        session->shutdown_fatal = MPLS_BOOL_TRUE;
        goto ldp_event_end;
      } 

      if (size < 0) {
        retval = MPLS_SUCCESS;
        *more = MPLS_BOOL_FALSE;
        goto ldp_event_end;
      }
      break;
    }
    case LDP_EVENT_UDP_DATA:
    {
      size = mpls_socket_udp_recvfrom(g->socket_handle, socket,
        buf->buffer + buf->size, buf->total - buf->size, from);

      if (!size) {
        LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
          LDP_TRACE_FLAG_ERROR, "ldp_event: LDP_EVENT_UDP_DATA errno = %d\n",
        mpls_socket_get_errno(g->socket_handle, socket));
        retval = MPLS_FAILURE;
        goto ldp_event_end;
      }

      if (size < 0) {
        retval = MPLS_SUCCESS;
        *more = MPLS_BOOL_FALSE;
        goto ldp_event_end;
      }
      break;
    }
    default:
    {
      MPLS_ASSERT(0);
      break;
    }
  }

  buf->current_size += size;
  buf->size += size;

decode_again:

  if (buf->size < buf->want) {
    retval = MPLS_SUCCESS;
    *more = MPLS_BOOL_FALSE;
    goto ldp_event_end;
  }

  /* upon succesful decode the pduLength will be non 0 */
  if (!mesg.header.pduLength) {
    if (ldp_decode_header(g, buf, &mesg) != MPLS_SUCCESS) {
      retval = MPLS_FAILURE;

      if (session) {
        session->shutdown_notif = LDP_NOTIF_BAD_MESG_LEN;
      }
      goto ldp_event_end;
    }

    /* -buf->size is already 10 (the size of the full header
     * -pduLength include 6 bytes of the header
     *
     * therefore add 4 so we can compare buf->want to buf->size and
     * not have to adjust
     */
    buf->want = mesg.header.pduLength + 4;
    if (buf->size < buf->want) {
      goto read_again;
    }
    if (buf->size > buf->want) {
      buf->current_size = buf->want - MPLS_LDP_HDRSIZE;
    }
  }

  do {
    if (ldp_decode_one_mesg(g, buf, &mesg) != MPLS_SUCCESS) {
      retval = MPLS_FAILURE;

      if (session) {
        session->shutdown_notif = LDP_NOTIF_BAD_MESG_LEN;
      }
      goto ldp_event_end_loop;
    }

    switch (ldp_mesg_get_type(&mesg)) {
      case MPLS_HELLO_MSGTYPE:
      {
        mpls_oper_state_enum oper_state = MPLS_OPER_DOWN;
        mpls_inet_addr addr;
        int labelspace = 0;
        int targeted;

        event = LDP_EVENT_HELLO;

        targeted = 0;
        ldp_mesg_hello_get_targeted(&mesg, &targeted);
        ldp_mesg_hdr_get_lsraddr(&mesg, &addr);
        ldp_mesg_hdr_get_labelspace(&mesg, &labelspace);

        if (targeted) {
          ldp_peer *peer = NULL;
          if ((peer = ldp_global_find_peer_addr(g, &addr))) {
            entity = ldp_peer_get_entity(peer);
            oper_state = peer->oper_state;
          }
        } else {
          ldp_if *iff = NULL;
          if ((iff = ldp_global_find_if_handle(g, from->if_handle))) {
            entity = ldp_if_get_entity(iff);
            oper_state = iff->oper_state;
          }
        }

        if (!entity) {
          /* No entity! No choice but to ignore this packet */
          LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
            LDP_TRACE_FLAG_NORMAL, "ldp_event: unknown entity\n");
          goto ldp_event_end_loop;
        } else if (entity->admin_state == MPLS_ADMIN_DISABLE) {
          LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
            LDP_TRACE_FLAG_NORMAL, "ldp_event: entity is disabled\n");
          goto ldp_event_end_loop;
        } else if (oper_state == MPLS_OPER_DOWN) {
          LDP_TRACE_LOG(g->user_data, MPLS_TRACE_STATE_ALL,
            LDP_TRACE_FLAG_NORMAL, "ldp_event: entity is down\n");
          goto ldp_event_end_loop;
        }

        
	if ((adj = ldp_entity_find_adj(entity, &mesg))) {
	  session = adj->session;
	} else {
	  session = NULL;
	}
        /* if we don't have an adj one will be create by state machine */
        break;
      }
      case MPLS_INIT_MSGTYPE:
      {
        event = LDP_EVENT_INIT;
        break;
      }
      case MPLS_NOT_MSGTYPE:
      {
        event = LDP_EVENT_NOTIF;
        break;
      }
      case MPLS_KEEPAL_MSGTYPE:
      {
        event = LDP_EVENT_KEEP;
        break;
      }
      case MPLS_LBLWITH_MSGTYPE:
      case MPLS_LBLREL_MSGTYPE:
      case MPLS_LBLREQ_MSGTYPE:
      case MPLS_LBLMAP_MSGTYPE:
      case MPLS_LBLABORT_MSGTYPE:
      {
        event = LDP_EVENT_LABEL;
        break;
      }
      case MPLS_ADDR_MSGTYPE:
      case MPLS_ADDRWITH_MSGTYPE:
      {
        event = LDP_EVENT_ADDR;
        break;
      }
      default:
      {
        MPLS_ASSERT(0);
      }
    }

    retval =
      ldp_state_machine(g, session, adj, entity, event, &mesg, from);

ldp_event_end_loop:

    if (retval != MPLS_SUCCESS) {
      break;
    }
  } while ((buf->current_size > 0) && (*more == MPLS_BOOL_TRUE));

  if (buf->want < buf->size) {
    buf->current_size = buf->size - buf->want;
    buf->size = buf->current_size;
    memmove(buf->buffer, buf->current, buf->current_size);
  } else {
    buf->size = 0;
  }

  buf->current = buf->buffer;
  memset(&mesg, 0, sizeof(mesg));
  buf->want = MPLS_LDP_HDRSIZE;

  if (buf->current_size) {
    goto decode_again;
  }

ldp_event_end:

  LDP_EXIT(g->user_data, "ldp_buf_process");

  return retval;
}
