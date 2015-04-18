
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_STATE_MACHINE_H_
#define _LDP_STATE_MACHINE_H_

#include "ldp_struct.h"

extern mpls_return_enum ldp_event(mpls_cfg_handle g, mpls_socket_handle socket,
  void *extra, ldp_event_enum event);

extern mpls_return_enum ldp_state_machine(ldp_global *, ldp_session *,
  ldp_adj *, ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);

extern mpls_return_enum ldp_state_new_adjacency(ldp_global *, ldp_session *,
  ldp_adj *, ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);
extern mpls_return_enum ldp_state_maintainance(ldp_global *, ldp_session *,
  ldp_adj *, ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);
extern mpls_return_enum ldp_state_recv_init(ldp_global *, ldp_session *,
  ldp_adj *, ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);
extern mpls_return_enum ldp_state_connect(ldp_global *, ldp_session *,
  ldp_adj *, ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);
extern mpls_return_enum ldp_state_finish_init(ldp_global *, ldp_session *,
  ldp_adj *, ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);
extern mpls_return_enum ldp_state_process(ldp_global *, ldp_session *,
  ldp_adj *, ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);
extern mpls_return_enum ldp_state_ignore(ldp_global *, ldp_session *, ldp_adj *,
  ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);
extern mpls_return_enum ldp_state_close(ldp_global *, ldp_session *, ldp_adj *,
  ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);
extern mpls_return_enum ldp_state_keepalive_maintainance(ldp_global *,
  ldp_session *, ldp_adj *, ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);
extern mpls_return_enum ldp_state_notif(ldp_global *, ldp_session *, ldp_adj *,
  ldp_entity *, uint32_t, ldp_mesg *, mpls_dest *);

#endif
