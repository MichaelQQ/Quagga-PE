
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_PEER_H_
#define _LDP_PEER_H_

#include "ldp_struct.h"

extern ldp_peer *ldp_peer_create();
extern void ldp_peer_delete(ldp_peer * p);
extern mpls_return_enum ldp_peer_startup(ldp_global * g, ldp_peer * p);
extern mpls_return_enum ldp_peer_shutdown(ldp_global * g, ldp_peer * p);
extern mpls_bool ldp_peer_is_active(ldp_peer * p);
extern mpls_return_enum _ldp_peer_add_entity(ldp_peer * p, ldp_entity * e);
extern mpls_return_enum _ldp_peer_del_entity(ldp_peer * p);
extern ldp_entity *ldp_peer_get_entity(ldp_peer * p);
extern uint32_t _ldp_peer_get_next_index();
extern void ldp_peer_retry_stop(ldp_global * g, ldp_peer * p);
extern void ldp_peer_send_stop(ldp_global * g, ldp_peer * p);
extern void ldp_peer_retry_callback(mpls_timer_handle timer, void *extra,
  mpls_cfg_handle g);

#endif
