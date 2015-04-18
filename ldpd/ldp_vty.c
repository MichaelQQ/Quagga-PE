#include <zebra.h>

#include "zclient.h"
#include "vty.h"
#include "command.h"
#include "table.h"

#include "ldp.h"
#include "ldp_cfg.h"
#include "ldp_vty.h"
#include "ldp_interface.h"
#include "ldp_struct.h"
#include "ldp_remote_peer.h"
#include "ldp_zebra.h"

#include "impl_mpls.h"

#include "ldp_pw.h"
#include "connect_daemon.h" //add by here
#include "ldp_via_vpnm.h"
//#include "vpn_mesg.h"


uint32_t ldp_traceflags = 0;
uint8_t trace_buffer[16834];
int trace_buffer_len = 0;

static char *session_state[6] = { "NONE", "NON-EXIST", "INIT",
                           "OPENSENT", "OPENRECV", "OPERATIONAL" };
// static char *adj_role[3] = { "INVALID", "PASSIVE", "ACTIVE" };
static char *attr_state[12] = { "REQ_RECV", "REQ_SENT", "MAP_RECV", "MAP_SENT",
                         "WITH_SENT", "WITH_RECV", "NO_LABEL_RESOURCE_SENT",
                         "NO_LABEL_RESOURCE_RECV", "ABORT_SENT", "ABORT_RECV",
                         "NOTIF_SENT", "NOTIF_RECV" };
// static char *oper_state[2] = { "UP", "DOWN" };
static char *control_mode[3] = { "UNKNOWN", "INDEPENDENT", "ORDERED" };
static char *retention_mode[3] = { "UNKNOWN", "LIBERAL", "CONSERVATIVE" };
static char *repair_mode[3] = { "UNKNOWN", "LOCAL", "GLOBAL" };
static char *loop_detect_mode[5] = { "NONE", "HOPCOUNT", "PATHVECTOR",
                              "HOPCOUNT PATHVECTOR", "OTHER" };
char *bool[2] = { "FALSE", "TRUE" };
static char *admin_state[3] = { "NONE", "ENABLED", "DISABLED" };
static char *distribution_mode[2] = { "UNSOLICITED", "ONDEMAND" };

extern struct zclient *zclient;


DEFUN (ldp,
       ldp_cmd,
       "mpls ip",
       "MPLS configuration\n"
       "Dynamic Label distribution via LDP\n")
{
    vty->node = LDP_NODE;
    vty->index = ldp_get();
    if (!vty->index) {
	vty->index = ldp_new();
	if (!vty->index) {
	    vty_out (vty, "Unable to create LDP instance.%s", VTY_NEWLINE);
	    return CMD_WARNING;
	}
    }
    return CMD_SUCCESS;
}

DEFUN (no_ldp,
       no_ldp_cmd,
       "no mpls ip",
       NO_STR
       "MPLS configuration\n"
       "Dynamic Label distribution via LDP\n")
{
    struct ldp *ldp = ldp_get();

    if (!ldp) {
	vty_out (vty, "There isn't active an LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }

    ldp_finish(ldp);
    return CMD_SUCCESS;
}

DEFUN (ldp_lsrid,
       ldp_lsrid_cmd,
       "lsr-id A.B.C.D",
       "LDP Label Switch Router Identifier\n"
       "IP Address\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;

  ldp->lsr_id_is_static = MPLS_BOOL_TRUE;

  ldp_admin_state_start(ldp);
  do_ldp_router_id_update(ldp, ntohl(inet_addr(argv[0])));
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_lsrid,
       no_ldp_lsrid_cmd,
       "no lsr-id",
       NO_STR
       "LDP LSRID\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;

  ldp->lsr_id_is_static = MPLS_BOOL_FALSE;

  ldp_admin_state_start(ldp);
  do_ldp_router_id_update(ldp, ntohl(router_id.u.prefix4.s_addr));
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (ldp_disable,
       ldp_disable_cmd,
       "disable",
       "Disable\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;

  ldp_admin_state_start(ldp);
  ldp->admin_up = MPLS_BOOL_FALSE;
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_disable,
       no_ldp_disable_cmd,
       "no disable",
       NO_STR
       "Disable\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;

  ldp_admin_state_start(ldp);
  ldp->admin_up = MPLS_BOOL_TRUE;
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}


DEFUN (ldp_lsp_control_mode,
       ldp_lsp_control_mode_cmd,
       "lsp-control-mode (independent|ordered)",
       "control mode\n"
       "independent or ordered control mode\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  if (!strcmp(argv[0],"independent")) {
    g.lsp_control_mode = LDP_CONTROL_INDEPENDENT;
  } else if (!strcmp(argv[0],"ordered")) {
    g.lsp_control_mode = LDP_CONTROL_ORDERED;
  } else {
    return CMD_WARNING;
  }

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_CONTROL_MODE);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

#if 0
DEFUN (no_ldp_lsp_control_mode,
       no_ldp_lsp_control_mode_cmd,
       "no lsp-control-mode",
       NO_STR
       "control mode\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.lsp_control_mode = LDP_GLOBAL_DEF_CONTROL_MODE;

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_CONTROL_MODE);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (ldp_label_retention_mode,
       ldp_label_retention_mode_cmd,
       "label-retention-mode (liberal|conservative)",
       "label retention mode\n"
       "liberal or conservative retention mode\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  if (!strcmp(argv[0],"liberal")) {
    g.label_retention_mode = LDP_RETENTION_LIBERAL;
  } else if (!strcmp(argv[0],"conservative")) {
    g.label_retention_mode = LDP_RETENTION_CONSERVATIVE;
  } else {
    return CMD_WARNING;
  }

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_RETENTION_MODE);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_label_retention_mode,
       no_ldp_label_retention_mode_cmd,
       "no label-retention-mode",
       NO_STR
       "label retiontion mode\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.label_retention_mode = LDP_GLOBAL_DEF_RETENTION_MODE;

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_RETENTION_MODE);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (ldp_lsp_repair_mode,
       ldp_lsp_repair_mode_cmd,
       "lsp-repair-mode (local|global)",
       "repair mode\n"
       "local or global repair mode\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  if (!strcmp(argv[0],"local")) {
    g.lsp_repair_mode = LDP_REPAIR_LOCAL;
  } else if (!strcmp(argv[0],"global")) {
    g.lsp_repair_mode = LDP_REPAIR_GLOBAL;
  } else {
    return CMD_WARNING;
  }
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_REPAIR_MODE);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_lsp_repair_mode,
       no_ldp_lsp_repair_mode_cmd,
       "no lsp-repair-mode",
       NO_STR
       "repair mode\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.lsp_repair_mode = LDP_GLOBAL_DEF_REPAIR_MODE;
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_REPAIR_MODE);

  return CMD_SUCCESS;
}

DEFUN (ldp_propogate_release,
       ldp_propogate_release_cmd,
       "propagate-release",
       "propagate release\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.propagate_release = MPLS_BOOL_TRUE;
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_PROPOGATE_RELEASE);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_propogate_release,
       no_ldp_propogate_release_cmd,
       "no propagate-release",
       NO_STR
       "propagate release\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.propagate_release = MPLS_BOOL_FALSE;
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_PROPOGATE_RELEASE);

  return CMD_SUCCESS;
}

DEFUN (ldp_label_merge,
       ldp_label_merge_cmd,
       "label-merge",
       "label merge\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.label_merge = MPLS_BOOL_TRUE;

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_LABEL_MERGE);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_label_merge,
       no_ldp_label_merge_cmd,
       "no label-merge",
       NO_STR
       "label merge\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.label_merge = MPLS_BOOL_FALSE;

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_LABEL_MERGE);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (ldp_loop_detection_mode,
       ldp_loop_detection_mode_cmd,
       "loop-detection-mode (hop|path|both)",
       "loop detection\n"
       "Path Vector, Hop Count, or both\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  if (!strncmp(argv[0],"hop",3)) {
    g.loop_detection_mode = LDP_LOOP_HOPCOUNT;
  } else if (!strncmp(argv[0],"path",4)) {
    g.loop_detection_mode = LDP_LOOP_PATHVECTOR;
  } else if (!strncmp(argv[0],"both",4)) {
    g.loop_detection_mode = LDP_LOOP_HOPCOUNT_PATHVECTOR;
  } else {
    return CMD_WARNING;
  }
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_LOOP_DETECTION_MODE);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_loop_detection_mode,
       no_ldp_loop_detection_mode_cmd,
       "no loop-detection-mode (path|hop|both)",
       NO_STR
       "loop detection\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.loop_detection_mode = LDP_LOOP_NONE;
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_LOOP_DETECTION_MODE);

  return CMD_SUCCESS;
}

DEFUN (ldp_ttl_less_domain,
       ldp_ttl_less_domain_cmd,
       "ttl-less-domain",
       "TTL-less domain\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.ttl_less_domain = MPLS_BOOL_TRUE;
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_TTLLESS_DOMAIN);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_ttl_less_domain,
       no_ldp_ttl_less_domain_cmd,
       "no ttl-less-domain",
       NO_STR
       "TTL-less domain\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.ttl_less_domain = MPLS_BOOL_FALSE;
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_TTLLESS_DOMAIN);

  return CMD_SUCCESS;
}

DEFUN (ldp_local_tcp_port,
       ldp_local_tcp_port_cmd,
       "local-tcp-port <1-65535>",
       "local TCP port\n"
       "TCP port number\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.local_tcp_port = atoi(argv[0]);

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_LOCAL_TCP_PORT);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_local_tcp_port,
       no_ldp_local_tcp_port_cmd,
       "no local-tcp-port",
       NO_STR
       "local TCP port\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.local_tcp_port = LDP_GLOBAL_DEF_LOCAL_TCP_PORT;

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_LOCAL_TCP_PORT);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (ldp_local_udp_port,
       ldp_local_udp_port_cmd,
       "local-udp-port <1-65535>",
       "local UDP port\n"
       "UDP port number\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.local_udp_port = atoi(argv[0]);

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_LOCAL_UDP_PORT);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}

DEFUN (no_ldp_local_udp_port,
       no_ldp_local_udp_port_cmd,
       "no local-udp-port",
       NO_STR
       "local UDP port\n")
{
  struct ldp *ldp = (struct ldp*)vty->index;
  ldp_global g;

  g.local_udp_port = LDP_GLOBAL_DEF_LOCAL_UDP_PORT;

  ldp_admin_state_start(ldp);
  ldp_cfg_global_set(ldp->h,&g, LDP_GLOBAL_CFG_LOCAL_UDP_PORT);
  ldp_admin_state_finish(ldp);

  return CMD_SUCCESS;
}
#endif
//end here
DEFUN (ldp_trace_address,
       ldp_trace_address_cmd,
       "trace address",
       "LDP debugging\n"
       "Address PDUs\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_ADDRESS;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_binding,
       ldp_trace_binding_cmd,
       "trace binding",
       "LDP debugging\n"
       "Label Bindings\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_BINDING;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_debug,
       ldp_trace_debug_cmd,
       "trace debug",
       "LDP debugging\n"
       "Debug Messages\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_DEBUG;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_error,
       ldp_trace_error_cmd,
       "trace error",
       "LDP debugging\n"
       "Error Conditions\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_ERROR;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_event,
       ldp_trace_event_cmd,
       "trace event",
       "LDP debugging\n"
       "LDP Events\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_EVENT;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_general,
       ldp_trace_general_cmd,
       "trace general",
       "LDP debugging\n"
       "General Messages\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_GENERAL;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_init,
       ldp_trace_init_cmd,
       "trace init",
       "LDP debugging\n"
       "Init PDUs\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_INIT;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_label,
       ldp_trace_label_cmd,
       "trace label",
       "LDP debugging\n"
       "Label PDUs\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_LABEL;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_normal,
       ldp_trace_normal_cmd,
       "trace normal",
       "LDP debugging\n"
       "Normal Messages\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_NORMAL;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_notif,
       ldp_trace_notif_cmd,
       "trace notification",
       "LDP debugging\n"
       "Notification PDUs\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_NOTIF;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_packet_dump,
       ldp_trace_packet_dump_cmd,
       "trace packet-dump",
       "LDP debugging\n"
       "Packet Dump\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_PACKET_DUMP;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_packet,
       ldp_trace_packet_cmd,
       "trace packet",
       "LDP debugging\n"
       "Packet tracing\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_PACKET;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_path,
       ldp_trace_path_cmd,
       "trace path",
       "LDP debugging\n"
       "PATH Info\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_PATH;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_periodic,
       ldp_trace_periodic_cmd,
       "trace periodic",
       "LDP debugging\n"
       "Periodic PDUs\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_PERIODIC;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_policy,
       ldp_trace_policy_cmd,
       "trace policy",
       "LDP debugging\n"
       "Policy tracing\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_POLICY;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_route,
       ldp_trace_route_cmd,
       "trace route",
       "LDP debugging\n"
       "Route Lookup tracing\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_ROUTE;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_state,
       ldp_trace_state_cmd,
       "trace state",
       "LDP debugging\n"
       "State transitions\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_STATE;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_task,
       ldp_trace_task_cmd,
       "trace task",
       "LDP debugging\n"
       "Task tracing\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_TASK;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_timer,
       ldp_trace_timer_cmd,
       "trace timer",
       "LDP debugging\n"
       "Timer tracing\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_TIMER;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_all,
       ldp_trace_all_cmd,
       "trace all",
       "LDP debugging\n"
       "All tracing\n")
{
  ldp_traceflags |= LDP_TRACE_FLAG_ALL;
  return CMD_SUCCESS;
}

DEFUN (ldp_trace_none,
       ldp_trace_none_cmd,
       "trace none",
       "LDP debugging\n"
       "Turn off all tracing\n")
{
  ldp_traceflags = 0;
  return CMD_SUCCESS;
}

#if 0

/* address and egress changes should result in an event which goes through
   all of the existing FECs/addresses and decides which to withdrawl and then
   ask the system for which additional FECs/addresses should be sent */

DEFUN (ldp_address,
       ldp_address_cmd,
       "address-mode (lsr-id|ldp)",
       "Addresses this LSR will announce\n"
       "LSR-ID only\n"
       "Only LDP interfaces\n")
{
    struct ldp *ldp = (struct ldp*)vty->index;
    if (!strncmp(argv[0], "lsr-id",6)) {
	ldp->address = LDP_ADDRESS_LSRID;
    } else if (!strncmp(argv[0], "ldp",3)) {
	ldp->address = LDP_ADDRESS_LDP;
    } else {
	return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (no_ldp_address,
       no_ldp_address_cmd,
       "no address-mode",
       NO_STR
       "Addresses this LSR will announce\n")
{
    struct ldp *ldp = (struct ldp*)vty->index;
    ldp->address = LDP_ADDRESS_ALL;
    return CMD_SUCCESS;
}

DEFUN (ldp_egress,
       ldp_egress_cmd,
       "egress (lsr-id|connected)",
       "Filter FECs this LSR will send mappings for\n"
       "LSR-ID only\n"
       "All connected subnets\n")
{
    struct ldp *ldp = (struct ldp*)vty->index;
    if (!strncmp(argv[0], "lsr-id",6)) {
	ldp->egress = LDP_EGRESS_LSRID;
    } else if (!strncmp(argv[0], "connected", 9)) {
	ldp->egress = LDP_EGRESS_CONNECTED;
    } else {
	return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

DEFUN (no_ldp_egress,
       no_ldp_egress_cmd,
       "no egress",
       NO_STR
       "Filter FECs this LSR will send mappings for\n")
{
    struct ldp *ldp = (struct ldp*)vty->index;
    ldp->egress = LDP_EGRESS_ALL;
    return CMD_SUCCESS;
}
#endif

#if 0
DEFUN (ldp_egress_list,
       ldp_egress_list_cmd,
       "egress access-list (<1-199>|<1300-2699>|WORD)",
       "Filter FECs this LSR will send mappings for\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
    return CMD_SUCCESS;
}

DEFUN (no_ldp_egress_list,
       no_ldp_egress_list_cmd,
       "no egress access-list (<1-199>|<1300-2699>|WORD)",
       NO_STR
       "Filter FECs this LSR will send mappings for\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
    return CMD_SUCCESS;
}
#endif

DEFUN (mpls_show_ldp_attr, mpls_show_ldp_attr_cmd,
       "show ldp attr",
       SHOW_STR
       "LDP"
       "ATTR\n")
{
    struct ldp *ldp = ldp_get();

    if (!ldp) {
	vty_out (vty, "There isn't an active LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }
    ldp_cfg_global_attr(ldp->h);
    return CMD_SUCCESS;
}

DEFUN (mpls_show_ldp_fec, mpls_show_ldp_fec_cmd,
       "show ldp fec",
       SHOW_STR
       "LDP"
       "FEC\n")
{
    struct ldp *ldp = ldp_get();
    struct mpls_fec fec;
    struct mpls_nexthop nh;

    if (!ldp) {
	vty_out (vty, "There isn't an active LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }

    fec.index = 0;
    while (ldp_cfg_fec_getnext(ldp->h, &fec, 0xFFFFFFFF) == MPLS_SUCCESS) {
	vty_out(vty, "FEC: %d%s", fec.index, VTY_NEWLINE);
	nh.index = 0;
	while (ldp_cfg_fec_nexthop_getnext(ldp->h, &fec, &nh,
	    0xFFFFFFFF) == MPLS_SUCCESS) {
	    vty_out(vty, "\t%d %08x%s", nh.index, nh.ip.u.ipv4,
		VTY_NEWLINE);
	}
    }
    return CMD_SUCCESS;
}

DEFUN (mpls_show_ldp_interface, mpls_show_ldp_interface_cmd,
       "show ldp interface",
       SHOW_STR
       "LDP"
       "interface\n")
{
    struct ldp *ldp = ldp_get();
    struct ldp_if iff;
    struct ldp_addr addr;

    if (!ldp) {
	vty_out (vty, "There isn't an active LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }

    iff.index = 0;
    while (ldp_cfg_if_getnext(ldp->h, &iff, LDP_IF_CFG_BY_INDEX) ==
	MPLS_SUCCESS) {
	vty_out(vty, "INTF: %d%s", iff.index, VTY_NEWLINE);
	addr.index = 0;
	while (ldp_cfg_if_addr_getnext(ldp->h, &iff, &addr,
	    LDP_IF_ADDR_CFG_BY_INDEX | LDP_IF_CFG_BY_INDEX) == MPLS_SUCCESS) {
	    vty_out(vty, "\t%d%s", addr.index, VTY_NEWLINE);
	}
    }
    return CMD_SUCCESS;
}

DEFUN (mpls_show_ldp_addr, mpls_show_ldp_addr_cmd,
       "show ldp addr",
       SHOW_STR
       "LDP"
       "addrs\n")
{
    struct ldp *ldp = ldp_get();
    struct ldp_addr addr;

    if (!ldp) {
	vty_out (vty, "There isn't an active LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }

    memset(&addr, 0, sizeof(addr));
    while (ldp_cfg_addr_getnext(ldp->h, &addr, 0) == MPLS_SUCCESS) {
	vty_out(vty, "Addr: %d %08x%s", addr.index, addr.address.u.ipv4,
	    VTY_NEWLINE);
	vty_out(vty, "\t%d%s", addr.session_index, VTY_NEWLINE);
	vty_out(vty, "\t%d%s", addr.nexthop_index, VTY_NEWLINE);
	vty_out(vty, "\t%d%s", addr.if_index, VTY_NEWLINE);

	addr.session_index = 0;
	addr.nexthop_index = 0;
	addr.if_index = 0;
    }
    return CMD_SUCCESS;
}

DEFUN (mpls_show_ldp, mpls_show_ldp_cmd,
       "show ldp",
       SHOW_STR
       "LDP global setting\n")
{
    struct ldp *ldp = ldp_get();
    ldp_global g;

    if (!ldp) {
	vty_out (vty, "There isn't an active LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }

    ldp_cfg_global_get(ldp->h,&g,0xFFFFFFFF);

    vty_out(vty, "LSR-ID: %08x Admin State: %s%s",
      g.lsr_identifier.u.ipv4, admin_state[g.admin_state], VTY_NEWLINE);
    vty_out(vty, "Transport Address: %08x%s", g.transport_address.u.ipv4,
      VTY_NEWLINE);
    vty_out(vty, "Control Mode: %s\tRepair Mode: %s%s",
      control_mode[g.lsp_control_mode], repair_mode[g.lsp_repair_mode],
      VTY_NEWLINE);
    vty_out(vty, "Propogate Release: %s\tLabel Merge: %s%s",
      bool[g.propagate_release], bool[g.label_merge], VTY_NEWLINE);
    vty_out(vty, "Retention Mode: %s\tLoop Detection Mode: %s%s",
      retention_mode[g.label_retention_mode],
      loop_detect_mode[g.loop_detection_mode], VTY_NEWLINE);
    vty_out(vty, "TTL-less-domain: %s%s", bool[g.ttl_less_domain],
      VTY_NEWLINE);
    vty_out(vty, "Local TCP Port: %d\tLocal UDP Port: %d%s",
      g.local_tcp_port, g.local_udp_port, VTY_NEWLINE);
    vty_out(vty, "Keep-alive Time: %d\tKeep-alive Interval: %d%s",
      g.keepalive_timer, g.keepalive_interval, VTY_NEWLINE);
    vty_out(vty, "Hello Time: %d\tHello Interval: %d%s",
      g.hellotime_timer, g.hellotime_interval, VTY_NEWLINE);

    return CMD_SUCCESS;
}

void convert_seconds_to_string(uint32_t secs, char* buf) {
  div_t mins;
  div_t hours;
  div_t days;
  int h = 0;
  int m = 0;
  int s = 0;

  if (secs >= 60) {
    mins = div(secs, 60);
    if (mins.quot >= 60) {
      hours = div(mins.quot, 60);
      if (hours.quot >= 24) {
        days = div(hours.quot, 24);
        h = days.rem;
        m = hours.rem;
        s = mins.rem;
        sprintf(buf, "%dd %02d:%02d:%02d", days.quot, h, m, s);
        return;
      } else {
        h = hours.quot;
        m = hours.rem;
        s = mins.rem;
      }
    } else {
      h = 0;
      m = mins.quot;
      s = mins.rem;
    }
  } else {
    h = 0;
    m = 0;
    s = secs;
  }
  sprintf(buf,"%02d:%02d:%02d", h, m, s);
}

DEFUN (mpls_show_ldp_neighbor, mpls_show_ldp_neighbor_cmd,
       "show ldp neighbor",
       SHOW_STR
       "LDP related commands\n"
       "Discovered neighbors\n"
       "LDP identifier\n")
{
  struct ldp *ldp = ldp_get();
  ldp_adj adj;
  ldp_addr addr;
  ldp_entity e;
  ldp_global g;
  ldp_session s;
  int count;
  int addr_count;
  uint32_t time_now;
  char time_buf[13];
  struct in_addr lsr;
  struct in_addr src;
  struct in_addr tr;
  int label_space = 0;
  ldp_if iff;
  ldp_peer peer;

#if 0

Peer LDP Ident: 7.1.1.1:0; Local LDP Ident 8.1.1.1:0
        TCP connection: 7.1.1.1.646 - 8.1.1.1.11006
        State: Oper; Msgs sent/rcvd: 4/411; Downstream
        Up time: 00:00:52
        LDP discovery sources:
          Ethernet1/0/0
        Addresses bound to peer LDP Ident:
          2.0.0.29        7.1.1.1         59.0.0.199      212.10.1.1
          10.205.0.9

#endif

    if (!ldp) {
	vty_out (vty, "There isn't an active LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }

    ldp_cfg_global_get(ldp->h,&g,0xFFFFFFFF);

    count = 0;
    adj.index = 0;
    while (ldp_cfg_adj_getnext(ldp->h, &adj, 0xFFFFFFFF) ==
      MPLS_SUCCESS) {
      count++;

      if (adj.entity_index) {
        e.index = adj.entity_index;
        ldp_cfg_entity_get(ldp->h,&e,0xFFFFFFFF);
        if (e.entity_type == LDP_DIRECT) {
          iff.index = e.sub_index;
          ldp_cfg_if_get(ldp->h,&iff,0xFFFFFFFF);
          label_space = iff.label_space;
        } else {
          peer.index = e.sub_index;
          ldp_cfg_peer_get(ldp->h,&peer,0xFFFFFFFF);
          label_space = peer.label_space;
        }
      }

      lsr.s_addr = htonl(adj.remote_lsr_address.u.ipv4);
      vty_out(vty, "Peer LDP Ident: %s:%d; Local LDP Ident: ", inet_ntoa(lsr),
        adj.remote_label_space);
      lsr.s_addr = htonl(g.lsr_identifier.u.ipv4);
      vty_out(vty, "%s:%d%s", inet_ntoa(lsr), label_space, VTY_NEWLINE);

      if (adj.session_index) {
        s.index = adj.session_index;

        if (ldp_cfg_session_get(ldp->h,&s,0xFFFFFFFF) != MPLS_SUCCESS) {
	  continue;
        }

        tr.s_addr = 0;
        vty_out(vty, "\tTCP connection: %s.%d", inet_ntoa(tr),
          g.local_tcp_port);

        src.s_addr = htonl(s.remote_dest.addr.u.ipv4);
        vty_out(vty, " - %s.%d%s", inet_ntoa(src), s.remote_dest.port,
          VTY_NEWLINE);

        vty_out(vty, "\tState: %s; Msgs sent/recv: %d/%d; %s%s",
          session_state[s.state], s.mesg_tx, s.mesg_rx,
          distribution_mode[s.oper_distribution_mode], VTY_NEWLINE);
        time_now = time(NULL);
        convert_seconds_to_string(time_now - s.oper_up, time_buf);
        vty_out(vty, "\tUp time: %s%s", time_buf, VTY_NEWLINE);

        vty_out(vty, "\tLDP discovery sources:%s", VTY_NEWLINE);
      } else {
        vty_out(vty, "\tTCP connection: %s%s", "n/a", VTY_NEWLINE);
        vty_out(vty, "\tState: discovery; Msgs sent/recv: -/-;%s",VTY_NEWLINE);
        vty_out(vty, "\tUp time: %s%s", "-", VTY_NEWLINE);
        vty_out(vty, "\tLDP discovery sources:%s", VTY_NEWLINE);
      }
      vty_out(vty, "\t  ");

      if (e.entity_type == LDP_DIRECT) {
        vty_out(vty, "%s ", iff.handle->name);
      } else {
        vty_out(vty, "%s ", peer.peer_name);
      }
      vty_out(vty, "%s", VTY_NEWLINE);

      if (adj.session_index) {
        vty_out(vty, "\tAddresses bound to peer:%s", VTY_NEWLINE);

        addr.index = 0;
        addr_count = 0;
        while (ldp_cfg_session_raddr_getnext(ldp->h, &s, &addr, 0xFFFFFFFF) ==
          MPLS_SUCCESS) {
          lsr.s_addr = htonl(addr.address.u.ipv4);
          vty_out(vty, "\t");
          if (!addr_count) {
            vty_out(vty, "  ");
          }

          vty_out(vty, "%s",inet_ntoa(lsr));
          addr_count++;

          if (addr_count == 4) {
            vty_out(vty, "%s", VTY_NEWLINE);
            addr_count = 0;
          }
        }
        vty_out(vty, "%s", VTY_NEWLINE);
      }
    }
    vty_out(vty, "%s", VTY_NEWLINE);
    if (count == 0) {
      vty_out(vty, "\tNo discovered neighbors%s", VTY_NEWLINE);
    }
  vty_out(vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (mpls_show_ldp_session, mpls_show_ldp_session_cmd,
       "show ldp session [A.B.C.D:E]",
       SHOW_STR
       "LDP related commands\n"
       "Session information\n"
       "LDP identifier\n")
{
  struct ldp *ldp = ldp_get();
  ldp_session session;
  ldp_addr addr;
  struct in_addr in;
  int count = 0;

    if (!ldp) {
	vty_out (vty, "There isn't active LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }

    session.index = 0;
    while (ldp_cfg_session_getnext(ldp->h, &session, 0xFFFFFFFF) ==
      MPLS_SUCCESS) {
      count++;
      in.s_addr = htonl(session.remote_dest.addr.u.ipv4);
      vty_out(vty, "%-2d %s %-3d %s%s", session.index,
        inet_ntoa(in), session.oper_keepalive,
        session_state[session.state], VTY_NEWLINE);
      addr.index = 0;
      while (ldp_cfg_session_raddr_getnext(ldp->h, &session,
        &addr, 0xFFFFFFFF) == MPLS_SUCCESS) {
        in.s_addr = htonl(addr.address.u.ipv4);
        vty_out(vty, "\t%s%s",inet_ntoa(in), VTY_NEWLINE);
      }
    }
    if (count == 0) {
      vty_out(vty, "    no established sessions%s", VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

DEFUN (mpls_show_ldp_discovery, mpls_show_ldp_discovery_cmd,
       "show ldp discovery",
       SHOW_STR
       "LDP related commands\n"
       "Discovery information\n")
{
  struct ldp *ldp = ldp_get();
  struct ldp_interface *li;
  ldp_if iff;
  int count;
  ldp_global g;
  ldp_adj adj;
  ldp_entity entity;
  ldp_peer peer;
  struct in_addr dst;
  int first;

    if (!ldp) {
	vty_out (vty, "There isn't an active LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }

  vty_out(vty, "%s", VTY_NEWLINE);

    ldp_cfg_global_get(ldp->h,&g,0xFFFFFFFF);
    dst.s_addr = htonl(g.lsr_identifier.u.ipv4);
    vty_out(vty, "Local LSR Identifier: %s%s", inet_ntoa(dst), VTY_NEWLINE);
    vty_out(vty, "%s", VTY_NEWLINE);
    vty_out(vty, "Interface Discovery Sources:%s", VTY_NEWLINE);

    count = 0;
    iff.index = 0;
    while (ldp_cfg_if_getnext(ldp->h, &iff, 0xFFFFFFFF) == MPLS_SUCCESS) {
      li = iff.handle->info;
      if (li->configured == MPLS_BOOL_FALSE) {
	continue;
      }
      first = 1;
      count++;
      vty_out(vty, "\t%s: ", iff.handle->name);
      if (iff.oper_state != MPLS_OPER_UP) {
        vty_out(vty, "down");
      } else {
        vty_out(vty, "xmit");
        entity.index = iff.entity_index;
	if (ldp_cfg_entity_get(ldp->h, &entity, 0xFFFFFFFF) != MPLS_SUCCESS) {
          continue;
	}
        do {
          adj.index = entity.adj_index;
          if (ldp_cfg_adj_get(ldp->h, &adj, 0xFFFFFFFF) == MPLS_SUCCESS) {
            if (first) {
              vty_out(vty, "/recv%s", VTY_NEWLINE);
              first = 0;
            }
            dst.s_addr = htonl(adj.remote_lsr_address.u.ipv4);
            vty_out(vty, "\t    LDP Id: %s:%d%s ", inet_ntoa(dst),
              adj.remote_label_space, VTY_NEWLINE);
          }
        } while (ldp_cfg_entity_adj_getnext(ldp->h, &entity) == MPLS_SUCCESS);
      }
      if (first) {
        vty_out(vty, "%s", VTY_NEWLINE);
      }
    }
    if (count == 0) {
      vty_out(vty, "\tNo configured interfaces%s", VTY_NEWLINE);
    }

    vty_out(vty, "%s", VTY_NEWLINE);
    vty_out(vty, "Targeted Discovery Sources:%s", VTY_NEWLINE);

    count = 0;
    peer.index = 0;
    while (ldp_cfg_peer_getnext(ldp->h, &peer, 0xFFFFFFFF) ==
      MPLS_SUCCESS) {
      first = 1;
      count++;
      dst.s_addr = htonl(peer.dest.addr.u.ipv4);
      vty_out(vty, "\t%s: xmit ", inet_ntoa(dst));
      while (ldp_cfg_adj_getnext(ldp->h, &adj, 0xFFFFFFFF) == MPLS_SUCCESS) {
        if (peer.entity_index == adj.entity_index) {
          if (first) {
            vty_out(vty, "/recv%s", VTY_NEWLINE);
            first = 0;
          }
          dst.s_addr = htonl(adj.remote_lsr_address.u.ipv4);
          vty_out(vty, "\t    LDP Id: %s:%d%s ", inet_ntoa(dst),
            adj.remote_label_space, VTY_NEWLINE);
        }
      }
      if (first) {
        vty_out(vty, "%s", VTY_NEWLINE);
      }
    }
    if (count == 0) {
      vty_out(vty, "\tNo configured peers%s", VTY_NEWLINE);
    }
  vty_out(vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

void ldp_print_label(struct vty *vty, mpls_label_struct *l) {
  switch(l->type) {
    case MPLS_LABEL_TYPE_NONE:
      vty_out(vty, "label: unknown");
      break;
    case MPLS_LABEL_TYPE_GENERIC:
      vty_out(vty, "label: gen %d",l->u.gen);
      break;
    case MPLS_LABEL_TYPE_ATM:
      vty_out(vty, "label: atm %d/%d",l->u.atm.vpi,l->u.atm.vci);
      break;
    case MPLS_LABEL_TYPE_FR:
      vty_out(vty, "label: dlci %d",l->u.fr.dlci);
      break;
  }
}

DEFUN (mpls_show_ldp_database, mpls_show_ldp_database_cmd,
       "show ldp database [A.B.C.D:E]",
       SHOW_STR
       "LDP related commands\n"
       "Labeling information\n"
       "LDP identifier\n")
{
  struct ldp *ldp = ldp_get();
  ldp_session session;
  ldp_outlabel out;
  ldp_inlabel in;
  ldp_attr attr;
  ldp_adj adj;
  int count = 0;
  struct in_addr fec;

    if (!ldp) {
	vty_out (vty, "There isn't an active LDP instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }

    attr.index = 0;
    while (ldp_cfg_attr_getnext(ldp->h, &attr, 0xFFFFFFFF) == MPLS_SUCCESS) {
      count++;

      fec.s_addr = htonl(attr.fecTlv.fecElArray[0].addressEl.address);

      vty_out(vty, "  %s/%d  ", inet_ntoa(fec),
        attr.fecTlv.fecElArray[0].addressEl.preLen);

      session.index = attr.session_index;
      if (ldp_cfg_session_get(ldp->h, &session, 0xFFFFFFFF) != MPLS_SUCCESS) {
        vty_out(vty, "no session%s",VTY_NEWLINE);
        continue;
      }

      adj.index = session.adj_index;
      if (ldp_cfg_adj_get(ldp->h, &adj, 0xFFFFFFFF) != MPLS_SUCCESS) {
        vty_out(vty, "no adj%s",VTY_NEWLINE);
        continue;
      }

      switch(attr.state) {
        case LDP_LSP_STATE_MAP_RECV:
          vty_out(vty, "remote binding:  ");
          out.index = attr.outlabel_index;
          if (ldp_cfg_outlabel_get(ldp->h, &out, 0xFFFFFFFF) != MPLS_SUCCESS) {
            vty_out(vty, "no outlabel");
          } else {
            ldp_print_label(vty,&out.info.label);
          }
          fec.s_addr = htonl(adj.remote_lsr_address.u.ipv4);
          vty_out(vty, " lsr: %s:%d ", inet_ntoa(fec), adj.remote_label_space);
          if (attr.ingress == MPLS_BOOL_TRUE) {
            vty_out(vty, "ingress");
          }
          break;
        case LDP_LSP_STATE_MAP_SENT:
          in.index = attr.inlabel_index;
          if (ldp_cfg_inlabel_get(ldp->h, &in, 0xFFFFFFFF) != MPLS_SUCCESS) {
            vty_out(vty, "no inlabel%s", VTY_NEWLINE);
            continue;
          }
          vty_out(vty, "local binding:   ");
          ldp_print_label(vty,&in.info.label);
          break;
        case LDP_LSP_STATE_WITH_SENT:
        case LDP_LSP_STATE_WITH_RECV:
        case LDP_LSP_STATE_NO_LABEL_RESOURCE_SENT:
        case LDP_LSP_STATE_NO_LABEL_RESOURCE_RECV:
        case LDP_LSP_STATE_ABORT_SENT:
        case LDP_LSP_STATE_ABORT_RECV:
        case LDP_LSP_STATE_NOTIF_SENT:
        case LDP_LSP_STATE_NOTIF_RECV:
        case LDP_LSP_STATE_REQ_RECV:
        case LDP_LSP_STATE_REQ_SENT:
          vty_out(vty, "%s:\t", attr_state[attr.state]);
          fec.s_addr = htonl(adj.remote_lsr_address.u.ipv4);
          vty_out(vty, "lsr: %s:%d", inet_ntoa(fec), adj.remote_label_space);
          break;
        default:
	  break;
      }
      vty_out(vty, "%s", VTY_NEWLINE);
    }
    if (count == 0) {
      vty_out(vty, "    no labeling info has been exchanged%s", VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

DEFUN(ldp_intf,
      ldp_intf_cmd,
      "mpls interface",
      "MPLS interface configuration\n"
      "Dynamic label distribution via LDP\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li;

  MPLS_ASSERT(ifp->info);

  li = ifp->info;
  if (li->configured == MPLS_BOOL_FALSE) {
    li->labelspace = 0;
    li->configured = MPLS_BOOL_TRUE;
    li->admin_up = MPLS_BOOL_TRUE;

    if (ifp->ifindex > 0) {
      do_mpls_labelspace(li);
    }

    ldp_interface_create(li);
  }
  vty->node = LDP_IF_NODE;

  return CMD_SUCCESS;
}

DEFUN(no_ldp_intf,
      no_ldp_intf_cmd,
      "no mpls ip",
      NO_STR
      "MPLS interface configuration\n"
      "remove LDP\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li;

  if (!ifp->info) {
    vty_out(vty, "LDP is not enabled on '%s'%s", ifp->name, VTY_NEWLINE);
    return CMD_WARNING;
  }

  li = ifp->info;
  li->configured = MPLS_BOOL_FALSE;
  li->admin_up = MPLS_BOOL_FALSE;
  li->labelspace = -1;

  if (ifp->ifindex > 0) {
    do_mpls_labelspace(li);
  }
  
  ldp_interface_delete(li);
  return CMD_SUCCESS;
}

#if 0
DEFUN(ldp_l2cc_intf,
      ldp_l2cc_intf_cmd,
      "mpls l2cc peer IPADDR vc-id VCID <group-id GROUPID>",
      "MPLS interface configuration\n"
      "Create a Layer 2 Cross Connect\n"
      "Remote Peer\n"
      "IP Address\n"
      "Virtual Circuit ID\n"
      "<0-255>\n"
      "Optional Group ID\n"
      "<0-255>\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  uint32_t peer_addr;
  int vcid = 0;
  int gid = -1;

  if (!li->l2cc) {
    /* user is trying to create a new L2CC interface */
    li->l2cc = l2cc_if_new(li);
  }

  VTY_GET_IPV4_ADDRESS("IPADDR",peer_addr,argv[0]);
  VTY_GET_UINT32_RANGE("VCID",vcid,argv[1],0,255);
  if (argc > 2) {
      VTY_GET_UINT32_RANGE("GROUPID",gid,argv[2],0,255);
  }

  l2cc_interface_create(li);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_l2cc_intf,
      no_ldp_l2cc_intf_cmd,
      "no mpls l2cc",
      NO_STR
      "MPLS interface configuration\n"
      "Delete a Layer 2 Cross Connect\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;

  if (li->l2cc) {
    l2cc_interface_delete(li);
    l2cc_if_free(li->l2cc);
    li->l2cc = NULL;
  }
  return CMD_SUCCESS;
}
#endif
DEFUN(ldp_remote_peer,
      ldp_remote_peer_cmd,
      "peer IPADDR",
      "MPLS peer configuration\n"
      "Peer's IPv4 Address\n")
{
  struct ldp *ldp = vty->index;
  struct mpls_dest dest;
  struct ldp_remote_peer *rp;

  dest.addr.type = MPLS_FAMILY_IPV4;
  VTY_GET_IPV4_ADDRESS("IPADDR",dest.addr.u.ipv4,argv[0]);
  dest.port = 646;

  if (ldp_remote_peer_find(ldp,&dest)) {
    return CMD_WARNING;
  }

  rp = ldp_remote_peer_new(ldp);
  listnode_add(ldp->peer_list, rp);
  ldp_remote_peer_create(rp,&dest);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_remote_peer,
      no_ldp_remote_peer_cmd,
      "no peer IPADDR",
      NO_STR
      "MPLS peer configuration\n"
      "Peer's IPv4 Address\n")
{
  struct ldp *ldp = vty->index;
  struct mpls_dest dest;
  struct ldp_remote_peer *rp;

  dest.addr.type = MPLS_FAMILY_IPV4;
  dest.addr.u.ipv4 = ntohl(inet_addr(argv[0]));
  dest.port = 646;

  if ((rp = ldp_remote_peer_find(ldp,&dest))) {
    listnode_delete(ldp->peer_list, rp);
    ldp_remote_peer_delete(rp);
    ldp_remote_peer_free(rp);
  }
  return CMD_SUCCESS;
}
#if 0
DEFUN(ldp_if_distribution_mode,
      ldp_if_distribution_mode_cmd,
      "distribution-mode (dod|du)",
      "MPLS interface configuration\n"
      "distribution mode\n"
      "Downstream on Demand or Downstream unsolicited\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  if (!strncmp(argv[0],"dod",3)) {
    li->entity.label_distribution_mode = LDP_DISTRIBUTION_ONDEMAND;
  } else if (!strncmp(argv[0],"du",2)) {
    li->entity.label_distribution_mode = LDP_DISTRIBUTION_UNSOLICITED;
  } else {
    return CMD_WARNING;
  }

  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }
  ldp_interface_admin_state_start(li);
  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_DISTRIBUTION_MODE);
  ldp_interface_admin_state_finish(li);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_distribution_mode,
      no_ldp_if_distribution_mode_cmd,
      "no distribution-mode",
      NO_STR
      "MPLS interface configuration\n"
      "distribution mode\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.label_distribution_mode = LDP_ENTITY_DEF_DISTRIBUTION_MODE;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_DISTRIBUTION_MODE);
  return CMD_SUCCESS;
}

DEFUN(ldp_if_remote_tcp_port,
      ldp_if_remote_tcp_port_cmd,
      "remote-tcp-port <1-65535>",
      "MPLS interface configuration\n"
      "remote LDP port\n"
      "port number\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.remote_tcp_port = atoi(argv[0]);
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_REMOTE_TCP);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_remote_tcp_port,
      no_ldp_if_remote_tcp_port_cmd,
      "no remote-tcp-port",
      NO_STR
      "MPLS interface configuration\n"
      "remote LDP port\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;

  li->entity.remote_tcp_port = LDP_ENTITY_DEF_REMOTE_TCP;
  if (!li->ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(li->ldp->h, &li->entity, LDP_ENTITY_CFG_REMOTE_TCP);
  return CMD_SUCCESS;
}

DEFUN(ldp_if_remote_udp_port,
      ldp_if_remote_udp_port_cmd,
      "remote-udp-port <1-65535>",
      "MPLS interface configuration\n"
      "remote LDP port\n"
      "port number\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.remote_udp_port = atoi(argv[0]);
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_REMOTE_UDP);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_remote_udp_port,
      no_ldp_if_remote_udp_port_cmd,
      "no remote-udp-port",
      NO_STR
      "MPLS interface configuration\n"
      "remote LDP port\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.remote_udp_port = LDP_ENTITY_DEF_REMOTE_UDP;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_REMOTE_UDP);
  return CMD_SUCCESS;
}

DEFUN(ldp_if_max_pdu,
      ldp_if_max_pdu_cmd,
      "max-pdu <64-9182>",
      "MPLS interface configuration\n"
      "maximum LDP PDU size\n"
      "PDU size\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.max_pdu = atoi(argv[0]);
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_MAX_PDU);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_max_pdu,
      no_ldp_if_max_pdu_cmd,
      "no max-pdu",
      NO_STR
      "MPLS interface configuration\n"
      "maximum LDP pdu size\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.max_pdu = LDP_ENTITY_DEF_MAX_PDU;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_MAX_PDU);
  return CMD_SUCCESS;
}

DEFUN(ldp_if_hello_interval,
      ldp_if_hello_interval_cmd,
      "hello-interval <1-60>",
      "MPLS interface configuration\n"
      "hello interval\n"
      "interval in seconds\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.hellotime_interval = atoi(argv[0]);
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_HELLOTIME_INTERVAL);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_hello_interval,
      no_ldp_if_hello_interval_cmd,
      "no hello-interval",
      NO_STR
      "MPLS interface configuration\n"
      "hello interval\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.hellotime_interval = LDP_ENTITY_DEF_HELLOTIME_INTERVAL;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_HELLOTIME_INTERVAL);
  return CMD_SUCCESS;
}

DEFUN(ldp_if_keepalive_interval,
      ldp_if_keepalive_interval_cmd,
      "keepalive-interval <1-60>",
      "MPLS interface configuration\n"
      "keepalive interval\n"
      "interval in seconds\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.keepalive_interval = atoi(argv[0]);
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_KEEPALIVE_INTERVAL);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_keepalive_interval,
      no_ldp_if_keepalive_interval_cmd,
      "no keepalive-interval",
      NO_STR
      "MPLS interface configuration\n"
      "keepalive interval\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.keepalive_interval = LDP_ENTITY_DEF_KEEPALIVE_INTERVAL;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_KEEPALIVE_INTERVAL);
  return CMD_SUCCESS;
}

DEFUN(ldp_if_max_session_attempt,
      ldp_if_max_session_attempt_cmd,
      "max-session-attempt <0-1024>",
      "MPLS interface configuration\n"
      "maximum LDP session setup attempt\n"
      "Number of attempts (0 means keep trying)\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.session_setup_count = atoi(argv[0]);
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_SESSION_SETUP_COUNT);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_max_session_attempt,
      no_ldp_if_max_session_attempt_cmd,
      "no max-session-attempt\n",
      NO_STR
      "MPLS interface configuration\n"
      "maximum LDP session setup attempt\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.session_setup_count = LDP_ENTITY_DEF_SESSIONSETUP_COUNT;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_SESSION_SETUP_COUNT);
  return CMD_SUCCESS;
}

DEFUN(ldp_if_max_path_vector,
      ldp_if_max_path_vector_cmd,
      "max-path-vector <1-255>",
      "MPLS interface configuration\n"
      "maximum path vector\n"
      "number of entries\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.path_vector_limit = atoi(argv[0]);
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_PATHVECTOR_LIMIT);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_max_path_vector,
      no_ldp_if_max_path_vector_cmd,
      "no max-path-vector",
      NO_STR
      "MPLS interface configuration\n"
      "maximum path vector\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.path_vector_limit = LDP_ENTITY_DEF_PATHVECTOR_LIMIT;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_PATHVECTOR_LIMIT);
  return CMD_SUCCESS;
}

DEFUN(ldp_if_max_hop_count,
      ldp_if_max_hop_count_cmd,
      "max-hop-count <1-1024>",
      "MPLS interface configuration\n"
      "maximum hop count\n"
      "number of hops\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.hop_count_limit = atoi(argv[0]);
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_HOPCOUNT_LIMIT);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_max_hop_count,
      no_ldp_if_max_hop_count_cmd,
      "no max-hop-count",
      NO_STR
      "MPLS interface configuration\n"
      "maximum hop count\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.hop_count_limit = LDP_ENTITY_DEF_HOPCOUNT_LIMIT;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_HOPCOUNT_LIMIT);
  return CMD_SUCCESS;
}

DEFUN(ldp_if_max_label_requests,
      ldp_if_max_label_requests_cmd,
      "max-label-requests <0-1024>",
      "MPLS interface configuration\n"
      "maximum times to make a request for a FEC\n"
      "Number of attempts (0 means keep trying)\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.label_request_count = atoi(argv[0]);
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_REQUEST_COUNT);
  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_max_label_requests,
      no_ldp_if_max_label_requests_cmd,
      "no max-label-requests",
      NO_STR
      "MPLS interface configuration\n"
      "maximum times to make a request for a FEC\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.label_request_count = LDP_ENTITY_DEF_REQUEST_COUNT;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  ldp_cfg_entity_set(ldp->h, &li->entity, LDP_ENTITY_CFG_REQUEST_COUNT);
  return CMD_SUCCESS;
}

#endif
#if 0
DEFUN(ldp_if_ttl_less_domain,
      ldp_if_ttl_less_domain_cmd,
      "ttl-less-domain",
      "MPLS interface configuration\n"
      "TTL less domain\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.remote_in_ttl_less_domain = MPLS_BOOL_TRUE;
  if (!ldp) {
    li->create_on_hold = MPLS_BOOL_TRUE;
    return CMD_SUCCESS;
  }

  return CMD_SUCCESS;
}

DEFUN(no_ldp_if_ttl_less_domain,
      no_ldp_if_ttl_less_domain_cmd,
      "no ttl-less-domain",
      NO_STR
      "MPLS interface configuration\n"
      "TTL less domain\n")
{
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = li->ldp;

  li->entity.remote_in_ttl_less_domain = MPLS_BOOL_FALSE;
  if (!ldp) {
    return CMD_SUCCESS;
  }

  return CMD_SUCCESS;
}
#endif
static int ldp_if_config_write (struct vty *vty) {
  return 0;
}

static int ldp_config_write (struct vty *vty) {
  struct ldp *ldp = ldp_get();
  ldp_global g;
  int write = 0;
//#if 0 //testing
  struct in_addr addr;
  struct ldp_remote_peer *rp;
  struct listnode *ln;
//#endif //testing

  if (ldp) {
    vty_out (vty, "!%s", VTY_NEWLINE);
    vty_out (vty, "mpls ip%s", VTY_NEWLINE);
    write++;

#if 0

    LIST_LOOP(ldp->peer_list,rp,ln) {
      addr.s_addr = htonl(rp->peer.dest.addr.u.ipv4);
      vty_out (vty, " peer %s%s", inet_ntoa(addr), VTY_NEWLINE);
    }

#endif

    if (ldp_traceflags & LDP_TRACE_FLAG_ADDRESS)
      vty_out (vty, " trace address%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_BINDING)
      vty_out (vty, " trace binding%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_DEBUG)
      vty_out (vty, " trace debug%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_ERROR)
      vty_out (vty, " trace error%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_EVENT)
      vty_out (vty, " trace event%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_GENERAL)
      vty_out (vty, " trace general%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_INIT)
      vty_out (vty, " trace init%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_LABEL)
      vty_out (vty, " trace label%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_NORMAL)
      vty_out (vty, " trace normal%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_NOTIF)
      vty_out (vty, " trace notification%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_PACKET_DUMP)
      vty_out (vty, " trace packet-dump%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_PACKET)
      vty_out (vty, " trace packet%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_PATH)
      vty_out (vty, " trace path%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_PERIODIC)
      vty_out (vty, " trace periodic%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_POLICY)
      vty_out (vty, " trace policy%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_ROUTE)
      vty_out (vty, " trace route%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_STATE)
      vty_out (vty, " trace state%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_TASK)
      vty_out (vty, " trace task%s", VTY_NEWLINE);
    if (ldp_traceflags & LDP_TRACE_FLAG_TIMER)
      vty_out (vty, " trace timer%s", VTY_NEWLINE);

    ldp_cfg_global_get(ldp->h,&g, 0xFFFFFFFF);

    if (g.lsp_control_mode != LDP_GLOBAL_DEF_CONTROL_MODE) {
      vty_out (vty, " lsp-control-mode ");
      if (g.lsp_control_mode == LDP_CONTROL_INDEPENDENT) {
        vty_out (vty, "independent%s", VTY_NEWLINE);
      } else {
        vty_out (vty, "ordered%s", VTY_NEWLINE);
      }
    }
    if (g.label_retention_mode != LDP_GLOBAL_DEF_RETENTION_MODE) {
      vty_out (vty, " label-retention-mode ");
      if (g.label_retention_mode == LDP_RETENTION_LIBERAL) {
        vty_out (vty, "liberal%s", VTY_NEWLINE);
      } else {
        vty_out (vty, "conservative%s", VTY_NEWLINE);
      }
    }
    if (g.lsp_repair_mode != LDP_GLOBAL_DEF_REPAIR_MODE) {
      vty_out (vty, " lsp-repair-mode ");
      if (g.lsp_repair_mode == LDP_REPAIR_LOCAL) {
        vty_out (vty, "local%s", VTY_NEWLINE);
      } else {
        vty_out (vty, "global%s", VTY_NEWLINE);
      }
    }
    if (g.propagate_release != LDP_GLOBAL_DEF_PROPOGATE_RELEASE) {
      if (g.propagate_release == MPLS_BOOL_TRUE) {
        vty_out (vty, " propagate-release%s", VTY_NEWLINE);
      } else {
        vty_out (vty, " no propagate-release%s", VTY_NEWLINE);
      }
    }
    if (g.label_merge != LDP_GLOBAL_DEF_LABEL_MERGE) {
      if (g.label_merge == MPLS_BOOL_TRUE) {
        vty_out (vty, " label-merge%s", VTY_NEWLINE);
      } else {
        vty_out (vty, " no label-merge%s", VTY_NEWLINE);
      }
    }
    if (g.loop_detection_mode != LDP_GLOBAL_DEF_LOOP_DETECTION_MODE) {
      if (g.loop_detection_mode == LDP_LOOP_HOPCOUNT) {
        vty_out (vty, " loop-detection-mode hop%s", VTY_NEWLINE);
      } else if (g.loop_detection_mode == LDP_LOOP_PATHVECTOR) {
        vty_out (vty, " loop-detection-mode path%s", VTY_NEWLINE);
      } else if (g.loop_detection_mode == LDP_LOOP_HOPCOUNT_PATHVECTOR) {
        vty_out (vty, " loop-detection-mode both%s", VTY_NEWLINE);
      } else {
        vty_out (vty, " no loop-detection-mode%s", VTY_NEWLINE);
      }
    }
    if (g.ttl_less_domain != MPLS_BOOL_FALSE) {
      vty_out (vty, " ttl-less-domain%s", VTY_NEWLINE);
    }
    if (g.local_tcp_port != LDP_GLOBAL_DEF_LOCAL_TCP_PORT) {
      vty_out (vty, " local-tcp-port %d%s", g.local_tcp_port, VTY_NEWLINE);
    }
    if (g.local_udp_port != LDP_GLOBAL_DEF_LOCAL_UDP_PORT) {
      vty_out (vty, " local-udp-port %d%s", g.local_udp_port, VTY_NEWLINE);
    }

    switch (ldp->egress) {
      case LDP_EGRESS_LSRID:
        vty_out (vty, " egress lsr-id%s", VTY_NEWLINE);
        break;
      case LDP_EGRESS_CONNECTED:
        vty_out (vty, " egress connected%s", VTY_NEWLINE);
        break;
      default:
	break;
    }

    switch (ldp->address) {
      case LDP_ADDRESS_LSRID:
        vty_out (vty, " address-mode lsr-id%s", VTY_NEWLINE);
        break;
      case LDP_ADDRESS_LDP:
        vty_out (vty, " address-mode ldp%s", VTY_NEWLINE);
        break;
      default:
	break;
    }
  }
  return write;
}

#if 0
int ldp_interface_config_write(struct vty *vty) {
    struct ldp *ldp = ldp_get();
    listnode node;
    struct interface *ifp;

    ldp_entity e;
    mpls_fec l;
    int write = 0;

    if (li && li->ldp) {
	ldp = li->ldp;

	if (li->entity.index) {
          e.index = li->entity.index;
	  ldp_cfg_entity_get(ldp->h, &e, 0xFFFFFFFF);
	} else {
	  memcpy(&e,&li->entity,sizeof(ldp_entity));
	}

        vty_out(vty, " mpls ldp%s", VTY_NEWLINE);
        write++;

        if (e.label_distribution_mode != LDP_ENTITY_DEF_DISTRIBUTION_MODE) {
          vty_out(vty, "   distribution-mode ");
          if (e.label_distribution_mode == LDP_DISTRIBUTION_ONDEMAND) {
            vty_out(vty, "dod%s", VTY_NEWLINE);
          } else {
            vty_out(vty, "du%s", VTY_NEWLINE);
          }
        }
        if (e.remote_tcp_port != LDP_ENTITY_DEF_REMOTE_TCP) {
          vty_out(vty, "   remote-tcp-port %d%s", e.remote_tcp_port,
            VTY_NEWLINE);
        }
        if (e.remote_udp_port != LDP_ENTITY_DEF_REMOTE_UDP) {
          vty_out(vty, "   remote-udp-port %d%s", e.remote_udp_port,
            VTY_NEWLINE);
        }
        if (e.max_pdu != LDP_ENTITY_DEF_MAX_PDU) {
          vty_out(vty, "   max-pdu %d%s", e.max_pdu, VTY_NEWLINE);
        }
        if (e.hellotime_interval != LDP_ENTITY_DEF_HELLOTIME_INTERVAL) {
          vty_out(vty, "   hello-interval %d%s", e.hellotime_interval,
            VTY_NEWLINE);
        }
        if (e.keepalive_interval != LDP_ENTITY_DEF_KEEPALIVE_INTERVAL) {
          vty_out(vty, "   keepalive-interval %d%s",
            e.keepalive_interval, VTY_NEWLINE);
        }
        if (e.session_setup_count != LDP_ENTITY_DEF_SESSIONSETUP_COUNT) {
          vty_out(vty, "   max-session-attempt %d%s",
            e.session_setup_count, VTY_NEWLINE);
        }
        if (e.path_vector_limit != LDP_ENTITY_DEF_PATHVECTOR_LIMIT) {
          vty_out(vty, "   max-path-vector %d%s",
            e.path_vector_limit, VTY_NEWLINE);
        }
        if (e.hop_count_limit != LDP_ENTITY_DEF_HOPCOUNT_LIMIT) {
          vty_out(vty, "   max-hop-count %d%s",
            e.hop_count_limit, VTY_NEWLINE);
        }
        if (e.label_request_count != LDP_ENTITY_DEF_REQUEST_COUNT) {
          vty_out(vty, "   max-label-requests %d%s",
            e.label_request_count, VTY_NEWLINE);
        }
        vty_out(vty, " !%s",VTY_NEWLINE);
    } else if (li && li->l2cc) {
//	struct in_addr tmp;
	l2 = li->l2cc;
	ldp = li->ldp;

        write++;

	if (l2->l2cc.index) {
          l.index = l2->l2cc.index;
	  ldp_cfg_fec_get(ldp->h, &l, 0xFFFFFFFF);
	} else {
	  memcpy(&l,&l2->l2cc,sizeof(ldp_fec));
	}
#if 0
	tmp.s_addr = htonl(l.info.nh.ip.u.ipv4);
        vty_out(vty, " mpls l2cc peer %s",inet_ntoa(tmp));
	vty_out(vty, " vcid %d",l.info.u.l2cc.connection_id);
	if (l.info.u.l2cc.group_id) {
	  vty_out(vty, " groupid %d", l.info.u.l2cc.group_id);
	}
#endif
	vty_out(vty, "%s", VTY_NEWLINE);

        vty_out(vty, " !%s",VTY_NEWLINE);
    }


    return write;
}
#endif

void ldp_vty_show_init() {

#if 0
  install_element(VIEW_NODE, &mpls_show_fec_cmd);
  install_element(ENABLE_NODE, &mpls_show_fec_cmd);

  install_element(VIEW_NODE, &mpls_show_interface_cmd);
  install_element(ENABLE_NODE, &mpls_show_interface_cmd);

  install_element(VIEW_NODE, &mpls_show_lsr_id_cmd);
  install_element(ENABLE_NODE, &mpls_show_lsr_id_cmd);
#endif

  install_element(VIEW_NODE, &mpls_show_ldp_cmd);
  install_element(ENABLE_NODE, &mpls_show_ldp_cmd);

  install_element(VIEW_NODE, &mpls_show_ldp_fec_cmd);
  install_element(ENABLE_NODE, &mpls_show_ldp_fec_cmd);

  install_element(VIEW_NODE, &mpls_show_ldp_attr_cmd);
  install_element(ENABLE_NODE, &mpls_show_ldp_attr_cmd);

  install_element(VIEW_NODE, &mpls_show_ldp_addr_cmd);
  install_element(ENABLE_NODE, &mpls_show_ldp_addr_cmd);

  install_element(VIEW_NODE, &mpls_show_ldp_interface_cmd);
  install_element(ENABLE_NODE, &mpls_show_ldp_interface_cmd);

  install_element(VIEW_NODE, &mpls_show_ldp_neighbor_cmd);
  install_element(ENABLE_NODE, &mpls_show_ldp_neighbor_cmd);

  install_element(VIEW_NODE, &mpls_show_ldp_session_cmd);
  install_element(ENABLE_NODE, &mpls_show_ldp_session_cmd);

  install_element(VIEW_NODE, &mpls_show_ldp_discovery_cmd);
  install_element(ENABLE_NODE, &mpls_show_ldp_discovery_cmd);

  install_element(VIEW_NODE, &mpls_show_ldp_database_cmd);
  install_element(ENABLE_NODE, &mpls_show_ldp_database_cmd);
}


extern void dump_mpls_node(struct vty*,struct route_node*);

#if 0
DEFUN (mpls_show_fec, mpls_show_fec_cmd,
       "show fec",
       SHOW_STR
       "FEC\n") {
    struct mpls *mpls = mpls_get();
    struct route_node *node;

    for (node = route_top(mpls->table); node != NULL; node = route_next(node))
    {
	dump_mpls_node(vty,node);
    }
    return CMD_SUCCESS;
}

DEFUN (mpls_show_interface, mpls_show_interface_cmd,
       "show interface",
       SHOW_STR
       "interfaces\n") {
    struct interface *iff;

    iff = if_getfirst();
    while (iff) {
	struct listnode *ln;
	struct connected *c;
	vty_out(vty, "INTF: %s%s", iff->name, VTY_NEWLINE);
	LIST_LOOP(iff->connected, c, ln) {
	    vty_out(vty, "\t%s%s", inet_ntoa(c->address->u.prefix4),
		VTY_NEWLINE);
	}
	iff = if_getnext(iff);
    }
    return CMD_SUCCESS;
}

DEFUN (mpls_show_lsr_id, mpls_show_lsr_id_cmd,
       "show lsr-id",
       SHOW_STR
       "LSR identifier\n") {

    struct mpls *mpls = mpls_get();

    vty_out(vty, "lsr-id: %s%s", inet_ntoa(mpls->router_id.u.prefix4),
        VTY_NEWLINE);
    return CMD_SUCCESS;
}

#endif

DEFUN(interface_mpls_labelspace,
      interface_mpls_labelspace_cmd,
      "mpls labelspace <1-255>",
      "MPLS interface configuration\n"
      "labelspace\n"
      "labelspace number\n") {
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = ldp_get();
  struct mpls_range range;

  if (!li) {
    vty_out(vty, "LDP is not enabled on '%s'%s", ifp->name, VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((range.label_space = atoi(argv[0])) < 0) {
    return CMD_WARNING;
  }

  li->labelspace = range.label_space;
  /* we may be asked to set the labelspace on an interface which hasn't
   * be recongnized, in which case we set the labelspace but don't do
   * the kernel call */
  if (ifp->ifindex > 0) {
    do_mpls_labelspace(li);
  }

  if (li->entity.index) {
    ldp_interface_admin_state_start(li);
  }
  li->iff.label_space = li->labelspace;
  ldp_cfg_if_set(ldp->h, &li->iff, LDP_IF_CFG_LABEL_SPACE);
  if (li->entity.index) {
    ldp_interface_admin_state_finish(li);
  }

  return CMD_SUCCESS;
}

DEFUN(no_interface_mpls_labelspace,
      no_interface_mpls_labelspace_cmd,
      "no mpls labelspace",
      NO_STR
      "MPLS interface configuration\n"
      "labelspace\n") {
  struct interface *ifp = vty->index;
  struct ldp_interface *li = (struct ldp_interface*)ifp->info;
  struct ldp *ldp = ldp_get();

  li->labelspace = 0;
  /* we may be asked to set the labelspace on an interface which hasn't
   * be recongnized, in which case we set the labelspace but don't do
   * the kernel call */
  if (ifp->ifindex > 0) {
    do_mpls_labelspace(li);
  }

  if (li->entity.index) {
    ldp_interface_admin_state_start(li);
  }
  li->iff.label_space = li->labelspace;
  if (ldp) {
    ldp_cfg_if_set(ldp->h, &li->iff, LDP_IF_CFG_LABEL_SPACE);
  }
  if (li->entity.index) {
    ldp_interface_admin_state_finish(li);
  }
  return CMD_SUCCESS;
}
//add by here . This command is used for vpnmd ->ldpd
DEFUN(vpnmd_talk_to_ldpd,
      vpnmd_talk_to_ldpd_cmd,
      "cmd_type <0-4> arg0 WORD arg1 WORD arg2 WORD arg3 WORD",
      "Only used for vpnmd send command message to ldpd "
      "ldpd protocol")
{
	int pw_label;
	int retval=0;
 	switch(atoi(argv[0])){
 		case ldpSendHello:
 			printf("cmd_type : %s\n","ldpSendHello");
 			establish_ldp_session_here(inet_addr(argv[1]));
 			break;
 		case ldpStopHello:
 			printf("cmd_type : %s\n","ldpStopHello");
 			stop_ldp_session_here(inet_addr(argv[1]));
 			break;
 		case ldpVCInfo:
 			printf("cmd_type : %s\n","ldpVCInfo");
 			//verify_vc_state(atoi(argv[1]),atoi(argv[2]),atoi(argv[3]),inet_addr(argv[4]));
 			//int verify_vc_state(struct vty *vty,int vc_type,int vpn_id,int label,unsigned long dst_ip)
 			pw_label=verify_vc_state(vty,atoi(argv[1]),atoi(argv[2]),atoi(argv[3]),inet_addr(argv[4]));
 			vty_out(vty,"%d%s",pw_label,VTY_NEWLINE);
 			//return CMD_SUCCESS;
 			break;
 		case ldpWithdrawPW:
 			printf("cmd_type : %s\n","ldpWithdrawPW");
 			retval=withdraw_pw_here(atoi(argv[1]),atoi(argv[2]),atoi(argv[3]),inet_addr(argv[4]));
 			vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 			//return CMD_SUCCESS;
 			break;
 		case ldpReleasePW:
 			printf("cmd_type : %s\n","ldpReleasePW");
 			retval=release_pw_here(atoi(argv[1]),atoi(argv[2]),atoi(argv[3]),inet_addr(argv[4]));
 			vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 			break;
 		default :
 			printf("cmd_type : %s\n","Not support this command");
 			break;
 	}
 return CMD_SUCCESS;
}
//end by here
DEFUN(ldp_label_space_range_vpnmd,
      ldp_label_space_range_vpnmd_cmd,
      "set_label_space label_pool_id <1-10> min <1-3000> max <1-10000>",
      "specify label pool id¡Blabel space range "
      "LDP protocol")
{
	connect_daemon(VTYSH_INDEX_LMD);
	char buf[200];
	int retval=0;
  sprintf(buf,"createLabelPool pool_id %d min_label %d max_label %d",atoi(argv[0]),atoi(argv[1]),atoi(argv[2]));
	retval=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LMD], buf, stdout);
 	if(retval!= -1){
 		printf("Created a new Label Pool %d\n",retval);
 		exit_daemon(VTYSH_INDEX_LMD);
		return CMD_SUCCESS;
 	}else{
 		 printf("Label Pool creation failed!! \n");
 		 exit_daemon(VTYSH_INDEX_LMD);
 		 return CMD_WARNING;
 	}
}


static int interface_config_write(struct vty *vty) {
  struct listnode *node;
  struct interface *ifp;
  struct ldp_interface *li;

  for (node = listhead(iflist); node; listnextnode(node)) {
    ifp = listgetdata(node);

    vty_out(vty, "interface %s%s", ifp->name, VTY_NEWLINE);

    if (ifp->desc) {
      vty_out(vty, " description %s%s", ifp->desc, VTY_NEWLINE);
    }

    li = ifp->info;
    if (li) {
      if (li->configured == MPLS_BOOL_TRUE) {
	vty_out(vty, " mpls ip%s", VTY_NEWLINE);
      }
      if (li->labelspace > 0) {
        vty_out(vty, " mpls labelspace %d%s", li->labelspace, VTY_NEWLINE);
      }
    }
    vty_out(vty, "!%s", VTY_NEWLINE);
  }
  return 0;
}

static struct cmd_node ldp_node = {LDP_NODE,"%s(config-ldp)# ",1};
static struct cmd_node interface_node = {INTERFACE_NODE,"%s(config-if)# ",1};
static struct cmd_node ldp_if_node = {LDP_IF_NODE,"%s(config-if-ldp)# ",1};

void ldp_vty_init () {

  install_node (&ldp_node, ldp_config_write);

  install_default (LDP_NODE);

  install_element (CONFIG_NODE, &ldp_cmd);
  install_element (CONFIG_NODE, &no_ldp_cmd);
  
	install_element (CONFIG_NODE, &vpnmd_talk_to_ldpd_cmd); //add by here
	install_element (CONFIG_NODE, &ldp_label_space_range_vpnmd_cmd); //add by here
	
//#if 0 //testing

  install_element (LDP_NODE, &ldp_remote_peer_cmd);
  install_element (LDP_NODE, &no_ldp_remote_peer_cmd);

//#endif //testing

  install_element (LDP_NODE, &ldp_lsrid_cmd);
  install_element (LDP_NODE, &no_ldp_lsrid_cmd);

  install_element (LDP_NODE, &ldp_disable_cmd);
  install_element (LDP_NODE, &no_ldp_disable_cmd);

  install_element (LDP_NODE, &ldp_lsp_control_mode_cmd);
  
#if 0
  install_element (LDP_NODE, &no_ldp_lsp_control_mode_cmd);

  install_element (LDP_NODE, &ldp_label_retention_mode_cmd);
  install_element (LDP_NODE, &no_ldp_label_retention_mode_cmd);

  install_element (LDP_NODE, &ldp_lsp_repair_mode_cmd);
  install_element (LDP_NODE, &no_ldp_lsp_repair_mode_cmd);

  install_element (LDP_NODE, &ldp_propogate_release_cmd);
  install_element (LDP_NODE, &no_ldp_propogate_release_cmd);

  install_element (LDP_NODE, &ldp_label_merge_cmd);
  install_element (LDP_NODE, &no_ldp_label_merge_cmd);

  install_element (LDP_NODE, &ldp_loop_detection_mode_cmd);
  install_element (LDP_NODE, &no_ldp_loop_detection_mode_cmd);

  install_element (LDP_NODE, &ldp_ttl_less_domain_cmd);
  install_element (LDP_NODE, &no_ldp_ttl_less_domain_cmd);

  install_element (LDP_NODE, &ldp_local_tcp_port_cmd);
  install_element (LDP_NODE, &no_ldp_local_tcp_port_cmd);

  install_element (LDP_NODE, &ldp_local_udp_port_cmd);
  install_element (LDP_NODE, &no_ldp_local_udp_port_cmd);
  #endif 
  install_element (LDP_NODE, &ldp_trace_address_cmd);
  install_element (LDP_NODE, &ldp_trace_binding_cmd);
  install_element (LDP_NODE, &ldp_trace_debug_cmd);
  install_element (LDP_NODE, &ldp_trace_error_cmd);
  install_element (LDP_NODE, &ldp_trace_event_cmd);
  install_element (LDP_NODE, &ldp_trace_general_cmd);
  install_element (LDP_NODE, &ldp_trace_init_cmd);
  install_element (LDP_NODE, &ldp_trace_label_cmd);
  install_element (LDP_NODE, &ldp_trace_normal_cmd);
  install_element (LDP_NODE, &ldp_trace_notif_cmd);
  install_element (LDP_NODE, &ldp_trace_packet_dump_cmd);
  install_element (LDP_NODE, &ldp_trace_packet_cmd);
  install_element (LDP_NODE, &ldp_trace_path_cmd);
  install_element (LDP_NODE, &ldp_trace_periodic_cmd);
  install_element (LDP_NODE, &ldp_trace_policy_cmd);
  install_element (LDP_NODE, &ldp_trace_route_cmd);
  install_element (LDP_NODE, &ldp_trace_state_cmd);
  install_element (LDP_NODE, &ldp_trace_task_cmd);
  install_element (LDP_NODE, &ldp_trace_timer_cmd);
  install_element (LDP_NODE, &ldp_trace_all_cmd);
  install_element (LDP_NODE, &ldp_trace_none_cmd);

#if 0

  install_element (LDP_NODE, &ldp_egress_cmd);
  install_element (LDP_NODE, &no_ldp_egress_cmd);
  install_element (LDP_NODE, &ldp_address_cmd);
  install_element (LDP_NODE, &no_ldp_address_cmd);
#endif

  install_node(&interface_node, interface_config_write);

  install_element(CONFIG_NODE, &interface_cmd);
  install_default(INTERFACE_NODE);

  install_element(INTERFACE_NODE,&interface_desc_cmd);
  install_element(INTERFACE_NODE,&no_interface_desc_cmd);

  install_element(INTERFACE_NODE,&interface_mpls_labelspace_cmd);
  install_element(INTERFACE_NODE,&no_interface_mpls_labelspace_cmd);

  install_node (&ldp_if_node, ldp_if_config_write);
  install_default (LDP_IF_NODE);

  install_element(INTERFACE_NODE,&ldp_intf_cmd);
  install_element(INTERFACE_NODE,&no_ldp_intf_cmd);
    
  #if 0
  install_element(INTERFACE_NODE,&ldp_l2cc_intf_cmd);
  install_element(INTERFACE_NODE,&no_ldp_l2cc_intf_cmd);
  
  install_element(LDP_IF_NODE,&ldp_if_remote_tcp_port_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_remote_tcp_port_cmd);
  
  install_element(LDP_IF_NODE,&ldp_if_remote_udp_port_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_remote_udp_port_cmd);

  install_element(LDP_IF_NODE,&ldp_if_max_pdu_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_max_pdu_cmd);

  install_element(LDP_IF_NODE,&ldp_if_hello_interval_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_hello_interval_cmd);

  install_element(LDP_IF_NODE,&ldp_if_keepalive_interval_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_keepalive_interval_cmd);

#endif

#if 0
  install_element(LDP_IF_NODE,&ldp_if_loop_detect_mode_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_loop_detect_mode_cmd);
#endif

#if 0
  install_element(LDP_IF_NODE,&ldp_if_max_session_attempt_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_max_session_attempt_cmd);

  install_element(LDP_IF_NODE,&ldp_if_max_path_vector_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_max_path_vector_cmd);

  install_element(LDP_IF_NODE,&ldp_if_max_hop_count_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_max_hop_count_cmd);

  install_element(LDP_IF_NODE,&ldp_if_max_label_requests_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_max_label_requests_cmd);

  install_element(LDP_IF_NODE,&ldp_if_distribution_mode_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_distribution_mode_cmd);
#endif
#if 0
  install_element(LDP_IF_NODE,&ldp_if_ttl_less_domain_cmd);
  install_element(LDP_IF_NODE,&no_ldp_if_ttl_less_domain_cmd);
#endif
}
