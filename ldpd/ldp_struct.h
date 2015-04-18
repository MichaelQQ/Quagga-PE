
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_STRUCT_H_
#define _LDP_STRUCT_H_

#include "mpls_struct.h"
#include "mpls_list.h"
#include "mpls_refcnt.h"

MPLS_LIST_ROOT(ldp_outlabel_list, ldp_outlabel);
MPLS_LIST_ROOT(ldp_resource_list, ldp_resource);
MPLS_LIST_ROOT(ldp_hop_list_list, ldp_hop_list);
MPLS_LIST_ROOT(ldp_inlabel_list, ldp_inlabel);
MPLS_LIST_ROOT(ldp_session_list, ldp_session);
MPLS_LIST_ROOT(ldp_nexthop_list, ldp_nexthop);
MPLS_LIST_ROOT(ldp_entity_list, ldp_entity);
MPLS_LIST_ROOT(ldp_tunnel_list, ldp_tunnel);
MPLS_LIST_ROOT(ldp_addr_list, ldp_addr);
MPLS_LIST_ROOT(ldp_attr_list, ldp_attr);
MPLS_LIST_ROOT(ldp_peer_list, ldp_peer);
MPLS_LIST_ROOT(_ldp_hop_list, ldp_hop);
MPLS_LIST_ROOT(ldp_adj_list, ldp_adj);
MPLS_LIST_ROOT(ldp_fec_list, ldp_fec);
MPLS_LIST_ROOT(ldp_fs_list, ldp_fs);
MPLS_LIST_ROOT(ldp_if_list, ldp_if);

typedef struct ldp_attr_list ldp_attr_list;

typedef enum {
  LDP_UNKNOWN = 0,
  LDP_DIRECT,
  LDP_INDIRECT,
} ldp_entity_type_enum;

typedef enum {
  LDP_CONTROL_INDEPENDENT = 1,
  LDP_CONTROL_ORDERED
} ldp_control_mode;

typedef enum {
  LDP_RETENTION_LIBERAL = 1,
  LDP_RETENTION_CONSERVATIVE
} ldp_retention_mode;

typedef enum {
  LDP_REPAIR_LOCAL = 1,
  LDP_REPAIR_GLOBAL
} ldp_repaire_mode;

typedef enum {
  LDP_LOOP_NONE = 0,
  LDP_LOOP_HOPCOUNT,
  LDP_LOOP_PATHVECTOR,
  LDP_LOOP_HOPCOUNT_PATHVECTOR,
  LDP_LOOP_OTHER,
} ldp_loop_detection_mode;

typedef enum {
  LDP_TRANS_ADDR_NONE = 0,
  LDP_TRANS_ADDR_INTERFACE,
  LDP_TRANS_ADDR_LSRID
} ldp_trans_addr_mode;

typedef enum {
  LDP_DISTRIBUTION_UNSOLICITED = 0,
  LDP_DISTRIBUTION_ONDEMAND = 1,
} ldp_distribution_mode;

typedef enum {
  LDP_INFINIT = 0,
} ldp_count;

typedef enum {
  LDP_NONE,
  LDP_PASSIVE,
  LDP_ACTIVE
} ldp_role_enum;

typedef enum {
  LDP_EVENT_HELLO = 0,
  LDP_EVENT_CONNECT,
  LDP_EVENT_INIT,
  LDP_EVENT_KEEP,
  LDP_EVENT_ADDR,
  LDP_EVENT_LABEL,
  LDP_EVENT_NOTIF,
  LDP_EVENT_CLOSE,
  LDP_EVENT_HTIMER,
  LDP_EVENT_KTIMER,
  LDP_EVENT_TCP_LISTEN,
  LDP_EVENT_TCP_CONNECT,
  LDP_EVENT_UDP_DATA,
  LDP_EVENT_TCP_DATA,
} ldp_event_enum;

typedef enum {
  LDP_STATE_NONE = 0,
  LDP_STATE_NON_EXIST,
  LDP_STATE_INITIALIZED,
  LDP_STATE_OPENSENT,
  LDP_STATE_OPENREC,
  LDP_STATE_OPERATIONAL
} ldp_state_enum;

typedef enum {
  LDP_KEEPALIVE_RECV = 1,
  LDP_KEEPALIVE_SEND
} ldp_keepalive_type;

typedef enum {
  LDP_LSP_STATE_REQ_RECV,
  LDP_LSP_STATE_REQ_SENT,
  LDP_LSP_STATE_MAP_RECV,
  LDP_LSP_STATE_MAP_SENT,
  LDP_LSP_STATE_WITH_SENT,
  LDP_LSP_STATE_WITH_RECV,
  LDP_LSP_STATE_NO_LABEL_RESOURCE_SENT,
  LDP_LSP_STATE_NO_LABEL_RESOURCE_RECV,
  LDP_LSP_STATE_ABORT_SENT,
  LDP_LSP_STATE_ABORT_RECV,
  LDP_LSP_STATE_NOTIF_SENT,
  LDP_LSP_STATE_NOTIF_RECV
} ldp_lsp_state;

typedef enum {
  LDP_TRACE_FLAG_ADDRESS = 0x00000001,
  LDP_TRACE_FLAG_BINDING = 0x00000002,
  LDP_TRACE_FLAG_DEBUG = 0x00000004,
  LDP_TRACE_FLAG_ERROR = 0x00000008,
  LDP_TRACE_FLAG_EVENT = 0x00000010,
  LDP_TRACE_FLAG_GENERAL = 0x00000020,
  LDP_TRACE_FLAG_INIT = 0x00000040,
  LDP_TRACE_FLAG_LABEL = 0x00000080,
  LDP_TRACE_FLAG_NORMAL = 0x00000100,
  LDP_TRACE_FLAG_NOTIF = 0x00000200,
  LDP_TRACE_FLAG_PACKET_DUMP = 0x00000400,
  LDP_TRACE_FLAG_PACKET = 0x00000800,
  LDP_TRACE_FLAG_PATH = 0x00001000,
  LDP_TRACE_FLAG_PERIODIC = 0x00002000,
  LDP_TRACE_FLAG_POLICY = 0x00004000,
  LDP_TRACE_FLAG_ROUTE = 0x00008000,
  LDP_TRACE_FLAG_STATE = 0x00010000,
  LDP_TRACE_FLAG_TASK = 0x00020000,
  LDP_TRACE_FLAG_TIMER = 0x00040000,
  LDP_TRACE_FLAG_ALL = 0xFFFFFFFF
} ldp_trace_flags;

typedef enum {
  LDP_NOTIF_NONE = 0,
  LDP_NOTIF_SUCCESS,
  LDP_NOTIF_BAD_LDP_ID,
  LDP_NOTIF_BAD_PROTO,
  LDP_NOTIF_BAD_PDU_LEN,
  LDP_NOTIF_UNKNOWN_MESG,
  LDP_NOTIF_BAD_MESG_LEN,
  LDP_NOTIF_UNKNOWN_TVL,
  LDP_NOTIF_BAD_TLV_LEN,
  LDP_NOTIF_MALFORMED_TLV,
  LDP_NOTIF_HOLD_TIMER_EXPIRED,
  LDP_NOTIF_SHUTDOWN,
  LDP_NOTIF_LOOP_DETECTED,
  LDP_NOTIF_UNKNOWN_FEC,
  LDP_NOTIF_NO_ROUTE,
  LDP_NOTIF_NO_LABEL_RESOURCES_AVAILABLE,
  LDP_NOTIF_LABEL_RESOURCES_AVAILABLE,
  LDP_NOTIF_SESSION_REJECTED_NO_HELLO,
  LDP_NOTIF_SESSION_REJECTED_PARAMETERS_ADVERTISEMENT_MODE,
  LDP_NOTIF_SESSION_REJECTED_PARAMETERS_MAX_PDU_LEN,
  LDP_NOTIF_SESSION_REJECTED_PARAMETERS_LABEL_RANGE,
  LDP_NOTIF_KEEPALIVE_TIMER_EXPIRED,
  LDP_NOTIF_LABEL_ABORT,
  LDP_NOTIF_MISSING_MSG_PARAMS,
  LDP_NOTIF_UNSUPORTED_AF,
  LDP_NOTIF_SESSION_REJECTED_BAD_KEEPALIVE_TIME,
  LDP_NOTIF_INTERNAL_ERROR
} ldp_notif_status;

#define LDP_STATE_NUM 6
#define LDP_EVENT_NUM 10
#define LDP_FUNC_NUM 10

#include "ldp_defaults.h"
#include "mpls_handle_type.h"
#include "ldp_nortel.h"

typedef struct ldp_mesg {
  mplsLdpHeader_t header;
  union {
    mplsLdpMsg_t generic;
    mplsLdpInitMsg_t init;
    mplsLdpNotifMsg_t notif;
    mplsLdpHelloMsg_t hello;
    mplsLdpKeepAlMsg_t keep;
    mplsLdpAdrMsg_t addr;
    mplsLdpLblMapMsg_t map;
    mplsLdpLblReqMsg_t request;
    mplsLdpLbl_W_R_Msg_t release;
    mplsLdpLblAbortMsg_t abort;
  } u;
} ldp_mesg;

typedef struct ldp_buf {
  uint8_t *buffer;
  uint8_t *current;
  int current_size;
  int size;
  int total;
  int want;
} ldp_buf;

typedef struct ldp_global {
  struct ldp_outlabel_list outlabel;
  struct ldp_resource_list resource;
  struct ldp_hop_list_list hop_list;
  struct ldp_inlabel_list inlabel;
  struct ldp_nexthop_list nexthop;
  struct ldp_session_list session;
  struct ldp_tunnel_list tunnel;
  struct ldp_entity_list entity;
  struct ldp_peer_list peer;
  struct ldp_attr_list attr;
  struct ldp_addr_list addr;
  struct ldp_adj_list adj;
  struct ldp_if_list iff;
  struct ldp_fec_list fec;

  mpls_lock_handle global_lock;
  mpls_instance_handle user_data;

  mpls_tree_handle addr_tree;
  mpls_tree_handle fec_tree;

  mpls_socket_handle hello_socket;
  mpls_socket_handle listen_socket;

  mpls_timer_mgr_handle timer_handle;
  mpls_socket_mgr_handle socket_handle;
  mpls_fib_handle fib_handle;
  mpls_ifmgr_handle ifmgr_handle;

#if MPLS_USE_LSR
  mpls_cfg_handle lsr_handle;
#else
  mpls_mpls_handle mpls_handle;
#endif

  /*
   * CSN changes with every MIB set, BUT only when a entity goes through
   * shutdown/startup cycle will it grab the new CSN and use it in hellos
   */
  uint32_t configuration_sequence_number;

  /*
   * Message ID increaments with EVERY message, this means it will roll over
   */
  uint32_t message_identifier;

  struct mpls_inet_addr lsr_identifier;
  mpls_bool send_address_messages;
  mpls_bool send_lsrid_mapping;
  ldp_control_mode lsp_control_mode;
  ldp_retention_mode label_retention_mode;
  ldp_repaire_mode lsp_repair_mode;
  mpls_bool propagate_release;
  mpls_bool label_merge;
  ldp_loop_detection_mode loop_detection_mode;
  mpls_bool ttl_less_domain;
  uint16_t local_tcp_port;
  uint16_t local_udp_port;
  uint16_t backoff_step;
  int no_route_to_peer_time;

  /*
   * some global defaults, entities will inherit these values unless
   * instructed otherwise
   */
  struct mpls_inet_addr transport_address;
  uint16_t keepalive_timer;
  uint16_t keepalive_interval;
  uint16_t hellotime_timer;
  uint16_t hellotime_interval;

  mpls_admin_state_enum admin_state;
} ldp_global;

typedef struct ldp_entity {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_entity) _global;
  struct ldp_adj_list adj_root;

  ldp_entity_type_enum entity_type;
  union {
    struct ldp_peer *peer;
    struct ldp_if *iff;
  } p;

  ldp_state_enum state;
  uint32_t inherit_flag;
  uint32_t sub_index;
  uint32_t index;
  struct mpls_inet_addr transport_address;
  uint8_t protocol_version;
  uint16_t remote_tcp_port;
  uint16_t remote_udp_port;
  uint16_t max_pdu;
  uint16_t keepalive_timer;
  uint16_t keepalive_interval;
  uint16_t hellotime_timer;
  uint16_t hellotime_interval;
  uint16_t session_setup_count;
  uint16_t session_backoff_timer;
  ldp_distribution_mode label_distribution_mode;
  uint8_t path_vector_limit;
  uint8_t hop_count_limit;
  uint8_t label_request_count;
  uint16_t label_request_timer;
  ldp_loop_detection_mode loop_detection_mode;
  mpls_admin_state_enum admin_state;
  mpls_bool remote_in_ttl_less_domain;
  mpls_bool request_retry;

  /* mesg counters */
  uint32_t mesg_tx;
  uint32_t mesg_rx;

  /* only used for cfg gets */
  int adj_index;
  int adj_count;
} ldp_entity;

typedef struct ldp_if {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_if) _global;
  struct mpls_link_list session_root;
  struct ldp_nexthop_list nh_root;
  struct ldp_addr_list addr_root;
  struct ldp_entity *entity;
  mpls_timer_handle hellotime_send_timer;
  int hellotime_send_timer_duration;
  int label_space;
  uint32_t index;
  mpls_if_handle handle;

  struct ldp_mesg *tx_message;
  struct ldp_buf *tx_buffer;
  struct ldp_mesg *hello;

  /* YES this is a dest, it is what we use for sendto */
  struct mpls_dest dest;

  mpls_oper_state_enum oper_state;
  mpls_bool is_p2p;

  /* only used for cfg gets */
  uint32_t entity_index;
} ldp_if;

typedef struct ldp_peer {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_peer) _global;
  struct ldp_entity *entity;
  mpls_timer_handle no_route_to_peer_timer;
  mpls_timer_handle hellotime_send_timer;
  int hellotime_send_timer_duration;
  int label_space;
  uint32_t index;

  struct ldp_mesg *tx_message;
  struct ldp_buf *tx_buffer;
  struct ldp_mesg *hello;

  /* YES this is a dest, it is what we use for sendto */
  struct mpls_dest dest;
  ldp_role_enum target_role;

  char peer_name[MPLS_MAX_IF_NAME];
  mpls_oper_state_enum oper_state;

  /* only used for cfg gets */
  uint32_t entity_index;
} ldp_peer;

typedef struct ldp_session {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_session) _global;
  struct ldp_outlabel_list outlabel_root;
  struct mpls_link_list inlabel_root;
  struct mpls_link_list addr_root;
  struct ldp_attr_list attr_root;
  struct ldp_adj_list adj_root;
  mpls_timer_handle initial_distribution_timer;
  mpls_timer_handle keepalive_recv_timer;
  mpls_timer_handle keepalive_send_timer;
  uint32_t index;
  ldp_state_enum state;
  uint32_t oper_up;
  ldp_notif_status shutdown_notif;
  mpls_bool shutdown_fatal;
  mpls_socket_handle socket;
  mpls_timer_handle backoff_timer;
  int backoff;

  /* operational values learned from initialization */
  int oper_max_pdu;
  int oper_keepalive;
  int oper_keepalive_interval;
  int oper_path_vector_limit;
  ldp_distribution_mode oper_distribution_mode;
  ldp_loop_detection_mode oper_loop_detection;

  /* these values are learned form the remote peer */
  ldp_distribution_mode remote_distribution_mode;
  mpls_bool remote_loop_detection;
  int remote_path_vector_limit;
  int remote_keepalive;
  int remote_max_pdu;
  mpls_dest remote_dest;
  uint8_t session_name[20]; /* xxx.xxx.xxx.xxx:yyy\0 */

  mpls_bool no_label_resource_sent;
  mpls_bool no_label_resource_recv;
  mpls_bool on_global;

  /* various message and buffers used for tx and rx */
  struct ldp_mesg *keepalive;
  struct ldp_mesg *tx_message;
  struct ldp_buf *tx_buffer;

  /* cached from adj's */ 
  ldp_role_enum oper_role;

  /* these are config values come from entity */
  ldp_loop_detection_mode cfg_loop_detection_mode;
  ldp_distribution_mode cfg_distribution_mode;
  mpls_bool cfg_remote_in_ttl_less_domain;
  int cfg_label_request_count;
  int cfg_label_request_timer;
  uint16_t cfg_peer_tcp_port;
  int cfg_path_vector_limit;
  int cfg_hop_count_limit;
  int cfg_label_space;
  int cfg_keepalive;
  int cfg_max_pdu;

  /* mesg counters */
  uint32_t mesg_tx;
  uint32_t mesg_rx;

  /* only used by cfg gets */
  uint32_t adj_index;
} ldp_session;

typedef struct ldp_adj {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_adj) _global;
  MPLS_LIST_ELEM(ldp_adj) _session;
  MPLS_LIST_ELEM(ldp_adj) _entity;
  struct ldp_session *session;
  struct ldp_entity *entity;
  mpls_timer_handle hellotime_recv_timer;
  mpls_oper_state_enum state;
  ldp_role_enum role;
  uint32_t index;

  /* these values are learned form the remote peer */
  struct mpls_inet_addr remote_transport_address;
  struct mpls_inet_addr remote_source_address;
  struct mpls_inet_addr remote_lsr_address;
  int remote_label_space;
  int remote_hellotime;
  uint32_t remote_csn;

  /* only used by cfg gets */
  uint32_t session_index;
  uint32_t entity_index;
} ldp_adj;

typedef struct ldp_addr {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_addr) _global;
  MPLS_LIST_ELEM(ldp_addr) _if;
  struct mpls_link_list session_root;
  struct ldp_nexthop_list nh_root;
  struct mpls_inet_addr address;
  struct ldp_if *iff;

  /*
   * if an address has a if_handle it is locally attached
   */
  mpls_if_handle if_handle;
  uint32_t index;

  /*
   * only used durring gets
   */
  uint32_t session_index;
  uint32_t nexthop_index;
  uint32_t if_index;
} ldp_addr;

struct ldp_outlabel;

typedef struct ldp_nexthop {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_nexthop) _global;
  MPLS_LIST_ELEM(ldp_nexthop) _fec;
  MPLS_LIST_ELEM(ldp_nexthop) _addr;
  MPLS_LIST_ELEM(ldp_nexthop) _if;
  MPLS_LIST_ELEM(ldp_nexthop) _outlabel;
  struct ldp_outlabel_list outlabel_root;
  struct ldp_fec *fec;
  struct ldp_addr *addr;
  struct ldp_if *iff;
  struct ldp_outlabel *outlabel;
  struct mpls_nexthop info;

  uint32_t index;
} ldp_nexthop;

typedef struct ldp_outlabel {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_outlabel) _global;
  MPLS_LIST_ELEM(ldp_outlabel) _session;
  MPLS_LIST_ELEM(ldp_outlabel) _nexthop;
  struct ldp_inlabel_list inlabel_root;
  struct ldp_tunnel_list tunnel_root;
  struct ldp_nexthop_list nh_root;
  uint32_t merge_count;
  struct ldp_attr *attr;
  struct ldp_session *session;
  struct ldp_nexthop *nh;
  struct mpls_outsegment info;
  uint32_t index;
  mpls_bool switching;

  /* only used by get() */
  uint32_t session_index;
  uint32_t nh_index;
  uint32_t attr_index;
} ldp_outlabel;

typedef struct ldp_inlabel {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_inlabel) _global;
  MPLS_LIST_ELEM(ldp_inlabel) _outlabel;
  struct mpls_link_list session_root;
  struct mpls_link_list attr_root;
  struct ldp_outlabel *outlabel;
  uint32_t reuse_count;
  uint32_t index;
  struct mpls_insegment info;

  /* only used by get() */
  uint32_t outlabel_index;
} ldp_inlabel;

typedef struct ldp_fec {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_fec) _global;
  MPLS_LIST_ELEM(ldp_fec) _inlabel;
  MPLS_LIST_ELEM(ldp_fec) _outlabel;
  MPLS_LIST_ELEM(ldp_fec) _tree;
  MPLS_LIST_ELEM(ldp_fec) _addr;
  MPLS_LIST_ELEM(ldp_fec) _fec;
  MPLS_LIST_ELEM(ldp_fec) _if;
  struct ldp_fs_list fs_root_us;
  struct ldp_fs_list fs_root_ds;
  /* ECMP */
  struct ldp_nexthop_list nh_root;
  struct mpls_fec info;
  uint32_t index;
} ldp_fec;

typedef struct ldp_fs {
  struct ldp_attr_list attr_root;
  MPLS_LIST_ELEM(ldp_fs) _fec;
  struct ldp_session *session;
} ldp_fs;

typedef struct ldp_attr {
  MPLS_REFCNT_FIELD;
  uint32_t index;
  uint32_t msg_id;
  struct ldp_attr_list us_attr_root;
  struct ldp_attr *ds_attr;
  ldp_lsp_state state;
  mpls_bool ingress;
  mpls_bool filtered;
  mpls_bool in_tree;
  struct ldp_session *session;
  uint32_t attempt_count;
  mpls_timer_handle action_timer;
  ldp_lsp_state action;
  ldp_fec *fec;

  MPLS_LIST_ELEM(ldp_attr) _session;
  MPLS_LIST_ELEM(ldp_attr) _global;
  MPLS_LIST_ELEM(ldp_attr) _ds_attr;
  MPLS_LIST_ELEM(ldp_attr) _fs;

  mplsLdpFecTlv_t fecTlv;
  mplsLdpGenLblTlv_t genLblTlv;
  mplsLdpAtmLblTlv_t atmLblTlv;
  mplsLdpFrLblTlv_t frLblTlv;
  mplsLdpHopTlv_t hopCountTlv;
  mplsLdpPathTlv_t pathVecTlv;
  mplsLdpLblMsgIdTlv_t lblMsgIdTlv;
  mplsLdpLspIdTlv_t lspidTlv;
  mplsLdpTrafficTlv_t trafficTlv;
  mplsLdpStatusTlv_t statusTlv;
  mplsLdpRetMsgTlv_t retMsgTlv;

  uint8_t fecTlvExists:1;
  uint8_t genLblTlvExists:1;
  uint8_t atmLblTlvExists:1;
  uint8_t frLblTlvExists:1;
  uint8_t hopCountTlvExists:1;
  uint8_t pathVecTlvExists:1;
  uint8_t lblMsgIdTlvExists:1;
  uint8_t lspidTlvExists:1;
  uint8_t trafficTlvExists:1;
  uint8_t statusTlvExists:1;
  uint8_t retMsgTlvExists:1;

  struct ldp_outlabel *outlabel;
  struct ldp_inlabel *inlabel;

  /* only used for get() */
  uint32_t inlabel_index;
  uint32_t outlabel_index;
  uint32_t session_index;
} ldp_attr;

typedef struct ldp_resource {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_resource) _global;
  struct ldp_tunnel *tunnel;
  uint32_t index;
  uint32_t max_rate;
  uint32_t mean_rate;
  uint32_t burst_size;
} ldp_resource;

typedef struct ldp_hop {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_hop) _hop_list;
  struct ldp_hop_list *hop_list;
  uint32_t index;
  uint32_t hop_list_index;
  uint32_t path_option;
  mpls_inet_addr addr;
  uint32_t type;
} ldp_hop;

typedef struct ldp_hop_list {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_hop_list) _global;
  struct _ldp_hop_list hop;
  struct ldp_tunnel *tunnel;
  uint32_t index;
} ldp_hop_list;

typedef struct ldp_tunnel {
  MPLS_REFCNT_FIELD;
  MPLS_LIST_ELEM(ldp_tunnel) _global;
  MPLS_LIST_ELEM(ldp_tunnel) _outlabel;
  uint32_t index;
  mpls_inet_addr ingress_lsrid;
  ldp_addr egress_lsrid;
  char name[MPLS_MAX_IF_NAME];
  mpls_bool is_interface;
  uint32_t outlabel_index;
  struct ldp_outlabel *outlabel;
  uint32_t setup_prio;
  uint32_t hold_prio;
  uint32_t instance_prio;
  uint32_t resource_index;
  struct ldp_resource *resource;
  uint32_t hop_list_index;
  struct ldp_hop_list *hop_list;
  ldp_fec fec;
  mpls_admin_state_enum admin_state;

  uint32_t primary_instance;
  uint32_t any_affinity;
  uint32_t all_affinity;
  uint32_t no_all_affinity;
  uint32_t path_in_use;
  uint32_t protocol;
  mpls_bool local_protect;
  uint32_t session_attr;
  uint32_t owner;
} ldp_tunnel;

typedef void (*ldp_tree_callback) (void *);

#endif
