
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_STRUCT_H_
#define _MPLS_STRUCT_H_

#define MPLS_MAX_IF_NAME 16
#define MPLS_MAX_LABELSTACK 4

#include "mpls_handle_type.h"
#include "mpls_bitfield.h"

typedef enum {
  MPLS_SUCCESS = 1,
  MPLS_FAILURE,
  MPLS_FATAL,
  MPLS_CLOSED,
  MPLS_NON_BLOCKING,
  MPLS_END_OF_LIST,
  MPLS_NO_ROUTE,
} mpls_return_enum;

typedef enum {
  MPLS_UPDATE_ADD,
  MPLS_UPDATE_DEL,
  MPLS_UPDATE_MODIFY
} mpls_update_enum;

typedef enum {
  MPLS_OPER_UP = 1,
  MPLS_OPER_DOWN,
} mpls_oper_state_enum;

typedef enum {
  MPLS_TIMER_ONESHOT = 1,
  MPLS_TIMER_REOCCURRING,
} mpls_timer_type_enum;

typedef enum {
  MPLS_UNIT_MICRO = 1,
  MPLS_UNIT_SEC,
  MPLS_UNIT_MIN,
  MPLS_UNIT_HOUR
} mpls_time_unit_enum;

typedef enum {
  MPLS_ADMIN_ENABLE = 1,
  MPLS_ADMIN_DISABLE
} mpls_admin_state_enum;

typedef enum {
  MPLS_LABEL_RANGE_GENERIC = 1,
  MPLS_LABEL_RANGE_ATM_VP,
  MPLS_LABEL_RANGE_ATM_VC,
  MPLS_LABEL_RANGE_ATM_VP_VC,
  MPLS_LABEL_RANGE_FR_10,
  MPLS_LABEL_RANGE_FR_24
} mpls_label_range_type;

typedef enum {
  MPLS_LABEL_TYPE_NONE,
  MPLS_LABEL_TYPE_GENERIC,
  MPLS_LABEL_TYPE_ATM,
  MPLS_LABEL_TYPE_FR
} mpls_label_type;

typedef enum {
  MPLS_BOOL_FALSE = 0,
  MPLS_BOOL_TRUE = 1
} mpls_bool;

typedef enum {
  MPLS_SOCKET_UDP_DATA = 1,
  MPLS_SOCKET_TCP_LISTEN,
  MPLS_SOCKET_TCP_CONNECT,
  MPLS_SOCKET_TCP_DATA,
  MPLS_SOCKET_ROUTE_UPDATE,
} mpls_socket_enum;

typedef enum {
  MPLS_SOCKOP_NONBLOCK = 0x1,
  MPLS_SOCKOP_REUSE = 0x2,
  MPLS_SOCKOP_ROUTERALERT = 0x4,
  MPLS_SOCKOP_HDRINCL = 0x8
} mpls_socket_option_type;

typedef enum {
  MPLS_TRACE_STATE_SEND,
  MPLS_TRACE_STATE_RECV,
  MPLS_TRACE_STATE_ALL
} mpls_trace_states;

typedef enum {
  MPLS_OWNER_LDP,
  MPLS_OWNER_CRLDP,
  MPLS_OWNER_STATIC,
  MPLS_OWNER_RSVP_TE
} mpls_owners_enum;

/* this structure is slurped from GNU header files */
typedef struct mpls_iphdr {
  BITFIELDS_ASCENDING_2(unsigned int ihl:4,
			unsigned int version:4);
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
  /*The options start here. */
} mpls_iphdr;

typedef struct mpls_label_struct {
  mpls_label_type type;
  union {
    int gen;
    struct {
      int vpi;
      int vci;
    } atm;
    struct {
      int len;
      int dlci;
    } fr;
  } u;
} mpls_label_struct;

typedef enum mpls_family_enum {
  MPLS_FAMILY_NONE,
  MPLS_FAMILY_IPV4,
  MPLS_FAMILY_IPV6,
} mpls_family_enum;

typedef struct mpls_inet_addr {
  enum mpls_family_enum type;
  union {
    uint8_t ipv6[16];
    uint32_t ipv4;
  } u;
} mpls_inet_addr;

typedef struct mpls_dest {
  struct mpls_inet_addr addr;
  uint16_t port;
  mpls_if_handle if_handle;
} mpls_dest;

typedef struct mpls_range {
  int label_space;
  mpls_label_range_type type;
  struct mpls_label_struct min, max;
} mpls_range;

typedef enum mpls_nexthop_enum {
  MPLS_NH_NONE	= 0x0,
  MPLS_NH_IP	= 0x1,
  MPLS_NH_IF	= 0x2,
  MPLS_NH_OUTSEGMENT	= 0x4
} mpls_nexthop_enum;

typedef enum mpls_fec_enum {
  MPLS_FEC_NONE,
  MPLS_FEC_PREFIX,
  MPLS_FEC_HOST,
  MPLS_FEC_L2CC,
  MPLS_FEC_PW, //testig (add by timothy)
} mpls_fec_enum;

struct mpls_fec;

typedef struct mpls_nexthop {
  short distance;
  short metric;
  mpls_bool attached;

  unsigned char type;
  struct mpls_inet_addr ip;  
  mpls_if_handle if_handle;
  mpls_outsegment_handle outsegment_handle;

  /* only used during gets */
  uint32_t index;
} mpls_nexthop;

typedef struct mpls_fec {
  enum mpls_fec_enum type;
  union {
    struct {
      struct mpls_inet_addr network;
      uint8_t length;
    } prefix;
    struct mpls_inet_addr host;
    struct {
      mpls_if_handle interface;
      uint32_t connection_id;
      uint32_t group_id;
      uint8_t type;
    } l2cc;
  } u;

  /* only used during gets */
  uint32_t index;
} mpls_fec;

typedef struct mpls_insegment {
  struct mpls_label_struct label;
  uint32_t npop;
  uint32_t labelspace;
  uint16_t family;
  mpls_insegment_handle handle;
  mpls_owners_enum owner;
} mpls_insegment;

typedef struct mpls_outsegment {
  struct mpls_label_struct label;
  mpls_bool push_label;
  struct mpls_nexthop nexthop;
  mpls_outsegment_handle handle;
  mpls_owners_enum owner;
} mpls_outsegment;

typedef struct mpls_xconnect {
  uint32_t lspid;
  uint8_t stack_size;
  struct mpls_label_struct stack[MPLS_MAX_LABELSTACK];
  mpls_bool is_persistent;
  mpls_xconnect_handle handle;
  mpls_owners_enum owner;
} mpls_xconnect;

typedef void *mpls_cfg_handle;

#endif
