
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _LDP_CFG_H_
#define _LDP_CFG_H_

#include "ldp_struct.h"
#include "ldp_entity.h"
#include "ldp_session.h"

#define LDP_CFG_ADD				0x00000001
#define LDP_CFG_DEL				0x10000000

#define LDP_GLOBAL_CFG_ADMIN_STATE		0x00000002
#define LDP_GLOBAL_CFG_CONTROL_MODE		0x00000004
#define LDP_GLOBAL_CFG_RETENTION_MODE		0x00000008
#define LDP_GLOBAL_CFG_REPAIR_MODE		0x00000010
#define LDP_GLOBAL_CFG_PROPOGATE_RELEASE	0x00000020
#define LDP_GLOBAL_CFG_LABEL_MERGE		0x00000040
#define LDP_GLOBAL_CFG_LOOP_DETECTION_MODE	0x00000080
#define LDP_GLOBAL_CFG_TTLLESS_DOMAIN		0x00000100
#define LDP_GLOBAL_CFG_LOCAL_TCP_PORT		0x00000200
#define LDP_GLOBAL_CFG_LOCAL_UDP_PORT		0x00000400
#define LDP_GLOBAL_CFG_LSR_IDENTIFIER		0x00000800
#define LDP_GLOBAL_CFG_TRANS_ADDR		0x00001000
#define LDP_GLOBAL_CFG_KEEPALIVE_TIMER		0x00002000
#define LDP_GLOBAL_CFG_KEEPALIVE_INTERVAL	0x00004000
#define LDP_GLOBAL_CFG_HELLOTIME_TIMER		0x00008000
#define LDP_GLOBAL_CFG_HELLOTIME_INTERVAL	0x00010000
#define LDP_GLOBAL_CFG_LSR_HANDLE		0x00020000

#define LDP_GLOBAL_CFG_WHEN_DOWN	(LDP_GLOBAL_CFG_LOCAL_TCP_PORT|\
					LDP_GLOBAL_CFG_LOCAL_UDP_PORT|\
					LDP_GLOBAL_CFG_LSR_IDENTIFIER)

#define LDP_ENTITY_CFG_TRANS_ADDR		0x00000002
#define LDP_ENTITY_CFG_PROTO_VER		0x00000004
#define LDP_ENTITY_CFG_REMOTE_TCP		0x00000008
#define LDP_ENTITY_CFG_REMOTE_UDP		0x00000010
#define LDP_ENTITY_CFG_MAX_PDU			0x00000020
#define LDP_ENTITY_CFG_KEEPALIVE_TIMER		0x00000040
#define LDP_ENTITY_CFG_KEEPALIVE_INTERVAL       0x00000080
#define LDP_ENTITY_CFG_HELLOTIME_TIMER		0x00000100
#define LDP_ENTITY_CFG_HELLOTIME_INTERVAL       0x00000200
#define LDP_ENTITY_CFG_SESSION_SETUP_COUNT      0x00000400
#define LDP_ENTITY_CFG_SESSION_BACKOFF_TIMER    0x00000800
#define LDP_ENTITY_CFG_DISTRIBUTION_MODE	0x00001000
#define LDP_ENTITY_CFG_PATHVECTOR_LIMIT		0x00002000
#define LDP_ENTITY_CFG_HOPCOUNT_LIMIT		0x00004000
#define LDP_ENTITY_CFG_REQUEST_TIMER		0x00008000
#define LDP_ENTITY_CFG_REQUEST_COUNT		0x00010000
#define LDP_ENTITY_CFG_ADMIN_STATE		0x00020000
#define LDP_ENTITY_CFG_ADJ_COUNT		0x00040000
#define LDP_ENTITY_CFG_TYPE			0x00080000
#define LDP_ENTITY_CFG_SUB_INDEX		0x00100000
#define LDP_ENTITY_CFG_INHERIT_FLAG		0x00200000
#define LDP_ENTITY_CFG_MESG_TX			0x00400000
#define LDP_ENTITY_CFG_MESG_RX			0x00800000
#define LDP_ENTITY_CFG_ADJ_INDEX		0x01000000

#define LDP_ENTITY_CFG_WHEN_DOWN	(LDP_CFG_DEL|\
					LDP_ENTITY_CFG_TRANS_ADDR|\
					LDP_ENTITY_CFG_PROTO_VER|\
					LDP_ENTITY_CFG_REMOTE_TCP|\
					LDP_ENTITY_CFG_REMOTE_UDP|\
					LDP_ENTITY_CFG_DISTRIBUTION_MODE|\
					LDP_ENTITY_CFG_TYPE|\
					LDP_ENTITY_CFG_SUB_INDEX)

#define LDP_FEC_CFG_BY_INDEX			0x00000002
#define LDP_FEC_NEXTHOP_CFG_BY_INDEX		0x00000004

#define LDP_IF_CFG_LABEL_SPACE			0x00000002
#define LDP_IF_CFG_INDEX			0x00000004
#define LDP_IF_CFG_ENTITY_INDEX			0x00000008
#define LDP_IF_CFG_OPER_STATE			0x00000010
#define LDP_IF_CFG_BY_INDEX			0x00000080
#define LDP_IF_ADDR_CFG_BY_INDEX		0x00000100
#define LDP_IF_CFG_HANDLE			0x00000200

#define LDP_IF_CFG_WHEN_DOWN		(LDP_CFG_DEL|\
					LDP_IF_CFG_LABEL_SPACE|\
					LDP_IF_CFG_INDEX|\
					LDP_IF_CFG_ENTITY_INDEX|\
					LDP_IF_CFG_OPER_STATE|\
					LDP_IF_CFG_HANDLE)

#define LDP_PEER_CFG_LABEL_SPACE		0x00000002
#define LDP_PEER_CFG_DEST_ADDR			0x00000004
#define LDP_PEER_CFG_TARGET_ROLE		0x00000008
#define LDP_PEER_CFG_ENTITY_INDEX		0x00000010
#define LDP_PEER_CFG_OPER_STATE			0x00000020
#define LDP_PEER_CFG_PEER_NAME			0x00000040
#define LDP_PEER_CFG_LOCAL_SOURCE_ADDR		0x00000080

#define LDP_PEER_CFG_WHEN_DOWN 		(LDP_CFG_DEL|\
					LDP_PEER_CFG_LABEL_SPACE|\
					LDP_PEER_CFG_DEST_ADDR|\
					LDP_PEER_CFG_TARGET_ROLE)

#define LDP_SESSION_CFG_INDEX				0x00000002
#define LDP_SESSION_CFG_STATE				0x00000004
#define LDP_SESSION_CFG_MAX_PDU				0x00000008
#define LDP_SESSION_CFG_KEEPALIVE			0x00000010
#define LDP_SESSION_CFG_PATH_LIMIT			0x00000020
#define LDP_SESSION_CFG_DIST_MODE			0x00000040
#define LDP_SESSION_CFG_LOOP_DETECTION			0x00000080
#define LDP_SESSION_CFG_REMOTE_MAX_PDU			0x00000100
#define LDP_SESSION_CFG_REMOTE_KEEPALIVE		0x00000200
#define LDP_SESSION_CFG_REMOTE_PATH_LIMIT		0x00000400
#define LDP_SESSION_CFG_REMOTE_DIST_MODE		0x00000800
#define LDP_SESSION_CFG_REMOTE_LOOP_DETECTION		0x00001000
#define LDP_SESSION_CFG_REMOTE_ADDR			0x00002000
#define LDP_SESSION_CFG_REMOTE_PORT			0x00004000
#define LDP_SESSION_CFG_LABEL_RESOURCE_STATE_LOCAL	0x00008000
#define LDP_SESSION_CFG_LABEL_RESOURCE_STATE_REMOTE	0x00010000
#define LDP_SESSION_CFG_ENTITY_INDEX			0x00020000
#define LDP_SESSION_CFG_ADJ_INDEX			0x00040000
#define LDP_SESSION_CFG_MESG_TX				0x00080000
#define LDP_SESSION_CFG_MESG_RX				0x00100000
#define LDP_SESSION_CFG_OPER_UP				0x00200000

#define LDP_SESSION_RADDR_CFG_ADDR			0x00000002
#define LDP_SESSION_RADDR_CFG_INDEX			0x00000004

#define LDP_ATTR_CFG_STATE				0x00000002
#define LDP_ATTR_CFG_FEC				0x00000004
#define LDP_ATTR_CFG_LABEL				0x00000008
#define LDP_ATTR_CFG_HOP_COUNT				0x00000010
#define LDP_ATTR_CFG_PATH				0x00000020
#define LDP_ATTR_CFG_SESSION_INDEX			0x00000040
#define LDP_ATTR_CFG_INLABEL_INDEX			0x00000080
#define LDP_ATTR_CFG_OUTLABEL_INDEX			0x00000100
#define LDP_ATTR_CFG_INGRESS				0x00000200

#define LDP_ADJ_CFG_REMOTE_TRADDR			0x00000002
#define LDP_ADJ_CFG_REMOTE_SRCADDR			0x00000004
#define LDP_ADJ_CFG_REMOTE_LSRADDR			0x00000008
#define LDP_ADJ_CFG_REMOTE_CSN				0x00000010
#define LDP_ADJ_CFG_REMOTE_LABELSPACE			0x00000020
#define LDP_ADJ_CFG_REMOTE_HELLOTIME			0x00000040
#define LDP_ADJ_CFG_ENTITY_INDEX			0x00000080
#define LDP_ADJ_CFG_REMOTE_SESSION_INDEX		0x00000100
#define LDP_ADJ_CFG_ROLE				0x00000200

#define LDP_INLABEL_CFG_LABELSPACE			0x00000002
#define LDP_INLABEL_CFG_LABEL				0x00000004
#define LDP_INLABEL_CFG_OUTLABEL_INDEX			0x00000008

#define LDP_OUTLABEL_CFG_NH_INDEX			0x00000002
#define LDP_OUTLABEL_CFG_SESSION_INDEX			0x00000004
#define LDP_OUTLABEL_CFG_LABEL				0x00000008
#define LDP_OUTLABEL_CFG_MERGE_COUNT			0x00000010

#define LDP_TUNNEL_CFG_INDEX				0x00000002
#define LDP_TUNNEL_CFG_INSTANCE				0x00000004
#define LDP_TUNNEL_CFG_INGRESS				0x00000008
#define LDP_TUNNEL_CFG_EGRESS				0x00000010
#define LDP_TUNNEL_CFG_NAME				0x00000020
#define LDP_TUNNEL_CFG_IS_IF				0x00000040
#define LDP_TUNNEL_CFG_OUTLABEL				0x00000080
#define LDP_TUNNEL_CFG_SETUP_PRIO			0x00000100
#define LDP_TUNNEL_CFG_HOLD_PRIO			0x00000200
#define LDP_TUNNEL_CFG_INSTANCE_PRIO			0x00000400
#define LDP_TUNNEL_CFG_LOCAL_PROTECT			0x00000800
#define LDP_TUNNEL_CFG_RESOURCE_INDEX			0x00001000
#define LDP_TUNNEL_CFG_HOP_LIST_INDEX			0x00002000
#define LDP_TUNNEL_CFG_ROLE				0x00004000
#define LDP_TUNNEL_CFG_ADMIN_STATE			0x00008000
#define LDP_TUNNEL_CFG_FEC				0x00010000

#define LDP_TUNNEL_CFG_WHEN_DOWN		(LDP_CFG_DEL|\
						LDP_TUNNEL_CFG_OUTLABEL|\
						LDP_TUNNEL_CFG_RESOURCE_INDEX|\
						LDP_TUNNEL_CFG_HOP_LIST_INDEX)

#define LDP_RESOURCE_CFG_INDEX				0x00000002
#define LDP_RESOURCE_CFG_MAXBPS				0x00000004
#define LDP_RESOURCE_CFG_MEANBPS			0x00000008
#define LDP_RESOURCE_CFG_BURSTSIZE			0x00000010

#define LDP_RESOURCE_CFG_WHEN_DOWN		(LDP_CFG_DEL|\
						LDP_RESOURCE_CFG_MAXBPS|\
						LDP_RESOURCE_CFG_MEANBPS|\
						LDP_RESOURCE_CFG_BURSTSIZE)

#define LDP_HOP_CFG_INDEX				0x00000002
#define LDP_HOP_CFG_LIST_INDEX				0x00000004
#define LDP_HOP_CFG_PATH_OPTION				0x00000008
#define LDP_HOP_CFG_ADDR				0x00000010
#define LDP_HOP_CFG_TYPE				0x00000020

#define LDP_HOP_CFG_WHEN_DOWN			(LDP_CFG_DEL|\
						LDP_HOP_CFG_INDEX|\
						LDP_HOP_CFG_LIST_INDEX|\
						LDP_HOP_CFG_ADDR|\
						LDP_HOP_CFG_TYPE)

extern mpls_cfg_handle ldp_cfg_open(mpls_instance_handle data);
extern void ldp_cfg_close(mpls_cfg_handle handle);

extern mpls_return_enum ldp_cfg_global_get(mpls_cfg_handle handle,
  ldp_global * g, uint32_t flag);
extern mpls_return_enum ldp_cfg_global_set(mpls_cfg_handle handle,
  ldp_global * g, uint32_t flag);
extern void ldp_cfg_global_attr(mpls_cfg_handle handle);

extern mpls_return_enum ldp_cfg_entity_get(mpls_cfg_handle handle,
  ldp_entity * e, uint32_t flag);
extern mpls_return_enum ldp_cfg_entity_getnext(mpls_cfg_handle handle,
  ldp_entity * e, uint32_t flag);
extern mpls_return_enum ldp_cfg_entity_test(mpls_cfg_handle handle,
  ldp_entity * e, uint32_t flag);
extern mpls_return_enum ldp_cfg_entity_set(mpls_cfg_handle handle,
  ldp_entity * e, uint32_t flag);
extern mpls_return_enum ldp_cfg_entity_adj_getnext(mpls_cfg_handle handle,
  ldp_entity * e);

extern mpls_return_enum ldp_cfg_attr_get(mpls_cfg_handle handle, ldp_attr * a,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_attr_getnext(mpls_cfg_handle handle,
  ldp_attr * a, uint32_t flag);

extern mpls_return_enum ldp_cfg_peer_get(mpls_cfg_handle handle, ldp_peer * p,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_peer_getnext(mpls_cfg_handle handle,
  ldp_peer * p, uint32_t flag);
extern mpls_return_enum ldp_cfg_peer_test(mpls_cfg_handle handle, ldp_peer * p,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_peer_set(mpls_cfg_handle handle, ldp_peer * p,
  uint32_t flag);

extern mpls_return_enum ldp_cfg_fec_get(mpls_cfg_handle handle, mpls_fec * p,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_fec_getnext(mpls_cfg_handle handle,
  mpls_fec * p, uint32_t flag);
extern mpls_return_enum ldp_cfg_fec_test(mpls_cfg_handle handle, mpls_fec * p,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_fec_set(mpls_cfg_handle handle, mpls_fec * p,
  uint32_t flag);

extern mpls_return_enum ldp_cfg_fec_nexthop_get(mpls_cfg_handle handle,
  mpls_fec * p, mpls_nexthop *nh, uint32_t flag);
extern mpls_return_enum ldp_cfg_fec_nexthop_getnext(mpls_cfg_handle handle,
  mpls_fec * p, mpls_nexthop *nh, uint32_t flag);
extern mpls_return_enum ldp_cfg_fec_nexthop_test(mpls_cfg_handle handle,
  mpls_fec * p, mpls_nexthop *nh, uint32_t flag);
extern mpls_return_enum ldp_cfg_fec_nexthop_set(mpls_cfg_handle handle,
  mpls_fec * p, mpls_nexthop *nh, uint32_t flag);

extern mpls_return_enum ldp_cfg_addr_get(mpls_cfg_handle handle, ldp_addr * a,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_addr_getnext(mpls_cfg_handle handle,
  ldp_addr * a, uint32_t flag);

extern mpls_return_enum ldp_cfg_if_get(mpls_cfg_handle handle, ldp_if * i,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_if_getnext(mpls_cfg_handle handle, ldp_if * i,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_if_test(mpls_cfg_handle handle, ldp_if * i,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_if_set(mpls_cfg_handle handle, ldp_if * i,
  uint32_t flag);

extern mpls_return_enum ldp_cfg_if_addr_get(mpls_cfg_handle handle, ldp_if * i,
  ldp_addr * a, uint32_t flag);
extern mpls_return_enum ldp_cfg_if_addr_getnext(mpls_cfg_handle handle,
  ldp_if * i, ldp_addr *a, uint32_t flag);
extern mpls_return_enum ldp_cfg_if_addr_set(mpls_cfg_handle handle, ldp_if *i,
  ldp_addr * a, uint32_t flag);

extern mpls_return_enum ldp_cfg_labelrange_get(mpls_cfg_handle handle,
  mpls_range * r, uint32_t flag);
extern mpls_return_enum ldp_cfg_labelrange_test(mpls_cfg_handle handle,
  mpls_range * r, uint32_t flag);
extern mpls_return_enum ldp_cfg_labelrange_set(mpls_cfg_handle handle,
  mpls_range * r, uint32_t flag);

extern mpls_return_enum ldp_cfg_adj_get(mpls_cfg_handle handle, ldp_adj * a,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_adj_getnext(mpls_cfg_handle handle, ldp_adj * a,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_adj_entity_getnext(mpls_cfg_handle handle,
  ldp_adj * a);

extern mpls_return_enum ldp_cfg_session_get(mpls_cfg_handle handle,
  ldp_session * s, uint32_t flag);
extern mpls_return_enum ldp_cfg_session_getnext(mpls_cfg_handle handle,
  ldp_session * s, uint32_t flag);

extern mpls_return_enum ldp_cfg_session_raddr_get(mpls_cfg_handle handle,
  ldp_session * s, ldp_addr * a, uint32_t flag);
extern mpls_return_enum ldp_cfg_session_raddr_getnext(mpls_cfg_handle handle,
  ldp_session * s, ldp_addr * a, uint32_t flag);

extern mpls_return_enum ldp_cfg_inlabel_get(mpls_cfg_handle handle,
  ldp_inlabel * i, uint32_t flag);
mpls_return_enum ldp_cfg_inlabel_getnext(mpls_cfg_handle handle,
  ldp_inlabel * i, uint32_t flag);
extern mpls_return_enum ldp_cfg_outlabel_get(mpls_cfg_handle handle,
  ldp_outlabel * o, uint32_t flag);
mpls_return_enum ldp_cfg_outlabel_getnext(mpls_cfg_handle handle,
  ldp_outlabel * o, uint32_t flag);

extern mpls_return_enum ldp_cfg_range_set(mpls_cfg_handle handle,
  mpls_range * r, uint32_t flag);
extern mpls_return_enum ldp_cfg_range_test(mpls_cfg_handle handle,
  mpls_range * r, uint32_t flag);
extern mpls_return_enum ldp_cfg_range_get(mpls_cfg_handle handle,
  mpls_range * r, uint32_t flag);

extern mpls_return_enum ldp_cfg_tunnel_set(mpls_cfg_handle handle,
  ldp_tunnel * r, uint32_t flag);
extern mpls_return_enum ldp_cfg_tunnel_test(mpls_cfg_handle handle,
  ldp_tunnel * r, uint32_t flag);
extern mpls_return_enum ldp_cfg_tunnel_get(mpls_cfg_handle handle,
  ldp_tunnel * r, uint32_t flag);

extern mpls_return_enum ldp_cfg_resource_set(mpls_cfg_handle handle,
  ldp_resource * r, uint32_t flag);
extern mpls_return_enum ldp_cfg_resource_test(mpls_cfg_handle handle,
  ldp_resource * r, uint32_t flag);
extern mpls_return_enum ldp_cfg_resource_get(mpls_cfg_handle handle,
  ldp_resource * r, uint32_t flag);

extern mpls_return_enum ldp_cfg_hop_set(mpls_cfg_handle handle, ldp_hop * r,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_hop_test(mpls_cfg_handle handle, ldp_hop * r,
  uint32_t flag);
extern mpls_return_enum ldp_cfg_hop_get(mpls_cfg_handle handle, ldp_hop * r,
  uint32_t flag);

#endif
