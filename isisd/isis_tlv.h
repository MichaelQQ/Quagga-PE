/*
 * IS-IS Rout(e)ing protocol - isis_tlv.h
 *                             IS-IS TLV related routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _ZEBRA_ISIS_TLV_H
#define _ZEBRA_ISIS_TLV_H

/*
 * The list of TLVs we (should) support.
 * ____________________________________________________________________________
 * Name                   Value  IIH LSP SNP Status
 *                               LAN
 * ____________________________________________________________________________
 *
 * Area Addresses             1   y   y   n  ISO10589
 * IIS Neighbors              2   n   y   n  ISO10589
 * ES Neighbors               3   n   y   n  ISO10589
 * IIS Neighbors              6   y   n   n  ISO10589
 * Padding                    8   y   n   n  ISO10589
 * LSP Entries                9   n   n   y  ISO10589
 * Authentication            10   y   y   y  ISO10589, RFC3567
 * Checksum                  12   y   n   y  RFC3358
 * TE IS Reachability        22   n   y   n  RFC5305
 * IS Alias                  24   n   y   n  RFC3786
 * IP Int. Reachability     128   n   y   n  RFC1195
 * Protocols Supported      129   y   y   n  RFC1195
 * IP Ext. Reachability     130   n   y   n  RFC1195
 * IDRPI                    131   n   y   y  RFC1195
 * IP Interface Address     132   y   y   n  RFC1195
 * TE Router ID             134   n   y   n  RFC5305
 * Extended IP Reachability 135   n   y   n  RFC5305
 * Dynamic Hostname         137   n   y   n  RFC2763
 * Shared Risk Link Group   138   n   y   y  RFC5307
 * Restart TLV              211   y   n   n  RFC3847
 * MT IS Reachability       222   n   y   n  RFC5120
 * MT Supported             229   y   y   n  RFC5120
 * IPv6 Interface Address   232   y   y   n  RFC5308
 * MT IP Reachability       235   n   y   n  RFC5120
 * IPv6 IP Reachability     236   n   y   n  RFC5308
 * MT IPv6 IP Reachability  237   n   y   n  RFC5120
 * P2P Adjacency State      240   y   n   n  RFC3373
 * IIH Sequence Number      241   y   n   n  draft-shen-isis-iih-sequence
 * Router Capability        242   -   -   -  draft-ietf-isis-caps
 *
 *
 * IS Reachability sub-TLVs we (should) support.
 * ____________________________________________________________________________
 * Name                           Value   Status
 * ____________________________________________________________________________
 * Administartive group (color)       3   RFC5305
 * Link Local/Remote Identifiers      4   RFC5307
 * IPv4 interface address             6   RFC5305
 * IPv4 neighbor address              8   RFC5305
 * Maximum link bandwidth             9   RFC5305
 * Reservable link bandwidth         10   RFC5305
 * Unreserved bandwidth              11   RFC5305
 * TE Default metric                 18   RFC5305
 * Link Protection Type              20   RFC5307
 * Interface Switching Capability    21   RFC5307
 *
 *
 * IP Reachability sub-TLVs we (should) support.
 * ____________________________________________________________________________
 * Name                           Value   Status
 * ____________________________________________________________________________
 * 32bit administrative tag           1   RFC5130
 * 64bit administrative tag           2   RFC5130
 * Management prefix color          117   RFC5120
 *  Router Capability sub-TLVs we support
 * ____________________________________________________________________________
 * Name                           Value   Status
 * ____________________________________________________________________________
 * TRILL Nickname                    6    RFC 6326
 * TRILL Distribution Tree           7    RFC 6326
 * TRILL Distribution Tree Roots     8    RFC 6326
 * TRILL Distribution Tree Roots IDs 9    RFC 6326
 * TRILL INT VLANS                   10   RFC 6326
 * TRILL VERSION                     13   RFC 6326
 * TRILL VLAN Groups                 14   RFC 6326
 *
 *
 * Port Capability sub-TLVs we support
 * ____________________________________________________________________________
 * Name                           Value   Status
 * ____________________________________________________________________________
 * TRILL Special VLANs and Flags     1    RFC 6326
 * TRILL Enabled VLANs               2    RFC 6326
 * TRILL Appointed Forwarders        3
 *
 *
 * Reachability sub-TLVs we support
 * ____________________________________________________________________________
 * Name                           Value   Status
 * ____________________________________________________________________________
 * TRILL MTU                        28    RFC 6326
 */

#define AREA_ADDRESSES            1
#define IS_NEIGHBOURS             2
#define ES_NEIGHBOURS             3
#define LAN_NEIGHBOURS            6
#define PADDING                   8
#define LSP_ENTRIES               9
#define AUTH_INFO                 10
#define CHECKSUM                  12
#define TE_IS_NEIGHBOURS          22
#define IS_ALIAS                  24
#define IPV4_INT_REACHABILITY     128
#define PROTOCOLS_SUPPORTED       129
#define IPV4_EXT_REACHABILITY     130
#define IDRP_INFO                 131
#define IPV4_ADDR                 132
#define TE_ROUTER_ID              134
#define TE_IPV4_REACHABILITY      135
#define DYNAMIC_HOSTNAME          137
#define GRACEFUL_RESTART          211
#define IPV6_ADDR                 232
#define IPV6_REACHABILITY         236
#define WAY3_HELLO                240
#ifdef HAVE_TRILL
#define ROUTER_CAPABILITY         242
#define PORT_CAPABILITY           243   /* TBD TRILL port capability TLV */

/* PORT_CAPABILITY sub-TLVs for TRILL */

/**     RFC6326  2.2.1  Special VLANs and Flags
   +-+-+-+-+-+-+-+-+
   |     Type      |                  (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                  (1 byte)
   +---------------+---------------+
   |    Port ID                    |  (2 bytes)
   +-------------------------------+
   |     Sender Nickname           |  (2 bytes)
   +--+--+--+--+-------------------+
   |AF|AC|VM|BY|    Outer.VLAN     |  (2 bytes)
   +--+--+--+--+-------------------+
   |TR|R |R |R |    Desig.VLAN     |  (2 bytes)
   +--+--+--+--+-------------------+
*/
#define PCSTLV_VLANS              1

/**     RFC6326  2.2.2  Enabled VLANs
   +-+-+-+-+-+-+-+-+
   |     Type      |                  (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                  (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | RESV  |  Start VLAN ID        |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | VLAN bit-map....
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define PCSTLV_ENABLEDVLANS       2
/**     RFC6326  2.2.3   Appointed Forwarders
   +-+-+-+-+-+-+-+-+
   |     Type      |                          (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                          (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Appointment Information (1)         |  (6 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   .................                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Appointment Information (N)         |  (6 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   where each appointment is of the form:

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Appointee Nickname              |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | RESV  |        Start.VLAN             |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | RESV  |        End.VLAN               |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define PCSTLV_APPFORWARDERS      3


/* ROUTER_CAPABILITY sub-TLVs for TRILL */

 #define        RCSTLV_TRILL_FLAGS        21    /* TBD Flags */

/**     RFC6326  2.3.2  TBD Nickname

   +-+-+-+-+-+-+-+-+
   |Type = NICKNAME|                         (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                         (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                NICKNAME RECORDS (1)                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   .................                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                NICKNAME RECORDS (N)                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   where each nickname record is of the form:

   +-+-+-+-+-+-+-+-+
   | Nickname.Pri  |                  (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Tree Root Priority        |  (2 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Nickname            |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define RCSTLV_TRILL_NICKNAME     6

/**     RFC6326  2.3.3  TBD Distribution Tree to compute/able to compute / to use
   +-+-+-+-+-+-+-+-+
   |Type =  TREES  |                  (1 byte)
   +-+-+-+-+-+-+-+-+
   |  Length       |                  (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Number of trees to compute    |  (2 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Maximum trees able to compute |  (2 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Number of trees to use        |  (2 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define RCSTLV_TRILL_TREE         7
/**     RFC6326  2.3.4  TBD Distribution Tree Roots ID
   +-+-+-+-+-+-+-+-+
   |Type=TREE-RT-IDs|               (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Starting Tree Number         |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Nickname (K-th root)      |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Nickname (K+1 - th root)  |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Nickname (...)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define RCSTLV_TRILL_TREE_ROOTS   8
/**     RFC6326  2.3.5
   +-+-+-+-+-+-+-+-+
   |Type=TREE-RT-IDs|               (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Starting Tree Number         |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Nickname (K-th root)      |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Nickname (K+1 - th root)  |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Nickname (...)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define RCSTLV_TRILL_TREE_ROOTS_ID      9

/**     RFC6326  2.3.6
   +-+-+-+-+-+-+-+-+
   |Type = INT-VLAN|                  (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                  (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Nickname                    |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...+-+-+-+-+
   |   Interested VLANS                                  |  (4 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...+-+-+-+-+
   |   Appointed Forwarder Status Lost Counter           |  (4 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...+-+-+
   |         Root Bridges                                |  (6*n bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...+-+-+

   Interested VLANS:
        0    1    2    3     4 - 15      16 - 19     20 - 31
      +----+----+----+----+------------+----------+------------+
      | M4 | M6 |  R |  R | VLAN.start |   RESV   |  VLAN.end  |
      +----+----+----+----+------------+----------+------------+

*/
#define RCSTLV_TRILL_INT_VLAN   10
/**     RFC6326  2.3.1
   +-+-+-+-+-+-+-+-+
   | Type          |                  (1 byte)
   +-+-+-+-+-+-+-+-+
   | Length        |                  (1 byte)
   +-+-+-+-+-+-+-+-+
   | Max-version   |                  (1 byte)
   +-+-+-+-+-+-+-+-+
*/
#define RCSTLV_TRILL_VERSION    13
/**     RFC6326  2.3.7
   +-+-+-+-+-+-+-+-+
   |Type=VLAN-GROUP|                  (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                  (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | RESV  |  Primary VLAN ID      |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | RESV  |  Secondary VLAN ID    |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  more Secondary VLAN IDs ...     (2 bytes each)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   if working with vlan_tag (double vlan) structure will change to this one
   +-+-+-+-+-+-+-+-+
   |Type=VLAN-GROUP|                  (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                  (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | RESV  |  Primary VLAN ID      |  (4 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | RESV  |  Secondary VLAN ID    |  (4 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  more Secondary VLAN IDs ...     (4 bytes each)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define RCSTLV_TRILL_VLAN_GROUP 14
/* Reachability sub-TLVs for TRILL */
/** RFC6326  2.3.7   2.4
   +-+-+-+-+-+-+-+-+
   | Type = MTU    |                  (1 byte)
   +-+-+-+-+-+-+-+-+
   |   Length      |                  (1 byte)
   +-+-+-+-+-+-+-+-+
   |F|  Reserved   |                  (1 byte)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               MTU             |  (2 bytes)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define RSTLV_TRILL_MTU         28
#endif
#define AUTH_INFO_HDRLEN          3

#define IS_NEIGHBOURS_LEN (ISIS_SYS_ID_LEN + 5)
#define LAN_NEIGHBOURS_LEN 6
#define LSP_ENTRIES_LEN (10 + ISIS_SYS_ID_LEN)	/* FIXME: should be entry */
#define IPV4_REACH_LEN 12
#define IPV6_REACH_LEN 22
#define TE_IPV4_REACH_LEN 9

#ifdef HAVE_TRILL
#define TLFLDS_LEN 2                             /* Length of Type & Len 8-bit fields */
#define ROUTER_CAPABILITY_MIN_LEN  5             /* Min len of router capability TLV */
#define ROUTER_CAPABILITY_MAX_LEN  250           /* Max len of router capability TLV */

/* TRILL Flags sub-TLV */
#define TRILL_FLAGS_SUBTLV_MIN_LEN 1             /* Len of sub-TLV val */
#define TRILL_FLAGS_V0  0x80
#define TRILL_FLAGS_V1  0x40
#define TRILL_FLAGS_V2  0x20
#define TRILL_FLAGS_V3  0x10

#define TRILL_NICKNAME_SUBTLV_MIN_LEN 5          /* Len of TRILL nickname sub-TLV value field */
#define TRILL_VLANSNBRIROOTS_SUBTLV_MIN_LEN 4    /* Len of variable len TRILL VLANs and Bridge Roots sub-TLV value field */
#define PCSTLV_VLANS_LEN         4               /* Exact len of port capability VLANs sub-TLV */
#define PCSTLV_VLANFWDERS_MIN_LEN 6              /* Min. len of each appointed forwarders sub-TLV */
#define PCSTLV_ENABLEDVLANS_MIN_LEN 3            /* Min. len of enabled VLANS sub-TLV */
#endif

/* struct for neighbor */
struct is_neigh
{
  struct metric metrics;
  u_char neigh_id[ISIS_SYS_ID_LEN + 1];
};

/* struct for te is neighbor */
struct te_is_neigh
{
  u_char neigh_id[ISIS_SYS_ID_LEN + 1];
  u_char te_metric[3];
  u_char sub_tlvs_length;
};

/* Decode and encode three-octet metric into host byte order integer */
#define GET_TE_METRIC(t) \
  (((unsigned)(t)->te_metric[0]<<16) | ((t)->te_metric[1]<<8) | \
   (t)->te_metric[2])
#define SET_TE_METRIC(t, m) \
  (((t)->te_metric[0] = (m) >> 16), \
   ((t)->te_metric[1] = (m) >> 8), \
   ((t)->te_metric[2] = (m)))

/* struct for es neighbors */
struct es_neigh
{
  struct metric metrics;
  /* approximate position of first, we use the
   * length ((uchar*)metric-1) to know all     */
  u_char first_es_neigh[ISIS_SYS_ID_LEN];

};

struct partition_desig_level2_is
{
  struct list *isis_system_ids;
};

/* struct for lan neighbors */
struct lan_neigh
{
  u_char LAN_addr[6];
};

#ifdef __SUNPRO_C
#pragma pack(1)
#endif

/* struct for LSP entry */
struct lsp_entry
{
  u_int16_t rem_lifetime;
  u_char lsp_id[ISIS_SYS_ID_LEN + 2];
  u_int32_t seq_num;
  u_int16_t checksum;
} __attribute__ ((packed));

#ifdef __SUNPRO_C
#pragma pack()
#endif

/* struct for checksum */
struct checksum
{
  u_int16_t checksum;
};

/* ipv4 reachability */
struct ipv4_reachability
{
  struct metric metrics;
  struct in_addr prefix;
  struct in_addr mask;
};

/* te router id */
struct te_router_id
{
  struct in_addr id;
};

/* te ipv4 reachability */
struct te_ipv4_reachability
{
  u_int32_t te_metric;
  u_char control;
  u_char prefix_start;		/* since this is variable length by nature it only */
};				/* points to an approximate location */



struct idrp_info
{
  u_char len;
  u_char *value;
};

#ifdef HAVE_IPV6
struct ipv6_reachability
{
  u_int32_t metric;
  u_char control_info;
  u_char prefix_len;
  u_char prefix[16];
};

/* bits in control_info */
#define CTRL_INFO_DIRECTION    0x80
#define DIRECTION_UP           0
#define DIRECTION_DOWN         1
#define CTRL_INFO_DISTRIBUTION 0x40
#define DISTRIBUTION_INTERNAL  0
#define DISTRIBUTION_EXTERNAL  1
#define CTRL_INFO_SUBTLVS      0x20
#endif /* HAVE_IPV6 */

#ifdef HAVE_TRILL
/* Router Capability TLV: used in LSPs */
struct router_capability_tlv
{
  u_char router_id[4];             /* 4 octet Router ID */
  uint8_t flags;                  /* 1 octet flags */
};

/* internal router capability struct, includes tlv length */
struct router_capability
{
  uint8_t len;                 /* total length of the TLV */
  struct router_capability_tlv rt_cap_tlv;
};

/* Port Capability TLV: used in Hellos */
struct port_capability_tlv
{
  uint8_t len;
  uint8_t value[1];
};

#ifdef __SUNPRO_C
#pragma pack(1)
#endif

/* LSP: ROUTER_CAPABILITY RCSTLV_TRILL_NICKNAME */
struct trill_nickname_subtlv
{
    uint8_t tn_priority;
    uint16_t tn_trootpri;
    uint16_t tn_nickname;
} __attribute__ ((packed));

#ifdef __SUNPRO_C
#pragma pack()
#endif
#endif /* HAVE_TRILL */

#define MAX_VNI_PER_SUBTLV  60
/* LSP: ROUTER_CAPABILITY RCSTLV_TRILL_VLAN_GROUP */
struct trill_vni_subtlv
{
  u_int8_t length;
  /*dynamic allocation of vni list*/
};
/*
 * Pointer to each tlv type, filled by parse_tlvs()
 */
struct tlvs
{
  struct checksum *checksum;
  struct hostname *hostname;
  struct nlpids *nlpids;
  struct te_router_id *router_id;
  struct list *area_addrs;
  struct list *is_neighs;
  struct list *te_is_neighs;
  struct list *es_neighs;
  struct list *lsp_entries;
  struct list *prefix_neighs;
  struct list *lan_neighs;
  struct list *ipv4_addrs;
  struct list *ipv4_int_reachs;
  struct list *ipv4_ext_reachs;
  struct list *te_ipv4_reachs;
#ifdef HAVE_IPV6
  struct list *ipv6_addrs;
  struct list *ipv6_reachs;
#endif
  struct isis_passwd auth_info;
#ifdef HAVE_TRILL
  struct list *router_capabilities;
  struct list *port_capabilities;
#endif
};

/*
 * Own definitions - used to bitmask found and expected
 */

#define TLVFLAG_AREA_ADDRS                (1<<0)
#define TLVFLAG_IS_NEIGHS                 (1<<1)
#define TLVFLAG_ES_NEIGHS                 (1<<2)
#define TLVFLAG_PARTITION_DESIG_LEVEL2_IS (1<<3)
#define TLVFLAG_PREFIX_NEIGHS             (1<<4)
#define TLVFLAG_LAN_NEIGHS                (1<<5)
#define TLVFLAG_LSP_ENTRIES               (1<<6)
#define TLVFLAG_PADDING                   (1<<7)
#define TLVFLAG_AUTH_INFO                 (1<<8)
#define TLVFLAG_IPV4_INT_REACHABILITY     (1<<9)
#define TLVFLAG_NLPID                     (1<<10)
#define TLVFLAG_IPV4_EXT_REACHABILITY     (1<<11)
#define TLVFLAG_IPV4_ADDR                 (1<<12)
#define TLVFLAG_DYN_HOSTNAME              (1<<13)
#define TLVFLAG_IPV6_ADDR                 (1<<14)
#define TLVFLAG_IPV6_REACHABILITY         (1<<15)
#define TLVFLAG_TE_IS_NEIGHS              (1<<16)
#define TLVFLAG_TE_IPV4_REACHABILITY      (1<<17)
#define TLVFLAG_3WAY_HELLO                (1<<18)
#define TLVFLAG_TE_ROUTER_ID              (1<<19)
#define TLVFLAG_CHECKSUM                  (1<<20)
#define TLVFLAG_GRACEFUL_RESTART          (1<<21)
#ifdef HAVE_TRILL
#define TLVFLAG_ROUTER_CAPABILITY         (1<<22)
#define TLVFLAG_PORT_CAPABILITY           (1<<23)
#endif

void init_tlvs (struct tlvs *tlvs, uint32_t expected);
void free_tlvs (struct tlvs *tlvs);
int parse_tlvs (char *areatag, u_char * stream, int size,
		u_int32_t * expected, u_int32_t * found, struct tlvs *tlvs,
                u_int32_t * auth_tlv_offset);
int add_tlv (u_char, u_char, u_char *, struct stream *);
void free_tlv (void *val);

int tlv_add_area_addrs (struct list *area_addrs, struct stream *stream);
int tlv_add_is_neighs (struct list *is_neighs, struct stream *stream);
int tlv_add_te_is_neighs (struct list *te_is_neighs, struct stream *stream);
int tlv_add_lan_neighs (struct list *lan_neighs, struct stream *stream);
int tlv_add_nlpid (struct nlpids *nlpids, struct stream *stream);
int tlv_add_checksum (struct checksum *checksum, struct stream *stream);
int tlv_add_authinfo (u_char auth_type, u_char authlen, u_char *auth_value,
		      struct stream *stream);
int tlv_add_ip_addrs (struct list *ip_addrs, struct stream *stream);
int tlv_add_in_addr (struct in_addr *, struct stream *stream, u_char tag);
int tlv_add_dynamic_hostname (struct hostname *hostname,
			      struct stream *stream);
int tlv_add_lsp_entries (struct list *lsps, struct stream *stream);
int tlv_add_ipv4_reachs (struct list *ipv4_reachs, struct stream *stream);
int tlv_add_te_ipv4_reachs (struct list *te_ipv4_reachs, struct stream *stream);
#ifdef HAVE_IPV6
int tlv_add_ipv6_addrs (struct list *ipv6_addrs, struct stream *stream);
int tlv_add_ipv6_reachs (struct list *ipv6_reachs, struct stream *stream);
#endif /* HAVE_IPV6 */

int tlv_add_padding (struct stream *stream);

#endif /* _ZEBRA_ISIS_TLV_H */
