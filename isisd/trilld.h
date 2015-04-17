/*
 * IS-IS Rout(e)ing protocol - trill.h
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * modified by gandi.net
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#ifndef _ZEBRA_ISIS_TRILL_H
#define _ZEBRA_ISIS_TRILL_H

/* Nickname range */
#define RBRIDGE_NICKNAME_MIN		0x0000
#define RBRIDGE_NICKNAME_MAX		0xFFFF
/* Define well-known nicknames */
#define RBRIDGE_NICKNAME_NONE		RBRIDGE_NICKNAME_MIN
#define RBRIDGE_NICKNAME_MINRES		0xFFC0
#define RBRIDGE_NICKNAME_MAXRES		(RBRIDGE_NICKNAME_MAX - 1)
#define RBRIDGE_NICKNAME_UNUSED		RBRIDGE_NICKNAME_MAX

#define MIN_RBRIDGE_RANDOM_NICKNAME	(RBRIDGE_NICKNAME_NONE + 1)
#define MAX_RBRIDGE_RANDOM_NICKNAME	(RBRIDGE_NICKNAME_MINRES - 1)

/* IETF TRILL protocol defined constants */
#define DFLT_NICK_PRIORITY 0x40		/* Default priority for autogen nicks */
#define DFLT_NICK_ROOT_PRIORITY 0x40	/* Default priority for autogen nicks */
#define CONFIGURED_NICK_PRIORITY 0x80	/* MSB of priority set if nick is configured */
#define CONFIGURED_NICK_ROOT_PRIORITY 0x80/* MSB of priority set if nick is configured */
#define MIN_RBRIDGE_PRIORITY 1		/* Min priority of use value */
#define MAX_RBRIDGE_PRIORITY 127	/* Max priority of use value */
#define MIN_RBRIDGE_ROOT_PRIORITY 1	/* Min root priority of use value */
#define MAX_RBRIDGE_ROOT_PRIORITY 65534	/* Max root priority of use value*/
#define MAX_RBRIDGE_NODES (RBRIDGE_NICKNAME_MAX + 1) /* Max RBridges possible */
#define TRILL_NICKNAME_LEN   2		/* 16-bit nickname */
#define TRILL_DFLT_ROOT_PRIORITY 0x40	/* Default tree root priority */

/* trill_info status flags */
#define TRILL_AUTONICK       (1 << 0)  /* nickname auto-generated (else user-provided) */
#define TRILL_LSPDB_ACQUIRED (1 << 1)  /* LSP DB acquired before autogen nick is advertised */
#define TRILL_NICK_SET       (1 << 2)  /* nickname configured (random/user generated) */
#define TRILL_PRIORITY_SET   (1 << 3)  /* nickname priority configured by user */
#define TRILL_SPF_COMPUTED   (1 << 4)
#define TRILL_VNI_SUBTLV_MIN_LEN 4
#undef NEW_KERNEL_RELEASE
typedef u_char ether_addr_t[6];
/* trill nickname structure */
struct trill_nickname
{
  uint16_t name;
  uint8_t priority;
  uint8_t pad;
};

/* trill structure */
struct trill
{
  struct trill_nickname nick;	/* our nick */
  uint8_t status;		/* status flags */
  dict_t *nickdb;		/* TRILL nickname database */
  dict_t *sysidtonickdb;	/* TRILL sysid-to-nickname database */
  struct list *fwdtbl;		/* RBridge forwarding table */
  struct list *adjnodes;	/* Adjacent nicks for our distrib tree */
  struct list *dt_roots;	/* Our choice of DT roots */
  char * name;			/* bridge name */
  uint16_t root_priority;	/* Root tree priority */
  uint16_t  tree_root;
  struct list *configured_vni;	/* Configured VNI locally */
  struct list *supported_vni;	/* supported VNI*/
  uint16_t root_count;
};

/* TRILL nickname information (node-specific) */
typedef struct nickinfo
{
  struct trill_nickname nick;	/* Nick of the node  */
  u_char sysid[ISIS_SYS_ID_LEN];/* NET/sysid of node */
  uint8_t flags;		/* TRILL flags advertised by node */
  struct list *dt_roots;	/* Distrib. Trees chosen by node */
  uint16_t root_priority;	/* Root tree priority */
  uint16_t root_count;		/* Root tree count */
  uint8_t vni_count;
  struct list *supported_vni;	/* supported VNI*/
} nickinfo_t;

/* Nickname database node */
typedef struct trill_nickdb_node
{
  nickinfo_t info;	/* Nick info of the node */
  /* RBridge distribution tree with this nick as root */
  struct isis_spftree *rdtree;
  /* Our (host RBridge) adjacent nicks on this distrib tree */
  struct list *adjnodes;
  uint32_t refcnt;
} nicknode_t;

typedef struct nickfwdtable_node
{
  u_int16_t dest_nick;               /* destination RBridge nick */
  u_char adj_snpa[ETH_ALEN];         /* MAC address of the adj node */
  struct interface *interface;       /* if to reach the adj/neigh */
} nickfwdtblnode_t;
/* Constants used in nickname generation/allocation */
#define NICKNAMES_BITARRAY_SIZE (MAX_RBRIDGE_NODES / 8) /* nick usage array */
#define CLEAR_BITARRAY_ENTRYLEN 4         /* stores nicks available per 32 nicks in nick bitarray */
#define CLEAR_BITARRAY_ENTRYLENBITS (4*8)  /* 32 nicks tracked in each entry */
#define CLEAR_BITARRAY_SIZE (MAX_RBRIDGE_NODES / CLEAR_BITARRAY_ENTRYLENBITS)
static u_char clear_bit_count[CLEAR_BITARRAY_SIZE];
/* nickname routines */
static u_char nickbitvector[NICKNAMES_BITARRAY_SIZE];
#define NICK_IS_USED(n)		(nickbitvector[(n)/8] & (1<<((n)%8)))
#define NICK_SET_USED(n)	(nickbitvector[(n)/8] |= (1<<((n)%8)))
#define NICK_CLR_USED(n)	(nickbitvector[(n)/8] &= ~(1<<((n)%8)))
#define MIN_ROOT_COUNT	1

#define AF_TRILL        31
typedef enum
{
  NOTFOUND = 1,
  FOUND,
  DUPLICATE,
  NICK_CHANGED,
  PRIORITY_CHANGE_ONLY
} nickdb_search_result;

typedef struct trill_nickinfo_s {
  /* Nickname of the RBridge */
  uint16_t	tni_nick;
  /* Next-hop SNPA address to reach this RBridge */
  ether_addr_t	tni_adjsnpa;
  /* Link on our system to use to reach next-hop */
  uint32_t	tni_linkid;
  /* Num of *our* adjacencies on a tree rooted at this RBridge */
  uint16_t	tni_adjcount;
  /* Num of distribution tree root nicks chosen by this RBridge */
  uint16_t	tni_dtrootcount;
  /* Num of vni supported by this RBridge  */
#ifdef NEW_KERNEL_RELEASE
  uint16_t	tni_vnicount;
#endif
  /* Num of vlan supported by this RBridge  */
  /* Variable size bytes to store adjacency nicks, distribution
   * tree roots. Adjacency nicks and distribution tree roots are
   * 16-bit fields.
   */
} trill_nickinfo_t;

/* Access the adjacency nick list at the end of trill_nickinfo_t */
#define	TNI_ADJNICKSPTR(v) ((uint16_t *)((trill_nickinfo_t *)(v)+1))
#define	TNI_ADJNICK(v, n) (TNI_ADJNICKSPTR(v)[(n)])

/* Access the DT root nick list in trill_nickinfo_t after adjacency nicks */
#define	TNI_DTROOTNICKSPTR(v) ((uint16_t *)(TNI_ADJNICKSPTR(v)+(v)->tni_adjcount))
#define	TNI_DTROOTNICK(v, n)  (TNI_DTROOTNICKSPTR(v)[(n)])

/*
 * Acess vni list in trill_nickinfo_t after DT Roots
 * we cast TNI_VNIPTR to uint32_t pointer
 * to get correct value in TNI_VNI  (vni are 32bit size))
 */
#define	TNI_VNIPTR(v)	((uint32_t*)((uint16_t *)\
			(TNI_DTROOTNICKSPTR(v)+(v)->tni_dtrootcount)))
#define TNI_VNI(v,n)	((TNI_VNIPTR(v))[(n)])

#ifdef NEW_KERNEL_RELEASE
#define TNI_TOTALSIZE(v) (sizeof (trill_nickinfo_t) + \
	(sizeof (uint16_t) * (v)->tni_adjcount) + \
	(sizeof (uint16_t) * (v)->tni_dtrootcount) + \
	(sizeof (uint32_t) * (v)->tni_vnicount))
#else
#define TNI_TOTALSIZE(v) (sizeof (trill_nickinfo_t) + \
(sizeof (uint16_t) * (v)->tni_adjcount) + \
(sizeof (uint16_t) * (v)->tni_dtrootcount)
#endif
/* trilld.c */
void trill_area_init(struct isis_area *area);
void trill_area_free(struct isis_area *area);
nicknode_t * trill_nicknode_lookup(struct isis_area *area,
				   uint16_t nick);
int tlv_add_trill_nickname (struct trill_nickname *nick_info,
			    struct stream *stream, struct isis_area *area);
void trill_process_spf (struct isis_area *area);
void trill_parse_router_capability_tlvs (struct isis_area *,
					 struct isis_lsp *);

int trill_area_nickname(struct isis_area *area, u_int16_t nickname);
void trill_init();
uint16_t get_root_nick(struct isis_area *area);
void trill_nick_destroy(struct isis_lsp *lsp);
/* trill_vni.c */
extern int generate_supported_vni(struct isis_area *area);

#endif
