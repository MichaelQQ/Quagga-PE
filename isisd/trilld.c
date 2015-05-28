/*
 * IS-IS Rout(e)ing protocol - trilld.h
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
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#include <zebra.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"
#include "memory.h"
#include "hash.h"
#include "vty.h"
#include "linklist.h"
#include "thread.h"
#include "if.h"
#include "stream.h"
#include "command.h"
#include "privs.h"


#include "isisd/dict.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/trilld.h"
#include "isisd/isisd.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_adjacency.h"
#include "isisd/netlink.h"

/* Global variables needed for netlink genl socket*/
extern struct zebra_privs_t isisd_privs;
static struct nl_sock *sock_genl;
int genl_family;
int group_number;

static void trill_dict_delete_nodes (dict_t *dict1, dict_t *dict2,
				     void *key1, int key2isnick);
static nickdb_search_result trill_search_rbridge ( struct isis_area *area,
						   nickinfo_t *ni,
						   dnode_t **fndnode);
static int trill_nick_conflict(nickinfo_t *nick1, nickinfo_t *nick2);
int nickavailcnt = RBRIDGE_NICKNAME_MINRES - RBRIDGE_NICKNAME_NONE - 1;

void nickname_init()
{
  u_int i;
  memset(nickbitvector, 0, sizeof(nickbitvector));
  for (i = 0; i < sizeof (clear_bit_count); i++)
    clear_bit_count[i] = CLEAR_BITARRAY_ENTRYLENBITS;
  /* These two are always reserved */
  NICK_SET_USED(RBRIDGE_NICKNAME_NONE);
  NICK_SET_USED(RBRIDGE_NICKNAME_UNUSED);
  clear_bit_count[RBRIDGE_NICKNAME_NONE / CLEAR_BITARRAY_ENTRYLENBITS]--;
  clear_bit_count[RBRIDGE_NICKNAME_UNUSED / CLEAR_BITARRAY_ENTRYLENBITS]--;
}

int receiv_nl(struct thread *thread)
{
  struct isis_area *area;
  area = THREAD_ARG (thread);
  assert (area);
  nl_recvmsgs_default(sock_genl);
  area->nl_tick = NULL;
  THREAD_READ_ON(master, area->nl_tick, receiv_nl, area,
                    nl_socket_get_fd(sock_genl));
  return ISIS_OK;
}
void netlink_init(struct isis_area *area)
{
  isisd_privs.change(ZPRIVS_RAISE);
  sock_genl = nl_socket_alloc();
  genl_connect(sock_genl);
  genl_family = genl_ctrl_resolve(sock_genl, TRILL_NL_FAMILY);
  group_number = genl_ctrl_resolve_grp(sock_genl, TRILL_NL_FAMILY,
				       TRILL_MCAST_NAME);
  nl_socket_disable_seq_check(sock_genl);
  if(!genl_family){
    zlog_err("unable to find generic netlink family id");
    abort();
  }

  if(nl_socket_modify_cb(sock_genl, NL_CB_MSG_IN, NL_CB_CUSTOM,
    parse_cb, (void *)area))
    zlog_warn("unable to modify netlink callback");
  if(nl_socket_add_membership(sock_genl, group_number))
    zlog_warn("unable to join multicast group\n");
  THREAD_READ_ON(master, area->nl_tick, receiv_nl, area,
			nl_socket_get_fd(sock_genl));
}
static int trill_nickname_nickbitmap_op(u_int16_t nick, int update, int val)
{
  if (nick == RBRIDGE_NICKNAME_NONE || nick == RBRIDGE_NICKNAME_UNUSED)
    return false;
  if (val) {
    if (NICK_IS_USED(nick))
      return true;
    if (!update)
      return false;
    NICK_SET_USED(nick);
    if (nick < RBRIDGE_NICKNAME_MINRES)
      nickavailcnt--;
    clear_bit_count[nick / CLEAR_BITARRAY_ENTRYLENBITS]--;
  } else {
    if (!NICK_IS_USED(nick))
      return true;
    if (!update)
      return false;
    NICK_CLR_USED(nick);
    if (nick < RBRIDGE_NICKNAME_MINRES)
      nickavailcnt++;
    clear_bit_count[nick / CLEAR_BITARRAY_ENTRYLENBITS]++;
  }
  return false;
}
int is_nickname_used(uint16_t nick_nbo)
{
  return trill_nickname_nickbitmap_op(ntohs(nick_nbo), false, true);
}
static void trill_nickname_reserve(uint16_t nick_nbo)
{
  trill_nickname_nickbitmap_op(ntohs(nick_nbo), true, true);
}

static void trill_nickname_free(uint16_t nick_nbo)
{
  trill_nickname_nickbitmap_op(ntohs(nick_nbo), true, false);
}
static uint16_t trill_nickname_alloc(void)
{
  uint i, j, k;
  uint16_t nick;
  uint16_t nicknum;
  uint16_t freenickcnt = 0;
  if (nickavailcnt < 1)
    return RBRIDGE_NICKNAME_NONE;
  /*
   * Note that rand() usually returns 15 bits, so we overlap two values to make
   * sure we're getting at least 16 bits (as long as rand() returns 8 bits or
   * more).  Using random() instead would be better, but isis_main.c uses
   * srand.
   */
  nicknum = ((rand() << 8) | rand()) % nickavailcnt;
  for ( i = 0; i < sizeof (clear_bit_count); i++ ) {
    freenickcnt += clear_bit_count[i];
    if (freenickcnt <= nicknum)
      continue;
    nicknum -= freenickcnt - clear_bit_count[i];
    nick = i * CLEAR_BITARRAY_ENTRYLEN * 8;
    for ( j = 0; j < CLEAR_BITARRAY_ENTRYLEN; j++) {
      for (k = 0; k < 8; k++, nick++) {
	if (!NICK_IS_USED(nick) && nicknum-- == 0) {
	  trill_nickname_nickbitmap_op (nick, true, true);
	  return nick;
	}
      }
    }
    break;
  }
  return 0;
}

static void gen_nickname(struct isis_area *area)
{
  uint16_t nick;
  nick = trill_nickname_alloc();
  if (nick == RBRIDGE_NICKNAME_NONE) {
    zlog_err("RBridge nickname allocation failed.  No nicknames available.");
    abort();
  } else {
    area->trill->nick.name = htons(nick);
    if (isis->debugs & DEBUG_TRILL_EVENTS)
      zlog_debug("ISIS TRILL generated nick:%u", nick);
  }
}

/*
 * Called from isisd to handle trill nickname command.
 * Nickname is user configured and in host byte order
 */
int trill_area_nickname(struct isis_area *area, u_int16_t nickname)
{
  uint16_t savednick;

  if (nickname == RBRIDGE_NICKNAME_NONE) {
    /* Called from "no trill nickname" command */
    gen_nickname (area);
    SET_FLAG (area->trill->status, TRILL_NICK_SET);
    SET_FLAG (area->trill->status, TRILL_AUTONICK);
    return true;
  }
  isisd_privs.change(ZPRIVS_RAISE);
  nickname = htons(nickname);
  savednick = area->trill->nick.name;

  /*
   * Check if we know of another RBridge already using this nickname.
   * If yes check if it conflicts with the nickname in the database.
   */
  if (is_nickname_used(nickname)) {
    nickinfo_t ni;
    dnode_t *dnode;
    nicknode_t *tnode;
    ni.nick = area->trill->nick;
    memcpy(ni.sysid, isis->sysid, ISIS_SYS_ID_LEN);
    if (trill_search_rbridge (area, &ni, &dnode) == FOUND) {
      assert (dnode);
      tnode = dnode_get (dnode);
      if (trill_nick_conflict (&(tnode->info), &ni)) {
	trill_dict_delete_nodes (area->trill->nickdb,
				 area->trill->sysidtonickdb,
				 &nickname, false);
      } else {
	/*
	 * The other nick in our nickdb has greater priority so return
	 * fail, restore nick and let user configure another nick.
	 */
	if (savednick == RBRIDGE_NICKNAME_NONE)
	{
	  gen_nickname (area);
	  SET_FLAG (area->trill->status, TRILL_NICK_SET);
	  SET_FLAG (area->trill->status, TRILL_AUTONICK);
	  area->trill->nick.priority &= ~CONFIGURED_NICK_PRIORITY;
	}
	return false;
      }
    }
  }
  trill_nickname_reserve(nickname);
  area->trill->nick.name = nickname;
  area->trill->nick.priority |= CONFIGURED_NICK_PRIORITY;
  SET_FLAG(area->trill->status, TRILL_NICK_SET);
  UNSET_FLAG(area->trill->status, TRILL_AUTONICK);
  if (listcount(area->circuit_list) > 0) {
    struct nl_msg *msg;
    struct trill_nl_header *trnlhdr;
    struct isis_circuit *circuit = listgetdata(listhead(area->circuit_list));
    msg = nlmsg_alloc();
    trnlhdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family,
			sizeof(struct trill_nl_header), NLM_F_REQUEST,
			TRILL_CMD_SET_BRIDGE, TRILL_NL_VERSION);
    if(!trnlhdr)
      abort();
    nla_put_u16(msg, TRILL_ATTR_U16, htons(nickname));
    trnlhdr->ifindex = circuit->interface->ifindex;
    trnlhdr->total_length = sizeof(msg);
    trnlhdr->msg_number = 1;
    nl_send_auto_complete(sock_genl, msg);
    nlmsg_free(msg);
  }
  return true;
}

static void trill_nickname_priority_update(struct isis_area *area,
					   u_int8_t priority)
{
  struct isis_circuit *circuit;
  struct listnode *cnode;
  if (priority) {
    area->trill->nick.priority = priority;
    area->trill->root_priority = priority;
    SET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
  }
  else {
    /* Called from "no trill nickname priority" command */
    area->trill->nick.priority = DFLT_NICK_PRIORITY;
    area->trill->root_priority = TRILL_DFLT_ROOT_PRIORITY;
    UNSET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
  }

  /*
   * Set the configured nickname priority bit if the
   * nickname was not automatically generated.
   */
  if (!CHECK_FLAG(area->trill->status, TRILL_AUTONICK)) {
    area->trill->nick.priority |= CONFIGURED_NICK_PRIORITY;
  }
  for (ALL_LIST_ELEMENTS_RO (area->circuit_list, cnode, circuit)) {
    circuit->priority[TRILL_ISIS_LEVEL - 1] = priority;
  }
}

static int nick_cmp(const void *key1, const void *key2)
{
  return (memcmp(key1, key2, sizeof(u_int16_t)));
}

static int sysid_cmp(const void *key1, const void *key2)
{
  return (memcmp(key1, key2, ISIS_SYS_ID_LEN));
}

void trill_area_init(struct isis_area *area)
{
  struct trill* trill;
  area->trill = XCALLOC (MTYPE_ISIS_TRILLAREA, sizeof (struct trill));
  trill = area->trill;
  trill->nick.priority = DEFAULT_PRIORITY;
  trill->nick.name = RBRIDGE_NICKNAME_NONE;

  trill->nickdb = dict_create(MAX_RBRIDGE_NODES, nick_cmp);
  trill->sysidtonickdb = dict_create(MAX_RBRIDGE_NODES, sysid_cmp);
  trill->fwdtbl = list_new();
  trill->adjnodes = list_new();
  trill->dt_roots = list_new();
  trill->root_priority = DEFAULT_PRIORITY;
  trill->tree_root = RBRIDGE_NICKNAME_NONE;
  trill->configured_vni = list_new();
  trill->supported_vni = list_new();

  /* FIXME For the moment force all TRILL area to be level 1 */
  area->is_type = IS_LEVEL_1;
  netlink_init(area);
  nickname_init();
  if (!area->trill->root_count)
	  area->trill->root_count = MIN_ROOT_COUNT;
}

void trill_area_free(struct isis_area *area)
{
  if(area->trill->nickdb) {
    dict_free(area->trill->nickdb);
    dict_destroy (area->trill->nickdb);
  }
  if(area->trill->sysidtonickdb) {
    dict_free(area->trill->sysidtonickdb);
    dict_destroy (area->trill->sysidtonickdb);
  }
  if (area->trill->fwdtbl)
    list_delete (area->trill->fwdtbl);
  if (area->trill->adjnodes)
    list_delete (area->trill->adjnodes);
  if (area->trill->dt_roots)
    list_delete (area->trill->dt_roots);
  if (area->trill->configured_vni)
    list_delete (area->trill->configured_vni);
  if (area->trill->supported_vni)
    list_delete (area->trill->supported_vni);
  XFREE (MTYPE_ISIS_TRILLAREA, area->trill);
}

static int
add_subtlv (u_char tag, u_char len, u_char * value, size_t tlvpos,
    struct stream *stream)
{
  unsigned newlen;

  /* Compute new outer TLV length */
  newlen = stream_getc_from(stream, tlvpos + 1) + (unsigned) len + TLFLDS_LEN;

  /* Check if it's possible to fit the subTLV in the stream at all */
  if (STREAM_SIZE (stream) - stream_get_endp (stream) <
      (unsigned) len + TLFLDS_LEN ||
      len > 255 - TLFLDS_LEN)
    {
      zlog_debug ("No room for subTLV %d len %d", tag, len);
      return ISIS_ERROR;
    }

  /* Check if it'll fit in the current TLV */
  if (newlen > 255)
    {
#ifdef EXTREME_DEBUG
      /* extreme debug only, because repeating TLV is usually possible */
      zlog_debug ("No room for subTLV %d len %d in TLV %d", tag, len,
                  stream_getc_from(stream, tlvpos));
#endif /* EXTREME DEBUG */
      return ISIS_WARNING;
    }

  stream_putc (stream, tag);    /* TAG */
  stream_putc (stream, len);    /* LENGTH */
  stream_put (stream, value, (int) len);        /* VALUE */
  stream_putc_at (stream,  tlvpos + 1, newlen);

 #ifdef EXTREME_DEBUG
  zlog_debug ("Added subTLV %d len %d to TLV %d", tag, len,
              stream_getc_from(stream, tlvpos));
 #endif /* EXTREME DEBUG */
  return ISIS_OK;
}
/*
 * Add TLVs necessary to advertise TRILL nickname using router capabilities TLV
 */
int tlv_add_trill_nickname_pe(struct trill_nickname *nick_info,
         struct stream *stream, struct isis_area *area)
{
  size_t tlvstart;
  struct listnode *node;
  struct router_capability_tlv rtcap;
  u_char tflags;
  struct trill_nickname_subtlv tn;
  struct trill_vni_subtlv *vni_subtlv;
  int vni_count, tlv_number, last_tlv, size, i;
  uint32_t *pnt;
  void * vni;
  int rc;

  tlvstart = stream_get_endp (stream);
  (void) memset(&rtcap, 0, sizeof (rtcap));
  rc = add_tlv(ROUTER_CAPABILITY, sizeof ( struct router_capability_tlv),
         (u_char *)&rtcap, stream);
  if (rc != ISIS_OK)
    return rc;

  tn.tn_priority = nick_info->priority;
  tn.tn_trootpri = area->trill->root_priority;
  tn.tn_nickname = nick_info->name;
  printf("nickname: %d\n", tn.tn_nickname);
  rc = add_subtlv (RCSTLV_TRILL_NICKNAME,
       sizeof (struct trill_nickname_subtlv), (u_char *)&tn,
       tlvstart,
       stream);
  if (rc != ISIS_OK)
    return rc;
  /* Let's fill vni sub tlv */
#ifdef NEW_KERNEL_RELEASE
  vni_count = listcount(area->trill->supported_vni);
  tlv_number = vni_count / MAX_VNI_PER_SUBTLV;
  last_tlv = vni_count % MAX_VNI_PER_SUBTLV;
  /* one subTLV needed */
  if (!tlv_number){
    if(vni_count){
      size = sizeof(struct trill_vni_subtlv) + vni_count * sizeof(u_int32_t);
      vni_subtlv = calloc(1, size);
      vni_subtlv->length = vni_count;
      /* go to vni list position */
      pnt = (uint32_t *) (uint8_t *)(vni_subtlv + 1);
      i = 0;
      for (ALL_LIST_ELEMENTS_RO (area->trill->supported_vni, node, vni)) {
  pnt[i] = (uint32_t) (u_long) vni;
  i++;
      }

      tlvstart = stream_get_endp (stream);
      (void) memset(&rtcap, 0, sizeof (rtcap));
      rc = add_tlv(ROUTER_CAPABILITY,
       sizeof ( struct router_capability_tlv),
       (u_char *)&rtcap, stream);
      if (rc != ISIS_OK)
  return rc;
      rc = add_subtlv (RCSTLV_TRILL_VLAN_GROUP, size,
           (u_char *)vni_subtlv,
           tlvstart, stream);
      free(vni_subtlv);
    }
  /* multiple subTLV needed */
  } else {
      size = sizeof(struct trill_vni_subtlv) +
        MAX_VNI_PER_SUBTLV * sizeof(uint32_t);
      vni_subtlv = calloc(1, size);
      vni_subtlv->length = MAX_VNI_PER_SUBTLV;
      pnt = (uint32_t *) (uint8_t *)(vni_subtlv + 1);
      for (ALL_LIST_ELEMENTS_RO (area->trill->supported_vni, node, vni)) {
  pnt[i]= (uint32_t) (u_long) vni;
  i++;
  if (i >= MAX_VNI_PER_SUBTLV) {
    i = 0;
    tlvstart = stream_get_endp (stream);
    (void) memset(&rtcap, 0, sizeof (rtcap));
    rc = add_tlv(ROUTER_CAPABILITY,
           sizeof ( struct router_capability_tlv),
           (u_char *)&rtcap, stream);
    if (rc != ISIS_OK)
      return rc;
    rc = add_subtlv (RCSTLV_TRILL_VLAN_GROUP, size,
         (u_char *)vni_subtlv, tlvstart,stream);
    free(vni_subtlv);
    tlv_number --;
    if(tlv_number)
    {
      size = sizeof(struct trill_vni_subtlv) +
      MAX_VNI_PER_SUBTLV * sizeof(uint32_t);
      vni_subtlv = calloc(1, size);
      vni_subtlv->length = MAX_VNI_PER_SUBTLV;
      pnt = (uint32_t *) (uint8_t *)(vni_subtlv + 1);
    } else {
      /* last tlv size eq max*/
      if(last_tlv) {
        size = sizeof(struct trill_vni_subtlv) +
         last_tlv * sizeof(uint32_t);
        vni_subtlv = calloc (1, size);
        vni_subtlv->length = last_tlv;
        pnt = (uint32_t *) (uint8_t *)(vni_subtlv + 1);
      }
    }
  }
      }
      /* last tlv size less than max*/
      if(last_tlv) {
  tlvstart = stream_get_endp (stream);
  (void) memset(&rtcap, 0, sizeof (rtcap));
  rc = add_tlv(ROUTER_CAPABILITY,
         sizeof ( struct router_capability_tlv),
         (u_char *)&rtcap, stream);
  if (rc != ISIS_OK)
    return rc;
  rc = add_subtlv (RCSTLV_TRILL_VLAN_GROUP, size,
       (u_char *)vni_subtlv,
       tlvstart, stream);
  free(vni_subtlv);
    }
  }
#endif
  return rc;
}

/*
 * Add TLVs necessary to advertise TRILL nickname using router capabilities TLV
 */
int tlv_add_trill_nickname(struct trill_nickname *nick_info,
			   struct stream *stream, struct isis_area *area)
{
  size_t tlvstart;
  struct listnode *node;
  struct router_capability_tlv rtcap;
  u_char tflags;
  struct trill_nickname_subtlv tn;
  struct trill_vni_subtlv *vni_subtlv;
  int vni_count, tlv_number, last_tlv, size, i;
  uint32_t *pnt;
  void * vni;
  int rc;

  tlvstart = stream_get_endp (stream);
  (void) memset(&rtcap, 0, sizeof (rtcap));
  rc = add_tlv(ROUTER_CAPABILITY, sizeof ( struct router_capability_tlv),
	       (u_char *)&rtcap, stream);
  if (rc != ISIS_OK)
    return rc;

  tn.tn_priority = nick_info->priority;
  tn.tn_trootpri = area->trill->root_priority;
  tn.tn_nickname = nick_info->name;
  printf("nickname: %d\n", tn.tn_nickname);
  rc = add_subtlv (RCSTLV_TRILL_NICKNAME,
		   sizeof (struct trill_nickname_subtlv), (u_char *)&tn,
		   tlvstart,
		   stream);
  if (rc != ISIS_OK)
    return rc;
  /* Let's fill vni sub tlv */
#ifdef NEW_KERNEL_RELEASE
  vni_count = listcount(area->trill->supported_vni);
  tlv_number = vni_count / MAX_VNI_PER_SUBTLV;
  last_tlv = vni_count % MAX_VNI_PER_SUBTLV;
  /* one subTLV needed */
  if (!tlv_number){
    if(vni_count){
      size = sizeof(struct trill_vni_subtlv) + vni_count * sizeof(u_int32_t);
      vni_subtlv = calloc(1, size);
      vni_subtlv->length = vni_count;
      /* go to vni list position */
      pnt = (uint32_t *) (uint8_t *)(vni_subtlv + 1);
      i = 0;
      for (ALL_LIST_ELEMENTS_RO (area->trill->supported_vni, node, vni)) {
	pnt[i] = (uint32_t) (u_long) vni;
	i++;
      }

      tlvstart = stream_get_endp (stream);
      (void) memset(&rtcap, 0, sizeof (rtcap));
      rc = add_tlv(ROUTER_CAPABILITY,
		   sizeof ( struct router_capability_tlv),
		   (u_char *)&rtcap, stream);
      if (rc != ISIS_OK)
	return rc;
      rc = add_subtlv (RCSTLV_TRILL_VLAN_GROUP, size,
		       (u_char *)vni_subtlv,
		       tlvstart, stream);
      free(vni_subtlv);
    }
  /* multiple subTLV needed */
  } else {
      size = sizeof(struct trill_vni_subtlv) +
	      MAX_VNI_PER_SUBTLV * sizeof(uint32_t);
      vni_subtlv = calloc(1, size);
      vni_subtlv->length = MAX_VNI_PER_SUBTLV;
      pnt = (uint32_t *) (uint8_t *)(vni_subtlv + 1);
      for (ALL_LIST_ELEMENTS_RO (area->trill->supported_vni, node, vni)) {
	pnt[i]= (uint32_t) (u_long) vni;
	i++;
	if (i >= MAX_VNI_PER_SUBTLV) {
	  i = 0;
	  tlvstart = stream_get_endp (stream);
	  (void) memset(&rtcap, 0, sizeof (rtcap));
	  rc = add_tlv(ROUTER_CAPABILITY,
		       sizeof ( struct router_capability_tlv),
		       (u_char *)&rtcap, stream);
	  if (rc != ISIS_OK)
	    return rc;
	  rc = add_subtlv (RCSTLV_TRILL_VLAN_GROUP, size,
			   (u_char *)vni_subtlv, tlvstart,stream);
	  free(vni_subtlv);
	  tlv_number --;
	  if(tlv_number)
	  {
	    size = sizeof(struct trill_vni_subtlv) +
		  MAX_VNI_PER_SUBTLV * sizeof(uint32_t);
	    vni_subtlv = calloc(1, size);
	    vni_subtlv->length = MAX_VNI_PER_SUBTLV;
	    pnt = (uint32_t *) (uint8_t *)(vni_subtlv + 1);
	  } else {
	    /* last tlv size eq max*/
	    if(last_tlv) {
	      size = sizeof(struct trill_vni_subtlv) +
		     last_tlv * sizeof(uint32_t);
	      vni_subtlv = calloc (1, size);
	      vni_subtlv->length = last_tlv;
	      pnt = (uint32_t *) (uint8_t *)(vni_subtlv + 1);
	    }
	  }
	}
      }
      /* last tlv size less than max*/
      if(last_tlv) {
	tlvstart = stream_get_endp (stream);
	(void) memset(&rtcap, 0, sizeof (rtcap));
	rc = add_tlv(ROUTER_CAPABILITY,
		     sizeof ( struct router_capability_tlv),
		     (u_char *)&rtcap, stream);
	if (rc != ISIS_OK)
	  return rc;
	rc = add_subtlv (RCSTLV_TRILL_VLAN_GROUP, size,
			 (u_char *)vni_subtlv,
			 tlvstart, stream);
	free(vni_subtlv);
    }
  }
#endif
  return rc;
}
/*
 * Returns true if a nickname was received in the parsed LSP
 */
static int trill_parse_lsp (struct isis_lsp *lsp, nickinfo_t *recvd_nick)
{
  struct listnode *node;
  struct router_capability *rtr_cap;
  uint8_t subtlvs_len;
  uint8_t subtlv;
  uint8_t subtlv_len;
  uint8_t stlvlen;
  int nick_recvd = false;
  int flags_recvd = false;
  int vni_recvd = false;
  uint8_t vni_count;
  u_char *pnt;

  isisd_privs.change(ZPRIVS_RAISE);
  memset(recvd_nick, 0, sizeof(nickinfo_t));
  if (lsp->tlv_data.router_capabilities == NULL)
    return false;

  memcpy (recvd_nick->sysid, lsp->lsp_header->lsp_id, ISIS_SYS_ID_LEN);
  recvd_nick->root_priority = TRILL_DFLT_ROOT_PRIORITY;
  recvd_nick->dt_roots = list_new();
  recvd_nick->supported_vni = list_new();
  for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.router_capabilities, node, rtr_cap))
    {
       if (rtr_cap->len < ROUTER_CAPABILITY_MIN_LEN)
         continue;

       subtlvs_len = rtr_cap->len - ROUTER_CAPABILITY_MIN_LEN;
       pnt = ((u_char *)rtr_cap) + sizeof(struct router_capability);
       while (subtlvs_len >= TLFLDS_LEN) {
	 subtlv = *(u_int8_t *)pnt++; subtlvs_len--;
	 subtlv_len = *(u_int8_t *)pnt++; subtlvs_len--;

	 if (subtlv_len > subtlvs_len) {
	   zlog_warn("ISIS trill_parse_lsp received invalid router"
	   " capability subtlvs_len:%d subtlv_len:%d",
	   subtlvs_len, subtlv_len);
	   break;
	}
	switch (subtlv) {
	  case RCSTLV_TRILL_FLAGS:
	    stlvlen = subtlv_len;
	    /* var. len with min. one octet and must be included in
	     * each link state PDU
	     */
	    if (!flags_recvd && subtlv_len >= TRILL_FLAGS_SUBTLV_MIN_LEN) {
	      recvd_nick->flags = *(u_int8_t *)pnt;
	      flags_recvd = true;
	    } else {
	      if (flags_recvd)
		zlog_warn("ISIS trill_parse_lsp multiple TRILL"
		" flags sub-TLVs received");
	      else
		zlog_warn("ISIS trill_parse_lsp invalid len:%d"
		" of TRILL flags sub-TLV", subtlv_len);
	    }
	    pnt += stlvlen;
	    subtlvs_len -= subtlv_len;
	    break;
	  case RCSTLV_TRILL_NICKNAME:
	    stlvlen = subtlv_len;
	    if (!nick_recvd && subtlv_len >= TRILL_NICKNAME_SUBTLV_MIN_LEN) {
	      struct trill_nickname_subtlv *tn;
	      tn = (struct trill_nickname_subtlv *)pnt;
	      recvd_nick->nick.priority = tn->tn_priority;
	      recvd_nick->nick.name = tn->tn_nickname;
	      recvd_nick->root_priority = ntohs(tn->tn_trootpri);
	      nick_recvd = true;
	    } else {
	      if (nick_recvd)
		zlog_warn("ISIS trill_parse_lsp multiple TRILL"
		" nick sub-TLVs received");
	      else
		zlog_warn("ISIS trill_parse_lsp invalid len:%d"
		" of TRILL nick sub-TLV", subtlv_len);
	    }
	    pnt += stlvlen;
	    subtlvs_len -= subtlv_len;
	    break;
#ifdef NEW_KERNEL_RELEASE
	  case RCSTLV_TRILL_VLAN_GROUP:
	    if (!vni_recvd && subtlv_len >= TRILL_VNI_SUBTLV_MIN_LEN) {
	      recvd_nick->vni_count = *(uint8_t*)pnt;
	      pnt = (uint32_t *) ((uint8_t *) pnt + 1);
	      for (vni_count = 0; vni_count < recvd_nick->vni_count; vni_count++) {
		listnode_add (recvd_nick->supported_vni,
			      (void *) (u_long) *(uint32_t *)pnt);
		pnt = (uint32_t *)pnt + 1;
	      }
	      vni_recvd = true;
	    } else {
	      /* mulipart subtlv */
	      if (vni_recvd) {
		if (subtlv_len >= TRILL_VNI_SUBTLV_MIN_LEN) {
		  uint8_t sub_count;
		  sub_count = *(u_int8_t*)pnt;
		  recvd_nick->vni_count += sub_count;
		  pnt = (uint32_t *) ((uint8_t *) pnt + 1);
		  for (vni_count = 0;vni_count < sub_count; vni_count++) {
		    listnode_add (recvd_nick->supported_vni,
				  (void *) (u_long) *(uint32_t *)pnt);
		    pnt = (uint32_t *)pnt+1;
		  }
		}
	      } else
		zlog_warn("ISIS trill_parse_lsp invalid len:%d"
		" of TRILL vlan sub-TLV", subtlv_len);
	    }
	    pnt += stlvlen;
	    subtlvs_len -= subtlv_len;
	    break;
#endif
	  default:
	    stlvlen = subtlv_len;
	    pnt += subtlv_len;
	    subtlvs_len -= subtlv_len;
	    break;
	}
      }
    }
    return (nick_recvd);
}
static void trill_destroy_nickfwdtable(void *obj)
{
  XFREE (MTYPE_ISIS_TRILL_FWDTBL_NODE, obj);
}
/* Lookup nickname when given a system ID */
static uint16_t sysid_to_nick(struct isis_area *area, u_char *sysid)
{
  dnode_t *dnode;
  nicknode_t *tnode;

  dnode = dict_lookup (area->trill->sysidtonickdb, sysid);
  if (dnode == NULL)
    return 0;
  tnode = (nicknode_t *) dnode_get (dnode);
  return tnode->info.nick.name;
}
static void trill_create_nickfwdtable(struct isis_area *area)
{
  struct listnode *node;
  struct isis_vertex *vertex;
  struct isis_adjacency *adj;
  struct list *fwdlist = NULL;
  struct list *oldfwdlist;
  nickfwdtblnode_t *fwdnode;
  struct isis_spftree *rdtree;
  oldfwdlist = area->trill->fwdtbl;
  int firstnode = true;
  rdtree = area->spftree[TRILL_ISIS_LEVEL - 1];
  for (ALL_LIST_ELEMENTS_RO (rdtree->paths, node, vertex)) {
    if (firstnode) {
      /* first node in path list is us */
      fwdlist = list_new();
      fwdlist->del = trill_destroy_nickfwdtable;
      firstnode = false;
      continue;
    }
    if (
      vertex->type != VTYPE_NONPSEUDO_IS &&
      vertex->type != VTYPE_NONPSEUDO_TE_IS
    )
      continue;
      if (listhead (vertex->Adj_N) &&
	(adj = listgetdata (listhead (vertex->Adj_N)))) {
	fwdnode = XCALLOC (MTYPE_ISIS_TRILL_FWDTBL_NODE,
			   sizeof(nickfwdtblnode_t));
	fwdnode->dest_nick = sysid_to_nick (area, vertex->N.id);
	memcpy(fwdnode->adj_snpa, adj->snpa, sizeof(fwdnode->adj_snpa));
	fwdnode->interface = adj->circuit->interface;
	listnode_add (fwdlist, fwdnode);
      }
  }
  area->trill->fwdtbl = fwdlist;
  if (oldfwdlist != NULL)
    list_delete (oldfwdlist);
}

static nickfwdtblnode_t * trill_fwdtbl_lookup (struct isis_area *area, u_int16_t nick)
{
  struct listnode *node;
  nickfwdtblnode_t *fwdnode;
  if (area->trill->fwdtbl == NULL){
    zlog_warn("trill_fwdtbl_lookup : fwdtbl is null");
    return NULL;
  }

  for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, node, fwdnode)){
    if (fwdnode->dest_nick == nick)
      return fwdnode;
    }
  return NULL;
}
static void trill_add_nickadjlist(struct isis_area *area, struct list *adjlist, struct isis_vertex *vertex)
{
  u_int16_t nick;

  nick = sysid_to_nick (area, vertex->N.id);
  if (!nick)
    return;
  /*
   * check if nickname is availeable in forwarding database
   * if nick is not found in fwd database that means that something went wrong
   */
  if (!trill_fwdtbl_lookup(area, nick)){
    zlog_warn("node %s found in adj list but is not present"
    " in fwd database", sysid_print(vertex->N.id));
    return;
  }
  if (listnode_lookup (adjlist, (void *)(u_long)nick) != NULL)
    return;
  listnode_add (adjlist, (void *)(u_long)nick);
}

static void trill_create_nickadjlist(struct isis_area *area,
				     nicknode_t *nicknode)
{
  struct listnode *node;
  struct listnode *cnode;
  struct isis_vertex *vertex;
  struct isis_vertex *pvertex;
  struct isis_vertex *cvertex;
  struct isis_vertex *rbvertex = NULL;
  struct list *adjlist;
  struct list *oldadjlist;
  struct list *childlist;
  struct isis_spftree *rdtree;
  if (nicknode == NULL) {
    rdtree = area->spftree[TRILL_ISIS_LEVEL - 1];
    oldadjlist = area->trill->adjnodes;
  } else {
    rdtree = nicknode->rdtree;
    oldadjlist = nicknode->adjnodes;
  }
  /* Find our node in the distribution tree first */
  for (ALL_LIST_ELEMENTS_RO (rdtree->paths, node, vertex)) {
    if (vertex->type != VTYPE_NONPSEUDO_IS &&
      vertex->type != VTYPE_NONPSEUDO_TE_IS)
      continue;
    if (memcmp (vertex->N.id, area->isis->sysid, ISIS_SYS_ID_LEN) == 0) {
      rbvertex = vertex;
      break;
    }
  }

  /* Determine adjacencies by looking up the parent & child nodes */
  if (rbvertex) {
    adjlist = list_new();
    if (listcount (rbvertex->parents) > 0) {
      /* Add only non pseudo parents to adjacency list
       * if parent is a pseudo node add the first of his non pseudo
       * parents which is the non pseudo node version of the pseudo node
       */
      for (ALL_LIST_ELEMENTS_RO (rbvertex->parents, node, pvertex)){
	if (pvertex->type != VTYPE_PSEUDO_IS &&
	    pvertex->type != VTYPE_PSEUDO_TE_IS)
	  trill_add_nickadjlist (area, adjlist, pvertex);
	else
	  trill_add_nickadjlist (area, adjlist,
				 listgetdata(listhead(pvertex->parents)));
      }
    }
    if (listcount (rbvertex->children) > 0) {
      childlist = list_new();
      for (ALL_LIST_ELEMENTS_RO (rbvertex->children, node, vertex)) {
        if (vertex->type == VTYPE_PSEUDO_IS ||
            vertex->type == VTYPE_PSEUDO_TE_IS)
	  listnode_add(childlist, vertex);
	else if (listnode_lookup (rdtree->paths, vertex))
	  trill_add_nickadjlist (area, adjlist, vertex);
      }
      /*
       * If we find child vertices above with our system ID (pseudo node)
       * then we search their descendants and any that are found are
       * added as our adjacencies
       */
      if( listcount(childlist) > 0) {
	for (node = listhead(childlist); node != NULL;
	     node = listnextnode(node)) {
	  if ((vertex = listgetdata(node)) == NULL)
	    break;
	  for (ALL_LIST_ELEMENTS_RO (vertex->children, cnode, cvertex)) {
	    if ((memcmp (cvertex->N.id, area->isis->sysid, ISIS_SYS_ID_LEN) == 0)
	      && listnode_lookup(childlist, cvertex) == NULL)
	      listnode_add(childlist, cvertex);
	    if (listnode_lookup(rdtree->paths, cvertex))
	      trill_add_nickadjlist (area, adjlist, cvertex);
	  }
	}
      }
      if (childlist)
	list_delete(childlist);
    }
    if (nicknode != NULL)
      nicknode->adjnodes = adjlist;
    else
      area->trill->adjnodes = adjlist;
    if(oldadjlist)
      list_delete (oldadjlist);
  }
}

static void trill_publish_nick(struct isis_area *area, int fd,
			       uint16_t nick, nickfwdtblnode_t *fwdnode,
			       int port_id)
{
  int idx;
  uint16_t overhead;
  int new_ni_size;
  void *listdata;
  struct listnode *node;
  struct list *adjnodes;
  struct list *dtrootnodes;
  struct list *supported_vni;
  struct nl_msg *msg;
  struct trill_nl_header *trnlhdr;
  nicknode_t *nick_node;
  trill_nickinfo_t *ni;
  uint16_t adjcount = 0;
  uint16_t dtrootcount = 0;
  uint16_t vnicount = 0;

  /* If this is a forwarding entry (not us), then get node data */
  if (fwdnode != NULL)
  {
    nick_node = trill_nicknode_lookup (area, fwdnode->dest_nick);
    if (nick_node == NULL)
      return;
    adjnodes = nick_node->adjnodes;
    dtrootnodes = nick_node->info.dt_roots;
    supported_vni = nick_node->info.supported_vni;
  } else {
    adjnodes = area->trill->adjnodes;
    dtrootnodes = area->trill->dt_roots;
    supported_vni = area->trill->configured_vni;
  }

  if (adjnodes != NULL)
    adjcount = listcount(adjnodes);

  if (dtrootnodes != NULL)
    dtrootcount = listcount(dtrootnodes);
  if (supported_vni != NULL)
    vnicount = listcount(supported_vni);

  overhead = (
    (adjcount * sizeof (uint16_t))+
    (dtrootcount * sizeof (uint16_t))
#ifdef NEW_KERNEL_RELEASE
    +
    (vnicount * sizeof (uint32_t))
#endif
  );


  /*WARNING: extending tios size to have space for ajd list and treerot list*/

  new_ni_size = sizeof(trill_nickinfo_t) + (overhead > 0 ? overhead : 0);
  if (new_ni_size > PAGE_SIZE){
    zlog_err("netlink data over PAGE_SIZE");
    return;
  }
  ni = (trill_nickinfo_t *)calloc(1, new_ni_size);
  ni->tni_adjcount = adjcount;
  ni->tni_dtrootcount = dtrootcount;
#ifdef NEW_KERNEL_RELEASE
  ni->tni_vnicount = vnicount;
#endif
  ni->tni_nick = nick;

  if (fwdnode != NULL) {
    memcpy(ni->tni_adjsnpa, fwdnode->adj_snpa, sizeof(fwdnode->adj_snpa));
    ni->tni_linkid = fwdnode->interface->ifindex;
  }
  if (adjcount > 0) {
    idx = 0;
    for (ALL_LIST_ELEMENTS_RO (adjnodes, node, listdata)) {
      TNI_ADJNICK(ni, idx) = (uint16_t)(unsigned long)listdata;
      idx++;
    }
  }

  if (dtrootcount > 0) {
    idx = 0;
    for (ALL_LIST_ELEMENTS_RO (dtrootnodes, node, listdata)) {
      TNI_DTROOTNICK(ni, idx) = (uint16_t)(unsigned long)listdata;
      idx++;
    }
  }
#ifdef NEW_KERNEL_RELEASE
  if (vnicount > 0) {
    idx = 0;
    for (ALL_LIST_ELEMENTS_RO (supported_vni, node, listdata)) {
      TNI_VNI(ni, idx) = (uint32_t)(unsigned long)listdata;
      idx++;
    }
  }
#endif
  if (ni) {
    if (fwdnode == NULL) {
      /*
       * check if it's really self in case we remove fwdnode from
       * fwdtbl before finishing executing this function
       * (asynchronous threads)*/
      if (area->trill->nick.name == nick) {
	msg = nlmsg_alloc();
	trnlhdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family,
			    sizeof(struct trill_nl_header), NLM_F_REQUEST,
			    TRILL_CMD_SET_NICKS_INFO, TRILL_NL_VERSION);
      } else {
	free(ni);
	return;
      }
    } else {
      msg = nlmsg_alloc();
      trnlhdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family,
			    sizeof(struct trill_nl_header), NLM_F_REQUEST,
			    TRILL_CMD_SET_NICKS_INFO, TRILL_NL_VERSION);
    }

    printf("tni_nick: %x, tni_adjsnpa: %x, tni_linkid: %u, tni_adjcount: %u, tni_dtrootcount: %u\n", ni->tni_nick, ni->tni_adjsnpa, ni->tni_linkid, ni->tni_adjcount, ni->tni_dtrootcount);

    nla_put(msg,TRILL_ATTR_BIN, new_ni_size, ni);
    trnlhdr->ifindex = port_id;
    trnlhdr->total_length = sizeof(msg);
    trnlhdr->msg_number = 1;
    nl_send_auto_complete(sock_genl, msg);
    nlmsg_free(msg);
    free(ni);
  }
}
uint16_t get_root_nick(struct isis_area *area)
{
  uint8_t lpriority;
  uint16_t root_nick;
  u_char *lsysid;
  dnode_t *dnode;
  nicknode_t *tnode;
  int i;
  lpriority = area->trill->nick.priority;
  lsysid = area->isis->sysid;
  root_nick = area->trill->nick.name;

  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode))
  {
    i++;
    if (tnode->info.nick.priority < lpriority)
      continue;
    if (tnode->info.nick.priority == lpriority &&
	memcmp(tnode->info.sysid, lsysid, ISIS_SYS_ID_LEN) < 0)
      continue;

    lpriority = tnode->info.nick.priority;
    lsysid = tnode->info.sysid;
    root_nick = tnode->info.nick.name;
  }
  return root_nick;

}
static void trill_publish (struct isis_area *area)
{
  struct listnode *node;
  nickfwdtblnode_t *fwdnode;
  struct nl_msg *msg;
  struct trill_nl_header *trnlhdr;
  struct isis_circuit *circuit;
  if (area->circuit_list && listhead(area->circuit_list))
    circuit = listgetdata(listhead(area->circuit_list));
  if (circuit == NULL){
     printf("circuit == NULL\n"); 
     return;
  }

  if (area->trill->fwdtbl != NULL){
    for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, node, fwdnode))
      trill_publish_nick(area, circuit->fd, fwdnode->dest_nick,
			 fwdnode,circuit->interface->ifindex);
  }

  trill_publish_nick(area, circuit->fd, area->trill->nick.name,
		     NULL, circuit->interface->ifindex);

  msg = nlmsg_alloc();
  trnlhdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family,
			sizeof(struct trill_nl_header), NLM_F_REQUEST,
			TRILL_CMD_SET_TREEROOT_ID, TRILL_NL_VERSION);
  if(!trnlhdr)
    abort();
  trnlhdr->ifindex = circuit->interface->ifindex;
  trnlhdr->total_length = sizeof(msg);
  trnlhdr->msg_number = 1;
  nla_put_u16(msg, TRILL_ATTR_U16, ntohs(area->trill->tree_root));
  nl_send_auto_complete(sock_genl, msg);
  nlmsg_free(msg);
}
/*
 * Called upon computing the SPF trees to create the forwarding
 * and adjacency lists for TRILL.
 */
void trill_process_spf (struct isis_area *area)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  struct nl_msg *msg;
  struct trill_nl_header *trnlhdr;
  struct isis_circuit *circuit;

  /* Nothing to do if we don't have a nick yet */
  if (area->trill->nick.name == RBRIDGE_NICKNAME_NONE)
    return;

  trill_create_nickfwdtable(area);
  trill_create_nickadjlist(area, NULL);

  if(area->trill->tree_root != RBRIDGE_NICKNAME_NONE) {
    dnode = dict_lookup (area->trill->nickdb,
			 &(area->trill->tree_root));
    if (dnode) {
      tnode = (nicknode_t *) dnode_get (dnode);
      trill_create_nickadjlist(area, tnode);
    }
  }
#ifdef NEW_KERNEL_RELEASE
  msg = nlmsg_alloc();
  trnlhdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family,
		      sizeof(struct trill_nl_header), NLM_F_REQUEST,
		      TRILL_CMD_GET_VNIS, TRILL_NL_VERSION);
  if(trnlhdr) {
    if (area->circuit_list && listhead(area->circuit_list))
      circuit = listgetdata(listhead(area->circuit_list));
    if (circuit == NULL)
      return;
    trnlhdr->ifindex = circuit->interface->ifindex;
    trnlhdr->total_length = sizeof(msg);
    trnlhdr->msg_number = 1;
    nla_put_u16(msg, TRILL_ATTR_U16, RBRIDGE_NICKNAME_NONE);
    nl_send_auto_complete(sock_genl, msg);
    nlmsg_free(msg);
  }
#endif
  trill_publish(area);
  SET_FLAG(area->trill->status, TRILL_SPF_COMPUTED);
}
static int trill_nick_conflict(nickinfo_t *nick1, nickinfo_t *nick2)
{
  assert (nick1->nick.name == nick2->nick.name);

  /* If nick1 priority is greater (or)
   * If priorities match & nick1 sysid is greater
   * then nick1 has higher priority
   */
  if (
    (nick1->nick.priority > nick2->nick.priority)
    || (nick1->nick.priority == nick2->nick.priority
    && (sysid_cmp (nick1->sysid, nick2->sysid) > 0))
  )
    return false;
    return true;
}

static nickdb_search_result trill_search_rbridge ( struct isis_area *area,
						   nickinfo_t *ni,
						   dnode_t **fndnode)
{
  dnode_t *dnode;
  nicknode_t *tnode;

  dnode = dict_lookup (area->trill->nickdb, &(ni->nick.name));
  if (dnode == NULL)
    dnode = dict_lookup(area->trill->sysidtonickdb, ni->sysid);
  if (dnode == NULL)
    return NOTFOUND;

  tnode = (nicknode_t *) dnode_get (dnode);
  assert (tnode != NULL);
  assert (tnode->refcnt);
  if (fndnode)
    *fndnode = dnode;
  if ( memcmp(&(tnode->info.sysid), ni->sysid, ISIS_SYS_ID_LEN) != 0)
    return FOUND;
  if (tnode->info.nick.name != ni->nick.name)
    return NICK_CHANGED;
  if (tnode->info.nick.priority != ni->nick.priority)
    return PRIORITY_CHANGE_ONLY;
  /* Exact nick and sysid match */
  return DUPLICATE;
}
static void trill_nickinfo_del(nickinfo_t *ni)
{
  if (ni->dt_roots != NULL)
    list_delete (ni->dt_roots);
  if (ni->supported_vni != NULL)
    list_delete(ni->supported_vni);
}
static void trill_update_nickinfo (nicknode_t *tnode, nickinfo_t *recvd_nick)
{
  trill_nickinfo_del(&tnode->info);
  memcpy(&tnode->info, recvd_nick, sizeof(nickinfo_t));
  /*
   * clear copied nick this will avoid removing
   * pointer contained in nickinfo_t structure
   * when deleting recvd_nick
   */
  memset(recvd_nick, 0, sizeof (*recvd_nick));
}


static void trill_dict_remnode ( dict_t *dict, dnode_t *dnode)
{
  nicknode_t *tnode;

  assert (dnode);
  tnode = dnode_get (dnode);
  assert(tnode->refcnt);
  tnode->refcnt--;
  if (tnode->refcnt == 0) {
    isis_spftree_del (tnode->rdtree);
    trill_nickinfo_del (&tnode->info);
    if (tnode->adjnodes)
      list_delete (tnode->adjnodes);
    XFREE (MTYPE_ISIS_TRILL_NICKDB_NODE, tnode);
  }
  dict_delete_free (dict, dnode);
}
/*
 * Delete nickname node in both databases. First a lookup
 * of the node in first db by key1 and using the found node
 * a lookup of the node in second db is done. Asserts the
 * node if exists in one also exist in the second db.
 */
static void trill_dict_delete_nodes (dict_t *dict1, dict_t *dict2,
				      void *key1, int key2isnick)
{
  dnode_t *dnode1;
  dnode_t *dnode2;
  nicknode_t *tnode;
  int nickname;

  dnode1 = dict_lookup (dict1, key1);
  if (dnode1) {
    tnode = (nicknode_t *) dnode_get(dnode1);
    if (tnode) {
      if (key2isnick) {
	dnode2 = dict_lookup (dict2, &(tnode->info.nick.name));
	nickname = tnode->info.nick.name;
      } else {
	dnode2 = dict_lookup (dict2, tnode->info.sysid);
	nickname = *(int *)key1;
      }
      assert (dnode2);
      trill_dict_remnode (dict2, dnode2);
      /* Mark the nickname as available */
      trill_nickname_free(nickname);
    }
    trill_dict_remnode (dict1, dnode1);
  }
}
static void trill_dict_create_nodes (struct isis_area *area, nickinfo_t *nick)
{
  nicknode_t *tnode;

  tnode = XCALLOC (MTYPE_ISIS_TRILL_NICKDB_NODE, sizeof(nicknode_t));
  tnode->info = *nick;
  dict_alloc_insert (area->trill->nickdb, &(tnode->info.nick.name), tnode);
  tnode->refcnt = 1;
  dict_alloc_insert (area->trill->sysidtonickdb, tnode->info.sysid, tnode);
  tnode->refcnt++;
  /* Mark the nickname as reserved */
  trill_nickname_reserve(nick->nick.name);
  tnode->rdtree = isis_spftree_new(area);
  /* clear copied nick */
  memset(nick, 0, sizeof (*nick));
}
static void trill_nickdb_update ( struct isis_area *area, nickinfo_t *newnick)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  nickdb_search_result res;

  res = trill_search_rbridge (area, newnick, &dnode);
  if (res == NOTFOUND) {
    trill_dict_create_nodes (area, newnick);
    return;
  }
  assert (dnode);
  tnode = dnode_get (dnode);

  /* If nickname & system ID of the node in our database match
   * the nick received then we don't have to change any dictionary
   * nodes. Update only the node information. Otherwise we update
   * the dictionary nodes.
   */
  if (res == DUPLICATE || res == PRIORITY_CHANGE_ONLY) {
    trill_update_nickinfo (tnode, newnick);
    return;
  }
  /*
   * If the RBridge has a new nick then update its nick only.
   */
  if (res == NICK_CHANGED) {
    if (isis->debugs & DEBUG_TRILL_EVENTS)
      zlog_debug("ISIS TRILL storing new nick:%d from sysID:%s",
		 ntohs(tnode->info.nick.name), sysid_print(tnode->info.sysid));
      /* Delete the current nick in from our database */
      trill_dict_delete_nodes (area->trill->sysidtonickdb,
			       area->trill->nickdb, tnode->info.sysid, true);
      /* Store the new nick entry */
      trill_dict_create_nodes (area, newnick);
  } else {
    /*
     * There is another RBridge using the same nick.
     * Determine which of the two RBridges should use the nick.
     * But first we should delete any prev nick associated
     * with system ID sending the newnick as it has just
     * announced a new nick.
     */
    trill_dict_delete_nodes (area->trill->sysidtonickdb,
			     area->trill->nickdb, newnick->sysid, true);
    if (trill_nick_conflict (&(tnode->info), newnick)) {
      /*
       * RBridge in tnode should choose another nick.
       * Delete tnode from our nickdb and store newnick.
       */
      if (isis->debugs & DEBUG_TRILL_EVENTS) {
	zlog_debug("ISIS TRILL replacing conflict nick:%d of sysID:%s",
		   ntohs(tnode->info.nick.name),
		   sysid_print(tnode->info.sysid));
      }
      trill_dict_delete_nodes (area->trill->sysidtonickdb,
			       area->trill->nickdb, tnode->info.sysid, true);
      trill_dict_create_nodes (area, newnick);
    } else if (isis->debugs & DEBUG_TRILL_EVENTS) {
      zlog_debug("ISIS TRILL because of conflict with existing"
      "nick:%d of sysID:%s",
      ntohs(tnode->info.nick.name), sysid_print(tnode->info.sysid));
    }
  }
}
static void trill_nick_recv(struct isis_area *area, nickinfo_t *other_nick)
{
  nickinfo_t ournick;
  int nickchange = false;

  ournick.nick = area->trill->nick;
  memcpy (ournick.sysid, area->isis->sysid, ISIS_SYS_ID_LEN);

  /* Check for reserved TRILL nicknames that are not valid for use */
  if ((other_nick->nick.name == RBRIDGE_NICKNAME_NONE) ||
    (other_nick->nick.name == RBRIDGE_NICKNAME_UNUSED)) {
    zlog_warn("ISIS TRILL received reserved nickname:%d from sysID:%s",
	      ntohs (other_nick->nick.name),
	      sysid_print(other_nick->sysid) );
    return;
  }

  /* Check for conflict with our own nickname */
  if (other_nick->nick.name == area->trill->nick.name) {
    /* Check if our nickname has lower priority or our
     * system ID is lower, if not we keep our nickname
     */
    if (!(nickchange = trill_nick_conflict (&ournick, other_nick))){
	return;
	}
  }
  /* out nickname conflit and we have to change it */
  if (nickchange) {
    /* We choose another nickname */
    gen_nickname (area);
    SET_FLAG(area->trill->status, TRILL_AUTONICK);
    /* If previous nick was configured remove the bit
     * indicating nickname was configured  (0x80) */
    area->trill->nick.priority &= ~CONFIGURED_NICK_PRIORITY;
    /* Regenerate our LSP to advertise the new nickname */
    lsp_regenerate_schedule (area, TRILL_ISIS_LEVEL, 1);
    if (isis->debugs & DEBUG_TRILL_EVENTS)
      zlog_debug("ISIS TRILL our nick changed to:%d",
		 ntohs (area->trill->nick.name));
  }
  /* Update our nick database */
  trill_nickdb_update (area, other_nick);
  /* Update tree root based on new nick database */
  area->trill->tree_root = get_root_nick(area);
}
void trill_nick_destroy(struct isis_lsp *lsp)
{
  u_char *lsp_id;
  nickinfo_t ni;
  struct isis_area *area;
  int delnick;

  area = listgetdata(listhead (isis->area_list));
  lsp_id = lsp->lsp_header->lsp_id;

  /*
   * If LSP is our own or is a Pseudonode LSP (and we do not
   * learn nicks from Pseudonode LSPs) then no action is needed.
   */
  if ((memcmp (lsp_id, isis->sysid,
    ISIS_SYS_ID_LEN) == 0) || (LSP_PSEUDO_ID(lsp_id) != 0))
    return;

  if (!trill_parse_lsp (lsp, &ni) ||
    (ni.nick.name == RBRIDGE_NICKNAME_NONE)) {
    /* Delete the nickname associated with the LSP system ID
     * (if any) that did not include router capability TLV or
     * TRILL flags or the nickname in the LSP is unknown. This
     * happens when we recv a LSP from RBridge that just re-started
     * and we have to delete the prev nick associated with it.
     */
    trill_dict_delete_nodes (area->trill->sysidtonickdb,
			     area->trill->nickdb, lsp_id, true);
    if (isis->debugs & DEBUG_TRILL_EVENTS)
      zlog_debug("ISIS TRILL removed any nickname associated with "
      "sysID:%s LSP seqnum:0x%08x pseudonode:%x",
      sysid_print(lsp_id), ntohl (lsp->lsp_header->seq_num),
      LSP_PSEUDO_ID(lsp_id) );
    trill_nickinfo_del (&ni);
    return;

  }
  memcpy(ni.sysid, lsp_id, ISIS_SYS_ID_LEN);
  delnick = ntohs(ni.nick.name);
  if (delnick != RBRIDGE_NICKNAME_NONE &&
    delnick != RBRIDGE_NICKNAME_UNUSED &&
    ni.nick.priority >= MIN_RBRIDGE_PRIORITY
  ) {
    /* Only delete if the nickname was learned
     * from the LSP by ensuring both system ID
     * and nickname in the LSP match with a node
     * in our nick database.
     */
    if (trill_search_rbridge (area, &ni, NULL) == DUPLICATE) {
      trill_dict_delete_nodes (area->trill->sysidtonickdb,
			       area->trill->nickdb, ni.sysid, true);
      if (isis->debugs & DEBUG_TRILL_EVENTS)
	zlog_debug("ISIS TRILL removed nickname:%d associated with "
	"sysID:%s LSP ID:0x%08x pseudonode:%x",
	delnick, sysid_print(lsp_id),
	ntohl (lsp->lsp_header->seq_num), LSP_PSEUDO_ID(lsp_id) );
    }
  } else if (isis->debugs & DEBUG_TRILL_EVENTS)
    zlog_debug("ISIS TRILL nick destroy invalid nickname:%d from "
    "sysID:%s", delnick, sysid_print(lsp_id) );
  trill_nickinfo_del (&ni);
}

void trill_parse_router_capability_tlvs (struct isis_area *area,
					 struct isis_lsp *lsp)
{
  nickinfo_t recvd_nick;

  /* Return if LSP is our own or is a pseudonode LSP */
  if ((memcmp (lsp->lsp_header->lsp_id, isis->sysid, ISIS_SYS_ID_LEN) == 0)
       || (LSP_PSEUDO_ID(lsp->lsp_header->lsp_id) != 0))
    return;

  if (trill_parse_lsp (lsp, &recvd_nick)) {
      /* Parsed LSP correctly but process only if nick is not unknown */
      if (recvd_nick.nick.name != RBRIDGE_NICKNAME_NONE){
         trill_nick_recv (area, &recvd_nick);
	}
    } else {
      /* if we have a nickname stored from this RBridge we remove it as this
       * LSP without a nickname likely indicates the RBridge has re-started
       * and hasn't chosen a new nick.
       */
      trill_nick_destroy (lsp);
    }
    trill_nickinfo_del (&recvd_nick);
}
void trill_nickdb_print (struct vty *vty, struct isis_area *area)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  const char *sysid;
  struct listnode *node;
  void *data;
  uint32_t vni;

  u_char *lsysid;
  u_int16_t lpriority;

  vty_out(vty, "    System ID          Hostname     Nickname   Priority  %s",
	  VTY_NEWLINE);
  lpriority = area->trill->nick.priority;
  lsysid = area->isis->sysid;


  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode)) {
    sysid = sysid_print (tnode->info.sysid);
    vty_out (vty, "%-21s %-10s  %8d  %8d%s", sysid,
	     print_sys_hostname (tnode->info.sysid),
	     ntohs (tnode->info.nick.name),
	     tnode->info.nick.priority,VTY_NEWLINE);
    vty_out(vty, "\tSupported VNI:%s\t",VTY_NEWLINE);

    for (ALL_LIST_ELEMENTS_RO(tnode->info.supported_vni, node, data)) {
      vni = (uint32_t) (u_long) data;
      vty_out(vty, "%i    ",(((vni >>4)&0x00FFF000) | (vni &0x00000FFF)));
    }
    vty_out(vty, "%s",VTY_NEWLINE);
  }
  if(area->trill->tree_root)
    vty_out (vty,"    TREE_ROOT:       %8d    %s",
	     ntohs (area->trill->tree_root),VTY_NEWLINE);
}

void
trill_circuits_print_all (struct vty *vty, struct isis_area *area)
{
  struct listnode *node;
  struct isis_circuit *circuit;

  if (area->circuit_list == NULL)
    return;

  for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
    vty_out (vty, "%sInterface %s:%s", VTY_NEWLINE,
	     circuit->interface->name, VTY_NEWLINE);
}

nicknode_t * trill_nicknode_lookup(struct isis_area *area,
					  uint16_t nick)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  dnode = dict_lookup (area->trill->nickdb, &nick);
  if (dnode == NULL)
    return (NULL);
  tnode = (nicknode_t *) dnode_get (dnode);
  return (tnode);
}

/* Lookup system ID when given a nickname */
static u_char * nick_to_sysid(struct isis_area *area, u_int16_t nick)
{
  nicknode_t *tnode;

  tnode = trill_nicknode_lookup(area, nick);
  if (tnode == NULL)
    return (NULL);
  return tnode->info.sysid;
}
static void trill_fwdtbl_print (struct vty *vty, struct isis_area *area)
{
  struct listnode *node;
  nickfwdtblnode_t *fwdnode;

  if (area->trill->fwdtbl == NULL)
    return;

  vty_out(vty, "RBridge        nickname   interface  nexthop MAC%s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, node, fwdnode)) {
    vty_out (vty, "%-15s   %-5d      %-5s  %-15s%s",
	     print_sys_hostname (nick_to_sysid (area, fwdnode->dest_nick)),
	     ntohs (fwdnode->dest_nick), fwdnode->interface->name,
	     snpa_print (fwdnode->adj_snpa), VTY_NEWLINE);
  }
}
static void
trill_print_paths (struct vty *vty, struct isis_area *area)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  vty_out (vty, "%sRBridge distribution paths for RBridge:%s%s",
	   VTY_NEWLINE, print_sys_hostname (area->isis->sysid),
	   VTY_NEWLINE);
  isis_print_paths (vty, area->spftree[TRILL_ISIS_LEVEL -1]->paths,
		    area->isis->sysid);

  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode)) {
    if (tnode->rdtree && tnode->rdtree->paths->count > 0) {
      vty_out (vty, "%sRBridge distribution paths for RBridge:%s%s",
	       VTY_NEWLINE, print_sys_hostname (tnode->info.sysid),
	       VTY_NEWLINE);
      isis_print_paths (vty, tnode->rdtree->paths, tnode->info.sysid);
    }
  }
}

static void trill_adjtbl_print (struct vty *vty, struct isis_area *area,
				nicknode_t *nicknode)
{
  struct listnode *node;
  nickfwdtblnode_t *fwdnode;
  void *listdata;
  uint16_t nick;
  int idx = 0;
  struct list *adjnodes;
  if (nicknode != NULL) {
    adjnodes = nicknode->adjnodes;
  } else {
    adjnodes = area->trill->adjnodes;
    if (adjnodes != NULL)
      vty_out (vty,"Adj node count %d %s", listcount(adjnodes), VTY_NEWLINE);
  }
  if (adjnodes == NULL)
    return;
  vty_out(vty, "Hostname                           Nick     Iface    "
  "Nexthop%s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS_RO (adjnodes, node, listdata)) {
    nick = (u_int16_t)(u_long)listdata;
    fwdnode = trill_fwdtbl_lookup (area, nick);
    if (!fwdnode)
      continue;
    vty_out (vty, "%-32s   %-5d    %-5s    %-15s%s",
	     print_sys_hostname (nick_to_sysid(area, nick)),
	     ntohs (nick), fwdnode->interface->name,
	     snpa_print (fwdnode->adj_snpa), VTY_NEWLINE);
  }
}
static void trill_adjtbl_print_all (struct vty *vty, struct isis_area *area)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  vty_out(vty, "Adjacencies on our RBridge distribution tree:%s", VTY_NEWLINE);
  trill_adjtbl_print (vty, area, NULL);
  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode)) {
    if (tnode->info.nick.name == area->trill->tree_root) {
      vty_out(vty, "Adjacencies on RBridge %s distribution tree:%s",
	      print_sys_hostname (tnode->info.sysid), VTY_NEWLINE);
      trill_adjtbl_print (vty, area, tnode);
    }
  }
}

DEFUN (trill_nickname,
       trill_nickname_cmd,
       "trill nickname WORD",
       TRILL_STR
       TRILL_NICK_STR
       "<1-65534>\n")
{
  struct isis_area *area;
  uint16_t nickname;
  area = vty->index;
  assert (area);
  assert (area->trill);
  VTY_GET_INTEGER_RANGE ("TRILL nickname", nickname, argv[0],
			 RBRIDGE_NICKNAME_MIN + 1, RBRIDGE_NICKNAME_MAX);
  if (!trill_area_nickname (area, nickname)) {
    vty_out (vty, "TRILL nickname conflicts with another RBridge nickname,"
    " must select another.%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  /* this check will avoid generating an LSP on trill start */
  if (CHECK_FLAG(area->trill->status, TRILL_SPF_COMPUTED))
    lsp_regenerate_now(area, TRILL_ISIS_LEVEL);
  return CMD_SUCCESS;
}

DEFUN (no_trill_nickname,
       no_trill_nickname_cmd,
       "no trill nickname",
       TRILL_STR
       TRILL_NICK_STR)
{
  struct isis_area *area;
  area = vty->index;
  assert (area);
  assert (area->trill);
  trill_area_nickname (area, 0);
  /* this check will avoid generating an LSP on trill start */
  if (CHECK_FLAG(area->trill->status, TRILL_SPF_COMPUTED))
    lsp_regenerate_now(area, TRILL_ISIS_LEVEL);
  return CMD_SUCCESS;
}

DEFUN (trill_nickname_priority,
       trill_nickname_priority_cmd,
       "trill nickname priority WORD",
       TRILL_STR
       TRILL_NICK_STR
       "priority of use field\n"
       "<1-127>\n")
{
  struct isis_area *area;
  u_int8_t priority;
  area = vty->index;
  assert (area);
  assert (area->trill);
  VTY_GET_INTEGER_RANGE ("TRILL nickname priority", priority, argv[0],
			 MIN_RBRIDGE_PRIORITY, MAX_RBRIDGE_PRIORITY);
  trill_nickname_priority_update (area, priority);
  /* this check will avoid generating an LSP on trill start */
  if (CHECK_FLAG(area->trill->status, TRILL_SPF_COMPUTED))
    lsp_regenerate_now(area, TRILL_ISIS_LEVEL);
  return CMD_SUCCESS;
}
DEFUN (no_trill_nickname_priority,
       no_trill_nickname_priority_cmd,
       "no trill nickname priority WORD",
       TRILL_STR
       TRILL_NICK_STR
       "priority of use field\n")
{
  struct isis_area *area;
  area = vty->index;
  assert (area);
  assert (area->trill);
  trill_nickname_priority_update (area, 0);
  /* this check will avoid generating an LSP on trill start */
  if (CHECK_FLAG(area->trill->status, TRILL_SPF_COMPUTED))
    lsp_regenerate_now(area, TRILL_ISIS_LEVEL);
  return CMD_SUCCESS;
}
DEFUN (trill_instance, trill_instance_cmd,
       "trill instance WORD",
       TRILL_STR
       "TRILL instance\n"
       "instance name\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);
  assert (area->isis);
  area->trill->name = strdup(argv[0]);
  return CMD_SUCCESS;
}

DEFUN (show_trill_nickdatabase,
       show_trill_nickdatabase_cmd,
       "show trill nickname database",
       SHOW_STR TRILL_STR "TRILL IS-IS nickname information\n"
       "IS-IS TRILL nickname database\n")
{

  struct listnode *node;
  struct listnode *vninode;
  struct isis_area *area;
  dnode_t *dnode;
  void *data;
  uint32_t vni;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area)) {
    vty_out (vty, "Area %s nickname:%d priority:%d %s",
	     area->area_tag ? area->area_tag : "null",
	     ntohs(area->trill->nick.name),
	     area->trill->nick.priority,VTY_NEWLINE);

    vty_out(vty, "\tConfigured VNI%s\t",VTY_NEWLINE);
    for (ALL_LIST_ELEMENTS_RO(area->trill->configured_vni, vninode, data)) {
      vni = (uint32_t) (u_long) data;
      vty_out(vty, "%i    ",(((vni >>4)&0x00FFF000) | (vni &0x00000FFF)));
    }
    vty_out (vty, "%s", VTY_NEWLINE);
    vty_out (vty, "IS-IS TRILL nickname database:%s", VTY_NEWLINE);
    trill_nickdb_print (vty, area);
  }
  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}
DEFUN (show_trill_circuits,
       show_trill_circuits_cmd,
       "show trill circuits",
       SHOW_STR TRILL_STR
       "IS-IS TRILL circuits\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;

  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "IS-IS TRILL circuits:%s%s",
		      VTY_NEWLINE, VTY_NEWLINE);
      trill_circuits_print_all (vty, area);
    }
  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}
DEFUN (show_trill_fwdtable,
       show_trill_fwdtable_cmd,
       "show trill forwarding",
       SHOW_STR TRILL_STR
       "IS-IS TRILL forwarding table\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;
  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area)) {
    vty_out (vty, "IS-IS TRILL forwarding table:%s", VTY_NEWLINE);
    trill_fwdtbl_print (vty, area);
  }
  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (show_trill_topology,
       show_trill_topology_cmd,
       "show trill topology",
       SHOW_STR TRILL_STR "TRILL IS-IS topology information\n"
       "IS-IS TRILL topology\n")
{
  struct isis_area *area;
  area = listgetdata(listhead (isis->area_list));
  vty_out (vty, "IS-IS paths to RBridges that speak TRILL%s", VTY_NEWLINE);
  trill_print_paths (vty, area);
}
DEFUN (show_trill_adjtable,
       show_trill_adjtable_cmd,
       "show trill adjacencies",
       SHOW_STR TRILL_STR
       "IS-IS TRILL adjacency lists\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;

  area = listgetdata(listhead (isis->area_list));

  vty_out (vty, "IS-IS TRILL adjacencies in all distribution trees:%s%s",
	     VTY_NEWLINE, VTY_NEWLINE);
  trill_adjtbl_print_all (vty, area);
  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (trill_rootcount,
	   trill_rootcount_cmd,
	   "trill root count WORD",
	   TRILL_STR
	   TRILL_NICK_STR
	   "<1-65534>\n")
{
	struct isis_area *area;
	uint16_t count;
	area = vty->index;
	assert (area);
	assert (area->trill);
	VTY_GET_INTEGER_RANGE ("TRILL root count", count, argv[0],
						   MIN_ROOT_COUNT, RBRIDGE_NICKNAME_MAX);
	area->trill->root_count = count;
	return CMD_SUCCESS;
}

DEFUN (no_trill_rootcount,
	   no_trill_rootcount_cmd,
	   "no trill root count WORD",
	   TRILL_STR
	          TRILL_NICK_STR)
{
	struct isis_area *area;
	area = vty->index;
	assert (area);
	assert (area->trill);
	area->trill->root_count =  MIN_ROOT_COUNT;
	return CMD_SUCCESS;
}

void trill_init()
{
  install_element (ISIS_NODE, &trill_nickname_cmd);
  install_element (ISIS_NODE, &no_trill_nickname_cmd);
  install_element (ISIS_NODE, &trill_rootcount_cmd);
  install_element (ISIS_NODE, &no_trill_rootcount_cmd);
  install_element (ISIS_NODE, &trill_nickname_priority_cmd);
  install_element (ISIS_NODE, &no_trill_nickname_priority_cmd);
  install_element (ISIS_NODE, &trill_instance_cmd);

  install_element (VIEW_NODE, &show_trill_nickdatabase_cmd);
  install_element (VIEW_NODE, &show_trill_circuits_cmd);
  install_element (VIEW_NODE, &show_trill_fwdtable_cmd);
  install_element (VIEW_NODE, &show_trill_topology_cmd);
  install_element (VIEW_NODE, &show_trill_adjtable_cmd);

  install_element (ENABLE_NODE, &show_trill_nickdatabase_cmd);
  install_element (ENABLE_NODE, &show_trill_circuits_cmd);
  install_element (ENABLE_NODE, &show_trill_fwdtable_cmd);
  install_element (ENABLE_NODE, &show_trill_topology_cmd);
  install_element (ENABLE_NODE, &show_trill_adjtable_cmd);



}
