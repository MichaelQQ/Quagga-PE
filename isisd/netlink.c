/*
 * IS-IS Rout(e)ing protocol - netlink.c
 *
 * Copyright 2014 Gandi, SAS.  All rights reserved.
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

static struct nla_policy TRILL_U16_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_U16] = {.type = NLA_U16},
};
#ifdef NEW_KERNEL_RELEASE
static struct nla_policy TRILL_U32_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_U32] = {.type = NLA_U32},
};
static struct nla_policy TRILL_STRING_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_STRING] = {.type = NLA_STRING},
};
#endif
static struct nla_policy TRILL_BIN_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_BIN] = {.type = NLA_UNSPEC},
};

static struct nla_policy TRILL_VNI_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_U16] = {.type = NLA_U16},
  [TRILL_ATTR_BIN] = {.type = NLA_UNSPEC},
};
int parse_cb(struct nl_msg *msg, void *data)
{
  struct genlmsghdr* genlh;
  struct trill_nl_header *tnlh;
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  struct nlattr *attrs[TRILL_ATTR_MAX + 1];
  struct isis_area *area = (struct isis_area *) data;
  /* Validate message and parse attributes */
  genlh = nlmsg_data(nlh);
  tnlh = (struct trill_nl_header *)genlmsg_data(genlh);
  if(tnlh->ifindex != KERNL_RESPONSE_INTERFACE)
    return 0;
  switch (genlh->cmd){
#ifdef NEW_KERNEL_RELEASE
    case TRILL_CMD_SET_DESIG_VLAN:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		     TRILL_ATTR_MAX, TRILL_U32_POLICY);
      break;
    }
#endif
    case TRILL_CMD_SET_NICKS_INFO:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_GET_NICKS_INFO:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_ADD_NICKS_INFO:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_DEL_NICK:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, NULL);
      break;
    }
    case TRILL_CMD_SET_TREEROOT_ID:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_U16_POLICY);
      break;
    }
#ifdef NEW_KERNEL_RELEASE
    case TRILL_CMD_NEW_BRIDGE:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_STRING_POLICY);
      break;
    }
#endif
    case TRILL_CMD_GET_BRIDGE:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_U16_POLICY);
      break;
    }
    case TRILL_CMD_SET_BRIDGE:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_U16_POLICY);
      break;
    }
#ifdef NEW_KERNEL_RELEASE
    case TRILL_CMD_LIST_NICK:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_BIN_POLICY);
      break;
    }
#endif
    case TRILL_CMD_PORT_FLUSH:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, NULL);
      break;
    }
    case TRILL_CMD_NICK_FLUSH:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_U16_POLICY);
      break;
    }
#ifdef NEW_KERNEL_RELEASE
    case TRILL_CMD_GET_VNIS:
    {
      int16_t vni_nb;
      uint32_t vnis[MAX_VNI_ARR_SIZE];
      int i;
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_VNI_POLICY);
      vni_nb = nla_get_u16(attrs[TRILL_ATTR_U16]);
      nla_memcpy(vnis,attrs[TRILL_ATTR_BIN], sizeof(uint32_t)*vni_nb);
      list_delete(area->trill->configured_vni);
      area->trill->configured_vni = list_new();
      for (i=0; i< vni_nb; i++)
	listnode_add(area->trill->configured_vni, (void *)(u_long)vnis[i]);
      if (generate_supported_vni(area))
	lsp_regenerate_now(area, TRILL_ISIS_LEVEL);
      break;
    }
#endif
    default:
    {
      zlog_warn("received unknown command\n");
      break;
    }
  }
  return 0;
}