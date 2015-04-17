/*
 * IS-IS Rout(e)ing protocol - netlink.h
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

#ifndef _ZEBRA_ISIS_NETLINK_H
#define _ZEBRA_ISIS_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>

#define TRILL_NL_VERSION 0x1
#define TRILL_NL_FAMILY  "TRILL_NL"
#define TRILL_MCAST_NAME "TR_NL_MCAST"
#define KERNL_RESPONSE_INTERFACE -1

struct trill_nl_header {
  /* port id */
  int ifindex;
  /* message total length for mutipart messages check */
  int total_length;
  /* message number for multipart messages check */
  int msg_number;
};

enum{
  TRILL_ATTR_UNSPEC,
  TRILL_ATTR_U16,
#ifdef NEW_KERNEL_RELEASE
  TRILL_ATTR_U32,
  TRILL_ATTR_STRING,
#endif
  TRILL_ATTR_BIN,
  __TRILL_ATTR_MAX,
};
#define TRILL_ATTR_MAX (__TRILL_ATTR_MAX-1)

/*
 * GET and set are from user space perspective
 * example TRILL_CMD_GET_VLANS means that the kernel will
 * send this info to userspace
 */

enum{
  TRILL_CMD_UNSPEC,
#ifdef NEW_KERNEL_RELEASE
  TRILL_CMD_SET_DESIG_VLAN,
#endif
  TRILL_CMD_SET_NICKS_INFO,
  TRILL_CMD_GET_NICKS_INFO,
  TRILL_CMD_ADD_NICKS_INFO,
  TRILL_CMD_DEL_NICK,
  TRILL_CMD_SET_TREEROOT_ID,
#ifdef NEW_KERNEL_RELEASE
  TRILL_CMD_NEW_BRIDGE,
#endif
  TRILL_CMD_GET_BRIDGE,
  TRILL_CMD_SET_BRIDGE,
#ifdef NEW_KERNEL_RELEASE
  TRILL_CMD_LIST_NICK,
#endif
  TRILL_CMD_PORT_FLUSH,
  TRILL_CMD_NICK_FLUSH,
#ifdef NEW_KERNEL_RELEASE
  TRILL_CMD_GET_VNIS,
#endif
  __TRILL_CMD_MAX,
};
#define TRILL_CMD_MAX (__TRILL_CMD_MAX-1)

int init_netlink(struct nl_sock *,struct isis_area *);
int close_netlink(struct nl_sock *);
int parse_cb(struct nl_msg *msg, void *data);
#endif
