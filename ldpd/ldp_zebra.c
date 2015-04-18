#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"
#include "memory.h"
#include "zclient.h"
#include "log.h"

#include "ldp_cfg.h"
#include "mpls_compare.h"

#include "ldp.h"
#include "impl_fib.h"
#include "impl_ifmgr.h"
#include "impl_mpls.h"
#include "ldp_interface.h"

/* All information about zebra. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;

struct prefix router_id;
struct route_table *table;

/* Router-id update message from zebra. */
static int ldp_router_id_update_zebra(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct ldp *ldp = ldp_get();

    zebra_router_id_update_read(zclient->ibuf,&router_id);

    zlog_info("router-id change %s",
	inet_ntoa(router_id.u.prefix4));

    if (ldp && ldp->lsr_id_is_static != MPLS_BOOL_TRUE) 
	ldp_router_id_update(ldp, &router_id);
    return 0;
}

/* Inteface addition message from zebra. */
static int ldp_interface_add(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct interface *ifp;

    if (!(ifp = zebra_interface_add_read(zclient->ibuf))) {
	return 1;
    }

    MPLS_ASSERT (ifp->info);

    /* it must have a valid index now */
    do_mpls_labelspace(ifp->info);

    zlog_info("interface add %s index %d flags %ld metric %d mtu %d",
               ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

    return 0;
}

/* this is not the same as ldp_interface_delete() which is found in
 * ldp_interface.c
 */
static int ldp_interface_delete2(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct interface *ifp;
    struct stream *s;

    s = zclient->ibuf;
    /* zebra_interface_state_read() updates interface structure in iflist */
    ifp = zebra_interface_state_read(s);

    if (ifp == NULL) {
	return 0;
    }

    if (if_is_up(ifp)) {
	zlog_warn("got delete of %s, but interface is still up",
            ifp->name);
    }

    zlog_info("interface delete %s index %d flags %ld metric %d mtu %d",               ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

    if_delete(ifp);

    return 0;
}

struct interface * zebra_interface_if_lookup(struct stream *s) {
    struct interface *ifp;
    u_char ifname_tmp[INTERFACE_NAMSIZ];

    /* Read interface name. */
    stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

    /* Lookup this by interface index. */
    ifp = if_lookup_by_name(ifname_tmp);

    /* If such interface does not exist, indicate an error */
    if (!ifp) {
	return NULL;
    }

    return ifp;
}

static int ldp_interface_state_up(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct interface *ifp;
    struct interface if_tmp;

    ifp = zebra_interface_if_lookup(zclient->ibuf);
    if (ifp == NULL) {
	return 0;
    }

    /* Interface is already up. */
    if (if_is_up (ifp)) {
	/* Temporarily keep ifp values. */
	memcpy (&if_tmp, ifp, sizeof (struct interface));

	zebra_interface_if_set_value (zclient->ibuf, ifp);

	zlog_info ("Interface[%s] state update.", ifp->name);

	return 0;
    }

    zebra_interface_if_set_value(zclient->ibuf, ifp);

    zlog_info ("Interface[%s] state change to up.", ifp->name);

    ldp_interface_up(ifp->info);

    return 0;
}

static int ldp_interface_state_down(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct interface *ifp;

    ifp = zebra_interface_state_read (zclient->ibuf);
    if (ifp == NULL) {
	return 0;
    }

    zlog_info ("Interface[%s] state change to down.", ifp->name);

    ldp_interface_down(ifp->info);

    return 0;
}

void prefix2mpls_inet_addr(struct prefix *p, struct mpls_inet_addr *a)
{
    a->type = MPLS_FAMILY_IPV4;
    a->u.ipv4 = (uint32_t)ntohl(p->u.prefix4.s_addr);
}

void zebra_prefix2mpls_fec(struct prefix *p, mpls_fec *fec)
{
  fec->u.prefix.length = p->prefixlen;
  fec->type = MPLS_FEC_PREFIX;
  fec->u.prefix.network.type = MPLS_FAMILY_IPV4;
  fec->u.prefix.network.u.ipv4 = ntohl(p->u.prefix4.s_addr);
}

void mpls_fec2zebra_prefix(mpls_fec *lp, struct prefix *p)
{
  switch(lp->type) {
    case MPLS_FEC_PREFIX:
      p->prefixlen = lp->u.prefix.length;
      p->u.prefix4.s_addr = htonl(lp->u.prefix.network.u.ipv4);
      break;
    case MPLS_FEC_HOST:
      p->prefixlen = 32;
      p->u.prefix4.s_addr = htonl(lp->u.host.u.ipv4);
      break;
    default:
      break;
  }
}

static int ldp_interface_address_add(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct ldp *ldp = ldp_get();
    struct connected *c;
    struct interface *ifp;
    struct prefix *p;
    struct ldp_addr addr;
    struct ldp_if iff;

    c = zebra_interface_address_add_read(zclient->ibuf);
    if (c == NULL || c->address->family != AF_INET) {
	return 0;
    }

    ifp = c->ifp;
    p = c->address;

    zlog_info("address add %s to interface %s",inet_ntoa(p->u.prefix4),
	ifp->name);

    if (ldp) {
	prefix2mpls_inet_addr(p, &addr.address);
	iff.handle = ifp;
	ldp_cfg_if_addr_set(ldp->h, &iff, &addr, LDP_CFG_ADD);
    }

    return 0;
}

static int ldp_interface_address_delete(int command, struct zclient *zclient,
    zebra_size_t length) {
    struct ldp *ldp = ldp_get();
    struct connected *c;
    struct interface *ifp;
    struct prefix *p;
    struct ldp_addr addr;
    struct ldp_if iff;

    c = zebra_interface_address_delete_read(zclient->ibuf);
    if (c == NULL || c->address->family != AF_INET) {
	return 0;
    }

    ifp = c->ifp;
    p = c->address;

    zlog_info("address delete %s from interface %s",
	inet_ntoa(p->u.prefix4), ifp->name);

    if (ldp) {
	prefix2mpls_inet_addr(p, &addr.address);
	iff.handle = ifp;
	ldp_cfg_if_addr_set(ldp->h, &iff, &addr, LDP_CFG_DEL);
    }

    connected_free(c);

    return 0;
}

static int ldp_zebra_read_ipv4(int cmd, struct zclient *client,
    zebra_size_t length) {
    struct prefix_ipv4 prefix;
    struct stream *s;
    int ifindex_num;
    int nexthop_num;
    int message;
    int flags;
    int type;
    struct mpls_nexthop nexthop;

    s = client->ibuf;
    memset(&nexthop,0,sizeof(nexthop));

    /* Type, flags, message. */
    type = stream_getc(s);
    flags = stream_getc(s);
    message = stream_getc(s);

    /* IPv4 prefix. */
    memset (&prefix, 0, sizeof(struct prefix_ipv4));
    prefix.family = AF_INET;
    prefix.prefixlen = stream_getc (s);
    stream_get(&prefix.prefix, s, PSIZE(prefix.prefixlen));

    zlog_info("route %s/%d", inet_ntoa(prefix.prefix), prefix.prefixlen);
    if (type == ZEBRA_ROUTE_CONNECT) {
      nexthop.attached = MPLS_BOOL_TRUE;
      zlog_info("\tattached");
    }

    /* Nexthop, ifindex, distance, metric. */
    if (CHECK_FLAG(message, ZAPI_MESSAGE_NEXTHOP)) {
	struct in_addr tmp;
	nexthop_num = stream_getc(s);
	zlog_info("\tnum nexthop %d", nexthop_num);
	if (nexthop_num && (nexthop.ip.u.ipv4 = ntohl(stream_get_ipv4(s)))) {
	    nexthop.ip.type = MPLS_FAMILY_IPV4;
	    nexthop.type |= MPLS_NH_IP;
	    tmp.s_addr = htonl(nexthop.ip.u.ipv4);
	    zlog_info("\tnexthop %s", inet_ntoa(tmp));
	}
    }

    if (CHECK_FLAG(message, ZAPI_MESSAGE_IFINDEX)) {
	ifindex_num = stream_getc(s);
	zlog_info("\tnum ifindex %d", ifindex_num);
	if (ifindex_num && (nexthop.if_handle =
	    if_lookup_by_index(stream_getl(s)))) {
	    nexthop.type |= MPLS_NH_IF;
	    zlog_info("\tifindex %d", nexthop.if_handle->ifindex);
	}
    }

    /* Distance. */
    if (CHECK_FLAG(message, ZAPI_MESSAGE_DISTANCE)) {
	nexthop.distance = stream_getc(s);
    }

    /* Metric. */
    if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC)) {
	nexthop.metric = stream_getl(s);
    }

    if (cmd == ZEBRA_IPV4_ROUTE_ADD) {
	zlog_info("\tadd");
	mpls_fib_ipv4_add(&prefix, &nexthop);
    } else {
	zlog_info("\tdelete");
	mpls_fib_ipv4_delete(&prefix, &nexthop);
    }
    return 0;
}

void ldp_zebra_init() {
  int i;

  /* Allocate zebra structure. */
  zclient = zclient_new();
  zclient_init(zclient, ZEBRA_ROUTE_LDP);
  for (i = 0;i < ZEBRA_ROUTE_MAX;i++) {
	zclient->redist[i] = 1;
  }
  zclient->router_id_update = ldp_router_id_update_zebra;
  zclient->interface_add = ldp_interface_add;
  zclient->interface_delete = ldp_interface_delete2;
  zclient->interface_up = ldp_interface_state_up;
  zclient->interface_down = ldp_interface_state_down;
  zclient->interface_address_add = ldp_interface_address_add;
  zclient->interface_address_delete = ldp_interface_address_delete;
  zclient->ipv4_route_add = ldp_zebra_read_ipv4;
  zclient->ipv4_route_delete = ldp_zebra_read_ipv4;

  table = route_table_init();
  memset(&router_id, 0, sizeof(router_id));
}
