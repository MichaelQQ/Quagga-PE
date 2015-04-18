#include "mpls_struct.h"
#include "mpls_assert.h"

int mpls_inet_addr_compare(struct mpls_inet_addr *addr1,
		struct mpls_inet_addr *addr2) {
  if (addr1->type != addr2->type) {
    return 1;
  }
  switch(addr1->type) {
    case MPLS_FAMILY_IPV4:
      if (addr1->u.ipv4 != addr2->u.ipv4) {
	return addr1->u.ipv4 > addr2->u.ipv4 ? 1 : -1;
      }
      break;
    case MPLS_FAMILY_IPV6:
      return memcmp(addr1->u.ipv6, addr2->u.ipv6, 16);
    default:
      MPLS_ASSERT(0);
  }
  return 0;
}

int mpls_nexthop_compare(struct mpls_nexthop *nh1, struct mpls_nexthop *nh2) {
  int retval = 0;
  int match = 0;

  if (nh1->type != nh2->type) {
    return 1;
  }
  if (nh1->type & MPLS_NH_IP) {
    match++;
    if ((retval = mpls_inet_addr_compare(&nh1->ip, &nh2->ip))) {
      return retval;
    }
  }
  if (nh1->type & MPLS_NH_IF) {
    match++;
    if ((retval = mpls_if_handle_compare(nh1->if_handle, nh2->if_handle))) {
      return retval;
    }
  }
  if (nh1->type & MPLS_NH_OUTSEGMENT) {
    match++;
    if ((retval = mpls_outsegment_handle_compare(nh1->outsegment_handle,
      nh2->outsegment_handle))) {
      return retval;
    }
  }

  if (!match) {
    return 1;
  }
  return 0;
}

int mpls_label_struct_compare(struct mpls_label_struct* l1,
		struct mpls_label_struct* l2) {
  if (l1->type != l2->type) {
    return 1;
  }
  switch(l1->type) {
    case MPLS_LABEL_TYPE_GENERIC:
      if (l1->u.gen != l2->u.gen) {
	return (l1->u.gen > l2->u.gen) ? 1 : -1;
      }
      break;
    case MPLS_LABEL_TYPE_ATM:
      if (l1->u.atm.vpi != l2->u.atm.vpi) {
	return (l1->u.atm.vpi > l2->u.atm.vpi) ? 1 : -1;
      }
      if (l1->u.atm.vci != l2->u.atm.vci) {
	return (l1->u.atm.vci > l2->u.atm.vci) ? 1 : -1;
      }
      break;
    case MPLS_LABEL_TYPE_FR:
      if (l1->u.fr.len != l2->u.fr.len) {
	return (l1->u.fr.dlci > l2->u.fr.dlci) ? 1 : -1;
      }
      if (l1->u.fr.dlci != l2->u.fr.dlci) {
	return (l1->u.fr.len > l2->u.fr.len) ? 1 : -1;
      }
      break;
    default:
      MPLS_ASSERT(0);
  }
  return 0;
}

int mpls_dest_compare(struct mpls_dest* d1, struct mpls_dest* d2) {
  int retval;
  if ((retval = mpls_inet_addr_compare(&d1->addr, &d2->addr))) {
    return retval;
  }
  if (d1->port != d2->port) {
    return (d1->port > d2->port) ? 1 : -1;
  }
  if ((retval = mpls_if_handle_compare(d1->if_handle, d2->if_handle))) {
    return retval;
  }
  return 0;
}

int mpls_range_compare(struct mpls_range* r1, struct mpls_range* r2) {
  int retval;
  if ((retval = mpls_label_struct_compare(&r1->min, &r2->min))) {
    return retval;
  }
  if ((retval = mpls_label_struct_compare(&r1->max, &r2->max))) {
    return retval;
  }
  return 0;
}

int mpls_fec_compare(struct mpls_fec* f1, struct mpls_fec* f2) {
  int retval;

  if (f1->type != f2->type) {
    return 1;
  }

  switch(f1->type) {
    case MPLS_FEC_PREFIX:
      if ((retval = mpls_inet_addr_compare(&f1->u.prefix.network,
        &f2->u.prefix.network))) {
        return retval;
      }
      if (f1->u.prefix.length > f2->u.prefix.length) {
	return (f1->u.prefix.length != f2->u.prefix.length) ? 1 : -1;
      }
      break;
    case MPLS_FEC_HOST:
      return mpls_inet_addr_compare(&f1->u.host, &f2->u.host);
    case MPLS_FEC_L2CC:
      if (f1->u.l2cc.connection_id != f2->u.l2cc.connection_id) {
	return (f1->u.l2cc.connection_id>f2->u.l2cc.connection_id) ? 1 : -1;
      }
      if (f1->u.l2cc.group_id != f2->u.l2cc.group_id) {
	return (f1->u.l2cc.group_id > f2->u.l2cc.group_id) ? 1 : -1;
      }
      if (f1->u.l2cc.type != f2->u.l2cc.type) {
	return 1;
      }
      break;
    default:
      MPLS_ASSERT(0);
  }
  return 0;
}
