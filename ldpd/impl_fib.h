#ifndef LDP_IMPL_FIB_H
#define LDP_IMPL_FIB_H

#include <zebra.h>

#include "ldp_struct.h"
#include "ldp.h"

struct mpls_node {
  struct list *list;
  void *ldp_data;
};
                                                                                
struct mpls_nh {
  struct mpls_nexthop info;
  struct mpls_node *mn;
  void *ldp_data;
};

void mpls_fib_ipv4_add(struct prefix_ipv4 *p, mpls_nexthop *nexthop);
void mpls_fib_ipv4_delete(struct prefix_ipv4 *p, mpls_nexthop *nexthop);
mpls_bool is_fec_attached(mpls_fec *fec, mpls_nexthop *nexthop);
struct mpls_nexthop *lookup_fec_nexthop(mpls_fec *fec, mpls_nexthop *nexthop);

#endif
