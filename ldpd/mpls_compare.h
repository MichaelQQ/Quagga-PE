#ifndef MPLS_COMPARE_H
#define MPLS_COMPARE_H

#include "mpls_struct.h"

int mpls_inet_addr_compare(struct mpls_inet_addr*, struct mpls_inet_addr*);
int mpls_nexthop_compare(struct mpls_nexthop*, struct mpls_nexthop*);
int mpls_dest_compare(struct mpls_dest*, struct mpls_dest*);
int mpls_label_struct_compare(struct mpls_label_struct*,
		struct mpls_label_struct*);
int mpls_range_compare(struct mpls_range*, struct mpls_range*);
int mpls_fec_compare(struct mpls_fec*, struct mpls_fec*);

#endif
