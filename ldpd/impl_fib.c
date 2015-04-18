#include <zebra.h>
#include "prefix.h"
#include "table.h"
#include "if.h"
#include "memory.h"
#include "vty.h"

#include "mpls_compare.h"

#include "ldp.h"
#include "ldp_struct.h"
#include "ldp_cfg.h"

#include "ldp_zebra.h"
#include "impl_fib.h"

struct mpls_nexthop *lookup_fec_nexthop(mpls_fec *fec, mpls_nexthop *nexthop) {
    struct route_node *rn;
    struct mpls_node *mn;
    struct listnode *ln;
    struct mpls_nh *nh;
    struct prefix p;
    struct mpls_nexthop *result = NULL;

    mpls_fec2zebra_prefix(fec,&p);

    if ((rn = route_node_lookup(table,&p))) {
        mn = (struct mpls_node*)rn->info;
        for (ALL_LIST_ELEMENTS_RO (mn->list, ln, nh)) {
            /* if they match, remove it */
            if (!mpls_nexthop_compare(&nh->info, nexthop)) {
		          result = &nh->info;
		          break;
	          }
        }
	route_unlock_node(rn);
    }
    return result;
}

mpls_bool is_fec_attached(mpls_fec *fec, mpls_nexthop *nexthop) {
    struct mpls_nexthop *nh = lookup_fec_nexthop(fec, nexthop);

    if (nh) {
	return nh->attached;
    }
    return MPLS_BOOL_FALSE;
}

void dump_mpls_node(struct vty *vty, struct route_node *node) {
    struct mpls_node *mn;
    struct listnode *ln;
    struct mpls_nh *nh;
    char buf[128];

    if (node->info) {
    	prefix2str(&node->p,buf,sizeof(buf));
    	vty_out(vty, "%s%s", buf, VTY_NEWLINE);
    	mn = (struct mpls_node*)node->info;
      for (ALL_LIST_ELEMENTS_RO (mn->list, ln, nh)) {
    	    vty_out(vty, "  [%d] %d %s ", nh->info.distance, nh->info.metric,
    		nh->info.attached == MPLS_BOOL_TRUE ? "attached":"");
    	    if (nh->info.type & MPLS_NH_IP) {
    		struct in_addr addr;
    		addr.s_addr = htonl(nh->info.ip.u.ipv4);
    		vty_out(vty, "%s ", inet_ntoa(addr));
    	    }
    	    if (nh->info.type & MPLS_NH_IF) {
    		vty_out(vty, "%s ", nh->info.if_handle->name);
    	    }
    	    if (nh->info.type & MPLS_NH_OUTSEGMENT) {
    		vty_out(vty, "%d ", nh->info.outsegment_handle);
    	    }
    	    vty_out(vty, "%s", VTY_NEWLINE);
    	}
    }
}

void mpls_fib_close(mpls_fib_handle handle)
{
}

void mpls_fib_update_close(mpls_fib_handle handle)
{
}

mpls_fib_handle mpls_fib_open(const mpls_instance_handle handle,
  const mpls_cfg_handle cfg)
{
  struct ldp *ldp = ldp_get();
  return ldp;
}

int mpls_fib_get_route(mpls_fib_handle handle, const int num,
  const mpls_fec * fec, mpls_fec * entry)
{
  return 0;
}

int mpls_fib_get_best_route(mpls_fib_handle handle, const int num,
  const mpls_fec * dest, mpls_fec * entry)
{
  return 0;
}

static uint32_t mpls_nh_index() {
    static uint32_t index = 0;
    return ++index;
}

static struct mpls_nh* mpls_nh_create(struct mpls_nexthop* dup) {
  struct mpls_nh *nh;
  nh = XMALLOC (MTYPE_LDP, sizeof (struct mpls_nh));
  memset(nh, 0, sizeof(struct mpls_nh));
  if (dup) {
    memcpy(&nh->info, dup, sizeof(struct mpls_nexthop));
  }
  nh->info.index = mpls_nh_index();
  return nh;
}

static void mpls_nh_delete(void* v) {
  XFREE(MTYPE_LDP, v);
}

static int local_mpls_nexthop_compare(void* a,void* b) {
  if (((mpls_nexthop*)a)->index < ((mpls_nexthop*)b)->index) {
    return -1;
  }
  if (((mpls_nexthop*)a)->index > ((mpls_nexthop*)b)->index) {
    return 1;
  }
  return 0;
}

static struct mpls_node *mpls_node_new() {
  struct mpls_node * mn = XMALLOC (MTYPE_LDP, sizeof (struct mpls_node));
  if (mn) {
    memset(mn, 0, sizeof(*mn));
    mn->list = list_new();
    mn->list->cmp = local_mpls_nexthop_compare;
  }
  return mn;
}

static void mpls_node_delete(struct mpls_node* mn) {
  list_free(mn->list);
  XFREE(MTYPE_LDP, mn);
}

void mpls_fib_ipv4_add(struct prefix_ipv4 *p, struct mpls_nexthop *nexthop) {
  struct route_node *rn;
  struct mpls_node *mn;
  struct mpls_nh *nh = mpls_nh_create(nexthop);
  struct mpls_fec fec;
  struct ldp *ldp = ldp_get();

  if ((rn = route_node_lookup(table,(struct prefix*)p))) {
    mn = (struct mpls_node*)rn->info;
  } else {
    rn = route_node_get(table,(struct prefix*)p);
    route_lock_node(rn);
    mn = mpls_node_new();
    rn->info = mn;
  }
  listnode_add_sort(mn->list, nh);
  nh->mn = mn;

  zebra_prefix2mpls_fec((struct prefix*)p, &fec);
  if (ldp)
    ldp_add_ipv4(ldp, &fec, &nh->info);
  route_unlock_node(rn);
}

void mpls_fib_ipv4_delete(struct prefix_ipv4* p, struct mpls_nexthop* nexthop) {
  struct route_node* rn;
  struct mpls_node* mn;
  struct listnode* ln;
  struct mpls_nh* nh;
  struct mpls_fec fec;
  struct ldp *ldp = ldp_get();

  if ((rn = route_node_lookup(table,(struct prefix*)p))) {
    mn = (struct mpls_node*)rn->info;
    for (ALL_LIST_ELEMENTS_RO (mn->list, ln, nh)) {
      /* if they match, remove it */
      if (!mpls_nexthop_compare(&nh->info, nexthop)) {
      	zebra_prefix2mpls_fec((struct prefix*)p, &fec);
      	if (ldp)
                ldp_delete_ipv4(ldp, &fec, nexthop);
              list_delete_node(mn->list, ln);
      	mpls_nh_delete(nh);
        break;
      }
    }
    if (list_isempty(mn->list)) {
      rn->info = NULL;
      route_unlock_node(rn);
      mpls_node_delete(mn);
      mn = NULL;
    }
  }

  route_unlock_node(rn);
}

mpls_return_enum mpls_fib_getfirst_route(mpls_fib_handle handle,
  mpls_fec * fec, mpls_nexthop *nexthop) {
  struct route_node *rn;

  if ((rn = route_top(table))) {
    if (!rn->info) {
      rn = route_next2(rn);
    }

    if (rn) {
      struct mpls_node *mn;
      struct mpls_nh *nh;

      zebra_prefix2mpls_fec(&rn->p, fec);
      mn = rn->info;
      nh = listgetdata(listhead(mn->list));
      memcpy(nexthop, &nh->info, sizeof(mpls_nexthop));
      route_unlock_node(rn);
      return MPLS_SUCCESS;
    }
  }

  return MPLS_FAILURE;
}

mpls_return_enum mpls_fib_getnext_route(mpls_fib_handle handle,
  mpls_fec * fec, mpls_nexthop *nexthop) {
  struct route_node *rn_in;
  struct mpls_node *mn;
  struct listnode* ln;
  struct mpls_nh* nh;
  struct prefix p;
  int next = 0;

  mpls_fec2zebra_prefix(fec,&p);

  if (!(rn_in = route_node_lookup2(table,&p))) {
    return MPLS_FAILURE;
  }

  mn = rn_in->info;
  for (ALL_LIST_ELEMENTS_RO (mn->list, ln, nh)) {
    if (next) {
      memcpy(nexthop, &nh->info, sizeof(struct mpls_nexthop));
      route_unlock_node(rn_in);
      return MPLS_SUCCESS;
    }
    if (local_mpls_nexthop_compare(nexthop,&nh->info) <= 0) {
      next = 1;
    }
  }

  if ((rn_in = route_next2(rn_in))) {
    zebra_prefix2mpls_fec(&rn_in->p, fec);
    mn = rn_in->info;
    nh = listgetdata(listhead(mn->list));
    memcpy(nexthop, &nh->info, sizeof(mpls_nexthop));
    route_unlock_node(rn_in);
    return MPLS_SUCCESS;
  }

  return MPLS_FAILURE;
}

mpls_return_enum mpls_fib_set_data(mpls_fib_handle handle, mpls_fec * fec,
  mpls_owners_enum owner, void *data) {
  struct route_node *rn;
  struct mpls_node *mn;
  struct prefix p;

  mpls_fec2zebra_prefix(fec,&p);

  if (!(rn = route_node_lookup2(table,&p))) {
    return MPLS_NO_ROUTE;
  }
  mn = rn->info;
  mn->ldp_data = data;
  route_unlock_node(rn);

  return MPLS_SUCCESS;
}

mpls_return_enum mpls_fib_get_data(mpls_fib_handle handle, mpls_fec * fec,
  mpls_owners_enum owner, void **data) {
  struct route_node *rn;
  struct mpls_node *mn;
  struct prefix p;

  mpls_fec2zebra_prefix(fec,&p);

  if (!(rn = route_node_lookup2(table,&p))) {
    return MPLS_NO_ROUTE;
  }
  mn = rn->info;
  *data = mn->ldp_data;
  route_unlock_node(rn);

  return MPLS_SUCCESS;
}
