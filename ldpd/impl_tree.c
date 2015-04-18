#include <zebra.h>
#include "prefix.h"
#include "table.h"

#include "ldp_struct.h"
#include "mpls_mm_impl.h"
#include "mpls_tree_impl.h"

mpls_tree_handle mpls_tree_create(int depth)
{
  return route_table_init();
}

mpls_return_enum mpls_tree_insert(mpls_tree_handle tree, uint32_t key, int length,
  void *info)
{
  struct route_node *node;
  struct prefix p;

  p.family = AF_INET;
  p.prefixlen = length;
  p.u.prefix4.s_addr = key;

  if ((node = route_node_get(tree,&p))) {
    /* result is that the node is 'held', it will be held */
    /* until it is deleted from the tree */
    node->info = info;
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum mpls_tree_remove(mpls_tree_handle tree, uint32_t key,
  int length, void **info)
{
  struct route_node *node;
  struct prefix p;

  p.family = AF_INET;
  p.prefixlen = length;
  p.u.prefix4.s_addr = key;

  if ((node = route_node_lookup(tree,&p))) {
    *info = node->info;
    node->info = NULL;
    route_unlock_node(node);
    route_unlock_node(node);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum mpls_tree_replace(mpls_tree_handle tree, uint32_t key, int length,
  void *new, void **old)
{
  struct route_node *node;
  struct prefix p;

  p.family = AF_INET;
  p.prefixlen = length;
  p.u.prefix4.s_addr = key;

  if ((node = route_node_lookup(tree,&p))) {
    *old = node->info;
    node->info = new;
    route_unlock_node(node);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum mpls_tree_get(mpls_tree_handle tree, uint32_t key, int length,
  void **info)
{
  struct route_node *node;
  struct prefix p;

  p.family = AF_INET;
  p.prefixlen = length;
  p.u.prefix4.s_addr = key;

  if ((node = route_node_lookup(tree,&p))) {
    *info = node->info;
    route_unlock_node(node);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum mpls_tree_get_longest(mpls_tree_handle tree, uint32_t key,
  void **info)
{
  struct route_node *node;
  struct prefix p;

  p.family = AF_INET;
  p.prefixlen = 0;
  p.u.prefix4.s_addr = key;

  if ((node = route_node_match(tree,&p))) {
    *info = node->info;
    route_unlock_node(node);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

void mpls_tree_dump(const mpls_tree_handle tree, ldp_tree_callback callback)
{
}

void mpls_tree_delete(mpls_tree_handle tree)
{
  route_table_finish(tree);
}

mpls_return_enum mpls_tree_getfirst(mpls_tree_handle tree, uint32_t * key,
  int *length, void **info)
{
  struct route_node *node;
  struct prefix p;

  p.family = AF_INET;
  p.prefixlen = 0;
  p.u.prefix4.s_addr = 0;

  if ((node = route_node_match(tree,&p))) {
    *info = node->info;
    *length = node->p.prefixlen;
    *key = node->p.u.prefix4.s_addr;
    route_unlock_node(node);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}

mpls_return_enum mpls_tree_getnext(mpls_tree_handle tree, uint32_t * key,
  int *length, void **info)
{
  struct route_node *node;
  struct prefix p;

  p.family = AF_INET;
  p.prefixlen = *length;
  p.u.prefix4.s_addr = *key;

  if (!(node = route_node_match(tree,&p))) {
    return MPLS_FAILURE;
  }

  if ((node = route_next(node))) {
    *info = node->info;
    *length = node->p.prefixlen;
    *key = node->p.u.prefix4.s_addr;
    route_unlock_node(node);
    return MPLS_SUCCESS;
  }
  return MPLS_FAILURE;
}
