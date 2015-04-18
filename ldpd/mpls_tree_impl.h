
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_TREE_IMPL_H_
#define _MPLS_TREE_IMPL_H_

#include "mpls_struct.h"

/*
 * in: depth
 * return: mpls_tree_handle
 */
extern mpls_tree_handle mpls_tree_create(const int depth);

/*
 * in: tree
 */
extern void mpls_tree_delete(const mpls_tree_handle tree);

/*
 * in: tree,key, length, node
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_tree_insert(const mpls_tree_handle tree,
  const uint32_t key, const int length, void *node);

/*
 * in: tree, key, length, node
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_tree_remove(const mpls_tree_handle tree,
  const uint32_t key, const int length, void **node);

/*
 * in: tree, key, length, nnode, onode
 * return: mpls_return_enum, onode
 */
extern mpls_return_enum mpls_tree_replace(const mpls_tree_handle tree,
  const uint32_t key, const int length, void *nnode, void **onode);

/*
 * in: tree, key, length, node
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_tree_get(const mpls_tree_handle tree,
  const uint32_t key, const int length, void **node);

/*
 * in: tree, key, length, node
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_tree_get_longest(const mpls_tree_handle tree,
  const uint32_t key, void **node);

extern void mpls_tree_dump(const mpls_tree_handle tree,
  ldp_tree_callback callback);

#endif
