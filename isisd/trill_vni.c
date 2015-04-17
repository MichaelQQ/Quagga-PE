/*
 * IS-IS Rout(e)ing protocol - trilld_vni.c
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

static void
list_add_list_unique (struct list *l, struct list *m)
{
  struct listnode *n;

  for (n = listhead (m); n; n = listnextnode (n)) {
    if(!listnode_lookup (l,(void *)n->data)) {
      listnode_add (l, n->data);
    }
  }
}
static void add_vni_list(struct isis_area *area, struct list *list,
			 uint16_t nick )
{
  static nicknode_t  *tnode;
  tnode = trill_nicknode_lookup(area, nick);
  list_add_list_unique(list, tnode->info.supported_vni);
}

/*
 * get value that exist in two of lists
 * but are not already present in list
 */
static void intersect_list(struct list* list, struct list **lists, int count)
{
  int i,j;
  uint32_t * vni;
  struct listnode *node;
  for ( i = 0; i < count ; i++) {
    for (ALL_LIST_ELEMENTS_RO (lists[i], node, vni)) {
      /* if this vni is already supported no need to do other check */
      if(!listnode_lookup(list, vni))
	for (j = i; j < count ; j++) {
	  if (listnode_lookup(lists[j], vni)) {
	    listnode_add(list, vni);
	  }
	}
    }
    list_delete(lists[i]);
  }
  free(lists);
}
int generate_supported_vni(struct isis_area *area)
{
  int old_count, changed;
  struct listnode *node, *tnode;
  struct list * old_list;
  struct list * new_list;
  struct isis_circuit *circuit;
  nickfwdtblnode_t *fwdnode;
  void *vni;
  int i, circuit_number;
  struct list** tmp_list;
  changed = false;
  struct trill *trill = area->trill;
  old_count = listcount(trill->supported_vni);
  old_list = trill->supported_vni;
  new_list = list_new();

  /* Step one check portential change on configured vni list */
  for (ALL_LIST_ELEMENTS_RO (trill->configured_vni, node, vni)) {
      if (!listnode_lookup (trill->supported_vni, vni)) {
	changed = true;
      }
    listnode_add(new_list,(void *) (uint32_t)(u_long) vni);
  }
  trill->supported_vni = new_list;
  list_delete (old_list);

  /* Step two is use less if circuit list has a unique interface */
  circuit_number = listcount(area->circuit_list);
  if ( circuit_number < 2 )
    goto out;

  /*
   * Step two check if a vni is received from two diffrents interfaces
   *  in such case add it to supported vni list
   */
  /*
   * WARNING i am a struct list ** dont forget to free me
   * after deleting all the struct list *
   */
  tmp_list = calloc(1, sizeof(struct list *) * circuit_number);
  i = 0;
  /* Step 2.1  group vni per interface */
  for (ALL_LIST_ELEMENTS_RO (area->circuit_list, node, circuit)){
    /* tmp_list[i] will store all vni supported by interface i */
    tmp_list[i] = list_new();
    for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, tnode, fwdnode)) {
      if(circuit->interface->ifindex == fwdnode->interface->ifindex)
	add_vni_list(area, tmp_list[i], fwdnode->dest_nick);
    }
    i++;
  }
  /* Step 2.2 add vni that are present on multiple interface */
  intersect_list(trill->supported_vni, tmp_list, circuit_number);

out :
  /*
   * if vni count has changed or one vni was changed
   * return true in order to force a LSP send
   */
  return ( (listcount(trill->supported_vni) != old_count) || changed );
}
