/*
 * IS-IS Rout(e)ing protocol - isis_trill.h
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

#include "isisd/dict.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/trilld.h"
#include "isisd/isisd.h"



void trill_area_init(struct isis_area *area){}
void trill_area_free(struct isis_area *area){}
int tlv_add_trill_nickname_pe (struct trill_nickname *nick_info,
			    struct stream *stream, struct isis_area *area)
{
  return 0;
}
int tlv_add_trill_nickname (struct trill_nickname *nick_info,
			    struct stream *stream, struct isis_area *area)
{
  return 0;
}
void trill_process_spf (struct isis_area *area) {}
void trill_parse_router_capability_tlvs (struct isis_area *area,
					 struct isis_lsp *lsp) { }
int trill_area_nickname(struct isis_area *area, u_int16_t nickname)
{
  return 0;
}
uint16_t get_root_nick(struct isis_area *area)
{
  return 0;
}
nicknode_t * trill_nicknode_lookup(struct isis_area *area,
				   uint16_t nick)
{
  return NULL;
}
void trill_nick_destroy(struct isis_lsp *lsp){}
void trill_init() {}
