
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#include "ldp_struct.h"
#include "ldp_inet_addr.h"

#include "mpls_mm_impl.h"

mpls_inet_addr *mpls_inet_addr_create()
{
  mpls_inet_addr *ia = (mpls_inet_addr *) mpls_malloc(sizeof(mpls_inet_addr));

  if (ia != NULL)
    memset(ia, 0, sizeof(mpls_inet_addr));

  return ia;
}
