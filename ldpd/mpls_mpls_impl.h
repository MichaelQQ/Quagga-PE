
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_MPLS_IMPL_H_
#define _MPLS_MPLS_IMPL_H_

#include "mpls_struct.h"

struct ldp_inlabel;
struct ldp_outlabel;

/*
 * in: handle
 * return: mpls_mpls_handle
 */
extern mpls_mpls_handle mpls_mpls_open(mpls_instance_handle handle);

/*
 * in: handle
 */
extern void mpls_mpls_close(mpls_mpls_handle handle);

/*
 * in: handle, o
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_mpls_outsegment_add(mpls_mpls_handle handle,
  struct mpls_outsegment * o);

/*
 * in: handle, o
 */
extern void mpls_mpls_outsegment_del(mpls_mpls_handle handle, struct mpls_outsegment * o);

/*
 * in: handle, i
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_mpls_insegment_add(mpls_mpls_handle handle,
  struct mpls_insegment * i);

/*
 * in: handle, i
 */
extern void mpls_mpls_insegment_del(mpls_mpls_handle handle, struct mpls_insegment * i);

/*
 * in: handle, i, o
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_mpls_xconnect_add(mpls_mpls_handle handle,
  struct mpls_insegment * i, struct mpls_outsegment * o);

/*
 * in: handle, i, o
 */
extern void mpls_mpls_xconnect_del(mpls_mpls_handle handle,
  struct mpls_insegment * i, struct mpls_outsegment * o);

/*
 * in: handle, f, o
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_mpls_fec2out_add(mpls_mpls_handle handle,
  mpls_fec * f, struct mpls_outsegment * o);

/*
 * in: handle, f, o
 */
extern void mpls_mpls_fec2out_del(mpls_mpls_handle handle,
  mpls_fec * f, struct mpls_outsegment * o);

extern mpls_return_enum mpls_mpls_get_label_space_range(mpls_mpls_handle handle,
  mpls_range *range);

#endif
