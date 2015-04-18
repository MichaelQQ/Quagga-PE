
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_TIMER_IMPL_H_
#define _MPLS_TIMER_IMPL_H_

#include "mpls_struct.h"

/*
 * in: handle
 * return: mpls_timer_mgr_handle
 */
extern mpls_timer_mgr_handle mpls_timer_open(mpls_instance_handle handle);

/*
 * in: handle
 */
extern void mpls_timer_close(mpls_timer_mgr_handle handle);

/*
 * in: handle, unit, duration, object, cfg, callback
 * return: mpls_timer_handle
 */
extern mpls_timer_handle mpls_timer_create(const mpls_timer_mgr_handle handle,
  const mpls_time_unit_enum unit, const int duration, void *object,
  const mpls_cfg_handle cfg, void (*callback) (mpls_timer_handle timer,
    void *object, mpls_cfg_handle cfg));

/*
 * in: handle, timer
 */
extern void mpls_timer_delete(const mpls_timer_mgr_handle handle,
  const mpls_timer_handle timer);

/*
 * in: handle, timer, unit, duration, object, cfg, callback
 * out: mpls_return_enum
 */
extern mpls_return_enum mpls_timer_modify(const mpls_timer_mgr_handle handle,
  const mpls_timer_handle timer, const int duration);

/*
 * in: handle, timer, type
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_timer_start(const mpls_timer_mgr_handle handle,
  const mpls_timer_handle timer, const mpls_timer_type_enum type);

/*
 * in: handle, timer
 */
extern void mpls_timer_stop(const mpls_timer_mgr_handle handle,
  const mpls_timer_handle timer);

#endif
