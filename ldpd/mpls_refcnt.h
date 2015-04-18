
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_REFCNT_H_
#define _MPLS_REFCNT_H_

#include "mpls_assert.h"

#define MPLS_REFCNT_FIELD  uint32_t	_refcnt

#define MPLS_REFCNT_VALUE(obj) (obj)?((obj)->_refcnt):(-1)

#define MPLS_REFCNT_INIT(obj,count) {		\
  (obj)->_refcnt = count;			\
}

#define MPLS_REFCNT_HOLD(obj) {			\
  if((obj) != NULL) {				\
    (obj)->_refcnt++;				\
  }						\
}

#define MPLS_REFCNT_RELEASE(obj,dstry) {		\
  if((obj) != NULL) {				\
    (obj)->_refcnt--;				\
    if((obj)->_refcnt <= 0) {			\
      dstry(obj);				\
      obj = NULL;				\
    }						\
  }						\
}

#define MPLS_REFCNT_RELEASE2(global,obj,dstry) { \
  if((obj) != NULL) {				\
    (obj)->_refcnt--;				\
    if((obj)->_refcnt <= 0) {			\
      dstry(global,obj);			\
      obj = NULL;				\
    }						\
  }						\
}

#define MPLS_REFCNT_ASSERT(obj,count) {		\
  if((obj) != NULL) {				\
    MPLS_ASSERT((obj)->_refcnt == count);	\
  }						\
}

#define MPLS_REFCNT_PTR_TYPE  uint32_t*
#define MPLS_REFCNT_PTR(obj) (((obj) != NULL)?(&((obj)->_refcnt)):(NULL))

#define MPLS_REFCNT_PTR_HOLD(ptr) {		\
  if((ptr) != NULL) {				\
    ((*(ptr))++);				\
  }						\
}
#define MPLS_REFCNT_PTR_RELEASE(ptr) {		\
  if((ptr) != NULL) {				\
    ((*(ptr))--);				\
  }						\
}

#endif
