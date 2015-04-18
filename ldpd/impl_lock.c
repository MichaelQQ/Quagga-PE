#include "ldp_struct.h"
#include "mpls_assert.h"
#include "mpls_mm_impl.h"

mpls_lock_handle mpls_lock_create(mpls_lock_key_type key)
{
  int *i = mpls_malloc(sizeof(int));

  *i = 0;
  return i;
}

void mpls_lock_get(mpls_lock_handle handle)
{
  MPLS_ASSERT(*handle == 0);
  (*handle)++;
}

void mpls_lock_release(mpls_lock_handle handle)
{
  MPLS_ASSERT(*handle == 1);
  (*handle)--;
}

void mpls_lock_delete(mpls_lock_handle handle)
{
  mpls_free(handle);
}
