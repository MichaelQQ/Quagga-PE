#include "ldp_struct.h"
#include "mpls_mm_impl.h"
#include <stdio.h>
#include <stdlib.h>

#include "memory.h"

static int _mm_count = 0;

void *mpls_malloc(mpls_size_type size)
{
  void *mem = XMALLOC(MTYPE_LDP, size);
  if (mem) {
    _mm_count++;
  }
  return mem;
}

void mpls_free(void *mem)
{
  _mm_count--;
  XFREE(MTYPE_LDP,mem);
}

void mpls_mm_results()
{
  fprintf(stderr, "LDP MM RESULTS: %d\n", _mm_count);
}
