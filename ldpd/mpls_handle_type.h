#ifndef _LDP_HANDLE_TYPE_H_
#define _LDP_HANDLE_TYPE_H_

#define MPLS_USE_LSR 0

#if (__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ == 0))
#if 0
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
#endif
#else
#include <stdint.h>
#endif

#include <zebra.h>
#include "if.h"

struct ldp;
struct ldp_timer;
struct ldp_socket;

#define ptr_verify(x) (x ? MPLS_BOOL_TRUE : MPLS_BOOL_FALSE)

typedef void *mpls_tree_handle;
#define mpls_tree_handle_compare(x,y) (x != y)
#define mpls_tree_handle_verify(x) ptr_verify(x)

typedef void *mpls_instance_handle;
#define mpls_instance_handle_compare(x,y) (x != y)
#define mpls_instance_handle_verify(x) ptr_verify(x)

typedef struct ldp* mpls_fib_handle;
#define mpls_fib_handle_compare(x,y) (x == y)
#define mpls_fib_handle_verify(x) ptr_verify(x)

typedef int mpls_ifmgr_handle;
#define mpls_ifmgr_handle_compare(x,y) (x == y)
#define mpls_ifmgr_handle_verify(x) ptr_verify(x)

typedef struct interface* mpls_if_handle;
#define mpls_if_handle_compare(x,y) \
	((x->ifindex == y->ifindex) ? 0 : (x->ifindex > y->ifindex ? 1 : -1))
#define mpls_if_handle_verify(m,x) ptr_verify(x)

typedef int mpls_timer_mgr_handle;
#define mpls_timer_mgr_handle_compare(x,y) (x != y)
#define mpls_timer_mgr_handle_verify(x) ptr_verify(x)

typedef struct mpls_timer* mpls_timer_handle;
#define mpls_timer_handle_compare(x,y) (x != y)
#define mpls_timer_handle_verify(m,x) ptr_verify(x)

typedef int mpls_socket_mgr_handle;
#define mpls_socket_mgr_handle_compare(x,y) (x != y)
#define mpls_socket_mgr_handle_verify(x) MPLS_BOOL_TRUE

typedef struct mpls_socket* mpls_socket_handle;
#define mpls_socket_handle_compare(x,y) (x->fd != y->fd)
#define mpls_socket_handle_verify(m,x) ptr_verify(x)

typedef int mpls_mpls_handle;
#define mpls_mpls_handle_compare(x,y) (x != y)
#define mpls_mpls_handle_verify(x) ptr_verify(x)

typedef int mpls_insegment_handle;
#define mpls_insegment_handle_compare(x,y) (x != y)
#define mpls_insegment_handle_verify(m,x) ptr_verify(x)

typedef int mpls_outsegment_handle;
#define mpls_outsegment_handle_compare(x,y) (x != y)
#define mpls_outsegment_handle_verify(m,x) ptr_verify(x)

typedef int mpls_xconnect_handle;
#define mpls_xconnect_handle_compare(x,y) (x != y)
#define mpls_xconnect_handle_verify(m,x) ptr_verify(x)

typedef int *mpls_lock_handle;
#define mpls_lock_handle_compare(x,y) (x != y)
#define mpls_lock_handle_verify(x) ptr_verify(x)

typedef int mpls_tunnel_handle;
#define mpls_tunnel_handle_compare(x,y) (x != y)

typedef int mpls_policy_handle;
#define mpls_policy_handle_compare(x,y) (x != y)

typedef int mpls_trace_handle;
#define mpls_trace_handle_compare(x,y) (x != y)

typedef char *mpls_lock_key_type;
typedef int mpls_size_type;

#endif
