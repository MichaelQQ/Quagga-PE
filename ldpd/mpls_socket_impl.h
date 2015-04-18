
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_SOCKET_IMPL_H_
#define _MPLS_SOCKET_IMPL_H_

#include "ldp_struct.h"
#include "mpls_struct.h"

/*
 * in: handle
 * return: mpls_socket_mgr_handle
 */
extern mpls_socket_mgr_handle mpls_socket_mgr_open(const mpls_instance_handle
  handle);

/*
 * in: handle
 */
extern void mpls_socket_mgr_close(const mpls_socket_mgr_handle handle);

/*
 * in: handle
 * return: mpls_socket_handle
 */
extern mpls_socket_handle mpls_socket_create_tcp(const mpls_socket_mgr_handle
  handle);

/*
 * in: handle
 * return: mpls_socket_handle
 */
extern mpls_socket_handle mpls_socket_create_udp(const mpls_socket_mgr_handle
  handle);

/*
 * in: handle
 * return: mpls_socket_handle
 */
extern mpls_socket_handle mpls_socket_create_raw(const mpls_socket_mgr_handle
  handle, int proto);

/*
 * in: handle,socket,from
 * out: from
 * return: mpls_socket_handle
 */
extern mpls_socket_handle mpls_socket_tcp_accept(const mpls_socket_mgr_handle
  handle, const mpls_socket_handle socket, mpls_dest * from);

/*
 * in: handle,socket
 */
extern void mpls_socket_close(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket);

/*
 * in: handle,socket,local
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_bind(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, const mpls_dest * local);

/*
 * in: handle, socket, flag
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_options(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, const uint32_t flag);

/*
 * in: handle, socket, depth
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_tcp_listen(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, const int depth);

/*
 * in: handle, socket, to
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_tcp_connect(const mpls_socket_mgr_handle
  handle, mpls_socket_handle socket, const mpls_dest * to);

/*
 * in: handle, socket
 * return: int
 */
extern int mpls_socket_get_errno(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket);

/*
 * in: handle, socket
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_connect_status(const mpls_socket_mgr_handle
  handle, mpls_socket_handle socket);

/*
 * in: handle, socket, ttl, loop
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_multicast_options(const mpls_socket_mgr_handle handle, mpls_socket_handle socket, const int ttl, const int loop);

/*
 * in: handle, socket, iff
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_multicast_if_tx(const mpls_socket_mgr_handle
  handle, mpls_socket_handle socket, const ldp_if * iff);

/*
 * in: handle, socket, iff, mult
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_multicast_if_join(const mpls_socket_mgr_handle handle, mpls_socket_handle socket, const ldp_if * iff,
  const mpls_inet_addr * mult);

/*
 * in: handle, socket, iff, mult
 */
extern void mpls_socket_multicast_if_drop(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, const ldp_if * iff, const mpls_inet_addr * mult);

/*
 * in: handle, socket, object, type
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_readlist_add(const mpls_socket_mgr_handle
  handle, mpls_socket_handle socket, void *object, const mpls_socket_enum type);

/*
 * in: handle, socket
 */
extern void mpls_socket_readlist_del(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket);

/*
 * in: handle, socket, object, type
 * return: mpls_return_enum
 */
extern mpls_return_enum mpls_socket_writelist_add(const mpls_socket_mgr_handle
  handle, mpls_socket_handle socket, void *object, const mpls_socket_enum type);

/*
 * in: handle, socket
 */
extern void mpls_socket_writelist_del(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket);

/*
 * in: handle, o
 * return: int
 */
extern int mpls_socket_tcp_read(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, uint8_t * buffer, const int size);

/*
 * in: handle, o
 * return: int
 */
extern int mpls_socket_tcp_write(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, uint8_t * buffer, const int size);

/*
 * in: handle, o
 * return: int
 */
extern int mpls_socket_udp_sendto(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, uint8_t * buffer,

  const int size, const mpls_dest * to);

/*
 * in: handle, o
 * return: int
 */
extern int mpls_socket_udp_recvfrom(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, uint8_t * buffer, const int size, mpls_dest * from);

#endif
