#include <zebra.h>
#include "thread.h"
#include "sockopt.h"

#include "ldp.h"

#include "ldp_struct.h"
#include "ldp_state_machine.h"
#include "mpls_mm_impl.h"

extern struct thread_master *master;

struct mpls_socket {
    int fd;
    int type;
    struct thread *read;
    struct thread *write;
    void *extra;
};

void _sockaddr2mpls_dest(const struct sockaddr *addr, mpls_dest * dest)
{
  dest->addr.type = MPLS_FAMILY_IPV4;
  switch (dest->addr.type) {
    case MPLS_FAMILY_IPV4:
      dest->port = ntohs(((struct sockaddr_in *)addr)->sin_port);
      dest->addr.u.ipv4 = ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr);
      break;
    default:
      assert(0);
  }
}

void _mpls_dest2sockaddr(const mpls_dest * dest, struct sockaddr *addr)
{
  memset(addr, 0, sizeof(struct sockaddr));

  switch (dest->addr.type) {
    case MPLS_FAMILY_IPV4:
      {
        addr->sa_family = AF_INET;
        ((struct sockaddr_in *)addr)->sin_port = htons(dest->port);
        ((struct sockaddr_in *)addr)->sin_addr.s_addr = htonl(dest->addr.u.ipv4);
        break;
      }
    default:
      {
        assert(0);
      }
  }
}

int mplsd_read(struct thread *thread) {
  int retval;
  struct ldp *ldp = ldp_get();
  mpls_socket_handle socket;

  MPLS_ASSERT(thread); 

  socket = THREAD_ARG(thread);
  socket->read = thread_add_read(master,mplsd_read,socket,socket->fd);

  if (!ldp) {
    return 0;
  }

  switch (socket->type) {
    case MPLS_SOCKET_TCP_DATA:
    {
      retval = ldp_event(ldp->h, socket, socket->extra,
        LDP_EVENT_TCP_DATA);
      break;
    }
    case MPLS_SOCKET_TCP_LISTEN:
    {
      retval = ldp_event(ldp->h, socket, socket->extra,
        LDP_EVENT_TCP_LISTEN);
      break;
    }
    case MPLS_SOCKET_UDP_DATA:
    {
      retval = ldp_event(ldp->h, socket, socket->extra,
        LDP_EVENT_UDP_DATA);
      break;
    }
    default:
    {
      assert(0);
    }
  }
  return 0;
}

int mplsd_write(struct thread *thread) {
  struct ldp *ldp = ldp_get();
  int retval;
  mpls_socket_handle socket;

  MPLS_ASSERT(thread); 

  socket = THREAD_ARG(thread);
  socket->write = thread_add_write(master,mplsd_write,socket,socket->fd);
  if (socket->type != MPLS_SOCKET_TCP_CONNECT) {
    assert(0);
  }
  retval = ldp_event(ldp->h, socket, socket->extra,
    LDP_EVENT_TCP_CONNECT);

  return 0;
}

mpls_socket_mgr_handle mpls_socket_mgr_open(mpls_instance_handle user_data)
{
  return 0xdeadbeef;
}

void mpls_socket_mgr_close(mpls_socket_mgr_handle handle)
{
}

void mpls_socket_close(mpls_socket_mgr_handle handle, mpls_socket_handle socket)
{
  if (socket) {
    close(socket->fd);
    mpls_free(socket);
  }
}

mpls_socket_handle mpls_socket_create_tcp(mpls_socket_mgr_handle handle)
{
  struct mpls_socket *sock;
  sock = mpls_malloc(sizeof(struct mpls_socket));
  memset(sock,0,sizeof(struct mpls_socket));
  sock->fd = socket(AF_INET, SOCK_STREAM, 0);
  MPLS_ASSERT(sock->fd > -1);
  return sock;
}

mpls_socket_handle mpls_socket_create_udp(mpls_socket_mgr_handle handle)
{
  struct mpls_socket *sock;
  u_char one = 1;

  sock = mpls_malloc(sizeof(struct mpls_socket));
  memset(sock,0,sizeof(struct mpls_socket));
  sock->fd = socket(AF_INET, SOCK_DGRAM, 0);
  MPLS_ASSERT(sock->fd > -1);
  if (setsockopt(sock->fd,SOL_IP,IP_PKTINFO,&one,sizeof(one)) < 0) {
    perror("PKTINFO");
    mpls_free(sock);
    return NULL;
  }
  return sock;
}

mpls_socket_handle mpls_socket_create_raw(mpls_socket_mgr_handle handle,
  int proto)
{
  struct mpls_socket *sock;
  u_char one = 1;

  sock = mpls_malloc(sizeof(struct mpls_socket));
  memset(sock,0,sizeof(struct mpls_socket));
  sock->fd = socket(AF_INET, SOCK_RAW, proto);
  MPLS_ASSERT(sock->fd > -1);
  if (setsockopt(sock->fd,SOL_IP,IP_PKTINFO,&one,sizeof(one)) < 0) {
    perror("PKTINFO");
    mpls_free(sock);
    return NULL;
  }
  return sock;
}

mpls_socket_handle mpls_socket_tcp_accept(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, mpls_dest * from)
{
  struct mpls_socket *sock = mpls_malloc(sizeof(struct mpls_socket));
  struct sockaddr addr;
  int size = sizeof(addr);

  if ((sock->fd = accept(socket->fd,&addr,&size)) < 0) {
    return NULL;
  }

  _sockaddr2mpls_dest(&addr, from);
  return sock;
}

mpls_return_enum mpls_socket_bind(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, const mpls_dest * local)
{
  struct sockaddr addr;

  _mpls_dest2sockaddr(local, &addr);

  if (bind(socket->fd, &addr, sizeof(struct sockaddr_in)) < 0) {
    return MPLS_FAILURE;
  }

  return MPLS_SUCCESS;
}

mpls_return_enum mpls_socket_tcp_listen(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, int depth)
{
  if (listen(socket->fd, depth) < 0) {
    return MPLS_FAILURE;
  }
  return MPLS_SUCCESS;
}

mpls_return_enum mpls_socket_tcp_connect(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, const mpls_dest * to)
{
  struct sockaddr addr, *iaddr = NULL;

  if (to != NULL) {
    _mpls_dest2sockaddr(to, &addr);
    iaddr = &addr;
  } else {
    iaddr = NULL;
  }

  if (connect(socket->fd, iaddr, sizeof(struct sockaddr)) < 0) {
    if (errno == EINPROGRESS) {
      return MPLS_NON_BLOCKING;
    }

    if (errno == EALREADY) {
      return MPLS_SUCCESS;
    }
    perror("connect");
    return MPLS_FAILURE;
  }
  return MPLS_SUCCESS;
}

mpls_return_enum mpls_socket_connect_status(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket)
{
  int size = sizeof(int);
  int num = 1;

  if (getsockopt(socket->fd, SOL_SOCKET, SO_ERROR, &num, &size) < 0) {
    perror("getsockopt");
    return MPLS_FAILURE;
  }
  if (!num) {
    return MPLS_SUCCESS;
  }
  perror("getsockopt");
  return MPLS_NON_BLOCKING;
}

int mpls_socket_get_errno(const mpls_socket_mgr_handle handle,
  mpls_socket_handle socket)
{
  return errno;
}

mpls_return_enum mpls_socket_options(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, uint32_t flag)
{
  int one = 1;

  if (flag & MPLS_SOCKOP_REUSE) {
    if (setsockopt(socket->fd, SOL_SOCKET, SO_REUSEADDR, (char *)&one,
        sizeof(one)) < 0) {
      return MPLS_FAILURE;
    }
  }
  if (flag & MPLS_SOCKOP_NONBLOCK) {
    if (fcntl(socket->fd, F_SETFL, O_NONBLOCK) < 0) {
      return MPLS_FAILURE;
    }
  }
  if (flag & MPLS_SOCKOP_ROUTERALERT) {
    if (setsockopt(socket->fd, SOL_IP, IP_ROUTER_ALERT, (char *)&one,
      sizeof(one)) < 0) {
      return MPLS_FAILURE;
    }
  }
  if (flag & MPLS_SOCKOP_HDRINCL) {
    if (setsockopt(socket->fd, SOL_IP, IP_HDRINCL, (char *)&one,
      sizeof(one)) < 0) {
      return MPLS_FAILURE;
    }
  }
  return MPLS_SUCCESS;
}

mpls_return_enum mpls_socket_multicast_options(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, int ttl, int loop)
{
  int zero = loop;
  int one = ttl;

  if (setsockopt(socket->fd,SOL_IP,IP_MULTICAST_TTL,&one,sizeof(one))<0) {
    return MPLS_FAILURE;
  }

  if (setsockopt(socket->fd,SOL_IP,IP_MULTICAST_LOOP,&zero,sizeof(zero))<0) {
    return MPLS_FAILURE;
  }

  return MPLS_SUCCESS;
}

mpls_return_enum mpls_socket_multicast_if_tx(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, const ldp_if * iff)
{
  struct in_addr addr;
  unsigned int ifindex = 0;
  addr.s_addr = 0;

  if (iff == NULL) {
    addr.s_addr = ntohl(INADDR_ANY);
  } else {
    ifindex = iff->handle->ifindex;
  }

  if (setsockopt_ipv4_multicast (socket->fd, IP_MULTICAST_IF, 0, ifindex)<0) {
    return MPLS_FAILURE;
  }

  return MPLS_SUCCESS;
}

mpls_return_enum mpls_socket_multicast_if_join(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, const ldp_if * iff, const mpls_inet_addr * mult)
{
  struct in_addr addr;
  unsigned int ifindex = 0;
  addr.s_addr = 0;

  if (iff == NULL) {
    addr.s_addr = ntohl(INADDR_ANY);
  } else {
    ifindex = iff->handle->ifindex;
  }

  if (setsockopt_ipv4_multicast (socket->fd, IP_ADD_MEMBERSHIP, 
    htonl(mult->u.ipv4), ifindex)<0) {
    return MPLS_FAILURE;
  }

  return MPLS_SUCCESS;
}

void mpls_socket_multicast_if_drop(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, const ldp_if * iff, const mpls_inet_addr * mult)
{
  struct in_addr addr;
  unsigned int ifindex = 0;
  addr.s_addr = 0;

  if (iff == NULL) {
    addr.s_addr = ntohl(INADDR_ANY);
  } else {
    ifindex = iff->handle->ifindex;
  }

  if (setsockopt_ipv4_multicast(socket->fd, IP_DROP_MEMBERSHIP,
    htonl(mult->u.ipv4), ifindex)<0) {
    return;
  }

  return;
}

mpls_return_enum mpls_socket_readlist_add(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, void *extra, mpls_socket_enum type)
{
  socket->type = type;
  socket->extra = extra;
  MPLS_ASSERT(socket && (socket->fd > -1));
  socket->read = thread_add_read(master,mplsd_read,socket,socket->fd);
  MPLS_ASSERT(socket->read);
  return MPLS_SUCCESS;
}

void mpls_socket_readlist_del(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket)
{
  if (socket && socket->read) {
    thread_cancel(socket->read);
    socket->read = NULL;
  }
}

mpls_return_enum mpls_socket_writelist_add(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, void *extra, mpls_socket_enum type)
{
  socket->type = type;
  socket->extra = extra;
  MPLS_ASSERT(socket && (socket->fd > -1));
  socket->write = thread_add_write(master,mplsd_write,socket,socket->fd);
  MPLS_ASSERT(socket->write);
  return MPLS_SUCCESS;
}

void mpls_socket_writelist_del(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket)
{
  if (socket) {
    thread_cancel(socket->write);
    socket->write = NULL;
  }
}
  
int mpls_socket_tcp_read(mpls_socket_mgr_handle handle, mpls_socket_handle socket,
  uint8_t * buffer, int size)
{
  int ret = read(socket->fd,buffer,size);
  if (ret < 0 && errno != EAGAIN) {
    perror("mpls_socket_tcp_read");
    return 0;
  }
  return ret;
}

int mpls_socket_tcp_write(mpls_socket_mgr_handle handle, mpls_socket_handle socket,
  uint8_t * buffer, int size)
{
  return write(socket->fd,buffer,size);
}

int mpls_socket_udp_sendto(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, uint8_t * buffer, int size, const mpls_dest * to)
{
  struct sockaddr addr;
  int retval;

  _mpls_dest2sockaddr(to, &addr);

  retval = sendto(socket->fd,buffer,size,0,&addr,sizeof(struct sockaddr));

  return retval;
}

int mpls_socket_udp_recvfrom(mpls_socket_mgr_handle handle,
  mpls_socket_handle socket, uint8_t * buffer, int size, mpls_dest * from)
{
  int ret;
  unsigned int ifindex = 0;
  struct iovec iov;
  struct cmsghdr *cmsg;
  struct in_pktinfo *pktinfo;
  struct sockaddr addr;
  char buff [sizeof (*cmsg) + sizeof (*pktinfo)];
  struct msghdr msgh = {&addr, sizeof(struct sockaddr), &iov, 1, buff,
                        sizeof (*cmsg) + sizeof (*pktinfo), 0};

  iov.iov_base = buffer;
  iov.iov_len = size;
  ret = recvmsg(socket->fd,&msgh,0);

  if (ret < 0 && errno != EAGAIN) {
    return 0;
  }

  cmsg = CMSG_FIRSTHDR(&msgh);

  if (cmsg != NULL &&
      cmsg->cmsg_level == IPPROTO_IP &&
      cmsg->cmsg_type == IP_PKTINFO) {
      pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
      ifindex = pktinfo->ipi_ifindex;
      from->if_handle = if_lookup_by_index(ifindex);
      _sockaddr2mpls_dest((const struct sockaddr*)&addr, from);
  }

  return ret;
}
