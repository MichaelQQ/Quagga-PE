#define MPLS_LINUX 0

#include <zebra.h>

#include "stream.h"
#include "prefix.h"
#include "log.h"
#include "zclient.h"
#include "if.h"

#include "ldp.h"
#include "ldp_struct.h"
#include "ldp_entity.h"
#include "mpls_mpls_impl.h"
#include "mpls_socket_impl.h"
#if MPLS_LINUX
#include <linux/mpls.h>
#endif

#include "ldp_interface.h"
#include "impl_fib.h"

#include "ldp_zebra.h"

static int label = 10000;
extern struct zclient *zclient;

#if MPLS_LINUX

static int mplsd_socket = 0;

int mplsd_ioctl (u_long request, caddr_t buffer) {
  int ret = 0;
  int err = 0;
  
  if (!mplsd_socket) {
    mplsd_socket = socket (AF_INET, SOCK_DGRAM, 0);
    if (mplsd_socket < 0) {
      perror ("socket");
      exit (1);
    }
  }

  ret = ioctl (mplsd_socket, request, buffer);
  if (ret < 0) {
    err = errno;
  }

  if (ret < 0) {
    errno = err;
    return ret;
  }
  return 0;
}

#endif

int do_mpls_labelspace(struct ldp_interface *li) {
#if MPLS_LINUX
  struct mpls_labelspace_req mls;

  if (!mi || !mi->ifp->ifindex) {
    return 1;
  }

  memset(&mls,0,sizeof(struct mpls_labelspace_req));
  mls.mls_ifindex = mi->ifp->ifindex;
  mls.mls_labelspace = mi->labelspace;
  if (mplsd_ioctl(SIOCSLABELSPACEMPLS,(caddr_t)&mls)) {
    return 1;
  }
#endif
  return 0;
}

mpls_mpls_handle mpls_mpls_open(mpls_instance_handle user_data)
{
  return socket(AF_INET, SOCK_STREAM, 0);
}

void mpls_mpls_close(mpls_mpls_handle handle)
{
  close(handle);
}

mpls_return_enum mpls_mpls_outsegment_add(mpls_mpls_handle handle, mpls_outsegment * o)
{
#if MPLS_LINUX
  struct mpls_out_label_req oreq;
  struct mpls_instr_req mir;
  struct sockaddr_in sin;
  int result;

  memset(&oreq,0,sizeof(oreq));
  memset(&mir,0,sizeof(mir));
  oreq.mol_label.ml_type = MPLS_LABEL_KEY;
  result = ioctl(handle,SIOCMPLSNHLFEADD,&oreq);
  o->handle = oreq.mol_label.u.ml_key;

  mir.mir_direction = MPLS_OUT;
  mir.mir_label.ml_type = MPLS_LABEL_KEY;
  mir.mir_label.u.ml_key = o->handle;
  mir.mir_instr[0].mir_opcode = MPLS_OP_PUSH;
  mir.mir_instr[0].mir_data.push.ml_type = MPLS_LABEL_GEN;
  mir.mir_instr[0].mir_data.push.u.ml_gen = o->label.u.gen;

  mir.mir_instr[1].mir_opcode = MPLS_OP_SET;
  mir.mir_instr[1].mir_data.set.mni_if = o->nexthop.if_handle->ifindex;
  sin.sin_addr.s_addr = htonl(o->nexthop.ip.u.ipv4);
  sin.sin_family = AF_INET;
  memcpy(&mir.mir_instr[1].mir_data.set.mni_addr,
    &sin,sizeof(struct sockaddr));

  mir.mir_instr_length = 2;
  result = ioctl(handle,SIOCSMPLSOUTINSTR,&mir);

#endif
  return MPLS_SUCCESS;
}

void mpls_mpls_outsegment_del(mpls_mpls_handle handle, mpls_outsegment * o)
{
#if MPLS_LINUX
  struct mpls_out_label_req oreq;
  int result;

  oreq.mol_label.ml_type = MPLS_LABEL_KEY;
  oreq.mol_label.u.ml_key = o->handle;
  result = ioctl(handle,SIOCMPLSNHLFEDEL,&oreq);

#endif
}

mpls_return_enum mpls_mpls_insegment_add(mpls_mpls_handle handle,
  mpls_insegment * i)
{
#if MPLS_LINUX
  struct mpls_in_label_req ireq;
  int result;
#endif

  if (i->label.type == MPLS_LABEL_TYPE_NONE) {
    i->label.type = MPLS_LABEL_TYPE_GENERIC;
    i->label.u.gen = label++;
  }

#if MPLS_LINUX
  ireq.mil_label.ml_type = MPLS_LABEL_GEN;
  ireq.mil_label.u.ml_gen = i->label.u.gen;
  ireq.mil_label.ml_index = i->labelspace;
  i->handle = 0;

  result = ioctl(handle,SIOCMPLSILMADD,&ireq);

#endif
  return MPLS_SUCCESS;
}

void mpls_mpls_insegment_del(mpls_mpls_handle handle, mpls_insegment * i)
{
#if MPLS_LINUX
  struct mpls_in_label_req ireq;
  int result;

  ireq.mil_label.ml_type = MPLS_LABEL_GEN;
  ireq.mil_label.u.ml_gen = i->label.u.gen;
  ireq.mil_label.ml_index = i->labelspace;

  result = ioctl(handle,SIOCMPLSILMDEL,&ireq);
#endif
}

mpls_return_enum mpls_mpls_xconnect_add(mpls_mpls_handle handle, mpls_insegment * i, mpls_outsegment * o)
{
#if MPLS_LINUX
  struct mpls_xconnect_req xreq;
  int result;

  xreq.mx_in.ml_type = MPLS_LABEL_GEN;
  xreq.mx_in.u.ml_gen = i->label.u.gen;
  xreq.mx_in.ml_index = i->labelspace;

  xreq.mx_out.ml_type = MPLS_LABEL_KEY;
  xreq.mx_out.u.ml_key = o->handle;

  result = ioctl(handle,SIOCMPLSXCADD,&xreq);

#endif
  return MPLS_SUCCESS;
}

void mpls_mpls_xconnect_del(mpls_mpls_handle handle, mpls_insegment * i,
  mpls_outsegment * o)
{
#if MPLS_LINUX
  struct mpls_xconnect_req xreq;
  int result;

  xreq.mx_in.ml_type = MPLS_LABEL_GEN;
  xreq.mx_in.u.ml_gen = i->label.u.gen;
  xreq.mx_in.ml_index = i->labelspace;

  xreq.mx_out.ml_type = MPLS_LABEL_KEY;
  xreq.mx_out.u.ml_key = o->handle;

  result = ioctl(handle,SIOCMPLSXCDEL,&xreq);

#endif
}

mpls_return_enum mpls_mpls_fec2out_add(mpls_mpls_handle handle, mpls_fec * f,
  mpls_outsegment * o)
{
  struct prefix p;
  struct in_addr addr;
  unsigned int ifindex;
  unsigned int mplsindex;
#if 0
  int retval;
#endif

  mplsindex = o->handle;
  ifindex = o->nexthop.if_handle->ifindex;
  addr.s_addr = htonl(o->nexthop.ip.u.ipv4);

  mpls_fec2zebra_prefix(f,&p);
#if 0
  retval = zapi_ipv4_set_mplsindex(zclient,(struct prefix_ipv4*)&p,
    &addr,ifindex,mplsindex);
#endif

  return MPLS_SUCCESS;
}

void mpls_mpls_fec2out_del(mpls_mpls_handle handle, mpls_fec * f,
  mpls_outsegment * o)
{
  struct prefix p;
  struct in_addr addr;
  unsigned int ifindex;
  unsigned int mplsindex;
#if 0
  int retval;
#endif

  mplsindex = o->handle;
  ifindex = o->nexthop.if_handle->ifindex;
  addr.s_addr = htonl(o->nexthop.ip.u.ipv4);

  mpls_fec2zebra_prefix(f,&p);
#if 0
  retval = zapi_ipv4_set_mplsindex(zclient,(struct prefix_ipv4*)&p,
    &addr,ifindex,0);
#endif
}

mpls_return_enum mpls_mpls_get_label_space_range(mpls_mpls_handle handle,
  mpls_range * r)
{
  r->type = MPLS_LABEL_RANGE_GENERIC;
  r->min.u.gen = 16;
  r->max.u.gen = 0xFFFFF;

  return MPLS_SUCCESS;
}
