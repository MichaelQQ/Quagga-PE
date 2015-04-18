## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

noinst_LIBRARIES = libldp.a
sbin_PROGRAMS = ldpd

libldp_a_SOURCES = \
impl_fib.c        ldp_buf.c        ldp_interface.c       ldp_peer.c \
impl_ifmgr.c      ldp.c            ldp_keepalive.c       ldp_remote_peer.c \
impl_lock.c       ldp_cfg.c        ldp_label_abort.c     ldp_resource.c \
impl_mm.c         ldp_entity.c     ldp_label_mapping.c   ldp_session.c \
impl_mpls.c       ldp_fec.c        ldp_label_rel_with.c  ldp_state_funcs.c \
impl_policy.c     ldp_global.c     ldp_label_request.c   ldp_state_machine.c \
impl_socket.c     ldp_hello.c      ldp_tunnel.c \
impl_timer.c      ldp_hop.c        ldp_mesg.c            ldp_vty.c \
impl_tree.c       ldp_hop_list.c   ldp_nexthop.c         ldp_zebra.c \
l2cc_interface.c  ldp_if.c         ldp_nortel.c          mpls_compare.c \
ldp_addr.c        ldp_inet_addr.c  ldp_notif.c \
ldp_adj.c         ldp_init.c       ldp_outlabel.c \
ldp_attr.c        ldp_inlabel.c    ldp_pdu_setup.c \
connect_daemon.c  ldp_pw.c

noinst_HEADERS = \
impl_fib.h        ldp_hop_list.h        ldp_pdu.h            mpls_ifmgr_impl.h \
impl_ifmgr.h      ldp_if.h              ldp_pdu_setup.h      mpls_list.h \
impl_mpls.h       ldp_inet_addr.h       ldp_peer.h           mpls_lock_impl.h \
l2cc_interface.h  ldp_init.h            ldp_remote_peer.h    mpls_mm_impl.h \
ldp_addr.h        ldp_inlabel.h         ldp_resource.h       mpls_mpls_impl.h \
ldp_attr.h        ldp_keepalive.h       ldp_state_machine.h  mpls_refcnt.h \
ldp_buf.h         ldp_label_abort.h     ldp_struct.h         mpls_socket_impl.h\
ldp_cfg.h         ldp_label_mapping.h   ldp_tunnel.h         mpls_struct.h\
ldp_defaults.h    ldp_label_rel_with.h  ldp_vty.h            mpls_timer_impl.h\
ldp_entity.h      ldp_label_request.h   ldp_zebra.h          mpls_trace.h\
ldp_fec.h         ldp_mesg.h            mpls_assert.h        mpls_trace_impl.h\
ldp_global.h      ldp_nexthop.h         mpls_bitfield.h      mpls_tree_impl.h\
ldp.h             ldp_nortel.h          mpls_compare.h \
ldp_hello.h       ldp_notif.h           mpls_fib_impl.h \
ldp_hop.h         ldp_outlabel.h        mpls_handle_type.h \
connect_daemon.h     ldp_pw.h 

ldpd_SOURCES = \
	ldp_main.c $(libldp_a_SOURCES)

ldpd_LDADD = ../lib/libzebra.la @LIBCAP@

examplesdir = $(exampledir)
dist_examples_DATA = ldpd.conf.sample


