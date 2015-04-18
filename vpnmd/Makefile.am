# Process this file with automake to produce Makefile.in.
INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"
sbin_PROGRAMS = vpnmd
vpnmd_SOURCES = vpnmd_main.c vpnmd_zebra.c vpnmd_vty.c vpnmd_table.c vpnm.c vpnmd_process.c vpnmd_socket.c connect_daemon.c vpnm_via_ldp.c vpnm_via_rsvp.c vpnm_via_brctl.c vpnm_via_mpls.c
LIBS = @LIBS@ @CURSES@ @LIBPAM@
#noinst_HEADERS = mplsadmd.h
vpnmd_LDADD = -L../lib -lzebra @LIBCAP@
