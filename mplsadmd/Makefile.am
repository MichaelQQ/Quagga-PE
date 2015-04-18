# Process this file with automake to produce Makefile.in.
INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"
sbin_PROGRAMS = mplsadmd
mplsadmd_SOURCES = mplsadmd_main.c mplsadmd_zebra.c mplsadmd_vty.c libmpls.c mpls.c utils.c dnet_pton.c libnetlink.c ll_map.c mpls_monitor.c
LIBS = @LIBS@ @CURSES@ @LIBPAM@
#noinst_HEADERS = mplsadmd.h
mplsadmd_LDADD = -L../lib -lzebra @LIBCAP@
