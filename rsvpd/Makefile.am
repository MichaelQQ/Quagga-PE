# Process this file with automake to produce Makefile.in.
INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"
sbin_PROGRAMS = rsvpd
rsvpd_SOURCES = rsvpd_main.c rsvpd_zebra.c rsvpd_vty.c #rsvpd_lib.c rsvpd.c

LIBS = @LIBS@ @CURSES@ @LIBPAM@
#noinst_HEADERS = rsvpd.h
rsvpd_LDADD = -L../lib -lzebra @LIBCAP@
